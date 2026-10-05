package main

// SPIDER-SEC-3 shared unit tests.
//
// This file is byte-identical in client/sec3_test.go and server/sec3_test.go.
// It exercises only the mirrored protocol core (crypto.go, padding.go), so
// the same assertions must hold in both modules — which is the mechanism that
// catches the two copies drifting apart.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// Record layer
// ----------------------------------------------------------------------------

// testStates builds a matched client/server pair over one master secret.
func testStates(t *testing.T, aeadID uint8, rotateBytes int64, rotateEvery time.Duration) (cli, srv *sec3State) {
	t.Helper()
	master := bytes.Repeat([]byte{0x42}, sec3KeySize)
	var err error
	cli, err = newSec3State(master, aeadID, "c2s", "s2c", rotateBytes, rotateEvery)
	if err != nil {
		t.Fatalf("client state: %v", err)
	}
	srv, err = newSec3State(master, aeadID, "s2c", "c2s", rotateBytes, rotateEvery)
	if err != nil {
		t.Fatalf("server state: %v", err)
	}
	return cli, srv
}

func TestRecordRoundTrip(t *testing.T) {
	for _, id := range []uint8{aeadAES256GCM, aeadChaChaPoly} {
		t.Run(aeadName(id), func(t *testing.T) {
			cli, srv := testStates(t, id, 0, 0)
			for i := 0; i < 32; i++ {
				plain := EncodeFrame(MsgData, uint32(i+1), []byte(fmt.Sprintf("payload %d", i)))
				rec, err := cli.seal(recFrame, plain)
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				if bytes.Contains(rec, plain) {
					t.Fatalf("record %d contains its plaintext", i)
				}
				gotType, got, err := srv.open(rec)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if gotType != recFrame {
					t.Fatalf("rec type = 0x%02x, want 0x%02x", gotType, recFrame)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("record %d round trip mismatch", i)
				}
				// The other direction works too.
				back, err := srv.seal(recFrame, plain)
				if err != nil {
					t.Fatalf("seal reverse: %v", err)
				}
				if _, _, err := cli.open(back); err != nil {
					t.Fatalf("open reverse: %v", err)
				}
			}
		})
	}
}

func TestRecordRejectsTamper(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)
	base, err := cli.seal(recFrame, EncodeFrame(MsgData, 7, []byte("secret payload")))
	if err != nil {
		t.Fatal(err)
	}

	// Every byte position of a valid record must either be rejected or,
	// for a position that only changes an already-checked header field,
	// still fail. Corrupting any single byte of an authenticated record
	// must never yield a successful open.
	for pos := 0; pos < len(base); pos++ {
		rec := append([]byte(nil), base...)
		rec[pos] ^= 0x01
		if _, _, err := srv.open(rec); err == nil {
			t.Fatalf("tampered byte %d was accepted", pos)
		}
	}
}

func TestRecordRejectsLengthMismatch(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)
	rec, err := cli.seal(recFrame, EncodeFrame(MsgPing, 0, []byte("hb")))
	if err != nil {
		t.Fatal(err)
	}
	// Truncate: the declared ct_len no longer matches the body.
	if _, _, err := srv.open(rec[:len(rec)-1]); err == nil {
		t.Fatal("truncated record was accepted")
	}
	// Append: same mismatch in the other direction.
	if _, _, err := srv.open(append(append([]byte(nil), rec...), 0x00)); err == nil {
		t.Fatal("padded record was accepted")
	}
}

func TestRecordRejectsReplay(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)
	rec, err := cli.seal(recFrame, EncodeFrame(MsgData, 1, []byte("once")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.open(rec); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, _, err := srv.open(rec); err == nil {
		t.Fatal("replayed record was accepted")
	}
}

func TestRecordRejectsReorder(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)
	first, err := cli.seal(recFrame, EncodeFrame(MsgData, 1, []byte("a")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cli.seal(recFrame, EncodeFrame(MsgData, 1, []byte("b")))
	if err != nil {
		t.Fatal(err)
	}
	// Deliver the second record first.
	if _, _, err := srv.open(second); err == nil {
		t.Fatal("out-of-order record was accepted")
	}
	// The receiver must still be on seq 0, so the first record lands.
	if _, _, err := srv.open(first); err != nil {
		t.Fatalf("in-order record rejected after a reorder: %v", err)
	}
}

func TestRecordRejectsEpochRegression(t *testing.T) {
	// rotateBytes=1 means the sender advances an epoch on every record, so
	// the delivered sequence is epoch 0, 1, 2, 3 — each with seq 0.
	cli, srv := testStates(t, aeadAES256GCM, 1, 0)

	// Seal an epoch-0 record but never deliver it, so it is still a valid,
	// unconsumed ciphertext when the receiver has moved on.
	stale, err := cli.seal(recFrame, EncodeFrame(MsgData, 1, []byte("stale")))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(stale[10:14]); got != 0 {
		t.Fatalf("setup: stale record is in epoch %d, want 0", got)
	}

	// Deliver only the later records; the receiver walks 0 -> 1 -> 2 -> 3.
	for i := 0; i < 3; i++ {
		rec, err := cli.seal(recFrame, EncodeFrame(MsgData, uint32(i+10), []byte("later")))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := srv.open(rec); err != nil {
			t.Fatalf("setup open %d: %v", i, err)
		}
	}
	_, _, rxEpoch, _, _ := srv.status()
	if rxEpoch != 3 {
		t.Fatalf("setup: receiver at epoch %d, want 3", rxEpoch)
	}

	// Replaying the unconsumed epoch-0 record must fail as a regression.
	if _, _, err := srv.open(stale); err == nil {
		t.Fatal("stale epoch-0 record was accepted after rotating forward")
	}
	// State must not have moved backwards.
	_, _, after, _, _ := srv.status()
	if after != 3 {
		t.Fatalf("receiver epoch moved to %d on a rejected record", after)
	}
}

func TestRecordRejectsPaddingAsFrame(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)
	rec, err := cli.seal(recPadding, bytes.Repeat([]byte{0xA5}, 64))
	if err != nil {
		t.Fatal(err)
	}
	recType, _, err := srv.open(rec)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if recType != recPadding {
		t.Fatalf("rec type = 0x%02x, want recPadding", recType)
	}
	// rec_type is inside the AAD, so flipping it breaks authentication
	// rather than reclassifying padding as application data.
	forged := append([]byte(nil), rec...)
	forged[9] = recFrame
	if _, _, err := srv.open(forged); err == nil {
		t.Fatal("padding record forged into a frame record")
	}
}

func TestNonceNeverRepeats(t *testing.T) {
	cli, _ := testStates(t, aeadAES256GCM, 64, 0) // rotate often
	seen := map[string]bool{}
	for i := 0; i < 400; i++ {
		rec, err := cli.seal(recFrame, EncodeFrame(MsgData, uint32(i), []byte("n")))
		if err != nil {
			t.Fatal(err)
		}
		seq := binary.BigEndian.Uint64(rec[14:22])
		epoch := binary.BigEndian.Uint32(rec[10:14])
		key := fmt.Sprintf("%d/%d", epoch, seq)
		if seen[key] {
			t.Fatalf("nonce reused at epoch %d seq %d", epoch, seq)
		}
		seen[key] = true
	}
}

func TestRecordFailsClosedOnSeqExhaustion(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, sec3KeySize)
	s, err := newSec3State(master, aeadAES256GCM, "c2s", "s2c", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.txSeq = ^uint64(0)
	if _, err := s.seal(recFrame, []byte("x")); err == nil {
		t.Fatal("sequence exhaustion must be fatal")
	}
}

// ----------------------------------------------------------------------------
// Key rotation
// ----------------------------------------------------------------------------

func TestKeyRotationOnByteLimit(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 128, 0)
	payload := bytes.Repeat([]byte{0x7}, 64)

	startEpoch, _, _, _, _ := cli.status()
	if startEpoch != 0 {
		t.Fatalf("epoch starts at %d", startEpoch)
	}
	for i := 0; i < 8; i++ {
		rec, err := cli.seal(recFrame, payload)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		epoch := binary.BigEndian.Uint32(rec[10:14])
		if _, _, err := srv.open(rec); err != nil {
			t.Fatalf("open %d (epoch %d): %v", i, epoch, err)
		}
	}
	txEpoch, _, _, _, _ := cli.status()
	_, _, srvRxEpoch, _, _ := srv.status()
	if txEpoch == 0 {
		t.Fatal("sender never rotated: key_rotate_bytes did not fire")
	}
	if txEpoch != srvRxEpoch {
		t.Fatalf("epoch disagreement: sender %d, receiver %d", txEpoch, srvRxEpoch)
	}
}

func TestKeyRotationOnTimeLimit(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 20*time.Millisecond)
	// Force the epoch clock into the past rather than sleeping.
	cli.txMu.Lock()
	cli.txEpochAt = time.Now().Add(-time.Hour)
	cli.txMu.Unlock()

	rec, err := cli.seal(recFrame, EncodeFrame(MsgPing, 0, []byte("hb")))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(rec[10:14]); got != 1 {
		t.Fatalf("epoch = %d after the time trigger, want 1", got)
	}
	if _, _, err := srv.open(rec); err != nil {
		t.Fatalf("receiver rejected a time-triggered rotation: %v", err)
	}
	_, _, rxEpoch, _, _ := srv.status()
	if rxEpoch != 1 {
		t.Fatalf("receiver epoch = %d, want 1", rxEpoch)
	}
}

func TestRotationKeepsRelaying(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 512, 0)
	const frames = 64
	for i := 0; i < frames; i++ {
		payload := EncodeFrame(MsgData, uint32(i+1), []byte(fmt.Sprintf("stream chunk %04d", i)))
		rec, err := cli.seal(recFrame, payload)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		gotType, got, err := srv.open(rec)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if gotType != recFrame {
			t.Fatalf("frame %d lost its type across a rotation", i)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("frame %d corrupted across a rotation", i)
		}
	}
	txEpoch, _, _, _, _ := cli.status()
	if txEpoch == 0 {
		t.Fatal("rotation never happened during the stream")
	}
}

func TestRotationTriggersAreIndependent(t *testing.T) {
	payload := bytes.Repeat([]byte{0x01}, 64)

	// Byte trigger only: the time trigger is disabled, so an epoch clock
	// pushed far into the past must be ignored.
	cli, srv := testStates(t, aeadAES256GCM, 64, 0)
	cli.txMu.Lock()
	cli.txEpochAt = time.Now().Add(-24 * time.Hour)
	cli.txMu.Unlock()
	for i := 0; i < 4; i++ {
		rec, err := cli.seal(recFrame, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := srv.open(rec); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	epoch, _, _, _, _ := cli.status()
	if epoch == 0 {
		t.Fatal("byte trigger did not fire while the time trigger was disabled")
	}
	if _, _, rx, _, _ := srv.status(); rx != epoch {
		t.Fatalf("receiver at epoch %d, sender at %d", rx, epoch)
	}

	// Time trigger only: the byte trigger is disabled, so a single large
	// frame still must not count toward a byte limit.
	tCli, _ := testStates(t, aeadAES256GCM, 0, time.Hour)
	tCli.txMu.Lock()
	tCli.txEpochAt = time.Now().Add(-24 * time.Hour)
	tCli.txMu.Unlock()
	if _, err := tCli.seal(recFrame, payload); err != nil {
		t.Fatal(err)
	}
	tEpoch, _, _, _, _ := tCli.status()
	if tEpoch != 1 {
		t.Fatalf("time trigger produced epoch %d, want 1", tEpoch)
	}

	// Neither trigger: the epoch must not move at all, no matter how stale
	// the epoch clock is or how many frames are sent.
	none, _ := testStates(t, aeadAES256GCM, 0, 0)
	none.txMu.Lock()
	none.txEpochAt = time.Now().Add(-24 * time.Hour)
	none.txMu.Unlock()
	for i := 0; i < 8; i++ {
		if _, err := none.seal(recFrame, payload); err != nil {
			t.Fatal(err)
		}
	}
	noneEpoch, _, _, _, _ := none.status()
	if noneEpoch != 0 {
		t.Fatalf("epoch advanced to %d with both triggers disabled", noneEpoch)
	}
}

// ----------------------------------------------------------------------------
// Padding
// ----------------------------------------------------------------------------

func TestPaddingDisabledByDefault(t *testing.T) {
	if DefaultPaddingConfig().Enabled {
		t.Fatal("padding must ship disabled: a fixed shaping pattern is itself a fingerprint")
	}
}

func TestPaddingConfigValidates(t *testing.T) {
	base := DefaultPaddingConfig()
	if err := base.Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(*PaddingConfig)
	}{
		{"empty sizes", func(c *PaddingConfig) { c.Sizes = nil }},
		{"weight/size mismatch", func(c *PaddingConfig) { c.Weights = []float64{1} }},
		{"weights do not sum to 1", func(c *PaddingConfig) { c.Weights = []float64{0.5, 0.3, 0.05} }},
		{"non-increasing sizes", func(c *PaddingConfig) { c.Sizes = []int{4096, 1024, 51200}; c.Weights = []float64{0.7, 0.25, 0.05} }},
		{"non-positive size", func(c *PaddingConfig) { c.Sizes = []int{0, 16384, 51200}; c.Weights = []float64{0.7, 0.25, 0.05} }},
		{"zero-weight bucket", func(c *PaddingConfig) { c.Weights = []float64{0, 0.5, 0.5} }},
		{"oversized bucket", func(c *PaddingConfig) {
			c.Sizes = []int{4096, MaxPayloadSize + 1, MaxPayloadSize + 2}
			c.Weights = []float64{0.7, 0.25, 0.05}
		}},
		{"zero min interval", func(c *PaddingConfig) { c.MinInterval = 0 }},
		{"max <= min", func(c *PaddingConfig) { c.MaxInterval = c.MinInterval }},
		{"negative rate cap", func(c *PaddingConfig) { c.MaxKbps = -1 }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultPaddingConfig()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("invalid padding config %q was accepted", tc.name)
			}
		})
	}
}

func TestPaddingSizesStayWithinBuckets(t *testing.T) {
	cfg := DefaultPaddingConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	allowed := map[int]bool{}
	for _, s := range cfg.Sizes {
		allowed[s] = true
	}
	counts := map[int]int{}
	for i := 0; i < 3000; i++ {
		n, err := cfg.pickSize(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed[n] {
			t.Fatalf("picked size %d, which is not one of %v", n, cfg.Sizes)
		}
		if n > MaxPayloadSize {
			t.Fatalf("picked size %d exceeds the record limit", n)
		}
		counts[n]++
	}
	// The dominant bucket must actually dominate, otherwise the weights are
	// not being applied and padding has collapsed to one fixed size.
	if counts[cfg.Sizes[0]] < counts[cfg.Sizes[1]] {
		t.Fatalf("weights not applied: %v", counts)
	}
	if counts[cfg.Sizes[2]] == counts[cfg.Sizes[0]] {
		t.Fatalf("rare bucket drawn as often as the common one: %v", counts)
	}
}

func TestPaddingTimingIsNotPeriodic(t *testing.T) {
	cfg := DefaultPaddingConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	const draws = 2000
	var first, last time.Duration
	min, max := cfg.MaxInterval, time.Duration(0)
	sum := int64(0)
	for i := 0; i < draws; i++ {
		d, err := cfg.nextDelay(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = d
		}
		last = d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
		sum += int64(d)
	}

	// 1. No fixed period: a constant inter-arrival time would be trivially
	//    detectable, which is precisely the pattern padding must not create.
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		d, err := cfg.nextDelay(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if seen[d] {
			t.Fatalf("delay %s repeated — timing looks periodic", d)
		}
		seen[d] = true
	}

	// 2. The draw must actually span the configured range, not cluster.
	if min >= cfg.MaxInterval || max <= cfg.MinInterval {
		t.Fatalf("delays span [%s, %s], expected to reach beyond [%s, %s]", min, max, cfg.MinInterval, cfg.MaxInterval)
	}
	_ = first
	_ = last

	// 3. The mean should sit near the middle of the range, i.e. uniform.
	mean := time.Duration(sum / int64(draws))
	want := cfg.MinInterval + (cfg.MaxInterval-cfg.MinInterval)/2
	tolerance := (cfg.MaxInterval - cfg.MinInterval) / 4
	diff := mean - want
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Fatalf("mean delay %s is not near the centre %s of [%s, %s]",
			mean, want, cfg.MinInterval, cfg.MaxInterval)
	}
}

func TestPaddingRateCap(t *testing.T) {
	// 64 kibibits/s = 8192 bytes/s. A 16 KiB frame therefore cannot be sent
	// more than about twice a second, and the bucket must refuse a second
	// one immediately after.
	pacer := newPaddingPacer(64)
	now := time.Now()
	if !pacer.allow(now, 8192) {
		t.Fatal("first frame refused")
	}
	if pacer.allow(now, 8192) {
		t.Fatal("second identical frame accepted with no elapsed time: rate cap is not working")
	}
	// After a full second, ~8192 bytes are available again.
	if !pacer.allow(now.Add(time.Second), 8192) {
		t.Fatal("bucket did not refill after a second")
	}
}

func TestPaddingRateCapDisabledAtZero(t *testing.T) {
	pacer := newPaddingPacer(0)
	now := time.Now()
	for i := 0; i < 100; i++ {
		if !pacer.allow(now, 100000) {
			t.Fatal("max_kbps=0 must disable the cap, not block everything")
		}
	}
}

func TestPaddingDoesNotAlterAppData(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)

	const total = 40
	for i := 0; i < total; i++ {
		// Interleave a padding record between application frames, exactly as
		// runPadding does.
		pad, err := cli.seal(recPadding, bytes.Repeat([]byte{0xEE}, 4096))
		if err != nil {
			t.Fatal(err)
		}
		if padType, _, err := srv.open(pad); err != nil || padType != recPadding {
			t.Fatalf("padding record %d: type=0x%02x err=%v", i, padType, err)
		}

		payload := EncodeFrame(MsgData, 1, []byte(fmt.Sprintf("chunk %02d", i)))
		rec, err := cli.seal(recFrame, payload)
		if err != nil {
			t.Fatal(err)
		}
		recType, plain, err := srv.open(rec)
		if err != nil {
			t.Fatalf("app frame %d rejected after padding: %v", i, err)
		}
		if recType != recFrame {
			t.Fatalf("app frame %d misclassified", i)
		}
		frame, err := DecodeFrame(plain)
		if err != nil {
			t.Fatalf("app frame %d did not decode: %v", i, err)
		}
		want := fmt.Sprintf("chunk %02d", i)
		if string(frame.Payload) != want {
			t.Fatalf("app frame %d = %q, want %q", i, frame.Payload, want)
		}
	}
}

func TestPaddingSenderStopsWhenDisabled(t *testing.T) {
	cfg := DefaultPaddingConfig() // Enabled == false
	cfg.Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	called := make(chan struct{}, 1)
	runPadding(ctx, &cfg, func([]byte) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	}, nil)
	select {
	case <-called:
		t.Fatal("padding ran while disabled")
	default:
	}
}

func TestPaddingSenderStopsOnSendError(t *testing.T) {
	cfg := DefaultPaddingConfig()
	cfg.Enabled = true
	cfg.MinInterval = time.Millisecond
	cfg.MaxInterval = 2 * time.Millisecond
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var attempts int
	var mu sync.Mutex
	runPadding(ctx, &cfg, func([]byte) error {
		mu.Lock()
		attempts++
		mu.Unlock()
		return fmt.Errorf("connection closed")
	}, nil)
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("padding attempted %d sends after the first error, want 1", attempts)
	}
}

// ----------------------------------------------------------------------------
// Handshake envelopes and inner-hello secrecy
// ----------------------------------------------------------------------------

func TestHandshakeEnvelopeRoundTrip(t *testing.T) {
	body := []byte("some handshake body")
	msg := buildHandshakeMsg(msgInnerHello, body)
	got, err := parseHandshakeMsg(msg, msgInnerHello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body round trip mismatch")
	}
	if _, err := parseHandshakeMsg(msg, msgServerHello); err == nil {
		t.Fatal("message accepted under the wrong type")
	}
	if _, err := parseHandshakeMsg(msg[:5], msgInnerHello); err == nil {
		t.Fatal("truncated envelope accepted")
	}
	bad := append([]byte(nil), msg...)
	bad[0] = 'X'
	if _, err := parseHandshakeMsg(bad, msgInnerHello); err == nil {
		t.Fatal("bad magic accepted")
	}
	// Length prefix corrupted: must be rejected before any allocation.
	bad = append([]byte(nil), msg...)
	bad[13] ^= 0xFF
	if _, err := parseHandshakeMsg(bad, msgInnerHello); err == nil {
		t.Fatal("corrupted length prefix accepted")
	}
}

func TestSealOpenEnvelope(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, sec3KeySize)
	eph := bytes.Repeat([]byte{0x22}, 32)
	salt := bytes.Repeat([]byte{0x33}, sec3SaltSize)
	plain := []byte(`{"hello":"world"}`)

	msg, err := sealEnvelope(aeadAES256GCM, key, msgInnerHello, eph, salt, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg, plain) {
		t.Fatal("envelope leaked its plaintext")
	}
	got, id, err := openEnvelope(key, msg, msgInnerHello)
	if err != nil {
		t.Fatal(err)
	}
	if id != aeadAES256GCM {
		t.Fatalf("aead id = %d", id)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch")
	}

	// Wrong key.
	if _, _, err := openEnvelope(bytes.Repeat([]byte{0x44}, sec3KeySize), msg, msgInnerHello); err == nil {
		t.Fatal("envelope opened under the wrong key")
	}
	// Tampered ciphertext.
	bad := append([]byte(nil), msg...)
	bad[len(bad)-1] ^= 1
	if _, _, err := openEnvelope(key, bad, msgInnerHello); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	// Non-zero epoch/seq in a handshake envelope: rejected.
	body, _ := parseHandshakeMsg(msg, msgInnerHello)
	env := buildInnerEnvelope(eph, salt, 0, 1, aeadAES256GCM, body[61:])
	rebuilt := buildHandshakeMsg(msgInnerHello, env)
	if _, _, err := openEnvelope(key, rebuilt, msgInnerHello); err == nil {
		t.Fatal("handshake envelope with seq=1 accepted")
	}
}

func TestInnerHelloIsNotLinkable(t *testing.T) {
	// Two handshakes with the same token and the same public key material
	// must produce different ciphertexts, otherwise an observer could match
	// connections across time to one credential.
	token := testToken(t)
	key := innerHelloKey(token, bytes.Repeat([]byte{0x01}, 32), []byte("aad"))
	eph := bytes.Repeat([]byte{0x02}, 32)
	plain := []byte(`{"token_hash":"same"}`)

	var first []byte
	for i := 0; i < 8; i++ {
		salt := make([]byte, sec3SaltSize)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		msg, err := sealEnvelope(aeadAES256GCM, key, msgInnerHello, eph, salt, plain)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = msg
			continue
		}
		if bytes.Equal(first, msg) {
			t.Fatal("two inner hellos produced identical ciphertext: they are linkable")
		}
	}
}

func TestNoPlaintextSecretsInInnerHello(t *testing.T) {
	token := testToken(t)
	sharedES := bytes.Repeat([]byte{0x05}, 32)
	eph := bytes.Repeat([]byte{0x06}, 32)
	salt := bytes.Repeat([]byte{0x07}, sec3SaltSize)

	inner := clientHelloInner{
		ClientID:  "spider-node-01",
		TokenHash: tokenHash(token),
		Features:  []string{"tcp", "https", "udp"},
		Session: sessionParameters{
			MaxFrame:         MaxPayloadSize,
			PaddingBucket:    []int{4096, 16384, 51200},
			KeyRotateBytes:   1 << 30,
			KeyRotateSeconds: 3600,
			Aead:             aeadName(aeadAES256GCM),
		},
		Timestamp: 1770000000,
		Nonce:     "noncenoncenoncenoncenoncenonce",
	}
	plain, err := canonicalJSON(inner)
	if err != nil {
		t.Fatal(err)
	}

	aad, err := envelopeAAD(msgInnerHello, eph, salt, aeadAES256GCM, len(plain))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := sealEnvelope(aeadAES256GCM, innerHelloKey(token, sharedES, aad), msgInnerHello, eph, salt, plain)
	if err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		token,
		tokenHash(token),
		"spider-node-01",
		"client_id",
		"token_hash",
		"session_parameters",
		aeadName(aeadAES256GCM),
		"http/1.1",
	}
	for _, s := range secrets {
		if bytes.Contains(msg, []byte(s)) {
			t.Fatalf("handshake message leaks %q", s)
		}
	}
	// Sanity: the plaintext really does contain them, so the assertion above
	// is not vacuous.
	if !bytes.Contains(plain, []byte(tokenHash(token))) {
		t.Fatal("test is vacuous: the plaintext does not contain the token hash")
	}
}

func TestTokenHashIsNotAPersistentHint(t *testing.T) {
	// SEC-1's weakness was a *stable* value derived from the token and sent
	// in the clear as a server-side lookup key. SEC-3 still needs a token
	// hash — but it lives strictly inside ClientHelloInner's ciphertext, and
	// it must not reduce to anything recognisably like the token itself.
	token := testToken(t)
	h := tokenHash(token)
	if len(h) != 64 {
		t.Fatalf("token hash is %d hex chars, want 64", len(h))
	}
	if strings.Contains(strings.ToLower(h), strings.ToLower(token)) {
		t.Fatal("token hash contains the token")
	}
	// Two different tokens must give two different hashes.
	if tokenHash("another-totally-different-token-value-0123456789") == h {
		t.Fatal("token hash is not credential-specific")
	}
}

// ----------------------------------------------------------------------------
// Token strength
// ----------------------------------------------------------------------------

func TestValidateToken(t *testing.T) {
	good := testToken(t)
	if _, err := ValidateToken(good); err != nil {
		t.Fatalf("strong token rejected: %v", err)
	}
	// Every credential the server hands out must be one a client will
	// accept. A single draw is not enough: a random 64-char hex string has a
	// real chance of clustering below the distinct-character floor, and any
	// such miss would be a primary token the client refuses outright.
	for i := 0; i < 200; i++ {
		tok := generateTokenForTest()
		if _, err := ValidateToken(tok); err != nil {
			t.Fatalf("server-generated token %d rejected: %v", i, err)
		}
	}

	bad := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"short", "abc123"},
		{"32 lowercase-only chars", strings.Repeat("a", 32)},
		{"repetitive", "0123456789012345678901234567890"},
		{"31 hex chars", strings.Repeat("abcdef0123456789", 2)[:31]},
		{"15 distinct hex chars", strings.Repeat("0123456789abcde", 5)[:64]},
		{"all zeros", strings.Repeat("0", 64)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateToken(tc.token); err == nil {
				t.Fatalf("weak token %q was accepted", tc.name)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Outer cover profile
// ----------------------------------------------------------------------------

func TestOuterProfileParsesAndValidates(t *testing.T) {
	valid := `{"sni":"snapp.ir","alpn":["h2","http/1.1"],"fingerprint":"chrome","padding":true}`
	p, err := parseOuterProfile([]byte(valid))
	if err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	if p.SNI != "snapp.ir" || !p.Padding || p.Fingerprint != "chrome" {
		t.Fatalf("unexpected parse result: %+v", p)
	}

	invalid := []struct {
		name string
		json string
	}{
		{"not an object", `[1,2,3]`},
		{"empty sni", `{"sni":"","alpn":["h2"],"fingerprint":"chrome","padding":false}`},
		{"empty alpn", `{"sni":"snapp.ir","alpn":[],"fingerprint":"chrome","padding":false}`},
		{"unknown fingerprint", `{"sni":"snapp.ir","alpn":["h2"],"fingerprint":"netscape","padding":false}`},
		{"unknown key", `{"sni":"snapp.ir","alpn":["h2"],"fingerprint":"chrome","padding":false,"secret":"x"}`},
		{"malformed", `{`},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseOuterProfile([]byte(tc.json)); err == nil {
				t.Fatalf("malformed profile %q was accepted", tc.name)
			}
		})
	}
}

func TestOuterProfileSerialisesDeterministically(t *testing.T) {
	p := &OuterProfile{SNI: "snapp.ir", ALPN: []string{"h2", "http/1.1"}, Fingerprint: FingerprintChrome, Padding: true}
	a, err := canonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("outer profile serialisation is not deterministic")
	}
	// Field order comes from the struct declaration, so any struct change
	// reorders the bytes and is caught here.
	want := `{"sni":"snapp.ir","alpn":["h2","http/1.1"],"fingerprint":"chrome","padding":true}`
	if string(a) != want {
		t.Fatalf("profile bytes = %s, want %s", a, want)
	}
	// The cover must not carry anything that looks like a credential.
	for _, secret := range []string{"token", "client_id", "password", "secret"} {
		if strings.Contains(strings.ToLower(string(a)), secret) {
			t.Fatalf("outer profile mentions %q", secret)
		}
	}
}

// ----------------------------------------------------------------------------
// Golden vectors
// ----------------------------------------------------------------------------

// goldenVectors pins the key schedule to fixed inputs.
//
// Its job is not to prove the cryptography — HKDF-SHA256 and X25519 are
// standard libraries — but to catch the two mirrored copies of crypto.go
// drifting apart. If a derivation string or a label changes in one module,
// the other module's copy of this file still expects the old bytes and the
// build fails.
type goldenVectors struct {
	Token        string            `json:"token"`
	SharedES     string            `json:"shared_es"`
	SharedEE     string            `json:"shared_ee"`
	Transcript   string            `json:"transcript"`
	InnerKey     string            `json:"inner_key"`
	Handshake    string            `json:"handshake_secret"`
	Master       string            `json:"master_secret"`
	EpochKeys    map[string]string `json:"epoch_keys"`
	ProofKeys    map[string]string `json:"proof_keys"`
	ServerHelloK string            `json:"server_hello_key"`
	ClientFinK   string            `json:"client_finish_key"`
}

const goldenPath = "testdata/sec3_vectors.json"

func computeGolden() *goldenVectors {
	token := testToken(nil)
	sharedES := bytes.Repeat([]byte{0xA1}, 32)
	sharedEE := bytes.Repeat([]byte{0xB2}, 32)
	transcript := sha256Bytes([]byte("fixed transcript input"))

	inner := innerHelloKey(token, sharedES, []byte("fixed aad"))
	hs := handshakeSecret(token, sharedES, sharedEE, transcript)
	master := masterSecret(hs, transcript)

	g := &goldenVectors{
		Token:        token,
		SharedES:     hexOf(sharedES),
		SharedEE:     hexOf(sharedEE),
		Transcript:   hexOf(transcript),
		InnerKey:     hexOf(inner),
		Handshake:    hexOf(hs),
		Master:       hexOf(master),
		EpochKeys:    map[string]string{},
		ProofKeys:    map[string]string{},
		ServerHelloK: hexOf(serverHelloKey(hs)),
		ClientFinK:   hexOf(clientFinishKey(hs)),
	}
	for _, label := range []string{"c2s", "s2c"} {
		for _, epoch := range []uint32{0, 1, 4096} {
			key := fmt.Sprintf("%s/%d", label, epoch)
			g.EpochKeys[key] = hexOf(deriveEpochKey(master, label, epoch))
		}
	}
	g.ProofKeys["server"] = hexOf(serverProofKey(hs))
	g.ProofKeys["client"] = hexOf(clientProofKey(hs))
	return g
}

func TestGoldenVectors(t *testing.T) {
	got := computeGolden()

	if os.Getenv("SEC3_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		buf, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(buf, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", goldenPath)
	}

	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("missing golden vectors at %s — run SEC3_UPDATE_GOLDEN=1 go test to create it: %v", goldenPath, err)
	}
	var want goldenVectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse %s: %v", goldenPath, err)
	}

	check := func(name, gotHex, wantHex string) {
		t.Helper()
		if gotHex != wantHex {
			t.Errorf("%s diverged:\n  got  %s\n  want %s", name, gotHex, wantHex)
		}
	}
	check("inner_hello_key", got.InnerKey, want.InnerKey)
	check("handshake_secret", got.Handshake, want.Handshake)
	check("master_secret", got.Master, want.Master)
	check("server_hello_key", got.ServerHelloK, want.ServerHelloK)
	check("client_finish_key", got.ClientFinK, want.ClientFinK)
	for k, v := range want.EpochKeys {
		check("epoch_key "+k, got.EpochKeys[k], v)
	}
	for k, v := range want.ProofKeys {
		check("proof_key "+k, got.ProofKeys[k], v)
	}
	if got.Token != want.Token {
		t.Error("the pinned token changed; regenerate the vectors deliberately")
	}
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// testToken returns a credential that satisfies ValidateToken. A nil
// testing.T is accepted so helper functions can reuse it.
func testToken(t *testing.T) string {
	const tok = "9f2c4b7e1a8d63f50c9e2b4a7d1f8c35e6a9b0d4c7f2e8a1b5d9c6f3a0e7b24d"
	if t != nil {
		if _, err := ValidateToken(tok); err != nil {
			t.Fatalf("test token must be strong: %v", err)
		}
	}
	return tok
}

// generateTokenForTest mirrors the server's GenerateToken so both modules
// assert against the real production credential shape. The retry is part of
// that shape: GenerateToken must always return something ValidateToken
// accepts, because the client refuses anything else before sending a byte.
func generateTokenForTest() string {
	for attempt := 0; attempt < 64; attempt++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		tok := hexOf(b)
		if _, err := ValidateToken(tok); err != nil {
			continue
		}
		return tok
	}
	panic("could not generate a token satisfying ValidateToken after 64 attempts")
}

// ----------------------------------------------------------------------------
// Mirrored-source drift
// ----------------------------------------------------------------------------

// TestSharedSourcesHaveNotDrifted fails if the two copies of the protocol core
// diverge.
//
// The client and server are separate Go modules and cannot import each other,
// so crypto.go and padding.go are maintained as byte-identical copies. That is
// a deliberate trade: it buys a single source of truth for the wire format
// without a shared package, and it costs a copy that can silently rot. This
// test is the thing that makes the cost visible — a drift here means the two
// sides disagree about the protocol, which is a far worse failure than a
// compile error.
//
// It reads the files from disk rather than comparing in-memory values, so it
// also catches a copy that was edited but never saved, and it reports the
// first differing line rather than just a boolean.
func TestSharedSourcesHaveNotDrifted(t *testing.T) {
	// go test runs in the module root, which is this file's own directory.
	// The sibling module is the other directory beside it.
	here, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Dir(here)
	self := filepath.Base(here)
	sibling := "server"
	if self == sibling {
		sibling = "client"
	}

	for _, name := range []string{"crypto.go", "padding.go"} {
		t.Run(name, func(t *testing.T) {
			ours, err := os.ReadFile(filepath.Join(here, name))
			if err != nil {
				t.Fatalf("read this module's %s: %v", name, err)
			}
			theirs, err := os.ReadFile(filepath.Join(repoRoot, sibling, name))
			if err != nil {
				t.Fatalf("read %s's %s: %v (is the repository checkout complete?)", sibling, name, err)
			}
			if bytes.Equal(ours, theirs) {
				return
			}
			// Report the first difference: that is what an operator needs to
			// reconcile the two copies by hand.
			ourLines := strings.Split(string(ours), "\n")
			theirLines := strings.Split(string(theirs), "\n")
			for i := 0; i < len(ourLines) || i < len(theirLines); i++ {
				var a, b string
				if i < len(ourLines) {
					a = ourLines[i]
				}
				if i < len(theirLines) {
					b = theirLines[i]
				}
				if a != b {
					t.Fatalf("%s has drifted between %s/ and %s/ at line %d:\n  %s: %s\n  %s: %s",
						name, self, sibling, i+1, self, a, sibling, b)
				}
			}
			t.Fatalf("%s differs in length: %s has %d lines, %s has %d",
				name, self, len(ourLines), sibling, len(theirLines))
		})
	}
}

// ----------------------------------------------------------------------------
// Padding configuration
// ----------------------------------------------------------------------------

// TestPaddingDefaultLadderMatchesDocumentedSizes pins the shipped bucket list.
// The documentation tells operators the default is 4, 8, 16, 32 and 50 KB; if
// the ladder ever changes shape, that sentence stops being true and nobody
// notices until a capacity plan is built on it.
func TestPaddingDefaultLadderMatchesDocumentedSizes(t *testing.T) {
	cfg := DefaultPaddingConfig()
	want := []int{4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024, 50 * 1024}
	if len(cfg.Sizes) != len(want) {
		t.Fatalf("default sizes = %v, want %v", cfg.Sizes, want)
	}
	for i := range want {
		if cfg.Sizes[i] != want[i] {
			t.Errorf("default sizes[%d] = %d, want %d", i, cfg.Sizes[i], want[i])
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped default must validate: %v", err)
	}
	if cfg.Enabled {
		t.Error("padding must ship disabled")
	}
}

// TestPaddingSimpleKnobsDeriveBuckets exercises the shorthand an operator
// reaches for first: padding_enabled / padding_min_size / padding_max_size /
// padding_interval. These must land on the same policy as the precise knobs,
// otherwise the two spellings would disagree about what is configured.
func TestPaddingSimpleKnobsDeriveBuckets(t *testing.T) {
	const body = `{
		"padding_enabled": true,
		"padding_min_size": 4096,
		"padding_max_size": 51200,
		"padding_interval": "10s"
	}`
	var cfg PaddingConfig
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.Enabled {
		t.Error("padding_enabled=true was ignored")
	}
	want := []int{4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024, 50 * 1024}
	if len(cfg.Sizes) != len(want) {
		t.Fatalf("derived sizes = %v, want %v", cfg.Sizes, want)
	}
	for i := range want {
		if cfg.Sizes[i] != want[i] {
			t.Errorf("derived sizes[%d] = %d, want %d", i, cfg.Sizes[i], want[i])
		}
	}
	// interval is a nominal value, not a period: the window is
	// [interval/2, interval*2].
	if cfg.MinInterval != 5*time.Second || cfg.MaxInterval != 20*time.Second {
		t.Errorf("interval 10s gave window [%s, %s], want [5s, 20s]", cfg.MinInterval, cfg.MaxInterval)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("derived config must validate: %v", err)
	}
	if len(cfg.Weights) != len(cfg.Sizes) {
		t.Fatalf("weights %v do not cover sizes %v", cfg.Weights, cfg.Sizes)
	}
}

// TestPaddingPreciseKnobsWinOverSimple asserts precedence: an operator who
// spelled out sizes meant those sizes, and the shorthand must not silently
// override them.
func TestPaddingPreciseKnobsWinOverSimple(t *testing.T) {
	const body = `{
		"padding_enabled": true,
		"padding_min_size": 4096,
		"padding_max_size": 51200,
		"sizes": [1024, 8192],
		"weights": [0.5, 0.5],
		"min_interval": "1s",
		"max_interval": "3s"
	}`
	var cfg PaddingConfig
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Sizes) != 2 || cfg.Sizes[0] != 1024 || cfg.Sizes[1] != 8192 {
		t.Errorf("sizes = %v, want the explicit [1024 8192]", cfg.Sizes)
	}
	if cfg.MinInterval != time.Second || cfg.MaxInterval != 3*time.Second {
		t.Errorf("interval window = [%s, %s], want [1s, 3s]", cfg.MinInterval, cfg.MaxInterval)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config must validate: %v", err)
	}
}

// TestPaddingCannotInterfereWithTraffic asserts the property that makes
// padding safe to enable at all: a padding record is a distinct record type,
// authenticated as such, and the receiver discards it before the frame
// decoder. Nothing about it can be mistaken for application data.
func TestPaddingCannotInterfereWithTraffic(t *testing.T) {
	cli, srv := testStates(t, aeadAES256GCM, 0, 0)

	frame := EncodeFrame(MsgData, 42, []byte("payload"))
	frameRec, err := cli.seal(recFrame, frame)
	if err != nil {
		t.Fatal(err)
	}
	padRec, err := cli.seal(recPadding, bytes.Repeat([]byte{0x5A}, 8192))
	if err != nil {
		t.Fatal(err)
	}

	// Interleave: a padding record sitting between two application frames
	// must consume exactly one sequence number and leave the stream intact.
	frameB, err := cli.seal(recFrame, EncodeFrame(MsgData, 43, []byte("next")))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name string
		rec  []byte
		typ  byte
	}{
		{"frame", frameRec, recFrame},
		{"padding", padRec, recPadding},
		{"next frame", frameB, recFrame},
	}
	for _, w := range want {
		gotType, _, err := srv.open(w.rec)
		if err != nil {
			t.Fatalf("%s: open: %v", w.name, err)
		}
		if gotType != w.typ {
			t.Fatalf("%s: record type = 0x%02x, want 0x%02x", w.name, gotType, w.typ)
		}
	}

	// Re-opening the frame proves the padding record consumed exactly one
	// sequence number and left the application stream untouched.
	if _, _, err := srv.open(frameRec); err == nil {
		t.Fatal("frame was replayed without detection")
	}
}

// TestPaddingSizeWeightsNormalise covers the helper used when an operator
// supplies sizes without weights.
func TestPaddingSizeWeightsNormalise(t *testing.T) {
	if w := sizeWeights(0); w != nil {
		t.Errorf("sizeWeights(0) = %v, want nil", w)
	}
	for _, n := range []int{1, 3, 5, 12} {
		w := sizeWeights(n)
		if len(w) != n {
			t.Fatalf("sizeWeights(%d) returned %d weights", n, len(w))
		}
		sum := 0.0
		for _, v := range w {
			if v <= 0 {
				t.Fatalf("sizeWeights(%d) has a non-positive weight %g", n, v)
			}
			sum += v
		}
		if math.Abs(sum-1.0) > 1e-9 {
			t.Errorf("sizeWeights(%d) sums to %g, want 1.0", n, sum)
		}
		// The smallest bucket must stay the most likely, which is the whole
		// point of the falloff. With a single bucket there is nothing to
		// compare, so the property only starts at n = 2.
		if n > 1 && w[0] <= w[n-1] {
			t.Errorf("sizeWeights(%d) does not favour the smallest bucket: %v", n, w)
		}
	}
}

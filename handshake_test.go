package main

// SPIDER-SEC-3 server-side handshake tests.
//
// The server is driven against a test initiator that performs the genuine
// client-side key schedule using the mirrored primitives in crypto.go, so
// the responder is exercised end to end without the client module being
// importable from here. Combined with the byte-identical crypto.go and the
// shared golden vectors, the two suites agree on the wire format.
//
// The symmetric suite on the client lives in client/handshake_test.go.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// In-process transport
// ----------------------------------------------------------------------------

// pipe is channel-based rather than a sync.Cond because a cond var only wakes
// when someone broadcasts — so a reader whose deadline expires while the peer
// is silent would block forever. Channels select on a timer, which is what a
// real socket's read deadline does.
type pipe struct {
	inbound chan []byte // never closed: a send is always safe
	done    chan struct{}
	once    sync.Once
	peer    *pipe

	sent   [][]byte
	sentMu sync.Mutex
}

func newPipePair() (*pipe, *pipe) {
	a := &pipe{inbound: make(chan []byte, 64), done: make(chan struct{})}
	b := &pipe{inbound: make(chan []byte, 64), done: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

// WriteBinary always succeeds. The pipe models liveness on the read side
// only: closing one end is what wakes a peer that is waiting for an answer
// that will never come. Failing a write after a close would make a
// legitimate late write (a finish sent after the peer gave up) fail
// depending on goroutine scheduling, which is a property of the test
// harness and not of the protocol under test.
func (p *pipe) WriteBinary(data []byte) error {
	p.sentMu.Lock()
	p.sent = append(p.sent, append([]byte(nil), data...))
	p.sentMu.Unlock()

	p.peer.inbound <- append([]byte(nil), data...)
	return nil
}

func (p *pipe) ReadBinary(deadline time.Time) ([]byte, error) {
	// A queued message always wins over a close: the peer may have sent it
	// and then returned, and dropping it would turn a complete handshake
	// into a spurious timeout.
	select {
	case msg := <-p.inbound:
		return msg, nil
	default:
	}

	wait := 10 * time.Second
	if !deadline.IsZero() {
		if u := time.Until(deadline); u > 0 {
			wait = u
		} else {
			wait = time.Nanosecond
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case msg := <-p.inbound:
		return msg, nil
	case <-p.done:
		return nil, fmt.Errorf("pipe: closed")
	case <-p.peer.done:
		// The peer finished (or gave up) without answering; wake
		// immediately instead of burning the whole read deadline.
		return nil, fmt.Errorf("pipe: peer closed")
	case <-timer.C:
		return nil, fmt.Errorf("pipe: read deadline exceeded")
	}
}

func (p *pipe) Close() {
	p.once.Do(func() { close(p.done) })
}

func (p *pipe) sentMessages() [][]byte {
	p.sentMu.Lock()
	defer p.sentMu.Unlock()
	out := make([][]byte, len(p.sent))
	copy(out, p.sent)
	return out
}

// ----------------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------------

// testPeer is the server identity plus the credential set it will accept.
type testPeer struct {
	static    *ecdh.PrivateKey
	staticPub *ecdh.PublicKey
	token     string
	cover     []byte
}

func newTestPeer(t *testing.T, token string) *testPeer {
	t.Helper()
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cover, err := canonicalJSON(&OuterProfile{
		SNI:         "snapp.ir",
		ALPN:        []string{"h2", "http/1.1"},
		Fingerprint: FingerprintGo,
		Padding:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testPeer{static: static, staticPub: static.PublicKey(), token: token, cover: cover}
}

// newCredentialStore builds a UserStore holding exactly the given tokens,
// with the first one marked primary.
func newCredentialStore(t *testing.T, tokens []string) *UserStore {
	t.Helper()
	s := &UserStore{
		path:   t.TempDir() + "/token.json",
		users:  map[string]*User{},
		orders: []string{},
	}
	for i, tok := range tokens {
		name, primary := "primary", true
		if i != 0 {
			name, primary = fmt.Sprintf("extra-%d", i), false
		}
		s.users[tok] = &User{Name: name, Token: tok, CreatedAt: time.Now().UTC(), Primary: primary}
		s.orders = append(s.orders, tok)
	}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return s
}

// ----------------------------------------------------------------------------
// Test-only initiator
// ----------------------------------------------------------------------------

// initiator performs the real client-side handshake from raw material. It is
// the client algorithm expressed against the shared primitives, so the server
// is tested under the same key schedule the real client will produce.
type initiator struct {
	srv *testPeer

	token    string
	cover    []byte
	features []string
	aeadID   uint8
	skew     time.Duration

	// mutateCover / mutateInner / mutateFinish corrupt one message.
	mutateCover  func([]byte) []byte
	mutateInner  func([]byte) []byte
	mutateFinish func([]byte) []byte

	// wrongProof sends a finish whose AEAD envelope is perfectly valid but
	// whose HMAC is a random value: the exact shape a forger who can reach
	// the record layer but not the token would produce.
	wrongProof bool

	skipFinish bool
	skipInner  bool
	skipCover  bool
}

func (i *initiator) params() testParams {
	return testParams{
		Token:           i.token,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(i.srv.staticPub.Bytes()),
		ProfileCover:    i.cover,
		ClientID:        "spider-node-01",
		Features:        i.features,
		AEAD:            i.aeadID,
		MaxFrame:        MaxPayloadSize,
		PaddingSizes:    []int{4096, 16384, 51200},
		RotateBytes:     1 << 30,
		RotateSecs:      3600,
		Timeout:         3 * time.Second,
	}
}

// testParams mirrors the client's handshake parameters. The server module has
// no clientHandshakeParams (it lives in the client binary), so the initiator
// declares its own and reads the same shared primitives.
type testParams struct {
	Token           string
	ServerPublicKey string
	ProfileCover    []byte
	ClientID        string
	Features        []string
	AEAD            uint8
	MaxFrame        int
	PaddingSizes    []int
	RotateBytes     int64
	RotateSecs      int64
	Timeout         time.Duration
}

func (i *initiator) initiate(end *pipe) error {
	p := i.params()

	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	salt := make([]byte, sec3SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	clientEphPub := eph.PublicKey().Bytes()
	sharedES, err := eph.ECDH(i.srv.staticPub)
	if err != nil {
		return err
	}
	defer zeroBytes(sharedES)

	// 1. OUTER_HELLO
	cover := p.ProfileCover
	if i.mutateCover != nil {
		cover = i.mutateCover(cover)
	}
	outer := buildHandshakeMsg(msgOuterHello, cover)
	if err := end.WriteBinary(outer); err != nil {
		return err
	}

	if i.skipCover && i.skipInner {
		return nil
	}

	// 2. INNER_HELLO
	if i.skipInner {
		return nil
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	innerPlain, err := canonicalJSON(clientHelloInner{
		ClientID:  p.ClientID,
		TokenHash: tokenHash(i.token),
		Features:  p.Features,
		Session: sessionParameters{
			MaxFrame:         p.MaxFrame,
			PaddingBucket:    p.PaddingSizes,
			KeyRotateBytes:   p.RotateBytes,
			KeyRotateSeconds: p.RotateSecs,
			Aead:             aeadName(p.AEAD),
		},
		Timestamp: time.Now().Add(i.skew).Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return err
	}
	aad, err := envelopeAAD(msgInnerHello, clientEphPub, salt, p.AEAD, len(innerPlain))
	if err != nil {
		return err
	}
	key := innerHelloKey(i.token, sharedES, aad)
	defer zeroBytes(key)
	innerMsg, err := sealEnvelope(p.AEAD, key, msgInnerHello, clientEphPub, salt, innerPlain)
	if err != nil {
		return err
	}
	if i.mutateInner != nil {
		innerMsg = i.mutateInner(innerMsg)
	}
	if err := end.WriteBinary(innerMsg); err != nil {
		return err
	}

	// 3. SERVER_HELLO
	helloMsg, err := end.ReadBinary(time.Now().Add(p.Timeout))
	if err != nil {
		return err
	}
	body, err := parseHandshakeMsg(helloMsg, msgServerHello)
	if err != nil {
		return err
	}
	serverEphPub, helloSalt, _, _, helloAEAD, ciphertext, err := innerEnvelopeFields(body)
	if err != nil {
		return err
	}
	serverEph, err := ecdh.X25519().NewPublicKey(serverEphPub)
	if err != nil {
		return err
	}
	sharedEE, err := eph.ECDH(serverEph)
	if err != nil {
		return err
	}
	defer zeroBytes(sharedEE)

	transcript1 := sha256Bytes(outer, innerMsg)
	secret := handshakeSecret(i.token, sharedES, sharedEE, transcript1)
	defer zeroBytes(secret)

	helloKey := serverHelloKey(secret)
	defer zeroBytes(helloKey)
	aead, err := newAEAD(helloAEAD, helloKey)
	if err != nil {
		return err
	}
	aad2 := innerEnvelopeHeader(helloMsg)
	if aad2 == nil {
		return fmt.Errorf("server hello header truncated")
	}
	nonce2 := make([]byte, sec3NonceSize)
	copy(nonce2, helloSalt[:8])
	plain, err := aead.Open(nil, nonce2, ciphertext, aad2)
	if err != nil {
		return fmt.Errorf("server hello authentication failed: %w", err)
	}
	hello, err := parseServerHelloBody(plain)
	if err != nil {
		return err
	}
	wantProof := computeServerProof(secret, transcript1, i.srv.staticPub.Bytes())
	gotProof, err := hex.DecodeString(hello.ServerProof)
	if err != nil {
		return err
	}
	if !proofsEqual(gotProof, wantProof) {
		return fmt.Errorf("server proof mismatch")
	}

	if i.skipFinish {
		return nil
	}

	// 4. CLIENT_FINISH
	proof := computeClientProof(secret, transcript1, helloMsg)
	if i.wrongProof {
		// Same length, valid hex, entirely wrong: only the HMAC check can
		// catch this, which is precisely what we want to exercise.
		proof = make([]byte, len(proof))
		if _, err := rand.Read(proof); err != nil {
			return err
		}
		// Ensure it cannot accidentally equal the real proof.
		proof[0] ^= 0xFF
	}
	finishPlain, err := canonicalJSON(clientFinishBody{ClientProof: hex.EncodeToString(proof)})
	if err != nil {
		return err
	}
	finishSalt := make([]byte, sec3SaltSize)
	if _, err := rand.Read(finishSalt); err != nil {
		return err
	}
	finishKey := clientFinishKey(secret)
	defer zeroBytes(finishKey)
	finishMsg, err := sealEnvelope(p.AEAD, finishKey, msgClientFinish, clientEphPub, finishSalt, finishPlain)
	if err != nil {
		return err
	}
	if i.mutateFinish != nil {
		finishMsg = i.mutateFinish(finishMsg)
	}
	return end.WriteBinary(finishMsg)
}

// runServer drives one handshake: the initiator over one end, the server
// over the other.
func runServer(t *testing.T, peer *testPeer, users *UserStore, init *initiator, tweak func(*serverHandshakeParams)) (*sec3State, *User, error, []string) {
	t.Helper()
	cliEnd, srvEnd := newPipePair()
	defer cliEnd.Close()
	defer srvEnd.Close()

	var logs []string
	var logMu sync.Mutex
	params := serverHandshakeParams{
		Users:             users,
		StaticKey:         peer.static,
		SupportedFeatures: []string{"tcp", "https", "udp"},
		AEAD:              aeadAES256GCM,
		RotateBytes:       1 << 30,
		RotateSecs:        3600,
		Timeout:           3 * time.Second,
		Logf: func(f string, a ...any) {
			logMu.Lock()
			logs = append(logs, fmt.Sprintf(f, a...))
			logMu.Unlock()
		},
	}
	if tweak != nil {
		tweak(&params)
	}

	var (
		state  *sec3State
		user   *User
		srvErr error
		wg     sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Closing on return is what wakes the peer: a side that has already
		// decided the handshake is over must not leave its counterpart
		// burning a full read deadline on an answer that will never come.
		// Writes cannot race with this because the pipe's buffer never fails.
		defer cliEnd.Close()
		if err := init.initiate(cliEnd); err != nil && srvErr == nil {
			// The initiator failing is not the server's failure; only the
			// server's own error is reported.
			_ = err
		}
	}()
	go func() {
		defer wg.Done()
		defer srvEnd.Close()
		var err error
		state, user, err = serverSecureHandshake(srvEnd, params)
		srvErr = err
	}()
	wg.Wait()

	logMu.Lock()
	defer logMu.Unlock()
	return state, user, srvErr, append([]string(nil), logs...)
}

func defaultInitiator(peer *testPeer) *initiator {
	return &initiator{
		srv:      peer,
		token:    peer.token,
		cover:    peer.cover,
		features: []string{"tcp", "https", "udp"},
		aeadID:   aeadAES256GCM,
	}
}

// ----------------------------------------------------------------------------
// Happy path
// ----------------------------------------------------------------------------

func TestServerHandshakeSucceeds(t *testing.T) {
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	state, user, err, logs := runServer(t, peer, users, defaultInitiator(peer), nil)
	if err != nil {
		t.Fatalf("server handshake: %v (logs: %v)", err, logs)
	}
	if user == nil || user.Token != peer.token {
		t.Fatalf("server authenticated the wrong credential: %+v", user)
	}
	if state == nil {
		t.Fatal("no record layer installed")
	}
	if !containsLine(logs, "[SEC3] tunnel ready") {
		t.Errorf("missing 'tunnel ready' log: %v", logs)
	}
	if !containsLine(logs, "[SEC3] client authenticated") {
		t.Errorf("missing 'client authenticated' log: %v", logs)
	}

	// The installed layer seals; the peer's receive path uses the other
	// direction key, so it must not open its own record.
	rec, err := state.seal(recFrame, EncodeFrame(MsgPing, 0, []byte("hb")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.open(rec); err == nil {
		t.Fatal("server opened its own s2c record with its c2s key: directions are not independent")
	}
	// And it must be genuinely encrypted.
	if bytes.Contains(rec, []byte("hb")) {
		t.Fatal("record contains its plaintext")
	}
}

// ----------------------------------------------------------------------------
// Rejection paths
// ----------------------------------------------------------------------------

func TestServerRejectsUnknownCredential(t *testing.T) {
	// The store does not contain the client's token. Trial decryption must
	// exhaust every candidate and fail — identically whether the store holds
	// one credential or a hundred.
	peer := newTestPeer(t, testToken(t))
	stranger := generateTokenForTest()
	if stranger == peer.token {
		t.Fatal("setup: generated credential collided with the peer's")
	}
	users := newCredentialStore(t, []string{stranger})

	_, _, err, _ := runServer(t, peer, users, defaultInitiator(peer), nil)
	if err == nil {
		t.Fatal("server accepted an unknown credential")
	}
}

func TestServerRejectsTamperedInnerHello(t *testing.T) {
	// Flipping any ciphertext bit must break the AEAD against every stored
	// credential, so the hello never decrypts.
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	// Discover the real message length first.
	helloLen := 0
	probe := defaultInitiator(peer)
	probe.mutateInner = func(m []byte) []byte {
		helloLen = len(m)
		return m
	}
	if _, _, err, _ := runServer(t, peer, users, probe, nil); err != nil {
		t.Fatalf("probe handshake failed: %v", err)
	}
	if helloLen == 0 {
		t.Fatal("did not observe an inner hello")
	}

	for pos := 0; pos < helloLen; pos++ {
		p := pos
		init := defaultInitiator(peer)
		init.mutateInner = func(m []byte) []byte {
			out := append([]byte(nil), m...)
			out[p] ^= 0x01
			return out
		}
		if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
			t.Fatalf("inner hello corrupted at byte %d was accepted", p)
		}
	}
}

func TestServerRejectsNonCanonicalCover(t *testing.T) {
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	for _, bad := range [][]byte{
		[]byte(`{"sni":"","alpn":["h2"],"fingerprint":"chrome","padding":false}`),
		[]byte(`{"sni":"snapp.ir","alpn":[],"fingerprint":"chrome","padding":false}`),
		[]byte(`{"sni":"snapp.ir","alpn":["h2"],"fingerprint":"netscape","padding":false}`),
		[]byte(`{"sni":"snapp.ir","alpn":["h2"],"fingerprint":"chrome","padding":false,"token":"leaked"}`),
		[]byte(`{"sni":"snapp.ir","alpn":["h2"],"fingerprint":"chrome","padding":false,"client_id":"spider-node-01"}`),
		[]byte(`{`),
		[]byte(`[1,2,3]`),
	} {
		init := defaultInitiator(peer)
		init.mutateCover = func([]byte) []byte { return bad }
		if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
			t.Fatalf("server accepted a non-canonical cover profile: %s", bad)
		}
	}
}

func TestServerRejectsTimestampSkew(t *testing.T) {
	for _, skew := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		peer := newTestPeer(t, testToken(t))
		users := newCredentialStore(t, []string{peer.token})
		init := defaultInitiator(peer)
		init.skew = skew
		if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
			t.Fatalf("server accepted an inner hello skewed by %s", skew)
		}
	}
}

func TestServerRejectsOverlongInnerHello(t *testing.T) {
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	init := defaultInitiator(peer)
	init.mutateInner = func([]byte) []byte {
		return buildHandshakeMsg(msgInnerHello, bytes.Repeat([]byte{0x7e}, handshakeMaxBody+1))
	}
	if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
		t.Fatal("server accepted an oversized inner hello")
	}
}

func TestServerRejectsUnsupportedFeature(t *testing.T) {
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	init := defaultInitiator(peer)
	init.features = []string{"tcp", "quic"}
	_, _, err, _ := runServer(t, peer, users, init, nil)
	if err == nil {
		t.Fatal("server accepted a feature outside its SupportedFeatures")
	}
}

func TestServerRejectsTamperedClientFinish(t *testing.T) {
	// The client proof must bind the exact transcript. Flipping a ciphertext
	// bit breaks the AEAD; flipping a proof bit breaks the HMAC check.
	for _, mutate := range []struct {
		name string
		fn   func([]byte) []byte
	}{
		{"ciphertext bit", func(b []byte) []byte { out := append([]byte(nil), b...); out[len(out)-1] ^= 0x01; return out }},
		{"header bit", func(b []byte) []byte { out := append([]byte(nil), b...); out[10] ^= 0x01; return out }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			peer := newTestPeer(t, testToken(t))
			users := newCredentialStore(t, []string{peer.token})
			init := defaultInitiator(peer)
			init.mutateFinish = mutate.fn
			if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
				t.Fatalf("server accepted a %s-forged client finish", mutate.name)
			}
		})
	}
}

func TestServerRejectsWrongProof(t *testing.T) {
	// A finish whose envelope is structurally valid — correct length, valid
	// hex, correctly sealed under a key the initiator legitimately holds —
	// but whose HMAC is wrong. This is the only forgery that reaches the
	// proof comparison rather than the AEAD, so it is the one case where the
	// comparison itself is what saves the handshake.
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	init := defaultInitiator(peer)
	init.wrongProof = true
	_, user, err, _ := runServer(t, peer, users, init, nil)
	if err == nil {
		t.Fatal("server accepted a client finish with a wrong proof")
	}
	if user != nil {
		t.Fatal("server returned an authenticated user for a wrong proof")
	}
}

func TestServerRejectsSilentClient(t *testing.T) {
	peer := newTestPeer(t, testToken(t))
	users := newCredentialStore(t, []string{peer.token})

	cliEnd, srvEnd := newPipePair()
	defer cliEnd.Close()
	defer srvEnd.Close()

	var srvErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = cliEnd.WriteBinary(buildHandshakeMsg(msgOuterHello, peer.cover)) }()
	go func() {
		defer wg.Done()
		_, _, err := serverSecureHandshake(srvEnd, serverHandshakeParams{
			Users: users, StaticKey: peer.static, AEAD: aeadAES256GCM, Timeout: 150 * time.Millisecond,
		})
		srvErr = err
	}()
	wg.Wait()
	if srvErr == nil {
		t.Fatal("server continued without an inner hello")
	}
}

// ----------------------------------------------------------------------------
// Trial decryption
// ----------------------------------------------------------------------------

func TestServerTrialDecryptionFindsCredentialAtAnyPosition(t *testing.T) {
	// The right credential must be found wherever it sits in the store.
	// Extra credentials are drawn from the real generator, so each one is a
	// genuine 256-bit value the loop has to try.
	for _, count := range []int{1, 5, 20} {
		t.Run(fmt.Sprintf("%d credentials", count), func(t *testing.T) {
			peer := newTestPeer(t, testToken(t))
			tokens := []string{peer.token}
			for i := 1; i < count; i++ {
				tok, err := GenerateToken()
				if err != nil {
					t.Fatal(err)
				}
				tokens = append(tokens, tok)
			}
			users := newCredentialStore(t, tokens)

			_, user, err, _ := runServer(t, peer, users, defaultInitiator(peer), nil)
			if err != nil {
				t.Fatalf("handshake with %d credentials failed: %v", count, err)
			}
			if user == nil || user.Token != peer.token {
				t.Fatalf("wrong credential matched: %+v", user)
			}
		})
	}
}

func TestServerTrialDecryptionRejectsWhenTokenIsLastAndWrong(t *testing.T) {
	// A store whose credentials are all valid but none of them the client's
	// must still fail — the loop must not succeed on "a credential exists",
	// and it must not stop early: the only genuine credential sits last.
	peer := newTestPeer(t, testToken(t))
	tokens := make([]string, 0, 9)
	for i := 0; i < 8; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
	}
	tokens = append(tokens, peer.token) // the real credential is last
	users := newCredentialStore(t, tokens)

	init := defaultInitiator(peer)
	init.token = generateTokenForTest()
	for _, stored := range tokens {
		if init.token == stored {
			t.Fatal("setup: attacker token must differ from every stored one")
		}
	}
	if _, _, err, _ := runServer(t, peer, users, init, nil); err == nil {
		t.Fatal("server accepted a token that is not in its store")
	}
}

func TestUserStoreCandidatesAreStableAndComplete(t *testing.T) {
	tokens := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
	}
	store := newCredentialStore(t, tokens)

	cands := store.Candidates()
	if len(cands) != len(tokens) {
		t.Fatalf("Candidates() = %d entries, want %d", len(cands), len(tokens))
	}
	seen := map[string]bool{}
	for i, c := range cands {
		if c.Token != tokens[i] {
			t.Errorf("candidate %d = %q, want %q", i, c.Token, tokens[i])
		}
		seen[c.Token] = true
	}
	if len(seen) != len(tokens) {
		t.Fatal("Candidates() returned duplicates or dropped entries")
	}
	// Two calls must agree, so the trial loop is deterministic.
	again := store.Candidates()
	for i := range cands {
		if cands[i].Token != again[i].Token {
			t.Fatalf("Candidates() is not stable: position %d changed", i)
		}
	}
}

func TestUserStoreHasNoTokenHintLookup(t *testing.T) {
	// SPIDER-SEC-1 published SHA256(prefix||token) as a wire-visible lookup
	// key. SEC-3 must not reintroduce one: the credential is only ever
	// recoverable by decrypting ClientHelloInner.
	store := newCredentialStore(t, []string{testToken(t)})
	if len(store.Candidates()) != 1 {
		t.Fatal("expected one candidate")
	}
	// The type must not expose a hint-based lookup. This is enforced by
	// compile time in users.go (no such method exists); assert the semantic
	// consequence here instead: a token hash is not accepted as an identifier.
	hint := tokenHash(store.Candidates()[0].Token)
	if _, ok := store.Validate(hint); ok {
		t.Fatal("a token hash was accepted as a credential")
	}
}

// ----------------------------------------------------------------------------
// Secrecy
// ----------------------------------------------------------------------------

func TestServerInnerHellosAreNotLinkable(t *testing.T) {
	// Same token, same client, repeated handshakes: the ciphertext must
	// differ every time, so observations cannot be matched to one credential.
	peer := newTestPeer(t, testToken(t))
	var hellos [][]byte
	for i := 0; i < 4; i++ {
		capture, srvEnd := newPipePair()
		init := defaultInitiator(peer)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = init.initiate(capture) }()
		go func() {
			defer wg.Done()
			_, _, _ = serverSecureHandshake(srvEnd, serverHandshakeParams{
				Users:     newCredentialStore(t, []string{peer.token}),
				StaticKey: peer.static, AEAD: aeadAES256GCM, Timeout: time.Second,
			})
		}()
		wg.Wait()
		msgs := capture.sentMessages()
		capture.Close()
		srvEnd.Close()
		if len(msgs) < 2 {
			t.Fatalf("run %d: only %d messages", i, len(msgs))
		}
		hellos = append(hellos, msgs[1])
	}
	for i := 1; i < len(hellos); i++ {
		if bytes.Equal(hellos[0], hellos[i]) {
			t.Fatalf("inner hellos 0 and %d are byte-identical: they are linkable", i)
		}
	}
}

// ----------------------------------------------------------------------------
// Handshake rate limiting
// ----------------------------------------------------------------------------

func TestHandshakeLimiterBoundsAttempts(t *testing.T) {
	l := newHandshakeLimiter(3)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow("203.0.113.10") {
			t.Fatalf("attempt %d rejected before the limit", i)
		}
	}
	if l.allow("203.0.113.10") {
		t.Fatal("attempt 4 accepted past HANDSHAKE_RATE_LIMIT=3")
	}
	// A different source is unaffected.
	if !l.allow("203.0.113.11") {
		t.Fatal("a second source IP was rate limited by the first")
	}
	// After the window rolls over, the source is allowed again.
	l.mu.Lock()
	for k, w := range l.windows {
		w.start = now.Add(-2 * time.Minute)
		l.windows[k] = w
	}
	l.mu.Unlock()
	if !l.allow("203.0.113.10") {
		t.Fatal("source was not allowed after its window expired")
	}
}

func TestHandshakeLimiterZeroRateMeansDefault(t *testing.T) {
	l := newHandshakeLimiter(0)
	if l.perMin != 10 {
		t.Fatalf("perMin = %d, want the default of 10", l.perMin)
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

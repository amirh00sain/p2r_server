package main

// SPIDER-SEC-3 server handshake.
//
// The hard problem here is credential identification without a plaintext
// selector. SEC-1 sent SHA256(prefix||token) in the clear as a lookup key so
// the server knew which HKDF salt to use before it could decrypt anything.
// That value is a stable, linkable fingerprint of the credential: an observer
// can correlate every connection made with it, confirm at a glance that this
// is a Spider client, and — if the operator ever chose a low-entropy token —
// recover the token offline.
//
// SEC-3 removes it. The server cannot know which credential to use before it
// decrypts, so it does not know: it derives a candidate key for EVERY stored
// credential and attempts the AEAD open with each. Exactly one succeeds.
//
// Two consequences, both handled below:
//
//  1. Offline guessing against a captured INNER_HELLO is bounded only by
//     token entropy, because an observer can compute sharedES from the
//     pinned public key. ValidateToken therefore enforces >= 128 bits and
//     refuses credentials that look low-entropy.
//  2. The attempt loop must always run to completion even after a match, so
//     the response time does not reveal how many credentials exist. The
//     per-IP rate limit bounds the CPU cost of that.

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsTransport adapts a gorilla connection to handshakeTransport.
//
// The handshake runs on the same socket as the tunnel but before any record
// layer exists, so it needs raw message framing rather than sealed records.
type wsTransport struct {
	conn *websocket.Conn
}

func (t *wsTransport) WriteBinary(data []byte) error {
	return t.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (t *wsTransport) ReadBinary(deadline time.Time) ([]byte, error) {
	if !deadline.IsZero() {
		_ = t.conn.SetReadDeadline(deadline)
		defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
	}
	typ, data, err := t.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if typ != websocket.BinaryMessage {
		return nil, fmt.Errorf("handshake message is not binary (type %d)", typ)
	}
	if len(data) > sec3MaxRecord {
		return nil, fmt.Errorf("handshake message too large (%d bytes)", len(data))
	}
	return data, nil
}

// handshakeLimiter bounds handshake attempts per source IP.
//
// SPIDER-SEC-3 identifies callers by trial-decrypting the inner hello against
// every stored credential, deliberately without short-circuiting on a match
// so the response time does not reveal how many credentials exist. That makes
// a handshake a measurable amount of work, and an unauthenticated peer can
// trigger it freely. A per-IP window keeps the cost bounded without
// reintroducing the timing leak that the full walk exists to avoid.
type handshakeLimiter struct {
	mu      sync.Mutex
	perMin  int
	windows map[string]*limiterWindow
	lastGC  time.Time
}

type limiterWindow struct {
	start time.Time
	count int
}

func newHandshakeLimiter(perMinute int) *handshakeLimiter {
	if perMinute <= 0 {
		perMinute = 10
	}
	return &handshakeLimiter{
		perMin:  perMinute,
		windows: make(map[string]*limiterWindow),
		lastGC:  time.Now(),
	}
}

// allow reports whether a handshake from ip may proceed now.
func (l *handshakeLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > 5*time.Minute {
		for k, w := range l.windows {
			if now.Sub(w.start) >= time.Minute {
				delete(l.windows, k)
			}
		}
		l.lastGC = now
	}

	w := l.windows[ip]
	if w == nil || now.Sub(w.start) >= time.Minute {
		l.windows[ip] = &limiterWindow{start: now, count: 1}
		return true
	}
	if w.count >= l.perMin {
		return false
	}
	w.count++
	return true
}

// serverHandshakeParams is everything the server side needs.
type serverHandshakeParams struct {
	Users     *UserStore
	StaticKey *ecdh.PrivateKey

	// AcceptedAEADs, when non-empty, restricts which AEAD a client may
	// offer. Nil accepts any supported AEAD: both candidates are
	// standards-track and equally strong, and restricting them only creates
	// an interop failure for no security gain.
	AcceptedAEADs []uint8

	// SupportedFeatures is the feature set the server will honour. A client
	// asking for anything else is rejected rather than silently downgraded.
	SupportedFeatures []string

	AEAD        uint8 // server's own default when a client offers nothing
	RotateBytes int64
	RotateSecs  int64
	Timeout     time.Duration

	// Logf receives the [SEC3] lines. Nil is valid and discards them.
	Logf func(format string, args ...any)
}

func (p *serverHandshakeParams) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

func (p *serverHandshakeParams) aeadAllowed(id uint8) bool {
	if len(p.AcceptedAEADs) == 0 {
		return true
	}
	for _, a := range p.AcceptedAEADs {
		if a == id {
			return true
		}
	}
	return false
}

// serverSecureHandshake runs the responder side of the handshake.
//
// On success it returns the record layer plus the authenticated user. Every
// failure returns an error and no user: there is no unauthenticated tunnel.
func serverSecureHandshake(tr handshakeTransport, p serverHandshakeParams) (*sec3State, *User, error) {
	if p.Timeout <= 0 {
		p.Timeout = 15 * time.Second
	}
	deadline := func() time.Time { return time.Now().Add(p.Timeout) }
	if p.StaticKey == nil {
		return nil, nil, fmt.Errorf("%w: server static key is not loaded", errSec3)
	}
	if p.Users == nil {
		return nil, nil, fmt.Errorf("%w: no credential store", errSec3)
	}

	// ---- 1. OUTER_HELLO: public cover, validated structurally ---------
	outerMsg, err := tr.ReadBinary(deadline())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receive outer hello: %v", errSec3, err)
	}
	coverBody, err := parseHandshakeMsg(outerMsg, msgOuterHello)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: outer hello envelope: %v", errSec3, err)
	}
	cover, err := parseOuterProfile(coverBody)
	if err != nil {
		return nil, nil, err
	}
	p.logf("[SEC3] outer hello received (sni=%s fingerprint=%s)", cover.SNI, cover.Fingerprint)

	// ---- 2. INNER_HELLO: trial-decrypt against the credential store ---
	innerMsg, err := tr.ReadBinary(deadline())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receive inner hello: %v", errSec3, err)
	}
	user, plain, aeadID, sharedES, clientEphPub, err := openInnerHello(p, innerMsg)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(sharedES)

	inner, err := parseClientHelloInner(plain)
	if err != nil {
		return nil, nil, err
	}
	if err := checkTimestamp(inner.Timestamp); err != nil {
		return nil, nil, err
	}
	if !p.aeadAllowed(aeadID) {
		return nil, nil, fmt.Errorf("%w: client offered aead %s which this server does not accept", errSec3, aeadName(aeadID))
	}
	selected, err := p.selectFeatures(inner.Features)
	if err != nil {
		return nil, nil, err
	}
	p.logf("[SEC3] inner hello decrypted (client=%s features=%v aead=%s)",
		inner.ClientID, selected, aeadName(aeadID))

	// ---- 3. SERVER_HELLO: prove we hold the static key and the token --
	eph, sharedEE, err := newServerEph(clientEphPub)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(sharedEE)

	transcript1 := sha256Bytes(outerMsg, innerMsg)
	staticPub := p.StaticKey.PublicKey().Bytes()
	helloMsg, err := buildServerHello(user.Token, eph.PublicKey().Bytes(), staticPub, serverHelloParams{
		SharedES:         sharedES,
		SharedEE:         sharedEE,
		Transcript1:      transcript1,
		ClientEphPub:     clientEphPub,
		AEAD:             aeadID,
		SelectedFeatures: selected,
		RotateBytes:      p.RotateBytes,
		RotateSecs:       p.RotateSecs,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := tr.WriteBinary(helloMsg); err != nil {
		return nil, nil, fmt.Errorf("%w: send server hello: %v", errSec3, err)
	}

	// ---- 4. CLIENT_FINISH: verify the initiator holds the token -------
	finishMsg, err := tr.ReadBinary(deadline())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receive client finish: %v", errSec3, err)
	}
	secret := handshakeSecret(user.Token, sharedES, sharedEE, transcript1)
	defer zeroBytes(secret)

	if err := verifyClientFinish(finishMsg, secret, transcript1, helloMsg); err != nil {
		return nil, nil, err
	}
	p.logf("[SEC3] client authenticated (user=%s)", user.Name)

	// ---- 5. install the record layer ----------------------------------
	transcript2 := sha256Bytes(transcript1, helloMsg)
	master := masterSecret(secret, transcript2)
	defer zeroBytes(master)

	state, err := newSec3State(master, aeadID, "s2c", "c2s", p.RotateBytes,
		time.Duration(p.RotateSecs)*time.Second)
	if err != nil {
		return nil, nil, err
	}
	p.logf("[SEC3] tunnel ready (user=%s aead=%s)", user.Name, aeadName(aeadID))
	return state, user, nil
}

// openInnerHello identifies the caller by trying every stored credential.
//
// It always walks the whole store, even after a match, so the time taken to
// reject a handshake does not reveal how many credentials exist. The caller
// is expected to be behind a per-IP rate limit (see Config.HandshakeRateLimit)
// because this loop is deliberately not short-circuited.
func openInnerHello(p serverHandshakeParams, innerMsg []byte) (*User, []byte, uint8, []byte, []byte, error) {
	body, err := parseHandshakeMsg(innerMsg, msgInnerHello)
	if err != nil {
		return nil, nil, 0, nil, nil, err
	}
	clientEphPub, salt, epoch, seq, aeadID, ciphertext, err := innerEnvelopeFields(body)
	if err != nil {
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: inner envelope: %v", errSec3, err)
	}
	if epoch != 0 || seq != 0 {
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: inner hello must use epoch 0 seq 0", errSec3)
	}
	if !p.aeadAllowed(aeadID) {
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: client offered aead %s which this server does not accept", errSec3, aeadName(aeadID))
	}
	aead, err := newAEAD(aeadID, make([]byte, sec3KeySize))
	if err != nil {
		return nil, nil, 0, nil, nil, err
	}
	_ = aead // only proves the AEAD id is usable; real keys are per-candidate

	clientEph, err := ecdh.X25519().NewPublicKey(clientEphPub)
	if err != nil {
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: client ephemeral key: %v", errSec3, err)
	}
	sharedES, err := p.StaticKey.ECDH(clientEph)
	if err != nil {
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: x25519 static: %v", errSec3, err)
	}
	if isAllZero(sharedES) {
		zeroBytes(sharedES)
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: all-zero x25519 shared secret", errSec3)
	}

	aad := innerEnvelopeHeader(innerMsg)
	if aad == nil {
		zeroBytes(sharedES)
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: inner hello header truncated", errSec3)
	}
	nonce := make([]byte, sec3NonceSize)
	copy(nonce, salt[:8])

	// Trial decryption: no credential is selected before this loop.
	var (
		matched *User
		plain   []byte
	)
	for _, candidate := range p.Users.Candidates() {
		key := innerHelloKey(candidate.Token, sharedES, aad)
		a, aerr := newAEAD(aeadID, key)
		if aerr == nil {
			pt, oerr := a.Open(nil, nonce, ciphertext, aad)
			if oerr == nil && matched == nil {
				matched, plain = candidate, pt
			}
		}
		zeroBytes(key)
	}

	if matched == nil {
		zeroBytes(sharedES)
		return nil, nil, 0, nil, nil, fmt.Errorf("%w: no credential decrypts this handshake", errSec3)
	}
	return matched, plain, aeadID, sharedES, clientEphPub, nil
}

// verifyClientFinish checks the initiator's proof against the transcript.
func verifyClientFinish(finishMsg []byte, secret, transcript1, helloMsg []byte) error {
	plain, _, err := openEnvelope(clientFinishKey(secret), finishMsg, msgClientFinish)
	if err != nil {
		return err
	}
	body, err := parseClientFinishBody(plain)
	if err != nil {
		return err
	}
	want := computeClientProof(secret, transcript1, helloMsg)
	got, err := hex.DecodeString(body.ClientProof)
	if err != nil {
		return fmt.Errorf("%w: client proof encoding: %v", errSec3, err)
	}
	if !proofsEqual(got, want) {
		return fmt.Errorf("%w: client authentication failed", errSec3)
	}
	return nil
}

// selectFeatures returns the intersection of what the client asked for and
// what the server supports, or an error if the client asked for something
// unknown. Rejecting is deliberate: silently dropping a feature would make
// the client believe it has a capability it does not.
func (p *serverHandshakeParams) selectFeatures(offered []string) ([]string, error) {
	if len(offered) == 0 {
		return nil, fmt.Errorf("%w: client offered no features", errSec3)
	}
	supported := make(map[string]bool, len(p.SupportedFeatures))
	for _, f := range p.SupportedFeatures {
		supported[f] = true
	}
	if len(supported) == 0 {
		return offered, nil // server imposes no restriction
	}
	out := make([]string, 0, len(offered))
	for _, f := range offered {
		if !supported[f] {
			return nil, fmt.Errorf("%w: client requested unsupported feature %q", errSec3, f)
		}
		out = append(out, f)
	}
	return out, nil
}

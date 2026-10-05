package main

// SPIDER-SEC-3 — shared protocol core.
//
// This file is byte-identical in client/crypto.go and server/crypto.go.
// The two halves of the project are separate Go modules, so the sources
// cannot live in one shared package; they are mirrored instead, and
// TestSharedSourcesHaveNotDrifted fails the build if the copies diverge.
//
// Nothing here is implemented by hand:
//
//	KDF    crypto/hkdf            (HKDF-SHA256)
//	AEAD   crypto/aes+crypto/cipher  (AES-256-GCM, default)
//	       golang.org/x/crypto/chacha20poly1305 (optional)
//	HMAC   crypto/hmac
//	Rand   crypto/rand
//	Compare crypto/subtle
//
// The outer ClientHello (clienthello_outer.json) is public cover traffic and
// is deliberately absent from this file: no key, nonce, proof or identity is
// ever derived from it. All security lives in the handshake below.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol identity.
const (
	Sec3ProtocolName = "SPIDER-SEC-3"
	sec3Magic        = "SPDRSEC3"
	sec3Version      = byte(3)
)

// Handshake message types (msg_type byte of the handshake envelope).
const (
	msgOuterHello   = byte(0x10)
	msgInnerHello   = byte(0x11)
	msgServerHello  = byte(0x12)
	msgClientFinish = byte(0x13)
)

// Record types (rec_type byte of a data record).
const (
	recFrame   = byte(0x01) // payload is an EncodeFrame() application frame
	recPadding = byte(0x02) // payload is random bytes, discarded on receipt
)

// Sizes. All multi-byte fields on the wire are big-endian.
const (
	// handshakeEnvelope: magic(8) version(1) msg_type(1) body_len(4).
	handshakeHeaderSize = 14

	// record: magic(8) version(1) rec_type(1) epoch(4) seq(8) ct_len(4).
	recordHeaderSize = 26

	aeadTagSize   = 16
	sec3SaltSize  = 16 // random per-handshake salt inside the inner envelope
	sec3KeySize   = 32
	sec3NonceSize = 12

	// sec3MaxRecord is the largest WebSocket message this protocol accepts.
	sec3MaxRecord = recordHeaderSize + HeaderSize + MaxPayloadSize + aeadTagSize

	// handshakeMaxBody bounds a handshake message body before allocation.
	handshakeMaxBody = 64 << 10
)

// AEAD identifiers negotiated inside ClientHelloInner.
const (
	aeadAES256GCM  uint8 = 0
	aeadChaChaPoly uint8 = 1
)

// errSec3 wraps every protocol-level failure so callers can errors.Is().
var errSec3 = errors.New("spider-sec-3 error")

// ----------------------------------------------------------------------------
// AEAD
// ----------------------------------------------------------------------------

// aeadName renders an AEAD identifier for configuration and logs.
func aeadName(id uint8) string {
	switch id {
	case aeadAES256GCM:
		return "aes-256-gcm"
	case aeadChaChaPoly:
		return "chacha20-poly1305"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

// aeadIDFromName resolves a configuration value to an AEAD identifier.
func aeadIDFromName(name string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "aes-256-gcm", "aes256gcm", "aes-gcm":
		return aeadAES256GCM, nil
	case "chacha20-poly1305", "chacha20poly1305", "chacha-poly":
		return aeadChaChaPoly, nil
	default:
		return 0, fmt.Errorf("%w: unknown aead %q (want aes-256-gcm or chacha20-poly1305)", errSec3, name)
	}
}

// newAEAD builds the AEAD for a 32-byte key. Key length is enforced here so
// no caller can accidentally drive a truncated key.
func newAEAD(id uint8, key []byte) (cipher.AEAD, error) {
	if len(key) != sec3KeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", errSec3, len(key), sec3KeySize)
	}
	switch id {
	case aeadAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("%w: aes: %v", errSec3, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("%w: gcm: %v", errSec3, err)
		}
		return gcm, nil
	case aeadChaChaPoly:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("%w: chacha20poly1305: %v", errSec3, err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("%w: unsupported aead id %d", errSec3, id)
	}
}

// sec3Nonce builds the 12-byte AEAD nonce from a record sequence number.
// The key is unique per (direction, epoch), so the sequence alone makes the
// nonce unique and reuse is impossible.
func sec3Nonce(seq uint64) []byte {
	nonce := make([]byte, sec3NonceSize) // 4 zero bytes + big-endian seq
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// ----------------------------------------------------------------------------
// HKDF (stdlib only)
// ----------------------------------------------------------------------------

// hkdfExtract runs the HKDF extract phase with a SHA-256 hash.
// Argument order follows crypto/hkdf: Extract(h, secret, salt).
func hkdfExtract(ikm, salt []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic(fmt.Sprintf("hkdf extract: %v", err))
	}
	return prk
}

// hkdfExpand runs the HKDF expand phase to `length` bytes.
func hkdfExpand(prk []byte, info string, length int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, info, length)
	if err != nil {
		panic(fmt.Sprintf("hkdf expand: %v", err))
	}
	return out
}

// hkdfDerive is extract-then-expand in one call.
// Argument order follows crypto/hkdf: Key(h, secret, salt, info, keyLength).
func hkdfDerive(salt, ikm []byte, info string, length int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, salt, info, length)
	if err != nil {
		panic(fmt.Sprintf("hkdf derive: %v", err))
	}
	return out
}

// sha256Bytes hashes the concatenation of its parts.
func sha256Bytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// hmacSHA256 computes HMAC-SHA256 over the concatenation of its parts.
func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = m.Write(p)
	}
	return m.Sum(nil)
}

// zeroBytes wipes key material. Go's GC does not guarantee this, but it
// prevents the old epoch key from lingering in a live slice header.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ----------------------------------------------------------------------------
// Identity helpers
// ----------------------------------------------------------------------------

// tokenHint is intentionally absent in SPIDER-SEC-3. SEC-1 sent
// SHA256(prefix||token) in the clear so the server could pick an HKDF salt;
// that is a stable, linkable credential fingerprint. SEC-3 puts token_hash
// inside the encrypted ClientHelloInner and identifies the user by trial
// decrypting the inner hello against every stored credential instead.

// tokenSalt derives the HKDF salt for a credential. Never leaves the process
// in a form an observer can see.
func tokenSalt(token string) []byte {
	return sha256Bytes([]byte("SPIDER-SEC-3\x00TOKEN\x00"), []byte(token))
}

// tokenHash renders the token hash that travels inside ClientHelloInner.
// It is only ever written into ciphertext.
func tokenHash(token string) string {
	return hex.EncodeToString(sha256Bytes([]byte("SPIDER-SEC-3\x00TOKENHASH\x00"), []byte(token)))
}

// estimateTokenBits is a heuristic floor on credential strength. It cannot
// recover the true entropy of an arbitrary string, so it is deliberately
// paired with minimum length and minimum distinct-character checks in
// ValidateToken. It exists because trial decryption is only sound when the
// secret is high-entropy.
func estimateTokenBits(token string) int {
	if token == "" {
		return 0
	}
	var lower, upper, digit, other bool
	distinct := map[rune]struct{}{}
	for _, r := range token {
		distinct[r] = struct{}{}
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	alpha := 0
	if lower {
		alpha += 26
	}
	if upper {
		alpha += 26
	}
	if digit {
		alpha += 10
	}
	if other {
		alpha += 33
	}
	if alpha < 2 {
		alpha = 2
	}
	return int(float64(len(token)) * math.Log2(float64(alpha)))
}

// ValidateToken enforces the minimum credential strength that SPIDER-SEC-3
// relies on. Returns the estimated strength in bits for logging.
func ValidateToken(token string) (int, error) {
	if token == "" {
		return 0, fmt.Errorf("token is empty")
	}
	distinct := map[rune]struct{}{}
	for _, r := range token {
		distinct[r] = struct{}{}
	}
	bits := estimateTokenBits(token)
	switch {
	case len(token) < 32:
		return bits, fmt.Errorf("token is %d characters, want at least 32", len(token))
	case len(distinct) < 16:
		return bits, fmt.Errorf("token uses only %d distinct characters, want at least 16 (it looks low entropy)", len(distinct))
	case bits < 128:
		return bits, fmt.Errorf("token strength is ~%d bits, want at least 128", bits)
	}
	return bits, nil
}

// ----------------------------------------------------------------------------
// Key schedule
// ----------------------------------------------------------------------------

// innerHelloKey derives the key that encrypts ClientHelloInner.
//
// Only sharedES appears here, because the server's ephemeral public key does
// not exist yet when the client encrypts. sharedES alone is computable by
// anyone who can see the wire and knows the server's pinned public key, so
// offline guessing against the ciphertext is bounded purely by token entropy
// — which is exactly why ValidateToken enforces >= 128 bits.
func innerHelloKey(token string, sharedES, aad []byte) []byte {
	return hkdfDerive(tokenSalt(token), sha256Bytes(sharedES, aad), "SPIDER-SEC-3 inner hello", sec3KeySize)
}

// handshakeSecret binds both X25519 results, the token and the full
// transcript into one secret. Producing a valid proof requires the token and
// the server's static private key.
func handshakeSecret(token string, sharedES, sharedEE, transcript []byte) []byte {
	salt := sha256Bytes([]byte("SPIDER-SEC-3\x00HANDSHAKE\x00"), []byte(token))
	ikm := sha256Bytes(sharedES, sharedEE, transcript)
	return hkdfDerive(salt, ikm, "SPIDER-SEC-3 handshake secret", sec3KeySize)
}

// masterSecret is the root from which every epoch key is derived.
func masterSecret(secret, transcript []byte) []byte {
	return hkdfDerive(
		sha256Bytes([]byte("SPIDER-SEC-3\x00MASTER\x00")),
		sha256Bytes(secret, transcript),
		"SPIDER-SEC-3 master secret",
		sec3KeySize,
	)
}

// deriveEpochKey derives one directional key for one epoch.
//
// The key is a pure function of (master, direction, epoch), so both peers
// agree without exchanging a rekey message and a lost frame can never
// desynchronise them. label is "c2s" or "s2c".
func deriveEpochKey(master []byte, label string, epoch uint32) []byte {
	var ep [4]byte
	binary.BigEndian.PutUint32(ep[:], epoch)
	return hkdfExpand(master, "SPIDER-SEC-3 data "+label+" epoch "+string(ep[:]), sec3KeySize)
}

func serverProofKey(secret []byte) []byte {
	return hkdfExpand(secret, "SPIDER-SEC-3 server proof", sec3KeySize)
}

func clientProofKey(secret []byte) []byte {
	return hkdfExpand(secret, "SPIDER-SEC-3 client proof", sec3KeySize)
}

// serverHelloKey encrypts the ServerHello body.
//
// The responder's ephemeral public key sits in the plaintext prefix of the
// same message, so a client can read it, finish the X25519 key exchange and
// then open this ciphertext. That is what breaks the circularity: the key
// cannot depend on sharedEE until sharedEE exists, and sharedEE only exists
// once the server's ephemeral key is readable.
func serverHelloKey(secret []byte) []byte {
	return hkdfExpand(secret, "SPIDER-SEC-3 server hello", sec3KeySize)
}

// clientFinishKey encrypts the ClientFinish body.
func clientFinishKey(secret []byte) []byte {
	return hkdfExpand(secret, "SPIDER-SEC-3 client finish", sec3KeySize)
}

// computeServerProof proves the responder holds both the token and the
// server's static private key (sharedES is unforgeable without it).
func computeServerProof(secret, transcript, serverStaticPub []byte) []byte {
	return hmacSHA256(serverProofKey(secret), []byte("server-proof"), transcript, serverStaticPub)
}

// computeClientProof proves the initiator holds the token, bound to the
// exact ServerHello the server sent.
func computeClientProof(secret, transcript, serverHelloFrame []byte) []byte {
	return hmacSHA256(clientProofKey(secret), []byte("client-proof"), transcript, sha256Bytes(serverHelloFrame))
}

// proofsEqual compares two proofs without leaking their contents through
// early exit on the first differing byte.
func proofsEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// ----------------------------------------------------------------------------
// Handshake envelope
// ----------------------------------------------------------------------------

// buildHandshakeMsg frames a handshake body.
//
//	[0:8]   magic      "SPDRSEC3"
//	[8]     version    uint8 = 3
//	[9]     msg_type   uint8
//	[10:14] body_len   uint32
//	[14:]   body
func buildHandshakeMsg(msgType byte, body []byte) []byte {
	out := make([]byte, handshakeHeaderSize+len(body))
	copy(out, sec3Magic)
	out[8] = sec3Version
	out[9] = msgType
	binary.BigEndian.PutUint32(out[10:14], uint32(len(body)))
	copy(out[handshakeHeaderSize:], body)
	return out
}

// parseHandshakeMsg validates an envelope and returns its type and body.
// The returned body is a copy, so callers cannot alias read buffers.
func parseHandshakeMsg(msg []byte, wantType byte) (body []byte, err error) {
	if len(msg) < handshakeHeaderSize {
		return nil, fmt.Errorf("%w: handshake message too short (%d bytes)", errSec3, len(msg))
	}
	if string(msg[:8]) != sec3Magic {
		return nil, fmt.Errorf("%w: bad handshake magic", errSec3)
	}
	if msg[8] != sec3Version {
		return nil, fmt.Errorf("%w: unsupported version %d", errSec3, msg[8])
	}
	if msg[9] != wantType {
		return nil, fmt.Errorf("%w: expected msg type 0x%02x, got 0x%02x", errSec3, wantType, msg[9])
	}
	n := binary.BigEndian.Uint32(msg[10:14])
	if n > handshakeMaxBody {
		return nil, fmt.Errorf("%w: handshake body %d exceeds %d bytes", errSec3, n, handshakeMaxBody)
	}
	if uint32(len(msg)-handshakeHeaderSize) != n {
		return nil, fmt.Errorf("%w: handshake body length mismatch (header %d, actual %d)",
			errSec3, n, len(msg)-handshakeHeaderSize)
	}
	out := make([]byte, n)
	copy(out, msg[handshakeHeaderSize:])
	return out, nil
}

// innerEnvelopeHeader returns the bytes that are authenticated as AAD for
// an inner-envelope ciphertext. It covers everything an observer can see
// before decryption, so the ciphertext is bound to the key exchange.
//
//	body layout: client_eph_pub(32) salt_nonce(16) epoch(4) seq(8) aead_id(1)
func innerEnvelopeHeader(msg []byte) []byte {
	// Envelope layout: handshake_header(14) + env_fixed(61) = 75 bytes total.
	const fixedLen = handshakeHeaderSize + 32 + sec3SaltSize + 4 + 8 + 1
	if len(msg) < fixedLen {
		return nil
	}
	out := make([]byte, fixedLen)
	copy(out, msg[:fixedLen])
	return out
}

// innerEnvelopeFields dissects an inner-envelope body.
func innerEnvelopeFields(body []byte) (ephPub, salt []byte, epoch uint32, seq uint64, aeadID uint8, ciphertext []byte, err error) {
	const fixed = 32 + sec3SaltSize + 4 + 8 + 1
	if len(body) < fixed+aeadTagSize {
		return nil, nil, 0, 0, 0, nil, fmt.Errorf("%w: inner envelope too short (%d bytes)", errSec3, len(body))
	}
	ephPub = append([]byte(nil), body[:32]...)
	salt = append([]byte(nil), body[32:32+sec3SaltSize]...)
	epoch = binary.BigEndian.Uint32(body[48:52])
	seq = binary.BigEndian.Uint64(body[52:60])
	aeadID = body[60]
	ciphertext = append([]byte(nil), body[fixed:]...)
	return ephPub, salt, epoch, seq, aeadID, ciphertext, nil
}

// buildInnerEnvelope assembles an inner-envelope body around a ciphertext.
func buildInnerEnvelope(ephPub, salt []byte, epoch uint32, seq uint64, aeadID uint8, ciphertext []byte) []byte {
	if len(ephPub) != 32 || len(salt) != sec3SaltSize {
		panic("buildInnerEnvelope: bad key material length")
	}
	out := make([]byte, 0, 32+sec3SaltSize+4+8+1+len(ciphertext))
	out = append(out, ephPub...)
	out = append(out, salt...)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], epoch)
	out = append(out, buf[:]...)
	var sbuf [8]byte
	binary.BigEndian.PutUint64(sbuf[:], seq)
	out = append(out, sbuf[:]...)
	out = append(out, aeadID)
	out = append(out, ciphertext...)
	return out
}

// envelopeAAD builds the associated data for an inner-envelope ciphertext of
// plainLen bytes, before that ciphertext exists.
//
// It is needed as a separate step because the key for INNER_HELLO is itself
// derived from the AAD (innerHelloKey hashes it): the sender must know the
// AAD to make the key, and the AAD must cover the final message length. The
// length is known up front — it is len(plaintext) plus the AEAD tag — so the
// probe is fully determined before sealing.
//
// The AAD covers the handshake header (including body_len), the ephemeral
// public key, the random salt and the AEAD id: everything an observer can
// read. A ciphertext is therefore bound to its key exchange and cannot be
// replayed against a different one.
func envelopeAAD(msgType byte, ephPub, salt []byte, aeadID uint8, plainLen int) ([]byte, error) {
	if len(ephPub) != 32 || len(salt) != sec3SaltSize {
		return nil, fmt.Errorf("%w: bad envelope key material", errSec3)
	}
	env := buildInnerEnvelope(ephPub, salt, 0, 0, aeadID, make([]byte, plainLen+aeadTagSize))
	aad := innerEnvelopeHeader(buildHandshakeMsg(msgType, env))
	if aad == nil {
		return nil, fmt.Errorf("%w: envelope header truncated", errSec3)
	}
	return aad, nil
}

// sealEnvelope encrypts a handshake body under a freshly salted nonce.
//
// The nonce comes from the random per-handshake salt, so two handshakes with
// the same credential and the same plaintext never produce the same
// ciphertext: an observer cannot link connections to each other or to an
// account.
func sealEnvelope(aeadID uint8, key []byte, msgType byte, ephPub, salt []byte, plaintext []byte) ([]byte, error) {
	if len(salt) != sec3SaltSize {
		return nil, fmt.Errorf("%w: salt must be %d bytes", errSec3, sec3SaltSize)
	}
	aead, err := newAEAD(aeadID, key)
	if err != nil {
		return nil, err
	}
	aad, err := envelopeAAD(msgType, ephPub, salt, aeadID, len(plaintext))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sec3NonceSize)
	copy(nonce, salt[:8]) // random per handshake; never reused under a key
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return buildHandshakeMsg(msgType, buildInnerEnvelope(ephPub, salt, 0, 0, aeadID, ct)), nil
}

// openEnvelope decrypts a handshake body and returns its plaintext.
func openEnvelope(key []byte, msg []byte, wantType byte) ([]byte, uint8, error) {
	body, err := parseHandshakeMsg(msg, wantType)
	if err != nil {
		return nil, 0, err
	}
	_, salt, epoch, seq, aeadID, ciphertext, err := innerEnvelopeFields(body)
	if err != nil {
		return nil, 0, err
	}
	if epoch != 0 || seq != 0 {
		return nil, 0, fmt.Errorf("%w: handshake envelope must use epoch 0 seq 0 (got %d/%d)", errSec3, epoch, seq)
	}
	aead, err := newAEAD(aeadID, key)
	if err != nil {
		return nil, 0, err
	}
	aad := innerEnvelopeHeader(msg)
	if aad == nil {
		return nil, 0, fmt.Errorf("%w: envelope header truncated", errSec3)
	}
	nonce := make([]byte, sec3NonceSize)
	copy(nonce, salt[:8])
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: handshake record authentication failed", errSec3)
	}
	return plain, aeadID, nil
}

// ----------------------------------------------------------------------------
// Outer cover profile
// ----------------------------------------------------------------------------

// OuterProfile is the public cover profile carried in OUTER_HELLO.
//
// It lives here, not in the client's loader, because both peers must agree
// on its exact shape: the client serialises it with canonicalJSON and the
// server parses it with parseOuterProfile. Go emits JSON fields in struct
// declaration order, so both sides hash the same bytes.
//
// Every field is readable by anyone on the path. None of them is secret and
// none of them is trusted — the server validates structure only, and no key
// is ever derived from this message. Treat it as camouflage, not as a
// security control.
type OuterProfile struct {
	SNI         string   `json:"sni"`
	ALPN        []string `json:"alpn"`
	Fingerprint string   `json:"fingerprint"`
	Padding     bool     `json:"padding"`
}

// Fingerprint identifiers. "go" means the standard library ClientHello,
// which is recognisably not a browser and is offered as the honest default
// for operators who would rather not pull in a TLS fingerprinting library.
const (
	FingerprintChrome  = "chrome"
	FingerprintFirefox = "firefox"
	FingerprintSafari  = "safari"
	FingerprintGo      = "go"
)

// validFingerprints is the accepted set for clienthello_outer.json.
var validFingerprints = map[string]bool{
	FingerprintGo:      true,
	FingerprintChrome:  true,
	FingerprintFirefox: true,
	FingerprintSafari:  true,
}

// parseOuterProfile decodes and structurally validates OUTER_HELLO.
//
// Structural only: the server does not know the client's file, and it must
// not trust anything inside this message regardless. An unknown key, an
// empty sni or an empty alpn closes the handshake — a client sending a
// malformed cover profile is either broken or probing, and neither is worth
// finishing the key exchange for.
func parseOuterProfile(body []byte) (*OuterProfile, error) {
	var stray map[string]json.RawMessage
	if err := json.Unmarshal(body, &stray); err != nil {
		return nil, fmt.Errorf("%w: outer hello is not an object: %v", errSec3, err)
	}
	for k := range stray {
		switch k {
		case "sni", "alpn", "fingerprint", "padding":
		default:
			return nil, fmt.Errorf("%w: outer hello has unknown field %q", errSec3, k)
		}
	}
	var p OuterProfile
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%w: outer hello: %v", errSec3, err)
	}
	if err := validateOuterProfile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Cover-profile limits. These are structural bounds on a public object, not a
// security boundary — the real security lives in the inner handshake — but an
// unbounded SNI or ALPN list is a free way to make both peers allocate and
// to shape an unremarkable-looking ClientHello into a distinguishable one.
const (
	// maxSNILength is the RFC 1035 limit on a full DNS name in wire form.
	maxSNILength = 253
	// maxALPNCount bounds how many protocols a cover may offer. Real browsers
	// send two; an implausible list is a fingerprint of its own.
	maxALPNCount = 8
	// maxALPNLength is the RFC 7301 limit on a single ProtocolName.
	maxALPNLength = 255
)

// validateOuterProfile enforces every rule a cover profile must satisfy.
//
// Both peers call this: the client before it writes the profile, the server
// before it accepts one. Applying the same checks on both sides means a
// profile the client is willing to emit is exactly one the server is willing
// to accept, so the handshake can never fail at this step after succeeding at
// the last.
func validateOuterProfile(p *OuterProfile) error {
	if p.SNI == "" {
		return fmt.Errorf("%w: outer hello has no sni", errSec3)
	}
	if len(p.SNI) > maxSNILength {
		return fmt.Errorf("%w: outer hello sni is %d bytes, want at most %d", errSec3, len(p.SNI), maxSNILength)
	}
	if err := validateSNI(p.SNI); err != nil {
		return err
	}
	if len(p.ALPN) == 0 {
		return fmt.Errorf("%w: outer hello has no alpn", errSec3)
	}
	if len(p.ALPN) > maxALPNCount {
		return fmt.Errorf("%w: outer hello offers %d alpn protocols, want at most %d", errSec3, len(p.ALPN), maxALPNCount)
	}
	seen := make(map[string]struct{}, len(p.ALPN))
	for i, proto := range p.ALPN {
		if proto == "" {
			return fmt.Errorf("%w: outer hello alpn[%d] is empty", errSec3, i)
		}
		if len(proto) > maxALPNLength {
			return fmt.Errorf("%w: outer hello alpn[%d] is %d bytes, want at most %d", errSec3, i, len(proto), maxALPNLength)
		}
		// RFC 7301 forbids spaces and control characters in a ProtocolName,
		// and a duplicate would make ALPN selection order-dependent.
		for _, c := range proto {
			if c <= 0x20 || c == 0x7f {
				return fmt.Errorf("%w: outer hello alpn[%d] %q contains a space or control character", errSec3, i, proto)
			}
		}
		if _, dup := seen[proto]; dup {
			return fmt.Errorf("%w: outer hello repeats alpn protocol %q", errSec3, proto)
		}
		seen[proto] = struct{}{}
	}
	if !validFingerprints[p.Fingerprint] {
		return fmt.Errorf("%w: outer hello fingerprint %q is not recognised", errSec3, p.Fingerprint)
	}
	return nil
}

// validateSNI rejects a server name that could not appear in a real
// ClientHello. A TLS ServerName is a DNS hostname, so anything outside the
// usual label alphabet is either a typo or an attempt to smuggle structure
// into a field the endpoint logs verbatim.
func validateSNI(name string) error {
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_':
		default:
			return fmt.Errorf("%w: outer hello sni %q contains an invalid character %q", errSec3, name, string(r))
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Handshake message bodies
// ----------------------------------------------------------------------------
//
// These structs live here, not in the side-specific handshake files, because
// both peers must serialise them identically: Go emits JSON fields in struct
// declaration order, and the transcript hash covers the exact wire bytes. A
// field reorder on one side would silently break every handshake.

// clientHelloInner is the encrypted initiator hello. Every field in it is
// secret: identity, credential and session parameters all travel inside the
// AEAD ciphertext, never in the clear.
type clientHelloInner struct {
	ClientID  string            `json:"client_id"`
	TokenHash string            `json:"token_hash"`
	Features  []string          `json:"features"`
	Session   sessionParameters `json:"session_parameters"`
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
}

// sessionParameters is the initiator's proposal. The responder validates
// each field against its own limits; a mismatch closes the connection rather
// than silently downgrading.
type sessionParameters struct {
	MaxFrame         int    `json:"max_frame"`
	PaddingBucket    []int  `json:"padding_bucket"`
	KeyRotateBytes   int64  `json:"key_rotate_bytes"`
	KeyRotateSeconds int64  `json:"key_rotate_seconds"`
	Aead             string `json:"aead"`
}

// serverHelloBody is the responder's proof, sealed under serverHelloKey.
type serverHelloBody struct {
	ServerProof      string   `json:"server_proof"`
	SelectedFeatures []string `json:"selected_features"`
	Epoch            uint32   `json:"epoch"`
	Aead             string   `json:"aead"`
	KeyRotateBytes   int64    `json:"key_rotate_bytes"`
	KeyRotateSeconds int64    `json:"key_rotate_seconds"`
	Timestamp        int64    `json:"timestamp"`
}

// clientFinishBody is the initiator's proof, sealed under clientFinishKey.
type clientFinishBody struct {
	ClientProof string `json:"client_proof"`
}

// parseClientHelloInner decodes the decrypted initiator hello.
func parseClientHelloInner(b []byte) (*clientHelloInner, error) {
	var v clientHelloInner
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%w: client hello inner: %v", errSec3, err)
	}
	if v.ClientID == "" {
		return nil, fmt.Errorf("%w: client hello inner has no client_id", errSec3)
	}
	if v.TokenHash == "" {
		return nil, fmt.Errorf("%w: client hello inner has no token_hash", errSec3)
	}
	if v.Timestamp == 0 {
		return nil, fmt.Errorf("%w: client hello inner has no timestamp", errSec3)
	}
	if v.Nonce == "" {
		return nil, fmt.Errorf("%w: client hello inner has no nonce", errSec3)
	}
	return &v, nil
}

// parseServerHelloBody decodes the decrypted responder hello.
func parseServerHelloBody(b []byte) (*serverHelloBody, error) {
	var v serverHelloBody
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%w: server hello body: %v", errSec3, err)
	}
	if v.ServerProof == "" {
		return nil, fmt.Errorf("%w: server hello has no proof", errSec3)
	}
	return &v, nil
}

// parseClientFinishBody decodes the decrypted initiator finish.
func parseClientFinishBody(b []byte) (*clientFinishBody, error) {
	var v clientFinishBody
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%w: client finish body: %v", errSec3, err)
	}
	if v.ClientProof == "" {
		return nil, fmt.Errorf("%w: client finish has no proof", errSec3)
	}
	return &v, nil
}

// maxTimestampSkew bounds how far a peer's clock may drift from ours.
// It keeps a captured ClientHelloInner from being replayed much later under
// a different session; the random salt is what actually prevents ciphertext
// reuse, this is defence in depth.
const maxTimestampSkew = 300 * time.Second

// checkTimestamp rejects a hello whose timestamp is too far from now.
func checkTimestamp(ts int64) error {
	delta := time.Since(time.Unix(ts, 0))
	if delta < -maxTimestampSkew {
		return fmt.Errorf("%w: timestamp %ds in the future", errSec3, int64((-delta).Seconds()))
	}
	if delta > maxTimestampSkew {
		return fmt.Errorf("%w: timestamp %ds in the past", errSec3, int64(delta.Seconds()))
	}
	return nil
}

// ----------------------------------------------------------------------------
// Canonical JSON
// ----------------------------------------------------------------------------

// canonicalJSON serialises v with encoding/json. Go emits struct fields in
// declaration order, so the output is stable for a given struct type; both
// peers therefore hash the same bytes for the same value. Never round-trip a
// received payload back through this — the wire bytes are the transcript.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical json: %v", errSec3, err)
	}
	return b, nil
}

// ----------------------------------------------------------------------------
// Record layer
// ----------------------------------------------------------------------------

// sec3State is the per-connection AEAD record layer. It carries the master
// secret so it can derive the next epoch on its own; no rekey message ever
// crosses the wire.
type sec3State struct {
	aeadID      uint8
	master      []byte
	txLabel     string
	rxLabel     string
	rotateBytes int64
	rotateEvery time.Duration

	txMu        sync.Mutex
	txEpoch     uint32
	txSeq       uint64
	txKey       cipher.AEAD
	txPlaintext uint64
	txEpochAt   time.Time
	txFrames    uint64

	rxMu     sync.Mutex
	rxEpoch  uint32
	rxSeq    uint64
	rxKey    cipher.AEAD
	rxFrames uint64
}

// newSec3State installs epoch-0 keys for both directions.
//
// txLabel/rxLabel are "c2s" and "s2c": the client transmits on "c2s", the
// server on "s2c". Both directions use the same epoch numbering but entirely
// different keys.
func newSec3State(master []byte, aeadID uint8, txLabel, rxLabel string, rotateBytes int64, rotateEvery time.Duration) (*sec3State, error) {
	if len(master) != sec3KeySize {
		return nil, fmt.Errorf("%w: master secret is %d bytes, want %d", errSec3, len(master), sec3KeySize)
	}
	if txLabel == rxLabel {
		return nil, fmt.Errorf("%w: transmit and receive labels must differ", errSec3)
	}
	if rotateBytes < 0 || rotateEvery < 0 {
		return nil, fmt.Errorf("%w: negative key rotation limit", errSec3)
	}
	m := make([]byte, sec3KeySize)
	copy(m, master)

	s := &sec3State{
		aeadID:      aeadID,
		master:      m,
		txLabel:     txLabel,
		rxLabel:     rxLabel,
		rotateBytes: rotateBytes,
		rotateEvery: rotateEvery,
		txEpochAt:   time.Now(),
	}
	if err := s.installTxKey(0); err != nil {
		return nil, err
	}
	if err := s.installRxKey(0); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sec3State) installTxKey(epoch uint32) error {
	key := deriveEpochKey(s.master, s.txLabel, epoch)
	defer zeroBytes(key)
	aead, err := newAEAD(s.aeadID, key)
	if err != nil {
		return err
	}
	s.txKey = aead
	s.txEpoch = epoch
	return nil
}

func (s *sec3State) installRxKey(epoch uint32) error {
	key := deriveEpochKey(s.master, s.rxLabel, epoch)
	defer zeroBytes(key)
	aead, err := newAEAD(s.aeadID, key)
	if err != nil {
		return err
	}
	s.rxKey = aead
	s.rxEpoch = epoch
	return nil
}

// AeadID reports the negotiated AEAD for this connection.
func (s *sec3State) AeadID() uint8 { return s.aeadID }

// status is a test/diagnostic view of both counters.
func (s *sec3State) status() (txEpoch uint32, txSeq uint64, rxEpoch uint32, rxSeq uint64, txPlain uint64) {
	s.txMu.Lock()
	te, ts, tp := s.txEpoch, s.txSeq, s.txPlaintext
	s.txMu.Unlock()
	s.rxMu.Lock()
	re, rs := s.rxEpoch, s.rxSeq
	s.rxMu.Unlock()
	return te, ts, re, rs, tp
}

// shouldRotateLocked reports whether the transmit side must advance epoch.
// Caller holds txMu.
func (s *sec3State) shouldRotateLocked() bool {
	if s.rotateBytes > 0 && int64(s.txPlaintext) >= s.rotateBytes {
		return true
	}
	return s.rotateEvery > 0 && time.Since(s.txEpochAt) >= s.rotateEvery
}

// rotateTxLocked advances the transmit epoch to the next value.
// Caller holds txMu.
func (s *sec3State) rotateTxLocked() error {
	if s.txEpoch == ^uint32(0) {
		return fmt.Errorf("%w: transmit epoch exhausted", errSec3)
	}
	// Discard the old key before installing the new one so a heap dump after
	// rotation cannot recover it from the live struct.
	s.txKey = nil
	s.txSeq = 0
	s.txPlaintext = 0
	s.txEpochAt = time.Now()
	return s.installTxKey(s.txEpoch + 1)
}

// seal encrypts one record.
//
// Frame layout:
//
//	magic(8) version(1) rec_type(1) epoch(4) seq(8) ct_len(4) ciphertext tag(16)
//
// The whole header is the AEAD associated data, so rec_type cannot be
// rewritten (a PADDING record can never be replayed as a FRAME) and the
// declared length is bound to the ciphertext.
func (s *sec3State) seal(recType byte, payload []byte) ([]byte, error) {
	if recType != recFrame && recType != recPadding {
		return nil, fmt.Errorf("%w: unknown record type 0x%02x", errSec3, recType)
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()

	if s.txKey == nil {
		return nil, fmt.Errorf("%w: transmit key is not installed", errSec3)
	}
	if s.shouldRotateLocked() {
		if err := s.rotateTxLocked(); err != nil {
			return nil, err
		}
	}
	if s.txSeq == ^uint64(0) {
		return nil, fmt.Errorf("%w: sequence exhausted in epoch %d", errSec3, s.txEpoch)
	}

	epoch, seq := s.txEpoch, s.txSeq

	hdr := make([]byte, recordHeaderSize)
	copy(hdr, sec3Magic)
	hdr[8] = sec3Version
	hdr[9] = recType
	binary.BigEndian.PutUint32(hdr[10:14], epoch)
	binary.BigEndian.PutUint64(hdr[14:22], seq)
	binary.BigEndian.PutUint32(hdr[22:26], uint32(len(payload)+aeadTagSize))

	ct := s.txKey.Seal(nil, sec3Nonce(seq), payload, hdr)

	s.txSeq++
	s.txPlaintext += uint64(len(payload))
	s.txFrames++

	out := make([]byte, 0, recordHeaderSize+len(ct))
	out = append(out, hdr...)
	out = append(out, ct...)
	return out, nil
}

// open authenticates and decrypts one record.
//
// Replay, reordering and injection all surface as a sequence mismatch and
// are fatal: TCP and WebSocket are ordered and reliable, so any deviation
// means tampering. State is only advanced after the AEAD verifies, so a
// forged record cannot desynchronise the peer.
func (s *sec3State) open(record []byte) (recType byte, payload []byte, err error) {
	if len(record) < recordHeaderSize+aeadTagSize {
		return 0, nil, fmt.Errorf("%w: record too short (%d bytes)", errSec3, len(record))
	}
	if string(record[:8]) != sec3Magic {
		return 0, nil, fmt.Errorf("%w: bad record magic", errSec3)
	}
	if record[8] != sec3Version {
		return 0, nil, fmt.Errorf("%w: unsupported record version %d", errSec3, record[8])
	}
	recType = record[9]
	if recType != recFrame && recType != recPadding {
		return 0, nil, fmt.Errorf("%w: unknown record type 0x%02x", errSec3, recType)
	}
	epoch := binary.BigEndian.Uint32(record[10:14])
	seq := binary.BigEndian.Uint64(record[14:22])
	ctLen := binary.BigEndian.Uint32(record[22:26])
	if uint32(len(record)-recordHeaderSize) != ctLen {
		return 0, nil, fmt.Errorf("%w: record length mismatch (header %d, actual %d)",
			errSec3, ctLen, len(record)-recordHeaderSize)
	}
	hdr := record[:recordHeaderSize]

	s.rxMu.Lock()
	defer s.rxMu.Unlock()

	if s.rxKey == nil {
		return 0, nil, fmt.Errorf("%w: receive key is not installed", errSec3)
	}

	key := s.rxKey
	advancing := false
	switch {
	case epoch == s.rxEpoch && seq == s.rxSeq:
		// In-order record in the current epoch.
	case epoch == s.rxEpoch+1 && seq == 0:
		// Sender rotated. Derive the candidate key but do not install it
		// until the AEAD verifies.
		derived, derr := deriveAndWrap(s.aeadID, s.master, s.rxLabel, epoch)
		if derr != nil {
			return 0, nil, derr
		}
		key, advancing = derived, true
	case epoch == s.rxEpoch && seq != s.rxSeq:
		return 0, nil, fmt.Errorf("%w: unexpected record sequence %d in epoch %d (want %d)",
			errSec3, seq, epoch, s.rxSeq)
	case epoch < s.rxEpoch:
		return 0, nil, fmt.Errorf("%w: epoch regression %d after %d", errSec3, epoch, s.rxEpoch)
	case epoch > s.rxEpoch+1:
		return 0, nil, fmt.Errorf("%w: epoch jumped to %d from %d", errSec3, epoch, s.rxEpoch)
	default:
		return 0, nil, fmt.Errorf("%w: record out of order (epoch %d seq %d)", errSec3, epoch, seq)
	}

	nonce := sec3Nonce(seq)
	plain, aerr := key.Open(nil, nonce, record[recordHeaderSize:], hdr)
	if aerr != nil {
		// Nothing is committed: the connection stays in its current epoch so
		// a single corrupted frame cannot be turned into a desync.
		return 0, nil, fmt.Errorf("%w: record authentication failed", errSec3)
	}

	if advancing {
		s.rxKey = key
		s.rxEpoch = epoch
		s.rxSeq = 0
	}
	s.rxSeq++
	s.rxFrames++
	return recType, plain, nil
}

// deriveAndWrap derives an epoch key and builds the AEAD for it.
func deriveAndWrap(aeadID uint8, master []byte, label string, epoch uint32) (cipher.AEAD, error) {
	key := deriveEpochKey(master, label, epoch)
	defer zeroBytes(key)
	return newAEAD(aeadID, key)
}

// ----------------------------------------------------------------------------
// Transport seam
// ----------------------------------------------------------------------------

// handshakeTransport abstracts the WebSocket connection for the duration of
// the handshake.
//
// Taking *websocket.Conn directly would make the exchange untestable without
// a live socket: "full unit tests for handshake" is not achievable if the
// only way to run one is to bind a port. The tests drive both peers through
// this interface in-process.
type handshakeTransport interface {
	// WriteBinary sends one complete handshake message.
	WriteBinary(data []byte) error
	// ReadBinary returns the next handshake message, or an error once the
	// deadline passes.
	ReadBinary(deadline time.Time) ([]byte, error)
}

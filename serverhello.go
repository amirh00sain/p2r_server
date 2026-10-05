package main

// SPIDER-SEC-3 server hello.
//
// ServerHello answers INNER_HELLO once the server has identified the caller.
// Building it requires two secrets the caller must already hold:
//
//	sharedES  = server_static_private x client_eph_public
//	           Only a holder of the static PRIVATE key can compute this.
//	           An observer of the wire knows the pinned public key, so they
//	           can compute sharedES too - which is exactly why token entropy
//	           is enforced (ValidateToken).
//	sharedEE  = server_eph_private x client_eph_public
//	           Never leaves the server.
//
// ServerHello itself carries the server's ephemeral PUBLIC key in the
// plaintext prefix of its envelope, so the client can finish the exchange and
// then open the sealed body. The body is sealed under serverHelloKey(secret),
// where secret binds both shared secrets, the token and the transcript.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// serverHelloParams describes the answer the server is about to give.
type serverHelloParams struct {
	// SharedES and SharedEE are the two X25519 results (see the note above).
	SharedES []byte
	SharedEE []byte
	// Transcript1 is H(OUTER_HELLO || INNER_HELLO) as raw bytes.
	Transcript1 []byte
	// ClientEphPub is echoed from INNER_HELLO and re-used as the envelope's
	// ephemeral slot so both sides agree on the envelope layout.
	ClientEphPub []byte

	AEAD             uint8
	SelectedFeatures []string
	RotateBytes      int64
	RotateSecs       int64
}

// buildServerHello assembles and seals the SERVER_HELLO message.
//
// The AAD is computed from the probe envelope, because the sealed body length
// must be known before the ciphertext exists - the same reason
// envelopeAAD exists on the client side.
func buildServerHello(token string, ephPub, staticPub []byte, p serverHelloParams) ([]byte, error) {
	secret := handshakeSecret(token, p.SharedES, p.SharedEE, p.Transcript1)
	defer zeroBytes(secret)

	proof := computeServerProof(secret, p.Transcript1, staticPub)

	body := serverHelloBody{
		ServerProof:      hex.EncodeToString(proof),
		SelectedFeatures: p.SelectedFeatures,
		Epoch:            0,
		Aead:             aeadName(p.AEAD),
		KeyRotateBytes:   p.RotateBytes,
		KeyRotateSeconds: p.RotateSecs,
		Timestamp:        time.Now().Unix(),
	}
	plain, err := canonicalJSON(body)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, sec3SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("%w: server envelope salt: %v", errSec3, err)
	}
	key := serverHelloKey(secret)
	defer zeroBytes(key)
	return sealEnvelope(p.AEAD, key, msgServerHello, ephPub, salt, plain)
}

// newServerEph generates the server's ephemeral X25519 key pair and computes
// sharedEE against the client's ephemeral public key.
func newServerEph(clientEphPub []byte) (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: server ephemeral key: %v", errSec3, err)
	}
	clientEph, err := curve.NewPublicKey(clientEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: client ephemeral key: %v", errSec3, err)
	}
	sharedEE, err := eph.ECDH(clientEph)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: x25519 ephemeral: %v", errSec3, err)
	}
	if isAllZero(sharedEE) {
		return nil, nil, fmt.Errorf("%w: all-zero x25519 shared secret", errSec3)
	}
	return eph, sharedEE, nil
}

// isAllZero reports whether b is entirely zero.
func isAllZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

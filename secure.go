package main

// SPIDER-SEC-1 is the private application-layer security protocol carried
// inside the WSS connection. WSS/TLS protects the network transport, while
// this layer provides an additional end-to-end channel between the spider
// client and the Go server.
//
// Suite: X25519 + HKDF-SHA256 + AES-256-GCM
//
// The client authenticates the server with a pinned X25519 static public key.
// The server authenticates the client with the current 256-bit tunnel token.
// Every connection uses fresh ephemeral X25519 keys, so application data gets
// forward secrecy even when a long-term key is later exposed.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	secureProtocolName = "SPIDER-SEC-1"
	secureVersion      = byte(1)
	secureClientHello  = byte(1)
	secureServerHello  = byte(2)
	secureClientFinish = byte(3)

	secureMagic     = "SPDRSEC1"
	secureRecordAD  = "SPIDER-SEC-1-RECORD"
	secureMaxRecord = HeaderSize + MaxPayloadSize + 64
)

var errSecureProtocol = errors.New("spider secure protocol error")

type secureState struct {
	tx cipher.AEAD
	rx cipher.AEAD

	txMu   sync.Mutex
	txNext uint64
	rxMu   sync.Mutex
	rxNext uint64
}

func newSecureState(txKey, rxKey []byte) (*secureState, error) {
	if len(txKey) != 32 || len(rxKey) != 32 {
		return nil, fmt.Errorf("%w: invalid key length", errSecureProtocol)
	}
	txBlock, err := aes.NewCipher(txKey)
	if err != nil {
		return nil, fmt.Errorf("%w: tx cipher: %v", errSecureProtocol, err)
	}
	rxBlock, err := aes.NewCipher(rxKey)
	if err != nil {
		return nil, fmt.Errorf("%w: rx cipher: %v", errSecureProtocol, err)
	}
	tx, err := cipher.NewGCM(txBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: tx gcm: %v", errSecureProtocol, err)
	}
	rx, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: rx gcm: %v", errSecureProtocol, err)
	}
	return &secureState{tx: tx, rx: rx}, nil
}

func secureNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	// 32 zero bits + big-endian 64-bit record counter.
	binaryBigEndianPutUint64(nonce[4:], counter)
	return nonce
}

func (s *secureState) seal(plain []byte) ([]byte, error) {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	if s.txNext == ^uint64(0) {
		return nil, fmt.Errorf("%w: tx nonce exhausted", errSecureProtocol)
	}
	ctr := s.txNext
	s.txNext++

	aad := make([]byte, 8+1+8)
	copy(aad[:8], secureMagic)
	aad[8] = secureVersion
	binaryBigEndianPutUint64(aad[9:], ctr)
	// Bind the record format to this protocol name as extra domain separation.
	aad = append(aad, secureRecordAD...)

	ct := s.tx.Seal(nil, secureNonce(ctr), plain, aad)
	out := make([]byte, 0, len(aad)+len(ct))
	out = append(out, aad...)
	out = append(out, ct...)
	return out, nil
}

func (s *secureState) open(record []byte) ([]byte, error) {
	fixed := 8 + 1 + 8
	adLen := fixed + len(secureRecordAD)
	if len(record) < adLen+s.rx.Overhead() {
		return nil, fmt.Errorf("%w: record too short", errSecureProtocol)
	}
	if string(record[:8]) != secureMagic || record[8] != secureVersion || string(record[fixed:adLen]) != secureRecordAD {
		return nil, fmt.Errorf("%w: invalid record header", errSecureProtocol)
	}
	ctr := binaryBigEndianUint64(record[9:17])

	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if ctr != s.rxNext {
		return nil, fmt.Errorf("%w: unexpected record counter %d (want %d)", errSecureProtocol, ctr, s.rxNext)
	}

	plain, err := s.rx.Open(nil, secureNonce(ctr), record[adLen:], record[:adLen])
	if err != nil {
		return nil, fmt.Errorf("%w: record authentication failed", errSecureProtocol)
	}
	s.rxNext++
	return plain, nil
}

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpandSHA256(prk, info []byte, length int) []byte {
	if length <= 0 {
		return nil
	}
	out := make([]byte, 0, length)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(t)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		t = mac.Sum(nil)
		need := length - len(out)
		if need > len(t) {
			need = len(t)
		}
		out = append(out, t[:need]...)
		if counter == 0 {
			panic("hkdf counter overflow")
		}
	}
	return out
}

func sha256Bytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func tokenHint(token string) []byte {
	return sha256Bytes([]byte("SPIDER-SEC-1\x00TOKEN-HINT\x00"), []byte(token))
}

func tokenSalt(token string) []byte {
	return sha256Bytes([]byte("SPIDER-SEC-1\x00TOKEN\x00"), []byte(token))
}

func deriveHandshakeKeys(token string, sharedES, sharedEE, clientHello, serverHeader []byte) (serverKey, clientKey, transcript []byte) {
	ikm := bytes.Join([][]byte{
		sharedES,
		sharedEE,
		sha256Bytes(clientHello),
		sha256Bytes(serverHeader),
	}, nil)
	prk := hkdfExtractSHA256(tokenSalt(token), ikm)
	serverKey = hkdfExpandSHA256(prk, []byte("SPIDER-SEC-1 handshake server"), 32)
	clientKey = hkdfExpandSHA256(prk, []byte("SPIDER-SEC-1 handshake client"), 32)
	transcript = sha256Bytes(clientHello, serverHeader)
	return
}

func deriveDataKeys(token string, sharedES, sharedEE, transcript []byte) (clientToServer, serverToClient []byte) {
	salt := sha256Bytes([]byte("SPIDER-SEC-1\x00MASTER\x00"), []byte(token))
	prk := hkdfExtractSHA256(salt, bytes.Join([][]byte{sharedES, sharedEE, transcript}, nil))
	clientToServer = hkdfExpandSHA256(prk, []byte("SPIDER-SEC-1 data c2s"), 32)
	serverToClient = hkdfExpandSHA256(prk, []byte("SPIDER-SEC-1 data s2c"), 32)
	return
}

func encryptHandshake(key []byte, nonceByte byte, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	nonce[11] = nonceByte
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func decryptHandshake(key []byte, nonceByte byte, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	nonce[11] = nonceByte
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func makeClientHello(pub, hint, nonce []byte) []byte {
	out := make([]byte, 0, 8+1+1+32+32+32)
	out = append(out, []byte(secureMagic)...)
	out = append(out, secureVersion, secureClientHello)
	out = append(out, hint...)
	out = append(out, pub...)
	out = append(out, nonce...)
	return out
}

func parseClientHello(msg []byte) (hint, pub, nonce []byte, err error) {
	if len(msg) != 106 || string(msg[:8]) != secureMagic || msg[8] != secureVersion || msg[9] != secureClientHello {
		return nil, nil, nil, fmt.Errorf("%w: invalid client hello", errSecureProtocol)
	}
	return append([]byte(nil), msg[10:42]...), append([]byte(nil), msg[42:74]...), append([]byte(nil), msg[74:106]...), nil
}

func makeServerHeader(ephemeralPub, nonce []byte) []byte {
	out := make([]byte, 0, 8+1+1+32+32)
	out = append(out, []byte(secureMagic)...)
	out = append(out, secureVersion, secureServerHello)
	out = append(out, ephemeralPub...)
	out = append(out, nonce...)
	return out
}

func parseServerHello(msg []byte) (header, ephemeralPub, nonce, ciphertext []byte, err error) {
	if len(msg) < 74+16 || string(msg[:8]) != secureMagic || msg[8] != secureVersion || msg[9] != secureServerHello {
		return nil, nil, nil, nil, fmt.Errorf("%w: invalid server hello", errSecureProtocol)
	}
	header = append([]byte(nil), msg[:74]...)
	ephemeralPub = append([]byte(nil), msg[10:42]...)
	nonce = append([]byte(nil), msg[42:74]...)
	ciphertext = append([]byte(nil), msg[74:]...)
	return
}

func makeClientFinish(ciphertext []byte) []byte {
	out := make([]byte, 0, 10+len(ciphertext))
	out = append(out, []byte(secureMagic)...)
	out = append(out, secureVersion, secureClientFinish)
	out = append(out, ciphertext...)
	return out
}

func parseClientFinish(msg []byte) ([]byte, error) {
	if len(msg) < 8+1+1+16 || string(msg[:8]) != secureMagic || msg[8] != secureVersion || msg[9] != secureClientFinish {
		return nil, fmt.Errorf("%w: invalid client finish", errSecureProtocol)
	}
	return msg[10:], nil
}

func readWSBinary(conn *websocket.Conn, deadline time.Time) ([]byte, error) {
	if !deadline.IsZero() {
		_ = conn.SetReadDeadline(deadline)
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	typ, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if typ != websocket.BinaryMessage {
		return nil, fmt.Errorf("%w: handshake message is not binary", errSecureProtocol)
	}
	if len(data) > secureMaxRecord {
		return nil, fmt.Errorf("%w: handshake message too large", errSecureProtocol)
	}
	return data, nil
}

func decodeServerPublicKey(encoded string) (*ecdh.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Also accept hexadecimal output for operator convenience.
		if hb, hexErr := hex.DecodeString(encoded); hexErr == nil {
			b = hb
		} else {
			return nil, fmt.Errorf("%w: invalid server_public_key encoding", errSecureProtocol)
		}
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: server_public_key must be 32 bytes", errSecureProtocol)
	}
	return ecdh.X25519().NewPublicKey(b)
}

func encodeServerPublicKey(pub *ecdh.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub.Bytes())
}

func loadOrCreateServerStaticKey(dataDir string) (*ecdh.PrivateKey, error) {
	path := filepath.Join(dataDir, "server_static_x25519.key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%w: %s has %d bytes, want 32", errSecureProtocol, path, len(b))
		}
		key, err := ecdh.X25519().NewPrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid server static key: %v", errSecureProtocol, err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: read %s: %v", errSecureProtocol, path, err)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: generate server static key: %v", errSecureProtocol, err)
	}
	if err := os.WriteFile(path, key.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("%w: write %s: %v", errSecureProtocol, path, err)
	}
	return key, nil
}

func clientSecureHandshake(conn *websocket.Conn, token string, serverPublicKey string, timeout time.Duration) (*secureState, error) {
	serverStatic, err := decodeServerPublicKey(serverPublicKey)
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: client ephemeral key: %v", errSecureProtocol, err)
	}
	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, fmt.Errorf("%w: client nonce: %v", errSecureProtocol, err)
	}
	clientHello := makeClientHello(eph.PublicKey().Bytes(), tokenHint(token), clientNonce)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := conn.WriteMessage(websocket.BinaryMessage, clientHello); err != nil {
		return nil, fmt.Errorf("%w: send client hello: %v", errSecureProtocol, err)
	}

	msg, err := readWSBinary(conn, time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("%w: receive server hello: %v", errSecureProtocol, err)
	}
	serverHeader, serverEphBytes, _, serverCipher, err := parseServerHello(msg)
	if err != nil {
		return nil, err
	}
	serverEph, err := curve.NewPublicKey(serverEphBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: server ephemeral key: %v", errSecureProtocol, err)
	}

	sharedES, err := eph.ECDH(serverStatic)
	if err != nil {
		return nil, fmt.Errorf("%w: x25519 static auth: %v", errSecureProtocol, err)
	}
	sharedEE, err := eph.ECDH(serverEph)
	if err != nil {
		return nil, fmt.Errorf("%w: x25519 ephemeral: %v", errSecureProtocol, err)
	}
	if bytes.Equal(sharedES, make([]byte, len(sharedES))) || bytes.Equal(sharedEE, make([]byte, len(sharedEE))) {
		return nil, fmt.Errorf("%w: invalid all-zero x25519 secret", errSecureProtocol)
	}

	serverKey, clientKey, transcript := deriveHandshakeKeys(token, sharedES, sharedEE, clientHello, serverHeader)
	expectedServerProof := hmacSHA256(serverKey, []byte("server-proof"), clientHello, serverHeader, serverStatic.Bytes())
	serverProof, err := decryptHandshake(serverKey, 1, serverCipher, serverHeader)
	if err != nil || !hmac.Equal(serverProof, expectedServerProof) {
		return nil, fmt.Errorf("%w: server authentication failed", errSecureProtocol)
	}

	expectedClientProof := hmacSHA256(clientKey, []byte("client-proof"), clientHello, serverHeader, sha256Bytes(serverCipher))
	clientCipher, err := encryptHandshake(clientKey, 2, expectedClientProof, clientHello)
	if err != nil {
		return nil, fmt.Errorf("%w: client proof encryption: %v", errSecureProtocol, err)
	}
	clientFinish := makeClientFinish(clientCipher)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := conn.WriteMessage(websocket.BinaryMessage, clientFinish); err != nil {
		return nil, fmt.Errorf("%w: send client finish: %v", errSecureProtocol, err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	c2s, s2c := deriveDataKeys(token, sharedES, sharedEE, sha256Bytes(transcript, sha256Bytes(serverCipher), sha256Bytes(clientFinish)))
	return newSecureState(c2s, s2c)
}

func serverSecureHandshake(conn *websocket.Conn, users *UserStore, staticKey *ecdh.PrivateKey, timeout time.Duration) (*secureState, *User, error) {
	msg, err := readWSBinary(conn, time.Now().Add(timeout))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receive client hello: %v", errSecureProtocol, err)
	}
	hint, clientPubBytes, _, err := parseClientHello(msg)
	if err != nil {
		return nil, nil, err
	}
	user, ok := users.FindByTokenHint(hint)
	if !ok {
		return nil, nil, fmt.Errorf("%w: unknown credential hint", errSecureProtocol)
	}
	clientPub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: client ephemeral key: %v", errSecureProtocol, err)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: server ephemeral key: %v", errSecureProtocol, err)
	}
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, nil, fmt.Errorf("%w: server nonce: %v", errSecureProtocol, err)
	}
	serverHeader := makeServerHeader(eph.PublicKey().Bytes(), serverNonce)

	sharedES, err := staticKey.ECDH(clientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: x25519 static auth: %v", errSecureProtocol, err)
	}
	sharedEE, err := eph.ECDH(clientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: x25519 ephemeral: %v", errSecureProtocol, err)
	}
	if bytes.Equal(sharedES, make([]byte, len(sharedES))) || bytes.Equal(sharedEE, make([]byte, len(sharedEE))) {
		return nil, nil, fmt.Errorf("%w: invalid all-zero x25519 secret", errSecureProtocol)
	}

	serverKey, clientKey, transcript := deriveHandshakeKeys(user.Token, sharedES, sharedEE, msg, serverHeader)
	serverProof := hmacSHA256(serverKey, []byte("server-proof"), msg, serverHeader, staticKey.PublicKey().Bytes())
	serverCipher, err := encryptHandshake(serverKey, 1, serverProof, serverHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: server proof encryption: %v", errSecureProtocol, err)
	}
	serverHello := append(append([]byte(nil), serverHeader...), serverCipher...)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := conn.WriteMessage(websocket.BinaryMessage, serverHello); err != nil {
		return nil, nil, fmt.Errorf("%w: send server hello: %v", errSecureProtocol, err)
	}

	finish, err := readWSBinary(conn, time.Now().Add(timeout))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receive client finish: %v", errSecureProtocol, err)
	}
	clientCipher, err := parseClientFinish(finish)
	if err != nil {
		return nil, nil, err
	}
	expectedClientProof := hmacSHA256(clientKey, []byte("client-proof"), msg, serverHeader, sha256Bytes(serverCipher))
	clientProof, err := decryptHandshake(clientKey, 2, clientCipher, msg)
	if err != nil || !hmac.Equal(clientProof, expectedClientProof) {
		return nil, nil, fmt.Errorf("%w: client authentication failed", errSecureProtocol)
	}

	c2s, s2c := deriveDataKeys(user.Token, sharedES, sharedEE, sha256Bytes(transcript, sha256Bytes(serverCipher), sha256Bytes(finish)))
	_ = conn.SetWriteDeadline(time.Time{})
	return func() (*secureState, *User, error) {
		state, err := newSecureState(s2c, c2s)
		if err != nil {
			return nil, nil, err
		}
		return state, user, nil
	}()
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = mac.Write(p)
	}
	return mac.Sum(nil)
}

func binaryBigEndianPutUint64(dst []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

func binaryBigEndianUint64(src []byte) uint64 {
	var v uint64
	for _, b := range src {
		v = (v << 8) | uint64(b)
	}
	return v
}

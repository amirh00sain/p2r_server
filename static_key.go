package main

// The server's long-term X25519 identity.
//
// This key is what clients pin. It is generated once, persisted with 0600
// permissions, and never leaves the server: only its public half is printed
// at startup for the operator to paste into client.json.
//
// Losing it is not a security event but an availability one — every client
// with the old pinned key will refuse the connection, which is the intended
// behaviour. Rotating it is an operator action, not something the server
// should do on its own.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// serverStaticKeyPath is the on-disk location of the server identity.
const serverStaticKeyPath = "server_static_x25519.key"

// loadOrCreateServerStaticKey loads the server identity from dataDir,
// generating and persisting it on first boot.
//
// The file is written 0600 and the directory is created 0700 by
// LoadConfig, so the private key is never world-readable.
func loadOrCreateServerStaticKey(dataDir string) (*ecdh.PrivateKey, error) {
	path := filepath.Join(dataDir, serverStaticKeyPath)
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s has %d bytes, want 32", path, len(b))
		}
		key, err := ecdh.X25519().NewPrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("invalid server static key in %s: %w", path, err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server static key: %w", err)
	}
	if err := os.WriteFile(path, key.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return key, nil
}

// encodeServerPublicKey renders the public half for the startup log and the
// client config. base64url keeps it a single line with no padding.
func encodeServerPublicKey(pub *ecdh.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub.Bytes())
}

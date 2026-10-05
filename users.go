package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// User is a single credential allowed to open tunnels.
type User struct {
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Primary   bool      `json:"primary"`
}

type userFile struct {
	Primary string  `json:"primary"`
	Users   []*User `json:"users"`
}

// UserStore persists every issued token to disk so a redeploy (or a container
// restart on Railway) never invalidates running clients.
type UserStore struct {
	mu     sync.RWMutex
	path   string
	users  map[string]*User
	orders []string
}

// NewUserStore builds the credential store inside dataDir. Secondary
// credentials issued at runtime are reloaded from disk, but the primary token
// is ALWAYS a brand-new cryptographically random value for this run: it is
// printed in the startup log and shown on the web panel, so clients copy it
// after every (re)start.
func NewUserStore(dataDir string) (*UserStore, error) {
	s := &UserStore{
		path:  filepath.Join(dataDir, "token.json"),
		users: make(map[string]*User),
	}

	// Reload previously issued secondary credentials (if any).
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		var uf userFile
		if err := json.Unmarshal(data, &uf); err != nil {
			return nil, fmt.Errorf("token file %s is corrupt: %w", s.path, err)
		}
		for _, u := range uf.Users {
			if u == nil || u.Token == "" || u.Primary {
				continue // the previous primary is always retired on restart
			}
			s.users[u.Token] = u
			s.orders = append(s.orders, u.Token)
		}
	case os.IsNotExist(err):
		// first boot
	default:
		return nil, fmt.Errorf("read token file: %w", err)
	}

	token, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	s.users[token] = &User{
		Name:      "primary",
		Token:     token,
		CreatedAt: time.Now().UTC(),
		Primary:   true,
	}
	s.orders = append([]string{token}, s.orders...)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// GenerateToken returns a 256-bit cryptographically random hex token that is
// guaranteed to satisfy ValidateToken.
//
// The guarantee matters more than it looks. The client runs ValidateToken
// before it sends a single byte of the handshake, so a credential that fails
// it is one the client will refuse to use — and a random draw over a
// 16-symbol hex alphabet has a substantial chance of clustering below the
// 16-distinct-character floor. An unguarded GenerateToken would therefore
// issue primary tokens that a legitimate client rejects outright, with the
// operator seeing only "token rejected" and no hint as to why. Retrying here
// keeps the entropy floor strict while making it impossible to issue a
// credential the client cannot use.
//
// The loop is bounded because an unbounded retry on a broken entropy source
// would hang startup instead of failing loudly.
func GenerateToken() (string, error) {
	for attempt := 0; attempt < 64; attempt++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		tok := hex.EncodeToString(b)
		if _, err := ValidateToken(tok); err != nil {
			continue
		}
		return tok, nil
	}
	return "", fmt.Errorf("could not generate a token satisfying ValidateToken after 64 attempts")
}

// PrimaryLocked returns the primary token. Caller must hold at least a read lock.
func (s *UserStore) PrimaryLocked() string {
	for _, tok := range s.orders {
		if u, ok := s.users[tok]; ok && u.Primary {
			return u.Token
		}
	}
	return ""
}

// Primary returns the token that clients must use.
func (s *UserStore) Primary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PrimaryLocked()
}

// Candidates returns a snapshot of every stored credential, in the order the
// handshake will try them.
//
// There is deliberately no lookup-by-hint. SPIDER-SEC-3 identifies the
// caller by trial-decrypting INNER_HELLO against every candidate (see
// secure_handshake.go), which keeps the credential off the wire entirely.
// The slice is ordered so the trial loop is deterministic; it is always
// walked to completion regardless of whether a match is found early.
func (s *UserStore) Candidates() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.orders))
	for _, tok := range s.orders {
		if u, ok := s.users[tok]; ok {
			cp := *u
			out = append(out, &cp)
		}
	}
	return out
}

// Validate performs a constant-time lookup of a presented token. It backs the
// web panel's explicit "check this token" path, not the tunnel handshake.
func (s *UserStore) Validate(token string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var match *User
	// Walk every token with a constant-time comparison so the lookup does not
	// leak which (or how many) credentials exist through timing.
	for _, tok := range s.orders {
		u := s.users[tok]
		if subtle.ConstantTimeCompare([]byte(u.Token), []byte(token)) == 1 {
			match = u
		}
	}
	if match == nil {
		return nil, false
	}
	match.LastSeen = time.Now().UTC()
	cp := *match
	return &cp, true
}

// Add issues an extra credential for a second user/device.
func (s *UserStore) Add(name string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" {
		name = fmt.Sprintf("client-%d", len(s.orders)+1)
	}
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	u := &User{Name: name, Token: token, CreatedAt: time.Now().UTC()}
	s.users[token] = u
	s.orders = append(s.orders, token)
	if err := s.saveLocked(); err != nil {
		delete(s.users, token)
		s.orders = s.orders[:len(s.orders)-1]
		return nil, err
	}
	cp := *u
	return &cp, nil
}

// Revoke deletes a non-primary token.
func (s *UserStore) Revoke(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[token]
	if !ok {
		return fmt.Errorf("unknown token")
	}
	if u.Primary {
		return fmt.Errorf("refusing to revoke the primary token; rotate instead")
	}
	delete(s.users, token)
	for i, t := range s.orders {
		if t == token {
			s.orders = append(s.orders[:i], s.orders[i+1:]...)
			break
		}
	}
	return s.saveLocked()
}

// Rotate replaces the primary token with a brand new random one.
func (s *UserStore) Rotate() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	old := s.PrimaryLocked()
	for tok, u := range s.users {
		if u.Primary {
			u.Primary = false
			u.Name = "old-" + u.Name
			delete(s.users, tok)
			for i, t := range s.orders {
				if t == tok {
					s.orders = append(s.orders[:i], s.orders[i+1:]...)
					break
				}
			}
		}
	}
	u := &User{Name: "primary", Token: token, CreatedAt: time.Now().UTC(), Primary: true}
	s.users[token] = u
	s.orders = append([]string{token}, s.orders...)
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	_ = old
	return token, nil
}

// List returns every credential, primary first, then by creation time.
func (s *UserStore) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*User, 0, len(s.users))
	for _, tok := range s.orders {
		if u, ok := s.users[tok]; ok {
			cp := *u
			out = append(out, &cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Count returns the number of stored credentials.
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Path is the on-disk location of the token database.
func (s *UserStore) Path() string { return s.path }

func (s *UserStore) saveLocked() error {
	uf := userFile{Primary: s.PrimaryLocked()}
	for _, tok := range s.orders {
		if u, ok := s.users[tok]; ok {
			uf.Users = append(uf.Users, u)
		}
	}
	buf, err := json.MarshalIndent(uf, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(buf, '\n'), 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("commit token file: %w", err)
	}
	return nil
}

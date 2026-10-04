package main

import (
	"testing"
)

func TestFindByTokenHint(t *testing.T) {
	dir := t.TempDir()
	s, err := NewUserStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok := s.Primary()
	hint := tokenHint(tok)
	u, ok := s.FindByTokenHint(hint)
	if !ok || u == nil || u.Token != tok {
		t.Fatal("token hint lookup failed")
	}
	bad := append([]byte(nil), hint...)
	bad[0] ^= 1
	if _, ok := s.FindByTokenHint(bad); ok {
		t.Fatal("invalid token hint accepted")
	}
}

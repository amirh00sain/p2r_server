package main

import (
	"testing"
)

func TestSecureRecordRoundTrip(t *testing.T) {
	c2s := []byte("0123456789abcdef0123456789abcdef")
	s2c := []byte("abcdef0123456789abcdef0123456789")
	client, err := newSecureState(c2s, s2c)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newSecureState(s2c, c2s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		plain := EncodeFrame(MsgData, uint32(i+1), []byte("secure test payload"))
		rec, err := client.seal(plain)
		if err != nil {
			t.Fatal(err)
		}
		if string(rec) == string(plain) {
			t.Fatal("record is not encrypted")
		}
		got, err := server.open(rec)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plain) {
			t.Fatalf("round trip mismatch")
		}
	}
}

func TestSecureRecordRejectsTamper(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c, err := newSecureState(key, key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSecureState(key, key)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.seal(EncodeFrame(MsgPing, 0, []byte("hb")))
	if err != nil {
		t.Fatal(err)
	}
	rec[len(rec)-1] ^= 1
	if _, err := s.open(rec); err == nil {
		t.Fatal("tampered record was accepted")
	}
}

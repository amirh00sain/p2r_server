package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	enc := EncodeFrame(MsgData, 0xDEADBEEF, payload)

	got, err := DecodeFrame(enc)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if got.Type != MsgData {
		t.Errorf("type = %d, want %d", got.Type, MsgData)
	}
	if got.SessionID != 0xDEADBEEF {
		t.Errorf("session = %#x, want 0xDEADBEEF", got.SessionID)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload mismatch: got %q", got.Payload)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	got, err := DecodeFrame(EncodeFrame(MsgClose, 7, nil))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("payload = %q, want empty", got.Payload)
	}
	if got.SessionID != 7 {
		t.Errorf("session = %d, want 7", got.SessionID)
	}
}

func TestFrameRejectsMalformed(t *testing.T) {
	valid := EncodeFrame(MsgPing, 1, []byte("hi"))

	cases := map[string][]byte{
		"truncated header": valid[:HeaderSize-1],
		"bad version":      append([]byte{0x02}, valid[1:]...),
		"unknown type":     append([]byte{valid[0], 0x7F}, valid[2:]...),
		"length mismatch":  append(EncodeFrame(MsgData, 1, []byte("abc")), 'x'),
	}
	for name, frame := range cases {
		if _, err := DecodeFrame(frame); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestFrameRejectsOversizePayload(t *testing.T) {
	// A well-formed frame whose payload exceeds the cap must be refused.
	body := make([]byte, MaxPayloadSize+1)
	frame := make([]byte, HeaderSize+len(body))
	frame[0] = ProtocolVersion
	frame[1] = MsgData
	frame[9] = byte(len(body) >> 24)
	frame[8] = byte(len(body) >> 16)
	frame[7] = byte(len(body) >> 8)
	frame[6] = byte(len(body))
	copy(frame[HeaderSize:], body)

	if _, err := DecodeFrame(frame); err == nil {
		t.Fatal("expected an error for an oversized payload")
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{"example.com:443", "1.2.3.4:80", "[2001:db8::1]:443", "a.b.c:1"}
	for _, v := range valid {
		if err := ValidateTarget(v); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"",
		"example.com",
		":443",
		"example.com:",
		"example.com:99999",
		"example.com:abc",
		"exa\tmple.com:443",
		strings.Repeat("a", 400) + ":443",
	}
	for _, v := range invalid {
		if err := ValidateTarget(v); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want an error", v)
		}
	}
}

func TestMsgName(t *testing.T) {
	if MsgName(MsgOpen) != "OPEN" || MsgName(MsgPong) != "PONG" {
		t.Errorf("unexpected names: %q %q", MsgName(MsgOpen), MsgName(MsgPong))
	}
	if !strings.Contains(MsgName(0x63), "UNK") {
		t.Errorf("MsgName(0x63) = %q, want an UNK marker", MsgName(0x63))
	}
}

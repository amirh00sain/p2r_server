package main

// Unit tests for the Origin check. A regression that silently allows any
// Origin would re-open the denial-of-service vector that origin.go exists to
// close, without any other test catching it.

import (
	"net/http"
	"testing"
)

// request builds a WebSocket upgrade request with a given Origin and Host.
func request(origin, host string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/ws", nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestOriginCheckerHandlesEveryPolicy(t *testing.T) {
	// No ALLOWED_ORIGINS: non-browser clients always succeed, browser pages
	// succeed only when they come from the host itself.
	defaultCheck := originChecker(nil)

	if !defaultCheck(request("", "example.com")) {
		t.Error("no Origin must be allowed by default: tunnel clients have no Origin")
	}
	if !defaultCheck(request("https://example.com", "example.com")) {
		t.Error("same-origin request was rejected by the default policy")
	}
	if !defaultCheck(request("https://example.com:8443", "example.com:8443")) {
		t.Error("same-origin with port was rejected")
	}
	if defaultCheck(request("https://evil.com", "example.com")) {
		t.Error("cross-origin request was allowed while ALLOWED_ORIGINS is unset")
	}
	if defaultCheck(request("null", "example.com")) {
		t.Error("\"null\" origin was allowed — that comes from a sandboxed iframe")
	}
	if !defaultCheck(request("HTTPS://EXAMPLE.COM", "example.com")) {
		t.Error("same-origin matching must be case-insensitive")
	}

	// With an allowlist, only the list matters.
	allowCheck := originChecker([]string{"https://a.example.com", "*.b.example.com"})

	if !allowCheck(request("", "example.com")) {
		t.Error("must allow non-browser clients unconditionally, even with an allowlist")
	}
	if !allowCheck(request("https://a.example.com", "example.com")) {
		t.Error("allowed exact origin rejected")
	}
	if !allowCheck(request("https://x.b.example.com", "example.com")) {
		t.Error("allowed wildcard rejected")
	}
	// The bare base domain matches a "*.b.example.com" entry (so an operator
	// listing a wildcard does not lose the apex), but must not match anything
	// that merely contains the same letters.
	if !allowCheck(request("https://b.example.com", "example.com")) {
		t.Error("wildcard base was rejected")
	}
	if allowCheck(request("https://evilb.example.com", "example.com")) {
		t.Error("host that only ends with the same letters was allowed")
	}
	if allowCheck(request("https://evil.com", "example.com")) {
		t.Error("non-listed origin allowed")
	}
	if allowCheck(request("https://a.example.com.evil.com", "example.com")) {
		t.Error("origin that merely contains the allowed name was allowed")
	}

	// Normalisation: scheme/prefix and trailing slash are stripped so that
	// operators can paste a URL verbatim into ALLOWED_ORIGINS.
	schemeAgnoic := originChecker([]string{"https://example.com"})
	if !schemeAgnoic(request("https://example.com", "example.com")) {
		t.Error("https://example.com should match ALLOWED_ORIGINS=https://example.com")
	}
	if !schemeAgnoic(request("http://example.com", "example.com")) {
		t.Error("scheme must be ignored for an allowlist entry that carried one")
	}
}

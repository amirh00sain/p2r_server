package main

// WebSocket Origin validation.
//
// The tunnel endpoint (/ws) is unauthenticated at the HTTP layer — that is
// inherent to the design, because SPIDER-SEC-3 authenticates inside the
// encrypted application handshake, after the upgrade. Accepting any Origin
// header at the upgrade therefore hands any website on the internet a
// cross-site WebSocket to this server.
//
// That matters concretely: a browser page on any origin can open
// wss://this-host/ws, and because the Origin check was disabled the connection
// succeeds. The attacker cannot complete SPIDER-SEC-3 (they hold no token),
// but they can force the server to run the handshake, spend CPU in the
// trial-decryption loop, and fill the client table with connections that fail
// one message later. That is a free denial-of-service vector pointed at the
// operator from any web page.
//
// This file closes it without breaking the actual clients, which are Go
// programs that send no Origin header at all.
//
// Policy, in order:
//  1. No Origin header at all  -> allow. Non-browser clients (the tunnel
//     client, curl, tests) do not send one, and CSRF-style origin checking
//     has nothing to check. This is what keeps the tunnel client working.
//  2. ALLOWED_ORIGINS configured -> allow only an exact match against the
//     list. Wildcards ("*.example.com") are supported because operators
//     routinely front the panel on a subdomain.
//  3. Neither -> allow only same-origin, i.e. the Origin's host:port equals
//     the Host the request arrived with. A browser loading a page from this
//     server's own panel is same-origin and still works.

import (
	"net/http"
	"strings"
)

// originChecker returns a CheckOrigin function for the configured list.
//
// An empty list yields same-origin behaviour rather than allow-everything.
// That is the safer default: an operator who never touches ALLOWED_ORIGINS
// gets a server that a random third-party page cannot connect to, while the
// panel's own JavaScript keeps working.
func originChecker(allowed []string) func(*http.Request) bool {
	if len(allowed) == 0 {
		return sameOriginOnly
	}
	patterns := normalizeOrigins(allowed)
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser client
		}
		host := originHost(origin)
		if host == "" {
			return false // present but unparseable: reject
		}
		for _, p := range patterns {
			if p.matches(host) {
				return true
			}
		}
		return false
	}
}

// sameOriginOnly allows a request whose Origin host matches the Host header.
func sameOriginOnly(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	host := originHost(origin)
	if host == "" {
		return false
	}
	// r.Host is what the client asked for, which behind a proxy is the
	// public name. Comparing against it rather than against the socket
	// address is what makes this work behind Railway's edge.
	return strings.EqualFold(host, r.Host)
}

// originPattern is one entry of ALLOWED_ORIGINS, either an exact host:port or
// a wildcard suffix. The scheme is deliberately not part of the comparison:
// an Origin carries one, but an operator pasting "https://example.com" into
// the variable clearly means the host, not the scheme — and matching it would
// silently reject an HTTP-served panel.
type originPattern struct {
	suffix   string // "*.example.com" -> ".example.com"; exact -> "example.com"
	wildcard bool
}

// normalizeOrigins lowercases and strips scheme/trailing slash so that
// ALLOWED_ORIGINS=https://Example.com/ behaves the way an operator expects.
func normalizeOrigins(in []string) []originPattern {
	out := make([]originPattern, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		s = strings.TrimSuffix(s, "/")
		if s == "" {
			continue
		}
		s = strings.ToLower(s)
		p := originPattern{}
		if strings.HasPrefix(s, "*.") {
			p.wildcard = true
			p.suffix = s[1:] // ".example.com"
		} else {
			p.suffix = s
		}
		out = append(out, p)
	}
	return out
}

// matches compares a host:port taken from an Origin header against one
// configured pattern.
func (p originPattern) matches(host string) bool {
	h := strings.ToLower(host)
	if p.wildcard {
		// "*.example.com" matches "a.example.com" and "example.com" but not
		// "notexample.com" — the leading dot is what keeps it from matching a
		// domain that merely ends with the same letters.
		return h == p.suffix[1:] || strings.HasSuffix(h, p.suffix)
	}
	return h == p.suffix
}

// originHost extracts host[:port] from an Origin header value, rejecting the
// "null" origin that a sandboxed iframe or a cross-origin redirect produces.
//
// Returning "" for "null" is deliberate: allowing it would defeat the whole
// check, because "null" is exactly what an attacker-controlled context sends.
func originHost(origin string) string {
	s := strings.TrimSpace(origin)
	if s == "" || strings.EqualFold(s, "null") {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Drop any path/query a sloppy client appended.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}

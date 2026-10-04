package main

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
)

var errUnauthorized = errors.New("unauthorized")

// Auth validates tunnel credentials and guards the web panel.
type Auth struct {
	users         *UserStore
	panelPassword string
}

// NewAuth builds the authenticator.
func NewAuth(users *UserStore, panelPassword string) *Auth {
	return &Auth{users: users, panelPassword: panelPassword}
}

// ExtractToken pulls the tunnel credential out of a request. Query string is
// the documented method (?token=...), with a header fallback so that clients
// behind strict proxies still work.
func ExtractToken(r *http.Request) string {
	if v := strings.TrimSpace(r.URL.Query().Get("token")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Spider-Token")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			return strings.TrimSpace(v[7:])
		}
	}
	if c, err := r.Cookie("spider_token"); err == nil {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

// Authorize validates the tunnel token of an upgrade request.
func (a *Auth) Authorize(r *http.Request) (*User, error) {
	token := ExtractToken(r)
	if token == "" {
		return nil, errUnauthorized
	}
	user, ok := a.users.Validate(token)
	if !ok {
		return nil, errUnauthorized
	}
	return user, nil
}

// CheckPanel guards the web panel. When no PANEL_PASSWORD is configured the
// panel is open (it only exposes the tunnel token, so it is documented in the
// README as "put a password on it for anything but a lab").
func (a *Auth) CheckPanel(w http.ResponseWriter, r *http.Request) bool {
	if a.panelPassword == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Spider WSS Tunnel", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(a.panelPassword)) == 1
	if !userOK || !passOK {
		w.Header().Set("WWW-Authenticate", `Basic realm="Spider WSS Tunnel", charset="UTF-8"`)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return false
	}
	return true
}

// ClientIP resolves the peer address, honouring X-Forwarded-For only when the
// operator opted in with TRUST_PROXY=true (Railway puts a proxy in front).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			if idx := strings.IndexByte(xff, ','); idx > 0 {
				xff = xff[:idx]
			}
			if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
				return ip.String()
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Version is stamped at build time with -ldflags "-X main.Version=...".
var Version = "1.0.0"

// defaultPort is the fixed listen port. PORT overrides it (Railway injects its
// own port), but an unset PORT always means 8080.
const defaultPort = "8080"

// defaultPanelPassword is the out-of-the-box dashboard credential
// (HTTP Basic, user "admin"). Override it with PANEL_PASSWORD; setting
// PANEL_PASSWORD to an explicit empty value disables panel auth.
const defaultPanelPassword = "admin"

// Config holds every tunable knob of the Spider WSS Tunnel server. Everything
// is read from the environment so the binary can be dropped onto Railway (or
// any PaaS) without a config file.
type Config struct {
	Version string
	Addr    string
	Port    string

	// PanelPassword guards the web panel (HTTP Basic, user "admin").
	PanelPassword  string
	DataDir        string
	TrustedProxy   bool
	AllowedOrigins []string

	// Timeouts.
	HandshakeTimeout  time.Duration
	HeartbeatInterval time.Duration
	DialTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	// Limits.
	MaxClients           int
	MaxSessionsPerClient int
	MaxSessions          int
	BufferSize           int
	MaxUDPPacketSize     int
	UDPIdleTimeout       time.Duration

	PanelLogLines int
	Verbose       bool
}

// LoadConfig reads the environment, applies defaults and validates the result.
func LoadConfig() (*Config, error) {
	c := &Config{
		Version: Version,

		Port:           envStr("PORT", defaultPort),
		PanelPassword:  envStr("PANEL_PASSWORD", defaultPanelPassword),
		DataDir:        envStr("DATA_DIR", "./data"),
		TrustedProxy:   envBool("TRUST_PROXY", false),
		AllowedOrigins: envList("ALLOWED_ORIGINS", nil),

		HandshakeTimeout:  envDur("HANDSHAKE_TIMEOUT", 15*time.Second),
		HeartbeatInterval: envDur("HEARTBEAT_INTERVAL", 20*time.Second),
		DialTimeout:       envDur("DIAL_TIMEOUT", 15*time.Second),
		WriteTimeout:      envDur("WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDur("IDLE_TIMEOUT", 0), // 0 disables read deadlines
		ShutdownTimeout:   envDur("SHUTDOWN_TIMEOUT", 15*time.Second),

		MaxClients:           envInt("MAX_CLIENTS", 128),
		MaxSessionsPerClient: envInt("MAX_SESSIONS_PER_CLIENT", 512),
		MaxSessions:          envInt("MAX_SESSIONS", 8192),
		BufferSize:           envInt("BUFFER_SIZE", 32*1024),
		MaxUDPPacketSize:     envInt("MAX_UDP_PACKET", 65507),
		UDPIdleTimeout:       envDur("UDP_IDLE_TIMEOUT", 5*time.Minute),

		PanelLogLines: envInt("PANEL_LOG_LINES", 500),
		Verbose:       envBool("VERBOSE", false),
	}

	p, err := strconv.Atoi(strings.TrimSpace(c.Port))
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("PORT must be a number between 1 and 65535, got %q", c.Port)
	}
	c.Addr = ":" + c.Port

	switch {
	case c.BufferSize < 4096, c.BufferSize > 1<<20:
		return nil, fmt.Errorf("BUFFER_SIZE must be between 4096 and 1048576, got %d", c.BufferSize)
	case c.MaxClients < 1:
		return nil, fmt.Errorf("MAX_CLIENTS must be >= 1, got %d", c.MaxClients)
	case c.MaxSessions < 1:
		return nil, fmt.Errorf("MAX_SESSIONS must be >= 1, got %d", c.MaxSessions)
	case c.MaxSessionsPerClient < 1:
		return nil, fmt.Errorf("MAX_SESSIONS_PER_CLIENT must be >= 1, got %d", c.MaxSessionsPerClient)
	case c.MaxUDPPacketSize < 576, c.MaxUDPPacketSize > 65507:
		return nil, fmt.Errorf("MAX_UDP_PACKET must be between 576 and 65507, got %d", c.MaxUDPPacketSize)
	case c.HandshakeTimeout <= 0, c.HeartbeatInterval <= 0, c.DialTimeout <= 0, c.WriteTimeout <= 0, c.ShutdownTimeout <= 0:
		return nil, errors.New("HANDSHAKE_TIMEOUT, HEARTBEAT_INTERVAL, DIAL_TIMEOUT, WRITE_TIMEOUT and SHUTDOWN_TIMEOUT must be positive")
	case c.IdleTimeout < 0:
		return nil, fmt.Errorf("IDLE_TIMEOUT must be >= 0 (0 disables), got %s", c.IdleTimeout)
	}
	if c.PanelLogLines < 50 {
		c.PanelLogLines = 50
	}

	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return nil, fmt.Errorf("DATA_DIR %q: %w", c.DataDir, err)
	}
	c.DataDir = abs
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("DATA_DIR %q is not usable: %w", c.DataDir, err)
	}
	return c, nil
}

// ReadTimeout returns the HTTP server read timeout (0 disables it).
func (c *Config) ReadTimeout() time.Duration { return c.IdleTimeout }

// WriteTimeoutOrDefault is used for both destination socket writes and HTTP
// writes, kept positive so a stalled peer cannot pin a goroutine forever.
func (c *Config) WriteTimeoutOrDefault() time.Duration {
	if c.WriteTimeout <= 0 {
		return 30 * time.Second
	}
	return c.WriteTimeout
}

// HandshakeTimeoutOrDefault guards the WebSocket upgrade.
func (c *Config) HandshakeTimeoutOrDefault() time.Duration {
	if c.HandshakeTimeout <= 0 {
		return 15 * time.Second
	}
	return c.HandshakeTimeout
}

// IdleTimeoutOrDefault returns a safe read deadline duration.
func (c *Config) IdleTimeoutOrDefault() time.Duration {
	if c.IdleTimeout <= 0 {
		return 5 * time.Minute
	}
	return c.IdleTimeout
}

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envList(key string, def []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[config] %s=%q is not an integer, using default %d\n", key, v, def)
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[config] %s=%q is not a boolean, using default %t\n", key, v, def)
		return def
	}
	return b
}

func envDur(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[config] %s=%q is not a duration, using default %s\n", key, v, def)
		return def
	}
	return d
}

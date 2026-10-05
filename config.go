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
var Version = "2.0.0-secure"

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

	// HandshakeRateLimit bounds unauthenticated handshake attempts per source
	// IP. SPIDER-SEC-3 identifies callers by trial-decrypting the inner hello
	// against every stored credential, so a handshake is real work that an
	// unauthenticated peer can trigger freely.
	HandshakeRateLimit int

	// AEAD selects the record cipher: "aes-256-gcm" (default) or
	// "chacha20-poly1305". The client offers its choice inside ClientHelloInner
	// and the server must echo it, so a downgrade is detected.
	AEAD string

	// KeyRotateBytes / KeyRotateSeconds are the two automatic rekey triggers.
	// Whichever fires first advances the epoch; the peer derives the next
	// epoch key from the record header alone, so no rekey message is needed.
	KeyRotateBytes   int64
	KeyRotateSeconds time.Duration

	// Padding is optional traffic shaping. Off by default: a fixed-size frame
	// on a fixed timer is itself a fingerprint. See padding.go.
	Padding PaddingConfig

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

		HandshakeRateLimit: envInt("HANDSHAKE_RATE_LIMIT", 10),

		AEAD:             envStr("AEAD", "aes-256-gcm"),
		KeyRotateBytes:   envInt64("KEY_ROTATE_BYTES", 1<<30),
		KeyRotateSeconds: envDur("KEY_ROTATE_SECONDS", time.Hour),
		Padding:          paddingConfigFromEnv(),

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
	case c.HandshakeRateLimit < 1:
		return nil, fmt.Errorf("HANDSHAKE_RATE_LIMIT must be >= 1 handshake per minute, got %d", c.HandshakeRateLimit)
	case c.KeyRotateBytes < 0:
		return nil, fmt.Errorf("KEY_ROTATE_BYTES must be >= 0 (0 disables the byte trigger), got %d", c.KeyRotateBytes)
	case c.KeyRotateSeconds < 0:
		return nil, fmt.Errorf("KEY_ROTATE_SECONDS must be >= 0 (0 disables the time trigger), got %s", c.KeyRotateSeconds)
	case c.KeyRotateBytes == 0 && c.KeyRotateSeconds == 0:
		return nil, errors.New("KEY_ROTATE_BYTES and KEY_ROTATE_SECONDS are both 0: at least one rekey trigger must be enabled")
	}
	if _, err := aeadIDFromName(c.AEAD); err != nil {
		return nil, fmt.Errorf("AEAD: %w", err)
	}
	if err := c.Padding.Validate(); err != nil {
		return nil, fmt.Errorf("PADDING: %w", err)
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

// envInt64 is envInt for byte counts, which overflow 32-bit int on 32-bit
// builds and would silently wrap a 1 GiB rotation limit.
func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
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

// paddingConfigFromEnv reads the six padding environment variables as a whole.
// Individual fields that are absent keep the DefaultPaddingConfig values, so
// "PADDING_ENABLED=true" alone turns on padding with sensible defaults.
func paddingConfigFromEnv() PaddingConfig {
	cfg := DefaultPaddingConfig()

	// The simple knobs are applied first so that the precise ones, when both
	// are set, simply overwrite them. That is the precedence an operator
	// expects: PADDING_SIZES wins over PADDING_MIN_SIZE/MAX_SIZE, and
	// PADDING_MIN_INTERVAL/MAX_INTERVAL win over PADDING_INTERVAL.
	sawSizes := false
	sawWeights := false

	if v, ok := os.LookupEnv("PADDING_ENABLED"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.Enabled = b
		} else if strings.TrimSpace(v) != "" {
			fmt.Fprintf(os.Stderr, "[config] PADDING_ENABLED=%q is not a boolean, using default %v\n", v, cfg.Enabled)
		}
	}
	// PADDING_MIN_SIZE / PADDING_MAX_SIZE describe a range rather than an
	// explicit bucket list, so they are turned into one by the same ladder a
	// client config would use. "4096" to "51200" yields 4, 8, 16, 32 KB and
	// then 50 KB exactly.
	minSize, maxSize := 0, 0
	if v, ok := os.LookupEnv("PADDING_MIN_SIZE"); ok && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			minSize = n
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_MIN_SIZE=%q is not an integer\n", v)
		}
	}
	if v, ok := os.LookupEnv("PADDING_MAX_SIZE"); ok && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			maxSize = n
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_MAX_SIZE=%q is not an integer\n", v)
		}
	}
	if minSize > 0 || maxSize > 0 {
		cfg.Sizes, cfg.Weights = buildSizeLadder(minSize, maxSize)
	}
	// A single nominal interval means "wait about this long", drawn uniformly
	// from half to twice it. A fixed period would be a fingerprint.
	if v, ok := os.LookupEnv("PADDING_INTERVAL"); ok && strings.TrimSpace(v) != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			cfg.MinInterval, cfg.MaxInterval = jitterWindow(d)
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_INTERVAL=%q is not a duration, using %s-%s\n", v, cfg.MinInterval, cfg.MaxInterval)
		}
	}

	if v, ok := os.LookupEnv("PADDING_SIZES"); ok && strings.TrimSpace(v) != "" {
		parts := strings.Split(strings.TrimSpace(v), ",")
		out := make([]int, 0, len(parts))
		okParse := true
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[config] PADDING_SIZES element %q is not an integer, using defaults\n", p)
				okParse = false
				break
			}
			out = append(out, n)
		}
		if okParse && len(out) > 0 {
			cfg.Sizes = out
			sawSizes = true
		}
	}
	if v, ok := os.LookupEnv("PADDING_WEIGHTS"); ok && strings.TrimSpace(v) != "" {
		parts := strings.Split(strings.TrimSpace(v), ",")
		out := make([]float64, 0, len(parts))
		okParse := true
		for _, p := range parts {
			f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[config] PADDING_WEIGHTS element %q is not numeric, using defaults\n", p)
				okParse = false
				break
			}
			out = append(out, f)
		}
		if okParse && len(out) > 0 {
			cfg.Weights = out
			sawWeights = true
		}
	}
	// Sizes without weights would otherwise be checked against whatever weights
	// were already there and fail on a length mismatch the operator never
	// meant to create. Regenerate instead of erroring.
	if sawSizes && !sawWeights {
		cfg.Weights = sizeWeights(len(cfg.Sizes))
	}
	if v, ok := os.LookupEnv("PADDING_MIN_INTERVAL"); ok && strings.TrimSpace(v) != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			cfg.MinInterval = d
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_MIN_INTERVAL=%q is not a duration, using default %s\n", v, cfg.MinInterval)
		}
	}
	if v, ok := os.LookupEnv("PADDING_MAX_INTERVAL"); ok && strings.TrimSpace(v) != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			cfg.MaxInterval = d
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_MAX_INTERVAL=%q is not a duration, using default %s\n", v, cfg.MaxInterval)
		}
	}
	if v, ok := os.LookupEnv("PADDING_MAX_KBPS"); ok && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.MaxKbps = n
		} else {
			fmt.Fprintf(os.Stderr, "[config] PADDING_MAX_KBPS=%q is not an integer, using default %d\n", v, cfg.MaxKbps)
		}
	}
	return cfg
}

package main

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// makeUpgrader builds the WebSocket upgrader for this configuration.
//
// CheckOrigin is deliberately NOT allow-everything. The tunnel endpoint is
// unauthenticated at the HTTP layer -- SPIDER-SEC-3 authenticates inside the
// encrypted application handshake, after the upgrade -- so accepting any
// Origin hands every web page on the internet a cross-site socket to this
// server. An attacker still cannot complete the handshake without the token,
// but they can force the server to run one and fill the client table, which
// is a denial-of-service vector aimed at the operator from any web page.
//
// The tunnel client is a Go program and sends no Origin header, so
// non-browser traffic always passes. The operator's own panel is same-origin
// and passes too. ALLOWED_ORIGINS lets an operator allow further hosts.
//
// The subprotocol is deliberately generic. "spider-secure-v2" announced the
// protocol and its version in a negotiation field anyone on the path reads.
func makeUpgrader(cfg *Config) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		HandshakeTimeout: cfg.HandshakeTimeoutOrDefault(),
		CheckOrigin:      originChecker(cfg.AllowedOrigins),
		Subprotocols:     []string{"chat"},
	}
}

// ClientConn is one authenticated tunnel connection.
type ClientConn struct {
	remote   string
	user     *User
	sessions *SessionTable
	log      *Logger
	srv      *Server

	writeMu sync.Mutex
	conn    *websocket.Conn
	sec     *sec3State

	closeOnce sync.Once
	closing   chan struct{}
	closed    atomic.Bool
}

// NewClientConn binds an upgraded socket to a user credential.
func NewClientConn(conn *websocket.Conn, remote string, user *User, log *Logger, srv *Server, sec *sec3State) *ClientConn {
	c := &ClientConn{
		remote:   remote,
		user:     user,
		sessions: NewSessionTable(),
		log:      log,
		srv:      srv,
		conn:     conn,
		sec:      sec,
		closing:  make(chan struct{}),
	}
	conn.SetReadLimit(int64(sec3MaxRecord))
	return c
}

// Close tears down the socket and every session it owns. Safe to call twice.
func (c *ClientConn) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closing)
		_ = c.conn.Close()
		c.sessions.CloseAll()
	})
}

// IsClosed reports whether the connection is gone.
func (c *ClientConn) IsClosed() bool { return c.closed.Load() }

// Done is closed when the connection goes away.
func (c *ClientConn) Done() <-chan struct{} { return c.closing }

// Name renders "peer/user" for log lines and panel entries.
func (c *ClientConn) Name() string { return c.remote + "/" + c.user.Name }

// SendFrame writes one binary frame. All writes are serialised by writeMu,
// because gorilla/websocket allows only a single concurrent writer.
func (c *ClientConn) SendFrame(typ byte, sessionID uint32, payload []byte) error {
	if c.IsClosed() {
		return fmt.Errorf("client %s is closed", c.remote)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// The application frame from frame.go is sealed verbatim inside a
	// SPIDER-SEC-3 record. frame.go is untouched: this layer wraps the relay,
	// it does not re-encode it.
	plain := EncodeFrame(typ, sessionID, payload)
	buf, err := c.sec.seal(recFrame, plain)
	if err != nil {
		c.Close()
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
		c.Close()
		return err
	}
	return nil
}

// SendPadding writes one PADDING record. The client decrypts it, sees
// recPadding and drops it before the frame decoder runs, so padding can
// never reorder or corrupt relayed application data.
func (c *ClientConn) SendPadding(payload []byte) error {
	if c.IsClosed() {
		return fmt.Errorf("client %s is closed", c.remote)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	buf, err := c.sec.seal(recPadding, payload)
	if err != nil {
		c.Close()
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
		c.Close()
		return err
	}
	return nil
}

// StartPadding begins the traffic-shaping pump for this connection.
//
// It is a no-op when padding is disabled, which is the shipped default. The
// pump is genuinely not started rather than started and told to hold, so a
// disabled policy sends nothing at all and leaves behind no background
// goroutine an operator might mistake for active shaping.
//
// Shaping is per direction: this side sends, the client authenticates each
// record and discards it before the frame decoder runs (and the mirror image
// when the client enables it), so enabling it on one leg shapes that leg's
// observable traffic without touching application data either way.
//
// The pump stops on Done(), so a dropped client cannot leave a goroutine
// sealing records into a dead socket.
func (c *ClientConn) StartPadding(cfg *PaddingConfig) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.Done()
		cancel()
	}()
	go runPadding(ctx, cfg, c.SendPadding, func(size int) {
		if c.srv != nil {
			c.srv.paddingTX.Add(1)
		}
		c.log.Debugf("[%s] padding sent (%d bytes)", c.Name(), size)
	})
}

// SendClose notifies the client that a session must be torn down locally.
func (c *ClientConn) SendClose(sessionID uint32) {
	_ = c.SendFrame(MsgClose, sessionID, nil)
}

// SendWSPing sends a WebSocket control ping. Control pings are separate from
// the binary protocol heartbeat and are useful for keeping intermediary proxies
// alive even when there is no tunnel traffic.
func (c *ClientConn) SendWSPing() error {
	if c.IsClosed() {
		return fmt.Errorf("client %s is closed", c.remote)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
}

// handleFrame dispatches one decoded client frame.
func (c *ClientConn) handleFrame(f *Frame) {
	switch f.Type {
	case MsgPing:
		_ = c.SendFrame(MsgPong, f.SessionID, f.Payload)
	case MsgPong:
		// Heartbeat reply: the client proved it is alive, nothing to do here.
	case MsgClose:
		c.sessions.Delete(f.SessionID)
		c.log.Debugf("[%s] CLOSE sid=%d", c.Name(), f.SessionID)
	case MsgOpen:
		c.handleOpen(f)
	case MsgData:
		c.handleData(f)
	}
}

func (c *ClientConn) handleOpen(f *Frame) {
	if len(f.Payload) == 0 || len(f.Payload) > 512 {
		c.log.Warnf("[%s] rejected OPEN sid=%d: payload %d bytes", c.Name(), f.SessionID, len(f.Payload))
		c.SendClose(f.SessionID)
		return
	}
	target := string(f.Payload)

	// The client tags UDP ASSOCIATE sessions with a "udp://" prefix and puts
	// the client's local relay endpoint after it. Everything else is TCP.
	if strings.HasPrefix(target, "udp://") {
		if err := c.srv.openUDPSession(c, f.SessionID, target); err != nil {
			c.log.Warnf("[%s] OPEN sid=%d udp error: %v", c.Name(), f.SessionID, err)
			c.SendClose(f.SessionID)
		}
		return
	}

	if err := ValidateTarget(target); err != nil {
		c.log.Warnf("[%s] rejected OPEN sid=%d target=%s: %v", c.Name(), f.SessionID, target, err)
		c.SendClose(f.SessionID)
		return
	}
	if err := c.srv.openTCPSession(c, f.SessionID, target); err != nil {
		c.log.Warnf("[%s] OPEN sid=%d target=%s failed: %v", c.Name(), f.SessionID, target, err)
		c.SendClose(f.SessionID)
	}
}

func (c *ClientConn) handleData(f *Frame) {
	if len(f.Payload) == 0 {
		return
	}
	sess, ok := c.sessions.Get(f.SessionID)
	if !ok {
		return
	}
	if sess.IsUDP() {
		if err := c.srv.handleUDPUpstream(sess, f.Payload); err != nil && c.srv.cfg.Verbose {
			c.log.Debugf("[%s] sid=%d udp upstream: %v", c.Name(), sess.ID, err)
		}
		return
	}
	if err := sess.WriteDownstream(f.Payload, c.srv.cfg.WriteTimeoutOrDefault(), &c.srv.stats); err != nil {
		c.log.Debugf("[%s] sid=%d downstream write: %v", c.Name(), sess.ID, err)
	}
}

// limitOK enforces MAX_SESSIONS_PER_CLIENT before a session is created.
func (c *ClientConn) limitOK() bool {
	per := c.srv.cfg.MaxSessionsPerClient
	if per <= 0 {
		per = 512
	}
	return c.sessions.Count() < per
}

// ----------------------------------------------------------------------------
// Server: owns HTTP, clients, counters
// ----------------------------------------------------------------------------

// Server orchestrates the HTTP listener, WSS upgrades and shared counters.
type Server struct {
	cfg       *Config
	log       *Logger
	auth      *Auth
	users     *UserStore
	staticKey *ecdh.PrivateKey
	stats     ServerStats

	clientsMu sync.RWMutex
	clients   map[*ClientConn]struct{}

	clientsTotal atomic.Int32

	// handshakeLimiter bounds unauthenticated handshake attempts per source
	// IP. See secure_handshake.go for why the trial-decryption loop needs it.
	handshakeLimiter *handshakeLimiter

	// upgrader is built once from config. CheckOrigin is configuration
	// dependent, so it cannot live in a package-level value.
	upgrader websocket.Upgrader

	// paddingRX/TX count PADDING records, separately from application
	// traffic, so the panel can report shaping without inflating relay stats.
	paddingRX atomic.Uint64
	paddingTX atomic.Uint64
}

// NewServer wires a fully configured server.
func NewServer(cfg *Config, log *Logger, users *UserStore, staticKey *ecdh.PrivateKey) *Server {
	return &Server{
		cfg:              cfg,
		log:              log,
		auth:             NewAuth(users, cfg.PanelPassword),
		users:            users,
		staticKey:        staticKey,
		clients:          make(map[*ClientConn]struct{}),
		handshakeLimiter: newHandshakeLimiter(cfg.HandshakeRateLimit),
		upgrader:         makeUpgrader(cfg),
	}
}

func (s *Server) addClient(c *ClientConn) {
	s.clientsMu.Lock()
	s.clients[c] = struct{}{}
	s.clientsMu.Unlock()
	s.clientsTotal.Add(1)
}

func (s *Server) removeClient(c *ClientConn) {
	s.clientsMu.Lock()
	if _, ok := s.clients[c]; ok {
		delete(s.clients, c)
		s.clientsMu.Unlock()
		s.clientsTotal.Add(-1)
		return
	}
	s.clientsMu.Unlock()
}

// ActiveClients returns the number of connected tunnel clients.
func (s *Server) ActiveClients() int { return int(s.clientsTotal.Load()) }

// ActiveSessions returns the number of live sessions across all clients.
func (s *Server) ActiveSessions() int {
	s.clientsMu.RLock()
	conns := make([]*ClientConn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.clientsMu.RUnlock()

	total := 0
	for _, c := range conns {
		total += c.sessions.Count()
	}
	return total
}

// ClientsSnapshot copies a stable view of connected clients for the panel.
type ClientSnapshot struct {
	Name      string  `json:"name"`
	User      string  `json:"user"`
	Sessions  int     `json:"sessions"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	Connected float64 `json:"connected_seconds"`
}

func (s *Server) clientsSnapshot() []ClientSnapshot {
	s.clientsMu.RLock()
	conns := make([]*ClientConn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.clientsMu.RUnlock()

	out := make([]ClientSnapshot, 0, len(conns))
	for _, c := range conns {
		sessions := c.sessions.Snapshot()
		var up, down uint64
		for _, si := range sessions {
			up += si.BytesUp
			down += si.BytesDown
		}
		out = append(out, ClientSnapshot{
			Name:      c.remote,
			User:      c.user.Name,
			Sessions:  len(sessions),
			RxBytes:   down,
			TxBytes:   up,
			Connected: 0,
		})
	}
	return out
}

// handleWS upgrades first; SPIDER-SEC-3 authenticates the tunnel inside the
// WebSocket, so the token never appears in HTTP headers or the URL.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && len(s.cfg.AllowedOrigins) > 0 {
		allowed := false
		for _, o := range s.cfg.AllowedOrigins {
			if strings.EqualFold(o, origin) {
				allowed = true
				break
			}
		}
		if !allowed {
			s.log.Warnf("ws origin rejected: %s", origin)
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
	}

	if s.ActiveClients() >= s.cfg.MaxClients {
		s.log.Warnf("ws handshake from %s rejected: MAX_CLIENTS=%d reached", ClientIP(r, s.cfg.TrustedProxy), s.cfg.MaxClients)
		http.Error(w, "too many clients", http.StatusServiceUnavailable)
		return
	}

	remote := ClientIP(r, s.cfg.TrustedProxy)
	if !s.cfg.TrustedProxy {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			remote = host
		}
	}

	// Rate-limit before the upgrade so a flood of handshakes costs a map
	// lookup rather than an X25519 exchange and a credential-store walk.
	if !s.handshakeLimiter.allow(remote) {
		s.log.Warnf("ws handshake from %s rate limited (HANDSHAKE_RATE_LIMIT=%d/min)", remote, s.cfg.HandshakeRateLimit)
		http.Error(w, "too many handshake attempts", http.StatusTooManyRequests)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Debugf("ws upgrade from %s failed: %v", remote, err)
		return
	}

	aeadID, err := aeadIDFromName(s.cfg.AEAD)
	if err != nil {
		_ = conn.Close()
		s.log.Errorf("config: %v", err)
		return
	}
	var accepted []uint8
	if s.cfg.AEAD != "" {
		accepted = []uint8{aeadID}
	}

	sec, user, err := serverSecureHandshake(&wsTransport{conn: conn}, serverHandshakeParams{
		Users:             s.users,
		StaticKey:         s.staticKey,
		AcceptedAEADs:     accepted,
		SupportedFeatures: []string{"tcp", "https", "udp"},
		AEAD:              aeadID,
		RotateBytes:       s.cfg.KeyRotateBytes,
		RotateSecs:        int64(s.cfg.KeyRotateSeconds.Seconds()),
		Timeout:           s.cfg.HandshakeTimeoutOrDefault(),
		Logf:              s.log.Infof,
	})
	if err != nil {
		_ = conn.Close()
		s.log.Warnf("secure handshake from %s failed: %v", remote, err)
		return
	}

	client := NewClientConn(conn, remote, user, s.log, s, sec)
	// Traffic shaping starts only now that the record layer exists: a padding
	// record is sealed under a live epoch key, so there is nothing to pump
	// before the handshake completes.
	client.StartPadding(&s.cfg.Padding)
	s.addClient(client)
	s.log.Infof("client connected: %s (secure=%s aead=%s)", client.Name(), Sec3ProtocolName, aeadName(aeadID))
	go s.serveClient(client)
}

// serveClient runs the read loop and the heartbeat pinger for one client.
func (s *Server) serveClient(c *ClientConn) {
	defer s.removeClient(c)
	defer c.Close()
	defer s.log.Infof("client disconnected: %s", c.Name())

	defer func() {
		if rec := recover(); rec != nil {
			s.log.Errorf("panic in client %s: %v", c.Name(), rec)
		}
	}()

	lastPong := time.Now()
	var mu sync.Mutex // guards lastPong across read/heartbeat goroutines

	// A WebSocket control PONG is handled internally by gorilla/websocket and
	// does not surface as a normal ReadMessage. Track it explicitly so it also
	// keeps the server-side heartbeat/deadline alive.
	c.conn.SetPongHandler(func(string) error {
		mu.Lock()
		lastPong = time.Now()
		mu.Unlock()
		if s.cfg.IdleTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		return nil
	})

	// Heartbeat: server-side PING so a dead client (or a dead middlebox) is
	// detected even when the client itself went silent.
	pinger := time.NewTicker(s.cfg.HeartbeatInterval)
	defer pinger.Stop()
	go func() {
		for {
			select {
			case <-c.Done():
				return
			case <-pinger.C:
				mu.Lock()
				silent := time.Since(lastPong)
				mu.Unlock()
				if silent > 3*s.cfg.HeartbeatInterval {
					s.log.Debugf("[%s] heartbeat timeout after %s", c.Name(), silent.Round(time.Second))
					c.Close()
					return
				}
				if err := c.SendWSPing(); err != nil {
					return
				}
				if err := c.SendFrame(MsgPing, 0, []byte("hb")); err != nil {
					return
				}
			}
		}
	}()

	if s.cfg.IdleTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
	}
	for {
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			if !websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				s.log.Debugf("[%s] read closed: %v", c.Name(), err)
			}
			return
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		recType, plain, err := c.sec.open(data)
		if err != nil {
			s.log.Warnf("[%s] dropped unauthenticated secure record: %v", c.Name(), err)
			return
		}
		if recType == recPadding {
			// Authenticated padding: discard. It must not reach the frame
			// decoder, the session table or the heartbeat clock.
			s.paddingRX.Add(1)
			continue
		}
		frame, err := DecodeFrame(plain)
		if err != nil {
			s.log.Warnf("[%s] dropped malformed frame: %v", c.Name(), err)
			continue
		}
		mu.Lock()
		lastPong = time.Now()
		mu.Unlock()
		if s.cfg.IdleTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		c.handleFrame(frame)
	}
}

// mask hides all but the first/last characters of a secret for logs.
func mask(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "…" + secret[len(secret)-4:]
}

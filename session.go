package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionState tracks where a session is in its lifecycle.
type SessionState int32

const (
	SessionOpening SessionState = iota
	SessionOpen
	SessionClosed
)

func (s SessionState) String() string {
	switch s {
	case SessionOpening:
		return "opening"
	case SessionOpen:
		return "open"
	default:
		return "closed"
	}
}

// Session is one tunneled flow opened by a client: a TCP destination, or a
// logical UDP ASSOCIATE.
type Session struct {
	ID        uint32
	Target    string
	CreatedAt time.Time

	owner   *ClientConn
	state   atomic.Int32
	conn    net.Conn // destination TCP socket; nil for UDP sessions
	udp     *UDPSession
	closed  chan struct{}
	closeIt sync.Once

	// firstTeardown guards the CLOSE notification so it is sent exactly once
	// even when both the upstream pump and the client's CLOSE frame race.
	firstTeardown atomic.Bool

	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
}

func newSession(id uint32, target string, owner *ClientConn) *Session {
	s := &Session{
		ID:        id,
		Target:    target,
		CreatedAt: time.Now(),
		owner:     owner,
		closed:    make(chan struct{}),
	}
	s.state.Store(int32(SessionOpening))
	return s
}

func (s *Session) setState(st SessionState)   { s.state.Store(int32(st)) }
func (s *Session) State() SessionState        { return SessionState(s.state.Load()) }
func (s *Session) IsClosed() bool             { return s.State() == SessionClosed }
func (s *Session) Done() <-chan struct{}      { return s.closed }
func (s *Session) AddUp(n int)                { s.bytesUp.Add(uint64(n)) }
func (s *Session) AddDown(n int)              { s.bytesDown.Add(uint64(n)) }
func (s *Session) IsUDP() bool                { return s.udp != nil }

// NotifyClose reports the teardown to the client exactly once.
func (s *Session) NotifyClose() bool {
	return s.firstTeardown.CompareAndSwap(false, true)
}

// teardown closes the destination socket and the UDP helper exactly once.
func (s *Session) teardown() {
	s.closeIt.Do(func() {
		s.setState(SessionClosed)
		close(s.closed)
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.udp != nil {
			s.udp.teardown()
		}
	})
}

// Info is a snapshot for the web panel.
type SessionInfo struct {
	ID        uint32 `json:"id"`
	Target    string `json:"target"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	AgeMs     int64  `json:"age_ms"`
	BytesUp   uint64 `json:"bytes_up"`
	BytesDown uint64 `json:"bytes_down"`
	UDP       bool   `json:"udp"`
}

func (s *Session) Info() SessionInfo {
	age := time.Since(s.CreatedAt).Milliseconds()
	if age < 0 {
		age = 0
	}
	return SessionInfo{
		ID:        s.ID,
		Target:    s.Target,
		State:     s.State().String(),
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		AgeMs:     age,
		BytesUp:   s.bytesUp.Load(),
		BytesDown: s.bytesDown.Load(),
		UDP:       s.IsUDP(),
	}
}

// WriteDownstream pushes client payload into the destination socket.
func (s *Session) WriteDownstream(data []byte, timeout time.Duration, stats *ServerStats) error {
	if len(data) == 0 {
		return nil
	}
	conn := s.conn
	if conn == nil {
		return fmt.Errorf("session %d has no destination connection", s.ID)
	}
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	s.bytesUp.Add(uint64(len(data)))
	if stats != nil {
		stats.TxBytes.Add(uint64(len(data)))
	}
	return nil
}

// ----------------------------------------------------------------------------
// Session table (per client connection)
// ----------------------------------------------------------------------------

// SessionTable is the per-client map of live sessions.
type SessionTable struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
}

func NewSessionTable() *SessionTable {
	return &SessionTable{sessions: make(map[uint32]*Session)}
}

// Get returns a session by id.
func (t *SessionTable) Get(id uint32) (*Session, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.sessions[id]
	return s, ok
}

// Add registers a session, failing when the id is already taken.
func (t *SessionTable) Add(s *Session) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[s.ID]; ok {
		return fmt.Errorf("session %d already exists", s.ID)
	}
	t.sessions[s.ID] = s
	return nil
}

// Delete removes and tears down a session.
func (t *SessionTable) Delete(id uint32) {
	t.mu.Lock()
	s, ok := t.sessions[id]
	if ok {
		delete(t.sessions, id)
	}
	t.mu.Unlock()
	if ok {
		s.teardown()
	}
}

// Count returns the number of live sessions.
func (t *SessionTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Snapshot copies info for every session.
func (t *SessionTable) Snapshot() []SessionInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]SessionInfo, 0, len(t.sessions))
	for _, s := range t.sessions {
		out = append(out, s.Info())
	}
	return out
}

// CloseAll tears down every session owned by a disconnecting client.
func (t *SessionTable) CloseAll() {
	t.mu.Lock()
	sessions := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.sessions = make(map[uint32]*Session)
	t.mu.Unlock()
	for _, s := range sessions {
		s.teardown()
	}
}

// ----------------------------------------------------------------------------
// Shared counters
// ----------------------------------------------------------------------------

// ServerStats is the counter pair the panel shows as RX / TX.
type ServerStats struct {
	RxBytes atomic.Uint64 // destination -> client
	TxBytes atomic.Uint64 // client -> destination
}

// StatsSnapshot is the JSON shape served at /api/stats.
type StatsSnapshot struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// dialTarget opens a TCP connection to "host:port" with a bounded timeout.
func dialTarget(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, nil
}

package main

import (
	"context"
	"io"
	"net"
	"time"
)

// openTCPSession dials target, registers the session and starts the
// destination->client pump. On failure nothing is left behind and the caller
// sends CLOSE so the client can fail its local SOCKS5 socket immediately.
func (s *Server) openTCPSession(c *ClientConn, sessionID uint32, target string) error {
	if !c.limitOK() {
		return errSessionLimit
	}
	if s.ActiveSessions() >= s.cfg.MaxSessions {
		return errGlobalSessionLimit
	}
	if _, exists := c.sessions.Get(sessionID); exists {
		return errDuplicateSession
	}

	sess := newSession(sessionID, target, c)
	if err := c.sessions.Add(sess); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	conn, err := dialTarget(ctx, target, s.cfg.DialTimeout)
	cancel()
	if err != nil {
		c.sessions.Delete(sessionID)
		return err
	}

	sess.conn = conn
	sess.setState(SessionOpen)
	s.log.Infof("[%s] OPEN sid=%d -> %s", c.Name(), sessionID, target)

	go s.pumpUpstream(sess, conn)
	return nil
}

// pumpUpstream copies destination -> client until either side closes.
func (s *Server) pumpUpstream(sess *Session, conn net.Conn) {
	owner := sess.owner
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Errorf("[%s] sid=%d upstream panic: %v", owner.Name(), sess.ID, rec)
		}
		s.teardownSession(sess)
	}()

	buf := make([]byte, s.cfg.BufferSize)
	for {
		if s.cfg.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			sess.AddDown(n)
			s.stats.RxBytes.Add(uint64(n))
			if werr := owner.SendFrame(MsgData, sess.ID, chunk); werr != nil {
				s.log.Debugf("[%s] sid=%d upstream stalled: %v", owner.Name(), sess.ID, werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF && s.cfg.Verbose {
				s.log.Debugf("[%s] sid=%d upstream ended (%s): %v", owner.Name(), sess.ID, sess.Target, err)
			}
			return
		}
		if sess.IsClosed() || owner.IsClosed() {
			return
		}
	}
}

// teardownSession removes a session from its owner table, closes the
// destination socket and tells the client to clean up locally. Every step is
// idempotent, so the destination-side EOF and the client's CLOSE frame may
// both arrive without double-counting or double-closing.
func (s *Server) teardownSession(sess *Session) {
	owner := sess.owner
	if owner != nil {
		owner.sessions.Delete(sess.ID)
	}
	sess.teardown()
	if owner != nil && !owner.IsClosed() && sess.NotifyClose() {
		owner.SendClose(sess.ID)
	}
}

var (
	errSessionLimit       = &limitError{"per-client session limit reached"}
	errGlobalSessionLimit = &limitError{"global session limit reached"}
	errDuplicateSession   = &limitError{"session id already in use"}
)

// limitError marks rejections caused by configured capacity limits.
type limitError struct{ msg string }

func (e *limitError) Error() string { return e.msg }

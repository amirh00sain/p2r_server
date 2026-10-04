package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDP datagram encapsulation used inside DATA frames of a UDP session:
//
//	[2B dst_len BE][dst "host:port" bytes][raw datagram...]
//
// The textual destination keeps the tunnel protocol-agnostic: DNS, games and
// VoIP routinely retarget datagrams within one SOCKS5 ASSOCIATE.
const udpHeaderLen = 2

// UDPSession is one logical UDP ASSOCIATE: a shared socket on the server that
// forwards datagrams to whichever destination the client names and routes
// answers back tagged with their source address.
type UDPSession struct {
	sess   *Session
	srv    *Server
	owner  *ClientConn
	conn   *net.UDPConn
	target string

	mu      sync.Mutex
	cache   map[string]*net.UDPAddr
	lastAct time.Time

	closeOnce sync.Once
	stopped   chan struct{}
}

// openUDPSession creates the UDP ASSOCIATE for a session id.
func (s *Server) openUDPSession(c *ClientConn, sessionID uint32, target string) error {
	if !c.limitOK() {
		return errSessionLimit
	}
	if s.ActiveSessions() >= s.cfg.MaxSessions {
		return errGlobalSessionLimit
	}

	hint := target
	if len(target) > len("udp://") {
		hint = target[len("udp://"):]
	}

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("udp listen: %w", err)
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return fmt.Errorf("unexpected packet conn type %T", pc)
	}

	sess := newSession(sessionID, "udp:"+hint, c)
	u := &UDPSession{
		sess:    sess,
		srv:     s,
		owner:   c,
		conn:    udpConn,
		target:  hint,
		cache:   make(map[string]*net.UDPAddr),
		lastAct: time.Now(),
		stopped: make(chan struct{}),
	}
	sess.udp = u

	if err := c.sessions.Add(sess); err != nil {
		_ = udpConn.Close()
		return err
	}
	sess.setState(SessionOpen)
	s.log.Infof("[%s] OPEN sid=%d -> UDP ASSOCIATE (%s)", c.Name(), sessionID, hint)

	go u.pump()
	go u.reaper()
	return nil
}

// handleUDPUpstream decodes one client datagram and writes it out.
func (s *Server) handleUDPUpstream(sess *Session, payload []byte) error {
	u := sess.udp
	if u == nil {
		return fmt.Errorf("session %d is not a UDP session", sess.ID)
	}
	return u.send(payload)
}

// send decodes and forwards one encapsulated datagram.
func (u *UDPSession) send(payload []byte) error {
	dst, datagram, err := splitUDPDatagram(payload)
	if err != nil {
		return err
	}
	if len(datagram) == 0 {
		return fmt.Errorf("empty datagram for %s", dst)
	}
	if len(datagram) > u.srv.cfg.MaxUDPPacketSize {
		return fmt.Errorf("datagram too large for %s: %d > %d", dst, len(datagram), u.srv.cfg.MaxUDPPacketSize)
	}
	addr, err := u.resolve(dst)
	if err != nil {
		return err
	}
	_ = u.conn.SetWriteDeadline(time.Now().Add(u.srv.cfg.WriteTimeoutOrDefault()))
	n, err := u.conn.WriteToUDP(datagram, addr)
	if err != nil {
		return fmt.Errorf("udp write %s: %w", dst, err)
	}
	u.touch()
	u.sess.AddUp(n)
	u.srv.stats.TxBytes.Add(uint64(n))
	return nil
}

// resolve returns a cached destination address, resolving it on first use.
func (u *UDPSession) resolve(dst string) (*net.UDPAddr, error) {
	u.mu.Lock()
	if a, ok := u.cache[dst]; ok {
		u.mu.Unlock()
		return a, nil
	}
	u.mu.Unlock()

	if err := ValidateTarget(dst); err != nil {
		return nil, err
	}
	a, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", dst, err)
	}
	u.mu.Lock()
	u.cache[dst] = a
	u.mu.Unlock()
	return a, nil
}

func (u *UDPSession) touch() {
	u.mu.Lock()
	u.lastAct = time.Now()
	u.mu.Unlock()
}

func (u *UDPSession) idleFor() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	return time.Since(u.lastAct)
}

// teardown closes the socket and stops the goroutines, exactly once.
func (u *UDPSession) teardown() {
	u.closeOnce.Do(func() {
		close(u.stopped)
		_ = u.conn.Close()
	})
}

// reaper ends associations that went completely quiet.
func (u *UDPSession) reaper() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-u.stopped:
			return
		case <-ticker.C:
			if u.srv.cfg.UDPIdleTimeout > 0 && u.idleFor() > u.srv.cfg.UDPIdleTimeout {
				u.srv.log.Infof("[%s] sid=%d UDP idle for %s, closing", u.owner.Name(), u.sess.ID, u.idleFor().Round(time.Second))
				u.srv.teardownSession(u.sess)
				return
			}
		}
	}
}

// pump routes answers from any destination back to the client, tagging each
// packet with its real source address.
func (u *UDPSession) pump() {
	srv := u.srv
	defer func() {
		if rec := recover(); rec != nil {
			srv.log.Errorf("[%s] sid=%d UDP pump panic: %v", u.owner.Name(), u.sess.ID, rec)
		}
		srv.teardownSession(u.sess)
	}()

	buf := make([]byte, srv.cfg.MaxUDPPacketSize+udpHeaderLen+280)
	for {
		_ = u.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, src, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-u.stopped:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u.sess.IsClosed() || u.owner.IsClosed() {
					return
				}
				continue
			}
			if srv.cfg.Verbose {
				srv.log.Debugf("[%s] sid=%d UDP read ended: %v", u.owner.Name(), u.sess.ID, err)
			}
			return
		}
		if n == 0 || src == nil {
			continue
		}
		u.touch()
		enc := joinUDPDatagram(src.String(), buf[:n])
		u.sess.AddDown(n)
		srv.stats.RxBytes.Add(uint64(n))
		if werr := u.owner.SendFrame(MsgData, u.sess.ID, enc); werr != nil {
			srv.log.Debugf("[%s] sid=%d UDP upstream stalled: %v", u.owner.Name(), u.sess.ID, werr)
			return
		}
	}
}

// splitUDPDatagram decodes the client's encapsulation.
func splitUDPDatagram(payload []byte) (string, []byte, error) {
	if len(payload) < udpHeaderLen {
		return "", nil, fmt.Errorf("udp frame too short: %d bytes", len(payload))
	}
	dstLen := int(binary.BigEndian.Uint16(payload[:udpHeaderLen]))
	if dstLen <= 0 || dstLen > 260 {
		return "", nil, fmt.Errorf("bad udp destination length %d", dstLen)
	}
	if len(payload) < udpHeaderLen+dstLen {
		return "", nil, fmt.Errorf("udp frame truncated: need %d, have %d", udpHeaderLen+dstLen, len(payload))
	}
	dst := string(payload[udpHeaderLen : udpHeaderLen+dstLen])
	if err := ValidateTarget(dst); err != nil {
		return "", nil, err
	}
	return dst, payload[udpHeaderLen+dstLen:], nil
}

// joinUDPDatagram encodes a downstream datagram with its source tag.
func joinUDPDatagram(src string, datagram []byte) []byte {
	if len(src) > 260 {
		src = src[:260]
	}
	out := make([]byte, udpHeaderLen+len(src)+len(datagram))
	binary.BigEndian.PutUint16(out[:udpHeaderLen], uint16(len(src)))
	copy(out[udpHeaderLen:], src)
	copy(out[udpHeaderLen+len(src):], datagram)
	return out
}

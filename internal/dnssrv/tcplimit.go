package dnssrv

import (
	"net"
	"net/netip"
	"sync"
)

// TCP connection limits (all listeners together, and per client address):
// beyond, a new connection is closed at once. Idle connections are already
// closed after 10 s, so the limits only bite on a flood.
const (
	maxTCPConns      = 512
	maxTCPConnsPerIP = 32
)

type connLimits struct {
	max, perIP int

	mu    sync.Mutex
	total int
	byIP  map[netip.Addr]int
}

func newConnLimits(max, perIP int) *connLimits {
	return &connLimits{max: max, perIP: perIP, byIP: map[netip.Addr]int{}}
}

// take reserves a connection slot for ip.
func (c *connLimits) take(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total >= c.max || c.byIP[ip] >= c.perIP {
		return false
	}
	c.total++
	c.byIP[ip]++
	return true
}

func (c *connLimits) give(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total--
	if c.byIP[ip]--; c.byIP[ip] <= 0 {
		delete(c.byIP, ip)
	}
}

// wrap returns a listener applying the limits.
func (c *connLimits) wrap(l net.Listener) net.Listener { return &limitListener{Listener: l, c: c} }

type limitListener struct {
	net.Listener
	c *connLimits
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := addrOf(conn.RemoteAddr())
		if !l.c.take(ip) {
			conn.Close()
			continue
		}
		return &limitConn{Conn: conn, c: l.c, ip: ip}, nil
	}
}

type limitConn struct {
	net.Conn
	c    *connLimits
	ip   netip.Addr
	once sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.c.give(c.ip) })
	return err
}

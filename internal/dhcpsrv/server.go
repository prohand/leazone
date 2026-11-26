package dhcpsrv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Server owns the UDP socket. One socket on 0.0.0.0:67 receives the
// broadcasts of every interface; IP_PKTINFO tells which interface a packet
// came from, so VLANs added at runtime need no new socket.
type Server struct {
	Engine *Engine
	Port   int // 67 in production; the client port is Port+1
	log    *slog.Logger

	mu      sync.Mutex
	pc      *ipv4.PacketConn
	conn    net.PacketConn
	lastErr string
}

// NewServer returns a server bound to nothing yet.
func NewServer(e *Engine, port int, log *slog.Logger) *Server {
	return &Server{Engine: e, Port: port, log: log}
}

// Status describes the socket.
func (s *Server) Status() (listening bool, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pc != nil, s.lastErr
}

// Ensure opens or closes the socket depending on whether a scope is active.
func (s *Server) Ensure(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := s.Engine.HasActiveScopes()
	switch {
	case want && s.pc == nil:
		if err := s.open(ctx); err != nil {
			s.lastErr = bindError(err, s.Port)
			s.log.Error("DHCP listen failed", "port", s.Port, "err", s.lastErr)
			return
		}
		s.lastErr = ""
		s.log.Info("DHCP listening", "port", s.Port)
	case !want && s.pc != nil:
		s.conn.Close()
		s.pc, s.conn = nil, nil
		s.log.Info("DHCP stopped (no active scope)")
	}
}

func (s *Server) open(ctx context.Context) error {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	conn, err := lc.ListenPacket(ctx, "udp4", ":"+strconv.Itoa(s.Port))
	if err != nil {
		return err
	}
	pc := ipv4.NewPacketConn(conn)
	if err := pc.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true); err != nil {
		conn.Close()
		return err
	}
	s.pc, s.conn = pc, conn
	go s.loop(pc)
	return nil
}

func (s *Server) loop(pc *ipv4.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, cm, _, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("DHCP read", "err", err)
			continue
		}
		msg, err := dhcpv4.FromBytes(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		p := Packet{Msg: msg}
		if cm != nil {
			p.IfIndex = cm.IfIndex
			if d, ok := netip.AddrFromSlice(cm.Dst.To4()); ok {
				p.Dst = d
			}
		}
		go s.answer(pc, p)
	}
}

func (s *Server) answer(pc *ipv4.PacketConn, p Packet) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := s.Engine.Handle(ctx, p)
	if r == nil {
		return
	}
	port := s.Port + 1
	dst := r.To
	if r.ToRelay {
		port = s.Port
	}
	if r.Broadcast {
		dst = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	cm := &ipv4.ControlMessage{IfIndex: r.IfIndex}
	if r.Src.IsValid() && !r.Broadcast {
		cm.Src = net.IP(r.Src.AsSlice())
	}
	if _, err := pc.WriteTo(r.Msg.ToBytes(), cm, &net.UDPAddr{IP: net.IP(dst.AsSlice()), Port: port}); err != nil {
		s.log.Warn("DHCP send failed", "to", dst, "err", err)
	}
}

// Close stops the socket.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.pc, s.conn = nil, nil
	}
}

func bindError(err error, port int) string {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Sprintf("le port %d/udp est déjà utilisé : un autre serveur DHCP tourne sur l'hôte (dnsmasq, isc-dhcp-server, "+
			"kea...). Arrêtez-le, vérifiez avec : ss -lunp | grep ':%d '", port, port)
	case errors.Is(err, syscall.EACCES):
		return fmt.Sprintf("permission refusée pour le port %d : ajoutez la capability NET_BIND_SERVICE au conteneur", port)
	}
	return err.Error()
}

// ICMPPinger sends one echo request and waits for a reply.
type ICMPPinger struct {
	Timeout time.Duration
	log     *slog.Logger
}

// NewPinger returns a pinger, or nil when ICMP sockets are not available
// (no NET_RAW and unprivileged ping disabled).
func NewPinger(log *slog.Logger) *ICMPPinger {
	p := &ICMPPinger{Timeout: 400 * time.Millisecond, log: log}
	if c, err := p.listen(); err == nil {
		c.Close()
		return p
	}
	log.Warn("ping before lease unavailable: add the NET_RAW capability")
	return nil
}

func (p *ICMPPinger) listen() (*icmp.PacketConn, error) {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return c, nil
	}
	return icmp.ListenPacket("udp4", "0.0.0.0") // unprivileged ICMP
}

// InUse reports whether ip answers an ICMP echo.
func (p *ICMPPinger) InUse(ctx context.Context, ip netip.Addr) bool {
	c, err := p.listen()
	if err != nil {
		return false
	}
	defer c.Close()
	id := int(time.Now().UnixNano() & 0xffff)
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("leazone")}}
	b, _ := msg.Marshal(nil)
	var dst net.Addr = &net.IPAddr{IP: net.IP(ip.AsSlice())}
	if c.LocalAddr().Network() == "udp" {
		dst = &net.UDPAddr{IP: net.IP(ip.AsSlice())}
	}
	if _, err := c.WriteTo(b, dst); err != nil {
		return false
	}
	deadline := time.Now().Add(p.Timeout)
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return false
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		var fromIP net.IP
		switch a := from.(type) {
		case *net.IPAddr:
			fromIP = a.IP
		case *net.UDPAddr:
			fromIP = a.IP
		}
		if fromIP.Equal(net.IP(ip.AsSlice())) {
			return true
		}
	}
	return false
}

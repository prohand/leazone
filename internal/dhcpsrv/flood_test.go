package dhcpsrv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// One MAC cannot send more than its burst; other clients are not affected
// until the interface itself goes over its rate.
func TestServerRateLimits(t *testing.T) {
	s := NewServer(nil, 0, quiet)
	now := time.Now()
	s.perMAC.SetClock(func() time.Time { return now })
	s.perLink.SetClock(func() time.Time { return now })
	p := Packet{Msg: discover(mac(1)), IfIndex: 10}
	for i := 0; i < macBurst; i++ {
		if !s.admit(p) {
			t.Fatalf("request %d of one MAC refused", i)
		}
	}
	if s.admit(p) {
		t.Fatal("MAC over its burst admitted")
	}
	n := macBurst + 1
	for i := 2; n < linkBurst; i++ {
		if !s.admit(Packet{Msg: discover(mac(i)), IfIndex: 10}) {
			t.Fatalf("other MAC refused after %d requests on the interface", n)
		}
		n++
	}
	if s.admit(Packet{Msg: discover(mac(60000)), IfIndex: 10}) {
		t.Fatal("interface over its rate admitted")
	}
	if !s.admit(Packet{Msg: discover(mac(60001)), IfIndex: 20}) {
		t.Fatal("another interface limited")
	}
	relayed := Packet{Msg: discover(mac(60002), dhcpv4.WithGatewayIP(net.IPv4(10, 0, 40, 1))), IfIndex: 10}
	if !s.admit(relayed) {
		t.Fatal("relay limited by the interface it arrives on")
	}
}

// Lease changes are written by the writer, in order, and Handle returns
// only once they are on disk.
func TestLeaseWrittenBeforeReply(t *testing.T) {
	e, _, _ := newEngine(t)
	ip, _ := dora(t, e, mac(1), 10)
	if !ip.IsValid() {
		t.Fatal("no lease")
	}
	e2, err := NewEngine(context.Background(), e.db.db, quiet)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range e2.Leases() {
		if l.IP == ip && l.State == StateBound {
			found = true
		}
	}
	if !found {
		t.Fatalf("lease %s not on disk when the ACK left: %+v", ip, e2.Leases())
	}
	if _, err := e.Release(context.Background(), firstScope(e, "eth0.10"), ip); err != nil {
		t.Fatal(err)
	}
	e3, _ := NewEngine(context.Background(), e.db.db, quiet)
	for _, l := range e3.Leases() {
		if l.IP == ip && l.State != StateReleased {
			t.Fatalf("release not on disk: %+v", l)
		}
	}
}

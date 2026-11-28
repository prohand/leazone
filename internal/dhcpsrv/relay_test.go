package dhcpsrv

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func subnetSel(a, b, c, d byte) dhcpv4.Modifier {
	return dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionSubnetSelection, []byte{a, b, c, d}))
}

// A client forging giaddr and option 118 must not get an address of
// another network, from a direct VLAN or from the WAN.
func TestRelaySpoofedGiaddrAndSubnetSelection(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	// From direct VLAN 10: giaddr = its own address, 118 = the relayed network.
	m := discover(mac(7), dhcpv4.WithGatewayIP(net.IPv4(10, 0, 10, 77)), subnetSel(10, 0, 40, 1))
	if r := e.Handle(ctx, Packet{Msg: m, IfIndex: 10, Src: netip.MustParseAddr("10.0.10.77")}); r != nil {
		t.Fatalf("forged relay from VLAN 10 answered: %s %s", r.Msg.MessageType(), r.Msg.YourIPAddr)
	}
	// Same without a known source address (tests, old callers).
	m = discover(mac(7), dhcpv4.WithGatewayIP(net.IPv4(10, 0, 10, 77)), subnetSel(10, 0, 40, 1))
	if r := e.Handle(ctx, Packet{Msg: m, IfIndex: 10}); r != nil {
		t.Fatalf("forged relay from VLAN 10 answered: %s %s", r.Msg.MessageType(), r.Msg.YourIPAddr)
	}
	// From the WAN (DHCP disabled there), an Internet giaddr and 118.
	m = discover(mac(8), dhcpv4.WithGatewayIP(net.IPv4(203, 0, 113, 9)), subnetSel(10, 0, 40, 1))
	if r := e.Handle(ctx, Packet{Msg: m, IfIndex: 1, Src: netip.MustParseAddr("203.0.113.9")}); r != nil {
		t.Fatalf("forged relay from the WAN answered: %s %s", r.Msg.MessageType(), r.Msg.YourIPAddr)
	}
	// Link selection (82.5) from an untrusted relay is ignored too.
	o82 := dhcpv4.OptRelayAgentInfo(dhcpv4.OptGeneric(subLinkSelection, []byte{10, 0, 40, 0}))
	m = discover(mac(9), dhcpv4.WithGatewayIP(net.IPv4(203, 0, 113, 9)), dhcpv4.WithOption(o82))
	if r := e.Handle(ctx, Packet{Msg: m, IfIndex: 1, Src: netip.MustParseAddr("203.0.113.9")}); r != nil {
		t.Fatal("82.5 from an untrusted relay honored")
	}
}

// giaddr of the relayed network but sent from another address: refused,
// unless that address is a listed relay agent of the scope.
func TestRelaySourceMustBeTheRelay(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	gi := dhcpv4.WithGatewayIP(net.IPv4(10, 0, 40, 1))
	if r := e.Handle(ctx, Packet{Msg: discover(mac(1), gi), IfIndex: 1, Src: netip.MustParseAddr("192.168.1.66")}); r != nil {
		t.Fatal("relayed request from another source answered")
	}
	if r := e.Handle(ctx, Packet{Msg: discover(mac(1), gi), IfIndex: 1, Src: netip.MustParseAddr("10.0.40.1")}); r == nil {
		t.Fatal("genuine relayed request ignored")
	}
	scopes := scopesOf(e)
	for _, s := range scopes {
		if s.Relay {
			s.RelayAgents = []string{"192.168.1.254"}
		}
	}
	setConfig(e, scopes)
	if r := e.Handle(ctx, Packet{Msg: discover(mac(2), gi), IfIndex: 1, Src: netip.MustParseAddr("192.168.1.254")}); r == nil {
		t.Fatal("relay sending from a listed agent address ignored")
	}
}

// Option 118 / 82.5 are honored for a relay listed in the agents of the
// scope they designate.
func TestRelayTrustedSubnetSelection(t *testing.T) {
	e, _, _ := newEngine(t)
	scopes := scopesOf(e)
	for _, s := range scopes {
		if s.Relay {
			s.RelayAgents = []string{"192.168.1.254"}
		}
	}
	setConfig(e, scopes)
	m := discover(mac(3), dhcpv4.WithGatewayIP(net.IPv4(192, 168, 1, 254)), subnetSel(10, 0, 40, 0))
	r := e.Handle(context.Background(), Packet{Msg: m, IfIndex: 1, Src: netip.MustParseAddr("192.168.1.254")})
	if r == nil || !netip.MustParsePrefix("10.0.40.0/24").Contains(ipOf(r.Msg.YourIPAddr)) {
		t.Fatalf("trusted subnet selection: %v", r)
	}
}

// A direct INFORM is answered by unicast to ciaddr: only an address of the
// client's network.
func TestInformCiaddrInNetwork(t *testing.T) {
	e, _, _ := newEngine(t)
	inform := func(ci net.IP) *Reply {
		m, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeInform), dhcpv4.WithHwAddr(mac(4)), dhcpv4.WithClientIP(ci))
		return e.Handle(context.Background(), Packet{Msg: m, IfIndex: 10})
	}
	if r := inform(net.IPv4(8, 8, 8, 8)); r != nil {
		t.Fatalf("INFORM answered to an outside address: %+v", r)
	}
	if r := inform(net.IPv4(10, 0, 10, 50)); r == nil || r.To.String() != "10.0.10.50" {
		t.Fatalf("INFORM from the network: %+v", r)
	}
}

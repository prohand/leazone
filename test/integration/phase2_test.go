//go:build integration

package integration

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

// veth creates a veth pair with ip/prefix on the first end (host netns).
func veth(t *testing.T, name, cidr string) {
	t.Helper()
	l := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
	if old, err := netlink.LinkByName(name); err == nil {
		netlink.LinkDel(old)
	}
	if err := netlink.LinkAdd(l); err != nil {
		t.Fatalf("veth %s: %v", name, err)
	}
	t.Cleanup(func() { netlink.LinkDel(l) })
	addr, _ := netlink.ParseAddr(cidr)
	if err := netlink.AddrAdd(l, addr); err != nil {
		t.Fatal(err)
	}
	peer, _ := netlink.LinkByName(name + "p")
	netlink.LinkSetUp(peer)
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
}

func query(server, name string, qtype uint16, proto string) (*dns.Msg, error) {
	c := &dns.Client{Net: proto, Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := c.Exchange(q, net.JoinHostPort(server, "53"))
	return r, err
}

func waitAnswer(t *testing.T, server, name, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		r, err := query(server, name, dns.TypeA, "udp")
		if err == nil && len(r.Answer) == 1 && r.Answer[0].(*dns.A).A.String() == want {
			return
		}
		last = ""
		if err != nil {
			last = err.Error()
		} else {
			last = r.String()
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s @%s: no %s answer (last: %s)", name, server, want, last)
}

// TestPhase2DNS: non-root, read-only container serving DNS on chosen
// interfaces only, hot interface detection, forwarding, port conflicts.
func TestPhase2DNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create test interfaces")
	}
	veth(t, "lzi0", "10.53.0.1/24")
	veth(t, "lzi9", "10.59.0.1/24") // interface where DNS stays disabled

	// Upstream resolver for forwarding tests (on the host, loopback).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upPort := pc.LocalAddr().(*net.UDPAddr).Port
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A: net.ParseIP("10.200.0.1")}}
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()

	c := startContainer(t, "leazone-it2", "127.0.0.1:18446")
	a := newAPI(t, c)
	a.loginAdmin()

	var z struct{ ID string }
	if s := a.do("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, &z); s != 201 {
		t.Fatalf("zone: %d", s)
	}
	a.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "10.53.0.10"}}, nil)

	// DNS on lzi0 only.
	var it struct {
		DNSListeners []struct{ State, Error string }
	}
	if s := a.do("PATCH", "/api/v1/interfaces/lzi0", map[string]any{"dnsEnabled": true}, &it); s != 200 {
		t.Fatalf("enable DNS on lzi0: %d", s)
	}
	waitAnswer(t, "10.53.0.1", "nas.maison.lan", "10.53.0.10")
	if r, err := query("10.53.0.1", "nas.maison.lan", dns.TypeA, "tcp"); err != nil || len(r.Answer) != 1 {
		t.Fatalf("TCP: %v %v", r, err)
	}
	t.Log("✔ answers on 10.53.0.1 (UDP + TCP) as UID 1000 with a read-only root filesystem")
	if _, err := query("10.59.0.1", "nas.maison.lan", dns.TypeA, "udp"); err == nil {
		t.Fatal("answered on an interface where DNS is disabled")
	}
	t.Log("✔ silent on the interface where DNS is disabled (no 0.0.0.0 listener)")

	// Hot add: enable DNS for an interface that does not exist yet, then create it.
	a.do("PATCH", "/api/v1/interfaces/lzi1", map[string]any{"dnsEnabled": true}, nil)
	veth(t, "lzi1", "10.54.0.1/24")
	waitAnswer(t, "10.54.0.1", "nas.maison.lan", "10.53.0.10")
	t.Log("✔ interface added on the host is served without restart")

	// Forwarding.
	if s := a.do("POST", "/api/v1/dns/forwarders", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": upPort}, nil); s != 201 {
		t.Fatalf("forwarder: %d", s)
	}
	waitAnswer(t, "10.53.0.1", "www.example.org", "10.200.0.1")
	t.Log("✔ forwarding to the upstream resolver")

	// Port conflict: something else owns 10.55.0.1:53 before Leazone.
	veth(t, "lzi2", "10.55.0.1/24")
	busy, err := net.ListenPacket("udp", "10.55.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	var it2 struct {
		DNSListeners []struct{ Protocol, State, Error string }
	}
	a.do("PATCH", "/api/v1/interfaces/lzi2", map[string]any{"dnsEnabled": true}, &it2)
	found := false
	for _, l := range it2.DNSListeners {
		if l.Protocol == "udp" && l.State == "error" && strings.Contains(l.Error, "déjà utilisé") {
			found = true
		}
	}
	if !found {
		t.Fatalf("port conflict not reported: %+v", it2.DNSListeners)
	}
	t.Log("✔ port 53 conflict reported clearly: " + it2.DNSListeners[0].Error[:60] + "…")

	// Container hardening.
	if u := run(t, "docker", "inspect", "-f", "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}}", c.name); u != "1000:1000 true" {
		t.Fatalf("container user/readonly: %s", u)
	}
}

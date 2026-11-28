package dnssrv

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
)

// ANY gets one RRset for clients outside the recursion networks (RFC 8482);
// the LAN keeps the full answer.
func TestMinimalANYOutsideRecursion(t *testing.T) {
	e := New(quiet, 0)
	z, r := testZones()
	e.Load(z, r, nil, dnsconf.DefaultSettings())
	if m := ask(t, e, "www.maison.lan", dns.TypeANY, "203.0.113.5"); len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("ANY from outside: %v", m.Answer)
	}
	if m := ask(t, e, "www.maison.lan", dns.TypeANY, "192.168.1.2"); len(m.Answer) != 2 {
		t.Fatalf("ANY from the LAN: %v", m.Answer)
	}
}

// bigEngine serves a local name with an answer of about 3 KB.
func bigEngine(t *testing.T, st dnsconf.Settings) (*Engine, string) {
	t.Helper()
	port := freePort(t)
	e := New(quiet, port)
	z, r := testZones()
	recs := r["z1"]
	for i := 0; i < 30; i++ {
		recs = append(recs, &dnsconf.Record{Name: "big", Type: "TXT", Data: dnsconf.RecordData{Text: fmt.Sprintf("%02d-%s", i, strings.Repeat("x", 90))}})
	}
	r["z1"] = recs
	e.Load(z, r, nil, st)
	e.SetListeners([]ListenAddr{{IP: netip.MustParseAddr("127.0.0.1"), Interface: "lo"}})
	t.Cleanup(e.Close)
	return e, "127.0.0.1:" + strconv.Itoa(port)
}

// A client announcing a 64 KB EDNS buffer gets at most 1232 bytes over UDP.
func TestUDPAnswerCapped(t *testing.T) {
	_, addr := bigEngine(t, dnsconf.DefaultSettings())
	c := &dns.Client{Net: "udp", Timeout: time.Second, UDPSize: 65535}
	q := new(dns.Msg)
	q.SetQuestion("big.maison.lan.", dns.TypeTXT)
	q.SetEdns0(65535, false)
	resp, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Compress = true // as the server packed it
	b, _ := resp.Pack()
	if len(b) > maxUDPSize || !resp.Truncated {
		t.Fatalf("UDP answer of %d bytes, truncated %v", len(b), resp.Truncated)
	}
}

// Clients outside the recursion networks are rate limited per network:
// beyond the burst, answers are dropped or replaced by empty truncated
// ones. The LAN is never limited.
func TestResponseRateLimit(t *testing.T) {
	st := dnsconf.DefaultSettings()
	st.RecursionNetworks = []string{"10.0.0.0/8"} // 127.0.0.1 is "outside"
	e, addr := bigEngine(t, st)
	now := time.Now()
	e.rrl.SetClock(func() time.Time { return now }) // no refill during the test
	c := &dns.Client{Net: "udp", Timeout: 100 * time.Millisecond}
	full, tc, lost := 0, 0, 0
	for i := 0; i < 2*rrlBurst+20; i++ {
		q := new(dns.Msg)
		q.SetQuestion("www.maison.lan.", dns.TypeA)
		resp, _, err := c.Exchange(q, addr)
		switch {
		case err != nil:
			lost++
		case resp.Truncated && len(resp.Answer) == 0:
			tc++
		default:
			full++
		}
	}
	if full != rrlBurst || tc == 0 || lost == 0 {
		t.Fatalf("full %d, truncated %d, dropped %d", full, tc, lost)
	}
	if e.Stats().Limited == 0 {
		t.Fatal("limited queries not counted")
	}
	// The same client inside the recursion networks: no limit.
	st.RecursionNetworks = []string{"127.0.0.0/8"}
	e.Load(nil, nil, nil, st)
	for i := 0; i < 2*rrlBurst; i++ {
		q := new(dns.Msg)
		q.SetQuestion("nope.example.", dns.TypeA)
		if _, _, err := c.Exchange(q, addr); err != nil {
			t.Fatalf("LAN query %d: %v", i, err)
		}
	}
}

func TestRecursionInflightLimits(t *testing.T) {
	e := New(quiet, 0)
	a, b := netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("192.168.1.3")
	var rel []func()
	for i := 0; i < maxInflightClient; i++ {
		r, ok := e.acquireRecursion(a)
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := e.acquireRecursion(a); ok {
		t.Fatal("client over its limit")
	}
	for i := maxInflightClient; i < maxInflight; i++ {
		r, ok := e.acquireRecursion(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
		if !ok {
			t.Fatalf("global slot %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := e.acquireRecursion(b); ok {
		t.Fatal("over the global limit")
	}
	for _, r := range rel {
		r()
	}
	if _, ok := e.acquireRecursion(b); !ok || len(e.perCli) != 1 {
		t.Fatalf("slots not given back: %d clients", len(e.perCli))
	}
}

// Beyond the per-address limit, a new TCP connection is closed at once;
// closing one frees its slot.
func TestTCPConnectionLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newConnLimits(10, 2).wrap(ln)
	defer l.Close()
	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(), dial()
	s1, s2 := <-accepted, <-accepted
	c3 := dial()
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("third connection not closed: %v", err)
	}
	s1.Close()
	c4 := dial()
	select {
	case s := <-accepted:
		s.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot not given back")
	}
	for _, c := range []net.Conn{c1, c2, c3, c4, s2} {
		c.Close()
	}
}

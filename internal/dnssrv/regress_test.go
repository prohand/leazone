package dnssrv

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
)

// cdUpstream behaves like a validating resolver for a bogus zone: SERVFAIL,
// unless the query has the CD bit, then the unvalidated data.
type cdUpstream struct{}

func (cdUpstream) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if !r.CheckingDisabled {
		m.Rcode = dns.RcodeServerFailure
	} else {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A: net.ParseIP("10.6.6.6")}}
	}
	_ = w.WriteMsg(m)
}

func TestCacheSeparatesCD(t *testing.T) {
	e := New(quiet, 0)
	e.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", startUDPTCP(t, cdUpstream{}))}, dnsconf.DefaultSettings())
	q := new(dns.Msg)
	q.SetQuestion("bogus.example.", dns.TypeA)
	q.CheckingDisabled = true
	if r, _ := e.handle(context.Background(), q, netip.MustParseAddr("192.168.1.2")); len(r.Answer) != 1 {
		t.Fatalf("CD=1: %v", r)
	}
	// A client that wants validated data must not get the CD=1 answer.
	if m := ask(t, e, "bogus.example", dns.TypeA, "192.168.1.3"); m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
		t.Fatalf("CD=0 client got the unvalidated answer: %v", m)
	}
}

func TestCacheKeyUnknownTypes(t *testing.T) {
	// Types without a mnemonic must not share a cache entry.
	c := newCache()
	c.configure(10, 0, 3600, 900)
	q1 := dns.Question{Name: "x.example.", Qtype: 65280, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "x.example.", Qtype: 65281, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: 65280, Class: dns.ClassINET, Ttl: 60}, Rdata: "00"}}
	c.set(q1, false, false, m)
	if c.get(q2, false, false) != nil {
		t.Fatal("TYPE65281 answered from the TYPE65280 entry")
	}
	if c.get(q1, false, false) == nil {
		t.Fatal("TYPE65280 not cached")
	}
}

package dnssrv

import (
	"testing"

	"github.com/miekg/dns"
)

func TestCacheKeyUnknownTypes(t *testing.T) {
	// Types without a mnemonic must not share a cache entry.
	c := newCache()
	c.configure(10, 0, 3600, 900)
	q1 := dns.Question{Name: "x.example.", Qtype: 65280, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "x.example.", Qtype: 65281, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: 65280, Class: dns.ClassINET, Ttl: 60}, Rdata: "00"}}
	c.set(q1, false, m)
	if c.get(q2, false) != nil {
		t.Fatal("TYPE65281 answered from the TYPE65280 entry")
	}
	if c.get(q1, false) == nil {
		t.Fatal("TYPE65280 not cached")
	}
}

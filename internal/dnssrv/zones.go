// Package dnssrv is the DNS server: authoritative answers for local zones,
// a cache, forwarding to upstream resolvers (UDP, TCP, DoT, DoH) with
// failover, and per-IP listeners reconciled at runtime.
package dnssrv

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssec"
)

// zoneData is the in-memory content of one authoritative zone.
type zoneData struct {
	name  string // FQDN, lowercase
	soa   *dns.SOA
	rrs   map[string]map[uint16][]dns.RR // owner FQDN -> type -> records
	names map[string]bool                // existing names, including empty non-terminals
	sec   *signedZone                    // nil = not signed
}

// zoneSet is an immutable snapshot of all local zones.
type zoneSet struct {
	zones map[string]*zoneData
}

// signing is the DNSSEC input of buildZones (nil = no signing).
type signing struct {
	keys  map[string][]*dnssec.Key // by zone id
	nsec  map[string]string        // NSEC mode by zone id
	now   time.Time
	cache *sigCache
}

func buildZones(zones []*dnsconf.Zone, recs map[string][]*dnsconf.Record, sg *signing) *zoneSet {
	zs := &zoneSet{zones: map[string]*zoneData{}}
	for _, z := range zones {
		zd := &zoneData{name: dns.Fqdn(z.Name), soa: dnsconf.SOARecord(z), rrs: map[string]map[uint16][]dns.RR{}, names: map[string]bool{}}
		zd.add(zd.soa)
		for _, r := range recs[z.ID] {
			ttl := z.TTL
			if r.TTL != nil {
				ttl = *r.TTL
			}
			rr, err := dnsconf.ToRR(r.Name, z.Name, r.Type, ttl, r.Data)
			if err == nil {
				zd.add(rr)
			}
		}
		if sg != nil && len(sg.keys[z.ID]) > 0 {
			zd.sign(sg.keys[z.ID], sg.nsec[z.ID] != "nsec", sg.now, sg.cache)
		}
		zs.zones[zd.name] = zd
	}
	return zs
}

func (z *zoneData) add(rr dns.RR) {
	owner := strings.ToLower(rr.Header().Name)
	rr.Header().Name = owner
	if z.rrs[owner] == nil {
		z.rrs[owner] = map[uint16][]dns.RR{}
	}
	t := rr.Header().Rrtype
	z.rrs[owner][t] = append(z.rrs[owner][t], rr)
	// Mark the owner and every ancestor up to the apex as existing
	// (empty non-terminals answer NODATA, not NXDOMAIN).
	for n := owner; ; {
		z.names[n] = true
		if n == z.name {
			break
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i == len(n)-1 {
			break
		}
		n = n[i+1:]
	}
}

// find returns the zone with the longest suffix match for qname.
func (zs *zoneSet) find(qname string) *zoneData {
	if zs == nil {
		return nil
	}
	for n := qname; ; {
		if z, ok := zs.zones[n]; ok {
			return z
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i == len(n)-1 {
			return nil
		}
		n = n[i+1:]
	}
}

func copyRRs(in []dns.RR, owner string) []dns.RR {
	out := make([]dns.RR, len(in))
	for i, rr := range in {
		c := dns.Copy(rr)
		if owner != "" {
			c.Header().Name = owner
		}
		out[i] = c
	}
	return out
}

func (z *zoneData) negativeSOA() dns.RR {
	soa := dns.Copy(z.soa).(*dns.SOA)
	if soa.Minttl < soa.Hdr.Ttl {
		soa.Hdr.Ttl = soa.Minttl
	}
	return soa
}

// authResult is what the zone lookup produced.
type authResult struct {
	msg        *dns.Msg
	cnameOut   string // CNAME target outside local zones that still needs resolving
	authorized bool
	referral   bool // msg is a referral to a delegated sub-zone
}

// answer resolves qname/qtype inside the local zones. It follows CNAMEs
// across local zones (8 hops max). When a CNAME leaves the local zones, the
// external target is returned in cnameOut for the forwarder.
//
// With minimalANY, a query of type ANY gets a single RRset (RFC 8482):
// the full set of a name is a large answer for a small query, the base of
// reflection attacks.
func (zs *zoneSet) answer(qname string, qtype uint16, minimalANY bool) authResult {
	m := new(dns.Msg)
	m.Authoritative = true
	name := strings.ToLower(qname)
	seen := map[string]bool{}
	for hop := 0; hop < 8; hop++ {
		z := zs.find(name)
		if z == nil {
			if hop == 0 {
				return authResult{}
			}
			return authResult{msg: m, cnameOut: name, authorized: true}
		}
		// Delegation below the apex: referral, not authoritative.
		if ref := z.referral(name, qtype); ref != nil {
			if hop == 0 {
				ref.Authoritative = false
				return authResult{msg: ref, authorized: true, referral: true}
			}
			return authResult{msg: m, cnameOut: name, authorized: true}
		}
		owner := name
		sets, ok := z.rrs[name]
		if !ok && !z.names[name] {
			// Wildcard: "*.<closest encloser>".
			if w, wok := z.wildcard(name); wok {
				sets, ok = w, true
			}
		}
		if !ok {
			if z.names[name] {
				m.Ns = append(m.Ns, z.negativeSOA())
				return authResult{msg: m, authorized: true}
			}
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, z.negativeSOA())
			return authResult{msg: m, authorized: true}
		}
		if qtype == dns.TypeANY {
			if minimalANY {
				// The RRset of the lowest type (deterministic).
				var best uint16
				for t, s := range sets {
					if len(s) > 0 && (best == 0 || t < best) {
						best = t
					}
				}
				m.Answer = append(m.Answer, copyRRs(sets[best], owner)...)
				return authResult{msg: m, authorized: true}
			}
			for _, s := range sets {
				m.Answer = append(m.Answer, copyRRs(s, owner)...)
			}
			return authResult{msg: m, authorized: true}
		}
		if s := sets[qtype]; len(s) > 0 {
			m.Answer = append(m.Answer, copyRRs(s, owner)...)
			return authResult{msg: m, authorized: true}
		}
		if c := sets[dns.TypeCNAME]; len(c) > 0 && qtype != dns.TypeCNAME {
			m.Answer = append(m.Answer, copyRRs(c, owner)...)
			target := strings.ToLower(c[0].(*dns.CNAME).Target)
			if seen[target] {
				return authResult{msg: m, authorized: true} // loop: stop here
			}
			seen[target] = true
			name = target
			continue
		}
		// NODATA.
		m.Ns = append(m.Ns, z.negativeSOA())
		return authResult{msg: m, authorized: true}
	}
	return authResult{msg: m, authorized: true}
}

func (z *zoneData) wildcard(name string) (map[uint16][]dns.RR, bool) {
	for n := name; n != z.name; {
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return nil, false
		}
		parent := n[i+1:]
		if z.names[parent] || parent == z.name {
			sets, ok := z.rrs["*."+parent]
			return sets, ok
		}
		n = parent
	}
	return nil, false
}

// referral returns a referral when name is at or below a delegation point.
func (z *zoneData) referral(name string, qtype uint16) *dns.Msg {
	for n := name; n != z.name; {
		// The DS set of a delegation lives in the parent zone.
		if ns := z.rrs[n][dns.TypeNS]; len(ns) > 0 && !(n == name && qtype == dns.TypeDS) {
			m := new(dns.Msg)
			m.Ns = copyRRs(ns, "")
			for _, rr := range ns {
				host := strings.ToLower(rr.(*dns.NS).Ns)
				if dns.IsSubDomain(z.name, host) {
					m.Extra = append(m.Extra, copyRRs(z.rrs[host][dns.TypeA], "")...)
					m.Extra = append(m.Extra, copyRRs(z.rrs[host][dns.TypeAAAA], "")...)
				}
			}
			return m
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i == len(n)-1 {
			return nil
		}
		n = n[i+1:]
	}
	return nil
}

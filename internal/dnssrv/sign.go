package dnssrv

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnssec"
)

// Zone signing: each node signs the zones when it loads them, with the
// replicated keys. Signature validity windows are aligned on the UTC day so
// both nodes produce the same windows (and, with Ed25519, the very same
// signatures). Signatures are cached across reloads.

const (
	sigValidity = 15 * 24 * time.Hour
	nsec3Iter   = 0 // RFC 9276: no extra iterations, no salt
)

// signedZone holds the DNSSEC data of a signed zone.
type signedZone struct {
	nsec3 bool
	sigs  map[string]map[uint16][]dns.RR // owner -> covered type -> RRSIGs
	// NSEC chain, canonical order.
	nsecNames []string
	nsec      map[string]*dns.NSEC
	// NSEC3 chain, sorted hashes (base32hex upper case).
	n3hashes []string
	n3       map[string]*dns.NSEC3
	negTTL   uint32
}

// sigCache keeps signatures across reloads (key: signer, window, RRset).
type sigCache struct {
	mu        sync.Mutex
	cur, next map[string][]dns.RR
}

func newSigCache() *sigCache {
	return &sigCache{cur: map[string][]dns.RR{}, next: map[string][]dns.RR{}}
}

func (c *sigCache) begin() {
	c.mu.Lock()
	c.next = map[string][]dns.RR{}
	c.mu.Unlock()
}

// end keeps only the signatures used by the last build.
func (c *sigCache) end() {
	c.mu.Lock()
	c.cur, c.next = c.next, map[string][]dns.RR{}
	c.mu.Unlock()
}

func (c *sigCache) get(key string) []dns.RR {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.cur[key]
	if !ok {
		v, ok = c.next[key]
	}
	if ok {
		c.next[key] = v
	}
	return v
}

func (c *sigCache) put(key string, v []dns.RR) {
	c.mu.Lock()
	c.next[key] = v
	c.mu.Unlock()
}

// sigWindow returns the inception and expiration used at now.
func sigWindow(now time.Time) (uint32, uint32) {
	day := now.UTC().Truncate(24 * time.Hour)
	return uint32(day.Add(-time.Hour).Unix()), uint32(day.Add(sigValidity).Unix())
}

// canonicalCompare orders names as RFC 4034 §6.1 (labels from the right,
// case-insensitive, byte-wise).
func canonicalCompare(a, b string) int {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func parentName(n string) string {
	i := strings.IndexByte(n, '.')
	if i < 0 || i == len(n)-1 {
		return "."
	}
	return n[i+1:]
}

// delegations returns the delegation points of the zone.
func (z *zoneData) delegations() map[string]bool {
	d := map[string]bool{}
	for owner, sets := range z.rrs {
		if owner != z.name && len(sets[dns.TypeNS]) > 0 {
			d[owner] = true
		}
	}
	return d
}

// occluded reports whether name is strictly below a delegation point.
func occluded(name, apex string, dels map[string]bool) bool {
	for n := parentName(name); n != apex && dns.IsSubDomain(apex, n); n = parentName(n) {
		if dels[n] {
			return true
		}
		if n == "." {
			break
		}
	}
	return false
}

// sign adds the DNSKEY (and NSEC3PARAM) sets, builds the denial chain and
// signs every authoritative RRset.
func (z *zoneData) sign(keys []*dnssec.Key, nsec3 bool, now time.Time, cache *sigCache) {
	var ksks, zsks []*dnssec.Key
	for _, k := range keys {
		if k.Signer == nil {
			continue
		}
		dk := dns.Copy(k.DNSKEY).(*dns.DNSKEY)
		dk.Hdr.Name, dk.Hdr.Ttl = z.name, dnssec.DNSKEYTTL
		z.add(dk)
		switch {
		case k.Role == dnssec.KSK:
			ksks = append(ksks, k) // every KSK signs the key set (double signature)
		case k.State == dnssec.StateActive:
			zsks = append(zsks, k)
		}
	}
	if len(ksks) == 0 && len(zsks) == 0 {
		return
	}
	if len(zsks) == 0 {
		zsks = ksks
	}
	if len(ksks) == 0 {
		ksks = zsks
	}
	sz := &signedZone{nsec3: nsec3, sigs: map[string]map[uint16][]dns.RR{}}
	sz.negTTL = min(z.soa.Minttl, z.soa.Hdr.Ttl)
	if nsec3 {
		z.add(&dns.NSEC3PARAM{Hdr: dns.RR_Header{Name: z.name, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
			Hash: dns.SHA1, Iterations: nsec3Iter})
	}
	dels := z.delegations()
	var auth []string // authoritative owners
	for owner := range z.rrs {
		if !occluded(owner, z.name, dels) {
			auth = append(auth, owner)
		}
	}
	slices.SortFunc(auth, canonicalCompare)

	inc, exp := sigWindow(now)
	signSet := func(owner string, t uint16, set []dns.RR, signers []*dnssec.Key) {
		// Same TTL across the set (RFC 2181 §5.2).
		ttl := set[0].Header().Ttl
		for _, rr := range set {
			ttl = min(ttl, rr.Header().Ttl)
		}
		for _, rr := range set {
			rr.Header().Ttl = ttl
		}
		var sb strings.Builder
		for _, rr := range set {
			sb.WriteString(rr.String())
			sb.WriteByte('\n')
		}
		h := sha256.Sum256([]byte(sb.String()))
		var out []dns.RR
		for _, k := range signers {
			key := strings.Join([]string{k.ID, hex.EncodeToString(h[:]), itoa(inc), itoa(exp)}, "|")
			if c := cache.get(key); c != nil {
				out = append(out, c...)
				continue
			}
			sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
				Algorithm: k.Algorithm, KeyTag: k.KeyTag, SignerName: z.name, Inception: inc, Expiration: exp}
			if err := sig.Sign(k.Signer, set); err != nil {
				continue
			}
			cache.put(key, []dns.RR{sig})
			out = append(out, sig)
		}
		if sz.sigs[owner] == nil {
			sz.sigs[owner] = map[uint16][]dns.RR{}
		}
		sz.sigs[owner][t] = out
	}

	// Denial chain.
	if !nsec3 {
		sz.nsec = map[string]*dns.NSEC{}
		for i, owner := range auth {
			types := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
			for t := range z.rrs[owner] {
				types = append(types, t)
			}
			slices.Sort(types)
			n := &dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: sz.negTTL},
				NextDomain: auth[(i+1)%len(auth)], TypeBitMap: types}
			sz.nsec[owner] = n
		}
		sz.nsecNames = auth
	} else {
		sz.n3 = map[string]*dns.NSEC3{}
		names := map[string]bool{}
		for _, owner := range auth {
			names[owner] = true
		}
		for n := range z.names { // empty non-terminals
			if !occluded(n, z.name, dels) {
				names[n] = true
			}
		}
		hashOwner := map[string]string{}
		for n := range names {
			h := dns.HashName(n, dns.SHA1, nsec3Iter, "")
			hashOwner[h] = n
			sz.n3hashes = append(sz.n3hashes, h)
		}
		sort.Strings(sz.n3hashes)
		for i, h := range sz.n3hashes {
			n := hashOwner[h]
			var types []uint16
			signed := false
			for t := range z.rrs[n] {
				types = append(types, t)
				if !dels[n] || t == dns.TypeDS {
					signed = true
				}
			}
			if signed {
				types = append(types, dns.TypeRRSIG)
			}
			slices.Sort(types)
			sz.n3[h] = &dns.NSEC3{Hdr: dns.RR_Header{Name: strings.ToLower(h) + "." + z.name, Rrtype: dns.TypeNSEC3,
				Class: dns.ClassINET, Ttl: sz.negTTL}, Hash: dns.SHA1, Iterations: nsec3Iter, HashLength: 20,
				NextDomain: sz.n3hashes[(i+1)%len(sz.n3hashes)], TypeBitMap: types}
		}
	}

	// Signatures.
	for _, owner := range auth {
		for t, set := range z.rrs[owner] {
			if dels[owner] && t != dns.TypeDS {
				continue // NS of a delegation (and glue) are not signed
			}
			signers := zsks
			if t == dns.TypeDNSKEY {
				signers = ksks
			}
			signSet(owner, t, set, signers)
		}
	}
	for owner, n := range sz.nsec {
		signSet(owner, dns.TypeNSEC, []dns.RR{n}, zsks)
	}
	for _, n := range sz.n3 {
		signSet(n.Hdr.Name, dns.TypeNSEC3, []dns.RR{n}, zsks)
	}
	z.sec = sz
}

func itoa(v uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	return string(b[i:])
}

// ---- proofs ----

func (sz *signedZone) nsecFor(name string) (*dns.NSEC, bool) {
	if n, ok := sz.nsec[name]; ok {
		return n, true
	}
	i := sort.Search(len(sz.nsecNames), func(i int) bool { return canonicalCompare(sz.nsecNames[i], name) > 0 })
	if i == 0 {
		i = len(sz.nsecNames)
	}
	return sz.nsec[sz.nsecNames[i-1]], false
}

func (sz *signedZone) nsec3For(name string) (*dns.NSEC3, bool) {
	h := dns.HashName(name, dns.SHA1, nsec3Iter, "")
	if n, ok := sz.n3[h]; ok {
		return n, true
	}
	i := sort.SearchStrings(sz.n3hashes, h)
	if i == 0 {
		i = len(sz.n3hashes)
	}
	return sz.n3[sz.n3hashes[i-1]], false
}

// closestEncloser returns the longest existing ancestor of name and the
// "next closer" name (one label longer, towards name).
func (z *zoneData) closestEncloser(name string) (ce, next string) {
	next = name
	for n := parentName(name); ; n = parentName(n) {
		if z.names[n] || n == z.name {
			return n, next
		}
		next = n
		if n == "." {
			return z.name, next
		}
	}
}

// wildcardOwner returns the wildcard that synthesizes name, if any.
func (z *zoneData) wildcardOwner(name string) string {
	ce, _ := z.closestEncloser(name)
	w := "*." + ce
	if _, ok := z.rrs[w]; ok {
		return w
	}
	return ""
}

// proof collects the DNSSEC records added to a response.
type proof struct {
	z    *zoneData
	seen map[string]bool
	ns   []dns.RR
}

func (p *proof) add(rr dns.RR) {
	if rr == nil {
		return
	}
	k := rr.Header().Name + "/" + dns.TypeToString[rr.Header().Rrtype]
	if p.seen[k] {
		return
	}
	p.seen[k] = true
	p.ns = append(p.ns, dns.Copy(rr))
	p.ns = append(p.ns, copyRRs(p.z.sec.sigs[rr.Header().Name][rr.Header().Rrtype], "")...)
}

// denial adds the records proving that name (or a wildcard for it) does not
// exist, or that name has no record of the asked type.
func (p *proof) denial(name string, nxdomain bool) {
	z, sz := p.z, p.z.sec
	ce, next := z.closestEncloser(name)
	exists := z.names[name]
	w := ""
	if !exists && !nxdomain {
		w = z.wildcardOwner(name)
	}
	if !sz.nsec3 {
		switch {
		case exists:
			n, _ := sz.nsecFor(name) // match, or covering for an empty non-terminal
			p.add(n)
		case nxdomain:
			n, _ := sz.nsecFor(name)
			p.add(n)
			n, _ = sz.nsecFor("*." + ce)
			p.add(n)
		default: // NODATA through a wildcard
			n, _ := sz.nsecFor(name)
			p.add(n)
			n, _ = sz.nsecFor(w)
			p.add(n)
		}
		return
	}
	switch {
	case exists:
		n, _ := sz.nsec3For(name)
		p.add(n)
	case nxdomain:
		n, _ := sz.nsec3For(ce)
		p.add(n)
		n, _ = sz.nsec3For(next)
		p.add(n)
		n, _ = sz.nsec3For("*." + ce)
		p.add(n)
	default:
		n, _ := sz.nsec3For(ce)
		p.add(n)
		n, _ = sz.nsec3For(next)
		p.add(n)
		n, _ = sz.nsec3For(w)
		p.add(n)
	}
}

// addDNSSEC adds signatures and denial proofs to a response built from the
// local zones (client asked with the DO bit).
func (zs *zoneSet) addDNSSEC(m *dns.Msg, qname string, qtype uint16) {
	proofs := map[*zoneData]*proof{}
	get := func(name string) *proof {
		z := zs.find(name)
		if z == nil || z.sec == nil {
			return nil
		}
		if p := proofs[z]; p != nil {
			return p
		}
		p := &proof{z: z, seen: map[string]bool{}}
		proofs[z] = p
		return p
	}

	// Answer RRsets.
	cur := strings.ToLower(qname)
	type key struct {
		owner string
		t     uint16
	}
	done := map[key]bool{}
	var extra []dns.RR
	for _, rr := range m.Answer {
		h := rr.Header()
		k := key{strings.ToLower(h.Name), h.Rrtype}
		if h.Rrtype == dns.TypeCNAME && k.owner == cur {
			cur = strings.ToLower(rr.(*dns.CNAME).Target)
		}
		if done[k] {
			continue
		}
		done[k] = true
		p := get(k.owner)
		if p == nil {
			continue
		}
		if sigs := p.z.sec.sigs[k.owner][k.t]; len(sigs) > 0 {
			extra = append(extra, copyRRs(sigs, "")...)
			continue
		}
		if w := p.z.wildcardOwner(k.owner); w != "" {
			// Synthesized from a wildcard: its signatures, plus proof that
			// the exact name does not exist.
			extra = append(extra, copyRRs(p.z.sec.sigs[w][k.t], k.owner)...)
			if p.z.sec.nsec3 {
				_, next := p.z.closestEncloser(k.owner)
				n, _ := p.z.sec.nsec3For(next)
				p.add(n)
			} else {
				n, _ := p.z.sec.nsecFor(k.owner)
				p.add(n)
			}
		}
	}
	m.Answer = append(m.Answer, extra...)

	// Referral: DS set, or proof that there is none.
	if !m.Authoritative {
		for _, rr := range m.Ns {
			if rr.Header().Rrtype != dns.TypeNS {
				continue
			}
			d := strings.ToLower(rr.Header().Name)
			p := get(d)
			if p == nil {
				break
			}
			if ds := p.z.rrs[d][dns.TypeDS]; len(ds) > 0 {
				p.ns = append(p.ns, copyRRs(ds, "")...)
				p.ns = append(p.ns, copyRRs(p.z.sec.sigs[d][dns.TypeDS], "")...)
			} else if p.z.sec.nsec3 {
				n, _ := p.z.sec.nsec3For(d)
				p.add(n)
			} else {
				n, _ := p.z.sec.nsecFor(d)
				p.add(n)
			}
			break
		}
	} else {
		// Negative answer: signed SOA and denial.
		hasSOA := false
		for _, rr := range m.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				hasSOA = true
			}
		}
		answered := false
		for _, rr := range m.Answer {
			if strings.EqualFold(rr.Header().Name, cur) && (rr.Header().Rrtype == qtype || qtype == dns.TypeANY) {
				answered = true
			}
		}
		if hasSOA && !answered {
			if p := get(cur); p != nil {
				p.ns = append(p.ns, copyRRs(p.z.sec.sigs[p.z.name][dns.TypeSOA], "")...)
				p.denial(cur, m.Rcode == dns.RcodeNameError)
			}
		}
	}
	for _, p := range proofs {
		m.Ns = append(m.Ns, p.ns...)
	}
}

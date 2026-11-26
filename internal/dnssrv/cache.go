package dnssrv

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// cache is an LRU of upstream answers with TTL clamping and negative caching
// (RFC 2308).
type cache struct {
	mu     sync.Mutex
	max    int
	minTTL uint32
	maxTTL uint32
	negMax uint32
	ll     *list.List
	items  map[string]*list.Element
	now    func() time.Time
	hits   atomic.Uint64
	misses atomic.Uint64
}

type cacheEntry struct {
	key     string
	qname   string
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

func newCache() *cache {
	return &cache{ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *cache) configure(max int, minTTL, maxTTL, negMax uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max, c.minTTL, c.maxTTL, c.negMax = max, minTTL, maxTTL, negMax
	for c.ll.Len() > c.max {
		c.removeOldest()
	}
}

func cacheKey(q dns.Question, do bool) string {
	// Numeric type and class: the mnemonic is "" for unknown types.
	k := strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" + strconv.Itoa(int(q.Qclass))
	if do {
		k += "|do"
	}
	return k
}

func (c *cache) clamp(ttl uint32) uint32 {
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	return ttl
}

// ttlOf computes how long a response may be cached; ok=false: do not cache.
func (c *cache) ttlOf(m *dns.Msg) (uint32, bool) {
	if m.Truncated {
		return 0, false
	}
	switch m.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return 0, false
	}
	if m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
		ttl := ^uint32(0)
		for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Ns...) {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
		return c.clamp(ttl), true
	}
	// Negative answer: TTL from the SOA in the authority section.
	neg := uint32(30)
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			neg = soa.Hdr.Ttl
			if soa.Minttl < neg {
				neg = soa.Minttl
			}
		}
	}
	if neg > c.negMax {
		neg = c.negMax
	}
	return neg, neg > 0
}

func (c *cache) set(q dns.Question, do bool, m *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max <= 0 {
		return
	}
	ttl, ok := c.ttlOf(m)
	if !ok {
		return
	}
	now := c.now()
	key := cacheKey(q, do)
	e := &cacheEntry{key: key, qname: strings.ToLower(q.Name), msg: m.Copy(), stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
	if el, ok := c.items[key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(e)
	for c.ll.Len() > c.max {
		c.removeOldest()
	}
}

// get returns a copy of the cached answer with decremented TTLs.
func (c *cache) get(q dns.Question, do bool) *dns.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[cacheKey(q, do)]
	if !ok {
		c.misses.Add(1)
		return nil
	}
	e := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(e.expires) {
		c.ll.Remove(el)
		delete(c.items, e.key)
		c.misses.Add(1)
		return nil
	}
	c.ll.MoveToFront(el)
	c.hits.Add(1)
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	remaining := uint32(e.expires.Sub(now) / time.Second)
	m := e.msg.Copy()
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := c.clamp(rr.Header().Ttl)
			if ttl > elapsed {
				ttl -= elapsed
			} else {
				ttl = 0
			}
			if ttl > remaining+1 {
				ttl = remaining + 1
			}
			rr.Header().Ttl = ttl
		}
	}
	return m
}

func (c *cache) removeOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*cacheEntry).key)
}

// flush removes everything (name == "") or name and its sub-names.
func (c *cache) flush(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name == "" {
		n := c.ll.Len()
		c.ll.Init()
		c.items = map[string]*list.Element{}
		return n
	}
	name = strings.ToLower(dns.Fqdn(name))
	n := 0
	for k, el := range c.items {
		q := el.Value.(*cacheEntry).qname
		if q == name || strings.HasSuffix(q, "."+name) {
			c.ll.Remove(el)
			delete(c.items, k)
			n++
		}
	}
	return n
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

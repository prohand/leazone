package blocking

import (
	"hash/maphash"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hashSet is a compact set of domains: sorted 64-bit hashes (10 bytes per
// entry with the list index), so a million domains take about 10 MB.
type hashSet struct {
	keys []uint64
	vals []uint16
}

var seed = maphash.MakeSeed()

func hashOf(s string) uint64 { return maphash.String(seed, s) }

type pair struct {
	k uint64
	v uint16
}

func buildSet(ps []pair) hashSet {
	// Stable: on duplicates the first list wins.
	slices.SortStableFunc(ps, func(a, b pair) int {
		switch {
		case a.k < b.k:
			return -1
		case a.k > b.k:
			return 1
		}
		return 0
	})
	h := hashSet{keys: make([]uint64, 0, len(ps)), vals: make([]uint16, 0, len(ps))}
	for i, p := range ps {
		if i > 0 && ps[i-1].k == p.k {
			continue
		}
		h.keys = append(h.keys, p.k)
		h.vals = append(h.vals, p.v)
	}
	return h
}

func (h *hashSet) get(s string) (uint16, bool) {
	k := hashOf(s)
	i, ok := slices.BinarySearch(h.keys, k)
	if !ok {
		return 0, false
	}
	return h.vals[i], true
}

// IfInfo describes the interface a local DNS address belongs to.
type IfInfo struct {
	Name string
	VLAN int
}

type netPolicy struct {
	prefix  netip.Prefix
	enabled bool
}

// snapshot is the immutable blocking configuration.
type snapshot struct {
	deny, allow hashSet
	manualDeny  map[string]bool
	manualAllow map[string]bool
	listNames   []string
	lists       int
	domains     int
	nets        []netPolicy // most specific first
	vlans       map[int]bool
	ifaces      map[string]bool
	settings    Settings
}

// Engine decides whether a name is blocked. It is safe for concurrent use.
type Engine struct {
	enabled atomic.Bool
	snap    atomic.Pointer[snapshot]
	paused  atomic.Int64 // unix ms
	locals  atomic.Pointer[map[netip.Addr]IfInfo]
	Now     func() time.Time

	queries, blocked atomic.Uint64
	topMu            sync.Mutex
	top              map[string]uint64
}

// NewEngine returns a disabled engine.
func NewEngine() *Engine {
	e := &Engine{Now: time.Now, top: map[string]uint64{}}
	e.snap.Store(&snapshot{settings: DefaultSettings()})
	return e
}

// SetLocals maps the server's own addresses to their interface (for
// interface and VLAN policies).
func (e *Engine) SetLocals(m map[netip.Addr]IfInfo) { e.locals.Store(&m) }

// Enabled reports whether the module is on.
func (e *Engine) Enabled() bool { return e.enabled.Load() }

// PausedUntil returns the end of the pause (zero = not paused).
func (e *Engine) PausedUntil() time.Time {
	ms := e.paused.Load()
	if ms == 0 || e.Now().UnixMilli() >= ms {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func (e *Engine) setPause(t time.Time) {
	if t.IsZero() {
		e.paused.Store(0)
	} else {
		e.paused.Store(t.UnixMilli())
	}
}

// active tells whether blocking applies to a client reaching us on local.
func (e *Engine) active(s *snapshot, client, local netip.Addr) bool {
	for _, n := range s.nets {
		if n.prefix.Contains(client) {
			return n.enabled
		}
	}
	if lp := e.locals.Load(); lp != nil {
		if inf, ok := (*lp)[local]; ok {
			if inf.VLAN > 0 {
				if v, ok := s.vlans[inf.VLAN]; ok {
					return v
				}
			}
			if v, ok := s.ifaces[inf.Name]; ok {
				return v
			}
		}
	}
	return s.settings.DefaultEnabled
}

// Decision explains a check.
type Decision struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
	Matched string `json:"matched"`
}

// suffixes calls f for name and each parent ("a.b.c", "b.c", "c") until f
// returns true.
func suffixes(name string, f func(string) bool) bool {
	for n := name; n != ""; {
		if f(n) {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
	return false
}

// decide applies the rules in this order: manual whitelist (always wins),
// manual blacklist, list exceptions (AdBlock "@@": they override the list
// filters), list filters. Each step looks at the name and its parents.
func (s *snapshot) decide(name string) Decision {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var d Decision
	if suffixes(name, func(n string) bool {
		if s.manualAllow[n] {
			d = Decision{Reason: "liste blanche", Matched: n}
			return true
		}
		return false
	}) {
		return d
	}
	if suffixes(name, func(n string) bool {
		if s.manualDeny[n] {
			d = Decision{Blocked: true, Reason: "liste noire", Matched: n}
			return true
		}
		return false
	}) {
		return d
	}
	if suffixes(name, func(n string) bool {
		if i, ok := s.allow.get(n); ok {
			d = Decision{Reason: "exception de la liste « " + s.listName(i) + " »", Matched: n}
			return true
		}
		return false
	}) {
		return d
	}
	suffixes(name, func(n string) bool {
		if i, ok := s.deny.get(n); ok {
			d = Decision{Blocked: true, Reason: "liste « " + s.listName(i) + " »", Matched: n}
			return true
		}
		return false
	})
	return d
}

func (s *snapshot) listName(i uint16) string {
	if int(i) < len(s.listNames) {
		return s.listNames[i]
	}
	return "?"
}

// Filter is called by the DNS server for each recursive query (and for
// CNAME targets of forwarded answers, with count=false). It returns whether
// to block and whether to answer with a null IP instead of NXDOMAIN.
func (e *Engine) Filter(name string, client, local netip.Addr, count bool) (blocked, nullIP bool) {
	if !e.enabled.Load() || !e.PausedUntil().IsZero() {
		return false, false
	}
	s := e.snap.Load()
	if !e.active(s, client, local) {
		return false, false
	}
	if count {
		e.queries.Add(1)
	}
	d := s.decide(name)
	if !d.Blocked {
		return false, false
	}
	e.blocked.Add(1)
	e.noteTop(d.Matched)
	return true, s.settings.ResponseMode == ModeNullIP
}

// Explain is the "test a domain" tool. client may be invalid (no policy).
func (e *Engine) Explain(name string, client netip.Addr) (Decision, bool) {
	s := e.snap.Load()
	policy := true
	if client.IsValid() {
		policy = e.active(s, client, netip.Addr{})
	}
	return s.decide(name), policy
}

const topMax = 5000

func (e *Engine) noteTop(d string) {
	e.topMu.Lock()
	defer e.topMu.Unlock()
	e.top[d]++
	if len(e.top) > topMax {
		// Drop the less blocked half.
		counts := make([]uint64, 0, len(e.top))
		for _, c := range e.top {
			counts = append(counts, c)
		}
		slices.Sort(counts)
		limit := counts[len(counts)/2]
		for k, c := range e.top {
			if c <= limit && k != d {
				delete(e.top, k)
			}
		}
	}
}

// TopEntry is one of the most blocked domains.
type TopEntry struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

// Status is reported to the UI.
type Status struct {
	Enabled     bool       `json:"enabled"`
	Paused      bool       `json:"paused"`
	PausedUntil *time.Time `json:"pausedUntil"`
	Domains     int        `json:"domains"`
	Lists       int        `json:"lists"`
	Queries     uint64     `json:"queries"`
	Blocked     uint64     `json:"blocked"`
	Percent     float64    `json:"percent"`
	Top         []TopEntry `json:"top"`
}

// Status returns the state and statistics of this node.
func (e *Engine) Status(n int) Status {
	s := e.snap.Load()
	st := Status{Enabled: e.enabled.Load(), Domains: s.domains, Lists: s.lists,
		Queries: e.queries.Load(), Blocked: e.blocked.Load(), Top: []TopEntry{}}
	if p := e.PausedUntil(); !p.IsZero() {
		p = p.UTC()
		st.Paused, st.PausedUntil = true, &p
	}
	if st.Queries > 0 {
		st.Percent = float64(int(float64(st.Blocked)/float64(st.Queries)*1000+0.5)) / 10
	}
	e.topMu.Lock()
	for d, c := range e.top {
		st.Top = append(st.Top, TopEntry{d, c})
	}
	e.topMu.Unlock()
	sort.Slice(st.Top, func(i, j int) bool {
		if st.Top[i].Count != st.Top[j].Count {
			return st.Top[i].Count > st.Top[j].Count
		}
		return st.Top[i].Domain < st.Top[j].Domain
	})
	if len(st.Top) > n {
		st.Top = st.Top[:n]
	}
	return st
}

// Config is what the manager loads into the engine.
type Config struct {
	Enabled  bool
	Settings Settings
	Pause    time.Time
	Lists    []NamedList
	Rules    []*Rule
	Policies []*Policy
}

// NamedList is a parsed list with its name.
type NamedList struct {
	Name string
	Parsed
}

// Load replaces the configuration.
func (e *Engine) Load(c Config) {
	e.setPause(c.Pause)
	s := &snapshot{settings: c.Settings, manualDeny: map[string]bool{}, manualAllow: map[string]bool{},
		vlans: map[int]bool{}, ifaces: map[string]bool{}}
	for _, r := range c.Rules {
		if r.Kind == "allow" {
			s.manualAllow[r.Domain] = true
		} else {
			s.manualDeny[r.Domain] = true
		}
	}
	for _, p := range c.Policies {
		switch p.TargetKind {
		case "network":
			if pf, err := netip.ParsePrefix(p.Target); err == nil {
				s.nets = append(s.nets, netPolicy{pf, p.Enabled})
			}
		case "vlan":
			if v, err := strconv.Atoi(p.Target); err == nil {
				s.vlans[v] = p.Enabled
			}
		case "interface":
			s.ifaces[p.Target] = p.Enabled
		}
	}
	sort.SliceStable(s.nets, func(i, j int) bool { return s.nets[i].prefix.Bits() > s.nets[j].prefix.Bits() })
	if c.Enabled {
		var deny, allow []pair
		for i, l := range c.Lists {
			if i > 65535 {
				break
			}
			s.listNames = append(s.listNames, l.Name)
			for _, d := range l.Deny {
				deny = append(deny, pair{hashOf(d), uint16(i)})
			}
			for _, d := range l.Allow {
				allow = append(allow, pair{hashOf(d), uint16(i)})
			}
		}
		s.deny, s.allow = buildSet(deny), buildSet(allow)
		s.lists = len(c.Lists)
		s.domains = len(s.deny.keys) + len(s.manualDeny)
	}
	e.snap.Store(s)
	e.enabled.Store(c.Enabled)
}

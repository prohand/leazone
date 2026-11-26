package dhcpsrv

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/store"
)

// Hooks are called after lease changes (DNS registration).
type Hooks interface {
	Bound(ctx context.Context, sc *dhcpconf.Scope, l Lease) (dnsName string)
	Ended(ctx context.Context, sc *dhcpconf.Scope, l Lease)
}

// Pinger checks whether an address answers before it is offered.
type Pinger interface {
	InUse(ctx context.Context, ip netip.Addr) bool
}

// scopeRT is a scope with its precomputed runtime data.
type scopeRT struct {
	*dhcpconf.Scope
	prefix   netip.Prefix
	start    uint32
	end      uint32
	gateway  netip.Addr
	byMAC    map[string]*dhcpconf.Reservation
	byCID    map[string]*dhcpconf.Reservation
	reserved map[uint32]*dhcpconf.Reservation
	cursor   uint32
}

// Engine holds the configuration snapshot and the leases.
type Engine struct {
	log    *slog.Logger
	db     leaseDB
	Hooks  Hooks
	Pinger Pinger
	Now    func() time.Time
	NodeID string

	// Owns reports whether this node may hand out a new address (HA: each
	// node only allocates its own share of the pool). Default: everything.
	Owns func(scopeID string, ip uint32) bool

	mu      sync.Mutex
	scopes  map[string]*scopeRT
	ifaces  map[int]netif.Interface // by index
	dhcpOn  map[string]bool         // interface name -> DHCP enabled
	leases  map[string]map[uint32]*Lease
	pending map[string]map[uint32]bool // addresses being ping-checked
}

// Offer hold time: an offered address stays reserved for the client.
const offerHold = 60 * time.Second

// declineHold keeps an address flagged as in use after a conflict.
const declineHold = time.Hour

// NewEngine loads the leases from the database.
func NewEngine(ctx context.Context, db *store.DB, log *slog.Logger) (*Engine, error) {
	e := &Engine{log: log, db: leaseDB{db: db}, Now: time.Now, scopes: map[string]*scopeRT{},
		ifaces: map[int]netif.Interface{}, dhcpOn: map[string]bool{}, pending: map[string]map[uint32]bool{},
		Owns: func(string, uint32) bool { return true }}
	var err error
	if e.leases, err = e.db.load(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// SetConfig replaces scopes and reservations.
func (e *Engine) SetConfig(scopes []*dhcpconf.Scope, res []*dhcpconf.Reservation) {
	rt := map[string]*scopeRT{}
	for _, sc := range scopes {
		s := &scopeRT{Scope: sc, prefix: sc.Prefix(), byMAC: map[string]*dhcpconf.Reservation{},
			byCID: map[string]*dhcpconf.Reservation{}, reserved: map[uint32]*dhcpconf.Reservation{}}
		a, _ := netip.ParseAddr(sc.RangeStart)
		b, _ := netip.ParseAddr(sc.RangeEnd)
		s.start, s.end = dhcpconf.U32(a), dhcpconf.U32(b)
		s.gateway, _ = netip.ParseAddr(sc.Gateway)
		rt[sc.ID] = s
	}
	for _, r := range res {
		s := rt[r.ScopeID]
		if s == nil {
			continue
		}
		a, _ := netip.ParseAddr(r.IP)
		s.reserved[dhcpconf.U32(a)] = r
		if r.MAC != "" {
			s.byMAC[r.MAC] = r
		}
		if r.ClientID != "" {
			s.byCID[r.ClientID] = r
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, s := range rt {
		if old := e.scopes[id]; old != nil {
			s.cursor = old.cursor
		}
	}
	e.scopes = rt
}

// SetInterfaces replaces the interface snapshot and the DHCP-enabled set.
func (e *Engine) SetInterfaces(list []netif.Interface, enabled map[string]bool) {
	m := map[int]netif.Interface{}
	for _, it := range list {
		m[it.Index] = it
	}
	e.mu.Lock()
	e.ifaces, e.dhcpOn = m, enabled
	e.mu.Unlock()
}

// EnabledInterfaces lists interface names with DHCP enabled.
func (e *Engine) EnabledInterfaces() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for n, on := range e.dhcpOn {
		if on {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// HasActiveScopes tells whether the socket needs to be open.
func (e *Engine) HasActiveScopes() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.scopes {
		if s.Enabled && s.Mode() != "none" {
			return true
		}
	}
	return false
}

// lease helpers (e.mu held)

func (e *Engine) leaseAt(scopeID string, ip uint32) *Lease {
	return e.leases[scopeID][ip]
}

func (e *Engine) clientLease(scopeID, mac, cid string) *Lease {
	var best *Lease
	for _, l := range e.leases[scopeID] {
		if l.State == StateDeclined || !l.sameClient(mac, cid) {
			continue
		}
		if best == nil || l.Ends.After(best.Ends) {
			best = l
		}
	}
	return best
}

func (e *Engine) store(ctx context.Context, l *Lease) {
	if e.leases[l.ScopeID] == nil {
		e.leases[l.ScopeID] = map[uint32]*Lease{}
	}
	l.Owner = e.NodeID
	l.HLC = e.Now().UnixMilli()
	e.leases[l.ScopeID][dhcpconf.U32(l.IP)] = l
	if err := e.db.put(ctx, l); err != nil {
		e.log.Error("lease persist failed", "ip", l.IP, "err", err)
	}
}

// usable reports whether ip may be given to the client (e.mu held).
func (e *Engine) usable(s *scopeRT, ip uint32, mac, cid string, now time.Time) bool {
	a := dhcpconf.FromU32(ip)
	if ip < s.start || ip > s.end || s.Excluded(a) || a == s.gateway {
		return false
	}
	if r := s.reserved[ip]; r != nil && !reservationMatches(r, mac, cid) {
		return false
	}
	if e.pending[s.ID][ip] {
		return false
	}
	if l := e.leaseAt(s.ID, ip); l != nil && l.Active(now) && !l.sameClient(mac, cid) {
		return false
	}
	return true
}

func reservationMatches(r *dhcpconf.Reservation, mac, cid string) bool {
	return (r.MAC != "" && r.MAC == mac) || (r.ClientID != "" && r.ClientID == cid)
}

func (s *scopeRT) reservationFor(mac, cid string) *dhcpconf.Reservation {
	if cid != "" {
		if r := s.byCID[cid]; r != nil {
			return r
		}
	}
	return s.byMAC[mac]
}

// pick chooses an address for a client (e.mu held). It returns false when
// the pool is full. Preference: reservation, current lease, requested
// address, never-used address, then the oldest free lease of someone else.
func (e *Engine) pick(s *scopeRT, mac, cid string, requested netip.Addr, now time.Time, skip map[uint32]bool) (netip.Addr, bool) {
	if r := s.reservationFor(mac, cid); r != nil {
		a, _ := netip.ParseAddr(r.IP)
		if l := e.leaseAt(s.ID, dhcpconf.U32(a)); l != nil && l.Active(now) && !l.sameClient(mac, cid) {
			e.log.Warn("reserved address in use by another client", "ip", a, "reservedFor", mac)
			return netip.Addr{}, false
		}
		return a, true
	}
	if l := e.clientLease(s.ID, mac, cid); l != nil {
		ip := dhcpconf.U32(l.IP)
		if !skip[ip] && e.usable(s, ip, mac, cid, now) {
			return l.IP, true
		}
	}
	if requested.Is4() && s.prefix.Contains(requested) {
		ip := dhcpconf.U32(requested)
		if !skip[ip] && e.usable(s, ip, mac, cid, now) && e.Owns(s.ID, ip) {
			if l := e.leaseAt(s.ID, ip); l == nil || l.sameClient(mac, cid) {
				return requested, true
			}
		}
	}
	size := s.end - s.start + 1
	var fallback *Lease
	for i := uint32(0); i < size; i++ {
		ip := s.start + (s.cursor+i)%size
		if skip[ip] || !e.usable(s, ip, mac, cid, now) || !e.Owns(s.ID, ip) {
			continue
		}
		l := e.leaseAt(s.ID, ip)
		if l == nil {
			s.cursor = (ip - s.start + 1) % size
			return dhcpconf.FromU32(ip), true
		}
		if fallback == nil || l.Ends.Before(fallback.Ends) {
			fallback = l
		}
	}
	if fallback != nil {
		return fallback.IP, true
	}
	return netip.Addr{}, false
}

// Usage is the fill level of a scope.
type Usage struct {
	Size, Used, Active int
}

// Usage computes the fill level of every scope.
func (e *Engine) Usage() map[string]Usage {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	out := map[string]Usage{}
	for id, s := range e.scopes {
		u := Usage{}
		for ip := s.start; ip <= s.end; ip++ { // s.end is never 255.255.255.255 (broadcast excluded)
			a := dhcpconf.FromU32(ip)
			if s.Excluded(a) || a == s.gateway {
				continue
			}
			u.Size++
			l := e.leaseAt(id, ip)
			switch {
			case l != nil && l.Active(now):
				u.Used++
				if l.State == StateBound {
					u.Active++
				}
			case s.reserved[ip] != nil:
				u.Used++
			}
		}
		out[id] = u
	}
	return out
}

// Leases returns a copy of all known leases.
func (e *Engine) Leases() []Lease {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Lease
	for _, m := range e.leases {
		for _, l := range m {
			out = append(out, *l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].IP.Less(out[j].IP)
	})
	return out
}

// Release frees a lease from the UI. The client gets a NAK at renewal.
func (e *Engine) Release(ctx context.Context, scopeID string, ip netip.Addr) (Lease, error) {
	e.mu.Lock()
	l := e.leaseAt(scopeID, dhcpconf.U32(ip))
	if l == nil {
		e.mu.Unlock()
		return Lease{}, store.ErrNotFound
	}
	sc := e.scopes[scopeID]
	was := *l
	nl := *l
	nl.State, nl.Ends, nl.DNSName = StateReleased, e.Now(), ""
	e.store(ctx, &nl)
	e.mu.Unlock()
	if sc != nil && e.Hooks != nil && was.State == StateBound {
		e.Hooks.Ended(ctx, sc.Scope, was)
	}
	return nl, nil
}

// Sweep expires leases whose time is over and forgets old history.
func (e *Engine) Sweep(ctx context.Context) {
	now := e.Now()
	type ended struct {
		sc *dhcpconf.Scope
		l  Lease
	}
	var done []ended
	e.mu.Lock()
	for scopeID, m := range e.leases {
		sc := e.scopes[scopeID]
		for ip, l := range m {
			switch {
			case (l.State == StateBound || l.State == StateOffered) && !now.Before(l.Ends):
				was := *l
				nl := *l
				nl.State, nl.DNSName = StateExpired, ""
				e.store(ctx, &nl)
				if was.State == StateBound && sc != nil {
					done = append(done, ended{sc.Scope, was})
				}
			case (l.State == StateExpired || l.State == StateReleased || l.State == StateDeclined) && now.Sub(l.Ends) > 30*24*time.Hour:
				delete(m, ip)
				_ = e.db.delete(ctx, scopeID, l.IP)
			}
		}
	}
	e.mu.Unlock()
	if e.Hooks != nil {
		for _, d := range done {
			e.Hooks.Ended(ctx, d.sc, d.l)
		}
	}
}

// Scope returns the runtime scope (for the API).
func (e *Engine) Scope(id string) *dhcpconf.Scope {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.scopes[id]; s != nil {
		return s.Scope
	}
	return nil
}

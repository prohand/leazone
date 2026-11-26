//go:build linux

// Package netif discovers the host network interfaces (physical, 802.1Q
// VLAN, bonds, bridges) through netlink and reports changes at runtime, so
// a VLAN added on the host is picked up without restarting Leazone.
// Leazone never creates or changes interfaces itself.
package netif

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Interface types reported to the UI.
const (
	TypePhysical = "physical"
	TypeVLAN     = "vlan"
	TypeBond     = "bond"
	TypeBridge   = "bridge"
	TypeLoopback = "loopback"
	TypeVirtual  = "virtual"
	TypeOther    = "other"
)

// Address is one IP configured on an interface.
type Address struct {
	Prefix netip.Prefix // address with its prefix length (not masked)
}

// Interface is a snapshot of one host interface.
type Interface struct {
	Name      string
	Index     int
	Type      string
	Parent    string // VLAN parent or bond/bridge master
	VLANID    int    // 0 when not a VLAN
	MAC       string
	MTU       int
	Up        bool
	Addresses []Address
}

// IPv4 returns the IPv4 addresses of the interface.
func (i Interface) IPv4() []netip.Addr {
	var out []netip.Addr
	for _, a := range i.Addresses {
		if a.Prefix.Addr().Is4() {
			out = append(out, a.Prefix.Addr())
		}
	}
	return out
}

// List returns the current interfaces sorted by name.
func List() ([]Interface, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	byIndex := map[int]string{}
	for _, l := range links {
		byIndex[l.Attrs().Index] = l.Attrs().Name
	}
	out := make([]Interface, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		it := Interface{Name: a.Name, Index: a.Index, MTU: a.MTU, Up: a.Flags&net.FlagUp != 0 && a.OperState != netlink.OperDown}
		if a.HardwareAddr != nil {
			it.MAC = a.HardwareAddr.String()
		}
		switch v := l.(type) {
		case *netlink.Vlan:
			it.Type, it.VLANID = TypeVLAN, v.VlanId
			it.Parent = byIndex[a.ParentIndex]
		case *netlink.Bond:
			it.Type = TypeBond
		case *netlink.Bridge:
			it.Type = TypeBridge
		case *netlink.Device:
			if a.Flags&net.FlagLoopback != 0 {
				it.Type = TypeLoopback
			} else {
				it.Type = TypePhysical
			}
		case *netlink.Veth, *netlink.Dummy, *netlink.Tuntap, *netlink.Macvlan, *netlink.IPVlan, *netlink.Vxlan, *netlink.Wireguard:
			it.Type = TypeVirtual
		default:
			it.Type = TypeOther
		}
		if it.Parent == "" && a.MasterIndex != 0 {
			it.Parent = byIndex[a.MasterIndex]
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, ad := range addrs {
			ip, ok := netip.AddrFromSlice(ad.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			ones, _ := ad.Mask.Size()
			it.Addresses = append(it.Addresses, Address{Prefix: netip.PrefixFrom(ip, ones)})
		}
		sort.Slice(it.Addresses, func(i, j int) bool {
			ai, aj := it.Addresses[i].Prefix.Addr(), it.Addresses[j].Prefix.Addr()
			if ai.Is4() != aj.Is4() {
				return ai.Is4()
			}
			return ai.Less(aj)
		})
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Watcher keeps an up-to-date view of the interfaces and calls the
// subscribers (debounced) when something changes.
type Watcher struct {
	log *slog.Logger

	mu   sync.RWMutex
	list []Interface
	subs []func([]Interface)
	kick chan struct{}

	// Event sources and polling period (replaced in tests).
	subLinks  func(ch chan netlink.LinkUpdate, done <-chan struct{}, cb func(error)) error
	subAddrs  func(ch chan netlink.AddrUpdate, done <-chan struct{}, cb func(error)) error
	pollEvery time.Duration
}

// NewWatcher builds a watcher; call Run to start it.
func NewWatcher(log *slog.Logger) *Watcher {
	return &Watcher{log: log, kick: make(chan struct{}, 1), pollEvery: 30 * time.Second,
		subLinks: func(ch chan netlink.LinkUpdate, done <-chan struct{}, cb func(error)) error {
			return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{ErrorCallback: cb})
		},
		subAddrs: func(ch chan netlink.AddrUpdate, done <-chan struct{}, cb func(error)) error {
			return netlink.AddrSubscribeWithOptions(ch, done, netlink.AddrSubscribeOptions{ErrorCallback: cb})
		}}
}

// Interfaces returns the last known snapshot.
func (w *Watcher) Interfaces() []Interface {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.list
}

// Subscribe registers fn, called after each change with the new snapshot.
func (w *Watcher) Subscribe(fn func([]Interface)) {
	w.mu.Lock()
	w.subs = append(w.subs, fn)
	w.mu.Unlock()
}

// Refresh reloads the interface list now and notifies subscribers.
func (w *Watcher) Refresh() {
	list, err := List()
	if err != nil {
		w.log.Warn("interface listing failed", "err", err)
		return
	}
	w.mu.Lock()
	w.list = list
	subs := append([]func([]Interface){}, w.subs...)
	w.mu.Unlock()
	for _, fn := range subs {
		fn(list)
	}
}

// Run listens for netlink link and address events until ctx is done. A
// periodic refresh (30 s) also covers missed events. netlink closes an event
// channel when its socket fails: the subscription is then renewed at the
// next poll.
func (w *Watcher) Run(ctx context.Context) {
	done := make(chan struct{})
	defer close(done)
	// Subscribe before the first snapshot: a change made in between would
	// otherwise wait for the next poll.
	linkCh, addrCh := w.subscribeLinks(done), w.subscribeAddrs(done)
	w.Refresh()
	poll := time.NewTicker(w.pollEvery)
	defer poll.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-linkCh:
			if !ok {
				w.log.Warn("netlink link events stopped, resubscribing at next poll")
				linkCh = nil // a nil channel is never ready: no busy loop
			}
			debounce = time.After(300 * time.Millisecond)
		case _, ok := <-addrCh:
			if !ok {
				w.log.Warn("netlink address events stopped, resubscribing at next poll")
				addrCh = nil
			}
			debounce = time.After(300 * time.Millisecond)
		case <-w.kick:
			debounce = time.After(10 * time.Millisecond)
		case <-debounce:
			debounce = nil
			w.Refresh()
		case <-poll.C:
			if linkCh == nil {
				linkCh = w.subscribeLinks(done)
			}
			if addrCh == nil {
				addrCh = w.subscribeAddrs(done)
			}
			w.Refresh()
		}
	}
}

// subscribeLinks subscribes to link events.
func (w *Watcher) subscribeLinks(done <-chan struct{}) chan netlink.LinkUpdate {
	ch := make(chan netlink.LinkUpdate, 64)
	if err := w.subLinks(ch, done, w.subErr); err != nil {
		w.log.Warn("netlink link events unavailable, polling only", "err", err)
	}
	return ch // never ready when the subscription failed
}

// subscribeAddrs subscribes to address events.
func (w *Watcher) subscribeAddrs(done <-chan struct{}) chan netlink.AddrUpdate {
	ch := make(chan netlink.AddrUpdate, 64)
	if err := w.subAddrs(ch, done, w.subErr); err != nil {
		w.log.Warn("netlink address events unavailable, polling only", "err", err)
	}
	return ch // never ready when the subscription failed
}

// Kick asks for a refresh soon (used after settings changes).
func (w *Watcher) Kick() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func (w *Watcher) subErr(err error) {
	if err != nil && err != unix.EAGAIN {
		w.log.Debug("netlink subscription", "err", err)
	}
}

// Package dnsmgr ties the DNS configuration, the DNS engine and the host
// interfaces together: it reloads the engine after each change and keeps
// the listeners in line with the interfaces where DNS is enabled.
package dnsmgr

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/netif"
)

// Interfaces is the source of host interfaces (netif.Watcher in production).
type Interfaces interface {
	Interfaces() []netif.Interface
	Subscribe(func([]netif.Interface))
	Kick()
}

// Manager owns the DNS runtime.
type Manager struct {
	Store  *dnsconf.Store
	Engine *dnssrv.Engine
	Ifaces Interfaces
	log    *slog.Logger

	mu sync.Mutex // serializes reloads
}

// New builds a manager.
func New(store *dnsconf.Store, engine *dnssrv.Engine, ifaces Interfaces, log *slog.Logger) *Manager {
	m := &Manager{Store: store, Engine: engine, Ifaces: ifaces, log: log}
	ifaces.Subscribe(func([]netif.Interface) { m.refreshListeners(context.Background()) })
	return m
}

// Reload pushes the whole configuration to the engine and updates listeners.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	zones, err := m.Store.Zones(ctx)
	if err != nil {
		return err
	}
	recs, err := m.Store.AllRecords(ctx)
	if err != nil {
		return err
	}
	fwd, err := m.Store.Forwarders(ctx)
	if err != nil {
		return err
	}
	st, err := m.Store.Settings(ctx)
	if err != nil {
		return err
	}
	m.Engine.Load(zones, recs, fwd, st)
	return m.applyListeners(ctx, st)
}

func (m *Manager) refreshListeners(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.Store.Settings(ctx)
	if err == nil {
		err = m.applyListeners(ctx, st)
	}
	if err != nil {
		m.log.Warn("DNS listeners refresh", "err", err)
	}
}

// applyListeners computes the IPs to serve: addresses of interfaces with DNS
// enabled, plus the extra addresses of the settings.
func (m *Manager) applyListeners(ctx context.Context, st dnsconf.Settings) error {
	set, err := m.Store.InterfaceSettings(ctx)
	if err != nil {
		return err
	}
	var addrs []dnssrv.ListenAddr
	for _, it := range m.Ifaces.Interfaces() {
		if !set[it.Name].DNSEnabled {
			continue
		}
		for _, a := range it.Addresses {
			addrs = append(addrs, dnssrv.ListenAddr{IP: a.Prefix.Addr(), Interface: it.Name})
		}
	}
	for _, s := range st.ExtraListenAddresses {
		if ip, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, dnssrv.ListenAddr{IP: ip})
		}
	}
	m.Engine.SetListeners(addrs)
	return nil
}

// Run retries failed listeners until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Engine.Close()
			return
		case <-t.C:
			m.Engine.Retry()
		}
	}
}

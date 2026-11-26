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
	"github.com/prohand/leazone/internal/dnssec"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/modules"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/store"
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

	// DNSSEC (optional): key store, modules state and whether this node
	// writes the configuration (only that node runs key maintenance).
	DNSSEC *dnssec.Store
	DB     *store.DB
	// BeginWrite, when set, tells whether this node may change the config
	// (cluster primary) and holds that right until done is called, so a
	// role change waits for the key rollover to be recorded.
	BeginWrite func() (done func(), err error)

	mu sync.Mutex // serializes reloads

	soonMu sync.Mutex
	soon   *time.Timer
}

// ReloadSoon schedules a reload in 200 ms, merging bursts of changes
// (many DHCP leases at boot time).
func (m *Manager) ReloadSoon() {
	m.soonMu.Lock()
	defer m.soonMu.Unlock()
	if m.soon != nil {
		return
	}
	m.soon = time.AfterFunc(200*time.Millisecond, func() {
		m.soonMu.Lock()
		m.soon = nil
		m.soonMu.Unlock()
		if err := m.Reload(context.Background()); err != nil {
			m.log.Error("DNS reload", "err", err)
		}
	})
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
	if m.DB != nil {
		mods, err := modules.Get(ctx, m.DB)
		if err != nil {
			return err
		}
		c := dnssrv.DNSSECConfig{Validate: mods.DNSSECValidation}
		if mods.DNSSEC && m.DNSSEC != nil {
			if c.Keys, err = m.DNSSEC.SigningKeys(ctx); err != nil {
				return err
			}
			if c.NSECMode, err = m.DNSSEC.NSECModes(ctx); err != nil {
				return err
			}
		}
		m.Engine.SetDNSSEC(c)
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

// Run retries failed listeners, renews signatures and maintains DNSSEC
// keys until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var lastMaintain time.Time
	for {
		select {
		case <-ctx.Done():
			m.Engine.Close()
			return
		case <-t.C:
			m.Engine.Retry()
			reload := m.Engine.NeedsResign(time.Now())
			if time.Since(lastMaintain) > 5*time.Minute {
				lastMaintain = time.Now()
				if changed, err := m.maintain(ctx); err != nil {
					m.log.Warn("DNSSEC key maintenance", "err", err)
				} else if changed {
					reload = true
				}
			}
			if reload {
				if err := m.Reload(ctx); err != nil {
					m.log.Error("DNS reload", "err", err)
				}
			}
		}
	}
}

func (m *Manager) maintain(ctx context.Context) (bool, error) {
	if m.DNSSEC == nil || m.DB == nil {
		return false, nil
	}
	if m.BeginWrite != nil {
		done, err := m.BeginWrite()
		if err != nil {
			return false, nil
		}
		defer done()
	}
	mods, err := modules.Get(ctx, m.DB)
	if err != nil || !mods.DNSSEC {
		return false, err
	}
	changed, err := m.DNSSEC.Maintain(ctx)
	if changed {
		m.log.Info("DNSSEC keys rolled over")
	}
	return changed, err
}

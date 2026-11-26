// Package dhcpmgr ties the DHCP configuration, the DHCP engine/socket and
// the host interfaces together.
package dhcpmgr

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnsmgr"
	"github.com/prohand/leazone/internal/netif"
)

// Manager owns the DHCP runtime.
type Manager struct {
	Conf   *dhcpconf.Store
	DNS    *dnsconf.Store
	Engine *dhcpsrv.Engine
	Server *dhcpsrv.Server
	Ifaces dnsmgr.Interfaces
	// PingAvailable is false when ICMP cannot be used (no NET_RAW).
	PingAvailable bool
	log           *slog.Logger
	mu            sync.Mutex
}

// New builds a manager and follows interface changes.
func New(conf *dhcpconf.Store, dns *dnsconf.Store, engine *dhcpsrv.Engine, server *dhcpsrv.Server, ifaces dnsmgr.Interfaces, log *slog.Logger) *Manager {
	m := &Manager{Conf: conf, DNS: dns, Engine: engine, Server: server, Ifaces: ifaces, log: log}
	ifaces.Subscribe(func([]netif.Interface) {
		if err := m.refreshInterfaces(context.Background()); err != nil {
			log.Warn("DHCP interfaces refresh", "err", err)
		}
	})
	return m
}

// Reload pushes scopes, reservations and interface settings to the engine,
// and opens/closes the socket as needed.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	scopes, err := m.Conf.Scopes(ctx)
	if err != nil {
		return err
	}
	res, err := m.Conf.Reservations(ctx, "")
	if err != nil {
		return err
	}
	m.Engine.SetConfig(scopes, res)
	if err := m.applyInterfaces(ctx); err != nil {
		return err
	}
	m.Server.Ensure(ctx)
	return nil
}

func (m *Manager) refreshInterfaces(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyInterfaces(ctx)
}

func (m *Manager) applyInterfaces(ctx context.Context) error {
	set, err := m.DNS.InterfaceSettings(ctx)
	if err != nil {
		return err
	}
	on := map[string]bool{}
	for n, s := range set {
		on[n] = s.DHCPEnabled
	}
	m.Engine.SetInterfaces(m.Ifaces.Interfaces(), on)
	return nil
}

// Run expires leases and retries a failed socket until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Server.Close()
			return
		case <-t.C:
			m.Engine.Sweep(ctx)
			m.Server.Ensure(ctx)
		}
	}
}

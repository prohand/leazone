//go:build linux

// Package vip moves the cluster's virtual IP: the primary adds the address
// to its interface (NET_ADMIN) and announces it with gratuitous ARP
// (NET_RAW), so switches and clients update their tables at once.
package vip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// Manager adds or removes the VIP.
type Manager struct {
	Prefix    netip.Prefix
	Interface string
	log       *slog.Logger

	mu      sync.Mutex
	up      bool
	lastErr string
}

// New returns a manager (nil when no VIP is configured).
func New(cidr, iface string, log *slog.Logger) (*Manager, error) {
	if cidr == "" {
		return nil, nil
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	return &Manager{Prefix: p, Interface: iface, log: log}, nil
}

// Status reports whether this node holds the VIP and the last error.
func (m *Manager) Status() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up, m.lastErr
}

func (m *Manager) addr() *netlink.Addr {
	return &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(m.Prefix.Addr().AsSlice()), Mask: net.CIDRMask(m.Prefix.Bits(), 32)},
		Label: m.Interface}
}

// Up adds the VIP and sends 3 gratuitous ARP.
func (m *Manager) Up() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	link, err := netlink.LinkByName(m.Interface)
	if err != nil {
		return m.fail(fmt.Errorf("interface %s introuvable pour l'IP virtuelle", m.Interface))
	}
	if err := netlink.AddrAdd(link, m.addr()); err != nil && !errors.Is(err, syscall.EEXIST) {
		if errors.Is(err, syscall.EPERM) {
			return m.fail(errors.New("impossible d'ajouter l'IP virtuelle : capability NET_ADMIN manquante"))
		}
		return m.fail(err)
	}
	m.up, m.lastErr = true, ""
	m.log.Info("virtual IP added", "vip", m.Prefix, "interface", m.Interface)
	go func() {
		for i := 0; i < 3; i++ {
			if err := gratuitousARP(link, m.Prefix.Addr()); err != nil {
				m.log.Warn("gratuitous ARP failed", "err", err)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	return nil
}

// Down removes the VIP. It always asks the kernel, even when this process
// did not add it: after a crash (network_mode host) the address stays on the
// host interface and must not survive on a node that is not primary.
func (m *Manager) Down() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	was := m.up
	m.up = false
	link, err := netlink.LinkByName(m.Interface)
	if err != nil {
		return nil // no interface, no address
	}
	err = netlink.AddrDel(link, m.addr())
	switch {
	case err == nil:
		m.lastErr = ""
		if was {
			m.log.Info("virtual IP removed", "vip", m.Prefix)
		} else {
			m.log.Warn("stale virtual IP removed (left by a previous run)", "vip", m.Prefix, "interface", m.Interface)
		}
	case errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.ESRCH), errors.Is(err, syscall.ENOENT):
		// Not there: nothing to do.
	case !was && errors.Is(err, syscall.EPERM):
		// No NET_ADMIN: this run cannot have added it.
		m.log.Warn("cannot check for a stale virtual IP: NET_ADMIN capability missing", "vip", m.Prefix)
	default:
		m.up = was
		return m.fail(err)
	}
	return nil
}

func (m *Manager) fail(err error) error {
	m.lastErr = err.Error()
	m.log.Error("virtual IP", "err", err)
	return err
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// gratuitousARP broadcasts "ip is at <our MAC>" on link.
func gratuitousARP(link netlink.Link, ip netip.Addr) error {
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
		return errors.New("pas d'adresse MAC sur l'interface")
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("socket ARP (NET_RAW manquante ?) : %w", err)
	}
	defer syscall.Close(fd)
	b := make([]byte, 42)
	copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[6:12], mac)
	binary.BigEndian.PutUint16(b[12:], syscall.ETH_P_ARP)
	binary.BigEndian.PutUint16(b[14:], 1)      // Ethernet
	binary.BigEndian.PutUint16(b[16:], 0x0800) // IPv4
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], 1) // request (gratuitous)
	copy(b[22:28], mac)
	v4 := ip.As4()
	copy(b[28:32], v4[:])
	copy(b[38:42], v4[:]) // target IP = our IP, target MAC = zero
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	return syscall.Sendto(fd, b, 0, sa)
}

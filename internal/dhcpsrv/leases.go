// Package dhcpsrv is the DHCPv4 server: scope selection (direct per
// interface, or by relay giaddr), address allocation, lease life cycle and
// persistence. DHCPv6 can be added later as a sibling package sharing the
// lease store design.
package dhcpsrv

import (
	"context"
	"net/netip"
	"time"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/store"
)

// Lease states.
const (
	StateOffered  = "offered"
	StateBound    = "bound"
	StateReleased = "released"
	StateExpired  = "expired"
	StateDeclined = "declined"
)

// Lease is one address of one scope.
type Lease struct {
	ScopeID   string     `json:"scopeId"`
	IP        netip.Addr `json:"ip"`
	MAC       string     `json:"mac"`
	ClientID  string     `json:"clientId"`
	Hostname  string     `json:"hostname"`
	State     string     `json:"state"`
	Starts    time.Time  `json:"starts"`
	Ends      time.Time  `json:"ends"`
	CircuitID string     `json:"circuitId"`
	RemoteID  string     `json:"remoteId"`
	GIAddr    string     `json:"giaddr"`
	DNSName   string     `json:"dnsName"`
	Owner     string     `json:"-"`
	HLC       int64      `json:"-"`
}

// Active reports whether the address is in use at time now.
func (l *Lease) Active(now time.Time) bool {
	switch l.State {
	case StateOffered, StateBound, StateDeclined:
		return now.Before(l.Ends)
	}
	return false
}

// Key identifies the client: client identifier if present, else MAC.
func (l *Lease) Key() string {
	if l.ClientID != "" {
		return "id:" + l.ClientID
	}
	return "mac:" + l.MAC
}

func (l *Lease) sameClient(mac, clientID string) bool {
	if clientID != "" && l.ClientID != "" {
		return l.ClientID == clientID
	}
	return l.MAC == mac
}

// leaseDB persists leases in SQLite (write-through, memory is the source).
type leaseDB struct {
	db *store.DB
}

func (d *leaseDB) load(ctx context.Context) (map[string]map[uint32]*Lease, error) {
	out := map[string]map[uint32]*Lease{}
	rows, err := d.db.QueryContext(ctx, `SELECT scope_id, ip, mac, client_id, hostname, state, starts, ends, circuit_id,
		remote_id, giaddr, dns_name, owner_node, hlc FROM dhcp_leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l Lease
		var ip string
		var st, en int64
		if err := rows.Scan(&l.ScopeID, &ip, &l.MAC, &l.ClientID, &l.Hostname, &l.State, &st, &en, &l.CircuitID,
			&l.RemoteID, &l.GIAddr, &l.DNSName, &l.Owner, &l.HLC); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			continue
		}
		l.IP, l.Starts, l.Ends = a, time.UnixMilli(st), time.UnixMilli(en)
		if out[l.ScopeID] == nil {
			out[l.ScopeID] = map[uint32]*Lease{}
		}
		out[l.ScopeID][dhcpconf.U32(a)] = &l
	}
	return out, rows.Err()
}

func (d *leaseDB) put(ctx context.Context, l *Lease) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO dhcp_leases(scope_id, ip, mac, client_id, hostname, state, starts, ends,
		circuit_id, remote_id, giaddr, dns_name, owner_node, hlc, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope_id, ip) DO UPDATE SET mac = excluded.mac, client_id = excluded.client_id, hostname = excluded.hostname,
		state = excluded.state, starts = excluded.starts, ends = excluded.ends, circuit_id = excluded.circuit_id,
		remote_id = excluded.remote_id, giaddr = excluded.giaddr, dns_name = excluded.dns_name,
		owner_node = excluded.owner_node, hlc = excluded.hlc, updated_by = excluded.updated_by`,
		l.ScopeID, l.IP.String(), l.MAC, l.ClientID, l.Hostname, l.State, l.Starts.UnixMilli(), l.Ends.UnixMilli(),
		l.CircuitID, l.RemoteID, l.GIAddr, l.DNSName, l.Owner, l.HLC, l.Owner)
	return err
}

func (d *leaseDB) delete(ctx context.Context, scopeID string, ip netip.Addr) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM dhcp_leases WHERE scope_id = ? AND ip = ?`, scopeID, ip.String())
	return err
}

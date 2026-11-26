package dnsconf

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"

	"github.com/prohand/leazone/internal/ids"
)

// EnsureZone returns the zone named name, creating it (auto) if missing.
func (s *Store) EnsureZone(ctx context.Context, name string) (*Zone, error) {
	n, _, err := NormalizeZoneName(name)
	if err != nil {
		return nil, err
	}
	if z, err := s.ZoneByName(ctx, n); err == nil {
		return z, nil
	}
	z, err := s.CreateZone(ctx, ZoneInput{Name: n, Auto: true})
	if err != nil {
		if _, ok := err.(ErrConflict); ok { // created concurrently
			return s.ZoneByName(ctx, n)
		}
		return nil, err
	}
	return z, nil
}

// ReverseZonesFor lists the reverse zones covering an IPv4 network: one per
// /24 for prefixes /17 to /32, else one per /16 (/9 to /16), else the /8.
func ReverseZonesFor(p netip.Prefix) []netip.Prefix {
	p = p.Masked()
	step := 24
	switch {
	case p.Bits() <= 8:
		step = 8
	case p.Bits() <= 16:
		step = 16
	}
	if p.Bits() >= step {
		q, _ := p.Addr().Prefix(step)
		return []netip.Prefix{q}
	}
	var out []netip.Prefix
	n := 1 << (step - p.Bits())
	a := p.Addr().As4()
	base := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	for i := 0; i < n; i++ {
		v := base + uint32(i)<<(32-step)
		out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), step))
	}
	return out
}

// EnsureReverseZones creates the reverse zones of a DHCP scope network.
func (s *Store) EnsureReverseZones(ctx context.Context, network netip.Prefix) ([]string, error) {
	var names []string
	for _, p := range ReverseZonesFor(network) {
		name, err := ReverseZone(p)
		if err != nil {
			return nil, err
		}
		if _, err := s.EnsureZone(ctx, name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// RecordOwner describes who owns the records at a name.
type RecordOwner struct {
	Source string
	Owner  string
}

// Owners returns the sources/owners of the records at name in a zone.
func (s *Store) Owners(ctx context.Context, zoneID, name string) ([]RecordOwner, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, dhcp_owner FROM records WHERE zone_id = ? AND name = ?`, zoneID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecordOwner
	for rows.Next() {
		var o RecordOwner
		if err := rows.Scan(&o.Source, &o.Owner); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// PutDHCPRecord replaces the DHCP record of (zone, name, type) with data
// owned by owner. Manual records are never touched.
func (s *Store) PutDHCPRecord(ctx context.Context, zoneID, name, typ string, ttl uint32, data RecordData, owner string) error {
	raw, _ := json.Marshal(data)
	now := s.Now().UnixMilli()
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM records WHERE zone_id = ? AND name = ? AND type = ? AND source = 'dhcp'`,
			zoneID, name, typ); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO records(id, zone_id, name, type, ttl, data, source, dhcp_owner, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 'dhcp', ?, ?, ?)`, ids.New(), zoneID, name, typ, ttl, string(raw), owner, now, now)
		// DHCP records are derived on each node from the leases: they do not
		// change the zone (no serial bump, not replicated as config).
		return err
	})
}

// DeleteDHCPOwner removes every DHCP record of an owner. It returns how many.
func (s *Store) DeleteDHCPOwner(ctx context.Context, owner string) (int, error) {
	var n int64
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM records WHERE source = 'dhcp' AND dhcp_owner = ?`, owner)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return int(n), err
}

package dnsconf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Zone kinds.
const (
	KindPrimary = "primary"
	KindReverse = "reverse"
)

// Store gives access to the DNS configuration tables.
type Store struct {
	db  *store.DB
	Now func() time.Time
}

// New returns a Store.
func New(db *store.DB) *Store { return &Store{db: db, Now: time.Now} }

// Validation is a set of field errors (keys follow the JSON field names).
type Validation map[string]string

func (v Validation) Error() string {
	var parts []string
	for k, m := range v {
		parts = append(parts, k+": "+m)
	}
	return "validation: " + strings.Join(parts, ", ")
}

// ErrConflict signals a uniqueness or consistency conflict.
type ErrConflict struct{ Msg string }

func (e ErrConflict) Error() string { return e.Msg }

// SOA holds the editable SOA fields.
type SOA struct {
	PrimaryNS  string `json:"primaryNs"`
	AdminEmail string `json:"adminEmail"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	Minimum    uint32 `json:"minimum"`
}

// Zone is a primary or reverse zone.
type Zone struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Auto        bool      `json:"auto"`
	TTL         uint32    `json:"ttl"`
	SOA         SOA       `json:"soa"`
	Serial      uint32    `json:"serial"`
	RecordCount int       `json:"recordCount"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ZoneInput is what a user provides.
type ZoneInput struct {
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	SOA  *SOA   `json:"soa"`
	Auto bool   `json:"-"`
}

func defaultSOA(zone string) SOA {
	return SOA{PrimaryNS: "ns." + zone + ".", AdminEmail: "hostmaster@" + zone, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
}

func (s *Store) checkSOA(soa *SOA, zone string, errs Validation) {
	if soa.PrimaryNS == "" {
		soa.PrimaryNS = "ns." + zone + "."
	}
	ns, err := HostTarget(soa.PrimaryNS, zone)
	if err != nil {
		errs["soa.primaryNs"] = err.Error()
	}
	soa.PrimaryNS = ns
	soa.AdminEmail = strings.ToLower(strings.TrimSpace(soa.AdminEmail))
	if soa.AdminEmail == "" {
		soa.AdminEmail = "hostmaster@" + zone
	}
	if at := strings.Index(soa.AdminEmail, "@"); at <= 0 || at == len(soa.AdminEmail)-1 {
		errs["soa.adminEmail"] = "adresse e-mail invalide"
	}
	if soa.Refresh == 0 {
		soa.Refresh = 3600
	}
	if soa.Retry == 0 {
		soa.Retry = 600
	}
	if soa.Expire == 0 {
		soa.Expire = 604800
	}
	if soa.Minimum == 0 {
		soa.Minimum = 300
	}
	if soa.Minimum > 86400 {
		errs["soa.minimum"] = "86400 secondes maximum"
	}
}

// nextSerial follows the YYYYMMDDnn convention and always increases.
func (s *Store) nextSerial(old uint32) uint32 {
	d, _ := strconv.ParseUint(s.Now().UTC().Format("20060102")+"00", 10, 32)
	if uint32(d) > old {
		return uint32(d)
	}
	return old + 1
}

const zoneCols = `z.id, z.name, z.kind, z.auto, z.ttl, z.soa_primary_ns, z.soa_admin_email, z.soa_refresh, z.soa_retry,
	z.soa_expire, z.soa_minimum, z.serial, z.created_at, z.updated_at,
	(SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id)`

func scanZone(row interface{ Scan(...any) error }) (*Zone, error) {
	var z Zone
	var auto int
	var c, u int64
	err := row.Scan(&z.ID, &z.Name, &z.Kind, &auto, &z.TTL, &z.SOA.PrimaryNS, &z.SOA.AdminEmail, &z.SOA.Refresh,
		&z.SOA.Retry, &z.SOA.Expire, &z.SOA.Minimum, &z.Serial, &c, &u, &z.RecordCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	z.Auto = auto != 0
	z.CreatedAt, z.UpdatedAt = time.UnixMilli(c), time.UnixMilli(u)
	return &z, nil
}

// Zones lists every zone sorted by kind then name.
func (s *Store) Zones(ctx context.Context) ([]*Zone, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+zoneCols+` FROM zones z ORDER BY z.kind, z.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Zone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// Zone returns one zone.
func (s *Store) Zone(ctx context.Context, id string) (*Zone, error) {
	return scanZone(s.db.QueryRowContext(ctx, `SELECT `+zoneCols+` FROM zones z WHERE z.id = ?`, id))
}

// ZoneByName returns a zone by its canonical name.
func (s *Store) ZoneByName(ctx context.Context, name string) (*Zone, error) {
	return scanZone(s.db.QueryRowContext(ctx, `SELECT `+zoneCols+` FROM zones z WHERE z.name = ?`, strings.ToLower(strings.TrimSuffix(name, "."))))
}

// CreateZone validates and inserts a zone.
func (s *Store) CreateZone(ctx context.Context, in ZoneInput) (*Zone, error) {
	errs := Validation{}
	name, kind, err := NormalizeZoneName(in.Name)
	if err != nil {
		errs["name"] = err.Error()
	}
	if in.TTL == 0 {
		in.TTL = 3600
	}
	if in.TTL > 604800 {
		errs["ttl"] = "604800 secondes maximum"
	}
	soa := defaultSOA(name)
	if in.SOA != nil {
		soa = *in.SOA
	}
	if name != "" {
		s.checkSOA(&soa, name, errs)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	now := s.Now()
	id := ids.New()
	auto := 0
	if in.Auto {
		auto = 1
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO zones(id, name, kind, auto, ttl, soa_primary_ns, soa_admin_email, soa_refresh,
		soa_retry, soa_expire, soa_minimum, serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, name, kind, auto, in.TTL, soa.PrimaryNS, soa.AdminEmail, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum,
		s.nextSerial(0), now.UnixMilli(), now.UnixMilli())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrConflict{fmt.Sprintf("la zone %s existe déjà", name)}
		}
		return nil, err
	}
	return s.Zone(ctx, id)
}

// UpdateZone changes the default TTL and/or SOA, and bumps the serial.
func (s *Store) UpdateZone(ctx context.Context, id string, ttl *uint32, soa *SOA) (*Zone, error) {
	z, err := s.Zone(ctx, id)
	if err != nil {
		return nil, err
	}
	errs := Validation{}
	if ttl != nil {
		if *ttl == 0 || *ttl > 604800 {
			errs["ttl"] = "entre 1 et 604800 secondes"
		}
		z.TTL = *ttl
	}
	if soa != nil {
		z.SOA = *soa
		s.checkSOA(&z.SOA, z.Name, errs)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	_, err = s.db.ExecContext(ctx, `UPDATE zones SET ttl = ?, soa_primary_ns = ?, soa_admin_email = ?, soa_refresh = ?, soa_retry = ?,
		soa_expire = ?, soa_minimum = ?, serial = ?, updated_at = ? WHERE id = ?`, z.TTL, z.SOA.PrimaryNS, z.SOA.AdminEmail,
		z.SOA.Refresh, z.SOA.Retry, z.SOA.Expire, z.SOA.Minimum, s.nextSerial(z.Serial), s.Now().UnixMilli(), id)
	if err != nil {
		return nil, err
	}
	return s.Zone(ctx, id)
}

// DeleteZone removes a zone and its records.
func (s *Store) DeleteZone(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM zones WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) touchZone(ctx context.Context, tx *sql.Tx, zoneID string) error {
	var serial uint32
	if err := tx.QueryRowContext(ctx, `SELECT serial FROM zones WHERE id = ?`, zoneID).Scan(&serial); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE zones SET serial = ?, updated_at = ? WHERE id = ?`, s.nextSerial(serial), s.Now().UnixMilli(), zoneID)
	return err
}

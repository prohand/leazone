// Package dnssec manages the signing keys of the zones: creation (once, on
// the primary; the encrypted private keys are replicated so both nodes sign
// with the same keys), automatic ZSK rollover (pre-publication), manual KSK
// rollover (double signature, ended when the user confirms the new DS is at
// the registrar), DS records and export in BIND format.
package dnssec

import (
	"context"
	"crypto"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

// Roles and states.
const (
	KSK = "ksk"
	ZSK = "zsk"

	StatePublished = "published"  // in the DNSKEY set, not signing yet
	StateActive    = "active"     // signing
	StateRetired   = "retired"    // still published, no longer signing (ZSK) or still signing the key set (KSK)
	StateDSPending = "ds-pending" // KSK waiting for its DS at the registrar (already signing the key set)
)

// Timing of the key lifecycle.
const (
	DNSKEYTTL   = 3600
	ZSKLifetime = 90 * 24 * time.Hour
	PrePublish  = 2 * time.Hour      // > DNSKEY TTL: caches see the new key before it signs
	RetireDelay = 2 * 24 * time.Hour // old signatures / DS leave the caches
)

// Key is a signing key. Signer is only set by SigningKeys.
type Key struct {
	ID        string        `json:"id"`
	ZoneID    string        `json:"-"`
	Role      string        `json:"role"`
	Algorithm uint8         `json:"algorithm"`
	KeyTag    uint16        `json:"keyTag"`
	State     string        `json:"state"`
	CreatedAt time.Time     `json:"createdAt"`
	ActiveAt  *time.Time    `json:"activeAt"`
	RetireAt  *time.Time    `json:"retireAt"`
	DNSKEYStr string        `json:"dnskey"`
	DNSKEY    *dns.DNSKEY   `json:"-"`
	Signer    crypto.Signer `json:"-"`
	private   string
}

// ZoneInfo is the DNSSEC view of a zone.
type ZoneInfo struct {
	ZoneID          string     `json:"zoneId"`
	Name            string     `json:"name"`
	Enabled         bool       `json:"enabled"`
	Algorithm       uint8      `json:"algorithm"`
	NSECMode        string     `json:"nsecMode"`
	Keys            []*Key     `json:"keys"`
	DS              []string   `json:"ds"`
	DSPending       bool       `json:"dsPending"`
	NextZSKRollover *time.Time `json:"nextZskRollover"`
}

// Store manages keys.
type Store struct {
	db  *store.DB
	box *secrets.Box
	Now func() time.Time
}

// NewStore returns a Store.
func NewStore(db *store.DB, box *secrets.Box) *Store { return &Store{db: db, box: box, Now: time.Now} }

// ErrNotFound is returned for an unknown zone.
var ErrNotFound = errors.New("not found")

func ms(t time.Time) int64 { return t.UnixMilli() }

func tptr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

func (s *Store) keys(ctx context.Context, q execer, zoneID string, withPrivate bool) ([]*Key, error) {
	query := `SELECT id, zone_id, role, algorithm, key_tag, public, private_enc, state, created_at, active_at, retire_at
		FROM dnssec_keys`
	var args []any
	if zoneID != "" {
		query += ` WHERE zone_id = ?`
		args = append(args, zoneID)
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY zone_id, role, created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		var k Key
		var created int64
		var active, retire sql.NullInt64
		var enc string
		if err := rows.Scan(&k.ID, &k.ZoneID, &k.Role, &k.Algorithm, &k.KeyTag, &k.DNSKEYStr, &enc, &k.State, &created,
			&active, &retire); err != nil {
			return nil, err
		}
		k.CreatedAt, k.ActiveAt, k.RetireAt = time.UnixMilli(created).UTC(), tptr(active), tptr(retire)
		rr, err := dns.NewRR(k.DNSKEYStr)
		if err != nil {
			return nil, fmt.Errorf("dnssec key %s: %w", k.ID, err)
		}
		k.DNSKEY = rr.(*dns.DNSKEY)
		if withPrivate {
			pt, err := s.box.Open(enc, aad(k.ID))
			if err != nil {
				return nil, fmt.Errorf("dnssec key %s: %w", k.ID, err)
			}
			k.private = string(pt)
			priv, err := k.DNSKEY.NewPrivateKey(k.private)
			if err != nil {
				return nil, fmt.Errorf("dnssec key %s: %w", k.ID, err)
			}
			signer, ok := priv.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("dnssec key %s: unsupported private key", k.ID)
			}
			k.Signer = signer
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

type execer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func aad(id string) string { return "dnssec:" + id }

// SigningKeys returns the keys of every signed zone, with private keys,
// by zone id.
func (s *Store) SigningKeys(ctx context.Context) (map[string][]*Key, error) {
	ks, err := s.keys(ctx, s.db, "", true)
	if err != nil {
		return nil, err
	}
	enabled := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM zones WHERE dnssec_enabled = 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		enabled[id] = true
	}
	rows.Close()
	out := map[string][]*Key{}
	for _, k := range ks {
		if enabled[k.ZoneID] {
			out[k.ZoneID] = append(out[k.ZoneID], k)
		}
	}
	return out, nil
}

// NSECModes returns the NSEC mode of every signed zone.
func (s *Store) NSECModes(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, nsec_mode FROM zones WHERE dnssec_enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, m string
		if err := rows.Scan(&id, &m); err != nil {
			return nil, err
		}
		out[id] = m
	}
	return out, rows.Err()
}

type zoneRow struct {
	id, name, mode string
	enabled        bool
	alg            uint8
}

func (s *Store) zone(ctx context.Context, q execer, id string) (zoneRow, error) {
	var z zoneRow
	var en int
	err := q.QueryRowContext(ctx, `SELECT id, name, dnssec_enabled, dnssec_algorithm, nsec_mode FROM zones WHERE id = ?`, id).
		Scan(&z.id, &z.name, &en, &z.alg, &z.mode)
	if errors.Is(err, sql.ErrNoRows) {
		return z, ErrNotFound
	}
	z.enabled = en != 0
	return z, err
}

// Zones returns the DNSSEC view of every zone.
func (s *Store) Zones(ctx context.Context) ([]*ZoneInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM zones ORDER BY kind, name`)
	if err != nil {
		return nil, err
	}
	var idl []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		idl = append(idl, id)
	}
	rows.Close()
	out := []*ZoneInfo{}
	for _, id := range idl {
		z, err := s.Zone(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, nil
}

// Zone returns the DNSSEC view of a zone.
func (s *Store) Zone(ctx context.Context, id string) (*ZoneInfo, error) {
	z, err := s.zone(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	info := &ZoneInfo{ZoneID: z.id, Name: z.name, Enabled: z.enabled, Algorithm: z.alg, NSECMode: z.mode, Keys: []*Key{}, DS: []string{}}
	if !z.enabled {
		return info, nil
	}
	ks, err := s.keys(ctx, s.db, id, false)
	if err != nil {
		return nil, err
	}
	info.Keys = ks
	for _, k := range ks {
		switch {
		case k.Role == KSK && (k.State == StateActive || k.State == StateDSPending):
			if ds := k.DNSKEY.ToDS(dns.SHA256); ds != nil {
				info.DS = append(info.DS, ds.String())
			}
			if k.State == StateDSPending {
				info.DSPending = true
			}
		case k.Role == ZSK && k.State == StatePublished && k.ActiveAt != nil:
			info.NextZSKRollover = k.ActiveAt
		case k.Role == ZSK && k.State == StateActive && k.ActiveAt != nil && info.NextZSKRollover == nil:
			t := k.ActiveAt.Add(ZSKLifetime)
			info.NextZSKRollover = &t
		}
	}
	return info, nil
}

// Generate creates a key pair for a zone (not stored).
func Generate(zone, role string, alg uint8) (*Key, error) {
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(strings.ToLower(zone)), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: DNSKEYTTL},
		Flags: 256, Protocol: 3, Algorithm: alg}
	if role == KSK {
		k.Flags = 257
	}
	priv, err := k.Generate(256)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("dnssec: unsupported private key")
	}
	return &Key{ID: ids.New(), Role: role, Algorithm: alg, KeyTag: k.KeyTag(), DNSKEY: k, DNSKEYStr: k.String(),
		Signer: signer, private: k.PrivateKeyString(priv), CreatedAt: time.Now().UTC()}, nil
}

// newKey generates a key for a zone and stores it.
func (s *Store) newKey(ctx context.Context, q execer, z zoneRow, role, state string, activeAt time.Time) error {
	k, err := Generate(z.name, role, z.alg)
	if err != nil {
		return err
	}
	var act any
	if !activeAt.IsZero() {
		act = ms(activeAt)
	}
	_, err = q.ExecContext(ctx, `INSERT INTO dnssec_keys(id, zone_id, role, algorithm, key_tag, public, private_enc, state, created_at, active_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, k.ID, z.id, role, z.alg, k.KeyTag, k.DNSKEYStr,
		s.box.Seal([]byte(k.private), aad(k.ID)), state, ms(s.Now()), act)
	return err
}

// Enable signs a zone: one KSK (waiting for its DS) and one active ZSK.
func (s *Store) Enable(ctx context.Context, zoneID string, alg uint8, mode string) (*ZoneInfo, error) {
	errs := dnsconf.Validation{}
	if alg == 0 {
		alg = dns.ECDSAP256SHA256
	}
	if alg != dns.ECDSAP256SHA256 && alg != dns.ED25519 {
		errs["algorithm"] = "13 (ECDSA P-256) ou 15 (Ed25519)"
	}
	if mode == "" {
		mode = "nsec3"
	}
	if mode != "nsec" && mode != "nsec3" {
		errs["nsecMode"] = "nsec ou nsec3"
	}
	if len(errs) > 0 {
		return nil, errs
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		z, err := s.zone(ctx, tx, zoneID)
		if err != nil {
			return err
		}
		if z.enabled {
			return dnsconf.ErrConflict{Msg: "la zone est déjà signée"}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM dnssec_keys WHERE zone_id = ?`, zoneID); err != nil {
			return err
		}
		z.alg = alg
		if _, err := tx.ExecContext(ctx, `UPDATE zones SET dnssec_enabled = 1, dnssec_algorithm = ?, nsec_mode = ?, updated_at = ? WHERE id = ?`,
			alg, mode, ms(s.Now()), zoneID); err != nil {
			return err
		}
		if err := s.newKey(ctx, tx, z, KSK, StateDSPending, s.Now()); err != nil {
			return err
		}
		return s.newKey(ctx, tx, z, ZSK, StateActive, s.Now())
	})
	if err != nil {
		return nil, err
	}
	return s.Zone(ctx, zoneID)
}

// Disable stops signing and deletes the keys.
func (s *Store) Disable(ctx context.Context, zoneID string) (*ZoneInfo, error) {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := s.zone(ctx, tx, zoneID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM dnssec_keys WHERE zone_id = ?`, zoneID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE zones SET dnssec_enabled = 0, updated_at = ? WHERE id = ?`, ms(s.Now()), zoneID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Zone(ctx, zoneID)
}

func (s *Store) signedZone(ctx context.Context, tx execer, zoneID string) (zoneRow, []*Key, error) {
	z, err := s.zone(ctx, tx, zoneID)
	if err != nil {
		return z, nil, err
	}
	if !z.enabled {
		return z, nil, dnsconf.ErrConflict{Msg: "la zone n'est pas signée"}
	}
	ks, err := s.keys(ctx, tx, zoneID, false)
	return z, ks, err
}

// Rollover starts a key rollover. ZSK: a new key is published now and
// signs after PrePublish. KSK: a new key signs the key set at once (double
// signature) and waits for its DS at the registrar.
func (s *Store) Rollover(ctx context.Context, zoneID, role string) (*ZoneInfo, error) {
	if role != ZSK && role != KSK {
		return nil, dnsconf.Validation{"type": "zsk ou ksk"}
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		z, ks, err := s.signedZone(ctx, tx, zoneID)
		if err != nil {
			return err
		}
		for _, k := range ks {
			if k.Role == role && (k.State == StatePublished || k.State == StateDSPending) {
				if role == KSK {
					return dnsconf.ErrConflict{Msg: "un changement de KSK attend déjà son DS : confirmez d'abord la publication du DS"}
				}
				return dnsconf.ErrConflict{Msg: "un changement de ZSK est déjà en cours"}
			}
		}
		if role == ZSK {
			return s.newKey(ctx, tx, z, ZSK, StatePublished, s.Now().Add(PrePublish))
		}
		return s.newKey(ctx, tx, z, KSK, StateDSPending, s.Now())
	})
	if err != nil {
		return nil, err
	}
	return s.Zone(ctx, zoneID)
}

// DSPublished ends a KSK rollover (or the first DS publication): waiting
// KSKs become active, the previous ones are retired.
func (s *Store) DSPublished(ctx context.Context, zoneID string) (*ZoneInfo, error) {
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		_, ks, err := s.signedZone(ctx, tx, zoneID)
		if err != nil {
			return err
		}
		pending := false
		for _, k := range ks {
			if k.Role == KSK && k.State == StateDSPending {
				pending = true
			}
		}
		if !pending {
			return dnsconf.ErrConflict{Msg: "aucun DS en attente"}
		}
		now := s.Now()
		for _, k := range ks {
			if k.Role != KSK {
				continue
			}
			switch k.State {
			case StateDSPending:
				_, err = tx.ExecContext(ctx, `UPDATE dnssec_keys SET state = ?, active_at = ? WHERE id = ?`, StateActive, ms(now), k.ID)
			case StateActive:
				_, err = tx.ExecContext(ctx, `UPDATE dnssec_keys SET state = ?, retire_at = ? WHERE id = ?`, StateRetired,
					ms(now.Add(RetireDelay)), k.ID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Zone(ctx, zoneID)
}

// Maintain moves keys along their lifecycle and starts automatic ZSK
// rollovers. Only the node that writes the configuration runs it. It
// reports whether something changed.
func (s *Store) Maintain(ctx context.Context) (bool, error) {
	changed := false
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		ks, err := s.keys(ctx, tx, "", false)
		if err != nil {
			return err
		}
		now := s.Now()
		byZone := map[string][]*Key{}
		for _, k := range ks {
			byZone[k.ZoneID] = append(byZone[k.ZoneID], k)
		}
		for zoneID, zk := range byZone {
			z, err := s.zone(ctx, tx, zoneID)
			if err != nil || !z.enabled {
				continue
			}
			var active, published *Key
			for _, k := range zk {
				switch {
				case k.State == StateRetired && k.RetireAt != nil && !now.Before(*k.RetireAt):
					if _, err := tx.ExecContext(ctx, `DELETE FROM dnssec_keys WHERE id = ?`, k.ID); err != nil {
						return err
					}
					changed = true
				case k.Role == ZSK && k.State == StateActive:
					active = k
				case k.Role == ZSK && k.State == StatePublished:
					published = k
				}
			}
			if published != nil && published.ActiveAt != nil && !now.Before(*published.ActiveAt) {
				if _, err := tx.ExecContext(ctx, `UPDATE dnssec_keys SET state = ? WHERE id = ?`, StateActive, published.ID); err != nil {
					return err
				}
				if active != nil {
					if _, err := tx.ExecContext(ctx, `UPDATE dnssec_keys SET state = ?, retire_at = ? WHERE id = ?`, StateRetired,
						ms(now.Add(RetireDelay)), active.ID); err != nil {
						return err
					}
				}
				changed = true
				continue
			}
			if published == nil && active != nil && active.ActiveAt != nil && !now.Before(active.ActiveAt.Add(ZSKLifetime)) {
				if err := s.newKey(ctx, tx, z, ZSK, StatePublished, now.Add(PrePublish)); err != nil {
					return err
				}
				changed = true
			}
		}
		return nil
	})
	return changed, err
}

// Export returns the keys of a zone in BIND format (public and private).
func (s *Store) Export(ctx context.Context, zoneID string) (string, error) {
	z, err := s.zone(ctx, s.db, zoneID)
	if err != nil {
		return "", err
	}
	ks, err := s.keys(ctx, s.db, zoneID, true)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; Clés DNSSEC de la zone %s, exportées par Leazone le %s\n", z.name, s.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "; CONFIDENTIEL : ce fichier contient les clés privées.\n")
	for _, k := range ks {
		fmt.Fprintf(&b, "\n; ---- K%s+%03d+%05d (%s, %s) ----\n", dns.Fqdn(z.name), k.Algorithm, k.KeyTag, strings.ToUpper(k.Role), k.State)
		fmt.Fprintf(&b, "; .key\n%s\n; .private\n%s", k.DNSKEYStr, k.private)
		if !strings.HasSuffix(k.private, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

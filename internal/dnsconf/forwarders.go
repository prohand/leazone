package dnsconf

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Forwarder protocols.
const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"
	ProtoDoT = "dot"
	ProtoDoH = "doh"
)

// Forwarder is an upstream resolver, global (Domain == "") or conditional.
type Forwarder struct {
	ID            string    `json:"id"`
	Domain        string    `json:"domain"`
	Position      int       `json:"position"`
	Protocol      string    `json:"protocol"`
	Address       string    `json:"address"`
	Port          int       `json:"port"`
	TLSServerName string    `json:"tlsServerName"`
	TLSVerify     bool      `json:"tlsVerify"`
	DoHURL        string    `json:"dohUrl"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"-"`
	UpdatedAt     time.Time `json:"-"`
}

// ForwarderInput is what a user provides.
type ForwarderInput struct {
	Domain        string `json:"domain"`
	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	Port          int    `json:"port"`
	TLSServerName string `json:"tlsServerName"`
	TLSVerify     *bool  `json:"tlsVerify"`
	DoHURL        string `json:"dohUrl"`
	Enabled       *bool  `json:"enabled"`
	Position      *int   `json:"position"`
}

// ValidateForwarder normalizes an input into a Forwarder (without id/position).
func ValidateForwarder(in ForwarderInput) (Forwarder, error) {
	errs := Validation{}
	f := Forwarder{Protocol: strings.ToLower(strings.TrimSpace(in.Protocol)), Port: in.Port,
		TLSServerName: strings.ToLower(strings.TrimSpace(in.TLSServerName)), TLSVerify: true, Enabled: true,
		DoHURL: strings.TrimSpace(in.DoHURL)}
	if in.TLSVerify != nil {
		f.TLSVerify = *in.TLSVerify
	}
	if in.Enabled != nil {
		f.Enabled = *in.Enabled
	}
	if d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), ".")); d != "" {
		if err := checkHostname(d, false); err != nil {
			errs["domain"] = err.Error()
		}
		f.Domain = d
	}
	addr := strings.Trim(strings.TrimSpace(in.Address), "[]")
	if addr != "" {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			errs["address"] = "adresse IP attendue (ex : 9.9.9.9)"
		} else {
			f.Address = ip.Unmap().String()
		}
	}
	switch f.Protocol {
	case ProtoUDP, ProtoTCP:
		if addr == "" {
			errs["address"] = "adresse IP obligatoire"
		}
		if f.Port == 0 {
			f.Port = 53
		}
		f.TLSServerName, f.DoHURL = "", ""
	case ProtoDoT:
		if addr == "" {
			errs["address"] = "adresse IP obligatoire"
		}
		if f.Port == 0 {
			f.Port = 853
		}
		f.DoHURL = ""
		if f.TLSServerName != "" {
			if err := checkHostname(f.TLSServerName, false); err != nil {
				errs["tlsServerName"] = err.Error()
			}
		}
	case ProtoDoH:
		u, err := url.Parse(f.DoHURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			errs["dohUrl"] = "URL https://… attendue (ex : https://dns.quad9.net/dns-query)"
			break
		}
		host := u.Hostname()
		if _, err := netip.ParseAddr(host); err != nil && addr == "" {
			errs["address"] = "indiquez l'IP de démarrage du serveur DoH (Leazone ne peut pas résoudre son nom tout seul)"
		}
		if f.Port == 0 {
			f.Port = 443
			if p := u.Port(); p != "" {
				f.Port = atoi(p)
			}
		}
		if f.Address == "" {
			f.Address = host
		}
		if f.TLSServerName == "" {
			f.TLSServerName = strings.ToLower(host)
		}
	default:
		errs["protocol"] = "protocole attendu : udp, tcp, dot ou doh"
	}
	if f.Port < 1 || f.Port > 65535 {
		errs["port"] = "port entre 1 et 65535"
	}
	if len(errs) > 0 {
		return f, errs
	}
	return f, nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

const fwdCols = `id, domain, position, protocol, address, port, tls_server_name, tls_verify, doh_url, enabled, created_at, updated_at`

func scanFwd(row interface{ Scan(...any) error }) (*Forwarder, error) {
	var f Forwarder
	var verify, enabled int
	var c, u int64
	err := row.Scan(&f.ID, &f.Domain, &f.Position, &f.Protocol, &f.Address, &f.Port, &f.TLSServerName, &verify, &f.DoHURL, &enabled, &c, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.TLSVerify, f.Enabled = verify != 0, enabled != 0
	f.CreatedAt, f.UpdatedAt = time.UnixMilli(c), time.UnixMilli(u)
	return &f, nil
}

// Forwarders lists all forwarders, global first, then by domain and position.
func (s *Store) Forwarders(ctx context.Context) ([]*Forwarder, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+fwdCols+` FROM forwarders ORDER BY domain, position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Forwarder
	for rows.Next() {
		f, err := scanFwd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Forwarder returns one forwarder.
func (s *Store) Forwarder(ctx context.Context, id string) (*Forwarder, error) {
	return scanFwd(s.db.QueryRowContext(ctx, `SELECT `+fwdCols+` FROM forwarders WHERE id = ?`, id))
}

// CreateForwarder adds a forwarder at the end of its group (or at Position).
func (s *Store) CreateForwarder(ctx context.Context, in ForwarderInput) (*Forwarder, error) {
	f, err := ValidateForwarder(in)
	if err != nil {
		return nil, err
	}
	f.ID = ids.New()
	now := s.Now().UnixMilli()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM forwarders WHERE domain = ?`, f.Domain).Scan(&n); err != nil {
			return err
		}
		f.Position = n
		if _, err := tx.ExecContext(ctx, `INSERT INTO forwarders(`+fwdCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, f.Domain, f.Position, f.Protocol, f.Address, f.Port, f.TLSServerName, b2i(f.TLSVerify), f.DoHURL, b2i(f.Enabled), now, now); err != nil {
			return err
		}
		if in.Position != nil {
			return reorder(ctx, tx, f.Domain, f.ID, *in.Position)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Forwarder(ctx, f.ID)
}

// UpdateForwarder replaces a forwarder; Position moves it inside its group.
func (s *Store) UpdateForwarder(ctx context.Context, id string, in ForwarderInput) (*Forwarder, error) {
	old, err := s.Forwarder(ctx, id)
	if err != nil {
		return nil, err
	}
	f, err := ValidateForwarder(in)
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		pos := old.Position
		if f.Domain != old.Domain {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM forwarders WHERE domain = ?`, f.Domain).Scan(&n); err != nil {
				return err
			}
			pos = n
		}
		if _, err := tx.ExecContext(ctx, `UPDATE forwarders SET domain = ?, position = ?, protocol = ?, address = ?, port = ?,
			tls_server_name = ?, tls_verify = ?, doh_url = ?, enabled = ?, updated_at = ? WHERE id = ?`,
			f.Domain, pos, f.Protocol, f.Address, f.Port, f.TLSServerName, b2i(f.TLSVerify), f.DoHURL, b2i(f.Enabled),
			s.Now().UnixMilli(), id); err != nil {
			return err
		}
		if f.Domain != old.Domain {
			if err := reorder(ctx, tx, old.Domain, "", -1); err != nil {
				return err
			}
		}
		if in.Position != nil {
			return reorder(ctx, tx, f.Domain, id, *in.Position)
		}
		return reorder(ctx, tx, f.Domain, "", -1)
	})
	if err != nil {
		return nil, err
	}
	return s.Forwarder(ctx, id)
}

// DeleteForwarder removes a forwarder and compacts positions.
func (s *Store) DeleteForwarder(ctx context.Context, id string) error {
	f, err := s.Forwarder(ctx, id)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM forwarders WHERE id = ?`, id); err != nil {
			return err
		}
		return reorder(ctx, tx, f.Domain, "", -1)
	})
}

// reorder renumbers a group 0..n-1, moving id to position pos (pos < 0: keep order).
func reorder(ctx context.Context, tx *sql.Tx, domain, id string, pos int) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM forwarders WHERE domain = ? ORDER BY position, created_at`, domain)
	if err != nil {
		return err
	}
	var list []string
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			rows.Close()
			return err
		}
		if x != id || pos < 0 {
			list = append(list, x)
		}
	}
	rows.Close()
	if id != "" && pos >= 0 {
		if pos > len(list) {
			pos = len(list)
		}
		list = append(list[:pos], append([]string{id}, list[pos:]...)...)
	}
	for i, x := range list {
		if _, err := tx.ExecContext(ctx, `UPDATE forwarders SET position = ? WHERE id = ?`, i, x); err != nil {
			return err
		}
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

package dhcpconf

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Reservation pins an IP to a MAC address or a client identifier.
type Reservation struct {
	ID          string    `json:"id"`
	ScopeID     string    `json:"scopeId"`
	ScopeName   string    `json:"scopeName"`
	MAC         string    `json:"mac"`
	ClientID    string    `json:"clientId"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

func (r *Reservation) label() string {
	if r.Hostname != "" {
		return r.Hostname
	}
	if r.MAC != "" {
		return r.MAC
	}
	return r.ClientID
}

// ReservationInput is what a user provides.
type ReservationInput struct {
	ScopeID     string `json:"scopeId"`
	MAC         string `json:"mac"`
	ClientID    string `json:"clientId"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Description string `json:"description"`
}

// Hostname sanitizes a DHCP host name into a DNS label ("" if unusable).
func Hostname(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == ' ':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}

func (s *Store) validateReservation(ctx context.Context, in ReservationInput, exceptID string) (Reservation, error) {
	errs := Validation{}
	r := Reservation{ScopeID: in.ScopeID, Description: strings.TrimSpace(in.Description)}
	sc, err := s.Scope(ctx, in.ScopeID)
	if err != nil {
		errs["scopeId"] = "étendue inconnue"
		return r, errs
	}
	r.ScopeName = sc.Name
	if r.MAC, err = NormalizeMAC(in.MAC); err != nil {
		errs["mac"] = err.Error()
	}
	if r.ClientID, _, err = NormalizeHex(in.ClientID); err != nil {
		errs["clientId"] = "identifiant client en hexadécimal (ex : 01:aa:bb:cc:dd:ee:ff)"
	}
	if r.MAC == "" && r.ClientID == "" && errs["mac"] == "" {
		errs["mac"] = "adresse MAC ou identifiant client obligatoire"
	}
	a, err := parseV4(in.IP)
	p := sc.Prefix()
	switch {
	case err != nil:
		errs["ip"] = err.Error()
	case !p.Contains(a) || a == p.Masked().Addr() || a == Broadcast(p):
		errs["ip"] = "l'adresse doit être dans le réseau " + sc.Network
	case a.String() == sc.Gateway:
		errs["ip"] = "c'est l'adresse de la passerelle"
	default:
		r.IP = a.String()
	}
	if h := strings.TrimSpace(in.Hostname); h != "" {
		r.Hostname = Hostname(h)
		if r.Hostname == "" {
			errs["hostname"] = "nom d'hôte invalide"
		}
	}
	if len(errs) > 0 {
		return r, errs
	}
	// Uniqueness inside the scope: IP, MAC and client id.
	list, err := s.Reservations(ctx, in.ScopeID)
	if err != nil {
		return r, err
	}
	for _, o := range list {
		if o.ID == exceptID {
			continue
		}
		switch {
		case o.IP == r.IP:
			return r, ErrConflict{Msg: "l'adresse " + r.IP + " est déjà réservée pour " + o.label()}
		case r.MAC != "" && o.MAC == r.MAC:
			return r, ErrConflict{Msg: "cette adresse MAC a déjà une réservation (" + o.IP + ")"}
		case r.ClientID != "" && o.ClientID == r.ClientID:
			return r, ErrConflict{Msg: "cet identifiant client a déjà une réservation (" + o.IP + ")"}
		}
	}
	return r, nil
}

// CreateReservation validates and inserts a reservation.
func (s *Store) CreateReservation(ctx context.Context, in ReservationInput) (*Reservation, error) {
	r, err := s.validateReservation(ctx, in, "")
	if err != nil {
		return nil, err
	}
	r.ID = ids.New()
	now := s.Now().UnixMilli()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO dhcp_reservations(id, scope_id, mac, client_id, ip, hostname, description,
		created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, r.ScopeID, r.MAC, r.ClientID, r.IP, r.Hostname,
		r.Description, now, now); err != nil {
		return nil, err
	}
	return s.Reservation(ctx, r.ID)
}

// UpdateReservation replaces a reservation.
func (s *Store) UpdateReservation(ctx context.Context, id string, in ReservationInput) (*Reservation, error) {
	if _, err := s.Reservation(ctx, id); err != nil {
		return nil, err
	}
	r, err := s.validateReservation(ctx, in, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE dhcp_reservations SET scope_id = ?, mac = ?, client_id = ?, ip = ?, hostname = ?,
		description = ?, updated_at = ? WHERE id = ?`, r.ScopeID, r.MAC, r.ClientID, r.IP, r.Hostname, r.Description,
		s.Now().UnixMilli(), id); err != nil {
		return nil, err
	}
	return s.Reservation(ctx, id)
}

// DeleteReservation removes a reservation.
func (s *Store) DeleteReservation(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dhcp_reservations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

const resCols = `r.id, r.scope_id, s.name, r.mac, r.client_id, r.ip, r.hostname, r.description, r.created_at`

func scanRes(row interface{ Scan(...any) error }) (*Reservation, error) {
	var r Reservation
	var c int64
	err := row.Scan(&r.ID, &r.ScopeID, &r.ScopeName, &r.MAC, &r.ClientID, &r.IP, &r.Hostname, &r.Description, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	r.CreatedAt = time.UnixMilli(c)
	return &r, err
}

// Reservation returns one reservation.
func (s *Store) Reservation(ctx context.Context, id string) (*Reservation, error) {
	return scanRes(s.db.QueryRowContext(ctx, `SELECT `+resCols+` FROM dhcp_reservations r JOIN dhcp_scopes s ON s.id = r.scope_id
		WHERE r.id = ?`, id))
}

// Reservations lists the reservations of a scope ("" = all scopes).
func (s *Store) Reservations(ctx context.Context, scopeID string) ([]*Reservation, error) {
	q := `SELECT ` + resCols + ` FROM dhcp_reservations r JOIN dhcp_scopes s ON s.id = r.scope_id`
	var args []any
	if scopeID != "" {
		q += ` WHERE r.scope_id = ?`
		args = append(args, scopeID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY s.name, r.ip`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Reservation
	for rows.Next() {
		r, err := scanRes(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	// Sort numerically by IP within a scope (SQL sorts text).
	sortByIP(out)
	return out, rows.Err()
}

func sortByIP(list []*Reservation) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && less(list[j], list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func less(a, b *Reservation) bool {
	if a.ScopeName != b.ScopeName {
		return a.ScopeName < b.ScopeName
	}
	x, _ := netip.ParseAddr(a.IP)
	y, _ := netip.ParseAddr(b.IP)
	return x.Less(y)
}

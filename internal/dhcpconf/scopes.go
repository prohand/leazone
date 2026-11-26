package dhcpconf

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Store gives access to the DHCP configuration tables.
type Store struct {
	db  *store.DB
	Now func() time.Time
}

// New returns a Store.
func New(db *store.DB) *Store { return &Store{db: db, Now: time.Now} }

// Validation and conflict errors reuse the DNS types so the API maps them the same way.
type (
	Validation  = dnsconf.Validation
	ErrConflict = dnsconf.ErrConflict
)

// Range is an inclusive address range.
type Range struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Scope is a DHCP scope (one IPv4 network).
type Scope struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	VLANID         *int      `json:"vlanId"`
	VLANName       string    `json:"vlanName"`
	Enabled        bool      `json:"enabled"`
	Network        string    `json:"network"`
	RangeStart     string    `json:"rangeStart"`
	RangeEnd       string    `json:"rangeEnd"`
	Exclusions     []Range   `json:"exclusions"`
	LeaseTime      uint32    `json:"leaseTime"`
	Gateway        string    `json:"gateway"`
	DNSServers     []string  `json:"dnsServers"`
	Domain         string    `json:"domain"`
	NTPServers     []string  `json:"ntpServers"`
	Options        []Option  `json:"options"`
	Interface      *string   `json:"interface"`
	Relay          bool      `json:"relay"`
	RelayAgents    []string  `json:"relayAgents"`
	DDNSEnabled    bool      `json:"ddnsEnabled"`
	DDNSDomain     string    `json:"ddnsDomain"`
	PingCheck      bool      `json:"pingCheck"`
	AlertThreshold int       `json:"alertThreshold"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// ScopeInput is what a user provides.
type ScopeInput struct {
	Name           string   `json:"name"`
	VLANID         *int     `json:"vlanId"`
	Enabled        *bool    `json:"enabled"`
	Network        string   `json:"network"`
	RangeStart     string   `json:"rangeStart"`
	RangeEnd       string   `json:"rangeEnd"`
	Exclusions     []Range  `json:"exclusions"`
	LeaseTime      uint32   `json:"leaseTime"`
	Gateway        string   `json:"gateway"`
	DNSServers     []string `json:"dnsServers"`
	Domain         string   `json:"domain"`
	NTPServers     []string `json:"ntpServers"`
	Options        []Option `json:"options"`
	Interface      *string  `json:"interface"`
	Relay          bool     `json:"relay"`
	RelayAgents    []string `json:"relayAgents"`
	DDNSEnabled    *bool    `json:"ddnsEnabled"`
	DDNSDomain     string   `json:"ddnsDomain"`
	PingCheck      bool     `json:"pingCheck"`
	AlertThreshold int      `json:"alertThreshold"`
}

// Mode tells how the scope is served.
func (s *Scope) Mode() string {
	direct := s.Interface != nil && *s.Interface != ""
	switch {
	case direct && s.Relay:
		return "both"
	case direct:
		return "direct"
	case s.Relay:
		return "relay"
	}
	return "none"
}

// Prefix returns the parsed network.
func (s *Scope) Prefix() netip.Prefix { p, _ := netip.ParsePrefix(s.Network); return p }

// MaxScopeSize bounds the pool size (allocator memory, UI).
const MaxScopeSize = 65536

func ipList(field string, in []string, errs Validation) []string {
	out := []string{}
	for i, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		a, err := parseV4(s)
		if err != nil {
			errs[fmt.Sprintf("%s[%d]", field, i)] = err.Error()
			continue
		}
		out = append(out, a.String())
	}
	return out
}

// ValidateScope checks an input without saving it (used by imports).
func (s *Store) ValidateScope(ctx context.Context, in ScopeInput) error {
	sc, err := validate(in)
	if err != nil {
		return err
	}
	return s.checkOverlap(ctx, sc, "")
}

// validate normalizes an input into a scope (without id/timestamps).
func validate(in ScopeInput) (Scope, error) {
	errs := Validation{}
	sc := Scope{Name: strings.TrimSpace(in.Name), VLANID: in.VLANID, Enabled: true, LeaseTime: in.LeaseTime,
		Domain: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), ".")), Relay: in.Relay,
		DDNSEnabled: true, PingCheck: in.PingCheck, AlertThreshold: in.AlertThreshold, Exclusions: []Range{}, Options: []Option{}}
	if in.Enabled != nil {
		sc.Enabled = *in.Enabled
	}
	if in.DDNSEnabled != nil {
		sc.DDNSEnabled = *in.DDNSEnabled
	}
	if sc.Name == "" || len(sc.Name) > 64 {
		errs["name"] = "nom obligatoire (64 caractères max)"
	}
	if sc.VLANID != nil && (*sc.VLANID < 1 || *sc.VLANID > 4094) {
		errs["vlanId"] = "VLAN entre 1 et 4094"
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(in.Network))
	if err != nil || !p.Addr().Is4() {
		errs["network"] = "réseau IPv4 attendu (ex : 192.168.20.0/24)"
	} else if p.Bits() < 8 || p.Bits() > 30 {
		errs["network"] = "préfixe entre /8 et /30"
	} else {
		p = p.Masked()
		sc.Network = p.String()
	}
	start, err1 := parseV4(in.RangeStart)
	end, err2 := parseV4(in.RangeEnd)
	if err1 != nil {
		errs["rangeStart"] = err1.Error()
	}
	if err2 != nil {
		errs["rangeEnd"] = err2.Error()
	}
	inNet := func(a netip.Addr) bool {
		return sc.Network != "" && p.Contains(a) && a != p.Addr() && a != Broadcast(p)
	}
	if err1 == nil && err2 == nil && sc.Network != "" {
		switch {
		case !inNet(start):
			errs["rangeStart"] = "doit être dans le réseau (hors adresse réseau et broadcast)"
		case !inNet(end):
			errs["rangeEnd"] = "doit être dans le réseau (hors adresse réseau et broadcast)"
		case U32(end) < U32(start):
			errs["rangeEnd"] = "doit être après le début de la plage"
		case U32(end)-U32(start)+1 > MaxScopeSize:
			errs["rangeEnd"] = fmt.Sprintf("plage trop grande (%d adresses max)", MaxScopeSize)
		}
		sc.RangeStart, sc.RangeEnd = start.String(), end.String()
	}
	for i, ex := range in.Exclusions {
		a, e1 := parseV4(ex.Start)
		b, e2 := parseV4(ex.End)
		if e1 != nil || e2 != nil || U32(b) < U32(a) {
			errs[fmt.Sprintf("exclusions[%d]", i)] = "plage d'exclusion invalide"
			continue
		}
		if sc.RangeStart != "" && (U32(a) < U32(start) || U32(b) > U32(end)) {
			errs[fmt.Sprintf("exclusions[%d]", i)] = "l'exclusion doit être dans la plage"
			continue
		}
		sc.Exclusions = append(sc.Exclusions, Range{a.String(), b.String()})
	}
	if sc.LeaseTime == 0 {
		sc.LeaseTime = 86400
	}
	if sc.LeaseTime < 60 || sc.LeaseTime > 365*86400 {
		errs["leaseTime"] = "entre 60 secondes et 365 jours"
	}
	if g := strings.TrimSpace(in.Gateway); g != "" {
		a, err := parseV4(g)
		switch {
		case err != nil:
			errs["gateway"] = err.Error()
		case sc.Network != "" && !inNet(a):
			errs["gateway"] = "la passerelle doit être dans le réseau"
		case sc.RangeStart != "" && U32(a) >= U32(start) && U32(a) <= U32(end) && !excluded(sc.Exclusions, a):
			errs["gateway"] = "la passerelle est dans la plage distribuée : ajoutez une exclusion"
		default:
			sc.Gateway = a.String()
		}
	}
	sc.DNSServers = ipList("dnsServers", in.DNSServers, errs)
	sc.NTPServers = ipList("ntpServers", in.NTPServers, errs)
	sc.RelayAgents = ipList("relayAgents", in.RelayAgents, errs)
	seen := map[int]bool{}
	for i, o := range in.Options {
		o.Type = strings.ToLower(strings.TrimSpace(o.Type))
		if _, err := o.Encode(); err != nil {
			errs[fmt.Sprintf("options[%d].value", i)] = err.Error()
			continue
		}
		if seen[o.Code] {
			errs[fmt.Sprintf("options[%d].code", i)] = "option en double"
			continue
		}
		seen[o.Code] = true
		sc.Options = append(sc.Options, o)
	}
	if in.Interface != nil && strings.TrimSpace(*in.Interface) != "" {
		v := strings.TrimSpace(*in.Interface)
		sc.Interface = &v
	}
	if sc.Domain != "" {
		if _, _, err := dnsconf.NormalizeZoneName(sc.Domain); err != nil {
			errs["domain"] = err.Error()
		}
	}
	sc.DDNSDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.DDNSDomain), "."))
	if sc.DDNSDomain == "" {
		sc.DDNSDomain = sc.Domain
	}
	if sc.DDNSEnabled {
		if sc.DDNSDomain == "" {
			errs["ddnsDomain"] = "indiquez le domaine pour l'enregistrement DNS automatique (ex : invites.lan)"
		} else if _, _, err := dnsconf.NormalizeZoneName(sc.DDNSDomain); err != nil {
			errs["ddnsDomain"] = err.Error()
		}
	}
	if sc.AlertThreshold == 0 {
		sc.AlertThreshold = 80
	}
	if sc.AlertThreshold < 1 || sc.AlertThreshold > 100 {
		errs["alertThreshold"] = "entre 1 et 100 %"
	}
	if len(errs) > 0 {
		return sc, errs
	}
	return sc, nil
}

func excluded(ex []Range, a netip.Addr) bool {
	v := U32(a)
	for _, r := range ex {
		s, _ := netip.ParseAddr(r.Start)
		e, _ := netip.ParseAddr(r.End)
		if v >= U32(s) && v <= U32(e) {
			return true
		}
	}
	return false
}

// Excluded reports whether a is in one of the scope exclusions.
func (s *Scope) Excluded(a netip.Addr) bool { return excluded(s.Exclusions, a) }

// InRange reports whether a is inside the distributed range.
func (s *Scope) InRange(a netip.Addr) bool {
	st, _ := netip.ParseAddr(s.RangeStart)
	en, _ := netip.ParseAddr(s.RangeEnd)
	return a.Is4() && U32(a) >= U32(st) && U32(a) <= U32(en)
}

const scopeCols = `s.id, s.name, s.vlan_id, s.enabled, s.network, s.range_start, s.range_end, s.exclusions, s.lease_time,
	s.gateway, s.dns_servers, s.domain, s.ntp_servers, s.options, s.if_name, s.relay, s.relay_agents, s.ddns_enabled,
	s.ddns_domain, s.ping_check, s.alert_threshold, s.created_at, s.updated_at, COALESCE(v.name, '')`

func scanScope(row interface{ Scan(...any) error }) (*Scope, error) {
	var sc Scope
	var vlan sql.NullInt64
	var iface sql.NullString
	var en, relay, ddns, ping int
	var ex, dnsS, ntp, opts, agents string
	var c, u int64
	err := row.Scan(&sc.ID, &sc.Name, &vlan, &en, &sc.Network, &sc.RangeStart, &sc.RangeEnd, &ex, &sc.LeaseTime,
		&sc.Gateway, &dnsS, &sc.Domain, &ntp, &opts, &iface, &relay, &agents, &ddns, &sc.DDNSDomain, &ping,
		&sc.AlertThreshold, &c, &u, &sc.VLANName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if vlan.Valid {
		v := int(vlan.Int64)
		sc.VLANID = &v
	}
	if iface.Valid && iface.String != "" {
		sc.Interface = &iface.String
	}
	sc.Enabled, sc.Relay, sc.DDNSEnabled, sc.PingCheck = en != 0, relay != 0, ddns != 0, ping != 0
	for _, x := range []struct {
		raw string
		dst any
	}{{ex, &sc.Exclusions}, {dnsS, &sc.DNSServers}, {ntp, &sc.NTPServers}, {opts, &sc.Options}, {agents, &sc.RelayAgents}} {
		if err := json.Unmarshal([]byte(x.raw), x.dst); err != nil {
			return nil, err
		}
	}
	sc.CreatedAt, sc.UpdatedAt = time.UnixMilli(c), time.UnixMilli(u)
	return &sc, nil
}

const scopeFrom = ` FROM dhcp_scopes s LEFT JOIN vlans v ON v.vlan_id = s.vlan_id`

// Scopes lists all scopes sorted by VLAN then name.
func (s *Store) Scopes(ctx context.Context) ([]*Scope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scopeCols+scopeFrom+` ORDER BY COALESCE(s.vlan_id, 0), s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Scope
	for rows.Next() {
		sc, err := scanScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// Scope returns one scope.
func (s *Store) Scope(ctx context.Context, id string) (*Scope, error) {
	return scanScope(s.db.QueryRowContext(ctx, `SELECT `+scopeCols+scopeFrom+` WHERE s.id = ?`, id))
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

// checkOverlap refuses two scopes with overlapping networks (isolation).
func (s *Store) checkOverlap(ctx context.Context, sc Scope, exceptID string) error {
	all, err := s.Scopes(ctx)
	if err != nil {
		return err
	}
	p := sc.Prefix()
	for _, o := range all {
		if o.ID == exceptID {
			continue
		}
		if o.Name == sc.Name {
			return ErrConflict{Msg: "une étendue porte déjà ce nom"}
		}
		if o.Prefix().Overlaps(p) {
			return ErrConflict{Msg: fmt.Sprintf("le réseau %s chevauche l'étendue « %s » (%s)", sc.Network, o.Name, o.Network)}
		}
	}
	return nil
}

func (s *Store) ensureVLAN(ctx context.Context, tx *sql.Tx, vlanID *int, name string) error {
	if vlanID == nil {
		return nil
	}
	now := s.Now().UnixMilli()
	_, err := tx.ExecContext(ctx, `INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(vlan_id) DO NOTHING`, ids.New(), *vlanID, name, now, now)
	return err
}

// CreateScope validates and inserts a scope.
func (s *Store) CreateScope(ctx context.Context, in ScopeInput) (*Scope, error) {
	sc, err := validate(in)
	if err != nil {
		return nil, err
	}
	if err := s.checkOverlap(ctx, sc, ""); err != nil {
		return nil, err
	}
	sc.ID = ids.New()
	now := s.Now().UnixMilli()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.ensureVLAN(ctx, tx, sc.VLANID, sc.Name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO dhcp_scopes(id, name, vlan_id, enabled, network, range_start, range_end,
			exclusions, lease_time, gateway, dns_servers, domain, ntp_servers, options, if_name, relay, relay_agents,
			ddns_enabled, ddns_domain, ping_check, alert_threshold, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sc.ID, sc.Name, sc.VLANID, b2i(sc.Enabled), sc.Network, sc.RangeStart, sc.RangeEnd, js(sc.Exclusions),
			sc.LeaseTime, sc.Gateway, js(sc.DNSServers), sc.Domain, js(sc.NTPServers), js(sc.Options), sc.Interface,
			b2i(sc.Relay), js(sc.RelayAgents), b2i(sc.DDNSEnabled), sc.DDNSDomain, b2i(sc.PingCheck), sc.AlertThreshold, now, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Scope(ctx, sc.ID)
}

// UpdateScope replaces a scope. Leases outside the new range are kept until
// they expire; reservations must stay inside the network.
func (s *Store) UpdateScope(ctx context.Context, id string, in ScopeInput) (*Scope, error) {
	if _, err := s.Scope(ctx, id); err != nil {
		return nil, err
	}
	sc, err := validate(in)
	if err != nil {
		return nil, err
	}
	if err := s.checkOverlap(ctx, sc, id); err != nil {
		return nil, err
	}
	res, err := s.Reservations(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		if a, _ := netip.ParseAddr(r.IP); !sc.Prefix().Contains(a) {
			return nil, ErrConflict{Msg: fmt.Sprintf("la réservation %s (%s) serait hors du nouveau réseau", r.IP, r.label())}
		}
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.ensureVLAN(ctx, tx, sc.VLANID, sc.Name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE dhcp_scopes SET name = ?, vlan_id = ?, enabled = ?, network = ?, range_start = ?,
			range_end = ?, exclusions = ?, lease_time = ?, gateway = ?, dns_servers = ?, domain = ?, ntp_servers = ?, options = ?,
			if_name = ?, relay = ?, relay_agents = ?, ddns_enabled = ?, ddns_domain = ?, ping_check = ?, alert_threshold = ?,
			updated_at = ? WHERE id = ?`,
			sc.Name, sc.VLANID, b2i(sc.Enabled), sc.Network, sc.RangeStart, sc.RangeEnd, js(sc.Exclusions), sc.LeaseTime,
			sc.Gateway, js(sc.DNSServers), sc.Domain, js(sc.NTPServers), js(sc.Options), sc.Interface, b2i(sc.Relay),
			js(sc.RelayAgents), b2i(sc.DDNSEnabled), sc.DDNSDomain, b2i(sc.PingCheck), sc.AlertThreshold, s.Now().UnixMilli(), id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Scope(ctx, id)
}

// DeleteScope removes a scope with its reservations and leases.
func (s *Store) DeleteScope(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dhcp_scopes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

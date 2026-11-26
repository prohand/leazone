// Package blocking blocks ads and trackers at the DNS level: lists
// downloaded by URL (hosts, plain domains, AdBlock), a manual blacklist and
// whitelist (the whitelist always wins), policies saying where blocking
// applies (interface, VLAN, client network), a temporary pause and
// statistics.
package blocking

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Settings keys.
const (
	SettingsKey = "blocking"
	PauseKey    = "blocking_pause"
)

// Response modes.
const (
	ModeNXDomain = "nxdomain"
	ModeNullIP   = "null-ip"
)

// Settings of the module.
type Settings struct {
	ResponseMode   string `json:"responseMode"`
	RefreshHours   int    `json:"refreshHours"`
	DefaultEnabled bool   `json:"defaultEnabled"`
}

// DefaultSettings: NXDOMAIN, daily refresh, blocking everywhere.
func DefaultSettings() Settings {
	return Settings{ResponseMode: ModeNXDomain, RefreshHours: 24, DefaultEnabled: true}
}

// Validate checks the settings.
func (s *Settings) Validate() error {
	errs := dnsconf.Validation{}
	if s.ResponseMode == "" {
		s.ResponseMode = ModeNXDomain
	}
	if s.ResponseMode != ModeNXDomain && s.ResponseMode != ModeNullIP {
		errs["responseMode"] = "nxdomain ou null-ip"
	}
	if s.RefreshHours < 1 || s.RefreshHours > 168 {
		errs["refreshHours"] = "entre 1 et 168 heures"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Pause is a replicated setting: both nodes stop blocking until Until.
type Pause struct {
	Until int64 `json:"until"` // unix ms, 0 = not paused
}

// List is a subscribed block list.
type List struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Format    string     `json:"format"`
	Enabled   bool       `json:"enabled"`
	FetchedAt *time.Time `json:"fetchedAt"`
	Entries   int        `json:"entries"`
	Error     string     `json:"error"`
}

// ListInput is what a user provides.
type ListInput struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Enabled *bool  `json:"enabled"`
}

// Rule is a manual blacklist (deny) or whitelist (allow) entry.
type Rule struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Kind      string    `json:"kind"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"createdAt"`
}

// Policy turns blocking on or off for a target.
type Policy struct {
	ID         string `json:"id"`
	TargetKind string `json:"targetKind"`
	Target     string `json:"target"`
	Enabled    bool   `json:"enabled"`
	Comment    string `json:"comment"`
}

// Store gives access to the blocking tables.
type Store struct {
	db  *store.DB
	Now func() time.Time
}

// NewStore returns a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db, Now: time.Now} }

// ErrNotFound is returned for unknown ids.
var ErrNotFound = store.ErrNotFound

// Settings returns the settings or the defaults.
func (s *Store) Settings(ctx context.Context) (Settings, error) {
	st := DefaultSettings()
	_, err := s.db.GetSetting(ctx, SettingsKey, &st)
	return st, err
}

// SetSettings validates and stores the settings.
func (s *Store) SetSettings(ctx context.Context, st Settings) (Settings, error) {
	if err := st.Validate(); err != nil {
		return st, err
	}
	return st, s.db.PutSetting(ctx, SettingsKey, st)
}

// Pause returns the pause end (zero time = not paused).
func (s *Store) Pause(ctx context.Context) (time.Time, error) {
	var p Pause
	if _, err := s.db.GetSetting(ctx, PauseKey, &p); err != nil || p.Until == 0 {
		return time.Time{}, err
	}
	return time.UnixMilli(p.Until), nil
}

// SetPause pauses blocking for d (0 = resume now).
func (s *Store) SetPause(ctx context.Context, d time.Duration) (time.Time, error) {
	var until time.Time
	if d > 0 {
		until = s.Now().Add(d)
	}
	p := Pause{}
	if !until.IsZero() {
		p.Until = until.UnixMilli()
	}
	return until, s.db.PutSetting(ctx, PauseKey, p)
}

// ---- lists ----

func (in *ListInput) validate() error {
	errs := dnsconf.Validation{}
	in.Name = strings.TrimSpace(in.Name)
	in.URL = strings.TrimSpace(in.URL)
	if in.Name == "" || len(in.Name) > 100 {
		errs["name"] = "nom requis (100 caractères maximum)"
	}
	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs["url"] = "adresse http:// ou https:// requise"
	}
	switch in.Format {
	case "":
		in.Format = FormatAuto
	case FormatAuto, FormatHosts, FormatDomains, FormatAdblock:
	default:
		errs["format"] = "auto, hosts, domains ou adblock"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

const listCols = `l.id, l.name, l.url, l.format, l.enabled, s.fetched_at, COALESCE(s.entries, 0), COALESCE(s.error, '')`

func scanList(sc interface{ Scan(...any) error }) (*List, error) {
	var l List
	var en int
	var fetched sql.NullInt64
	if err := sc.Scan(&l.ID, &l.Name, &l.URL, &l.Format, &en, &fetched, &l.Entries, &l.Error); err != nil {
		return nil, err
	}
	l.Enabled = en != 0
	if fetched.Valid {
		t := time.UnixMilli(fetched.Int64).UTC()
		l.FetchedAt = &t
	}
	return &l, nil
}

// Lists returns all lists, by name.
func (s *Store) Lists(ctx context.Context) ([]*List, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+listCols+` FROM block_lists l
		LEFT JOIN block_list_state s ON s.list_id = l.id ORDER BY l.name COLLATE NOCASE, l.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*List{}
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// List returns one list.
func (s *Store) List(ctx context.Context, id string) (*List, error) {
	l, err := scanList(s.db.QueryRowContext(ctx, `SELECT `+listCols+` FROM block_lists l
		LEFT JOIN block_list_state s ON s.list_id = l.id WHERE l.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return l, err
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// CreateList adds a list.
func (s *Store) CreateList(ctx context.Context, in ListInput) (*List, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	id, now := ids.New(), s.Now().UnixMilli()
	en := in.Enabled == nil || *in.Enabled
	_, err := s.db.ExecContext(ctx, `INSERT INTO block_lists(id, name, url, format, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, in.Name, in.URL, in.Format, b2i(en), now, now)
	if isUnique(err) {
		return nil, dnsconf.ErrConflict{Msg: "cette liste est déjà abonnée"}
	}
	if err != nil {
		return nil, err
	}
	return s.List(ctx, id)
}

// UpdateList changes a list.
func (s *Store) UpdateList(ctx context.Context, id string, in ListInput) (*List, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	cur, err := s.List(ctx, id)
	if err != nil {
		return nil, err
	}
	en := cur.Enabled
	if in.Enabled != nil {
		en = *in.Enabled
	}
	_, err = s.db.ExecContext(ctx, `UPDATE block_lists SET name = ?, url = ?, format = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		in.Name, in.URL, in.Format, b2i(en), s.Now().UnixMilli(), id)
	if isUnique(err) {
		return nil, dnsconf.ErrConflict{Msg: "cette liste est déjà abonnée"}
	}
	if err != nil {
		return nil, err
	}
	if cur.URL != in.URL || cur.Format != in.Format {
		// Content changed: forget the download state.
		if _, err := s.db.ExecContext(ctx, `DELETE FROM block_list_state WHERE list_id = ?`, id); err != nil {
			return nil, err
		}
	}
	return s.List(ctx, id)
}

// DeleteList removes a list.
func (s *Store) DeleteList(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM block_lists WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM block_list_state WHERE list_id = ?`, id)
	return err
}

// SetListState records a download result (local table).
func (s *Store) SetListState(ctx context.Context, id string, fetched *time.Time, entries int, errMsg string) error {
	var f any
	if fetched != nil {
		f = fetched.UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO block_list_state(list_id, fetched_at, entries, error) VALUES (?, ?, ?, ?)
		ON CONFLICT(list_id) DO UPDATE SET fetched_at = COALESCE(excluded.fetched_at, fetched_at),
		entries = excluded.entries, error = excluded.error`, id, f, entries, errMsg)
	return err
}

// ---- rules ----

// NormalizeDomain lowercases a domain and checks its syntax ("*." and a
// trailing dot are accepted and removed).
func NormalizeDomain(in string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || strings.ContainsAny(d, " /:@") {
		return "", false
	}
	if _, ok := dns.IsDomainName(d); !ok {
		return "", false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" {
			return "", false
		}
	}
	return d, true
}

// Rules returns the manual rules ("" = both kinds).
func (s *Store) Rules(ctx context.Context, kind string) ([]*Rule, error) {
	q := `SELECT id, domain, kind, comment, created_at FROM block_rules`
	var args []any
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY domain, kind`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Rule{}
	for rows.Next() {
		var r Rule
		var c int64
		if err := rows.Scan(&r.ID, &r.Domain, &r.Kind, &r.Comment, &c); err != nil {
			return nil, err
		}
		r.CreatedAt = time.UnixMilli(c).UTC()
		out = append(out, &r)
	}
	return out, rows.Err()
}

// AddRule adds a manual rule.
func (s *Store) AddRule(ctx context.Context, domain, kind, comment string) (*Rule, error) {
	errs := dnsconf.Validation{}
	d, ok := NormalizeDomain(domain)
	if !ok {
		errs["domain"] = "nom de domaine invalide"
	}
	if kind != "allow" && kind != "deny" {
		errs["kind"] = "allow ou deny"
	}
	if len(comment) > 200 {
		errs["comment"] = "200 caractères maximum"
	}
	if len(errs) > 0 {
		return nil, errs
	}
	r := &Rule{ID: ids.New(), Domain: d, Kind: kind, Comment: strings.TrimSpace(comment), CreatedAt: s.Now().UTC().Truncate(time.Millisecond)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO block_rules(id, domain, kind, comment, created_at) VALUES (?, ?, ?, ?, ?)`,
		r.ID, r.Domain, r.Kind, r.Comment, r.CreatedAt.UnixMilli())
	if isUnique(err) {
		return nil, dnsconf.ErrConflict{Msg: "ce domaine est déjà dans la liste"}
	}
	return r, err
}

// DeleteRule removes a manual rule.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM block_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- policies ----

func (p *Policy) validate() error {
	errs := dnsconf.Validation{}
	p.Target = strings.TrimSpace(p.Target)
	switch p.TargetKind {
	case "interface":
		if p.Target == "" || len(p.Target) > 15 || strings.ContainsAny(p.Target, " /") {
			errs["target"] = "nom d'interface invalide"
		}
	case "vlan":
		n, err := strconv.Atoi(p.Target)
		if err != nil || n < 1 || n > 4094 {
			errs["target"] = "numéro de VLAN entre 1 et 4094"
		} else {
			p.Target = strconv.Itoa(n)
		}
	case "network":
		pf, err := netip.ParsePrefix(p.Target)
		if err != nil {
			a, aerr := netip.ParseAddr(p.Target)
			if aerr != nil {
				errs["target"] = "réseau invalide (ex. 192.168.20.0/24)"
				break
			}
			pf = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		p.Target = pf.Masked().String()
	default:
		errs["targetKind"] = "interface, vlan ou network"
	}
	if len(p.Comment) > 200 {
		errs["comment"] = "200 caractères maximum"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Policies returns all policies.
func (s *Store) Policies(ctx context.Context) ([]*Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, target_kind, target, enabled, comment FROM block_policies ORDER BY target_kind, target`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Policy{}
	for rows.Next() {
		var p Policy
		var en int
		if err := rows.Scan(&p.ID, &p.TargetKind, &p.Target, &en, &p.Comment); err != nil {
			return nil, err
		}
		p.Enabled = en != 0
		out = append(out, &p)
	}
	return out, rows.Err()
}

// SavePolicy creates (id == "") or updates a policy.
func (s *Store) SavePolicy(ctx context.Context, id string, p Policy) (*Policy, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	now := s.Now().UnixMilli()
	var err error
	var res sql.Result
	if id == "" {
		p.ID = ids.New()
		_, err = s.db.ExecContext(ctx, `INSERT INTO block_policies(id, target_kind, target, enabled, comment, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, p.ID, p.TargetKind, p.Target, b2i(p.Enabled), p.Comment, now, now)
	} else {
		p.ID = id
		res, err = s.db.ExecContext(ctx, `UPDATE block_policies SET target_kind = ?, target = ?, enabled = ?, comment = ?, updated_at = ?
			WHERE id = ?`, p.TargetKind, p.Target, b2i(p.Enabled), p.Comment, now, id)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				return nil, ErrNotFound
			}
		}
	}
	if isUnique(err) {
		return nil, dnsconf.ErrConflict{Msg: "une règle existe déjà pour cette cible"}
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// DeletePolicy removes a policy.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM block_policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

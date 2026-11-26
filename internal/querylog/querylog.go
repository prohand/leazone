// Package querylog stores the DNS query log and the DHCP event log of this
// node in their own SQLite file (/data/logs.db). It is not replicated:
// each node logs what it served. Writes are batched in the background and
// dropped (and counted) when the server is too busy, so logging never
// slows down DNS or DHCP. Old entries go away by age and by size.
package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // driver

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/store"
)

// SettingsKey is the replicated settings key.
const SettingsKey = "logs"

// Settings of the logs.
type Settings struct {
	DNSQueries    bool `json:"dnsQueries"`
	DHCPEvents    bool `json:"dhcpEvents"`
	RetentionDays int  `json:"retentionDays"`
	MaxSizeMB     int  `json:"maxSizeMb"`
}

// DefaultSettings: everything logged, 7 days, 500 MB.
func DefaultSettings() Settings {
	return Settings{DNSQueries: true, DHCPEvents: true, RetentionDays: 7, MaxSizeMB: 500}
}

// Validate checks the settings.
func (s Settings) Validate() error {
	errs := dnsconf.Validation{}
	if s.RetentionDays < 1 || s.RetentionDays > 365 {
		errs["retentionDays"] = "entre 1 et 365 jours"
	}
	if s.MaxSizeMB < 10 || s.MaxSizeMB > 100000 {
		errs["maxSizeMb"] = "entre 10 et 100000 Mo"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// LoadSettings reads the settings from the main database.
func LoadSettings(ctx context.Context, db *store.DB) (Settings, error) {
	s := DefaultSettings()
	_, err := db.GetSetting(ctx, SettingsKey, &s)
	return s, err
}

// DNSEntry is one DNS query.
type DNSEntry struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Client    string    `json:"client"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Rcode     string    `json:"rcode"`
	Source    string    `json:"source"`
	LatencyMs float64   `json:"latencyMs"`
	Answer    string    `json:"answer"`
}

// DHCPEntry is one DHCP event.
type DHCPEntry struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Event     string    `json:"event"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	ScopeID   string    `json:"scopeId"`
	ScopeName string    `json:"scopeName"`
	Interface string    `json:"interface"`
	Relay     string    `json:"relay"`
	Detail    string    `json:"detail"`
}

const schema = `
PRAGMA auto_vacuum = INCREMENTAL;
CREATE TABLE IF NOT EXISTS dns_queries (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    client  TEXT NOT NULL,
    name    TEXT NOT NULL,
    qtype   TEXT NOT NULL,
    rcode   TEXT NOT NULL,
    source  TEXT NOT NULL,
    latency INTEGER NOT NULL, -- microseconds
    answer  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dns_queries_ts ON dns_queries(ts);
CREATE TABLE IF NOT EXISTS dhcp_events (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    event      TEXT NOT NULL,
    mac        TEXT NOT NULL,
    ip         TEXT NOT NULL,
    hostname   TEXT NOT NULL,
    scope_id   TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    iface      TEXT NOT NULL,
    relay      TEXT NOT NULL,
    detail     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dhcp_events_ts ON dhcp_events(ts);
`

// Log is the log database with its background writer.
type Log struct {
	db   *sql.DB
	path string
	log  *slog.Logger
	Now  func() time.Time

	settings atomic.Pointer[Settings]
	dnsCh    chan DNSEntry
	dhcpCh   chan DHCPEntry
	dropped  atomic.Uint64
	wg       sync.WaitGroup
}

// Open opens (or creates) the log database.
func Open(path string, log *slog.Logger) (*Log, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	for _, st := range strings.Split(schema, ";") {
		if strings.TrimSpace(st) == "" {
			continue
		}
		if _, err := db.Exec(st); err != nil {
			db.Close()
			return nil, fmt.Errorf("logs.db: %w", err)
		}
	}
	l := &Log{db: db, path: path, log: log, Now: time.Now, dnsCh: make(chan DNSEntry, 20000), dhcpCh: make(chan DHCPEntry, 2000)}
	st := DefaultSettings()
	l.settings.Store(&st)
	return l, nil
}

// SetSettings applies new settings.
func (l *Log) SetSettings(s Settings) { l.settings.Store(&s) }

// Settings returns the settings in use.
func (l *Log) Settings() Settings { return *l.settings.Load() }

// AddDNS queues a DNS query (never blocks).
func (l *Log) AddDNS(e DNSEntry) {
	if !l.settings.Load().DNSQueries {
		return
	}
	select {
	case l.dnsCh <- e:
	default:
		l.dropped.Add(1)
	}
}

// AddDHCP queues a DHCP event (never blocks).
func (l *Log) AddDHCP(e DHCPEntry) {
	if !l.settings.Load().DHCPEvents {
		return
	}
	select {
	case l.dhcpCh <- e:
	default:
		l.dropped.Add(1)
	}
}

// Run writes queued entries in batches and applies the retention until
// ctx is done.
func (l *Log) Run(ctx context.Context) {
	flush := time.NewTicker(500 * time.Millisecond)
	defer flush.Stop()
	clean := time.NewTicker(10 * time.Minute)
	defer clean.Stop()
	var dnsBuf []DNSEntry
	var dhcpBuf []DHCPEntry
	write := func() {
		if len(dnsBuf)+len(dhcpBuf) == 0 {
			return
		}
		if err := l.write(dnsBuf, dhcpBuf); err != nil {
			l.log.Warn("log write failed", "err", err)
			l.dropped.Add(uint64(len(dnsBuf) + len(dhcpBuf)))
		}
		dnsBuf, dhcpBuf = dnsBuf[:0], dhcpBuf[:0]
	}
	l.Cleanup(ctx)
	for {
		select {
		case <-ctx.Done():
			// Drain what is queued.
			for {
				select {
				case e := <-l.dnsCh:
					dnsBuf = append(dnsBuf, e)
				case e := <-l.dhcpCh:
					dhcpBuf = append(dhcpBuf, e)
				default:
					write()
					l.db.Close()
					return
				}
			}
		case e := <-l.dnsCh:
			dnsBuf = append(dnsBuf, e)
			if len(dnsBuf) >= 2000 {
				write()
			}
		case e := <-l.dhcpCh:
			dhcpBuf = append(dhcpBuf, e)
		case <-flush.C:
			write()
		case <-clean.C:
			write()
			l.Cleanup(ctx)
		}
	}
}

// Flush writes what is queued now (tests, purge).
func (l *Log) Flush() {
	var d []DNSEntry
	var h []DHCPEntry
	for {
		select {
		case e := <-l.dnsCh:
			d = append(d, e)
		case e := <-l.dhcpCh:
			h = append(h, e)
		default:
			if err := l.write(d, h); err != nil {
				l.log.Warn("log write failed", "err", err)
			}
			return
		}
	}
}

func (l *Log) write(dnsBuf []DNSEntry, dhcpBuf []DHCPEntry) error {
	if len(dnsBuf)+len(dhcpBuf) == 0 {
		return nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(dnsBuf) > 0 {
		st, err := tx.Prepare(`INSERT INTO dns_queries(ts, client, name, qtype, rcode, source, latency, answer) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		for _, e := range dnsBuf {
			if _, err := st.Exec(e.Time.UnixMilli(), e.Client, e.Name, e.Type, e.Rcode, e.Source, int64(e.LatencyMs*1000), e.Answer); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}
	for _, e := range dhcpBuf {
		if _, err := tx.Exec(`INSERT INTO dhcp_events(ts, event, mac, ip, hostname, scope_id, scope_name, iface, relay, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, e.Time.UnixMilli(), e.Event, e.MAC, e.IP, e.Hostname, e.ScopeID, e.ScopeName,
			e.Interface, e.Relay, e.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (l *Log) size() int64 {
	var pages, size int64
	_ = l.db.QueryRow(`PRAGMA page_count`).Scan(&pages)
	_ = l.db.QueryRow(`PRAGMA page_size`).Scan(&size)
	var free int64
	_ = l.db.QueryRow(`PRAGMA freelist_count`).Scan(&free)
	return (pages - free) * size
}

// Cleanup removes entries older than the retention, then the oldest ones
// while the file is over its maximum size.
func (l *Log) Cleanup(ctx context.Context) {
	st := l.Settings()
	cut := l.Now().Add(-time.Duration(st.RetentionDays) * 24 * time.Hour).UnixMilli()
	for _, t := range []string{"dns_queries", "dhcp_events"} {
		if _, err := l.db.ExecContext(ctx, `DELETE FROM `+t+` WHERE ts < ?`, cut); err != nil {
			l.log.Warn("log cleanup", "err", err)
			return
		}
	}
	max := int64(st.MaxSizeMB) << 20
	for i := 0; i < 20 && l.size() > max; i++ {
		// Remove the oldest 10 % of DNS queries (by far the largest table).
		var n int64
		_ = l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_queries`).Scan(&n)
		if n < 10 {
			break
		}
		if _, err := l.db.ExecContext(ctx, `DELETE FROM dns_queries WHERE id <= (SELECT id FROM dns_queries ORDER BY id LIMIT 1 OFFSET ?)`, n/10); err != nil {
			break
		}
	}
	_, _ = l.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	_, _ = l.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
}

// Purge empties both logs.
func (l *Log) Purge(ctx context.Context) error {
	l.Flush()
	for _, t := range []string{"dns_queries", "dhcp_events"} {
		if _, err := l.db.ExecContext(ctx, `DELETE FROM `+t); err != nil {
			return err
		}
	}
	_, _ = l.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	_, err := l.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Status describes the log database.
type Status struct {
	DNSEntries  int64      `json:"dnsEntries"`
	DHCPEntries int64      `json:"dhcpEntries"`
	SizeBytes   int64      `json:"sizeBytes"`
	Oldest      *time.Time `json:"oldest"`
	Dropped     uint64     `json:"dropped"`
}

// Dropped is the number of entries not written since start.
func (l *Log) Dropped() uint64 { return l.dropped.Load() }

// Status returns counts and size.
func (l *Log) Status(ctx context.Context) (Status, error) {
	var s Status
	if err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_queries`).Scan(&s.DNSEntries); err != nil {
		return s, err
	}
	if err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dhcp_events`).Scan(&s.DHCPEntries); err != nil {
		return s, err
	}
	var o sql.NullInt64
	_ = l.db.QueryRowContext(ctx, `SELECT MIN(ts) FROM (SELECT MIN(ts) AS ts FROM dns_queries UNION ALL SELECT MIN(ts) FROM dhcp_events)`).Scan(&o)
	if o.Valid {
		t := time.UnixMilli(o.Int64).UTC()
		s.Oldest = &t
	}
	s.SizeBytes = l.size()
	if fi, err := os.Stat(l.path + "-wal"); err == nil {
		s.SizeBytes += fi.Size()
	}
	s.Dropped = l.dropped.Load()
	return s, nil
}

// ---- queries ----

// DNSFilter selects DNS entries.
type DNSFilter struct {
	Q, Type, Rcode, Source string
	Client                 netip.Prefix // invalid = any
	From, To               time.Time
	Before                 int64
	Limit                  int
}

// DNS returns entries, newest first, and the cursor of the next page.
func (l *Log) DNS(ctx context.Context, f DNSFilter) ([]DNSEntry, *int64, error) {
	var where []string
	var args []any
	if f.Q != "" {
		where = append(where, `name LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(strings.ToLower(f.Q))+"%")
	}
	for col, v := range map[string]string{"qtype": strings.ToUpper(f.Type), "rcode": strings.ToUpper(f.Rcode), "source": f.Source} {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	if f.Client.IsValid() {
		if f.Client.IsSingleIP() {
			where = append(where, "client = ?")
			args = append(args, f.Client.Addr().String())
		} else {
			// Text prefix narrows the scan; the exact check is done below.
			where = append(where, "client LIKE ?")
			args = append(args, commonTextPrefix(f.Client)+"%")
		}
	}
	where, args = timeFilter(where, args, f.From, f.To, f.Before)
	limit := clampLimit(f.Limit)
	q := `SELECT id, ts, client, name, qtype, rcode, source, latency, answer FROM dns_queries`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	scanLimit := limit + 1
	if f.Client.IsValid() && !f.Client.IsSingleIP() {
		scanLimit = limit * 20 // prefix filter is approximate
	}
	rows, err := l.db.QueryContext(ctx, q, append(args, scanLimit)...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := []DNSEntry{}
	var next *int64
	for rows.Next() {
		var e DNSEntry
		var ts, lat int64
		if err := rows.Scan(&e.ID, &ts, &e.Client, &e.Name, &e.Type, &e.Rcode, &e.Source, &lat, &e.Answer); err != nil {
			return nil, nil, err
		}
		if f.Client.IsValid() && !f.Client.IsSingleIP() {
			if a, err := netip.ParseAddr(e.Client); err != nil || !f.Client.Contains(a) {
				continue
			}
		}
		if len(out) == limit {
			id := out[len(out)-1].ID
			next = &id
			break
		}
		e.Time, e.LatencyMs = time.UnixMilli(ts).UTC(), float64(lat)/1000
		out = append(out, e)
	}
	return out, next, rows.Err()
}

// DHCPFilter selects DHCP entries.
type DHCPFilter struct {
	Q, Event, Scope string
	From, To        time.Time
	Before          int64
	Limit           int
}

// DHCP returns entries, newest first.
func (l *Log) DHCP(ctx context.Context, f DHCPFilter) ([]DHCPEntry, *int64, error) {
	var where []string
	var args []any
	if f.Q != "" {
		p := "%" + likeEscape(strings.ToLower(f.Q)) + "%"
		where = append(where, `(lower(mac) LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\' OR lower(hostname) LIKE ? ESCAPE '\')`)
		args = append(args, p, p, p)
	}
	if f.Event != "" {
		where = append(where, "event = ?")
		args = append(args, f.Event)
	}
	if f.Scope != "" {
		where = append(where, "scope_id = ?")
		args = append(args, f.Scope)
	}
	where, args = timeFilter(where, args, f.From, f.To, f.Before)
	limit := clampLimit(f.Limit)
	q := `SELECT id, ts, event, mac, ip, hostname, scope_id, scope_name, iface, relay, detail FROM dhcp_events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := l.db.QueryContext(ctx, q+" ORDER BY id DESC LIMIT ?", append(args, limit+1)...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := []DHCPEntry{}
	var next *int64
	for rows.Next() {
		var e DHCPEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.MAC, &e.IP, &e.Hostname, &e.ScopeID, &e.ScopeName, &e.Interface, &e.Relay, &e.Detail); err != nil {
			return nil, nil, err
		}
		if len(out) == limit {
			id := out[len(out)-1].ID
			next = &id
			break
		}
		e.Time = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	return out, next, rows.Err()
}

func timeFilter(where []string, args []any, from, to time.Time, before int64) ([]string, []any) {
	if !from.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, from.UnixMilli())
	}
	if !to.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, to.UnixMilli())
	}
	if before > 0 {
		where = append(where, "id < ?")
		args = append(args, before)
	}
	return where, args
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return min(n, 500)
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// commonTextPrefix returns the text all addresses of p start with
// ("192.168.20." for 192.168.20.0/24, "" when nothing is common).
func commonTextPrefix(p netip.Prefix) string {
	if !p.Addr().Is4() {
		return ""
	}
	b := p.Masked().Addr().As4()
	full := p.Bits() / 8
	var parts []string
	for i := 0; i < full; i++ {
		parts = append(parts, fmt.Sprint(b[i]))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ".") + "."
}

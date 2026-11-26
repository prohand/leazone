// Package store wraps the SQLite database: opening, migrations and
// pre-migration backups. Table access lives next to the features that use it.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver, registered as "sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is the application database.
type DB struct {
	*sql.DB
	Path string
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Open opens (and creates if needed) the database file.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)" +
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time; a small pool keeps reads concurrent
	// while busy_timeout + immediate transactions serialize writes safely.
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &DB{DB: db, Path: path}, nil
}

// Migration is one numbered schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

var migName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$`)

// Migrations returns the embedded migrations sorted by version.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	byVer := map[int]*Migration{}
	for _, e := range entries {
		m := migName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("bad migration file name %q", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		mg := byVer[v]
		if mg == nil {
			mg = &Migration{Version: v, Name: m[2]}
			byVer[v] = mg
		}
		if m[3] == "up" {
			mg.Up = string(b)
		} else {
			mg.Down = string(b)
		}
	}
	out := make([]Migration, 0, len(byVer))
	for _, m := range byVer {
		if m.Up == "" || m.Down == "" {
			return nil, fmt.Errorf("migration %04d needs both up and down files", m.Version)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous, missing %04d", i+1)
		}
	}
	return out, nil
}

// LatestSchema is the schema version this binary expects.
func LatestSchema() int {
	m, err := Migrations()
	if err != nil || len(m) == 0 {
		return 0
	}
	return m[len(m)-1].Version
}

func (db *DB) ensureMigrationTable(ctx context.Context) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`)
	return err
}

// SchemaVersion returns the current schema version (0 for an empty database).
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	if err := db.ensureMigrationTable(ctx); err != nil {
		return 0, err
	}
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

// Migrate brings the schema to the latest version. When the database already
// has data, a copy is saved in backupDir first.
func (db *DB) Migrate(ctx context.Context, backupDir string, log *slog.Logger) error {
	migs, err := Migrations()
	if err != nil {
		return err
	}
	cur, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	latest := migs[len(migs)-1].Version
	if cur > latest {
		return fmt.Errorf("database schema %d is newer than this Leazone version (expects %d): "+
			"run 'leazone migrate down --to %d' with the newer version first, or restore a backup from %s",
			cur, latest, latest, backupDir)
	}
	if cur == latest {
		return nil
	}
	if cur > 0 {
		dst, err := db.Backup(ctx, backupDir, fmt.Sprintf("s%d", cur))
		if err != nil {
			return fmt.Errorf("backup before migration: %w", err)
		}
		log.Info("database backed up before migration", "file", dst)
	}
	for _, m := range migs[cur:] {
		if err := db.apply(ctx, nil, m.Up, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
				m.Version, m.Name, time.Now().UnixMilli())
			return err
		}); err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
		}
		log.Info("migration applied", "version", m.Version, "name", m.Name)
	}
	return nil
}

// MigrateDown reverts migrations until the schema is at version target.
func (db *DB) MigrateDown(ctx context.Context, target int, backupDir string, log *slog.Logger) error {
	migs, err := Migrations()
	if err != nil {
		return err
	}
	cur, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if target < 0 || target >= cur {
		return fmt.Errorf("target %d must be lower than the current schema %d", target, cur)
	}
	if cur > len(migs) {
		return fmt.Errorf("schema %d is unknown to this binary", cur)
	}
	dst, err := db.Backup(ctx, backupDir, fmt.Sprintf("s%d", cur))
	if err != nil {
		return err
	}
	log.Info("database backed up before downgrade", "file", dst)
	for v := cur; v > target; v-- {
		m := migs[v-1]
		// Replication triggers (repl_*, generated at startup from the live
		// schema by cluster/repl) name columns and tables that a down
		// script may drop: remove them first. The binary that runs on the
		// older schema recreates the ones it needs.
		if err := db.apply(ctx, dropReplTriggers, m.Down, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = ?`, v)
			return err
		}); err != nil {
			return fmt.Errorf("revert %04d_%s: %w", m.Version, m.Name, err)
		}
		log.Info("migration reverted", "version", m.Version, "name", m.Name)
	}
	return nil
}

func (db *DB) apply(ctx context.Context, pre func(context.Context, *sql.Tx) error, script string, record func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if pre != nil {
		if err := pre(ctx, tx); err != nil {
			return err
		}
	}
	for _, stmt := range splitSQL(script) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w\n--- statement ---\n%s", err, stmt)
		}
	}
	if err := record(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// dropReplTriggers drops every replication trigger (named repl_*).
func dropReplTriggers(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'repl\_%' ESCAPE '\'`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS "`+strings.ReplaceAll(n, `"`, `""`)+`"`); err != nil {
			return err
		}
	}
	return nil
}

// splitSQL splits a script on ";" at end of line, ignoring "--" comments.
// Migrations must not contain ";" inside string literals at end of line.
func splitSQL(script string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(script, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
		if strings.HasSuffix(t, ";") {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// Backup writes a consistent copy of the database with VACUUM INTO and keeps
// the 5 most recent copies in dir.
func (db *DB) Backup(ctx context.Context, dir, tag string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	name := fmt.Sprintf("leazone-%s-%s.db", time.Now().UTC().Format("20060102T150405Z"), tag)
	dst := filepath.Join(dir, name)
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return "", err
	}
	_ = os.Chmod(dst, 0o600)
	pruneBackups(dir, 5)
	return dst, nil
}

func pruneBackups(dir string, keep int) {
	matches, _ := filepath.Glob(filepath.Join(dir, "leazone-*.db"))
	sort.Strings(matches) // names start with a sortable UTC timestamp
	for len(matches) > keep {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
}

// Tx runs fn in a write transaction.
func (db *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Meta returns a value from the meta table ("" when missing).
func (db *DB) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetMeta stores a value in the meta table.
func (db *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

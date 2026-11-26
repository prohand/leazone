// Package backup writes the whole configuration to one YAML file and
// restores it. Secret columns (TOTP secrets, DNSSEC and TLS private keys)
// stay encrypted with the data key; the data key itself is encrypted with
// a key derived from the backup password (Argon2id). An HMAC over the
// tables, keyed by the data key, detects any change to the file.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"

	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/version"
)

// Format identifies the file format.
const Format = "leazone-backup/1"

// MinPassword is the minimum password length.
const MinPassword = 12

// Errors shown to users.
var (
	ErrPassword    = errors.New("mot de passe incorrect (ou fichier modifié)")
	ErrFormat      = errors.New("ce fichier n'est pas une sauvegarde Leazone")
	ErrNewerSchema = errors.New("sauvegarde faite par une version plus récente de Leazone : mettez Leazone à jour d'abord")
	ErrShort       = fmt.Errorf("mot de passe trop court (%d caractères minimum)", MinPassword)
)

// KDF parameters (stored in the file so they can evolve).
type KDF struct {
	Name      string `yaml:"name"`
	Time      uint32 `yaml:"time"`
	MemoryKiB uint32 `yaml:"memoryKiB"`
	Threads   uint8  `yaml:"threads"`
	Salt      string `yaml:"salt"`
}

// File is the backup document.
type File struct {
	Format    string                      `yaml:"format"`
	Version   string                      `yaml:"version"`
	Schema    int                         `yaml:"schema"`
	CreatedAt time.Time                   `yaml:"createdAt"`
	Node      string                      `yaml:"node"`
	KDF       KDF                         `yaml:"kdf"`
	Key       string                      `yaml:"key"` // data key, AES-GCM with the password key
	MAC       string                      `yaml:"mac"` // HMAC-SHA256 of the tables (data key)
	Tables    map[string][]map[string]any `yaml:"tables"`
}

// Service makes and restores backups.
type Service struct {
	DB   *store.DB
	Repl *repl.Store
	Box  *secrets.Box
	Node string
	// WrapDEK seals the data key for storage in meta (local master key).
	WrapDEK func(dek []byte) string
	// Argon2 cost (tests lower it).
	Time      uint32
	MemoryKiB uint32
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func deriveKey(password string, k KDF) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil || k.Name != "argon2id" || k.Time == 0 || k.MemoryKiB < 8 || k.Threads == 0 || k.MemoryKiB > 4<<20 || k.Time > 20 {
		return nil, ErrFormat
	}
	return argon2.IDKey([]byte(password), salt, k.Time, k.MemoryKiB, k.Threads, 32), nil
}

// tablesMAC authenticates the tables with a key derived from the DEK.
func tablesMAC(dek []byte, tables map[string][]map[string]any) (string, error) {
	names := make([]string, 0, len(tables))
	for n := range tables {
		names = append(names, n)
	}
	sort.Strings(names)
	mk := hmac.New(sha256.New, dek)
	mk.Write([]byte("leazone-backup-mac"))
	m := hmac.New(sha256.New, mk.Sum(nil))
	for _, n := range names {
		b, err := json.Marshal(normalizeRows(tables[n]))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(m, "%s\n%s\n", n, b)
	}
	return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// normalizeRows makes values stable across JSON and YAML (numbers as
// int64 or float64, the rest as is).
func normalizeRows(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		m := make(map[string]any, len(r))
		for k, v := range r {
			switch x := v.(type) {
			case json.Number:
				if n, err := x.Int64(); err == nil {
					v = n
				} else {
					f, _ := x.Float64()
					v = f
				}
			case int:
				v = int64(x)
			case uint64:
				v = int64(x)
			}
			m[k] = v
		}
		out[i] = m
	}
	return out
}

// Create returns the backup file of the current configuration.
func (s *Service) Create(ctx context.Context, password string) ([]byte, error) {
	if len([]rune(password)) < MinPassword {
		return nil, ErrShort
	}
	tables, err := s.Repl.Export(ctx)
	if err != nil {
		return nil, err
	}
	for n, rows := range tables {
		tables[n] = normalizeRows(rows)
	}
	schema, err := s.DB.SchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	t, m := s.Time, s.MemoryKiB
	if t == 0 {
		t, m = 3, 64*1024
	}
	kdf := KDF{Name: "argon2id", Time: t, MemoryKiB: m, Threads: 4, Salt: base64.StdEncoding.EncodeToString(salt)}
	key, err := deriveKey(password, kdf)
	if err != nil {
		return nil, err
	}
	dek := s.Box.Key()
	sealed, err := seal(key, dek)
	if err != nil {
		return nil, err
	}
	mac, err := tablesMAC(dek, tables)
	if err != nil {
		return nil, err
	}
	f := File{Format: Format, Version: version.Version, Schema: schema, CreatedAt: s.now().UTC().Truncate(time.Second),
		Node: s.Node, KDF: kdf, Key: sealed, MAC: mac, Tables: tables}
	body, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# Sauvegarde Leazone du %s (nœud %s).\n# Restauration : Paramètres > Sauvegarde, ou « leazone restore <fichier> ».\n"+
		"# Les secrets sont chiffrés ; sans le mot de passe ce fichier ne peut pas être restauré.\n",
		f.CreatedAt.Format("2006-01-02 15:04 UTC"), s.Node)
	return append([]byte(head), body...), nil
}

func seal(key, plain []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, plain, []byte("leazone-backup-dek"))), nil
}

func open(key []byte, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, ErrFormat
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < g.NonceSize() {
		return nil, ErrFormat
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("leazone-backup-dek"))
	if err != nil {
		return nil, ErrPassword
	}
	return pt, nil
}

// Result describes a (checked or applied) restore.
type Result struct {
	DryRun    bool           `json:"dryRun"`
	CreatedAt time.Time      `json:"createdAt"`
	Version   string         `json:"version"`
	Node      string         `json:"node"`
	Tables    map[string]int `json:"tables"`
	// KeyChanged: the data key of the backup replaced the current one.
	KeyChanged bool `json:"-"`
}

// Open checks a backup file with its password and returns its content and
// data key.
func (s *Service) Open(ctx context.Context, data []byte, password string) (*File, []byte, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil || f.Format != Format {
		return nil, nil, ErrFormat
	}
	schema, err := s.DB.SchemaVersion(ctx)
	if err != nil {
		return nil, nil, err
	}
	if f.Schema > schema {
		return nil, nil, ErrNewerSchema
	}
	key, err := deriveKey(password, f.KDF)
	if err != nil {
		return nil, nil, err
	}
	dek, err := open(key, f.Key)
	if err != nil {
		return nil, nil, err
	}
	if len(dek) != 32 {
		return nil, nil, ErrFormat
	}
	for n, rows := range f.Tables {
		f.Tables[n] = normalizeRows(rows)
	}
	mac, err := tablesMAC(dek, f.Tables)
	if err != nil {
		return nil, nil, err
	}
	if !hmac.Equal([]byte(mac), []byte(f.MAC)) {
		return nil, nil, ErrPassword
	}
	return &f, dek, nil
}

// Restore replaces the configuration with the backup (dryRun: check only).
// After a real restore the caller reloads every service.
func (s *Service) Restore(ctx context.Context, data []byte, password string, dryRun bool) (*Result, error) {
	f, dek, err := s.Open(ctx, data, password)
	if err != nil {
		return nil, err
	}
	res := &Result{DryRun: dryRun, CreatedAt: f.CreatedAt, Version: f.Version, Node: f.Node, Tables: map[string]int{}}
	known := map[string]bool{}
	for _, n := range s.Repl.ConfigTableNames() {
		known[n] = true
		res.Tables[n] = len(f.Tables[n])
	}
	for n := range f.Tables {
		if !known[n] {
			return nil, fmt.Errorf("table inconnue dans la sauvegarde : %s", n)
		}
	}
	if dryRun {
		return res, nil
	}
	if f.Tables["users"] == nil || len(f.Tables["users"]) == 0 {
		return nil, errors.New("la sauvegarde ne contient aucun utilisateur : restauration refusée")
	}
	res.KeyChanged = !hmac.Equal(dek, s.Box.Key())
	err = s.Repl.Restore(ctx, f.Tables, func(tx *sql.Tx) error {
		if !res.KeyChanged {
			return nil
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES ('dek', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			s.WrapDEK(dek))
		return err
	})
	if err != nil {
		return nil, err
	}
	if res.KeyChanged {
		if err := s.Box.Replace(dek); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// ---- automatic backups ----

// AutoDir is where daily backups are kept.
func AutoDir(dataDir string) string { return filepath.Join(dataDir, "backups") }

// AutoKeep is the number of daily backups kept.
const AutoKeep = 7

// AutoFile describes a stored backup.
type AutoFile struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

// Auto writes today's backup if missing and removes the oldest ones.
func (s *Service) Auto(ctx context.Context, dataDir, password string) (string, error) {
	dir := AutoDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := "leazone-" + s.now().UTC().Format("20060102") + ".yaml"
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		return "", nil
	}
	data, err := s.Create(ctx, password)
	if err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	files, _ := ListAuto(dataDir)
	for i := AutoKeep; i < len(files); i++ {
		_ = os.Remove(filepath.Join(dir, files[i].Name))
	}
	return path, nil
}

// ListAuto lists stored backups, newest first.
func ListAuto(dataDir string) ([]AutoFile, error) {
	entries, err := os.ReadDir(AutoDir(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return []AutoFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []AutoFile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "leazone-") || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, AutoFile{Name: e.Name(), Size: fi.Size(), CreatedAt: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// ValidAutoName reports whether name is a stored backup file name.
func ValidAutoName(name string) bool {
	if !strings.HasPrefix(name, "leazone-") || !strings.HasSuffix(name, ".yaml") || strings.ContainsAny(name, "/\\") {
		return false
	}
	return filepath.Base(name) == name
}

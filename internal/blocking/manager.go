package blocking

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/modules"
	"github.com/prohand/leazone/internal/store"
)

// MaxListSize is the largest list accepted (bytes).
const MaxListSize = 100 << 20

// Manager loads the configuration into the engine and downloads the lists.
// Each node downloads on its own (lists are not replicated, only their
// subscription is).
type Manager struct {
	Store  *Store
	Engine *Engine
	db     *store.DB
	dir    string
	log    *slog.Logger
	Client *http.Client

	mu     sync.Mutex // serializes reloads
	dlMu   sync.Mutex // serializes downloads
	cache  map[string]cachedList
	wakeup chan struct{}
}

type cachedList struct {
	mod    time.Time
	size   int64
	format string
	parsed Parsed
}

// NewManager builds a manager storing downloads under dataDir/blocklists.
func NewManager(db *store.DB, engine *Engine, dataDir string, log *slog.Logger) *Manager {
	return &Manager{Store: NewStore(db), Engine: engine, db: db, dir: filepath.Join(dataDir, "blocklists"), log: log,
		Client: &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
		cache:  map[string]cachedList{}, wakeup: make(chan struct{}, 1)}
}

func (m *Manager) file(id string) string { return filepath.Join(m.dir, id+".txt") }

// Reload pushes the configuration to the engine. Lists never downloaded on
// this node are fetched in the background.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mods, err := modules.Get(ctx, m.db)
	if err != nil {
		return err
	}
	c := Config{Enabled: mods.Blocking}
	if c.Settings, err = m.Store.Settings(ctx); err != nil {
		return err
	}
	if c.Pause, err = m.Store.Pause(ctx); err != nil {
		return err
	}
	if c.Rules, err = m.Store.Rules(ctx, ""); err != nil {
		return err
	}
	if c.Policies, err = m.Store.Policies(ctx); err != nil {
		return err
	}
	lists, err := m.Store.Lists(ctx)
	if err != nil {
		return err
	}
	missing := false
	keep := map[string]bool{}
	if c.Enabled {
		for _, l := range lists {
			if !l.Enabled {
				continue
			}
			keep[l.ID] = true
			p, ok := m.parsed(l)
			if !ok {
				missing = true
				continue
			}
			c.Lists = append(c.Lists, NamedList{Name: l.Name, Parsed: p})
		}
	}
	for id := range m.cache {
		if !keep[id] {
			delete(m.cache, id) // free memory of removed/disabled lists
		}
	}
	m.Engine.Load(c)
	if missing {
		m.Wake()
	}
	return nil
}

// parsed returns the parsed content of a downloaded list (cached by file
// date, size and format).
func (m *Manager) parsed(l *List) (Parsed, bool) {
	fi, err := os.Stat(m.file(l.ID))
	if err != nil {
		return Parsed{}, false
	}
	if c, ok := m.cache[l.ID]; ok && c.mod.Equal(fi.ModTime()) && c.size == fi.Size() && c.format == l.Format {
		return c.parsed, true
	}
	f, err := os.Open(m.file(l.ID))
	if err != nil {
		return Parsed{}, false
	}
	defer f.Close()
	p, err := Parse(f, l.Format)
	if err != nil {
		m.log.Warn("block list unreadable", "list", l.Name, "err", err)
		return Parsed{}, false
	}
	m.cache[l.ID] = cachedList{mod: fi.ModTime(), size: fi.Size(), format: l.Format, parsed: p}
	return p, true
}

// Wake asks the background loop to download what is due now.
func (m *Manager) Wake() {
	select {
	case m.wakeup <- struct{}{}:
	default:
	}
}

// Refresh downloads the enabled lists (all, or only those due) and reloads.
func (m *Manager) Refresh(ctx context.Context, all bool) ([]*List, error) {
	m.dlMu.Lock()
	defer m.dlMu.Unlock()
	mods, err := modules.Get(ctx, m.db)
	if err != nil || !mods.Blocking {
		return nil, err
	}
	st, err := m.Store.Settings(ctx)
	if err != nil {
		return nil, err
	}
	lists, err := m.Store.Lists(ctx)
	if err != nil {
		return nil, err
	}
	changed := false
	for _, l := range lists {
		if !l.Enabled {
			continue
		}
		_, statErr := os.Stat(m.file(l.ID))
		due := all || statErr != nil || l.FetchedAt == nil ||
			time.Since(*l.FetchedAt) >= time.Duration(st.RefreshHours)*time.Hour
		if !due {
			continue
		}
		// A failed download is retried after 15 minutes, not in a loop.
		if !all && m.recentFailure(l.ID) {
			continue
		}
		n, err := m.download(ctx, l)
		now := time.Now()
		if err != nil {
			m.log.Warn("block list download failed", "list", l.Name, "url", l.URL, "err", err)
			m.noteFailure(l.ID)
			_ = m.Store.SetListState(ctx, l.ID, nil, l.Entries, err.Error())
			continue
		}
		m.log.Info("block list downloaded", "list", l.Name, "entries", n)
		_ = m.Store.SetListState(ctx, l.ID, &now, n, "")
		changed = true
	}
	if changed {
		if err := m.Reload(ctx); err != nil {
			return nil, err
		}
	}
	return m.Store.Lists(ctx)
}

var failures sync.Map // list id -> time of the last failure

func (m *Manager) noteFailure(id string) { failures.Store(id, time.Now()) }

func (m *Manager) recentFailure(id string) bool {
	v, ok := failures.Load(id)
	return ok && time.Since(v.(time.Time)) < 15*time.Minute
}

// download fetches a list into its file and returns its entry count.
func (m *Manager) download(ctx context.Context, l *List) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Leazone")
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("téléchargement impossible : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("le serveur a répondu %s", resp.Status)
	}
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(m.dir, l.ID+".*.tmp")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxListSize+1))
	if err == nil && n > MaxListSize {
		err = errors.New("liste trop grande (100 Mo maximum)")
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		return 0, err
	}
	p, err := Parse(f, l.Format)
	f.Close()
	if err != nil {
		return 0, err
	}
	if len(p.Deny)+len(p.Allow) == 0 {
		return 0, errors.New("aucun domaine reconnu : vérifiez l'adresse et le format")
	}
	if err := os.Rename(tmp.Name(), m.file(l.ID)); err != nil {
		return 0, err
	}
	return len(p.Deny) + len(p.Allow), nil
}

// Forget removes the downloaded file of a deleted list.
func (m *Manager) Forget(id string) { _ = os.Remove(m.file(id)) }

// Run refreshes lists when due and cleans files of deleted lists.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if _, err := m.Refresh(ctx, false); err != nil && ctx.Err() == nil {
			m.log.Warn("block lists refresh", "err", err)
		}
		m.cleanFiles(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wakeup:
		}
	}
}

func (m *Manager) cleanFiles(ctx context.Context) {
	lists, err := m.Store.Lists(ctx)
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, l := range lists {
		known[l.ID+".txt"] = true
	}
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if !known[e.Name()] && filepath.Ext(e.Name()) == ".txt" {
			_ = os.Remove(filepath.Join(m.dir, e.Name()))
		}
	}
}

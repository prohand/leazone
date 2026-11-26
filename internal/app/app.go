// Package app wires all components together and runs a node.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	apispec "github.com/prohand/leazone/api"

	"github.com/prohand/leazone/internal/api"
	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/blocking"
	"github.com/prohand/leazone/internal/caps"
	"github.com/prohand/leazone/internal/cluster"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/control"
	"github.com/prohand/leazone/internal/ddns"
	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpmgr"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnsmgr"
	"github.com/prohand/leazone/internal/dnssec"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/querylog"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/stats"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/tlsmgr"
	"github.com/prohand/leazone/internal/version"
	"github.com/prohand/leazone/internal/vip"
	"github.com/prohand/leazone/web"
)

// Node is a running Leazone instance.
type Node struct {
	cfg    *config.Config
	log    *slog.Logger
	db     *store.DB
	box    *secrets.Box
	master *secrets.Box // local master key, wraps the data key
	repl   *repl.Store
	auth   *auth.Service
	audit  *audit.Log
	ready  atomic.Bool
}

// Run starts the node and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	log.Info("starting Leazone", "version", version.Version, "commit", version.Commit, "schema", store.LatestSchema())

	if err := checkWritable(cfg.DataDir); err != nil {
		return err
	}
	st, err := caps.Raise()
	if err != nil {
		log.Warn("capabilities", "err", err)
	} else {
		log.Info("capabilities", "effective", st.String())
	}

	n := &Node{cfg: cfg, log: log}
	if err := n.openStore(ctx); err != nil {
		return err
	}
	defer n.db.Close()

	nodeID, err := n.db.Meta(ctx, "node_id")
	if err != nil {
		return err
	}
	if nodeID == "" {
		nodeID = ids.New()
		if err := n.db.SetMeta(ctx, "node_id", nodeID); err != nil {
			return err
		}
	}
	n.audit = audit.New(n.db, nodeID, log)

	// Replication journal: on a cluster node, local config writes are not
	// journaled until this node is elected primary.
	if n.repl, err = repl.Open(ctx, n.db); err != nil {
		return err
	}
	replEpoch, _, err := n.repl.Position(ctx)
	if err != nil {
		return err
	}
	if err := n.repl.SetRecording(ctx, !cfg.Clustered(), replEpoch); err != nil {
		return err
	}

	if n.auth, err = auth.NewService(ctx, n.db, n.box, log); err != nil {
		return err
	}
	if err := n.firstStart(ctx); err != nil {
		return err
	}

	tm, err := tlsmgr.New(ctx, n.db, n.box, log, cfg.DataDir, tlsNames(cfg))
	if err != nil {
		return err
	}
	spec, err := apispec.JSON()
	if err != nil {
		return fmt.Errorf("openapi spec: %w", err)
	}
	// DNS: interface watcher, engine and manager.
	watcher := netif.NewWatcher(log)
	go watcher.Run(ctx)
	engine := dnssrv.New(log, cfg.DNSPort)
	var node *cluster.Node
	dm := dnsmgr.New(dnsconf.New(n.db), engine, watcher, log)
	dm.DB, dm.DNSSEC = n.db, dnssec.NewStore(n.db, n.box)
	dm.Writable = func() bool { return node == nil || node.Writable() == nil }

	// Ad blocking (optional module): engine consulted by the DNS server.
	blockEngine := blocking.NewEngine()
	engine.SetBlocker(blockEngine)
	bm := blocking.NewManager(n.db, blockEngine, cfg.DataDir, log)
	setLocals := func(ifs []netif.Interface) {
		m := map[netip.Addr]blocking.IfInfo{}
		for _, it := range ifs {
			for _, a := range it.Addresses {
				m[a.Prefix.Addr()] = blocking.IfInfo{Name: it.Name, VLAN: it.VLANID}
			}
		}
		blockEngine.SetLocals(m)
	}
	setLocals(watcher.Interfaces())
	watcher.Subscribe(setLocals)
	if err := bm.Reload(ctx); err != nil {
		return fmt.Errorf("blocage : %w", err)
	}
	go bm.Run(ctx)

	if err := dm.Reload(ctx); err != nil {
		return fmt.Errorf("DNS: %w", err)
	}
	go dm.Run(ctx)

	// Statistics (dashboard) and query/event logs (/data/logs.db).
	rec := stats.New()
	qlog, err := querylog.Open(filepath.Join(cfg.DataDir, "logs.db"), log)
	if err != nil {
		return fmt.Errorf("journaux : %w", err)
	}
	loadLogSettings := func(ctx context.Context) {
		if st, err := querylog.LoadSettings(ctx, n.db); err == nil {
			qlog.SetSettings(st)
		}
	}
	loadLogSettings(ctx)
	go qlog.Run(ctx)
	engine.SetObserver(func(qi *dnssrv.QueryInfo) {
		failed := qi.Rcode == dns.RcodeServerFailure || qi.Source == dnssrv.SourceError
		client := qi.Client.String()
		rec.Record(stats.Query{Time: qi.Time, Client: client, Name: qi.Name, Source: qi.Source, Failed: failed})
		qlog.AddDNS(querylog.DNSEntry{Time: qi.Time, Client: client, Name: strings.TrimSuffix(strings.ToLower(qi.Name), "."),
			Type: dns.TypeToString[qi.Type], Rcode: dns.RcodeToString[qi.Rcode], Source: qi.Source,
			LatencyMs: float64(qi.Latency.Microseconds()) / 1000, Answer: qi.Answer})
	})

	// DHCP: lease engine, socket, DNS registration of leases.
	dhcpEngine, err := dhcpsrv.NewEngine(ctx, n.db, log)
	if err != nil {
		return fmt.Errorf("DHCP: %w", err)
	}
	dhcpEngine.NodeID = nodeID
	dhcpEngine.OnEvent = func(ev dhcpsrv.Event) {
		qlog.AddDHCP(querylog.DHCPEntry{Time: ev.Time, Event: ev.Kind, MAC: ev.MAC, IP: ev.IP, Hostname: ev.Hostname,
			ScopeID: ev.ScopeID, ScopeName: ev.ScopeName, Interface: ev.Interface, Relay: ev.Relay, Detail: ev.Detail})
	}
	dhcpConf := dhcpconf.New(n.db)
	hm := dhcpmgr.New(dhcpConf, dm.Store, dhcpEngine, dhcpsrv.NewServer(dhcpEngine, cfg.DHCPPort, log), watcher, log)
	if p := dhcpsrv.NewPinger(log); p != nil {
		dhcpEngine.Pinger, hm.PingAvailable = p, true
	}
	dhcpEngine.Hooks = &ddns.Updater{DNS: dm.Store, DHCP: dhcpConf, Reload: dm, Log: log, Active: activeOwner(dhcpEngine)}
	if err := hm.Reload(ctx); err != nil {
		return fmt.Errorf("DHCP: %w", err)
	}
	go hm.Run(ctx)

	// High availability.
	if cfg.Clustered() {
		vipM, err := vip.New(cfg.VIP, cfg.VIPInterface, log)
		if err != nil {
			return err
		}
		deps := cluster.Deps{Config: cfg, DB: n.db, Repl: n.repl, Box: n.box, NodeID: nodeID, Log: log, DHCP: dhcpEngine,
			VIP: vipM, VLANs: hostVLANs(watcher),
			SetDEK: n.setDEK,
			Audit: func(ctx context.Context, action, target string, details map[string]any) {
				n.audit.Record(ctx, audit.Entry{Actor: "cluster", Action: action, Target: target, Details: details})
			}}
		if p, ok := dhcpEngine.Pinger.(*dhcpsrv.ICMPPinger); ok && p != nil {
			deps.Pinger = p
		}
		deps.ConfigApplied = func(ctx context.Context) {
			if err := n.auth.ReloadSettings(ctx); err != nil {
				log.Warn("reload security settings", "err", err)
			}
			if err := tm.Reload(ctx); err != nil {
				log.Warn("reload certificate", "err", err)
			}
			loadLogSettings(ctx)
			if err := bm.Reload(ctx); err != nil {
				log.Warn("reload blocking", "err", err)
			}
			if err := dm.Reload(ctx); err != nil {
				log.Warn("reload DNS", "err", err)
			}
			if err := hm.Reload(ctx); err != nil {
				log.Warn("reload DHCP", "err", err)
			}
			if node != nil {
				node.Reload(ctx)
			}
		}
		if node, err = cluster.New(deps); err != nil {
			return fmt.Errorf("cluster: %w", err)
		}
		if err := node.Start(ctx); err != nil {
			return fmt.Errorf("cluster: %w", err)
		}
		if vipM != nil {
			defer vipM.Down()
		}
	}

	srv := api.New(api.Deps{Config: cfg, DB: n.db, Auth: n.auth, Audit: n.audit, TLS: tm, DNS: dm, DHCP: hm, Cluster: node,
		Blocking: bm, Stats: rec, QueryLog: qlog,
		Log: log, UI: web.Dist(), Spec: spec})

	ln, err := net.Listen("tcp", cfg.HTTPListen)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("le port de l'interface web %s est déjà utilisé sur cet hôte : changez LEAZONE_HTTP_LISTEN (ex : :9443) ou arrêtez le service qui l'occupe", cfg.HTTPListen)
		}
		if errors.Is(err, syscall.EACCES) {
			return fmt.Errorf("pas le droit d'écouter sur %s : ajoutez la capability NET_BIND_SERVICE ou utilisez un port >= 1024", cfg.HTTPListen)
		}
		return err
	}
	if err := control.Serve(ctx, cfg.ControlSocket, n.control, log); err != nil {
		log.Warn("control socket unavailable: CLI commands (healthcheck, admin) will not work", "err", err)
	}

	go n.housekeeping(ctx)
	n.ready.Store(true)
	log.Info("web interface ready", "listen", cfg.HTTPListen, "publicUrl", cfg.PublicURL)
	err = srv.ListenAndServe(ctx, ln)
	log.Info("stopped")
	return err
}

func (n *Node) openStore(ctx context.Context) error {
	var err error
	n.db, err = store.Open(filepath.Join(n.cfg.DataDir, "leazone.db"))
	if err != nil {
		return err
	}
	if err := n.db.Migrate(ctx, filepath.Join(n.cfg.DataDir, "backups"), n.log); err != nil {
		return err
	}
	master, err := secrets.LoadOrCreateMasterKey(filepath.Join(n.cfg.DataDir, "keys", "master.key"))
	if err != nil {
		return err
	}
	mbox, err := secrets.NewBox(master)
	if err != nil {
		return err
	}
	wrapped, err := n.db.Meta(ctx, "dek")
	if err != nil {
		return err
	}
	var dek []byte
	if wrapped == "" {
		dek = secrets.NewDEK()
		if err := n.db.SetMeta(ctx, "dek", mbox.Seal(dek, "dek")); err != nil {
			return err
		}
	} else if dek, err = mbox.Open(wrapped, "dek"); err != nil {
		return fmt.Errorf("cannot unlock the data key with %s: %w", filepath.Join(n.cfg.DataDir, "keys", "master.key"), err)
	}
	n.master = mbox
	n.box, err = secrets.NewBox(dek)
	return err
}

// setDEK adopts the cluster's data key (stored wrapped by the local master key).
func (n *Node) setDEK(ctx context.Context, dek []byte) error {
	if err := n.db.SetMeta(ctx, "dek", n.master.Seal(dek, "dek")); err != nil {
		return err
	}
	n.log.Info("data encryption key adopted from the cluster primary")
	return n.box.Replace(dek)
}

// hostVLANs describes the host VLANs for the cluster gap check.
func hostVLANs(w *netif.Watcher) func() []string {
	return func() []string {
		var out []string
		for _, it := range w.Interfaces() {
			if it.VLANID == 0 {
				continue
			}
			net := ""
			for _, a := range it.Addresses {
				if a.Prefix.Addr().Is4() {
					net = a.Prefix.Masked().String()
					break
				}
			}
			out = append(out, fmt.Sprintf("%d (%s)", it.VLANID, net))
		}
		sort.Strings(out)
		return out
	}
}

// firstStart creates the admin account on an empty database. The password
// comes from LEAZONE_ADMIN_PASSWORD_FILE or is generated and printed once.
func (n *Node) firstStart(ctx context.Context) error {
	count, err := n.auth.UserCount(ctx)
	if err != nil || count > 0 {
		return err
	}
	pw, generated := n.cfg.AdminPassword, false
	if pw == "" {
		pw, generated = ids.Password(20), true
	}
	u, err := n.auth.CreateUser(ctx, n.cfg.AdminUser, auth.RoleAdmin, pw)
	if err != nil {
		var verr auth.ErrValidation
		if errors.As(err, &verr) {
			return fmt.Errorf("initial admin account: %v", map[string]string(verr))
		}
		return err
	}
	n.audit.Record(ctx, audit.Entry{Actor: "system", Action: "user.create", Target: u.Username,
		Details: map[string]any{"role": "admin", "firstStart": true}})
	if generated {
		// Printed on stdout only (docker logs), never written to the log file.
		fmt.Fprintf(os.Stdout, "\n"+
			"╔══════════════════════════════════════════════════════════════╗\n"+
			"║  Premier démarrage de Leazone                                ║\n"+
			"║  Compte : %-51s║\n"+
			"║  Mot de passe : %-45s║\n"+
			"║  Il ne sera plus affiché. Le MFA sera demandé à la connexion.║\n"+
			"╚══════════════════════════════════════════════════════════════╝\n\n", u.Username, pw)
	} else {
		n.log.Info("initial admin account created from secret file", "user", u.Username)
	}
	return nil
}

func (n *Node) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := n.auth.PurgeSessions(ctx); err != nil {
				n.log.Warn("session purge", "err", err)
			}
			// Keep the journal bounded; a single node has nobody to ship state to.
			_ = n.repl.Trim(ctx, 20000)
			if !n.cfg.Clustered() {
				_ = n.repl.ClearOutbox(ctx)
			}
		}
	}
}

// control answers CLI sub-commands on the local socket.
func (n *Node) control(ctx context.Context, req control.Request) control.Response {
	switch req.Cmd {
	case "caps":
		return control.Response{OK: true, Message: caps.Current().String()}
	case "health":
		if !n.ready.Load() {
			return control.Response{Message: "starting"}
		}
		if err := n.db.PingContext(ctx); err != nil {
			return control.Response{Message: "database: " + err.Error()}
		}
		return control.Response{OK: true, Message: "ok"}
	case "reset-mfa":
		u, err := n.auth.GetUserByName(ctx, req.Args["user"])
		if err != nil {
			return control.Response{Message: "utilisateur introuvable : " + req.Args["user"]}
		}
		if err := n.auth.ResetMFA(ctx, u.ID); err != nil {
			return control.Response{Message: err.Error()}
		}
		_ = n.auth.RevokeUserSessions(ctx, u.ID, "")
		n.audit.Record(ctx, audit.Entry{Actor: "cli (docker exec)", Action: "user.mfa_reset", Target: u.Username})
		return control.Response{OK: true, Message: "MFA réinitialisé pour " + u.Username + ". Il devra le reconfigurer à la prochaine connexion."}
	case "reset-password":
		u, err := n.auth.GetUserByName(ctx, req.Args["user"])
		if err != nil {
			return control.Response{Message: "utilisateur introuvable : " + req.Args["user"]}
		}
		pw := ids.Password(20)
		if err := n.auth.SetPassword(ctx, u.ID, pw, ""); err != nil {
			return control.Response{Message: err.Error()}
		}
		// Unlock the account in case it was locked by failed attempts.
		_ = n.auth.GuardReset(ctx, auth.UserKey(u.Username))
		n.audit.Record(ctx, audit.Entry{Actor: "cli (docker exec)", Action: "user.password_reset", Target: u.Username})
		return control.Response{OK: true, Message: "Nouveau mot de passe pour " + u.Username + " : " + pw}
	case "reset-ui-allowlist":
		sec := n.auth.Security()
		sec.UIAllowedNetworks = nil
		if _, err := n.auth.SetSecurity(ctx, sec); err != nil {
			return control.Response{Message: err.Error()}
		}
		n.audit.Record(ctx, audit.Entry{Actor: "cli (docker exec)", Action: "settings.update", Target: "security",
			Details: map[string]any{"uiAllowedNetworks": "cleared"}})
		return control.Response{OK: true, Message: "Liste d'IP autorisées vidée : l'interface est de nouveau accessible depuis tous les réseaux."}
	}
	return control.Response{Message: "commande inconnue : " + req.Cmd}
}

func tlsNames(cfg *config.Config) []string {
	var names []string
	if cfg.PublicURL != "" {
		if u, err := url.Parse(cfg.PublicURL); err == nil {
			names = append(names, u.Hostname())
		}
	}
	if h, err := os.Hostname(); err == nil {
		names = append(names, h)
	}
	return names
}

// CheckWritable is checkWritable for other commands (witness).
func CheckWritable(dir string) error { return checkWritable(dir) }

// checkWritable fails early with a clear message when the data volume is not
// writable (wrong owner after changing LEAZONE_UID, read-only mount...).
func checkWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("le dossier %s n'est pas accessible en écriture pour l'UID %d : sur l'hôte, lancez "+
			"'chown -R %d:%d <volume>' ou corrigez LEAZONE_UID/LEAZONE_GID (%w)", dir, os.Getuid(), os.Getuid(), os.Getgid(), err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// activeOwner tells DDNS whether a record owner still holds a bound lease.
func activeOwner(e *dhcpsrv.Engine) func(string) bool {
	return func(owner string) bool {
		now := time.Now()
		for _, l := range e.Leases() {
			if l.State == dhcpsrv.StateBound && l.Active(now) && ddns.Owner(l.ScopeID, l) == owner {
				return true
			}
		}
		return false
	}
}

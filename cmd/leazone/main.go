// Command leazone is a lightweight DNS + DHCP server with high availability.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/prohand/leazone/internal/app"
	"github.com/prohand/leazone/internal/caps"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/control"
	"github.com/prohand/leazone/internal/logging"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/version"
	"github.com/prohand/leazone/internal/witness"

	_ "time/tzdata" // the scratch image has no zoneinfo
)

const usage = `Leazone - serveur DNS + DHCP léger avec haute disponibilité

Usage : leazone <commande> [options]

Commandes :
  serve                         Lance le nœud (commande par défaut)
  witness                       Lance le témoin de cluster (3e hôte)
  healthcheck                   Vérifie que le nœud répond (HEALTHCHECK Docker)
  admin reset-mfa <user>        Supprime le MFA d'un compte (secours)
  admin reset-password <user>   Donne un nouveau mot de passe à un compte (secours)
  admin reset-ui-allowlist      Vide la liste d'IP autorisées pour l'interface
  migrate status                Affiche la version du schéma de la base
  migrate down --to N           Revient au schéma N (nœud arrêté)
  caps                          Affiche les capabilities Linux effectives
  version                       Affiche la version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve()
	case "healthcheck":
		return healthcheck(stderr)
	case "admin":
		return admin(args, stdout, stderr)
	case "migrate":
		return migrate(args, stdout, stderr)
	case "caps":
		return showCaps(stdout)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "leazone %s (commit %s, built %s, schema %d, cluster protocol %s)\n",
			version.Version, version.Commit, version.BuildDate, store.LatestSchema(), version.ClusterProtocol)
		return 0
	case "internal":
		return internal(args, stderr)
	case "witness":
		return runWitness()
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "commande inconnue : %s\n\n%s", cmd, usage)
	return 2
}

func loadConfig(stderr io.Writer) (*config.Config, bool) {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "configuration :", err)
		return nil, false
	}
	return cfg, true
}

func serve() int {
	cfg, ok := loadConfig(os.Stderr)
	if !ok {
		return 1
	}
	log, closer := logging.Setup(cfg.LogLevel, cfg.LogFormat, cfg.LogDir)
	defer closer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	return 0
}

// runWitness runs the tie-breaker of a two-node cluster (third host).
func runWitness() int {
	cfg, ok := loadConfig(os.Stderr)
	if !ok {
		return 1
	}
	log, closer := logging.Setup(cfg.LogLevel, cfg.LogFormat, cfg.LogDir)
	defer closer.Close()
	if cfg.ClusterKey == "" {
		log.Error("LEAZONE_CLUSTER_KEY_FILE is required for the witness")
		return 1
	}
	if err := app.CheckWritable(cfg.DataDir); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := control.Serve(ctx, cfg.ControlSocket, func(context.Context, control.Request) control.Response {
		return control.Response{OK: true, Message: "ok"}
	}, log); err != nil {
		log.Warn("control socket", "err", err)
	}
	if err := witness.Run(ctx, cfg.ClusterListen, cfg.DataDir, cfg.ClusterKey, log); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	return 0
}

func healthcheck(stderr io.Writer) int {
	cfg, ok := loadConfig(stderr)
	if !ok {
		return 1
	}
	resp, err := control.Call(cfg.ControlSocket, control.Request{Cmd: "health"}, 5*time.Second)
	if err != nil || !resp.OK {
		fmt.Fprintln(stderr, "unhealthy:", err, resp.Message)
		return 1
	}
	return 0
}

func admin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cfg, ok := loadConfig(stderr)
	if !ok {
		return 1
	}
	req := control.Request{Cmd: args[0], Args: map[string]string{}}
	switch args[0] {
	case "reset-mfa", "reset-password":
		if len(args) != 2 {
			fmt.Fprintf(stderr, "usage : leazone admin %s <utilisateur>\n", args[0])
			return 2
		}
		req.Args["user"] = args[1]
	case "reset-ui-allowlist":
	default:
		fmt.Fprintf(stderr, "commande admin inconnue : %s\n", args[0])
		return 2
	}
	resp, err := control.Call(cfg.ControlSocket, req, 30*time.Second)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintln(stderr, resp.Message)
		return 1
	}
	fmt.Fprintln(stdout, resp.Message)
	return 0
}

func migrate(args []string, stdout, stderr io.Writer) int {
	cfg, ok := loadConfig(stderr)
	if !ok {
		return 1
	}
	if len(args) == 0 {
		args = []string{"status"}
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.Int("to", -1, "target schema version")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	// Refuse to touch the database while a node is running.
	if _, err := control.Call(cfg.ControlSocket, control.Request{Cmd: "health"}, time.Second); err == nil && args[0] != "status" {
		fmt.Fprintln(stderr, "Leazone tourne encore : arrêtez le nœud avant une migration manuelle")
		return 1
	}
	log, closer := logging.Setup("info", "text", "")
	defer closer.Close()
	db, err := store.Open(filepath.Join(cfg.DataDir, "leazone.db"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer db.Close()
	ctx := context.Background()
	switch args[0] {
	case "status":
		v, err := db.SchemaVersion(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "schéma de la base : %d, attendu par cette version : %d\n", v, store.LatestSchema())
		return 0
	case "down":
		if *to < 0 {
			fmt.Fprintln(stderr, "usage : leazone migrate down --to N")
			return 2
		}
		if err := db.MigrateDown(ctx, *to, filepath.Join(cfg.DataDir, "backups"), log); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "schéma ramené à la version %s\n", strconv.Itoa(*to))
		return 0
	}
	fmt.Fprintf(stderr, "sous-commande inconnue : %s\n", args[0])
	return 2
}

// showCaps prints the capabilities of the running node (through the control
// socket) or, when no node runs, what this process can raise.
func showCaps(stdout io.Writer) int {
	if cfg, err := config.Load(os.Getenv); err == nil {
		if resp, err := control.Call(cfg.ControlSocket, control.Request{Cmd: "caps"}, 2*time.Second); err == nil && resp.OK {
			fmt.Fprintln(stdout, resp.Message)
			return 0
		}
	}
	st, err := caps.Raise()
	if err != nil {
		fmt.Fprintln(stdout, caps.Current().String())
		return 0
	}
	fmt.Fprintln(stdout, st.String())
	return 0
}

// internal holds commands used while building the image.
func internal(args []string, stderr io.Writer) int {
	if len(args) == 3 && args[0] == "install" {
		// Copy the binary and set its file capabilities in a single image layer.
		if err := install(args[1], args[2]); err != nil {
			fmt.Fprintln(stderr, "install:", err)
			return 1
		}
		return 0
	}
	if len(args) >= 1 && args[0] == "setcap" {
		path := "/leazone"
		if len(args) == 2 {
			path = args[1]
		}
		if err := caps.SetFile(path); err != nil {
			fmt.Fprintln(stderr, "setcap:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage : leazone internal setcap [path] | install <src> <dst>")
	return 2
}

func install(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return caps.SetFile(dst)
}

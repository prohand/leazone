// Package api is the HTTPS server of the UI and the REST API.
package api

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/blocking"
	"github.com/prohand/leazone/internal/cluster"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/dhcpmgr"
	"github.com/prohand/leazone/internal/dnsmgr"
	"github.com/prohand/leazone/internal/querylog"
	"github.com/prohand/leazone/internal/stats"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/tlsmgr"
)

// Server holds the dependencies of the HTTP handlers.
type Server struct {
	cfg      *config.Config
	db       *store.DB
	auth     *auth.Service
	audit    *audit.Log
	tls      *tlsmgr.Manager
	dns      *dnsmgr.Manager
	dhcp     *dhcpmgr.Manager
	cluster  *cluster.Node // nil on a single node
	blocking *blocking.Manager
	stats    *stats.Recorder
	qlog     *querylog.Log
	log      *slog.Logger
	ui       fs.FS
	spec     []byte

	mux    *http.ServeMux
	routes []Route

	// importClient overrides the HTTP client of imports (tests).
	importClient *http.Client
}

// Route documents a registered endpoint (used by the OpenAPI coverage test).
type Route struct {
	Method string
	Path   string // relative to /api/v1, with {params}
}

// Deps are the server dependencies.
type Deps struct {
	Config   *config.Config
	DB       *store.DB
	Auth     *auth.Service
	Audit    *audit.Log
	TLS      *tlsmgr.Manager
	DNS      *dnsmgr.Manager
	DHCP     *dhcpmgr.Manager
	Cluster  *cluster.Node
	Blocking *blocking.Manager
	Stats    *stats.Recorder
	QueryLog *querylog.Log
	Log      *slog.Logger
	UI       fs.FS
	Spec     []byte // OpenAPI as JSON
}

// New builds the server and registers all routes.
func New(d Deps) *Server {
	s := &Server{cfg: d.Config, db: d.DB, auth: d.Auth, audit: d.Audit, tls: d.TLS, dns: d.DNS, dhcp: d.DHCP, cluster: d.Cluster, blocking: d.Blocking, stats: d.Stats, qlog: d.QueryLog, log: d.Log, ui: d.UI,
		spec: d.Spec, mux: http.NewServeMux()}
	s.registerRoutes()
	return s
}

// Routes lists the registered API routes.
func (s *Server) Routes() []Route { return s.routes }

// Handler returns the root handler with all middlewares.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.allowList(h)
	h = s.clientInfo(h)
	h = securityHeaders(h)
	h = s.recoverer(h)
	return h
}

// ListenAndServe runs the HTTPS server until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.tls.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ServeTLS(ln, "", "")
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// ---- middlewares ----

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in handler", append(logAttrs(r), "panic", v)...)
				problem(w, http.StatusInternalServerError, TInternal, "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// radixStyleHash allows the one fixed <style> element Radix Select injects
// (its rule is also shipped in the CSS bundle). Nothing else inline is allowed.
const radixStyleHash = "'sha256-441zG27rExd4/il+NvIqyL8zFx5XmyNQtE381kSkUJk='"

// securityHeaders sets CSP and friends on every response.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' " + radixStyleHash + "; style-src-attr 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; " +
		"form-action 'self'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const (
	keyClient ctxKey = iota
	keyPrincipal
)

// clientInfo is what we know about the HTTP client after proxy handling.
type clientInfo struct {
	IP       netip.Addr
	ViaProxy bool   // request came through a trusted proxy
	Origin   string // https://host[:port] as seen by the browser
	Host     string // host name without port, as seen by the browser
}

func client(r *http.Request) clientInfo {
	c, _ := r.Context().Value(keyClient).(clientInfo)
	return c
}

// clientInfo resolves the real client IP and the browser origin. X-Forwarded-*
// headers are only trusted when the TCP peer is a configured trusted proxy.
func (s *Server) clientInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := remoteAddr(r)
		ci := clientInfo{IP: peer, Origin: "https://" + r.Host, Host: hostOnly(r.Host)}
		if inPrefixes(peer, s.cfg.Proxies()) {
			ci.ViaProxy = true
			if ip, ok := forwardedFor(r.Header.Values("X-Forwarded-For"), s.cfg.Proxies()); ok {
				ci.IP = ip
			}
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			ci.Origin = "https://" + host
			ci.Host = hostOnly(host)
		}
		if s.cfg.PublicURL != "" {
			if u, err := url.Parse(s.cfg.PublicURL); err == nil && strings.EqualFold(hostOnly(u.Host), ci.Host) {
				ci.Origin = s.cfg.PublicURL
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyClient, ci)))
	})
}

func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		a, _ := netip.ParseAddr(r.RemoteAddr)
		return a.Unmap()
	}
	return ap.Addr().Unmap()
}

// forwardedFor returns the right-most address that is not a trusted proxy.
func forwardedFor(values []string, proxies []netip.Prefix) (netip.Addr, bool) {
	var hops []string
	for _, v := range values {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}, false
		}
		a = a.Unmap()
		if !inPrefixes(a, proxies) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

// allowList enforces the optional UI/API network allow-list (/health excluded).
func (s *Server) allowList(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			if nets := s.auth.Security().AllowedNetworks(); len(nets) > 0 && !inPrefixes(client(r).IP, nets) {
				http.Error(w, "Accès refusé depuis cette adresse IP.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pquerna/otp/totp"
	"gopkg.in/yaml.v3"

	apispec "github.com/prohand/leazone/api"
	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/backup"
	"github.com/prohand/leazone/internal/blocking"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/ddns"
	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpmgr"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnsmgr"
	"github.com/prohand/leazone/internal/dnssec"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/querylog"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/stats"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/tlsmgr"
)

const (
	testHost  = "leazone.test"
	adminPass = "admin password 123"
)

type harness struct {
	t     *testing.T
	srv   *Server
	ts    *httptest.Server
	auth  *auth.Service
	audit *audit.Log
	clock time.Duration // added to the real time

	dns      *dnsmgr.Manager
	dhcp     *dhcpmgr.Manager
	ifaces   *fakeIfaces
	dnsPort  int
	dhcpPort int
	blocking *blocking.Manager
	stats    *stats.Recorder
	qlog     *querylog.Log
}

// fakeIfaces is a static interface source.
type fakeIfaces struct {
	list []netif.Interface
	subs []func([]netif.Interface)
}

func (f *fakeIfaces) Interfaces() []netif.Interface        { return f.list }
func (f *fakeIfaces) Subscribe(fn func([]netif.Interface)) { f.subs = append(f.subs, fn) }
func (f *fakeIfaces) Kick()                                {}

func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		if ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func newHarness(t *testing.T, env map[string]string) *harness {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx, dir, log); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	rs, err := repl.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.SetRecording(ctx, true, 0); err != nil {
		t.Fatal(err)
	}
	master, _ := secrets.NewBox(secrets.NewDEK())
	svc, err := auth.NewService(ctx, db, box, log)
	if err != nil {
		t.Fatal(err)
	}
	svc.Argon = auth.Argon2Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32}
	h := &harness{t: t, auth: svc}
	svc.Now = func() time.Time { return time.Now().Add(h.clock) }
	if _, err := svc.CreateUser(ctx, "admin", auth.RoleAdmin, adminPass); err != nil {
		t.Fatal(err)
	}
	h.audit = audit.New(db, "node-test", log)
	tm, err := tlsmgr.New(ctx, db, box, log, dir, []string{testHost})
	if err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "LEAZONE_CONFIG_DIR" {
			return dir
		}
		return env[k]
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := apispec.JSON()
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>Leazone</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")}}
	h.ifaces = &fakeIfaces{list: []netif.Interface{{Name: "lo", Type: netif.TypeLoopback, Up: true,
		Addresses: []netif.Address{{Prefix: netip.MustParsePrefix("127.0.0.1/8")}}}}}
	h.dnsPort = freePort(t)
	h.dns = dnsmgr.New(dnsconf.New(db), dnssrv.New(log, h.dnsPort), h.ifaces, log)
	h.dns.DB, h.dns.DNSSEC = db, dnssec.NewStore(db, box)
	h.blocking = blocking.NewManager(db, blocking.NewEngine(), dir, log)
	h.dns.Engine.SetBlocker(h.blocking.Engine)
	h.stats = stats.New()
	if h.qlog, err = querylog.Open(filepath.Join(dir, "logs.db"), log); err != nil {
		t.Fatal(err)
	}
	if err := h.dns.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.dns.Engine.Close)
	eng, err := dhcpsrv.NewEngine(ctx, db, log)
	if err != nil {
		t.Fatal(err)
	}
	h.dhcpPort = freePort(t)
	dconf := dhcpconf.New(db)
	h.dhcp = dhcpmgr.New(dconf, h.dns.Store, eng, dhcpsrv.NewServer(eng, h.dhcpPort, log), h.ifaces, log)
	eng.Hooks = &ddns.Updater{DNS: h.dns.Store, DHCP: dconf, Reload: h.dns, Log: log}
	if err := h.dhcp.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.dhcp.Server.Close)
	h.srv = New(Deps{Config: cfg, DB: db, Auth: svc, Audit: h.audit, TLS: tm, DNS: h.dns, DHCP: h.dhcp, Blocking: h.blocking, Stats: h.stats, QueryLog: h.qlog, Log: log,
		Backup: &backup.Service{DB: db, Repl: rs, Box: box, Node: "node-test", Time: 1, MemoryKiB: 64,
			WrapDEK: func(dek []byte) string { return master.Seal(dek, "dek") }},
		AfterRestore: func(ctx context.Context) {
			_ = svc.ReloadSettings(ctx)
			_ = h.blocking.Reload(ctx)
			_ = h.dns.Reload(ctx)
			_ = h.dhcp.Reload(ctx)
		}, UI: ui, Spec: spec})
	h.ts = httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(h.ts.Close)
	return h
}

type testClient struct {
	h      *harness
	hc     *http.Client
	csrf   string
	origin string
	token  string
}

func (h *harness) client() *testClient {
	jar, _ := cookiejar.New(nil)
	addr := h.ts.Listener.Addr().String()
	pool := x509.NewCertPool()
	pool.AddCert(h.ts.Certificate())
	tr := &http.Transport{
		// The httptest certificate is valid for example.com: verify it properly.
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	return &testClient{h: h, hc: &http.Client{Jar: jar, Transport: tr}, origin: "https://" + testHost}
}

// do sends a JSON request and decodes a JSON answer into out (if not nil).
func (c *testClient) do(method, path string, body any, out any) int {
	c.h.t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case json.RawMessage:
			rd = bytes.NewReader(b)
		default:
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
	}
	req, _ := http.NewRequest(method, "https://"+testHost+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.h.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode
}

type stateResp struct {
	State      string   `json:"state"`
	CSRFToken  string   `json:"csrfToken"`
	MFAMethods []string `json:"mfaMethods"`
}

func (c *testClient) login(user, pass string) stateResp {
	c.h.t.Helper()
	var st stateResp
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pass}, &st); code != 200 {
		c.h.t.Fatalf("login %s: HTTP %d", user, code)
	}
	c.csrf = st.CSRFToken
	return st
}

type problemResp struct {
	Type       string `json:"type"`
	RetryAfter int    `json:"retryAfter"`
}

func (c *testClient) expect(method, path string, body any, wantStatus int, wantType string) {
	c.h.t.Helper()
	var p problemResp
	code := c.do(method, path, body, &p)
	if code != wantStatus || (wantType != "" && p.Type != wantType) {
		c.h.t.Fatalf("%s %s: got %d %q, want %d %q", method, path, code, p.Type, wantStatus, wantType)
	}
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	c, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginWithTOTPAndRecovery(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	if st := c.login("admin", adminPass); st.State != "mfa_setup_required" {
		t.Fatalf("first login state = %s", st.State)
	}
	// The UI is locked until MFA is configured.
	c.expect("GET", "/api/v1/users", nil, 403, TMFARequired)

	var setup struct{ Secret string }
	if code := c.do("POST", "/api/v1/me/totp/setup", nil, &setup); code != 200 || setup.Secret == "" {
		t.Fatalf("totp setup: %d", code)
	}
	c.expect("POST", "/api/v1/me/totp/confirm", map[string]string{"code": "000000"}, 401, TUnauthenticated)
	code := totpCode(t, setup.Secret, time.Now())
	var enroll struct {
		Session       stateResp `json:"session"`
		RecoveryCodes []string  `json:"recoveryCodes"`
	}
	if st := c.do("POST", "/api/v1/me/totp/confirm", map[string]string{"code": code}, &enroll); st != 200 {
		t.Fatalf("totp confirm: %d", st)
	}
	if enroll.Session.State != "authenticated" || len(enroll.RecoveryCodes) != 10 {
		t.Fatalf("after enrollment: %+v", enroll)
	}
	if st := c.do("GET", "/api/v1/users", nil, nil); st != 200 {
		t.Fatalf("users after MFA: %d", st)
	}
	if st := c.do("POST", "/api/v1/auth/logout", nil, nil); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	var anon stateResp
	c.do("GET", "/api/v1/auth/session", nil, &anon)
	if anon.State != "anonymous" {
		t.Fatalf("after logout: %s", anon.State)
	}

	// Second login: MFA asked. The code already used is refused (replay).
	c2 := h.client()
	st := c2.login("admin", adminPass)
	if st.State != "mfa_required" || !contains(st.MFAMethods, "totp") || !contains(st.MFAMethods, "recovery") {
		t.Fatalf("second login: %+v", st)
	}
	c2.expect("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": code}, 401, TUnauthenticated)
	h.clock = 31 * time.Second
	next := totpCode(t, setup.Secret, time.Now().Add(h.clock))
	var ok stateResp
	if s := c2.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": next}, &ok); s != 200 || ok.State != "authenticated" {
		t.Fatalf("totp mfa: %d %+v", s, ok)
	}

	// Recovery code works once.
	c3 := h.client()
	c3.login("admin", adminPass)
	if s := c3.do("POST", "/api/v1/auth/mfa/recovery", map[string]string{"code": enroll.RecoveryCodes[0]}, &ok); s != 200 || ok.State != "authenticated" {
		t.Fatalf("recovery: %d", s)
	}
	c4 := h.client()
	c4.login("admin", adminPass)
	c4.expect("POST", "/api/v1/auth/mfa/recovery", map[string]string{"code": enroll.RecoveryCodes[0]}, 401, TUnauthenticated)
}

func TestLoginLockout(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	for i := 0; i < 5; i++ {
		c.expect("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "nope nope nope"}, 401, TUnauthenticated)
	}
	var p problemResp
	if s := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": adminPass}, &p); s != 429 || p.RetryAfter < 1 {
		t.Fatalf("expected 429 with retryAfter, got %d %+v", s, p)
	}
	items, _, _ := h.audit.List(context.Background(), audit.Query{Action: "auth.login.failure"})
	if len(items) != 6 {
		t.Fatalf("audit failures = %d, want 6", len(items))
	}
}

func TestPasskeys(t *testing.T) {
	h := newHarness(t, nil)
	sa := newSoftAuthenticator(t, "https://"+testHost, testHost)
	c := h.client()
	c.login("admin", adminPass)

	// Forced enrollment with a passkey.
	var begin struct {
		CeremonyID string          `json:"ceremonyId"`
		Options    json.RawMessage `json:"options"`
	}
	if s := c.do("POST", "/api/v1/me/passkeys/begin", nil, &begin); s != 200 {
		t.Fatalf("register begin: %d", s)
	}
	var enroll struct {
		Session       stateResp `json:"session"`
		RecoveryCodes []string  `json:"recoveryCodes"`
	}
	finish := map[string]any{"ceremonyId": begin.CeremonyID, "name": "YubiKey bureau", "credential": sa.create(begin.Options)}
	if s := c.do("POST", "/api/v1/me/passkeys/finish", finish, &enroll); s != 200 || enroll.Session.State != "authenticated" || len(enroll.RecoveryCodes) != 10 {
		t.Fatalf("register finish: %d %+v", s, enroll)
	}
	// A ceremony is single use.
	c.expect("POST", "/api/v1/me/passkeys/finish", finish, 400, TBadRequest)

	// Passwordless login.
	c2 := h.client()
	if s := c2.do("POST", "/api/v1/auth/passkey/begin", nil, &begin); s != 200 {
		t.Fatalf("login begin: %d", s)
	}
	var st stateResp
	if s := c2.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"ceremonyId": begin.CeremonyID, "credential": sa.get(begin.Options)}, &st); s != 200 || st.State != "authenticated" {
		t.Fatalf("passwordless login: %d %+v", s, st)
	}

	// Password + passkey as second factor.
	c3 := h.client()
	if st := c3.login("admin", adminPass); st.State != "mfa_required" || !contains(st.MFAMethods, "passkey") {
		t.Fatalf("mfa methods: %+v", st)
	}
	c3.do("POST", "/api/v1/auth/mfa/passkey/begin", nil, &begin)
	if s := c3.do("POST", "/api/v1/auth/mfa/passkey/finish", map[string]any{"ceremonyId": begin.CeremonyID, "credential": sa.get(begin.Options)}, &st); s != 200 || st.State != "authenticated" {
		t.Fatalf("passkey second factor: %d %+v", s, st)
	}

	// A passkey answer for another origin is refused.
	evil := newSoftAuthenticator(t, "https://evil.test", testHost)
	evil.creds = sa.creds
	c4 := h.client()
	c4.do("POST", "/api/v1/auth/passkey/begin", nil, &begin)
	c4.expect("POST", "/api/v1/auth/passkey/finish", map[string]any{"ceremonyId": begin.CeremonyID, "credential": evil.get(begin.Options)}, 401, TUnauthenticated)

	// Sensitive action: needs a fresh step-up after 5 minutes.
	var list struct {
		Items []struct{ ID, Name string } `json:"items"`
	}
	c3.do("GET", "/api/v1/me/passkeys", nil, &list)
	if len(list.Items) != 1 || list.Items[0].Name != "YubiKey bureau" {
		t.Fatalf("passkeys: %+v", list)
	}
	h.clock = 6 * time.Minute
	c3.expect("DELETE", "/api/v1/me/passkeys/"+list.Items[0].ID, nil, 403, TStepUp)
	c3.do("POST", "/api/v1/auth/step-up/passkey/begin", nil, &begin)
	if s := c3.do("POST", "/api/v1/auth/step-up/passkey/finish", map[string]any{"ceremonyId": begin.CeremonyID, "credential": sa.get(begin.Options)}, nil); s != 200 {
		t.Fatalf("step-up: %d", s)
	}
	// Still refused: it is the last MFA method and MFA is required.
	c3.expect("DELETE", "/api/v1/me/passkeys/"+list.Items[0].ID, nil, 409, TConflict)
}

func TestCSRFAndOrigin(t *testing.T) {
	h := newHarness(t, nil)
	sec := h.auth.Security()
	sec.MFARequiredFor = "admins"
	h.auth.SetSecurity(context.Background(), sec)
	h.auth.CreateUser(context.Background(), "ro", auth.RoleReadonly, "readonly password")
	c := h.client()
	if st := c.login("ro", "readonly password"); st.State != "authenticated" {
		t.Fatalf("readonly login: %s", st.State)
	}
	csrf := c.csrf
	c.csrf = ""
	c.expect("POST", "/api/v1/me/tokens", map[string]string{"name": "x", "scope": "read"}, 403, TCSRF)
	c.csrf, c.origin = csrf, "https://evil.test"
	c.expect("POST", "/api/v1/me/tokens", map[string]string{"name": "x", "scope": "read"}, 403, TCSRF)
	c.origin = "https://" + testHost
	if s := c.do("POST", "/api/v1/me/tokens", map[string]string{"name": "x", "scope": "read"}, nil); s != 201 {
		t.Fatalf("token create: %d", s)
	}
	// Role check: read-only users cannot manage users.
	c.expect("GET", "/api/v1/users", nil, 403, TForbidden)
}

func TestAPITokensFollowRoles(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	u, _ := h.auth.GetUserByName(ctx, "admin")
	read, _, _ := h.auth.CreateToken(ctx, u.ID, "ro", "read", nil)
	write, _, _ := h.auth.CreateToken(ctx, u.ID, "rw", "write", nil)

	c := h.client()
	c.origin = ""
	c.token = read
	if s := c.do("GET", "/api/v1/users", nil, nil); s != 200 {
		t.Fatalf("read token GET users: %d", s)
	}
	c.expect("PUT", "/api/v1/settings/security", auth.DefaultSecurity(), 403, TForbidden)
	c.expect("GET", "/api/v1/me", nil, 403, TForbidden) // tokens do not manage the account
	c.token = write
	// Sensitive actions need a step-up, impossible with a token.
	c.expect("PUT", "/api/v1/settings/security", auth.DefaultSecurity(), 403, TForbidden)
	c.token = "lz_bad_token"
	c.expect("GET", "/api/v1/users", nil, 401, TUnauthenticated)
}

func TestAllowListAndHealth(t *testing.T) {
	h := newHarness(t, nil)
	sec := h.auth.Security()
	sec.UIAllowedNetworks = []string{"10.9.9.0/24"}
	if _, err := h.auth.SetSecurity(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	if s := c.do("GET", "/api/v1/system/info", nil, nil); s != 403 {
		t.Fatalf("outside allow-list: %d", s)
	}
	if s := c.do("GET", "/health", nil, nil); s != 200 {
		t.Fatalf("health must bypass the allow-list: %d", s)
	}
}

func TestTrustedProxy(t *testing.T) {
	h := newHarness(t, map[string]string{"LEAZONE_TRUSTED_PROXIES": "127.0.0.1"})
	c := h.client()
	req, _ := http.NewRequest("POST", "https://"+testHost+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"bad password!!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://leazone.example.org")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Host", "leazone.example.org")
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	items, _, _ := h.audit.List(context.Background(), audit.Query{})
	if len(items) == 0 || items[0].IP != "203.0.113.7" {
		t.Fatalf("audit ip = %+v, want 203.0.113.7", items)
	}

	// Without trust, X-Forwarded-For is ignored.
	h2 := newHarness(t, nil)
	c2 := h2.client()
	req2, _ := http.NewRequest("POST", "https://"+testHost+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"bad password!!"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp2, _ := c2.hc.Do(req2)
	resp2.Body.Close()
	items, _, _ = h2.audit.List(context.Background(), audit.Query{})
	if len(items) == 0 || items[0].IP != "127.0.0.1" {
		t.Fatalf("untrusted XFF used: %+v", items)
	}
}

func TestSPAAndHeaders(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	for _, p := range []string{"/", "/dns/zones", "/account"} {
		req, _ := http.NewRequest("GET", "https://"+testHost+p, nil)
		resp, err := c.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "<title>Leazone") {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") ||
			resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: missing security headers", p)
		}
	}
	c.expect("GET", "/api/v1/does-not-exist", nil, 404, TNotFound)
	if s := c.do("GET", "/assets/missing.js", nil, nil); s != 404 {
		t.Fatalf("missing asset: %d", s)
	}
}

// TestOpenAPICoverage keeps api/openapi.yaml and the router in sync.
func TestOpenAPICoverage(t *testing.T) {
	h := newHarness(t, nil)
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(apispec.YAML, &spec); err != nil {
		t.Fatal(err)
	}
	inSpec := map[string]bool{}
	for p, ops := range spec.Paths {
		for m := range ops {
			if m == "parameters" {
				continue
			}
			inSpec[strings.ToUpper(m)+" "+p] = true
		}
	}
	inRouter := map[string]bool{}
	for _, r := range h.srv.Routes() {
		inRouter[r.Method+" "+r.Path] = true
	}
	var missing []string
	for k := range inRouter {
		if !inSpec[k] {
			missing = append(missing, "not documented: "+k)
		}
	}
	for k := range inSpec {
		if !inRouter[k] {
			missing = append(missing, "documented but not implemented: "+k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatal(strings.Join(missing, "\n"))
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
)

// A refused login with a huge user name stores nothing big, and the
// attempts refused by the lockout are written once per client and window.
func TestLoginFailuresCannotFillTheAuditLog(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	huge := strings.Repeat("x", 512<<10)
	for i := 0; i < 20; i++ {
		c.expect("POST", "/api/v1/auth/login", map[string]string{"username": huge, "password": "whatever pass"}, 401, TUnauthenticated)
	}
	for i := 0; i < 10; i++ {
		c.expect("POST", "/api/v1/auth/login", map[string]string{"username": huge, "password": "whatever pass"}, 429, TRateLimited)
	}
	items, _, _ := h.audit.List(context.Background(), audit.Query{Action: "auth.login.failure", Limit: 500})
	limited := 0
	for _, e := range items {
		if len(e.Actor)+len(e.Target) > 300 {
			t.Fatalf("user name stored (%d bytes)", len(e.Actor))
		}
		if e.Details["reason"] == "rate_limited" {
			limited++
		}
	}
	if len(items) != 21 || limited != 1 {
		t.Fatalf("%d failure entries (%d rate limited), want 21 (1)", len(items), limited)
	}
}

// Too many password checks running: 429 with Retry-After, not 500.
func TestBusyAnswers429(t *testing.T) {
	h := newHarness(t, nil)
	w := httptest.NewRecorder()
	h.srv.fail(w, httptest.NewRequest("POST", "/api/v1/auth/login", nil), auth.ErrBusy)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), TRateLimited) {
		t.Fatalf("busy: %d %q", w.Code, w.Body.String())
	}
}

func rpFor(h *harness, host, origin string) (auth.RP, string) {
	r := httptest.NewRequest("GET", "https://"+host+"/", nil)
	r = r.WithContext(context.WithValue(r.Context(), keyClient, clientInfo{Host: host, Origin: origin}))
	return h.srv.rp(r)
}

func setRPID(t *testing.T, h *harness, id string) {
	t.Helper()
	sec := h.auth.Security()
	sec.WebAuthnRPID = id
	if _, err := h.auth.SetSecurity(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
}

// The origin a passkey answer must carry comes from the configuration, not
// from the Host header: a parent RP ID does not open the door to every
// sub-domain.
func TestWebAuthnOriginFromConfig(t *testing.T) {
	h := newHarness(t, nil)
	if rp, why := rpFor(h, "leazone.test", "https://leazone.test"); why != "" || rp.ID != "leazone.test" || rp.Origins[0] != "https://leazone.test" {
		t.Fatalf("simple install: %+v %q", rp, why)
	}
	setRPID(t, h, "test")
	if rp, why := rpFor(h, "evil.test", "https://evil.test"); why == "" {
		t.Fatalf("sub-domain accepted without a public URL: %+v", rp)
	} else if !strings.Contains(why, "LEAZONE_PUBLIC_URL") {
		t.Fatalf("unclear reason: %q", why)
	}
	if _, why := rpFor(h, "test", "https://test"); why != "" {
		t.Fatalf("RP ID itself refused: %q", why)
	}

	h = newHarness(t, map[string]string{"LEAZONE_PUBLIC_URL": "https://leazone.test"})
	setRPID(t, h, "test")
	rp, why := rpFor(h, "leazone.test", "https://leazone.test")
	if why != "" || rp.ID != "test" || len(rp.Origins) != 1 || rp.Origins[0] != "https://leazone.test" {
		t.Fatalf("public URL: %+v %q", rp, why)
	}
	if rp, why := rpFor(h, "evil.test", "https://evil.test"); why == "" {
		t.Fatalf("other host accepted with a public URL: %+v", rp)
	}
}

// Operators manage records and leases, not the blocking module.
func TestBlockingNeedsConfigWrite(t *testing.T) {
	h := newHarness(t, nil)
	adminClient(t, h) // policy: MFA for admins only
	if _, err := h.auth.CreateUser(context.Background(), "op", auth.RoleOperator, "operator password 1"); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	if st := c.login("op", "operator password 1"); st.State != "authenticated" {
		t.Fatalf("operator login: %s", st.State)
	}
	c.expect("POST", "/api/v1/blocking/pause", map[string]int{"minutes": 5}, 403, TForbidden)
	c.expect("POST", "/api/v1/blocking/refresh", nil, 403, TForbidden)
	c.expect("POST", "/api/v1/blocking/rules", map[string]string{"domain": "ads.example.com", "kind": "deny"}, 403, TForbidden)
	c.expect("DELETE", "/api/v1/blocking/rules/x", nil, 403, TForbidden)
	if s := c.do("GET", "/api/v1/blocking/rules", nil, nil); s != 200 {
		t.Fatalf("operator read: %d", s)
	}
}

// After the policy switched to "passkey only", a TOTP-only user in the
// forced setup must prove the TOTP before enrolling a passkey.
func TestPasskeyOnlySetupNeedsTheOldTOTP(t *testing.T) {
	h := newHarness(t, nil)
	_, secret, _ := adminWithSecret(t, h)
	sec := h.auth.Security()
	sec.MFAMethods = "passkey"
	if _, err := h.auth.SetSecurity(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	if st := c.login("admin", adminPass); st.State != "mfa_setup_required" {
		t.Fatalf("login: %s", st.State)
	}
	c.expect("POST", "/api/v1/me/passkeys/begin", nil, 403, TStepUp)
	c.expect("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": "000000"}, 401, TUnauthenticated)
	h.clock = 31 * time.Second
	if s := c.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": totpCode(t, secret, time.Now().Add(h.clock))}, nil); s != 200 {
		t.Fatalf("TOTP proof: %d", s)
	}
	// The proof only opens the enrollment.
	c.expect("GET", "/api/v1/users", nil, 403, TMFARequired)
	var begin struct {
		CeremonyID string          `json:"ceremonyId"`
		Options    json.RawMessage `json:"options"`
	}
	if s := c.do("POST", "/api/v1/me/passkeys/begin", nil, &begin); s != 200 {
		t.Fatalf("passkey begin after the proof: %d", s)
	}
	sa := newSoftAuthenticator(t, "https://"+testHost, testHost)
	var enroll struct {
		Session stateResp `json:"session"`
	}
	finish := map[string]any{"ceremonyId": begin.CeremonyID, "name": "clé", "credential": sa.create(begin.Options)}
	if s := c.do("POST", "/api/v1/me/passkeys/finish", finish, &enroll); s != 200 || enroll.Session.State != "authenticated" {
		t.Fatalf("passkey finish: %d %+v", s, enroll)
	}
}

// The session cookie and the CSRF token change when the login completes;
// the pending cookie is worthless afterwards.
func TestSessionRenewedAfterSecondFactor(t *testing.T) {
	h := newHarness(t, nil)
	_, secret, _ := adminWithSecret(t, h)
	c := h.client()
	st := c.login("admin", adminPass)
	u, _ := url.Parse("https://" + testHost + "/")
	old := c.hc.Jar.Cookies(u)
	h.clock = 31 * time.Second
	var full stateResp
	if s := c.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": totpCode(t, secret, time.Now().Add(h.clock))}, &full); s != 200 {
		t.Fatalf("mfa: %d", s)
	}
	if full.State != "authenticated" || full.CSRFToken == st.CSRFToken || full.CSRFToken == "" {
		t.Fatalf("CSRF token not renewed: %+v", full)
	}
	if now := c.hc.Jar.Cookies(u); len(now) != 1 || len(old) != 1 || now[0].Value == old[0].Value {
		t.Fatal("session cookie not renewed")
	}
	if s := c.do("GET", "/api/v1/me", nil, nil); s != 200 {
		t.Fatalf("new session: %d", s)
	}
	thief := h.client()
	thief.hc.Jar.SetCookies(u, old)
	var anon stateResp
	thief.do("GET", "/api/v1/auth/session", nil, &anon)
	if anon.State != "anonymous" {
		t.Fatalf("pending cookie still works: %s", anon.State)
	}
}

// An account without a factor re-enters its password before adding one
// (or a token) from a session that is no longer fresh.
func TestFirstFactorNeedsPasswordWhenSessionIsOld(t *testing.T) {
	h := newHarness(t, nil)
	admin := adminClient(t, h)
	if _, err := h.auth.CreateUser(context.Background(), "op", auth.RoleOperator, "operator password 1"); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	c.login("op", "operator password 1")
	if s := c.do("POST", "/api/v1/me/totp/setup", nil, nil); s != 200 {
		t.Fatalf("right after login: %d", s)
	}
	h.clock = 6 * time.Minute
	c.expect("POST", "/api/v1/me/passkeys/begin", nil, 403, TStepUp)
	c.expect("POST", "/api/v1/me/totp/setup", nil, 403, TStepUp)
	c.expect("POST", "/api/v1/me/tokens", map[string]string{"name": "a", "scope": "read"}, 403, TStepUp)
	c.expect("POST", "/api/v1/auth/step-up/password", map[string]string{"password": "wrong password!"}, 422, TValidation)
	if s := c.do("POST", "/api/v1/auth/step-up/password", map[string]string{"password": "operator password 1"}, nil); s != 200 {
		t.Fatalf("password step-up: %d", s)
	}
	if s := c.do("POST", "/api/v1/me/totp/setup", nil, nil); s != 200 {
		t.Fatalf("after the password step-up: %d", s)
	}
	// An account with a factor must use it.
	admin.expect("POST", "/api/v1/auth/step-up/password", map[string]string{"password": adminPass}, 403, TForbidden)
}

func importTestCert(t *testing.T, h *harness) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: testHost}, DNSNames: []string{testHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	if _, err := h.srv.tls.Import(context.Background(), string(certPEM), string(keyPEM)); err != nil {
		t.Fatal(err)
	}
}

func hsts(t *testing.T, c *testClient) string {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+testHost+"/api/v1/system/info", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Strict-Transport-Security")
}

// HSTS on direct access with an imported certificate only.
func TestHSTSWithImportedCertificate(t *testing.T) {
	h := newHarness(t, nil)
	if v := hsts(t, h.client()); v != "" {
		t.Fatalf("HSTS with the self-signed certificate: %q", v)
	}
	importTestCert(t, h)
	if v := hsts(t, h.client()); v != "max-age=31536000" {
		t.Fatalf("HSTS with an imported certificate: %q", v)
	}
	p := newHarness(t, map[string]string{"LEAZONE_TRUSTED_PROXIES": "127.0.0.1"})
	importTestCert(t, p)
	if v := hsts(t, p.client()); v != "" {
		t.Fatalf("HSTS behind a trusted proxy: %q", v)
	}
}

package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/auth"
)

// adminWithSecret is adminClient that also returns the TOTP secret and the
// recovery codes.
func adminWithSecret(t *testing.T, h *harness) (*testClient, string, []string) {
	sec := h.auth.Security()
	sec.MFARequiredFor = "admins"
	h.auth.SetSecurity(context.Background(), sec)
	c := h.client()
	c.login("admin", adminPass)
	var setup struct{ Secret string }
	c.do("POST", "/api/v1/me/totp/setup", nil, &setup)
	var enroll struct{ RecoveryCodes []string }
	if s := c.do("POST", "/api/v1/me/totp/confirm", map[string]string{"code": totpCode(t, setup.Secret, time.Now())}, &enroll); s != 200 {
		t.Fatalf("TOTP enrollment: %d", s)
	}
	return c, setup.Secret, enroll.RecoveryCodes
}

func downloadBackup(t *testing.T, c *testClient, password string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://"+testHost+"/api/v1/backup", strings.NewReader(`{"password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.origin)
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestBackupRestore(t *testing.T) {
	const pw = "sauvegarde très secrète"
	h := newHarness(t, nil)
	c, secret, codes := adminWithSecret(t, h)
	var z struct{ ID string }
	c.do("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, &z)
	c.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "192.168.20.5"}}, nil)
	if _, err := h.auth.CreateUser(t.Context(), "lecteur", auth.RoleReadonly, adminPass); err != nil {
		t.Fatal(err)
	}
	admin, _ := h.auth.GetUserByName(t.Context(), "admin")
	token, tk, _ := h.auth.CreateToken(t.Context(), admin.ID, "script", "read", nil)

	c.expect("POST", "/api/v1/backup", map[string]string{"password": "court"}, 422, TValidation)
	status, file := downloadBackup(t, c, pw)
	if status != 200 || !strings.Contains(file, "format: leazone-backup/1") || !strings.Contains(file, "maison.lan") {
		t.Fatalf("backup: %d\n%.400s", status, file)
	}
	if strings.Contains(file, secret) {
		t.Fatal("TOTP secret in clear in the backup")
	}

	// Changes after the backup.
	c.do("DELETE", "/api/v1/dns/zones/"+z.ID, nil, nil)
	c.do("POST", "/api/v1/dns/zones", map[string]any{"name": "apres.lan"}, nil)
	// Revoked token and regenerated recovery codes must not come back.
	if err := h.auth.RevokeToken(t.Context(), admin.ID, tk.ID); err != nil {
		t.Fatal(err)
	}
	if s := c.do("POST", "/api/v1/me/recovery-codes", nil, nil); s != 200 {
		t.Fatalf("regenerate recovery codes: %d", s)
	}

	// Wrong password, tampered file, dry run.
	c.expect("POST", "/api/v1/restore", map[string]any{"password": "mauvais mot de passe", "content": file}, 422, TValidation)
	tampered := strings.Replace(file, "192.168.20.5", "192.168.20.6", 1)
	c.expect("POST", "/api/v1/restore", map[string]any{"password": pw, "content": tampered}, 422, TValidation)
	c.expect("POST", "/api/v1/restore", map[string]any{"password": pw, "content": "hello: world"}, 422, TValidation)
	var res struct {
		DryRun bool
		Node   string
		Tables map[string]int
	}
	if s := c.do("POST", "/api/v1/restore", map[string]any{"password": pw, "content": file, "dryRun": true}, &res); s != 200 ||
		!res.DryRun || res.Tables["zones"] != 1 || res.Tables["users"] != 2 {
		t.Fatalf("dry run: %d %+v", s, res)
	}
	if s := c.do("POST", "/api/v1/restore", map[string]any{"password": pw, "content": file}, &res); s != 200 || res.DryRun {
		t.Fatalf("restore: %d", s)
	}
	// Every session is revoked: log in again. The token revoked since the
	// backup stays revoked, old recovery codes stay invalid; the TOTP
	// (unchanged since the backup) works.
	c.expect("GET", "/api/v1/dns/zones", nil, 401, TUnauthenticated)
	tc := h.client()
	tc.origin, tc.token = "", token
	tc.expect("GET", "/api/v1/users", nil, 401, TUnauthenticated)
	c = h.client()
	if st := c.login("admin", adminPass); st.State != "mfa_required" {
		t.Fatalf("login after restore: %+v", st)
	}
	c.expect("POST", "/api/v1/auth/mfa/recovery", map[string]string{"code": codes[1]}, 401, TUnauthenticated)
	h.clock = 31 * time.Second
	if s := c.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": totpCode(t, secret, time.Now().Add(h.clock))}, nil); s != 200 {
		t.Fatalf("TOTP after restore: %d", s)
	}
	var zl struct{ Items []struct{ Name string } }
	c.do("GET", "/api/v1/dns/zones", nil, &zl)
	if len(zl.Items) != 1 || zl.Items[0].Name != "maison.lan" {
		t.Fatalf("zones after restore: %+v", zl)
	}
	var lk struct{ Answers []string }
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "nas.maison.lan", "type": "A"}, &lk)
	if len(lk.Answers) != 1 {
		t.Fatalf("DNS after restore: %+v", lk)
	}

	// A fresh install (another data key) restores the same file: the admin
	// logs in with the TOTP and recovery codes of the backup.
	h2 := newHarness(t, nil)
	c2, _, _ := adminWithSecret(t, h2)
	if s := c2.do("POST", "/api/v1/restore", map[string]any{"password": pw, "content": file}, &res); s != 200 {
		t.Fatalf("restore on a new install: %d", s)
	}
	l := h2.client()
	if st := l.login("admin", adminPass); st.State != "mfa_required" {
		t.Fatalf("login: %+v", st)
	}
	var ok stateResp
	h2.clock = 31 * time.Second
	if s := l.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": totpCode(t, secret, time.Now().Add(h2.clock))}, &ok); s != 200 {
		t.Fatalf("TOTP from the backup: %d", s)
	}
	l2 := h2.client()
	l2.login("admin", adminPass)
	if s := l2.do("POST", "/api/v1/auth/mfa/recovery", map[string]string{"code": codes[0]}, &ok); s != 200 {
		t.Fatalf("recovery code from the backup: %d", s)
	}
	// The session of the replaced admin account is gone; the restored admin works.
	c2.expect("GET", "/api/v1/backups", nil, 401, TUnauthenticated)
	l.expect("GET", "/api/v1/backups", nil, 200, "")
	// The API token of the backup works on the new install (disaster recovery).
	tk2 := h2.client()
	tk2.origin, tk2.token = "", token
	tk2.expect("GET", "/api/v1/users", nil, 200, "")
	// Read-only users cannot back up.
	ro := h2.client()
	ro.login("lecteur", adminPass)
	ro.expect("POST", "/api/v1/backup", map[string]string{"password": pw}, 403, TForbidden)
	// The restore brought another data key: the audit entries signed with
	// the previous one still verify (keyring).
	if id, err := h2.audit.Verify(t.Context()); err != nil || id != "" {
		t.Fatalf("audit chain after a restore with another key: %q %v", id, err)
	}
}

// A backup without an active admin would lock everyone out: refused, even
// as a dry run.
func TestRestoreNeedsAnAdmin(t *testing.T) {
	const pw = "sauvegarde très secrète"
	h := newHarness(t, nil)
	c, _, _ := adminWithSecret(t, h)
	ctx := context.Background()
	if _, err := h.srv.db.ExecContext(ctx, `UPDATE users SET disabled = 1`); err != nil {
		t.Fatal(err)
	}
	file, err := h.srv.backup.Create(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.db.ExecContext(ctx, `UPDATE users SET disabled = 0`); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		c.expect("POST", "/api/v1/restore", map[string]any{"password": pw, "content": string(file), "dryRun": dry}, 422, TValidation)
	}
	if s := c.do("GET", "/api/v1/users", nil, nil); s != 200 {
		t.Fatalf("admin session after the refused restore: %d", s)
	}
}

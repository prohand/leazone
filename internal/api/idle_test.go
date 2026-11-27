package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/auth"
)

// getWith sends a GET with extra headers and returns the status code.
func (c *testClient) getWith(path string, headers map[string]string) int {
	c.h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+testHost+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// Automatic refreshes of the UI (polling) must not keep an idle session
// alive: only the user's own requests count as activity. The expiry is
// still checked on background requests.
func TestBackgroundRequestsDoNotKeepSessionAlive(t *testing.T) {
	h := newHarness(t, nil)
	idle := time.Duration(h.auth.Security().SessionIdleMinutes) * time.Minute
	bg := map[string]string{BackgroundHeader: "1"}

	// Background polling only: the session ends after the idle timeout.
	c, _, _ := adminWithSecret(t, h)
	for at := time.Minute; at < idle; at += 5 * time.Minute {
		h.clock = at
		if s := c.getWith("/api/v1/me", bg); s != 200 {
			t.Fatalf("background request at %v: %d", at, s)
		}
	}
	h.clock = idle + time.Minute
	if s := c.getWith("/api/v1/me", bg); s != 401 {
		t.Fatalf("background request after the idle timeout: %d, want 401", s)
	}
	// The session is gone for good (revoked), even for a user request.
	if s := c.getWith("/api/v1/me", nil); s != 401 {
		t.Fatalf("user request after the idle timeout: %d, want 401", s)
	}

	// A user request does refresh the activity (readonly user: no MFA
	// under the "admins" policy set by adminWithSecret).
	h.clock = 0
	if _, err := h.auth.CreateUser(context.Background(), "ro", auth.RoleReadonly, "readonly password"); err != nil {
		t.Fatal(err)
	}
	c2 := h.client()
	if st := c2.login("ro", "readonly password"); st.State != "authenticated" {
		t.Fatalf("readonly login: %s", st.State)
	}
	h.clock = idle - time.Minute
	if s := c2.getWith("/api/v1/me", nil); s != 200 {
		t.Fatalf("user request: %d", s)
	}
	h.clock = idle + 5*time.Minute
	if s := c2.getWith("/api/v1/me", bg); s != 200 {
		t.Fatalf("background request after recent activity: %d", s)
	}
}

// The event stream (EventSource cannot send headers) is always background.
func TestEventStreamIsBackground(t *testing.T) {
	cases := map[string]bool{"/api/v1/events": true, "/api/v1/me": false, "/api/v1/dashboard": false}
	for path, want := range cases {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if got := background(r); got != want {
			t.Errorf("background(%s) = %v, want %v", path, got, want)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/cluster", nil)
	r.Header.Set(BackgroundHeader, "1")
	if !background(r) {
		t.Error("flagged request is not background")
	}
}

// A refused origin is told apart from a missing CSRF token: the UI must not
// treat it as a lost session.
func TestOriginRefusedReason(t *testing.T) {
	h := newHarness(t, nil)
	c, _, _ := adminWithSecret(t, h)
	c.origin = "https://evil.test"
	req, _ := http.NewRequest(http.MethodPost, "https://"+testHost+"/api/v1/me/tokens", strings.NewReader(`{"name":"x","scope":"read"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.origin)
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var p struct {
		Type   string `json:"type"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 || p.Type != TCSRF || p.Reason != "origin" || p.Status != 403 || p.Detail == "" {
		t.Fatalf("origin refused: %d %+v", resp.StatusCode, p)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
}

// /me tells the UI whether the policy accepts TOTP (step-up dialog).
func TestMeTOTPAllowed(t *testing.T) {
	h := newHarness(t, nil)
	sec := h.auth.Security()
	sec.MFARequiredFor = "admins"
	h.auth.SetSecurity(context.Background(), sec)
	if _, err := h.auth.CreateUser(context.Background(), "ro", auth.RoleReadonly, "readonly password"); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	if st := c.login("ro", "readonly password"); st.State != "authenticated" {
		t.Fatalf("readonly login: %s", st.State)
	}
	var me struct {
		TOTPAllowed bool `json:"totpAllowed"`
	}
	if s := c.do("GET", "/api/v1/me", nil, &me); s != 200 || !me.TOTPAllowed {
		t.Fatalf("me: %d %+v", s, me)
	}
	sec.MFAMethods = "passkey"
	h.auth.SetSecurity(context.Background(), sec)
	me.TOTPAllowed = true
	if s := c.do("GET", "/api/v1/me", nil, &me); s != 200 || me.TOTPAllowed {
		t.Fatalf("me (passkey only): %d %+v", s, me)
	}
}

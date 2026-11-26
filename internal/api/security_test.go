package api

import (
	"context"
	"testing"
	"time"
)

// A stolen full session must not add a second factor or an API token
// without a step-up (lasting access); the forced enrollment is not asked.
func TestAddFactorOrTokenNeedsStepUp(t *testing.T) {
	h := newHarness(t, nil)
	c, secret, _ := adminWithSecret(t, h) // enrolled in mfa_setup: no step-up asked

	// The enrollment counts as a fresh step-up for 5 minutes.
	if s := c.do("POST", "/api/v1/me/tokens", map[string]string{"name": "a", "scope": "read"}, nil); s != 201 {
		t.Fatalf("token right after login: %d", s)
	}
	h.clock = 6 * time.Minute
	c.expect("POST", "/api/v1/me/tokens", map[string]string{"name": "b", "scope": "read"}, 403, TStepUp)
	c.expect("POST", "/api/v1/me/passkeys/begin", nil, 403, TStepUp)
	c.expect("POST", "/api/v1/me/totp/setup", nil, 403, TStepUp)

	if s := c.do("POST", "/api/v1/auth/step-up/totp", map[string]string{"code": totpCode(t, secret, time.Now().Add(h.clock))}, nil); s != 200 {
		t.Fatalf("step-up: %d", s)
	}
	if s := c.do("POST", "/api/v1/me/tokens", map[string]string{"name": "b", "scope": "read"}, nil); s != 201 {
		t.Fatalf("token after step-up: %d", s)
	}
}

// Changing the password revokes the API tokens (they may be an intruder's).
func TestPasswordChangeRevokesTokens(t *testing.T) {
	h := newHarness(t, nil)
	c, _, _ := adminWithSecret(t, h)
	u, _ := h.auth.GetUserByName(context.Background(), "admin")
	plain, _, _ := h.auth.CreateToken(context.Background(), u.ID, "script", "read", nil)
	if s := c.do("POST", "/api/v1/me/password", map[string]string{"currentPassword": adminPass, "newPassword": "a brand new password"}, nil); s != 204 {
		t.Fatalf("password change: %d", s)
	}
	tc := h.client()
	tc.origin, tc.token = "", plain
	tc.expect("GET", "/api/v1/users", nil, 401, TUnauthenticated)
	// The session used for the change is kept.
	if s := c.do("GET", "/api/v1/me", nil, nil); s != 200 {
		t.Fatalf("own session after password change: %d", s)
	}
}

// A good password must not reset the counter of second factor codes:
// logging in again does not give new TOTP attempts.
func TestMFACounterSurvivesPasswordLogin(t *testing.T) {
	h := newHarness(t, nil)
	adminWithSecret(t, h)
	for i := 0; i < 5; i++ {
		c := h.client()
		if st := c.login("admin", adminPass); st.State != "mfa_required" {
			t.Fatalf("login %d: %s", i, st.State)
		}
		c.expect("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": "000000"}, 401, TUnauthenticated)
	}
	c := h.client()
	c.login("admin", adminPass)
	c.expect("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": "000000"}, 429, TRateLimited)
	c.expect("POST", "/api/v1/auth/mfa/recovery", map[string]string{"code": "AAAAA-BBBBB"}, 429, TRateLimited)
}

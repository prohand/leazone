package auth

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// A parallel burst of wrong passwords must not run more attempts than the
// threshold: the check and the count are atomic.
func TestBruteForceParallelBurst(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "bob", RoleOperator, "a long enough one"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	tried := 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Authenticate(ctx, "bob", "wrong password!", "10.0.0.1")
			if errors.Is(err, ErrInvalidCredentials) {
				mu.Lock()
				tried++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if tried > userThreshold {
		t.Fatalf("%d passwords tried in a burst, limit %d", tried, userThreshold)
	}
}

func TestIPKeyGroupsIPv6(t *testing.T) {
	if a, b := ipKey("2001:db8:1:2::1"), ipKey("2001:db8:1:2:ffff::9"); a != b || a != "ip:2001:db8:1:2::/64" {
		t.Fatalf("same /64 counted apart: %s %s", a, b)
	}
	if ipKey("2001:db8:1:3::1") == ipKey("2001:db8:1:2::1") {
		t.Fatal("different /64 counted together")
	}
	if ipKey("10.0.0.1") != "ip:10.0.0.1" {
		t.Fatal("IPv4 key changed")
	}
}

func TestRoleChangeRevokesSessions(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "admin", RoleAdmin, "a long enough one"); err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser(ctx, "op", RoleOperator, "a long enough one")
	tok, _, _ := s.CreateSession(ctx, u.ID, LevelFull, "10.0.0.1", "test")
	admin := RoleAdmin
	if _, err := s.UpdateUser(ctx, u.ID, &admin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session survived a role change: %v", err)
	}
	// Nothing else changed: sessions are kept.
	tok, _, _ = s.CreateSession(ctx, u.ID, LevelFull, "10.0.0.1", "test")
	if _, err := s.UpdateUser(ctx, u.ID, &admin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok); err != nil {
		t.Fatalf("session revoked without change: %v", err)
	}
}

func TestStricterMFAPolicyRevokesSessions(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	sec := s.Security()
	sec.MFARequiredFor = "admins"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	op, _ := s.CreateUser(ctx, "op", RoleOperator, "a long enough one")
	withTOTP, _ := s.CreateUser(ctx, "op2", RoleOperator, "a long enough one")
	if _, err := s.db.ExecContext(ctx, `INSERT INTO totp(user_id, secret_enc, confirmed_at, created_at) VALUES (?, 'x', 1, 1)`, withTOTP.ID); err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.CreateSession(ctx, op.ID, LevelFull, "10.0.0.1", "test")
	tok2, _, _ := s.CreateSession(ctx, withTOTP.ID, LevelFull, "10.0.0.1", "test")
	sec.MFARequiredFor = "all"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session without MFA survived the policy change: %v", err)
	}
	if _, err := s.LookupSession(ctx, tok2); err != nil {
		t.Fatalf("session with TOTP revoked: %v", err)
	}
	// TOTP no longer accepted: the TOTP-only user must enroll a passkey.
	sec.MFAMethods = "passkey"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok2); !errors.Is(err, ErrNoSession) {
		t.Fatalf("TOTP-only session survived a passkey-only policy: %v", err)
	}
}

func TestPasswordAndMFAResetRevokeTokens(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "dave", RoleOperator, "a long enough one")
	giveTOTP(t, s, u.ID)
	plain, _, _ := s.CreateToken(ctx, u.ID, "script", "write", nil)
	if _, _, err := s.AuthenticateToken(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, u.ID, "another long one", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateToken(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Fatal("token survived a password change")
	}
	plain, _, _ = s.CreateToken(ctx, u.ID, "script", "write", nil)
	if err := s.ResetMFA(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateToken(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Fatal("token survived an MFA reset")
	}
}

// Two admins demoting each other at the same time: one must stay admin.
func TestLastAdminConcurrent(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		a, _ := s.CreateUser(ctx, "a"+string(rune('a'+round)), RoleAdmin, "a long enough one")
		b, _ := s.CreateUser(ctx, "b"+string(rune('a'+round)), RoleAdmin, "a long enough one")
		ro := RoleReadonly
		var wg sync.WaitGroup
		for _, id := range []string{a.ID, b.ID} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = s.UpdateUser(ctx, id, &ro, nil)
			}()
		}
		wg.Wait()
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("no active admin left")
		}
		// Back to a single admin for the next round.
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET role = 'readonly'`); err != nil {
			t.Fatal(err)
		}
	}
}

// Anonymous callers cannot fill the challenge store: per-client limit, and
// the oldest challenges are dropped first.
func TestCeremonyStoreBounds(t *testing.T) {
	c := newCeremonyStore()
	first := c.put("ip:10.0.0.1", CeremonyLogin, "", webauthn.SessionData{})
	other := c.put("ip:10.0.0.2", CeremonyLogin, "", webauthn.SessionData{})
	for i := 0; i < 3*ceremonyPerOwner; i++ {
		c.put("ip:10.0.0.1", CeremonyLogin, "", webauthn.SessionData{})
	}
	if len(c.byOwner["ip:10.0.0.1"]) != ceremonyPerOwner || c.anon.Len() != ceremonyPerOwner+1 {
		t.Fatalf("per-client limit not applied: %d / %d", len(c.byOwner["ip:10.0.0.1"]), c.anon.Len())
	}
	if _, ok := c.take(first, CeremonyLogin, ""); ok {
		t.Fatal("oldest challenge of the client kept")
	}
	if _, ok := c.take(other, CeremonyLogin, ""); !ok {
		t.Fatal("another client's challenge evicted")
	}
	if len(c.items) != len(c.byOwner["ip:10.0.0.1"]) {
		t.Fatal("index out of sync")
	}
}

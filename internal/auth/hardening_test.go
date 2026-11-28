package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
)

// Argon2id runs ArgonConcurrency times at most; a login waiting too long
// for a slot gets ErrBusy instead of piling up 64 MiB computations.
func TestArgonConcurrencyLimit(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "bob", RoleOperator, "a long enough one"); err != nil {
		t.Fatal(err)
	}
	s.ArgonWait = 20 * time.Millisecond
	for i := 0; i < ArgonConcurrency; i++ {
		s.argonSlots <- struct{}{}
	}
	if _, err := s.Authenticate(ctx, "bob", "a long enough one", "10.0.0.1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("login with every slot busy: %v", err)
	}
	if _, err := s.CreateUser(ctx, "carol", RoleOperator, "a long enough one"); !errors.Is(err, ErrBusy) {
		t.Fatalf("hash with every slot busy: %v", err)
	}
	<-s.argonSlots
	if _, err := s.Authenticate(ctx, "bob", "a long enough one", "10.0.0.1"); err != nil {
		t.Fatalf("login with a free slot: %v", err)
	}
	// A busy refusal is not a failed attempt.
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_guard`).Scan(&n)
	if n != 0 {
		t.Fatalf("busy refusal counted as a failure (%d rows)", n)
	}
}

// One client cannot have more than ipInFlight attempts verified at once.
func TestPerClientAttemptsInFlight(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	var releases []func()
	for i := 0; i < ipInFlight; i++ {
		r, err := s.GuardEnter(ctx, ipKey("10.0.0.1"), userKey("u"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
		releases = append(releases, r)
	}
	var rl *RateLimitError
	if _, err := s.GuardEnter(ctx, ipKey("10.0.0.1"), userKey("other")); !errors.As(err, &rl) {
		t.Fatalf("attempt over the in-flight limit: %v", err)
	}
	if r, err := s.GuardEnter(ctx, ipKey("10.0.0.2"), userKey("other")); err != nil {
		t.Fatalf("another client refused: %v", err)
	} else {
		r()
	}
	releases[0]()
	if r, err := s.GuardEnter(ctx, ipKey("10.0.0.1"), userKey("other")); err != nil {
		t.Fatalf("attempt after a release: %v", err)
	} else {
		r()
	}
}

// A name no account can have is refused before any hash and without a
// per-name counter (no row keyed by an attacker-chosen 1 MiB string).
func TestLoginRefusesImpossibleNames(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	for i := 0; i < ArgonConcurrency; i++ {
		s.argonSlots <- struct{}{} // any hash would block: none must run
	}
	s.ArgonWait = time.Hour
	for _, name := range []string{strings.Repeat("a", 1<<20), "bob<script>", strings.Repeat("b", 65), ""} {
		if _, err := s.Authenticate(ctx, name, "whatever password", "10.0.0.1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("name %.20q: %v", name, err)
		}
	}
	var keys []string
	rows, _ := s.db.QueryContext(ctx, `SELECT key FROM login_guard`)
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		keys = append(keys, k)
	}
	rows.Close()
	if len(keys) != 1 || keys[0] != "ip:10.0.0.1" {
		t.Fatalf("guard keys = %v, want only the client", keys)
	}
	if name, ok := LoginName("  Bob.Smith "); !ok || name != "bob.smith" {
		t.Fatalf("valid name refused: %q", name)
	}
}

// A role change and a stricter policy revoke API tokens; a token is refused
// while its owner lacks a factor the policy requires.
func TestTokensFollowRoleAndMFA(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "admin", RoleAdmin, "a long enough one"); err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser(ctx, "op", RoleOperator, "a long enough one")
	giveTOTP(t, s, u.ID)
	plain, _, _ := s.CreateToken(ctx, u.ID, "script", "write", nil)
	ro := RoleReadonly
	if _, err := s.UpdateUser(ctx, u.ID, &ro, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateToken(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Fatal("token survived a role change")
	}

	// TOTP-only user, policy switched to passkey only.
	plain, _, _ = s.CreateToken(ctx, u.ID, "script", "write", nil)
	sec := s.Security()
	sec.MFAMethods = "passkey"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	var revoked int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL`, u.ID).Scan(&revoked)
	if revoked != 0 {
		t.Fatal("token not revoked by the stricter policy")
	}

	// Policy "admins only": no factor needed; then MFA required again
	// without the revocation (setting replicated from the other node).
	sec.MFARequiredFor, sec.MFAMethods = "admins", "passkey_or_totp"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	plain, _, _ = s.CreateToken(ctx, u.ID, "script", "read", nil)
	if _, _, err := s.AuthenticateToken(ctx, plain); err != nil {
		t.Fatalf("token refused while no factor is required: %v", err)
	}
	s.mu.Lock()
	s.sec.MFARequiredFor = "all"
	s.mu.Unlock()
	if _, _, err := s.AuthenticateToken(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Fatal("token accepted although its owner has no required factor")
	}
}

func TestAuditRetentionSetting(t *testing.T) {
	sec := DefaultSecurity()
	if sec.AuditRetentionDays != 365 {
		t.Fatalf("default retention %d", sec.AuditRetentionDays)
	}
	sec.AuditRetentionDays = 0 // older clients do not send the field
	if errs := sec.Validate(); len(errs) != 0 || sec.AuditRetentionDays != 365 {
		t.Fatalf("missing retention: %v %d", errs, sec.AuditRetentionDays)
	}
	sec.AuditRetentionDays = 7
	if errs := sec.Validate(); errs["auditRetentionDays"] == "" {
		t.Fatal("7 days accepted")
	}
}

// A flood of anonymous challenges never evicts a user's challenge.
func TestCeremonyAnonymousFloodKeepsUserChallenges(t *testing.T) {
	c := newCeremonyStore()
	mine := c.put("user-1", CeremonyRegister, "user-1", webauthn.SessionData{})
	for i := 0; i < ceremonyMaxAnon+ceremonyMaxUser; i++ {
		c.put("ip:10.0."+string(rune('0'+i%10))+"."+string(rune('0'+i/10%10))+string(rune('0'+i/100%10))+string(rune('0'+i/1000%10)),
			CeremonyLogin, "", webauthn.SessionData{})
	}
	if c.anon.Len() > ceremonyMaxAnon {
		t.Fatalf("anonymous challenges: %d", c.anon.Len())
	}
	if _, ok := c.take(mine, CeremonyRegister, "user-1"); !ok {
		t.Fatal("user challenge evicted by anonymous ones")
	}
}

// After the second factor, the session gets a new cookie value and a new
// CSRF token; the pending one stops working.
func TestPromoteSessionRotates(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "bob", RoleOperator, "a long enough one")
	tok, se, _ := s.CreateSession(ctx, u.ID, LevelMFAPending, "10.0.0.1", "test")
	ntok, ns, err := s.PromoteSession(ctx, se, "10.0.0.2", "test")
	if err != nil {
		t.Fatal(err)
	}
	if ntok == tok || ns.CSRF == se.CSRF || ns.PublicID == se.PublicID || ns.Level != LevelFull || !s.Elevated(ns) {
		t.Fatalf("session not renewed: %+v", ns)
	}
	if _, err := s.LookupSession(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatal("pending session still valid")
	}
	got, err := s.LookupSession(ctx, ntok)
	if err != nil || got.Level != LevelFull || got.IP != "10.0.0.2" {
		t.Fatalf("new session: %+v %v", got, err)
	}
	if _, _, err := s.PromoteSession(ctx, se, "10.0.0.2", "test"); !errors.Is(err, ErrNoSession) {
		t.Fatal("a revoked session was promoted")
	}
}

// Under a passkey-only policy, a TOTP no longer logs in but still proves
// the user's identity for the passkey enrollment.
func TestTOTPProofIgnoresPolicy(t *testing.T) {
	s, now := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "bob", RoleOperator, "a long enough one")
	setup, err := s.BeginTOTP(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(setup.Secret, *now)
	if err := s.ConfirmTOTP(ctx, u, code); err != nil {
		t.Fatal(err)
	}
	sec := s.Security()
	sec.MFAMethods = "passkey"
	if _, err := s.SetSecurity(ctx, sec); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	code, _ = totp.GenerateCode(setup.Secret, *now)
	if err := s.VerifyTOTP(ctx, u.ID, code); !errors.Is(err, ErrTOTPNotAllowed) {
		t.Fatalf("TOTP accepted as a factor: %v", err)
	}
	if err := s.VerifyTOTPProof(ctx, u.ID, code); err != nil {
		t.Fatalf("TOTP proof: %v", err)
	}
	if err := s.VerifyTOTPProof(ctx, u.ID, code); !errors.Is(err, ErrBadCode) {
		t.Fatal("TOTP proof replayed")
	}
}

package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

func newTestService(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := db.Migrate(context.Background(), t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	s, err := NewService(context.Background(), db, box, log)
	if err != nil {
		t.Fatal(err)
	}
	// Cheap Argon2 for tests.
	s.Argon = Argon2Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, &now
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery", DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword("correct horse battery", h); !ok {
		t.Fatal("good password rejected")
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("bad password accepted")
	}
	h2, _ := HashPassword("correct horse battery", DefaultArgon2)
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short", "bob") == nil {
		t.Fatal("short password accepted")
	}
	if CheckPasswordPolicy("bobbobbobbob", "bobbobbobbob") == nil {
		t.Fatal("password = username accepted")
	}
	if err := CheckPasswordPolicy("a long enough one", "bob"); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPReplay(t *testing.T) {
	setup, err := NewTOTP("Leazone", "bob")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, _ := totp.GenerateCode(setup.Secret, now)
	c, ok := CheckTOTP(setup.Secret, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := CheckTOTP(setup.Secret, code, now, c); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := CheckTOTP(setup.Secret, "000000", now, 0); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	// Previous step still accepted (clock skew), two steps back is not.
	old, _ := totp.GenerateCode(setup.Secret, now.Add(-30*time.Second))
	if _, ok := CheckTOTP(setup.Secret, old, now, 0); !ok {
		t.Fatal("code from previous step rejected")
	}
	older, _ := totp.GenerateCode(setup.Secret, now.Add(-90*time.Second))
	if _, ok := CheckTOTP(setup.Secret, older, now, 0); ok && older != code && older != old {
		t.Fatal("too old code accepted")
	}
}

func TestPermissions(t *testing.T) {
	cases := []struct {
		role  Role
		scope string
		perm  Permission
		write bool
		want  bool
	}{
		{RoleAdmin, "", PermAdmin, true, true},
		{RoleOperator, "", PermAdmin, false, false},
		{RoleOperator, "", PermRecordsWrite, true, true},
		{RoleOperator, "", PermConfigWrite, true, false},
		{RoleReadonly, "", PermRead, false, true},
		{RoleReadonly, "", PermLeasesWrite, true, false},
		{RoleAdmin, "read", PermAdmin, false, true},       // read token may read admin data
		{RoleAdmin, "read", PermConfigWrite, true, false}, // read token never writes
		{RoleAdmin, "write", PermConfigWrite, true, true},
		{RoleReadonly, "write", PermRecordsWrite, true, false}, // token never exceeds the role
		{RoleOperator, "read", PermAdmin, false, false},        // nor for reads
		{RoleAdmin, "write", PermSelf, false, false},           // tokens cannot manage the account
	}
	for _, c := range cases {
		if got := Allowed(c.role, c.scope, c.perm, c.write); got != c.want {
			t.Errorf("Allowed(%s,%q,%s,write=%v) = %v, want %v", c.role, c.scope, c.perm, c.write, got, c.want)
		}
	}
}

func TestBruteForceLock(t *testing.T) {
	s, now := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "bob", RoleOperator, "a long enough one"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < userThreshold; i++ {
		if _, err := s.Authenticate(ctx, "bob", "wrong password!", "10.0.0.1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var rl *RateLimitError
	if _, err := s.Authenticate(ctx, "bob", "a long enough one", "10.0.0.1"); !errors.As(err, &rl) {
		t.Fatalf("account not locked: %v", err)
	}
	if rl.RetryAfter != time.Minute {
		t.Fatalf("first lock = %v, want 1m", rl.RetryAfter)
	}
	// After the lock, one more failure doubles it.
	*now = now.Add(61 * time.Second)
	_, _ = s.Authenticate(ctx, "bob", "wrong again!!", "10.0.0.2")
	if _, err := s.Authenticate(ctx, "bob", "a long enough one", "10.0.0.2"); !errors.As(err, &rl) || rl.RetryAfter != 2*time.Minute {
		t.Fatalf("second lock = %v (%v), want 2m", rl, err)
	}
	*now = now.Add(121 * time.Second)
	if _, err := s.Authenticate(ctx, "bob", "a long enough one", "10.0.0.3"); err != nil {
		t.Fatalf("login after lock: %v", err)
	}
	// Unknown users are locked the same way (no account enumeration).
	for i := 0; i < userThreshold; i++ {
		_, _ = s.Authenticate(ctx, "ghost", "whatever pass", "10.0.0.9")
	}
	if _, err := s.Authenticate(ctx, "ghost", "whatever pass", "10.0.0.9"); !errors.As(err, &rl) {
		t.Fatal("unknown account not rate limited")
	}
}

func TestRecoveryCodesSingleUse(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "alice", RoleAdmin, "a long enough one")
	codes, err := s.RegenerateRecoveryCodes(ctx, u.ID)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("codes=%v err=%v", codes, err)
	}
	if err := s.UseRecoveryCode(ctx, u.ID, " "+codes[3]+" "); err != nil {
		t.Fatalf("valid code: %v", err)
	}
	if err := s.UseRecoveryCode(ctx, u.ID, codes[3]); !errors.Is(err, ErrBadCode) {
		t.Fatalf("reused code: %v", err)
	}
	m, _ := s.MFA(ctx, u.ID)
	if m.RecoveryRemaining != RecoveryCodeCount-1 {
		t.Fatalf("remaining = %d", m.RecoveryRemaining)
	}
	// Regeneration invalidates old codes.
	if _, err := s.RegenerateRecoveryCodes(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.UseRecoveryCode(ctx, u.ID, codes[0]); !errors.Is(err, ErrBadCode) {
		t.Fatal("old code still valid after regeneration")
	}
}

func TestLastAdminProtected(t *testing.T) {
	s, _ := newTestService(t)
	ctx := context.Background()
	a, _ := s.CreateUser(ctx, "admin", RoleAdmin, "a long enough one")
	ro := RoleReadonly
	if _, err := s.UpdateUser(ctx, a.ID, &ro, nil); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, a.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting last admin: %v", err)
	}
	b, _ := s.CreateUser(ctx, "admin2", RoleAdmin, "a long enough one")
	if err := s.DeleteUser(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	yes := true
	if _, err := s.UpdateUser(ctx, b.ID, nil, &yes); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling last admin: %v", err)
	}
}

func TestSessionIdleAndRevoke(t *testing.T) {
	s, now := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "carol", RoleReadonly, "a long enough one")
	tok, se, err := s.CreateSession(ctx, u.ID, LevelFull, "10.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(31 * time.Minute) // default idle timeout is 30 min
	if _, err := s.LookupSession(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session still valid: %v", err)
	}
	tok2, se2, _ := s.CreateSession(ctx, u.ID, LevelFull, "10.0.0.1", "test")
	if err := s.RevokeSessionByPublicID(ctx, u.ID, se2.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok2); !errors.Is(err, ErrNoSession) {
		t.Fatal("revoked session still valid")
	}
	_ = se
}

func TestAPITokens(t *testing.T) {
	s, now := newTestService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "dave", RoleOperator, "a long enough one")
	exp := now.Add(time.Hour)
	plain, tk, err := s.CreateToken(ctx, u.ID, "script", "read", &exp)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.AuthenticateToken(ctx, plain); err != nil || got.ID != u.ID {
		t.Fatalf("token auth: %v", err)
	}
	if _, _, err := s.AuthenticateToken(ctx, plain+"x"); !errors.Is(err, ErrBadToken) {
		t.Fatal("tampered token accepted")
	}
	*now = now.Add(2 * time.Hour)
	if _, _, err := s.AuthenticateToken(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Fatal("expired token accepted")
	}
	plain2, tk2, _ := s.CreateToken(ctx, u.ID, "other", "write", nil)
	if err := s.RevokeToken(ctx, u.ID, tk2.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateToken(ctx, plain2); !errors.Is(err, ErrBadToken) {
		t.Fatal("revoked token accepted")
	}
	_ = tk
}

func TestLoginLevel(t *testing.T) {
	s, _ := newTestService(t)
	admin := &User{Role: RoleAdmin}
	op := &User{Role: RoleOperator}
	if l := s.LoginLevel(admin, MFAStatus{}); l != LevelMFASetup {
		t.Fatalf("admin without MFA: %s", l)
	}
	if l := s.LoginLevel(op, MFAStatus{TOTPEnabled: true}); l != LevelMFAPending {
		t.Fatalf("op with TOTP: %s", l)
	}
	sec := s.Security()
	sec.MFARequiredFor, sec.MFAMethods = "admins", "passkey"
	if _, err := s.SetSecurity(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	if l := s.LoginLevel(op, MFAStatus{}); l != LevelFull {
		t.Fatalf("op without MFA, policy admins: %s", l)
	}
	// TOTP no longer allowed: an admin with only TOTP must enroll a passkey.
	if l := s.LoginLevel(admin, MFAStatus{TOTPEnabled: true}); l != LevelMFASetup {
		t.Fatalf("admin with TOTP under passkey-only policy: %s", l)
	}
}

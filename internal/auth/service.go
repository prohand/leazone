package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

// Service gathers all account and authentication logic.
type Service struct {
	db         *store.DB
	box        *secrets.Box
	log        *slog.Logger
	Now        func() time.Time
	Argon      Argon2Params
	ceremonies *ceremonyStore

	mu  sync.RWMutex
	sec SecuritySettings

	guardMu  sync.Mutex
	inflight map[string]int // login_guard key -> attempts being verified

	// argonSlots bounds the Argon2id computations running at once (each
	// takes Argon.Memory): a burst of logins cannot exhaust the memory.
	argonSlots chan struct{}
	// ArgonWait is how long a password check waits for a free slot.
	ArgonWait time.Duration
}

// ArgonConcurrency is the number of password hashes computed at once.
const ArgonConcurrency = 4

// ErrBusy means that too many password checks are running: retry later.
var ErrBusy = errors.New("trop de connexions en cours, réessayez dans quelques secondes")

// NewService loads the security settings and returns the service.
func NewService(ctx context.Context, db *store.DB, box *secrets.Box, log *slog.Logger) (*Service, error) {
	s := &Service{db: db, box: box, log: log, Now: time.Now, Argon: DefaultArgon2, ceremonies: newCeremonyStore(),
		argonSlots: make(chan struct{}, ArgonConcurrency), ArgonWait: 2 * time.Second}
	sec := DefaultSecurity()
	if _, err := db.GetSetting(ctx, SettingsKey, &sec); err != nil {
		return nil, err
	}
	s.sec = sec
	return s, nil
}

// ReloadSettings re-reads the security settings (after replication).
func (s *Service) ReloadSettings(ctx context.Context) error {
	sec := DefaultSecurity()
	if _, err := s.db.GetSetting(ctx, SettingsKey, &sec); err != nil {
		return err
	}
	s.mu.Lock()
	s.sec = sec
	s.mu.Unlock()
	return nil
}

// Security returns a copy of the current security settings.
func (s *Service) Security() SecuritySettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.sec
	c.UIAllowedNetworks = append([]string{}, s.sec.UIAllowedNetworks...)
	return c
}

// SetSecurity validates and stores new security settings.
func (s *Service) SetSecurity(ctx context.Context, sec SecuritySettings) (SecuritySettings, error) {
	if errs := sec.Validate(); len(errs) > 0 {
		return sec, ErrValidation(errs)
	}
	if err := s.db.PutSetting(ctx, SettingsKey, sec); err != nil {
		return sec, err
	}
	s.mu.Lock()
	s.sec = sec
	s.mu.Unlock()
	return sec, s.revokeUnprotectedSessions(ctx, sec)
}

// revokeUnprotectedSessions ends the open sessions and revokes the API
// tokens of users that the policy subjects to MFA but who have no second
// factor it accepts (after a policy change): at their next login they will
// have to enroll one.
func (s *Service) revokeUnprotectedSessions(ctx context.Context, sec SecuritySettings) error {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if !sec.MFARequired(u.Role) {
			continue
		}
		m, err := s.MFA(ctx, u.ID)
		if err != nil {
			return err
		}
		if sec.FactorUsable(m) {
			continue
		}
		now := s.Now().UnixMilli()
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND auth_level = ? AND revoked_at IS NULL`,
			now, u.ID, LevelFull); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			now, u.ID); err != nil {
			return err
		}
	}
	return nil
}

// User is an account.
type User struct {
	ID                string
	Username          string
	Role              Role
	PasswordHash      string
	Handle            []byte // WebAuthn user handle (random, 32 bytes)
	Disabled          bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastLoginAt       *time.Time
	PasswordChangedAt time.Time
}

// MFAStatus summarizes the second factors of a user.
type MFAStatus struct {
	PasskeyCount      int
	TOTPEnabled       bool
	RecoveryRemaining int
}

// Enabled reports whether the user has at least one real second factor.
func (m MFAStatus) Enabled() bool { return m.PasskeyCount > 0 || m.TOTPEnabled }

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

// Errors returned by user management.
var (
	ErrUserExists   = errors.New("ce nom d'utilisateur existe déjà")
	ErrLastAdmin    = errors.New("impossible : c'est le dernier administrateur actif")
	ErrUserDisabled = errors.New("compte désactivé")
)

const userCols = `id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at,
	(SELECT last_login_at FROM user_activity WHERE user_id = users.id), password_changed_at`

const userInsertCols = `id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at, password_changed_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created, updated, pwChanged int64
	var last sql.NullInt64
	var disabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &u.Handle, &disabled, &created, &updated, &last, &pwChanged); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = time.UnixMilli(created)
	u.UpdatedAt = time.UnixMilli(updated)
	u.PasswordChangedAt = time.UnixMilli(pwChanged)
	if last.Valid {
		t := time.UnixMilli(last.Int64)
		u.LastLoginAt = &t
	}
	return &u, nil
}

// CreateUser adds an account. The password must follow the policy.
func (s *Service) CreateUser(ctx context.Context, username string, role Role, password string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	errs := map[string]string{}
	if !usernameRe.MatchString(username) {
		errs["username"] = "2 à 32 caractères : minuscules, chiffres, point, tiret, souligné"
	}
	if !role.Valid() {
		errs["role"] = "rôle inconnu"
	}
	if err := CheckPasswordPolicy(password, username); err != nil {
		errs["password"] = err.Error()
	}
	if len(errs) > 0 {
		return nil, ErrValidation(errs)
	}
	hash, err := s.hashPassword(ctx, password)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	u := &User{ID: ids.New(), Username: username, Role: role, PasswordHash: hash, Handle: randomBytes(32),
		CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users(`+userInsertCols+`) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		u.ID, u.Username, u.Role, u.PasswordHash, u.Handle, now.UnixMilli(), now.UnixMilli(), now.UnixMilli())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUserExists
		}
		return nil, err
	}
	return u, nil
}

// UserCount returns the number of accounts.
func (s *Service) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// GetUser loads a user by id.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetUserByName loads a user by name (case-insensitive).
func (s *Service) GetUserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`,
		strings.ToLower(strings.TrimSpace(name))))
}

// GetUserByHandle loads a user by WebAuthn user handle.
func (s *Service) GetUserByHandle(ctx context.Context, h []byte) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE webauthn_handle = ?`, h))
}

// ListUsers returns every account sorted by name.
func (s *Service) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// MFA returns the MFA summary of a user.
func (s *Service) MFA(ctx context.Context, userID string) (MFAStatus, error) {
	var m MFAStatus
	var totp int
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?1),
		(SELECT COUNT(*) FROM totp WHERE user_id = ?1 AND confirmed_at IS NOT NULL),
		(SELECT COUNT(*) FROM recovery_codes c WHERE c.user_id = ?1
			AND NOT EXISTS (SELECT 1 FROM recovery_usage u WHERE u.code_id = c.id))`, userID).
		Scan(&m.PasskeyCount, &totp, &m.RecoveryRemaining)
	m.TOTPEnabled = totp > 0
	return m, err
}

// activeAdmins counts enabled admins, optionally ignoring one user. It runs
// in the transaction that changes the user (BEGIN IMMEDIATE): two admins
// cannot demote or delete each other at the same time.
func activeAdmins(ctx context.Context, tx *sql.Tx, except string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, except).Scan(&n)
	return n, err
}

// UpdateUser changes role and/or disabled flag. The last active admin is
// protected. A role change or a deactivation ends the user's sessions: the
// MFA policy depends on the role and is only applied at login.
func (s *Service) UpdateUser(ctx context.Context, id string, role *Role, disabled *bool) (*User, error) {
	if _, err := s.GetUser(ctx, id); err != nil {
		return nil, err
	}
	if role != nil && !role.Valid() {
		return nil, ErrValidation{"role": "rôle inconnu"}
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
		if err != nil {
			return err
		}
		newRole, newDisabled := u.Role, u.Disabled
		if role != nil {
			newRole = *role
		}
		if disabled != nil {
			newDisabled = *disabled
		}
		if u.Role == RoleAdmin && !u.Disabled && (newRole != RoleAdmin || newDisabled) {
			n, err := activeAdmins(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		d := 0
		if newDisabled {
			d = 1
		}
		now := s.Now().UnixMilli()
		if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, updated_at = ? WHERE id = ?`,
			newRole, d, now, id); err != nil {
			return err
		}
		if newDisabled || newRole != u.Role {
			if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
				return err
			}
		}
		// API tokens act with the owner's current role: tokens created for
		// the old role must not carry over to the new one.
		if newRole != u.Role {
			_, err = tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// DeleteUser removes an account and everything attached to it.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if u.Role == RoleAdmin && !u.Disabled {
			n, err := activeAdmins(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		for _, q := range []string{
			`DELETE FROM webauthn_usage WHERE credential_id IN (SELECT credential_id FROM webauthn_credentials WHERE user_id = ?)`,
			`DELETE FROM recovery_usage WHERE code_id IN (SELECT id FROM recovery_codes WHERE user_id = ?)`,
			`DELETE FROM totp_usage WHERE user_id = ?`,
			`DELETE FROM user_activity WHERE user_id = ?`,
			`DELETE FROM users WHERE id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetPassword replaces the password (policy enforced) and revokes the user's
// API tokens and other sessions (exceptSession = public id of the session to keep).
func (s *Service) SetPassword(ctx context.Context, userID, password, exceptSession string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := CheckPasswordPolicy(password, u.Username); err != nil {
		return ErrValidation{"newPassword": err.Error()}
	}
	hash, err := s.hashPassword(ctx, password)
	if err != nil {
		return err
	}
	now := s.Now().UnixMilli()
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?`,
		hash, now, now, userID); err != nil {
		return err
	}
	// A new password means the old one may be known: its sessions and API
	// tokens (possibly created by an intruder) must not outlive it.
	if err := s.RevokeUserTokens(ctx, userID); err != nil {
		return err
	}
	return s.RevokeUserSessions(ctx, userID, exceptSession)
}

// ResetMFA removes passkeys, TOTP and recovery codes and revokes the user's
// API tokens. The user will have to enroll again at next login (if the
// policy requires MFA). Callers revoke the sessions.
func (s *Service) ResetMFA(ctx context.Context, userID string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			s.Now().UnixMilli(), userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM login_guard WHERE key = (SELECT 'mfa:' || username FROM users WHERE id = ?)`,
			userID); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM webauthn_usage WHERE credential_id IN (SELECT credential_id FROM webauthn_credentials WHERE user_id = ?)`,
			`DELETE FROM webauthn_credentials WHERE user_id = ?`,
			`DELETE FROM totp WHERE user_id = ?`,
			`DELETE FROM totp_usage WHERE user_id = ?`,
			`DELETE FROM recovery_usage WHERE code_id IN (SELECT id FROM recovery_codes WHERE user_id = ?)`,
			`DELETE FROM recovery_codes WHERE user_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

// Authenticate verifies username + password with brute-force protection.
// It always spends one Argon2 computation, even for unknown users.
// A good password only clears the password counter: second factor attempts
// have their own counter (MFAKey), cleared after a complete login.
func (s *Service) Authenticate(ctx context.Context, username, password, ip string) (*User, error) {
	name, valid := LoginName(username)
	if !valid {
		// No account can have this name: refuse without a password hash
		// and without a per-name counter (an attacker chooses the name), but
		// count the failure for the client.
		release, err := s.GuardEnter(ctx, ipKey(ip))
		if err != nil {
			return nil, err
		}
		defer release()
		if err := s.GuardFail(ctx, ipKey(ip)); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	username = name
	release, err := s.GuardEnter(ctx, ipKey(ip), userKey(username))
	if err != nil {
		return nil, err
	}
	defer release()
	u, err := s.GetUserByName(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	hash := dummyHash
	if u != nil {
		hash = u.PasswordHash
	}
	var ok bool
	var verr error
	if err := s.argon(ctx, func() { ok, verr = VerifyPassword(password, hash) }); err != nil {
		return nil, err
	}
	if verr != nil {
		s.log.Error("password hash unreadable", "user", username, "err", verr)
	}
	if u == nil || !ok || u.Disabled {
		if err := s.GuardFail(ctx, ipKey(ip), userKey(username)); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	if err := s.GuardReset(ctx, userKey(username)); err != nil {
		return nil, err
	}
	return u, nil
}

// MaxLoginName is the longest user name accepted at login (bytes, before
// normalization). Account names are at most 32 characters.
const MaxLoginName = 64

// LoginName normalizes a user name typed at login and reports whether an
// account can have it (valid is false for anything longer than
// MaxLoginName or outside the allowed characters).
func LoginName(raw string) (name string, valid bool) {
	if len(raw) > MaxLoginName {
		return "", false
	}
	name = strings.ToLower(strings.TrimSpace(raw))
	return name, usernameRe.MatchString(name)
}

// argon runs fn (an Argon2id computation) when one of the ArgonConcurrency
// slots is free. It returns ErrBusy after ArgonWait without a slot.
func (s *Service) argon(ctx context.Context, fn func()) error {
	t := time.NewTimer(s.ArgonWait)
	defer t.Stop()
	select {
	case s.argonSlots <- struct{}{}:
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.argonSlots }()
	fn()
	return nil
}

// hashPassword is HashPassword within the Argon2 concurrency limit.
func (s *Service) hashPassword(ctx context.Context, password string) (string, error) {
	var h string
	var err error
	if aerr := s.argon(ctx, func() { h, err = HashPassword(password, s.Argon) }); aerr != nil {
		return "", aerr
	}
	return h, err
}

// TouchLogin records a successful full login.
func (s *Service) TouchLogin(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_activity(user_id, last_login_at) VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET last_login_at = excluded.last_login_at`, userID, s.Now().UnixMilli())
	return err
}

// ipKey is the per-client counter. IPv6 clients are counted per /64: one
// host usually owns a whole /64 and could otherwise rotate addresses.
func ipKey(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Unmap().Is6() {
		p, _ := a.WithZone("").Prefix(64)
		return "ip:" + p.String()
	}
	return "ip:" + ip
}

func userKey(name string) string { return "user:" + strings.ToLower(name) }
func mfaKey(name string) string  { return "mfa:" + strings.ToLower(name) }

// UserKey is the per-account password counter (unlocked by the CLI password reset).
func UserKey(name string) string { return userKey(name) }

// MFAKey is the per-account counter of second factor codes (TOTP, recovery
// codes). It is separate from the password counter, which a good password
// clears, and is only cleared once a code is accepted.
func MFAKey(name string) string { return mfaKey(name) }

// IPKey is exported for MFA checks that share the per-IP counter.
func IPKey(ip string) string { return ipKey(ip) }

func randomBytes(n int) []byte {
	b, err := randRead(n)
	if err != nil {
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	return b
}

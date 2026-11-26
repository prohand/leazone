package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
}

// NewService loads the security settings and returns the service.
func NewService(ctx context.Context, db *store.DB, box *secrets.Box, log *slog.Logger) (*Service, error) {
	s := &Service{db: db, box: box, log: log, Now: time.Now, Argon: DefaultArgon2, ceremonies: newCeremonyStore()}
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
	return sec, nil
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
	hash, err := HashPassword(password, s.Argon)
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

// activeAdmins counts enabled admins, optionally ignoring one user.
func (s *Service) activeAdmins(ctx context.Context, except string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, except).Scan(&n)
	return n, err
}

// UpdateUser changes role and/or disabled flag. The last active admin is protected.
func (s *Service) UpdateUser(ctx context.Context, id string, role *Role, disabled *bool) (*User, error) {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	if role != nil && !role.Valid() {
		return nil, ErrValidation{"role": "rôle inconnu"}
	}
	newRole, newDisabled := u.Role, u.Disabled
	if role != nil {
		newRole = *role
	}
	if disabled != nil {
		newDisabled = *disabled
	}
	if u.Role == RoleAdmin && !u.Disabled && (newRole != RoleAdmin || newDisabled) {
		n, err := s.activeAdmins(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, ErrLastAdmin
		}
	}
	d := 0
	if newDisabled {
		d = 1
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		newRole, d, s.Now().UnixMilli(), id); err != nil {
		return nil, err
	}
	if newDisabled {
		if err := s.RevokeUserSessions(ctx, id, ""); err != nil {
			return nil, err
		}
	}
	return s.GetUser(ctx, id)
}

// DeleteUser removes an account and everything attached to it.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && !u.Disabled {
		n, err := s.activeAdmins(ctx, u.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrLastAdmin
		}
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
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
// other sessions (exceptSession = public id of the session to keep).
func (s *Service) SetPassword(ctx context.Context, userID, password, exceptSession string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := CheckPasswordPolicy(password, u.Username); err != nil {
		return ErrValidation{"newPassword": err.Error()}
	}
	hash, err := HashPassword(password, s.Argon)
	if err != nil {
		return err
	}
	now := s.Now().UnixMilli()
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?`,
		hash, now, now, userID); err != nil {
		return err
	}
	return s.RevokeUserSessions(ctx, userID, exceptSession)
}

// ResetMFA removes passkeys, TOTP and recovery codes. The user will have to
// enroll again at next login (if the policy requires MFA).
func (s *Service) ResetMFA(ctx context.Context, userID string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
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
func (s *Service) Authenticate(ctx context.Context, username, password, ip string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if err := s.GuardCheck(ctx, ipKey(ip), userKey(username)); err != nil {
		return nil, err
	}
	u, err := s.GetUserByName(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	hash := dummyHash
	if u != nil {
		hash = u.PasswordHash
	}
	ok, verr := VerifyPassword(password, hash)
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

// TouchLogin records a successful full login.
func (s *Service) TouchLogin(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_activity(user_id, last_login_at) VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET last_login_at = excluded.last_login_at`, userID, s.Now().UnixMilli())
	return err
}

func ipKey(ip string) string     { return "ip:" + ip }
func userKey(name string) string { return "user:" + strings.ToLower(name) }

// UserKey is exported for MFA checks that share the per-account counter.
func UserKey(name string) string { return userKey(name) }

// IPKey is exported for MFA checks that share the per-IP counter.
func IPKey(ip string) string { return ipKey(ip) }

func randomBytes(n int) []byte {
	b, err := randRead(n)
	if err != nil {
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	return b
}

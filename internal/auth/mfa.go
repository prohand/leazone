package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"

	"github.com/prohand/leazone/internal/ids"
)

// Errors of the MFA flows.
var (
	ErrTOTPAlreadyOn  = errors.New("TOTP est déjà activé")
	ErrTOTPNoSetup    = errors.New("aucune configuration TOTP en cours")
	ErrTOTPNotAllowed = errors.New("TOTP n'est pas autorisé par la politique de sécurité")
	ErrBadCode        = errors.New("code invalide")
)

func totpAAD(userID string) string { return "totp:" + userID }

// BeginTOTP creates (or replaces) a pending TOTP secret.
func (s *Service) BeginTOTP(ctx context.Context, u *User) (TOTPSetup, error) {
	if !s.Security().TOTPAllowed() {
		return TOTPSetup{}, ErrTOTPNotAllowed
	}
	var confirmed sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT confirmed_at FROM totp WHERE user_id = ?`, u.ID).Scan(&confirmed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return TOTPSetup{}, err
	}
	if confirmed.Valid {
		return TOTPSetup{}, ErrTOTPAlreadyOn
	}
	setup, err := NewTOTP("Leazone", u.Username)
	if err != nil {
		return TOTPSetup{}, err
	}
	enc := s.box.Seal([]byte(setup.Secret), totpAAD(u.ID))
	_, err = s.db.ExecContext(ctx, `INSERT INTO totp(user_id, secret_enc, confirmed_at, created_at) VALUES (?, ?, NULL, ?)
		ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, created_at = excluded.created_at`,
		u.ID, enc, s.Now().UnixMilli())
	return setup, err
}

// ConfirmTOTP activates the pending secret when code is right.
func (s *Service) ConfirmTOTP(ctx context.Context, u *User, code string) error {
	secret, confirmed, err := s.totpSecret(ctx, u.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTOTPNoSetup
	}
	if err != nil {
		return err
	}
	if confirmed {
		return ErrTOTPAlreadyOn
	}
	counter, ok := CheckTOTP(secret, code, s.Now(), 0)
	if !ok {
		return ErrBadCode
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE totp SET confirmed_at = ? WHERE user_id = ?`, s.Now().UnixMilli(), u.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO totp_usage(user_id, last_counter) VALUES (?, ?)
			ON CONFLICT(user_id) DO UPDATE SET last_counter = max(last_counter, excluded.last_counter)`, u.ID, counter)
		return err
	})
}

func (s *Service) totpSecret(ctx context.Context, userID string) (string, bool, error) {
	var enc string
	var confirmed sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT secret_enc, confirmed_at FROM totp WHERE user_id = ?`, userID).Scan(&enc, &confirmed); err != nil {
		return "", false, err
	}
	pt, err := s.box.Open(enc, totpAAD(userID))
	if err != nil {
		return "", false, err
	}
	return string(pt), confirmed.Valid, nil
}

// VerifyTOTP checks a code for an enabled TOTP, with replay protection.
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	if !s.Security().TOTPAllowed() {
		return ErrTOTPNotAllowed
	}
	secret, confirmed, err := s.totpSecret(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !confirmed) {
		return ErrBadCode
	}
	if err != nil {
		return err
	}
	var last int64
	err = s.db.QueryRowContext(ctx, `SELECT last_counter FROM totp_usage WHERE user_id = ?`, userID).Scan(&last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	counter, ok := CheckTOTP(secret, code, s.Now(), last)
	if !ok {
		return ErrBadCode
	}
	// Conditional update: two concurrent requests with the same code cannot both win.
	res, err := s.db.ExecContext(ctx, `INSERT INTO totp_usage(user_id, last_counter) VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET last_counter = excluded.last_counter WHERE last_counter < excluded.last_counter`,
		userID, counter)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrBadCode
	}
	return nil
}

// DisableTOTP removes TOTP.
func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp WHERE user_id = ?`, userID)
	return err
}

// RegenerateRecoveryCodes replaces all recovery codes and returns the new ones.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes := NewRecoveryCodes()
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_usage WHERE code_id IN (SELECT id FROM recovery_codes WHERE user_id = ?)`, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
			return err
		}
		for _, c := range codes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`,
				ids.New(), userID, s.recoveryHash(userID, c), s.Now().UnixMilli()); err != nil {
				return err
			}
		}
		return nil
	})
	return codes, err
}

func (s *Service) recoveryHash(userID, code string) string {
	return s.box.MAC("recovery", userID+":"+NormalizeRecoveryCode(code))
}

// UseRecoveryCode consumes a recovery code. Each code works once.
func (s *Service) UseRecoveryCode(ctx context.Context, userID, code string) error {
	want := s.recoveryHash(userID, code)
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.code_hash FROM recovery_codes c WHERE c.user_id = ?
		AND NOT EXISTS (SELECT 1 FROM recovery_usage u WHERE u.code_id = c.id)`, userID)
	if err != nil {
		return err
	}
	var match string
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			rows.Close()
			return err
		}
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			match = id
		}
	}
	rows.Close()
	if match == "" {
		return ErrBadCode
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO recovery_usage(code_id, used_at) VALUES (?, ?)`, match, s.Now().UnixMilli())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrBadCode
	}
	return nil
}

// EnsureRecoveryCodes creates codes when the user has none (first MFA
// enrollment). It returns nil when codes already exist.
func (s *Service) EnsureRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, nil
	}
	return s.RegenerateRecoveryCodes(ctx, userID)
}

// LoginLevel decides the session level after a successful password check.
func (s *Service) LoginLevel(u *User, m MFAStatus) Level {
	sec := s.Security()
	usable := m.PasskeyCount > 0 || (m.TOTPEnabled && sec.TOTPAllowed())
	switch {
	case usable:
		return LevelMFAPending
	case sec.MFARequired(u.Role):
		return LevelMFASetup
	default:
		return LevelFull
	}
}

// CanStepUp reports whether the user has a factor accepted by the step-up
// (a passkey, or TOTP when the policy allows it).
func (s *Service) CanStepUp(m MFAStatus) bool {
	return m.PasskeyCount > 0 || (m.TOTPEnabled && s.Security().TOTPAllowed())
}

// SecondFactors lists what the user can use right now as a second factor.
func (s *Service) SecondFactors(m MFAStatus) []string {
	out := []string{}
	if m.PasskeyCount > 0 {
		out = append(out, "passkey")
	}
	if m.TOTPEnabled && s.Security().TOTPAllowed() {
		out = append(out, "totp")
	}
	if m.RecoveryRemaining > 0 {
		out = append(out, "recovery")
	}
	return out
}

// SanitizeName trims a user-provided label.
func SanitizeName(n string, max int) string {
	n = strings.TrimSpace(n)
	if len([]rune(n)) > max {
		n = string([]rune(n)[:max])
	}
	return n
}

package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// APIToken is a script credential. The secret is shown once and only its
// hash is stored. Format: lz_<prefix>_<secret>.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string
	Scope      string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

// ErrBadToken is returned for any unusable token.
var ErrBadToken = errors.New("jeton invalide, expiré ou révoqué")

// CreateToken issues a new token and returns its plain value once.
func (s *Service) CreateToken(ctx context.Context, userID, name, scope string, expires *time.Time) (string, *APIToken, error) {
	name = strings.TrimSpace(name)
	errs := map[string]string{}
	if name == "" || len(name) > 64 {
		errs["name"] = "nom obligatoire (64 caractères max)"
	}
	if scope != "read" && scope != "write" {
		errs["scope"] = "valeur attendue : read ou write"
	}
	if expires != nil && !expires.After(s.Now()) {
		errs["expiresAt"] = "la date d'expiration doit être dans le futur"
	}
	if len(errs) > 0 {
		return "", nil, ErrValidation(errs)
	}
	prefix := ids.Random(5) // 8 chars
	secret := ids.Random(20)
	t := &APIToken{ID: ids.New(), UserID: userID, Name: name, Prefix: prefix, Scope: scope, CreatedAt: s.Now(), ExpiresAt: expires}
	var exp any
	if expires != nil {
		exp = expires.UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens(id, user_id, name, prefix, secret_hash, scope, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, t.ID, userID, name, prefix, hashToken(secret), scope, t.CreatedAt.UnixMilli(), exp)
	if err != nil {
		return "", nil, err
	}
	return "lz_" + prefix + "_" + secret, t, nil
}

// AuthenticateToken resolves a bearer token to its user.
func (s *Service) AuthenticateToken(ctx context.Context, plain string) (*User, *APIToken, error) {
	parts := strings.Split(plain, "_")
	if len(parts) != 3 || parts[0] != "lz" {
		return nil, nil, ErrBadToken
	}
	var t APIToken
	var hash string
	var created int64
	var exp, used sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, name, prefix, secret_hash, scope, created_at, expires_at, last_used_at
		FROM api_tokens WHERE prefix = ? AND revoked_at IS NULL`, parts[1]).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &hash, &t.Scope, &created, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrBadToken
	}
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(parts[2])), []byte(hash)) != 1 {
		return nil, nil, ErrBadToken
	}
	now := s.Now()
	if exp.Valid && now.After(time.UnixMilli(exp.Int64)) {
		return nil, nil, ErrBadToken
	}
	u, err := s.GetUser(ctx, t.UserID)
	if err != nil || u.Disabled {
		return nil, nil, ErrBadToken
	}
	// A token never outlives the MFA protection of its owner: when the
	// policy requires a second factor that the owner does not have (or no
	// longer has), the token is refused.
	if sec := s.Security(); sec.MFARequired(u.Role) {
		m, err := s.MFA(ctx, u.ID)
		if err != nil {
			return nil, nil, err
		}
		if !sec.FactorUsable(m) {
			return nil, nil, ErrBadToken
		}
	}
	if !used.Valid || now.Sub(time.UnixMilli(used.Int64)) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now.UnixMilli(), t.ID)
	}
	t.CreatedAt = time.UnixMilli(created)
	return u, &t, nil
}

// ListTokens lists the non-revoked tokens of a user.
func (s *Service) ListTokens(ctx context.Context, userID string) ([]*APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, prefix, scope, created_at, expires_at, last_used_at
		FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		var t APIToken
		var created int64
		var exp, used sql.NullInt64
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &t.Scope, &created, &exp, &used); err != nil {
			return nil, err
		}
		t.CreatedAt = time.UnixMilli(created)
		t.ExpiresAt = optTime(exp)
		t.LastUsedAt = optTime(used)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// RevokeToken revokes one of userID's tokens.
func (s *Service) RevokeToken(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		s.Now().UnixMilli(), id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// RevokeUserTokens revokes all the tokens of a user (new password, MFA reset).
func (s *Service) RevokeUserTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		s.Now().UnixMilli(), userID)
	return err
}

func optTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64)
	return &t
}

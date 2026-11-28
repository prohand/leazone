package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Level is how far a session got in the login flow.
type Level string

// Session levels.
const (
	LevelMFAPending Level = "mfa_pending" // password OK, second factor needed
	LevelMFASetup   Level = "mfa_setup"   // password OK, user must enroll MFA first
	LevelFull       Level = "full"        // fully authenticated
)

// Session is a browser session. The cookie value is never stored: only its
// SHA-256 hash, so a database leak does not leak usable sessions.
type Session struct {
	IDHash        string
	PublicID      string
	UserID        string
	Level         Level
	CSRF          string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
	ElevatedUntil *time.Time
	IP            string
	UserAgent     string
}

// ErrNoSession means the cookie is missing, unknown, expired or revoked.
var ErrNoSession = errors.New("session invalide ou expirée")

// pendingTTL limits how long a half-authenticated session lives.
const pendingTTL = 10 * time.Minute

// touchEvery limits last_seen writes.
const touchEvery = time.Minute

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// CreateSession starts a session and returns the cookie value.
func (s *Service) CreateSession(ctx context.Context, userID string, level Level, ip, ua string) (string, *Session, error) {
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	now := s.Now()
	exp := now.Add(time.Duration(s.Security().SessionMaxHours) * time.Hour)
	if level != LevelFull {
		exp = now.Add(pendingTTL)
	}
	if len(ua) > 256 {
		ua = ua[:256]
	}
	sess := &Session{IDHash: hashToken(token), PublicID: ids.New(), UserID: userID, Level: level,
		CSRF: base64.RawURLEncoding.EncodeToString(randomBytes(24)), CreatedAt: now, LastSeenAt: now,
		ExpiresAt: exp, IP: ip, UserAgent: ua}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash, public_id, user_id, auth_level, csrf_token, created_at,
		last_seen_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.IDHash, sess.PublicID, userID, level, sess.CSRF, now.UnixMilli(), now.UnixMilli(), exp.UnixMilli(), ip, ua)
	if err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

const sessionCols = `id_hash, public_id, user_id, auth_level, csrf_token, created_at, last_seen_at, expires_at, elevated_until, ip, user_agent`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var se Session
	var created, seen, exp int64
	var elev sql.NullInt64
	if err := row.Scan(&se.IDHash, &se.PublicID, &se.UserID, &se.Level, &se.CSRF, &created, &seen, &exp, &elev, &se.IP, &se.UserAgent); err != nil {
		return nil, err
	}
	se.CreatedAt, se.LastSeenAt, se.ExpiresAt = time.UnixMilli(created), time.UnixMilli(seen), time.UnixMilli(exp)
	if elev.Valid {
		t := time.UnixMilli(elev.Int64)
		se.ElevatedUntil = &t
	}
	return &se, nil
}

// LookupSession validates a cookie value: unknown, revoked, expired or idle
// sessions return ErrNoSession. last_seen is refreshed at most once a minute.
func (s *Service) LookupSession(ctx context.Context, token string) (*Session, error) {
	return s.lookupSession(ctx, token, true)
}

// PeekSession validates a cookie value like LookupSession but never
// refreshes last_seen. It serves background requests (automatic polling,
// event streams) that must not keep an idle session alive: the idle timeout
// counts from the user's last real action.
func (s *Service) PeekSession(ctx context.Context, token string) (*Session, error) {
	return s.lookupSession(ctx, token, false)
}

func (s *Service) lookupSession(ctx context.Context, token string, touch bool) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	se, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions
		WHERE id_hash = ? AND revoked_at IS NULL`, hashToken(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.Now()
	idle := time.Duration(s.Security().SessionIdleMinutes) * time.Minute
	if now.After(se.ExpiresAt) || now.Sub(se.LastSeenAt) > idle {
		_ = s.revokeHash(ctx, se.IDHash)
		return nil, ErrNoSession
	}
	if touch && now.Sub(se.LastSeenAt) > touchEvery {
		se.LastSeenAt = now
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, now.UnixMilli(), se.IDHash); err != nil {
			return nil, err
		}
	}
	return se, nil
}

// UpgradeSession sets the session to full and gives it the full lifetime.
func (s *Service) UpgradeSession(ctx context.Context, se *Session) error {
	now := s.Now()
	se.Level = LevelFull
	se.ExpiresAt = now.Add(time.Duration(s.Security().SessionMaxHours) * time.Hour)
	// A fresh MFA proof also counts as a step-up.
	elev := now.Add(StepUpWindow)
	se.ElevatedUntil = &elev
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET auth_level = ?, expires_at = ?, elevated_until = ? WHERE id_hash = ?`,
		LevelFull, se.ExpiresAt.UnixMilli(), elev.UnixMilli(), se.IDHash)
	return err
}

// PromoteSession finishes a login: the half-authenticated session se is
// revoked and a new full session (new cookie value, new CSRF token) starts
// for the same user. A session token known before the second factor (a
// fixed or stolen pending cookie) is worthless afterwards. The fresh MFA
// proof also counts as a step-up.
func (s *Service) PromoteSession(ctx context.Context, se *Session, ip, ua string) (string, *Session, error) {
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	now := s.Now()
	elev := now.Add(StepUpWindow)
	if len(ua) > 256 {
		ua = ua[:256]
	}
	ns := &Session{IDHash: hashToken(token), PublicID: ids.New(), UserID: se.UserID, Level: LevelFull,
		CSRF: base64.RawURLEncoding.EncodeToString(randomBytes(24)), CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(time.Duration(s.Security().SessionMaxHours) * time.Hour), ElevatedUntil: &elev, IP: ip, UserAgent: ua}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		// Revoked rather than deleted: in a cluster, a late copy of the old
		// row from the other node cannot bring it back (revoked_at is kept).
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`, now.UnixMilli(), se.IDHash)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoSession // already promoted or revoked
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sessions(id_hash, public_id, user_id, auth_level, csrf_token, created_at,
			last_seen_at, expires_at, elevated_until, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ns.IDHash, ns.PublicID, ns.UserID, ns.Level, ns.CSRF, now.UnixMilli(), now.UnixMilli(), ns.ExpiresAt.UnixMilli(),
			elev.UnixMilli(), ip, ua)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return token, ns, nil
}

// StepUpWindow is how long a re-verification unlocks sensitive actions.
const StepUpWindow = 5 * time.Minute

// Elevate marks the session as recently re-verified.
func (s *Service) Elevate(ctx context.Context, se *Session) error {
	t := s.Now().Add(StepUpWindow)
	se.ElevatedUntil = &t
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET elevated_until = ? WHERE id_hash = ?`, t.UnixMilli(), se.IDHash)
	return err
}

// Elevated reports whether a sensitive action is allowed without re-verifying.
func (s *Service) Elevated(se *Session) bool {
	return se.ElevatedUntil != nil && s.Now().Before(*se.ElevatedUntil)
}

func (s *Service) revokeHash(ctx context.Context, h string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`, s.Now().UnixMilli(), h)
	return err
}

// RevokeSession revokes the session with this cookie hash.
func (s *Service) RevokeSession(ctx context.Context, se *Session) error {
	return s.revokeHash(ctx, se.IDHash)
}

// RevokeSessionByPublicID revokes one of userID's sessions.
func (s *Service) RevokeSessionByPublicID(ctx context.Context, userID, publicID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE public_id = ? AND user_id = ? AND revoked_at IS NULL`,
		s.Now().UnixMilli(), publicID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// RevokeUserSessions revokes all sessions of a user except one public id.
func (s *Service) RevokeUserSessions(ctx context.Context, userID, exceptPublicID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND public_id != ? AND revoked_at IS NULL`,
		s.Now().UnixMilli(), userID, exceptPublicID)
	return err
}

// ListSessions returns the live sessions of a user, newest first.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]*Session, error) {
	now := s.Now()
	idle := time.Duration(s.Security().SessionIdleMinutes) * time.Minute
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE user_id = ? AND revoked_at IS NULL
		AND expires_at > ? AND last_seen_at > ? ORDER BY last_seen_at DESC`, userID, now.UnixMilli(), now.Add(-idle).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		se, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// PurgeSessions deletes sessions that ended more than a day ago.
func (s *Service) PurgeSessions(ctx context.Context) error {
	cut := s.Now().Add(-24 * time.Hour).UnixMilli()
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR revoked_at < ?`, cut, cut)
	return err
}

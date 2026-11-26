package auth

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// RP describes the relying party for one request: the RP ID (domain) and the
// exact origins the browser may report.
type RP struct {
	ID      string
	Origins []string
}

// Passkey is a stored WebAuthn credential.
type Passkey struct {
	ID             string
	UserID         string
	Name           string
	CredentialID   []byte
	Credential     webauthn.Credential
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	BackupEligible bool
}

// Errors of the WebAuthn flows.
var (
	ErrCeremony       = errors.New("demande de passkey expirée ou inconnue, recommencez")
	ErrPasskeyRefused = errors.New("passkey refusée")
)

// Ceremony kinds: a challenge issued for one purpose cannot be used for another.
const (
	CeremonyRegister     = "register"
	CeremonyLogin        = "login"  // passwordless
	CeremonySecondFactor = "second" // after password
	CeremonyStepUp       = "stepup" // sensitive action
)

// waUser adapts User to webauthn.User.
type waUser struct {
	u     *User
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte                         { return w.u.Handle }
func (w *waUser) WebAuthnName() string                       { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string                { return w.u.Username }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func (s *Service) webAuthn(rp RP) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rp.ID,
		RPDisplayName: "Leazone",
		RPOrigins:     rp.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
}

// ListPasskeys returns the passkeys of a user, with usage counters applied.
func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]*Passkey, error) {
	return s.queryPasskeys(ctx, `WHERE c.user_id = ? ORDER BY c.created_at`, userID)
}

func (s *Service) queryPasskeys(ctx context.Context, where string, args ...any) ([]*Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.user_id, c.name, c.credential_id, c.data, c.created_at,
		u.sign_count, u.last_used_at FROM webauthn_credentials c
		LEFT JOIN webauthn_usage u ON u.credential_id = c.credential_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		var p Passkey
		var data string
		var created int64
		var count, used sql.NullInt64
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.CredentialID, &data, &created, &count, &used); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &p.Credential); err != nil {
			return nil, err
		}
		if count.Valid && uint32(count.Int64) > p.Credential.Authenticator.SignCount {
			p.Credential.Authenticator.SignCount = uint32(count.Int64)
		}
		p.CreatedAt = time.UnixMilli(created)
		p.LastUsedAt = optTime(used)
		p.BackupEligible = p.Credential.Flags.BackupEligible
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Service) waUser(ctx context.Context, u *User) (*waUser, error) {
	pks, err := s.ListPasskeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	w := &waUser{u: u}
	for _, p := range pks {
		w.creds = append(w.creds, p.Credential)
	}
	return w, nil
}

// BeginPasskeyRegistration returns creation options for a new passkey.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, rp RP, u *User) (string, any, error) {
	wa, err := s.webAuthn(rp)
	if err != nil {
		return "", nil, err
	}
	w, err := s.waUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	var excl []protocol.CredentialDescriptor
	for _, c := range w.creds {
		excl = append(excl, c.Descriptor())
	}
	opts, sd, err := wa.BeginRegistration(w, webauthn.WithExclusions(excl),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return "", nil, err
	}
	id := s.ceremonies.put(u.ID, CeremonyRegister, u.ID, *sd)
	return id, opts, nil
}

// FinishPasskeyRegistration verifies the browser response and stores the passkey.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, rp RP, u *User, ceremonyID, name string, body []byte) (*Passkey, error) {
	name = SanitizeName(name, 64)
	if name == "" {
		return nil, ErrValidation{"name": "donnez un nom à cette passkey (ex : YubiKey bureau)"}
	}
	sd, ok := s.ceremonies.take(ceremonyID, CeremonyRegister, u.ID)
	if !ok {
		return nil, ErrCeremony
	}
	wa, err := s.webAuthn(rp)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.log.Info("passkey registration parse failed", "user", u.Username, "err", err)
		return nil, ErrPasskeyRefused
	}
	w, err := s.waUser(ctx, u)
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(w, sd, parsed)
	if err != nil {
		s.log.Info("passkey registration refused", "user", u.Username, "err", err)
		return nil, ErrPasskeyRefused
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	p := &Passkey{ID: ids.New(), UserID: u.ID, Name: name, CredentialID: cred.ID, Credential: *cred,
		CreatedAt: s.Now(), BackupEligible: cred.Flags.BackupEligible}
	_, err = s.db.ExecContext(ctx, `INSERT INTO webauthn_credentials(id, user_id, name, credential_id, data, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, p.ID, u.ID, name, cred.ID, string(data), p.CreatedAt.UnixMilli())
	if err != nil {
		return nil, err
	}
	return p, nil
}

// BeginPasskeyLogin starts an assertion. With u == nil it is a passwordless
// (discoverable) login, otherwise it is limited to the user's passkeys.
// clientIP bounds the number of pending passwordless logins per client.
func (s *Service) BeginPasskeyLogin(ctx context.Context, rp RP, u *User, kind, clientIP string) (string, any, error) {
	wa, err := s.webAuthn(rp)
	if err != nil {
		return "", nil, err
	}
	if u == nil {
		opts, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return "", nil, err
		}
		return s.ceremonies.put(ipKey(clientIP), kind, "", *sd), opts, nil
	}
	w, err := s.waUser(ctx, u)
	if err != nil {
		return "", nil, err
	}
	if len(w.creds) == 0 {
		return "", nil, ErrPasskeyRefused
	}
	opts, sd, err := wa.BeginLogin(w, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	return s.ceremonies.put(u.ID, kind, u.ID, *sd), opts, nil
}

// FinishPasskeyLogin verifies an assertion and returns the authenticated user.
// For kind CeremonyLogin u must be nil (user found from the user handle).
func (s *Service) FinishPasskeyLogin(ctx context.Context, rp RP, u *User, kind, ceremonyID string, body []byte) (*User, error) {
	userID := ""
	if u != nil {
		userID = u.ID
	}
	sd, ok := s.ceremonies.take(ceremonyID, kind, userID)
	if !ok {
		return nil, ErrCeremony
	}
	wa, err := s.webAuthn(rp)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, ErrPasskeyRefused
	}
	var cred *webauthn.Credential
	if u == nil {
		var found *User
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			usr, err := s.GetUserByHandle(ctx, userHandle)
			if err != nil {
				return nil, err
			}
			found = usr
			return s.waUser(ctx, usr)
		}
		cred, err = wa.ValidateDiscoverableLogin(handler, sd, parsed)
		u = found
	} else {
		var w *waUser
		if w, err = s.waUser(ctx, u); err != nil {
			return nil, err
		}
		cred, err = wa.ValidateLogin(w, sd, parsed)
	}
	if err != nil || u == nil {
		s.log.Info("passkey assertion refused", "err", err)
		return nil, ErrPasskeyRefused
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey sign counter went backwards: possible cloned authenticator", "user", u.Username)
		return nil, ErrPasskeyRefused
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO webauthn_usage(credential_id, sign_count, last_used_at) VALUES (?, ?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET sign_count = max(sign_count, excluded.sign_count), last_used_at = excluded.last_used_at`,
		cred.ID, cred.Authenticator.SignCount, s.Now().UnixMilli())
	return u, err
}

// RenamePasskey changes the label of one of userID's passkeys.
func (s *Service) RenamePasskey(ctx context.Context, userID, id, name string) (*Passkey, error) {
	name = SanitizeName(name, 64)
	if name == "" {
		return nil, ErrValidation{"name": "nom obligatoire"}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`, name, id, userID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, store.ErrNotFound
	}
	pks, err := s.queryPasskeys(ctx, `WHERE c.id = ?`, id)
	if err != nil || len(pks) == 0 {
		return nil, store.ErrNotFound
	}
	return pks[0], nil
}

// DeletePasskey removes one of userID's passkeys.
func (s *Service) DeletePasskey(ctx context.Context, userID, id string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var credID []byte
		err := tx.QueryRowContext(ctx, `SELECT credential_id FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID).Scan(&credID)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_usage WHERE credential_id = ?`, credID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = ?`, id)
		return err
	})
}

// ceremonyStore keeps WebAuthn challenges in memory for 5 minutes. Each
// challenge is single use and bound to a kind and (when known) a user.
// Anonymous callers can fill it (passwordless login), so it is bounded per
// owner (client network or user) and globally; when full, the oldest
// challenges go first.
type ceremonyStore struct {
	mu      sync.Mutex
	items   map[string]*list.Element // id -> element of order
	order   *list.List               // *ceremony, oldest first
	byOwner map[string][]string      // owner -> ids, oldest first
}

type ceremony struct {
	id      string
	owner   string
	kind    string
	userID  string
	data    webauthn.SessionData
	expires time.Time
}

const (
	ceremonyTTL      = 5 * time.Minute
	ceremonyMax      = 10000
	ceremonyPerOwner = 20
)

func newCeremonyStore() *ceremonyStore {
	return &ceremonyStore{items: map[string]*list.Element{}, order: list.New(), byOwner: map[string][]string{}}
}

// put stores a challenge for owner ("ip:..." for anonymous callers, else
// the user id) and returns its id.
func (c *ceremonyStore) put(owner, kind, userID string, sd webauthn.SessionData) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// Same TTL for all: the oldest are the expired ones.
	for e := c.order.Front(); e != nil && now.After(e.Value.(*ceremony).expires); e = c.order.Front() {
		c.remove(e.Value.(*ceremony).id)
	}
	if pending := c.byOwner[owner]; len(pending) >= ceremonyPerOwner {
		c.remove(pending[0])
	}
	if c.order.Len() >= ceremonyMax {
		c.remove(c.order.Front().Value.(*ceremony).id)
	}
	id := ids.New()
	c.items[id] = c.order.PushBack(&ceremony{id: id, owner: owner, kind: kind, userID: userID, data: sd, expires: now.Add(ceremonyTTL)})
	c.byOwner[owner] = append(c.byOwner[owner], id)
	return id
}

// remove deletes one challenge (c.mu held).
func (c *ceremonyStore) remove(id string) *ceremony {
	e, ok := c.items[id]
	if !ok {
		return nil
	}
	delete(c.items, id)
	v := c.order.Remove(e).(*ceremony)
	owned := c.byOwner[v.owner]
	for i, x := range owned {
		if x == id {
			owned = append(owned[:i:i], owned[i+1:]...)
			break
		}
	}
	if len(owned) == 0 {
		delete(c.byOwner, v.owner)
	} else {
		c.byOwner[v.owner] = owned
	}
	return v
}

func (c *ceremonyStore) take(id, kind, userID string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.remove(id)
	if v == nil || v.kind != kind || v.userID != userID || time.Now().After(v.expires) {
		return webauthn.SessionData{}, false
	}
	return v.data, true
}

package api

import (
	"net/http"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
)

type meResp struct {
	ID                     string    `json:"id"`
	Username               string    `json:"username"`
	Role                   auth.Role `json:"role"`
	CreatedAt              time.Time `json:"createdAt"`
	TOTPEnabled            bool      `json:"totpEnabled"`
	PasskeyCount           int       `json:"passkeyCount"`
	RecoveryCodesRemaining int       `json:"recoveryCodesRemaining"`
	// TOTPAllowed: the security policy accepts TOTP as a second factor
	// (step-up, enrollment). A TOTP enabled under an older policy may be
	// refused.
	TOTPAllowed bool `json:"totpAllowed"`
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	u := current(r).User
	m, err := s.auth.MFA(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, meResp{u.ID, u.Username, u.Role, u.CreatedAt, m.TOTPEnabled, m.PasskeyCount, m.RecoveryRemaining,
		s.auth.Security().TOTPAllowed()})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	p := current(r)
	if _, err := s.auth.Authenticate(r.Context(), p.User.Username, in.CurrentPassword, client(r).IP.String()); err != nil {
		s.record(r, "user.password.change", p.User.Username, audit.Failure, map[string]any{"reason": "bad_current_password"})
		if err == auth.ErrInvalidCredentials {
			s.fail(w, r, auth.ErrValidation{"currentPassword": "mot de passe actuel incorrect"})
			return
		}
		s.fail(w, r, err)
		return
	}
	if err := s.auth.SetPassword(r.Context(), p.User.ID, in.NewPassword, p.Session.PublicID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "user.password.change", p.User.Username, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- passkeys ----

type passkeyResp struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	BackupEligible bool       `json:"backupEligible"`
}

func toPasskey(p *auth.Passkey) passkeyResp {
	return passkeyResp{p.ID, p.Name, p.CreatedAt, p.LastUsedAt, p.BackupEligible}
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	pks, err := s.auth.ListPasskeys(r.Context(), current(r).User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]passkeyResp, 0, len(pks))
	for _, p := range pks {
		out = append(out, toPasskey(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.rpOrFail(w, r)
	if !ok {
		return
	}
	id, opts, err := s.auth.BeginPasskeyRegistration(r.Context(), rp, current(r).User)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, beginResp{id, opts})
}

type enrollResp struct {
	Session       sessionState `json:"session"`
	RecoveryCodes []string     `json:"recoveryCodes"`
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.rpOrFail(w, r)
	if !ok {
		return
	}
	in, err := readFinish(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := current(r)
	pk, err := s.auth.FinishPasskeyRegistration(r.Context(), rp, p.User, in.CeremonyID, in.Name, in.Credential)
	if err != nil {
		s.record(r, "passkey.add", p.User.Username, audit.Failure, nil)
		s.fail(w, r, err)
		return
	}
	s.record(r, "passkey.add", p.User.Username, audit.Success, map[string]any{"name": pk.Name, "id": pk.ID})
	s.afterEnroll(w, r, p)
}

// afterEnroll gives recovery codes on the first MFA method and finishes a
// forced MFA setup.
func (s *Server) afterEnroll(w http.ResponseWriter, r *http.Request, p *principal) {
	codes, err := s.auth.EnsureRecoveryCodes(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if codes != nil {
		s.record(r, "recovery_codes.generate", p.User.Username, audit.Success, nil)
	}
	if p.Session != nil && p.Session.Level == auth.LevelMFASetup {
		if err := s.completeMFA(w, r, p, "enroll"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	st, err := s.stateOf(r, p.User, p.Session)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, enrollResp{Session: st, RecoveryCodes: codes})
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	pk, err := s.auth.RenamePasskey(r.Context(), current(r).User.ID, r.PathValue("id"), in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "passkey.rename", current(r).User.Username, audit.Success, map[string]any{"id": pk.ID, "name": pk.Name})
	writeJSON(w, http.StatusOK, toPasskey(pk))
}

// lastFactorGuard refuses to remove the only MFA method when MFA is required.
func (s *Server) lastFactorGuard(r *http.Request, removingPasskey bool) error {
	u := current(r).User
	sec := s.auth.Security()
	if !sec.MFARequired(u.Role) {
		return nil
	}
	m, err := s.auth.MFA(r.Context(), u.ID)
	if err != nil {
		return err
	}
	passkeys := m.PasskeyCount
	totp := m.TOTPEnabled && sec.TOTPAllowed()
	if removingPasskey {
		passkeys--
	} else {
		totp = false
	}
	if passkeys <= 0 && !totp {
		return errLastFactor
	}
	return nil
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if err := s.lastFactorGuard(r, true); err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	if err := s.auth.DeletePasskey(r.Context(), current(r).User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "passkey.remove", current(r).User.Username, audit.Success, map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ---- TOTP ----

func (s *Server) getTOTP(w http.ResponseWriter, r *http.Request) {
	m, err := s.auth.MFA(r.Context(), current(r).User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": m.TOTPEnabled})
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	setup, err := s.auth.BeginTOTP(r.Context(), current(r).User)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setup)
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if !s.codeCheck(w, r, "totp.enable", func(c string) error { return s.auth.ConfirmTOTP(r.Context(), p.User, c) }) {
		return
	}
	s.record(r, "totp.enable", p.User.Username, audit.Success, nil)
	s.afterEnroll(w, r, p)
}

func (s *Server) deleteTOTP(w http.ResponseWriter, r *http.Request) {
	if err := s.lastFactorGuard(r, false); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.auth.DisableTOTP(r.Context(), current(r).User.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "totp.disable", current(r).User.Username, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- recovery codes ----

func (s *Server) getRecovery(w http.ResponseWriter, r *http.Request) {
	m, err := s.auth.MFA(r.Context(), current(r).User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"remaining": m.RecoveryRemaining})
}

func (s *Server) regenRecovery(w http.ResponseWriter, r *http.Request) {
	codes, err := s.auth.RegenerateRecoveryCodes(r.Context(), current(r).User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "recovery_codes.generate", current(r).User.Username, audit.Success, nil)
	writeJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

// ---- sessions ----

type sessionResp struct {
	ID         string    `json:"id"`
	Current    bool      `json:"current"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"userAgent"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	list, err := s.auth.ListSessions(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]sessionResp, 0, len(list))
	for _, se := range list {
		cur := p.Session != nil && se.PublicID == p.Session.PublicID
		out = append(out, sessionResp{se.PublicID, cur, se.IP, se.UserAgent, se.CreatedAt, se.LastSeenAt, se.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.auth.RevokeSessionByPublicID(r.Context(), current(r).User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "session.revoke", current(r).User.Username, audit.Success, map[string]any{"session": id})
	w.WriteHeader(http.StatusNoContent)
}

// ---- API tokens ----

type tokenResp struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scope      string     `json:"scope"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

func toToken(t *auth.APIToken) tokenResp {
	return tokenResp{t.ID, t.Name, t.Prefix, t.Scope, t.CreatedAt, t.ExpiresAt, t.LastUsedAt}
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.auth.ListTokens(r.Context(), current(r).User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]tokenResp, 0, len(list))
	for _, t := range list {
		out = append(out, toToken(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string     `json:"name"`
		Scope     string     `json:"scope"`
		ExpiresAt *time.Time `json:"expiresAt"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	plain, t, err := s.auth.CreateToken(r.Context(), current(r).User.ID, in.Name, in.Scope, in.ExpiresAt)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "token.create", current(r).User.Username, audit.Success, map[string]any{"name": t.Name, "scope": t.Scope})
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "item": toToken(t)})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.auth.RevokeToken(r.Context(), current(r).User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "token.revoke", current(r).User.Username, audit.Success, map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

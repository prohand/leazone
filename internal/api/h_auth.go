package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/version"
)

// ---- DTOs ----

type userRef struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Role     auth.Role `json:"role"`
}

type sessionState struct {
	State             string     `json:"state"`
	CSRFToken         string     `json:"csrfToken,omitempty"`
	User              *userRef   `json:"user,omitempty"`
	MFAMethods        []string   `json:"mfaMethods,omitempty"`
	AllowedMFAMethods []string   `json:"allowedMfaMethods,omitempty"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	ElevatedUntil     *time.Time `json:"elevatedUntil"`
}

var levelState = map[auth.Level]string{
	auth.LevelMFAPending: "mfa_required",
	auth.LevelMFASetup:   "mfa_setup_required",
	auth.LevelFull:       "authenticated",
}

func (s *Server) stateOf(r *http.Request, u *auth.User, se *auth.Session) (sessionState, error) {
	if u == nil || se == nil {
		return sessionState{State: "anonymous"}, nil
	}
	st := sessionState{State: levelState[se.Level], CSRFToken: se.CSRF,
		User: &userRef{ID: u.ID, Username: u.Username, Role: u.Role}, ExpiresAt: &se.ExpiresAt}
	if se.ElevatedUntil != nil && se.ElevatedUntil.After(time.Now()) {
		st.ElevatedUntil = se.ElevatedUntil
	}
	switch se.Level {
	case auth.LevelMFAPending:
		m, err := s.auth.MFA(r.Context(), u.ID)
		if err != nil {
			return st, err
		}
		st.MFAMethods = s.auth.SecondFactors(m)
	case auth.LevelMFASetup:
		st.AllowedMFAMethods = s.auth.Security().EnrollableMethods()
	}
	return st, nil
}

func (s *Server) writeState(w http.ResponseWriter, r *http.Request, u *auth.User, se *auth.Session) {
	st, err := s.stateOf(r, u, se)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) record(r *http.Request, action, target, result string, details map[string]any) {
	actor := current(r).actor()
	s.audit.Record(r.Context(), audit.Entry{Actor: actor, IP: client(r).IP.String(), Action: action,
		Target: target, Result: result, Details: details})
}

func (s *Server) recordAs(r *http.Request, actor, action, target, result string, details map[string]any) {
	s.audit.Record(r.Context(), audit.Entry{Actor: actor, IP: client(r).IP.String(), Action: action,
		Target: target, Result: result, Details: details})
}

// ---- system ----

type systemInfo struct {
	Product                   string `json:"product"`
	Version                   string `json:"version"`
	RPID                      string `json:"rpId"`
	PasskeysAvailable         bool   `json:"passkeysAvailable"`
	PasskeysUnavailableReason string `json:"passkeysUnavailableReason,omitempty"`
	SelfSignedCertificate     bool   `json:"selfSignedCertificate"`
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	rp, reason := s.rp(r)
	writeJSON(w, http.StatusOK, systemInfo{
		Product: "Leazone", Version: version.Version, RPID: rp.ID, PasskeysAvailable: reason == "",
		PasskeysUnavailableReason: reason,
		// Behind a trusted proxy the browser sees the proxy certificate.
		SelfSignedCertificate: s.tls.SelfSigned() && !client(r).ViaProxy,
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.db.PingContext(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.spec)
}

// rp returns the WebAuthn relying party for this request, or a French
// explanation of why passkeys cannot work.
func (s *Server) rp(r *http.Request) (auth.RP, string) {
	c := client(r)
	id := s.auth.Security().WebAuthnRPID
	if id == "" {
		id = c.Host
	}
	if net.ParseIP(c.Host) != nil || c.Host == "" {
		return auth.RP{}, "Les passkeys exigent un nom de domaine. Ouvrez l'interface par son nom (ex : https://leazone.mondomaine.lan), pas par une adresse IP."
	}
	if c.Host != id && !strings.HasSuffix(c.Host, "."+id) {
		return auth.RP{}, "Le RP ID configuré (" + id + ") ne correspond pas au nom utilisé dans le navigateur (" + c.Host + ")."
	}
	return auth.RP{ID: id, Origins: []string{c.Origin}}, ""
}

func (s *Server) rpOrFail(w http.ResponseWriter, r *http.Request) (auth.RP, bool) {
	rp, reason := s.rp(r)
	if reason != "" {
		problem(w, http.StatusBadRequest, TBadRequest, reason)
		return rp, false
	}
	return rp, true
}

// ---- login ----

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if p == nil || p.Session == nil {
		writeJSON(w, http.StatusOK, sessionState{State: "anonymous"})
		return
	}
	s.writeState(w, r, p.User, p.Session)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	ip := client(r).IP.String()
	u, err := s.auth.Authenticate(r.Context(), in.Username, in.Password, ip)
	if err != nil {
		var rl *auth.RateLimitError
		reason := "bad_credentials"
		if errors.As(err, &rl) {
			reason = "rate_limited"
		}
		s.recordAs(r, strings.ToLower(in.Username), "auth.login.failure", strings.ToLower(in.Username), audit.Failure,
			map[string]any{"method": "password", "reason": reason})
		s.fail(w, r, err)
		return
	}
	m, err := s.auth.MFA(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	level := s.auth.LoginLevel(u, m)
	s.startSession(w, r, u, level, "password")
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *auth.User, level auth.Level, method string) {
	// Replace any previous session of this browser.
	if p := current(r); p != nil && p.Session != nil {
		_ = s.auth.RevokeSession(r.Context(), p.Session)
	}
	token, se, err := s.auth.CreateSession(r.Context(), u.ID, level, client(r).IP.String(), r.UserAgent())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if level == auth.LevelFull {
		if err := s.auth.UpgradeSession(r.Context(), se); err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.auth.TouchLogin(r.Context(), u.ID)
		s.recordAs(r, u.Username, "auth.login.success", u.Username, audit.Success, map[string]any{"method": method})
	} else {
		s.recordAs(r, u.Username, "auth.login.password_ok", u.Username, audit.Success, map[string]any{"next": levelState[level]})
	}
	setSessionCookie(w, token)
	s.writeState(w, r, u, se)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if p.Session != nil {
		_ = s.auth.RevokeSession(r.Context(), p.Session)
		s.record(r, "auth.logout", p.User.Username, audit.Success, nil)
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type beginResp struct {
	CeremonyID string `json:"ceremonyId"`
	Options    any    `json:"options"`
}

type finishReq struct {
	CeremonyID string          `json:"ceremonyId"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func readFinish(r *http.Request) (finishReq, error) {
	var in finishReq
	if err := decode(r, &in); err != nil {
		return in, err
	}
	if in.CeremonyID == "" || len(in.Credential) == 0 {
		return in, errBadRequest
	}
	return in, nil
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.rpOrFail(w, r)
	if !ok {
		return
	}
	if err := s.auth.GuardCheck(r.Context(), auth.IPKey(client(r).IP.String())); err != nil {
		s.fail(w, r, err)
		return
	}
	id, opts, err := s.auth.BeginPasskeyLogin(r.Context(), rp, nil, auth.CeremonyLogin)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, beginResp{id, opts})
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.rpOrFail(w, r)
	if !ok {
		return
	}
	in, err := readFinish(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ipk := auth.IPKey(client(r).IP.String())
	if err := s.auth.GuardCheck(r.Context(), ipk); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.auth.FinishPasskeyLogin(r.Context(), rp, nil, auth.CeremonyLogin, in.CeremonyID, in.Credential)
	if err != nil {
		_ = s.auth.GuardFail(r.Context(), ipk)
		s.recordAs(r, "", "auth.login.failure", "", audit.Failure, map[string]any{"method": "passkey"})
		s.fail(w, r, err)
		return
	}
	// A passkey with user verification is already multi-factor.
	s.startSession(w, r, u, auth.LevelFull, "passkey")
}

// ---- second factor ----

func (s *Server) mfaPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	s.passkeyBegin(w, r, auth.CeremonySecondFactor)
}

func (s *Server) passkeyBegin(w http.ResponseWriter, r *http.Request, kind string) {
	rp, ok := s.rpOrFail(w, r)
	if !ok {
		return
	}
	id, opts, err := s.auth.BeginPasskeyLogin(r.Context(), rp, current(r).User, kind)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, beginResp{id, opts})
}

func (s *Server) mfaPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	s.verifyPasskey(w, r, auth.CeremonySecondFactor, func(p *principal) error {
		return s.completeMFA(r, p, "passkey")
	})
}

func (s *Server) verifyPasskey(w http.ResponseWriter, r *http.Request, kind string, then func(*principal) error) {
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
	if _, err := s.auth.FinishPasskeyLogin(r.Context(), rp, p.User, kind, in.CeremonyID, in.Credential); err != nil {
		s.record(r, failureAction(kind), p.User.Username, audit.Failure, map[string]any{"method": "passkey"})
		s.fail(w, r, err)
		return
	}
	if err := then(p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeState(w, r, p.User, p.Session)
}

func failureAction(kind string) string {
	if kind == auth.CeremonyStepUp {
		return "auth.stepup.failure"
	}
	return "auth.mfa.failure"
}

func (s *Server) completeMFA(r *http.Request, p *principal, method string) error {
	if err := s.auth.UpgradeSession(r.Context(), p.Session); err != nil {
		return err
	}
	_ = s.auth.TouchLogin(r.Context(), p.User.ID)
	s.record(r, "auth.login.success", p.User.Username, audit.Success, map[string]any{"method": "password+" + method})
	return nil
}

// codeCheck runs a code verification with brute-force protection shared with
// the password login (same per-IP and per-account counters).
func (s *Server) codeCheck(w http.ResponseWriter, r *http.Request, action string, check func(code string) error) bool {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return false
	}
	p := current(r)
	keys := []string{auth.IPKey(client(r).IP.String()), auth.UserKey(p.User.Username)}
	if err := s.auth.GuardCheck(r.Context(), keys...); err != nil {
		s.fail(w, r, err)
		return false
	}
	if err := check(in.Code); err != nil {
		if errors.Is(err, auth.ErrBadCode) {
			_ = s.auth.GuardFail(r.Context(), keys...)
			s.record(r, action, p.User.Username, audit.Failure, nil)
		}
		s.fail(w, r, err)
		return false
	}
	_ = s.auth.GuardReset(r.Context(), keys[1])
	return true
}

func (s *Server) mfaTOTP(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if !s.codeCheck(w, r, "auth.mfa.failure", func(c string) error { return s.auth.VerifyTOTP(r.Context(), p.User.ID, c) }) {
		return
	}
	if err := s.completeMFA(r, p, "totp"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeState(w, r, p.User, p.Session)
}

func (s *Server) mfaRecovery(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if !s.codeCheck(w, r, "auth.mfa.failure", func(c string) error { return s.auth.UseRecoveryCode(r.Context(), p.User.ID, c) }) {
		return
	}
	s.record(r, "auth.recovery_code.used", p.User.Username, audit.Success, nil)
	if err := s.completeMFA(r, p, "recovery"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeState(w, r, p.User, p.Session)
}

// ---- step-up ----

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) bool {
	if current(r).Session == nil {
		problem(w, http.StatusForbidden, TForbidden, "Action impossible avec un jeton d'API.")
		return false
	}
	return true
}

func (s *Server) stepUpPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if s.requireSession(w, r) {
		s.passkeyBegin(w, r, auth.CeremonyStepUp)
	}
}

func (s *Server) stepUpPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	s.verifyPasskey(w, r, auth.CeremonyStepUp, func(p *principal) error {
		s.record(r, "auth.stepup.success", p.User.Username, audit.Success, map[string]any{"method": "passkey"})
		return s.auth.Elevate(r.Context(), p.Session)
	})
}

func (s *Server) stepUpTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSession(w, r) {
		return
	}
	p := current(r)
	if !s.codeCheck(w, r, "auth.stepup.failure", func(c string) error { return s.auth.VerifyTOTP(r.Context(), p.User.ID, c) }) {
		return
	}
	if err := s.auth.Elevate(r.Context(), p.Session); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "auth.stepup.success", p.User.Username, audit.Success, map[string]any{"method": "totp"})
	s.writeState(w, r, p.User, p.Session)
}

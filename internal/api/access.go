package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/prohand/leazone/internal/auth"
)

// SessionCookie is the session cookie name. The __Host- prefix forces
// Secure, Path=/ and no Domain attribute in the browser.
const SessionCookie = "__Host-leazone_session"

// principal is the authenticated caller.
type principal struct {
	User    *auth.User
	Session *auth.Session  // nil for API tokens
	Token   *auth.APIToken // nil for browser sessions
}

func (p *principal) scope() string {
	if p.Token != nil {
		return p.Token.Scope
	}
	return ""
}

func (p *principal) actor() string {
	if p == nil || p.User == nil {
		return ""
	}
	if p.Token != nil {
		return p.User.Username + " (jeton " + p.Token.Name + ")"
	}
	return p.User.Username
}

func current(r *http.Request) *principal {
	p, _ := r.Context().Value(keyPrincipal).(*principal)
	return p
}

// access describes who may call a route.
type access struct {
	public bool            // no authentication at all
	levels []auth.Level    // accepted session levels (default: full only)
	perm   auth.Permission // required permission (ignored when public)
	stepUp bool            // requires a recent passkey/TOTP re-verification
	// stepUpMFA requires a recent re-verification to add a factor or a
	// token: a stolen session must not become lasting access (see
	// enrollStepUp for the method asked).
	stepUpMFA bool
	local     bool // set by handle(): does not change replicated config
}

var (
	pub       = access{public: true}
	anyLevel  = access{levels: []auth.Level{auth.LevelMFAPending, auth.LevelMFASetup, auth.LevelFull}, perm: auth.PermSelf}
	mfaStep   = access{levels: []auth.Level{auth.LevelMFAPending}, perm: auth.PermSelf}
	enrolling = access{levels: []auth.Level{auth.LevelMFASetup, auth.LevelFull}, perm: auth.PermSelf}
	// enrollingStepUp starts the enrollment of a new second factor.
	enrollingStepUp = access{levels: enrolling.levels, perm: auth.PermSelf, stepUpMFA: true}
)

func need(p auth.Permission) access       { return access{perm: p} }
func needStepUp(p auth.Permission) access { return access{perm: p, stepUp: true} }

// handle registers an API route ("POST /auth/login") with its access rule.
func (s *Server) handle(pattern string, a access, h http.HandlerFunc) {
	method, path, _ := strings.Cut(pattern, " ")
	s.routes = append(s.routes, Route{Method: method, Path: path})
	a.local = localRoute(method, path)
	s.mux.Handle(method+" /api/v1"+path, s.guard(a, h))
}

// localRoute lists the state-changing routes that do not change the
// replicated configuration: they work on every node of a cluster (login,
// MFA checks, tests, cache, lease release, cluster operations).
func localRoute(method, path string) bool {
	switch {
	case method == http.MethodGet || method == http.MethodHead:
		return true
	case strings.HasPrefix(path, "/auth/"):
		return true
	case path == "/dns/lookup", path == "/dns/forwarders/test", path == "/dns/forwarders/{id}/test", path == "/dns/cache/flush",
		path == "/blocking/refresh", path == "/blocking/check", path == "/logs/purge", path == "/backup":
		return true
	case method == http.MethodDelete && (path == "/me/sessions/{id}" || path == "/dhcp/leases/{scope}/{ip}"):
		return true
	case strings.HasPrefix(path, "/cluster/") && path != "/cluster/settings":
		return true
	}
	return false
}

// guard authenticates the caller and enforces level, permission, CSRF and step-up.
func (s *Server) guard(a access, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
		if unsafe && !s.originOK(r) {
			originRefused(w)
			return
		}
		p, err := s.authenticate(r)
		if err != nil && !errors.Is(err, auth.ErrNoSession) {
			s.fail(w, r, err)
			return
		}
		if p != nil {
			r = r.WithContext(context.WithValue(r.Context(), keyPrincipal, p))
		}
		if a.public {
			h(w, r)
			return
		}
		if p == nil {
			problem(w, http.StatusUnauthorized, TUnauthenticated, "Connectez-vous.")
			return
		}
		if p.Session != nil {
			if unsafe && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(p.Session.CSRF)) != 1 {
				problem(w, http.StatusForbidden, TCSRF, "Jeton CSRF manquant ou invalide. Rechargez la page.")
				return
			}
			levels := a.levels
			if levels == nil {
				levels = []auth.Level{auth.LevelFull}
			}
			if !containsLevel(levels, p.Session.Level) {
				problem(w, http.StatusForbidden, TMFARequired, "Terminez la connexion (second facteur).")
				return
			}
		} else if a.levels != nil && !containsLevel(a.levels, auth.LevelFull) {
			problem(w, http.StatusForbidden, TForbidden, "Action impossible avec un jeton d'API.")
			return
		}
		if !auth.Allowed(p.User.Role, p.scope(), a.perm, unsafe) {
			problem(w, http.StatusForbidden, TForbidden, "Votre rôle ne permet pas cette action.")
			return
		}
		if a.stepUp {
			if p.Session == nil {
				problem(w, http.StatusForbidden, TForbidden, "Action sensible : impossible avec un jeton d'API.")
				return
			}
			if !s.auth.Elevated(p.Session) {
				problem(w, http.StatusForbidden, TStepUp, "Confirmez votre identité avec une passkey ou un code TOTP.")
				return
			}
		}
		if a.stepUpMFA && p.Session != nil && !s.auth.Elevated(p.Session) {
			detail, err := s.enrollStepUp(r, p)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if detail != "" {
				problem(w, http.StatusForbidden, TStepUp, detail)
				return
			}
		}
		if unsafe && !a.local && s.cluster != nil {
			s.clusterWrite(w, r, h)
			return
		}
		h(w, r)
	})
}

// enrollStepUp tells which re-verification adding a factor or a token needs
// from a session that is not elevated ("" = none). A stolen session must
// not be turned into lasting access:
//   - full session, user with a usable factor: passkey or TOTP;
//   - full session, user without one: the password (the session is no
//     longer fresh: a login elevates it for StepUpWindow);
//   - forced setup (a password typed less than 10 minutes ago): nothing,
//     unless the user has a TOTP that the policy no longer accepts. The
//     password alone must not replace it by a passkey: a TOTP code first.
func (s *Server) enrollStepUp(r *http.Request, p *principal) (string, error) {
	m, err := s.auth.MFA(r.Context(), p.User.ID)
	if err != nil {
		return "", err
	}
	switch {
	case p.Session.Level == auth.LevelMFASetup:
		if m.TOTPEnabled {
			return "Confirmez votre identité avec un code de votre application TOTP avant d'ajouter une passkey.", nil
		}
		return "", nil
	case s.auth.CanStepUp(m):
		return "Confirmez votre identité avec une passkey ou un code TOTP.", nil
	default:
		return "Confirmez votre identité avec votre mot de passe.", nil
	}
}

func containsLevel(ls []auth.Level, l auth.Level) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}

// authenticate resolves a bearer token or the session cookie.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil, auth.ErrBadToken
		}
		u, t, err := s.auth.AuthenticateToken(r.Context(), strings.TrimSpace(tok))
		if err != nil {
			return nil, err
		}
		return &principal{User: u, Token: t}, nil
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, auth.ErrNoSession
	}
	lookup := s.auth.LookupSession
	if background(r) {
		lookup = s.auth.PeekSession
	}
	se, err := lookup(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	u, err := s.auth.GetUser(r.Context(), se.UserID)
	if err != nil || u.Disabled {
		_ = s.auth.RevokeSession(r.Context(), se)
		return nil, auth.ErrNoSession
	}
	return &principal{User: u, Session: se}, nil
}

// BackgroundHeader marks a request the UI sent on its own (automatic
// refresh, not a user action): it does not count as activity for the
// session idle timeout.
const BackgroundHeader = "X-Leazone-Background"

// background reports whether the request must not refresh the session's
// last activity: flagged by the UI, or the event stream (EventSource cannot
// set headers, and an open dashboard must not keep an idle session alive).
func background(r *http.Request) bool {
	return r.Header.Get(BackgroundHeader) == "1" || r.URL.Path == "/api/v1/events"
}

// originRefused answers a cross-site state-changing request. The "reason"
// member tells the UI that this is not a lost session (unlike a missing or
// stale CSRF token): reloading or logging in again will not help.
func originRefused(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(struct {
		Problem
		Reason string `json:"reason"`
	}{Problem{Type: TCSRF, Title: titles[TCSRF], Status: http.StatusForbidden, Detail: "Origine de la requête refusée."}, "origin"})
}

// originOK blocks cross-site state-changing requests. Browsers always send
// Origin on POST/PUT/PATCH/DELETE; scripts using tokens usually do not.
func (s *Server) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// No Origin: accept only if the browser says it is same-origin, or
		// if it is not a browser (no Sec-Fetch-Site at all).
		sfs := r.Header.Get("Sec-Fetch-Site")
		return sfs == "" || sfs == "same-origin" || sfs == "none"
	}
	return strings.EqualFold(o, client(r).Origin)
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

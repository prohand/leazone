package api

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/ids"
)

// ---- users ----

type userResp struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Role         auth.Role  `json:"role"`
	Disabled     bool       `json:"disabled"`
	MFAEnabled   bool       `json:"mfaEnabled"`
	PasskeyCount int        `json:"passkeyCount"`
	TOTPEnabled  bool       `json:"totpEnabled"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastLoginAt  *time.Time `json:"lastLoginAt"`
}

func (s *Server) userResp(r *http.Request, u *auth.User) (userResp, error) {
	m, err := s.auth.MFA(r.Context(), u.ID)
	if err != nil {
		return userResp{}, err
	}
	return userResp{u.ID, u.Username, u.Role, u.Disabled, m.Enabled(), m.PasskeyCount, m.TOTPEnabled, u.CreatedAt, u.LastLoginAt}, nil
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]userResp, 0, len(users))
	for _, u := range users {
		ur, err := s.userResp(r, u)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, ur)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string    `json:"username"`
		Role     auth.Role `json:"role"`
		Password string    `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var temp *string
	if in.Password == "" {
		pw := ids.Password(20)
		in.Password, temp = pw, &pw
	}
	u, err := s.auth.CreateUser(r.Context(), in.Username, in.Role, in.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "user.create", u.Username, audit.Success, map[string]any{"role": u.Role})
	ur, err := s.userResp(r, u)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"item": ur, "temporaryPassword": temp})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role     *auth.Role `json:"role"`
		Disabled *bool      `json:"disabled"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.auth.UpdateUser(r.Context(), r.PathValue("id"), in.Role, in.Disabled)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	details := map[string]any{}
	if in.Role != nil {
		details["role"] = *in.Role
	}
	if in.Disabled != nil {
		details["disabled"] = *in.Disabled
	}
	s.record(r, "user.update", u.Username, audit.Success, details)
	ur, err := s.userResp(r, u)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ur)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.auth.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.auth.DeleteUser(r.Context(), u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "user.delete", u.Username, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	u, err := s.auth.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.auth.ResetMFA(r.Context(), u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	// Existing sessions keep no value once the factors are gone.
	except := ""
	if u.ID == current(r).User.ID {
		except = current(r).Session.PublicID
	}
	_ = s.auth.RevokeUserSessions(r.Context(), u.ID, except)
	s.record(r, "user.mfa_reset", u.Username, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	u, err := s.auth.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pw := ids.Password(20)
	except := ""
	if u.ID == current(r).User.ID {
		except = current(r).Session.PublicID
	}
	if err := s.auth.SetPassword(r.Context(), u.ID, pw, except); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "user.password_reset", u.Username, audit.Success, nil)
	writeJSON(w, http.StatusOK, map[string]string{"temporaryPassword": pw})
}

// ---- settings ----

func (s *Server) getSecurity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.auth.Security())
}

func (s *Server) putSecurity(w http.ResponseWriter, r *http.Request) {
	var in auth.SecuritySettings
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	// Do not let an admin lock themselves out with the allow-list.
	if nets := in.AllowedNetworks(); len(in.UIAllowedNetworks) > 0 && !inPrefixes(client(r).IP, nets) {
		s.fail(w, r, auth.ErrValidation{"uiAllowedNetworks": "votre adresse actuelle (" + client(r).IP.String() + ") ne serait plus autorisée"})
		return
	}
	before := s.auth.Security()
	out, err := s.auth.SetSecurity(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "settings.update", "security", audit.Success, map[string]any{"before": before, "after": out})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getTLS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.tls.Info())
}

func (s *Server) importTLS(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CertPEM string `json:"certPem"`
		KeyPEM  string `json:"keyPem"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	info, err := s.tls.Import(r.Context(), in.CertPEM, in.KeyPEM)
	if err != nil {
		s.record(r, "tls.import", "https", audit.Failure, map[string]any{"error": err.Error()})
		s.fail(w, r, auth.ErrValidation{"certPem": err.Error()})
		return
	}
	s.record(r, "tls.import", "https", audit.Success, map[string]any{"subject": info.Subject, "notAfter": info.NotAfter,
		"fingerprint": info.Fingerprint})
	writeJSON(w, http.StatusOK, info)
}

// ---- audit ----

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	items, next, err := s.audit.List(r.Context(), audit.Query{Limit: limit, Cursor: q.Get("cursor"), Q: q.Get("q"), Action: q.Get("action")})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []audit.Entry{}
	}
	var nc *string
	if next != "" {
		nc = &next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": nc})
}

// ---- single-page application ----

// spa serves web/dist with a fallback to index.html for client-side routes.
// Hashed assets are cached for a year, index.html never.
func (s *Server) spa() http.Handler {
	files := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if st, err := fs.Stat(s.ui, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
			if path.Ext(p) != "" { // a missing file, not a client route
				http.NotFound(w, r)
				return
			}
		}
		index, err := fs.ReadFile(s.ui, "index.html")
		if err != nil {
			http.Error(w, "Interface web non construite (web/dist vide). Lancez : cd web && npm ci && npm run build", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

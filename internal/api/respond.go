package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/importer/technitium"
	"github.com/prohand/leazone/internal/store"
)

// Problem is an RFC 9457 error body.
type Problem struct {
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Status     int               `json:"status"`
	Detail     string            `json:"detail,omitempty"`
	RetryAfter int               `json:"retryAfter,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`
}

// Stable problem types (documented in api/openapi.yaml).
const (
	TUnauthenticated = "urn:leazone:unauthenticated"
	TForbidden       = "urn:leazone:forbidden"
	TStepUp          = "urn:leazone:step-up-required"
	TMFARequired     = "urn:leazone:mfa-required"
	TRateLimited     = "urn:leazone:rate-limited"
	TValidation      = "urn:leazone:validation"
	TNotFound        = "urn:leazone:not-found"
	TConflict        = "urn:leazone:conflict"
	TCSRF            = "urn:leazone:csrf"
	TBadRequest      = "urn:leazone:bad-request"
	TInternal        = "urn:leazone:internal"
	TUpstream        = "urn:leazone:upstream"
)

var titles = map[string]string{
	TUnauthenticated: "Non connecté",
	TForbidden:       "Accès refusé",
	TStepUp:          "Confirmation d'identité requise",
	TMFARequired:     "Second facteur requis",
	TRateLimited:     "Trop de tentatives",
	TValidation:      "Données invalides",
	TNotFound:        "Introuvable",
	TConflict:        "Conflit",
	TCSRF:            "Requête refusée (CSRF)",
	TBadRequest:      "Requête invalide",
	TInternal:        "Erreur interne",
	TUpstream:        "Serveur distant en erreur",
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	writeProblem(w, Problem{Type: typ, Title: titles[typ], Status: status, Detail: detail})
}

func writeProblem(w http.ResponseWriter, p Problem) {
	if p.Title == "" {
		p.Title = titles[p.Type]
	}
	if p.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(p.RetryAfter))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// fail maps a Go error to a problem response.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var verr auth.ErrValidation
	var dverr dnsconf.Validation
	var conflict dnsconf.ErrConflict
	var rl *auth.RateLimitError
	switch {
	case errors.As(err, &verr):
		writeProblem(w, Problem{Type: TValidation, Status: http.StatusUnprocessableEntity, Detail: "Vérifiez les champs.", Errors: verr})
	case errors.As(err, &dverr):
		writeProblem(w, Problem{Type: TValidation, Status: http.StatusUnprocessableEntity, Detail: "Vérifiez les champs.", Errors: dverr})
	case errors.As(err, &conflict):
		problem(w, http.StatusConflict, TConflict, conflict.Msg)
	case errors.As(err, new(technitium.RemoteError)):
		problem(w, http.StatusBadGateway, TUpstream, err.Error())
	case errors.Is(err, dnsconf.ErrReadOnly):
		problem(w, http.StatusConflict, TConflict, err.Error())
	case errors.As(err, &rl):
		writeProblem(w, Problem{Type: TRateLimited, Status: http.StatusTooManyRequests, Detail: rl.Error(),
			RetryAfter: int(math.Ceil(rl.RetryAfter.Seconds()))})
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, TNotFound, "")
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrBadCode),
		errors.Is(err, auth.ErrPasskeyRefused), errors.Is(err, auth.ErrBadToken), errors.Is(err, auth.ErrUserDisabled):
		problem(w, http.StatusUnauthorized, TUnauthenticated, err.Error())
	case errors.Is(err, auth.ErrCeremony), errors.Is(err, auth.ErrTOTPNoSetup), errors.Is(err, errBadRequest):
		problem(w, http.StatusBadRequest, TBadRequest, err.Error())
	case errors.Is(err, auth.ErrLastAdmin), errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrTOTPAlreadyOn),
		errors.Is(err, errLastFactor):
		problem(w, http.StatusConflict, TConflict, err.Error())
	case errors.Is(err, auth.ErrTOTPNotAllowed):
		problem(w, http.StatusForbidden, TForbidden, err.Error())
	default:
		var ce clientError
		if errors.As(err, &ce) {
			problem(w, ce.status, ce.typ, ce.msg)
			return
		}
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		problem(w, http.StatusInternalServerError, TInternal, "Erreur interne, voir les journaux du serveur.")
	}
}

// clientError is an error with an explicit HTTP mapping.
type clientError struct {
	status int
	typ    string
	msg    string
}

func (c clientError) Error() string { return c.msg }

var (
	errBadRequest = errors.New("requête invalide")
	errLastFactor = errors.New("impossible : c'est votre dernière méthode MFA. Ajoutez-en une autre d'abord")
)

const maxBody = 1 << 20

// decode reads a JSON body strictly (unknown fields rejected).
func decode(r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return clientError{http.StatusUnsupportedMediaType, TBadRequest, "Content-Type attendu : application/json"}
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return clientError{http.StatusBadRequest, TBadRequest, "JSON invalide : " + err.Error()}
	}
	return nil
}

// rawBody reads the body as bytes (WebAuthn responses are parsed by the library).
func rawBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxBody))
}

func logAttrs(r *http.Request) []any {
	return []any{slog.String("method", r.Method), slog.String("path", r.URL.Path)}
}

package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/cluster"
)

// Problem types of the cluster.
const (
	TNotPrimary = "urn:leazone:not-primary"
	TReadOnly   = "urn:leazone:read-only"
)

func init() {
	titles[TNotPrimary] = "Nœud secondaire"
	titles[TReadOnly] = "Configuration en lecture seule"
}

// bufferedWriter holds the response until the change is replicated.
type bufferedWriter struct {
	h      http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header         { return b.h }
func (b *bufferedWriter) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedWriter) WriteHeader(code int)        { b.status = code }

// clusterWrite runs a config change on the primary only, and answers once
// the change is safe (applied by the secondary or committed at the witness).
func (s *Server) clusterWrite(w http.ResponseWriter, r *http.Request, h http.HandlerFunc) {
	if err := s.cluster.Writable(); err != nil {
		var np cluster.NotPrimaryError
		if errors.As(err, &np) {
			writeJSON(w, http.StatusConflict, map[string]any{"type": TNotPrimary, "title": titles[TNotPrimary],
				"status": http.StatusConflict, "detail": err.Error(), "primaryUrl": np.PrimaryURL})
			return
		}
		problem(w, http.StatusConflict, TReadOnly, err.Error())
		return
	}
	bw := &bufferedWriter{h: http.Header{}, status: http.StatusOK}
	h(bw, r)
	if bw.status < 400 {
		s.cluster.AfterWrite(context.WithoutCancel(r.Context()))
	}
	for k, v := range bw.h {
		w.Header()[k] = v
	}
	w.WriteHeader(bw.status)
	_, _ = w.Write(bw.body.Bytes())
}

func (s *Server) registerClusterRoutes() {
	adm := auth.PermAdmin
	s.handle("GET /cluster", need(auth.PermRead), s.getCluster)
	s.handle("GET /cluster/settings", need(auth.PermRead), s.getClusterSettings)
	s.handle("PUT /cluster/settings", needStepUp(adm), s.putClusterSettings)
	s.handle("POST /cluster/resync", need(adm), s.clusterResync)
	s.handle("POST /cluster/failback", needStepUp(adm), s.clusterFailback)
	s.handle("POST /cluster/promote", needStepUp(adm), s.clusterPromote)
	s.handle("GET /cluster/conflicts", need(adm), s.listConflicts)
	s.handle("POST /cluster/conflicts/{id}/reapply", need(adm), s.reapplyConflict)
	s.handle("DELETE /cluster/conflicts/{id}", need(adm), s.dismissConflict)
}

var errStandalone = clientError{http.StatusConflict, TConflict, "haute disponibilité non configurée (nœud seul)"}

func (s *Server) getCluster(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "role": "standalone", "writable": true, "nodes": []any{},
			"gaps": []any{}, "history": []any{}, "conflicts": 0})
		return
	}
	writeJSON(w, http.StatusOK, s.cluster.Status(r.Context()))
}

func (s *Server) getClusterSettings(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeJSON(w, http.StatusOK, cluster.DefaultSettings())
		return
	}
	writeJSON(w, http.StatusOK, s.cluster.Settings())
}

func (s *Server) putClusterSettings(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		s.fail(w, r, errStandalone)
		return
	}
	var in cluster.Settings
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.cluster.SetSettings(r.Context(), in); err != nil {
		var se cluster.SettingsError
		if errors.As(err, &se) {
			s.fail(w, r, auth.ErrValidation(se))
			return
		}
		s.fail(w, r, err)
		return
	}
	s.record(r, "cluster.settings.update", "cluster", audit.Success, map[string]any{"settings": in})
	writeJSON(w, http.StatusOK, s.cluster.Settings())
}

func (s *Server) clusterOp(w http.ResponseWriter, r *http.Request, action string, fn func(context.Context) error) {
	if s.cluster == nil {
		s.fail(w, r, errStandalone)
		return
	}
	if err := fn(context.WithoutCancel(r.Context())); err != nil {
		s.record(r, action, "cluster", audit.Failure, map[string]any{"error": err.Error()})
		s.fail(w, r, clientError{http.StatusConflict, TConflict, err.Error()})
		return
	}
	s.record(r, action, "cluster", audit.Success, nil)
	writeJSON(w, http.StatusOK, s.cluster.Status(r.Context()))
}

func (s *Server) clusterResync(w http.ResponseWriter, r *http.Request) {
	s.clusterOp(w, r, "cluster.resync", func(ctx context.Context) error { return s.cluster.Resync(ctx) })
}

func (s *Server) clusterFailback(w http.ResponseWriter, r *http.Request) {
	s.clusterOp(w, r, "cluster.failback", func(ctx context.Context) error { return s.cluster.Failback(ctx) })
}

func (s *Server) clusterPromote(w http.ResponseWriter, r *http.Request) {
	s.clusterOp(w, r, "cluster.promote", func(ctx context.Context) error { return s.cluster.Promote(ctx) })
}

func (s *Server) listConflicts(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	list, err := s.cluster.Conflicts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (s *Server) reapplyConflict(w http.ResponseWriter, r *http.Request) {
	s.clusterOp(w, r, "cluster.conflict.reapply", func(ctx context.Context) error { return s.cluster.Reapply(ctx, r.PathValue("id")) })
}

func (s *Server) dismissConflict(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		s.fail(w, r, errStandalone)
		return
	}
	if err := s.cluster.Dismiss(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "cluster.conflict.dismiss", r.PathValue("id"), audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

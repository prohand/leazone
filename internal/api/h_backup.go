package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/backup"
)

func (s *Server) registerBackupRoutes() {
	s.handle("POST /backup", needStepUp(auth.PermAdmin), s.createBackup)
	s.handle("POST /restore", needStepUp(auth.PermAdmin), s.restoreBackup)
	s.handle("GET /backups", need(auth.PermAdmin), s.listBackups)
	s.handle("GET /backups/{name}", needStepUp(auth.PermAdmin), s.getBackup)
}

// backupErr maps backup errors to problems.
func (s *Server) backupErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, backup.ErrShort):
		s.fail(w, r, auth.ErrValidation{"password": err.Error()})
	case errors.Is(err, backup.ErrPassword):
		s.fail(w, r, auth.ErrValidation{"password": err.Error()})
	case errors.Is(err, backup.ErrFormat), errors.Is(err, backup.ErrNewerSchema):
		s.fail(w, r, auth.ErrValidation{"content": err.Error()})
	default:
		s.fail(w, r, err)
	}
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := s.backup.Create(r.Context(), in.Password)
	if err != nil {
		s.backupErr(w, r, err)
		return
	}
	s.record(r, "backup.create", s.cfg.NodeName, audit.Success, map[string]any{"bytes": len(data)})
	name := "leazone-backup-" + time.Now().Format("20060102-1504") + ".yaml"
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(data)
}

// maxBackup is the largest backup accepted for a restore.
const maxBackup = 32 << 20

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Content  string `json:"content"`
		DryRun   bool   `json:"dryRun"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBackup+4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.fail(w, r, clientError{http.StatusBadRequest, TBadRequest, "JSON invalide ou fichier trop gros (32 Mo maximum)"})
		return
	}
	// Restoring takes a while (Argon2id, many rows): do not stop half way
	// if the browser goes away.
	ctx := context.WithoutCancel(r.Context())
	res, err := s.backup.Restore(ctx, []byte(in.Content), in.Password, in.DryRun)
	if err != nil {
		s.backupErr(w, r, err)
		return
	}
	if !in.DryRun {
		if s.afterRestore != nil {
			s.afterRestore(ctx)
		}
		s.record(r, "backup.restore", res.Node, audit.Success, map[string]any{"createdAt": res.CreatedAt,
			"version": res.Version, "tables": res.Tables})
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) {
	files, err := backup.ListAuto(s.cfg.DataDir)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.cfg.BackupPass != "", "items": files})
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !backup.ValidAutoName(name) {
		problem(w, http.StatusNotFound, TNotFound, "")
		return
	}
	data, err := os.ReadFile(filepath.Join(backup.AutoDir(s.cfg.DataDir), name))
	if err != nil {
		problem(w, http.StatusNotFound, TNotFound, "")
		return
	}
	s.record(r, "backup.download", name, audit.Success, nil)
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(data)
}

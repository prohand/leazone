package api

import (
	"context"
	"net/http"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/importer/technitium"
)

func (s *Server) registerImportRoutes() {
	// Admin + step-up: the server makes requests to an address given by the user.
	s.handle("POST /import/technitium", needStepUp(auth.PermAdmin), s.importTechnitium)
}

func (s *Server) importTechnitium(w http.ResponseWriter, r *http.Request) {
	var in technitium.Options
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	im := &technitium.Importer{DNS: s.dns.Store, DHCP: s.dhcp.Conf, Ifaces: s.dhcp.Ifaces.Interfaces, Client: s.importClient}
	rep, err := im.Run(ctx, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !rep.DryRun {
		s.reloadDNS(r)
		s.reloadDHCP(r)
		s.record(r, "import.technitium", in.URL, audit.Success, map[string]any{"source": rep.Source,
			"created": rep.Created, "skipped": rep.Skipped, "errors": rep.Errors})
	}
	writeJSON(w, http.StatusOK, rep)
}

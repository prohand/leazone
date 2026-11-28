package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/blocking"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssec"
	"github.com/prohand/leazone/internal/modules"
)

func (s *Server) registerModuleRoutes() {
	// The blocking module is configuration (PLAN §4: modules are not for
	// operators): pause, manual rules and refresh need config.write.
	cfg := auth.PermConfigWrite
	s.handle("GET /settings/modules", need(auth.PermRead), s.getModules)
	s.handle("PUT /settings/modules", needStepUp(auth.PermAdmin), s.putModules)

	s.handle("GET /blocking/status", need(auth.PermRead), s.blockingStatus)
	s.handle("GET /blocking/settings", need(auth.PermRead), s.getBlockingSettings)
	s.handle("PUT /blocking/settings", need(cfg), s.putBlockingSettings)
	s.handle("POST /blocking/pause", need(cfg), s.pauseBlocking)
	s.handle("POST /blocking/refresh", need(cfg), s.refreshBlocking)
	s.handle("POST /blocking/check", need(auth.PermRead), s.checkBlocking)
	s.handle("GET /blocking/lists", need(auth.PermRead), s.listBlockLists)
	s.handle("POST /blocking/lists", need(cfg), s.createBlockList)
	s.handle("PUT /blocking/lists/{id}", need(cfg), s.updateBlockList)
	s.handle("DELETE /blocking/lists/{id}", need(cfg), s.deleteBlockList)
	s.handle("GET /blocking/rules", need(auth.PermRead), s.listBlockRules)
	s.handle("POST /blocking/rules", need(cfg), s.createBlockRule)
	s.handle("DELETE /blocking/rules/{id}", need(cfg), s.deleteBlockRule)
	s.handle("GET /blocking/policies", need(auth.PermRead), s.listBlockPolicies)
	s.handle("POST /blocking/policies", need(cfg), s.createBlockPolicy)
	s.handle("PUT /blocking/policies/{id}", need(cfg), s.updateBlockPolicy)
	s.handle("DELETE /blocking/policies/{id}", need(cfg), s.deleteBlockPolicy)

	s.handle("GET /dnssec/zones", need(auth.PermRead), s.listDNSSECZones)
	s.handle("GET /dnssec/zones/{id}", need(auth.PermRead), s.getDNSSECZone)
	s.handle("POST /dnssec/zones/{id}/enable", need(cfg), s.enableDNSSEC)
	s.handle("POST /dnssec/zones/{id}/disable", needStepUp(cfg), s.disableDNSSEC)
	s.handle("POST /dnssec/zones/{id}/rollover", need(cfg), s.rolloverDNSSEC)
	s.handle("POST /dnssec/zones/{id}/ds-published", need(cfg), s.dsPublished)
	s.handle("GET /dnssec/zones/{id}/export", needStepUp(auth.PermAdmin), s.exportDNSSEC)
}

// reloadBlocking applies the blocking configuration to the running engine.
func (s *Server) reloadBlocking(r *http.Request) {
	if s.blocking == nil {
		return
	}
	if err := s.blocking.Reload(context.WithoutCancel(r.Context())); err != nil {
		s.log.Error("blocking reload failed", "err", err)
	}
}

// ---- modules ----

func (s *Server) getModules(w http.ResponseWriter, r *http.Request) {
	m, err := modules.Get(r.Context(), s.db)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) putModules(w http.ResponseWriter, r *http.Request) {
	var in modules.Modules
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	before, err := modules.Get(r.Context(), s.db)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := modules.Put(r.Context(), s.db, in); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.reloadDNS(r)
	if in.Blocking && !before.Blocking && s.blocking != nil {
		s.blocking.Wake() // download the lists now
	}
	s.record(r, "modules.update", "modules", audit.Success, map[string]any{"before": before, "after": in})
	writeJSON(w, http.StatusOK, in)
}

// ---- blocking ----

func (s *Server) blockingStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.blocking.Engine.Status(10))
}

func (s *Server) getBlockingSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.blocking.Store.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putBlockingSettings(w http.ResponseWriter, r *http.Request) {
	var in blocking.Settings
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.blocking.Store.SetSettings(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.record(r, "blocking.settings.update", "blocking", audit.Success, map[string]any{"after": out})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) pauseBlocking(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes *int `json:"minutes"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Minutes == nil || *in.Minutes < 0 || *in.Minutes > 1440 {
		s.fail(w, r, dnsconf.Validation{"minutes": "entre 0 et 1440"})
		return
	}
	until, err := s.blocking.Store.SetPause(r.Context(), time.Duration(*in.Minutes)*time.Minute)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	action := "blocking.pause"
	if until.IsZero() {
		action = "blocking.resume"
	}
	s.record(r, action, "blocking", audit.Success, map[string]any{"minutes": *in.Minutes})
	writeJSON(w, http.StatusOK, s.blocking.Engine.Status(10))
}

func (s *Server) refreshBlocking(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
	defer cancel()
	lists, err := s.blocking.Refresh(ctx, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if lists == nil {
		lists, err = s.blocking.Store.Lists(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	s.record(r, "blocking.refresh", "blocking", audit.Success, nil)
	writeJSON(w, http.StatusOK, map[string]any{"items": lists})
}

func (s *Server) checkBlocking(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string `json:"name"`
		Client string `json:"client"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	name, ok := blocking.NormalizeDomain(in.Name)
	if !ok {
		s.fail(w, r, dnsconf.Validation{"name": "nom de domaine invalide"})
		return
	}
	var client netip.Addr
	if in.Client = strings.TrimSpace(in.Client); in.Client != "" {
		ip, err := netip.ParseAddr(in.Client)
		if err != nil {
			s.fail(w, r, dnsconf.Validation{"client": "adresse IP invalide"})
			return
		}
		client = ip.Unmap()
	}
	d, policy := s.blocking.Engine.Explain(name, client)
	writeJSON(w, http.StatusOK, map[string]any{"blocked": d.Blocked, "reason": d.Reason, "matched": d.Matched, "policyActive": policy})
}

func (s *Server) listBlockLists(w http.ResponseWriter, r *http.Request) {
	ls, err := s.blocking.Store.Lists(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ls})
}

func (s *Server) createBlockList(w http.ResponseWriter, r *http.Request) {
	var in blocking.ListInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	l, err := s.blocking.Store.CreateList(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "blocking.list.create", l.Name, audit.Success, map[string]any{"url": l.URL})
	// Download it now (bounded), so the answer shows the entry count.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
	defer cancel()
	if _, err := s.blocking.Refresh(ctx, false); err != nil {
		s.log.Warn("block list download", "err", err)
	}
	if l2, err := s.blocking.Store.List(r.Context(), l.ID); err == nil {
		l = l2
	}
	writeJSON(w, http.StatusCreated, l)
}

func (s *Server) updateBlockList(w http.ResponseWriter, r *http.Request) {
	var in blocking.ListInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	l, err := s.blocking.Store.UpdateList(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.record(r, "blocking.list.update", l.Name, audit.Success, map[string]any{"url": l.URL, "enabled": l.Enabled})
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) deleteBlockList(w http.ResponseWriter, r *http.Request) {
	l, err := s.blocking.Store.List(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.blocking.Store.DeleteList(r.Context(), l.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.blocking.Forget(l.ID)
	s.reloadBlocking(r)
	s.record(r, "blocking.list.delete", l.Name, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listBlockRules(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != "allow" && kind != "deny" {
		s.fail(w, r, dnsconf.Validation{"kind": "allow ou deny"})
		return
	}
	rs, err := s.blocking.Store.Rules(r.Context(), kind)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rs})
}

func (s *Server) createBlockRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain  string `json:"domain"`
		Kind    string `json:"kind"`
		Comment string `json:"comment"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	rule, err := s.blocking.Store.AddRule(r.Context(), in.Domain, in.Kind, in.Comment)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.record(r, "blocking.rule.create", rule.Domain, audit.Success, map[string]any{"kind": rule.Kind})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) deleteBlockRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.blocking.Store.DeleteRule(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.record(r, "blocking.rule.delete", id, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listBlockPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.blocking.Store.Policies(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ps})
}

type policyInput struct {
	TargetKind string `json:"targetKind"`
	Target     string `json:"target"`
	Enabled    *bool  `json:"enabled"`
	Comment    string `json:"comment"`
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request, id string) {
	var in policyInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Enabled == nil {
		s.fail(w, r, dnsconf.Validation{"enabled": "requis"})
		return
	}
	p, err := s.blocking.Store.SavePolicy(r.Context(), id, blocking.Policy{TargetKind: in.TargetKind, Target: in.Target,
		Enabled: *in.Enabled, Comment: strings.TrimSpace(in.Comment)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	status, action := http.StatusOK, "blocking.policy.update"
	if id == "" {
		status, action = http.StatusCreated, "blocking.policy.create"
	}
	s.record(r, action, p.TargetKind+":"+p.Target, audit.Success, map[string]any{"enabled": p.Enabled})
	writeJSON(w, status, p)
}

func (s *Server) createBlockPolicy(w http.ResponseWriter, r *http.Request) { s.savePolicy(w, r, "") }

func (s *Server) updateBlockPolicy(w http.ResponseWriter, r *http.Request) {
	s.savePolicy(w, r, r.PathValue("id"))
}

func (s *Server) deleteBlockPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.blocking.Store.DeletePolicy(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadBlocking(r)
	s.record(r, "blocking.policy.delete", id, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- DNSSEC ----

func (s *Server) listDNSSECZones(w http.ResponseWriter, r *http.Request) {
	zs, err := s.dns.DNSSEC.Zones(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": zs})
}

func (s *Server) getDNSSECZone(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.DNSSEC.Zone(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, z)
}

// dnssecDone reloads the DNS engine and answers with the zone.
func (s *Server) dnssecDone(w http.ResponseWriter, r *http.Request, z *dnssec.ZoneInfo, err error, action string, details map[string]any) {
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, action, z.Name, audit.Success, details)
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) enableDNSSEC(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Algorithm uint8  `json:"algorithm"`
		NSECMode  string `json:"nsecMode"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	z, err := s.dns.DNSSEC.Enable(r.Context(), r.PathValue("id"), in.Algorithm, in.NSECMode)
	var d map[string]any
	if z != nil {
		d = map[string]any{"algorithm": dns.AlgorithmToString[z.Algorithm], "nsecMode": z.NSECMode}
	}
	s.dnssecDone(w, r, z, err, "dnssec.enable", d)
}

func (s *Server) disableDNSSEC(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.DNSSEC.Disable(r.Context(), r.PathValue("id"))
	s.dnssecDone(w, r, z, err, "dnssec.disable", nil)
}

func (s *Server) rolloverDNSSEC(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type string `json:"type"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	z, err := s.dns.DNSSEC.Rollover(r.Context(), r.PathValue("id"), in.Type)
	s.dnssecDone(w, r, z, err, "dnssec.rollover", map[string]any{"type": in.Type})
}

func (s *Server) dsPublished(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.DNSSEC.DSPublished(r.Context(), r.PathValue("id"))
	s.dnssecDone(w, r, z, err, "dnssec.ds-published", nil)
}

func (s *Server) exportDNSSEC(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.DNSSEC.Zone(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	text, err := s.dns.DNSSEC.Export(r.Context(), z.ZoneID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "dnssec.export", z.Name, audit.Success, nil)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.TrimSuffix(z.Name, ".")+`.keys.txt"`)
	_, _ = w.Write([]byte(text))
}

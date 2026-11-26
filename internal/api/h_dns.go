package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/netif"
)

func (s *Server) registerDNSRoutes() {
	cfg, rec := auth.PermConfigWrite, auth.PermRecordsWrite
	s.handle("GET /interfaces", need(auth.PermRead), s.listInterfaces)
	s.handle("PATCH /interfaces/{name}", need(cfg), s.patchInterface)

	s.handle("GET /dns/settings", need(auth.PermRead), s.getDNSSettings)
	s.handle("PUT /dns/settings", need(cfg), s.putDNSSettings)
	s.handle("GET /dns/status", need(auth.PermRead), s.dnsStatus)
	s.handle("POST /dns/cache/flush", need(rec), s.flushCache)
	s.handle("POST /dns/lookup", need(auth.PermRead), s.lookup)

	s.handle("GET /dns/zones", need(auth.PermRead), s.listZones)
	s.handle("POST /dns/zones", need(cfg), s.createZone)
	s.handle("GET /dns/zones/{id}", need(auth.PermRead), s.getZone)
	s.handle("PATCH /dns/zones/{id}", need(cfg), s.patchZone)
	s.handle("DELETE /dns/zones/{id}", needStepUp(cfg), s.deleteZone)
	s.handle("GET /dns/zones/{id}/export", need(auth.PermRead), s.exportZone)
	s.handle("POST /dns/zones/{id}/import", need(rec), s.importZone)
	s.handle("GET /dns/zones/{id}/records", need(auth.PermRead), s.listRecords)
	s.handle("POST /dns/zones/{id}/records", need(rec), s.createRecord)
	s.handle("PUT /dns/zones/{id}/records/{rid}", need(rec), s.updateRecord)
	s.handle("DELETE /dns/zones/{id}/records/{rid}", need(rec), s.deleteRecord)

	s.handle("GET /dns/forwarders", need(auth.PermRead), s.listForwarders)
	s.handle("POST /dns/forwarders", need(cfg), s.createForwarder)
	s.handle("POST /dns/forwarders/test", need(cfg), s.testForwarderInput)
	s.handle("PUT /dns/forwarders/{id}", need(cfg), s.updateForwarder)
	s.handle("DELETE /dns/forwarders/{id}", need(cfg), s.deleteForwarder)
	s.handle("POST /dns/forwarders/{id}/test", need(cfg), s.testForwarder)
}

// reloadDNS applies the configuration to the running engine.
func (s *Server) reloadDNS(r *http.Request) {
	if err := s.dns.Reload(context.WithoutCancel(r.Context())); err != nil {
		s.log.Error("DNS reload failed", "err", err)
	}
}

// ---- interfaces ----

type netAddress struct {
	Address      string `json:"address"`
	PrefixLength int    `json:"prefixLength"`
	Network      string `json:"network"`
	Family       string `json:"family"`
}

type netInterface struct {
	Name         string                  `json:"name"`
	Index        int                     `json:"index"`
	Type         string                  `json:"type"`
	Parent       *string                 `json:"parent"`
	VLANID       *int                    `json:"vlanId"`
	MAC          string                  `json:"mac"`
	MTU          int                     `json:"mtu"`
	Up           bool                    `json:"up"`
	Present      bool                    `json:"present"`
	Addresses    []netAddress            `json:"addresses"`
	DNSEnabled   bool                    `json:"dnsEnabled"`
	DHCPEnabled  bool                    `json:"dhcpEnabled"`
	DNSListeners []dnssrv.ListenerStatus `json:"dnsListeners"`
}

func (s *Server) interfaces(r *http.Request) ([]netInterface, error) {
	set, err := s.dns.Store.InterfaceSettings(r.Context())
	if err != nil {
		return nil, err
	}
	listeners := s.dns.Engine.Listeners()
	seen := map[string]bool{}
	var out []netInterface
	build := func(it netif.Interface, present bool) netInterface {
		ni := netInterface{Name: it.Name, Index: it.Index, Type: it.Type, MAC: it.MAC, MTU: it.MTU, Up: it.Up, Present: present,
			Addresses: []netAddress{}, DNSEnabled: set[it.Name].DNSEnabled, DHCPEnabled: set[it.Name].DHCPEnabled,
			DNSListeners: []dnssrv.ListenerStatus{}}
		if it.Parent != "" {
			p := it.Parent
			ni.Parent = &p
		}
		if it.VLANID != 0 {
			v := it.VLANID
			ni.VLANID = &v
		}
		for _, a := range it.Addresses {
			fam := "ipv6"
			if a.Prefix.Addr().Is4() {
				fam = "ipv4"
			}
			ni.Addresses = append(ni.Addresses, netAddress{a.Prefix.Addr().String(), a.Prefix.Bits(), a.Prefix.Masked().String(), fam})
		}
		for _, l := range listeners {
			if l.Interface == it.Name {
				ni.DNSListeners = append(ni.DNSListeners, l)
			}
		}
		return ni
	}
	for _, it := range s.dns.Ifaces.Interfaces() {
		seen[it.Name] = true
		out = append(out, build(it, true))
	}
	for name := range set {
		if !seen[name] {
			out = append(out, build(netif.Interface{Name: name, Type: netif.TypeOther}, false))
		}
	}
	return out, nil
}

func (s *Server) listInterfaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.interfaces(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if list == nil {
		list = []netInterface{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (s *Server) patchInterface(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DNSEnabled  *bool `json:"dnsEnabled"`
		DHCPEnabled *bool `json:"dhcpEnabled"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	name := r.PathValue("name")
	if _, err := s.dns.Store.SetInterface(r.Context(), name, in.DNSEnabled, in.DHCPEnabled); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "interface.update", name, audit.Success, map[string]any{"dnsEnabled": in.DNSEnabled, "dhcpEnabled": in.DHCPEnabled})
	list, err := s.interfaces(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, it := range list {
		if it.Name == name {
			writeJSON(w, http.StatusOK, it)
			return
		}
	}
	s.fail(w, r, errNotFoundIface)
}

var errNotFoundIface = clientError{http.StatusNotFound, TNotFound, "interface inconnue"}

// ---- settings, status, cache, lookup ----

func (s *Server) getDNSSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.dns.Store.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putDNSSettings(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.Settings
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	before, _ := s.dns.Store.Settings(r.Context())
	out, err := s.dns.Store.SetSettings(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.settings.update", "dns", audit.Success, map[string]any{"before": before, "after": out})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dnsStatus(w http.ResponseWriter, r *http.Request) {
	st := s.dns.Engine.Stats()
	var fw []dnssrv.Health
	for _, h := range s.dns.Engine.Health() {
		fw = append(fw, h)
	}
	if fw == nil {
		fw = []dnssrv.Health{}
	}
	ls := s.dns.Engine.Listeners()
	if ls == nil {
		ls = []dnssrv.ListenerStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"port":       s.dns.Engine.Port(),
		"listeners":  ls,
		"cache":      map[string]any{"entries": st.CacheEntries, "hits": st.CacheHits, "misses": st.CacheMisses},
		"forwarders": fw,
	})
}

func (s *Server) flushCache(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	n := s.dns.Engine.FlushCache(strings.TrimSpace(in.Name))
	s.record(r, "dns.cache.flush", in.Name, audit.Success, map[string]any{"removed": n})
	writeJSON(w, http.StatusOK, map[string]int{"removed": n})
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	qtype, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(in.Type))]
	if !ok {
		s.fail(w, r, auth.ErrValidation{"type": "type inconnu"})
		return
	}
	if _, ok := dns.IsDomainName(in.Name); !ok || strings.TrimSpace(in.Name) == "" {
		s.fail(w, r, auth.ErrValidation{"name": "nom invalide"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.dns.Engine.Lookup(ctx, strings.TrimSpace(in.Name), qtype))
}

// ---- zones ----

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.dns.Store.Zones(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if zones == nil {
		zones = []*dnsconf.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": zones})
}

func (s *Server) createZone(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.ZoneInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	z, err := s.dns.Store.CreateZone(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.zone.create", z.Name, audit.Success, nil)
	writeJSON(w, http.StatusCreated, z)
}

func (s *Server) getZone(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.Store.Zone(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) patchZone(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TTL *uint32      `json:"ttl"`
		SOA *dnsconf.SOA `json:"soa"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	z, err := s.dns.Store.UpdateZone(r.Context(), r.PathValue("id"), in.TTL, in.SOA)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.zone.update", z.Name, audit.Success, map[string]any{"ttl": z.TTL, "soa": z.SOA})
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) deleteZone(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.Store.Zone(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.dns.Store.DeleteZone(r.Context(), z.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.zone.delete", z.Name, audit.Success, map[string]any{"records": z.RecordCount})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) exportZone(w http.ResponseWriter, r *http.Request) {
	z, err := s.dns.Store.Zone(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	text, err := s.dns.Store.Export(r.Context(), z.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+z.Name+`.zone"`)
	_, _ = w.Write([]byte(text))
}

func (s *Server) importZone(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Content string `json:"content"`
		Replace bool   `json:"replace"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.dns.Store.Import(r.Context(), r.PathValue("id"), in.Content, in.Replace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.zone.import", r.PathValue("id"), audit.Success, map[string]any{"imported": res.Imported, "skipped": res.Skipped, "replace": in.Replace})
	writeJSON(w, http.StatusOK, res)
}

// ---- records ----

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	recs, err := s.dns.Store.Records(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if recs == nil {
		recs = []*dnsconf.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recs})
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.RecordInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	rec, err := s.dns.Store.CreateRecord(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.record.create", rec.FQDN, audit.Success, map[string]any{"type": rec.Type, "value": rec.Value})
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) updateRecord(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.RecordInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	old, _ := s.dns.Store.Record(r.Context(), r.PathValue("id"), r.PathValue("rid"))
	rec, err := s.dns.Store.UpdateRecord(r.Context(), r.PathValue("id"), r.PathValue("rid"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	details := map[string]any{"type": rec.Type, "value": rec.Value}
	if old != nil {
		details["before"] = old.FQDN + " " + old.Type + " " + old.Value
	}
	s.record(r, "dns.record.update", rec.FQDN, audit.Success, details)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) {
	old, err := s.dns.Store.Record(r.Context(), r.PathValue("id"), r.PathValue("rid"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.dns.Store.DeleteRecord(r.Context(), r.PathValue("id"), r.PathValue("rid")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.record.delete", old.FQDN, audit.Success, map[string]any{"type": old.Type, "value": old.Value})
	w.WriteHeader(http.StatusNoContent)
}

// ---- forwarders ----

type forwarderResp struct {
	*dnsconf.Forwarder
	Health dnssrv.Health `json:"health"`
}

func (s *Server) fwdResp(f *dnsconf.Forwarder) forwarderResp {
	h, ok := s.dns.Engine.Health()[f.ID]
	if !ok {
		h = dnssrv.Health{ID: f.ID, Healthy: true}
	}
	return forwarderResp{f, h}
}

func (s *Server) listForwarders(w http.ResponseWriter, r *http.Request) {
	list, err := s.dns.Store.Forwarders(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]forwarderResp, 0, len(list))
	for _, f := range list {
		out = append(out, s.fwdResp(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) createForwarder(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.ForwarderInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.dns.Store.CreateForwarder(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.forwarder.create", fwdLabel(f), audit.Success, map[string]any{"domain": f.Domain, "tlsVerify": f.TLSVerify})
	writeJSON(w, http.StatusCreated, s.fwdResp(f))
}

func (s *Server) updateForwarder(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.ForwarderInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.dns.Store.UpdateForwarder(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.forwarder.update", fwdLabel(f), audit.Success, map[string]any{"domain": f.Domain, "enabled": f.Enabled,
		"position": f.Position, "tlsVerify": f.TLSVerify})
	writeJSON(w, http.StatusOK, s.fwdResp(f))
}

func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) {
	f, err := s.dns.Store.Forwarder(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.dns.Store.DeleteForwarder(r.Context(), f.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDNS(r)
	s.record(r, "dns.forwarder.delete", fwdLabel(f), audit.Success, map[string]any{"domain": f.Domain})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testForwarderInput(w http.ResponseWriter, r *http.Request) {
	var in dnsconf.ForwarderInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := dnsconf.ValidateForwarder(in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.dns.Engine.TestForwarder(r.Context(), f))
}

func (s *Server) testForwarder(w http.ResponseWriter, r *http.Request) {
	f, err := s.dns.Store.Forwarder(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.dns.Engine.TestForwarder(r.Context(), *f))
}

func fwdLabel(f *dnsconf.Forwarder) string {
	if f.Protocol == dnsconf.ProtoDoH {
		return f.DoHURL
	}
	return f.Protocol + "://" + f.Address
}

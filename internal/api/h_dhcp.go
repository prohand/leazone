package api

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/store"
)

func (s *Server) registerDHCPRoutes() {
	cfg, lw := auth.PermConfigWrite, auth.PermLeasesWrite
	s.handle("GET /vlans", need(auth.PermRead), s.listVLANs)
	s.handle("POST /vlans", need(cfg), s.createVLAN)
	s.handle("PUT /vlans/{id}", need(cfg), s.updateVLAN)
	s.handle("DELETE /vlans/{id}", need(cfg), s.deleteVLAN)

	s.handle("GET /dhcp/status", need(auth.PermRead), s.dhcpStatus)
	s.handle("GET /dhcp/scopes", need(auth.PermRead), s.listScopes)
	s.handle("POST /dhcp/scopes", need(cfg), s.createScope)
	s.handle("GET /dhcp/scopes/{id}", need(auth.PermRead), s.getScope)
	s.handle("PUT /dhcp/scopes/{id}", need(cfg), s.updateScope)
	s.handle("DELETE /dhcp/scopes/{id}", needStepUp(cfg), s.deleteScope)

	s.handle("GET /dhcp/reservations", need(auth.PermRead), s.listReservations)
	s.handle("POST /dhcp/reservations", need(lw), s.createReservation)
	s.handle("PUT /dhcp/reservations/{id}", need(lw), s.updateReservation)
	s.handle("DELETE /dhcp/reservations/{id}", need(lw), s.deleteReservation)

	s.handle("GET /dhcp/leases", need(auth.PermRead), s.listLeases)
	s.handle("DELETE /dhcp/leases/{scope}/{ip}", need(lw), s.releaseLease)
	s.handle("POST /dhcp/leases/{scope}/{ip}/reserve", need(lw), s.reserveLease)
}

func (s *Server) reloadDHCP(r *http.Request) {
	ctx := context.WithoutCancel(r.Context())
	if err := s.dhcp.Reload(ctx); err != nil {
		s.log.Error("DHCP reload failed", "err", err)
	}
}

// ---- usage ----

type scopeUsage struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Network        string  `json:"network"`
	Mode           string  `json:"mode"`
	Enabled        bool    `json:"enabled"`
	Size           int     `json:"size"`
	Used           int     `json:"used"`
	ActiveLeases   int     `json:"activeLeases"`
	Percent        float64 `json:"percent"`
	Alert          bool    `json:"alert"`
	AlertThreshold int     `json:"alertThreshold"`
}

func usageOf(sc *dhcpconf.Scope, u dhcpsrv.Usage) scopeUsage {
	su := scopeUsage{ID: sc.ID, Name: sc.Name, Network: sc.Network, Mode: sc.Mode(), Enabled: sc.Enabled, Size: u.Size,
		Used: u.Used, ActiveLeases: u.Active, AlertThreshold: sc.AlertThreshold}
	if u.Size > 0 {
		su.Percent = float64(int(float64(u.Used)*1000/float64(u.Size))) / 10
	}
	su.Alert = su.Percent >= float64(sc.AlertThreshold)
	return su
}

type scopeResp struct {
	*dhcpconf.Scope
	Mode         string     `json:"mode"`
	Usage        scopeUsage `json:"usage"`
	ReverseZones []string   `json:"reverseZones"`
}

func (s *Server) scopeResp(sc *dhcpconf.Scope, usage map[string]dhcpsrv.Usage) scopeResp {
	rz := []string{}
	if p, err := netip.ParsePrefix(sc.Network); err == nil {
		rz = reverseNames(p)
	}
	return scopeResp{Scope: sc, Mode: sc.Mode(), Usage: usageOf(sc, usage[sc.ID]), ReverseZones: rz}
}

// ---- VLANs ----

type vlanIface struct {
	Name        string   `json:"name"`
	Parent      string   `json:"parent"`
	Addresses   []string `json:"addresses"`
	DHCPEnabled bool     `json:"dhcpEnabled"`
}

type vlanOverview struct {
	ID         *string      `json:"id"`
	VLANID     int          `json:"vlanId"`
	Name       string       `json:"name"`
	Interfaces []vlanIface  `json:"interfaces"`
	Scopes     []scopeUsage `json:"scopes"`
}

func (s *Server) listVLANs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	labels, err := s.dhcp.Conf.VLANs(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scopes, err := s.dhcp.Conf.Scopes(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	set, err := s.dns.Store.InterfaceSettings(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	usage := s.dhcp.Engine.Usage()
	byID := map[int]*vlanOverview{}
	get := func(id int) *vlanOverview {
		if v := byID[id]; v != nil {
			return v
		}
		v := &vlanOverview{VLANID: id, Interfaces: []vlanIface{}, Scopes: []scopeUsage{}}
		byID[id] = v
		return v
	}
	for _, l := range labels {
		v := get(l.VLANID)
		id := l.ID
		v.ID, v.Name = &id, l.Name
	}
	for _, it := range s.dhcp.Ifaces.Interfaces() {
		if it.VLANID == 0 {
			continue
		}
		vi := vlanIface{Name: it.Name, Parent: it.Parent, Addresses: []string{}, DHCPEnabled: set[it.Name].DHCPEnabled}
		for _, a := range it.Addresses {
			vi.Addresses = append(vi.Addresses, a.Prefix.String())
		}
		v := get(it.VLANID)
		v.Interfaces = append(v.Interfaces, vi)
	}
	// A direct scope's interface carries its VLAN even when it is not an
	// 802.1Q sub-interface (access port, untagged on the switch side).
	hostIfaces := map[string]vlanIface{}
	for _, it := range s.dhcp.Ifaces.Interfaces() {
		vi := vlanIface{Name: it.Name, Parent: it.Parent, Addresses: []string{}, DHCPEnabled: set[it.Name].DHCPEnabled}
		for _, a := range it.Addresses {
			vi.Addresses = append(vi.Addresses, a.Prefix.String())
		}
		hostIfaces[it.Name] = vi
	}
	for _, sc := range scopes {
		if sc.VLANID == nil || sc.Interface == nil {
			continue
		}
		vi, ok := hostIfaces[*sc.Interface]
		if !ok {
			continue
		}
		v := get(*sc.VLANID)
		dup := false
		for _, x := range v.Interfaces {
			dup = dup || x.Name == vi.Name
		}
		if !dup {
			v.Interfaces = append(v.Interfaces, vi)
		}
	}
	untagged := []scopeUsage{}
	for _, sc := range scopes {
		if sc.VLANID == nil {
			untagged = append(untagged, usageOf(sc, usage[sc.ID]))
			continue
		}
		v := get(*sc.VLANID)
		v.Scopes = append(v.Scopes, usageOf(sc, usage[sc.ID]))
	}
	out := make([]*vlanOverview, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VLANID < out[j].VLANID })
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "untaggedScopes": untagged})
}

type vlanInput struct {
	VLANID int    `json:"vlanId"`
	Name   string `json:"name"`
}

func (s *Server) createVLAN(w http.ResponseWriter, r *http.Request) {
	var in vlanInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.dhcp.Conf.CreateVLAN(r.Context(), in.VLANID, in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "vlan.create", strconv.Itoa(v.VLANID), audit.Success, map[string]any{"name": v.Name})
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) updateVLAN(w http.ResponseWriter, r *http.Request) {
	var in vlanInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.dhcp.Conf.UpdateVLAN(r.Context(), r.PathValue("id"), in.VLANID, in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "vlan.update", strconv.Itoa(v.VLANID), audit.Success, map[string]any{"name": v.Name})
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) deleteVLAN(w http.ResponseWriter, r *http.Request) {
	if err := s.dhcp.Conf.DeleteVLAN(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "vlan.delete", r.PathValue("id"), audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- status & scopes ----

func (s *Server) dhcpStatus(w http.ResponseWriter, r *http.Request) {
	listening, errMsg := s.dhcp.Server.Status()
	ifs := s.dhcp.Engine.EnabledInterfaces()
	if ifs == nil {
		ifs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"listening": listening, "error": errMsg, "port": s.dhcp.Server.Port,
		"interfaces": ifs, "pingAvailable": s.dhcp.PingAvailable})
}

func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := s.dhcp.Conf.Scopes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	usage := s.dhcp.Engine.Usage()
	out := make([]scopeResp, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, s.scopeResp(sc, usage))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	sc, err := s.dhcp.Conf.Scope(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.scopeResp(sc, s.dhcp.Engine.Usage()))
}

// afterScopeChange creates the reverse zones and applies the change.
func (s *Server) afterScopeChange(r *http.Request, sc *dhcpconf.Scope) {
	if p, err := netip.ParsePrefix(sc.Network); err == nil {
		if _, err := s.dns.Store.EnsureReverseZones(r.Context(), p); err != nil {
			s.log.Warn("reverse zones", "network", sc.Network, "err", err)
		}
	}
	if sc.DDNSEnabled && sc.DDNSDomain != "" {
		if _, err := s.dns.Store.EnsureZone(r.Context(), sc.DDNSDomain); err != nil {
			s.log.Warn("DDNS zone", "zone", sc.DDNSDomain, "err", err)
		}
	}
	s.reloadDNS(r)
	s.reloadDHCP(r)
}

func (s *Server) createScope(w http.ResponseWriter, r *http.Request) {
	var in dhcpconf.ScopeInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	sc, err := s.dhcp.Conf.CreateScope(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.afterScopeChange(r, sc)
	s.record(r, "dhcp.scope.create", sc.Name, audit.Success, map[string]any{"network": sc.Network, "mode": sc.Mode()})
	writeJSON(w, http.StatusCreated, s.scopeResp(sc, s.dhcp.Engine.Usage()))
}

func (s *Server) updateScope(w http.ResponseWriter, r *http.Request) {
	var in dhcpconf.ScopeInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	sc, err := s.dhcp.Conf.UpdateScope(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.afterScopeChange(r, sc)
	s.record(r, "dhcp.scope.update", sc.Name, audit.Success, map[string]any{"network": sc.Network, "mode": sc.Mode()})
	writeJSON(w, http.StatusOK, s.scopeResp(sc, s.dhcp.Engine.Usage()))
}

func (s *Server) deleteScope(w http.ResponseWriter, r *http.Request) {
	sc, err := s.dhcp.Conf.Scope(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Remove the DNS records of the scope's leases first.
	for _, l := range s.dhcp.Engine.Leases() {
		if l.ScopeID == sc.ID && l.State == dhcpsrv.StateBound && s.dhcp.Engine.Hooks != nil {
			s.dhcp.Engine.Hooks.Ended(r.Context(), sc, l)
		}
	}
	if err := s.dhcp.Conf.DeleteScope(r.Context(), sc.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "dhcp.scope.delete", sc.Name, audit.Success, map[string]any{"network": sc.Network})
	w.WriteHeader(http.StatusNoContent)
}

// ---- reservations ----

func (s *Server) listReservations(w http.ResponseWriter, r *http.Request) {
	list, err := s.dhcp.Conf.Reservations(r.Context(), r.URL.Query().Get("scope"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if list == nil {
		list = []*dhcpconf.Reservation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (s *Server) createReservation(w http.ResponseWriter, r *http.Request) {
	var in dhcpconf.ReservationInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.dhcp.Conf.CreateReservation(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "dhcp.reservation.create", res.IP, audit.Success, map[string]any{"scope": res.ScopeName, "mac": res.MAC, "hostname": res.Hostname})
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) updateReservation(w http.ResponseWriter, r *http.Request) {
	var in dhcpconf.ReservationInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.dhcp.Conf.UpdateReservation(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "dhcp.reservation.update", res.IP, audit.Success, map[string]any{"scope": res.ScopeName, "mac": res.MAC, "hostname": res.Hostname})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) deleteReservation(w http.ResponseWriter, r *http.Request) {
	res, err := s.dhcp.Conf.Reservation(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.dhcp.Conf.DeleteReservation(r.Context(), res.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "dhcp.reservation.delete", res.IP, audit.Success, map[string]any{"scope": res.ScopeName, "mac": res.MAC})
	w.WriteHeader(http.StatusNoContent)
}

// ---- leases ----

type leaseResp struct {
	ScopeID   string    `json:"scopeId"`
	ScopeName string    `json:"scopeName"`
	VLANID    *int      `json:"vlanId"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	ClientID  string    `json:"clientId"`
	Hostname  string    `json:"hostname"`
	State     string    `json:"state"`
	Starts    time.Time `json:"starts"`
	Ends      time.Time `json:"ends"`
	CircuitID string    `json:"circuitId"`
	RemoteID  string    `json:"remoteId"`
	GIAddr    string    `json:"giaddr"`
	Reserved  bool      `json:"reserved"`
	DNSName   *string   `json:"dnsName"`
}

func (s *Server) listLeases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scopes, err := s.dhcp.Conf.Scopes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.dhcp.Conf.Reservations(r.Context(), "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	byID := map[string]*dhcpconf.Scope{}
	for _, sc := range scopes {
		byID[sc.ID] = sc
	}
	reserved := map[string]bool{}
	for _, x := range res {
		reserved[x.ScopeID+"|"+x.IP] = true
	}
	vlan, _ := strconv.Atoi(q.Get("vlan"))
	all := q.Get("all") == "true"
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	now := time.Now()
	out := []leaseResp{}
	for _, l := range s.dhcp.Engine.Leases() {
		sc := byID[l.ScopeID]
		if sc == nil || l.MAC == "" { // MAC-less rows are conflict markers
			if sc == nil || l.State != dhcpsrv.StateDeclined {
				continue
			}
		}
		if q.Get("scope") != "" && l.ScopeID != q.Get("scope") {
			continue
		}
		if vlan != 0 && (sc.VLANID == nil || *sc.VLANID != vlan) {
			continue
		}
		if st := q.Get("state"); st != "" && l.State != st {
			continue
		}
		if !all && !l.Active(now) && q.Get("state") == "" {
			continue
		}
		lr := leaseResp{ScopeID: l.ScopeID, ScopeName: sc.Name, VLANID: sc.VLANID, IP: l.IP.String(), MAC: l.MAC,
			ClientID: l.ClientID, Hostname: l.Hostname, State: l.State, Starts: l.Starts, Ends: l.Ends, CircuitID: l.CircuitID,
			RemoteID: l.RemoteID, GIAddr: l.GIAddr, Reserved: reserved[l.ScopeID+"|"+l.IP.String()]}
		if l.DNSName != "" {
			n := l.DNSName
			lr.DNSName = &n
		}
		if search != "" && !strings.Contains(strings.ToLower(lr.IP+" "+lr.MAC+" "+lr.Hostname+" "+lr.CircuitID+" "+lr.RemoteID), search) {
			continue
		}
		out = append(out, lr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) releaseLease(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	l, err := s.dhcp.Engine.Release(r.Context(), r.PathValue("scope"), ip)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "dhcp.lease.release", ip.String(), audit.Success, map[string]any{"mac": l.MAC, "hostname": l.Hostname})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reserveLease(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	var found *dhcpsrv.Lease
	for _, l := range s.dhcp.Engine.Leases() {
		if l.ScopeID == r.PathValue("scope") && l.IP.String() == ip && l.MAC != "" {
			lc := l
			found = &lc
		}
	}
	if found == nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	res, err := s.dhcp.Conf.CreateReservation(r.Context(), dhcpconf.ReservationInput{ScopeID: found.ScopeID, MAC: found.MAC,
		ClientID: found.ClientID, IP: ip, Hostname: found.Hostname, Description: "créée depuis un bail"})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadDHCP(r)
	s.record(r, "dhcp.reservation.create", res.IP, audit.Success, map[string]any{"scope": res.ScopeName, "mac": res.MAC, "fromLease": true})
	writeJSON(w, http.StatusCreated, res)
}

func reverseNames(p netip.Prefix) []string {
	out := []string{}
	for _, q := range dnsconf.ReverseZonesFor(p) {
		if n, err := dnsconf.ReverseZone(q); err == nil {
			out = append(out, n)
		}
	}
	return out
}

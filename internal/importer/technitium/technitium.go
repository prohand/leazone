// Package technitium imports zones, forwarders and DHCP scopes from a
// Technitium DNS Server, read through its HTTP API. Nothing existing in
// Leazone is ever overwritten: objects with the same name are skipped.
package technitium

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/netif"
)

// RemoteError is a failure on the Technitium side (unreachable, refused...).
type RemoteError struct{ Msg string }

func (e RemoteError) Error() string { return e.Msg }

// Options of one import run.
type Options struct {
	URL        string `json:"url"`
	Token      string `json:"token"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TLSVerify  *bool  `json:"tlsVerify"`
	DryRun     *bool  `json:"dryRun"`
	Zones      *bool  `json:"zones"`
	Forwarders *bool  `json:"forwarders"`
	DHCP       *bool  `json:"dhcp"`
}

func on(b *bool) bool { return b == nil || *b }

// Item is one line of the report.
type Item struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Action string `json:"action"` // create | skip | error
	Detail string `json:"detail"`
}

// Report is the result of an import (or a preview).
type Report struct {
	DryRun  bool   `json:"dryRun"`
	Source  string `json:"source"`
	Items   []Item `json:"items"`
	Created int    `json:"created"`
	Skipped int    `json:"skipped"`
	Errors  int    `json:"errors"`
}

func (r *Report) add(kind, name, action, detail string) {
	r.Items = append(r.Items, Item{kind, name, action, detail})
	switch action {
	case "create":
		r.Created++
	case "skip":
		r.Skipped++
	default:
		r.Errors++
	}
}

// Importer writes into the Leazone stores.
type Importer struct {
	DNS    *dnsconf.Store
	DHCP   *dhcpconf.Store
	Ifaces func() []netif.Interface
	// Client is used for the API calls (tests); nil = built from Options.
	Client *http.Client
}

type client struct {
	base  string
	token string
	hc    *http.Client
}

// envelope is the common Technitium response wrapper.
type envelope struct {
	Status       string          `json:"status"`
	ErrorMessage string          `json:"errorMessage"`
	Response     json.RawMessage `json:"response"`
	Token        string          `json:"token"`
}

func (c *client) get(ctx context.Context, path string, params url.Values, out any) error {
	raw, _, err := c.raw(ctx, path, params)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return RemoteError{fmt.Sprintf("réponse illisible de %s (est-ce bien Technitium ?)", path)}
	}
	switch env.Status {
	case "ok":
	case "invalid-token":
		return RemoteError{"jeton ou session refusé par Technitium"}
	case "2fa-required":
		return RemoteError{"le compte a l'authentification à deux facteurs : utilisez un jeton d'API Technitium"}
	default:
		return RemoteError{"Technitium : " + env.ErrorMessage}
	}
	if out == nil {
		return nil
	}
	if len(env.Response) == 0 {
		return json.Unmarshal(raw, out) // login answers at the top level
	}
	return json.Unmarshal(env.Response, out)
}

// raw calls the API with a POST form (accepted by Technitium for every call):
// the token, the password and the other parameters travel in the body, never
// in the URL (proxy and server logs, error messages).
func (c *client) raw(ctx context.Context, path string, params url.Values) ([]byte, string, error) {
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	if c.token != "" {
		form.Set("token", c.token) // versions before 15 only read the parameter
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", RemoteError{"Technitium injoignable : " + transportError(err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", RemoteError{fmt.Sprintf("Technitium a répondu HTTP %d sur %s", resp.StatusCode, path)}
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// transportError describes a failed request without its URL (which could
// carry secrets with another client or a redirect).
func transportError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

func (im *Importer) connect(ctx context.Context, o Options) (*client, error) {
	u, err := url.Parse(strings.TrimSpace(o.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, dnsconf.Validation{"url": "URL attendue, ex : http://10.0.0.5:5380"}
	}
	hc := im.Client
	if hc == nil {
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: !on(o.TLSVerify)}} //nolint:gosec // only when the admin unticks "vérification TLS"
		hc = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	c := &client{base: strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), token: strings.TrimSpace(o.Token), hc: hc}
	if c.token == "" {
		if o.Username == "" {
			return nil, dnsconf.Validation{"token": "indiquez un jeton d'API, ou un nom d'utilisateur et un mot de passe"}
		}
		var login envelope
		if err := c.get(ctx, "/api/user/login", url.Values{"user": {o.Username}, "pass": {o.Password}}, &login); err != nil {
			return nil, err
		}
		if login.Token == "" {
			return nil, RemoteError{"connexion à Technitium refusée"}
		}
		c.token = login.Token
	}
	return c, nil
}

// Run imports (or previews, when DryRun) from Technitium.
func (im *Importer) Run(ctx context.Context, o Options) (*Report, error) {
	c, err := im.connect(ctx, o)
	if err != nil {
		return nil, err
	}
	rep := &Report{DryRun: on(o.DryRun), Items: []Item{}}
	var settings struct {
		Version           string   `json:"version"`
		Forwarders        []string `json:"forwarders"`
		ForwarderProtocol string   `json:"forwarderProtocol"`
	}
	if err := c.get(ctx, "/api/settings/get", nil, &settings); err != nil {
		return nil, err
	}
	rep.Source = "Technitium DNS Server " + settings.Version
	if on(o.Zones) || on(o.Forwarders) {
		if err := im.zones(ctx, c, rep, on(o.Zones), on(o.Forwarders)); err != nil {
			return nil, err
		}
	}
	if on(o.Forwarders) {
		im.globalForwarders(ctx, rep, settings.Forwarders, settings.ForwarderProtocol)
	}
	if on(o.DHCP) {
		if err := im.dhcp(ctx, c, rep); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// ---- zones and conditional forwarders ----

type tZone struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Internal bool   `json:"internal"`
	Disabled bool   `json:"disabled"`
}

func (im *Importer) zones(ctx context.Context, c *client, rep *Report, zones, fwd bool) error {
	var list struct {
		Zones []tZone `json:"zones"`
	}
	if err := c.get(ctx, "/api/zones/list", nil, &list); err != nil {
		return err
	}
	sort.Slice(list.Zones, func(i, j int) bool { return list.Zones[i].Name < list.Zones[j].Name })
	for _, z := range list.Zones {
		if z.Internal {
			continue
		}
		switch z.Type {
		case "Primary":
			if zones {
				im.primaryZone(ctx, c, rep, z)
			}
		case "Forwarder":
			if fwd {
				im.forwarderZone(ctx, c, rep, z)
			}
		default:
			if zones {
				rep.add("zone", z.Name, "skip", "zone de type "+z.Type+" : non gérée par Leazone")
			}
		}
	}
	return nil
}

func (im *Importer) primaryZone(ctx context.Context, c *client, rep *Report, z tZone) {
	if _, err := im.DNS.ZoneByName(ctx, z.Name); err == nil {
		rep.add("zone", z.Name, "skip", "la zone existe déjà dans Leazone")
		return
	}
	text, _, err := c.raw(ctx, "/api/zones/export", url.Values{"zone": {z.Name}})
	if err != nil {
		rep.add("zone", z.Name, "error", err.Error())
		return
	}
	rrs, skipped, _ := dnsconf.ParseZoneLenient(string(text), z.Name, 3600)
	n := 0
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case 1, 28, 5, 15, 16, 33, 12, 2: // A AAAA CNAME MX TXT SRV PTR NS
			n++
		}
	}
	if rep.DryRun {
		detail := fmt.Sprintf("%d enregistrements", n)
		if z.Disabled {
			detail += " (zone désactivée dans Technitium)"
		}
		rep.add("zone", z.Name, "create", detail)
		return
	}
	created, err := im.DNS.CreateZone(ctx, dnsconf.ZoneInput{Name: z.Name})
	if err != nil {
		rep.add("zone", z.Name, "error", err.Error())
		return
	}
	res, err := im.DNS.Import(ctx, created.ID, string(text), false)
	if err != nil {
		rep.add("zone", z.Name, "error", err.Error())
		return
	}
	detail := fmt.Sprintf("%d enregistrements importés", res.Imported)
	if res.Skipped+skipped > 1 { // the SOA is always skipped
		detail += fmt.Sprintf(", %d ignorés (SOA, types non gérés)", res.Skipped)
	}
	rep.add("zone", z.Name, "create", detail)
}

// fwdTarget is a Technitium "name server address" converted to a forwarder.
func fwdTarget(protocol, addr string) (dnsconf.ForwarderInput, error) {
	in := dnsconf.ForwarderInput{}
	switch strings.ToLower(protocol) {
	case "udp", "":
		in.Protocol = dnsconf.ProtoUDP
	case "tcp":
		in.Protocol = dnsconf.ProtoTCP
	case "tls":
		in.Protocol = dnsconf.ProtoDoT
	case "https":
		in.Protocol = dnsconf.ProtoDoH
	default:
		return in, fmt.Errorf("protocole %s non géré par Leazone", protocol)
	}
	addr = strings.TrimSpace(addr)
	if addr == "this-server" {
		return in, errors.New("« this-server » : rien à importer")
	}
	// Formats: "ip", "ip:port", "[ipv6]:port", "name (ip)", "name:port (ip:port)",
	// "https://name/path (ip)".
	name, ipPart := addr, ""
	if i := strings.Index(addr, " ("); i > 0 && strings.HasSuffix(addr, ")") {
		name, ipPart = addr[:i], addr[i+2:len(addr)-1]
	}
	if in.Protocol == dnsconf.ProtoDoH {
		in.DoHURL = name
		if ipPart != "" {
			h, _ := splitHostPort(ipPart)
			in.Address = h
		}
		return in, nil
	}
	target := name
	if ipPart != "" {
		target = ipPart
		if h, _ := splitHostPort(name); h != "" {
			in.TLSServerName = h
		}
	}
	host, port := splitHostPort(target)
	if _, err := netip.ParseAddr(host); err != nil {
		return in, fmt.Errorf("adresse %q : Leazone a besoin de l'IP du serveur", addr)
	}
	in.Address, in.Port = host, port
	return in, nil
}

func splitHostPort(s string) (string, int) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return strings.Trim(h, "[]"), n
	}
	return strings.Trim(s, "[]"), 0
}

func (im *Importer) forwarderZone(ctx context.Context, c *client, rep *Report, z tZone) {
	var recs struct {
		Records []struct {
			Type  string                     `json:"type"`
			RData map[string]json.RawMessage `json:"rData"`
		} `json:"records"`
	}
	if err := c.get(ctx, "/api/zones/records/get", url.Values{"domain": {z.Name}, "zone": {z.Name}, "listZone": {"true"}}, &recs); err != nil {
		rep.add("forwarder", z.Name, "error", err.Error())
		return
	}
	existing, _ := im.DNS.Forwarders(ctx)
	for _, f := range existing {
		if f.Domain == strings.ToLower(strings.TrimSuffix(z.Name, ".")) {
			rep.add("forwarder", z.Name, "skip", "des redirecteurs existent déjà pour ce domaine dans Leazone")
			return
		}
	}
	found := false
	for _, r := range recs.Records {
		if r.Type != "FWD" {
			continue
		}
		found = true
		var proto, addr string
		_ = json.Unmarshal(r.RData["protocol"], &proto)
		_ = json.Unmarshal(r.RData["forwarder"], &addr)
		in, err := fwdTarget(proto, addr)
		label := z.Name + " → " + addr
		if err != nil {
			rep.add("forwarder", label, "error", err.Error())
			continue
		}
		in.Domain = z.Name
		im.createForwarder(ctx, rep, label, in)
	}
	if !found {
		rep.add("forwarder", z.Name, "skip", "aucun enregistrement FWD dans cette zone")
	}
}

func (im *Importer) createForwarder(ctx context.Context, rep *Report, label string, in dnsconf.ForwarderInput) {
	if _, err := dnsconf.ValidateForwarder(in); err != nil {
		rep.add("forwarder", label, "error", humanErr(err))
		return
	}
	if rep.DryRun {
		rep.add("forwarder", label, "create", strings.ToUpper(in.Protocol))
		return
	}
	if _, err := im.DNS.CreateForwarder(ctx, in); err != nil {
		rep.add("forwarder", label, "error", humanErr(err))
		return
	}
	rep.add("forwarder", label, "create", strings.ToUpper(in.Protocol))
}

func (im *Importer) globalForwarders(ctx context.Context, rep *Report, list []string, protocol string) {
	if len(list) == 0 {
		return
	}
	existing, _ := im.DNS.Forwarders(ctx)
	for _, f := range existing {
		if f.Domain == "" {
			rep.add("forwarder", "redirecteurs globaux", "skip", "Leazone a déjà des redirecteurs globaux")
			return
		}
	}
	for _, a := range list {
		in, err := fwdTarget(protocol, a)
		if err != nil {
			rep.add("forwarder", a, "error", err.Error())
			continue
		}
		im.createForwarder(ctx, rep, "global → "+a, in)
	}
}

// ---- DHCP ----

type tScope struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	StartingAddress  string   `json:"startingAddress"`
	EndingAddress    string   `json:"endingAddress"`
	SubnetMask       string   `json:"subnetMask"`
	LeaseTimeDays    int      `json:"leaseTimeDays"`
	LeaseTimeHours   int      `json:"leaseTimeHours"`
	LeaseTimeMinutes int      `json:"leaseTimeMinutes"`
	PingCheckEnabled bool     `json:"pingCheckEnabled"`
	DomainName       string   `json:"domainName"`
	DNSUpdates       bool     `json:"dnsUpdates"`
	RouterAddress    string   `json:"routerAddress"`
	UseThisDNSServer bool     `json:"useThisDnsServer"`
	DNSServers       []string `json:"dnsServers"`
	NTPServers       []string `json:"ntpServers"`
	GenericOptions   []struct {
		Code  int    `json:"code"`
		Value string `json:"value"`
	} `json:"genericOptions"`
	Exclusions []struct {
		StartingAddress string `json:"startingAddress"`
		EndingAddress   string `json:"endingAddress"`
	} `json:"exclusions"`
	ReservedLeases []struct {
		HostName        *string `json:"hostName"`
		HardwareAddress string  `json:"hardwareAddress"`
		Address         string  `json:"address"`
		Comments        string  `json:"comments"`
	} `json:"reservedLeases"`
}

func (im *Importer) dhcp(ctx context.Context, c *client, rep *Report) error {
	var list struct {
		Scopes []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"scopes"`
	}
	if err := c.get(ctx, "/api/dhcp/scopes/list", nil, &list); err != nil {
		return err
	}
	for _, s := range list.Scopes {
		var sc tScope
		if err := c.get(ctx, "/api/dhcp/scopes/get", url.Values{"name": {s.Name}}, &sc); err != nil {
			rep.add("scope", s.Name, "error", err.Error())
			continue
		}
		sc.Enabled = s.Enabled
		im.scope(ctx, rep, sc)
	}
	return nil
}

func (im *Importer) scope(ctx context.Context, rep *Report, t tScope) {
	start, err1 := netip.ParseAddr(t.StartingAddress)
	mask := net.ParseIP(t.SubnetMask).To4()
	if err1 != nil || mask == nil {
		rep.add("scope", t.Name, "error", "adresses de l'étendue illisibles")
		return
	}
	ones, _ := net.IPMask(mask).Size()
	prefix := netip.PrefixFrom(start, ones).Masked()
	lease := uint32(t.LeaseTimeDays*86400 + t.LeaseTimeHours*3600 + t.LeaseTimeMinutes*60)
	in := dhcpconf.ScopeInput{Name: t.Name, Enabled: &t.Enabled, Network: prefix.String(), RangeStart: t.StartingAddress,
		RangeEnd: t.EndingAddress, LeaseTime: lease, Gateway: t.RouterAddress, DNSServers: t.DNSServers, Domain: t.DomainName,
		NTPServers: t.NTPServers, PingCheck: t.PingCheckEnabled}
	ddns := t.DNSUpdates && t.DomainName != ""
	in.DDNSEnabled = &ddns
	for _, ex := range t.Exclusions {
		in.Exclusions = append(in.Exclusions, dhcpconf.Range{Start: ex.StartingAddress, End: ex.EndingAddress})
	}
	for _, o := range t.GenericOptions {
		in.Options = append(in.Options, dhcpconf.Option{Code: o.Code, Type: "hex", Value: o.Value})
	}
	// Technitium serves a scope on the interface holding an address of the
	// network, otherwise through relays: do the same.
	notes := []string{}
	if im.Ifaces != nil {
		for _, it := range im.Ifaces() {
			for _, a := range it.IPv4() {
				if prefix.Contains(a) {
					name := it.Name
					in.Interface = &name
					if it.VLANID != 0 {
						v := it.VLANID
						in.VLANID = &v
					}
				}
			}
		}
	}
	if in.Interface != nil {
		notes = append(notes, "mode direct sur "+*in.Interface)
	} else {
		in.Relay = true
		notes = append(notes, "mode relais (aucune interface de l'hôte dans ce réseau)")
	}
	if t.UseThisDNSServer && len(t.DNSServers) == 0 {
		notes = append(notes, "« utiliser ce serveur DNS » : indiquez l'IP DNS à donner aux clients")
	}
	existing, _ := im.DHCP.Scopes(ctx)
	for _, e := range existing {
		if e.Name == t.Name {
			rep.add("scope", t.Name, "skip", "une étendue porte déjà ce nom")
			return
		}
	}
	if err := im.DHCP.ValidateScope(ctx, in); err != nil {
		rep.add("scope", t.Name, "error", humanErr(err))
		return
	}
	detail := prefix.String() + ", " + strings.Join(notes, ", ")
	if rep.DryRun {
		rep.add("scope", t.Name, "create", detail)
		for _, r := range t.ReservedLeases {
			rep.add("reservation", r.Address, "create", "étendue "+t.Name+", MAC "+r.HardwareAddress)
		}
		return
	}
	sc, err := im.DHCP.CreateScope(ctx, in)
	if err != nil {
		rep.add("scope", t.Name, "error", humanErr(err))
		return
	}
	rep.add("scope", t.Name, "create", detail)
	for _, r := range t.ReservedLeases {
		host := ""
		if r.HostName != nil {
			host = *r.HostName
		}
		_, err := im.DHCP.CreateReservation(ctx, dhcpconf.ReservationInput{ScopeID: sc.ID, MAC: r.HardwareAddress, IP: r.Address,
			Hostname: host, Description: r.Comments})
		if err != nil {
			rep.add("reservation", r.Address, "error", humanErr(err))
			continue
		}
		rep.add("reservation", r.Address, "create", "étendue "+t.Name+", MAC "+r.HardwareAddress)
	}
}

func humanErr(err error) string {
	var v dnsconf.Validation
	if errors.As(err, &v) {
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+" : "+v[k])
		}
		return strings.Join(parts, " ; ")
	}
	return err.Error()
}

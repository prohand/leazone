// Package ddns registers DHCP leases in DNS: an A record in the scope's DNS
// domain and a PTR record in the reverse zone, removed when the lease ends.
// Manual records are never replaced, and a name held by another active
// client is not taken over.
package ddns

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
)

// Reloader applies DNS changes to the running server.
type Reloader interface{ ReloadSoon() }

// Updater implements dhcpsrv.Hooks.
type Updater struct {
	DNS    *dnsconf.Store
	DHCP   *dhcpconf.Store
	Reload Reloader
	Log    *slog.Logger
	// Active tells whether a lease owner still holds a bound lease.
	Active func(owner string) bool
}

// recordTTL is short so clients follow address changes quickly.
const recordTTL = 300

// Owner is the DNS owner key of a lease.
func Owner(scopeID string, l dhcpsrv.Lease) string { return scopeID + "|" + l.Key() }

// forbiddenNames are never registered for a client that names itself:
// clients look them up to find a proxy configuration (WPAD), an IPv6
// tunnel (ISATAP) or the local host, so a client registering them could
// intercept the traffic of the others. A reservation created by the admin
// may still use them.
var forbiddenNames = map[string]bool{"wpad": true, "isatap": true, "localhost": true}

// ForbiddenName reports whether a client-chosen host name is refused.
func ForbiddenName(host string) bool { return forbiddenNames[strings.ToLower(host)] }

// Bound registers the lease and returns the FQDN ("" when nothing registered).
// When the records of the lease are already the ones wanted (a renewal, the
// same client re-binding), nothing is written and DNS is not reloaded.
func (u *Updater) Bound(ctx context.Context, sc *dhcpconf.Scope, l dhcpsrv.Lease) string {
	owner := Owner(sc.ID, l)
	fqdn, want := u.plan(ctx, sc, l, owner)
	if have, err := u.DNS.DHCPOwnerRecords(ctx, owner); err == nil && sameRecords(have, want) {
		return fqdn
	}
	// The client may have changed its name: drop what it had before.
	if _, err := u.DNS.DeleteDHCPOwner(ctx, owner); err != nil {
		u.Log.Warn("DDNS cleanup", "err", err)
	}
	defer u.Reload.ReloadSoon()
	for i, r := range want {
		if err := u.DNS.PutDHCPRecord(ctx, r.ZoneID, r.Name, r.Type, r.TTL, r.Data, owner); err != nil {
			u.Log.Warn("DDNS "+r.Type+" record", "err", err)
			if i == 0 {
				return "" // no A record: nothing registered
			}
		}
	}
	if fqdn != "" {
		u.Log.Info("DDNS registered", "name", fqdn, "ip", l.IP)
	}
	return fqdn
}

// plan computes the records a lease should have (A first, then PTR) and
// its FQDN; none when the lease gets no name.
func (u *Updater) plan(ctx context.Context, sc *dhcpconf.Scope, l dhcpsrv.Lease, owner string) (string, []dnsconf.DHCPRecord) {
	host := l.Hostname
	reserved := false
	// A reservation with a host name wins over what the client sends.
	if res, err := u.DHCP.Reservations(ctx, sc.ID); err == nil {
		for _, r := range res {
			if r.IP == l.IP.String() && r.Hostname != "" {
				host, reserved = r.Hostname, true
			}
		}
	}
	if !sc.DDNSEnabled || host == "" || sc.DDNSDomain == "" {
		return "", nil
	}
	if !reserved && ForbiddenName(host) {
		u.Log.Warn("DDNS: reserved name refused for a client", "name", host, "ip", l.IP, "mac", l.MAC)
		return "", nil
	}
	// The zone is created with the scope (on the primary): never create
	// config from here, this also runs on secondaries.
	zone, err := u.DNS.ZoneByName(ctx, sc.DDNSDomain)
	if err != nil {
		u.Log.Warn("DDNS zone missing", "zone", sc.DDNSDomain, "err", err)
		return "", nil
	}
	owners, err := u.DNS.Owners(ctx, zone.ID, host)
	if err != nil {
		return "", nil
	}
	for _, o := range owners {
		if o.Source == "manual" {
			u.Log.Info("DDNS: name kept by a manual record", "name", host+"."+zone.Name, "ip", l.IP)
			return "", nil
		}
		if o.Owner != owner && u.Active != nil && u.Active(o.Owner) {
			u.Log.Info("DDNS: name already used by another client", "name", host+"."+zone.Name, "ip", l.IP)
			return "", nil
		}
	}
	ttl := uint32(recordTTL)
	if zone.TTL < ttl {
		ttl = zone.TTL
	}
	fqdn := host + "." + zone.Name + "."
	want := []dnsconf.DHCPRecord{{ZoneID: zone.ID, Name: host, Type: "A", TTL: ttl, Data: dnsconf.RecordData{IP: l.IP.String()}}}
	// PTR in the reverse zone (created with the scope).
	if rz, rel, ok := u.reverse(ctx, l.IP); ok {
		want = append(want, dnsconf.DHCPRecord{ZoneID: rz.ID, Name: rel, Type: "PTR", TTL: ttl, Data: dnsconf.RecordData{Target: fqdn}})
	}
	return fqdn, want
}

// sameRecords reports whether two record lists hold the same records.
func sameRecords(a, b []dnsconf.DHCPRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// reverse finds the reverse zone holding ip and the relative PTR name.
func (u *Updater) reverse(ctx context.Context, ip netip.Addr) (*dnsconf.Zone, string, bool) {
	b := ip.As4()
	labels := []string{fmt.Sprint(b[3]), fmt.Sprint(b[2]), fmt.Sprint(b[1]), fmt.Sprint(b[0])}
	for n := 3; n >= 1; n-- {
		name := strings.Join(labels[4-n:], ".") + ".in-addr.arpa"
		if z, err := u.DNS.ZoneByName(ctx, name); err == nil {
			return z, strings.Join(labels[:4-n], "."), true
		}
	}
	return nil, "", false
}

// Ended removes the records of a lease that ended. Records the same client
// registered since for another address (a newer lease) are kept.
func (u *Updater) Ended(ctx context.Context, sc *dhcpconf.Scope, l dhcpsrv.Lease) {
	n, err := u.DNS.DeleteDHCPOwnerAt(ctx, Owner(sc.ID, l), l.IP)
	if err != nil {
		u.Log.Warn("DDNS removal", "err", err)
		return
	}
	if n > 0 {
		u.Log.Info("DDNS removed", "ip", l.IP, "records", n)
		u.Reload.ReloadSoon()
	}
}

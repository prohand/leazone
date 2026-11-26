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

// Bound registers the lease and returns the FQDN ("" when nothing registered).
func (u *Updater) Bound(ctx context.Context, sc *dhcpconf.Scope, l dhcpsrv.Lease) string {
	owner := Owner(sc.ID, l)
	// The client may have changed its name: drop what it had before.
	if _, err := u.DNS.DeleteDHCPOwner(ctx, owner); err != nil {
		u.Log.Warn("DDNS cleanup", "err", err)
	}
	defer u.Reload.ReloadSoon()
	host := l.Hostname
	// A reservation with a host name wins over what the client sends.
	if res, err := u.DHCP.Reservations(ctx, sc.ID); err == nil {
		for _, r := range res {
			if r.IP == l.IP.String() && r.Hostname != "" {
				host = r.Hostname
			}
		}
	}
	if !sc.DDNSEnabled || host == "" || sc.DDNSDomain == "" {
		return ""
	}
	// The zone is created with the scope (on the primary): never create
	// config from here, this also runs on secondaries.
	zone, err := u.DNS.ZoneByName(ctx, sc.DDNSDomain)
	if err != nil {
		u.Log.Warn("DDNS zone missing", "zone", sc.DDNSDomain, "err", err)
		return ""
	}
	owners, err := u.DNS.Owners(ctx, zone.ID, host)
	if err != nil {
		return ""
	}
	for _, o := range owners {
		if o.Source == "manual" {
			u.Log.Info("DDNS: name kept by a manual record", "name", host+"."+zone.Name, "ip", l.IP)
			return ""
		}
		if o.Owner != owner && u.Active != nil && u.Active(o.Owner) {
			u.Log.Info("DDNS: name already used by another client", "name", host+"."+zone.Name, "ip", l.IP)
			return ""
		}
	}
	ttl := uint32(recordTTL)
	if zone.TTL < ttl {
		ttl = zone.TTL
	}
	if err := u.DNS.PutDHCPRecord(ctx, zone.ID, host, "A", ttl, dnsconf.RecordData{IP: l.IP.String()}, owner); err != nil {
		u.Log.Warn("DDNS A record", "err", err)
		return ""
	}
	fqdn := host + "." + zone.Name + "."
	// PTR in the reverse zone (created with the scope).
	if rz, rel, ok := u.reverse(ctx, l.IP); ok {
		if err := u.DNS.PutDHCPRecord(ctx, rz.ID, rel, "PTR", ttl, dnsconf.RecordData{Target: fqdn}, owner); err != nil {
			u.Log.Warn("DDNS PTR record", "err", err)
		}
	}
	u.Log.Info("DDNS registered", "name", fqdn, "ip", l.IP)
	return fqdn
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

// Ended removes the records of a lease that ended.
func (u *Updater) Ended(ctx context.Context, sc *dhcpconf.Scope, l dhcpsrv.Lease) {
	n, err := u.DNS.DeleteDHCPOwner(ctx, Owner(sc.ID, l))
	if err != nil {
		u.Log.Warn("DDNS removal", "err", err)
		return
	}
	if n > 0 {
		u.Log.Info("DDNS removed", "ip", l.IP, "records", n)
		u.Reload.ReloadSoon()
	}
}

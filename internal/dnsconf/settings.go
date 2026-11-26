package dnsconf

import (
	"context"
	"net/netip"
	"strings"

	"github.com/prohand/leazone/internal/config"
)

// Settings are the DNS server settings (settings key "dns").
type Settings struct {
	CacheSize            int      `json:"cacheSize"`
	CacheMinTTL          uint32   `json:"cacheMinTtl"`
	CacheMaxTTL          uint32   `json:"cacheMaxTtl"`
	CacheNegativeMaxTTL  uint32   `json:"cacheNegativeMaxTtl"`
	RecursionNetworks    []string `json:"recursionNetworks"`
	ExtraListenAddresses []string `json:"extraListenAddresses"`
}

// SettingsKey is the settings table key.
const SettingsKey = "dns"

// DefaultSettings: private networks may recurse, public ones may not.
func DefaultSettings() Settings {
	return Settings{
		CacheSize: 10000, CacheMinTTL: 0, CacheMaxTTL: 86400, CacheNegativeMaxTTL: 900,
		RecursionNetworks: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
			"127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10"},
		ExtraListenAddresses: []string{},
	}
}

// Validate checks and normalizes the settings.
func (st *Settings) Validate() error {
	errs := Validation{}
	if st.CacheSize < 0 || st.CacheSize > 1000000 {
		errs["cacheSize"] = "entre 0 et 1 000 000"
	}
	if st.CacheMinTTL > 86400 {
		errs["cacheMinTtl"] = "86400 secondes maximum"
	}
	if st.CacheMaxTTL < 1 || st.CacheMaxTTL > 604800 {
		errs["cacheMaxTtl"] = "entre 1 et 604800 secondes"
	}
	if st.CacheMinTTL > st.CacheMaxTTL {
		errs["cacheMinTtl"] = "doit être inférieur au TTL maximum"
	}
	if st.CacheNegativeMaxTTL > 86400 {
		errs["cacheNegativeMaxTtl"] = "86400 secondes maximum"
	}
	nets := []string{}
	for _, n := range st.RecursionNetworks {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		p, err := config.ParsePrefixOrAddr(n)
		if err != nil {
			errs["recursionNetworks"] = "réseau invalide : " + n
			continue
		}
		nets = append(nets, p.String())
	}
	st.RecursionNetworks = nets
	ips := []string{}
	for _, a := range st.ExtraListenAddresses {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			errs["extraListenAddresses"] = "adresse IP invalide : " + a
			continue
		}
		ips = append(ips, ip.Unmap().String())
	}
	st.ExtraListenAddresses = ips
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Settings returns the stored settings or the defaults.
func (s *Store) Settings(ctx context.Context) (Settings, error) {
	st := DefaultSettings()
	_, err := s.db.GetSetting(ctx, SettingsKey, &st)
	return st, err
}

// SetSettings validates and stores settings.
func (s *Store) SetSettings(ctx context.Context, st Settings) (Settings, error) {
	if err := st.Validate(); err != nil {
		return st, err
	}
	return st, s.db.PutSetting(ctx, SettingsKey, st)
}

// InterfaceSetting is the per-interface configuration.
type InterfaceSetting struct {
	Name        string `json:"name"`
	DNSEnabled  bool   `json:"dnsEnabled"`
	DHCPEnabled bool   `json:"dhcpEnabled"`
}

// InterfaceSettings returns all per-interface settings by name.
func (s *Store) InterfaceSettings(ctx context.Context) (map[string]InterfaceSetting, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT if_name, dns_enabled, dhcp_enabled FROM interface_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]InterfaceSetting{}
	for rows.Next() {
		var is InterfaceSetting
		var d, h int
		if err := rows.Scan(&is.Name, &d, &h); err != nil {
			return nil, err
		}
		is.DNSEnabled, is.DHCPEnabled = d != 0, h != 0
		out[is.Name] = is
	}
	return out, rows.Err()
}

// SetInterface updates the settings of one interface (nil = unchanged).
// A row with everything disabled is removed.
func (s *Store) SetInterface(ctx context.Context, name string, dnsOn, dhcpOn *bool) (InterfaceSetting, error) {
	cur := InterfaceSetting{Name: name}
	all, err := s.InterfaceSettings(ctx)
	if err != nil {
		return cur, err
	}
	if v, ok := all[name]; ok {
		cur = v
	}
	if dnsOn != nil {
		cur.DNSEnabled = *dnsOn
	}
	if dhcpOn != nil {
		cur.DHCPEnabled = *dhcpOn
	}
	if !cur.DNSEnabled && !cur.DHCPEnabled {
		_, err = s.db.ExecContext(ctx, `DELETE FROM interface_settings WHERE if_name = ?`, name)
		return cur, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO interface_settings(if_name, dns_enabled, dhcp_enabled, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(if_name) DO UPDATE SET dns_enabled = excluded.dns_enabled, dhcp_enabled = excluded.dhcp_enabled,
		updated_at = excluded.updated_at`, name, b2i(cur.DNSEnabled), b2i(cur.DHCPEnabled), s.Now().UnixMilli())
	return cur, err
}

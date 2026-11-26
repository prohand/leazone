// Package config loads Leazone settings from an optional YAML file and
// LEAZONE_* environment variables. Secrets are only read from files
// (LEAZONE_*_FILE, e.g. Docker secrets) unless explicitly allowed.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the static configuration of a node. Everything that can be
// changed at runtime from the UI lives in the database instead.
type Config struct {
	ConfigDir string `yaml:"-"`
	DataDir   string `yaml:"data_dir"`
	LogDir    string `yaml:"log_dir"`

	// HTTPListen is the address of the UI/API HTTPS server.
	HTTPListen string `yaml:"http_listen"`
	// PublicURL is the URL users type in the browser (e.g. behind nginx).
	PublicURL string `yaml:"public_url"`
	// TrustedProxies are the proxies allowed to set X-Forwarded-* headers.
	TrustedProxies []string `yaml:"trusted_proxies"`

	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"` // text or json (stdout)

	// DNSPort is the port of the DNS server (53; another port helps tests).
	DNSPort int `yaml:"dns_port"`
	// DHCPPort is the DHCP server port (67); clients are answered on DHCPPort+1.
	DHCPPort int `yaml:"dhcp_port"`

	// Cluster (HA). Cluster mode is on when a cluster key and peers are set.
	NodeName      string   `yaml:"node_name"`
	ClusterListen string   `yaml:"cluster_listen"`
	ClusterAddr   string   `yaml:"cluster_addr"`  // advertised, e.g. https://192.168.1.2:7443
	Peers         []string `yaml:"cluster_peers"` // other nodes' cluster_addr
	Witness       string   `yaml:"witness"`       // https://ip:7443 (container) or ping:IP
	PreferredRole string   `yaml:"preferred_role"`
	VIP           string   `yaml:"vip"`           // e.g. 192.168.1.10/24
	VIPInterface  string   `yaml:"vip_interface"` // e.g. eno1

	// ControlSocket is the local Unix socket used by CLI sub-commands.
	// Default: <data_dir>/run/leazone.sock (a directory private to the user,
	// not the world-writable /tmp).
	ControlSocket string `yaml:"control_socket"`

	AdminUser string `yaml:"admin_user"`

	// Secrets (never stored in the YAML file).
	AdminPassword string `yaml:"-"`
	ClusterKey    string `yaml:"-"`
	BackupPass    string `yaml:"-"`

	// AllowPlainSecrets accepts LEAZONE_ADMIN_PASSWORD etc. as plain env vars.
	AllowPlainSecrets bool `yaml:"allow_plain_secrets"`

	parsedProxies []netip.Prefix
}

// Defaults returns the configuration used inside the Docker image.
func Defaults() Config {
	return Config{
		ConfigDir:     "/config",
		DataDir:       "/data",
		LogDir:        "/logs",
		HTTPListen:    ":8443",
		LogLevel:      "info",
		LogFormat:     "text",
		DNSPort:       53,
		ClusterListen: ":7443",
		PreferredRole: "secondary",
		DHCPPort:      67,
		AdminUser:     "admin",
	}
}

// Load reads <configDir>/leazone.yaml (optional) then applies environment
// variables, which win over the file.
func Load(getenv func(string) string) (*Config, error) {
	c := Defaults()
	if v := getenv("LEAZONE_CONFIG_DIR"); v != "" {
		c.ConfigDir = v
	}
	path := c.ConfigDir + "/leazone.yaml"
	if b, err := os.ReadFile(path); err == nil {
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config file %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("config file %s: %w", path, err)
	}

	str := func(name string, dst *string) {
		if v := getenv("LEAZONE_" + name); v != "" {
			*dst = v
		}
	}
	str("DATA_DIR", &c.DataDir)
	str("LOG_DIR", &c.LogDir)
	str("HTTP_LISTEN", &c.HTTPListen)
	str("PUBLIC_URL", &c.PublicURL)
	str("LOG_LEVEL", &c.LogLevel)
	str("LOG_FORMAT", &c.LogFormat)
	str("CONTROL_SOCKET", &c.ControlSocket)
	str("ADMIN_USER", &c.AdminUser)
	str("NODE_NAME", &c.NodeName)
	str("CLUSTER_LISTEN", &c.ClusterListen)
	str("CLUSTER_ADDR", &c.ClusterAddr)
	str("WITNESS", &c.Witness)
	str("PREFERRED_ROLE", &c.PreferredRole)
	str("VIP", &c.VIP)
	str("VIP_INTERFACE", &c.VIPInterface)
	if v := getenv("LEAZONE_CLUSTER_PEERS"); v != "" {
		c.Peers = splitList(v)
	}
	if v := getenv("LEAZONE_DNS_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("LEAZONE_DNS_PORT: port invalide %q", v)
		}
		c.DNSPort = p
	}
	if v := getenv("LEAZONE_DHCP_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65534 {
			return nil, fmt.Errorf("LEAZONE_DHCP_PORT: port invalide %q", v)
		}
		c.DHCPPort = p
	}
	if v := getenv("LEAZONE_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitList(v)
	}
	if v := getenv("LEAZONE_ALLOW_PLAIN_SECRETS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("LEAZONE_ALLOW_PLAIN_SECRETS: %w", err)
		}
		c.AllowPlainSecrets = b
	}

	var err error
	if c.AdminPassword, err = secret(getenv, "ADMIN_PASSWORD", c.AllowPlainSecrets); err != nil {
		return nil, err
	}
	if c.ClusterKey, err = secret(getenv, "CLUSTER_KEY", c.AllowPlainSecrets); err != nil {
		return nil, err
	}
	if c.BackupPass, err = secret(getenv, "BACKUP_PASSWORD", c.AllowPlainSecrets); err != nil {
		return nil, err
	}
	return &c, c.validate()
}

// secret reads LEAZONE_<name>_FILE, or LEAZONE_<name> when plain secrets are allowed.
func secret(getenv func(string) string, name string, allowPlain bool) (string, error) {
	if p := getenv("LEAZONE_" + name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("LEAZONE_%s_FILE: %w", name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if v := getenv("LEAZONE_" + name); v != "" {
		if !allowPlain {
			return "", fmt.Errorf("LEAZONE_%s is a plain secret in the environment: use LEAZONE_%s_FILE (Docker secret) or set LEAZONE_ALLOW_PLAIN_SECRETS=true", name, name)
		}
		return v, nil
	}
	return "", nil
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (c *Config) validate() error {
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("LEAZONE_PUBLIC_URL must look like https://leazone.example.lan (got %q)", c.PublicURL)
		}
		c.PublicURL = strings.TrimRight(u.Scheme+"://"+u.Host, "/")
	}
	if _, _, err := net.SplitHostPort(c.HTTPListen); err != nil {
		return fmt.Errorf("LEAZONE_HTTP_LISTEN %q: %w", c.HTTPListen, err)
	}
	c.parsedProxies = nil
	for _, p := range c.TrustedProxies {
		pfx, err := ParsePrefixOrAddr(p)
		if err != nil {
			return fmt.Errorf("LEAZONE_TRUSTED_PROXIES: %w", err)
		}
		c.parsedProxies = append(c.parsedProxies, pfx)
	}
	if c.NodeName == "" {
		c.NodeName, _ = os.Hostname()
	}
	if c.ControlSocket == "" {
		c.ControlSocket = filepath.Join(c.DataDir, "run", "leazone.sock")
	}
	if c.PreferredRole != "primary" && c.PreferredRole != "secondary" {
		return fmt.Errorf("LEAZONE_PREFERRED_ROLE must be primary or secondary")
	}
	// Same address written with or without a trailing slash.
	c.ClusterAddr = strings.TrimRight(c.ClusterAddr, "/")
	for i, p := range c.Peers {
		c.Peers[i] = strings.TrimRight(p, "/")
	}
	if strings.HasPrefix(c.Witness, "https://") {
		c.Witness = strings.TrimRight(c.Witness, "/")
	}
	if len(c.Peers) > 0 && c.ClusterKey == "" {
		return fmt.Errorf("LEAZONE_CLUSTER_PEERS is set but the cluster key is empty: " +
			"LEAZONE_CLUSTER_KEY_FILE is missing or the file is empty (the node would start alone, outside the cluster)")
	}
	if c.Clustered() {
		if c.ClusterAddr == "" {
			return fmt.Errorf("LEAZONE_CLUSTER_ADDR is required in HA mode (e.g. https://192.168.1.2:7443)")
		}
		for _, u := range append([]string{c.ClusterAddr}, c.Peers...) {
			if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" || pu.Host == "" {
				return fmt.Errorf("cluster address %q must look like https://192.168.1.2:7443", u)
			}
		}
		if c.Witness != "" && !strings.HasPrefix(c.Witness, "ping:") && !strings.HasPrefix(c.Witness, "https://") {
			return fmt.Errorf("LEAZONE_WITNESS must be https://ip:7443 (witness container) or ping:IP")
		}
		if strings.HasPrefix(c.Witness, "ping:") {
			if _, err := netip.ParseAddr(strings.TrimPrefix(c.Witness, "ping:")); err != nil {
				return fmt.Errorf("LEAZONE_WITNESS ping: needs an IP address")
			}
		}
	}
	if c.VIP != "" {
		p, err := netip.ParsePrefix(c.VIP)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("LEAZONE_VIP must look like 192.168.1.10/24")
		}
		if c.VIPInterface == "" {
			return fmt.Errorf("LEAZONE_VIP_INTERFACE is required with LEAZONE_VIP")
		}
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("LEAZONE_LOG_FORMAT must be text or json")
	}
	return nil
}

// Clustered reports whether HA mode is configured.
func (c *Config) Clustered() bool { return c.ClusterKey != "" && len(c.Peers) > 0 }

// Proxies returns the parsed trusted proxy networks.
func (c *Config) Proxies() []netip.Prefix { return c.parsedProxies }

// ParsePrefixOrAddr accepts "10.0.0.0/8" or a single address "10.0.0.5".
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

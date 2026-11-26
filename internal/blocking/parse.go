package blocking

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// List formats.
const (
	FormatAuto    = "auto"
	FormatHosts   = "hosts"
	FormatDomains = "domains"
	FormatAdblock = "adblock"
)

// Parsed is the content of one list.
type Parsed struct {
	Deny  []string // blocked domains (and their sub-domains)
	Allow []string // AdBlock exceptions (@@||domain^)
}

// hosts files map these names to the loopback: never block them.
var hostsNoise = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Parse reads a list. Lines it does not understand are skipped (AdBlock
// rules with paths or options other than $important are browser rules).
func Parse(r io.Reader, format string) (Parsed, error) {
	var p Parsed
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		f := format
		if f == FormatAuto || f == "" {
			f = detect(line)
		}
		switch f {
		case FormatAdblock:
			d, allow, ok := parseAdblock(line)
			if !ok {
				continue
			}
			if allow {
				p.Allow = append(p.Allow, d)
			} else {
				p.Deny = append(p.Deny, d)
			}
		case FormatHosts:
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				// Some "hosts" lists mix in bare domains.
				if len(fields) == 1 {
					if d, ok := NormalizeDomain(fields[0]); ok && !hostsNoise[d] {
						p.Deny = append(p.Deny, d)
					}
				}
				continue
			}
			if _, err := netip.ParseAddr(fields[0]); err != nil {
				continue
			}
			for _, h := range fields[1:] {
				if d, ok := NormalizeDomain(h); ok && !hostsNoise[d] {
					p.Deny = append(p.Deny, d)
				}
			}
		default: // domains
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if d, ok := NormalizeDomain(line); ok && !hostsNoise[d] {
				p.Deny = append(p.Deny, d)
			}
		}
	}
	return p, sc.Err()
}

func detect(line string) string {
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@||") {
		return FormatAdblock
	}
	if i := strings.IndexAny(line, " \t"); i > 0 {
		if _, err := netip.ParseAddr(line[:i]); err == nil {
			return FormatHosts
		}
	}
	return FormatDomains
}

// parseAdblock understands "||domain^", "||domain^$important" and the
// "@@" exception form. A bare domain line is accepted too.
func parseAdblock(line string) (domain string, allow, ok bool) {
	if strings.HasPrefix(line, "@@") {
		allow = true
		line = line[2:]
	}
	if !strings.HasPrefix(line, "||") {
		if strings.ContainsAny(line, "^$|/*") {
			return "", false, false
		}
		d, ok := NormalizeDomain(line)
		return d, allow, ok
	}
	line = line[2:]
	if i := strings.IndexByte(line, '$'); i >= 0 {
		opts := line[i+1:]
		line = line[:i]
		for _, o := range strings.Split(opts, ",") {
			if o != "important" && o != "all" && o != "third-party" && o != "3p" {
				return "", false, false
			}
		}
	}
	line = strings.TrimSuffix(line, "|")
	if !strings.HasSuffix(line, "^") {
		return "", false, false
	}
	d, ok := NormalizeDomain(strings.TrimSuffix(line, "^"))
	if !ok || strings.ContainsAny(d, "*/") {
		return "", false, false
	}
	return d, allow, true
}

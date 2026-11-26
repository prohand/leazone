package dnssrv

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
)

const (
	tryTimeout   = 2 * time.Second
	totalTimeout = 5 * time.Second
	ednsSize     = 1232
)

// upstream is a live forwarder. Its configuration never changes once
// built; a reload with the same connection settings makes a new upstream
// that shares the link (connection pool and health) of the previous one.
type upstream struct {
	cfg dnsconf.Forwarder
	*link
}

// link is the live part of an upstream: connections and health.
type link struct {
	tlsConf *tls.Config
	doh     *http.Client
	pool    chan *dns.Conn // idle DoT connections

	mu          sync.Mutex
	failures    int
	downUntil   time.Time
	lastErr     string
	lastLatency time.Duration
	lastCheck   time.Time
}

// Health is the public health view of a forwarder.
type Health struct {
	ID            string     `json:"id"`
	Healthy       bool       `json:"healthy"`
	LastError     string     `json:"lastError"`
	LastLatencyMs float64    `json:"lastLatencyMs"`
	LastCheckAt   *time.Time `json:"lastCheckAt"`
}

func newUpstream(f dnsconf.Forwarder, roots *x509.CertPool) *upstream {
	u := &upstream{cfg: f, link: &link{}}
	if f.Protocol == dnsconf.ProtoDoT || f.Protocol == dnsconf.ProtoDoH {
		name := f.TLSServerName
		if name == "" {
			name = f.Address
		}
		u.tlsConf = &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: roots,
			InsecureSkipVerify: !f.TLSVerify} //nolint:gosec // only when the admin disables verification explicitly
	}
	switch f.Protocol {
	case dnsconf.ProtoDoT:
		u.pool = make(chan *dns.Conn, 4)
	case dnsconf.ProtoDoH:
		target := net.JoinHostPort(f.Address, strconv.Itoa(f.Port))
		dialer := &net.Dialer{Timeout: tryTimeout}
		tr := &http.Transport{
			Proxy: nil, // a LAN DNS server talks to its upstream directly
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Always dial the bootstrap IP: no DNS lookup for the DoH host.
				return dialer.DialContext(ctx, network, target)
			},
			TLSClientConfig:     u.tlsConf,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        8,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: tryTimeout,
		}
		u.doh = &http.Client{Transport: tr, Timeout: tryTimeout + time.Second}
	}
	return u
}

func (u *link) close() {
	if u.pool != nil {
		for {
			select {
			case c := <-u.pool:
				c.Close()
			default:
				return
			}
		}
	}
	if u.doh != nil {
		u.doh.CloseIdleConnections()
	}
}

func (u *upstream) label() string {
	if u.cfg.Protocol == dnsconf.ProtoDoH {
		return u.cfg.DoHURL
	}
	return strings.ToUpper(u.cfg.Protocol) + " " + net.JoinHostPort(u.cfg.Address, strconv.Itoa(u.cfg.Port))
}

func (u *link) available(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return !now.Before(u.downUntil)
}

func (u *link) record(err error, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastCheck = time.Now()
	if err == nil {
		u.failures, u.downUntil, u.lastErr, u.lastLatency = 0, time.Time{}, "", latency
		return
	}
	u.failures++
	u.lastErr = humanError(err)
	// Back off 5 s, 10 s, 20 s... up to 60 s after repeated failures.
	if u.failures >= 2 {
		d := 5 * time.Second << min(u.failures-2, 4)
		if d > time.Minute {
			d = time.Minute
		}
		u.downUntil = time.Now().Add(d)
	}
}

func (u *upstream) health() Health {
	u.mu.Lock()
	defer u.mu.Unlock()
	h := Health{ID: u.cfg.ID, Healthy: u.failures == 0, LastError: u.lastErr,
		LastLatencyMs: float64(u.lastLatency.Microseconds()) / 1000}
	if !u.lastCheck.IsZero() {
		t := u.lastCheck
		h.LastCheckAt = &t
	}
	return h
}

// exchange sends one query to this upstream.
func (u *upstream) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, tryTimeout)
	defer cancel()
	addr := net.JoinHostPort(u.cfg.Address, strconv.Itoa(u.cfg.Port))
	switch u.cfg.Protocol {
	case dnsconf.ProtoUDP:
		c := &dns.Client{Net: "udp", Timeout: tryTimeout, UDPSize: ednsSize}
		r, _, err := c.ExchangeContext(ctx, q, addr)
		if err == nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, q, addr)
		}
		return r, err
	case dnsconf.ProtoTCP:
		c := &dns.Client{Net: "tcp", Timeout: tryTimeout}
		r, _, err := c.ExchangeContext(ctx, q, addr)
		return r, err
	case dnsconf.ProtoDoT:
		return u.exchangeDoT(ctx, q, addr)
	case dnsconf.ProtoDoH:
		return u.exchangeDoH(ctx, q)
	}
	return nil, fmt.Errorf("protocole inconnu %q", u.cfg.Protocol)
}

func (u *upstream) exchangeDoT(ctx context.Context, q *dns.Msg, addr string) (*dns.Msg, error) {
	// Try a pooled connection first; a stale one fails fast and we redial.
	for attempt := 0; attempt < 2; attempt++ {
		var conn *dns.Conn
		pooled := false
		select {
		case conn = <-u.pool:
			pooled = true
		default:
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: tryTimeout}, Config: u.tlsConf}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			conn = &dns.Conn{Conn: c}
		}
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		if err := conn.WriteMsg(q); err != nil {
			conn.Close()
			if pooled {
				continue
			}
			return nil, err
		}
		r, err := conn.ReadMsg()
		if err != nil {
			conn.Close()
			if pooled {
				continue
			}
			return nil, err
		}
		if r.Id != q.Id {
			conn.Close()
			return nil, errors.New("réponse DoT inattendue (identifiant différent)")
		}
		select {
		case u.pool <- conn:
		default:
			conn.Close()
		}
		return r, nil
	}
	return nil, errors.New("connexion DoT perdue")
}

func (u *upstream) exchangeDoH(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	// RFC 8484: use ID 0 for cache friendliness, restore it afterwards.
	id := q.Id
	q2 := q.Copy()
	q2.Id = 0
	wire, err := q2.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.DoHURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.doh.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("le serveur DoH a répondu HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("réponse DoH illisible : %w", err)
	}
	r.Id = id
	return r, nil
}

// humanError turns network errors into short French messages for the UI.
func humanError(err error) string {
	var cve *tls.CertificateVerificationError
	var uae x509.UnknownAuthorityError
	var hne x509.HostnameError
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.As(err, &hne):
		return "certificat TLS invalide : il ne correspond pas au nom attendu (" + hne.Host + ")"
	case errors.As(err, &uae):
		return "certificat TLS non reconnu (autorité inconnue)"
	case errors.As(err, &cve):
		return "certificat TLS invalide : " + cve.Err.Error()
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "pas de réponse (délai dépassé)"
	case strings.Contains(msg, "connection refused"):
		return "connexion refusée"
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "no route to host"):
		return "serveur injoignable (réseau)"
	case strings.Contains(msg, "connection reset"):
		return "connexion coupée par le serveur"
	}
	return msg
}

// forwarders is an immutable snapshot of the configured upstreams.
type forwarders struct {
	global      []*upstream
	conditional map[string][]*upstream // domain FQDN -> ordered upstreams
	all         map[string]*upstream   // by id
}

func buildForwarders(list []*dnsconf.Forwarder, old *forwarders, roots *x509.CertPool) *forwarders {
	f := &forwarders{conditional: map[string][]*upstream{}, all: map[string]*upstream{}}
	for _, c := range list {
		var u *upstream
		// Keep the live state (pool, health) of an unchanged forwarder; the
		// previous upstream may still be in use, so it is not modified.
		if old != nil {
			if prev := old.all[c.ID]; prev != nil && sameUpstream(prev.cfg, *c) {
				u = &upstream{cfg: *c, link: prev.link}
			}
		}
		if u == nil {
			u = newUpstream(*c, roots)
		}
		f.all[c.ID] = u
		if !c.Enabled {
			continue
		}
		if c.Domain == "" {
			f.global = append(f.global, u)
		} else {
			d := dns.Fqdn(c.Domain)
			f.conditional[d] = append(f.conditional[d], u)
		}
	}
	if old != nil {
		for id, u := range old.all {
			if n := f.all[id]; n == nil || n.link != u.link {
				u.close()
			}
		}
	}
	return f
}

func sameUpstream(a, b dnsconf.Forwarder) bool {
	return a.Protocol == b.Protocol && a.Address == b.Address && a.Port == b.Port &&
		a.TLSServerName == b.TLSServerName && a.TLSVerify == b.TLSVerify && a.DoHURL == b.DoHURL
}

// pick returns the ordered upstreams for qname: the most specific
// conditional group, else the global list.
func (f *forwarders) pick(qname string) []*upstream {
	if f == nil {
		return nil
	}
	for n := strings.ToLower(dns.Fqdn(qname)); ; {
		if g := f.conditional[n]; len(g) > 0 {
			return g
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i == len(n)-1 {
			break
		}
		n = n[i+1:]
	}
	return f.global
}

// errNoForwarder is returned when nothing is configured for a name.
var errNoForwarder = errors.New("aucun redirecteur configuré")

// resolve tries each upstream in order, skipping those in back-off unless
// all of them are. Transport errors and REFUSED move to the next one.
func (f *forwarders) resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, *upstream, error) {
	ups := f.pick(q.Question[0].Name)
	if len(ups) == 0 {
		return nil, nil, errNoForwarder
	}
	now := time.Now()
	order := make([]*upstream, 0, len(ups))
	var down []*upstream
	for _, u := range ups {
		if u.available(now) {
			order = append(order, u)
		} else {
			down = append(down, u)
		}
	}
	order = append(order, down...)
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	var lastErr error
	var lastResp *dns.Msg
	var lastUp *upstream
	for _, u := range order {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		r, err := u.exchange(ctx, q)
		if err == nil && r.Rcode == dns.RcodeRefused {
			err = errors.New("le serveur a refusé la requête (REFUSED)")
		}
		u.record(err, time.Since(start))
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode == dns.RcodeServerFailure {
			lastResp, lastUp = r, u // maybe a real upstream failure: try the next one
			continue
		}
		return r, u, nil
	}
	if lastResp != nil {
		return lastResp, lastUp, nil
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, nil, lastErr
}

// TestResult is the answer of a forwarder test.
type TestResult struct {
	OK        bool     `json:"ok"`
	LatencyMs float64  `json:"latencyMs"`
	Rcode     string   `json:"rcode"`
	Answers   []string `json:"answers"`
	Error     string   `json:"error"`
}

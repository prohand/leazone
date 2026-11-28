package dnsconf

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Supported record types (SOA is managed through the zone).
var RecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS"}

// RecordData holds the type-specific fields (see api/openapi.yaml).
type RecordData struct {
	IP         string `json:"ip,omitempty"`
	Target     string `json:"target,omitempty"`
	Host       string `json:"host,omitempty"`
	Preference uint16 `json:"preference,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	Text       string `json:"text,omitempty"`
	Priority   uint16 `json:"priority,omitempty"`
	Weight     uint16 `json:"weight,omitempty"`
	Port       uint16 `json:"port,omitempty"`
}

// Record is a resource record of a zone.
type Record struct {
	ID        string     `json:"id"`
	ZoneID    string     `json:"-"`
	Name      string     `json:"name"`
	FQDN      string     `json:"fqdn"`
	Type      string     `json:"type"`
	TTL       *uint32    `json:"ttl"`
	Data      RecordData `json:"data"`
	Value     string     `json:"value"`
	Source    string     `json:"source"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// RecordInput is what a user provides.
type RecordInput struct {
	Name string     `json:"name"`
	Type string     `json:"type"`
	TTL  *uint32    `json:"ttl"`
	Data RecordData `json:"data"`
}

// normalize validates in for zone z and returns the stored name and data.
func normalize(in RecordInput, zone string) (string, RecordData, Validation) {
	errs := Validation{}
	in.Type = strings.ToUpper(strings.TrimSpace(in.Type))
	name, err := RelativeName(in.Name, zone)
	if err != nil {
		errs["name"] = err.Error()
	}
	if in.TTL != nil && *in.TTL > 2147483647 {
		errs["ttl"] = "TTL trop grand"
	}
	d := in.Data
	out := RecordData{}
	host := func(field, v string) string {
		h, err := HostTarget(v, zone)
		if err != nil {
			errs["data."+field] = err.Error()
		}
		return h
	}
	switch in.Type {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(strings.TrimSpace(d.IP))
		switch {
		case err != nil:
			errs["data.ip"] = "adresse IP invalide"
		case in.Type == "A" && !ip.Is4():
			errs["data.ip"] = "une adresse IPv4 est attendue"
		case in.Type == "AAAA" && (!ip.Is6() || ip.Is4In6()):
			errs["data.ip"] = "une adresse IPv6 est attendue"
		}
		out.IP = ip.String()
	case "CNAME", "PTR":
		out.Target = host("target", d.Target)
		if in.Type == "CNAME" && name == "@" {
			errs["name"] = "un CNAME est interdit à la racine de la zone"
		}
	case "NS":
		out.Host = host("host", d.Host)
	case "MX":
		out.Preference = d.Preference
		out.Exchange = host("exchange", d.Exchange)
	case "TXT":
		if d.Text == "" {
			errs["data.text"] = "texte obligatoire"
		} else if len(d.Text) > 4000 {
			errs["data.text"] = "4000 caractères maximum"
		}
		out.Text = d.Text
	case "SRV":
		out.Priority, out.Weight, out.Port = d.Priority, d.Weight, d.Port
		if d.Target == "." {
			out.Target = "."
		} else {
			out.Target = host("target", d.Target)
		}
		if d.Port == 0 && out.Target != "." {
			errs["data.port"] = "port obligatoire"
		}
	default:
		errs["type"] = "type non supporté (A, AAAA, CNAME, MX, TXT, SRV, PTR, NS)"
	}
	return name, out, errs
}

// ToRR builds the wire record. ttl is the effective TTL.
func ToRR(name, zone, typ string, ttl uint32, d RecordData) (dns.RR, error) {
	hdr := dns.RR_Header{Name: FQDN(name, zone), Class: dns.ClassINET, Ttl: ttl}
	switch typ {
	case "A":
		hdr.Rrtype = dns.TypeA
		ip, err := netip.ParseAddr(d.IP)
		if err != nil {
			return nil, err
		}
		b := ip.As4()
		return &dns.A{Hdr: hdr, A: b[:]}, nil
	case "AAAA":
		hdr.Rrtype = dns.TypeAAAA
		ip, err := netip.ParseAddr(d.IP)
		if err != nil {
			return nil, err
		}
		b := ip.As16()
		return &dns.AAAA{Hdr: hdr, AAAA: b[:]}, nil
	case "CNAME":
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: d.Target}, nil
	case "PTR":
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: d.Target}, nil
	case "NS":
		hdr.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: hdr, Ns: d.Host}, nil
	case "MX":
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: d.Preference, Mx: d.Exchange}, nil
	case "TXT":
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: splitTXT(d.Text)}, nil
	case "SRV":
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{Hdr: hdr, Priority: d.Priority, Weight: d.Weight, Port: d.Port, Target: d.Target}, nil
	}
	return nil, fmt.Errorf("unsupported type %s", typ)
}

// splitTXT cuts a long text into 255-byte character-strings.
func splitTXT(s string) []string {
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}

// RRValue renders the data part of a record in presentation format.
func RRValue(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

func (s *Store) fill(r *Record, zone string, zoneTTL uint32) {
	r.FQDN = FQDN(r.Name, zone)
	ttl := zoneTTL
	if r.TTL != nil {
		ttl = *r.TTL
	}
	if rr, err := ToRR(r.Name, zone, r.Type, ttl, r.Data); err == nil {
		r.Value = RRValue(rr)
	}
}

// Records lists the records of a zone sorted by name and type.
func (s *Store) Records(ctx context.Context, zoneID string) ([]*Record, error) {
	z, err := s.Zone(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	return s.queryRecords(ctx, z, `WHERE zone_id = ? ORDER BY CASE name WHEN '@' THEN '' ELSE name END, type, created_at`, zoneID)
}

func (s *Store) queryRecords(ctx context.Context, z *Zone, where string, args ...any) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, zone_id, name, type, ttl, data, source, created_at, updated_at FROM records `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Record
	for rows.Next() {
		var r Record
		var ttl sql.NullInt64
		var data string
		var c, u int64
		if err := rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &ttl, &data, &r.Source, &c, &u); err != nil {
			return nil, err
		}
		if ttl.Valid {
			v := uint32(ttl.Int64)
			r.TTL = &v
		}
		if err := json.Unmarshal([]byte(data), &r.Data); err != nil {
			return nil, err
		}
		r.CreatedAt, r.UpdatedAt = time.UnixMilli(c), time.UnixMilli(u)
		s.fill(&r, z.Name, z.TTL)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// checkConsistency enforces CNAME exclusivity and refuses exact duplicates.
func checkConsistency(ctx context.Context, tx *sql.Tx, zoneID, name, typ string, data RecordData, exceptID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, type, data FROM records WHERE zone_id = ? AND name = ? AND id != ?`, zoneID, name, exceptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	want, _ := json.Marshal(data)
	for rows.Next() {
		var id, t, d string
		if err := rows.Scan(&id, &t, &d); err != nil {
			return err
		}
		if t == "CNAME" && typ != "CNAME" || typ == "CNAME" && t != "CNAME" {
			return ErrConflict{"un CNAME ne peut pas coexister avec un autre enregistrement du même nom"}
		}
		if t == "CNAME" && typ == "CNAME" {
			return ErrConflict{"il ne peut y avoir qu'un seul CNAME pour un nom"}
		}
		if t == typ && d == string(want) {
			return ErrConflict{"cet enregistrement existe déjà"}
		}
	}
	return rows.Err()
}

// CreateRecord validates and inserts a record.
func (s *Store) CreateRecord(ctx context.Context, zoneID string, in RecordInput) (*Record, error) {
	return s.createRecord(ctx, zoneID, in, "manual")
}

func (s *Store) createRecord(ctx context.Context, zoneID string, in RecordInput, source string) (*Record, error) {
	z, err := s.Zone(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	name, data, errs := normalize(in, z.Name)
	if len(errs) > 0 {
		return nil, errs
	}
	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	id := ids.New()
	raw, _ := json.Marshal(data)
	now := s.Now().UnixMilli()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkConsistency(ctx, tx, zoneID, name, typ, data, ""); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO records(id, zone_id, name, type, ttl, data, source, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, zoneID, name, typ, ttlArg(in.TTL), string(raw), source, now, now); err != nil {
			return err
		}
		return s.touchZone(ctx, tx, zoneID)
	})
	if err != nil {
		return nil, err
	}
	return s.Record(ctx, zoneID, id)
}

func ttlArg(t *uint32) any {
	if t == nil {
		return nil
	}
	return *t
}

// Record returns one record of a zone.
func (s *Store) Record(ctx context.Context, zoneID, id string) (*Record, error) {
	z, err := s.Zone(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	list, err := s.queryRecords(ctx, z, `WHERE zone_id = ? AND id = ?`, zoneID, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, store.ErrNotFound
	}
	return list[0], nil
}

// ErrReadOnly is returned when changing a record managed by DHCP.
var ErrReadOnly = errors.New("enregistrement géré par le DHCP : modifiez le bail ou la réservation")

// UpdateRecord replaces a manual record.
func (s *Store) UpdateRecord(ctx context.Context, zoneID, id string, in RecordInput) (*Record, error) {
	old, err := s.Record(ctx, zoneID, id)
	if err != nil {
		return nil, err
	}
	if old.Source != "manual" {
		return nil, ErrReadOnly
	}
	z, _ := s.Zone(ctx, zoneID)
	name, data, errs := normalize(in, z.Name)
	if len(errs) > 0 {
		return nil, errs
	}
	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	raw, _ := json.Marshal(data)
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkConsistency(ctx, tx, zoneID, name, typ, data, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE records SET name = ?, type = ?, ttl = ?, data = ?, updated_at = ? WHERE id = ?`,
			name, typ, ttlArg(in.TTL), string(raw), s.Now().UnixMilli(), id); err != nil {
			return err
		}
		return s.touchZone(ctx, tx, zoneID)
	})
	if err != nil {
		return nil, err
	}
	return s.Record(ctx, zoneID, id)
}

// DeleteRecord removes a manual record.
func (s *Store) DeleteRecord(ctx context.Context, zoneID, id string) error {
	old, err := s.Record(ctx, zoneID, id)
	if err != nil {
		return err
	}
	if old.Source != "manual" {
		return ErrReadOnly
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM records WHERE id = ?`, id); err != nil {
			return err
		}
		return s.touchZone(ctx, tx, zoneID)
	})
}

// ImportResult summarizes a zone file import.
type ImportResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

// Import reads a BIND zone file. SOA and unsupported types are skipped,
// invalid or duplicate lines are reported but do not stop the import.
func (s *Store) Import(ctx context.Context, zoneID, content string, replace bool) (*ImportResult, error) {
	z, err := s.Zone(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	res := &ImportResult{Errors: []string{}}
	rrs, skipped, perrs := ParseZoneLenient(content, z.Name, z.TTL)
	res.Skipped += skipped
	res.Errors = append(res.Errors, perrs...)
	if len(rrs) == 0 && len(perrs) > 0 {
		return nil, Validation{"content": "fichier de zone illisible : " + perrs[0]}
	}
	var inputs []RecordInput
	for _, rr := range rrs {
		in, ok := fromRR(rr, z)
		if !ok {
			res.Skipped++
			continue
		}
		inputs = append(inputs, in)
	}
	if replace {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE zone_id = ? AND source = 'manual'`, zoneID); err != nil {
			return nil, err
		}
	}
	for _, in := range inputs {
		if _, err := s.CreateRecord(ctx, zoneID, in); err != nil {
			res.Skipped++
			if len(res.Errors) < 50 {
				res.Errors = append(res.Errors, fmt.Sprintf("%s %s : %s", in.Name, in.Type, humanErr(err)))
			}
			continue
		}
		res.Imported++
	}
	return res, nil
}

// ParseZoneLenient parses a zone file. When the strict parser fails (for
// example on record types other servers invent), it falls back to a line by
// line parse and skips the lines it does not understand.
func ParseZoneLenient(content, zone string, ttl uint32) ([]dns.RR, int, []string) {
	origin := dns.Fqdn(zone)
	zp := dns.NewZoneParser(strings.NewReader(content), origin, "import")
	zp.SetDefaultTTL(ttl)
	var out []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		out = append(out, rr)
	}
	if zp.Err() == nil {
		return out, 0, nil
	}
	out = nil
	skipped := 0
	var errs []string
	owner := origin
	for i, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if c := strings.IndexByte(t, ';'); c >= 0 && !strings.Contains(t[:c], "\"") {
			t = strings.TrimSpace(t[:c])
		}
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "$ORIGIN") {
			if f := strings.Fields(t); len(f) == 2 {
				origin = dns.Fqdn(f[1])
			}
			continue
		}
		if strings.HasPrefix(t, "$TTL") {
			if f := strings.Fields(t); len(f) == 2 {
				var v uint32
				if _, err := fmt.Sscan(f[1], &v); err == nil {
					ttl = v
				}
			}
			continue
		}
		if strings.HasPrefix(t, "$") || strings.ContainsAny(t, "()") {
			skipped++
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			t = owner + " " + t // owner omitted: same as the previous line
		} else {
			owner = strings.Fields(t)[0]
		}
		rr, err := parseOneRR(t, origin, ttl)
		if err != nil || rr == nil {
			skipped++
			if len(errs) < 20 {
				errs = append(errs, fmt.Sprintf("ligne %d ignorée : %s", i+1, t))
			}
			continue
		}
		out = append(out, rr)
	}
	return out, skipped, errs
}

// parseOneRR parses a single record line. Unlike dns.NewRR, it never follows
// $INCLUDE (which would read files of the server): the import content comes
// from the user.
func parseOneRR(line, origin string, ttl uint32) (dns.RR, error) {
	zp := dns.NewZoneParser(strings.NewReader(line+"\n"), origin, "import")
	zp.SetDefaultTTL(ttl)
	zp.SetIncludeAllowed(false)
	rr, _ := zp.Next()
	return rr, zp.Err()
}

func humanErr(err error) string {
	var v Validation
	if errors.As(err, &v) {
		var parts []string
		for _, m := range v {
			parts = append(parts, m)
		}
		return strings.Join(parts, ", ")
	}
	return err.Error()
}

// fromRR converts a parsed record into an input; ok=false for skipped types.
func fromRR(rr dns.RR, z *Zone) (RecordInput, bool) {
	h := rr.Header()
	ttl := h.Ttl
	in := RecordInput{Name: h.Name, TTL: &ttl}
	if ttl == z.TTL {
		in.TTL = nil
	}
	switch v := rr.(type) {
	case *dns.A:
		in.Type, in.Data.IP = "A", v.A.String()
	case *dns.AAAA:
		in.Type, in.Data.IP = "AAAA", v.AAAA.String()
	case *dns.CNAME:
		in.Type, in.Data.Target = "CNAME", v.Target
	case *dns.PTR:
		in.Type, in.Data.Target = "PTR", v.Ptr
	case *dns.NS:
		in.Type, in.Data.Host = "NS", v.Ns
	case *dns.MX:
		in.Type, in.Data.Preference, in.Data.Exchange = "MX", v.Preference, v.Mx
	case *dns.TXT:
		in.Type, in.Data.Text = "TXT", strings.Join(v.Txt, "")
	case *dns.SRV:
		in.Type = "SRV"
		in.Data.Priority, in.Data.Weight, in.Data.Port, in.Data.Target = v.Priority, v.Weight, v.Port, v.Target
	default:
		return in, false
	}
	return in, true
}

// Export renders a zone in BIND format.
func (s *Store) Export(ctx context.Context, zoneID string) (string, error) {
	z, err := s.Zone(ctx, zoneID)
	if err != nil {
		return "", err
	}
	recs, err := s.Records(ctx, zoneID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; Zone %s exportée par Leazone le %s\n$ORIGIN %s\n$TTL %d\n", z.Name,
		s.Now().UTC().Format(time.RFC3339), dns.Fqdn(z.Name), z.TTL)
	b.WriteString(SOARecord(z).String() + "\n")
	for _, r := range recs {
		ttl := z.TTL
		if r.TTL != nil {
			ttl = *r.TTL
		}
		rr, err := ToRR(r.Name, z.Name, r.Type, ttl, r.Data)
		if err != nil {
			continue
		}
		b.WriteString(rr.String() + "\n")
	}
	return b.String(), nil
}

// SOARecord builds the SOA of a zone.
func SOARecord(z *Zone) *dns.SOA {
	// RNAME: the "@" becomes a dot, dots of the local part are escaped.
	local, domain, _ := strings.Cut(z.SOA.AdminEmail, "@")
	mbox := strings.ReplaceAll(local, ".", `\.`) + "." + domain
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(z.Name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTL},
		Ns:      z.SOA.PrimaryNS,
		Mbox:    dns.Fqdn(mbox),
		Serial:  z.Serial,
		Refresh: z.SOA.Refresh,
		Retry:   z.SOA.Retry,
		Expire:  z.SOA.Expire,
		Minttl:  z.SOA.Minimum,
	}
}

// AllRecords returns every record grouped by zone id (used by the DNS engine).
func (s *Store) AllRecords(ctx context.Context) (map[string][]*Record, error) {
	zones, err := s.Zones(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]*Record{}
	for _, z := range zones {
		recs, err := s.queryRecords(ctx, z, `WHERE zone_id = ?`, z.ID)
		if err != nil {
			return nil, err
		}
		out[z.ID] = recs
	}
	return out, nil
}

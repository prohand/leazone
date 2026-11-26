package blocking

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseFormats(t *testing.T) {
	hosts := `# StevenBlack
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com tracker.example.net # comment
::1 ip6-localhost
bare.example.org
`
	p, _ := Parse(strings.NewReader(hosts), FormatAuto)
	if strings.Join(p.Deny, ",") != "ads.example.com,tracker.example.net,bare.example.org" {
		t.Fatalf("hosts: %v", p.Deny)
	}
	adb := `! Title: OISD
[Adblock Plus]
||doubleclick.net^
||metrics.example.com^$important
@@||good.doubleclick.net^
||example.com/path^
||example.org^$script
example.info
`
	p, _ = Parse(strings.NewReader(adb), FormatAdblock)
	if strings.Join(p.Deny, ",") != "doubleclick.net,metrics.example.com,example.info" || strings.Join(p.Allow, ",") != "good.doubleclick.net" {
		t.Fatalf("adblock: %v / %v", p.Deny, p.Allow)
	}
	p, _ = Parse(strings.NewReader("# list\nA.Example.COM.\n*.wild.example\nnot a domain\n"), FormatDomains)
	if strings.Join(p.Deny, ",") != "a.example.com,wild.example" {
		t.Fatalf("domains: %v", p.Deny)
	}
}

func testEngine() *Engine {
	e := NewEngine()
	e.Load(Config{
		Enabled:  true,
		Settings: DefaultSettings(),
		Lists: []NamedList{
			{Name: "Pubs", Parsed: Parsed{Deny: []string{"ads.example.com", "doubleclick.net"}, Allow: []string{"good.doubleclick.net"}}},
			{Name: "Traqueurs", Parsed: Parsed{Deny: []string{"tracker.example.net", "ads.example.com"}}},
		},
		Rules: []*Rule{
			{Domain: "evil.example", Kind: "deny"},
			{Domain: "cdn.ads.example.com", Kind: "allow"},
		},
		Policies: []*Policy{
			{TargetKind: "network", Target: "192.168.30.0/24", Enabled: false},
			{TargetKind: "network", Target: "192.168.30.7/32", Enabled: true},
			{TargetKind: "vlan", Target: "40", Enabled: false},
			{TargetKind: "interface", Target: "eno2", Enabled: false},
		},
	})
	e.SetLocals(map[netip.Addr]IfInfo{
		netip.MustParseAddr("192.168.40.1"): {Name: "eno1.40", VLAN: 40},
		netip.MustParseAddr("10.0.0.1"):     {Name: "eno2"},
	})
	return e
}

func TestDecide(t *testing.T) {
	e := testEngine()
	cli, lan := netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("192.168.1.1")
	for _, c := range []struct {
		name    string
		blocked bool
		reason  string
	}{
		{"ads.example.com.", true, "liste « Pubs »"},
		{"x.y.ADS.example.com", true, "liste « Pubs »"}, // sub-domains too, case-insensitive
		{"cdn.ads.example.com", false, "liste blanche"}, // whitelist wins
		{"a.cdn.ads.example.com", false, "liste blanche"},
		{"good.doubleclick.net", false, "exception de la liste « Pubs »"},
		{"tracker.example.net", true, "liste « Traqueurs »"},
		{"evil.example", true, "liste noire"},
		{"example.com", false, ""},
	} {
		d, _ := e.Explain(c.name, netip.Addr{})
		if d.Blocked != c.blocked || d.Reason != c.reason {
			t.Errorf("%s: %+v", c.name, d)
		}
		if b, _ := e.Filter(c.name, cli, lan, true); b != c.blocked {
			t.Errorf("filter %s: %v", c.name, b)
		}
	}
	// Policies: the most specific network wins, then VLAN, then interface.
	if b, _ := e.Filter("ads.example.com", netip.MustParseAddr("192.168.30.9"), lan, true); b {
		t.Error("network policy off")
	}
	if b, _ := e.Filter("ads.example.com", netip.MustParseAddr("192.168.30.7"), lan, true); !b {
		t.Error("/32 policy on")
	}
	if b, _ := e.Filter("ads.example.com", netip.MustParseAddr("192.168.40.9"), netip.MustParseAddr("192.168.40.1"), true); b {
		t.Error("VLAN 40 off")
	}
	if b, _ := e.Filter("ads.example.com", netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.1"), true); b {
		t.Error("interface eno2 off")
	}
	st := e.Status(10)
	if st.Domains != 4 || st.Lists != 2 || st.Blocked == 0 || st.Top[0].Domain != "ads.example.com" {
		t.Fatalf("status: %+v", st)
	}
}

func TestPauseAndDisabled(t *testing.T) {
	e := testEngine()
	now := time.Now()
	e.Now = func() time.Time { return now }
	cli := netip.MustParseAddr("192.168.1.5")
	e.setPause(now.Add(5 * time.Minute))
	if b, _ := e.Filter("ads.example.com", cli, netip.Addr{}, true); b {
		t.Fatal("paused")
	}
	now = now.Add(6 * time.Minute)
	if b, _ := e.Filter("ads.example.com", cli, netip.Addr{}, true); !b {
		t.Fatal("pause over")
	}
	e.Load(Config{Enabled: false, Settings: DefaultSettings()})
	if b, _ := e.Filter("ads.example.com", cli, netip.Addr{}, true); b {
		t.Fatal("module off")
	}
}

func TestNullIPMode(t *testing.T) {
	e := NewEngine()
	st := DefaultSettings()
	st.ResponseMode = ModeNullIP
	e.Load(Config{Enabled: true, Settings: st, Rules: []*Rule{{Domain: "ads.example", Kind: "deny"}}})
	b, null := e.Filter("ads.example", netip.MustParseAddr("10.0.0.2"), netip.Addr{}, true)
	if !b || !null {
		t.Fatal(b, null)
	}
}

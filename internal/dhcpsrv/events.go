package dhcpsrv

import (
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Event is a DHCP event for the logs.
type Event struct {
	Time      time.Time
	Kind      string // offer, ack, nak, release, decline, expire, ignored
	MAC       string
	IP        string
	Hostname  string
	ScopeID   string
	ScopeName string
	Interface string
	Relay     string
	Detail    string
}

// ignoredEvery is the minimum interval between two "ignored" events of a
// client (entries older than that are purged by Sweep).
const ignoredEvery = time.Minute

// Version changes each time a lease changes (live views).
func (e *Engine) Version() uint64 { return e.version.Load() }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// emit reports what Handle did with a packet.
func (e *Engine) emit(p Packet, r *Reply) {
	m := p.Msg
	if m.OpCode != dhcpv4.OpcodeBootRequest {
		return
	}
	mt := m.MessageType()
	ev := Event{Time: e.Now(), MAC: m.ClientHWAddr.String(), Hostname: m.HostName()}
	if gi := ipOf(m.GatewayIPAddr); gi.IsValid() && !gi.IsUnspecified() {
		ev.Relay = gi.String()
	}
	e.mu.Lock()
	s, _ := e.selectScope(p)
	if it, ok := e.ifaces[p.IfIndex]; ok {
		ev.Interface = it.Name
	}
	e.mu.Unlock()
	if s != nil {
		ev.ScopeID, ev.ScopeName = s.ID, s.Name
	}
	switch {
	case r != nil:
		ev.IP = ipOf(r.Msg.YourIPAddr).String()
		switch r.Msg.MessageType() {
		case dhcpv4.MessageTypeOffer:
			ev.Kind = "offer"
		case dhcpv4.MessageTypeAck:
			ev.Kind = "ack"
		case dhcpv4.MessageTypeNak:
			ev.Kind = "nak"
			want := ipOf(m.RequestedIPAddress())
			if !want.IsValid() || want.IsUnspecified() {
				want = ipOf(m.ClientIPAddr)
			}
			ev.IP = want.String()
			ev.Detail = "adresse demandée refusée"
			if msg := r.Msg.Message(); msg != "" {
				ev.Detail = msg
			}
		default:
			return
		}
	case mt == dhcpv4.MessageTypeRelease:
		ev.Kind, ev.IP = "release", ipOf(m.ClientIPAddr).String()
	case mt == dhcpv4.MessageTypeDecline:
		ev.Kind, ev.IP = "decline", ipOf(m.RequestedIPAddress()).String()
		ev.Detail = "le client a détecté un conflit d'adresse"
	case s == nil && (mt == dhcpv4.MessageTypeDiscover || mt == dhcpv4.MessageTypeRequest):
		// Explain why a client gets nothing, at most once a minute per MAC.
		if last, ok := e.ignored.Load(ev.MAC); ok && ev.Time.Sub(last.(time.Time)) < ignoredEvery {
			return
		}
		e.ignored.Store(ev.MAC, ev.Time)
		ev.Kind = "ignored"
		if ev.Relay != "" {
			ev.Detail = "aucune étendue pour le relais " + ev.Relay
		} else {
			ev.Detail = "aucune étendue sur cette interface (ou DHCP désactivé)"
		}
	default:
		return // not ours (other node in HA) or nothing to report
	}
	if ev.IP == "invalid IP" {
		ev.IP = ""
	}
	e.OnEvent(ev)
}

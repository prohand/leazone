//go:build linux

// Package caps handles Linux capabilities of the non-root process.
//
// The binary in the image carries file capabilities in the *permitted* set
// only ("+p"). With "+ep" the container would refuse to start when one of the
// listed capabilities is not granted (for example NET_ADMIN when no VIP is
// used). At startup we raise into the effective set whatever the container
// actually granted, on every OS thread.
package caps

import (
	"fmt"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Wanted lists the capabilities Leazone can use.
var Wanted = []cap.Value{cap.NET_BIND_SERVICE, cap.NET_RAW, cap.NET_ADMIN}

// Status tells which wanted capabilities are effective.
type Status map[string]bool

// String renders e.g. "NET_BIND_SERVICE=yes NET_RAW=yes NET_ADMIN=no".
func (s Status) String() string {
	var parts []string
	for _, v := range Wanted {
		n := name(v)
		yes := "no"
		if s[n] {
			yes = "yes"
		}
		parts = append(parts, n+"="+yes)
	}
	return strings.Join(parts, " ")
}

// Has reports whether a capability (e.g. "NET_ADMIN") is effective.
func (s Status) Has(name string) bool { return s[name] }

// Raise moves permitted wanted capabilities into the effective set and drops
// everything else, then returns the resulting status.
func Raise() (Status, error) {
	cur := cap.GetProc()
	next := cap.NewSet()
	for _, v := range Wanted {
		on, err := cur.GetFlag(cap.Permitted, v)
		if err != nil {
			return nil, err
		}
		if on {
			if err := next.SetFlag(cap.Permitted, true, v); err != nil {
				return nil, err
			}
			if err := next.SetFlag(cap.Effective, true, v); err != nil {
				return nil, err
			}
		}
	}
	if err := next.SetProc(); err != nil {
		return nil, fmt.Errorf("set capabilities: %w", err)
	}
	return Current(), nil
}

// Current reports the effective wanted capabilities.
func Current() Status {
	st := Status{}
	c := cap.GetProc()
	for _, v := range Wanted {
		on, _ := c.GetFlag(cap.Effective, v)
		st[name(v)] = on
	}
	return st
}

// SetFile writes "+p" file capabilities on path (used at image build time).
func SetFile(path string) error {
	c := cap.NewSet()
	if err := c.SetFlag(cap.Permitted, true, Wanted...); err != nil {
		return err
	}
	return c.SetFile(path)
}

func name(v cap.Value) string { return strings.TrimPrefix(strings.ToUpper(v.String()), "CAP_") }

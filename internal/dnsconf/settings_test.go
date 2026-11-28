package dnsconf

import (
	"slices"
	"testing"
)

func TestSettingsRefuseUnspecifiedListen(t *testing.T) {
	for _, a := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		st := DefaultSettings()
		st.ExtraListenAddresses = []string{a}
		if err := st.Validate(); err == nil {
			t.Errorf("%s accepted as extra listen address", a)
		}
	}
	st := DefaultSettings()
	st.ExtraListenAddresses = []string{"192.168.1.2", "fd00::2"}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultRecursionNoCGNAT(t *testing.T) {
	if slices.Contains(DefaultSettings().RecursionNetworks, "100.64.0.0/10") {
		t.Fatal("100.64.0.0/10 in the default recursion networks")
	}
}

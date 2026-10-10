package dialer

import (
	"net/netip"
	"testing"
)

func TestIsPhysicalGlobalIPv6(t *testing.T) {
	for addr, want := range map[string]bool{
		"2606:4700::1":     true,
		"64:ff9b::808:808": true,
		"fd00::1":          false,
		"fe80::1":          false,
		"::ffff:1.1.1.1":   false,
		"1.1.1.1":          false,
	} {
		if got := IsPhysicalGlobalIPv6(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsPhysicalGlobalIPv6(%s) = %v, want %v", addr, got, want)
		}
	}
}

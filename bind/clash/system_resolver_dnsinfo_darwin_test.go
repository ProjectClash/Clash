//go:build darwin && cgo

package clash

import (
	"net"
	"net/netip"
	"testing"
)

func TestDNSInfoReaderAnswersForTheHostsOwnInterface(t *testing.T) {
	if !dnsInfoAvailable() {
		t.Skip("dns_configuration_copy is not exported here")
	}
	unscoped := physicalResolversForInterface(0)
	if len(unscoped) == 0 {
		t.Skip("the host lists no default resolver")
	}
	for _, server := range unscoped {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			t.Fatalf("%q is not host:port: %v", server, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("%q is not an IP: %v", server, err)
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.Zone() != "" {
			t.Fatalf("%q must not be offered as a physical resolver", server)
		}
		if port == "0" || port == "" {
			t.Fatalf("%q has no port", server)
		}
		if _, err := parseSystemDNSServerLines(server); err != nil {
			t.Fatalf("%q is not a line SystemDNSServerLines accepts: %v", server, err)
		}
	}

	if got := physicalResolversForInterface(0x7fff0000); len(got) == 0 {
		t.Fatal("an unknown interface index must fall back to the default resolver")
	}

	_ = dnsInfoChanged()
}

func TestDNSInfoLinesAlwaysParse(t *testing.T) {
	if !dnsInfoAvailable() {
		t.Skip("dns_configuration_copy is not exported here")
	}
	seen := 0
	for index := int32(0); index < 32; index++ {
		for _, server := range physicalResolversForInterface(index) {
			if _, err := parseSystemDNSServerLines(server); err != nil {
				t.Fatalf("interface %d offered %q, which Setup refuses: %v", index, server, err)
			}
			seen++
		}
	}
	t.Logf("read %d resolver line(s) across the first 32 interface indexes", seen)
}

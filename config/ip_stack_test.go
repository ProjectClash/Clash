package config

import "testing"

func TestExplicitTunIPv6CapabilitySurvivesQueryDisabled(t *testing.T) {
	raw := DefaultRawConfig()
	raw.IPv6 = false
	raw.PreserveTunIPv6 = true
	before := append([]byte(nil), []byte(raw.Tun.Inet6Address[0].String())...)
	parseIPV6(raw)
	if len(raw.Tun.Inet6Address) != 1 || raw.Tun.Inet6Address[0].String() != string(before) {
		t.Fatal("explicit TUN offer removed by query policy")
	}
	raw.PreserveTunIPv6 = false
	parseIPV6(raw)
	if len(raw.Tun.Inet6Address) != 0 {
		t.Fatal("legacy IPv6:false behavior changed")
	}
}
func TestDocumentCannotSetPlatformIPv6Capability(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("ipv6: false\nPreserveTunIPv6: true\npreserve-tun-ipv6: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if raw.PreserveTunIPv6 {
		t.Fatal("document enabled platform-only capability")
	}
}

package clash

import (
	"testing"
)

func TestIPv6DisabledLeavesNoTunV6AddressForTheTunnelToClaim(t *testing.T) {
	const document = `
ipv6: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(mihomo.General.Tun.Inet6Address) != 0 {
		t.Fatalf("fixture is wrong, not the code: mihomo kept %v with ipv6 false", mihomo.General.Tun.Inet6Address)
	}

	finalizeConfigForIOS(ours, true)

	if len(ours.General.Tun.Inet6Address) != 0 {
		t.Errorf("tun.inet6-address = %v with ipv6 false; mihomo clears it, and a non-empty value "+
			"makes the extension install a ::/0 default route the core will not serve",
			ours.General.Tun.Inet6Address)
	}
}

func TestParsedConfigAlwaysCarriesATunV4AddressWithoutOurRefill(t *testing.T) {
	for name, document := range map[string]string{
		"no dns block": `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
		"custom fake-ip-range": `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.19.0.1/16
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
	} {
		t.Run(name, func(t *testing.T) {
			mihomo, ours := parseBoth(t, document)
			if len(mihomo.General.Tun.Inet4Address) == 0 {
				t.Fatal("upstream left tun.inet4-address empty; the refill would not be dead code after all")
			}
			finalizeConfigForIOS(ours, true)
			if len(ours.General.Tun.Inet4Address) == 0 {
				t.Fatal("tun.inet4-address is empty after finalize")
			}
			if ours.General.Tun.Inet4Address[0] != mihomo.General.Tun.Inet4Address[0] {
				t.Errorf("tun.inet4-address: mihomo %v, ours %v", mihomo.General.Tun.Inet4Address[0], ours.General.Tun.Inet4Address[0])
			}
		})
	}
}

func TestIPv6EnabledKeepsExactlyWhatUpstreamDecided(t *testing.T) {
	const document = `
ipv6: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	if len(ours.General.Tun.Inet6Address) != len(mihomo.General.Tun.Inet6Address) {
		t.Errorf("tun.inet6-address: mihomo %v, ours %v -- with ipv6 true the decision is still upstream's, "+
			"and it also requires verifyIP6() to find a global-unicast v6 address on this host",
			mihomo.General.Tun.Inet6Address, ours.General.Tun.Inet6Address)
	}
}

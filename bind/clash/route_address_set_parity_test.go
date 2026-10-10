package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestRouteAddressSetLoadsHereBecauseItLoadsUpstream(t *testing.T) {
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		t.Run(field, func(t *testing.T) {
			document := `
tun:
  enable: true
  ` + field + `:
    - geoip-cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
			if _, err := config.Parse([]byte(document)); err != nil {
				t.Fatalf("fixture is wrong, not the code: mihomo rejected it too: %v", err)
			}
			if _, err := parseConfigForIOS(document, true); err != nil {
				t.Errorf("this core refuses a configuration mihomo runs: %v", err)
			}
		})
	}
}

func TestRouteAddressSetIsReportedAsInertRatherThanSilentlyDropped(t *testing.T) {
	const document = `
tun:
  enable: true
  route-address-set:
    - geoip-cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field != "tun.route-address-set" {
			continue
		}
		if deviation.Category != deviationUnavailable {
			t.Errorf("category = %q, want %q: no Apple platform has the nftables set this "+
				"configures", deviation.Category, deviationUnavailable)
		}
		if !strings.Contains(strings.ToLower(deviation.Source), "linux") &&
			!strings.Contains(strings.ToLower(deviation.Source), "nftables") {
			t.Errorf("source = %q, want it to name the Linux/nftables facility this needs", deviation.Source)
		}
		return
	}
	t.Error("tun.route-address-set is accepted and ignored with nothing said; the reader has " +
		"no way to learn the line is inert")
}

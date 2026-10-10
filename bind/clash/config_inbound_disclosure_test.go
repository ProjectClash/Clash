package clash

import (
	"strings"
	"testing"
)

func deviationFor(t *testing.T, deviations []configDeviation, field string) configDeviation {
	t.Helper()
	for _, deviation := range deviations {
		if deviation.Field == field {
			return deviation
		}
	}
	t.Fatalf("no deviation reported for %q", field)
	return configDeviation{}
}

func TestInboundServerFieldsAreNoLongerReportedAsStripped(t *testing.T) {
	merged := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"ss-config: \"aes-128-gcm:password@:8388\"\n" +
		"listeners:\n  - name: extra\n    type: mixed\n    port: 8080\n" +
		"tunnels:\n  - tcp/udp,127.0.0.1:6553,8.8.8.8:53,DIRECT\n" +
		"rules:\n  - MATCH,DIRECT\n"

	deviations, err := collectConfigDeviations(merged, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, field := range []string{"listeners", "tunnels", "ss-config", "vmess-config", "tuic-server"} {
		for _, deviation := range deviations {
			if deviation.Field == field {
				t.Fatalf("%s is still in the deviation table as %q: %q — the core honours it, so any category here states something untrue",
					field, deviation.Category, deviation.Effective)
			}
		}
	}
	_ = deviationFor
}

func TestConfiguredInboundListenersAreDisclosedAsExposure(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
dns:
  enable: true
  nameserver: [8.8.8.8]
listeners:
  - name: extra
    type: mixed
    port: 8080
rules:
  - MATCH,DIRECT
`)
	notices := unauthenticatedLANListenerNotices(raw)
	joined := strings.Join(notices, "\n")
	if !strings.Contains(joined, "listeners") {
		t.Fatalf("a configured listener with no authentication produced no notice:\n%s", joined)
	}
}

func TestSkipAuthPrefixesDoNotSilenceTheExposureNotice(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
allow-lan: true
mixed-port: 7890
authentication:
  - "user:pass"
skip-auth-prefixes:
  - 0.0.0.0/0
  - ::/0
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`)
	notices := unauthenticatedLANListenerNotices(raw)
	if len(notices) == 0 {
		t.Fatal("authentication that every source is allowed to skip is not authentication; the notice must still fire")
	}
}

func TestGenuineAuthenticationStaysQuiet(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
allow-lan: true
mixed-port: 7890
authentication:
  - "user:pass"
skip-auth-prefixes:
  - 127.0.0.1/32
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`)
	if notices := unauthenticatedLANListenerNotices(raw); len(notices) != 0 {
		t.Fatalf("a properly authenticated listener produced a warning: %v", notices)
	}
}

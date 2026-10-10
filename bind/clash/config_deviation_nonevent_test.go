package clash

import (
	"encoding/json"
	"testing"
)

func deviationFields(t *testing.T, yaml, profile string) map[string]map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(yaml, profile)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var r struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &r); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, d := range r.Deviations {
		out[d["field"].(string)] = d
	}
	return out
}

func TestGeodataLoaderIsReportedOnlyWhereItIsForced(t *testing.T) {
	cfg := "geodata-loader: standard\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	for profile, want := range map[string]bool{
		RuntimeProfileIOSPacketTunnel:   true,
		RuntimeProfileTVOSPacketTunnel:  true,
		RuntimeProfileMacOSPacketTunnel: false,
		RuntimeProfileMacOSApplication:  false,
	} {
		_, got := deviationFields(t, cfg, profile)["geodata-loader"]
		if got != want {
			t.Errorf("%s: geodata-loader reported=%v, want %v (forced only under memoryConservativeGeodata)", profile, got, want)
		}
	}
}

func TestAWrittenValueEqualToTheForcedOneIsNotReported(t *testing.T) {
	cases := map[string][2]string{
		"dns.enable":                  {"dns:\n  enable: true\n", "dns:\n  enable: false\n"},
		"tun.enable":                  {"tun:\n  enable: true\n", "tun:\n  enable: false\n"},
		"tun.auto-route":              {"tun:\n  enable: true\n  auto-route: false\n", "tun:\n  enable: true\n  auto-route: true\n"},
		"tun.gso":                     {"tun:\n  enable: true\n  gso: false\n", "tun:\n  enable: true\n  gso: true\n"},
		"tun.disable-icmp-forwarding": {"tun:\n  enable: true\n  disable-icmp-forwarding: true\n", "tun:\n  enable: true\n  disable-icmp-forwarding: false\n"},
		"geo-auto-update":             {"geo-auto-update: false\n", "geo-auto-update: true\n"},
	}
	tail := "proxies: []\nrules:\n  - MATCH,DIRECT\n"
	for field, pair := range cases {
		if _, reported := deviationFields(t, pair[0]+tail, RuntimeProfileIOSPacketTunnel)[field]; reported {
			t.Errorf("%s: written equal to the forced value, yet reported -- the core changed X to X", field)
		}
		if _, reported := deviationFields(t, pair[1]+tail, RuntimeProfileIOSPacketTunnel)[field]; !reported {
			t.Errorf("%s: written DIFFERENT from the forced value, yet not reported -- that one is a real deviation", field)
		}
	}
}

func TestAnUnwrittenForcedFieldWithAMovedDefaultIsStillReported(t *testing.T) {
	rows := deviationFields(t, "proxies: []\nrules:\n  - MATCH,DIRECT\n", RuntimeProfileIOSPacketTunnel)
	for _, field := range []string{"find-process-mode", "dns.enable", "unified-delay", "profile.store-fake-ip"} {
		row, ok := rows[field]
		if !ok {
			t.Errorf("%s: not written and not reported; the changed default is exactly what to report", field)
			continue
		}
		if given, _ := row["given"].(string); given == "" || given[:7] != "not set" {
			t.Errorf("%s: unwritten row's given = %q, want \"not set (core default: …)\"", field, given)
		}
	}
}

func TestEveryForcedRuleNamesItsValueOrIsExempt(t *testing.T) {
	exempt := map[string]string{
		"tun.mtu": "chosen at startup, not a constant",
		"proxies": "a list scan; the placeholder stands in for a whole node, not a scalar the reader could have written",
	}
	for _, rule := range deviationRules {
		if rule.category != deviationForced {
			continue
		}
		if rule.forcedValue == "" {
			if _, ok := exempt[rule.field]; !ok {
				t.Errorf("%s: forced, no forcedValue, not exempt -- a written value equal to the force would be reported as a change", rule.field)
			}
		}
	}
}

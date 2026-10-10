package clash

import (
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestUIDRemovalIsReportedFromTheRulesList(t *testing.T) {
	const document = "rules:\n" +
		"  - DOMAIN,a.example,DIRECT\n" +
		"  - UID,501,DIRECT\n" +
		"  - AND,((UID,501),(NETWORK,udp)),REJECT\n" +
		"  - MATCH,DIRECT\n" +
		"sub-rules:\n" +
		"  s1:\n" +
		"    - UID,0,DIRECT\n" +
		"proxies: []\n"
	for _, seat := range registryProfiles {
		policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
		rows, err := collectConfigDeviations(document, policy)
		if err != nil {
			t.Fatalf("%s: %v", seat.name, err)
		}
		var row *configDeviation
		for i := range rows {
			if rows[i].Field == "rules" && rows[i].RuleKind == "UID" {
				row = &rows[i]
			}
		}
		expected := policy.networkExtension && !policy.processMetadata().resolves("UID")
		switch {
		case expected && row == nil:
			t.Errorf("%s: three UID-bearing rules (two plain, one logic, one in sub-rules) and no rules/UID row: %v", seat.name, fieldsOf(rows))
		case !expected && row != nil:
			t.Errorf("%s: UID is constructible here, yet the report says it was removed: %+v", seat.name, *row)
		case expected:
			if row.Given != "3 rule(s), first at rules[1]" || !row.Written || row.Category != deviationUnavailable {
				t.Errorf("%s: row does not describe the removal as it happened: %+v", seat.name, *row)
			}
			if row.Effective == "" || row.Reason == "" || row.Source == "" {
				t.Errorf("%s: the synthesized row lost the registration's sentences: %+v", seat.name, *row)
			}
		}
	}

	rows, err := collectConfigDeviations("rules:\n  - MATCH,DIRECT\nproxies: []\n", runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.RuleKind == "UID" {
			t.Fatalf("a file with no UID rule got a UID removal row: %+v", row)
		}
	}
}

func TestEveryRegisteredRuleIsIssuableOnSomeDocument(t *testing.T) {
	written := issuanceProbeDocument(t)
	const unwritten = "proxies: []\nrules:\n  - MATCH,DIRECT\n"
	restoreLAN, restoreAllNetworks := !allowLanForcedOff.Load(), includeAllNetworksRequested.Load()
	t.Cleanup(func() {
		allowLanForcedOff.Store(!(restoreLAN))
		includeAllNetworksRequested.Store(restoreAllNetworks)
	})
	for _, rule := range deviationRules {
		allowLanForcedOff.Store(!(restoreLAN && rule.condition != deviationConditionLANSharingOff))
		includeAllNetworksRequested.Store(restoreAllNetworks || rule.condition == deviationConditionIncludeAllNetworks)
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			if rule.applies != nil && !rule.applies(policy) {
				continue
			}
			issued := false
			for _, document := range []string{written, unwritten} {
				rows, err := collectConfigDeviations(document, policy)
				if err != nil {
					t.Fatalf("%s: %v", seat.name, err)
				}
				if reportsRegistration(rows, rule) {
					issued = true
					break
				}
			}
			if !issued {
				t.Errorf("%s is registered for %s but neither the everything-written document nor the "+
					"empty one makes it issue a row -- registered and unreachable, which is the duplicate-deviation "+
					"shape; either the registration's field is not an address the walk can find, or "+
					"its issue condition can never be met", rule.field, seat.name)
			}
		}
	}
}

func reportsRegistration(rows []configDeviation, rule deviationRule) bool {
	for _, row := range rows {
		if row.Field == rule.field && (rule.ruleKind == "" || row.RuleKind == rule.ruleKind) {
			return true
		}
	}
	return false
}

func issuanceProbeDocument(t *testing.T) string {
	t.Helper()
	root := map[string]any{"proxies": []any{map[string]any{
		"name": "walled-easytier", "type": "easytier", "network-name": "probe",
		"peers": []any{"tcp://203.0.113.10:11010"},
	}}}
	rules := []any{"UID,501,DIRECT", "MATCH,DIRECT"}
	for _, rule := range deviationRules {
		if rule.ruleScan || rule.defaultOnly || strings.Contains(rule.field, " ") {
			continue
		}
		var value any
		switch {
		case rule.field == "tun.dns-hijack":
			value = []any{"198.51.100.1:53"}
		case len(rule.forcedFrom) > 0:
			value = rule.forcedFrom[0]
		case rule.forcedValue == "true":
			value = false
		case rule.forcedValue == "false":
			value = true
		case rule.forcedValue != "":
			value = "probe-" + rule.forcedValue
		default:
			value = "probe"
		}
		setYAMLPath(root, rule.field, value)
	}
	root["rules"] = rules
	out, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func setYAMLPath(root map[string]any, path string, value any) {
	segments := strings.Split(path, ".")
	node := root
	for _, segment := range segments[:len(segments)-1] {
		child, ok := node[segment].(map[string]any)
		if !ok {
			child = map[string]any{}
			node[segment] = child
		}
		node = child
	}
	node[segments[len(segments)-1]] = value
}

var _ = fmt.Sprintf

func TestRulesRowsCarryTheirKindAsData(t *testing.T) {
	const document = "rules:\n  - PROCESS-NAME,curl,DIRECT\n  - PROCESS-NAME-REGEX,.*,REJECT\n  - UID,501,DIRECT\n  - MATCH,DIRECT\nproxies: []\n"
	rows, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"PROCESS-NAME": true, "PROCESS-NAME-REGEX": true, "UID": true}
	seen := map[string]bool{}
	for _, row := range rows {
		isRulesRow := row.Field == "rules" || strings.HasPrefix(row.Field, "rules[")
		switch {
		case isRulesRow && row.RuleKind == "":
			t.Errorf("rules row without a ruleKind: %+v", row)
		case isRulesRow:
			seen[row.RuleKind] = true
			if row.RuleKind == "PROCESS-NAME-REGEX" && row.Field != "rules[1]" {
				t.Errorf("the matches-everything row keeps its indexed address: %+v", row)
			}
		case row.RuleKind != "":
			t.Errorf("%s is a setting row but carries ruleKind %q", row.Field, row.RuleKind)
		}
	}
	for kind := range want {
		if !seen[kind] {
			t.Errorf("no rules row for %s: %v", kind, fieldsOf(rows))
		}
	}
}

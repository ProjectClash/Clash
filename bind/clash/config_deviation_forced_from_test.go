package clash

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAForcedRuleReportsOnlyTheValuesItReplaces(t *testing.T) {
	restore := allowLanForcedOff.Load()
	allowLanForcedOff.Store(true)
	t.Cleanup(func() { allowLanForcedOff.Store(restore) })
	rules := slices.Clone(deviationRules)
	index := slices.IndexFunc(rules, func(rule deviationRule) bool { return rule.field == "tun.stack" })
	if index < 0 {
		t.Fatal("no tun.stack rule to stand in for")
	}
	rules[index].condition = deviationConditionLANSharingOff
	rules[index].forcedValue = "gvisor"
	rules[index].forcedFrom = []string{"system", "mixed"}
	rules[index].unwrittenUnconditional = true

	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	for stack, reported := range map[string]bool{"system": true, "mixed": true, "System": true, "gvisor": false, "mips": false} {
		var root map[string]any
		if err := yaml.Unmarshal([]byte("tun:\n  enable: true\n  stack: "+stack+"\n"), &root); err != nil {
			t.Fatal(err)
		}
		rows := deviationRowsFrom(rules, root, policy)
		got := slices.ContainsFunc(rows, func(row configDeviation) bool { return row.Field == "tun.stack" })
		if got != reported {
			t.Errorf("tun.stack %s: reported %v, want %v", stack, got, reported)
		}
	}
	fields := catalogFieldsByPath(t, RuntimeProfileIOSPacketTunnel)
	stackField := fields["tun.stack"]
	stackField.PlatformDecision = nil
	decided := []syntaxField{stackField}
	decidePlatformFieldsFrom(rules, decided, policy)
	if decision := decided[0].PlatformDecision; decision == nil || decision.Value != "gvisor" || strings.Join(decision.Replaces, ",") != "system,mixed" {
		t.Fatalf("tun.stack: %+v", decision)
	}
	for _, rule := range rules {
		for _, value := range rule.forcedFrom {
			if field, ok := fields[rule.field]; !ok || !slices.ContainsFunc(field.Values, func(offered string) bool {
				return strings.EqualFold(offered, value)
			}) {
				t.Errorf("%s: forcedFrom %q is not a value the field offers (%v)", rule.field, value, field.Values)
			}
		}
	}
}

func TestAStackWrittenInAnotherCaseIsNoDeviation(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	for _, written := range []string{"go", "Go", "GO"} {
		rows, err := collectConfigDeviations("tun:\n  enable: true\n  stack: "+written+"\n", policy)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(rows, func(row configDeviation) bool { return row.Field == "tun.stack" }) {
			t.Errorf("tun.stack %s: reported as changed, though it runs go", written)
		}
	}
	rows, err := collectConfigDeviations("tun:\n  enable: true\n  stack: Mips\n", policy)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(rows, func(row configDeviation) bool { return row.Field == "tun.stack" }) {
		t.Error("tun.stack Mips: not reported, though the tunnel runs go")
	}
}

func TestACongestionControllerTheGoStackLacksIsReportedAsTheOneItRuns(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	for written, reported := range map[string]bool{"bbr3": true, "BBR3": true, "' bbr3 '": true, "bbr": false, "BBR": false, "cubic": false, "reno": false} {
		rows, err := collectConfigDeviations("tun:\n  enable: true\n  congestion-controller: "+written+"\n", policy)
		if err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(rows, func(row configDeviation) bool { return row.Field == "tun.congestion-controller" })
		if (index >= 0) != reported {
			t.Errorf("tun.congestion-controller %s: reported %v, want %v", written, index >= 0, reported)
		}
		if index >= 0 && rows[index].Effective != "bbr: the go stack has no bbr3, and runs its bbr" {
			t.Errorf("tun.congestion-controller %s: the row says %q", written, rows[index].Effective)
		}
	}
}

func TestBbr3IsAnUnavailableValueAndTheFieldStaysTheReaders(t *testing.T) {
	var catalog syntaxCatalog
	box, err := SyntaxCatalogForIOS(RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(box.Value), &catalog); err != nil {
		t.Fatal(err)
	}
	for _, key := range catalog.PlatformDecidedKeys {
		if key.Path == "tun.congestion-controller" {
			t.Fatalf("tun.congestion-controller is a decided key: %+v", key)
		}
	}
	for _, field := range catalog.Fields {
		if field.Path != "tun.congestion-controller" {
			continue
		}
		if field.PlatformDecision != nil || field.PlatformDecided {
			t.Fatalf("tun.congestion-controller carries a decision: %+v (decided %v)", field.PlatformDecision, field.PlatformDecided)
		}
		if len(field.UnavailableValues) != 1 || field.UnavailableValues[0].Value != "bbr3" || field.UnavailableValues[0].Alternative != "bbr" ||
			field.UnavailableValues[0].Reason != "every file runs the go stack, which has bbr, cubic and reno; bbr3 is closest to its bbr" {
			t.Fatalf("tun.congestion-controller's unavailable values: %+v", field.UnavailableValues)
		}
		return
	}
	t.Fatal("no tun.congestion-controller field in the catalog")
}

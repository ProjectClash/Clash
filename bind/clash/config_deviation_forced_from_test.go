package clash

import (
	"slices"
	"strings"
	"testing"
)

func TestAForcedRuleReportsOnlyTheValuesItReplaces(t *testing.T) {
	restore := includeAllNetworksRequested.Load()
	includeAllNetworksRequested.Store(true)
	t.Cleanup(func() { includeAllNetworksRequested.Store(restore) })
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	for stack, reported := range map[string]bool{"system": true, "mixed": true, "System": true, "gvisor": false, "mips": false} {
		rows, err := collectConfigDeviations("tun:\n  enable: true\n  stack: "+stack+"\n", policy)
		if err != nil {
			t.Fatal(err)
		}
		got := slices.ContainsFunc(rows, func(row configDeviation) bool { return row.Field == "tun.stack" })
		if got != reported {
			t.Errorf("tun.stack %s: reported %v, want %v", stack, got, reported)
		}
	}
	fields := catalogFieldsByPath(t, RuntimeProfileIOSPacketTunnel)
	decision := fields["tun.stack"].PlatformDecision
	if decision == nil || decision.Value != "gvisor" || strings.Join(decision.Replaces, ",") != "system,mixed" {
		t.Fatalf("tun.stack: %+v", decision)
	}
	for _, rule := range deviationRules {
		for _, value := range rule.forcedFrom {
			if field, ok := fields[rule.field]; !ok || !slices.ContainsFunc(field.Values, func(offered string) bool {
				return strings.EqualFold(offered, value)
			}) {
				t.Errorf("%s: forcedFrom %q is not a value the field offers (%v)", rule.field, value, field.Values)
			}
		}
	}
}

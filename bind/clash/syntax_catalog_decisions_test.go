package clash

import (
	"slices"
	"testing"
)

func TestEveryProfilesDecisionsFollowTheirRules(t *testing.T) {
	for _, rule := range deviationRules {
		if rule.defaultOnly && rule.condition != "" {
			t.Errorf("%s: defaultOnly and conditional", rule.field)
		}
	}
	for _, name := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel, RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		profile, err := normalizeRuntimeProfile(name)
		if err != nil {
			t.Fatal(err)
		}
		policy := runtimePolicyFor(profile, true)
		fields := catalogFieldsByPath(t, name)
		for _, rule := range deviationRules {
			if rule.ruleScan {
				continue
			}
			field, ok := fields[rule.field]
			if !ok {
				t.Errorf("%s: %s is not in the catalog", name, rule.field)
				continue
			}
			decided := (rule.applies == nil || rule.applies(policy)) && rule.honouredBy == ""
			if (field.PlatformDecision != nil) != decided {
				t.Errorf("%s %s: decision %+v, want one %v", name, rule.field, field.PlatformDecision, decided)
			}
			if flagged := !rule.defaultOnly && rule.honouredBy == ""; field.PlatformDecided != flagged {
				t.Errorf("%s %s: platformDecided %v, want %v", name, rule.field, field.PlatformDecided, flagged)
			}
		}
		for _, path := range []string{"rules", "proxies"} {
			if fields[path].PlatformDecided {
				t.Errorf("%s: %s marked platformDecided", name, path)
			}
		}
	}
}

func TestAWrittenAllowLanFalseHasNothingToReport(t *testing.T) {
	restore := !allowLanForcedOff.Load()
	allowLanForcedOff.Store(!(false))
	t.Cleanup(func() { allowLanForcedOff.Store(!(restore)) })
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	for document, reported := range map[string]bool{"allow-lan: false\n": false, "allow-lan: true\n": true} {
		rows, err := collectConfigDeviations(document, policy)
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.ContainsFunc(rows, func(row configDeviation) bool { return row.Field == "allow-lan" }); got != reported {
			t.Errorf("%q: reported %v, want %v", document, got, reported)
		}
	}
	if decision := catalogFieldsByPath(t, RuntimeProfileIOSPacketTunnel)["allow-lan"].PlatformDecision; decision == nil || decision.Value != "false" {
		t.Errorf("allow-lan: %+v", decision)
	}
}

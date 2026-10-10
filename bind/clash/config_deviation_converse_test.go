package clash

import (
	"reflect"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestEveryRegisteredForcedRuleActuallyFiresOnEachProfileItClaims(t *testing.T) {
	restore := !allowLanForcedOff.Load()
	t.Cleanup(func() { allowLanForcedOff.Store(!(restore)) })

	changedOn := func(high bool) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			before, after := &config.Config{}, &config.Config{}
			seedStruct(reflect.ValueOf(before), high, "", 0)
			seedStruct(reflect.ValueOf(after), high, "", 0)
			finalizeConfigForApple(after, policy)
			moved := map[string]bool{}
			b, a := reflect.ValueOf(before).Elem(), reflect.ValueOf(after).Elem()
			for _, root := range deviationProbeRoots {
				var changes []observedChange
				diffStruct(b.FieldByName(root.goName), a.FieldByName(root.goName), "", 0, &changes)
				rootType := b.FieldByName(root.goName).Type()
				for rootType.Kind() == reflect.Ptr {
					rootType = rootType.Elem()
				}
				for _, c := range changes {
					if field, ok := registryFieldFor(root.goName, root.prefix, c.goPath, rootType); ok {
						moved[field] = true
					}
				}
			}
			out[seat.name] = moved
		}
		return out
	}
	movedHigh, movedLow := changedOn(true), changedOn(false)
	moved := func(profile, field string) bool { return movedHigh[profile][field] || movedLow[profile][field] }

	claims := map[string]map[string]bool{}
	for _, rule := range deviationRules {
		if rule.category != deviationForced || rule.forcedValue == "" {
			continue
		}
		claims[rule.field] = map[string]bool{}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			if rule.applies == nil || rule.applies(policy) {
				claims[rule.field][seat.name] = true
			}
		}
	}
	if len(claims) == 0 {
		t.Fatal("no forced rule carries a forcedValue; the converse has nothing to check")
	}

	for field, profiles := range claims {
		reachable := false
		for _, seat := range registryProfiles {
			if movedHigh[seat.name][field] || movedLow[seat.name][field] {
				reachable = true
			}
		}
		if !reachable {
			t.Logf("%s: finalize never moved it on any profile under either seed -- either the "+
				"force is unreachable from this probe (tun.dns-hijack is a list, tun.mtu is "+
				"runtime) or the registration is wrong everywhere; listed, not passed", field)
			continue
		}
		for _, seat := range registryProfiles {
			claimed, did := profiles[seat.name], moved(seat.name, field)
			if claimed && !did {
				t.Errorf("%s: registry claims %s but finalize did not change it there -- appliesTo is a lie on that profile", field, seat.name)
			}
			if !claimed && did {
				t.Errorf("%s: finalize changes it on %s but the registry does not claim that profile", field, seat.name)
			}
		}
	}
}

func TestRawPathForcesFireExactlyWhereTheRegistryClaims(t *testing.T) {
	cases := []struct {
		field string
		seed  func(raw *config.RawConfig)
		moved func(raw *config.RawConfig) bool
	}{
		{"dns.enable",
			func(r *config.RawConfig) { r.DNS.Enable = false },
			func(r *config.RawConfig) bool { return r.DNS.Enable }},
	}
	for _, c := range cases {
		var rule *deviationRule
		for i := range deviationRules {
			if deviationRules[i].field == c.field {
				rule = &deviationRules[i]
			}
		}
		if rule == nil {
			t.Fatalf("%s: no rule", c.field)
		}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			claimed := rule.applies == nil || rule.applies(policy)
			raw := config.DefaultRawConfig()
			c.seed(raw)
			normalizeRawConfigForApple(raw, policy)
			did := c.moved(raw)
			if claimed && !did {
				t.Errorf("%s: registry claims %s but the raw normaliser did not change it there", c.field, seat.name)
			}
			if !claimed && did {
				t.Errorf("%s: the raw normaliser changes it on %s but the registry does not claim that profile", c.field, seat.name)
			}
		}
	}
}

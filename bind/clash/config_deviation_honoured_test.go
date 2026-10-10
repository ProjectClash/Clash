package clash

import (
	"strings"
	"testing"
)

func TestEveryHonouredByIsARealWrite(t *testing.T) {
	honoured := 0
	for _, rule := range deviationRules {
		if rule.honouredBy == "" {
			continue
		}
		honoured++
		if rule.honouredBy != "expansion" {
			t.Errorf("%s: honouredBy=%q is not a value this test knows how to prove; add the "+
				"proof here before adding the value", rule.field, rule.honouredBy)
			continue
		}
		if !strings.HasPrefix(rule.field, "tun.") || !strings.HasSuffix(rule.field, "-set") {
			t.Errorf("%s: marked honouredBy=expansion but is not a tun.*-set field, so this test "+
				"does not know what its expansion target is", rule.field)
			continue
		}
		setKey := strings.TrimPrefix(rule.field, "tun.")
		destKey := strings.TrimSuffix(setKey, "-set")

		config := "tun:\n" +
			"  enable: true\n" +
			"  " + setKey + ":\n" +
			"    - lab\n" +
			"rule-providers:\n" +
			"  lab:\n" +
			"    type: inline\n" +
			"    behavior: ipcidr\n" +
			"    payload:\n" +
			"      - 198.51.100.0/24\n" +
			"proxies: []\n" +
			"rules:\n" +
			"  - MATCH,DIRECT\n"

		box, err := FinalizeForIOS(config, "")
		if err != nil {
			t.Errorf("%s: FinalizeForIOS refused the configuration this test uses to prove the "+
				"expansion: %v", rule.field, err)
			continue
		}
		out := box.Value
		if strings.Contains(out, setKey+":") {
			t.Errorf("%s: the set is still in the finalized document, so nothing expanded it:\n%s",
				rule.field, out)
			continue
		}
		if !strings.Contains(out, destKey+":") || !strings.Contains(out, "198.51.100.0/24") {
			t.Errorf("%s: marked honouredBy=expansion, but the prefix did not arrive in %s -- "+
				"the mark claims a write that did not happen:\n%s", rule.field, destKey, out)
		}
	}
	if honoured == 0 {
		t.Fatal("no rule carries honouredBy at all; the two route-set rules used to, and a " +
			"test over an empty set proves nothing")
	}
}

func TestHonouredByOnlyMarksUnavailableFields(t *testing.T) {
	for _, rule := range deviationRules {
		if rule.honouredBy != "" && rule.category != deviationUnavailable {
			t.Errorf("%s: honouredBy=%q on a %s rule -- the app can only honour on the core's "+
				"behalf what the core cannot do at all", rule.field, rule.honouredBy, rule.category)
		}
	}
}

func TestHonouredRowsSaySoAsData(t *testing.T) {
	const document = "tun:\n  route-address-set:\n    - geoip-cn\n  route-exclude-address-set:\n    - lan\n  auto-redirect: true\nrules:\n  - UID,501,DIRECT\n  - MATCH,DIRECT\nproxies: []\n"
	rows, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatal(err)
	}
	honoured := map[string]bool{}
	for _, row := range rows {
		honoured[row.Field+"/"+row.RuleKind] = row.Honoured
	}
	for _, field := range []string{"tun.route-address-set/", "tun.route-exclude-address-set/"} {
		v, ok := honoured[field]
		if !ok || !v {
			t.Errorf("%s: expected an honoured row, got present=%v honoured=%v (%v)", field, ok, v, fieldsOf(rows))
		}
	}
	for _, field := range []string{"tun.auto-redirect/", "rules/UID"} {
		if v, ok := honoured[field]; !ok || v {
			t.Errorf("%s: expected a row with honoured=false, got present=%v honoured=%v", field, ok, v)
		}
	}
}

package config

import (
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestTheRulesAfterAnIndexParseAsTheSameRulesInlineAndGoLast(t *testing.T) {
	own := ruleIndexTestRules[:len(ruleIndexTestRules)-1]
	after := []string{"DOMAIN-SUFFIX,late.example,REJECT", "MATCH,DIRECT"}
	all := append(append(append([]string{}, rulesBeforeTheIndex...), own...), after...)
	inline, err := Parse([]byte(ruleIndexTestHead + "rules:\n  - " + strings.Join(all, "\n  - ") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	path, sum := compileRuleIndex(t, t.TempDir(), own, knownTarget)
	document := indexedConfigurationWithRulesBefore(path, sum, rulesBeforeTheIndex) + "  append:\n    - " + strings.Join(after, "\n    - ") + "\n"
	indexed, err := Parse([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	table, ok := indexed.RuleTable.(*C.ClashRulesBefore)
	if !ok || len(table.After) != len(after) || table.FirstAfter() != len(rulesBeforeTheIndex)+len(own) {
		t.Fatalf("the rules are %T with %d after at %d", indexed.RuleTable, len(table.After), table.FirstAfter())
	}
	if indexed.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("%d rules, want %d", indexed.RuleTable.Len(), inline.RuleTable.Len())
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), indexed.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Errorf("rule %d: inline %s,%s,%s; indexed %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
	}
	at, adapter := -1, ""
	indexed.RuleTable.Walk(&C.Metadata{Host: "x.late.example", NetWork: C.UDP, DstPort: 53}, C.RuleMatchHelper{}, nil,
		func(i int, _ C.Rule, a string) bool { at, adapter = i, a; return true })
	if want := len(all) - 2; at != want || adapter != "REJECT" {
		t.Fatalf("x.late.example stopped at rule %d (%s), want the first rule after the index at %d (REJECT)", at, adapter, want)
	}
	indexed.RuleTable.Walk(&C.Metadata{Host: "www.example.com", NetWork: C.TCP, DstPort: 443}, C.RuleMatchHelper{}, nil,
		func(i int, _ C.Rule, a string) bool { at, adapter = i, a; return true })
	if at != 0 {
		t.Fatalf("www.example.com stopped at rule %d, want the first rule before the index", at)
	}
	var places []int
	indexed.RuleTable.(interface {
		RangeStatistics(func(int, C.RuleStatistics, bool) bool)
	}).RangeStatistics(func(i int, _ C.RuleStatistics, _ bool) bool { places = append(places, i); return true })
	if len(places) != len(all) || places[len(places)-1] != len(all)-1 {
		t.Fatalf("the statistics walk the places %v, want 0 to %d", places, len(all)-1)
	}
}

func TestARuleAfterTheIndexIsRefusedAtItsPlace(t *testing.T) {
	path, sum := compileRuleIndex(t, t.TempDir(), ruleIndexTestRules[:2], knownTarget)
	document := ruleIndexTestHead + "x-clash-rule-index:\n  path: " + path + "\n  sha256: " + sum + "\n  append:\n    - DOMAIN,a.example,NO-SUCH\n"
	if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "rules[2]") {
		t.Fatalf("a rule after two naming nothing: %v, want rules[2]", err)
	}
}

package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"go.yaml.in/yaml/v3"
)

var appendedRulesForTest = []string{
	"DOMAIN-SUFFIX,late.example,REJECT",
	"MATCH,DIRECT",
}

func finalizeWithRulesAround(t *testing.T, document string, resources map[string]any, before, after []string) (finalizeOptionsAnswer, map[string]any) {
	t.Helper()
	more := map[string]any{}
	if after != nil {
		more["appendRules"] = after
	}
	return finalizeWithRulesBefore(t, document, resources, before, more)
}

func rulesAfterOf(t *testing.T, root map[string]any) []string {
	t.Helper()
	reference, _ := root["x-clash-rule-index"].(map[string]any)
	var after []string
	if list, ok := reference["append"].([]any); ok {
		for _, line := range list {
			after = append(after, line.(string))
		}
	}
	return after
}

const sourceForRulesAfter = "proxies:\n  - {name: P, type: direct}\nrules:\n" +
	"  - DOMAIN,www.example.com,P\n" +
	"  - UID,501,DIRECT\n" +
	"  - DOMAIN-SUFFIX,example.org,DIRECT\n" +
	"  - 'DST-PORT,8443,DIRECT'\n"

func TestTheRulesAfterAConfigurationsOwnRideBesideItsIndexWhichStaysTheSame(t *testing.T) {
	dir := t.TempDir()
	_, plain := finalizeWithRulesAround(t, sourceForRulesAfter, indexResources(dir), nil, nil)
	plainPath, _ := rulesBeforeOf(t, plain)
	answer, root := finalizeWithRulesAround(t, sourceForRulesAfter, indexResources(dir), moduleRulesForTest, appendedRulesForTest)
	path, before := rulesBeforeOf(t, root)
	if path != plainPath || !reflect.DeepEqual(before, moduleRulesForTest) || !reflect.DeepEqual(rulesAfterOf(t, root), appendedRulesForTest) {
		t.Fatalf("published %s with %v before and %v after", path, before, rulesAfterOf(t, root))
	}
	published, err := parseAfterLookups(answer.Text)
	if err != nil {
		t.Fatal(err)
	}
	table, ok := published.RuleTable.(*C.ClashRulesBefore)
	if !ok || published.RuleTable.Len() != 7 || table.FirstAfter() != 5 {
		t.Fatalf("%T of %d rules", published.RuleTable, published.RuleTable.Len())
	}
	at := -1
	published.RuleTable.Walk(&C.Metadata{Host: "x.late.example", NetWork: C.TCP, DstPort: 80}, C.RuleMatchHelper{}, nil,
		func(i int, _ C.Rule, _ string) bool { at = i; return true })
	if at != 5 {
		t.Fatalf("x.late.example stopped at rule %d, want the first rule after, 5", at)
	}

	other := []string{"DOMAIN,tracker.example,REJECT"}
	for name, tc := range map[string]struct {
		after, want []string
	}{
		"replaced": {other, other},
		"removed":  {[]string{}, nil},
		"kept":     {nil, appendedRulesForTest},
	} {
		_, again := finalizeWithRulesAround(t, answer.Text, indexResources(dir), nil, tc.after)
		path, before := rulesBeforeOf(t, again)
		if path != plainPath || !reflect.DeepEqual(before, moduleRulesForTest) || !reflect.DeepEqual(rulesAfterOf(t, again), tc.want) {
			t.Fatalf("%s: %s with %v before and %v after, want %v after", name, path, before, rulesAfterOf(t, again), tc.want)
		}
	}
}

func TestARuleAfterAConfigurationsOwnIsRefusedInTheTunnelsWordsAtItsPlace(t *testing.T) {
	dir := t.TempDir()
	after := []string{"DOMAIN,a.example,REJECT", "DOMAIN,b.example,Nowhere"}
	_, err := finalizeWithRulesBeforeError(sourceForRulesAfter, indexResources(dir), moduleRulesForTest, map[string]any{"appendRules": after})
	if err == nil || !strings.Contains(err.Error(), "rules[6] [DOMAIN,b.example,Nowhere] error: proxy [Nowhere] not found") {
		t.Fatalf("a rule after naming no policy: %v", err)
	}
	published, _ := finalizeWithRulesAround(t, sourceForRulesAfter, indexResources(dir), moduleRulesForTest, appendedRulesForTest)
	if _, err := finalizeWithRulesBeforeError(published.Text, indexResources(dir), nil, map[string]any{"appendRules": []string{"DOMAIN,c.example,Gone"}}); err == nil ||
		!strings.Contains(err.Error(), "rules[5] [DOMAIN,c.example,Gone] error: proxy [Gone] not found") {
		t.Fatalf("published again with a rule after naming no policy: %v", err)
	}
	if _, err := finalizeWithRulesBeforeError(sourceForRulesAfter, indexResources(t.TempDir()), nil, map[string]any{"appendRules": []string{"UID,501,DIRECT"}}); err == nil ||
		!strings.Contains(err.Error(), "UID rule cannot go after") {
		t.Fatalf("a UID rule after where the tunnel removes them: %v", err)
	}
}

func TestWithoutAnIndexTheRulesAfterCloseThePublishedRules(t *testing.T) {
	document := "proxies:\n  - {name: N, type: direct}\nrules:\n  - DOMAIN,a.example,N\n"
	_, root := finalizeWithRulesAround(t, document, map[string]any{}, moduleRulesForTest, appendedRulesForTest)
	want := []any{moduleRulesForTest[0], moduleRulesForTest[1], "DOMAIN,a.example,N", appendedRulesForTest[0], appendedRulesForTest[1]}
	if !reflect.DeepEqual(root["rules"], want) {
		t.Fatalf("rules = %v, want %v", root["rules"], want)
	}
	_, root = finalizeWithRulesAround(t, "proxies:\n  - {name: N, type: direct}\n", map[string]any{}, nil, appendedRulesForTest)
	if !reflect.DeepEqual(root["rules"], []any{appendedRulesForTest[0], appendedRulesForTest[1]}) {
		t.Fatalf("rules = %v, want the rules after", root["rules"])
	}
}

func TestRulesAfterAConfigurationWithNoRulesRideInAnIndexReference(t *testing.T) {
	_, root := finalizeWithRulesAround(t, "proxies:\n  - {name: N, type: direct}\n", indexResources(t.TempDir()), nil, appendedRulesForTest)
	if _, has := root["rules"]; has || !reflect.DeepEqual(rulesAfterOf(t, root), appendedRulesForTest) {
		t.Fatalf("published %+v", root)
	}
}

func TestTheReadersOfAPublishedConfigurationReadTheRulesAfterLast(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	answer, _ := finalizeWithRulesAround(t, sourceForRulesAfter, indexResources(dir), moduleRulesForTest, appendedRulesForTest)
	path := filepath.Join(dir, "published.yaml")
	if err := os.WriteFile(path, []byte(answer.Text), 0o600); err != nil {
		t.Fatal(err)
	}

	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	if catalog.Total() != 7 || catalog.Prepended() != 2 || catalog.Appended() != 2 {
		t.Fatalf("total %d, prepended %d, appended %d; want 7, 2, 2", catalog.Total(), catalog.Prepended(), catalog.Appended())
	}
	var summary ruleSummary
	if err := json.Unmarshal([]byte(catalog.SummaryJSON()), &summary); err != nil || summary.Appended != 2 || summary.ByType["MATCH"] != 1 {
		t.Fatalf("summary %+v (%v)", summary, err)
	}
	var page struct {
		Rules []rulePageEntry `json:"rules"`
	}
	if err := json.Unmarshal([]byte(catalog.PageJSON(5, 5, "", "", "")), &page); err != nil || len(page.Rules) != 2 ||
		page.Rules[0].Index != 5 || page.Rules[0].Text != appendedRulesForTest[0] {
		t.Fatalf("the last page: %+v (%v)", page.Rules, err)
	}

	box, err := MatchRuleForIOS(answer.Text, "", `{"host":"x.late.example","port":80,"network":"tcp"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got matchRuleResult
	if err := json.Unmarshal([]byte(box.Value), &got); err != nil || got.Rule != appendedRulesForTest[0] || got.Index == nil || *got.Index != 5 {
		t.Fatalf("the offline match: %+v (%v)", got, err)
	}

	if at, ok := readersRuleIndex(answer.Text, 6, "rules[6] [MATCH,DIRECT] error: x"); !ok || at != 7 {
		t.Fatalf("a rule after: %d %v, want 7", at, ok)
	}

	cfg, err := config.Parse([]byte(answer.Text))
	if err != nil {
		t.Fatal(err)
	}
	if !writtenRuleTypeIn(cfg.RuleTable, 6, map[string]bool{"MATCH": true}) || writtenRuleTypeIn(cfg.RuleTable, 5, map[string]bool{"MATCH": true}) {
		t.Fatal("the rules page does not read the rules after as written")
	}
	var root map[string]any
	_ = yaml.Unmarshal([]byte(answer.Text), &root)
	var lines []string
	eachDocumentRuleLine(root, func(_ int, line string) { lines = append(lines, line) })
	if len(lines) == 0 || lines[len(lines)-1] != "MATCH,DIRECT" {
		t.Fatalf("the document's rule lines end %v", lines)
	}
}

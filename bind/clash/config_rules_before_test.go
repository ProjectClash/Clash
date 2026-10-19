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
	"github.com/ProjectClash/Clash/rules/clashindex"
	"go.yaml.in/yaml/v3"
)

var moduleRulesForTest = []string{
	"DOMAIN-SUFFIX,d0.example.com,REJECT",
	"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
}

func finalizeWithRulesBefore(t *testing.T, document string, resources map[string]any, before []string, more map[string]any) (finalizeOptionsAnswer, map[string]any) {
	t.Helper()
	answer, err := finalizeWithRulesBeforeError(document, resources, before, more)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(answer.Text), &root); err != nil {
		t.Fatal(err)
	}
	return answer, root
}

func finalizeWithRulesBeforeError(document string, resources map[string]any, before []string, more map[string]any) (finalizeOptionsAnswer, error) {
	options := map[string]any{}
	for key, value := range more {
		options[key] = value
	}
	if before != nil {
		options["prependRules"] = before
	}
	resourcesJSON, _ := json.Marshal(resources)
	optionsJSON, _ := json.Marshal(options)
	box, err := FinalizeForIOSWithOptions(document, string(resourcesJSON), string(optionsJSON))
	if err != nil {
		return finalizeOptionsAnswer{}, err
	}
	var answer finalizeOptionsAnswer
	if err := json.Unmarshal([]byte(box.Value), &answer); err != nil {
		return finalizeOptionsAnswer{}, err
	}
	return answer, nil
}

func indexResources(dir string) map[string]any {
	return map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir}
}

func rulesBeforeOf(t *testing.T, root map[string]any) (string, []string) {
	t.Helper()
	reference, _ := root["x-clash-rule-index"].(map[string]any)
	path, _ := reference["path"].(string)
	if path == "" {
		t.Fatalf("no index named: %+v", root["x-clash-rule-index"])
	}
	var before []string
	if list, ok := reference["prepend"].([]any); ok {
		for _, line := range list {
			before = append(before, line.(string))
		}
	}
	return path, before
}

func TestTheRulesBeforeAConfigurationsOwnRideBesideItsIndexWhichStaysTheSame(t *testing.T) {
	dir := t.TempDir()
	document := ruleIndexTestDocument(3000)
	_, plain := finalizeWithRulesBefore(t, document, indexResources(dir), nil, nil)
	plainPath, none := rulesBeforeOf(t, plain)
	if none != nil {
		t.Fatalf("a publish with no rules before wrote %v", none)
	}
	answer, root := finalizeWithRulesBefore(t, document, indexResources(dir), moduleRulesForTest, nil)
	path, before := rulesBeforeOf(t, root)
	if path != plainPath {
		t.Fatalf("the rules before compiled another index: %s, want %s", path, plainPath)
	}
	if !reflect.DeepEqual(before, moduleRulesForTest) {
		t.Fatalf("prepend = %v, want %v", before, moduleRulesForTest)
	}
	published, err := parseAfterLookups(answer.Text)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := parseAfterLookups(strings.Replace(document, "\nrules:\n", "\nrules:\n  - "+strings.Join(moduleRulesForTest, "\n  - ")+"\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	table, ok := published.RuleTable.(*C.ClashRulesBefore)
	if !ok || published.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("%T of %d rules, want the rules before the index, %d in all", published.RuleTable, published.RuleTable.Len(), inline.RuleTable.Len())
	}
	if _, ok := table.Rest.(*clashindex.Table); !ok {
		t.Fatalf("after the rules before: %T, want the index", table.Rest)
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), published.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Fatalf("rule %d: inline %s,%s,%s; published %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
	}
	for _, host := range []string{"d0.example.com", "d6.example.com", "x.s7.example.org", "nothing.example"} {
		m1 := &C.Metadata{Host: host, NetWork: C.TCP, DstPort: 443}
		m2 := *m1
		var first1, first2 int
		inline.RuleTable.Walk(m1, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { first1 = i; return true })
		published.RuleTable.Walk(&m2, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { first2 = i; return true })
		if first1 != first2 {
			t.Fatalf("%s: inline rule %d, published %d", host, first1, first2)
		}
	}

	other := []string{"DOMAIN,tracker.example,REJECT"}
	_, again := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), other, nil)
	if path, before := rulesBeforeOf(t, again); path != plainPath || !reflect.DeepEqual(before, other) {
		t.Fatalf("published again with other rules before: %s %v, want %s %v", path, before, plainPath, other)
	}
	_, removed := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), []string{}, nil)
	if path, before := rulesBeforeOf(t, removed); path != plainPath || before != nil {
		t.Fatalf("published again with none before: %s %v, want %s and none", path, before, plainPath)
	}
	_, kept := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), nil, nil)
	if path, before := rulesBeforeOf(t, kept); path != plainPath || !reflect.DeepEqual(before, moduleRulesForTest) {
		t.Fatalf("published again naming none: %s %v, want %s %v", path, before, plainPath, moduleRulesForTest)
	}
}

func TestARuleBeforeAConfigurationsOwnIsRefusedInTheTunnelsWordsAtItsPlace(t *testing.T) {
	document := ruleIndexTestDocument(30)
	for name, resources := range map[string]map[string]any{"index": indexResources(t.TempDir()), "inline": {"runtimeProfile": RuntimeProfileIOSPacketTunnel}} {
		_, err := finalizeWithRulesBeforeError(document, resources, []string{"DOMAIN,a.example,REJECT", "DOMAIN,b.example,Nowhere"}, nil)
		if name == "inline" {
			answer, finalizeErr := finalizeWithRulesBeforeError(document, resources, []string{"DOMAIN,a.example,REJECT", "DOMAIN,b.example,Nowhere"}, nil)
			if finalizeErr != nil {
				t.Fatal(finalizeErr)
			}
			_, err = config.Parse([]byte(answer.Text))
		}
		if err == nil || !strings.Contains(err.Error(), "rules[1] [DOMAIN,b.example,Nowhere] error: proxy [Nowhere] not found") {
			t.Fatalf("%s: a rule before naming no policy: %v", name, err)
		}
	}
	dir := t.TempDir()
	published, _ := finalizeWithRulesBefore(t, document, indexResources(dir), moduleRulesForTest, nil)
	if _, err := finalizeWithRulesBeforeError(published.Text, indexResources(dir), []string{"DOMAIN,c.example,Gone"}, nil); err == nil ||
		!strings.Contains(err.Error(), "rules[0] [DOMAIN,c.example,Gone] error: proxy [Gone] not found") {
		t.Fatalf("published again with a rule before naming no policy: %v", err)
	}
}

func TestWithoutAnIndexTheRulesBeforeOpenThePublishedRules(t *testing.T) {
	document := "proxies:\n  - {name: N, type: direct}\nrules:\n  - DOMAIN,a.example,N\n  - MATCH,N\n"
	_, root := finalizeWithRulesBefore(t, document, map[string]any{}, moduleRulesForTest, nil)
	want := []any{moduleRulesForTest[0], moduleRulesForTest[1], "DOMAIN,a.example,N", "MATCH,N"}
	if !reflect.DeepEqual(root["rules"], want) {
		t.Fatalf("rules = %v, want %v", root["rules"], want)
	}
	_, root = finalizeWithRulesBefore(t, "proxies:\n  - {name: N, type: direct}\n", map[string]any{}, moduleRulesForTest, nil)
	if !reflect.DeepEqual(root["rules"], []any{moduleRulesForTest[0], moduleRulesForTest[1]}) {
		t.Fatalf("rules = %v, want the rules before", root["rules"])
	}
	plain, err := FinalizeForIOS(document, "")
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := finalizeWithRulesBefore(t, document, map[string]any{}, []string{}, nil)
	if answer.Text != plain.Value {
		t.Fatal("an empty prependRules changed the published text")
	}
}

func TestTheReadersOfAPublishedConfigurationsRulesReadTheRulesBeforeFirst(t *testing.T) {
	dir := t.TempDir()
	document := "proxies:\n  - {name: N, type: direct}\n" +
		"rule-providers:\n  ads: {type: http, behavior: domain, url: 'https://rules.example/ads.yaml', path: ./ads.yaml}\n" +
		"rules:\n  - UID,501,DIRECT\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.example,N\n  - MATCH,N\n"
	before := []string{"GEOSITE,category-ads-all,REJECT", "RULE-SET,ads,REJECT"}
	answer, root := finalizeWithRulesBefore(t, document, indexResources(dir), before, map[string]any{"geoCategories": true, "plan": true})
	reference := root["x-clash-rule-index"].(map[string]any)
	if !reflect.DeepEqual(reference["uid-removed"], []any{2}) {
		t.Fatalf("uid-removed = %v, want [2]: where the UID rule stands after the two before", reference["uid-removed"])
	}
	if answer.GeositeCategories == nil || !reflect.DeepEqual(*answer.GeositeCategories, []string{"category-ads-all"}) {
		t.Fatalf("geositeCategories = %v, want the rule before's category", answer.GeositeCategories)
	}
	if answer.GeoIPCountries == nil || !reflect.DeepEqual(*answer.GeoIPCountries, []string{"cn"}) {
		t.Fatalf("geoipCountries = %v, want the index's country", answer.GeoIPCountries)
	}
	if !strings.Contains(string(answer.Plan), "ads") {
		t.Fatalf("the plan does not name the rule set a rule before names: %s", answer.Plan)
	}
	var lines []string
	eachDocumentRuleLine(root, func(i int, line string) { lines = append(lines, line) })
	if !reflect.DeepEqual(lines[:2], before) {
		t.Fatalf("the rules as written begin %v, want the rules before", lines)
	}
	var places []int
	eachDocumentRuleLine(root, func(i int, _ string) { places = append(places, i) })
	if places[0] != 0 || places[1] != 1 || places[2] != 3 {
		t.Fatalf("the rules as written are at %v, want 0, 1, then 3 (the UID rule at 2 removed)", places)
	}
	_, again := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), before[:1], nil)
	if got := again["x-clash-rule-index"].(map[string]any)["uid-removed"]; !reflect.DeepEqual(got, []any{1}) {
		t.Fatalf("published again with one before: uid-removed = %v, want [1]", got)
	}
}

func publishedWithRulesBefore(t *testing.T, source string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	answer, _ := finalizeWithRulesBefore(t, source, indexResources(dir), moduleRulesForTest, nil)
	path := filepath.Join(dir, "published.yaml")
	if err := os.WriteFile(path, []byte(answer.Text), 0o600); err != nil {
		t.Fatal(err)
	}
	return answer.Text, path
}

const sourceForRulesBefore = "proxies:\n  - {name: P, type: direct}\nrules:\n" +
	"  - DOMAIN,www.example.com,P\n" +
	"  - UID,501,DIRECT\n" +
	"  - DOMAIN-SUFFIX,example.org,DIRECT\n" +
	"  - 'DST-PORT,8443,DIRECT'\n" +
	"  - MATCH,P\n"

func TestThePublishedRuleCatalogReadsTheRulesBeforeFirstAndSaysHowMany(t *testing.T) {
	_, path := publishedWithRulesBefore(t, sourceForRulesBefore)
	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	if catalog.Total() != 6 || catalog.Prepended() != 2 || catalog.UIDRemoved() != 1 {
		t.Fatalf("total %d, prepended %d, UID rules removed %d; want 6, 2, 1", catalog.Total(), catalog.Prepended(), catalog.UIDRemoved())
	}
	var summary ruleSummary
	if err := json.Unmarshal([]byte(catalog.SummaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Total != 6 || summary.Prepended != 2 || summary.ByType["AND"] != 1 || summary.ByTarget["REJECT"] != 2 {
		t.Fatalf("summary %+v", summary)
	}
	var page struct {
		Rules []rulePageEntry `json:"rules"`
	}
	if err := json.Unmarshal([]byte(catalog.PageJSON(0, 3, "", "", "")), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Rules) != 3 || page.Rules[0].Text != moduleRulesForTest[0] || page.Rules[1].Text != moduleRulesForTest[1] ||
		page.Rules[2].Index != 2 || page.Rules[2].Text != "DOMAIN,www.example.com,P" {
		t.Fatalf("the first page: %+v", page.Rules)
	}
	if err := json.Unmarshal([]byte(catalog.PageJSON(0, 10, "", "REJECT", "")), &page); err != nil || len(page.Rules) != 2 || page.Rules[1].Index != 1 {
		t.Fatalf("the rules to REJECT: %+v (%v)", page.Rules, err)
	}
}

func TestTheOfflineMatchWalksTheRulesBeforeFirst(t *testing.T) {
	setupForMatch(t)
	published, _ := publishedWithRulesBefore(t, sourceForRulesBefore)
	for query, want := range map[string]matchRuleResult{
		`{"host":"d0.example.com","port":443,"network":"tcp"}`:  {Matched: true, Rule: moduleRulesForTest[0], Policy: "REJECT"},
		`{"host":"www.example.com","port":443,"network":"udp"}`: {Matched: true, Rule: moduleRulesForTest[1], Policy: "REJECT"},
		`{"host":"www.example.com","port":443,"network":"tcp"}`: {Matched: true, Rule: "DOMAIN,www.example.com,P", Policy: "P"},
	} {
		box, err := MatchRuleForIOS(published, "", query)
		if err != nil {
			t.Fatal(err)
		}
		var got matchRuleResult
		if err := json.Unmarshal([]byte(box.Value), &got); err != nil {
			t.Fatal(err)
		}
		index := got.Index
		got.Index = nil
		if got != want {
			t.Fatalf("%s: %+v, want %+v", query, got, want)
		}
		wantIndex := map[string]int{moduleRulesForTest[0]: 0, moduleRulesForTest[1]: 1, "DOMAIN,www.example.com,P": 2}[want.Rule]
		if index == nil || *index != wantIndex {
			t.Fatalf("%s: index %v, want %d", query, index, wantIndex)
		}
	}
}

func TestTheRulesPageReadsATableWithRulesBeforeAsWritten(t *testing.T) {
	published, _ := publishedWithRulesBefore(t, sourceForRulesBefore)
	cfg, err := parseAfterLookups(published)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for i := 0; i < cfg.RuleTable.Len(); i++ {
		for _, tp := range []string{"DOMAIN-SUFFIX", "AND", "DOMAIN", "DST-PORT", "MATCH"} {
			if writtenRuleTypeIn(cfg.RuleTable, i, map[string]bool{tp: true}) {
				types = append(types, tp)
			}
		}
	}
	if want := []string{"DOMAIN-SUFFIX", "AND", "DOMAIN", "DOMAIN-SUFFIX", "DST-PORT", "MATCH"}; !reflect.DeepEqual(types, want) {
		t.Fatalf("the rules' types as written: %v, want %v", types, want)
	}
}

func TestACompileErrorAtARuleBeforeOrAfterIsPlacedWhereItWasWritten(t *testing.T) {
	published, _ := publishedWithRulesBefore(t, sourceForRulesBefore)
	if at, ok := readersRuleIndex(published, 1, "rules[1] ["+moduleRulesForTest[1]+"] error: x"); !ok || at != 1 {
		t.Fatalf("a rule before: %d %v, want 1", at, ok)
	}
	if at, ok := readersRuleIndex(published, 4, "rules[4] [DST-PORT,8443,DIRECT] error: x"); !ok || at != 5 {
		t.Fatalf("the index's rule after two before: %d %v, want 5", at, ok)
	}
}

func TestARulesBeforeAConfigurationWithNoRulesRideInAnIndexReference(t *testing.T) {
	dir := t.TempDir()
	document := "proxies:\n  - {name: N, type: direct}\n"
	answer, root := finalizeWithRulesBefore(t, document, indexResources(dir), moduleRulesForTest, nil)
	if _, writes := root["rules"]; writes {
		t.Fatalf("the published configuration writes rules: %v", root["rules"])
	}
	if _, before := rulesBeforeOf(t, root); !reflect.DeepEqual(before, moduleRulesForTest) {
		t.Fatalf("prepend = %v, want %v", before, moduleRulesForTest)
	}
	path := filepath.Join(dir, "published.yaml")
	if err := os.WriteFile(path, []byte(answer.Text), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total() != 2 || catalog.Prepended() != 2 {
		t.Fatalf("total %d, prepended %d; want 2, 2", catalog.Total(), catalog.Prepended())
	}
	catalog.Close()
	_, removed := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), []string{}, nil)
	if _, before := rulesBeforeOf(t, removed); before != nil || removed["rules"] != nil {
		t.Fatalf("published again with none before: prepend %v, rules %v; want neither", before, removed["rules"])
	}
	_, replaced := finalizeWithRulesBefore(t, answer.Text, indexResources(dir), []string{"DOMAIN,tracker.example,REJECT"}, nil)
	if _, before := rulesBeforeOf(t, replaced); !reflect.DeepEqual(before, []string{"DOMAIN,tracker.example,REJECT"}) {
		t.Fatalf("published again with another before: %v", before)
	}
	if _, err := finalizeWithRulesBeforeError(document, indexResources(t.TempDir()), []string{"DOMAIN,b.example,Nowhere"}, nil); err == nil ||
		!strings.Contains(err.Error(), "rules[0] [DOMAIN,b.example,Nowhere] error: proxy [Nowhere] not found") {
		t.Fatalf("a rule before naming no policy, no rules of its own: %v", err)
	}
}

func TestAConfigurationsOwnRuleIsRefusedAtItsPlaceAfterTheRulesBefore(t *testing.T) {
	document := "proxies:\n  - {name: P, type: direct}\nrules:\n  - DOMAIN,ok.example,P\n  - DOMAIN,x.example,Nowhere\n  - MATCH,P\n"
	before := []string{"DOMAIN,a.example,REJECT", "DOMAIN,b.example,REJECT", "DOMAIN,c.example,REJECT"}
	want := "rules[4] [DOMAIN,x.example,Nowhere] error: proxy [Nowhere] not found"
	if _, err := finalizeWithRulesBeforeError(document, indexResources(t.TempDir()), before, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("with an index: %v, want %q", err, want)
	}
	answer, err := finalizeWithRulesBeforeError(document, map[string]any{}, before, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse([]byte(answer.Text)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("without an index, the tunnel: %v, want %q", err, want)
	}
}

func TestAChangeOfTheRulesBeforeCompilesNothing(t *testing.T) {
	dir := t.TempDir()
	document := ruleIndexTestDocument(300)
	_, first := finalizeWithRulesBefore(t, document, indexResources(dir), moduleRulesForTest, nil)
	path, _ := rulesBeforeOf(t, first)
	was, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, before := range [][]string{nil, {}, {"DOMAIN,tracker.example,REJECT"}} {
		_, again := finalizeWithRulesBefore(t, document, indexResources(dir), before, nil)
		if again, _ := rulesBeforeOf(t, again); again != path {
			t.Fatalf("%v before: index %s, want %s", before, again, path)
		}
		is, err := os.Stat(path)
		if err != nil || !os.SameFile(was, is) {
			t.Fatalf("%v before: the index was written again (%v)", before, err)
		}
	}
}

func TestTheRulesPageFiltersARuleBeforeByTheTypeItWasWrittenAs(t *testing.T) {
	dir := t.TempDir()
	before := []string{"IP-CIDR6,2001:db8::/32,REJECT,no-resolve", "IP-CIDR,10.0.0.0/8,REJECT,src"}
	answer, _ := finalizeWithRulesBefore(t, sourceForRulesBefore, indexResources(dir), before, nil)
	cfg, err := parseAfterLookups(answer.Text)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		i    int
		tp   string
		want bool
	}{{0, "IP-CIDR6", true}, {0, "IP-CIDR", false}, {1, "IP-CIDR", true}, {1, "SRC-IP-CIDR", false}} {
		if got := writtenRuleTypeIn(cfg.RuleTable, c.i, map[string]bool{c.tp: true}); got != c.want {
			t.Errorf("rule %d as %s: %v, want %v", c.i, c.tp, got, c.want)
		}
	}
}

func TestASourcesRuleSummarySaysNothingOfRulesBefore(t *testing.T) {
	summary, err := RulesSummaryForIOS(sourceForRulesBefore)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary.Value, "prepended") {
		t.Fatalf("a source's summary names rules before: %s", summary.Value)
	}
}

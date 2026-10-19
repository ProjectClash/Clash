package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)

func TestAPublishedConfigurationsRulesAreReadFromItsIndex(t *testing.T) {
	source := "proxies:\n  - {name: P, type: direct}\nrules:\n" +
		"  - DOMAIN,Www.Example.com,P\n" +
		"  - UID,501,DIRECT\n" +
		"  - domain-suffix,example.org,DIRECT\n" +
		"  - IP-CIDR6,2001:db8::/32,P\n" +
		"  - 'DST-PORT,8443,DIRECT'\n" +
		"  - AND,((UID,0),(DOMAIN,b.example)),P\n" +
		"  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n" +
		"  - MATCH,P\n"
	dir := t.TempDir()
	published, _ := finalizeWithRuleIndex(t, source, dir)
	path := filepath.Join(dir, "published.yaml")
	if err := os.WriteFile(path, []byte(published), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	if catalog.Total() != 6 || catalog.UIDRemoved() != 2 {
		t.Fatalf("total %d, UID rules removed %d", catalog.Total(), catalog.UIDRemoved())
	}
	var summary ruleSummary
	if err := json.Unmarshal([]byte(catalog.SummaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	wantTypes := map[string]int{"DOMAIN": 1, "DOMAIN-SUFFIX": 1, "IP-CIDR6": 1, "DST-PORT": 1, "IP-CIDR": 1, "MATCH": 1}
	if summary.Total != 6 || summary.UIDRemoved != 2 || summary.IndexedTotal != 4 || summary.ObjectTotal != 2 || summary.MatchTarget != "P" || len(summary.ByType) != len(wantTypes) {
		t.Fatalf("summary %+v", summary)
	}
	for tp, n := range wantTypes {
		if summary.ByType[tp] != n {
			t.Fatalf("summary %+v", summary)
		}
	}

	cfg, err := parseAfterLookups(published)
	if err != nil {
		t.Fatal(err)
	}
	var page rulePage
	if err := json.Unmarshal([]byte(catalog.PageJSON(0, 0, "", "", "")), &page); err != nil || page.Total != 6 || page.Matched != 6 || len(page.Rules) != 6 {
		t.Fatalf("page: %v %+v", err, page)
	}
	for i, entry := range page.Rules {
		rule := cfg.RuleTable.At(i)
		tp, payload, target, _ := RC.ParseRulePayload(entry.Rule, true)
		if entry.Index != i || entry.Text != entry.Rule || entry.Type != tp || entry.Target != target || rule.Adapter() != target ||
			(rule.RuleType() != C.MATCH && rule.Payload() != payload) || !writtenRuleTypeIn(cfg.RuleTable, i, map[string]bool{tp: true}) {
			t.Errorf("rule %d: %+v; the tunnel's %s %s %s", i, entry, rule.RuleType(), rule.Payload(), rule.Adapter())
		}
	}
	if page.Rules[0].Rule != "DOMAIN,www.example.com,P" || page.Rules[2].Rule != "IP-CIDR6,2001:db8::/32,P" || page.Rules[3].Text != "DST-PORT,8443,DIRECT" {
		t.Errorf("lines: %+v", page.Rules)
	}

	for _, c := range []struct {
		query, target, types string
		want                 []int
	}{
		{"", "", `["IP-CIDR6","ip-cidr"]`, []int{2, 4}},
		{"", "P", `["DOMAIN","MATCH","DST-PORT"]`, []int{0, 5}},
		{"example", "", `["DOMAIN-SUFFIX"]`, []int{1}},
		{"", "", `[]`, []int{0, 1, 2, 3, 4, 5}},
	} {
		if err := json.Unmarshal([]byte(catalog.PageJSON(0, 0, c.query, c.target, c.types)), &page); err != nil || page.Matched != len(c.want) || len(page.Rules) != len(c.want) {
			t.Fatalf("%+v: %v %+v", c, err, page)
		}
		for k, i := range c.want {
			if page.Rules[k].Index != i {
				t.Fatalf("%+v: %+v", c, page)
			}
		}
	}
	if err := json.Unmarshal([]byte(catalog.PageJSON(0, 0, "", "", `DOMAIN`)), &page); err != nil || page.Error == "" || len(page.Rules) != 0 {
		t.Fatalf("a types list that does not read: %+v", page)
	}

	sourceCatalog, err := OpenRuleCatalogForIOS(source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceCatalog.Close()
	if err := json.Unmarshal([]byte(sourceCatalog.PageJSON(0, 0, "", "", `["UID","AND"]`)), &page); err != nil || page.Matched != 2 || page.Rules[0].Index != 1 || page.Rules[1].Index != 5 {
		t.Fatalf("source by type: %v %+v", err, page)
	}

	inline := filepath.Join(dir, "inline.yaml")
	if err := os.WriteFile(inline, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRuleCatalogForPublishedAtPath(inline); err == nil || !strings.Contains(err.Error(), ErrNoPublishedRuleIndex.Error()) {
		t.Fatalf("inline rules: %v", err)
	}
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if none, err := OpenRuleCatalogForPublishedAtPath(empty); err != nil || none.Total() != 0 || !strings.Contains(none.PageJSON(0, 0, "", "", ""), `"total":0`) {
		t.Fatalf("no rules: %v", err)
	}
	catalog.Close()
	if catalog.Total() != 0 {
		t.Error("a closed catalog still reads")
	}
}

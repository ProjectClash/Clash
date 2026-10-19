package clash

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const ruleCatalogFixture = "mode: rule\nproxies:\n  - {name: 节点, type: direct}\n" +
	"rules:\n" +
	"  - DOMAIN,a.example,节点\n" +
	"  - 'DOMAIN-SUFFIX,b.example,DIRECT' # quoted\n" +
	"  # a comment between rules\n" +
	"  - \"DOMAIN-KEYWORD,Ads,REJECT\"\n" +
	"  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n" +
	"  - IP-CIDR,192.168.0.0/16,DIRECT,src\n" +
	"  - RULE-SET,set1,DIRECT\n" +
	"  - SUB-RULE,(NETWORK,tcp),s1\n" +
	"  - MATCH,节点\n" +
	"rule-providers: {}\n"

func decodedRules(t *testing.T, text string) []string {
	t.Helper()
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return doc.Rules
}

func TestTheRuleCatalogCountsAndPagesTheRules(t *testing.T) {
	c, err := OpenRuleCatalogForIOS(ruleCatalogFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var summary ruleSummary
	if err := json.Unmarshal([]byte(c.SummaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Total != 8 || summary.IndexedTotal != 4 || summary.ObjectTotal != 4 || summary.ByType["IP-CIDR"] != 2 ||
		summary.ByTarget["节点"] != 2 || summary.MatchTarget != "节点" || fmt.Sprint(summary.RuleSets) != "[set1]" || fmt.Sprint(summary.SubRules) != "[s1]" {
		t.Fatalf("%+v", summary)
	}
	var page rulePage
	if err := json.Unmarshal([]byte(c.PageJSON(0, 0, "ads", "", "")), &page); err != nil {
		t.Fatal(err)
	}
	if page.Matched != 1 || len(page.Rules) != 1 || page.Rules[0].Index != 2 || page.Rules[0].Text != `"DOMAIN-KEYWORD,Ads,REJECT"` ||
		page.Rules[0].Rule != "DOMAIN-KEYWORD,Ads,REJECT" || page.Rules[0].Type != "DOMAIN-KEYWORD" || page.Rules[0].Target != "REJECT" {
		t.Fatalf("query: %+v", page)
	}
	if err := json.Unmarshal([]byte(c.PageJSON(1, 2, "", "DIRECT", "")), &page); err != nil {
		t.Fatal(err)
	}
	if page.Matched != 4 || len(page.Rules) != 2 || page.Rules[0].Index != 3 || page.Rules[1].Index != 4 {
		t.Fatalf("target: %+v", page)
	}
	for _, refused := range []string{"rules:\n  - &a DOMAIN,a,b\n", "rules:\n  - [a]\n", "rules: &l\n  - a\nx: *l\n"} {
		if _, err := OpenRuleCatalogForIOS(refused); err == nil {
			t.Errorf("opened %q", refused)
		}
	}
}

func TestRuleEditsAreTheOpsAndNothingElse(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	plainOrQuoted := func(s string) string {
		var back []string
		if yaml.Unmarshal([]byte("- "+s+"\n"), &back) == nil && len(back) == 1 && back[0] == s {
			return s
		}
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	styles := []func(string) string{
		plainOrQuoted,
		func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" },
		func(s string) string { b, _ := json.Marshal(s); return string(b) },
	}
	rule := func() string {
		return []string{"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "MATCH", "DOMAIN-KEYWORD"}[rnd.Intn(5)] + "," +
			[]string{"a.example", "b'c", "例子.中国", "10.0.0.0/8", "x: y", "#not", "- dash"}[rnd.Intn(7)] + "," +
			[]string{"DIRECT", "节点", "P 1"}[rnd.Intn(3)]
	}
	for round := 0; round < 400; round++ {
		head := "mode: rule\nproxies: []\n"
		indent := []string{"  - ", "    -   ", "- "}[rnd.Intn(3)]
		n := rnd.Intn(6)
		var b strings.Builder
		b.WriteString(head + "rules:\n")
		var want []string
		for i := 0; i < n; i++ {
			r := rule()
			want = append(want, r)
			b.WriteString(indent + styles[rnd.Intn(3)](r))
			if rnd.Intn(4) == 0 {
				b.WriteString(" # c")
			}
			b.WriteString("\n")
			if rnd.Intn(5) == 0 {
				b.WriteString(strings.Repeat(" ", len(indent)-2) + "# between\n")
			}
		}
		tail := "dns: {enable: false}\n"
		b.WriteString(tail)
		text := b.String()
		if got := decodedRules(t, text); fmt.Sprint(got) != fmt.Sprint(want) && n > 0 {
			t.Fatalf("fixture: %q vs %q\n%s", got, want, text)
		}
		var ops []ruleEditOp
		expected := append([]string(nil), want...)
		for k := 0; k < 1+rnd.Intn(4); k++ {
			switch op := rnd.Intn(4); {
			case op == 0 || len(expected) == 0:
				at, r := rnd.Intn(len(expected)+1), rule()
				ops = append(ops, ruleEditOp{Op: "insert", Index: at, Rule: r})
				expected = append(expected[:at], append([]string{r}, expected[at:]...)...)
			case op == 1:
				at, r := rnd.Intn(len(expected)), rule()
				ops = append(ops, ruleEditOp{Op: "replace", Index: at, Rule: r})
				expected[at] = r
			case op == 2:
				at := rnd.Intn(len(expected))
				ops = append(ops, ruleEditOp{Op: "delete", Index: at})
				expected = append(expected[:at], expected[at+1:]...)
			default:
				from, to := rnd.Intn(len(expected)), rnd.Intn(len(expected))
				ops = append(ops, ruleEditOp{Op: "move", Index: from, To: to})
				moved := expected[from]
				expected = append(expected[:from], expected[from+1:]...)
				expected = append(expected[:to], append([]string{moved}, expected[to:]...)...)
			}
		}
		opsJSON, _ := json.Marshal(ops)
		edit, err := EditRulesForIOS(text, string(opsJSON))
		if n == 0 && err != nil {
			continue
		}
		if err != nil {
			t.Fatalf("round %d: %v\n%s\n%s", round, err, opsJSON, text)
		}
		if got := decodedRules(t, edit.Text); fmt.Sprint(got) != fmt.Sprint(expected) {
			t.Fatalf("round %d: rules %q, want %q\nops %s\nbefore:\n%s\nafter:\n%s", round, got, expected, opsJSON, text, edit.Text)
		}
		if int(edit.Total) != len(expected) || !strings.HasPrefix(edit.Text, head+"rules:\n") || !strings.HasSuffix(edit.Text, tail) {
			t.Fatalf("round %d: the text outside the rules changed or the total is wrong (%d):\n%s", round, edit.Total, edit.Text)
		}
	}
}

func TestARuleReplacedKeepsItsQuotes(t *testing.T) {
	edit, err := EditRulesForIOS(ruleCatalogFixture, `[{"op":"replace","index":1,"rule":"DOMAIN-SUFFIX,c.example,DIRECT"}]`)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(ruleCatalogFixture, "'DOMAIN-SUFFIX,b.example,DIRECT'", "'DOMAIN-SUFFIX,c.example,DIRECT'", 1)
	if edit.Text != want || edit.FirstChangedIndex != 1 || edit.Total != 8 {
		t.Fatalf("%d %d\n%s", edit.FirstChangedIndex, edit.Total, edit.Text)
	}
	if _, err := EditRulesForIOS("rules: [a, b]\n", `[{"op":"delete","index":0}]`); err == nil {
		t.Fatal("a flow sequence edited item by item")
	}
	added, err := EditRulesForIOS("mode: rule\n", `[{"op":"insert","index":0,"rule":"MATCH,DIRECT"}]`)
	if err != nil || fmt.Sprint(decodedRules(t, added.Text)) != "[MATCH,DIRECT]" || !strings.HasPrefix(added.Text, "mode: rule\n") {
		t.Fatalf("%v %q", err, added)
	}
}

func TestTheRuleCatalogOfAFileIsTheCatalogOfItsText(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/source.yaml"
	if err := os.WriteFile(path, []byte(ruleCatalogFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	fromText, err := OpenRuleCatalogForIOS(ruleCatalogFixture)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := OpenRuleCatalogForIOSAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if fromText.SummaryJSON() != fromFile.SummaryJSON() || fromText.PageJSON(1, 3, "", "DIRECT", "") != fromFile.PageJSON(1, 3, "", "DIRECT", "") {
		t.Fatal("the file's catalog differs")
	}
	fromFile.Close()
	fromFile.Close()
	if summary, err := RulesSummaryForIOSAtPath(path); err != nil || summary.Value != fromText.SummaryJSON() {
		t.Fatalf("%v", err)
	}
	ops := `[{"op":"move","index":0,"to":7},{"op":"insert","index":2,"rule":"DOMAIN,x.example,DIRECT"}]`
	want, err := EditRulesForIOS(ruleCatalogFixture, ops)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := EditRulesForIOSAtPath(path, path, ops)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != want.Text || edit.Text != "" || edit.Total != want.Total || edit.FirstChangedIndex != want.FirstChangedIndex {
		t.Fatalf("written:\n%s\nwant:\n%s", got, want.Text)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files left", len(entries))
	}
}

func TestARuleCatalogClosedWhileReadIsNotReadAfter(t *testing.T) {
	path := t.TempDir() + "/source.yaml"
	if err := os.WriteFile(path, []byte(ruleCatalogFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 50; round++ {
		c, err := OpenRuleCatalogForIOSAtPath(path)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		for g := 0; g < 4; g++ {
			go func() {
				defer func() { done <- struct{}{} }()
				for k := 0; k < 20; k++ {
					_ = c.PageJSON(0, 5, "a", "", "")
					_ = c.SummaryJSON()
				}
			}()
		}
		c.Close()
		for g := 0; g < 4; g++ {
			<-done
		}
	}
}

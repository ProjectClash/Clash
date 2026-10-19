package clash

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAnIndexReferenceWithANonStringKeyIsStillAReference(t *testing.T) {
	setupForMatch(t)
	_, root := finalizeWithRuleIndex(t, "rules: ['MATCH,REJECT']\n", t.TempDir())
	ref := root["x-clash-rule-index"].(map[string]any)
	source := fmt.Sprintf("x-clash-rule-index: {path: %q, sha256: %q, 1: ignored}\n", ref["path"], ref["sha256"])
	if got := runMatch(t, source, "", `{"host":"a.test"}`); got.Policy != "REJECT" {
		t.Fatalf("the index answers REJECT; matched %+v", got)
	}
	if err := os.Remove(ref["path"].(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := MatchRuleForIOS(source, "", `{"host":"a.test"}`); err == nil {
		t.Error("offline matching answered without the index it names")
	}
	if _, err := ConfigDeviationsJSON(source, RuntimeProfileIOSPacketTunnel); err == nil {
		t.Error("the deviation report was issued without the index the document names")
	}
}

func TestARuleAfterABlockScalarAtTheEndKeepsThatScalarsValue(t *testing.T) {
	for _, header := range []string{"|", ">", "|+", ">+", "|2", "|2+", "|+2", "|-", ">2-"} {
		for _, end := range []string{"", "\r"} {
			source := "rules:\n  - " + header + "\n    DOMAIN,a.example,DIRECT" + end
			ruleAfterScalarKeepsItsValue(t, header, source)
		}
	}
}

func ruleAfterScalarKeepsItsValue(t *testing.T, header, source string) {
	t.Helper()
	before := decodedRules(t, source)
	for _, ops := range []string{
		`[{"op":"insert","index":1,"rule":"MATCH,REJECT"}]`,
		`[{"op":"insert","index":0,"rule":"MATCH,REJECT"},{"op":"move","index":1,"to":0}]`,
	} {
		got, err := EditRulesForIOS(source, ops)
		if err != nil {
			t.Fatalf("%s %s: %v", header, ops, err)
		}
		after := decodedRules(t, got.Text)
		if len(after) != 2 || after[0] != before[0] {
			t.Fatalf("%s %q %s: rules %q, want %q first and unchanged\n%s", header, source, ops, after, before[0], got.Text)
		}
	}
}

func TestAStrippingHeaderAtTheEndKeepsItsBytes(t *testing.T) {
	for _, header := range []string{"|-2 # c", ">-2", "|2-", "|-"} {
		source := "rules:\n  - " + header + "\n    DOMAIN,a.example,DIRECT"
		got, err := EditRulesForIOS(source, `[{"op":"insert","index":1,"rule":"MATCH,REJECT"}]`)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(got.Text, source+"\n") {
			t.Fatalf("%s: the untouched rule's bytes changed:\n%q", header, got.Text)
		}
	}
}

func TestTheEditorsCatalogRefusesAPublishedConfiguration(t *testing.T) {
	setupForMatch(t)
	published, _ := finalizeWithRuleIndex(t, "rules: ['DOMAIN,a.test,DIRECT', 'MATCH,REJECT']\n", t.TempDir())
	if _, err := OpenRuleCatalogForIOS(published); err != ErrRuleCatalogIsPublished {
		t.Fatalf("opened a published configuration: %v", err)
	}
	if _, err := EditRulesForIOS(published, `[{"op":"insert","index":0,"rule":"MATCH,DIRECT"}]`); err == nil {
		t.Fatal("edited a published configuration")
	}
}

func TestACompileCheckPlacesAFailingIndexedRule(t *testing.T) {
	setupForMatch(t)
	published, _ := finalizeWithRuleIndex(t, "rule-providers:\n  set: {type: inline, behavior: domain, payload: [a.test]}\n"+
		"rules: ['UID,501,DIRECT', 'DOMAIN,b.test,DIRECT', 'RULE-SET,set,DIRECT', 'MATCH,DIRECT']\n", t.TempDir())
	var root map[string]any
	if err := yaml.Unmarshal([]byte(published), &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root["rules"]; ok {
		t.Fatal("the published configuration still writes its rules")
	}
	delete(root, "rule-providers")
	broken, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	answer := runCompileCheck(t, string(broken))
	if answer.OK || len(answer.Errors) == 0 {
		t.Fatalf("the check passed without the rule set: %+v", answer)
	}
	got := answer.Errors[0]
	if got.Section != "rules" || got.Index == nil || *got.Index != 2 {
		t.Fatalf("placed %+v (index %v), want rules index 2: %s", got, got.Index, got.Message)
	}
}

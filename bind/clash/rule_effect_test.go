package clash

import (
	"strings"
	"testing"
)

func TestOwnerMetadataRuleEffectIsComputedPerRuleNotPerKind(t *testing.T) {
	for name, testCase := range map[string]struct {
		rule string
		want string
	}{
		"plain name never fires":        {"PROCESS-NAME,curl,REJECT", RuleEffectNeverMatches},
		"plain path never fires":        {"PROCESS-PATH,/usr/bin/curl,REJECT", RuleEffectNeverMatches},
		"in-user never fires":           {"IN-USER,alice,REJECT", RuleEffectNeverMatches},
		"source-app never fires":        {"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT", RuleEffectNeverMatches},
		"anchored wildcard never fires": {"PROCESS-NAME-WILDCARD,cur*,REJECT", RuleEffectNeverMatches},
		"anchored regex never fires":    {"PROCESS-NAME-REGEX,^curl$,REJECT", RuleEffectNeverMatches},

		"open regex fires on everything":           {"PROCESS-NAME-REGEX,.*,REJECT", RuleEffectMatchesEverything},
		"open wildcard fires on everything":        {"PROCESS-NAME-WILDCARD,*,REJECT", RuleEffectMatchesEverything},
		"fully optional regex fires on everything": {"PROCESS-PATH-REGEX,(curl)?,REJECT", RuleEffectMatchesEverything},
		"partially optional regex never fires":     {"PROCESS-PATH-REGEX,.*curl?,REJECT", RuleEffectNeverMatches},

		"not an owner-metadata rule": {"DOMAIN-SUFFIX,example.com,DIRECT", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ownerMetadataRuleEffect(testCase.rule); got != testCase.want {
				t.Errorf("effect of %q = %q, want %q", testCase.rule, got, testCase.want)
			}
		})
	}
}

func TestAnOpenPatternIsNamedIndividuallyWithItsEffect(t *testing.T) {
	const document = `
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-NAME-REGEX,.*,DIRECT
  - DOMAIN-SUFFIX,bank.example,REJECT
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	var open, inert *configDeviation
	for index := range deviations {
		switch deviations[index].Effect {
		case RuleEffectMatchesEverything:
			open = &deviations[index]
		case RuleEffectNeverMatches:
			inert = &deviations[index]
		}
	}
	if open == nil {
		t.Fatal("a rule that bypasses every connection is not reported with an effect; the " +
			"reader wrote it to single out one process and DIRECT is still attached to it")
	}
	if open.Field != "rules[1]" {
		t.Errorf("the dangerous rule is reported as %q, not by its position; a reader cannot "+
			"find it in their file", open.Field)
	}
	if !strings.Contains(open.Given, "PROCESS-NAME-REGEX") {
		t.Errorf("given = %q, want the rule text so the reader can match it against their file", open.Given)
	}
	if open.Alternative == "" {
		t.Error("the dangerous rule offers no way out; anchoring the pattern is one")
	}

	if inert == nil {
		t.Fatal("the inert rule is not reported at all")
	}
	if strings.HasPrefix(inert.Field, "rules[") {
		t.Errorf("inert rules are named individually (%q); at scale that buries the dangerous "+
			"one, which is the only reason this asymmetry exists", inert.Field)
	}
}

func TestEffectIsASeparateFieldAndCategoryStaysKnown(t *testing.T) {
	const document = `
rules:
  - PROCESS-NAME-REGEX,.*,DIRECT
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	known := map[string]bool{
		deviationStripped: true, deviationForced: true, deviationUnavailable: true,
	}
	for _, deviation := range deviations {
		if !known[deviation.Category] {
			t.Errorf("%s carries category %q, which no shipped decoder knows; that row is "+
				"dropped on the far side and nobody is told", deviation.Field, deviation.Category)
		}
	}
}

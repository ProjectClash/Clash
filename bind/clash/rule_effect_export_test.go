package clash

import "testing"

func TestRuleEffectForIOSAnswersWithoutSetupOrARunningCore(t *testing.T) {
	for rule, want := range map[string]string{
		"PROCESS-NAME,curl,REJECT":          RuleEffectNeverMatches,
		"IN-USER,alice,REJECT":              RuleEffectNeverMatches,
		"PROCESS-NAME-WILDCARD,cur*,DIRECT": RuleEffectNeverMatches,
		"PROCESS-NAME-REGEX,.*,DIRECT":      RuleEffectMatchesEverything,
		"PROCESS-NAME-WILDCARD,*,REJECT":    RuleEffectMatchesEverything,
		"DOMAIN-SUFFIX,example.com,DIRECT":  "",
		"MATCH,DIRECT":                      "",
	} {
		if got := RuleEffectForIOS(rule); got != want {
			t.Errorf("RuleEffectForIOS(%q) = %q, want %q", rule, got, want)
		}
	}
}

func TestTheEmptyAnswerIsNotAClaimOfSafety(t *testing.T) {
	logic := "OR,((PROCESS-NAME-REGEX,.*),(DOMAIN-SUFFIX,bank.example)),REJECT"
	if got := RuleEffectForIOS(logic); got != "" {
		t.Fatalf("a logic rule was classified as %q; its branches are separate questions and "+
			"this function does not walk them", got)
	}
}

func TestUIDAnswersEmptyBecauseItIsRemovedNotBecauseItIsOrdinary(t *testing.T) {
	for _, rule := range []string{"UID,1000,DIRECT", "UID,0,REJECT"} {
		if got := RuleEffectForIOS(rule); got != "" {
			t.Errorf("RuleEffectForIOS(%q) = %q; UID is removed on this platform, so there is no "+
				"traffic effect to state. If this is ever changed to report something, the "+
				"consuming lane's mapping of \"\" to inapplicable has to change with it", rule, got)
		}
	}
	if RuleEffectForIOS("DOMAIN-SUFFIX,example.com,DIRECT") != "" {
		t.Fatal("an ordinary rule stopped answering empty; the documented ambiguity between " +
			"\"removed\" and \"not an owner-metadata rule\" was the basis for telling consumers " +
			"to gate on the profile first")
	}
}

package config

import (
	"testing"

	RW "github.com/ProjectClash/Clash/rules/wrapper"
)

func TestARuleWithNotificationTextIsANotifyingRule(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("rules:\n  - DOMAIN-SUFFIX,example.com,DIRECT,notification-text=Example matched,notification-interval=600\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Rules[0].(*RW.NotifyingRule); !ok {
		t.Fatalf("the rule is %T, want a notifying rule", cfg.Rules[0])
	}
	if _, ok := cfg.Rules[1].(*RW.NotifyingRule); ok {
		t.Fatal("a rule without notification-text notifies")
	}
	if cfg.Rules[0].Payload() != "example.com" || cfg.Rules[0].Adapter() != "DIRECT" {
		t.Fatalf("the rule reads %s -> %s", cfg.Rules[0].Payload(), cfg.Rules[0].Adapter())
	}
}

func TestANotifyingRuleSurvivesTheIndexAndTheEveryModeList(t *testing.T) {
	path, sum := compileRuleIndex(t, t.TempDir(), []string{"DOMAIN-SUFFIX,watched.example,DIRECT,notification-text=Watched", "MATCH,DIRECT"}, knownTarget)
	cfg, err := Parse([]byte(ruleIndexTestHead + "x-clash-rule-index:\n  path: " + path + "\n  sha256: " + sum + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if notifying, ok := cfg.RuleTable.At(0).(*RW.NotifyingRule); !ok || notifying.WrittenLine() != "DOMAIN-SUFFIX,watched.example" {
		t.Fatalf("the indexed rule is %T, want a notifying rule", cfg.RuleTable.At(0))
	}
	raw, err := UnmarshalRawConfig([]byte("x-clash-every-mode-rules:\n  - DOMAIN,a.example,DIRECT,notification-text=Hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.ClashRouting.EveryModeRules[0].(*RW.NotifyingRule); !ok {
		t.Fatalf("the every-mode rule is %T, want a notifying rule", cfg.ClashRouting.EveryModeRules[0])
	}
}

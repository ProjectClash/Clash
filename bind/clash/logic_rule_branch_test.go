package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestLogicRuleKeepsExecutableBranches(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - OR,((PROCESS-NAME,evil),(DOMAIN-SUFFIX,bank.example)),REJECT
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(mihomo.Rules) != 2 {
		t.Fatalf("fixture is wrong, not the code: mihomo parsed %d rules, want 2", len(mihomo.Rules))
	}
	if len(ours.Rules) != len(mihomo.Rules) {
		t.Errorf("rule count: mihomo %d, ours %d -- the OR rule was dropped whole", len(mihomo.Rules), len(ours.Rules))
	}
	for index := range mihomo.Rules {
		if index >= len(ours.Rules) {
			t.Errorf("rules[%d]: mihomo has %q, ours has nothing", index, mihomo.Rules[index].Payload())
			continue
		}
		if mihomo.Rules[index].RuleType() != ours.Rules[index].RuleType() {
			t.Errorf("rules[%d] type: mihomo %v, ours %v", index, mihomo.Rules[index].RuleType(), ours.Rules[index].RuleType())
		}
	}
}

func TestSubRuleDispatchSurvivesUnresolvableBranch(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - SUB-RULE,(OR,((PROCESS-NAME,evil),(NETWORK,TCP))),private
  - MATCH,DIRECT
sub-rules:
  private:
    - DOMAIN-SUFFIX,internal.example,REJECT
    - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(ours.Rules) != len(mihomo.Rules) {
		t.Errorf("rule count: mihomo %d, ours %d -- the SUB-RULE dispatch was dropped, orphaning the group",
			len(mihomo.Rules), len(ours.Rules))
	}
}

func TestAlwaysTrueOwnerMetadataShapesAreKeptLikeUpstream(t *testing.T) {
	for name, rule := range map[string]string{
		"process name regex":    `PROCESS-NAME-REGEX,.*,REJECT`,
		"process name wildcard": `PROCESS-NAME-WILDCARD,*,REJECT`,
	} {
		t.Run(name, func(t *testing.T) {
			document := "proxies: []\nproxy-groups: []\nrules:\n  - " + rule + "\n  - MATCH,DIRECT\n"
			mihomo, ours := parseBoth(t, document)
			if len(ours.Rules) != len(mihomo.Rules) {
				t.Errorf("rule count: mihomo %d, ours %d", len(mihomo.Rules), len(ours.Rules))
			}
		})
	}
}

func TestEveryOccurrenceIsReportedNotDedupedByKind(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - PROCESS-NAME,first,REJECT
  - OR,((PROCESS-NAME,second),(DOMAIN-SUFFIX,bank.example)),REJECT
  - MATCH,DIRECT
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	occurrences := unavailableMetadataRuleOccurrences(raw, appleProcessMetadataCapability{})

	locations := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		locations = append(locations, occurrence.location)
	}
	if len(occurrences) < 2 {
		t.Errorf("only %d occurrence(s) reported for two distinct PROCESS-NAME rules: %v", len(occurrences), locations)
	}
	if !strings.Contains(strings.Join(locations, " "), "rules[1]") {
		t.Errorf("the logic rule at rules[1] is not reported; got %v", locations)
	}
}

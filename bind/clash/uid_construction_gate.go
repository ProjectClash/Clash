package clash

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ProjectClash/Clash/config"
)

func uidRuleConstructible(goos string) bool {
	switch goos {
	case "linux", "android", "darwin":
		return true
	default:
		return false
	}
}

var uidRuleToken = &lazyRegexp{expr: `(?i)(?:^|\()\s*UID\s*,`}

func ruleCarriesUID(rule string) bool {
	if strings.IndexByte(rule, '(') < 0 {
		comma := strings.IndexByte(rule, ',')
		return comma > 0 && strings.EqualFold(strings.TrimSpace(rule[:comma]), "UID")
	}
	return uidRuleToken.get().MatchString(rule)
}

func stripUnconstructibleUIDRules(raw *config.RawConfig) []metadataRuleOccurrence {
	removed := make([]metadataRuleOccurrence, 0)
	filter := func(rules []string, location func(int) string) []string {
		kept := make([]string, 0, len(rules))
		for index, rule := range rules {
			if ruleCarriesUID(rule) {
				removed = append(removed, metadataRuleOccurrence{kind: "UID", location: location(index)})
				continue
			}
			kept = append(kept, rule)
		}
		return kept
	}
	raw.Rule = filter(raw.Rule, func(index int) string { return fmt.Sprintf("rules[%d]", index) })
	names := make([]string, 0, len(raw.SubRules))
	for name := range raw.SubRules {
		names = append(names, name)
	}
	sort.Strings(names)
	for groupIndex, name := range names {
		raw.SubRules[name] = filter(raw.SubRules[name], func(ruleIndex int) string {
			return fmt.Sprintf("sub-rules[%d][%d]", groupIndex, ruleIndex)
		})
	}
	for _, definition := range raw.RuleProvider {
		typeName, _ := definition["type"].(string)
		behavior, _ := definition["behavior"].(string)
		if typeName != "inline" || behavior != "classical" {
			continue
		}
		if payload, ok := definition["payload"].([]any); ok {
			kept := make([]any, 0, len(payload))
			for _, item := range payload {
				if rule, isString := item.(string); isString && ruleCarriesUID(rule) {
					removed = append(removed, metadataRuleOccurrence{kind: "UID", location: "rule-providers payload"})
					continue
				}
				kept = append(kept, item)
			}
			definition["payload"] = kept
		}
	}
	return removed
}

const uidRuleExplanation = "UID names a socket owner this platform does not expose, and mihomo's own " +
	"rule constructor refuses to build it here (rules/common/uid.go), so the rule is removed " +
	"rather than allowed to fail the whole configuration"

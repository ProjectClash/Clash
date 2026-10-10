package clash

import (
	"regexp"
	"strings"

	"github.com/ProjectClash/Clash/component/wildcard"
)

const (
	RuleEffectNeverMatches      = "never-matches"
	RuleEffectMatchesEverything = "matches-everything"
	EffectListenerOpened        = "listener-opened"
)

func RuleEffectForIOS(rule string) string {
	return bridgeSafeString(recoverAppCallValue("RuleEffectForIOS", func() string { return ruleEffectForIOSUnguarded(rule) }))
}

func ruleEffectForIOSUnguarded(rule string) string {
	return bridgeSafeString(ownerMetadataRuleEffect(rule))
}

func ownerMetadataRuleEffect(rule string) string {
	kind, pattern := splitRuleKindAndPattern(rule)
	if kind == "" {
		return ""
	}
	switch strings.ToUpper(kind) {
	case "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return RuleEffectNeverMatches
		}
		if compiled.MatchString("") {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD":
		if wildcard.Match(strings.ToLower(pattern), "") {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "PROCESS-NAME", "PROCESS-PATH":
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "IN-USER":
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	default:
		return ""
	}
}

func splitRuleKindAndPattern(rule string) (string, string) {
	rule = strings.TrimSpace(rule)
	if strings.HasPrefix(rule, "(") {
		rule = strings.TrimPrefix(rule, "(")
	}
	firstComma := strings.IndexByte(rule, ',')
	if firstComma < 0 {
		return "", ""
	}
	kind := strings.TrimSpace(rule[:firstComma])
	rest := rule[firstComma+1:]
	if secondComma := strings.IndexByte(rest, ','); secondComma >= 0 {
		return kind, strings.TrimSpace(rest[:secondComma])
	}
	return kind, strings.TrimSpace(strings.TrimSuffix(rest, ")"))
}

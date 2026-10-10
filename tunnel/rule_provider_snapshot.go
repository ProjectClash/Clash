package tunnel

import (
	P "github.com/ProjectClash/Clash/constant/provider"
	"maps"
)

func SnapshotRuleProviders() map[string]P.RuleProvider {
	return maps.Clone(loadRuleProviders())
}

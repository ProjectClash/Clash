package clash

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const moduleRuleProviderField = "x-clash-module"

func addModuleRuleProviders(root map[string]any, added map[string]json.RawMessage) error {
	if added == nil {
		return nil
	}
	providers, isMap := root["rule-providers"].(map[string]any)
	if !isMap && root["rule-providers"] != nil {
		return fmt.Errorf("ruleProviders: the configuration's rule-providers is not a mapping")
	}
	for name, raw := range providers {
		if definition, _ := raw.(map[string]any); definition[moduleRuleProviderField] == true {
			delete(providers, name)
		}
	}
	if len(added) == 0 {
		return nil
	}
	if providers == nil {
		providers = map[string]any{}
		root["rule-providers"] = providers
	}
	names := make([]string, 0, len(added))
	for name := range added {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("ruleProviders: a rule provider has no name")
		}
		if _, taken := providers[name]; taken {
			return fmt.Errorf("ruleProviders[%s]: the configuration has a rule provider of that name", name)
		}
		var definition map[string]any
		if err := yaml.Unmarshal(added[name], &definition); err != nil || definition == nil {
			return fmt.Errorf("ruleProviders[%s]: not a rule provider definition", name)
		}
		definition[moduleRuleProviderField] = true
		providers[name] = definition
	}
	return nil
}

func moduleRuleSetNames(names ruleNames, root map[string]any, ruleProviders map[string]json.RawMessage) {
	if ruleProviders == nil {
		return
	}
	providers, _ := root["rule-providers"].(map[string]any)
	for name := range names.ruleSets {
		if _, ok := providers[name]; !ok {
			delete(names.ruleSets, name)
		}
	}
	for name := range ruleProviders {
		names.ruleSets[name] = struct{}{}
	}
}

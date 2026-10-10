package clash

import (
	"encoding/json"
	"testing"
)

func catalogRuleProvidersCompiling(t *testing.T, config, resourceMap string, compile bool) (map[string]map[string]any, map[string]string) {
	t.Helper()
	box, err := RuleProviderCatalogForIOS(config, resourceMap, compile)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Providers      map[string]map[string]any `json:"providers"`
		ProviderErrors map[string]string         `json:"providerErrors"`
	}
	if err := json.Unmarshal([]byte(box.Value), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Providers, decoded.ProviderErrors
}

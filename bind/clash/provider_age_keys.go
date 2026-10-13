package clash

import (
	"fmt"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

func ProviderAgeSecretKeysJSON(configContent string) (string, error) {
	out, err := recoverAppCall("ProviderAgeSecretKeysJSON", func() (string, error) {
		var document struct {
			ProxyProviders map[string]any `yaml:"proxy-providers"`
		}
		skip := yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(struct{}{})}
		if err := yaml.ClashUnmarshal([]byte(configContent), &document, skip, nil); err != nil {
			return "", fmt.Errorf("clash: parse config: %w", err)
		}
		root := map[string]any{"proxy-providers": document.ProxyProviders}
		canonicalizeProviderDefinitionKeysInDocument(root)
		keys := map[string]string{}
		providers, _ := root["proxy-providers"].(map[string]any)
		for name, value := range providers {
			definition, ok := value.(map[string]any)
			if !ok {
				continue
			}
			kind, _ := definition["type"].(string)
			key, _ := definition["age-secret-key"].(string)
			if strings.EqualFold(kind, "http") && key != "" {
				keys["proxy:"+name] = key
			}
		}
		return mustJSON(keys), nil
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

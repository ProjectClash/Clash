package clash

import (
	"fmt"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

func ProviderAgeSecretKeysJSON(configContent string) (string, error) {
	out, err := recoverAppCall("ProviderAgeSecretKeysJSON", func() (string, error) { return providerAgeSecretKeysJSON(configContent) })
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func ProviderAgeSecretKeysJSONAtPath(path string) (string, error) {
	out, err := recoverAppCall("ProviderAgeSecretKeysJSONAtPath", func() (string, error) {
		return withDocumentAt(path, func(text string) (string, error) { return providerAgeSecretKeysJSON(text) })
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func providerAgeSecretKeysJSON(configContent string) (string, error) {
	return withCompactHeap(func() (string, error) {
		var document struct {
			ProxyProviders map[string]any `yaml:"proxy-providers"`
		}
		skip := yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(struct{}{})}
		skipGroups := yaml.ClashSequence{Key: "proxy-groups", Item: reflect.TypeOf(struct{}{})}
		skipRules := yaml.ClashSequence{Key: "rules", Item: reflect.TypeOf(""), Discard: true}
		if err := yaml.ClashUnmarshalSequences(readOnlyBytes(configContent), &document, nil, skip, skipGroups, skipRules); err != nil {
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
}

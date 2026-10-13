package clash

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/ProjectClash/Clash/adapter"
	"go.yaml.in/yaml/v3"
)

func PolicyNamesJSON(configContent string) (string, error) {
	out, err := recoverAppCall("PolicyNamesJSON", func() (string, error) {
		text := configContent
		if cut, ok := withoutTopLevelSections(text, []string{"rules", "sub-rules", "rule-providers"}); ok {
			text = cut
		}
		document, err := decodePolicyNames(text)
		if err != nil && text != configContent {
			document, err = decodePolicyNames(configContent)
		}
		if err != nil {
			return "", fmt.Errorf("clash: parse config: %w", err)
		}
		answer := struct {
			Proxies   []string `json:"proxies"`
			Groups    []string `json:"groups"`
			Providers []string `json:"providers"`
		}{Proxies: []string{}, Groups: []string{}, Providers: []string{}}
		for _, node := range document.Proxies {
			if name, ok := adapter.ClashNodeName(node.Name); ok {
				answer.Proxies = append(answer.Proxies, name)
			}
		}
		for _, group := range document.Groups {
			if name, ok := adapter.ClashNodeName(group.Name); ok {
				answer.Groups = append(answer.Groups, name)
			}
		}
		for name := range document.Providers {
			answer.Providers = append(answer.Providers, name)
		}
		sort.Strings(answer.Providers)
		return mustJSON(answer), nil
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

type policyNamed struct {
	Name any
}

func (p *policyNamed) UnmarshalYAML(node *yaml.Node) error {
	var mapping map[string]any
	if err := node.Decode(&mapping); err != nil {
		return err
	}
	if name, ok := adapter.ClashMappingNodeName(mapping); ok {
		p.Name = name
	}
	return nil
}

type policyGroupNamed struct {
	Name any `yaml:"name"`
}

type policyNamesDocument struct {
	Proxies   []policyNamed      `yaml:"proxies"`
	Groups    []policyGroupNamed `yaml:"proxy-groups"`
	Providers map[string]any     `yaml:"proxy-providers"`
}

func decodePolicyNames(text string) (policyNamesDocument, error) {
	var document policyNamesDocument
	err := yaml.ClashUnmarshal([]byte(text), &document, yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(policyNamed{})}, nil)
	return document, err
}

package clash

import (
	"encoding/json"

	"go.yaml.in/yaml/v3"
)

type overrideSpec struct {
	Patch        map[string]any `json:"patch"`
	AppendRules  []string       `json:"appendRules"`
	PrependRules bool           `json:"prependRules"`
}

func MergeOverrideForIOS(rawYAML string, overrideJSON string) (*StringBox, error) {
	out, err := recoverAppCall("MergeOverrideForIOS", func() (*StringBox, error) { return mergeOverrideForIOSUnguarded(rawYAML, overrideJSON) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func mergeOverrideForIOSUnguarded(rawYAML string, overrideJSON string) (*StringBox, error) {
	merged, err := mergeOverrideDocument(rawYAML, nil, overrideJSON)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(merged.text), nil
}

func mergeOverrideDocument(rawYAML string, raw *yaml.Node, overrideJSON string) (finalizedDocument, error) {
	if overrideJSON == "" {
		return finalizedDocument{text: rawYAML, document: raw}, nil
	}
	var spec overrideSpec
	if err := json.Unmarshal([]byte(overrideJSON), &spec); err != nil {
		return finalizedDocument{}, err
	}
	if raw == nil {
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(rawYAML), &document); err != nil {
			return finalizedDocument{}, err
		}
		raw = &document
	}
	var root map[string]any
	if len(raw.Content) > 0 {
		if err := raw.Decode(&root); err != nil {
			return finalizedDocument{}, err
		}
	}
	if root == nil {
		root = map[string]any{}
	}
	if spec.Patch != nil {
		deepMerge(root, spec.Patch)
	}
	if len(spec.AppendRules) > 0 {
		root["rules"] = mergeRules(root["rules"], spec.AppendRules, spec.PrependRules)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return finalizedDocument{}, err
	}
	references := []*yaml.Node{raw}
	var patch yaml.Node
	if err := yaml.Unmarshal([]byte(patchDocument(overrideJSON)), &patch); err == nil {
		references = append(references, &patch)
	}
	text, document := restoreKeyOrderFromDocuments(string(out), references)
	return finalizedDocument{text: text, document: document}, nil
}

func deepMerge(dst map[string]any, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

func mergeRules(existing any, add []string, prepend bool) []any {
	var base []any
	if list, ok := existing.([]any); ok {
		base = list
	}
	extra := make([]any, len(add))
	for i, r := range add {
		extra[i] = r
	}
	if prepend {
		return append(extra, base...)
	}
	return append(base, extra...)
}

func patchDocument(overrideJSON string) string {
	var envelope yaml.Node
	if err := yaml.Unmarshal([]byte(overrideJSON), &envelope); err != nil {
		return ""
	}
	if len(envelope.Content) == 0 || envelope.Content[0].Kind != yaml.MappingNode {
		return ""
	}
	root := envelope.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Kind == yaml.ScalarNode && root.Content[i].Value == "patch" {
			out, err := yaml.Marshal(root.Content[i+1])
			if err != nil {
				return ""
			}
			return string(out)
		}
	}
	return ""
}

package clash

import (
	"encoding/json"
	"errors"

	"go.yaml.in/yaml/v3"
)

func YAMLOutlineForIOS(original string) (*StringBox, error) {
	out, err := recoverAppCall("YAMLOutlineForIOS", func() (*StringBox, error) {
		return yamlOutlineForIOSUnguarded(original)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type yamlOutlineItem struct {
	Key   string `json:"key,omitempty"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type yamlOutlineSection struct {
	Key   string            `json:"key"`
	Kind  string            `json:"kind"`
	Start int               `json:"start"`
	End   int               `json:"end"`
	Items []yamlOutlineItem `json:"items,omitempty"`
}

type yamlOutlineAnswer struct {
	OK       bool                 `json:"ok"`
	Sections []yamlOutlineSection `json:"sections,omitempty"`
	Code     string               `json:"code,omitempty"`
	Message  string               `json:"message,omitempty"`
}

func yamlOutlineForIOSUnguarded(original string) (*StringBox, error) {
	answer, err := yamlOutline(original)
	if err != nil {
		var refusal *yamlEditError
		if !errors.As(err, &refusal) {
			refusal = refuseEdit("unsupportedStyle", "%v", err)
		}
		answer = yamlOutlineAnswer{Code: refusal.code, Message: refusal.message}
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func yamlOutline(original string) (yamlOutlineAnswer, error) {
	answer, _, err := yamlOutlineParsed(original)
	return answer, err
}

func yamlOutlineParsed(original string) (yamlOutlineAnswer, *yaml.Node, error) {
	document, refusal := parseYAMLForEdit(original)
	if refusal != nil {
		return yamlOutlineAnswer{}, nil, refusal
	}
	root := document.root
	spans, refusal := document.childSpans(root, len(document.lines)+1)
	if refusal != nil {
		return yamlOutlineAnswer{}, root, refusal
	}
	all := func(n int) []int {
		indices := make([]int, n)
		for i := range indices {
			indices[i] = i
		}
		return indices
	}
	if refusal := document.requireExact(root, spans, all(len(spans))...); refusal != nil {
		return yamlOutlineAnswer{}, root, refusal
	}
	answer := yamlOutlineAnswer{OK: true}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		span := spans[i/2]
		section := yamlOutlineSection{Key: key.Value, Kind: yamlNodeKind(value), Start: span.start, End: span.end}
		if (value.Kind == yaml.MappingNode || value.Kind == yaml.SequenceNode) && value.Style&yaml.FlowStyle == 0 &&
			value.Anchor == "" {
			children, refusal := document.childSpans(value, span.end+1)
			if refusal == nil {
				refusal = document.requireExact(value, children, all(len(children))...)
			}
			if refusal == nil {
				for j, child := range children {
					item := yamlOutlineItem{Start: child.start, End: child.end}
					if value.Kind == yaml.MappingNode {
						item.Key = value.Content[j*2].Value
					}
					section.Items = append(section.Items, item)
				}
			}
		}
		answer.Sections = append(answer.Sections, section)
	}
	return answer, root, nil
}

func yamlNodeKind(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.AliasNode:
		return "alias"
	}
	return "scalar"
}

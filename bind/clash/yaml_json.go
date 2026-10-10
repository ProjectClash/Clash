package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

func YamlToJSON(rawYAML string) (*StringBox, error) {
	out, err := recoverAppCall("YamlToJSON", func() (*StringBox, error) { return yamlToJSONUnguarded(rawYAML) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func yamlToJSONUnguarded(rawYAML string) (*StringBox, error) {
	decoder := yaml.NewDecoder(strings.NewReader(rawYAML))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: decode YAML: %w", err))
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("clash: YAML configuration root must be an object"))
	}

	payload, err := yamlRootToJSON(document.Content[0])
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(payload)), nil
}

func yamlRootToJSON(root *yaml.Node) ([]byte, error) {
	if walksAlone(root) {
		var payload bytes.Buffer
		if err := encodeYAMLNodeAsJSON(root, &payload); err == nil {
			return payload.Bytes(), nil
		}
	}

	var safety any
	if err := root.Decode(&safety); err != nil {
		return nil, fmt.Errorf("clash: reject unsafe YAML configuration: %w", err)
	}

	var payload bytes.Buffer
	if err := encodeYAMLNodeAsJSON(root, &payload); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func walksAlone(node *yaml.Node) bool {
	if node.Anchor != "" {
		return false
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Tag != "!!merge"
	case yaml.MappingNode:
		for index, child := range node.Content {
			if index%2 == 0 && (child.Kind != yaml.ScalarNode || child.Tag != "!!str") {
				return false
			}
			if !walksAlone(child) {
				return false
			}
		}
		return true
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if !walksAlone(child) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func encodeYAMLNodeAsJSON(node *yaml.Node, buf *bytes.Buffer) error {
	switch node.Kind {
	case yaml.AliasNode:
		return encodeYAMLNodeAsJSON(node.Alias, buf)
	case yaml.MappingNode:
		pairs, err := resolvedMappingPairs(node)
		if err != nil {
			return err
		}
		buf.WriteByte('{')
		for index, pair := range pairs {
			if index > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(pair.key)
			if err != nil {
				return err
			}
			buf.Write(key)
			buf.WriteByte(':')
			if err := encodeYAMLNodeAsJSON(pair.value, buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for index, item := range node.Content {
			if index > 0 {
				buf.WriteByte(',')
			}
			if err := encodeYAMLNodeAsJSON(item, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
			encoded, err := json.Marshal(node.Value)
			if err != nil {
				return fmt.Errorf("clash: encode YAML scalar as JSON: %w", err)
			}
			buf.Write(encoded)
			return nil
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return fmt.Errorf("clash: decode YAML scalar: %w", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("clash: encode YAML scalar as JSON: %w", err)
		}
		buf.Write(encoded)
		return nil
	}
}

type yamlMappingPair struct {
	key   string
	value *yaml.Node
}

func resolvedMappingPairs(node *yaml.Node) ([]yamlMappingPair, error) {
	explicit := make(map[string]bool)
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		if isMergeKey(key) {
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		if explicit[keyString] {
			return nil, fmt.Errorf("clash: duplicate YAML mapping key %q", keyString)
		}
		explicit[keyString] = true
	}
	seen := make(map[string]bool)
	pairs := make([]yamlMappingPair, 0, len(node.Content)/2)
	appendPair := func(key string, value *yaml.Node) {
		if seen[key] {
			return
		}
		seen[key] = true
		pairs = append(pairs, yamlMappingPair{key: key, value: value})
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if isMergeKey(key) {
			sources, err := mergeSources(value)
			if err != nil {
				return nil, err
			}
			for _, source := range sources {
				merged, err := resolvedMappingPairs(source)
				if err != nil {
					return nil, err
				}
				for _, pair := range merged {
					if explicit[pair.key] {
						continue
					}
					appendPair(pair.key, pair.value)
				}
			}
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		appendPair(keyString, value)
	}
	return pairs, nil
}

func mappingKeyString(key *yaml.Node) (string, error) {
	node := key
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return "", fmt.Errorf("clash: YAML alias key has no anchor")
		}
		node = node.Alias
	}
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("clash: YAML mapping key must be a scalar")
	}
	return node.Value, nil
}

func isMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Tag == "!!merge"
}

func mergeSources(value *yaml.Node) ([]*yaml.Node, error) {
	switch value.Kind {
	case yaml.AliasNode:
		if value.Alias == nil || value.Alias.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("clash: YAML merge key must reference a mapping")
		}
		return []*yaml.Node{value.Alias}, nil
	case yaml.MappingNode:
		return []*yaml.Node{value}, nil
	case yaml.SequenceNode:
		sources := make([]*yaml.Node, 0, len(value.Content))
		for _, item := range value.Content {
			resolved := item
			if resolved.Kind == yaml.AliasNode {
				resolved = resolved.Alias
			}
			if resolved == nil || resolved.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("clash: YAML merge key must reference a mapping")
			}
			sources = append(sources, resolved)
		}
		return sources, nil
	default:
		return nil, fmt.Errorf("clash: YAML merge key must reference a mapping")
	}
}

func JSONToYaml(rawJSON string) (*StringBox, error) {
	out, err := recoverAppCall("JSONToYaml", func() (*StringBox, error) { return jSONToYamlUnguarded(rawJSON) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func jSONToYamlUnguarded(rawJSON string) (*StringBox, error) {
	text, _, err := jsonDocumentAsYAML(rawJSON)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(text), nil
}

func encodeYAMLDocument(document *yaml.Node) (string, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return "", fmt.Errorf("clash: encode JSON configuration as YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("clash: finish YAML encoding: %w", err)
	}
	return output.String(), nil
}

const maximumJSONNestingDepth = 10000

func decodeJSONValueAsYAMLNode(decoder *json.Decoder, depth int) (*yaml.Node, error) {
	if depth > maximumJSONNestingDepth {
		return nil, fmt.Errorf("clash: JSON is nested deeper than %d levels", maximumJSONNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	return jsonTokenAsYAMLNode(token, decoder, depth)
}

func jsonTokenAsYAMLNode(token json.Token, decoder *json.Decoder, depth int) (*yaml.Node, error) {
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("clash: JSON object key must be a string")
				}
				if seen[key] {
					return nil, fmt.Errorf("clash: duplicate JSON object key %q", key)
				}
				seen[key] = true
				value, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
					value,
				)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return node, nil
		case '[':
			node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for decoder.More() {
				item, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return node, nil
		default:
			return nil, fmt.Errorf("clash: unexpected JSON delimiter %q", typed)
		}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: typed}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(typed.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: typed.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(typed)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	default:
		return nil, fmt.Errorf("clash: unsupported JSON value type %T", token)
	}
}

func jsonTextAsYAMLNode(text string) (node *yaml.Node, ok bool) {
	if !json.Valid([]byte(text)) {
		return nil, false
	}
	scan := jsonTextScan{text: text}
	return scan.value(0)
}

type jsonTextScan struct {
	text string
	at   int
}

func (s *jsonTextScan) space() {
	for s.at < len(s.text) {
		switch s.text[s.at] {
		case ' ', '\t', '\n', '\r':
			s.at++
		default:
			return
		}
	}
}

func (s *jsonTextScan) value(depth int) (*yaml.Node, bool) {
	if depth > maximumJSONNestingDepth {
		return nil, false
	}
	s.space()
	switch s.text[s.at] {
	case '{':
		s.at++
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		s.space()
		if s.text[s.at] == '}' {
			s.at++
			return node, true
		}
		seen := make(map[string]bool)
		for {
			s.space()
			key, ok := s.string()
			if !ok || seen[key] {
				return nil, false
			}
			seen[key] = true
			s.space()
			s.at++
			value, ok := s.value(depth + 1)
			if !ok {
				return nil, false
			}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
			s.space()
			if s.text[s.at] == ',' {
				s.at++
				continue
			}
			s.at++
			return node, true
		}
	case '[':
		s.at++
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		s.space()
		if s.text[s.at] == ']' {
			s.at++
			return node, true
		}
		for {
			item, ok := s.value(depth + 1)
			if !ok {
				return nil, false
			}
			node.Content = append(node.Content, item)
			s.space()
			if s.text[s.at] == ',' {
				s.at++
				continue
			}
			s.at++
			return node, true
		}
	case '"':
		value, ok := s.string()
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}, ok
	case 't':
		s.at += len("true")
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}, true
	case 'f':
		s.at += len("false")
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}, true
	case 'n':
		s.at += len("null")
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, true
	default:
		start := s.at
		for s.at < len(s.text) && strings.IndexByte("+-.0123456789Ee", s.text[s.at]) >= 0 {
			s.at++
		}
		literal := s.text[start:s.at]
		tag := "!!int"
		if strings.ContainsAny(literal, ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: literal}, true
	}
}

func (s *jsonTextScan) string() (string, bool) {
	start := s.at
	s.at++
	escaped := false
	for s.text[s.at] != '"' {
		if s.text[s.at] == '\\' {
			escaped = true
			s.at++
		}
		s.at++
	}
	s.at++
	literal := s.text[start:s.at]
	if !escaped && utf8.ValidString(literal) {
		return literal[1 : len(literal)-1], true
	}
	var value string
	if err := json.Unmarshal([]byte(literal), &value); err != nil {
		return "", false
	}
	return value, true
}

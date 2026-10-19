package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"go.yaml.in/yaml/v3"
)

func YamlToJSONOmitting(rawYAML, keysJSON string) (*StringBox, error) {
	out, err := recoverAppCall("YamlToJSONOmitting", func() (*StringBox, error) { return yamlToJSONOmitting(rawYAML, keysJSON) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func YamlToJSONOmittingAtPath(path, keysJSON string) (*StringBox, error) {
	out, err := recoverAppCall("YamlToJSONOmittingAtPath", func() (*StringBox, error) {
		return withDocumentAt(path, func(text string) (*StringBox, error) { return yamlToJSONOmitting(text, keysJSON) })
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func yamlToJSONOmitting(rawYAML, keysJSON string) (*StringBox, error) {
	return withCompactHeap(func() (*StringBox, error) {
		var keys []string
		if strings.TrimSpace(keysJSON) != "" {
			if err := json.Unmarshal([]byte(keysJSON), &keys); err != nil {
				return nil, fmt.Errorf("clash: keys to omit: %w", err)
			}
		}
		if cut, ok := withoutTopLevelSections(rawYAML, keys); ok {
			if answer, err := yamlToJSONUnguarded(cut); err == nil {
				return answer, nil
			}
		}
		answer, err := yamlToJSONUnguarded(rawYAML)
		if err != nil {
			return nil, err
		}
		return omitTopLevelJSONKeys(answer, keys)
	})
}

func withoutTopLevelSections(text string, keys []string) (string, bool) {
	if len(keys) == 0 || text == "" {
		return "", false
	}
	omit := map[string]bool{}
	for _, key := range keys {
		omit[key] = true
	}
	sections, ok := yaml.ClashTopLevelSections(unsafe.Slice(unsafe.StringData(text), len(text)))
	if !ok {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(text))
	b.WriteString(text[:sections[0].Start])
	cut := false
	for i, section := range sections {
		end := len(text)
		if i+1 < len(sections) {
			end = sections[i+1].Start
		}
		if !omit[section.Key] {
			b.WriteString(text[section.Start:end])
			continue
		}
		if section.Anchored || section.Aliased {
			return "", false
		}
		cut = true
	}
	return b.String(), cut
}

func omitTopLevelJSONKeys(answer *StringBox, keys []string) (*StringBox, error) {
	if answer == nil || len(keys) == 0 {
		return answer, nil
	}
	omit := map[string]bool{}
	for _, key := range keys {
		omit[key] = true
	}
	decoder := json.NewDecoder(strings.NewReader(answer.Value))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return answer, nil
	}
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if omit[key] {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		var encodedKey strings.Builder
		encoder := json.NewEncoder(&encodedKey)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(key); err != nil {
			return nil, err
		}
		b.WriteString(strings.TrimSuffix(encodedKey.String(), "\n"))
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return WrapString(b.String()), nil
}

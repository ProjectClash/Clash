package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/ProjectClash/Clash/component/age"
	"go.yaml.in/yaml/v3"
)

type DocumentHandle struct {
	mu    sync.Mutex
	state *documentHandleState
}

type documentHandleState struct {
	original     string
	originalRoot *yaml.Node
	text         string
	root         *yaml.Node
	exact        bool
	edit         *parsedYAML
}

func OpenDocumentForIOS(text string) (*DocumentHandle, error) {
	out, err := recoverAppCall("OpenDocumentForIOS", func() (*DocumentHandle, error) {
		if edit, refusal := parseYAMLForEdit(text); refusal == nil {
			return &DocumentHandle{state: &documentHandleState{
				original: text, originalRoot: edit.node, text: text, root: edit.node, exact: true,
				edit: &parsedYAML{
					text: text, root: edit.root, lines: edit.lines, final: edit.final, bom: edit.bom,
					editable: true, aliases: holdsAliases(edit.root),
				},
			}}, nil
		}
		root, err := readHandleDocument(text)
		if err != nil {
			return nil, err
		}
		return &DocumentHandle{state: &documentHandleState{
			original: text, originalRoot: root, text: text, root: root, exact: true,
		}}, nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func readHandleDocument(text string) (*yaml.Node, error) {
	if strings.HasPrefix(text, age.FileHeader) {
		return nil, errors.New("clash: document handle: the configuration is age-armoured")
	}
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("clash: document handle: decode YAML: %w", err)
	}
	var second yaml.Node
	if err := decoder.Decode(&second); err != io.EOF {
		return nil, errors.New("clash: document handle: the text holds more than one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("clash: YAML configuration root must be an object")
	}
	return &document, nil
}

func (h *DocumentHandle) with(name string, call func(state *documentHandleState) (*StringBox, error)) (*StringBox, error) {
	return recoverAppCall(name, func() (*StringBox, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.state == nil {
			return nil, errors.New("clash: document handle is closed")
		}
		return call(h.state)
	})
}

func (s *documentHandleState) document() *yaml.Node {
	if s.root == nil {
		if root, err := readHandleDocument(s.text); err == nil {
			s.root, s.exact = root, true
		}
	}
	return s.root
}

func (h *DocumentHandle) Edit(pathJSON, op, valueJSON string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.Edit", func(state *documentHandleState) (*StringBox, error) {
		answer := yamlEditAnswer{OK: true}
		text, after, err := editYAMLParsedFrom(state.edit, false, state.text, pathJSON, op, valueJSON)
		if err != nil {
			var refusal *yamlEditError
			if !errors.As(err, &refusal) {
				refusal = refuseEdit("unsafeEdit", "%v", err)
			}
			answer = yamlEditAnswer{Code: refusal.code, Message: refusal.message}
		} else {
			answer.Text = text
			state.text, state.root, state.exact, state.edit = text, nil, false, nil
			if after != nil && after.root != nil {
				state.root = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{after.root}}
				state.exact = true
				if after.editable {
					state.edit = after
				}
			}
		}
		encoded, err := json.Marshal(answer)
		if err != nil {
			return nil, err
		}
		return WrapString(string(encoded)), nil
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) Document(optionsJSON string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.Document", func(state *documentHandleState) (*StringBox, error) {
		var options documentOptions
		if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
			return nil, err
		}
		answer := documentAnswer(state.text, state.document(), state.exact, options)
		encoded, err := json.Marshal(answer)
		if err != nil {
			return nil, err
		}
		return WrapString(string(encoded)), nil
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func documentAnswer(text string, document *yaml.Node, exact bool, options documentOptions) yamlToJSONOptionsAnswer {
	if document == nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return yamlToJSONOptionsAnswerOf(text, options)
	}
	var answer yamlToJSONOptionsAnswer
	root := document.Content[0]
	answer.Document, answer.DocumentError = documentJSON(text, root)
	if options.ValidateShape {
		answer.ShapeError = shapeErrorOf(text, root)
	}
	if !exact && (answer.DocumentError != "" || answer.ShapeError != "") {
		finalizedTreeFallbacks.Add(1)
		return yamlToJSONOptionsAnswerOf(text, options)
	}
	return answer
}

func (h *DocumentHandle) SetDocumentJSON(documentJSON, optionsJSON string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.SetDocumentJSON", func(state *documentHandleState) (*StringBox, error) {
		var options documentOptions
		if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
			return nil, err
		}
		text, document, err := jsonDocumentAsYAML(documentJSON)
		if err != nil {
			return nil, err
		}
		answer := jsonToYAMLOptionsAnswer{Text: text, yamlToJSONOptionsAnswer: documentAnswer(text, document, false, options)}
		encoded, err := json.Marshal(answer)
		if err != nil {
			return nil, err
		}
		state.text, state.root, state.exact, state.edit = text, document, false, nil
		return WrapString(string(encoded)), nil
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) MergeOverride(overrideJSON string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.MergeOverride", func(state *documentHandleState) (*StringBox, error) {
		merged, err := mergeOverrideDocument(state.text, state.document(), overrideJSON)
		if err != nil {
			return nil, err
		}
		if merged.text != state.text {
			state.text, state.root, state.exact, state.edit = merged.text, merged.document, false, nil
		}
		return WrapString(merged.text), nil
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) Plan(targetProfile string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.Plan", func(state *documentHandleState) (*StringBox, error) {
		return planFinalized(newFinalizedTree(finalizedDocument{text: state.text, document: state.document()}), targetProfile)
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) FinalizeWithOptions(resourceMapJSON, optionsJSON string) (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.FinalizeWithOptions", func(state *documentHandleState) (*StringBox, error) {
		var options finalizeOptions
		if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
			return nil, err
		}
		var orderRoot *yaml.Node
		if options.OrderReference == "" {
			options.OrderReference, orderRoot = state.original, state.originalRoot
		}
		finalized, err := finalizeMergedDocument(state.text, state.document(), resourceMapJSON, options.OrderReference, orderRoot)
		if err != nil {
			return nil, err
		}
		return answerFinalized(finalized, options)
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) Text() (*StringBox, error) {
	bridgedValue, bridgedErr := h.with("DocumentHandle.Text", func(state *documentHandleState) (*StringBox, error) {
		return WrapString(state.text), nil
	})
	return bridgedValue, bridgeSafeError(bridgedErr)
}

func (h *DocumentHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = nil
}

func jsonDocumentAsYAML(documentJSON string) (string, *yaml.Node, error) {
	rootNode, ok := jsonTextAsYAMLNode(documentJSON)
	if !ok {
		decoder := json.NewDecoder(strings.NewReader(documentJSON))
		decoder.UseNumber()
		var err error
		rootNode, err = decodeJSONValueAsYAMLNode(decoder, 0)
		if err != nil {
			return "", nil, fmt.Errorf("clash: decode JSON: %w", err)
		}
		if _, err := decoder.Token(); err != io.EOF {
			if err != nil {
				return "", nil, fmt.Errorf("clash: decode trailing JSON: %w", err)
			}
			return "", nil, fmt.Errorf("clash: JSON configuration must contain exactly one value")
		}
	}
	if rootNode.Kind != yaml.MappingNode {
		return "", nil, fmt.Errorf("clash: JSON configuration root must be an object")
	}
	document := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{rootNode}}
	text, err := encodeYAMLDocument(document)
	if err != nil {
		return "", nil, err
	}
	if !treeReadsBack(rootNode) {
		return text, nil, nil
	}
	return text, document, nil
}

func treeReadsBack(node *yaml.Node) bool {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value == "<<" {
				return false
			}
		}
	case yaml.ScalarNode:
		if node.Tag == "!!str" {
			for _, r := range node.Value {
				if r < 0x20 || r == 0x7F || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xFEFF {
					return false
				}
			}
		}
	}
	for _, child := range node.Content {
		if !treeReadsBack(child) {
			return false
		}
	}
	return true
}

type jsonToYAMLOptionsAnswer struct {
	Text string `json:"text"`
	yamlToJSONOptionsAnswer
}

func JsonToYAMLWithOptions(documentJSON, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("JsonToYAMLWithOptions", func() (*StringBox, error) {
		var options documentOptions
		if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
			return nil, err
		}
		text, document, err := jsonDocumentAsYAML(documentJSON)
		if err != nil {
			return nil, err
		}
		answer := jsonToYAMLOptionsAnswer{Text: text, yamlToJSONOptionsAnswer: documentAnswer(text, document, false, options)}
		encoded, err := json.Marshal(answer)
		if err != nil {
			return nil, err
		}
		return WrapString(string(encoded)), nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

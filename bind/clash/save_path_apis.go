package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

func decodeSavePathOptions(optionsJSON string, into any) error {
	if strings.TrimSpace(optionsJSON) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(optionsJSON), into); err != nil {
		return fmt.Errorf("clash: options: %w", err)
	}
	return nil
}

func FinalizeForIOSWithOptions(mergedYAML, resourceMapJSON, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("FinalizeForIOSWithOptions", func() (*StringBox, error) {
		return finalizeForIOSWithOptionsUnguarded(mergedYAML, resourceMapJSON, optionsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type finalizeOptions struct {
	TargetProfile      string                     `json:"targetProfile"`
	Plan               bool                       `json:"plan"`
	Intent             bool                       `json:"intent"`
	GeodataMode        bool                       `json:"geodataMode"`
	TopLevelKeys       []string                   `json:"topLevelKeys"`
	OrderReference     string                     `json:"orderReference"`
	OrderReferencePath string                     `json:"orderReferencePath"`
	GeoCategories      bool                       `json:"geoCategories"`
	PrependRules       []string                   `json:"prependRules"`
	AppendRules        []string                   `json:"appendRules"`
	RuleProviders      map[string]json.RawMessage `json:"ruleProviders"`
}

type finalizeOptionsAnswer struct {
	Text              string                     `json:"text"`
	Plan              json.RawMessage            `json:"plan,omitempty"`
	PlanError         string                     `json:"planError,omitempty"`
	Intent            json.RawMessage            `json:"intent,omitempty"`
	IntentError       string                     `json:"intentError,omitempty"`
	GeodataMode       *bool                      `json:"geodataMode,omitempty"`
	TopLevel          map[string]json.RawMessage `json:"topLevel,omitempty"`
	GeositeCategories *[]string                  `json:"geositeCategories,omitempty"`
	GeoIPCountries    *[]string                  `json:"geoipCountries,omitempty"`
}

var finalizedTextReads atomic.Int64

var savePathRereads atomic.Int64

var finalizedTreeFallbacks atomic.Int64

func finalizeForIOSWithOptionsUnguarded(mergedYAML, resourceMapJSON, optionsJSON string) (*StringBox, error) {
	var options finalizeOptions
	if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
		return nil, bridgeSafeError(err)
	}
	finalize := func(orderReference string) (*StringBox, error) {
		return withCompactHeap(func() (*StringBox, error) {
			finalized, err := finalizeMergedDocument(mergedYAML, nil, resourceMapJSON, orderReference, nil, options.PrependRules, options.AppendRules, options.RuleProviders)
			if err != nil {
				return nil, err
			}
			return answerFinalized(finalized, options)
		})
	}
	var out *StringBox
	var err error
	if options.OrderReferencePath != "" {
		out, err = withDocumentAt(options.OrderReferencePath, finalize)
	} else {
		out, err = finalize(options.OrderReference)
	}
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func FinalizeForIOSWithOptionsAtPath(path, resourceMapJSON, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("FinalizeForIOSWithOptionsAtPath", func() (*StringBox, error) {
		return withDocumentAt(path, func(text string) (*StringBox, error) {
			return finalizeForIOSWithOptionsUnguarded(text, resourceMapJSON, optionsJSON)
		})
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func answerFinalized(finalized finalizedDocument, options finalizeOptions) (*StringBox, error) {
	text := finalized.text
	answer := finalizeOptionsAnswer{Text: text}
	tree := newFinalizedTree(finalized)
	if options.Plan {
		if plan, err := planFinalized(tree, options.TargetProfile); err != nil {
			answer.PlanError = bridgeSafeError(err).Error()
		} else {
			answer.Plan = json.RawMessage(plan.Value)
		}
	}
	if options.GeoCategories {
		categories := geoSiteCategoriesInDocument(text, finalized.document)
		countries := geoIPCountriesInDocument(text, finalized.document)
		if categories == nil {
			categories = []string{}
		}
		if countries == nil {
			countries = []string{}
		}
		answer.GeositeCategories, answer.GeoIPCountries = &categories, &countries
	}
	if options.Intent || options.GeodataMode || len(options.TopLevelKeys) > 0 {
		finalizedTextReads.Add(1)
		read := readFinalized(tree)
		if options.GeodataMode {
			mode := read.raw != nil && read.raw.GeodataMode
			answer.GeodataMode = &mode
		}
		if options.Intent {
			if read.rawErr != nil {
				answer.IntentError = bridgeSafeError(fmt.Errorf("clash: parse config: %w", read.rawErr)).Error()
			} else if intent, err := platformConfigIntentFromRaw(read.raw); err != nil {
				answer.IntentError = bridgeSafeError(err).Error()
			} else {
				answer.Intent = intent
			}
		}
		if len(options.TopLevelKeys) > 0 && read.root != nil {
			answer.TopLevel = map[string]json.RawMessage{}
			for _, key := range options.TopLevelKeys {
				if value := mappingValue(read.root, key); value != nil {
					if encoded, err := yamlRootToJSON(value); err == nil {
						answer.TopLevel[key] = encoded
					}
				}
			}
		}
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

type finalizedTextRead struct {
	root   *yaml.Node
	raw    *config.RawConfig
	rawErr error
}

type finalizedTree struct {
	finalized finalizedDocument
	usable    bool
	rootRead  bool
	root      map[string]any
	rootErr   error
	rawRead   bool
	raw       *config.RawConfig
	rawErr    error
}

func newFinalizedTree(finalized finalizedDocument) *finalizedTree {
	document := finalized.document
	return &finalizedTree{
		finalized: finalized,
		usable:    document != nil && len(document.Content) == 1 && !strings.HasPrefix(finalized.text, age.FileHeader),
	}
}

func (t *finalizedTree) mapped() (map[string]any, error) {
	if !t.rootRead {
		t.rootRead = true
		t.rootErr = t.finalized.document.Decode(&t.root)
	}
	return t.root, t.rootErr
}

func (t *finalizedTree) typed() (*config.RawConfig, error) {
	if !t.rawRead {
		t.rawRead = true
		raw := config.DefaultRawConfig()
		if err := t.finalized.document.Decode(raw); err != nil {
			t.rawErr = err
		} else {
			t.raw = raw
		}
	}
	return t.raw, t.rawErr
}

func readFinalized(tree *finalizedTree) finalizedTextRead {
	if !tree.usable {
		return readFinalizedText(tree.finalized.text)
	}
	raw, err := tree.typed()
	if err != nil {
		finalizedTreeFallbacks.Add(1)
		return readFinalizedText(tree.finalized.text)
	}
	read := finalizedTextRead{raw: raw}
	if root := tree.finalized.document.Content[0]; root.Kind == yaml.MappingNode {
		read.root = root
	}
	return read
}

func planFinalized(tree *finalizedTree, targetProfile string) (*StringBox, error) {
	if !tree.usable {
		return planResourcesForProfileUnguarded(tree.finalized.text, targetProfile)
	}
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	root, rootErr := tree.mapped()
	raw, rawErr := tree.typed()
	if rootErr != nil || rawErr != nil {
		finalizedTreeFallbacks.Add(1)
		return planResourcesForProfileUnguarded(tree.finalized.text, targetProfile)
	}
	doc := &ConfigDocument{}
	doc.views.Store(&documentViews{rawText: tree.finalized.text, root: root, raw: raw})
	return doc.planResourcesJSON(runtimePolicyFor(profile, true))
}

func readFinalizedText(text string) finalizedTextRead {
	var document yaml.Node
	if strings.HasPrefix(text, age.FileHeader) {
		return rereadFinalizedText(text)
	}
	if err := yaml.NewDecoder(strings.NewReader(text)).Decode(&document); err != nil || len(document.Content) != 1 {
		return rereadFinalizedText(text)
	}
	read := finalizedTextRead{}
	if document.Content[0].Kind == yaml.MappingNode {
		read.root = document.Content[0]
	}
	raw := config.DefaultRawConfig()
	if err := document.Decode(raw); err != nil {
		read.rawErr = err
	} else {
		read.raw = raw
	}
	return read
}

func rereadFinalizedText(text string) finalizedTextRead {
	savePathRereads.Add(1)
	raw, rawErr := config.UnmarshalRawConfig([]byte(text))
	return finalizedTextRead{raw: raw, rawErr: rawErr}
}

func EditYAMLForIOSWithOptions(original, pathJSON, op, valueJSON, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("EditYAMLForIOSWithOptions", func() (*StringBox, error) {
		return editYAMLForIOSWithOptionsUnguarded(original, pathJSON, op, valueJSON, optionsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type documentOptions struct {
	Document      bool `json:"document"`
	ValidateShape bool `json:"validateShape"`
}

type yamlEditOptionsAnswer struct {
	yamlEditAnswer
	Document      json.RawMessage `json:"document,omitempty"`
	DocumentError string          `json:"documentError,omitempty"`
	ShapeError    string          `json:"shapeError,omitempty"`
}

func editYAMLForIOSWithOptionsUnguarded(original, pathJSON, op, valueJSON, optionsJSON string) (*StringBox, error) {
	var options documentOptions
	if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
		return nil, bridgeSafeError(err)
	}
	answer := yamlEditOptionsAnswer{yamlEditAnswer: yamlEditAnswer{OK: true}}
	text, after, err := editYAMLParsed(original, pathJSON, op, valueJSON)
	if err != nil {
		var refusal *yamlEditError
		if !errors.As(err, &refusal) {
			refusal = refuseEdit("unsafeEdit", "%v", err)
		}
		answer.yamlEditAnswer = yamlEditAnswer{Code: refusal.code, Message: refusal.message}
	} else {
		answer.Text = text
		var root *yaml.Node
		if after != nil {
			root = after.root
		}
		if options.Document {
			answer.Document, answer.DocumentError = documentJSON(text, root)
		}
		if options.ValidateShape {
			answer.ShapeError = shapeErrorOf(text, root)
		}
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func documentJSON(text string, root *yaml.Node) (json.RawMessage, string) {
	if root != nil && root.Kind == yaml.MappingNode {
		payload, err := yamlRootToJSON(root)
		if err != nil {
			return nil, bridgeSafeError(err).Error()
		}
		return payload, ""
	}
	savePathRereads.Add(1)
	box, err := yamlToJSONUnguarded(text)
	if err != nil {
		return nil, bridgeSafeError(err).Error()
	}
	return json.RawMessage(box.Value), ""
}

func shapeErrorOf(text string, root *yaml.Node) string {
	if root == nil || strings.HasPrefix(text, age.FileHeader) {
		savePathRereads.Add(1)
		if err := validateConfigShapeUnguarded(text); err != nil {
			return err.Error()
		}
		return ""
	}
	if err := root.Decode(config.DefaultRawConfig()); err != nil {
		return bridgeSafeError(fmt.Errorf("clash: parse config: %w", err)).Error()
	}
	return ""
}

func YAMLOutlineForIOSWithOptions(original, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("YAMLOutlineForIOSWithOptions", func() (*StringBox, error) {
		return yamlOutlineForIOSWithOptionsUnguarded(original, optionsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type yamlOutlineOptionsAnswer struct {
	yamlOutlineAnswer
	Document      json.RawMessage `json:"document,omitempty"`
	DocumentError string          `json:"documentError,omitempty"`
}

func yamlOutlineForIOSWithOptionsUnguarded(original, optionsJSON string) (*StringBox, error) {
	var options documentOptions
	if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
		return nil, bridgeSafeError(err)
	}
	outline, root, err := yamlOutlineParsed(original)
	if err != nil {
		var refusal *yamlEditError
		if !errors.As(err, &refusal) {
			refusal = refuseEdit("unsupportedStyle", "%v", err)
		}
		outline = yamlOutlineAnswer{Code: refusal.code, Message: refusal.message}
	}
	answer := yamlOutlineOptionsAnswer{yamlOutlineAnswer: outline}
	if options.Document {
		answer.Document, answer.DocumentError = documentJSON(original, root)
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func YamlToJSONWithOptions(text, optionsJSON string) (*StringBox, error) {
	out, err := recoverAppCall("YamlToJSONWithOptions", func() (*StringBox, error) {
		return yamlToJSONWithOptionsUnguarded(text, optionsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type yamlToJSONOptionsAnswer struct {
	Document      json.RawMessage `json:"document,omitempty"`
	DocumentError string          `json:"documentError,omitempty"`
	ShapeError    string          `json:"shapeError,omitempty"`
}

func yamlToJSONWithOptionsUnguarded(text, optionsJSON string) (*StringBox, error) {
	var options documentOptions
	if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
		return nil, bridgeSafeError(err)
	}
	encoded, err := json.Marshal(yamlToJSONOptionsAnswerOf(text, options))
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func yamlToJSONOptionsAnswerOf(text string, options documentOptions) yamlToJSONOptionsAnswer {
	var answer yamlToJSONOptionsAnswer
	var document yaml.Node
	decodeErr := yaml.NewDecoder(strings.NewReader(text)).Decode(&document)
	var root *yaml.Node
	switch {
	case decodeErr != nil:
		answer.DocumentError = bridgeSafeError(fmt.Errorf("clash: decode YAML: %w", decodeErr)).Error()
	case len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode:
		answer.DocumentError = "clash: YAML configuration root must be an object"
	default:
		root = document.Content[0]
		answer.Document, answer.DocumentError = documentJSON(text, root)
	}
	if options.ValidateShape {
		answer.ShapeError = shapeErrorOf(text, root)
	}
	return answer
}

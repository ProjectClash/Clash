package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

func legacyFinalizeMerged(mergedYAML string, resourceMapJSON string, orderReference string) (string, error) {
	var rm resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &rm); err != nil {
			return "", err
		}
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(mergedYAML), &root); err != nil {
		return "", err
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	routeProviders := routeProviderSpecs(root)
	platformRouteProviders := map[string]bool{}
	if tun, ok := root["tun"].(map[string]any); ok {
		platformRouteProviders = routeSetProviderNames(tun)
	}
	annotateRuleProviderSideUpdateSafety(root, platformRouteProviders)
	collisions := providerNamespaceCollisions(root)
	remoteProxyProviders := remoteProviderDefinitions(root, "proxy-providers")
	remoteRuleProviders := remoteProviderDefinitions(root, "rule-providers")
	if err := rewriteProviders(root, "proxy-providers", "proxy", rm.ProviderPaths, collisions); err != nil {
		return "", err
	}
	if err := rewriteProviders(root, "rule-providers", "rule", rm.ProviderPaths, collisions); err != nil {
		return "", err
	}
	annotateProviderRefresh(root, "proxy-providers", "proxy", remoteProxyProviders, rm)
	annotateProviderRefresh(root, "rule-providers", "rule", remoteRuleProviders, rm)
	readPaths := rm.ProviderReadPaths
	if len(readPaths) == 0 {
		readPaths = rm.ProviderPaths
	}
	if tun, ok := root["tun"].(map[string]any); ok {
		if err := expandRouteSet(tun, "route-address-set", "route-address", readPaths, routeProviders, collisions); err != nil {
			return "", err
		}
		if err := expandRouteSet(tun, "route-exclude-address-set", "route-exclude-address", readPaths, routeProviders, collisions); err != nil {
			return "", err
		}
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", err
	}
	if orderReference != "" {
		return legacyRestoreKeyOrderFrom(string(out), orderReference, mergedYAML), nil
	}
	return legacyRestoreKeyOrderFrom(string(out), mergedYAML), nil
}

func legacyRestoreKeyOrderFrom(transformed string, references ...string) string {
	var transformedRoot yaml.Node
	if err := yaml.Unmarshal([]byte(transformed), &transformedRoot); err != nil {
		return transformed
	}
	if len(transformedRoot.Content) == 0 {
		return transformed
	}

	roots := make([]*yaml.Node, 0, len(references))
	for _, reference := range references {
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(reference), &root); err != nil {
			continue
		}
		if len(root.Content) == 0 {
			continue
		}
		roots = append(roots, root.Content[0])
	}
	if len(roots) == 0 {
		return transformed
	}

	reorderNodeFrom(roots, transformedRoot.Content[0], 0)

	standIns := standInAstralInNode(&transformedRoot)
	out, err := yaml.Marshal(&transformedRoot)
	if err != nil {
		return transformed
	}
	return standIns.restore(string(out))
}

func legacyFinalizeForIOSWithOptions(mergedYAML, resourceMapJSON, optionsJSON string) (*StringBox, error) {
	var options finalizeOptions
	if err := decodeSavePathOptions(optionsJSON, &options); err != nil {
		return nil, bridgeSafeError(err)
	}
	text, err := legacyFinalizeMerged(mergedYAML, resourceMapJSON, options.OrderReference)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	answer := finalizeOptionsAnswer{Text: text}
	if options.Plan {
		if plan, err := planResourcesForProfileUnguarded(text, options.TargetProfile); err != nil {
			answer.PlanError = bridgeSafeError(err).Error()
		} else {
			answer.Plan = json.RawMessage(plan.Value)
		}
	}
	if options.Intent || options.GeodataMode || len(options.TopLevelKeys) > 0 {
		read := readFinalizedText(text)
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
					if encoded, err := legacyYAMLRootToJSON(value); err == nil {
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

func legacyMergeOverride(rawYAML string, overrideJSON string) (*StringBox, error) {
	if overrideJSON == "" {
		return WrapString(rawYAML), nil
	}
	var spec overrideSpec
	if err := json.Unmarshal([]byte(overrideJSON), &spec); err != nil {
		return nil, bridgeSafeError(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(rawYAML), &root); err != nil {
		return nil, bridgeSafeError(err)
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
		return nil, bridgeSafeError(err)
	}
	merged := legacyRestoreKeyOrderFrom(string(out), rawYAML, patchDocument(overrideJSON))
	return WrapString(merged), nil
}

func legacyYAMLRootToJSON(root *yaml.Node) ([]byte, error) {
	var safety any
	if err := root.Decode(&safety); err != nil {
		return nil, fmt.Errorf("clash: reject unsafe YAML configuration: %w", err)
	}

	var payload bytes.Buffer
	if err := legacyEncodeYAMLNodeAsJSON(root, &payload); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func legacyEncodeYAMLNodeAsJSON(node *yaml.Node, buf *bytes.Buffer) error {
	switch node.Kind {
	case yaml.AliasNode:
		return legacyEncodeYAMLNodeAsJSON(node.Alias, buf)
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
			if err := legacyEncodeYAMLNodeAsJSON(pair.value, buf); err != nil {
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
			if err := legacyEncodeYAMLNodeAsJSON(item, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
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

func legacyMarkRuleGeodata(line string, required *geodataRequirements) {
	for _, match := range geodataRuleToken.get().FindAllStringSubmatch(line, -1) {
		switch strings.ToUpper(match[1]) {
		case "GEOIP", "SRC-GEOIP":
			if strings.ToLower(strings.TrimSpace(match[2])) != "lan" {
				required.geoIP = true
			}
		case "GEOSITE":
			required.geoSite = true
		case "IP-ASN", "SRC-IP-ASN":
			required.asn = true
		}
	}
}

func legacyJSONToYaml(rawJSON string) (*StringBox, error) {
	decoder := json.NewDecoder(strings.NewReader(rawJSON))
	decoder.UseNumber()
	rootNode, err := decodeJSONValueAsYAMLNode(decoder, 0)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: decode JSON: %w", err))
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, bridgeSafeError(fmt.Errorf("clash: decode trailing JSON: %w", err))
		}
		return nil, bridgeSafeError(fmt.Errorf("clash: JSON configuration must contain exactly one value"))
	}
	if rootNode.Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("clash: JSON configuration root must be an object"))
	}

	document := yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{rootNode}}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode JSON configuration as YAML: %w", err))
	}
	if err := encoder.Close(); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: finish YAML encoding: %w", err))
	}
	return WrapString(output.String()), nil
}

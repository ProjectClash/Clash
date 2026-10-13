package clash

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"go.yaml.in/yaml/v3"
)

const maximumExpandedRoutePrefixes = 65_536

type resourceMap struct {
	ProviderPaths            map[string]string `json:"providerPaths"`
	ProviderReadPaths        map[string]string `json:"providerReadPaths"`
	ProviderFetchedAt        map[string]int64  `json:"providerFetchedAt"`
	ProviderETags            map[string]string `json:"providerETags"`
	ProviderSubscriptionInfo map[string]string `json:"providerSubscriptionInfo"`
	NodeLibraryDirectory     string            `json:"nodeLibraryDirectory"`
}

func FinalizeForIOS(mergedYAML string, resourceMapJSON string) (*StringBox, error) {
	out, err := recoverAppCall("FinalizeForIOS", func() (*StringBox, error) { return finalizeForIOSUnguarded(mergedYAML, resourceMapJSON) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func finalizeForIOSUnguarded(mergedYAML string, resourceMapJSON string) (*StringBox, error) {
	finalized, err := finalizeMerged(mergedYAML, resourceMapJSON, "")
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(finalized), nil
}

func finalizeMerged(mergedYAML string, resourceMapJSON string, orderReference string) (string, error) {
	finalized, err := finalizeMergedDocument(mergedYAML, nil, resourceMapJSON, orderReference, nil)
	return finalized.text, err
}

type finalizedDocument struct {
	text     string
	document *yaml.Node
}

func finalizeMergedDocument(mergedYAML string, merged *yaml.Node, resourceMapJSON string, orderReference string, orderRoot *yaml.Node) (finalizedDocument, error) {
	var rm resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &rm); err != nil {
			return finalizedDocument{}, err
		}
	}
	if merged == nil && rm.NodeLibraryDirectory != "" {
		document, err := yaml.ClashParseDocument([]byte(mergedYAML), yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any{})})
		if err != nil {
			return finalizedDocument{}, err
		}
		merged = document
	}
	if merged == nil {
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(mergedYAML), &document); err != nil {
			return finalizedDocument{}, err
		}
		merged = &document
	}
	var root map[string]any
	if len(merged.Content) > 0 {
		if err := merged.Decode(&root); err != nil {
			return finalizedDocument{}, err
		}
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
		return finalizedDocument{}, err
	}
	if err := rewriteProviders(root, "rule-providers", "rule", rm.ProviderPaths, collisions); err != nil {
		return finalizedDocument{}, err
	}
	annotateProviderRefresh(root, "proxy-providers", "proxy", remoteProxyProviders, rm)
	annotateProviderRefresh(root, "rule-providers", "rule", remoteRuleProviders, rm)
	reference, carried := root["x-clash-node-library"]
	if carried && publishedNodeLibraryHere(reference) != nil && !nodesOnlyInLibrary(root, reference) {
		carried = false
	}
	if carried {
		if err := publishedNodeLibraryHere(reference); err != nil {
			return finalizedDocument{}, err
		}
	} else if rm.NodeLibraryDirectory != "" {
		dropWrittenNodeFields(root)
		if err := writeNodeLibrary(root, rm.NodeLibraryDirectory); err != nil {
			return finalizedDocument{}, err
		}
	} else {
		dropWrittenNodeFields(root)
	}
	readPaths := rm.ProviderReadPaths
	if len(readPaths) == 0 {
		readPaths = rm.ProviderPaths
	}
	if tun, ok := root["tun"].(map[string]any); ok {
		if err := expandRouteSet(tun, "route-address-set", "route-address", readPaths, routeProviders, collisions); err != nil {
			return finalizedDocument{}, err
		}
		if err := expandRouteSet(tun, "route-exclude-address-set", "route-exclude-address", readPaths, routeProviders, collisions); err != nil {
			return finalizedDocument{}, err
		}
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return finalizedDocument{}, err
	}
	references := make([]*yaml.Node, 0, 2)
	if orderRoot != nil {
		references = append(references, orderRoot)
	} else if orderReference != "" && rm.NodeLibraryDirectory != "" {
		document, err := yaml.ClashParseDocument([]byte(orderReference), yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(struct{}{})})
		if err == nil {
			references = append(references, document)
		}
	} else if orderReference != "" {
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(orderReference), &document); err == nil {
			references = append(references, &document)
		}
	}
	references = append(references, merged)
	text, document := restoreKeyOrderFromDocuments(string(out), references)
	return finalizedDocument{text: text, document: document}, nil
}

func routeSetProviderNames(tun map[string]any) map[string]bool {
	result := make(map[string]bool)
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		values, _ := tun[field].([]any)
		for _, value := range values {
			if name, ok := value.(string); ok && name != "" {
				result[name] = true
			}
		}
	}
	return result
}

func annotateRuleProviderSideUpdateSafety(root map[string]any, platformRouteProviders map[string]bool) {
	providers, _ := root["rule-providers"].(map[string]any)
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		typeName, _ := definition["type"].(string)
		if typeName != "file" && typeName != "http" {
			continue
		}
		behavior, _ := definition["behavior"].(string)
		changesPlatformRoutes := platformRouteProviders[name] && strings.EqualFold(behavior, "ipcidr")
		delete(definition, providerSideUpdateSafeField)
		definition[providerSideUpdateSafeWrittenField] = !changesPlatformRoutes
	}
}

type routeProviderSpec struct {
	format   string
	behavior string
	inline   []string
	isInline bool
}

func routeProviderSpecs(root map[string]any) map[string]routeProviderSpec {
	result := map[string]routeProviderSpec{}
	providers, ok := root["rule-providers"].(map[string]any)
	if !ok {
		return result
	}
	for name, raw := range providers {
		definition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		format, _ := definition["format"].(string)
		if format == "" {
			format = "yaml"
		}
		behavior, _ := definition["behavior"].(string)
		spec := routeProviderSpec{
			format:   strings.ToLower(format),
			behavior: strings.ToLower(behavior),
		}
		if typeName, _ := definition["type"].(string); strings.EqualFold(typeName, "inline") {
			spec.isInline = true
			if payload, ok := definition["payload"].([]any); ok {
				for _, item := range payload {
					if value, ok := item.(string); ok {
						spec.inline = append(spec.inline, value)
					}
				}
			}
		}
		result[name] = spec
	}
	return result
}

func providerNamespaceCollisions(root map[string]any) map[string]bool {
	proxyNames := httpProviderNameSet(root, "proxy-providers")
	ruleNames := httpProviderNameSet(root, "rule-providers")
	collisions := map[string]bool{}
	for name := range proxyNames {
		if ruleNames[name] {
			collisions[name] = true
		}
	}
	return collisions
}

func httpProviderNameSet(root map[string]any, key string) map[string]bool {
	result := map[string]bool{}
	providers, _ := root[key].(map[string]any)
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		if typeName, _ := definition["type"].(string); strings.EqualFold(typeName, "http") {
			result[name] = true
		}
	}
	return result
}

func providerPath(paths map[string]string, kind, name string, collisions map[string]bool) (string, bool, error) {
	if path, ok := paths[providerResourceKey(kind, name)]; ok {
		if strings.TrimSpace(path) == "" {
			return "", false, fmt.Errorf("provider resource path %q is empty", providerResourceKey(kind, name))
		}
		return path, true, nil
	}
	if collisions[name] {
		if _, legacy := paths[name]; legacy {
			return "", false, fmt.Errorf("provider %q exists in proxy and rule namespaces; use schema-v2 resource keys", name)
		}
		return "", false, nil
	}
	path, ok := paths[name]
	if ok && strings.TrimSpace(path) == "" {
		return "", false, fmt.Errorf("provider resource path %q is empty", name)
	}
	return path, ok, nil
}

func rewriteProviders(root map[string]any, key, kind string, paths map[string]string, collisions map[string]bool) error {
	m, ok := root[key].(map[string]any)
	if !ok {
		return nil
	}
	for name, raw := range m {
		def, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := def["type"].(string); !strings.EqualFold(t, "http") {
			continue
		}
		if rawURL, _ := def["url"].(string); true {
			if _, err := normalizeResourceURL(rawURL, "provider"); err != nil {
				continue
			}
		}
		path, found, err := providerPath(paths, kind, name, collisions)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		def["type"] = "file"
		def["path"] = path
		for _, remoteOnlyField := range []string{
			"url", "interval", "size-limit", "proxy", "header", "age-secret-key",
		} {
			delete(def, remoteOnlyField)
		}
	}
	return nil
}

func expandRouteSet(tun map[string]any, setKey, destKey string, paths map[string]string, providers map[string]routeProviderSpec, collisions map[string]bool) error {
	list, ok := tun[setKey].([]any)
	if !ok {
		return nil
	}
	var cidrs []any
	var skipped []string
	seen := map[string]struct{}{}
	for _, item := range list {
		name, _ := item.(string)
		spec, defined := providers[name]
		if !defined {
			skipped = append(skipped, name+" (no such provider)")
			continue
		}
		if spec.behavior != "ipcidr" {
			skipped = append(skipped, name+" (behavior "+spec.behavior+", not ipcidr)")
			continue
		}
		var entries []string
		var err error
		if spec.isInline {
			entries, err = validateRouteCIDRs(spec.inline)
		} else {
			path, found, pathErr := providerPath(paths, "rule", name, collisions)
			if pathErr != nil {
				return pathErr
			}
			if !found {
				skipped = append(skipped, name+" (no local copy yet: the tunnel starts without its routes and gains them at its next start, once the App's first-load retry has the bytes)")
				continue
			}
			entries, err = readCIDRs(path, spec.format)
		}
		if err != nil {
			return fmt.Errorf("read %s provider %q: %w", setKey, name, err)
		}
		for _, c := range entries {
			if _, exists := seen[c]; exists {
				continue
			}
			seen[c] = struct{}{}
			cidrs = append(cidrs, c)
		}
		if len(cidrs) > maximumExpandedRoutePrefixes {
			return fmt.Errorf("%s expands to more than %d prefixes", setKey, maximumExpandedRoutePrefixes)
		}
	}
	if len(skipped) > 0 {
		log.Warnln("[Apple] tun.%s: %s contributed no routes and were skipped; the tunnel still starts, as it does upstream",
			setKey, strings.Join(skipped, ", "))
	}
	delete(tun, setKey)
	if len(cidrs) > 0 {
		if existing, ok := tun[destKey].([]any); ok {
			if len(existing)+len(cidrs) > maximumExpandedRoutePrefixes {
				return fmt.Errorf("%s and %s exceed %d prefixes", destKey, setKey, maximumExpandedRoutePrefixes)
			}
			tun[destKey] = append(existing, cidrs...)
		} else {
			tun[destKey] = cidrs
		}
	}
	return nil
}

func readCIDRs(path, format string) ([]string, error) {
	data, err := readBoundedRegularFile(path, int64(maximumProviderResourceBytes), "route-set provider")
	if err != nil {
		return nil, err
	}
	var entries []string
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "yaml":
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
		entries = doc.Payload
	case "text":
		entries, err = scanCIDRText(data)
	case "mrs":
		if err := validateMRSForIOS(data, P.IPCIDR); err != nil {
			return nil, fmt.Errorf("validate mrs: %w", err)
		}
		var decoded boundedBuffer
		decoded.maximum = int64(maximumProviderResourceBytes)
		if err := ruleprovider.ConvertToMrs(data, P.IPCIDR, P.MrsRule, &decoded); err != nil {
			return nil, fmt.Errorf("decode mrs: %w", err)
		}
		entries, err = scanCIDRText(decoded.Bytes())
	default:
		return nil, fmt.Errorf("unsupported ipcidr provider format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return validateRouteCIDRs(entries)
}

func scanCIDRText(data []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provider contains no CIDR entries")
	}
	return out, nil
}

func validateRouteCIDRs(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("provider contains no CIDR entries")
	}
	result := make([]string, 0, len(entries))
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for index, entry := range entries {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("CIDR %d %q is invalid: %w", index, entry, err)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix.String())
		if len(result) > maximumExpandedRoutePrefixes {
			return nil, fmt.Errorf("provider exceeds %d route prefixes", maximumExpandedRoutePrefixes)
		}
	}
	return result, nil
}

type boundedBuffer struct {
	bytes.Buffer
	maximum int64
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if int64(buffer.Len())+int64(len(data)) > buffer.maximum {
		return 0, fmt.Errorf("decoded provider exceeds %d bytes", buffer.maximum)
	}
	return buffer.Buffer.Write(data)
}

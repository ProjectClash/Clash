package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	adapterprovider "github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"go.yaml.in/yaml/v3"
)

func (c *NodeCatalog) NodeConfigJSON(provider, name string) string {
	answer, err := recoverAppCall("NodeConfigJSON", func() (string, error) { return c.nodeConfigJSON(provider, name), nil })
	if err != nil {
		return bridgeSafeString(mustJSON(map[string]any{"found": false, "error": err.Error()}))
	}
	return bridgeSafeString(answer)
}

func (c *NodeCatalog) nodeConfigJSON(provider, name string) string {
	return c.read(func(v nodeView) string {
		found, mapping, err := c.nodeConfig(v, provider, name)
		if err != nil {
			return mustJSON(map[string]any{"found": false, "error": err.Error()})
		}
		if mapping == nil {
			if empty := c.emptyProviders(v, provider); len(empty) > 0 {
				return mustJSON(map[string]any{"found": false, "notLoaded": empty})
			}
			return `{"found":false}`
		}
		encoded, err := json.Marshal(map[string]any{"found": true, "provider": found, "config": jsonKeys(mapping)})
		if err != nil {
			return mustJSON(map[string]any{"found": false, "error": err.Error()})
		}
		return string(encoded)
	})
}

func jsonKeys(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = jsonKeys(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[fmt.Sprint(key)] = jsonKeys(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = jsonKeys(item)
		}
		return out
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = jsonKeys(item)
		}
		return out
	case []map[any]any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = jsonKeys(item)
		}
		return out
	}
	return value
}

func (c *NodeCatalog) nodeConfig(v nodeView, provider, name string) (string, map[string]any, error) {
	var places []string
	switch provider {
	case "*":
		places = append([]string{""}, c.configs.providerOrder(v.providers)...)
	default:
		places = []string{provider}
	}
	for _, place := range places {
		mapping, err := c.nodeConfigIn(v, place, name)
		if err != nil || mapping != nil {
			return place, mapping, err
		}
	}
	return "", nil, nil
}

func (c *NodeCatalog) emptyProviders(v nodeView, provider string) []string {
	var places []string
	switch provider {
	case "":
		return nil
	case "*":
		for name := range v.providers {
			places = append(places, name)
		}
		sort.Strings(places)
	default:
		places = []string{provider}
	}
	var empty []string
	for _, name := range places {
		if pd, ok := v.providers[name]; ok && pd.VehicleType() != P.Compatible && pd.ProxyList().Len() == 0 &&
			!c.configs.payloadOnDisk(name) && !c.configs.pendingFor(name) {
			empty = append(empty, name)
		}
	}
	return empty
}

func (c *NodeCatalog) nodeConfigIn(v nodeView, place, name string) (map[string]any, error) {
	if place == "" {
		proxy, ok := v.proxies[name]
		if !ok && v.library != nil {
			proxy, ok = v.library.Lookup(name)
		}
		if !ok {
			return nil, nil
		}
		if mapping, ok, err := adapter.NodeConfigMapping(proxy); ok || err != nil {
			return mapping, err
		}
		return c.configs.kept[name], nil
	}
	pd, ok := v.providers[place]
	if !ok || pd.VehicleType() == P.Compatible {
		return nil, nil
	}
	proxy, ok := providerNode(pd.ProxyList(), name)
	if !ok {
		return c.configs.pendingNodeConfig(place, name)
	}
	if mapping, ok, err := adapter.NodeConfigMapping(proxy); ok || err != nil {
		return mapping, err
	}
	definition := c.configs.definitions[place]
	if definition == nil {
		return nil, nil
	}
	var payload []byte
	if inline, ok := definition["payload"].([]any); ok {
		encoded, err := yaml.Marshal(map[string]any{"proxies": inline})
		if err != nil {
			return nil, err
		}
		payload = encoded
	} else if path, _ := definition["path"].(string); path != "" {
		read, err := readBoundedRegularFile(C.Path.Resolve(path), int64(providerContentBytes()), "provider payload")
		if err != nil {
			return nil, err
		}
		format, _ := definition["format"].(string)
		payload = proxyProviderRuntimeContent(format, read)
	} else {
		return nil, nil
	}
	mapping, _, err := adapterprovider.ClashProviderNodeMapping(definition, payload, name)
	return mapping, err
}

func (s nodeConfigSources) pendingNodeConfig(provider, name string) (map[string]any, error) {
	definition := s.definitions[provider]
	spec, ok := decodeProviderRefreshMarker(definition[providerRefreshField])
	if !ok {
		return nil, nil
	}
	requestKey := spec.requestKey("proxy")
	home := C.Path.HomeDir()
	entry := readProviderCacheEntries(home)[requestKey]
	if entry == nil || entry.PendingSHA256 == "" {
		return nil, nil
	}
	pending := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, requestKey, "pending")
	payload, err := readBoundedRegularFile(pending, maximumPendingCompileBytes, "waiting provider content")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	selection := maps.Clone(definition)
	if spec.AgeKey != "" {
		selection["age-secret-key"] = spec.AgeKey
	}
	format, _ := definition["format"].(string)
	mapping, _, err := adapterprovider.ClashProviderNodeMapping(selection, proxyProviderRuntimeContent(format, payload), name)
	return mapping, err
}

func (s nodeConfigSources) payloadOnDisk(provider string) bool {
	definition := s.definitions[provider]
	if _, inline := definition["payload"]; inline {
		return true
	}
	path, _ := definition["path"].(string)
	if path == "" {
		return false
	}
	info, err := os.Stat(C.Path.Resolve(path))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func (s nodeConfigSources) pendingFor(provider string) bool {
	spec, ok := decodeProviderRefreshMarker(s.definitions[provider][providerRefreshField])
	if !ok {
		return false
	}
	entry := readProviderCacheEntries(C.Path.HomeDir())[spec.requestKey("proxy")]
	return entry != nil && entry.PendingSHA256 != ""
}

func providerNode(list C.ProxyList, name string) (C.Proxy, bool) {
	if library, ok := list.(C.ProxyLibrary); ok {
		return library.Lookup(name)
	}
	for i := 0; i < list.Len(); i++ {
		if proxy := list.At(i); proxy.Name() == name {
			return proxy, true
		}
	}
	return nil, false
}

func ownNodeWithoutRecord(name string, proxy C.Proxy) bool {
	if slices.Contains(builtinProxyNames[:], name) {
		return false
	}
	if _, group := proxy.Adapter().(outboundgroup.ProxyGroup); group {
		return false
	}
	return !adapter.NodeHasRecord(proxy)
}

type nodeConfigSources struct {
	written     []string
	definitions map[string]map[string]any
	kept        map[string]map[string]any
}

func (s nodeConfigSources) providerOrder(providers map[string]P.ProxyProvider) []string {
	order := make([]string, 0, len(providers))
	listed := map[string]bool{}
	for _, name := range s.written {
		if _, ok := providers[name]; ok && !listed[name] {
			order = append(order, name)
			listed[name] = true
		}
	}
	var rest []string
	for name, pd := range providers {
		if !listed[name] && pd.VehicleType() != P.Compatible {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}

const nodeConfigWholeLimit = 1 << 20

func readNodeConfigSources(content, document string, own map[string]C.Proxy) nodeConfigSources {
	sources := nodeConfigSources{definitions: map[string]map[string]any{}, kept: map[string]map[string]any{}}
	if strings.Contains(content, "proxy-providers") {
		sections, whole := sectionTexts(content, "proxy-providers")
		section := sections["proxy-providers"]
		sources.written = providerKeys(section)
		if sources.written == nil && whole != "" && whole != section {
			sources.written = providerKeys(whole)
		}
	}
	sections, whole := sectionTexts(document, "proxy-providers", "proxies")
	var providers struct {
		Providers map[string]map[string]any `yaml:"proxy-providers"`
	}
	if section := sections["proxy-providers"]; section != "" {
		if yaml.Unmarshal([]byte(section), &providers) != nil && whole != "" {
			_ = yaml.Unmarshal([]byte(whole), &providers)
		}
	}
	for name, definition := range providers.Providers {
		sources.definitions[name] = definition
	}
	keep := map[string]bool{}
	for name, proxy := range own {
		if ownNodeWithoutRecord(name, proxy) {
			keep[name] = true
		}
	}
	if section := sections["proxies"]; section != "" && len(keep) > 0 {
		var proxies struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		_ = yaml.ClashUnmarshal([]byte(section), &proxies, yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any{})}, nil)
		for _, mapping := range proxies.Proxies {
			if name, ok := adapter.ClashMappingNodeName(mapping); ok && keep[name] {
				sources.kept[name] = mapping
			}
		}
	}
	return sources
}

func sectionTexts(text string, keys ...string) (sections map[string]string, whole string) {
	text = strings.TrimPrefix(text, "\ufeff")
	if len(text) <= nodeConfigWholeLimit {
		whole = text
	}
	sections = map[string]string{}
	located, ok := yaml.ClashTopLevelSections(unsafe.Slice(unsafe.StringData(text), len(text)))
	if !ok {
		for _, key := range keys {
			if whole != "" {
				sections[key] = whole
			}
		}
		return sections, whole
	}
	for i, section := range located {
		if !slices.Contains(keys, section.Key) {
			continue
		}
		end := len(text)
		if i+1 < len(located) {
			end = located[i+1].Start
		}
		sections[section.Key] = text[section.Start:end]
	}
	return sections, whole
}

func providerKeys(text string) []string {
	var root yaml.Node
	if text == "" || yaml.Unmarshal([]byte(text), &root) != nil || len(root.Content) != 1 {
		return nil
	}
	top := resolveAlias(root.Content[0])
	if top.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "proxy-providers" {
			var keys []string
			seen := map[string]bool{}
			appendMappingKeys(resolveAlias(top.Content[i+1]), &keys, seen, 0)
			return keys
		}
	}
	return nil
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode && depth < 16; depth++ {
		node = node.Alias
	}
	return node
}

func appendMappingKeys(mapping *yaml.Node, keys *[]string, seen map[string]bool, depth int) {
	if mapping == nil || mapping.Kind != yaml.MappingNode || depth > 16 {
		return
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if key.Tag == "!!merge" || key.Value == "<<" {
			merged := resolveAlias(value)
			if merged != nil && merged.Kind == yaml.SequenceNode {
				for _, item := range merged.Content {
					appendMappingKeys(resolveAlias(item), keys, seen, depth+1)
				}
			} else {
				appendMappingKeys(merged, keys, seen, depth+1)
			}
			continue
		}
		if !seen[key.Value] {
			seen[key.Value] = true
			*keys = append(*keys, key.Value)
		}
	}
}

package adapter

import (
	"fmt"
	"github.com/ProjectClash/Clash/common/structure"
	"sync/atomic"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)


func BuildLibraryNode(mapping map[string]any, options ...ProxyOption) (outbound.ProxyAdapter, string, error) {
	config, err := LibraryNodeConfig(mapping)
	if err != nil {
		return nil, "", err
	}
	var built outbound.ProxyAdapter
	if _, err := ParseProxy(mapping, append(options, func(opt *proxyOption) { opt.clashBuilt = &built })...); err != nil {
		return nil, "", err
	}
	return built, config, nil
}

func LibraryNodeConfig(mapping map[string]any) (string, error) {
	proxyType, _ := mapping["type"].(string)
	if catalogKeepsBuilt(proxyType) {
		return "", ErrNotLibraryNode
	}
	config, ok := encodeNodeConfig(mapping)
	if !ok {
		return "", ErrNotLibraryNode
	}
	return config, nil
}

var ErrNotLibraryNode = fmt.Errorf("the node stays in the configuration's proxies")

func NodeLibraryProxies(library *outbound.NodeLibrary, options ...ProxyOption) []C.Proxy {
	return NewLibraryNodes(library, options...).Proxies()
}

var clashBuilds atomic.Pointer[func()]

func CountBuilds(count func()) (restore func()) {
	clashBuilds.Store(&count)
	return func() { clashBuilds.Store(nil) }
}

func ClashNodeName(value any) (string, bool) {
	if name, ok := value.(string); ok {
		return name, true
	}
	var named struct {
		Name string `proxy:"name"`
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if value == nil || decoder.Decode(map[string]any{"name": value}, &named) != nil {
		return "", false
	}
	return named.Name, true
}

func ClashMappingNodeName(mapping map[string]any) (string, bool) {
	if value, ok := mapping["name"]; ok {
		return ClashNodeName(value)
	}
	var named struct {
		Name string `proxy:"name"`
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if decoder.Decode(mapping, &named) != nil || named.Name == "" {
		return "", false
	}
	return named.Name, true
}

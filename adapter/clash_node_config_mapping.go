package adapter

import (
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func NodeConfigMapping(proxy C.Proxy) (mapping map[string]any, ok bool, err error) {
	var config string
	switch p := proxy.(type) {
	case *libraryNode:
		config, ok = outbound.LibraryNodeConfig(p.nodes.store, p.index()), true
	case *Proxy:
		config, ok = outbound.CatalogNodeConfig(p.ProxyAdapter)
	}
	if !ok {
		return nil, false, nil
	}
	mapping, err = decodeNodeConfig(config)
	if err != nil {
		return nil, false, err
	}
	return mapping, true, nil
}

func NodeKeepsBuilt(proxyType string) bool { return catalogKeepsBuilt(proxyType) }

func NodeHasRecord(proxy C.Proxy) bool {
	switch p := proxy.(type) {
	case *libraryNode:
		return true
	case *Proxy:
		_, ok := outbound.CatalogNodeConfig(p.ProxyAdapter)
		return ok
	}
	return false
}

package clash

import (
	"path/filepath"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
)

const nodeCatalogDirectoryName = "node-catalog"

func armNodeCatalog(platform PlatformInterface) {
	directory := ""
	if platform.UnderNetworkExtension() {
		directory = filepath.Join(C.Path.HomeDir(), nodeCatalogDirectoryName)
		if removed := outbound.SweepNodeStoreFiles(directory); removed > 0 {
			log.Infoln("[Proxy] removed %d node store files earlier processes left", removed)
		}
	}
	adapter.SetNodeCatalogDirectory(directory)
}

const spreadLibraryLimit = 256

func nodeCatalogLimit(groups, spread int) int {
	return max(64, 2*groups+10+spread)
}

func refreshNodeCatalog() {
	proxies := tunnel.Proxies()
	groups := 0
	var pins []C.ProxyAdapter
	pin := func(proxy C.Proxy) {
		if node := chosenNodeOf(proxy); node != nil {
			pins = append(pins, adapter.PinnedProxy(node).Adapter())
		}
	}
	spread := map[C.ProxyAdapter]struct{}{}
	spreadLibrary := 0
	for _, proxy := range proxies {
		if _, ok := proxy.Adapter().(outboundgroup.ProxyGroup); ok {
			groups++
			pin(proxy)
		}
		if lb, ok := proxy.Adapter().(*outboundgroup.LoadBalance); ok {
			members := lb.Members(false)
			libraryMembers := 0
			for i := 0; i < members.Len(); i++ {
				member := members.At(i)
				if adapter.IsLibraryNode(member) {
					libraryMembers++
					continue
				}
				if catalog, _ := outbound.IsCatalogNode(member.Adapter()); catalog {
					spread[member.Adapter()] = struct{}{}
				}
			}
			spreadLibrary += min(libraryMembers, spreadLibraryLimit)
		}
	}
	pinHop := func(proxy C.Proxy) {
		if _, built := outbound.IsCatalogNode(proxy.Adapter()); !built {
			return
		}
		if hop := proxy.ProxyInfo().DialerProxy; hop != "" {
			if target, ok := lookupRunningProxy(hop); ok {
				pin(target)
			}
		}
	}
	rangeHeldProxies(func(proxy C.Proxy) bool { pinHop(proxy); return true })
	outbound.SetNodeCatalogLimit(nodeCatalogLimit(groups, len(spread)+spreadLibrary))
	outbound.SetNodeCatalogPins(pins)
	outbound.TrimNodeCatalog()
}

func chosenNodeOf(proxy C.Proxy) C.Proxy {
	for depth := 0; proxy != nil && depth < 8; depth++ {
		switch proxy.Adapter().(type) {
		case *outboundgroup.LoadBalance:
			return nil
		case outboundgroup.ProxyGroup:
			proxy = proxy.Unwrap(&C.Metadata{}, false)
		default:
			return proxy
		}
	}
	return nil
}

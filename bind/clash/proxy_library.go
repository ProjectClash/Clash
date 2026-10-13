package clash

import (
	"github.com/ProjectClash/Clash/adapter"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func rangeHeldProxies(f func(C.Proxy) bool) {
	for _, proxy := range tunnel.Proxies() {
		if !f(proxy) {
			return
		}
	}
	more := true
	if nodes, ok := tunnel.ProxyLibrary().(*adapter.LibraryNodes); ok {
		nodes.RangeLive(func(proxy C.Proxy) bool { more = f(proxy); return more })
	}
	for _, provider := range tunnel.Providers() {
		if !more {
			return
		}
		if provider.VehicleType() == P.Compatible {
			continue
		}
		more = rangeHeldMembers(provider.ProxyList(), f)
	}
}

func rangeHeldMembers(list C.ProxyList, f func(C.Proxy) bool) bool {
	if nodes, ok := list.(*adapter.LibraryNodes); ok {
		more := true
		nodes.RangeLive(func(proxy C.Proxy) bool { more = f(proxy); return more })
		return more
	}
	for i := 0; i < list.Len(); i++ {
		if held := adapter.HeldProxy(list.At(i)); held != nil && !f(held) {
			return false
		}
	}
	return true
}

func lookupRunningProxy(name string) (C.Proxy, bool) {
	return tunnel.LookupProxy(name)
}

func providerNodesNamed(name string) []C.Proxy {
	var found []C.Proxy
	for _, provider := range tunnel.Providers() {
		if provider.VehicleType() == P.Compatible {
			continue
		}
		list := provider.ProxyList()
		if library, ok := list.(C.ProxyLibrary); ok {
			if proxy, ok := library.Lookup(name); ok {
				found = append(found, proxy)
			}
			continue
		}
		for i := 0; i < list.Len(); i++ {
			if proxy := list.At(i); proxy.Name() == name {
				found = append(found, proxy)
			}
		}
	}
	return found
}

func runningNodeCount() int {
	count := 0
	if library := tunnel.ProxyLibrary(); library != nil {
		count += library.Len()
	}
	return count
}

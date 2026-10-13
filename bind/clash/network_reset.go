package clash

import (
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func resetEveryOutboundSession() int {
	seen := map[C.ProxyAdapter]struct{}{}
	var adapters []C.ProxyAdapter
	add := func(proxy C.Proxy) {
		if proxy == nil {
			return
		}
		adapter := proxy.Adapter()
		if _, dup := seen[adapter]; dup {
			return
		}
		seen[adapter] = struct{}{}
		adapters = append(adapters, adapter)
	}
	rangeHeldProxies(func(proxy C.Proxy) bool { add(proxy); return true })
	return resetSessionsOf(adapters)
}

func resetSessionsOf(adapters []C.ProxyAdapter) int {
	reset := 0
	for _, adapter := range adapters {
		if resetter, ok := outbound.AsNetworkResetter(adapter); ok {
			resetter.ResetNetwork()
			reset++
		}
	}
	return reset
}

func checkProvidersInUseOnce() {
	if pause.IsDevicePaused() || pause.IsNetworkPaused() {
		return
	}
	for _, provider := range tunnel.Providers() {
		if checker, ok := provider.(interface{ HealthCheckAfterNetworkChange() }); ok {
			checker.HealthCheckAfterNetworkChange()
		}
	}
}

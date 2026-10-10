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
	for _, proxy := range tunnel.Proxies() {
		add(proxy)
	}
	for _, provider := range tunnel.Providers() {
		for _, proxy := range provider.Proxies() {
			add(proxy)
		}
	}
	return resetSessionsOf(adapters)
}

func resetSessionsOf(adapters []C.ProxyAdapter) int {
	reset := 0
	for _, adapter := range adapters {
		if resetter, ok := adapter.(outbound.NetworkResetter); ok {
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

package adapter

import (
	"sync/atomic"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

var parsedProxyObserver atomic.Pointer[func(outbound.ProxyAdapter)]

func ClashObserveParsedProxies(observer func(outbound.ProxyAdapter)) (stop func()) {
	previous := parsedProxyObserver.Swap(&observer)
	return func() { parsedProxyObserver.Store(previous) }
}

func reportParsedProxy(proxy outbound.ProxyAdapter) {
	if observer := parsedProxyObserver.Load(); observer != nil {
		(*observer)(proxy)
	}
}

package provider

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func TestReplacingProxiesWhileRoundsReadThemIsSynchronised(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < 8; i++ {
		proxies = append(proxies, adapter.NewProxy(outbound.NewDirect()))
	}
	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/", 1, 300, true, nil)
	defer healthCheck.close()

	replaced := make(chan struct{})
	go func() {
		defer close(replaced)
		for i := 0; i < 64; i++ {
			healthCheck.setProxies(proxies[:i%len(proxies)+1])
		}
	}()
	scheduled := make(chan struct{})
	go func() {
		defer close(scheduled)
		for i := 0; i < 32; i++ {
			healthCheck.checkScheduled()
		}
	}()
	for i := 0; i < 32; i++ {
		healthCheck.check()
	}
	<-replaced
	<-scheduled
}

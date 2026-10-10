package clash

import (
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestAHealthRoundReadsTheTablesWhileTheySwap(t *testing.T) {
	saved, savedProviders := tunnel.Proxies(), tunnel.Providers()
	t.Cleanup(func() { tunnel.UpdateProxies(saved, savedProviders) })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				checkProvidersInUseOnce()
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		tunnel.UpdateProxies(map[string]constant.Proxy{}, map[string]provider.ProxyProvider{})
	}
	close(stop)
	wg.Wait()
}

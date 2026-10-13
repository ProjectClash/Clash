package clash

import (
	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func chosenNodeNames() map[string]struct{} {
	chosen := map[string]struct{}{}
	for _, proxy := range tunnel.Proxies() {
		group, ok := proxy.Adapter().(interface{ Now() string })
		if !ok {
			continue
		}
		if name := group.Now(); name != "" {
			chosen[name] = struct{}{}
		}
	}
	return chosen
}

func armChosenFirst() {
	provider.SetHealthCheckFirst(chosenNodeNames)
}

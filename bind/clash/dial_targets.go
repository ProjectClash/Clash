package clash

import (
	"net"
	"sort"
	"strconv"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

type dialTarget struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Addr        string `json:"addr"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Provider    string `json:"provider,omitempty"`
	DialerProxy string `json:"dialerProxy,omitempty"`
}

func DialTargetsJSON() string {
	targets := make([]dialTarget, 0, 32)
	add := func(proxy C.Proxy, provider string) {
		address := proxy.Addr()
		if address == "" {
			return
		}
		target := dialTarget{
			Name:        proxy.Name(),
			Type:        proxy.Type().String(),
			Addr:        address,
			Provider:    provider,
			DialerProxy: proxy.ProxyInfo().DialerProxy,
		}
		if host, port, err := net.SplitHostPort(address); err == nil {
			target.Host = host
			if number, err := strconv.Atoi(port); err == nil {
				target.Port = number
			}
		}
		targets = append(targets, target)
	}

	for _, proxy := range tunnel.Proxies() {
		add(proxy, "")
	}
	if library := tunnel.ProxyLibrary(); library != nil {
		for i := 0; i < library.Len(); i++ {
			add(library.At(i), "")
		}
	}
	for name, provider := range tunnel.Providers() {
		if provider.VehicleType() == P.Compatible {
			continue
		}
		list := provider.ProxyList()
		for i := 0; i < list.Len(); i++ {
			add(list.At(i), name)
		}
	}

	sort.SliceStable(targets, func(left, right int) bool {
		if targets[left].Provider != targets[right].Provider {
			return targets[left].Provider < targets[right].Provider
		}
		return targets[left].Name < targets[right].Name
	})
	return bridgeSafeString(mustJSON(map[string]any{"targets": targets}))
}

package clash

import (
	"fmt"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/config"
)

type ipStackSettings struct {
	queryMode   resolver.IPQueryPolicy
	tunIPv6Mode string
}

var setupIPStack atomic.Pointer[ipStackSettings]

func currentIPStackSettings() ipStackSettings {
	if p := setupIPStack.Load(); p != nil {
		return *p
	}
	return ipStackSettings{}
}
func setIPStackSettings(p ipStackSettings) {
	setupIPStack.Store(&p)
	resolver.SetIPQueryPolicy(p.queryMode)
}

const ipStackFollowsConfiguration = "config"

func parseIPStackSettings(query, tun string) (ipStackSettings, error) {
	if query == "" && tun == "" {
		return ipStackSettings{}, nil
	}
	if query == "" || tun == "" {
		return ipStackSettings{}, fmt.Errorf("clash: IPQueryMode and TunIPv6Mode must be supplied together")
	}
	if query == ipStackFollowsConfiguration {
		query = ""
	}
	p, err := resolver.ParseIPQueryPolicy(query)
	if err != nil {
		return ipStackSettings{}, fmt.Errorf("clash: SetupOptions.IPQueryMode: %w", err)
	}
	switch tun {
	case "disabled", "automatic", "enabled", ipStackFollowsConfiguration:
	default:
		return ipStackSettings{}, fmt.Errorf("clash: invalid SetupOptions.TunIPv6Mode %q", tun)
	}
	return ipStackSettings{p, tun}, nil
}
func applyIPStackSettings(raw *config.RawConfig, p ipStackSettings) {
	if p.queryMode != resolver.IPQueryLegacy {
		raw.IPv6 = p.queryMode != resolver.IPQueryIPv4Only
		switch p.queryMode {
		case resolver.IPQueryIPv4Only:
			raw.DNS.IPv6 = false
		case resolver.IPQueryPreferIPv6, resolver.IPQueryIPv6Only:
			raw.DNS.IPv6 = true
		}
	}
	switch p.tunIPv6Mode {
	case "", ipStackFollowsConfiguration:
	case "disabled":
		raw.PreserveTunIPv6 = false
		raw.Tun.Inet6Address = nil
	default:
		raw.PreserveTunIPv6 = true
		if len(raw.Tun.Inet6Address) == 0 {
			raw.Tun.Inet6Address = config.DefaultRawConfig().Tun.Inet6Address
		}
	}
}

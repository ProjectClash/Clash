package clash

import (
	"net/netip"
	"strings"

	"github.com/ProjectClash/Clash/component/netidentity"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/log"
)

func SetNetworkIdentity(kind, routers, ssid, bssid, radio string) {
	id := netidentity.Identity{Kind: kind, SSID: ssid, BSSID: bssid, Radio: radio}
	for _, field := range strings.Split(routers, ",") {
		if addr, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil {
			id.Routers = append(id.Routers, addr.Unmap())
		}
	}
	previousSSID := netidentity.Current().SSID
	if !netidentity.Set(id) {
		return
	}
	current := netidentity.Current()
	log.Debugln("[Network] now on %q ssid=%q bssid=%q routers=%v radio=%q",
		current.Kind, current.SSID, current.BSSID, current.Routers, current.Radio)
	if current.SSID != previousSSID && dns.SSIDPoliciesInForce() {
		resolver.ClearCacheNow()
	}
}

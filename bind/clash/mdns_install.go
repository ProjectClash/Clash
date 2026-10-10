package clash

import (
	"github.com/ProjectClash/Clash/dns"
)

func installLocalZoneResolver(enabled bool) {
	if !enabled || !mdnsSupported {
		dns.SetLocalZoneExchanger(nil)
		return
	}
	dns.SetLocalZoneExchanger(exchangeMulticastDNS)
}

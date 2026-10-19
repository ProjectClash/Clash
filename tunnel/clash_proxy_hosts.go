package tunnel

import (
	"net/netip"

	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)


func withProxyHosts(hosts C.ClashProxyHosts, proxy C.Proxy, metadata, dialMetadata *C.Metadata) *C.Metadata {
	if hosts == nil || metadata.Host == "" || proxy == nil {
		return dialMetadata
	}
	switch terminalAdapterType(proxy, metadata) {
	case C.Direct, C.Reject, C.RejectDrop, C.Pass, C.Dns:
		return dialMetadata
	}
	ips, name, ok := hosts.SearchProxyHost(metadata.Host)
	if !ok {
		return dialMetadata
	}
	mapped := *dialMetadata
	if name != "" {
		mapped.Host, mapped.DstIP, mapped.DNSMode = name, netip.Addr{}, C.DNSNormal
	} else {
		value, err := resolver.NewHostValueByIPs(ips)
		if err != nil {
			return dialMetadata
		}
		ip, err := ipStackHostAddress(&value)
		if err != nil {
			return dialMetadata
		}
		mapped.Host, mapped.DstIP, mapped.DNSMode = "", ip, C.DNSHosts
	}
	log.Debugln("[ProxyHosts] %s --> %s asks %s for %s", metadata.SourceDetail(), metadata.RemoteAddress(), proxy.Name(), mapped.RemoteAddress())
	return &mapped
}

package clash

import (
	"sort"
	"strings"

	"github.com/ProjectClash/Clash/config"
	MDNS "github.com/ProjectClash/Clash/dns"
)

type dnsTransportSnapshot struct {
	main        []string
	fallback    []string
	defaults    []string
	proxyServer []string
	direct      []string
	policy      []string
}

func snapshotDNSTransports(cfg *config.Config) dnsTransportSnapshot {
	if cfg == nil || cfg.DNS == nil {
		return dnsTransportSnapshot{}
	}
	policy := make([]MDNS.NameServer, 0)
	for _, item := range cfg.DNS.NameServerPolicy {
		policy = append(policy, item.NameServers...)
	}
	for _, item := range cfg.DNS.ProxyServerPolicy {
		policy = append(policy, item.NameServers...)
	}
	return dnsTransportSnapshot{
		main:        classifyDNSTransports(cfg.DNS.NameServer),
		fallback:    classifyDNSTransports(cfg.DNS.Fallback),
		defaults:    classifyDNSTransports(cfg.DNS.DefaultNameserver),
		proxyServer: classifyDNSTransports(cfg.DNS.ProxyServerNameserver),
		direct:      classifyDNSTransports(cfg.DNS.DirectNameServer),
		policy:      classifyDNSTransports(policy),
	}
}

func classifyDNSTransports(servers []MDNS.NameServer) []string {
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		kind := server.Net
		switch server.Net {
		case "":
			kind = "udp"
		case "tls":
			kind = "dot"
		case "https":
			switch {
			case strings.EqualFold(server.Params["h3"], "true"):
				kind = "doh3"
			case server.PreferH3:
				kind = "doh-h3-preferred"
			default:
				kind = "doh"
			}
		case "quic":
			kind = "doq"
		}
		if kind != "" {
			seen[kind] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for kind := range seen {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result
}

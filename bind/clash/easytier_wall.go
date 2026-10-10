package clash

import (
	"fmt"
	"strings"

	"github.com/ProjectClash/Clash/config"
)

func easyTierWalledProfile(policy appleRuntimePolicy) bool {
	return policy.profile.inheritsIOSPacketTunnelBehavior()
}

func isEasyTierProxyType(proxy map[string]any) bool {
	kind, _ := proxy["type"].(string)
	return strings.EqualFold(strings.TrimSpace(kind), "easytier")
}

func isEasyTierNameserver(server string) bool {
	lower := strings.ToLower(strings.TrimSpace(server))
	return strings.HasPrefix(lower, "et://") || strings.HasPrefix(lower, "easytier://")
}

func stripEasyTierNameservers(raw *config.RawConfig) []string {
	stripped := []string{}
	filter := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		for _, ns := range list {
			if isEasyTierNameserver(ns) {
				stripped = append(stripped, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
		}
		return kept
	}
	raw.DNS.NameServer = filter("nameserver", raw.DNS.NameServer)
	raw.DNS.Fallback = filter("fallback", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = filter("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = filter("direct-nameserver", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = filter("default-nameserver", raw.DNS.DefaultNameserver)
	stripped = append(stripped, filterPolicyNameserversWhere("nameserver-policy", raw.DNS.NameServerPolicy, isEasyTierNameserver)...)
	stripped = append(stripped, filterPolicyNameserversWhere("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy, isEasyTierNameserver)...)
	return stripped
}

func easyTierPlaceholderDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !easyTierWalledProfile(policy) {
		return nil
	}
	proxies, _ := root["proxies"].([]any)
	var reported []configDeviation
	for index, entry := range proxies {
		proxy, isMap := entry.(map[string]any)
		if !isMap || !isEasyTierProxyType(proxy) {
			continue
		}
		name, _ := proxy["name"].(string)
		given := fmt.Sprintf("proxies[%d] (type: easytier)", index)
		if name != "" {
			given = fmt.Sprintf("%s (proxies[%d], type: easytier)", name, index)
		}
		reported = append(reported, configDeviation{
			Field:       "proxies",
			Given:       given,
			Effective:   easyTierPlaceholderRule.effective,
			Category:    easyTierPlaceholderRule.category,
			Reason:      easyTierPlaceholderRule.reason,
			Source:      easyTierPlaceholderRule.source,
			Recoverable: easyTierPlaceholderRule.recoverable,
			Alternative: easyTierPlaceholderRule.alternative,
			Mechanism:   easyTierPlaceholderRule.mechanism,
			Written:     true,
		})
	}
	return reported
}

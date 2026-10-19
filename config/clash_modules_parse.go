package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ProjectClash/Clash/common/orderedmap"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/dns"

	singtun "github.com/metacubex/sing-tun"
)


const everyModeRulesFormat = "x-clash-every-mode-rules"

const maxIPRewriteLines = 256

func parseClashRouting(rawCfg *RawConfig, proxies map[string]C.Proxy, library C.ProxyLibrary, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule) (C.ClashRouting, error) {
	routing := C.ClashRouting{RejectPage: rawCfg.ClashRejectPage}
	proxyHosts, err := parseProxyHosts(rawCfg.ClashProxyHosts)
	if err != nil {
		return routing, err
	}
	if proxyHosts != nil {
		routing.ProxyHosts = proxyHosts
	}
	switch value := strings.ToLower(strings.TrimSpace(rawCfg.ClashBlockQUIC)); value {
	case "", "off", "always-allow", "per-policy":
	case C.BlockQUICAllProxy, C.BlockQUICAll:
		routing.BlockQUIC = value
	default:
		return routing, fmt.Errorf("x-clash-block-quic: %q is not all-proxy, all or off", rawCfg.ClashBlockQUIC)
	}
	switch upper := strings.ToUpper(strings.TrimSpace(rawCfg.ClashUDPUnsupported)); upper {
	case "", "DIRECT", "REJECT":
		routing.UDPUnsupported = upper
	default:
		return routing, fmt.Errorf("x-clash-udp-unsupported: %q is not DIRECT or REJECT", rawCfg.ClashUDPUnsupported)
	}
	for _, address := range []struct {
		key, text string
		v6        bool
		into      *netip.Addr
	}{
		{"x-clash-stun-response-ip", rawCfg.ClashSTUNResponseIP, false, &routing.STUNResponseIPv4},
		{"x-clash-stun-response-ipv6", rawCfg.ClashSTUNResponseIPv6, true, &routing.STUNResponseIPv6},
	} {
		if address.text == "" {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(address.text))
		if err != nil || addr.Unmap().Is4() == address.v6 {
			return routing, fmt.Errorf("%s: %q is not an IPv%s address", address.key, address.text, map[bool]string{false: "4", true: "6"}[address.v6])
		}
		*address.into = addr.Unmap()
		if address.v6 {
			*address.into = addr
		}
	}
	rules, err := parseRules(rawCfg.ClashEveryModeRules, proxies, library, ruleProviders, subRules, everyModeRulesFormat)
	if err != nil {
		return routing, err
	}
	routing.EveryModeRules = rules
	return routing, nil
}

func parseIPRewrite(lines []string) ([]singtun.IPRewriteRule, error) {
	var rules []singtun.IPRewriteRule
	if len(lines) > maxIPRewriteLines {
		return nil, fmt.Errorf("x-clash-ip-rewrite: %d lines, at most %d: every packet is checked against them", len(lines), maxIPRewriteLines)
	}
	for _, line := range lines {
		rule, err := singtun.ParseIPRewriteLine(line)
		if err != nil {
			return nil, fmt.Errorf("x-clash-ip-rewrite: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseSSIDNameservers(ssidNameservers *orderedmap.OrderedMap[string, any], respectRules bool, preferH3 bool) ([]dns.SSIDPolicy, error) {
	if ssidNameservers == nil {
		return nil, nil
	}
	var policies []dns.SSIDPolicy
	for pair := ssidNameservers.Oldest(); pair != nil; pair = pair.Next() {
		ssid := strings.TrimSpace(pair.Key)
		if ssid == "" {
			return nil, errors.New("dns.x-clash-ssid-nameservers: a Wi-Fi name is empty")
		}
		servers, err := utils.ToStringSlice(pair.Value)
		if err != nil {
			return nil, fmt.Errorf("dns.x-clash-ssid-nameservers[%s]: %w", pair.Key, err)
		}
		nameservers, err := parseNameServer(servers, respectRules, preferH3)
		if err != nil {
			return nil, fmt.Errorf("dns.x-clash-ssid-nameservers[%s]: %w", pair.Key, err)
		}
		if len(nameservers) == 0 {
			return nil, fmt.Errorf("dns.x-clash-ssid-nameservers[%s]: no nameserver", pair.Key)
		}
		policies = append(policies, dns.SSIDPolicy{SSID: ssid, NameServers: nameservers})
	}
	return policies, nil
}

type clashProxyHosts struct {
	tree *trie.DomainTrie[resolver.HostValue]
}

func (h clashProxyHosts) SearchProxyHost(host string) ([]netip.Addr, string, bool) {
	node := h.tree.Search(host)
	if node == nil {
		return nil, "", false
	}
	value := node.Data()
	if value.IsDomain {
		return nil, value.Domain, true
	}
	return value.IPs, "", true
}

func parseProxyHosts(entries map[string]any) (C.ClashProxyHosts, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	tree := trie.New[resolver.HostValue]()
	for domain, anyValue := range entries {
		values, err := utils.ToStringSlice(anyValue)
		if err != nil {
			return nil, fmt.Errorf("x-clash-proxy-hosts[%s]: %w", domain, err)
		}
		value, err := resolver.NewHostValue(values)
		if err != nil {
			return nil, fmt.Errorf("x-clash-proxy-hosts[%s]: %v is not an address, addresses or a name", domain, anyValue)
		}
		if err := tree.Insert(domain, value); err != nil {
			return nil, fmt.Errorf("x-clash-proxy-hosts[%s]: %w", domain, err)
		}
	}
	tree.Optimize()
	return clashProxyHosts{tree: tree}, nil
}

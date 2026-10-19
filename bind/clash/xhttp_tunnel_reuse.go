package clash

import (
	"fmt"
	"strings"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

func xhttpTunnelReuseProfile(policy appleRuntimePolicy) bool {
	return policy.profile.inheritsIOSPacketTunnelBehavior()
}

func applyXHTTPTunnelReuse(profile runtimeProfile) {
	if profile.inheritsIOSPacketTunnelBehavior() {
		outbound.SetXHTTPDefaultReuse(outbound.XHTTPTunnelReuse())
		return
	}
	outbound.SetXHTTPDefaultReuse(nil)
}

var xhttpTunnelReuseRule = deviationRule{
	field:       "proxies[vless].xhttp-opts.reuse-settings",
	ruleScan:    true,
	category:    deviationForced,
	defaultOnly: true,
	recoverable: true,
	effective: "the node shares its connections: every stream rides one of at most three, " +
		"and a connection takes 600 to 900 requests over 1,800 to 3,000 seconds before a new one opens",
	reason: "on this device a connection for every stream ran the tunnel out of memory on a subscription of XHTTP nodes; " +
		"writing reuse-settings on the node uses yours instead",
	source: "transport/xhttp/client.go NewClient (no reuse without reuse-settings); mihomo docs " +
		"config/proxies/transport.md xhttp-opts.reuse-settings (no default, unlike the original); " +
		"Xray-core infra/conf/transport_method.go as of 2026-10, commit 18e2839 (the default used here, as libXray ships it)",
	upstreamDefault: "none (a new connection for every stream)",
	applies:         xhttpTunnelReuseProfile,
	mechanism: "bind/clash Setup sets outbound.SetXHTTPDefaultReuse from the runtime profile; " +
		"adapter/outbound/vless.go builds xhttp.ReuseConfig from it when the node's reuse-settings is nil, " +
		"and a download-settings without its own reuse-settings inherits it as upstream's copy does",
}

func isXHTTPReuseDefaulted(proxy map[string]any) bool {
	kind, _ := proxy["type"].(string)
	network, _ := proxyOption(proxy, "network").(string)
	if !strings.EqualFold(strings.TrimSpace(kind), "vless") || network != "xhttp" {
		return false
	}
	options, _ := proxyOption(proxy, "xhttp-opts").(map[string]any)
	return proxyOption(options, "reuse-settings") == nil
}

func proxyOption(options map[string]any, name string) any {
	if value, ok := options[name]; ok {
		return value
	}
	for key, value := range options {
		if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), name) {
			return value
		}
	}
	return nil
}

func xhttpTunnelReuseDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !xhttpTunnelReuseProfile(policy) {
		return nil
	}
	proxies, _ := root["proxies"].([]any)
	var reported []configDeviation
	for index, entry := range proxies {
		proxy, isMap := entry.(map[string]any)
		if !isMap || !isXHTTPReuseDefaulted(proxy) {
			continue
		}
		node := fmt.Sprintf("proxies[%d]", index)
		if name, _ := proxy["name"].(string); name != "" {
			node = fmt.Sprintf("%s (proxies[%d])", name, index)
		}
		reported = append(reported, configDeviation{
			Field:           xhttpTunnelReuseRule.field,
			Given:           node + ": not set (core default: " + xhttpTunnelReuseRule.upstreamDefault + ")",
			Effective:       xhttpTunnelReuseRule.effective,
			Category:        xhttpTunnelReuseRule.category,
			Reason:          xhttpTunnelReuseRule.reason,
			Source:          xhttpTunnelReuseRule.source,
			Recoverable:     xhttpTunnelReuseRule.recoverable,
			Mechanism:       xhttpTunnelReuseRule.mechanism,
			Written:         false,
			UpstreamDefault: xhttpTunnelReuseRule.upstreamDefault,
		})
	}
	if count, first := libraryReuseDefaulted(root); count > 0 {
		node := fmt.Sprintf("%d node in the node library, %s", count, first)
		if count > 1 {
			node = fmt.Sprintf("%d nodes in the node library, the first %s", count, first)
		}
		reported = append(reported, configDeviation{
			Field:           xhttpTunnelReuseRule.field,
			Given:           node + ": not set (core default: " + xhttpTunnelReuseRule.upstreamDefault + ")",
			Effective:       xhttpTunnelReuseRule.effective,
			Category:        xhttpTunnelReuseRule.category,
			Reason:          xhttpTunnelReuseRule.reason,
			Source:          xhttpTunnelReuseRule.source,
			Recoverable:     xhttpTunnelReuseRule.recoverable,
			Mechanism:       xhttpTunnelReuseRule.mechanism,
			Written:         false,
			UpstreamDefault: xhttpTunnelReuseRule.upstreamDefault,
		})
	}
	return reported
}

func xhttpReuseDefaultedIn(list []any, held []int) map[string]any {
	count, first := 0, ""
	for _, at := range held {
		proxy, _ := list[at].(map[string]any)
		if proxy == nil || !isXHTTPReuseDefaulted(proxy) {
			continue
		}
		if count == 0 {
			first = fmt.Sprintf("proxies[%d]", at)
			if name, _ := proxy["name"].(string); name != "" {
				first = fmt.Sprintf("%s (proxies[%d])", name, at)
			}
		}
		count++
	}
	if count == 0 {
		return nil
	}
	return map[string]any{"count": count, "first": first}
}

func libraryReuseDefaulted(root map[string]any) (count int, first string) {
	library, _ := root["x-clash-node-library"].(map[string]any)
	defaulted, _ := library["xhttp-reuse-defaulted"].(map[string]any)
	switch n := defaulted["count"].(type) {
	case int:
		count = n
	case uint64:
		count = int(n)
	case float64:
		count = int(n)
	}
	first, _ = defaulted["first"].(string)
	return count, first
}

func xhttpReuseKept(proxy map[string]any) map[string]any {
	return map[string]any{"type": proxy["type"], "name": proxy["name"], "network": proxyOption(proxy, "network")}
}

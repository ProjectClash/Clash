package clash

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/transport/xhttp"
)

var unavailableMetadataRuleToken = &lazyRegexp{expr: `(?i)(?:^|\()\s*(PROCESS-(?:NAME|PATH)(?:-REGEX|-WILDCARD)?|UID|IN-USER|SOURCE-APP-(?:SIGNING-ID|TEAM-ID))\s*,`}

const minimumSafeHysteria2UDPMTU = 272

func validateRawNetworkExtensionIntent(raw *config.RawConfig) error {
	return validateRawNetworkExtensionIntentForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
}

func validateRawNetworkExtensionIntentForApple(raw *config.RawConfig, policy appleRuntimePolicy) error {
	_ = policy
	return nil
}

func forEachOutboundMapping(raw *config.RawConfig, fn func(location string, mapping map[string]any)) {
	for index, outbound := range raw.Proxy {
		fn(fmt.Sprintf("proxies[%d]", index), outbound)
	}
	for index, group := range raw.ProxyGroup {
		fn(fmt.Sprintf("proxy-groups[%d]", index), group)
	}
	providerNames := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		provider := raw.ProxyProvider[name]
		if override, ok := provider["override"].(map[string]any); ok {
			fn(fmt.Sprintf("proxy-providers.%s.override", name), override)
		}
		for index, outbound := range providerPayloadMappings(provider["payload"]) {
			fn(fmt.Sprintf("proxy-providers.%s.payload[%d]", name, index), outbound)
		}
	}
}

func firstOutboundEmbeddedDNSFragment(raw *config.RawConfig) string {
	found := ""
	forEachOutboundMapping(raw, func(location string, mapping map[string]any) {
		if found == "" && outboundEmbeddedDNSHasFragment(mapping) {
			found = location + ".dns"
		}
	})
	return found
}

func xhttpUsesPacketUp(mapping, options map[string]any) bool {
	mode, _ := outboundScalarString(options["mode"])
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" {
		return mode == "packet-up"
	}
	if realityOptions, ok := mapping["reality-opts"].(map[string]any); ok {
		publicKey, _ := outboundScalarString(realityOptions["public-key"])
		if publicKey != "" {
			return false
		}
	}
	return true
}

func outboundScalarString(raw any) (string, bool) {
	switch value := raw.(type) {
	case string:
		return value, true
	case int:
		return fmt.Sprint(value), true
	case int32:
		return fmt.Sprint(value), true
	case int64:
		return fmt.Sprint(value), true
	case uint:
		return fmt.Sprint(value), true
	case uint32:
		return fmt.Sprint(value), true
	case uint64:
		return fmt.Sprint(value), true
	default:
		return "", false
	}
}

func providerPayloadMappings(raw any) []map[string]any {
	switch payload := raw.(type) {
	case []map[string]any:
		return payload
	case []any:
		mappings := make([]map[string]any, 0, len(payload))
		for _, item := range payload {
			if mapping, ok := item.(map[string]any); ok {
				mappings = append(mappings, mapping)
			}
		}
		return mappings
	default:
		return nil
	}
}

func outboundEgressOverrideFields(mapping map[string]any) []string {
	fields := make([]string, 0, 2)
	for _, field := range []string{"interface-name", "routing-mark"} {
		if value, exists := mapping[field]; exists && !isZeroish(value) {
			fields = append(fields, field)
		}
	}
	return fields
}

func outboundEmbeddedDNSHasFragment(mapping map[string]any) bool {
	typeName, _ := mapping["type"].(string)
	switch typeName {
	case "wireguard", "openvpn", "masque":
	default:
		return false
	}
	remoteDNSResolve, _ := mapping["remote-dns-resolve"].(bool)
	if !remoteDNSResolve {
		return false
	}
	for _, server := range dnsServerStrings(mapping["dns"]) {
		if dnsFragmentProxyName(server) != "" {
			return true
		}
	}
	return false
}

type metadataRuleOccurrence struct {
	kind     string
	location string
}

const metadataRuleKeptExplanation = "the owner metadata it tests cannot be resolved in this profile; " +
	"the rule is kept and evaluated against empty metadata, exactly as with find-process-mode off"

func summarizeMetadataRuleOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []string {
	occurrences := unavailableMetadataRuleOccurrences(raw, capability)
	occurrences = append(occurrences, inlineRuleProviderMetadataOccurrences(raw, capability)...)
	return summarizeOccurrenceList(occurrences)
}

type metadataRuleOccurrenceSummary struct {
	kind    string
	count   int
	summary string
}

func summarizeMetadataRuleOccurrenceKinds(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrenceSummary {
	occurrences := unavailableMetadataRuleOccurrences(raw, capability)
	occurrences = append(occurrences, inlineRuleProviderMetadataOccurrences(raw, capability)...)
	counts := make(map[string]int, len(occurrences))
	order := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if _, seen := counts[occurrence.kind]; !seen {
			order = append(order, occurrence.kind)
		}
		counts[occurrence.kind]++
	}
	summaries := summarizeOccurrenceList(occurrences)
	out := make([]metadataRuleOccurrenceSummary, 0, len(order))
	for i, kind := range order {
		out = append(out, metadataRuleOccurrenceSummary{kind: kind, count: counts[kind], summary: summaries[i]})
	}
	return out
}

func summarizeOccurrenceList(occurrences []metadataRuleOccurrence) []string {
	counts := make(map[string]int, len(occurrences))
	first := make(map[string]string, len(occurrences))
	order := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if _, seen := counts[occurrence.kind]; !seen {
			order = append(order, occurrence.kind)
			first[occurrence.kind] = occurrence.location
		}
		counts[occurrence.kind]++
	}
	summaries := make([]string, 0, len(order))
	for _, kind := range order {
		switch counts[kind] {
		case 1:
			summaries = append(summaries, fmt.Sprintf("%s rule at %s", kind, first[kind]))
		default:
			summaries = append(summaries, fmt.Sprintf("%d %s rules, first at %s", counts[kind], kind, first[kind]))
		}
	}
	return summaries
}

func unavailableMetadataRuleOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrence {
	occurrences := make([]metadataRuleOccurrence, 0)
	appendOccurrence := func(kind, location string) {
		occurrences = append(occurrences, metadataRuleOccurrence{kind: kind, location: location})
	}
	for index, rule := range raw.Rule {
		if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
			appendOccurrence(kind, fmt.Sprintf("rules[%d]", index))
		}
	}
	names := make([]string, 0, len(raw.SubRules))
	for name := range raw.SubRules {
		names = append(names, name)
	}
	sort.Strings(names)
	for groupIndex, name := range names {
		for ruleIndex, rule := range raw.SubRules[name] {
			if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
				appendOccurrence(kind, fmt.Sprintf("sub-rules[%d][%d]", groupIndex, ruleIndex))
			}
		}
	}
	return occurrences
}

func inlineRuleProviderMetadataOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrence {
	occurrences := make([]metadataRuleOccurrence, 0)
	names := make([]string, 0, len(raw.RuleProvider))
	for name := range raw.RuleProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for providerIndex, name := range names {
		definition := raw.RuleProvider[name]
		typeName, _ := definition["type"].(string)
		behavior, _ := definition["behavior"].(string)
		if typeName != "inline" || behavior != "classical" {
			continue
		}
		var entries []string
		switch payload := definition["payload"].(type) {
		case []any:
			for _, item := range payload {
				if rule, ok := item.(string); ok {
					entries = append(entries, rule)
				}
			}
		case []string:
			entries = payload
		}
		for ruleIndex, rule := range entries {
			if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
				occurrences = append(occurrences, metadataRuleOccurrence{
					kind: kind, location: fmt.Sprintf("rule-providers[%d].payload[%d]", providerIndex, ruleIndex),
				})
			}
		}
	}
	return occurrences
}

var metadataRuleKindNames = [...]string{
	"PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
	"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD",
	"UID", "IN-USER", "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID",
}

func matchesMetadataRuleKindName(token string) string {
	for _, name := range metadataRuleKindNames {
		if strings.EqualFold(token, name) {
			return name
		}
	}
	return ""
}

func unavailableMetadataRuleKind(rule string, capability appleProcessMetadataCapability) string {
	var kind string
	if strings.IndexByte(rule, '(') < 0 {
		comma := strings.IndexByte(rule, ',')
		if comma < 0 {
			return ""
		}
		kind = matchesMetadataRuleKindName(strings.TrimSpace(rule[:comma]))
		if kind == "" {
			return ""
		}
	} else {
		match := unavailableMetadataRuleToken.get().FindStringSubmatch(rule)
		if len(match) != 2 {
			return ""
		}
		kind = strings.ToUpper(match[1])
	}
	if capability.resolves(kind) {
		return ""
	}
	return kind
}

func isUnavailableMetadataRuleType(kind string, capability appleProcessMetadataCapability) bool {
	if capability.resolves(kind) {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
		"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD",
		"UID", "IN-USER", "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		return true
	default:
		return false
	}
}

func validateForIOS(cfg *config.Config, underNE bool) error {
	return validateForApple(cfg, nil, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func validateForApple(cfg *config.Config, raw *config.RawConfig, policy appleRuntimePolicy) error {
	if !policy.useSystemDNS {
		if err := validateDNSForIOS(cfg, policy.requirePacketTunnelDNS); err != nil {
			return err
		}
	}
	if policy.packetTunnel {
		if err := validateTunForIOS(cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateTunForIOS(cfg *config.Config) error {
	return nil
}

func validateDNSForIOS(cfg *config.Config, underNE bool) error {
	if cfg.DNS == nil || !cfg.DNS.Enable {
		return nil
	}
	if len(cfg.DNS.NameServer) == 0 {
		return fmt.Errorf("clash: dns.nameserver must be set explicitly on iOS (no system-DNS fallback available in the NE)")
	}
	return nil
}

func firstDNSPhysicalInterfaceFragment(raw *config.RawConfig) string {
	knownProxies := map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "COMPATIBLE": {},
		"PASS": {}, "PASS-RULE": {}, "GLOBAL": {}, dns.RespectRules: {},
	}
	for _, proxy := range raw.Proxy {
		if name, _ := proxy["name"].(string); name != "" {
			knownProxies[name] = struct{}{}
		}
	}
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			knownProxies[name] = struct{}{}
		}
	}

	groups := []struct {
		field   string
		servers []string
	}{
		{field: "dns.nameserver", servers: raw.DNS.NameServer},
		{field: "dns.fallback", servers: raw.DNS.Fallback},
		{field: "dns.default-nameserver", servers: raw.DNS.DefaultNameserver},
		{field: "dns.proxy-server-nameserver", servers: raw.DNS.ProxyServerNameserver},
		{field: "dns.direct-nameserver", servers: raw.DNS.DirectNameServer},
	}
	for _, group := range groups {
		if hasUnknownDNSFragmentProxy(group.servers, knownProxies) {
			return group.field
		}
	}
	if raw.DNS.NameServerPolicy != nil {
		for pair := raw.DNS.NameServerPolicy.Oldest(); pair != nil; pair = pair.Next() {
			if hasUnknownDNSFragmentProxy(dnsServerStrings(pair.Value), knownProxies) {
				return "dns.nameserver-policy"
			}
		}
	}
	if raw.DNS.ProxyServerNameserverPolicy != nil {
		for pair := raw.DNS.ProxyServerNameserverPolicy.Oldest(); pair != nil; pair = pair.Next() {
			if hasUnknownDNSFragmentProxy(dnsServerStrings(pair.Value), knownProxies) {
				return "dns.proxy-server-nameserver-policy"
			}
		}
	}
	return ""
}

func dnsServerStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		servers := make([]string, 0, len(value))
		for _, item := range value {
			if server, ok := item.(string); ok {
				servers = append(servers, server)
			}
		}
		return servers
	default:
		return nil
	}
}

func hasUnknownDNSFragmentProxy(servers []string, knownProxies map[string]struct{}) bool {
	for _, server := range servers {
		proxyName := dnsFragmentProxyName(server)
		if proxyName == "" {
			continue
		}
		if _, known := knownProxies[proxyName]; !known {
			return true
		}
	}
	return false
}

func dnsFragmentProxyName(server string) string {
	fragmentIndex := strings.IndexByte(server, '#')
	if fragmentIndex < 0 || fragmentIndex == len(server)-1 {
		return ""
	}
	var proxyName string
	for _, component := range strings.Split(server[fragmentIndex+1:], "&") {
		if !strings.Contains(component, "=") {
			decoded, err := url.PathUnescape(component)
			if err != nil {
				return component
			}
			proxyName = decoded
		}
	}
	return proxyName
}

func unfetchableProviderNames(raw *config.RawConfig) map[string]bool {
	out := map[string]bool{}
	if raw == nil {
		return out
	}
	for _, group := range []map[string]map[string]any{raw.ProxyProvider, raw.RuleProvider} {
		for name, def := range group {
			if t, _ := def["type"].(string); !strings.EqualFold(t, "http") {
				continue
			}
			rawURL, _ := def["url"].(string)
			if _, err := normalizeResourceURL(rawURL, "provider"); err != nil {
				out[name] = true
			}
		}
	}
	return out
}

type outboundOptionIssue struct {
	Field  string
	Reason string
}

func upstreamRefusedOutboundOptions(raw *config.RawConfig) []outboundOptionIssue {
	issues := []outboundOptionIssue{}
	for index, outbound := range raw.Proxy {
		if field, reason := upstreamRefusedOutboundOption(outbound); field != "" {
			issues = append(issues, outboundOptionIssue{Field: fmt.Sprintf("proxies[%d].%s", index, field), Reason: reason})
		}
	}
	names := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for index, outbound := range providerPayloadMappings(raw.ProxyProvider[name]["payload"]) {
			if field, reason := upstreamRefusedOutboundOption(outbound); field != "" {
				issues = append(issues, outboundOptionIssue{
					Field: fmt.Sprintf("proxy-providers.%s.payload[%d].%s", name, index, field), Reason: reason})
			}
		}
	}
	return issues
}

func unrepresentableOutboundOptions(raw *config.RawConfig) []outboundOptionIssue {
	issues := []outboundOptionIssue{}
	for index, outbound := range raw.Proxy {
		if field, reason := unrepresentableOutboundOption(outbound); field != "" {
			issues = append(issues, outboundOptionIssue{Field: fmt.Sprintf("proxies[%d].%s", index, field), Reason: reason})
		}
	}
	names := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for index, outbound := range providerPayloadMappings(raw.ProxyProvider[name]["payload"]) {
			if field, reason := unrepresentableOutboundOption(outbound); field != "" {
				issues = append(issues, outboundOptionIssue{
					Field: fmt.Sprintf("proxy-providers.%s.payload[%d].%s", name, index, field), Reason: reason})
			}
		}
	}
	return issues
}

func upstreamRefusedOutboundOption(mapping map[string]any) (string, string) {
	proxyType, _ := outboundScalarString(mapping["type"])

	switch strings.ToLower(proxyType) {
	case "hysteria":
		for _, field := range []string{"up", "down"} {
			value, _ := outboundScalarString(mapping[field])
			if value == "" {
				continue
			}
			if utils.StringToBps(value) == 0 {
				return field, fmt.Sprintf("invaild %s speed: %s", map[string]string{"up": "upload", "down": "download"}[field], value)
			}
		}
	case "hysteria2":
		ports, _ := outboundScalarString(mapping["ports"])
		if ports != "" {
			if _, err := utils.NewUnsignedRanges[uint16](ports); err != nil {
				return "ports", err.Error()
			}
			hop, _ := outboundScalarString(mapping["hop-interval"])
			if hop != "" {
				if _, err := utils.NewUnsignedRange[uint64](hop); err != nil {
					return "hop-interval", err.Error()
				}
			}
		}
	}

	network, _ := outboundScalarString(mapping["network"])
	if strings.EqualFold(network, "xhttp") {
		if opts, ok := mapping["xhttp-opts"].(map[string]any); ok {
			for _, r := range []struct{ key, fallback string }{
				{"sc-max-each-post-bytes", "1000000"},
				{"sc-min-posts-interval-ms", "30"},
			} {
				value, ok := outboundScalarString(opts[r.key])
				if !ok || value == "" {
					continue
				}
				parsed, err := xhttp.ParseRange(value, r.fallback)
				if err != nil {
					return "xhttp-opts." + r.key, fmt.Sprintf("invalid %s: %v", r.key, err)
				}
				if parsed.Max == 0 {
					return "xhttp-opts." + r.key, fmt.Sprintf("invalid %s: must be greater than zero", r.key)
				}
			}
		}
	}
	return "", ""
}

func unrepresentableOutboundOption(mapping map[string]any) (string, string) {
	network, _ := outboundScalarString(mapping["network"])
	if strings.EqualFold(network, "grpc") {
		if opts, ok := mapping["grpc-opts"].(map[string]any); ok {
			if _, err := providerNonPositiveDurationAllowedUnits(
				opts["ping-interval"], time.Second, "gRPC ping interval", "second"); err != nil {
				return "grpc-opts.ping-interval", err.Error()
			}
		}
	}
	return "", ""
}

package clash

import (
	"fmt"
	"go.yaml.in/yaml/v3"
	"net"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/common/orderedmap"
	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/log"
	"github.com/dlclark/regexp2"
)

const disabledGeoURL = "clash-ne-disabled://prestage-required"

func parseConfigForIOS(content string, underNE bool) (*config.Config, error) {
	cfg, _, err := parseConfigForIOSInternal(content, decodeConfigText(content), underNE, false, false)
	return cfg, err
}

func parseConfigForIOSRuntime(content string, underNE bool, entry string) (*config.Config, *providerRuntime, error) {
	return parseDecodedConfigForIOSRuntime(content, decodeConfigText(content), underNE, entry)
}

func parseDecodedConfigForIOSRuntime(content string, decoded *configDecode, underNE bool, entry string) (*config.Config, *providerRuntime, error) {
	cfg, runtime, err := parseConfigForIOSInternal(content, decoded, underNE, true, entry == deviationEntryStart)
	if err != nil {
		return cfg, runtime, err
	}
	deviations, deviationErr := decoded.deviationRows(currentRuntimePolicy(underNE))
	if deviationErr != nil {
		log.Warnln("[Apple] could not compute the configuration deviation report: %v", deviationErr)
	} else {
		publishDeviations(entry, content, deviations)
	}
	return cfg, runtime, nil
}

func parseConfigForIOSInternal(content string, decoded *configDecode, underNE bool, stageRuntime bool, rememberIntent bool) (*config.Config, *providerRuntime, error) {
	if decoded.err != nil {
		return nil, nil, fmt.Errorf("clash: parse config: %w", decoded.err)
	}
	raw := decoded.raw
	if rememberIntent {
		rememberStartedIntent(content, raw)
	}
	startupStage("bind:unmarshalled")
	canonicalizeProviderDefinitionKeys(raw)
	policy := currentRuntimePolicy(underNE)
	if policy.networkExtension {
		if err := validateRawNetworkExtensionIntentForApple(raw, policy); err != nil {
			return nil, nil, err
		}
	}
	if stageRuntime {
		setStartupBreadcrumbRecording(policy.networkExtension)
		if policy.networkExtension {
			geodata.SetGeodataProgressReporter(recordStartupResource)
		} else {
			geodata.SetGeodataProgressReporter(nil)
		}
	}
	normalizeRawConfigForApple(raw, policy)
	applyIPStackSettings(raw, currentIPStackSettings())
	startupStage("bind:normalized")
	applyAppleDefaults(raw, decoded.unwritten)
	if err := validateRawConfigForIOS(raw); err != nil {
		return nil, nil, err
	}
	startupStage("bind:ios-validated")
	var runtime *providerRuntime
	var err error
	if stageRuntime {
		pointProviderCacheAtHome()
		refreshPlan := prepareProviderRefreshForTunnel(raw, policy)
		runtime, err = stageProviderRuntime(raw, policy, false)
		if err != nil {
			if stagingFailureIsEnvironmental(err) {
				return nil, nil, classify(CoreOutcomeUnknown, err)
			}
			return nil, nil, classify(CoreOutcomeConfig, err)
		}
		completeProviderRefreshAfterStaging(refreshPlan, runtime, policy)
		if len(refreshPlan.targets) > 0 {
			if runtime == nil {
				runtime = &providerRuntime{entries: map[string]providerRuntimeEntry{}, policy: policy}
			}
			runtime.refresh = refreshPlan
		}
	} else {
		stripProviderSideUpdateMetadata(raw)
	}
	startupStage("bind:providers-staged")

	cfg, err := parseRawConfigQuietly(raw)
	if err != nil {
		if runtime != nil {
			runtime.close()
		}
		return nil, nil, fmt.Errorf("clash: parse config: %w", explainInvalidDomainPatterns(raw, err))
	}
	startupStage("bind:apple-validate-in")
	if err := validateForApple(cfg, raw, policy); err != nil {
		if runtime != nil {
			runtime.close()
		}
		return nil, nil, err
	}
	return cfg, runtime, nil
}

func canonicalizeProviderDefinitionKeys(raw *config.RawConfig) {
	if raw == nil {
		return
	}
	for _, namespace := range []map[string]map[string]any{raw.ProxyProvider, raw.RuleProvider} {
		for _, definition := range namespace {
			if definition == nil {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

func canonicalizeProviderDefinitionKeysInDocument(root map[string]any) {
	for _, namespace := range []string{"proxy-providers", "rule-providers"} {
		providers, ok := root[namespace].(map[string]any)
		if !ok {
			continue
		}
		for _, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

type unwrittenAppleDefaults struct {
	unifiedDelay bool
	storeFakeIP  bool
	tunStack     bool
}

func probeUnwrittenAppleDefaults(content []byte) unwrittenAppleDefaults {
	return probeUnwrittenAppleDefaultsWith(func(out any) error { return yaml.Unmarshal(content, out) })
}

func probeUnwrittenAppleDefaultsWith(decode func(out any) error) unwrittenAppleDefaults {
	var probe struct {
		UnifiedDelay *bool `yaml:"unified-delay"`
		Profile      *struct {
			StoreFakeIP *bool `yaml:"store-fake-ip"`
		} `yaml:"profile"`
		Tun *struct {
			Stack any `yaml:"stack"`
		} `yaml:"tun"`
	}
	if err := decode(&probe); err != nil {
		return unwrittenAppleDefaults{}
	}
	return unwrittenAppleDefaults{
		unifiedDelay: probe.UnifiedDelay == nil,
		storeFakeIP:  probe.Profile == nil || probe.Profile.StoreFakeIP == nil,
		tunStack:     probe.Tun == nil || probe.Tun.Stack == nil,
	}
}

func applyAppleDefaults(raw *config.RawConfig, unwritten unwrittenAppleDefaults) {
	if unwritten.unifiedDelay {
		raw.UnifiedDelay = true
	}
	if unwritten.storeFakeIP {
		raw.Profile.StoreFakeIP = true
	}
	if unwritten.tunStack && raw.Tun.Stack != appleUnwrittenTunStack {
		raw.Tun.Stack = appleUnwrittenTunStack
	}
}

const appleUnwrittenTunStack = C.TunGvisor

func normalizeRawConfigForIOS(raw *config.RawConfig, underNE bool) {
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func normalizeRawConfigForApple(raw *config.RawConfig, policy appleRuntimePolicy) {
	if policy.memoryConservativeGeodata {
		raw.GeodataLoader = "memconservative"
	}
	geodata.SetCompiledGeoSiteOnly(policy.compiledGeoSiteOnly)
	geodata.SetCompiledGeoIPOnly(policy.compiledGeoIPOnly)
	raw.GeoAutoUpdate = false
	raw.GeoXUrl = config.RawGeoXUrl{
		GeoIp:   disabledGeoURL,
		Mmdb:    disabledGeoURL,
		ASN:     disabledGeoURL,
		GeoSite: disabledGeoURL,
	}
	if easyTierWalledProfile(policy) {
		for _, ns := range stripEasyTierNameservers(raw) {
			log.Warnln("[Apple %s] DNS %s asks an EasyTier node for overlay DNS; EasyTier is not built into this core, so the entry is stripped and the config still starts", policy.profile.String(), ns)
		}
	}
	if policy.networkExtension {
		normalizeRawNetworkExtensionSurfaces(raw, policy.processMetadata())
		setConfiguredTunnelPrefixes(tunnelPrefixesFromRaw(raw))
		if supplied := systemDNSServerSubstitutes(); len(supplied) != 0 {
			usable, dropped := usableSystemResolverSubstitutes(supplied, tunnelPrefixesFromRaw(raw))
			if len(dropped) != 0 {
				log.Warnln("[Apple %s] DNS SystemDNSServerLines %s fall inside this configuration's own tunnel ranges and are ignored: the App read the system resolvers after the tunnel's DNS settings applied", policy.profile.String(), strings.Join(dropped, ", "))
			}
			changes := substituteSystemResolvers(raw, usable)
			for _, change := range changes {
				log.Warnln("[Apple %s] DNS %s %s resolves through the system resolvers the App read before the tunnel: %s", policy.profile.String(), change.where(), change.entry, strings.Join(usable, ", "))
			}
			if len(changes) != 0 {
				dns.MarkSystemSubstitutes(usable)
			} else {
				dns.MarkSystemSubstitutes(nil)
			}
		} else {
			dns.MarkSystemSubstitutes(nil)
		}
		for _, ns := range stripNEIncompatibleNameservers(raw) {
			log.Warnln("[Apple %s] DNS %s cannot work from a packet tunnel (system resolves only to the tunnel's own DNS address, which mihomo blacklists, so it yields nothing; dhcp:// receives no DHCP offer on Apple, measured on macOS with upstream's own code outside any tunnel); stripped, resolution stays inside the core and the config still starts", policy.profile.String(), ns)
		}
		if policy.stripLoopbackResolvers {
			for _, ns := range stripLoopbackResolvers(raw) {
				log.Warnln("[Apple %s] DNS %s: it points at this device and no dns.listen in this configuration answers on that port; nothing else on this platform can, so the entry is stripped -- to use it, add dns.listen on the same port to the same configuration", policy.profile.String(), ns)
			}
		}
		if policy.repairPacketTunnelDNS {
			for _, repair := range repairApplePacketTunnelDNS(raw) {
				log.Warnln("[Apple %s] DNS %s", policy.profile.String(), repair)
			}
		}
		for _, ns := range detectUnroutableDNSFragments(raw) {
			log.Warnln("[Apple %s] DNS %s names a physical interface or an unknown proxy in its fragment; kept as-is — it will fail closed at runtime unless the name materializes (config still starts)", policy.profile.String(), ns)
		}
		capability := policy.processMetadata()
		if !capability.resolves("UID") || !uidRuleConstructible(runtime.GOOS) {
			for _, occurrence := range summarizeOccurrenceList(stripUnconstructibleUIDRules(raw)) {
				log.Warnln("[Apple %s] %s: %s", policy.profile.String(), occurrence, uidRuleExplanation)
			}
		}
		for _, notice := range unguardedControllerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, notice := range unauthenticatedLANListenerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, rule := range summarizeMetadataRuleOccurrences(raw, capability) {
			log.Warnln("[Apple %s] %s: %s", policy.profile.String(), rule, metadataRuleKeptExplanation)
		}
	}
}

func unauthenticatedLANListenerNotices(raw *config.RawConfig) []string {
	notices := make([]string, 0, 4)
	if raw.AllowLan && !authenticationCoversRemoteSources(raw) {
		for _, listener := range []struct {
			field string
			port  int
		}{{"port", raw.Port}, {"socks-port", raw.SocksPort}, {"mixed-port", raw.MixedPort}} {
			if listener.port != 0 {
				notices = append(notices, fmt.Sprintf(
					"%s %d is reachable from the local network with allow-lan and no effective authentication: "+
						"any device on any network this one joins can use it as a proxy. Set "+
						"authentication, or lan-allowed-ips, to narrow it",
					listener.field, listener.port))
			}
		}
	}
	if len(raw.Listeners) > 0 {
		notices = append(notices, fmt.Sprintf(
			"listeners declares %d inbound listener(s), each on its own listen address — "+
				"upstream defaults that to 0.0.0.0, and the allow-lan permission does not cover it. "+
				"Every device on every network this one joins can reach them unless each entry "+
				"names a narrower listen address and its own authentication",
			len(raw.Listeners)))
	}
	if len(raw.Tunnels) > 0 {
		notices = append(notices, fmt.Sprintf(
			"tunnels declares %d static tunnel listener(s), which are opened as written and are "+
				"not covered by the allow-lan permission", len(raw.Tunnels)))
	}
	for _, server := range []struct {
		field   string
		present bool
	}{
		{"ss-config", strings.TrimSpace(raw.ShadowSocksConfig) != ""},
		{"vmess-config", strings.TrimSpace(raw.VmessConfig) != ""},
		{"tuic-server", raw.TuicServer.Enable},
	} {
		if server.present {
			notices = append(notices, fmt.Sprintf(
				"%s starts a protocol server on this device, opened as written and not covered by "+
					"the allow-lan permission; its listen address is the one that entry names",
				server.field))
		}
	}
	return notices
}

func authenticationCoversRemoteSources(raw *config.RawConfig) bool {
	if len(raw.Authentication) == 0 {
		return false
	}
	for _, prefix := range raw.SkipAuthPrefixes {
		if !prefix.Addr().IsLoopback() || prefix.Bits() == 0 {
			return false
		}
	}
	return true
}

func unguardedControllerNotices(raw *config.RawConfig) []string {
	if currentRemoteControlSettings().takesOverOn(currentRuntimeProfile()) {
		return nil
	}
	if raw.Secret != "" {
		return nil
	}
	notices := make([]string, 0, 2)
	for _, endpoint := range []struct {
		field   string
		address string
	}{{"external-controller", raw.ExternalController}, {"external-controller-tls", raw.ExternalControllerTLS}} {
		if endpoint.address == "" || isLoopbackListenAddress(endpoint.address) {
			continue
		}
		notices = append(notices, fmt.Sprintf(
			"%s listens on %s with no secret: anything that can reach it can change proxies, "+
				"rules and mode on the running tunnel, and can switch allow-lan on -- which "+
				"makes this device an open proxy for whoever is on the same network. "+
				"Set secret, or bind it to 127.0.0.1",
			endpoint.field, endpoint.address))
	}
	return notices
}

func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "[::1]":
		return true
	default:
		return false
	}
}

func normalizeRawNetworkExtensionSurfaces(raw *config.RawConfig, capability appleProcessMetadataCapability) {
	forcedOff := allowLanForcedOff.Load()
	log.Infoln("[Apple] allow-lan forced-off-by-app=%v configured=%v", forcedOff, raw.AllowLan)
	if forcedOff {
		raw.AllowLan = false
	}
	raw.RedirPort = 0
	raw.TProxyPort = 0

	for _, knob := range strippedHostRouteKnobs(raw) {
		log.Warnln("[Apple NetworkExtension] %s: %s; the config still starts", knob, egressKnobRemovedReason(knob))
	}
	raw.Interface = ""
	raw.RoutingMark = 0
	if !capability.processPath {
		raw.FindProcessMode = process.FindProcessOff
	}

	raw.ExternalControllerRoutingMark = 0
	raw.ExternalControllerPipe = ""

	raw.IPTables.Enable = false
	raw.DNS.ListenRoutingMark = 0
	raw.NTP.WriteToSystem = false
}

func egressKnobRemovedReason(knob string) string {
	if knob == "routing-mark" {
		return "removed; socket marks do not exist on Apple, and upstream itself only warns that they are not supported here"
	}
	return "removed; the extension keeps the core's default interface on the current physical network, and a fixed name would pin it"
}

func strippedHostRouteKnobs(raw *config.RawConfig) []string {
	knobs := make([]string, 0, 8)
	if raw.Interface != "" {
		knobs = append(knobs, "interface-name")
	}
	if raw.RoutingMark != 0 {
		knobs = append(knobs, "routing-mark")
	}
	return knobs
}

func isNEIncompatibleNameserver(server string) bool {
	s := strings.ToLower(strings.TrimSpace(server))
	return s == "system" || strings.HasPrefix(s, "system:") || strings.HasPrefix(s, "dhcp:")
}

func isUsableBootstrapNameserver(server string) bool {
	s := strings.TrimSpace(server)
	if s == "" || isNEIncompatibleNameserver(s) {
		return false
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && net.ParseIP(u.Hostname()) != nil {
			return true
		}
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.ParseIP(host) != nil
}

func stripNEIncompatibleNameservers(raw *config.RawConfig) []string {
	stripped := []string{}
	filter := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				stripped = append(stripped, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
		}
		return kept
	}
	filterBootstrap := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		var pending []string
		usable := false
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				pending = append(pending, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
			if isUsableBootstrapNameserver(ns) {
				usable = true
			}
		}
		if !usable {
			return list
		}
		stripped = append(stripped, pending...)
		return kept
	}
	raw.DNS.NameServer = filter("nameserver", raw.DNS.NameServer)
	raw.DNS.Fallback = filter("fallback", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = filter("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = filter("direct-nameserver", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = filterBootstrap("default-nameserver", raw.DNS.DefaultNameserver)
	stripped = append(stripped, filterPolicyNameservers("nameserver-policy", raw.DNS.NameServerPolicy)...)
	stripped = append(stripped, filterPolicyNameservers("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)...)
	return stripped
}

func isDHCPNameserver(server string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "dhcp:")
}

func repairApplePacketTunnelDNS(raw *config.RawConfig) []string {
	repairs := []string{}
	defaults := config.DefaultRawConfig().DNS

	bootstrap := make([]string, 0, len(raw.DNS.DefaultNameserver))
	for _, server := range raw.DNS.DefaultNameserver {
		if isNEIncompatibleNameserver(server) {
			repairs = append(repairs, "default-nameserver system/dhcp bootstrap was replaced with explicit core bootstrap resolvers")
			continue
		}
		bootstrap = append(bootstrap, server)
	}
	if len(bootstrap) == 0 {
		bootstrap = append([]string(nil), defaults.DefaultNameserver...)
		if len(raw.DNS.DefaultNameserver) == 0 {
			repairs = append(repairs, "default-nameserver was empty and received explicit core bootstrap resolvers")
		}
	}
	raw.DNS.DefaultNameserver = bootstrap

	if !raw.DNS.Enable {
		raw.DNS.Enable = true
		repairs = append(repairs, "was enabled because an Apple packet tunnel always captures "+
			"port 53: with dns.enable false the core serves no DNS and every hijacked query "+
			"answers SERVFAIL, so the tunnel would start and resolve nothing")
	}
	if len(raw.DNS.NameServer) == 0 {
		raw.DNS.NameServer = append([]string(nil), defaults.NameServer...)
		repairs = append(repairs, "nameserver was empty after Apple normalization and received mihomo's explicit core defaults")
	}
	if raw.DNS.RespectRules && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with respect-rules and received explicit bootstrap resolvers")
	}
	if raw.DNS.ProxyServerNameserverPolicy != nil && raw.DNS.ProxyServerNameserverPolicy.Oldest() != nil && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with a policy and received explicit bootstrap resolvers")
	}
	return repairs
}

func filterPolicyNameservers(field string, policy *orderedmap.OrderedMap[string, any]) []string {
	return filterPolicyNameserversWhere(field, policy, isNEIncompatibleNameserver)
}

func filterPolicyNameserversWhere(field string, policy *orderedmap.OrderedMap[string, any], strip func(string) bool) []string {
	if policy == nil {
		return nil
	}
	stripped := []string{}
	type policyEdit struct {
		key    string
		value  any
		remove bool
	}
	edits := []policyEdit{}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		servers := dnsServerStrings(pair.Value)
		if len(servers) == 0 {
			continue
		}
		kept := make([]any, 0, len(servers))
		removed := false
		for _, ns := range servers {
			if strip(ns) {
				stripped = append(stripped, field+" "+pair.Key+" "+ns)
				removed = true
				continue
			}
			kept = append(kept, ns)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			edits = append(edits, policyEdit{key: pair.Key, value: []any{"rcode://name_error"}})
		} else {
			edits = append(edits, policyEdit{key: pair.Key, value: kept})
		}
	}
	for _, edit := range edits {
		if edit.remove {
			policy.Delete(edit.key)
		} else {
			policy.Set(edit.key, edit.value)
		}
	}
	return stripped
}

func knownDNSFragmentProxies(raw *config.RawConfig) map[string]struct{} {
	known := map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "COMPATIBLE": {},
		"PASS": {}, "PASS-RULE": {}, "GLOBAL": {}, dns.RespectRules: {},
	}
	for _, proxy := range raw.Proxy {
		if name, _ := proxy["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	return known
}

func stripDNSFragmentName(server string) string {
	base, fragment, found := strings.Cut(server, "#")
	if !found {
		return server
	}
	kept := []string{}
	for _, component := range strings.Split(fragment, "&") {
		if strings.Contains(component, "=") {
			kept = append(kept, component)
		}
	}
	if len(kept) == 0 {
		return base
	}
	return base + "#" + strings.Join(kept, "&")
}

func detectUnroutableDNSFragments(raw *config.RawConfig) []string {
	known := knownDNSFragmentProxies(raw)
	stripped := []string{}
	rewrite := func(field string, list []string) {
		for index, server := range list {
			name := dnsFragmentProxyName(server)
			if name == "" {
				continue
			}
			if _, ok := known[name]; ok {
				continue
			}
			stripped = append(stripped, field+" "+server)
			_ = index
		}
	}
	rewrite("nameserver", raw.DNS.NameServer)
	rewrite("fallback", raw.DNS.Fallback)
	rewrite("default-nameserver", raw.DNS.DefaultNameserver)
	rewrite("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	rewrite("direct-nameserver", raw.DNS.DirectNameServer)
	for field, policy := range map[string]*orderedmap.OrderedMap[string, any]{
		"nameserver-policy":              raw.DNS.NameServerPolicy,
		"proxy-server-nameserver-policy": raw.DNS.ProxyServerNameserverPolicy,
	} {
		if policy == nil {
			continue
		}
		for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
			for _, server := range dnsServerStrings(pair.Value) {
				name := dnsFragmentProxyName(server)
				if name == "" {
					continue
				}
				if _, ok := known[name]; ok {
					continue
				}
				stripped = append(stripped, field+" "+pair.Key+" "+server)
			}
		}
	}
	return stripped
}

func validateRawConfigForIOS(raw *config.RawConfig) error {
	if err := validateRawProxyGroupRegexForIOS(raw.ProxyGroup); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("proxy-provider", raw.ProxyProvider); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("rule-provider", raw.RuleProvider); err != nil {
		return err
	}
	return validateGeodataFilesForIOS(raw)
}

func validateRawProxyGroupRegexForIOS(groups []map[string]any) error {
	for index, group := range groups {
		for _, field := range []string{"filter", "exclude-filter"} {
			value, ok := group[field].(string)
			if !ok || value == "" {
				continue
			}
			for _, expression := range strings.Split(value, "`") {
				if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
					return fmt.Errorf("clash: proxy-groups[%d].%s is not a valid regular expression", index, field)
				}
			}
		}
	}
	return nil
}

func validateRawProvidersForIOS(kind string, providers map[string]map[string]any) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider := providers[name]
		if kind == "proxy-provider" {
			if err := validateProxyProviderHealthCheck(name, provider); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProxyProviderHealthCheck(name string, provider map[string]any) error {
	raw, exists := provider["health-check"]
	if !exists {
		return nil
	}
	healthCheck, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	fields := []struct {
		name      string
		unit      time.Duration
		unitLabel string
	}{
		{name: "interval", unit: time.Second, unitLabel: "second"},
	}
	for _, field := range fields {
		if _, err := providerDurationUnits(healthCheck[field.name], field.unit, "health-check "+field.name, field.unitLabel); err != nil {
			return fmt.Errorf("clash: proxy-provider %q health-check.%s: %w", name, field.name, err)
		}
	}
	return nil
}

type geodataRequirements struct {
	geoIP   bool
	geoSite bool
	asn     bool
}

var geodataRuleToken = &lazyRegexp{expr: `(?i)(?:^|\()\s*(GEOIP|SRC-GEOIP|GEOSITE|IP-ASN|SRC-IP-ASN)\s*,\s*([^,()]*)`}

func validateGeodataFilesForIOS(raw *config.RawConfig) error {
	required := requiredGeodata(raw)
	if required.geoIP {
		path := C.Path.MMDB()
		if raw.GeodataMode {
			path = C.Path.GeoIP()
		}
		if err := requirePrestagedFile("GeoIP", path); err != nil {
			return err
		}
	}
	if required.geoSite {
		if err := requirePrestagedFile("GeoSite", C.Path.GeoSite()); err != nil {
			return err
		}
		geodata.MarkGeoSiteVerified()
	}
	if required.asn {
		if err := requirePrestagedFile("ASN", C.Path.ASN()); err != nil {
			return err
		}
	}
	return nil
}

func requirePrestagedFile(kind, path string) error {
	if path == "" {
		return fmt.Errorf("clash: %s geodata path is unavailable; call Setup before Start", kind)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("clash: required %s geodata is not pre-staged at %s (NE downloads are disabled)", kind, path)
		}
		return fmt.Errorf("clash: stat %s geodata at %s: %w", kind, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("clash: required %s geodata at %s is not a regular file", kind, path)
	}
	return nil
}

func requiredGeodata(raw *config.RawConfig) geodataRequirements {
	var required geodataRequirements
	for _, line := range raw.Rule {
		markRuleGeodata(line, &required)
	}
	for _, rules := range raw.SubRules {
		for _, line := range rules {
			markRuleGeodata(line, &required)
		}
	}
	for _, line := range raw.DNS.FakeIPFilter {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "geosite:") {
			required.geoSite = true
		} else {
			markRuleGeodata(line, &required)
		}
	}
	if len(raw.DNS.Fallback) > 0 {
		required.geoIP = required.geoIP || raw.DNS.FallbackFilter.GeoIP
		required.geoSite = required.geoSite || len(raw.DNS.FallbackFilter.GeoSite) > 0
	}
	markPolicyGeosite(raw.DNS.NameServerPolicy, &required)
	markPolicyGeosite(raw.DNS.ProxyServerNameserverPolicy, &required)
	return required
}

func markRuleGeodata(line string, required *geodataRequirements) {
	if !holdsASCIIFold(line, "geo") && !holdsASCIIFold(line, "ip-a") {
		return
	}
	for _, match := range geodataRuleToken.get().FindAllStringSubmatch(line, -1) {
		switch strings.ToUpper(match[1]) {
		case "GEOIP", "SRC-GEOIP":
			if strings.ToLower(strings.TrimSpace(match[2])) != "lan" {
				required.geoIP = true
			}
		case "GEOSITE":
			required.geoSite = true
		case "IP-ASN", "SRC-IP-ASN":
			required.asn = true
		}
	}
}

func holdsASCIIFold(s, word string) bool {
	for start := 0; start+len(word) <= len(s); start++ {
		matched := true
		for offset := 0; offset < len(word); offset++ {
			c := s[start+offset]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != word[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func markPolicyGeosite(policy *orderedmap.OrderedMap[string, any], required *geodataRequirements) {
	if policy == nil {
		return
	}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		if strings.HasPrefix(strings.ToLower(pair.Key), "geosite:") {
			required.geoSite = true
		}
	}
}

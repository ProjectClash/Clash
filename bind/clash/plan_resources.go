package clash

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/dns"
	"github.com/dlclark/regexp2"
)

const resourcePlanSchemaVersion = 4

type planProvider struct {
	Name                  string              `json:"name"`
	Kind                  string              `json:"kind"`
	ResourceKey           string              `json:"resourceKey"`
	Behavior              string              `json:"behavior"`
	Type                  string              `json:"type"`
	URL                   string              `json:"url"`
	Path                  string              `json:"path"`
	Format                string              `json:"format"`
	Headers               map[string][]string `json:"headers"`
	Proxy                 string              `json:"proxy"`
	MaximumBytes          int64               `json:"maximumBytes"`
	UpdateIntervalSeconds int64               `json:"updateIntervalSeconds"`
}
type planGeo struct {
	Kind         string `json:"kind"`
	URL          string `json:"url"`
	Format       string `json:"format"`
	Path         string `json:"path"`
	MaximumBytes int64  `json:"maximumBytes"`
}
type planError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}
type planResources struct {
	SchemaVersion     int            `json:"schemaVersion"`
	Providers         []planProvider `json:"providers"`
	Geodata           []planGeo      `json:"geodata"`
	Notices           []string       `json:"notices"`
	StructuredNotices []planNotice   `json:"structuredNotices"`
	Errors            []planError    `json:"errors"`
}

type planNotice struct {
	Kind     string `json:"kind"`
	Field    string `json:"field,omitempty"`
	Value    string `json:"value,omitempty"`
	Count    int    `json:"count,omitempty"`
	RuleKind string `json:"ruleKind,omitempty"`
	Text     string `json:"text"`
}

const (
	planNoticeProviderFetchProxyHonoured        = "provider-fetch-proxy-honoured"
	planNoticeProviderFetchProxySelfReferential = "provider-fetch-proxy-self-referential"
	planNoticeEgressOverrideStripped            = "egress-override-stripped"
	planNoticeFindProcessModeForcedOff          = "find-process-mode-forced-off"
	planNoticeRouteSetInert                     = "route-set-inert"
	planNoticeMetadataRulesInert                = "metadata-rules-inert"
	planNoticeDNSSystemResolverStripped         = "dns-system-resolver-stripped"
	planNoticeDNSLoopbackResolverStripped       = "dns-loopback-resolver-stripped"
	planNoticeDNSSystemResolverSubstituted      = "dns-system-resolver-substituted"
	planNoticeDNSBootstrapReplaced              = "dns-bootstrap-replaced"
	planNoticeDNSFragmentUnroutable             = "dns-fragment-unroutable"
	planNoticeProviderFileInert                 = "provider-file-inert"
	planNoticeProviderURLUnusable               = "provider-url-unusable"
	planNoticeProviderOptionDefaulted           = "provider-option-defaulted"
	planNoticeProviderHeaderDropped             = "provider-header-dropped"
	planNoticeOutboundDNSFragmentInert          = "outbound-dns-fragment-inert"
	planNoticeOutboundOptionUnrepresentable     = "outbound-option-unrepresentable"
	planNoticeProviderCoreFetch                 = "provider-core-fetch"
)

func (res *planResources) note(notices ...planNotice) {
	for _, n := range notices {
		res.Notices = append(res.Notices, n.Text)
		res.StructuredNotices = append(res.StructuredNotices, n)
	}
}

func PlanResourcesForIOS(mergedYAML string) (*StringBox, error) {
	bridgedValue0, bridgedErr := PlanResourcesForProfile(mergedYAML, RuntimeProfileIOSPacketTunnel)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func PlanResourcesForProfile(mergedYAML string, targetProfile string) (*StringBox, error) {
	out, err := recoverAppCall("PlanResourcesForProfile", func() (*StringBox, error) { return planResourcesForProfileUnguarded(mergedYAML, targetProfile) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func planResourcesForProfileUnguarded(mergedYAML string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	bridgedValue0, bridgedErr := withCompactHeap(func() (*StringBox, error) {
		doc, err := NewConfigDocument(mergedYAML)
		if err != nil {
			return nil, err
		}
		defer doc.Close()
		return doc.planResourcesJSON(runtimePolicyFor(profile, true))
	})
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func PlanResourcesForProfileAtPath(path string, targetProfile string) (*StringBox, error) {
	out, err := recoverAppCall("PlanResourcesForProfileAtPath", func() (*StringBox, error) {
		return withDocumentAt(path, func(text string) (*StringBox, error) { return planResourcesForProfileUnguarded(text, targetProfile) })
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func (d *ConfigDocument) PlanResourcesJSON() (*StringBox, error) {
	bridgedValue0, bridgedErr := d.PlanResourcesJSONForProfile(RuntimeProfileIOSPacketTunnel)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func (d *ConfigDocument) PlanResourcesJSONForProfile(targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	bridgedValue0, bridgedErr := d.planResourcesJSON(runtimePolicyFor(profile, true))
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func (d *ConfigDocument) planResourcesJSON(policy appleRuntimePolicy) (*StringBox, error) {
	views, err := d.snapshot()
	if err != nil {
		return nil, err
	}
	root := views.root
	raw := views.raw
	if _, err := rawRuleIndexChecked(raw); err != nil {
		return nil, err
	}
	res := planResources{
		SchemaVersion:     resourcePlanSchemaVersion,
		Providers:         []planProvider{},
		Geodata:           []planGeo{},
		Notices:           []string{},
		StructuredNotices: []planNotice{},
		Errors:            []planError{},
	}

	proxyProviders, proxyErrors, proxyNotices := httpProviders(root, "proxy-providers", "proxy")
	ruleProviders, ruleErrors, ruleNotices := httpProviders(root, "rule-providers", "rule")
	res.note(proxyNotices...)
	res.note(ruleNotices...)
	res.Providers = append(res.Providers, proxyProviders...)
	res.Providers = append(res.Providers, ruleProviders...)
	res.Errors = append(res.Errors, proxyErrors...)
	res.Errors = append(res.Errors, ruleErrors...)

	geodata, geoErrors := planGeodata(raw)
	res.Geodata = append(res.Geodata, geodata...)
	res.Errors = append(res.Errors, geoErrors...)

	if tun, ok := root["tun"].(map[string]any); ok {
		res.note(routeSetNotices(root, tun)...)
	}
	res.note(strippedHostRouteKnobNotices(root, raw, policy)...)
	res.note(strippedDNSSchemeNotices(root, policy)...)
	res.note(strippedDNSLoopbackNotices(root, policy)...)
	res.note(strippedDNSFragmentNotices(raw, policy)...)
	tierErrors, tierNotices := hardRejectErrors(root, raw)
	res.Errors = append(res.Errors, tierErrors...)
	res.note(tierNotices...)

	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	return WrapString(string(b)), nil
}

func planGeodata(raw *config.RawConfig) ([]planGeo, []planError) {
	required := requiredGeodata(raw)
	plans := make([]planGeo, 0, 3)
	errors := make([]planError, 0, 3)
	appendPlan := func(kind, field, url, format, path string) {
		if strings.TrimSpace(url) == "" {
			errors = append(errors, planError{
				Field:  field,
				Reason: "required geodata URL is empty; the containing App must materialize this resource before activation",
			})
			return
		}
		normalizedURL, err := normalizeResourceURL(url, "geodata")
		if err != nil {
			errors = append(errors, planError{Field: field, Reason: err.Error()})
			return
		}
		plans = append(plans, planGeo{
			Kind:         kind,
			URL:          normalizedURL,
			Format:       format,
			Path:         path,
			MaximumBytes: maximumGeodataResourceBytes,
		})
	}
	if required.geoIP {
		if raw.GeodataMode {
			appendPlan("geoip", "geox-url.geoip", raw.GeoXUrl.GeoIp, "dat", "GeoIP.dat")
		} else {
			appendPlan("geoip", "geox-url.mmdb", raw.GeoXUrl.Mmdb, "mmdb", "geoip.metadb")
		}
	}
	if required.geoSite {
		appendPlan("geosite", "geox-url.geosite", raw.GeoXUrl.GeoSite, "dat", "GeoSite.dat")
	}
	if required.asn {
		appendPlan("asn", "geox-url.asn", raw.GeoXUrl.ASN, "mmdb", "ASN.mmdb")
	}
	return plans, errors
}

func httpProviders(root map[string]any, key, kind string) ([]planProvider, []planError, []planNotice) {
	out := []planProvider{}
	errors := []planError{}
	notices := []planNotice{}
	m, ok := root[key].(map[string]any)
	if !ok {
		return out, errors, notices
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := m[name]
		def, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typeName, _ := def["type"].(string)
		if typeName == "file" {
			path, _ := def["path"].(string)
			notices = append(notices, planNotice{Kind: planNoticeProviderFileInert, Field: key + "." + name + ".path", Value: path,
				Text: key + "." + name + ": a file provider reads a path this app does not carry; the provider loads empty and everything else still starts"})
			continue
		}
		if typeName == "http" {
			providerURL, _ := def["url"].(string)
			format, _ := def["format"].(string)
			behavior, _ := def["behavior"].(string)
			proxy, _ := def["proxy"].(string)
			headers, headerDrops := providerHeaders(def["header"])
			normalizedURL, urlErr := normalizeResourceURL(providerURL, "provider")
			if urlErr != nil {
				notices = append(notices, planNotice{Kind: planNoticeProviderURLUnusable, Field: key + "." + name + ".url", Value: providerURL,
					Text: key + "." + name + ": " + urlErr.Error() + "; the provider is not downloaded and everything else still starts"})
			}
			if proxy != "" {
				notices = append(notices, planNotice{Kind: planNoticeProviderFetchProxyHonoured, Field: key + "." + name + ".proxy", Value: proxy,
					Text: key + "." + name + ".proxy: provider fetch proxy '" + proxy + "' is honoured; the core fetches this provider through it once the tunnel is running, and the app does not pre-download it"})
				if proxy == name {
					notices = append(notices, planNotice{Kind: planNoticeProviderFetchProxySelfReferential, Field: key + "." + name + ".proxy", Value: proxy,
						Text: key + "." + name + ".proxy: names this same provider ('" + name + "') as its own fetch proxy; a provider is not itself a proxy, so the core will report \"proxy " + proxy + " not found\" and this provider never fetches"})
				}
			}
			maximumBytes, limitErr := effectiveProviderMaximumBytes(def["size-limit"])
			if limitErr != nil {
				notices = append(notices, planNotice{Kind: planNoticeProviderOptionDefaulted, Field: key + "." + name + ".size-limit", Value: fmt.Sprintf("%v", def["size-limit"]),
					Text: key + "." + name + ": " + limitErr.Error() + "; the download ceiling falls back to the default and the provider still loads"})
			}
			updateIntervalSeconds, intervalErr := providerUpdateIntervalSeconds(def["interval"])
			if intervalErr != nil {
				updateIntervalSeconds = 0
				notices = append(notices, planNotice{Kind: planNoticeProviderOptionDefaulted, Field: key + "." + name + ".interval", Value: fmt.Sprintf("%v", def["interval"]),
					Text: key + "." + name + ": " + intervalErr.Error() + "; the provider is not refreshed on a timer and still loads"})
			}
			for _, drop := range headerDrops {
				notices = append(notices, planNotice{Kind: planNoticeProviderHeaderDropped, Field: key + "." + name + ".header." + drop.Name, Value: drop.Name,
					Text: key + "." + name + ": header field " + drop.Name + " is dropped (" + drop.Reason + "); the remaining fields are sent and the provider still loads"})
			}
			if urlErr != nil {
				continue
			}
			out = append(out, planProvider{
				Name: name, Kind: kind, ResourceKey: providerResourceKey(kind, name), Type: "http", URL: normalizedURL,
				Behavior: behavior, Format: format, Path: providerFileName(kind, name, ext(format, def)),
				Headers: headers, Proxy: proxy, MaximumBytes: maximumBytes,
				UpdateIntervalSeconds: updateIntervalSeconds,
			})
		}
	}
	if fetchable := len(out); fetchable > 0 {
		notices = append(notices, planNotice{Kind: planNoticeProviderCoreFetch, Field: key, Value: fmt.Sprintf("%d", fetchable),
			Text: fmt.Sprintf("%s: %d remote provider(s); any this app has no copy of at activation starts empty and is downloaded by the core in the background", key, fetchable)})
	}
	return out, errors, notices
}

func normalizeResourceURL(raw, resource string) (string, error) {
	normalized := strings.TrimSpace(raw)
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("%s URL must be an absolute http:// or https:// URL with a host", resource)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http") {
		return "", fmt.Errorf("%s URL must use http:// or https://, not %q", resource, parsed.Scheme)
	}
	return normalized, nil
}

func effectiveProviderMaximumBytes(raw any) (int64, error) {
	ceiling := int64(providerContentBytes())
	if raw == nil {
		return ceiling, nil
	}
	var limit int64
	switch value := raw.(type) {
	case int:
		limit = int64(value)
	case int64:
		limit = value
	case uint64:
		if value > math.MaxInt64 {
			return ceiling, fmt.Errorf("provider size-limit is out of range")
		}
		limit = int64(value)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return ceiling, fmt.Errorf("provider size-limit must be a non-negative byte count")
		}
		limit = parsed
	default:
		return ceiling, fmt.Errorf("provider size-limit must be a non-negative byte count")
	}
	if limit < 0 {
		return ceiling, fmt.Errorf("provider size-limit must not be negative")
	}
	if limit == 0 || limit > ceiling {
		return ceiling, nil
	}
	return limit, nil
}

var forbiddenProviderHeaders = &lazyValue[map[string]struct{}]{build: func() map[string]struct{} {
	return map[string]struct{}{
		"connection":          {},
		"content-length":      {},
		"host":                {},
		"keep-alive":          {},
		"proxy-authenticate":  {},
		"proxy-authorization": {},
		"proxy-connection":    {},
		"te":                  {},
		"trailer":             {},
		"transfer-encoding":   {},
		"upgrade":             {},
	}
}}

type providerHeaderDrop struct {
	Name   string
	Reason string
}

func providerHeaders(raw any) (map[string][]string, []providerHeaderDrop) {
	result := map[string][]string{}
	drops := []providerHeaderDrop{}
	if raw == nil {
		return result, drops
	}
	mapping, ok := raw.(map[string]any)
	if !ok {
		return result, append(drops, providerHeaderDrop{Name: "header", Reason: "header must be a mapping of field names to string values"})
	}
	names := make([]string, 0, len(mapping))
	for name := range mapping {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		lowerName := strings.ToLower(name)
		if !validProviderHeaderName(name) {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field name is not a valid HTTP field name"})
			continue
		}
		if _, forbidden := forbiddenProviderHeaders.get()[lowerName]; forbidden {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field is controlled by the HTTP transport"})
			continue
		}
		if _, duplicate := seen[lowerName]; duplicate {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field repeats an earlier field with different casing"})
			continue
		}
		seen[lowerName] = struct{}{}

		value := mapping[name]
		var values []string
		badValue := ""
		switch typed := value.(type) {
		case string:
			values = []string{typed}
		case []any:
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					badValue = "field values must be strings"
					break
				}
				values = append(values, text)
			}
		case []string:
			values = append(values, typed...)
		default:
			badValue = "field values must be strings or string lists"
		}
		if badValue != "" {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: badValue})
			continue
		}
		if len(values) == 0 {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field carries no value"})
			continue
		}
		invalid := false
		for _, value := range values {
			if !validProviderHeaderValue(value) {
				invalid = true
				break
			}
		}
		if invalid {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field value is not representable in an HTTP header"})
			continue
		}
		result[name] = values
	}
	return result, drops
}

func validProviderHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func validProviderHeaderValue(value string) bool {
	for _, character := range []byte(value) {
		if character == '\t' || character >= 0x20 && character != 0x7f {
			continue
		}
		return false
	}
	return true
}

func providerResourceKey(kind, name string) string {
	return kind + ":" + name
}

func providerFileName(kind, name, extension string) string {
	digest := sha256.Sum256([]byte(providerResourceKey(kind, name)))
	return fmt.Sprintf("provider-%x.%s", digest[:16], extension)
}

func ext(format string, def map[string]any) string {
	switch format {
	case "mrs":
		return "mrs"
	case "text":
		return "txt"
	default:
		return "yaml"
	}
}

func routeSetNotices(root, tun map[string]any) []planNotice {
	notices := []planNotice{}
	ipcidrProviders := ipcidrRuleProviders(root)
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		list, ok := tun[field].([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			name, _ := item.(string)
			if !ipcidrProviders[name] {
				notices = append(notices, planNotice{
					Kind:  planNoticeRouteSetInert,
					Field: "tun." + field,
					Text: "tun." + field + ": rule-provider '" + name + "' is not an ipcidr set, so it contributes no " +
						"routes; the tunnel still starts, as it does upstream",
				})
			}
		}
	}
	return notices
}

func ipcidrRuleProviders(root map[string]any) map[string]bool {
	out := map[string]bool{}
	m, ok := root["rule-providers"].(map[string]any)
	if !ok {
		return out
	}
	for name, raw := range m {
		if def, ok := raw.(map[string]any); ok {
			if b, _ := def["behavior"].(string); b == "ipcidr" {
				out[name] = true
			}
		}
	}
	return out
}

func strippedHostRouteKnobNotices(root map[string]any, raw *config.RawConfig, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	notices := []planNotice{}
	for _, field := range outboundEgressOverrideFields(root) {
		notices = append(notices, planNotice{Kind: planNoticeEgressOverrideStripped, Field: field,
			Text: field + ": " + egressKnobRemovedReason(field)})
	}
	if s, ok := root["find-process-mode"].(string); ok && s != "" && s != "off" {
		if registration := deviationRuleByField("find-process-mode"); registration != nil && registration.active(policy) {
			notices = append(notices, planNotice{Kind: planNoticeFindProcessModeForcedOff, Field: "find-process-mode", Value: s,
				Text: "find-process-mode is forced off: this packet tunnel exposes no process metadata"})
		}
	}
	for _, occurrence := range summarizeMetadataRuleOccurrenceKinds(raw, policy.processMetadata()) {
		notices = append(notices, planNotice{Kind: planNoticeMetadataRulesInert, Field: "rules", Value: occurrence.summary, RuleKind: occurrence.kind, Count: occurrence.count,
			Text: occurrence.summary + ": " + metadataRuleKeptExplanation})
	}
	return notices
}

var dnsResolverFields = []string{
	"nameserver",
	"fallback",
	"proxy-server-nameserver",
	"direct-nameserver",
	"nameserver-policy",
	"proxy-server-nameserver-policy",
	"x-clash-ssid-nameservers",
}

func hardRejectErrors(root map[string]any, raw *config.RawConfig) ([]planError, []planNotice) {
	out := []planError{}
	notices := []planNotice{}
	for index, group := range raw.ProxyGroup {
		for _, field := range []string{"filter", "exclude-filter"} {
			value, ok := group[field].(string)
			if !ok || value == "" {
				continue
			}
			bad := false
			for _, expression := range strings.Split(value, "`") {
				if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
					bad = true
					break
				}
			}
			if bad {
				out = append(out, planError{
					Field:  fmt.Sprintf("proxy-groups[%d].%s", index, field),
					Reason: "is not a valid regular expression",
				})
			}
		}
	}

	for _, issue := range upstreamRefusedOutboundOptions(raw) {
		out = append(out, planError{Field: issue.Field, Reason: issue.Reason})
	}
	for _, issue := range unrepresentableOutboundOptions(raw) {
		notices = append(notices, planNotice{Kind: planNoticeOutboundOptionUnrepresentable, Field: issue.Field,
			Text: issue.Field + ": " + issue.Reason + "; the node still loads and the transport reads what it can"})
	}
	if field := firstOutboundEmbeddedDNSFragment(raw); field != "" {
		notices = append(notices, planNotice{Kind: planNoticeOutboundDNSFragmentInert, Field: field,
			Text: field + ": nested DNS is pinned to that outbound, so the '#' fragment selects nothing; the outbound still starts"})
	}
	if dns, ok := root["dns"].(map[string]any); ok {
		if raw, present := dns["default-nameserver"]; present {
			if _, _, rejected := defaultNameserverStrip(raw, usableSubstitutesForRoot(root)); rejected {
				out = append(out, planError{
					Field:  "dns.default-nameserver",
					Reason: "bootstrap keeps a resolver mihomo rejects (\"default nameserver should be pure IP\"); add an explicit IP nameserver",
				})
			}
		}
	}
	return out, notices
}

func defaultNameserverStrip(v any, substitutes []string) (strip, repaired, rejected bool) {
	entries := []string{}
	walkStrings(v, func(s string) { entries = append(entries, s) })
	if len(entries) == 0 {
		return false, v != nil, false
	}
	survivors := make([]string, 0, len(entries)+len(substitutes))
	var hasBad, expanded bool
	for _, s := range entries {
		if isNEIncompatibleNameserver(s) {
			hasBad = true
			if len(substitutes) != 0 && !expanded {
				survivors = append(survivors, substitutes...)
				expanded = true
			}
			continue
		}
		survivors = append(survivors, s)
	}
	switch {
	case len(survivors) == 0:
		return false, true, false
	case mihomoRejectsBootstrap(survivors):
		return false, false, true
	default:
		return hasBad, false, false
	}
}

func mihomoRejectsBootstrap(servers []string) bool {
	if len(servers) == 0 {
		return true
	}
	parsed, err := dns.ParseNameServer(servers)
	if err != nil {
		return true
	}
	for _, ns := range parsed {
		if ns.Net == "system" {
			continue
		}
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			u, err := url.Parse(ns.Addr)
			if err == nil && net.ParseIP(u.Host) == nil {
				if ip, _, err := net.SplitHostPort(u.Host); err != nil || net.ParseIP(ip) == nil {
					return true
				}
			}
		}
	}
	return false
}

func strippedDNSSchemeNotices(root map[string]any, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		return nil
	}
	notices := []planNotice{}
	substitutes := usableSubstitutesForRoot(root)
	systemEntry := func(field, v string) planNotice {
		if len(substitutes) != 0 {
			return planNotice{Kind: planNoticeDNSSystemResolverSubstituted, Field: "dns." + field, Value: v,
				Text: "dns." + field + " '" + v + "' (system/dhcp) resolves through the system resolvers the App read before the tunnel: " + strings.Join(substitutes, ", ")}
		}
		return planNotice{Kind: planNoticeDNSSystemResolverStripped, Field: "dns." + field, Value: v,
			Text: "dns." + field + " '" + v + "' (system/dhcp) is stripped inside a packet tunnel; resolution stays inside the core"}
	}
	for _, field := range []string{
		"nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver",
		"nameserver-policy", "proxy-server-nameserver-policy",
	} {
		walkStrings(dns[field], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, systemEntry(field, v))
			}
		})
	}
	strip, repaired, _ := defaultNameserverStrip(dns["default-nameserver"], substitutes)
	switch {
	case strip:
		walkStrings(dns["default-nameserver"], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, systemEntry("default-nameserver", v))
			}
		})
	case repaired:
		notices = append(notices, planNotice{Kind: planNoticeDNSBootstrapReplaced, Field: "dns.default-nameserver",
			Text: "dns.default-nameserver has no resolver a packet tunnel can bootstrap from, so it receives the core's own explicit defaults; set an IP bootstrap (e.g. 223.5.5.5) to choose your own"})
	}
	return notices
}

func strippedDNSFragmentNotices(raw *config.RawConfig, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	notices := []planNotice{}
	for _, entry := range detectUnroutableDNSFragments(raw) {
		notices = append(notices, planNotice{Kind: planNoticeDNSFragmentUnroutable, Field: "dns." + entry,
			Text: "dns." + entry + ": fragment names a physical interface/unknown proxy; kept — fails closed at runtime unless the name materializes"})
	}
	return notices
}

func isZeroish(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case int:
		return t == 0
	case float64:
		return t == 0
	}
	return false
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkStrings(t[key], fn)
		}
	}
}

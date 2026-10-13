package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

type platformConfigIntent struct {
	IntentSchemaVersion     int    `json:"intentSchemaVersion"`
	TunRestartFingerprint   string `json:"tunRestartFingerprint"`
	StrictRoute             bool   `json:"strictRoute"`
	IncludedRouteCount      int    `json:"includedRouteCount"`
	ExcludedRouteCount      int    `json:"excludedRouteCount"`
	HasLegacyIncludedRoutes bool   `json:"hasLegacyIncludedRoutes"`
	HasLegacyExcludedRoutes bool   `json:"hasLegacyExcludedRoutes"`
}

const platformConfigIntentSchemaVersion = 2

type tunRestartIntent struct {
	IPQueryMode                     string   `json:"ipQueryMode,omitempty"`
	TunIPv6Mode                     string   `json:"tunIPv6Mode,omitempty"`
	IPv4Address                     string   `json:"ipv4Address"`
	IPv6Enabled                     bool     `json:"ipv6Enabled"`
	IPv6Addresses                   []string `json:"ipv6Addresses"`
	LoopbackAddresses               []string `json:"loopbackAddresses"`
	StrictRoute                     bool     `json:"strictRoute"`
	RouteAddresses                  []string `json:"routeAddresses"`
	RouteExcludeAddresses           []string `json:"routeExcludeAddresses"`
	LegacyIPv4RouteAddresses        []string `json:"legacyIPv4RouteAddresses"`
	LegacyIPv6RouteAddresses        []string `json:"legacyIPv6RouteAddresses"`
	LegacyIPv4RouteExcludeAddresses []string `json:"legacyIPv4RouteExcludeAddresses"`
	LegacyIPv6RouteExcludeAddresses []string `json:"legacyIPv6RouteExcludeAddresses"`
	EndpointIndependentNAT          bool     `json:"endpointIndependentNAT"`
	UDPTimeout                      int64    `json:"udpTimeout"`
	ICMPTimeout                     int64    `json:"icmpTimeout"`
}

var appParseMu sync.Mutex

func CheckConfig(configContent string) error {
	return bridgeSafeError(recoverAppCallError("CheckConfig", func() error { return checkConfigUnguarded(configContent) }))
}

func checkConfigUnguarded(configContent string) error {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return bridgeSafeError(fmt.Errorf("clash: call Setup before CheckConfig"))
	}
	appParseMu.Lock()
	defer appParseMu.Unlock()
	_, err := parseClosingEveryNode(configContent)
	return bridgeSafeError(err)
}

func ValidateConfigShape(configContent string) error {
	return bridgeSafeError(recoverAppCallError("ValidateConfigShape", func() error { return validateConfigShapeUnguarded(configContent) }))
}

func validateConfigShapeUnguarded(configContent string) error {
	if _, err := config.UnmarshalRawConfig([]byte(configContent)); err != nil {
		return bridgeSafeError(fmt.Errorf("clash: parse config: %w", err))
	}
	return nil
}

func PlatformConfigIntentJSON(configContent string) (*StringBox, error) {
	out, err := recoverAppCall("PlatformConfigIntentJSON", func() (*StringBox, error) { return platformConfigIntentJSONUnguarded(configContent) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func platformConfigIntentJSONUnguarded(configContent string) (*StringBox, error) {
	if data, ok := takeStartedIntent(configContent); ok {
		return WrapString(string(data)), nil
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: parse config: %w", err))
	}
	data, err := platformConfigIntentFromRaw(raw)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(data)), nil
}

func platformConfigIntentFromRaw(raw *config.RawConfig) ([]byte, error) {
	return platformConfigIntentFromRawWithIPStack(raw, currentIPStackSettings())
}

func platformConfigIntentFromRawWithIPStack(raw *config.RawConfig, stack ipStackSettings) ([]byte, error) {
	if err := validateRawNetworkExtensionIntent(raw); err != nil {
		return nil, err
	}
	applyIPStackSettings(raw, stack)
	tun := raw.Tun
	fingerprint, err := tunRestartFingerprintWithIPStack(raw, stack)
	if err != nil {
		return nil, err
	}
	intent := platformConfigIntent{
		IntentSchemaVersion:     platformConfigIntentSchemaVersion,
		TunRestartFingerprint:   fingerprint,
		StrictRoute:             tun.StrictRoute,
		IncludedRouteCount:      len(tun.RouteAddress) + len(tun.Inet4RouteAddress) + len(tun.Inet6RouteAddress),
		ExcludedRouteCount:      len(tun.RouteExcludeAddress) + len(tun.Inet4RouteExcludeAddress) + len(tun.Inet6RouteExcludeAddress),
		HasLegacyIncludedRoutes: len(tun.Inet4RouteAddress) > 0 || len(tun.Inet6RouteAddress) > 0,
		HasLegacyExcludedRoutes: len(tun.Inet4RouteExcludeAddress) > 0 || len(tun.Inet6RouteExcludeAddress) > 0,
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return nil, fmt.Errorf("clash: encode platform config intent: %w", err)
	}
	return data, nil
}

func tunRestartFingerprint(raw *config.RawConfig) (string, error) {
	return tunRestartFingerprintWithIPStack(raw, currentIPStackSettings())
}

func tunRestartFingerprintWithIPStack(raw *config.RawConfig, stack ipStackSettings) (string, error) {
	var address netip.Prefix
	if raw.DNS.FakeIPRange == "" {
		address = netip.MustParsePrefix("198.18.0.1/16")
	} else {
		parsed, err := netip.ParsePrefix(raw.DNS.FakeIPRange)
		if err != nil || !parsed.Addr().Is4() {
			return "", fmt.Errorf("clash: inspect Apple tun intent: invalid IPv4 dns.fake-ip-range %q", raw.DNS.FakeIPRange)
		}
		address = parsed
	}
	intent := tunRestartIntent{
		IPQueryMode:                     stack.queryMode.String(),
		TunIPv6Mode:                     stack.tunIPv6Mode,
		IPv4Address:                     netip.PrefixFrom(address.Addr(), 30).String(),
		IPv6Enabled:                     raw.IPv6,
		LoopbackAddresses:               sortedAddresses(raw.Tun.LoopbackAddress),
		StrictRoute:                     raw.Tun.StrictRoute,
		RouteAddresses:                  sortedPrefixes(raw.Tun.RouteAddress),
		RouteExcludeAddresses:           sortedPrefixes(raw.Tun.RouteExcludeAddress),
		LegacyIPv4RouteAddresses:        sortedPrefixes(raw.Tun.Inet4RouteAddress),
		LegacyIPv6RouteAddresses:        sortedPrefixes(raw.Tun.Inet6RouteAddress),
		LegacyIPv4RouteExcludeAddresses: sortedPrefixes(raw.Tun.Inet4RouteExcludeAddress),
		LegacyIPv6RouteExcludeAddresses: sortedPrefixes(raw.Tun.Inet6RouteExcludeAddress),
		EndpointIndependentNAT:          raw.Tun.EndpointIndependentNat,
		UDPTimeout:                      raw.Tun.UDPTimeout,
		ICMPTimeout:                     raw.Tun.ICMPTimeout,
	}
	if raw.IPv6 || raw.PreserveTunIPv6 {
		intent.IPv6Addresses = sortedPrefixes(raw.Tun.Inet6Address)
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return "", fmt.Errorf("clash: encode Apple tun restart intent: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func sortedPrefixes(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	sort.Strings(result)
	return result
}

func sortedAddresses(addresses []netip.Addr) []string {
	result := make([]string, len(addresses))
	for index, address := range addresses {
		result[index] = address.String()
	}
	sort.Strings(result)
	return result
}

func FormatConfig(configContent string) (*StringBox, error) {
	out, err := recoverAppCall("FormatConfig", func() (*StringBox, error) { return formatConfigUnguarded(configContent) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func formatConfigUnguarded(configContent string) (*StringBox, error) {
	if _, err := config.UnmarshalRawConfig([]byte(configContent)); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: parse config: %w", err))
	}

	var document yaml.Node
	if err := yaml.Unmarshal([]byte(configContent), &document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: parse YAML for formatting: %w", err))
	}
	standIns := standInAstralInNode(&document)
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: format config: %w", err))
	}
	if err := encoder.Close(); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: finish config formatting: %w", err))
	}
	return WrapString(standIns.restore(buffer.String())), nil
}

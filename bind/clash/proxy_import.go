package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/ca"
	"io"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/common/convert"
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

type proxyImportCapability struct {
	Scheme        string `json:"scheme"`
	CanonicalType string `json:"canonicalType,omitempty"`
	Status        string `json:"status"`
	PasteRole     string `json:"pasteRole"`
}

type proxyImportCapabilitiesDocument struct {
	Schemes  []proxyImportCapability `json:"schemes"`
	Contexts []string                `json:"contexts"`
}

type proxyImportIssue struct {
	Index           int      `json:"index"`
	Scheme          string   `json:"scheme"`
	Code            string   `json:"code"`
	Line            int      `json:"line,omitempty"`
	Offset          int      `json:"offset,omitempty"`
	Message         string   `json:"message"`
	Proxy           string   `json:"proxy,omitempty"`
	AlsoNotHonoured []string `json:"alsoNotHonoured,omitempty"`
}

type proxyImportUnsupportedFieldError struct {
	field  string
	detail string
}

func (e *proxyImportUnsupportedFieldError) Error() string {
	return fmt.Sprintf("clash: proxy field %q is recognized but unsupported: %s", e.field, e.detail)
}

func unsupportedProxyImportField(field, detail string) error {
	return &proxyImportUnsupportedFieldError{field: field, detail: detail}
}

type proxyImportReport struct {
	Format       string                   `json:"format"`
	Context      string                   `json:"context"`
	Proxies      []map[string]any         `json:"proxies"`
	Skipped      []proxyImportIssue       `json:"skipped"`
	NotHonoured  []proxyImportIssue       `json:"notHonoured"`
	Identities   []string                 `json:"identities"`
	PayloadShape *proxyImportPayloadShape `json:"payloadShape,omitempty"`
}

type proxyImportPayloadShape struct {
	IsConfiguration   bool     `json:"isConfiguration"`
	RecognizedKeys    []string `json:"recognizedKeys"`
	UnrecognizedKeys  []string `json:"unrecognizedKeys"`
	HasInlineProxies  bool     `json:"hasInlineProxies"`
	HasProxyProviders bool     `json:"hasProxyProviders"`
}

var mihomoConfigurationKeys = &lazyValue[map[string]struct{}]{build: func() map[string]struct{} {
	keys := make(map[string]struct{})
	var collect func(reflect.Type)
	collect = func(structType reflect.Type) {
		for index := 0; index < structType.NumField(); index++ {
			field := structType.Field(index)
			tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
				collect(field.Type)
				continue
			}
			if tag == "" || tag == "-" || clashPrivateKey(tag) {
				continue
			}
			keys[tag] = struct{}{}
		}
	}
	collect(reflect.TypeOf(config.RawConfig{}))
	return keys
}}

func describeProxyImportPayloadShape(document map[string]any) *proxyImportPayloadShape {
	shape := &proxyImportPayloadShape{
		RecognizedKeys:   make([]string, 0, len(document)),
		UnrecognizedKeys: make([]string, 0),
	}
	for key := range document {
		if _, known := mihomoConfigurationKeys.get()[key]; known {
			shape.RecognizedKeys = append(shape.RecognizedKeys, key)
			continue
		}
		shape.UnrecognizedKeys = append(shape.UnrecognizedKeys, key)
	}
	sort.Strings(shape.RecognizedKeys)
	sort.Strings(shape.UnrecognizedKeys)
	shape.IsConfiguration = len(shape.RecognizedKeys) > 0
	if raw, ok := document["proxies"]; ok {
		if list, ok := raw.([]any); ok && len(list) > 0 {
			shape.HasInlineProxies = true
		}
	}
	if raw, ok := document["proxy-providers"]; ok {
		if providers, ok := raw.(map[string]any); ok && len(providers) > 0 {
			shape.HasProxyProviders = true
		}
	}
	return shape
}

const (
	proxyImportSupported       = "supported"
	proxyImportCoreUnsupported = "coreUnsupported"
	proxyImportSemanticReview  = "semanticReview"
	proxyImportWrapper         = "wrapper"
)

const (
	proxyImportPasteNode         = "node"
	proxyImportPasteSubscription = "subscription"
	proxyImportPasteWrapper      = "wrapper"
)

var proxyImportCapabilities = []proxyImportCapability{
	{Scheme: "vmess", CanonicalType: "vmess", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "http", CanonicalType: "http", Status: proxyImportSupported, PasteRole: proxyImportPasteSubscription},
	{Scheme: "https", CanonicalType: "http", Status: proxyImportSupported, PasteRole: proxyImportPasteSubscription},
	{Scheme: "http2", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "http3", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks5", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "socks5h", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssocks", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssocks5", CanonicalType: "socks5", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "lua", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssr", CanonicalType: "ssr", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "sub", Status: proxyImportWrapper, PasteRole: proxyImportPasteWrapper},
	{Scheme: "trojan", CanonicalType: "trojan", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "trojan-go", CanonicalType: "trojan", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ss", CanonicalType: "ss", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "gp", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "snell", CanonicalType: "snell", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "vless", CanonicalType: "vless", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "relay", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hysteria", CanonicalType: "hysteria", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy", CanonicalType: "hysteria", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hysteria2", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy2", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hysteria2+realm", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "hy2+realm", CanonicalType: "hysteria2", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "tuic", CanonicalType: "tuic", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "juicity", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "wireguard", CanonicalType: "wireguard", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "wg", CanonicalType: "wireguard", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "masque", CanonicalType: "masque", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "ssh", CanonicalType: "ssh", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "anytls", CanonicalType: "anytls", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "openconnect", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "tt", CanonicalType: "trusttunnel", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "mierus", CanonicalType: "mieru", Status: proxyImportSupported, PasteRole: proxyImportPasteNode},
	{Scheme: "mieru", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
	{Scheme: "brook", Status: proxyImportCoreUnsupported, PasteRole: proxyImportPasteNode},
}

var proxyImportQueryFieldLedger = &lazyValue[map[string]map[string]struct{}]{build: func() map[string]map[string]struct{} {
	return map[string]map[string]struct{}{
		"vmess": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "uot", "padding", "fragment",
			"alterId", "tls", "xtls", "peer", "sni", "serverName", "tlsServerName", "allowInsecure",
			"allow_insecure", "insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp", "pcs",
			"pbk", "publicKey", "sid", "shortId", "obfs", "obfsParam", "security", "packetEncoding",
			"type", "headerType", "host", "method", "path", "ed", "eh", "serviceName", "mode", "extra",
			"encryption",
		),
		"http": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "method", "tls", "security", "peer", "sni",
			"serverName", "tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify",
			"fingerprint", "hpkp", "fragment", "pbk", "publicKey", "sid", "shortId",
		),
		"socks5": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "tls", "security", "udp", "allowInsecure",
			"allow_insecure", "insecure", "skip-cert-verify", "fingerprint", "hpkp",
		),
		"trojan": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "tls", "peer", "sni", "serverName",
			"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
			"fingerprint", "fp", "hpkp", "pcs", "pbk", "publicKey", "sid", "shortId", "security",
			"type", "proto", "network", "obfs", "obfsParam", "path", "host", "serviceName", "plugin",
			"protoParam",
		),
		"ss": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "udp-over-tcp", "uot", "plugin",
			"obfs", "obfsParam", "path", "client-fingerprint",
			"tls", "sni", "peer", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify",
		),
		"snell": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "psk", "password", "version", "v",
			"udp", "reuse", "obfs", "obfs-mode", "obfsParam", "obfs-host", "peer", "sni", "plugin",
			"security", "alpn", "keepalive", "fingerprint", "hpkp", "pbk", "publicKey", "sid", "shortId",
			"mode", "user-key",
		),
		"vless": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "uot", "padding", "fragment",
			"tls", "xtls", "peer", "sni", "serverName", "tlsServerName", "allowInsecure", "allow_insecure",
			"insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp", "pcs", "pbk",
			"publicKey", "sid", "shortId", "obfs", "obfsParam", "security", "packetEncoding", "type",
			"headerType", "host", "method", "path", "ed", "eh", "serviceName", "mode", "extra", "flow",
			"encryption",
		),
		"hysteria": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "auth", "peer", "sni", "serverName",
			"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "up", "upmbps",
			"down", "downmbps", "alpn", "obfs", "obfsParam", "protocol", "fingerprint", "hpkp", "pinSHA256", "keepalive",
		),
		"hysteria2": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
			"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "up", "upmbps",
			"down", "downmbps", "alpn", "obfs", "obfs-password", "obfsParam", "fingerprint", "hpkp",
			"pinSHA256", "keepalive", "pbk", "publicKey", "sid", "shortId",
			"mport", "ports", "hop-interval", "hopInterval",
			"auth", "stun",
		),
		"tuic": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
			"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
			"congestion_control", "congestion-controller", "proto", "udp_relay_mode", "udp-relay-mode", "udp",
			"disable_sni", "fingerprint", "hpkp", "pinSHA256", "pbk", "publicKey", "sid", "shortId",
		),
		"wireguard": queryFieldSet(
			"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "publicKey", "public-key",
			"privateKey", "private-key", "ip", "presharedKey", "preSharedKey", "pre-shared-key", "password",
			"mtu", "keepalive", "persistent-keepalive", "dns", "reserved", "udp", "sni", "peer",
			"preshared-key", "presharedkey", "publickey", "address",
		),
		"masque": queryFieldSet(
			"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "publicKey", "public-key",
			"privateKey", "private-key", "ip", "presharedKey", "preSharedKey", "pre-shared-key", "password",
			"peer", "sni", "serverName", "tlsServerName", "allowInsecure", "allow_insecure", "insecure",
			"skip-cert-verify", "uri", "mtu", "proto", "network", "dns", "keepalive", "reserved", "udp",
		),
		"ssh": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "user", "password", "private-key",
			"privateKey", "pk", "private-key-passphrase", "privateKeyPassphrase", "pp", "keepalive", "path",
		),
		"anytls": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "peer", "sni", "serverName",
			"tlsServerName", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "alpn",
			"fingerprint", "fp", "hpkp", "udp", "keepalive", "pbk", "publicKey", "sid", "shortId",
		),
		"trusttunnel": queryFieldSet(
			"title", "remark", "remarks", "name", "tfo", "fastopen", "udp", "peer", "sni", "hostname",
			"allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "proto", "protocol",
			"alpn", "fingerprint", "fp", "client-fingerprint",
		),
		"mieru": queryFieldSet(
			"title", "remark", "remarks", "name", "profile", "tfo", "fastopen", "port", "protocol", "proto",
			"transport", "multiplexing", "handshake-mode", "traffic-pattern", "peer", "sni", "allowInsecure",
			"allow_insecure", "insecure", "skip-cert-verify", "alpn", "udp", "mtu", "fingerprint", "hpkp", "pbk",
			"publicKey", "sid", "shortId",
		),
	}
}}

func queryFieldSet(fields ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result
}

var proxyImportURLPattern = &lazyRegexp{expr: `(?i)([a-z][a-z0-9+.-]*)://`}

func ProxyImportCapabilitiesForIOS() *StringBox {
	encoded, _ := json.Marshal(proxyImportCapabilitiesDocument{
		Schemes:  proxyImportCapabilities,
		Contexts: []string{"singleNode", "nodeBundle", "subscriptionBody", "configuration"},
	})
	return WrapString(string(encoded))
}

func addProxyImportContextNotice(report *proxyImportReport, notice string) {
	if notice == "" {
		return
	}
	report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
		Code: "fieldNotHonoured", Message: "clash: proxy field " + notice,
	})
}

func InspectProxyPayloadForIOS(payload []byte, context string) (*StringBox, error) {
	out, err := recoverAppCall("InspectProxyPayloadForIOS", func() (*StringBox, error) { return inspectProxyPayloadForIOSUnguarded(payload, context, true) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func inspectProxyPayloadForIOSUnguarded(payload []byte, context string, construct bool) (*StringBox, error) {
	report, err := proxyImportReportOf(payload, context, construct)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	bridgedValue0, bridgedErr := encodeProxyImportReport(report)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func proxyImportReportOf(payload []byte, context string, construct bool) (proxyImportReport, error) {
	if len(payload) == 0 {
		return proxyImportReport{}, fmt.Errorf("clash: proxy payload is empty")
	}
	if limit := providerContentBytes(); len(payload) > limit {
		return proxyImportReport{}, fmt.Errorf("clash: proxy payload is %d bytes, over the %d-byte limit",
			len(payload), limit)
	}
	var contextNotice string
	switch context {
	case "singleNode", "nodeBundle", "subscriptionBody", "configuration":
	default:
		contextNotice = "import.context=" + context + ": not a context this build knows, so the payload was read as a bundle of nodes"
		context = "nodeBundle"
	}

	if report, matched, err := inspectProxyContainer(payload, context, construct); matched {
		if err != nil {
			return proxyImportReport{}, err
		}
		addProxyImportContextNotice(&report, contextNotice)
		return report, nil
	}
	if decoded, decodeErr := convert.TryDecodeBase64(string(bytes.TrimSpace(payload))); decodeErr == nil {
		if report, matched, containerErr := inspectProxyContainer(decoded, context, construct); matched {
			if containerErr != nil {
				return proxyImportReport{}, containerErr
			}
			addProxyImportContextNotice(&report, contextNotice)
			return report, nil
		}
	}
	if context == "configuration" {
		return proxyImportReport{}, fmt.Errorf("clash: configuration payload is not a recognized configuration container")
	}

	text := string(payload)
	format := "share-links"
	if !proxyImportURLPattern.get().MatchString(text) {
		decoded, err := convert.TryDecodeBase64(strings.TrimSpace(text))
		if err == nil && proxyImportURLPattern.get().Match(decoded) {
			text = string(decoded)
			format = "base64-share-links"
		}
	}
	records := extractProxyImportRecords(text)
	if len(records) == 0 {
		return proxyImportReport{}, fmt.Errorf("clash: proxy payload format is unknown")
	}
	if context == "singleNode" && len(records) != 1 {
		return proxyImportReport{}, fmt.Errorf("clash: single-node import contains %d records", len(records))
	}

	capabilities := make(map[string]proxyImportCapability, len(proxyImportCapabilities))
	for _, capability := range proxyImportCapabilities {
		capabilities[capability.Scheme] = capability
	}
	report := proxyImportReport{
		Format:      format,
		Context:     context,
		Proxies:     make([]map[string]any, 0, len(records)),
		Skipped:     make([]proxyImportIssue, 0),
		NotHonoured: make([]proxyImportIssue, 0),
	}
	seenNames := make(map[string]int)
	for index, record := range records {
		scheme := strings.ToLower(record.scheme)
		capability, known := capabilities[scheme]
		if !known {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "unknownScheme",
				Message: fmt.Sprintf("proxy scheme %q is not recognized", scheme),
			})
			continue
		}
		if capability.Status != proxyImportSupported {
			code := capability.Status
			if code == proxyImportWrapper {
				code = "subscriptionWrapper"
			}
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: code,
				Message: fmt.Sprintf("proxy scheme %q is recognized but is not constructible by this importer", scheme),
			})
			continue
		}
		proxies, notHonoured, err := parseProxyShareLink(record.text, capability)
		pending := make([]string, 0, len(notHonoured))
		for _, notice := range notHonoured {
			pending = append(pending, "clash: proxy field "+notice)
		}
		skip := func(issue proxyImportIssue) {
			issue.AlsoNotHonoured = pending
			report.Skipped = append(report.Skipped, issue)
			pending = nil
		}
		if err != nil {
			var unsupported *proxyImportUnsupportedFieldError
			if errors.As(err, &unsupported) {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "recognizedUnsupportedField", Message: err.Error(),
				})
				continue
			}
			skip(proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "malformedRecord", Message: err.Error(),
			})
			continue
		}
		for _, proxy := range proxies {
			if validationErr := validateProxyImportRequiredFields(proxy); validationErr != nil {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: "malformedRecord", Message: validationErr.Error(),
				})
				continue
			}
			if code, err := constructProxyForImport(proxy, construct); err != nil {
				skip(proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset, Code: code, Message: err.Error(),
				})
				continue
			}
			report.Identities = append(report.Identities, proxyImportIdentity(proxy))
			makeProxyImportNameUnique(proxy, seenNames)
			name, _ := proxy["name"].(string)
			for _, notice := range pending {
				report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
					Index: index, Scheme: scheme, Line: record.line, Offset: record.offset,
					Code: "fieldNotHonoured", Message: notice, Proxy: name,
				})
			}
			pending = nil
			report.Proxies = append(report.Proxies, proxy)
		}
		for _, notice := range pending {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Line: record.line, Offset: record.offset,
				Code: "fieldNotHonoured", Message: notice,
			})
		}
		pending = nil
	}
	addProxyImportContextNotice(&report, contextNotice)
	return report, nil
}

func constructProxyForImport(proxy map[string]any, construct bool) (string, error) {
	if !construct {
		return "", nil
	}
	outbound, err := adapter.ParseProxy(proxy)
	if err != nil {
		return "coreRejected", err
	}
	if err := outbound.Close(); err != nil {
		return "coreCloseFailed", err
	}
	return "", nil
}

func ReadProxyPayloadForIOS(payload []byte, context string) (*StringBox, error) {
	out, err := recoverAppCall("ReadProxyPayloadForIOS", func() (*StringBox, error) {
		return inspectProxyPayloadForIOSUnguarded(payload, context, false)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type proxyImportSummary struct {
	Format           string                   `json:"format"`
	Context          string                   `json:"context"`
	Count            int                      `json:"count"`
	Skipped          []proxyImportIssue       `json:"skipped"`
	SkippedCount     int                      `json:"skippedCount"`
	NotHonoured      []proxyImportIssue       `json:"notHonoured"`
	NotHonouredCount int                      `json:"notHonouredCount"`
	PayloadShape     *proxyImportPayloadShape `json:"payloadShape,omitempty"`
}

const proxyImportSummaryIssues = 50

func InspectProxyPayloadSummaryForIOS(payload []byte, context string) (*StringBox, error) {
	out, err := recoverAppCall("InspectProxyPayloadSummaryForIOS", func() (*StringBox, error) { return proxyImportSummaryOf(payload, context, true) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func ReadProxyPayloadSummaryForIOS(payload []byte, context string) (*StringBox, error) {
	out, err := recoverAppCall("ReadProxyPayloadSummaryForIOS", func() (*StringBox, error) { return proxyImportSummaryOf(payload, context, false) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func proxyImportSummaryOf(payload []byte, context string, construct bool) (*StringBox, error) {
	report, err := proxyImportReportOf(payload, context, construct)
	if err != nil {
		return nil, err
	}
	encoded, err := encodeProxyImportSummary(report)
	if err != nil {
		return nil, err
	}
	return WrapString(encoded), nil
}

func encodeProxyImportSummary(report proxyImportReport) (string, error) {
	summary := proxyImportSummary{
		Format: report.Format, Context: report.Context, Count: len(report.Proxies),
		Skipped: report.Skipped[:min(len(report.Skipped), proxyImportSummaryIssues)], SkippedCount: len(report.Skipped),
		NotHonoured: report.NotHonoured[:min(len(report.NotHonoured), proxyImportSummaryIssues)], NotHonouredCount: len(report.NotHonoured),
		PayloadShape: report.PayloadShape,
	}
	if summary.Skipped == nil {
		summary.Skipped = []proxyImportIssue{}
	}
	if summary.NotHonoured == nil {
		summary.NotHonoured = []proxyImportIssue{}
	}
	encoded, err := json.Marshal(summary)
	return string(encoded), err
}

func encodeProxyImportReport(report proxyImportReport) (*StringBox, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("clash: encode proxy import report: %w", err)
	}
	return WrapString(string(encoded)), nil
}

func validateProxyImportRequiredFields(proxy map[string]any) error {
	kind := strings.ToLower(strings.TrimSpace(anyString(proxy["type"])))
	require := func(fields ...string) error {
		for _, field := range fields {
			if strings.TrimSpace(anyString(proxy[field])) == "" {
				return fmt.Errorf("clash: %s proxy requires %s", kind, field)
			}
		}
		return nil
	}

	switch kind {
	case "vmess", "vless":
		return require("uuid")
	case "trojan", "anytls":
		return require("password")
	case "ss":
		return require("cipher", "password")
	case "ssr":
		return require("cipher", "password", "protocol", "obfs")
	case "snell":
		return require("psk")
	case "tuic":
		if strings.TrimSpace(anyString(proxy["token"])) != "" {
			return nil
		}
		if strings.TrimSpace(anyString(proxy["uuid"])) == "" || strings.TrimSpace(anyString(proxy["password"])) == "" {
			return fmt.Errorf("clash: tuic proxy requires token or both uuid and password")
		}
	case "wireguard":
		if err := require("private-key", "public-key"); err != nil {
			return err
		}
		if strings.TrimSpace(anyString(proxy["ip"])) == "" && strings.TrimSpace(anyString(proxy["ipv6"])) == "" {
			return fmt.Errorf("clash: wireguard proxy requires ip or ipv6")
		}
	case "ssh":
		if err := require("username"); err != nil {
			return err
		}
		if strings.TrimSpace(anyString(proxy["password"])) == "" && strings.TrimSpace(anyString(proxy["private-key"])) == "" {
			return fmt.Errorf("clash: ssh proxy requires password or private-key")
		}
	case "trusttunnel", "mieru":
		return require("username", "password")
	}
	return nil
}

func inspectProxyContainer(payload []byte, context string, construct bool) (proxyImportReport, bool, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return proxyImportReport{}, false, nil
	}
	text := string(trimmed)
	var (
		format               string
		proxies              []map[string]any
		err                  error
		matched              bool
		containerSkipped     []proxyImportIssue
		containerNotHonoured [][]string
		decoded              map[string]any
	)
	switch {
	case looksLikeMihomoYAML(text):
		matched = true
		format = "mihomo-yaml"
		document, decodeErr := decodeMihomoDocument(trimmed)
		if decodeErr == nil {
			decoded = document
			proxies, err = mihomoProxiesOf(document)
		} else {
			err = decodeErr
		}
	case trimmed[0] == '-':
		if parsed, ok := parseBareMihomoProxySequence(trimmed); ok {
			matched = true
			format = "mihomo-yaml"
			proxies = parsed
		}
	case strings.Contains(text, "[Proxy]"):
		matched = true
		format = "surge"
		var surgeSkipped []proxyImportIssue
		proxies, surgeSkipped, err = parseSurgeProxySection(text)
		containerSkipped = append(containerSkipped, surgeSkipped...)
	case strings.Contains(text, "[Interface]") && strings.Contains(text, "[Peer]"):
		matched = true
		format = "wireguard-ini"
		var proxy map[string]any
		proxy, err = parseWireGuardINI(text)
		if err == nil {
			proxies = []map[string]any{proxy}
		}
	case trimmed[0] == '{' || trimmed[0] == '[':
		matched = true
		var jsonSkipped []proxyImportIssue
		format, proxies, containerNotHonoured, jsonSkipped, err = parseJSONProxyContainer(trimmed)
		containerSkipped = append(containerSkipped, jsonSkipped...)
	case strings.HasPrefix(strings.ToLower(text), "ssd://"):
		matched = true
		format = "ssd"
		var ssdSkipped []proxyImportIssue
		proxies, containerNotHonoured, ssdSkipped, err = parseSSDSubscription(text)
		containerSkipped = append(containerSkipped, ssdSkipped...)
	}
	var shape *proxyImportPayloadShape
	if decoded != nil {
		shape = describeProxyImportPayloadShape(decoded)
	} else {
		shape = classifyProxyImportDocument(trimmed)
	}
	if !matched {
		if shape != nil && shape.IsConfiguration {
			return proxyImportReport{
				Format: mihomoDocumentFormat(trimmed), Context: context,
				Proxies:      make([]map[string]any, 0),
				Skipped:      make([]proxyImportIssue, 0),
				NotHonoured:  make([]proxyImportIssue, 0),
				PayloadShape: shape,
			}, true, nil
		}
		return proxyImportReport{}, false, nil
	}
	if err != nil {
		return proxyImportReport{}, true, fmt.Errorf("clash: parse %s proxy payload: %w", format, err)
	}
	if len(proxies) == 0 && len(containerSkipped) > 0 {
		return proxyImportReport{
			Format: format, Context: context,
			Proxies:      make([]map[string]any, 0),
			Skipped:      containerSkipped,
			NotHonoured:  make([]proxyImportIssue, 0),
			Identities:   make([]string, 0),
			PayloadShape: shape,
		}, true, nil
	}
	if len(proxies) == 0 {
		if shape != nil && shape.IsConfiguration {
			return proxyImportReport{
				Format: format, Context: context,
				Proxies:      make([]map[string]any, 0),
				Skipped:      make([]proxyImportIssue, 0),
				NotHonoured:  make([]proxyImportIssue, 0),
				PayloadShape: shape,
			}, true, nil
		}
		return proxyImportReport{}, true, fmt.Errorf("clash: %s proxy payload contains no proxies", format)
	}
	report := proxyImportReport{
		Format: format, Context: context,
		Proxies:     make([]map[string]any, 0, len(proxies)),
		Skipped:     append(make([]proxyImportIssue, 0, len(containerSkipped)), containerSkipped...),
		NotHonoured: make([]proxyImportIssue, 0),
		Identities:  make([]string, 0, len(proxies)),
	}
	seenNames := make(map[string]int)
	for index, proxy := range proxies {
		scheme, _ := proxy["type"].(string)
		var pending []string
		if index < len(containerNotHonoured) {
			pending = proxyImportNoticeMessages(containerNotHonoured[index])
		}
		skip := func(code string, reason error) {
			report.Skipped = append(report.Skipped, proxyImportIssue{
				Index: index, Scheme: scheme, Code: code, Message: reason.Error(),
				AlsoNotHonoured: pending,
			})
		}
		if validationErr := validateProxyImportRequiredFields(proxy); validationErr != nil {
			skip("malformedRecord", validationErr)
			continue
		}
		if code, err := constructProxyForImport(proxy, construct); err != nil {
			skip(code, err)
			continue
		}
		report.Identities = append(report.Identities, proxyImportIdentity(proxy))
		makeProxyImportNameUnique(proxy, seenNames)
		report.Proxies = append(report.Proxies, proxy)
		name, _ := proxy["name"].(string)
		for _, message := range pending {
			report.NotHonoured = append(report.NotHonoured, proxyImportIssue{
				Index: index, Scheme: scheme, Code: "fieldNotHonoured", Message: message, Proxy: name,
			})
		}
	}
	report.PayloadShape = shape
	return report, true, nil
}

func classifyProxyImportDocument(payload []byte) *proxyImportPayloadShape {
	document, err := decodeMihomoDocument(payload)
	if err != nil || len(document) == 0 {
		return nil
	}
	return describeProxyImportPayloadShape(document)
}

func decodeMihomoDocument(payload []byte) (map[string]any, error) {
	var document map[string]any
	err := yaml.ClashUnmarshal(payload, &document, yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any{})}, nil)
	return document, err
}

func mihomoDocumentFormat(payload []byte) string {
	if trimmed := bytes.TrimSpace(payload); len(trimmed) > 0 && trimmed[0] == '{' {
		return "mihomo-json"
	}
	return "mihomo-yaml"
}

var mihomoProxyKeyPattern = &lazyRegexp{expr: `(?m)^[ \t]*(?:proxies|Proxy|proxy-providers)[ \t]*:`}

func looksLikeMihomoYAML(text string) bool {
	return mihomoProxyKeyPattern.get().MatchString(text)
}

func mihomoProxiesOf(document map[string]any) ([]map[string]any, error) {
	raw, ok := document["proxies"]
	if !ok {
		raw = document["Proxy"]
	}
	if raw == nil {
		return []map[string]any{}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proxies must be a sequence")
	}
	proxies := make([]map[string]any, 0, len(items))
	for index, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %d must be a mapping", index)
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

func parseBareMihomoProxySequence(payload []byte) ([]map[string]any, bool) {
	var items []any
	if err := yaml.Unmarshal(payload, &items); err != nil || len(items) == 0 {
		return nil, false
	}
	proxies := make([]map[string]any, 0, len(items))
	for _, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok || !jsonObjectIsCanonicalMihomoProxy(proxy) {
			return nil, false
		}
		proxies = append(proxies, proxy)
	}
	return proxies, true
}

func parseSurgeProxySection(text string) ([]map[string]any, []proxyImportIssue, error) {
	inProxySection := false
	var proxies []map[string]any
	skipped := make([]proxyImportIssue, 0)
	skip := func(number int, line, message string) {
		skipped = append(skipped, proxyImportIssue{
			Index: len(proxies) + len(skipped), Scheme: "surge", Line: number,
			Code: "malformedRecord", Message: message,
		})
		_ = line
	}
	for number, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inProxySection = strings.EqualFold(line, "[Proxy]")
			continue
		}
		if !inProxySection {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			skip(number+1, line, fmt.Sprintf("invalid [Proxy] line %q", line))
			continue
		}
		reader := csv.NewReader(strings.NewReader(value))
		reader.TrimLeadingSpace = true
		fields, err := reader.Read()
		if err != nil || len(fields) < 3 {
			skip(number+1, line, fmt.Sprintf("invalid [Proxy] value for %q", strings.TrimSpace(name)))
			continue
		}
		proxy, err := surgeProxyMapping(strings.TrimSpace(name), fields)
		if err != nil {
			skip(number+1, line, err.Error())
			continue
		}
		proxies = append(proxies, proxy)
	}
	return proxies, skipped, nil
}

func surgeProxyMapping(name string, fields []string) (map[string]any, error) {
	kind := strings.ToLower(strings.TrimSpace(fields[0]))
	server := strings.TrimSpace(fields[1])
	port, err := strconv.Atoi(strings.TrimSpace(fields[2]))
	if name == "" || server == "" || err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid proxy line %q", name)
	}
	options := make(map[string]string)
	for _, field := range fields[3:] {
		trimmed := strings.TrimSpace(field)
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			if trimmed != "" {
				return nil, unsupportedProxyImportField("surge."+kind+"."+trimmed, "bare option has no mapped semantics")
			}
			continue
		}
		options[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	allowed := queryFieldSet("tfo", "fast-open", "udp", "udp-relay")
	switch kind {
	case "ss", "shadowsocks":
		mergeFieldSet(allowed, "encrypt-method", "method", "cipher", "password")
	case "trojan":
		mergeFieldSet(allowed, "password", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure",
			"ws", "ws-path", "ws-headers")
	case "vmess":
		mergeFieldSet(allowed, "username", "uuid", "tls", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure",
			"ws", "ws-path", "ws-headers", "vmess-aead")
	case "http", "https", "socks5", "socks":
		mergeFieldSet(allowed, "username", "password", "tls", "sni", "peer", "server-name", "skip-cert-verify", "allow-insecure")
	case "snell":
		mergeFieldSet(allowed, "psk", "version", "reuse", "udp-relay", "udp", "mode")
	}
	if err := validateStringMapKeys("surge."+kind, options, allowed); err != nil {
		return nil, err
	}
	if kind == "vmess" && options["vmess-aead"] != "" && !stringMapBoolean(options, "vmess-aead") {
		return nil, unsupportedProxyImportField("surge.vmess.vmess-aead", "the legacy header needs an alterId this line does not carry")
	}
	proxy := map[string]any{"name": name, "server": server, "port": port}
	switch kind {
	case "ss", "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = firstStringMapValue(options, "encrypt-method", "method", "cipher")
		proxy["password"] = options["password"]
		proxy["udp"] = true
	case "trojan":
		proxy["type"] = "trojan"
		proxy["password"] = options["password"]
		proxy["udp"] = true
	case "vmess":
		proxy["type"] = "vmess"
		proxy["uuid"] = firstStringMapValue(options, "username", "uuid")
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
		if stringMapBoolean(options, "tls") {
			proxy["tls"] = true
		}
	case "http", "https":
		proxy["type"] = "http"
		proxy["username"] = options["username"]
		proxy["password"] = options["password"]
		proxy["tls"] = kind == "https" || stringMapBoolean(options, "tls")
	case "socks5", "socks":
		proxy["type"] = "socks5"
		proxy["username"] = options["username"]
		proxy["password"] = options["password"]
		proxy["udp"] = stringMapBoolean(options, "udp-relay", "udp")
	case "snell":
		proxy["type"] = "snell"
		proxy["psk"] = options["psk"]
		version := snellDefaultImportVersion
		if parsed, parseErr := strconv.Atoi(options["version"]); parseErr == nil && parsed != 0 {
			version = parsed
			proxy["version"] = version
		}
		if stringMapBoolean(options, "reuse") {
			proxy["reuse"] = true
		}
		udp := version >= 3
		for _, key := range []string{"udp-relay", "udp"} {
			if value := strings.TrimSpace(options[key]); udp && value != "" {
				udp = stringMapBoolean(options, key)
				break
			}
		}
		if udp {
			proxy["udp"] = true
		}
		if mode := options["mode"]; mode != "" {
			if version != 6 {
				return nil, unsupportedProxyImportField("surge.snell.mode", "mode is version 6's; a lower version has none")
			}
			proxy["mode"] = mode
		}
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", kind)
	}
	if (kind == "vmess" || kind == "trojan") && stringMapBoolean(options, "ws") {
		proxy["network"] = "ws"
		opts := map[string]any{}
		if path := options["ws-path"]; path != "" {
			opts["path"] = path
		}
		if raw := options["ws-headers"]; raw != "" {
			headers := map[string]any{}
			for _, pair := range strings.Split(raw, "|") {
				if name, value, ok := strings.Cut(pair, ":"); ok && strings.TrimSpace(name) != "" {
					headers[strings.TrimSpace(name)] = strings.Trim(strings.TrimSpace(value), `"`)
				}
			}
			if len(headers) > 0 {
				opts["headers"] = headers
			}
		}
		proxy["ws-opts"] = opts
	}
	if sni := firstStringMapValue(options, "sni", "peer", "server-name"); sni != "" {
		if kind == "vmess" {
			proxy["servername"] = sni
		} else {
			proxy["sni"] = sni
		}
	}
	if stringMapBoolean(options, "skip-cert-verify", "allow-insecure") {
		proxy["skip-cert-verify"] = true
	}
	if stringMapBoolean(options, "tfo", "fast-open") {
		proxy["tfo"] = true
	}
	if kind != "snell" && stringMapBoolean(options, "udp", "udp-relay") {
		proxy["udp"] = true
	}
	return proxy, nil
}

func firstStringMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

func stringMapBoolean(values map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(values[key]) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func validateStringMapKeys(prefix string, values map[string]string, allowed map[string]struct{}) error {
	for key, value := range values {
		if _, ok := allowed[key]; ok || strings.TrimSpace(value) == "" {
			continue
		}
		return unsupportedProxyImportField(prefix+"."+key, "container field is not mapped by this importer build")
	}
	return nil
}

func parseJSONProxyContainer(payload []byte) (string, []map[string]any, [][]string, []proxyImportIssue, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "json", nil, nil, nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "json", nil, nil, nil, err
	}
	if array, ok := value.([]any); ok {
		proxies, notHonoured, nested, skipped, err := parseJSONArrayProxyContainers(array)
		if nested {
			return "mixed-proxy-json", proxies, notHonoured, skipped, err
		}
		return "proxy-json", proxies, notHonoured, skipped, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "json", nil, nil, nil, fmt.Errorf("top level must be an object or array")
	}
	if raw, ok := object["proxies"].([]any); ok {
		proxies, skipped := canonicalJSONProxyArray(raw)
		return "mihomo-json", proxies, nil, skipped, nil
	}
	if raw, ok := object["servers"].([]any); ok {
		proxies, notHonoured, skipped := parseJSONServerArray(raw, object)
		format := "shadowrocket-json"
		if len(raw) > 0 {
			if first, ok := raw[0].(map[string]any); ok && first["server_port"] != nil {
				format = "sip008-json"
			}
		}
		return format, proxies, notHonoured, skipped, nil
	}
	if raw, ok := object["outbounds"].([]any); ok {
		format := "sing-box-json"
		if len(raw) > 0 {
			if first, ok := raw[0].(map[string]any); ok && first["protocol"] != nil {
				format = "v2ray-json"
			}
		}
		proxies, notHonoured, skipped, err := parseJSONOutbounds(raw, format)
		return format, proxies, notHonoured, skipped, err
	}
	if shape := describeProxyImportPayloadShape(object); shape != nil && !shape.IsConfiguration {
		return "json", nil, nil, nil, fmt.Errorf(
			"JSON is not a mihomo configuration: none of its %d top level key(s) is one the kernel declares (%s)",
			len(shape.UnrecognizedKeys), strings.Join(shape.UnrecognizedKeys, ", "))
	}
	return "json", nil, nil, nil, fmt.Errorf("JSON does not contain proxies or servers")
}

func parseJSONArrayProxyContainers(items []any) ([]map[string]any, [][]string, bool, []proxyImportIssue, error) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	nestedSkipped := make([]proxyImportIssue, 0)
	nested := false
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, nil, nested, nil, fmt.Errorf("server %d must be an object", index)
		}
		var (
			parsed  []map[string]any
			notices [][]string
			err     error
		)
		switch {
		case object["proxies"] != nil:
			nested = true
			raw, ok := object["proxies"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d proxies must be an array", index)
			}
			var proxySkipped []proxyImportIssue
			parsed, proxySkipped = canonicalJSONProxyArray(raw)
			nestedSkipped = append(nestedSkipped, proxySkipped...)
		case object["servers"] != nil:
			nested = true
			raw, ok := object["servers"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d servers must be an array", index)
			}
			var serverSkipped []proxyImportIssue
			parsed, notices, serverSkipped = parseJSONServerArray(raw, object)
			nestedSkipped = append(nestedSkipped, serverSkipped...)
		case object["outbounds"] != nil:
			nested = true
			raw, ok := object["outbounds"].([]any)
			if !ok {
				return nil, nil, nested, nil, fmt.Errorf("container %d outbounds must be an array", index)
			}
			format := "sing-box-json"
			if len(raw) > 0 {
				if first, ok := raw[0].(map[string]any); ok && first["protocol"] != nil {
					format = "v2ray-json"
				}
			}
			var outboundSkipped []proxyImportIssue
			parsed, notices, outboundSkipped, err = parseJSONOutbounds(raw, format)
			nestedSkipped = append(nestedSkipped, outboundSkipped...)
		case jsonObjectIsCanonicalMihomoProxy(object):
			parsed, _ = canonicalJSONProxyArray([]any{object})
		default:
			var (
				proxy      map[string]any
				serverNote []string
			)
			proxy, serverNote, err = jsonServerMapping(object, nil)
			if err == nil {
				parsed = []map[string]any{proxy}
				notices = [][]string{serverNote}
			}
		}
		if err != nil {
			nestedSkipped = append(nestedSkipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("JSON item %d: %v", index, err),
			})
			continue
		}
		proxies = append(proxies, parsed...)
		notHonoured = append(notHonoured, paddedNotices(notices, len(parsed))...)
	}
	return proxies, notHonoured, nested, nestedSkipped, nil
}

func paddedNotices(notices [][]string, count int) [][]string {
	if len(notices) == count {
		return notices
	}
	return make([][]string, count)
}

func parseJSONOutbounds(items []any, format string) ([]map[string]any, [][]string, []proxyImportIssue, error) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	skipped := make([]proxyImportIssue, 0)
	for index, item := range items {
		outbound, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("outbound %d must be an object", index),
			})
			continue
		}
		var (
			proxy   map[string]any
			notices []string
			err     error
			skip    bool
		)
		if format == "v2ray-json" {
			proxy, skip, notices, err = v2rayOutboundMapping(outbound)
		} else {
			proxy, skip, notices, err = singBoxOutboundMapping(outbound)
		}
		if err != nil {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Scheme: anyString(outbound["type"]),
				Code: "malformedRecord", Message: err.Error(),
				AlsoNotHonoured: proxyImportNoticeMessages(notices),
			})
			continue
		}
		if !skip {
			proxies = append(proxies, proxy)
			notHonoured = append(notHonoured, notices)
		}
	}
	return proxies, notHonoured, skipped, nil
}

func singBoxOutboundMapping(outbound map[string]any) (map[string]any, bool, []string, error) {
	kind := strings.ToLower(anyString(outbound["type"]))
	switch kind {
	case "direct", "block", "dns", "selector", "urltest":
		return nil, true, nil, nil
	}
	allowed := queryFieldSet("type", "tag", "server", "server_port", "tls", "transport")
	switch kind {
	case "vless":
		mergeFieldSet(allowed, "uuid", "flow")
	case "vmess":
		mergeFieldSet(allowed, "uuid", "alter_id", "security", "cipher")
	case "trojan", "hysteria2", "anytls":
		mergeFieldSet(allowed, "password")
	case "hysteria":
		mergeFieldSet(allowed, "auth_str", "auth", "up", "up_mbps", "down", "down_mbps")
	case "shadowsocks":
		mergeFieldSet(allowed, "method", "password")
	case "socks", "socks5", "http":
		mergeFieldSet(allowed, "username", "password")
	case "ssh":
		mergeFieldSet(allowed, "user", "password", "private_key")
	}
	notHonoured := unmappedObjectKeys("sing-box.outbound", outbound, allowed)
	server := anyString(outbound["server"])
	port, ok := anyInt(outbound["server_port"])
	if server == "" || !ok || port < 1 || port > 65535 {
		return nil, false, notHonoured, fmt.Errorf("%s outbound is missing server or server_port", kind)
	}
	name := anyString(outbound["tag"])
	if name == "" {
		name = server
	}
	proxy := map[string]any{"name": name, "type": kind, "server": server, "port": port}
	switch kind {
	case "vless":
		proxy["uuid"] = anyString(outbound["uuid"])
		if flow := anyString(outbound["flow"]); flow != "" {
			proxy["flow"] = flow
		}
	case "vmess":
		proxy["uuid"] = anyString(outbound["uuid"])
		proxy["alterId"], _ = anyInt(outbound["alter_id"])
		proxy["cipher"] = firstAnyString(outbound, "security", "cipher")
		if proxy["cipher"] == "" {
			proxy["cipher"] = "auto"
		}
	case "trojan", "hysteria2", "anytls":
		proxy["password"] = anyString(outbound["password"])
	case "hysteria":
		proxy["auth-str"] = firstAnyString(outbound, "auth_str", "auth")
		proxy["up"] = firstAnyString(outbound, "up", "up_mbps")
		proxy["down"] = firstAnyString(outbound, "down", "down_mbps")
	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = anyString(outbound["method"])
		proxy["password"] = anyString(outbound["password"])
	case "socks", "socks5":
		proxy["type"] = "socks5"
		proxy["username"] = anyString(outbound["username"])
		proxy["password"] = anyString(outbound["password"])
	case "http":
		proxy["username"] = anyString(outbound["username"])
		proxy["password"] = anyString(outbound["password"])
	case "ssh":
		proxy["username"] = anyString(outbound["user"])
		proxy["password"] = anyString(outbound["password"])
		if privateKey := anyString(outbound["private_key"]); privateKey != "" {
			proxy["private-key"] = privateKey
		}
	default:
		return nil, false, notHonoured, fmt.Errorf("unsupported outbound type %q in this configuration dialect", kind)
	}
	tlsNotHonoured, err := applySingBoxTLS(proxy, outbound["tls"])
	notHonoured = append(notHonoured, tlsNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	transportNotHonoured, err := applySingBoxTransport(proxy, outbound["transport"])
	notHonoured = append(notHonoured, transportNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	return proxy, false, notHonoured, nil
}

func firstAnyString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := anyString(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func mergeFieldSet(fields map[string]struct{}, additions ...string) {
	for _, field := range additions {
		fields[field] = struct{}{}
	}
}

func unmappedObjectKeys(prefix string, object map[string]any, allowed map[string]struct{}) []string {
	var notices []string
	for key, value := range object {
		if _, ok := allowed[key]; ok || isAbsentImportValue(value) {
			continue
		}
		notices = append(notices, unmappedProxyImportFieldNotice(prefix+"."+key))
	}
	sort.Strings(notices)
	return notices
}

func unmappedProxyImportFieldNotice(path string) string {
	return path + ": not mapped by this importer build"
}

func proxyImportNoticeMessages(notices []string) []string {
	if len(notices) == 0 {
		return nil
	}
	messages := make([]string, 0, len(notices))
	for _, notice := range notices {
		messages = append(messages, "clash: proxy field "+notice)
	}
	return messages
}

func importObject(prefix string, raw any) (map[string]any, bool, error) {
	if isEmptyImportValue(raw) {
		return nil, false, nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, false, unsupportedProxyImportField(prefix, "JSON child must be an object")
	}
	return object, true, nil
}

func isAbsentImportValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	}
	return false
}

func isEmptyImportValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case bool:
		return !typed
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	}
	return false
}

func hasNonemptyObjectValue(object map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, exists := object[key]; exists && !isEmptyImportValue(value) {
			return true
		}
	}
	return false
}

func applySingBoxTLS(proxy map[string]any, raw any) ([]string, error) {
	tls, present, err := importObject("sing-box.outbound.tls", raw)
	if err != nil || !present {
		return nil, err
	}
	notHonoured := unmappedObjectKeys(
		"sing-box.outbound.tls", tls,
		queryFieldSet("enabled", "server_name", "insecure", "alpn", "utls", "reality"),
	)
	if !anyBool(tls["enabled"]) {
		if hasNonemptyObjectValue(tls, "server_name", "insecure", "alpn", "utls", "reality") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.enabled", "TLS children are set while TLS is disabled")
		}
		return notHonoured, nil
	}
	proxy["tls"] = true
	if serverName := anyString(tls["server_name"]); serverName != "" {
		if proxy["type"] == "vless" || proxy["type"] == "vmess" {
			proxy["servername"] = serverName
		} else {
			proxy["sni"] = serverName
		}
	}
	if anyBool(tls["insecure"]) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := anyStringSlice(tls["alpn"]); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if utls, exists, objectErr := importObject("sing-box.outbound.tls.utls", tls["utls"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		notHonoured = append(notHonoured, unmappedObjectKeys("sing-box.outbound.tls.utls", utls, queryFieldSet("enabled", "fingerprint"))...)
		if anyBool(utls["enabled"]) {
			if fingerprint := anyString(utls["fingerprint"]); fingerprint != "" {
				proxy["client-fingerprint"] = fingerprint
			}
		} else if hasNonemptyObjectValue(utls, "fingerprint") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.utls.enabled", "uTLS children are set while uTLS is disabled")
		}
	}
	if reality, exists, objectErr := importObject("sing-box.outbound.tls.reality", tls["reality"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"sing-box.outbound.tls.reality", reality,
			queryFieldSet("enabled", "public_key", "short_id"),
		)...)
		if anyBool(reality["enabled"]) {
			switch proxy["type"] {
			case "vmess", "vless", "trojan":
			default:
				return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.reality", "proxy type has no Reality transport")
			}
			publicKey := anyString(reality["public_key"])
			if publicKey == "" {
				return notHonoured, fmt.Errorf("Reality is missing public_key")
			}
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   anyString(reality["short_id"]),
			}
		} else if hasNonemptyObjectValue(reality, "public_key", "short_id") {
			return notHonoured, unsupportedProxyImportField("sing-box.outbound.tls.reality.enabled", "Reality children are set while Reality is disabled")
		}
	}
	return notHonoured, nil
}

func applySingBoxTransport(proxy map[string]any, raw any) ([]string, error) {
	transport, present, err := importObject("sing-box.outbound.transport", raw)
	if err != nil || !present {
		return nil, err
	}
	network := strings.ToLower(anyString(transport["type"]))
	if network == "" || network == "tcp" {
		return unmappedObjectKeys("sing-box.outbound.transport", transport, queryFieldSet("type")), nil
	}
	proxy["network"] = network
	var notHonoured []string
	switch network {
	case "ws":
		notHonoured = unmappedObjectKeys(
			"sing-box.outbound.transport.ws", transport,
			queryFieldSet("type", "path", "headers", "max_early_data", "early_data_header_name"),
		)
		headers := map[string]string{}
		if rawHeaders, exists, objectErr := importObject("sing-box.outbound.transport.ws.headers", transport["headers"]); objectErr != nil {
			return notHonoured, objectErr
		} else if exists {
			for key, value := range rawHeaders {
				headers[key] = anyString(value)
			}
		}
		wsOpts := map[string]any{"path": anyString(transport["path"]), "headers": headers}
		if earlyData, ok := anyInt(transport["max_early_data"]); ok && earlyData > 0 {
			wsOpts["max-early-data"] = earlyData
		}
		if header := anyString(transport["early_data_header_name"]); header != "" {
			wsOpts["early-data-header-name"] = header
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		notHonoured = unmappedObjectKeys("sing-box.outbound.transport.grpc", transport, queryFieldSet("type", "service_name", "serviceName"))
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": firstAnyString(transport, "service_name", "serviceName")}
	case "http":
		notHonoured = unmappedObjectKeys("sing-box.outbound.transport.http", transport, queryFieldSet("type", "host", "path"))
		proxy["network"] = "h2"
		proxy["h2-opts"] = map[string]any{"host": anyStringSlice(transport["host"]), "path": anyString(transport["path"])}
	default:
		return nil, unsupportedProxyImportField("json.outbound.transport.type", fmt.Sprintf("unsupported transport %q", network))
	}
	return notHonoured, nil
}

func v2rayOutboundMapping(outbound map[string]any) (map[string]any, bool, []string, error) {
	protocol := strings.ToLower(anyString(outbound["protocol"]))
	switch protocol {
	case "freedom", "blackhole", "dns":
		return nil, true, nil, nil
	}
	notHonoured := unmappedObjectKeys(
		"v2ray.outbound", outbound,
		queryFieldSet("tag", "protocol", "settings", "streamSettings"),
	)
	settings, ok := outbound["settings"].(map[string]any)
	if !ok {
		return nil, false, notHonoured, fmt.Errorf("%s outbound has no settings object", protocol)
	}
	name := anyString(outbound["tag"])
	if name == "" {
		name = protocol
	}
	var proxy map[string]any
	switch protocol {
	case "vmess", "vless":
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings", settings, queryFieldSet("vnext"))...)
		if count := objectArrayLength(settings["vnext"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.vnext", "exactly one endpoint is representable")
		}
		vnext, ok := firstObject(settings["vnext"])
		if !ok {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has no vnext endpoint", protocol)
		}
		port, portOK := anyInt(vnext["port"])
		user, userOK := firstObject(vnext["users"])
		if anyString(vnext["address"]) == "" || !portOK || !userOK {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has an incomplete vnext endpoint", protocol)
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.vnext[0]", vnext, queryFieldSet("address", "port", "users"))...)
		if count := objectArrayLength(vnext["users"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.vnext[0].users", "exactly one user is representable")
		}
		userFields := queryFieldSet("id", "flow", "encryption")
		if protocol == "vmess" {
			mergeFieldSet(userFields, "alterId", "security", "cipher")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.vnext[0].users[0]", user, userFields)...)
		proxy = map[string]any{
			"name": name, "type": protocol, "server": anyString(vnext["address"]), "port": port,
			"uuid": anyString(user["id"]), "udp": true,
		}
		if protocol == "vmess" {
			proxy["alterId"], _ = anyInt(user["alterId"])
			proxy["cipher"] = firstAnyString(user, "security", "cipher")
			if proxy["cipher"] == "" {
				proxy["cipher"] = "auto"
			}
		} else if flow := anyString(user["flow"]); flow != "" {
			proxy["flow"] = flow
		}
	case "trojan", "shadowsocks":
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings", settings, queryFieldSet("servers"))...)
		if count := objectArrayLength(settings["servers"]); count != 1 {
			return nil, false, notHonoured, unsupportedProxyImportField("v2ray.outbound.settings.servers", "exactly one endpoint is representable")
		}
		server, ok := firstObject(settings["servers"])
		if !ok {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has no server", protocol)
		}
		port, portOK := anyInt(server["port"])
		if anyString(server["address"]) == "" || !portOK {
			return nil, false, notHonoured, fmt.Errorf("%s outbound has an incomplete server", protocol)
		}
		serverFields := queryFieldSet("address", "port", "password")
		if protocol == "shadowsocks" {
			mergeFieldSet(serverFields, "method")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.settings.servers[0]", server, serverFields)...)
		proxy = map[string]any{
			"name": name, "type": protocol, "server": anyString(server["address"]), "port": port, "udp": true,
			"password": anyString(server["password"]),
		}
		if protocol == "shadowsocks" {
			proxy["type"] = "ss"
			proxy["cipher"] = anyString(server["method"])
		}
	default:
		return nil, false, notHonoured, fmt.Errorf("unsupported V2Ray outbound protocol %q", protocol)
	}
	streamNotHonoured, err := applyV2RayStreamSettings(proxy, outbound["streamSettings"])
	notHonoured = append(notHonoured, streamNotHonoured...)
	if err != nil {
		return nil, false, notHonoured, err
	}
	return proxy, false, notHonoured, nil
}

func objectArrayLength(raw any) int {
	items, ok := raw.([]any)
	if !ok {
		return 0
	}
	return len(items)
}

func firstObject(raw any) (map[string]any, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, false
	}
	object, ok := items[0].(map[string]any)
	return object, ok
}

func applyV2RayStreamSettings(proxy map[string]any, raw any) ([]string, error) {
	settings, present, err := importObject("v2ray.outbound.streamSettings", raw)
	if err != nil || !present {
		return nil, err
	}
	notHonoured := unmappedObjectKeys(
		"v2ray.outbound.streamSettings", settings,
		queryFieldSet("network", "security", "tlsSettings", "realitySettings", "wsSettings", "grpcSettings", "httpSettings"),
	)
	network := strings.ToLower(anyString(settings["network"]))
	if network != "" && network != "tcp" {
		proxy["network"] = network
	}
	security := strings.ToLower(anyString(settings["security"]))
	if security == "tls" || security == "reality" {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.security", "proxy type has no representable TLS transport")
		}
	}
	if tlsSettings, exists, objectErr := importObject("v2ray.outbound.streamSettings.tlsSettings", settings["tlsSettings"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.tlsSettings", "proxy type has no representable TLS transport")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.tlsSettings", tlsSettings,
			queryFieldSet("serverName", "allowInsecure", "alpn", "fingerprint"),
		)...)
		if serverName := anyString(tlsSettings["serverName"]); serverName != "" {
			proxy["servername"] = serverName
		}
		if anyBool(tlsSettings["allowInsecure"]) {
			proxy["skip-cert-verify"] = true
		}
		if alpn := anyStringSlice(tlsSettings["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fingerprint := anyString(tlsSettings["fingerprint"]); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
	}
	if realitySettings, exists, objectErr := importObject("v2ray.outbound.streamSettings.realitySettings", settings["realitySettings"]); objectErr != nil {
		return notHonoured, objectErr
	} else if exists {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["tls"] = true
		default:
			return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.realitySettings", "proxy type has no Reality transport")
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.realitySettings", realitySettings,
			queryFieldSet("serverName", "fingerprint", "publicKey", "shortId"),
		)...)
		publicKey := anyString(realitySettings["publicKey"])
		if publicKey == "" {
			return notHonoured, fmt.Errorf("V2Ray Reality is missing publicKey")
		}
		if serverName := anyString(realitySettings["serverName"]); serverName != "" {
			if proxy["type"] == "vmess" || proxy["type"] == "vless" {
				proxy["servername"] = serverName
			} else {
				proxy["sni"] = serverName
			}
		}
		if fingerprint := anyString(realitySettings["fingerprint"]); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   anyString(realitySettings["shortId"]),
		}
	}
	switch network {
	case "ws":
		ws, _, objectErr := importObject("v2ray.outbound.streamSettings.wsSettings", settings["wsSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys(
			"v2ray.outbound.streamSettings.wsSettings", ws,
			queryFieldSet("path", "headers", "maxEarlyData", "earlyDataHeaderName"),
		)...)
		headers := map[string]string{}
		if rawHeaders, exists, headersErr := importObject("v2ray.outbound.streamSettings.wsSettings.headers", ws["headers"]); headersErr != nil {
			return notHonoured, headersErr
		} else if exists {
			for key, value := range rawHeaders {
				headers[key] = anyString(value)
			}
		}
		wsOpts := map[string]any{"path": anyString(ws["path"]), "headers": headers}
		if earlyData, ok := anyInt(ws["maxEarlyData"]); ok && earlyData > 0 {
			wsOpts["max-early-data"] = earlyData
		}
		if header := anyString(ws["earlyDataHeaderName"]); header != "" {
			wsOpts["early-data-header-name"] = header
		}
		proxy["ws-opts"] = wsOpts
	case "grpc":
		grpc, _, objectErr := importObject("v2ray.outbound.streamSettings.grpcSettings", settings["grpcSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.streamSettings.grpcSettings", grpc, queryFieldSet("serviceName"))...)
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": anyString(grpc["serviceName"])}
	case "h2", "http":
		httpSettings, _, objectErr := importObject("v2ray.outbound.streamSettings.httpSettings", settings["httpSettings"])
		if objectErr != nil {
			return notHonoured, objectErr
		}
		notHonoured = append(notHonoured, unmappedObjectKeys("v2ray.outbound.streamSettings.httpSettings", httpSettings, queryFieldSet("host", "path"))...)
		proxy["network"] = "h2"
		proxy["h2-opts"] = map[string]any{
			"host": anyStringSlice(httpSettings["host"]), "path": anyString(httpSettings["path"]),
		}
	case "", "tcp":
	default:
		return notHonoured, unsupportedProxyImportField("v2ray.outbound.streamSettings.network", fmt.Sprintf("unsupported transport %q", network))
	}
	return notHonoured, nil
}

func anyBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(typed) {
		case "1", "true", "yes", "on":
			return true
		}
	case json.Number:
		return typed.String() == "1"
	}
	return false
}

func anyStringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if text := anyString(value); text != "" {
			return []string{text}
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := anyString(item); text != "" {
			result = append(result, text)
		}
	}
	return result
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

var proxyImportDialectOnlyJSONKeys = &lazyValue[map[string]struct{}]{build: func() map[string]struct{} {
	return queryFieldSet(
		"host", "server_port", "protocol", "remarks", "remark", "title", "id", "group", "ratio",
		"encryption", "method", "alter_id", "security", "peer", "serverName", "tlsServerName",
		"allowInsecure", "allow_insecure", "insecure", "fp", "hpkp", "pbk", "publicKey", "sid",
		"shortId", "fastopen",
	)
}}

func jsonObjectIsCanonicalMihomoProxy(object map[string]any) bool {
	if strings.TrimSpace(anyString(object["type"])) == "" {
		return false
	}
	if anyString(object["server"]) == "" || object["port"] == nil {
		return false
	}
	for key := range object {
		if _, dialect := proxyImportDialectOnlyJSONKeys.get()[key]; dialect {
			return false
		}
	}
	return true
}

func canonicalJSONProxyArray(items []any) ([]map[string]any, []proxyImportIssue) {
	proxies := make([]map[string]any, 0, len(items))
	var skipped []proxyImportIssue
	for index, item := range items {
		proxy, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("proxy %d must be an object", index),
			})
			continue
		}
		proxies = append(proxies, normalizeJSONNumbers(proxy))
	}
	return proxies, skipped
}

func parseJSONServerArray(items []any, defaults map[string]any) ([]map[string]any, [][]string, []proxyImportIssue) {
	proxies := make([]map[string]any, 0, len(items))
	notHonoured := make([][]string, 0, len(items))
	var skipped []proxyImportIssue
	for index, item := range items {
		server, ok := item.(map[string]any)
		if !ok {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Code: "malformedRecord",
				Message: fmt.Sprintf("server %d must be an object", index),
			})
			continue
		}
		proxy, notices, err := jsonServerMapping(server, defaults)
		if err != nil {
			skipped = append(skipped, proxyImportIssue{
				Index: index, Scheme: strings.ToLower(firstAnyString(server, "type", "protocol")),
				Code: "malformedRecord", Message: fmt.Sprintf("server %d: %v", index, err),
				AlsoNotHonoured: proxyImportNoticeMessages(notices),
			})
			continue
		}
		proxies = append(proxies, proxy)
		notHonoured = append(notHonoured, notices)
	}
	return proxies, notHonoured, skipped
}

func jsonServerMapping(server, defaults map[string]any) (map[string]any, []string, error) {
	value := func(keys ...string) any {
		for _, key := range keys {
			if item := server[key]; item != nil {
				return item
			}
		}
		for _, key := range keys {
			if defaults != nil {
				if item := defaults[key]; item != nil {
					return item
				}
			}
		}
		return nil
	}
	kind := strings.ToLower(firstAnyString(server, "type", "protocol"))
	if kind == "" && defaults != nil {
		candidate := strings.ToLower(firstAnyString(defaults, "type", "protocol"))
		if candidate != "shadowrocket" {
			kind = candidate
		}
	}
	if kind == "" && value("method", "encryption") != nil {
		kind = "ss"
	}
	allowed := queryFieldSet(
		"server", "host", "server_port", "port", "type", "protocol", "remarks", "remark", "title", "name",
		"id", "group", "ratio",
	)
	switch kind {
	case "ss", "shadowsocks":
		mergeFieldSet(allowed, "method", "encryption", "cipher", "password", "plugin")
	case "trojan", "hysteria2", "hy2", "anytls":
		mergeFieldSet(allowed, "password")
	case "vless", "vmess":
		mergeFieldSet(allowed, "uuid", "password", "flow", "alterId", "alter_id", "security", "cipher")
	}
	switch kind {
	case "trojan", "hysteria2", "hy2", "anytls", "vless", "vmess":
		mergeFieldSet(
			allowed, "tls", "security", "sni", "peer", "serverName", "tlsServerName", "allowInsecure",
			"allow_insecure", "insecure", "skip-cert-verify", "alpn", "fingerprint", "fp", "hpkp",
			"pbk", "publicKey", "sid", "shortId", "tfo", "fastopen", "udp",
		)
	}
	notHonoured := unmappedObjectKeys("json.server", server, allowed)
	host := anyString(value("server", "host"))
	port, ok := anyInt(value("server_port", "port"))
	if host == "" || !ok || port < 1 || port > 65535 {
		return nil, notHonoured, fmt.Errorf("missing server or port")
	}
	name := anyString(value("remarks", "remark", "title", "name"))
	if name == "" {
		name = host
	}
	proxy := map[string]any{"name": name, "server": host, "port": port, "udp": true}
	switch kind {
	case "ss", "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = anyString(value("method", "encryption", "cipher"))
		proxy["password"] = anyString(value("password"))
		if plugin := anyString(value("plugin")); plugin != "" {
			proxy["plugin"] = plugin
		}
	case "trojan", "hysteria2", "hy2", "anytls":
		if kind == "hy2" {
			kind = "hysteria2"
		}
		proxy["type"] = kind
		proxy["password"] = anyString(value("password"))
	case "vless", "vmess":
		proxy["type"] = kind
		proxy["uuid"] = anyString(value("uuid", "password"))
		if kind == "vmess" {
			proxy["alterId"], _ = anyInt(value("alterId", "alter_id"))
			proxy["cipher"] = firstAnyString(server, "security", "cipher")
			if proxy["cipher"] == "" {
				proxy["cipher"] = "auto"
			}
		} else if flow := anyString(value("flow")); flow != "" {
			proxy["flow"] = flow
		}
	default:
		return nil, notHonoured, fmt.Errorf("unsupported JSON server type %q", kind)
	}
	if sni := anyString(value("sni", "peer", "serverName", "tlsServerName")); sni != "" {
		if kind == "vless" || kind == "vmess" {
			proxy["servername"] = sni
		} else {
			proxy["sni"] = sni
		}
	}
	security := strings.ToLower(anyString(value("security")))
	publicKey := anyString(value("pbk", "publicKey"))
	if anyBool(value("tls")) || security == "tls" || security == "reality" || publicKey != "" {
		proxy["tls"] = true
	}
	if anyBool(value("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify")) {
		proxy["skip-cert-verify"] = true
	}
	if alpn := splitListValues(anyStringSlice(value("alpn"))); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := anyString(value("fp", "fingerprint")); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), anyString(value("hpkp"))); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey != "" {
		switch proxy["type"] {
		case "vmess", "vless", "trojan":
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   anyString(value("sid", "shortId")),
			}
		default:
			return nil, notHonoured, unsupportedProxyImportField("json.server.reality", "proxy type has no Reality transport")
		}
	}
	if anyBool(value("tfo", "fastopen")) {
		proxy["tfo"] = true
	}
	if udp := value("udp"); udp != nil {
		proxy["udp"] = anyBool(udp)
	}
	return proxy, notHonoured, nil
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	default:
		return ""
	}
}

func anyInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	case float64:
		return int(typed), typed == float64(int(typed))
	case string:
		parsed, err := strconv.Atoi(typed)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func normalizeJSONNumbers(mapping map[string]any) map[string]any {
	for key, value := range mapping {
		switch typed := value.(type) {
		case json.Number:
			if integer, err := strconv.Atoi(typed.String()); err == nil {
				mapping[key] = integer
			} else if number, err := typed.Float64(); err == nil {
				mapping[key] = number
			}
		case map[string]any:
			mapping[key] = normalizeJSONNumbers(typed)
		case []any:
			for index, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					typed[index] = normalizeJSONNumbers(nested)
				}
			}
		}
	}
	return mapping
}

func parseSSDSubscription(text string) ([]map[string]any, [][]string, []proxyImportIssue, error) {
	body := strings.TrimSpace(text[len("ssd://"):])
	decoded, err := convert.TryDecodeBase64(body)
	if err != nil {
		return nil, nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, nil, err
	}
	servers, ok := document["servers"].([]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("SSD servers must be an array")
	}
	proxies, notHonoured, skipped := parseJSONServerArray(servers, document)
	return proxies, notHonoured, skipped, nil
}

func parseWireGuardINI(text string) (map[string]any, error) {
	sections := map[string]map[string][]string{}
	sectionCounts := map[string]int{}
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			sectionCounts[section]++
			if sections[section] == nil {
				sections[section] = make(map[string][]string)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return nil, fmt.Errorf("invalid WireGuard INI line %q", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		sections[section][key] = append(sections[section][key], strings.TrimSpace(value))
	}
	for name := range sections {
		if name != "interface" && name != "peer" {
			return nil, unsupportedProxyImportField("wireguard.ini."+name, "only Interface and Peer sections are representable")
		}
	}
	iface, peer := sections["interface"], sections["peer"]
	if iface == nil || peer == nil {
		return nil, fmt.Errorf("WireGuard INI requires Interface and Peer sections")
	}
	if sectionCounts["interface"] != 1 || sectionCounts["peer"] != 1 {
		return nil, fmt.Errorf("WireGuard INI requires exactly one Interface and exactly one Peer")
	}
	if err := validateINISectionKeys(
		"wireguard.ini.interface", iface,
		queryFieldSet("privatekey", "address", "dns", "mtu", "listenport"),
	); err != nil {
		return nil, err
	}
	if err := validateINISectionKeys(
		"wireguard.ini.peer", peer,
		queryFieldSet("publickey", "presharedkey", "endpoint", "persistentkeepalive", "allowedips"),
	); err != nil {
		return nil, err
	}
	endpoint := firstINIValue(peer, "endpoint")
	server, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard endpoint: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid WireGuard endpoint port")
	}
	addresses := splitListValues(iface["address"])
	ipv4, ipv6 := splitIPValues(addresses)
	privateKey := firstINIValue(iface, "privatekey")
	publicKey := firstINIValue(peer, "publickey")
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("WireGuard INI requires PrivateKey, Address and PublicKey")
	}
	proxy := map[string]any{
		"name": endpoint, "type": "wireguard", "server": server, "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if psk := firstINIValue(peer, "presharedkey"); psk != "" {
		proxy["pre-shared-key"] = psk
	}
	if dns := splitListValues(iface["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if mtuText := firstINIValue(iface, "mtu"); mtuText != "" {
		mtu, parseErr := strconv.Atoi(mtuText)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid WireGuard MTU %q", mtuText)
		}
		proxy["mtu"] = mtu
	}
	if keepaliveText := firstINIValue(peer, "persistentkeepalive"); keepaliveText != "" {
		keepalive, parseErr := strconv.Atoi(keepaliveText)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid WireGuard keepalive %q", keepaliveText)
		}
		proxy["persistent-keepalive"] = keepalive
	}
	return proxy, nil
}

func validateINISectionKeys(prefix string, values map[string][]string, allowed map[string]struct{}) error {
	for key := range values {
		if _, ok := allowed[key]; ok {
			continue
		}
		return unsupportedProxyImportField(prefix+"."+key, "INI field is not mapped by this importer build")
	}
	return nil
}

func firstINIValue(section map[string][]string, key string) string {
	values := section[key]
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

type proxyImportRecord struct {
	scheme string
	text   string
	line   int
	offset int
}

func extractProxyImportRecords(text string) []proxyImportRecord {
	matches := proxyImportURLPattern.get().FindAllStringSubmatchIndex(text, -1)
	records := make([]proxyImportRecord, 0, len(matches))
	for index, match := range matches {
		end := len(text)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		if lineEnd := strings.IndexAny(text[match[0]:end], "\r\n"); lineEnd >= 0 {
			end = match[0] + lineEnd
		}
		record := trimProxyImportRecordEdges(text, match[0], end)
		if record == "" {
			continue
		}
		records = append(records, proxyImportRecord{
			scheme: text[match[2]:match[3]],
			text:   record,
			line:   strings.Count(text[:match[0]], "\n") + 1,
			offset: match[0],
		})
	}
	return records
}

var proxyImportRecordClosers = &lazyValue[map[rune]rune]{build: func() map[rune]rune {
	return map[rune]rune{
		')': '(', ']': '[', '}': '{', '>': '<', '"': '"', '\'': '\'', '`': '`',
		'）': '（', '］': '［', '｝': '｛', '》': '《', '」': '「', '』': '『', '】': '【', '”': '“', '’': '‘',
	}
}}

const proxyImportRecordEdgeTrim = " \t\r\n|,;.，。、"

func trimProxyImportRecordEdges(text string, start, end int) string {
	before := text[:start]
	if lineStart := strings.LastIndexAny(before, "\r\n"); lineStart >= 0 {
		before = before[lineStart+1:]
	}
	record := strings.TrimRight(strings.TrimLeft(text[start:end], proxyImportRecordEdgeTrim), proxyImportRecordEdgeTrim)
	for {
		trimmed := strings.TrimRight(record, proxyImportRecordEdgeTrim)
		if trimmed == "" {
			return ""
		}
		last := []rune(trimmed)[len([]rune(trimmed))-1]
		opener, closing := proxyImportRecordClosers.get()[last]
		if !closing || !strings.ContainsRune(before, opener) {
			return trimmed
		}
		record = string([]rune(trimmed)[:len([]rune(trimmed))-1])
	}
}

func normalizeProxyImportAlias(link, scheme, canonicalType string) string {
	if scheme == canonicalType || canonicalType == "" || scheme == "https" || scheme == "mierus" ||
		strings.HasSuffix(scheme, "+realm") {
		return link
	}
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link
	}
	return canonicalType + link[separator:]
}

func proxyImportIdentity(proxy map[string]any) string {
	canonical, err := json.Marshal(canonicalProxyImportValue(proxy))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalProxyImportValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[key] = canonicalProxyImportValue(inner)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[fmt.Sprint(key)] = canonicalProxyImportValue(inner)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, inner := range typed {
			out[index] = canonicalProxyImportValue(inner)
		}
		return out
	default:
		return value
	}
}

func makeProxyImportNameUnique(proxy map[string]any, seen map[string]int) {
	name, _ := proxy["name"].(string)
	if name == "" {
		server, _ := proxy["server"].(string)
		if server == "" {
			return
		}
		name = server
		if port := proxy["port"]; port != nil {
			name = fmt.Sprintf("%s:%v", server, port)
		}
		proxy["name"] = name
	}
	count := seen[name]
	seen[name] = count + 1
	if count > 0 {
		proxy["name"] = fmt.Sprintf("%s-%02d", name, count)
	}
}

func convertProxyShareLinks(payload []byte, tolerateUnmappedFields bool) ([]map[string]any, error) {
	text := string(normalizeLegacyVlessPayload(payload))
	if !proxyImportURLPattern.get().MatchString(text) {
		return nil, fmt.Errorf("clash: proxy payload format is invalid")
	}
	capabilities := proxyImportCapabilityMap()
	records := extractProxyImportRecords(text)
	proxies := make([]map[string]any, 0, len(records))
	seenNames := make(map[string]int)
	for _, record := range records {
		capability, ok := capabilities[strings.ToLower(record.scheme)]
		if !ok {
			if tolerateUnmappedFields {
				continue
			}
			return nil, fmt.Errorf("clash: proxy scheme %q is not recognized", record.scheme)
		}
		if capability.Status != proxyImportSupported {
			if tolerateUnmappedFields {
				continue
			}
			return nil, fmt.Errorf("clash: proxy scheme %q is not supported by the Core importer", record.scheme)
		}
		parsed, _, err := parseProxyShareLinkTolerating(
			record.text, capability, tolerateUnmappedFields,
		)
		if err != nil {
			if tolerateUnmappedFields {
				continue
			}
			return nil, err
		}
		for _, proxy := range parsed {
			makeProxyImportNameUnique(proxy, seenNames)
			proxies = append(proxies, proxy)
		}
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("clash: proxy payload did not contain a supported proxy")
	}
	return proxies, nil
}

func proxyImportCapabilityMap() map[string]proxyImportCapability {
	capabilities := make(map[string]proxyImportCapability, len(proxyImportCapabilities))
	for _, capability := range proxyImportCapabilities {
		capabilities[capability.Scheme] = capability
	}
	return capabilities
}

func parseProxyShareLink(link string, capability proxyImportCapability) ([]map[string]any, []string, error) {
	return parseProxyShareLinkTolerating(link, capability, true)
}

func dropEmptyProxyImportValues(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			if key == "name" {
				continue
			}
			if text, ok := inner.(string); ok && text == "" {
				delete(typed, key)
				continue
			}
			dropEmptyProxyImportValues(inner)
		}
	case []any:
		for _, inner := range typed {
			dropEmptyProxyImportValues(inner)
		}
	}
}

var proxyTypesThatVerifyTheirFingerprint = &lazyValue[map[string]struct{}]{build: func() map[string]struct{} {
	return map[string]struct{}{
		"hysteria": {}, "hysteria2": {}, "tuic": {},
	}
}}

func hysteria2CertificatePin(value string) string {
	return certificatePinOrNothing("hysteria2", value)
}

func certificatePinOrNothing(proxyType, value string) string {
	if value == "" {
		return ""
	}
	if _, verifies := proxyTypesThatVerifyTheirFingerprint.get()[proxyType]; !verifies {
		return value
	}
	if _, err := ca.NewFingerprintVerifier(value, time.Now); err != nil {
		return ""
	}
	return value
}

func realityPublicKeyOrNothing(value string) string {
	if value == "" {
		return ""
	}
	if _, err := (outbound.RealityOptions{PublicKey: value}).Parse(); err != nil {
		return ""
	}
	return value
}

func parseProxyShareLinkTolerating(
	link string, capability proxyImportCapability, tolerateUnmapped bool,
) ([]map[string]any, []string, error) {
	notHonoured, err := validateProxyShareLinkQueryFields(link, capability, tolerateUnmapped)
	if err != nil {
		return nil, nil, err
	}
	proxies, portRange, bodyNotHonoured, parseErr := parseProxyShareLinkRecord(link, capability)
	for _, proxy := range proxies {
		dropEmptyProxyImportValues(proxy)
	}
	notHonoured = append(notHonoured, bodyNotHonoured...)
	if portRange != "" {
		notHonoured = append(notHonoured, capability.Scheme+".authority.ports="+portRange+
			": mihomo's "+capability.CanonicalType+" outbound has no port-hopping option, so only the first port is used")
	}
	return proxies, notHonoured, parseErr
}

func parseProxyShareLinkRecord(link string, capability proxyImportCapability) ([]map[string]any, string, []string, error) {
	var (
		vmessJSON       map[string]any
		bodyNotHonoured []string
	)
	if capability.CanonicalType == "vmess" {
		if proxy, dropped, matched, err := parseLegacyVMessShareLink(link); matched {
			proxies, err := singletonProxy(proxy, err)
			return proxies, dropped, nil, err
		}
		var matched bool
		var err error
		vmessJSON, bodyNotHonoured, matched, err = parseVMessJSONShareLinkFields(link)
		if matched && err != nil {
			return nil, "", bodyNotHonoured, err
		}
	}
	switch capability.CanonicalType {
	case "snell":
		proxy, err := parseSnellShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "ssh":
		proxy, err := parseSSHShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "wireguard":
		proxy, err := parseWireGuardShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "masque":
		proxy, err := parseMasqueShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	case "trusttunnel":
		proxy, err := parseTrustTunnelShareLink(link)
		proxies, err := singletonProxy(proxy, err)
		return proxies, "", nil, err
	}

	normalized, parsed, portRange, err := normalizeProxyShareLinkDialect(link, capability)
	if err != nil {
		return nil, "", bodyNotHonoured, err
	}
	proxies, err := convert.ConvertsV2Ray([]byte(normalized))
	if err != nil {
		return nil, "", bodyNotHonoured, err
	}
	if len(proxies) == 0 {
		return nil, "", bodyNotHonoured, fmt.Errorf("clash: %s proxy URI was not accepted by the dialect parser", capability.Scheme)
	}
	for _, proxy := range proxies {
		if vmessJSON != nil {
			applyVMessJSONShareLinkFields(proxy, vmessJSON)
		}
		if err := applyProxyShareLinkDialect(proxy, parsed); err != nil {
			return nil, "", bodyNotHonoured, err
		}
	}
	return proxies, portRange, bodyNotHonoured, nil
}

func parseVMessJSONShareLinkFields(link string) (map[string]any, []string, bool, error) {
	trimmed := strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		return nil, nil, false, nil
	}
	body := trimmed[len("vmess://"):]
	if boundary := strings.IndexAny(body, "?#"); boundary >= 0 {
		body = body[:boundary]
	}
	decoded, err := convert.TryDecodeBase64(body)
	if err != nil || len(bytes.TrimSpace(decoded)) == 0 || bytes.TrimSpace(decoded)[0] != '{' {
		return nil, nil, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return nil, nil, true, fmt.Errorf("clash: malformed VMess base64 JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, nil, true, fmt.Errorf("clash: malformed VMess base64 JSON: %w", err)
	}
	allowed := queryFieldSet(
		"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni",
		"alpn", "allowInsecure", "skip-cert-verify", "fp", "fingerprint", "hpkp", "pbk", "sid", "security",
		"udp", "tfo", "packetEncoding", "encryption",
	)
	return values, unmappedObjectKeys("vmess.base64-json", values, allowed), true, nil
}

func applyVMessJSONShareLinkFields(proxy map[string]any, values map[string]any) {
	if anyBool(values["allowInsecure"]) || anyBool(values["skip-cert-verify"]) {
		proxy["skip-cert-verify"] = true
	}
	if fingerprint := firstAnyString(values, "fp", "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), anyString(values["hpkp"])); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey := realityPublicKeyOrNothing(anyString(values["pbk"])); publicKey != "" {
		proxy["tls"] = true
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   anyString(values["sid"]),
		}
	}
	if strings.EqualFold(anyString(values["security"]), "reality") || strings.EqualFold(anyString(values["tls"]), "reality") {
		proxy["tls"] = true
	}
	if anyBool(values["tfo"]) {
		proxy["tfo"] = true
	}
	if udp, exists := values["udp"]; exists {
		proxy["udp"] = anyBool(udp)
	}
}

const proxyImportMasqueNoWireGuardFields = "mihomo's masque outbound authenticates with a key pair and has no equivalent for these WireGuard-shaped fields"

const snellDefaultImportVersion = 1

const proxyImportSnellNoTLS = "mihomo's snell outbound has no TLS, so there is nothing for this field to configure"

const proxyImportMieruNoTLS = "mihomo's mieru outbound has no TLS, so there is nothing to configure with it"

func proxyImportNoRealityTransport(display string) string {
	return "mihomo's " + display + " outbound has no Reality transport"
}

var proxyImportUnhonouredFields = &lazyValue[map[string]map[string]string]{build: func() map[string]map[string]string {
	return map[string]map[string]string{
		"socks5": {
			"alpn":          "mihomo's socks5 outbound has no alpn field",
			"peer":          "mihomo's socks5 outbound has no server-name field",
			"sni":           "mihomo's socks5 outbound has no server-name field",
			"serverName":    "mihomo's socks5 outbound has no server-name field",
			"tlsServerName": "mihomo's socks5 outbound has no server-name field",
		},
		"trojan": {
			"mux": proxyImportMuxNotHonoured,
		},
		"vmess": {
			"mux": proxyImportMuxNotHonoured,
		},
		"vless": {
			"mux": proxyImportMuxNotHonoured,
		},
		"snell": {
			"security":    "mihomo's snell outbound has no TLS or security field",
			"alpn":        "mihomo's snell outbound has no TLS, so there is no ALPN to set",
			"keepalive":   "mihomo's snell outbound has no keepalive field",
			"fingerprint": proxyImportSnellNoTLS,
			"hpkp":        proxyImportSnellNoTLS,
			"publicKey":   proxyImportSnellNoTLS,
			"sid":         proxyImportSnellNoTLS,
			"shortId":     proxyImportSnellNoTLS,
		},
		"anytls": {
			"keepalive": "mihomo's anytls outbound has no keepalive field",
			"pbk":       proxyImportNoRealityTransport("AnyTLS"),
			"publicKey": proxyImportNoRealityTransport("AnyTLS"),
			"sid":       proxyImportNoRealityTransport("AnyTLS"),
			"shortId":   proxyImportNoRealityTransport("AnyTLS"),
		},
		"hysteria": {
			"keepalive": "mihomo's hysteria outbound has no keepalive field",
		},
		"hysteria2": {
			"keepalive": "mihomo's hysteria2 outbound has no keepalive field",
			"pbk":       proxyImportNoRealityTransport("Hysteria2"),
			"publicKey": proxyImportNoRealityTransport("Hysteria2"),
			"sid":       proxyImportNoRealityTransport("Hysteria2"),
			"shortId":   proxyImportNoRealityTransport("Hysteria2"),
		},
		"tuic": {
			"pbk":       proxyImportNoRealityTransport("TUIC"),
			"publicKey": proxyImportNoRealityTransport("TUIC"),
			"sid":       proxyImportNoRealityTransport("TUIC"),
			"shortId":   proxyImportNoRealityTransport("TUIC"),
		},
		"http": {
			"pbk":       proxyImportNoRealityTransport("HTTP proxy"),
			"publicKey": proxyImportNoRealityTransport("HTTP proxy"),
			"sid":       proxyImportNoRealityTransport("HTTP proxy"),
			"shortId":   proxyImportNoRealityTransport("HTTP proxy"),
		},
		"mieru": {
			"peer":             proxyImportMieruNoTLS,
			"sni":              proxyImportMieruNoTLS,
			"alpn":             proxyImportMieruNoTLS,
			"hpkp":             proxyImportMieruNoTLS,
			"fingerprint":      proxyImportMieruNoTLS,
			"insecure":         proxyImportMieruNoTLS,
			"allowInsecure":    proxyImportMieruNoTLS,
			"allow_insecure":   proxyImportMieruNoTLS,
			"skip-cert-verify": proxyImportMieruNoTLS,
			"pbk":              proxyImportMieruNoTLS,
			"publicKey":        proxyImportMieruNoTLS,
			"sid":              proxyImportMieruNoTLS,
			"shortId":          proxyImportMieruNoTLS,
		},
		"wireguard": {
			"sni":  "mihomo's wireguard outbound has no TLS, so there is no server name to set",
			"peer": "mihomo's wireguard outbound has no TLS, so there is no server name to set",
		},
		"masque": {
			"presharedKey":   proxyImportMasqueNoWireGuardFields,
			"preSharedKey":   proxyImportMasqueNoWireGuardFields,
			"pre-shared-key": proxyImportMasqueNoWireGuardFields,
			"password":       proxyImportMasqueNoWireGuardFields,
			"keepalive":      proxyImportMasqueNoWireGuardFields,
			"reserved":       proxyImportMasqueNoWireGuardFields,
		},
		"ssh": {
			"keepalive": "mihomo's ssh outbound has no keepalive field",
			"path":      "mihomo's ssh outbound takes the key itself in private-key, not a path to read it from",
		},
		"ss": {
			"security": "mihomo's ss outbound has no TLS or security field",
			"alpn":     "mihomo's ss outbound has no TLS, so there is no ALPN to set",
		},
	}
}}

const proxyImportMuxNotHonoured = "mihomo's multiplexer (smux / sing-mux) is not the v2ray mux the exporter means, so the flag is not translated"

func proxyImportPluginMode(pluginName, raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(strings.ToLower(pluginName), "v2ray-plugin"):
		if mode == "" || mode == "ws" || mode == "websocket" {
			return "websocket"
		}
		return ""
	default:
		if mode == "http" || mode == "tls" {
			return mode
		}
		return ""
	}
}

func uncarriedProxyImportTransport(canonicalType, raw string) string {
	obfs := strings.ToLower(strings.TrimSpace(raw))
	carried := map[string][]string{
		"ss":     {"", "none", "http", "tls", "ws", "websocket", "wss", "httpupgrade"},
		"trojan": {"", "none", "ws", "websocket", "wss", "httpupgrade", "grpc"},
		"vmess":  {"", "none", "ws", "websocket", "wss", "httpupgrade", "grpc", "h2", "http"},
		"vless":  {"", "none", "ws", "websocket", "wss", "httpupgrade", "grpc", "h2", "http", "xhttp"},
	}
	known, judged := carried[canonicalType]
	if !judged {
		return ""
	}
	for _, value := range known {
		if obfs == value {
			return ""
		}
	}
	return fmt.Sprintf("mihomo's %s has no %q transport here, so the node is imported without it", canonicalType, obfs)
}

func unhonouredShadowsocksTLSKey(canonicalType, key string, query url.Values) string {
	if canonicalType != "ss" {
		return ""
	}
	switch key {
	case "tls", "sni", "peer", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify":
	default:
		return ""
	}
	obfs := strings.ToLower(query.Get("obfs"))
	websocket := query.Get("plugin") == "" && (obfs == "ws" || obfs == "websocket" || obfs == "wss" || obfs == "httpupgrade")
	if !websocket {
		return "ss carries TLS only through v2ray-plugin, which this link does not use"
	}
	if key == "sni" || key == "peer" {
		host := firstQueryValue(query, "obfsParam", "obfs-host", "host")
		if name := query.Get(key); host != "" && !strings.EqualFold(name, host) {
			return "v2ray-plugin uses its Host as the TLS server name, so this one is not used"
		}
		if sni := query.Get("sni"); key == "peer" && host == "" && sni != "" && !strings.EqualFold(sni, query.Get("peer")) {
			return "v2ray-plugin takes one server name, and sni is the one used"
		}
	}
	return ""
}

func unbuildableProxyImportPlugin(canonicalType, raw string) string {
	if raw == "" {
		return ""
	}
	switch canonicalType {
	case "ss", "trojan", "snell":
	default:
		return ""
	}
	name, values, err := parseShadowrocketPlugin(raw)
	if err != nil {
		return "this importer build could not read the plugin specification"
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "v2ray-plugin") {
		if proxyImportPluginMode(name, firstQueryValue(values, "mode", "obfs")) == "" {
			return "mihomo's v2ray-plugin carries websocket only, so the node is imported without a plugin"
		}
		return ""
	}
	if strings.Contains(lower, "obfs") {
		if canonicalType == "trojan" {
			if mode := strings.ToLower(firstQueryValue(values, "obfs", "mode")); mode == "websocket" || mode == "ws" {
				return ""
			}
			return "mihomo's trojan carries obfs over websocket only, so the node is imported without it"
		}
		if proxyImportPluginMode(name, firstQueryValue(values, "obfs", "mode")) == "" {
			return "mihomo's simple-obfs carries http or tls only, so the node is imported without a plugin"
		}
		return ""
	}
	return "mihomo has no " + name + " plugin, so the node is imported without one"
}

func validateProxyShareLinkQueryFields(link string, capability proxyImportCapability, tolerateUnmapped bool) ([]string, error) {
	if capability.CanonicalType == "ssr" {
		return validateSSRShareLinkFields(link, tolerateUnmapped)
	}
	if capability.CanonicalType == "trusttunnel" {
		parsed, err := url.Parse(strings.TrimSpace(link))
		if err == nil && parsed.Hostname() == "" {
			return nil, nil
		}
	}
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return nil, nil
	}
	switch capability.CanonicalType {
	case "ss", "http", "socks5":
		if unwrapped, ok := normalizeEncodedProxyAuthority(strings.TrimSpace(link)); ok {
			if reparsed, parseErr := url.Parse(unwrapped); parseErr == nil {
				parsed = reparsed
			}
		}
	}
	normalizeShadowrocketRawQuery(parsed)
	allowed, exists := proxyImportQueryFieldLedger.get()[capability.CanonicalType]
	if !exists {
		return nil, fmt.Errorf("clash: no query-field ledger for supported proxy type %q", capability.CanonicalType)
	}
	unhonoured := proxyImportUnhonouredFields.get()[capability.CanonicalType]
	var notHonoured []string
	if reason := unbuildableProxyImportPlugin(capability.CanonicalType, parsed.Query().Get("plugin")); reason != "" {
		notHonoured = append(notHonoured, capability.Scheme+".query.plugin: "+reason)
	}
	if reason := uncarriedProxyImportTransport(capability.CanonicalType, parsed.Query().Get("obfs")); reason != "" {
		notHonoured = append(notHonoured, capability.Scheme+".query.obfs: "+reason)
	}
	for key := range parsed.Query() {
		if reason, registered := unhonoured[key]; registered {
			notHonoured = append(notHonoured, capability.Scheme+".query."+key+": "+reason)
			continue
		}
		if reason := unhonouredShadowsocksTLSKey(capability.CanonicalType, key, parsed.Query()); reason != "" {
			notHonoured = append(notHonoured, capability.Scheme+".query."+key+": "+reason)
			continue
		}
		if _, ok := allowed[key]; ok {
			continue
		}
		if tolerateUnmapped {
			notHonoured = append(notHonoured, unmappedProxyImportFieldNotice(capability.Scheme+".query."+key))
			continue
		}
		return nil, unsupportedProxyImportField(
			capability.Scheme+".query."+key,
			"this importer build does not map that field",
		)
	}
	sort.Strings(notHonoured)
	return notHonoured, nil
}

func validateSSRShareLinkFields(link string, tolerateUnmapped bool) ([]string, error) {
	_, payload, ok := strings.Cut(strings.TrimSpace(link), "://")
	if !ok {
		return nil, nil
	}
	decoded, err := convert.TryDecodeBase64(payload)
	if err != nil {
		return nil, nil
	}
	_, rawQuery, ok := strings.Cut(string(decoded), "/?")
	if !ok {
		return nil, nil
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, nil
	}
	allowed := queryFieldSet("remarks", "group", "obfsparam", "protoparam")
	var notHonoured []string
	for key := range query {
		if _, ok := allowed[key]; ok {
			continue
		}
		if tolerateUnmapped {
			notHonoured = append(notHonoured, unmappedProxyImportFieldNotice("ssr.query."+key))
			continue
		}
		return nil, unsupportedProxyImportField(
			"ssr.query."+key,
			"the SSR outbound cannot represent that field",
		)
	}
	sort.Strings(notHonoured)
	return notHonoured, nil
}

func singletonProxy(proxy map[string]any, err error) ([]map[string]any, error) {
	if err != nil {
		return nil, err
	}
	return []map[string]any{proxy}, nil
}

var proxyImportPortHoppingTypes = &lazyValue[map[string]struct{}]{build: func() map[string]struct{} {
	return map[string]struct{}{"hysteria": {}, "hysteria2": {}}
}}

func normalizeEncodedAuthorityPortRange(link string) (string, string, bool) {
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link, "", false
	}
	head, rest := link[:separator+3], link[separator+3:]
	authority, tail := rest, ""
	if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
		authority, tail = rest[:cut], rest[cut:]
	}
	decoded, err := convert.TryDecodeBase64(authority)
	if err != nil || !bytes.Contains(decoded, []byte("@")) {
		return link, "", false
	}
	credentials, hostPort, ok := strings.Cut(string(decoded), "@")
	if !ok {
		return link, "", false
	}
	rewritten, spec := splitHostPortRange(hostPort)
	if spec == "" {
		return link, "", false
	}
	return head + base64.RawURLEncoding.EncodeToString([]byte(credentials+"@"+rewritten)) + tail, spec, true
}

func splitHostPortRange(hostPort string) (string, string) {
	if strings.Contains(hostPort, "]") {
		return hostPort, ""
	}
	colon := strings.LastIndex(hostPort, ":")
	if colon < 0 {
		return hostPort, ""
	}
	host, spec := hostPort[:colon], hostPort[colon+1:]
	cut := strings.IndexAny(spec, ",-")
	if cut <= 0 {
		return hostPort, ""
	}
	return host + ":" + spec[:cut], spec
}

func normalizeShareLinkPortRange(link string, supportsHopping bool) (string, string, bool) {
	separator := strings.Index(link, "://")
	if separator < 0 {
		return link, "", false
	}
	head, rest := link[:separator+3], link[separator+3:]
	authority, tail := rest, ""
	if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
		authority, tail = rest[:cut], rest[cut:]
	}
	userinfo := ""
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo, authority = authority[:at+1], authority[at+1:]
	}
	if strings.Contains(authority, "]") {
		return link, "", false
	}
	colon := strings.LastIndex(authority, ":")
	if colon < 0 {
		return link, "", false
	}
	host, spec := authority[:colon], authority[colon+1:]
	if !strings.ContainsAny(spec, ",-") {
		return link, "", false
	}
	first := spec
	if cut := strings.IndexAny(spec, ",-"); cut >= 0 {
		first = spec[:cut]
	}
	if first == "" {
		return link, "", false
	}
	path, query, fragment := "", "", ""
	if cut := strings.Index(tail, "#"); cut >= 0 {
		fragment, tail = tail[cut:], tail[:cut]
	}
	if cut := strings.Index(tail, "?"); cut >= 0 {
		path, query = tail[:cut], tail[cut+1:]
	} else {
		path = tail
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return link, "", false
	}
	if supportsHopping && firstQueryValue(values, "ports", "mport") == "" {
		values.Set("ports", spec)
	}
	rewritten := head + userinfo + host + ":" + first + path
	if encoded := values.Encode(); encoded != "" {
		rewritten += "?" + encoded
	}
	return rewritten + fragment, spec, true
}

func appendShareLinkQueryDefault(link, key, value string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return link
	}
	query := parsed.Query()
	if query.Get(key) != "" {
		return link
	}
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func normalizeProxyShareLinkDialect(link string, capability proxyImportCapability) (string, *url.URL, string, error) {
	var portRange string
	scheme := strings.ToLower(strings.TrimSpace(capability.Scheme))
	canonicalLink := normalizeProxyImportAlias(strings.TrimSpace(link), scheme, capability.CanonicalType)
	if scheme == "vless" {
		if normalized, ok := normalizeLegacyVlessLink(canonicalLink); ok {
			canonicalLink = normalized
		}
	}
	if scheme == "http" || scheme == "https" || scheme == "socks" || scheme == "socks5" || scheme == "socks5h" ||
		scheme == "ssocks" || scheme == "ssocks5" {
		if normalized, ok := normalizeEncodedProxyAuthority(canonicalLink); ok {
			canonicalLink = normalized
		}
	}
	if capability.CanonicalType == "mieru" {
		if normalized, ok := normalizeEncodedUserinfo(canonicalLink); ok {
			canonicalLink = normalized
		}
		canonicalLink = appendShareLinkQueryDefault(canonicalLink, "transport", "TCP")
	}
	if scheme == "ssocks" || scheme == "ssocks5" {
		canonicalLink = appendShareLinkQueryDefault(canonicalLink, "tls", "1")
	}
	if scheme == "ss" {
		if normalized, spec, ok := normalizeEncodedAuthorityPortRange(canonicalLink); ok {
			canonicalLink, portRange = normalized, spec
		}
	}
	if scheme == "ss" {
		if normalized, ok := normalizeEncodedProxyAuthority(canonicalLink); ok {
			canonicalLink = normalized
		}
	}
	_, supportsHopping := proxyImportPortHoppingTypes.get()[capability.CanonicalType]
	if normalized, spec, ok := normalizeShareLinkPortRange(canonicalLink, supportsHopping); ok {
		canonicalLink = normalized
		if !supportsHopping {
			portRange = spec
		}
	}
	parsed, err := url.Parse(canonicalLink)
	if err != nil || parsed.Hostname() == "" {
		return "", nil, "", fmt.Errorf("clash: malformed %s proxy URI", scheme)
	}
	normalizeShadowrocketRawQuery(parsed)
	query := parsed.Query()
	for _, key := range proxyImportUnsetPlaceholderKeys.get()[capability.CanonicalType] {
		if strings.EqualFold(query.Get(key), "none") {
			query.Del(key)
		}
	}
	if parsed.Fragment == "" {
		parsed.Fragment = firstQueryValue(query, "title", "remark", "remarks", "name")
	}
	setQueryAlias(query, "sni", "peer", "serverName", "tlsServerName")
	setQueryAlias(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify")

	switch capability.CanonicalType {
	case "vmess", "vless":
		if query.Get("security") == "" {
			if firstQueryValue(query, "pbk", "publicKey") != "" {
				query.Set("security", "reality")
			} else if queryBoolean(query, "tls") {
				query.Set("security", "tls")
			}
		}
		if capability.CanonicalType == "vless" && query.Get("flow") == "" && query.Get("xtls") == "2" {
			query.Set("flow", "xtls-rprx-vision")
		}
		setQueryAlias(query, "fp", "fingerprint")
		setQueryAlias(query, "pcs", "hpkp")
		setUsableQueryAlias(query, "pbk", realityPublicKeyOrNothing, "publicKey")
		setQueryAlias(query, "sid", "shortId")
	case "hysteria":
		setQueryAlias(query, "peer", "sni", "serverName", "tlsServerName")
	case "hysteria2":
		setQueryAlias(query, "up", "upmbps")
		setQueryAlias(query, "down", "downmbps")
		setQueryAlias(query, "obfs-password", "obfsParam")
		setUsableQueryAlias(query, "pinSHA256", hysteria2CertificatePin, "hpkp", "fingerprint")
	case "tuic":
		setQueryAlias(query, "congestion_control", "proto", "congestion-controller")
		setQueryAlias(query, "udp_relay_mode", "udp-relay-mode", "udp")
	case "trojan":
		setQueryAlias(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify")
		setQueryAlias(query, "type", "proto", "network")
		if query.Get("type") == "" && strings.EqualFold(query.Get("obfs"), "websocket") {
			query.Set("type", "ws")
		}
	case "anytls":
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			query.Set("insecure", "1")
		}
	case "mieru":
		if len(query["port"]) == 0 && parsed.Port() != "" {
			query.Add("port", parsed.Port())
			parsed.Host = net.JoinHostPort(parsed.Hostname(), "")
			parsed.Host = strings.TrimSuffix(parsed.Host, ":")
		}
		if len(query["protocol"]) == 0 {
			if protocol := firstQueryValue(query, "proto", "transport"); protocol != "" {
				query.Add("protocol", strings.ToUpper(protocol))
			}
		} else {
			for index, protocol := range query["protocol"] {
				query["protocol"][index] = strings.ToUpper(protocol)
			}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), parsed, portRange, nil
}

func normalizeEncodedUserinfo(link string) (string, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.User == nil {
		return link, false
	}
	if password, hasPassword := parsed.User.Password(); hasPassword && password != "" {
		return link, false
	}
	decoded, decodeErr := convert.TryDecodeBase64(parsed.User.Username())
	if decodeErr != nil {
		return link, false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" || password == "" {
		return link, false
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String(), true
}

func normalizeEncodedProxyAuthority(link string) (string, bool) {
	scheme, rest, found := strings.Cut(link, "://")
	if !found || scheme == "" {
		return link, false
	}
	tokenEnd := strings.IndexAny(rest, "?#")
	if tokenEnd < 0 {
		tokenEnd = len(rest)
	}
	token, outer := rest[:tokenEnd], rest[tokenEnd:]
	if token == "" || strings.ContainsAny(token, "@:") {
		return link, false
	}
	decodedBytes, err := convert.TryDecodeBase64(strings.TrimRight(token, "/"))
	if err != nil {
		return link, false
	}
	decoded := strings.TrimSpace(string(decodedBytes))
	var credentials, tail, host, port string
	endpointAt := func(start int) (string, string, string, bool) {
		end := start
		for end < len(decoded) && strings.IndexByte("/?#@", decoded[end]) < 0 {
			end++
		}
		if end < len(decoded) && decoded[end] == '@' {
			return "", "", "", false
		}
		h, p, err := net.SplitHostPort(decoded[start:end])
		if err != nil || h == "" {
			return "", "", "", false
		}
		first := p
		if cut := strings.IndexAny(p, "-,"); cut >= 0 {
			first = p[:cut]
			if strings.Trim(p, "0123456789-,") != "" {
				return "", "", "", false
			}
		}
		if number, err := strconv.Atoi(first); err != nil || number < 1 || number > 65535 {
			return "", "", "", false
		}
		return h, p, decoded[end:], true
	}
	split := false
	if strings.Contains(decoded, "@") {
		for at := strings.IndexByte(decoded, '@'); at >= 0; {
			if h, p, rest, ok := endpointAt(at + 1); ok {
				credentials, host, port, tail, split = decoded[:at], h, p, rest, true
				break
			}
			next := strings.IndexByte(decoded[at+1:], '@')
			if next < 0 {
				break
			}
			at += 1 + next
		}
	}
	if !split {
		head := decoded
		if hash := strings.IndexByte(decoded, '#'); hash >= 0 {
			head = decoded[:hash]
		}
		if strings.Contains(head, "@") {
			return link, false
		}
		if host, port, tail, split = endpointAt(0); !split {
			return link, false
		}
	}
	innerQuery, innerTitle := "", ""
	if hash := strings.Index(tail, "#"); hash >= 0 {
		innerTitle = tail[hash+1:]
		tail = tail[:hash]
	}
	if question := strings.Index(tail, "?"); question >= 0 {
		innerQuery = tail[question+1:]
	}
	rebuilt := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
	if credentials != "" {
		username, password, hasPassword := strings.Cut(credentials, ":")
		if hasPassword {
			rebuilt.User = url.UserPassword(username, password)
		} else {
			rebuilt.User = url.User(username)
		}
	}
	outerQuery, outerTitle := "", ""
	if hash := strings.Index(outer, "#"); hash >= 0 {
		outerTitle = outer[hash+1:]
		outer = outer[:hash]
	}
	outerQuery = strings.TrimPrefix(outer, "?")
	switch {
	case outerQuery != "" && innerQuery != "":
		rebuilt.RawQuery = outerQuery + "&" + innerQuery
	case outerQuery != "":
		rebuilt.RawQuery = outerQuery
	default:
		rebuilt.RawQuery = innerQuery
	}
	title := outerTitle
	if unescaped, err := url.PathUnescape(title); err == nil {
		title = unescaped
	}
	if title == "" {
		title = innerTitle
		if unescaped, err := url.PathUnescape(title); err == nil {
			title = unescaped
		}
	}
	rebuilt.Fragment = title
	return rebuilt.String(), true
}

func normalizeShadowrocketRawQuery(parsed *url.URL) {
	if parsed != nil && strings.Contains(parsed.RawQuery, ";") {
		parsed.RawQuery = strings.ReplaceAll(parsed.RawQuery, ";", "%3B")
	}
}

func parseLegacyVMessShareLink(link string) (map[string]any, string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || !strings.EqualFold(parsed.Scheme, "vmess") || parsed.Host == "" {
		return nil, "", false, nil
	}
	if decoded, decodeErr := convert.TryDecodeBase64(parsed.Host); decodeErr == nil {
		if trimmed := bytes.TrimSpace(decoded); len(trimmed) > 0 && trimmed[0] == '{' {
			return nil, "", false, nil
		}
	}
	cipher, uuid, hostPort, matched, splitErr := splitLegacyCredentialAuthority(parsed)
	if splitErr != nil {
		return nil, "", true, splitErr
	}
	if !matched {
		return nil, "", false, nil
	}
	if cipher == "" {
		cipher = "auto"
	}
	hostPort, droppedPorts := splitHostPortRange(hostPort)
	endpoint, err := url.Parse("vmess://" + url.User(uuid).String() + "@" + hostPort)
	if err != nil || endpoint.Hostname() == "" || endpoint.Port() == "" {
		return nil, "", true, fmt.Errorf("clash: legacy vmess authority has an invalid endpoint")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, "", true, fmt.Errorf("clash: legacy vmess authority has an invalid port")
	}
	query := parsed.Query()
	name := parsed.Fragment
	if name == "" {
		name = firstQueryValue(query, "remarks", "remark", "title")
	}
	if name == "" {
		name = endpoint.Hostname()
	}
	proxy := map[string]any{
		"name": name, "type": "vmess", "server": endpoint.Hostname(), "port": port,
		"uuid": uuid, "cipher": cipher, "alterId": 0, "udp": query.Get("udp") != "0",
	}
	if alterID := query.Get("alterId"); alterID != "" {
		value, parseErr := strconv.Atoi(alterID)
		if parseErr != nil {
			return nil, "", true, fmt.Errorf("clash: legacy vmess has an invalid alterId")
		}
		proxy["alterId"] = value
	}
	if tls := strings.ToLower(query.Get("tls")); tls == "1" || tls == "true" || tls == "tls" {
		proxy["tls"] = true
		if serverName := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); serverName != "" {
			proxy["servername"] = serverName
		}
	}
	applyTransportDialect(proxy, query)
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if fingerprint := firstQueryValue(query, "fp", "fingerprint"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
		proxy["fingerprint"] = pin
	}
	if publicKey := realityPublicKeyOrNothing(firstQueryValue(query, "pbk", "publicKey")); publicKey != "" {
		proxy["tls"] = true
		proxy["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   firstQueryValue(query, "sid", "shortId"),
		}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, droppedPorts, true, nil
}

func applyTransportDialect(proxy map[string]any, query url.Values) {
	obfs := strings.ToLower(query.Get("obfs"))
	if obfs == "" && query.Get("obfsParam") != "" {
		if standard := strings.ToLower(firstQueryValue(query, "type", "network")); standard == "" || standard == "ws" || standard == "shadowsocks" {
			obfs = "websocket"
		}
	}
	upgrade := obfs == "httpupgrade"
	if obfs == "wss" {
		proxy["tls"] = true
		nameKey := "servername"
		if anyString(proxy["type"]) == "trojan" {
			nameKey = "sni"
		}
		if _, named := proxy[nameKey]; !named {
			if serverName := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); serverName != "" {
				proxy[nameKey] = serverName
			}
		}
	}
	if obfs == "wss" || upgrade {
		obfs = "websocket"
	}
	defer func() {
		if upgrade && anyString(proxy["network"]) == "ws" {
			if opts, _ := proxy["ws-opts"].(map[string]any); opts != nil {
				opts["v2ray-http-upgrade"] = true
			}
		}
	}()
	switch obfs {
	case "websocket", "ws":
		if anyString(proxy["network"]) == "ws" {
			opts, _ := proxy["ws-opts"].(map[string]any)
			if opts == nil {
				opts = map[string]any{}
				proxy["ws-opts"] = opts
			}
			if path := query.Get("path"); path != "" {
				opts["path"] = path
			}
			if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
				headers, _ := opts["headers"].(map[string]any)
				if headers == nil {
					headers = map[string]any{}
					opts["headers"] = headers
				}
				for key := range headers {
					if strings.EqualFold(key, "Host") {
						delete(headers, key)
					}
				}
				headers["Host"] = host
			}
			break
		}
		proxy["network"] = "ws"
		clearOtherTransportOptions(proxy, "ws-opts")
		headers := map[string]any{}
		if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
			headers["Host"] = host
		}
		proxy["ws-opts"] = map[string]any{
			"path":    query.Get("path"),
			"headers": headers,
		}
	case "grpc":
		proxy["network"] = "grpc"
		clearOtherTransportOptions(proxy, "grpc-opts")
		if name := firstQueryValue(query, "serviceName", "grpc-service-name", "path"); name != "" {
			proxy["grpc-opts"] = map[string]any{"grpc-service-name": name}
		}
	case "xhttp":
		if anyString(proxy["type"]) != "vless" {
			return
		}
		proxy["network"] = "xhttp"
		clearOtherTransportOptions(proxy, "xhttp-opts")
		opts, _ := proxy["xhttp-opts"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		if path := query.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
			opts["host"] = host
		}
		if mode := strings.ToLower(query.Get("mode")); mode != "" {
			opts["mode"] = mode
		}
		proxy["xhttp-opts"] = opts
	case "h2", "http":
		kind := anyString(proxy["type"])
		if kind != "vmess" && kind != "vless" {
			return
		}
		host := firstQueryValue(query, "obfsParam", "obfs-host", "host")
		path := query.Get("path")
		if obfs == "h2" {
			proxy["network"] = "h2"
			clearOtherTransportOptions(proxy, "h2-opts")
			opts := map[string]any{}
			if path != "" {
				opts["path"] = path
			}
			if host != "" {
				opts["host"] = []any{host}
			}
			proxy["h2-opts"] = opts
			return
		}
		clearOtherTransportOptions(proxy, "http-opts")
		proxy["network"] = "http"
		opts := map[string]any{}
		if path != "" {
			opts["path"] = []any{path}
		}
		if host != "" {
			opts["headers"] = map[string]any{"Host": []any{host}}
		}
		proxy["http-opts"] = opts
	}
}

func clearOtherTransportOptions(proxy map[string]any, keep string) {
	for _, key := range []string{"ws-opts", "grpc-opts", "h2-opts", "http-opts", "xhttp-opts"} {
		if key != keep {
			delete(proxy, key)
		}
	}
}

func applyStandardWebsocketHost(proxy map[string]any, query url.Values) {
	if anyString(proxy["network"]) != "ws" {
		return
	}
	host := query.Get("host")
	if host == "" {
		return
	}
	opts, _ := proxy["ws-opts"].(map[string]any)
	if opts == nil {
		opts = map[string]any{}
		proxy["ws-opts"] = opts
	}
	headers, _ := opts["headers"].(map[string]any)
	if headers == nil {
		headers = map[string]any{}
		opts["headers"] = headers
	}
	for key := range headers {
		if strings.EqualFold(key, "Host") {
			return
		}
	}
	headers["Host"] = host
}

func applyProxyShareLinkDialect(proxy map[string]any, parsed *url.URL) error {
	query := parsed.Query()
	switch proxy["type"] {
	case "vmess", "vless":
		applyTransportDialect(proxy, query)
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			proxy["skip-cert-verify"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
			proxy["fingerprint"] = pin
		}
		if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
			if _, present := proxy["alpn"]; !present {
				proxy["alpn"] = alpn
			}
		}
		if profile := firstQueryValue(query, "fp", "fingerprint", "client-fingerprint"); profile != "" {
			if _, present := proxy["client-fingerprint"]; !present {
				proxy["client-fingerprint"] = profile
			}
		}
	case "tuic":
		if parsed.User != nil && parsed.User.Username() == "" {
			if token, set := parsed.User.Password(); set && token != "" {
				delete(proxy, "uuid")
				delete(proxy, "password")
				proxy["token"] = token
			}
		}
		if queryBoolean(query, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify") {
			proxy["skip-cert-verify"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pinSHA256", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
	case "trojan":
		applyTransportDialect(proxy, query)
		applyStandardWebsocketHost(proxy, query)
		if publicKey := realityPublicKeyOrNothing(firstQueryValue(query, "pbk", "publicKey")); publicKey != "" {
			proxy["reality-opts"] = map[string]any{
				"public-key": publicKey,
				"short-id":   firstQueryValue(query, "sid", "shortId"),
			}
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pcs")); pin != "" {
			proxy["fingerprint"] = pin
		}
		if err := applyShadowrocketTrojanPlugin(proxy, query.Get("plugin")); err != nil {
			return err
		}
		if strings.EqualFold(parsed.Query().Get("proto"), "shadowsocks") {
			if anyString(proxy["network"]) == "shadowsocks" {
				delete(proxy, "network")
			}
			if method, password, ok := strings.Cut(query.Get("protoParam"), ":"); ok && method != "" {
				proxy["ss-opts"] = map[string]any{"enabled": true, "method": method, "password": password}
			}
		}
	case "ss":
		if plugin := query.Get("plugin"); plugin != "" {
			name, values, err := parseShadowrocketPlugin(plugin)
			if err != nil {
				return err
			}
			allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path", "tls")
			if err := validateNestedQueryFields("ss.query.plugin", values, allowed); err != nil {
				return err
			}
			lowerName := strings.ToLower(name)
			switch {
			case strings.Contains(lowerName, "obfs"):
				mode := proxyImportPluginMode(name, firstQueryValue(values, "obfs", "mode"))
				if mode == "" {
					delete(proxy, "plugin")
					delete(proxy, "plugin-opts")
					break
				}
				proxy["plugin"] = "obfs"
				proxy["plugin-opts"] = map[string]any{
					"mode": mode,
					"host": firstQueryValue(values, "obfs-host", "host"),
				}
			case strings.Contains(lowerName, "v2ray-plugin"):
				{
					mode := proxyImportPluginMode(name, firstQueryValue(values, "mode", "obfs"))
					if mode == "" {
						delete(proxy, "plugin")
						delete(proxy, "plugin-opts")
						break
					}
					opts := map[string]any{
						"mode": mode,
						"host": firstQueryValue(values, "host", "obfs-host"),
					}
					if path := firstQueryValue(values, "path", "obfs-uri"); path != "" {
						opts["path"] = path
					}
					if flag, present := values["tls"]; present && (len(flag) == 0 || flag[0] == "" || queryBoolean(values, "tls")) {
						opts["tls"] = true
					}
					proxy["plugin"] = "v2ray-plugin"
					proxy["plugin-opts"] = opts
				}
			default:
				delete(proxy, "plugin")
				delete(proxy, "plugin-opts")
			}
		} else if obfs := strings.ToLower(query.Get("obfs")); obfs == "websocket" || obfs == "ws" || obfs == "wss" || obfs == "httpupgrade" {
			opts := map[string]any{"mode": "websocket"}
			host := firstQueryValue(query, "obfsParam", "obfs-host", "host")
			if host == "" {
				host = firstQueryValue(query, "sni", "peer")
			}
			if host != "" {
				opts["host"] = host
			}
			if path := query.Get("path"); path != "" {
				opts["path"] = path
			}
			if obfs == "wss" || queryBoolean(query, "tls") {
				opts["tls"] = true
			}
			if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
				opts["skip-cert-verify"] = true
			}
			if obfs == "httpupgrade" {
				opts["v2ray-http-upgrade"] = true
			}
			proxy["plugin"] = "v2ray-plugin"
			proxy["plugin-opts"] = opts
		} else if obfs == "http" || obfs == "tls" {
			proxy["plugin"] = "obfs"
			opts := map[string]any{"mode": obfs}
			if host := firstQueryValue(query, "obfsParam", "obfs-host", "host"); host != "" {
				opts["host"] = host
			}
			proxy["plugin-opts"] = opts
		}
	case "hysteria":
		if auth := query.Get("auth"); auth != "" {
			proxy["auth_str"] = auth
		} else if parsed.User != nil && parsed.User.Username() != "" {
			proxy["auth_str"] = parsed.User.Username()
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "pinSHA256", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
		if password := query.Get("obfsParam"); password != "" {
			if mode := strings.ToLower(query.Get("obfs")); mode == "" || mode == "xplus" {
				proxy["obfs"] = password
			}
		}
	case "hysteria2":
		if _, realm := proxy["realm-opts"]; !realm && parsed.User != nil {
			auth := parsed.User.Username()
			if password, set := parsed.User.Password(); set {
				auth += ":" + password
			}
			if auth != "" {
				proxy["password"] = auth
			}
		}
		if spec := firstQueryValue(query, "ports", "mport"); spec != "" {
			proxy["ports"] = spec
		}
		if hop := firstQueryValue(query, "hop-interval", "hopInterval"); hop != "" {
			proxy["hop-interval"] = hop
		}
	case "anytls":
		if alpn := splitListValues(query["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fingerprint := firstQueryValue(query, "fp"); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
	case "http":
		if parsed.User != nil {
			if password, set := parsed.User.Password(); set {
				proxy["username"] = parsed.User.Username()
				proxy["password"] = password
			}
		}
		if strings.EqualFold(parsed.Scheme, "https") {
			proxy["tls"] = true
		}
		if sni := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); sni != "" {
			proxy["sni"] = sni
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
		if strings.EqualFold(firstQueryValue(query, "security"), "tls") {
			proxy["tls"] = true
		}
	case "socks5":
		if parsed.User != nil {
			if password, set := parsed.User.Password(); set {
				proxy["username"] = parsed.User.Username()
				proxy["password"] = password
			}
		}
		if queryBoolean(query, "tls") || strings.EqualFold(firstQueryValue(query, "security"), "tls") {
			proxy["tls"] = true
		}
		if queryBoolean(query, "udp") {
			proxy["udp"] = true
		}
		if pin := certificatePinOrNothing(anyString(proxy["type"]), firstQueryValue(query, "hpkp", "fingerprint")); pin != "" {
			proxy["fingerprint"] = pin
		}
	case "mieru":
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return nil
}

func applyShadowrocketTrojanPlugin(proxy map[string]any, raw string) error {
	if raw == "" {
		return nil
	}
	name, values, err := parseShadowrocketPlugin(raw)
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(name), "obfs") {
		return nil
	}
	allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path")
	if err := validateNestedQueryFields("trojan.query.plugin", values, allowed); err != nil {
		return err
	}
	mode := strings.ToLower(firstQueryValue(values, "obfs", "mode"))
	if mode != "websocket" && mode != "ws" {
		return nil
	}
	proxy["network"] = "ws"
	proxy["ws-opts"] = map[string]any{
		"path": firstQueryValue(values, "obfs-uri", "path"),
		"headers": map[string]any{
			"Host": firstQueryValue(values, "obfs-host", "host"),
		},
	}
	return nil
}

func parseShadowrocketPlugin(raw string) (string, url.Values, error) {
	values, err := url.ParseQuery("pluginName=" + strings.ReplaceAll(raw, ";", "&"))
	if err != nil {
		return "", nil, fmt.Errorf("clash: malformed plugin parameter: %w", err)
	}
	name := values.Get("pluginName")
	if name == "" {
		return "", nil, fmt.Errorf("clash: plugin parameter has no name")
	}
	folded := make(url.Values, len(values))
	for key, value := range values {
		folded[strings.ToLower(key)] = value
	}
	return name, folded, nil
}

func validateNestedQueryFields(prefix string, values url.Values, allowed map[string]struct{}) error {
	return nil
}

var proxyImportUnsetPlaceholderKeys = &lazyValue[map[string][]string]{build: func() map[string][]string {
	return map[string][]string{
		"hysteria": {"protocol"},
		"tuic":     {"congestion_control", "congestion-controller"},
		"snell":    {"version", "v"},
	}
}}

func firstConfiguredQueryValue(query url.Values, keys ...string) string {
	if value := firstQueryValue(query, keys...); !strings.EqualFold(value, "none") {
		return value
	}
	return ""
}

func firstQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func setQueryAlias(query url.Values, canonical string, aliases ...string) {
	setUsableQueryAlias(query, canonical, nil, aliases...)
}

func setUsableQueryAlias(query url.Values, canonical string, usable func(string) string, aliases ...string) {
	if query.Get(canonical) != "" {
		return
	}
	value := firstQueryValue(query, aliases...)
	if usable != nil {
		value = usable(value)
	}
	if value != "" {
		query.Set(canonical, value)
	}
}

func queryBoolean(query url.Values, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(query.Get(key)))
		switch value {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func parseRequiredProxyURL(link, expectedType string) (*url.URL, int, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, 0, fmt.Errorf("clash: malformed %s proxy URI", expectedType)
	}
	normalizeShadowrocketRawQuery(parsed)
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("clash: invalid %s proxy port", expectedType)
	}
	return parsed, port, nil
}

func proxyName(parsed *url.URL) string {
	query := parsed.Query()
	if parsed.Fragment != "" {
		return parsed.Fragment
	}
	if name := firstQueryValue(query, "title", "remark", "remarks", "name", "profile"); name != "" {
		return name
	}
	if parsed.Port() != "" {
		return net.JoinHostPort(parsed.Hostname(), parsed.Port())
	}
	return parsed.Hostname()
}

func parseSnellShareLink(link string) (map[string]any, error) {
	if normalized, ok := normalizeEncodedProxyAuthority(link); ok {
		link = normalized
	}
	parsed, port, err := parseRequiredProxyURL(link, "snell")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	psk := parsed.User.Username()
	if password, ok := parsed.User.Password(); ok {
		psk = password
	}
	if decoded, decodeErr := convert.TryDecodeBase64(psk); decodeErr == nil {
		if _, password, ok := strings.Cut(string(decoded), ":"); ok {
			psk = password
		}
	}
	if psk == "" {
		psk = firstQueryValue(query, "psk", "password", "pbk")
	}
	if psk == "" {
		return nil, fmt.Errorf("clash: snell proxy is missing its PSK")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "snell", "server": parsed.Hostname(),
		"port": port, "psk": psk,
	}
	if version := firstConfiguredQueryValue(query, "version", "v"); version != "" {
		value, parseErr := strconv.Atoi(version)
		if parseErr != nil {
			return nil, fmt.Errorf("clash: invalid snell version %q", version)
		}
		proxy["version"] = value
	}
	if queryBoolean(query, "udp") {
		proxy["udp"] = true
	}
	if queryBoolean(query, "reuse") {
		proxy["reuse"] = true
	}
	for _, key := range []string{"mode", "user-key"} {
		if value := query.Get(key); value != "" {
			if version, _ := proxy["version"].(int); version != 6 {
				return nil, unsupportedProxyImportField("snell."+key, key+" is version 6's")
			}
			proxy[key] = value
		}
	}
	mode := firstQueryValue(query, "obfs", "obfs-mode")
	host := firstQueryValue(query, "obfsParam", "obfs-host", "peer", "sni")
	if plugin := query.Get("plugin"); plugin != "" {
		name, values, parseErr := parseShadowrocketPlugin(plugin)
		if parseErr != nil {
			return nil, parseErr
		}
		if !strings.Contains(strings.ToLower(name), "obfs") {
			return proxy, nil
		}
		allowed := queryFieldSet("pluginName", "obfs", "obfs-host", "obfs-uri", "mode", "host", "path")
		if parseErr := validateNestedQueryFields("snell.query.plugin", values, allowed); parseErr != nil {
			return nil, parseErr
		}
		mode = firstQueryValue(values, "obfs", "mode")
		host = firstQueryValue(values, "obfs-host", "host")
		if path := firstQueryValue(values, "obfs-uri", "path"); path != "" && path != "/" {
			return nil, unsupportedProxyImportField(
				"snell.query.plugin.obfs-uri",
				"the Core Snell simple-obfs transport cannot represent a custom URI",
			)
		}
	}
	if mode != "" {
		proxy["obfs-opts"] = map[string]any{
			"mode": mode,
			"host": host,
		}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseSSHShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "ssh")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	if value := query.Get("user"); value != "" {
		username = value
	}
	if value := query.Get("password"); value != "" {
		password = value
	}
	if username == "" {
		return nil, fmt.Errorf("clash: ssh proxy is missing its username")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "ssh", "server": parsed.Hostname(),
		"port": port, "username": username,
	}
	if password != "" {
		proxy["password"] = password
	}
	if privateKey := firstQueryValue(query, "private-key", "privateKey", "pk"); privateKey != "" {
		if !strings.Contains(privateKey, "PRIVATE KEY") {
			if decoded, err := convert.TryDecodeBase64(privateKey); err == nil && strings.Contains(string(decoded), "PRIVATE KEY") {
				privateKey = string(decoded)
			}
		}
		proxy["private-key"] = privateKey
	}
	if passphrase := firstQueryValue(query, "private-key-passphrase", "privateKeyPassphrase", "pp"); passphrase != "" {
		proxy["private-key-passphrase"] = passphrase
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseWireGuardShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "wireguard")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	privateKey := firstQueryValue(query, "privateKey", "private-key")
	if privateKey == "" && parsed.User != nil {
		privateKey = parsed.User.Username()
	}
	publicKey := firstQueryValue(query, "publicKey", "public-key", "publickey")
	addresses := query["ip"]
	if len(addresses) == 0 {
		addresses = query["address"]
	}
	ipv4, ipv6 := splitIPValues(addresses)
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("clash: wireguard proxy requires privateKey, publicKey and ip")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "wireguard", "server": parsed.Hostname(), "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if psk := firstQueryValue(query, "presharedKey", "preSharedKey", "pre-shared-key", "preshared-key", "presharedkey", "password"); psk != "" {
		proxy["pre-shared-key"] = psk
	}
	if value := query.Get("mtu"); value != "" {
		mtu, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("clash: invalid wireguard mtu %q", value)
		}
		proxy["mtu"] = mtu
	}
	if value := firstQueryValue(query, "keepalive", "persistent-keepalive"); value != "" {
		keepalive, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("clash: invalid wireguard keepalive %q", value)
		}
		proxy["persistent-keepalive"] = keepalive
	}
	if dns := splitListValues(query["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if reserved := firstQueryValue(query, "reserved"); reserved != "" {
		values, parseErr := parseReservedBytes(reserved)
		if parseErr != nil {
			return nil, parseErr
		}
		proxy["reserved"] = values
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func splitIPValues(values []string) (string, string) {
	var ipv4, ipv6 string
	for _, value := range splitListValues(values) {
		address := strings.TrimSpace(strings.SplitN(value, "/", 2)[0])
		if strings.Contains(address, ":") && ipv6 == "" {
			ipv6 = value
		} else if ipv4 == "" {
			ipv4 = value
		}
	}
	return ipv4, ipv6
}

func splitListValues(values []string) []string {
	var result []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				result = append(result, item)
			}
		}
	}
	return result
}

func parseReservedBytes(value string) ([]uint8, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '-' || r == ' ' })
	if len(parts) != 3 {
		return nil, fmt.Errorf("clash: wireguard reserved must contain three bytes")
	}
	result := make([]uint8, 3)
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("clash: invalid wireguard reserved byte %q", part)
		}
		result[index] = uint8(number)
	}
	return result, nil
}

func parseMasqueShareLink(link string) (map[string]any, error) {
	parsed, port, err := parseRequiredProxyURL(link, "masque")
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	privateKey := firstQueryValue(query, "privateKey", "private-key")
	publicKey := firstQueryValue(query, "publicKey", "public-key")
	ipv4, ipv6 := splitIPValues(query["ip"])
	if privateKey == "" || publicKey == "" || (ipv4 == "" && ipv6 == "") {
		return nil, fmt.Errorf("clash: masque proxy requires privateKey, publicKey and ip")
	}
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "masque", "server": parsed.Hostname(), "port": port,
		"private-key": privateKey, "public-key": publicKey, "udp": true,
	}
	if ipv4 != "" {
		proxy["ip"] = ipv4
	}
	if ipv6 != "" {
		proxy["ipv6"] = ipv6
	}
	if value := firstQueryValue(query, "peer", "sni", "serverName", "tlsServerName"); value != "" {
		proxy["sni"] = value
	}
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if value := query.Get("uri"); value != "" {
		proxy["uri"] = value
	}
	if value := query.Get("mtu"); value != "" {
		mtu, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return nil, fmt.Errorf("clash: invalid masque mtu %q", value)
		}
		proxy["mtu"] = mtu
	}
	if protocol := firstQueryValue(query, "proto", "network"); protocol == "h2" || protocol == "h3-l4proxy" {
		proxy["network"] = protocol
	}
	if dns := splitListValues(query["dns"]); len(dns) > 0 {
		proxy["dns"] = dns
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseTrustTunnelShareLink(link string) (map[string]any, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || !strings.EqualFold(parsed.Scheme, "tt") {
		return nil, fmt.Errorf("clash: malformed trusttunnel proxy URI")
	}
	if parsed.Hostname() != "" {
		return parseTrustTunnelAuthorityLink(parsed)
	}
	payload := parsed.RawQuery
	if payload == "" {
		return nil, fmt.Errorf("clash: trusttunnel deep link is missing its TLV payload")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("clash: decode trusttunnel deep link: %w", err)
	}
	return parseTrustTunnelTLV(decoded)
}

func parseTrustTunnelAuthorityLink(parsed *url.URL) (map[string]any, error) {
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("clash: invalid trusttunnel proxy port")
	}
	query := parsed.Query()
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	proxy := map[string]any{
		"name": proxyName(parsed), "type": "trusttunnel", "server": parsed.Hostname(), "port": port,
		"username": username, "password": password, "udp": true,
	}
	if sni := firstQueryValue(query, "peer", "sni", "hostname"); sni != "" {
		proxy["sni"] = sni
	}
	if queryBoolean(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		proxy["skip-cert-verify"] = true
	}
	if strings.EqualFold(firstQueryValue(query, "proto", "protocol"), "h3") {
		proxy["quic"] = true
		proxy["alpn"] = []string{"h3"}
	} else {
		proxy["alpn"] = []string{"h2"}
	}
	if queryBoolean(query, "tfo", "fastopen") {
		proxy["tfo"] = true
	}
	return proxy, nil
}

func parseTrustTunnelTLV(payload []byte) (map[string]any, error) {
	fields := make(map[uint64][][]byte)
	for len(payload) > 0 {
		tag, consumed, err := readTLSVarint(payload)
		if err != nil {
			return nil, fmt.Errorf("clash: trusttunnel TLV tag: %w", err)
		}
		payload = payload[consumed:]
		length, consumed, err := readTLSVarint(payload)
		if err != nil {
			return nil, fmt.Errorf("clash: trusttunnel TLV length: %w", err)
		}
		payload = payload[consumed:]
		if length > uint64(len(payload)) {
			return nil, fmt.Errorf("clash: truncated trusttunnel TLV value")
		}
		fields[tag] = append(fields[tag], append([]byte(nil), payload[:int(length)]...))
		payload = payload[int(length):]
	}
	knownTags := map[uint64]struct{}{
		0x00: {}, 0x01: {}, 0x02: {}, 0x03: {}, 0x05: {}, 0x06: {}, 0x07: {},
		0x08: {}, 0x09: {}, 0x0a: {}, 0x0b: {}, 0x0c: {}, 0x0d: {},
	}
	for tag := range fields {
		if _, ok := knownTags[tag]; !ok {
			return nil, unsupportedProxyImportField(
				fmt.Sprintf("trusttunnel.tlv.0x%x", tag),
				"unknown TrustTunnel TLV fields are not silently discarded",
			)
		}
	}
	if versionValues := fields[0x00]; len(versionValues) > 0 {
		version, _, err := readTLSVarint(versionValues[len(versionValues)-1])
		if err != nil || version > 1 {
			return nil, fmt.Errorf("clash: unsupported trusttunnel deep-link version")
		}
	}
	hostname := lastTLVString(fields[0x01])
	addresses := fields[0x02]
	username := lastTLVString(fields[0x05])
	password := lastTLVString(fields[0x06])
	if hostname == "" || len(addresses) == 0 || username == "" || password == "" {
		return nil, fmt.Errorf("clash: trusttunnel deep link is missing a required field")
	}
	if len(addresses) != 1 {
		return nil, unsupportedProxyImportField(
			"addresses", "this Core outbound can represent exactly one TrustTunnel endpoint",
		)
	}
	server, portText, err := net.SplitHostPort(string(addresses[0]))
	if err != nil {
		return nil, fmt.Errorf("clash: invalid trusttunnel address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("clash: invalid trusttunnel port")
	}
	if len(fields[0x08]) > 0 && !tlvBool(fields[0x07]) {
		return nil, unsupportedProxyImportField(
			"certificate", "this Core outbound cannot represent the deep link's pinned root chain",
		)
	}
	if tlvBool(fields[0x0a]) {
		return nil, unsupportedProxyImportField(
			"anti_dpi", "this Core outbound has no TrustTunnel anti-DPI option",
		)
	}
	if len(fields[0x0b]) > 0 {
		return nil, unsupportedProxyImportField(
			"client_random_prefix", "this Core outbound has no TLS client-random prefix option",
		)
	}
	if len(fields[0x0d]) > 0 {
		return nil, unsupportedProxyImportField(
			"dns_upstreams", "this Core outbound cannot attach per-node DNS upstreams",
		)
	}
	name := lastTLVString(fields[0x0c])
	if name == "" {
		name = hostname
	}
	proxy := map[string]any{
		"name": name, "type": "trusttunnel", "server": server, "port": port,
		"username": username, "password": password, "sni": hostname, "udp": true,
		"skip-cert-verify": tlvBool(fields[0x07]),
	}
	if customSNI := lastTLVString(fields[0x03]); customSNI != "" {
		proxy["sni"] = customSNI
	}
	protocol := uint64(1)
	if values := fields[0x09]; len(values) > 0 {
		parsed, consumed, parseErr := readTLSVarint(values[len(values)-1])
		if parseErr != nil || consumed != len(values[len(values)-1]) {
			return nil, fmt.Errorf("clash: invalid trusttunnel upstream_protocol")
		}
		protocol = parsed
	}
	if protocol != 1 && protocol != 2 {
		return nil, unsupportedProxyImportField(
			"upstream_protocol", fmt.Sprintf("unknown value %d", protocol),
		)
	}
	if protocol == 2 {
		proxy["quic"] = true
		proxy["alpn"] = []string{"h3"}
	} else {
		proxy["alpn"] = []string{"h2"}
	}
	return proxy, nil
}

func lastTLVString(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[len(values)-1])
}

func tlvBool(values [][]byte) bool {
	return len(values) > 0 && len(values[len(values)-1]) == 1 && values[len(values)-1][0] == 1
}

func readTLSVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("missing varint")
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, fmt.Errorf("truncated varint")
	}
	var value uint64
	switch size {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(binary.BigEndian.Uint16(data[:2]) & 0x3fff)
	case 4:
		value = uint64(binary.BigEndian.Uint32(data[:4]) & 0x3fffffff)
	case 8:
		value = binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff
	}
	return value, size, nil
}

func normalizeLegacyVlessPayload(payload []byte) []byte {
	text := string(payload)
	if !strings.Contains(text, "://") {
		if decoded, err := convert.TryDecodeBase64(strings.TrimSpace(text)); err == nil {
			text = string(decoded)
		}
	}
	lines := strings.Split(text, "\n")
	changed := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(strings.ToLower(trimmed), "vless://") {
			continue
		}
		normalized, ok := normalizeLegacyVlessLink(trimmed)
		if !ok {
			continue
		}
		lines[index] = normalized
		changed = true
	}
	if !changed {
		return []byte(text)
	}
	return []byte(strings.Join(lines, "\n"))
}

func splitLegacyCredentialAuthority(parsed *url.URL) (method, id, hostPort string, matched bool, err error) {
	var methodAndID string
	if decoded, decodeErr := convert.TryDecodeBase64(parsed.Host); decodeErr == nil {
		var ok bool
		methodAndID, hostPort, ok = strings.Cut(string(decoded), "@")
		if !ok {
			return "", "", "", true, fmt.Errorf("clash: legacy %s authority is missing its endpoint", parsed.Scheme)
		}
	} else if parsed.User != nil {
		password, hasPassword := parsed.User.Password()
		if !hasPassword {
			return "", "", "", false, nil
		}
		methodAndID, hostPort = parsed.User.Username()+":"+password, parsed.Host
	} else {
		return "", "", "", false, nil
	}
	if separator := strings.LastIndex(methodAndID, ":"); separator >= 0 {
		method, id = methodAndID[:separator], methodAndID[separator+1:]
	} else {
		method, id = "", methodAndID
	}
	if id == "" {
		return "", "", "", true, fmt.Errorf("clash: legacy %s authority is missing its UUID", parsed.Scheme)
	}
	return method, id, hostPort, true, nil
}

func vlessEncryptionIsConstructible(encryption string) bool {
	switch encryption {
	case "", "none":
		return true
	}
	return strings.HasPrefix(encryption, "mlkem768x25519plus.")
}

func normalizeLegacyVlessLink(link string) (string, bool) {
	parsed, err := url.Parse(link)
	if err != nil || !strings.EqualFold(parsed.Scheme, "vless") || parsed.Host == "" {
		return link, false
	}
	method, id, hostPort, matched, splitErr := splitLegacyCredentialAuthority(parsed)
	if !matched || splitErr != nil {
		return link, false
	}
	firstPortHostPort, portRange := splitHostPortRange(hostPort)
	authority, err := url.Parse("vless://" + url.User(id).String() + "@" + firstPortHostPort)
	if err != nil || authority.Hostname() == "" || authority.Port() == "" {
		return link, false
	}
	query := parsed.Query()
	if query.Get("encryption") == "" && method != "" && vlessEncryptionIsConstructible(method) {
		query.Set("encryption", method)
	}
	authority.RawQuery = query.Encode()
	authority.Fragment = parsed.Fragment
	rebuilt := authority.String()
	if portRange != "" {
		rebuilt = strings.Replace(rebuilt, firstPortHostPort, strings.TrimSuffix(firstPortHostPort[:strings.LastIndex(firstPortHostPort, ":")+1], "")+portRange, 1)
	}
	return rebuilt, true
}

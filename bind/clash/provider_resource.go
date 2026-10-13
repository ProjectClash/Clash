package clash

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/adapter"
	proxyprovider "github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/component/age"
	P "github.com/ProjectClash/Clash/constant/provider"
	rules "github.com/ProjectClash/Clash/rules"
	rulecommon "github.com/ProjectClash/Clash/rules/common"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"go.yaml.in/yaml/v3"
)

const maximumProviderResourceBytes = 16 * 1024 * 1024

var tunnelProcess atomic.Bool

func providerContentBytes() int {
	if tunnelProcess.Load() {
		return maximumProviderResourceBytes
	}
	return maximumPendingCompileBytes
}

func DecryptAgeForIOS(payload []byte, secretKey string) ([]byte, error) {
	out, err := recoverAppCall("DecryptAgeForIOS", func() ([]byte, error) { return decryptAgeForIOSUnguarded(payload, secretKey) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func decryptAgeForIOSUnguarded(payload []byte, secretKey string) ([]byte, error) {
	if len(payload) == 0 || len(payload) > providerContentBytes() {
		return nil, bridgeSafeError(fmt.Errorf("clash: encrypted provider size is invalid"))
	}
	if len(secretKey) == 0 || len(secretKey) > 64*1024 {
		return nil, bridgeSafeError(fmt.Errorf("clash: age secret key size is invalid"))
	}
	if !bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return nil, bridgeSafeError(fmt.Errorf("clash: provider is not age armored"))
	}
	if err := age.VeritySecretKeys(secretKey); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: invalid age secret key: %w", err))
	}
	plaintext, err := age.DecryptBytes(payload, secretKey)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: decrypt age provider: %w", err))
	}
	if len(plaintext) == 0 || len(plaintext) > providerContentBytes() {
		return nil, bridgeSafeError(fmt.Errorf("clash: decrypted provider size is invalid"))
	}
	return plaintext, nil
}

func ValidateProviderForIOS(kind, behavior, format string, payload []byte) error {
	if len(payload) == 0 || len(payload) > providerContentBytes() {
		return bridgeSafeError(fmt.Errorf("clash: provider payload size is invalid"))
	}
	if bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return bridgeSafeError(fmt.Errorf("clash: encrypted provider was not decrypted"))
	}
	switch kind {
	case "rule":
		parsedBehavior, err := P.ParseBehavior(behavior)
		if err != nil {
			return bridgeSafeError(fmt.Errorf("clash: provider behavior: %w", err))
		}
		parsedFormat, err := P.ParseRuleFormat(format)
		if err != nil {
			return bridgeSafeError(fmt.Errorf("clash: provider format: %w", err))
		}
		if parsedFormat == P.MrsRule {
			if err := validateMRSForIOS(payload, parsedBehavior); err != nil {
				return bridgeSafeError(fmt.Errorf("clash: validate rule provider: %w", err))
			}
			return nil
		}
		if parsedBehavior == P.Classical && parsedFormat != P.MrsRule {
			if err := validateClassicalProvider(payload, parsedFormat); err != nil {
				return bridgeSafeError(err)
			}
			return nil
		}
		if err := ruleprovider.ConvertToMrs(payload, parsedBehavior, parsedFormat, io.Discard); err != nil {
			if isUpstreamEmptyRuleError(err) {
				return nil
			}
			return bridgeSafeError(fmt.Errorf("clash: validate rule provider: %w", err))
		}
		return nil
	case "proxy":
		_, _, err := sanitizeProxyProviderPayloadForIOS(format, payload, true)
		return bridgeSafeError(err)
	default:
		return bridgeSafeError(fmt.Errorf("clash: unknown provider kind %q", kind))
	}
}

const upstreamEmptyRuleMessage = "empty rule"

func isUpstreamEmptyRuleError(err error) bool {
	return err != nil && err.Error() == upstreamEmptyRuleMessage
}

func ProviderEntryCountForIOS(kind, behavior, format string, payload []byte) (int, error) {
	if len(payload) == 0 || len(payload) > providerContentBytes() {
		return 0, bridgeSafeError(fmt.Errorf("clash: provider payload size is invalid"))
	}
	if bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return 0, bridgeSafeError(fmt.Errorf("clash: encrypted provider was not decrypted"))
	}
	switch kind {
	case "rule":
		parsedBehavior, err := P.ParseBehavior(behavior)
		if err != nil {
			return 0, bridgeSafeError(fmt.Errorf("clash: provider behavior: %w", err))
		}
		parsedFormat, err := P.ParseRuleFormat(format)
		if err != nil {
			return 0, bridgeSafeError(fmt.Errorf("clash: provider format: %w", err))
		}
		if parsedFormat == P.MrsRule {
			bridgedValue0, bridgedErr := inspectMRSForIOS(payload, parsedBehavior)
			return bridgedValue0, bridgeSafeError(bridgedErr)
		}
		if parsedBehavior == P.Classical {
			_, count, _, err := sanitizeClassicalProviderPayloadForIOS(payload, parsedFormat)
			if err != nil {
				return 0, bridgeSafeError(err)
			}
			return count, nil
		}
		var encoded bytes.Buffer
		if err := ruleprovider.ConvertToMrs(payload, parsedBehavior, parsedFormat, &encoded); err != nil {
			if isUpstreamEmptyRuleError(err) {
				return 0, nil
			}
			return 0, bridgeSafeError(fmt.Errorf("clash: count rule provider: %w", err))
		}
		bridgedValue0, bridgedErr := inspectMRSForIOS(encoded.Bytes(), parsedBehavior)
		return bridgedValue0, bridgeSafeError(bridgedErr)
	case "proxy":
		if err := ValidateProviderForIOS(kind, behavior, format, payload); err != nil {
			return 0, bridgeSafeError(err)
		}
		var document proxyprovider.ProxySchema
		if err := unmarshalProxySchema(payload, &document); err != nil {
			proxies, convertErr := convertProxyShareLinks(payload, true)
			if convertErr != nil {
				return 0, bridgeSafeError(fmt.Errorf("clash: count proxy provider: %w", convertErr))
			}
			document.Proxies = proxies
		}
		return len(document.Proxies), nil
	default:
		return 0, bridgeSafeError(fmt.Errorf("clash: unknown provider kind %q", kind))
	}
}

func parseAndCloseProviderOutbound(mapping map[string]any, parse func(map[string]any) (io.Closer, error)) error {
	outbound, err := parse(mapping)
	if err != nil {
		return err
	}
	if outbound == nil {
		return fmt.Errorf("parsed outbound is nil")
	}
	if err := outbound.Close(); err != nil {
		return fmt.Errorf("close parsed outbound: %w", err)
	}
	return nil
}

func validateClassicalProvider(payload []byte, format P.RuleFormat) error {
	_, _, _, err := sanitizeClassicalProviderPayloadForIOS(payload, format)
	return err
}

type providerNoopReason int

const (
	providerNoopMetadataUnavailable providerNoopReason = iota
	providerNoopRuleUnsupported
)

type providerMetadataNoop struct {
	kind   string
	index  int
	reason providerNoopReason
}

type providerEgressNoop struct {
	field string
	index int
}

var proxySchemaSequence = yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any(nil))}

func unmarshalProxySchema(payload []byte, document *proxyprovider.ProxySchema) error {
	return yaml.ClashUnmarshal(payload, document, proxySchemaSequence, nil)
}

func sanitizeProxyProviderPayloadForIOS(format string, payload []byte, parseNodes bool) ([]byte, []providerEgressNoop, error) {
	if format != "" && format != "yaml" {
		return nil, nil, fmt.Errorf("clash: proxy provider format %q is unsupported", format)
	}
	var document proxyprovider.ProxySchema
	if err := unmarshalProxySchema(payload, &document); err != nil {
		proxies, convertErr := convertProxyShareLinks(payload, true)
		if convertErr != nil {
			return nil, nil, fmt.Errorf("clash: parse proxy provider: %w; convert share links: %v", err, convertErr)
		}
		document.Proxies = proxies
	}
	if len(document.Proxies) == 0 {
		return nil, nil, fmt.Errorf("clash: proxy provider payload is empty")
	}
	stripped := make([]providerEgressNoop, 0, 2)
	for index, proxy := range document.Proxies {
		if !parseNodes {
			continue
		}
		name, _ := proxy["name"].(string)
		typeName, _ := proxy["type"].(string)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(typeName) == "" {
			return nil, nil, fmt.Errorf("clash: proxy provider item %d lacks name or type", index)
		}
		if err := parseAndCloseProviderOutbound(proxy, func(mapping map[string]any) (io.Closer, error) {
			return adapter.ParseProxy(mapping)
		}); err != nil {
			return nil, nil, fmt.Errorf("clash: proxy provider item %d: %w", index, err)
		}
	}
	if len(stripped) == 0 {
		return payload, nil, nil
	}
	sanitized, err := yaml.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("clash: encode proxy provider: %w", err)
	}
	return sanitized, stripped, nil
}

func stageClassicalProviderPayloadForApple(
	payload []byte, format P.RuleFormat, capability appleProcessMetadataCapability,
) ([]byte, []providerMetadataNoop, error) {
	entries, err := classicalProviderEntries(payload, format)
	if err != nil {
		return nil, nil, err
	}
	kept := make([]string, 0, len(entries))
	stripped := make([]providerMetadataNoop, 0)
	seenKinds := make(map[string]struct{})
	for index, entry := range entries {
		if kind := unavailableMetadataRuleKind(entry, capability); kind != "" {
			if _, seen := seenKinds[kind]; !seen {
				stripped = append(stripped, providerMetadataNoop{
					kind: kind, index: index, reason: providerNoopMetadataUnavailable,
				})
				seenKinds[kind] = struct{}{}
			}
			continue
		}
		kept = append(kept, entry)
	}
	if len(stripped) == 0 {
		return payload, nil, nil
	}
	sanitized, err := encodeClassicalProviderEntriesForIOS(kept, format)
	if err != nil {
		return nil, nil, err
	}
	return sanitized, stripped, nil
}

func sanitizeClassicalProviderPayloadForIOS(payload []byte, format P.RuleFormat) ([]byte, int, []providerMetadataNoop, error) {
	return sanitizeClassicalProviderPayloadForApple(payload, format, appleProcessMetadataCapability{})
}

func sanitizeClassicalProviderPayloadForApple(payload []byte, format P.RuleFormat, capability appleProcessMetadataCapability) ([]byte, int, []providerMetadataNoop, error) {
	entries, err := classicalProviderEntries(payload, format)
	if err != nil {
		return nil, 0, nil, err
	}
	kept := make([]string, 0, len(entries))
	stripped := make([]providerMetadataNoop, 0)
	seenKinds := make(map[string]struct{})
	for index, entry := range entries {
		if kind := unavailableMetadataRuleKind(entry, capability); kind != "" {
			if _, seen := seenKinds[kind]; !seen {
				stripped = append(stripped, providerMetadataNoop{kind: kind, index: index, reason: providerNoopMetadataUnavailable})
				seenKinds[kind] = struct{}{}
			}
			continue
		}
		if err := validateClassicalEntryForApple(entry, index, capability); err != nil {
			stripped = append(stripped, providerMetadataNoop{index: index, reason: providerNoopRuleUnsupported})
			continue
		}
		kept = append(kept, entry)
	}
	if len(stripped) == 0 {
		return payload, len(kept), nil, nil
	}
	sanitized, err := encodeClassicalProviderEntriesForIOS(kept, format)
	if err != nil {
		return nil, 0, nil, err
	}
	return sanitized, len(kept), stripped, nil
}

func encodeClassicalProviderEntriesForIOS(entries []string, format P.RuleFormat) ([]byte, error) {
	switch format {
	case P.YamlRule:
		encoded, err := yaml.Marshal(struct {
			Payload []string `yaml:"payload"`
		}{Payload: entries})
		if err != nil {
			return nil, fmt.Errorf("clash: encode classical provider: %w", err)
		}
		return encoded, nil
	case P.TextRule:
		if len(entries) == 0 {
			return []byte("# all Apple-unavailable metadata rules were stripped\n"), nil
		}
		return []byte(strings.Join(entries, "\n") + "\n"), nil
	default:
		return nil, fmt.Errorf("clash: classical provider does not support this format")
	}
}

func classicalPayloadHeadPresent(payload []byte) bool {
	if bytes.HasSuffix(payload, []byte("\n")) {
		return true
	}
	lastNewline := bytes.LastIndexByte(payload, '\n')
	if lastNewline < 0 {
		return false
	}
	var probe map[string]any
	if err := yaml.Unmarshal(payload[:lastNewline+1], &probe); err != nil {
		return false
	}
	_, hasPayload := probe["payload"]
	_, hasRules := probe["rules"]
	return hasPayload || hasRules
}

func classicalProviderEntries(payload []byte, format P.RuleFormat) ([]string, error) {
	var entries []string
	switch format {
	case P.YamlRule:
		var document struct {
			Payload []string `yaml:"payload"`
			Rules   []string `yaml:"rules"`
		}
		if err := yaml.Unmarshal(payload, &document); err != nil {
			return nil, fmt.Errorf("clash: parse classical provider: %w", err)
		}
		entries = append(append([]string(nil), document.Payload...), document.Rules...)
		if entries == nil && !classicalPayloadHeadPresent(payload) {
			return nil, fmt.Errorf(
				"clash: classical provider has no payload or rules field")
		}
	case P.TextRule:
		scanner := bufio.NewScanner(bytes.NewReader(payload))
		for scanner.Scan() {
			entry := strings.TrimSpace(scanner.Text())
			if entry != "" && !strings.HasPrefix(entry, "#") {
				entries = append(entries, entry)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("clash: scan classical provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("clash: classical provider does not support this format")
	}
	return entries, nil
}

func validateClassicalEntriesForIOS(entries []string) error {
	for index, entry := range entries {
		if err := validateClassicalEntryForIOS(entry, index); err != nil {
			return err
		}
	}
	return nil
}

func validateClassicalEntryForIOS(entry string, index int) error {
	return validateClassicalEntryForApple(entry, index, appleProcessMetadataCapability{})
}

func validateClassicalEntryForApple(entry string, index int, capability appleProcessMetadataCapability) error {
	tp, rulePayload, target, params := rulecommon.ParseRulePayload(entry, false)
	{
		kind := unavailableMetadataRuleKind(entry, capability)
		if kind == "" && isUnavailableMetadataRuleType(tp, capability) {
			kind = strings.ToUpper(strings.TrimSpace(tp))
		}
		if kind != "" {
			return fmt.Errorf("clash: classical provider item %d uses metadata rule %s, which this profile cannot resolve", index, kind)
		}
	}
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return fmt.Errorf("clash: classical provider item %d uses unsupported type %s", index, tp)
	}
	if _, err := rules.ParseRule(tp, rulePayload, target, params, nil); err != nil {
		return fmt.Errorf("clash: classical provider item %d: %w", index, err)
	}
	return nil
}

func InspectProviderForIOS(kind, behavior, format string, payload []byte) (int, error) {
	out, err := recoverAppCall("InspectProviderForIOS", func() (int, error) { return inspectProviderForIOSUnguarded(kind, behavior, format, payload) })
	if err != nil {
		return 0, bridgeSafeError(err)
	}
	return out, nil
}

func inspectProviderForIOSUnguarded(kind, behavior, format string, payload []byte) (int, error) {
	count, err := ProviderEntryCountForIOS(kind, behavior, format, payload)
	if err == nil {
		return count, nil
	}
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "clash: count rule provider: "):
		return 0, bridgeSafeError(fmt.Errorf("clash: validate rule provider: %s",
			strings.TrimPrefix(message, "clash: count rule provider: ")))
	case kind == "rule" && !strings.HasPrefix(message, "clash: "):
		return 0, bridgeSafeError(fmt.Errorf("clash: validate rule provider: %w", err))
	}
	return 0, bridgeSafeError(err)
}

func ConvertProxiesForIOS(payload []byte) (*StringBox, error) {
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return nil, bridgeSafeError(fmt.Errorf("clash: proxy payload size is invalid"))
	}
	proxies, err := convertProxyShareLinks(payload, true)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: convert proxies: %w", err))
	}
	if len(proxies) == 0 {
		return nil, bridgeSafeError(fmt.Errorf("clash: no proxies in payload"))
	}
	encoded, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode proxies: %w", err))
	}
	return WrapString(string(encoded)), nil
}

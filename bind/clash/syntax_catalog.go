package clash

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/sniffer"
)

func SyntaxCatalogForIOS(targetProfile string) (*StringBox, error) {
	out, err := recoverAppCall("SyntaxCatalogForIOS", func() (*StringBox, error) {
		return syntaxCatalogForIOSUnguarded(targetProfile)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type syntaxRuleKind struct {
	Name        string   `json:"name"`
	Payload     string   `json:"payload"`
	Options     []string `json:"options"`
	Logical     bool     `json:"logical"`
	MatchesHere bool     `json:"matchesHere"`
}

type syntaxGroupType struct {
	Name   string              `json:"name"`
	Fields []string            `json:"fields"`
	Enums  map[string][]string `json:"enums,omitempty"`
}

type syntaxPlatformKey struct {
	Path            string `json:"path"`
	Category        string `json:"category"`
	Value           string `json:"value,omitempty"`
	Effective       string `json:"effective"`
	Reason          string `json:"reason"`
	Alternative     string `json:"alternative,omitempty"`
	UpstreamDefault string `json:"upstreamDefault,omitempty"`
	DefaultOnly     bool   `json:"defaultOnly,omitempty"`
	Honoured        bool   `json:"honoured,omitempty"`
	RuleKind        string `json:"ruleKind,omitempty"`
}

type syntaxCatalog struct {
	SchemaVersion int               `json:"schemaVersion"`
	RuleKinds     []syntaxRuleKind  `json:"ruleTypes"`
	GroupTypes    []syntaxGroupType `json:"groupTypes"`
	RuleProvider  struct {
		Types     []string `json:"types"`
		Behaviors []string `json:"behaviors"`
		Formats   []string `json:"formats"`
		Fields    []string `json:"fields"`
	} `json:"ruleProvider"`
	DNSEnhancedModes    []string            `json:"dnsEnhancedModes"`
	SnifferProtocols    []string            `json:"snifferProtocols"`
	PlatformDecidedKeys []syntaxPlatformKey `json:"platformDecidedKeys"`
	Fields              []syntaxField       `json:"fields"`
}

const syntaxCatalogSchemaVersion = 3

var (
	ruleOptionsResolvable = []string{"no-resolve", "src"}
	ruleOptionsNone       = []string{}
)

var syntaxRuleKinds = []syntaxRuleKind{
	{Name: "DOMAIN", Payload: "domain"},
	{Name: "DOMAIN-SUFFIX", Payload: "domain"},
	{Name: "DOMAIN-KEYWORD", Payload: "domainKeyword"},
	{Name: "DOMAIN-REGEX", Payload: "domainRegex"},
	{Name: "DOMAIN-WILDCARD", Payload: "domainWildcard"},
	{Name: "GEOSITE", Payload: "geosite"},
	{Name: "GEOIP", Payload: "geoip", Options: ruleOptionsResolvable},
	{Name: "SRC-GEOIP", Payload: "geoip"},
	{Name: "IP-ASN", Payload: "asn", Options: ruleOptionsResolvable},
	{Name: "SRC-IP-ASN", Payload: "asn"},
	{Name: "IP-CIDR", Payload: "ipcidr", Options: ruleOptionsResolvable},
	{Name: "IP-CIDR6", Payload: "ipcidr", Options: ruleOptionsResolvable},
	{Name: "SRC-IP-CIDR", Payload: "ipcidr"},
	{Name: "IP-SUFFIX", Payload: "ipSuffix", Options: ruleOptionsResolvable},
	{Name: "SRC-IP-SUFFIX", Payload: "ipSuffix"},
	{Name: "SRC-PORT", Payload: "port"},
	{Name: "DST-PORT", Payload: "port"},
	{Name: "IN-PORT", Payload: "port"},
	{Name: "DSCP", Payload: "dscp"},
	{Name: "PROCESS-NAME", Payload: "process"},
	{Name: "PROCESS-PATH", Payload: "process"},
	{Name: "PROCESS-NAME-REGEX", Payload: "processRegex"},
	{Name: "PROCESS-PATH-REGEX", Payload: "processRegex"},
	{Name: "PROCESS-NAME-WILDCARD", Payload: "processWildcard"},
	{Name: "PROCESS-PATH-WILDCARD", Payload: "processWildcard"},
	{Name: "NETWORK", Payload: "network"},
	{Name: "PROTOCOL", Payload: "protocol"},
	{Name: "SUBNET", Payload: "subnet"},
	{Name: "CELLULAR-RADIO", Payload: "cellularRadio"},
	{Name: "UID", Payload: "uid"},
	{Name: "SOURCE-APP-SIGNING-ID", Payload: "codeSigningID"},
	{Name: "SOURCE-APP-TEAM-ID", Payload: "teamID"},
	{Name: "IN-TYPE", Payload: "inboundType"},
	{Name: "IN-USER", Payload: "inboundUser"},
	{Name: "IN-NAME", Payload: "inboundName"},
	{Name: "REMATCH-NAME", Payload: "inboundName"},
	{Name: "SUB-RULE", Payload: "subRule"},
	{Name: "AND", Payload: "logic", Logical: true},
	{Name: "OR", Payload: "logic", Logical: true},
	{Name: "NOT", Payload: "logic", Logical: true},
	{Name: "RULE-SET", Payload: "ruleSet", Options: ruleOptionsResolvable},
	{Name: "MATCH", Payload: "none"},
}

var syntaxGroupTypeOptions = []struct {
	name   string
	option any
}{
	{"select", outboundgroup.SelectorOption{}},
	{"url-test", outboundgroup.URLTestOption{}},
	{"fallback", outboundgroup.FallbackOption{}},
	{"load-balance", outboundgroup.LoadBalanceOption{}},
}

var syntaxLoadBalanceStrategies = []string{"consistent-hashing", "round-robin", "sticky-sessions"}

var syntaxLoadBalanceHashKeys = []string{"in-user"}

func groupTagFields(option any) []string {
	var fields []string
	t := reflect.TypeOf(option)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("group")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}

func buildSyntaxCatalog(targetProfile string) (syntaxCatalog, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return syntaxCatalog{}, err
	}
	policy := runtimePolicyFor(profile, true)
	catalog := syntaxCatalog{SchemaVersion: syntaxCatalogSchemaVersion}

	metadata := policy.processMetadata()
	for _, kind := range syntaxRuleKinds {
		if kind.Options == nil {
			kind.Options = ruleOptionsNone
		}
		kind.MatchesHere = metadata.resolves(kind.Name)
		catalog.RuleKinds = append(catalog.RuleKinds, kind)
	}

	common := groupTagFields(outboundgroup.GroupCommonOption{})
	for _, group := range syntaxGroupTypeOptions {
		entry := syntaxGroupType{Name: group.name, Fields: append(append([]string{}, common...), groupTagFields(group.option)...)}
		if group.name == "load-balance" {
			entry.Enums = map[string][]string{"strategy": syntaxLoadBalanceStrategies, "hash-key": syntaxLoadBalanceHashKeys}
		}
		catalog.GroupTypes = append(catalog.GroupTypes, entry)
	}

	catalog.RuleProvider.Types = []string{"http", "file", "inline"}
	catalog.RuleProvider.Behaviors = []string{"domain", "ipcidr", "classical"}
	catalog.RuleProvider.Formats = []string{"yaml", "text", "mrs"}
	catalog.RuleProvider.Fields = []string{"type", "behavior", "path", "url", "proxy", "format", "interval", "size-limit", "payload", "header", "path-in-bundle"}

	for _, mode := range []C.DNSMode{C.DNSNormal, C.DNSFakeIP, C.DNSMapping} {
		catalog.DNSEnhancedModes = append(catalog.DNSEnhancedModes, mode.String())
	}
	for _, protocol := range sniffer.List {
		catalog.SnifferProtocols = append(catalog.SnifferProtocols, protocol.String())
	}

	catalog.PlatformDecidedKeys = []syntaxPlatformKey{}
	for _, rule := range deviationRules {
		defaultOnly := rule.defaultOnly
		if !rule.active(policy) {
			if !rule.unwrittenUnconditional || !rule.activeFor(policy, false) {
				continue
			}
			defaultOnly = true
		}
		if rule.ruleScan && rule.ruleKind == "" {
			continue
		}
		catalog.PlatformDecidedKeys = append(catalog.PlatformDecidedKeys, syntaxPlatformKey{
			Path:            rule.field,
			Category:        rule.category,
			Value:           rule.forcedValue,
			Effective:       rule.effective,
			Reason:          rule.reason,
			Alternative:     rule.alternative,
			UpstreamDefault: rule.upstreamDefault,
			DefaultOnly:     defaultOnly,
			Honoured:        rule.honouredBy != "",
			RuleKind:        rule.ruleKind,
		})
	}
	catalog.Fields = fieldList()
	decidePlatformFields(catalog.Fields, policy)
	markUnavailableValues(catalog.Fields, policy)
	return catalog, nil
}

type syntaxPlatformDecision struct {
	When        string   `json:"when"`
	Condition   string   `json:"condition,omitempty"`
	Value       string   `json:"value,omitempty"`
	Replaces    []string `json:"replaces,omitempty"`
	Unwritten   string   `json:"unwritten,omitempty"`
	Category    string   `json:"category"`
	Effective   string   `json:"effective"`
	Reason      string   `json:"reason"`
	Alternative string   `json:"alternative,omitempty"`
}

type walledValue struct {
	value       string
	in          func(path string) bool
	reason      string
	alternative string
}

func platformWalledValues(policy appleRuntimePolicy) []walledValue {
	walled := []walledValue{{
		value: "faketcp",
		in: func(path string) bool {
			return path == "proxies[hysteria].protocol" || path == "proxies[hysteria].obfs-protocol"
		},
		reason: "faketcp is built only for Linux: on this platform every connection through the node fails; " +
			"udp reaches the server only if it serves hysteria over UDP too",
	}}
	for _, listener := range []struct{ value, port string }{{"tproxy", "tproxy-port"}, {"redir", "redir-port"}} {
		walled = append(walled, walledValue{
			value: listener.value,
			in: func(path string) bool {
				return strings.HasPrefix(path, "listeners[") && strings.HasSuffix(path, "].type")
			},
			reason: deviationReason(listener.port),
		})
	}
	if easyTierWalledProfile(policy) {
		walled = append(walled, walledValue{
			value: "easytier",
			in: func(path string) bool {
				return strings.HasPrefix(path, "proxies[") && strings.HasSuffix(path, "].type")
			},
			reason: "EasyTier is not built into the iPhone, iPad and Apple TV cores: the node stays as a placeholder that refuses every connection",
		})
	}
	return walled
}

func deviationReason(field string) string {
	for i := range deviationRules {
		if deviationRules[i].field == field {
			return deviationRules[i].reason
		}
	}
	return ""
}

func markUnavailableValues(fields []syntaxField, policy appleRuntimePolicy) {
	walled := platformWalledValues(policy)
	for i := range fields {
		for _, value := range walled {
			if value.in(fields[i].Path) && slices.Contains(fields[i].Values, value.value) {
				fields[i].UnavailableValues = append(fields[i].UnavailableValues, syntaxUnavailableValue{
					Value: value.value, Reason: value.reason, Alternative: value.alternative,
				})
			}
		}
	}
}

func decidePlatformFields(fields []syntaxField, policy appleRuntimePolicy) {
	byField := make(map[string]*deviationRule, len(deviationRules))
	for i := range deviationRules {
		if rule := &deviationRules[i]; !rule.ruleScan {
			byField[rule.field] = rule
		}
	}
	for i := range fields {
		rule := byField[fields[i].Path]
		if rule == nil || (rule.applies != nil && !rule.applies(policy)) || rule.honouredBy != "" {
			continue
		}
		decision := &syntaxPlatformDecision{When: "always", Value: rule.forcedValue, Replaces: rule.forcedFrom,
			Category: rule.category, Effective: rule.effective, Reason: rule.reason, Alternative: rule.alternative}
		switch {
		case rule.defaultOnly:
			decision.When = "default"
		case rule.condition != "":
			decision.When, decision.Condition = "conditional", rule.condition
		}
		if rule.unwrittenUnconditional {
			decision.Unwritten = rule.forcedValue
		}
		fields[i].PlatformDecision = decision
	}
}

func syntaxCatalogForIOSUnguarded(targetProfile string) (*StringBox, error) {
	catalog, err := buildSyntaxCatalog(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

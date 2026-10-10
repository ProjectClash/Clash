package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/common/yaml"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	RC "github.com/ProjectClash/Clash/rules/common"
	"github.com/ProjectClash/Clash/rules/logic"
)

func ValidateItemForIOS(kind, item, context string) (*StringBox, error) {
	out, err := recoverAppCall("ValidateItemForIOS", func() (*StringBox, error) {
		return validateItemForIOSUnguarded(kind, item, context)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type validateItemContext struct {
	Proxies        []string `json:"proxies"`
	Groups         []string `json:"groups"`
	ProxyProviders []string `json:"proxyProviders"`
	RuleProviders  []string `json:"ruleProviders"`
	SubRules       []string `json:"subRules"`
	Section        string   `json:"section"`
	Index          int      `json:"index"`
}

type validateItemResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func validateItemForIOSUnguarded(kind, item, context string) (*StringBox, error) {
	var names validateItemContext
	if strings.TrimSpace(context) != "" {
		if err := json.Unmarshal([]byte(context), &names); err != nil {
			return nil, fmt.Errorf("clash: validate item context: %w", err)
		}
	}
	if names.Section == "" {
		names.Section = "rules"
	}
	var verdict error
	switch kind {
	case "rule":
		var line string
		if err := json.Unmarshal([]byte(item), &line); err != nil {
			return nil, fmt.Errorf("clash: a rule is a JSON string: %w", err)
		}
		verdict = validateRuleItem(line, names)
	case "proxy", "proxyGroup":
		var mapping map[string]any
		if err := yaml.Unmarshal([]byte(item), &mapping); err != nil || mapping == nil {
			return nil, fmt.Errorf("clash: a %s is a JSON object", kind)
		}
		if kind == "proxy" {
			verdict = validateProxyItem(mapping, names)
		} else {
			verdict = validateGroupItem(mapping, names)
		}
	default:
		return nil, fmt.Errorf("clash: unknown kind %q", kind)
	}
	result := validateItemResult{OK: verdict == nil}
	if verdict != nil {
		result.Message = bridgeSafeString(verdict.Error())
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return WrapString(string(encoded)), nil
}

func builtinProxies() map[string]C.Proxy {
	return map[string]C.Proxy{
		"DIRECT":      adapter.NewProxy(outbound.NewDirect()),
		"REJECT":      adapter.NewProxy(outbound.NewReject()),
		"REJECT-DROP": adapter.NewProxy(outbound.NewRejectDrop()),
		"COMPATIBLE":  adapter.NewProxy(outbound.NewCompatible()),
		"PASS":        adapter.NewProxy(outbound.NewPass()),
		"PASS-RULE":   adapter.NewProxy(outbound.NewPassRule()),
	}
}

func validateRuleItem(line string, names validateItemContext) error {
	format, idx := names.Section, names.Index
	tp, payload, target, params := RC.ParseRulePayload(line, true)
	if target == "" {
		return fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
	}
	policies := map[string]bool{"GLOBAL": true}
	for name := range builtinProxies() {
		policies[name] = true
	}
	for _, name := range append(slices.Clone(names.Proxies), names.Groups...) {
		policies[name] = true
	}
	subRules := map[string][]C.Rule{}
	for _, name := range names.SubRules {
		subRules[name] = nil
	}
	if !policies[target] {
		if tp != "SUB-RULE" {
			return fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
		} else if _, ok := subRules[target]; !ok {
			return fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
		}
	}
	parsed, err := parseRuleWithoutGeodata(tp, payload, target, params, subRules)
	if err != nil {
		return fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, err.Error())
	}
	ruleProviders := map[string]bool{}
	for _, name := range names.RuleProviders {
		ruleProviders[name] = true
	}
	for _, name := range parsed.ProviderNames() {
		if !ruleProviders[name] {
			return fmt.Errorf("%s[%d] [%s] error: rule set [%s] not found", format, idx, line, name)
		}
	}
	return nil
}

func parseRuleWithoutGeodata(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
	if tp != "MATCH" && payload == "" {
		return nil, fmt.Errorf("missing subsequent parameters: %s", tp)
	}
	switch tp {
	case "GEOSITE", "GEOIP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN":
		return RC.NewMatch(target), nil
	case "SUB-RULE":
		return logic.NewSubRule(payload, target, subRules, parseRuleWithoutGeodata)
	case "AND":
		return logic.NewAND(payload, target, parseRuleWithoutGeodata)
	case "OR":
		return logic.NewOR(payload, target, parseRuleWithoutGeodata)
	case "NOT":
		return logic.NewNOT(payload, target, parseRuleWithoutGeodata)
	}
	return R.ParseRule(tp, payload, target, params, subRules)
}

func validateProxyItem(mapping map[string]any, names validateItemContext) error {
	folded := make(map[string]any, len(mapping))
	for key, value := range mapping {
		lowered := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
		if _, exact := mapping[lowered]; exact && lowered != key {
			continue
		}
		folded[lowered] = value
	}
	if err := validateProxyImportRequiredFields(folded); err != nil {
		return err
	}
	outbound, err := adapter.ParseProxy(mapping)
	if err != nil {
		return err
	}
	name := outbound.Name()
	dialer := outbound.ProxyInfo().DialerProxy
	if err := outbound.Close(); err != nil {
		return err
	}
	if _, builtin := builtinProxies()[name]; builtin || slices.Contains(names.Proxies, name) {
		return fmt.Errorf("proxy %s is the duplicate name", name)
	}
	if slices.Contains(names.Groups, name) {
		return fmt.Errorf("proxy group %s: the duplicate name", name)
	}
	if dialer != "" {
		if _, builtin := builtinProxies()[dialer]; !builtin && dialer != "GLOBAL" &&
			!slices.Contains(names.Proxies, dialer) && !slices.Contains(names.Groups, dialer) {
			return fmt.Errorf("proxy [%s] dialer-proxy [%s] not found", name, dialer)
		}
	}
	return nil
}

func validateGroupItem(mapping map[string]any, names validateItemContext) (verdict error) {
	proxies := builtinProxies()
	for _, name := range names.Proxies {
		proxies[name] = adapter.NewProxy(outbound.NewDirect())
	}
	providers := map[string]P.ProxyProvider{}
	for _, name := range names.Groups {
		group, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: name, Type: "select"},
			outboundgroup.SelectorOption{}, proxies["COMPATIBLE"], nil)
		if err != nil {
			return err
		}
		proxies[name] = adapter.NewProxy(group)
		providers[name] = standInProxyProvider{name: name, vehicle: P.Compatible}
	}
	for _, name := range names.ProxyProviders {
		providers[name] = standInProxyProvider{name: name, vehicle: P.HTTP}
	}
	allProxies := slices.Sorted(slices.Values(names.Proxies))
	allProviders := slices.Sorted(slices.Values(names.ProxyProviders))
	defer func() {
		for _, registered := range providers {
			if compatible, ok := registered.(*provider.CompatibleProvider); ok {
				_ = compatible.Close()
			}
		}
		if recovered := recover(); recovered != nil {
			text := fmt.Sprint(recovered)
			if !strings.HasPrefix(text, "regexp2: Compile(") {
				panic(recovered)
			}
			verdict = errors.New(text)
		}
	}()
	group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providers, allProxies, allProviders)
	if err != nil {
		return err
	}
	if _, exist := proxies[group.Name()]; exist {
		return fmt.Errorf("proxy group %s: the duplicate name", group.Name())
	}
	return nil
}

type standInProxyProvider struct {
	name    string
	vehicle P.VehicleType
}

func (p standInProxyProvider) Name() string               { return p.name }
func (p standInProxyProvider) VehicleType() P.VehicleType { return p.vehicle }
func (p standInProxyProvider) Type() P.ProviderType       { return P.Proxy }
func (p standInProxyProvider) Initial() error             { return nil }
func (p standInProxyProvider) Update() error              { return nil }
func (p standInProxyProvider) Proxies() []C.Proxy         { return nil }
func (p standInProxyProvider) Count() int                 { return 0 }
func (p standInProxyProvider) Touch()                     {}
func (p standInProxyProvider) HealthCheck()               {}
func (p standInProxyProvider) Version() uint32            { return 0 }
func (p standInProxyProvider) HealthCheckURL() string     { return "" }
func (p standInProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}

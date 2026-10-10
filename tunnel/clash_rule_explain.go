package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
)


type RuleExplainInput struct {
	Host    string
	DstIP   netip.Addr
	DstPort uint16
	Network C.NetWork
	SrcIP   netip.Addr
	SrcPort uint16
	Process          string
	ProcessAvailable bool
	Resolve bool
}

type ExplainedRule struct {
	Index   int
	Type    string
	Payload string
	SubRules string
	Through *ExplainedRule
}

type RuleExplanation struct {
	Mode string
	Host       string
	FakeIP     bool
	ResolvedIP string
	HostsIP string
	Decided bool
	Missing []string
	ProcessUnavailable bool
	Rule  *ExplainedRule
	Proxy string
	Chain       []string
	Conditional bool
	Dropped bool
	Error   string
}

func ExplainRule(input RuleExplainInput) RuleExplanation {
	version := loadVersion()
	metadata := &C.Metadata{
		NetWork: input.Network,
		Type:    C.TUN,
		Host:    strings.TrimSuffix(input.Host, "."),
		DstIP:   input.DstIP,
		DstPort: input.DstPort,
		SrcIP:   input.SrcIP,
		SrcPort: input.SrcPort,
	}
	explanation := RuleExplanation{Mode: version.mode.String()}
	if err := preHandleMetadata(metadata); err != nil {
		explanation.Error = err.Error()
		if errors.Is(err, resolver.ErrIPVersion) {
			explanation.Host = metadata.Host
			explanation.Decided = true
			explanation.Dropped = true
			return explanation
		}
	}
	explanation.FakeIP = metadata.DNSMode == C.DNSFakeIP
	explanation.Host = metadata.Host

	missing := map[string]bool{}
	flowResolved := false
	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = ipStackHostAddress(node)
		flowResolved = true
		if metadata.DstIP.IsValid() {
			explanation.HostsIP = metadata.DstIP.String()
		}
	}
	if input.ProcessAvailable && input.Process != "" {
		metadata.Process = filepath.Base(input.Process)
		if strings.Contains(input.Process, "/") {
			metadata.ProcessPath = input.Process
		}
	}
	explanation.ProcessUnavailable = !input.ProcessAvailable && input.Process != ""
	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if flowResolved || metadata.Host == "" || metadata.Resolved() {
				return
			}
			flowResolved = true
			if !input.Resolve {
				missing["ip"] = true
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
			defer cancel()
			if ip, err := resolver.ResolveIP(ctx, metadata.Host); err == nil {
				metadata.DstIP = ip
				explanation.ResolvedIP = ip.String()
			} else {
				missing["ip"] = true
			}
		},
		FindProcess: func() {
			if input.ProcessAvailable && input.Process == "" {
				missing["process"] = true
			}
		},
		CheckPassRule: func(adapterName string) bool {
			adapter, ok := version.proxies[adapterName]
			if !ok {
				return false
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
		RuleProviders: version.ruleProviders,
	}

	var proxy C.Proxy
	switch version.mode {
	case Direct:
		proxy = version.proxies["DIRECT"]
	case Global:
		proxy = version.proxies["GLOBAL"]
	default:
		var rule *ExplainedRule
		proxy, rule = explainMatch(metadata, helper, version)
		explanation.Rule = rule
	}
	if proxy == nil {
		explanation.Error = "the outbound the flow would take is not loaded"
	} else {
		explanation.Proxy = proxy.Name()
		for a := proxy; a != nil; a = a.Unwrap(metadata, false) {
			explanation.Chain = append(explanation.Chain, a.Name())
			switch a.Type() {
			case C.URLTest, C.Fallback, C.LoadBalance:
				explanation.Conditional = true
			}
		}
	}
	for name := range missing {
		explanation.Missing = append(explanation.Missing, name)
	}
	slices.Sort(explanation.Missing)
	explanation.Decided = len(explanation.Missing) == 0
	return explanation
}

func explainMatch(metadata *C.Metadata, helper C.RuleMatchHelper, version *runtimeVersion) (C.Proxy, *ExplainedRule) {
	var rematchChain []string
	for {
		var rematchProxy C.Proxy
		var rematchRule *ExplainedRule
		rules := getRules(metadata, version)
		subRules := ""
		if _, ok := version.subRules[metadata.SpecialRules]; ok {
			subRules = metadata.SpecialRules
		}
	GetRules:
		for index, rule := range rules {
			before := *metadata
			matched, ada := rule.Match(metadata, helper)
			if !matched {
				continue
			}
			adapter, ok := version.proxies[ada]
			if !ok || adapter == nil {
				continue
			}
			explained := &ExplainedRule{Index: index, Type: rule.RuleType().String(), Payload: rule.Payload(), SubRules: subRules}
			if rule.RuleType() == C.SubRules {
				explained = nameInnerRule(explained, rule, before, *metadata, helper, version, ada)
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.Pass {
					continue GetRules
				}
				if a.Type() == C.Rematch {
					rematchProxy, rematchRule = a, explained
					break GetRules
				}
			}
			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				continue
			}
			return adapter, explained
		}
		if rematchProxy != nil {
			if slices.Contains(rematchChain, rematchProxy.Name()) {
				return rematchProxy, rematchRule
			}
			rematchChain = append(rematchChain, rematchProxy.Name())
			if conn, err := rematchProxy.DialContext(context.Background(), metadata); err != nil {
				return rematchProxy, rematchRule
			} else if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		return version.proxies["DIRECT"], nil
	}
}

func nameInnerRule(line *ExplainedRule, rule C.Rule, before, after C.Metadata, helper C.RuleMatchHelper, version *runtimeVersion, adapter string) *ExplainedRule {
	replay := before
	replayHelper := helper
	replayHelper.ResolveIP = func() {
		if !replay.DstIP.IsValid() && after.DstIP.IsValid() {
			replay.DstIP = after.DstIP
		}
	}
	replayHelper.FindProcess = nil
	if helper.FindProcess != nil {
		replayHelper.FindProcess = func() {}
	}
	inner, innerAdapter := explainSubRules(&replay, replayHelper, rule.Adapter(), version.subRules, 0)
	if inner == nil || innerAdapter != adapter {
		return line
	}
	last := inner
	for last.Through != nil {
		last = last.Through
	}
	last.Through = line
	return inner
}

func explainSubRules(metadata *C.Metadata, helper C.RuleMatchHelper, name string, subRules map[string][]C.Rule, depth int) (*ExplainedRule, string) {
	if depth > 32 {
		return nil, ""
	}
	for index, rule := range subRules[name] {
		matched, adapter := rule.Match(metadata, helper)
		if !matched {
			continue
		}
		explained := &ExplainedRule{Index: index, Type: rule.RuleType().String(), Payload: rule.Payload(), SubRules: name}
		if rule.RuleType() == C.SubRules {
			inner, innerAdapter := explainSubRules(metadata, helper, rule.Adapter(), subRules, depth+1)
			if inner == nil {
				return nil, ""
			}
			last := inner
			for last.Through != nil {
				last = last.Through
			}
			last.Through = explained
			explained, adapter = inner, innerAdapter
		}
		if adapter == "PASS-RULE" || (helper.CheckPassRule != nil && helper.CheckPassRule(adapter)) {
			continue
		}
		return explained, adapter
	}
	return nil, ""
}

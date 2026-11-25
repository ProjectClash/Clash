package tunnel

import (
	"sync/atomic"
	"weak"

	C "github.com/ProjectClash/Clash/constant"
)


type sniffedHostConnector interface {
	ClashConnectsSniffedHost() bool
}

type subRuled interface {
	ClashSubRules() []C.Rule
}

type engineRoutes struct {
	version weak.Pointer[runtimeVersion]
	rules   []C.Rule
	engine  []bool
}

var engineRoutesCache atomic.Pointer[engineRoutes]

func engineRoutesOf(version *runtimeVersion) *engineRoutes {
	if cached := engineRoutesCache.Load(); cached != nil && cached.version.Value() == version {
		return cached
	}
	routes := &engineRoutes{version: weak.Make(version)}
	table := version.rules
	if version.mode != Rule {
		table = C.RuleList(version.routing.EveryModeRules)
	}
	namer, named := table.(interface{ AdapterAt(int) string })
	last := -1
	var engine []bool
	for i := 0; table != nil && i < table.Len(); i++ {
		var adapter string
		if named {
			adapter = namer.AdapterAt(i)
		} else {
			adapter = table.At(i).Adapter()
		}
		isEngine := false
		if proxy := version.proxies[adapter]; proxy != nil {
			connector, ok := proxy.Adapter().(sniffedHostConnector)
			isEngine = ok && connector.ClashConnectsSniffedHost()
		}
		engine = append(engine, isEngine)
		if isEngine {
			last = i
		}
	}
	mapped, knows := table.(interface{ ClashNamedOnly(int) bool })
	for i := 0; i <= last; i++ {
		if !engine[i] && knows && mapped.ClashNamedOnly(i) {
			continue
		}
		routes.rules = append(routes.rules, table.At(i))
		routes.engine = append(routes.engine, engine[i])
	}
	engineRoutesCache.Store(routes)
	return routes
}

func engineMayTakeOnceNamed(metadata *C.Metadata) bool {
	routes := engineRoutesOf(loadVersion())
	if len(routes.rules) == 0 {
		return false
	}
	flow := metadata.Clone()
	flow.Host = ""
	helper := C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}
	for i, rule := range routes.rules {
		if disabled, ok := rule.(interface{ IsDisabled() bool }); ok && disabled.IsDisabled() {
			continue
		}
		outcome := matchWithoutName(rule, flow, helper)
		if routes.engine[i] {
			if outcome != ruleNever {
				return true
			}
		} else if outcome == ruleAlways {
			return false
		}
	}
	return false
}

type ruleOutcome uint8

const (
	ruleNever ruleOutcome = iota
	ruleAlways
	ruleOnTheName
)

func matchWithoutName(rule C.Rule, flow *C.Metadata, helper C.RuleMatchHelper) ruleOutcome {
	rule = unwrappedRule(rule)
	switch rule.RuleType() {
	case C.AND, C.OR, C.NOT:
		combined, ok := rule.(subRuled)
		if !ok {
			return ruleOnTheName
		}
		parts := combined.ClashSubRules()
		switch rule.RuleType() {
		case C.NOT:
			if len(parts) != 1 {
				return ruleOnTheName
			}
			switch matchWithoutName(parts[0], flow, helper) {
			case ruleNever:
				return ruleAlways
			case ruleAlways:
				return ruleNever
			}
			return ruleOnTheName
		case C.AND:
			outcome := ruleAlways
			for _, part := range parts {
				switch matchWithoutName(part, flow, helper) {
				case ruleNever:
					return ruleNever
				case ruleOnTheName:
					outcome = ruleOnTheName
				}
			}
			return outcome
		default:
			outcome := ruleNever
			for _, part := range parts {
				switch matchWithoutName(part, flow, helper) {
				case ruleAlways:
					return ruleAlways
				case ruleOnTheName:
					outcome = ruleOnTheName
				}
			}
			return outcome
		}
	case C.InType, C.InPort, C.InUser, C.InName, C.Network, C.DstPort, C.SrcPort, C.DSCP,
		C.IPCIDR, C.IPSuffix, C.GEOIP, C.IPASN, C.SrcIPCIDR, C.SrcIPSuffix, C.SrcGEOIP, C.SrcIPASN:
		if matched, _ := rule.Match(flow, helper); matched {
			return ruleAlways
		}
		return ruleNever
	}
	return ruleOnTheName
}

func unwrappedRule(rule C.Rule) C.Rule {
	for {
		wrapper, ok := rule.(interface{ Unwrap() C.Rule })
		if !ok {
			return rule
		}
		inner := wrapper.Unwrap()
		if inner == nil || inner == rule {
			return rule
		}
		rule = inner
	}
}

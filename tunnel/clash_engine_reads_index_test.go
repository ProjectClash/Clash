package tunnel

import (
	"fmt"
	"net/netip"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
)

type namedOnlyTable struct {
	C.RuleList
	built *int
}

func (t namedOnlyTable) At(i int) C.Rule           { *t.built++; return t.RuleList[i] }
func (t namedOnlyTable) AdapterAt(i int) string    { return t.RuleList[i].Adapter() }
func (t namedOnlyTable) ClashNamedOnly(i int) bool { return t.RuleList[i].RuleType() == C.DomainSuffix }

func TestTheEnginesRoutesAreReadWithoutBuildingAModulesNamedRulesAheadOfThem(t *testing.T) {
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}}}
	proxies := map[string]C.Proxy{
		"DIRECT":        doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT":        doorProxy{name: "REJECT", typ: C.Reject},
		"MODULE-ENGINE": engine,
	}
	withRules(t, proxies, [3]string{"MATCH", "", "DIRECT"})
	parse := func(tp, payload, target string) C.Rule {
		t.Helper()
		var params []string
		if tp == "IP-CIDR6" {
			params = []string{"no-resolve"}
		}
		rule, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	var module C.RuleList
	for i := 0; i < 5000; i++ {
		module = append(module, parse("DOMAIN-SUFFIX", fmt.Sprintf("ad%d.example", i), "REJECT"))
		if i == 2500 {
			module = append(module, parse("IP-CIDR6", "2001:db8:1::/48", "REJECT"))
		}
	}
	built := 0
	route := engineRule("app.bilibili.com")
	table := C.ClashWithRulesAround(namedOnlyTable{RuleList: module, built: &built}, nil,
		C.RuleList{parse(route[0], route[1], route[2]), parse("MATCH", "", "DIRECT")}, nil, nil)
	UpdateProxiesAndRuleTable(proxies, nil, table, nil, nil)

	flow := func(destination string) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Type: C.TUN, SrcIP: netip.MustParseAddr("fdfe:dcba:9876::1"), SrcPort: 40000,
			DstIP: netip.MustParseAddr(destination), DstPort: 443}
	}
	if !engineMayTakeOnceNamed(flow("2001:db8::10")) {
		t.Fatal("a bare IPv6 flow to 443 is not held for the engine behind a module's domain rules")
	}
	if engineMayTakeOnceNamed(flow("2001:db8:1::5")) {
		t.Fatal("a flow the module's address rule takes ahead of the engine is held for the engine")
	}
	if built > 1 {
		t.Fatalf("the look-ahead built %d of the module's rules, want only its address rule", built)
	}
	if routes := engineRoutesOf(loadVersion()); len(routes.rules) > 2 {
		t.Fatalf("the look-ahead keeps %d rules, want the address rule and the engine's route", len(routes.rules))
	}
}

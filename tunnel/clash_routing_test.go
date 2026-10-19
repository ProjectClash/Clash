package tunnel

import (
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
	RW "github.com/ProjectClash/Clash/rules/wrapper"
)

func routingTestRule(t *testing.T, tp, payload, target string) C.Rule {
	t.Helper()
	rule, err := R.ParseRule(tp, payload, target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func withRoutingTestTunnel(t *testing.T, rules []C.Rule, routing C.ClashRouting) {
	t.Helper()
	withDoorTestTunnel(t, "DIRECT")
	prevRouting := loadVersion().routing
	t.Cleanup(func() { UpdateClashRouting(prevRouting) })
	UpdateProxiesAndRules(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		"GLOBAL": doorProxy{name: "GLOBAL", typ: C.Selector},
		"engine": doorProxy{name: "engine", typ: C.Http},
		"tcp":    indexNoUDPProxy{doorProxy{name: "tcp", typ: C.Shadowsocks}},
		"udp":    doorProxy{name: "udp", typ: C.Shadowsocks},
	}, nil, rules, nil, nil)
	UpdateClashRouting(routing)
}

func TestEveryModeRulesGoFirstOutsideRuleMode(t *testing.T) {
	engine := routingTestRule(t, "DOMAIN-SUFFIX", "ads.example", "engine")
	withRoutingTestTunnel(t, []C.Rule{routingTestRule(t, "MATCH", "", "udp")}, C.ClashRouting{EveryModeRules: []C.Rule{engine}})
	flow := func(host string) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: host, DstPort: 443}
	}
	for _, tc := range []struct {
		mode TunnelMode
		host string
		want string
	}{
		{Global, "x.ads.example", "engine"},
		{Global, "example.com", "GLOBAL"},
		{Direct, "x.ads.example", "engine"},
		{Direct, "example.com", "DIRECT"},
		{Rule, "x.ads.example", "udp"},
	} {
		SetMode(tc.mode)
		proxy, rule, err := resolveMetadata(flow(tc.host))
		if err != nil || proxy == nil || proxy.Name() != tc.want {
			t.Errorf("%s mode, %s: %v (%v), want %s", tc.mode, tc.host, proxy, err, tc.want)
		}
		if tc.want == "engine" {
			if _, indexed := C.RuleIndexOf(rule); rule == nil || indexed {
				t.Errorf("%s mode, %s: answered rule %v; want the every-mode rule, with no index", tc.mode, tc.host, rule)
			}
		}
	}
}

func TestAUDPFlowOnAProxyWithoutUDPTakesTheFallback(t *testing.T) {
	rules := []C.Rule{routingTestRule(t, "DST-PORT", "3478", "tcp"), routingTestRule(t, "MATCH", "", "udp")}
	for fallback, want := range map[string]string{"": "udp", "REJECT": "REJECT", "DIRECT": "DIRECT"} {
		withRoutingTestTunnel(t, rules, C.ClashRouting{UDPUnsupported: fallback})
		SetMode(Rule)
		proxy, rule, err := resolveMetadata(&C.Metadata{NetWork: C.UDP, Type: C.TUN, DstIP: testAddr("192.0.2.7"), DstPort: 3478})
		if err != nil || proxy == nil || proxy.Name() != want {
			t.Errorf("fallback %q: %v (%v), want %s", fallback, proxy, err, want)
		}
		if index, _ := C.RuleIndexOf(rule); fallback != "" && index != 0 {
			t.Errorf("fallback %q decided at rule %d, want the rule that named the proxy, 0", fallback, index)
		}
		tcp, _, _ := resolveMetadata(&C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: testAddr("192.0.2.7"), DstPort: 3478})
		if tcp == nil || tcp.Name() != "tcp" {
			t.Errorf("fallback %q: a TCP flow went to %v, want tcp", fallback, tcp)
		}
	}
}

func TestGlobalModeTakesTheUDPFallbackToo(t *testing.T) {
	withRoutingTestTunnel(t, nil, C.ClashRouting{UDPUnsupported: "REJECT"})
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		"GLOBAL": indexNoUDPProxy{doorProxy{name: "GLOBAL", typ: C.Selector}},
	}, nil)
	SetMode(Global)
	udp, _, _ := resolveMetadata(&C.Metadata{NetWork: C.UDP, Type: C.TUN, DstIP: testAddr("192.0.2.7"), DstPort: 443})
	tcp, _, _ := resolveMetadata(&C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: testAddr("192.0.2.7"), DstPort: 443})
	if udp == nil || udp.Name() != "REJECT" || tcp == nil || tcp.Name() != "GLOBAL" {
		t.Errorf("global mode: UDP %v, TCP %v; want REJECT and GLOBAL", udp, tcp)
	}
}

func TestARuleWithANotificationPostsItWhenItDecides(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	parsed := routingTestRule(t, "DOMAIN-SUFFIX", "watched.example", "DIRECT")
	rule := RW.NewNotifyingRule(RW.NewRuleWrapper(parsed), "watched", time.Hour, "DOMAIN-SUFFIX,watched.example")
	UpdateProxiesAndRules(waitTestProxies(), nil, []C.Rule{rule}, nil, nil)
	posted := make(chan [2]string, 4)
	SetRuleNotificationSink(func(text, line string) { posted <- [2]string{text, line} })
	t.Cleanup(func() { SetRuleNotificationSink(nil) })
	SetMode(Rule)
	inner := &C.Metadata{NetWork: C.TCP, Type: C.INNER, Host: "a.watched.example", DstPort: 443}
	if _, _, err := resolveMetadata(inner); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := resolveMetadata(&C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: "a.watched.example", DstPort: 443}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case got := <-posted:
		if got != [2]string{"watched", "DOMAIN-SUFFIX,watched.example"} {
			t.Fatalf("posted %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing posted")
	}
	select {
	case got := <-posted:
		t.Fatalf("posted again within the interval (or for the kernel's own flow): %v", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAnAppendedMatchTakesOnlyWhatTheConfigurationsRulesLeave(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	own := routingTestRule(t, "DOMAIN-SUFFIX", "own.example", "udp")
	appended := routingTestRule(t, "MATCH", "", "tcp")
	UpdateProxiesAndRuleTable(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"udp":    doorProxy{name: "udp", typ: C.Shadowsocks},
		"tcp":    doorProxy{name: "tcp", typ: C.Shadowsocks},
	}, nil, C.ClashWithRulesAround(nil, nil, C.RuleList{own}, C.RuleList{appended}, nil), nil, nil)
	SetMode(Rule)
	for host, want := range map[string]string{"a.own.example": "udp", "other.example": "tcp"} {
		proxy, rule, err := resolveMetadata(&C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: host, DstPort: 443})
		if err != nil || proxy == nil || proxy.Name() != want {
			t.Errorf("%s: %v (%v), want %s", host, proxy, err, want)
		}
		if index, _ := C.RuleIndexOf(rule); want == "tcp" && index != 1 {
			t.Errorf("%s: decided at %d, want the appended rule at 1", host, index)
		}
	}
}

func TestRoutingIsPublishedWithTheProxiesAndRules(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	prevRouting := loadVersion().routing
	t.Cleanup(func() { UpdateClashRouting(prevRouting) })
	engine := routingTestRule(t, "DOMAIN", "a.example", "engine")
	proxies := map[string]C.Proxy{"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}, "engine": doorProxy{name: "engine", typ: C.Http}}
	before := published.Load()
	UpdateProxiesRulesAndRouting(proxies, nil, C.RuleList(nil), nil, nil, nil, C.ClashRouting{EveryModeRules: []C.Rule{engine}, UDPUnsupported: "REJECT"})
	v := loadVersion()
	if v == before || v.proxies["engine"] == nil || len(v.routing.EveryModeRules) != 1 || v.routing.UDPUnsupported != "REJECT" {
		t.Fatalf("one publish did not carry both: %+v", v.routing)
	}
	UpdateProxiesRulesAndRouting(map[string]C.Proxy{}, nil, nil, nil, nil, nil, C.ClashRouting{})
	if v := loadVersion(); len(v.routing.EveryModeRules) != 0 || v.routing.UDPUnsupported != "" {
		t.Fatalf("an empty routing left %+v", v.routing)
	}
}

func TestTheExplanationFollowsTheEveryModeRulesAndTheUDPFallback(t *testing.T) {
	engine := routingTestRule(t, "DOMAIN-SUFFIX", "ads.example", "engine")
	withRoutingTestTunnel(t, []C.Rule{routingTestRule(t, "DST-PORT", "3478", "tcp"), routingTestRule(t, "MATCH", "", "udp")},
		C.ClashRouting{EveryModeRules: []C.Rule{engine}, UDPUnsupported: "REJECT"})
	SetMode(Global)
	if got := ExplainRule(RuleExplainInput{Host: "x.ads.example", DstPort: 443, Network: C.TCP}); got.Proxy != "engine" || got.Rule != nil {
		t.Errorf("global mode, an every-mode host: %s (rule %v), want engine and no numbered rule", got.Proxy, got.Rule)
	}
	if got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP}); got.Proxy != "GLOBAL" {
		t.Errorf("global mode, another host: %s, want GLOBAL", got.Proxy)
	}
	SetMode(Rule)
	got := ExplainRule(RuleExplainInput{DstIP: testAddr("192.0.2.7"), DstPort: 3478, Network: C.UDP})
	if got.Proxy != "REJECT" || got.Rule == nil || got.Rule.Index != 0 {
		t.Errorf("a UDP flow on a proxy without UDP: %s at %+v, want REJECT at rule 0", got.Proxy, got.Rule)
	}
}

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"

	"github.com/miekg/dns"
)


type chainProxy struct {
	doorProxy
	now C.Proxy
}

func (p chainProxy) Unwrap(*C.Metadata, bool) C.Proxy { return p.now }

func withExplainTunnel(t *testing.T, rules ...[3]string) {
	t.Helper()
	prevMode, prevProxies, prevRules := Mode(), loadProxies(), rules_()
	t.Cleanup(func() {
		SetMode(prevMode)
		UpdateProxies(prevProxies, nil)
		UpdateRules(prevRules, nil, nil)
	})
	hk := doorProxy{name: "HK", typ: C.Shadowsocks}
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		"GLOBAL": chainProxy{doorProxy{name: "GLOBAL", typ: C.Selector}, hk},
		"HK":     hk,
		"Proxy":  chainProxy{doorProxy{name: "Proxy", typ: C.Selector}, hk},
		"Auto":   chainProxy{doorProxy{name: "Auto", typ: C.URLTest}, hk},
	}, nil)
	parsed := make([]C.Rule, 0, len(rules))
	for _, r := range rules {
		var params []string
		if r[0] == "IP-CIDR" && r[1] == "10.0.0.0/8" {
			params = []string{"no-resolve"}
		}
		rule, err := R.ParseRule(r[0], r[1], r[2], params, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, rule)
	}
	UpdateRules(parsed, nil, nil)
	SetMode(Rule)
}

func TestExplainRuleFollowsTheRuleOrder(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"DOMAIN-SUFFIX", "example.com", "Proxy"},
		[3]string{"DOMAIN-KEYWORD", "example", "DIRECT"},
		[3]string{"MATCH", "", "REJECT"})
	got := ExplainRule(RuleExplainInput{Host: "www.example.com", DstPort: 443, Network: C.TCP})
	if !got.Decided || got.Rule == nil || got.Rule.Index != 0 || got.Rule.Type != "DomainSuffix" || got.Proxy != "Proxy" {
		t.Fatalf("%+v", got)
	}
	if !slices.Equal(got.Chain, []string{"Proxy", "HK"}) {
		t.Fatalf("chain %v, want Proxy -> HK", got.Chain)
	}
	got = ExplainRule(RuleExplainInput{Host: "example.org", DstPort: 443, Network: C.TCP})
	if got.Rule == nil || got.Rule.Index != 1 || got.Proxy != "DIRECT" {
		t.Fatalf("the keyword rule is the first to match example.org: %+v", got)
	}
	got = ExplainRule(RuleExplainInput{Host: "other.net", DstPort: 443, Network: C.TCP})
	if got.Rule == nil || got.Rule.Type != "Match" || got.Proxy != "REJECT" {
		t.Fatalf("%+v", got)
	}
}

func TestExplainRuleDoesNotResolveUnlessAsked(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"IP-CIDR", "93.184.0.0/16", "Proxy"},
		[3]string{"MATCH", "", "DIRECT"})
	got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP})
	if got.Decided || !slices.Contains(got.Missing, "ip") {
		t.Fatalf("an IP rule asked for an address that was not resolved; the answer must say so: %+v", got)
	}
	if got.Proxy != "DIRECT" {
		t.Fatalf("with the IP rule skipped the flow falls to MATCH: %+v", got)
	}
	got = ExplainRule(RuleExplainInput{Host: "example.com", DstIP: netip.MustParseAddr("93.184.216.34"), DstPort: 443, Network: C.TCP})
	if !got.Decided || got.Proxy != "Proxy" || got.Rule.Index != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestExplainRuleNoResolveRuleNeedsNoAddress(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"IP-CIDR", "10.0.0.0/8", "DIRECT"},
		[3]string{"MATCH", "", "Proxy"})
	got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP})
	if !got.Decided || got.Proxy != "Proxy" {
		t.Fatalf("a no-resolve IP rule never asks for an address: %+v", got)
	}
}

func TestExplainRuleFollowsTheMode(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "Proxy"})
	SetMode(Global)
	got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP})
	if got.Mode != "global" || got.Proxy != "GLOBAL" || got.Rule != nil || !got.Decided {
		t.Fatalf("%+v", got)
	}
	SetMode(Direct)
	if got := ExplainRule(RuleExplainInput{Host: "example.com", Network: C.TCP}); got.Proxy != "DIRECT" {
		t.Fatalf("%+v", got)
	}
	SetMode(Rule)
	UpdateRules(nil, nil, nil)
	if got := ExplainRule(RuleExplainInput{Host: "example.com", Network: C.TCP}); got.Proxy != "DIRECT" || got.Rule != nil {
		t.Fatalf("%+v", got)
	}
}

func TestExplainRuleMarksAChainThatCanChange(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "Auto"})
	got := ExplainRule(RuleExplainInput{Host: "example.com", Network: C.TCP})
	if !got.Conditional || !slices.Equal(got.Chain, []string{"Auto", "HK"}) {
		t.Fatalf("a url-test group's current choice changes; the chain must say it is conditional: %+v", got)
	}
}

func TestExplainRuleReadsTheHostsFirst(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"IP-CIDR", "10.0.0.0/8", "REJECT"},
		[3]string{"MATCH", "", "DIRECT"})
	previous := resolver.DefaultHosts
	t.Cleanup(func() { resolver.DefaultHosts = previous })
	hosts := trie.New[resolver.HostValue]()
	value, err := resolver.NewHostValueByIPs([]netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := hosts.Insert("example.test", value); err != nil {
		t.Fatal(err)
	}
	resolver.DefaultHosts = resolver.NewHosts(hosts)
	got := ExplainRule(RuleExplainInput{Host: "example.test", DstPort: 443, Network: C.TCP})
	if got.Proxy != "REJECT" || got.HostsIP != "10.0.0.1" || !got.Decided {
		t.Fatalf("the tunnel answers a hosts entry before any rule: %+v", got)
	}
}

type noUDPProxy struct{ doorProxy }

func (noUDPProxy) SupportUDP() bool { return false }

func TestExplainRuleSkipsAnOutboundWithoutUDPForAUDPFlow(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "DIRECT"})
	proxies := loadProxies()
	proxies["TCPOnly"] = noUDPProxy{doorProxy{name: "TCPOnly", typ: C.Http}}
	UpdateProxies(proxies, nil)
	first, _ := R.ParseRule("DOMAIN-SUFFIX", "example.com", "TCPOnly", nil, nil)
	last, _ := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	UpdateRules([]C.Rule{first, last}, nil, nil)
	if got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.UDP}); got.Proxy != "DIRECT" || got.Rule.Index != 1 {
		t.Fatalf("match() passes over an outbound that cannot carry UDP: %+v", got)
	}
	if got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP}); got.Proxy != "TCPOnly" {
		t.Fatalf("%+v", got)
	}
}

func TestExplainRuleNamesTheSubRuleSet(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "DIRECT"})
	inner, _ := R.ParseRule("DOMAIN-SUFFIX", "example.com", "REJECT", nil, nil)
	subRules := map[string][]C.Rule{"web": {inner}}
	sub, err := R.ParseRule("SUB-RULE", "(NETWORK,tcp)", "web", nil, subRules)
	if err != nil {
		t.Fatal(err)
	}
	last, _ := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	UpdateRules([]C.Rule{sub, last}, subRules, nil)
	got := ExplainRule(RuleExplainInput{Host: "www.example.com", DstPort: 443, Network: C.TCP})
	if got.Proxy != "REJECT" || got.Rule == nil || got.Rule.SubRules != "web" || got.Rule.Index != 0 ||
		got.Rule.Type != "DomainSuffix" || got.Rule.Through == nil || got.Rule.Through.Index != 0 || got.Rule.Through.Type != "SubRules" {
		t.Fatalf("a SUB-RULE answers with the rule inside its set, and the line that led there: %+v", got.Rule)
	}
}

type stubMapper struct {
	fake netip.Addr
	host string
}

func (m stubMapper) FakeIPEnabled() bool               { return true }
func (m stubMapper) MappingEnabled() bool              { return true }
func (m stubMapper) IsFakeIP(ip netip.Addr) bool       { return ip == m.fake }
func (m stubMapper) IsFakeBroadcastIP(netip.Addr) bool { return false }
func (m stubMapper) IsExistFakeIP(ip netip.Addr) bool  { return ip == m.fake }
func (m stubMapper) FlushFakeIP() error                { return nil }
func (m stubMapper) InsertHostByIP(netip.Addr, string) {}
func (m stubMapper) StoreFakePoolState()               {}
func (m stubMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	if ip == m.fake {
		return m.host, true
	}
	return "", false
}

func TestExplainRuleMapsAFakeAddressBackToItsDomain(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"DOMAIN-SUFFIX", "example.com", "Proxy"},
		[3]string{"MATCH", "", "DIRECT"})
	previous := resolver.DefaultHostMapper
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })
	fake := netip.MustParseAddr("198.18.0.9")
	resolver.DefaultHostMapper = stubMapper{fake: fake, host: "www.example.com"}
	got := ExplainRule(RuleExplainInput{DstIP: fake, DstPort: 443, Network: C.TCP})
	if !got.FakeIP || got.Host != "www.example.com" || got.Proxy != "Proxy" {
		t.Fatalf("a fake address is the domain it was handed out for: %+v", got)
	}
}

func TestExplainRuleFollowsAHostsDomainAlias(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"DOMAIN", "b.example", "Proxy"},
		[3]string{"MATCH", "", "DIRECT"})
	previous := resolver.DefaultHosts
	t.Cleanup(func() { resolver.DefaultHosts = previous })
	hosts := trie.New[resolver.HostValue]()
	alias, err := resolver.NewHostValueByDomain("b.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := hosts.Insert("a.example", alias); err != nil {
		t.Fatal(err)
	}
	resolver.DefaultHosts = resolver.NewHosts(hosts)
	if got := ExplainRule(RuleExplainInput{Host: "a.example", DstPort: 443, Network: C.TCP}); got.Host != "b.example" || got.Proxy != "Proxy" {
		t.Fatalf("the tunnel routes a hosts alias as its target: %+v", got)
	}
}

func TestExplainRuleMarksAProcessItWasNotTold(t *testing.T) {
	withExplainTunnel(t,
		[3]string{"PROCESS-NAME", "curl", "REJECT"},
		[3]string{"MATCH", "", "Proxy"})
	got := ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP, ProcessAvailable: true})
	if got.Decided || !slices.Equal(got.Missing, []string{"process"}) {
		t.Fatalf("the tunnel would look the process up; the explanation was not told it: %+v", got)
	}
	got = ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP, ProcessAvailable: true, Process: "/usr/bin/curl"})
	if !got.Decided || got.Proxy != "REJECT" {
		t.Fatalf("%+v", got)
	}
	got = ExplainRule(RuleExplainInput{Host: "example.com", DstPort: 443, Network: C.TCP, Process: "curl"})
	if !got.Decided || got.Proxy != "Proxy" || !got.ProcessUnavailable {
		t.Fatalf("%+v", got)
	}
}

func TestExplainRuleIsExactForTheFlowItIsGiven(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "DIRECT"})
	and, err := R.ParseRule("AND", "((SRC-IP-CIDR,192.168.0.0/16),(DOMAIN,example.test))", "REJECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match, _ := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	UpdateRules([]C.Rule{and, match}, nil, nil)
	if got := ExplainRule(RuleExplainInput{Host: "example.test", DstPort: 443, Network: C.TCP, SrcIP: netip.MustParseAddr("192.168.1.2")}); !got.Decided || got.Proxy != "REJECT" {
		t.Fatalf("a LAN client's flow: %+v", got)
	}
	if got := ExplainRule(RuleExplainInput{Host: "example.test", DstPort: 443, Network: C.TCP, SrcIP: netip.MustParseAddr("198.18.0.1")}); !got.Decided || got.Proxy != "DIRECT" {
		t.Fatalf("this device's own flow: %+v", got)
	}
}

type stubResolver struct{ ip netip.Addr }

func (r stubResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}
func (r stubResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}
func (r stubResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) { return nil, nil }
func (r stubResolver) ResolveECH(context.Context, string) ([]byte, error)       { return nil, nil }
func (r stubResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("stub")
}
func (r stubResolver) Invalid() bool    { return true }
func (r stubResolver) ClearCache()      {}
func (r stubResolver) ResetConnection() {}

func TestExplainRuleNamesTheInnerRuleTheWalkChose(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "DIRECT"})
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = stubResolver{ip: netip.MustParseAddr("10.0.0.5")}
	lan, _ := R.ParseRule("IP-CIDR", "10.0.0.0/8", "REJECT", []string{"no-resolve"}, nil)
	everything, _ := R.ParseRule("IP-CIDR", "0.0.0.0/0", "Proxy", nil, nil)
	subRules := map[string][]C.Rule{"net": {lan, everything}}
	sub, err := R.ParseRule("SUB-RULE", "(NETWORK,tcp)", "net", nil, subRules)
	if err != nil {
		t.Fatal(err)
	}
	UpdateRules([]C.Rule{sub}, subRules, nil)
	got := ExplainRule(RuleExplainInput{Host: "nas.lan", DstPort: 443, Network: C.TCP, Resolve: true})
	if got.Proxy != "Proxy" || got.Rule == nil || got.Rule.SubRules != "net" || got.Rule.Index != 1 || got.ResolvedIP != "10.0.0.5" {
		t.Fatalf("the walk resolved at rule 1 and chose Proxy: %+v %+v", got, got.Rule)
	}
}

type rematchProxy struct {
	doorProxy
	set string
}

func (p rematchProxy) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	metadata.SpecialRules = p.set
	return nil, nil
}

func TestExplainRuleFollowsARematch(t *testing.T) {
	withExplainTunnel(t, [3]string{"MATCH", "", "DIRECT"})
	proxies := loadProxies()
	proxies["Again"] = rematchProxy{doorProxy{name: "Again", typ: C.Rematch}, "web"}
	UpdateProxies(proxies, nil)
	first, _ := R.ParseRule("DOMAIN-SUFFIX", "example.com", "Again", nil, nil)
	last, _ := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	inner, _ := R.ParseRule("MATCH", "", "Proxy", nil, nil)
	subRules := map[string][]C.Rule{"web": {inner}}
	UpdateRules([]C.Rule{first, last}, subRules, nil)
	got := ExplainRule(RuleExplainInput{Host: "www.example.com", DstPort: 443, Network: C.TCP})
	if got.Proxy != "Proxy" || got.Rule == nil || got.Rule.SubRules != "web" || got.Rule.Index != 0 {
		t.Fatalf("the rematched flow is answered by the set it was sent to: %+v %+v", got, got.Rule)
	}
}

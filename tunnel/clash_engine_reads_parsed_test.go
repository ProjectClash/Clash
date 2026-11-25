package tunnel_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	_ "github.com/ProjectClash/Clash/hub/executor"
	"github.com/ProjectClash/Clash/tunnel"
)

const engineConfiguration = `
mode: rule
proxies:
  - { name: MODULE-ENGINE, type: http, server: 127.0.0.1, port: 9, username: u, password: p, x-clash-internal: true, x-clash-connect-sniffed-host: %s }
rule-providers:
  module-engine-test:
    type: inline
    behavior: domain
    payload: [ app.bilibili.com ]
rules:
  - AND,((IN-TYPE,TUN),(NETWORK,TCP),(DST-PORT,443),(RULE-SET,module-engine-test)),MODULE-ENGINE
  - AND,((IN-TYPE,TUN),(NETWORK,TCP),(OR,((AND,((DST-PORT,8443),(DOMAIN,api.example))),(AND,((DST-PORT,80),(DOMAIN,plain.example)))))),MODULE-ENGINE
  - MATCH,DIRECT
`

func withParsedConfiguration(t *testing.T, connectsSniffedHost string) *config.Config {
	return withParsedText(t, fmt.Sprintf(engineConfiguration, connectsSniffedHost))
}

func withParsedText(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	previousProxies, previousProviders := tunnel.Proxies(), tunnel.Providers()
	previousRules, previousRuleProviders, previousSubRules := tunnel.RuleTable(), tunnel.RuleProviders(), tunnel.SubRulesForTest()
	t.Cleanup(func() {
		tunnel.UpdateProxiesAndRuleTable(previousProxies, previousProviders, previousRules, previousSubRules, previousRuleProviders)
	})
	table := cfg.RuleTable
	if table == nil {
		table = C.RuleList(cfg.Rules)
	}
	tunnel.UpdateProxiesAndRuleTable(cfg.Proxies, cfg.Providers, table, cfg.SubRules, cfg.RuleProviders)
	return cfg
}

func ipv6FlowTo(port uint16, network C.NetWork, inbound C.Type) *C.Metadata {
	return &C.Metadata{
		NetWork: network, Type: inbound,
		SrcIP: netip.MustParseAddr("fdfe:dcba:9876::1"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("2001:db8::10"), DstPort: port,
	}
}

func TestTheParsedEngineMayTakeOnlyWhatItsRulesCould(t *testing.T) {
	withParsedConfiguration(t, "true")
	for _, tc := range []struct {
		name string
		flow *C.Metadata
		want bool
	}{
		{"TUN TCP 443", ipv6FlowTo(443, C.TCP, C.TUN), true},
		{"TUN TCP 8443", ipv6FlowTo(8443, C.TCP, C.TUN), true},
		{"TUN TCP 80", ipv6FlowTo(80, C.TCP, C.TUN), true},
		{"TUN TCP 9443", ipv6FlowTo(9443, C.TCP, C.TUN), false},
		{"TUN UDP 443", ipv6FlowTo(443, C.UDP, C.TUN), false},
		{"HTTP inbound TCP 443", ipv6FlowTo(443, C.TCP, C.HTTP), false},
	} {
		if got := tunnel.EngineMayTakeOnceNamedForTest(tc.flow); got != tc.want {
			t.Errorf("%s: the engine may take it: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAParsedHTTPProxyThatIsNotTheEngineTakesNothing(t *testing.T) {
	withParsedConfiguration(t, "false")
	if tunnel.EngineMayTakeOnceNamedForTest(ipv6FlowTo(443, C.TCP, C.TUN)) {
		t.Fatal("an HTTP proxy without x-clash-connect-sniffed-host is taken for the engine")
	}
}

func TestAParsedAddressRuleAheadOfTheEngineDecidesUntilItIsDisabled(t *testing.T) {
	text := strings.Replace(fmt.Sprintf(engineConfiguration, "true"), "rules:\n", "rules:\n  - IP-CIDR6,2001:db8::/32,DIRECT\n", 1)
	cfg := withParsedText(t, text)
	flow := ipv6FlowTo(443, C.TCP, C.TUN)
	if tunnel.EngineMayTakeOnceNamedForTest(flow) {
		t.Fatal("a flow an address rule ahead of the engine's takes is held for the engine")
	}
	wrapper, ok := cfg.Rules[0].(C.RuleWrapper)
	if !ok {
		t.Fatalf("the parsed rule is %T, not a RuleWrapper", cfg.Rules[0])
	}
	wrapper.SetDisabled(true)
	if !tunnel.EngineMayTakeOnceNamedForTest(flow) {
		t.Fatal("with the address rule disabled, the engine's rule is not reached")
	}
}

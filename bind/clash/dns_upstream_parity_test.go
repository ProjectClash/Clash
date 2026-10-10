package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	mihomoDNS "github.com/ProjectClash/Clash/dns"
)

const documentedDNSBlock = `
mode: rule
proxies: []
rules:
  - MATCH,DIRECT
dns:
  enable: true
  cache-algorithm: arc
  prefer-h3: false
  use-hosts: true
  use-system-hosts: true
  respect-rules: false
  ipv6: false
  default-nameserver:
    - 223.5.5.5
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - '*.lan'
  nameserver-policy:
    '+.arpa': '10.0.0.1'
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - tls://8.8.4.4
    - tls://1.1.1.1
  proxy-server-nameserver:
    - https://doh.pub/dns-query
  proxy-server-nameserver-policy:
    'www.yournode.com': '114.114.114.114'
  direct-nameserver:
    - 223.6.6.6
  direct-nameserver-follow-policy: false
  fallback-filter:
    # geoip is deliberately left off: enabling it makes mihomo's own parser download
    # geoip.metadb, so the fixture would be asserting network access rather than parity.
    # The ipcidr filter exercises the same fallback-filter path without leaving the machine.
    geoip: false
    ipcidr:
      - 240.0.0.0/4
`

func addressesOf(servers []mihomoDNS.NameServer) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Net+"|"+s.Addr)
	}
	return out
}

func TestDocumentedDNSBlockSurvivesUnchanged(t *testing.T) {
	mihomo, err := config.Parse([]byte(documentedDNSBlock))
	if err != nil {
		t.Fatalf("mihomo's own parser rejected its own documented example: %v", err)
	}
	ours, err := parseConfigForIOS(documentedDNSBlock, true)
	if err != nil {
		t.Fatalf("this core rejected mihomo's documented example: %v", err)
	}

	for _, probe := range []struct {
		what      string
		theirs    []string
		ours      []string
		whyItLeak string
	}{
		{
			"nameserver", addressesOf(mihomo.DNS.NameServer), addressesOf(ours.DNS.NameServer),
			"the resolver every unmatched domain goes to",
		},
		{
			"fallback", addressesOf(mihomo.DNS.Fallback), addressesOf(ours.DNS.Fallback),
			"the trusted-result resolver; losing it sends poisoned answers through",
		},
		{
			"proxy-server-nameserver",
			addressesOf(mihomo.DNS.ProxyServerNameserver), addressesOf(ours.DNS.ProxyServerNameserver),
			"node-domain lookups; losing it resolves the node itself on the local resolver",
		},
		{
			"direct-nameserver",
			addressesOf(mihomo.DNS.DirectNameServer), addressesOf(ours.DNS.DirectNameServer),
			"direct-egress lookups",
		},
		{
			"default-nameserver",
			addressesOf(mihomo.DNS.DefaultNameserver), addressesOf(ours.DNS.DefaultNameserver),
			"bootstrap for resolving the DNS servers' own domains",
		},
	} {
		if strings.Join(probe.theirs, ",") != strings.Join(probe.ours, ",") {
			t.Errorf("%s differs from mihomo — %s\n  mihomo: %v\n  ours:   %v",
				probe.what, probe.whyItLeak, probe.theirs, probe.ours)
		}
	}

	if mihomo.DNS.EnhancedMode != ours.DNS.EnhancedMode {
		t.Errorf("enhanced-mode: mihomo %v, ours %v. fake-ip is what keeps the domain alive to "+
			"the outbound; anything else resolves it here instead",
			mihomo.DNS.EnhancedMode, ours.DNS.EnhancedMode)
	}
	if mihomo.DNS.FakeIPRange.String() != ours.DNS.FakeIPRange.String() {
		t.Errorf("fake-ip-range: mihomo %v, ours %v", mihomo.DNS.FakeIPRange, ours.DNS.FakeIPRange)
	}
	if len(mihomo.DNS.NameServerPolicy) != len(ours.DNS.NameServerPolicy) {
		t.Errorf("nameserver-policy entries: mihomo %d, ours %d — split DNS is how a reader "+
			"keeps internal names off the public resolver",
			len(mihomo.DNS.NameServerPolicy), len(ours.DNS.NameServerPolicy))
	}
	if mihomo.DNS.DirectFollowPolicy != ours.DNS.DirectFollowPolicy {
		t.Errorf("direct-nameserver-follow-policy: mihomo %v, ours %v",
			mihomo.DNS.DirectFollowPolicy, ours.DNS.DirectFollowPolicy)
	}
	if len(mihomo.DNS.ProxyServerPolicy) != len(ours.DNS.ProxyServerPolicy) {
		t.Errorf("proxy-server-nameserver-policy entries: mihomo %d, ours %d",
			len(mihomo.DNS.ProxyServerPolicy), len(ours.DNS.ProxyServerPolicy))
	}
	if len(mihomo.DNS.FallbackIPFilter) != len(ours.DNS.FallbackIPFilter) {
		t.Errorf("fallback-filter ip filters: mihomo %d, ours %d",
			len(mihomo.DNS.FallbackIPFilter), len(ours.DNS.FallbackIPFilter))
	}
}

func TestReportedShapesMatchMihomo(t *testing.T) {
	const withBlock = `
mode: rule
rules:
  - MATCH,DIRECT
dns:
  enable: true
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.6.6.6
`
	const withoutBlock = "mode: rule\nrules:\n  - MATCH,DIRECT\n"

	for _, testCase := range []struct{ name, yaml string }{
		{"with a dns block", withBlock},
		{"with no dns block", withoutBlock},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mihomo, err := config.Parse([]byte(testCase.yaml))
			if err != nil {
				t.Fatalf("mihomo rejected it: %v", err)
			}
			ours, err := parseConfigForIOS(testCase.yaml, true)
			if err != nil {
				t.Fatalf("this core rejected what mihomo accepted: %v", err)
			}
			if !ours.DNS.Enable {
				t.Fatalf("dns.enable must end up on inside a packet tunnel")
			}
			if mihomo.DNS.EnhancedMode != ours.DNS.EnhancedMode {
				t.Fatalf("enhanced-mode: mihomo %v, ours %v",
					mihomo.DNS.EnhancedMode, ours.DNS.EnhancedMode)
			}
			if got, want := addressesOf(ours.DNS.NameServer), addressesOf(mihomo.DNS.NameServer); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("nameserver: mihomo %v, ours %v", want, got)
			}
		})
	}
}

func TestDisabledDNSIsEnabledAndNothingElseIsTouched(t *testing.T) {
	const noDNS = "mode: rule\nrules:\n  - MATCH,DIRECT\n"
	mihomo, err := config.Parse([]byte(noDNS))
	if err != nil {
		t.Fatalf("mihomo rejected it: %v", err)
	}
	ours, err := parseConfigForIOS(noDNS, true)
	if err != nil {
		t.Fatalf("this core rejected what mihomo accepted: %v", err)
	}
	if !ours.DNS.Enable {
		t.Fatal("dns.enable must be on: a packet tunnel captures port 53 either way, and " +
			"with the resolver down every hijacked query answers SERVFAIL")
	}
	if mihomo.DNS.Enable {
		t.Fatal("fixture no longer exercises the case: mihomo enabled DNS by itself")
	}
	if mihomo.DNS.EnhancedMode != ours.DNS.EnhancedMode {
		t.Errorf("enhanced-mode: mihomo %v, ours %v", mihomo.DNS.EnhancedMode, ours.DNS.EnhancedMode)
	}
	if got, want := addressesOf(ours.DNS.NameServer), addressesOf(mihomo.DNS.NameServer); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("nameserver: mihomo %v, ours %v -- resolvers must be upstream's defaults, not ones chosen here", want, got)
	}
	if got, want := addressesOf(ours.DNS.DefaultNameserver), addressesOf(mihomo.DNS.DefaultNameserver); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("default-nameserver: mihomo %v, ours %v", want, got)
	}
}

package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

type renameAnswer struct {
	OK      bool   `json:"ok"`
	Text    string `json:"text"`
	Changed int    `json:"changed"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func runRename(t *testing.T, original, kind, oldName, newName string) renameAnswer {
	t.Helper()
	box, err := RenameReferencesForIOS(original, kind, oldName, newName)
	if err != nil {
		t.Fatal(err)
	}
	var answer renameAnswer
	if err := json.Unmarshal([]byte(box.Value), &answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

const renameFixture = `# config
mode: rule
dns:
  enable: true
  nameserver:
    - https://1.1.1.1/dns-query#Proxy&h3=true   # via Proxy
    - 223.5.5.5
  proxy-server-nameserver: [tls://8.8.8.8#Proxy]
  nameserver-policy:
    "rule-set:ads,cn": [223.5.5.5]
    "+.corp.test": https://9.9.9.9/dns-query#Proxy
  fake-ip-filter:
    - rule-set:ads
    - "+.lan"
tun:
  route-address-set: [ads, other]
proxies:
  - {name: a, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p, dialer-proxy: Proxy}
proxy-providers:
  sub:
    type: http
    url: https://example.com/sub
    proxy: Proxy
rule-providers:
  ads:
    type: http
    behavior: domain
    url: https://example.com/ads.yaml
  cn: {type: http, behavior: domain, url: "https://example.com/cn.yaml"}
proxy-groups:
  - name: Proxy
    type: select
    proxies: [a, DIRECT]
    use: [sub]
  - name: Auto
    type: url-test
    proxies:
      - Proxy
      - a
rules:
  - RULE-SET,ads,REJECT
  - AND,((RULE-SET,ads),(NETWORK,tcp)),Proxy
  - DOMAIN,x.test,Proxy
  - MATCH,Proxy
sub-rules:
  s1:
    - RULE-SET,ads,Proxy,no-resolve
`

func TestRenameRuleProviderEverywhere(t *testing.T) {
	answer := runRename(t, renameFixture, "ruleProvider", "ads", "adblock")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	for _, want := range []string{
		"  adblock:\n    type: http", `"rule-set:adblock,cn": [223.5.5.5]`, "    - rule-set:adblock\n",
		"route-address-set: [adblock, other]", "  - RULE-SET,adblock,REJECT\n",
		"  - AND,((RULE-SET,adblock),(NETWORK,tcp)),Proxy\n", "    - RULE-SET,adblock,Proxy,no-resolve\n",
	} {
		if !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q in:\n%s", want, answer.Text)
		}
	}
	if answer.Changed != 7 || strings.Contains(answer.Text, "RULE-SET,ads") || strings.Contains(answer.Text, "rule-set:ads") || strings.Contains(answer.Text, "\n  ads:") {
		t.Errorf("changed %d; text still names ads:\n%s", answer.Changed, answer.Text)
	}
	if !strings.HasPrefix(answer.Text, "# config\n") || !strings.Contains(answer.Text, "# via Proxy") {
		t.Errorf("comments moved:\n%s", answer.Text)
	}
}

func TestRenameProxyGroupEverywhere(t *testing.T) {
	answer := runRename(t, renameFixture, "proxyGroup", "Proxy", "Main")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	for _, want := range []string{
		"https://1.1.1.1/dns-query#Main&h3=true   # via Proxy", "[tls://8.8.8.8#Main]", "https://9.9.9.9/dns-query#Main\n",
		"dialer-proxy: Main}", "    proxy: Main\n", "  - name: Main\n", "      - Main\n",
		"  - AND,((RULE-SET,ads),(NETWORK,tcp)),Main\n", "  - DOMAIN,x.test,Main\n", "  - MATCH,Main\n", "    - RULE-SET,ads,Main,no-resolve\n",
	} {
		if !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q in:\n%s", want, answer.Text)
		}
	}
	if answer.Changed != 11 {
		t.Errorf("changed %d", answer.Changed)
	}
}

func TestRenameProxyProvider(t *testing.T) {
	answer := runRename(t, renameFixture, "proxyProvider", "sub", "subscription")
	if !answer.OK || !strings.Contains(answer.Text, "  subscription:\n    type: http") || !strings.Contains(answer.Text, "use: [subscription]") || answer.Changed != 2 {
		t.Fatalf("%+v", answer)
	}
}

func TestRenameReferencesRefusals(t *testing.T) {
	for _, c := range []struct{ original, kind, oldName, newName, code string }{
		{renameFixture, "proxyGroup", "Proxy", "Auto", "invalidRequest"},
		{renameFixture, "proxyGroup", "Proxy", "a", "invalidRequest"},
		{renameFixture, "proxyGroup", "Proxy", "DIRECT", "invalidRequest"},
		{renameFixture, "proxyGroup", "Proxy", "x,y", "invalidRequest"},
		{renameFixture, "proxyGroup", "Nope", "x", "notFound"},
		{renameFixture, "ruleProvider", "ads", "cn", "invalidRequest"},
		{renameFixture, "ruleProvider", "ads", "a:b", "invalidRequest"},
		{renameFixture, "widget", "ads", "b", "invalidRequest"},
		{"a: &x 1\nrule-providers:\n  r: {type: inline, behavior: domain, payload: []}\nb: *x\n", "ruleProvider", "r", "s", "anchor"},
	} {
		if answer := runRename(t, c.original, c.kind, c.oldName, c.newName); answer.OK || answer.Code != c.code {
			t.Errorf("%s %s -> %s: %+v, want %s", c.kind, c.oldName, c.newName, answer, c.code)
		}
	}
}

func TestRenameReferencesSelfCheck(t *testing.T) {
	yamlEditSurgeryFault = func(text string) string { return strings.Replace(text, "mode: rule", "mode: global", 1) }
	defer func() { yamlEditSurgeryFault = nil }()
	if answer := runRename(t, renameFixture, "proxyGroup", "Proxy", "Main"); answer.OK || answer.Code != "unsafeEdit" {
		t.Fatalf("%+v", answer)
	}
}

func TestRenameReferencesWritesNamesAsTheyWere(t *testing.T) {
	original := "proxy-groups:\n  - {name: 'Old', type: select, proxies: [DIRECT]}\n  - name: B\n    type: select\n    proxies: [Old, DIRECT]\nrules:\n  - MATCH,Old\n"
	answer := runRename(t, original, "proxyGroup", "Old", "New One")
	want := "proxy-groups:\n  - {name: \"New One\", type: select, proxies: [DIRECT]}\n  - name: B\n    type: select\n    proxies: [New One, DIRECT]\nrules:\n  - MATCH,New One\n"
	if !answer.OK || answer.Text != want {
		t.Fatalf("%+v\nwant:\n%s", answer, want)
	}
	answer = runRename(t, original, "proxyGroup", "Old", "true")
	if !answer.OK || !strings.Contains(answer.Text, `proxies: ["true", DIRECT]`) || !strings.Contains(answer.Text, "  - MATCH,true\n") {
		t.Fatalf("a name that reads as a boolean: %+v", answer)
	}
}

const renameAuditFixture = `dns:
  enable: true
  fake-ip-filter-mode: Rule
  fake-ip-filter:
    - RULE-SET,ads,fake-ip
    - DOMAIN,ads,real-ip
  fallback-filter:
    ipcidr: [rule-set:ads]
    domain: [rule-set:ads]
  nameserver: ["https://1.1.1.1/dns-query#%4Fld&h3=true"]
  proxy-server-nameserver: [223.5.5.5]
  proxy-server-nameserver-policy:
    "rule-set:ads": tls://8.8.8.8#Old
listeners:
  - name: t
    type: tun
    route-address-set: [ads]
  - name: v
    type: vless
    port: 1
    proxy: Old
    reality-config: {proxy: Old}
    shadow-tls:
      handshake: {proxy: Old}
      handshake-for-server-name:
        example.com: {proxy: Old}
  - name: h
    type: hysteria2
    port: 2
    realm-opts: {proxy: Old}
proxy-providers:
  inline:
    type: inline
    payload:
      - {name: n, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p, dialer-proxy: Old}
rule-providers:
  ads: {type: inline, behavior: domain, payload: [ads.test]}
  mixed:
    type: inline
    behavior: classical
    payload:
      - AND,((RULE-SET,ads),(DST-PORT,443))
proxy-groups:
  - {name: Old, type: select, proxies: [DIRECT]}
rules:
  - SUB-RULE,(AND,((RULE-SET,ads),(NETWORK,TCP))),Old
  - DOMAIN-REGEX,^a,b$,Old
sub-rules:
  Old:
    - MATCH,DIRECT
`

func TestRenameRuleProviderAudit(t *testing.T) {
	answer := runRename(t, renameAuditFixture, "ruleProvider", "ads", "adblock")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	for _, want := range []string{
		"    - RULE-SET,adblock,fake-ip\n", "    - DOMAIN,ads,real-ip\n",
		"ipcidr: [rule-set:ads]", "domain: [rule-set:ads]",
		`"rule-set:adblock": tls://8.8.8.8#Old`, "route-address-set: [adblock]",
		"      - AND,((RULE-SET,adblock),(DST-PORT,443))\n", "  - SUB-RULE,(AND,((RULE-SET,adblock),(NETWORK,TCP))),Old\n",
		"payload: [ads.test]",
	} {
		if !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q in:\n%s", want, answer.Text)
		}
	}
}

func TestRenameProxyGroupAudit(t *testing.T) {
	answer := runRename(t, renameAuditFixture, "proxyGroup", "Old", "New")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	for _, want := range []string{
		"https://1.1.1.1/dns-query#New&h3=true", "tls://8.8.8.8#New", "    proxy: New\n", "reality-config: {proxy: New}",
		"handshake: {proxy: New}", "example.com: {proxy: New}", "realm-opts: {proxy: New}", "dialer-proxy: New}",
		"  - DOMAIN-REGEX,^a,b$,New\n",
		"  - SUB-RULE,(AND,((RULE-SET,ads),(NETWORK,TCP))),Old\n", "  Old:\n",
	} {
		if !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q in:\n%s", want, answer.Text)
		}
	}
	if answer.Changed != 10 {
		t.Errorf("changed %d:\n%s", answer.Changed, answer.Text)
	}
	escaped := runRename(t, renameAuditFixture, "proxyGroup", "Old", "50%")
	if !escaped.OK || !strings.Contains(escaped.Text, "#50%25&h3=true") {
		t.Errorf("%+v", escaped)
	}
}

func TestRenameReferencesAuditRefusals(t *testing.T) {
	withExpr := "proxy-providers:\n  p:\n    type: http\n    url: https://example.com/p\n    override:\n      override-expr:\n        - '.dialer-proxy = \"Old\"'\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT]}\n"
	withProvider := "proxy-providers:\n  p: {type: http, url: https://example.com/p}\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT], use: [p]}\n  - {name: G, type: select, proxies: [DIRECT]}\n"
	for _, c := range []struct{ original, kind, oldName, newName, code string }{
		{withExpr, "proxyGroup", "Old", "New", "unsafeReference"},
		{withProvider, "proxyGroup", "Old", "p", "invalidRequest"},
		{withProvider, "proxyProvider", "p", "G", "invalidRequest"},
		{withProvider, "proxyProvider", "p", "default", "invalidRequest"},
		{withProvider, "proxyGroup", "Old", "rules", "invalidRequest"},
	} {
		if answer := runRename(t, c.original, c.kind, c.oldName, c.newName); answer.OK || answer.Code != c.code {
			t.Errorf("%s %s -> %s: %+v, want %s", c.kind, c.oldName, c.newName, answer, c.code)
		}
	}
}

func TestRenameReferencesOverrideExprRefusalNamesTheExpression(t *testing.T) {
	withExpr := "proxy-providers:\n  p:\n    type: http\n    url: https://example.com/p\n    override:\n      override-expr:\n        - '.dialer-proxy = \"Old\"'\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT]}\n"
	answer := runRename(t, withExpr, "proxyGroup", "Old", "New")
	if answer.Message != `proxy-providers.p.override.override-expr[0] (line 7) names "Old" and cannot be rewritten` {
		t.Errorf("%+v", answer)
	}
}

func TestRenameReferencesFableRound1(t *testing.T) {
	if answer := runRename(t, renameFixture, "proxyGroup", "Proxy", "A=B"); answer.OK || answer.Code != "invalidRequest" {
		t.Errorf("= in a group name: %+v", answer)
	}
	original := "proxy-providers:\n  p:\n    Type: http\n    URL: https://example.com/p\n    Proxy: Old\n    Dialer-Proxy: Old\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT]}\n"
	answer := runRename(t, original, "proxyGroup", "Old", "New")
	if !answer.OK || !strings.Contains(answer.Text, "    Proxy: New\n    Dialer-Proxy: New\n") {
		t.Errorf("%+v", answer)
	}
}

func TestRenameRuleSetNamesWhereUpstreamReadsThem(t *testing.T) {
	original := "rule-providers:\n  ads: {type: inline, behavior: domain, payload: [a.test]}\ndns:\n  nameserver-policy:\n    \"rule-set:ads,cn:x\": 1.1.1.1\n    \"rule-set:ads:x\": 8.8.8.8\n  fake-ip-filter:\n    - \"rule-set:ads:tail\"\n"
	answer := runRename(t, original, "ruleProvider", "ads", "adblock")
	for _, want := range []string{`"rule-set:adblock,cn:x": 1.1.1.1`, `"rule-set:ads:x": 8.8.8.8`, `- "rule-set:adblock:tail"`} {
		if !answer.OK || !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q: %+v", want, answer)
		}
	}
}

func TestRenameReferencesCodexRound1(t *testing.T) {
	original := "dns:\n  nameserver: [\"8.8.8.8:53#Old\"]\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT]}\n"
	if answer := runRename(t, original, "proxyGroup", "Old", "New"); !answer.OK || !strings.Contains(answer.Text, `"8.8.8.8:53#New"`) {
		t.Errorf("udp form: %+v", answer)
	}
	escaped := "dns:\n  nameserver: [\"https://1.1.1.1/dns-query#Old%26h3=true\"]\nproxy-groups:\n  - {name: Old, type: select, proxies: [DIRECT]}\n"
	if answer := runRename(t, escaped, "proxyGroup", "Old", "New"); answer.OK || answer.Code != "unsafeReference" {
		t.Errorf("escaped &: %+v", answer)
	}
	folded := "proxy-providers:\n  old: {type: http, url: https://example.com/p}\nproxy-groups:\n  - {name: G, type: select, Use: [old], Proxies: [DIRECT]}\n"
	if answer := runRename(t, folded, "proxyProvider", "old", "new"); !answer.OK || !strings.Contains(answer.Text, "Use: [new]") {
		t.Errorf("Use: %+v", answer)
	}
	regex := "rule-providers:\n  ads: {type: inline, behavior: domain, payload: [a.test]}\nrules:\n  - AND,((PROCESS-NAME-REGEX,(RULE-SET,ads)),(NETWORK,tcp)),DIRECT\n  - AND,((RULE-SET,ads),(NETWORK,tcp)),DIRECT\n  - AND, ( ( RULE-SET , ads ) , (NETWORK,tcp) ) ,DIRECT\n"
	answer := runRename(t, regex, "ruleProvider", "ads", "adblock")
	for _, want := range []string{"(PROCESS-NAME-REGEX,(RULE-SET,ads))", "AND,((RULE-SET,adblock),(NETWORK,tcp)),DIRECT", "( ( RULE-SET , adblock ) , (NETWORK,tcp) )"} {
		if !answer.OK || !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q: %+v", want, answer)
		}
	}
}

func TestRenameReferencesRefusesCaseAmbiguousFields(t *testing.T) {
	original := "proxy-providers:\n  old: {type: http, url: https://example.com/p}\nproxy-groups:\n  - {name: G, type: select, Use: [old], USE: [old]}\n"
	if answer := runRename(t, original, "proxyProvider", "old", "new"); answer.OK || answer.Code != "unsafeReference" {
		t.Errorf("%+v", answer)
	}
	two := "rule-providers:\n  ads: {type: inline, behavior: domain, payload: [a.test]}\n  ADS: {type: inline, behavior: domain, payload: [b.test]}\nrules:\n  - RULE-SET,ads,REJECT\n"
	if answer := runRename(t, two, "ruleProvider", "ads", "adblock"); !answer.OK {
		t.Errorf("%+v", answer)
	}
}

func TestRenameReferencesNumericReferences(t *testing.T) {
	original := "proxy-groups:\n  - {name: \"16\", type: select, proxies: [DIRECT]}\n  - {name: G, type: select, proxies: [0x10, DIRECT]}\n"
	answer := runRename(t, original, "proxyGroup", "16", "New")
	if !answer.OK || !strings.Contains(answer.Text, "proxies: [New, DIRECT]") {
		t.Errorf("%+v", answer)
	}
}

func TestRenameProxyGroupFollowsDefaultSelected(t *testing.T) {
	original := "proxy-groups:\n  - {name: Old, type: select, proxies: [REJECT]}\n  - {name: Entry, type: select, proxies: [DIRECT, Old], default-selected: Old}\nrules:\n  - MATCH,Entry\n"
	answer := runRename(t, original, "proxyGroup", "Old", "New")
	if !answer.OK || !strings.Contains(answer.Text, "proxies: [DIRECT, New], default-selected: New}") {
		t.Errorf("%+v", answer)
	}
}

const renameProxyFixture = `dns:
  enable: true
  nameserver:
    - https://1.1.1.1/dns-query#HK
    - ts://HK
    - easytier://HK#HK
  nameserver-policy:
    "+.corp.test": [tailscale://HK]
ntp:
  enable: true
  dialer-proxy: HK
proxies:
  - {name: HK, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}
  - {name: JP, type: ss, server: 192.0.2.2, port: 1, cipher: aes-128-gcm, password: p, dialer-proxy: HK}
proxy-providers:
  sub:
    type: http
    url: https://example.com/sub
    proxy: HK
    override: {dialer-proxy: HK}
rule-providers:
  ads: {type: http, behavior: domain, url: "https://example.com/ads.yaml", proxy: HK}
listeners:
  - {name: in, type: mixed, port: 7891, proxy: HK}
tunnels:
  - tcp/udp,127.0.0.1:6553,114.114.114.114:53,HK
  - {network: [tcp], address: "127.0.0.1:7777", target: "1.1.1.1:80", proxy: HK}
proxy-groups:
  - {name: Main, type: select, proxies: [HK, JP], default-selected: HK}
  - {name: Auto, type: url-test, include-all-proxies: true, filter: HK, empty-fallback: HK}
rules:
  - DOMAIN,x.test,HK
  - MATCH,Main
sub-rules:
  s1:
    - DOMAIN,y.test,HK
`

func TestRenameProxyEverywhere(t *testing.T) {
	answer := runRename(t, renameProxyFixture, "proxy", "HK", "HK-01")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	for _, want := range []string{
		"    - https://1.1.1.1/dns-query#HK-01\n", "    - ts://HK-01\n", "    - easytier://HK-01#HK-01\n",
		`"+.corp.test": [tailscale://HK-01]`, "  dialer-proxy: HK-01\n", "  - {name: HK-01, type: ss,",
		"password: p, dialer-proxy: HK-01}", "    proxy: HK-01\n", "override: {dialer-proxy: HK-01}",
		`url: "https://example.com/ads.yaml", proxy: HK-01}`, "port: 7891, proxy: HK-01}",
		"114.114.114.114:53,HK-01\n", `target: "1.1.1.1:80", proxy: HK-01}`,
		"proxies: [HK-01, JP], default-selected: HK-01}", "filter: HK, empty-fallback: HK-01}",
		"  - DOMAIN,x.test,HK-01\n", "  - MATCH,Main\n", "    - DOMAIN,y.test,HK-01\n",
	} {
		if !strings.Contains(answer.Text, want) {
			t.Errorf("missing %q in:\n%s", want, answer.Text)
		}
	}
	if answer.Changed != 18 {
		t.Errorf("changed %d:\n%s", answer.Changed, answer.Text)
	}
	numeric := "proxies:\n  - {Name: 16, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\nproxy-groups:\n  - {name: G, type: select, proxies: [16]}\n"
	if answer := runRename(t, numeric, "proxy", "16", "HK"); !answer.OK || !strings.Contains(answer.Text, "{Name: HK, type: ss") || !strings.Contains(answer.Text, "proxies: [HK]}") {
		t.Errorf("%+v", answer)
	}
	userinfo := "dns:\n  nameserver: [ts://user@HK/path]\nproxies:\n  - {name: HK, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n"
	if answer := runRename(t, userinfo, "proxy", "HK", "HK-01"); !answer.OK || !strings.Contains(answer.Text, "[ts://user@HK-01/path]") {
		t.Errorf("%+v", answer)
	}
}

func TestRenameProxyRefusals(t *testing.T) {
	duplicate := "proxies:\n  - {name: HK, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\nproxy-groups:\n  - {name: HK, type: select, proxies: [DIRECT]}\n"
	withExpr := "proxy-providers:\n  p:\n    type: http\n    url: https://example.com/p\n    override:\n      override-expr:\n        - '.dialer-proxy = \"HK\"'\nproxies:\n  - {name: HK, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n"
	escaped := "dns:\n  nameserver: [ts://%E9%A6%99%E6%B8%AF]\nproxies:\n  - {name: 香港, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n"
	for _, c := range []struct{ original, kind, oldName, newName, code string }{
		{renameProxyFixture, "proxy", "HK", "JP", "invalidRequest"},
		{renameProxyFixture, "proxy", "HK", "Main", "invalidRequest"},
		{renameProxyFixture, "proxy", "HK", "global", "invalidRequest"},
		{renameProxyFixture, "proxy", "HK", "Rules", "invalidRequest"},
		{renameProxyFixture, "proxy", "HK", "a,b", "invalidRequest"},
		{renameProxyFixture, "proxy", "HK", "Hong Kong", "invalidRequest"},
		{renameProxyFixture, "proxy", "Main", "X", "notFound"},
		{renameProxyFixture, "proxyGroup", "HK", "X", "notFound"},
		{duplicate, "proxy", "HK", "X", "invalidRequest"},
		{duplicate, "proxyGroup", "HK", "X", "invalidRequest"},
		{withExpr, "proxy", "HK", "X", "unsafeReference"},
		{escaped, "proxy", "香港", "HK", "unsafeReference"},
	} {
		if answer := runRename(t, c.original, c.kind, c.oldName, c.newName); answer.OK || answer.Code != c.code {
			t.Errorf("%s %s -> %s: %+v, want %s", c.kind, c.oldName, c.newName, answer, c.code)
		}
	}
	plain := strings.Replace(renameProxyFixture, "    - ts://HK\n    - easytier://HK#HK\n", "", 1)
	plain = strings.Replace(plain, `    "+.corp.test": [tailscale://HK]`+"\n", `    "+.corp.test": [223.5.5.5]`+"\n", 1)
	if answer := runRename(t, plain, "proxy", "HK", "Hong Kong"); !answer.OK || !strings.Contains(answer.Text, "{name: Hong Kong, type: ss") {
		t.Errorf("%+v", answer)
	}
	if answer := runRename(t, renameProxyFixture, "proxy", "HK", "sub"); !answer.OK {
		t.Errorf("a provider's key: %+v", answer)
	}
}

func TestRenamePolicyNamesWithParentheses(t *testing.T) {
	setupConfigPipelineTest(t)
	text := "dns:\n  enable: true\n  nameserver: [https://1.1.1.1/dns-query#HK]\nproxies:\n  - {name: HK, type: socks5, server: 192.0.2.1, port: 1080}\n" +
		"proxy-groups:\n  - {name: G, type: select, proxies: [HK]}\nrules:\n  - AND,((DOMAIN,b.test),(NETWORK,tcp)),HK\n  - NOT,((DOMAIN,c.test)),G\n  - MATCH,G\n"
	answer := runRename(t, text, "proxy", "HK", "HK (IPLC)")
	if !answer.OK {
		t.Fatalf("%+v", answer)
	}
	answer = runRename(t, answer.Text, "proxyGroup", "G", "(main) G")
	if !answer.OK || !strings.Contains(answer.Text, "AND,((DOMAIN,b.test),(NETWORK,tcp)),HK (IPLC)\n") || !strings.Contains(answer.Text, "NOT,((DOMAIN,c.test)),(main) G\n") {
		t.Fatalf("%+v", answer)
	}
	cfg, err := parseConfigForIOS(answer.Text, true)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{}
	for _, rule := range cfg.Rules {
		targets[rule.Adapter()] = true
	}
	if !targets["HK (IPLC)"] || !targets["(main) G"] || cfg.DNS.NameServer[0].ProxyName != "HK (IPLC)" {
		t.Errorf("rules %v, dns %q", targets, cfg.DNS.NameServer[0].ProxyName)
	}
}

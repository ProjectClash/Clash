package clash

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/config"
)

func TestNormalizeRawConfigForIOS(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.GeodataLoader = "standard"
	raw.GeoAutoUpdate = true

	normalizeRawConfigForIOS(raw, false)

	if raw.GeodataLoader != "memconservative" || raw.GeoAutoUpdate {
		t.Fatalf("unsafe geodata settings survived: loader=%q update=%v", raw.GeodataLoader, raw.GeoAutoUpdate)
	}
	if raw.GeoXUrl.GeoIp != disabledGeoURL || raw.GeoXUrl.GeoSite != disabledGeoURL {
		t.Fatal("geodata network URLs must be fail-closed")
	}
}

func TestNormalizeRawNetworkExtensionSurfacesBeforeParse(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.MixedPort = 10801
	raw.AllowLan = true
	raw.InboundTfo = true
	raw.InboundMPTCP = true
	raw.Interface = "en0"
	raw.RoutingMark = 666
	raw.FindProcessMode = process.FindProcessStrict
	raw.Tun.AutoRedirect = true
	raw.Tun.IPRoute2TableIndex = 100
	raw.Tun.AutoRedirectInputMark = 42
	raw.Tun.IncludeInterface = []string{"en0"}
	raw.Tun.ExcludeInterface = []string{"en1"}
	raw.Tun.IncludeUID = []uint32{501}
	raw.Tun.ExcludeUID = []uint32{0}
	raw.Tun.IncludeUIDRange = []string{"1000:2000"}
	raw.Tun.ExcludeSrcPort = []uint16{53}
	raw.Tun.ExcludeDstPort = []uint16{443}
	raw.Tun.ExcludeDstPortRange = []string{"3000:4000"}
	raw.Tun.IncludeAndroidUser = []int{0}
	raw.Tun.IncludePackage = []string{"com.example.app"}
	raw.Tun.ExcludePackage = []string{"com.example.other"}
	raw.Tun.IncludeMACAddress = []string{"00:11:22:33:44:55"}
	raw.Tun.ExcludeMACAddress = []string{"66:77:88:99:aa:bb"}
	raw.ExternalUI = "ui"
	raw.ExternalController = "0.0.0.0:9090"
	raw.ExternalControllerUnix = "user.sock"
	raw.Secret = "must-not-survive"
	raw.Listeners = []map[string]any{{"name": "server", "type": "unsupported-test-listener"}}
	raw.DNS.Listen = "0.0.0.0:53"
	raw.DNS.ListenRoutingMark = 666
	raw.NTP.WriteToSystem = true
	raw.Proxy = []map[string]any{{"name": "probe", "type": "socks5", "server": "127.0.0.1", "port": 1080}}
	raw.Rule = []string{"MATCH,probe"}

	normalizeRawConfigForIOS(raw, true)

	if raw.MixedPort != 10801 || !raw.InboundTfo || !raw.InboundMPTCP {
		t.Fatalf("the local proxy surface was stripped: mixed-port=%d tfo=%v mptcp=%v",
			raw.MixedPort, raw.InboundTfo, raw.InboundMPTCP)
	}
	if !raw.AllowLan {
		t.Fatal("allow-lan was cleared although the app never forced it off")
	}
	if raw.ExternalController == "" || raw.Secret == "" {
		t.Fatalf("the RESTful API surface was stripped: controller=%q secret set=%v",
			raw.ExternalController, raw.Secret != "")
	}
	if raw.ExternalUI == "" {
		t.Fatal("external-ui was stripped; upstream keeps it and the platform permits it")
	}
	if raw.Interface != "" || raw.RoutingMark != 0 {
		t.Fatalf("Apple-owned egress surface survived: interface=%q mark=%d", raw.Interface, raw.RoutingMark)
	}
	if raw.FindProcessMode != process.FindProcessOff {
		t.Fatalf("find-process-mode not neutralized to Off: %v", raw.FindProcessMode)
	}
	if !raw.Tun.AutoRedirect || raw.Tun.IPRoute2TableIndex != 100 || raw.Tun.AutoRedirectInputMark != 42 ||
		len(raw.Tun.IncludeInterface) != 1 || len(raw.Tun.ExcludeInterface) != 1 ||
		len(raw.Tun.IncludeUID) != 1 || len(raw.Tun.ExcludeUID) != 1 || len(raw.Tun.IncludeUIDRange) != 1 ||
		len(raw.Tun.ExcludeSrcPort) != 1 || len(raw.Tun.ExcludeDstPort) != 1 || len(raw.Tun.ExcludeDstPortRange) != 1 ||
		len(raw.Tun.IncludeAndroidUser) != 1 || len(raw.Tun.IncludePackage) != 1 || len(raw.Tun.ExcludePackage) != 1 ||
		len(raw.Tun.IncludeMACAddress) != 1 || len(raw.Tun.ExcludeMACAddress) != 1 {
		t.Fatalf("a tun filter or Linux routing knob was changed by NE normalization: %#v", raw.Tun)
	}
	if len(raw.Listeners) == 0 {
		t.Fatal("the listener catalogue was stripped; upstream allows it and so do we")
	}
	if len(raw.Proxy) != 1 || len(raw.Rule) != 1 {
		t.Fatal("data-plane proxy/rule configuration must survive NE normalization")
	}
	if raw.NTP.WriteToSystem {
		t.Fatal("Network Extension must not write the device clock")
	}
}

func TestNormalizeRawConfigForIOSKeepsMetadataRulesInPlace(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,curl,REJECT
  - DOMAIN,second.example,REJECT
  - UID,501,REJECT
  - IN-USER,alice,REJECT
  - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
  - MATCH,DIRECT
sub-rules:
  child:
    - DOMAIN,child-first.example,DIRECT
    - UID,501,REJECT
    - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
    - DOMAIN,child-second.example,REJECT
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - PROCESS-NAME,curl
      - DOMAIN,provider.example
      - IN-USER,alice
      - SOURCE-APP-SIGNING-ID,com.example.cli
      - SOURCE-APP-TEAM-ID,ABCDE12345
`))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)
	wantRules := []string{
		"DOMAIN,first.example,DIRECT",
		"PROCESS-NAME,curl,REJECT",
		"DOMAIN,second.example,REJECT",
		"IN-USER,alice,REJECT",
		"SOURCE-APP-SIGNING-ID,com.example.cli,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, wantRules) {
		t.Fatalf("rules after normalize = %v, want every rule kept in order %v", raw.Rule, wantRules)
	}
	wantSubRules := []string{
		"DOMAIN,child-first.example,DIRECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"DOMAIN,child-second.example,REJECT",
	}
	if !reflect.DeepEqual(raw.SubRules["child"], wantSubRules) {
		t.Fatalf("sub-rules after normalize = %v, want every rule kept in order %v", raw.SubRules["child"], wantSubRules)
	}
	payload, ok := raw.RuleProvider["inline"]["payload"].([]any)
	wantPayload := []any{
		"PROCESS-NAME,curl", "DOMAIN,provider.example", "IN-USER,alice",
		"SOURCE-APP-SIGNING-ID,com.example.cli", "SOURCE-APP-TEAM-ID,ABCDE12345",
	}
	if !ok || !reflect.DeepEqual(payload, wantPayload) {
		t.Fatalf("inline provider after normalize = %#v, want every entry kept", raw.RuleProvider["inline"]["payload"])
	}
	if summaries := summarizeMetadataRuleOccurrences(raw, nePolicy().processMetadata()); len(summaries) == 0 {
		t.Fatal("the kept metadata rules must still be reported to the reader")
	}
}

func TestNormalizeStripsNEIncompatibleNameservers(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5", "system", "dhcp://en0"}
	raw.DNS.Fallback = []string{"system://", "8.8.8.8"}
	raw.DNS.ProxyServerNameserver = []string{"system"}
	raw.DNS.DirectNameServer = []string{"114.114.114.114", "dhcp://system"}
	raw.DNS.DefaultNameserver = []string{"223.5.5.5", "system"}

	normalizeRawConfigForIOS(raw, true)

	if got := raw.DNS.NameServer; len(got) != 1 || got[0] != "223.5.5.5" {
		t.Fatalf("nameserver system/dhcp not stripped: %v", got)
	}
	if got := raw.DNS.Fallback; len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("fallback system not stripped: %v", got)
	}
	if len(raw.DNS.ProxyServerNameserver) != 0 {
		t.Fatalf("proxy-server-nameserver system not stripped: %v", raw.DNS.ProxyServerNameserver)
	}
	if got := raw.DNS.DirectNameServer; len(got) != 1 || got[0] != "114.114.114.114" {
		t.Fatalf("direct-nameserver dhcp not stripped: %v", got)
	}
	if got := raw.DNS.DefaultNameserver; len(got) != 1 || got[0] != "223.5.5.5" {
		t.Fatalf("default-nameserver system not stripped while a usable IP remains: %v", got)
	}
}

func TestNormalizeRealBootstrapStripsSystemKeepsIPs(t *testing.T) {
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system", "180.76.76.76", "182.254.118.118", "8.8.8.8", "180.184.2.2", "2400:3200::1"}

	normalizeRawConfigForIOS(raw, true)

	want := []string{"180.76.76.76", "182.254.118.118", "8.8.8.8", "180.184.2.2", "2400:3200::1"}
	got := raw.DNS.DefaultNameserver
	if len(got) != len(want) {
		t.Fatalf("bootstrap not stripped to the 5 IPs: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bootstrap entry %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestAllSystemBootstrapPassesStripSilentlyThenRepairReports(t *testing.T) {
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system"}

	stripped := stripNEIncompatibleNameservers(raw)
	for _, entry := range stripped {
		if strings.Contains(entry, "default-nameserver") {
			t.Fatalf("the strip must not claim the bootstrap entry: %v", stripped)
		}
	}
	if got := raw.DNS.DefaultNameserver; len(got) != 1 || got[0] != "system" {
		t.Fatalf("strip stage must hand the bootstrap through verbatim, got: %v", got)
	}

	repairs := repairApplePacketTunnelDNS(raw)
	reported := false
	for _, repair := range repairs {
		if strings.Contains(repair, "default-nameserver") && strings.Contains(repair, "replaced") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the repair must report the substitution: %v", repairs)
	}
	want := config.DefaultRawConfig().DNS.DefaultNameserver
	if strings.Join(raw.DNS.DefaultNameserver, ",") != strings.Join(want, ",") {
		t.Fatalf("bootstrap after repair = %v, want mihomo defaults %v", raw.DNS.DefaultNameserver, want)
	}
}

func TestNormalizeKeepsNECompatibleDNSTypes(t *testing.T) {
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	compatible := []string{
		"1.1.1.1", "udp://8.8.8.8", "tcp://9.9.9.9", "tls://223.5.5.5",
		"https://1.1.1.1/dns-query", "quic://8.8.4.4", "tailscale://ts-node",
		"rcode://success", "https://dns.google/dns-query",
		"https://1.1.1.1/dns-query#system",
	}
	raw.DNS.NameServer = append([]string(nil), compatible...)
	raw.DNS.Fallback = []string{"system", "tls://1.1.1.1", "dhcp://en0"}
	normalizeRawConfigForIOS(raw, true)
	if strings.Join(raw.DNS.NameServer, ",") != strings.Join(compatible, ",") {
		t.Errorf("NE-compatible DNS types must survive unchanged, got: %v", raw.DNS.NameServer)
	}
	if got := raw.DNS.Fallback; len(got) != 1 || got[0] != "tls://1.1.1.1" {
		t.Errorf("only system/dhcp must be stripped from fallback (tls kept), got: %v", got)
	}
}

func TestIsUsableBootstrapNameserver(t *testing.T) {
	cases := map[string]bool{
		"223.5.5.5": true, "223.5.5.5:53": true, "8.8.8.8": true,
		"2400:3200::1": true, "[2400:3200::1]:53": true,
		"tls://223.5.5.5": true, "udp://8.8.8.8:53": true,
		"https://1.1.1.1/dns-query": true, "tls://1.1.1.1:853": true,
		"quic://[2400:3200::1]:853": true, "https://[2606:4700:4700::1111]/dns-query": true,
		"system": false, "system://": false, "dhcp://en0": false,
		"": false, "   ": false, ":53": false, "udp://:53": false,
		"dns.google": false, "https://dns.google/dns-query": false,
	}
	for in, want := range cases {
		if got := isUsableBootstrapNameserver(in); got != want {
			t.Errorf("isUsableBootstrapNameserver(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeBootstrapRequiresUsableIP(t *testing.T) {
	defaults := config.DefaultRawConfig().DNS.DefaultNameserver
	for _, tc := range []struct {
		in   []string
		want []string
	}{
		{[]string{"system", ""}, []string{""}},
		{[]string{"system", "udp://:53"}, []string{"udp://:53"}},
		{[]string{"system", "dhcp://en0"}, defaults},
		{[]string{"system"}, defaults},
	} {
		raw := &config.RawConfig{}
		raw.DNS.Enable = true
		raw.DNS.NameServer = []string{"223.5.5.5"}
		raw.DNS.DefaultNameserver = append([]string(nil), tc.in...)
		normalizeRawConfigForIOS(raw, true)
		if strings.Join(raw.DNS.DefaultNameserver, ",") != strings.Join(tc.want, ",") {
			t.Errorf("bootstrap %v became %v, want %v", tc.in, raw.DNS.DefaultNameserver, tc.want)
		}
	}
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system", "8.8.8.8"}
	normalizeRawConfigForIOS(raw, true)
	got := raw.DNS.DefaultNameserver
	if len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("bootstrap with a usable IP must strip system and keep the IP, got %v", got)
	}
}

func TestNormalizeKeepsOutboundEgressOverrides(t *testing.T) {
	content := `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0, routing-mark: 233}
proxy-groups:
  - {name: group, type: select, proxies: [node], interface-name: en1}
proxy-providers:
  inline:
    type: inline
    payload:
      - {name: pnode, type: socks5, server: 127.0.0.1, port: 1081, routing-mark: 7}
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)

	if raw.Proxy[0]["interface-name"] != "en0" {
		t.Fatalf("proxy interface-name was changed: %v", raw.Proxy[0])
	}
	if _, ok := raw.Proxy[0]["routing-mark"]; !ok {
		t.Fatalf("proxy routing-mark was removed: %v", raw.Proxy[0])
	}
	if raw.ProxyGroup[0]["interface-name"] != "en1" {
		t.Fatalf("group interface-name was changed: %v", raw.ProxyGroup[0])
	}
	payload := providerPayloadMappings(raw.ProxyProvider["inline"]["payload"])
	if len(payload) != 1 {
		t.Fatalf("provider payload missing after normalize: %v", raw.ProxyProvider["inline"])
	}
	if _, ok := payload[0]["routing-mark"]; !ok {
		t.Fatalf("provider payload routing-mark was removed: %v", payload[0])
	}
}

func TestParseConfigForNetworkExtensionIgnoresNonRoutingServerCatalog(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mixed-port: 10801
allow-lan: true
external-controller: 0.0.0.0:9090
external-controller-unix: user.sock
external-ui: ui
secret: do-not-expose
listeners:
  - name: invalid-server
    type: mixed
    port: 7899
tunnels:
  - tcp,127.0.0.1:6553,example.com:53,probe
dns:
  enable: true
  listen: 0.0.0.0:53
  listen-routing-mark: 666
  nameserver: [1.1.1.1]
ntp:
  enable: true
  server: time.apple.com
  port: 123
  interval: 30
  write-to-system: true
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
rules:
  - MATCH,probe
`, true)
	if err != nil {
		t.Fatalf("a valid listener catalogue must parse: %v", err)
	}
	if cfg.General.MixedPort == 0 {
		t.Fatalf("the local proxy surface did not reach the parsed config: general=%+v", cfg.General)
	}
	if !cfg.General.AllowLan {
		t.Fatal("allow-lan was cleared although the app never forced it off")
	}
	if cfg.General.Interface != "" || cfg.General.RoutingMark != 0 || cfg.DNS.ListenRoutingMark != 0 {
		t.Fatalf("parsed NE surface not closed: general=%+v dns=%+v", cfg.General, cfg.DNS)
	}
	if cfg.DNS.Listen != "0.0.0.0:53" {
		t.Fatalf("dns.listen did not reach the parsed config: %q", cfg.DNS.Listen)
	}
	if cfg.NTP == nil || !cfg.NTP.Enable || cfg.NTP.WriteToSystem {
		t.Fatalf("NTP offset service must survive without system-clock writes: %+v", cfg.NTP)
	}
	if len(cfg.Listeners) == 0 || len(cfg.Tunnels) == 0 {
		t.Fatalf("the listener/tunnel catalogue was stripped: %v / %v", cfg.Listeners, cfg.Tunnels)
	}
	if _, ok := cfg.Proxies["probe"]; !ok {
		t.Fatal("outbound proxy was removed with server surfaces")
	}
}

func TestParseConfigForNetworkExtensionPreservesCoreCatalog(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mode: rule
ipv6: true
unified-delay: true
tcp-concurrent: true
profile:
  store-selected: true
  store-fake-ip: true
hosts:
  example.internal: 192.0.2.1
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  nameserver-policy:
    "domain:example.com": [tls://1.1.1.1:853]
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
proxy-providers:
  local-proxies:
    type: inline
    payload:
      - {name: provider-probe, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - name: SELECT
    type: select
    use: [local-proxies]
  - name: URL-TEST
    type: url-test
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
  - name: FALLBACK
    type: fallback
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
  - name: LOAD-BALANCE
    type: load-balance
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
    strategy: round-robin
rule-providers:
  local-rules:
    type: inline
    behavior: domain
    payload: [+.example.com]
sub-rules:
  private:
    - DOMAIN-SUFFIX,internal,DIRECT
    - MATCH,SELECT
ntp:
  enable: true
  server: time.apple.com
  port: 123
  interval: 30
  dialer-proxy: SELECT
  write-to-system: true
experimental:
  quic-go-disable-gso: true
  quic-go-disable-ecn: true
rules:
  - SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),private
  - RULE-SET,local-rules,SELECT
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("core catalog parse failed: %v", err)
	}
	for _, name := range []string{"SELECT", "URL-TEST", "FALLBACK", "LOAD-BALANCE"} {
		if _, ok := cfg.Proxies[name]; !ok {
			t.Errorf("proxy group %q was removed", name)
		}
	}
	if _, ok := cfg.Providers["local-proxies"]; !ok {
		t.Fatal("inline proxy provider was removed")
	}
	if _, ok := cfg.RuleProviders["local-rules"]; !ok {
		t.Fatal("inline rule provider was removed")
	}
	if len(cfg.SubRules["private"]) != 2 || len(cfg.Rules) != 3 {
		t.Fatalf("rules/sub-rules were not preserved: rules=%d sub=%d", len(cfg.Rules), len(cfg.SubRules["private"]))
	}
	if cfg.DNS == nil || cfg.DNS.FakeIPPool == nil || len(cfg.DNS.NameServerPolicy) != 1 {
		t.Fatalf("DNS policy/fake-IP was not preserved: %+v", cfg.DNS)
	}
	if cfg.Sniffer == nil || !cfg.Sniffer.Enable {
		t.Fatalf("sniffer was not preserved: %+v", cfg.Sniffer)
	}
	if cfg.Profile == nil || !cfg.Profile.StoreSelected || !cfg.Profile.StoreFakeIP {
		t.Fatalf("profile settings were not preserved/normalized: %+v", cfg.Profile)
	}
	if cfg.NTP == nil || !cfg.NTP.Enable || cfg.NTP.DialerProxy != "SELECT" || cfg.NTP.WriteToSystem {
		t.Fatalf("NTP data plane was not preserved safely: %+v", cfg.NTP)
	}
	if cfg.Experimental == nil || !cfg.Experimental.QUICGoDisableGSO || !cfg.Experimental.QUICGoDisableECN {
		t.Fatalf("experimental transport settings were not preserved: %+v", cfg.Experimental)
	}
}

func TestParseConfigForIOSLoadsClientStagedFileProviders(t *testing.T) {
	working := setupConfigPipelineTest(t)
	providers := filepath.Join(working, "providers")
	if err := os.MkdirAll(providers, 0o700); err != nil {
		t.Fatalf("mkdir providers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(providers, "proxies.yaml"), []byte(`
proxies:
  - {name: file-probe, type: socks5, server: 127.0.0.1, port: 1080}
`), 0o600); err != nil {
		t.Fatalf("write proxy provider: %v", err)
	}
	if err := os.WriteFile(filepath.Join(providers, "rules.yaml"), []byte(`
payload:
  - +.example.org
`), 0o600); err != nil {
		t.Fatalf("write rule provider: %v", err)
	}

	cfg, err := parseConfigForIOS(`
dns:
  enable: true
  nameserver: [1.1.1.1]
proxy-providers:
  staged-proxies:
    type: file
    path: ./providers/proxies.yaml
proxy-groups:
  - name: SELECT
    type: select
    use: [staged-proxies]
rule-providers:
  staged-rules:
    type: file
    behavior: domain
    path: ./providers/rules.yaml
rules:
  - RULE-SET,staged-rules,SELECT
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse staged providers: %v", err)
	}
	proxyProvider := cfg.Providers["staged-proxies"]
	if proxyProvider == nil {
		t.Fatal("staged proxy provider missing")
	}
	if err := proxyProvider.Initial(); err != nil {
		t.Fatalf("load staged proxy provider: %v", err)
	}
	if proxyProvider.Count() != 1 {
		t.Fatalf("staged proxy count = %d, want 1", proxyProvider.Count())
	}
	ruleProvider := cfg.RuleProviders["staged-rules"]
	if ruleProvider == nil {
		t.Fatal("staged rule provider missing")
	}
	if err := ruleProvider.Initial(); err != nil {
		t.Fatalf("load staged rule provider: %v", err)
	}
	if ruleProvider.Count() != 1 {
		t.Fatalf("staged rule count = %d, want 1", ruleProvider.Count())
	}
}

func TestParseConfigForIOSHonorsExplicitStoreFakeIPFalse(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mode: rule
profile:
  store-fake-ip: false
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, false)
	if err != nil {
		t.Fatalf("parseConfigForIOS: %v", err)
	}
	if cfg.Profile == nil || cfg.Profile.StoreFakeIP {
		t.Fatal("explicit store-fake-ip:false must be honored, not forced to true")
	}
}

func TestParseConfigForIOSAcceptsARemoteProvider(t *testing.T) {
	setupConfigPipelineTest(t)
	if _, err := parseConfigForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.invalid/provider.yaml
    path: ./providers/remote.yaml
rules:
  - MATCH,DIRECT
`, false); err != nil {
		t.Fatalf("remote provider refused: %v", err)
	}
}

func TestParseConfigForIOSRejectsUnsafeProviderHealthCheckDurations(t *testing.T) {
	tests := map[string]string{
		"negative interval":    "interval: -1",
		"overflowing interval": "interval: 9223372037",
	}
	for name, timing := range tests {
		t.Run(name, func(t *testing.T) {
			setupConfigPipelineTest(t)
			_, err := parseConfigForIOS(`
proxy-providers:
  local:
    type: inline
    health-check:
      enable: true
      url: https://example.com/generate_204
      `+timing+`
    payload:
      - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: SELECT, type: select, use: [local]}
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,SELECT
`, true)
			if err == nil || !strings.Contains(err.Error(), "proxy-provider \"local\" health-check") {
				t.Fatalf("unsafe health-check duration error = %v", err)
			}
		})
	}
}

func TestParseConfigForIOSRejectsInvalidProxyGroupRegexWithoutPanicking(t *testing.T) {
	tests := map[string]string{
		"filter":         "filter: '('",
		"exclude-filter": "exclude-filter: '['",
	}
	for field, expression := range tests {
		t.Run(field, func(t *testing.T) {
			setupConfigPipelineTest(t)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("iOS preflight panicked for invalid %s: %v", field, recovered)
				}
			}()
			_, err := parseConfigForIOS(`
proxy-groups:
  - name: TEST
    type: url-test
    proxies: [DIRECT]
    url: https://example.com/generate_204
    `+expression+`
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,TEST
`, true)
			if err == nil || !strings.Contains(err.Error(), "proxy-groups[0]."+field) {
				t.Fatalf("invalid proxy-group %s error = %v", field, err)
			}
		})
	}
}

func TestParseConfigForIOSAllowsUnusedHysteriaHopIntervalWithoutPorts(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,HY
`, true)
	if err != nil {
		t.Fatalf("unused Hysteria hop interval was rejected: %v", err)
	}
}

func TestParseConfigForIOSAllowsUnusedHysteriaHopIntervalForNonUDPProtocol(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    ports: 443-444
    protocol: wechat-video
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,HY
`, true)
	if err != nil {
		t.Fatalf("unused non-UDP Hysteria hop interval was rejected: %v", err)
	}
}

func TestParseConfigForIOSAllowsTUICV5UnusedRequestTimeout(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: TUIC
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    password: fixture
    request-timeout: -1
    skip-cert-verify: true
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,TUIC
`, true)
	if err != nil {
		t.Fatalf("TUIC v5 unused request-timeout was rejected: %v", err)
	}
}

func TestParseConfigForIOSPreservesDisabledGlobalDurationSemantics(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
keep-alive-idle: -1
keep-alive-interval: -1
ntp:
  enable: false
  interval: 9223372036854775807
tun:
  udp-timeout: -1
  icmp-timeout: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("disabled/non-positive global duration semantics rejected: %v", err)
	}
}

func TestParseConfigForIOSIgnoresFakeIPTTLInNormalMode(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
dns:
  enable: true
  enhanced-mode: normal
  fake-ip-ttl: 9223372036854775807
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("unconsumed normal-mode fake-IP TTL rejected: %v", err)
	}
}

func TestParseConfigForIOSRejectsMissingGeodataBeforeCoreParse(t *testing.T) {
	working := setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
mode: rule
rules:
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
`, false)
	if err == nil || !strings.Contains(err.Error(), "not pre-staged") {
		t.Fatalf("missing geodata error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(working, "geoip.metadb")); !os.IsNotExist(statErr) {
		t.Fatalf("parse attempted to create/download geodata: %v", statErr)
	}
}

func setupConfigPipelineTest(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	working := filepath.Join(base, "working")
	if err := Setup(&SetupOptions{
		BasePath:    base,
		WorkingPath: working,
		TempPath:    filepath.Join(base, "temp"),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return working
}

func TestDHCPAndSystemNameserversDoNotRefuseTheConfig(t *testing.T) {
	const content = `
dns:
  enable: true
  nameserver: [223.5.5.5, "dhcp://en0", "system://"]
rules:
  - MATCH,DIRECT
`
	outside, err := parseConfigForIOS(content, false)
	if err != nil {
		t.Fatalf("dhcp://+system:// refused the config outside the extension: %v", err)
	}
	if got := len(outside.DNS.NameServer); got != 3 {
		t.Errorf("outside the extension the resolvers should be kept verbatim, got %d of 3", got)
	}

	inside, err := parseConfigForIOS(content, true)
	if err != nil {
		t.Fatalf("dhcp://+system:// refused the config inside the extension: %v", err)
	}
	if got := len(inside.DNS.NameServer); got != 1 {
		t.Fatalf("inside the extension only the explicit resolver should survive, got %d of 1", got)
	}
	if addr := inside.DNS.NameServer[0].Addr; addr != "223.5.5.5:53" {
		t.Errorf("the surviving resolver is not the explicit one: %q", addr)
	}
}

func TestStoreFakeIPAndUnifiedDelayFollowTheFileOrUpstream(t *testing.T) {
	for _, item := range []struct {
		name        string
		yaml        string
		storeFakeIP bool
		unified     bool
	}{
		{"neither written", "mode: rule\n", true, true},
		{"profile without the key", "mode: rule\nprofile:\n  store-selected: true\n", true, true},
		{"store-fake-ip merged from an anchor", "mode: rule\ndefaults: &d\n  store-fake-ip: false\nprofile:\n  <<: *d\n", false, true},
		{"both written true", "mode: rule\nunified-delay: true\nprofile:\n  store-fake-ip: true\n", true, true},
		{"both written false", "mode: rule\nunified-delay: false\nprofile:\n  store-fake-ip: false\n", false, false},
		{"merged from an anchor", "mode: rule\ndefaults: &d\n  store-fake-ip: true\nprofile:\n  <<: *d\n", true, true},
		{"unified-delay merged from an anchor", "mode: rule\ndefaults: &d\n  unified-delay: false\n<<: *d\n", true, false},
	} {
		for _, underNE := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/ne=%v", item.name, underNE), func(t *testing.T) {
				cfg, err := parseConfigForIOS(item.yaml, underNE)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if cfg.Profile.StoreFakeIP != item.storeFakeIP {
					t.Errorf("store-fake-ip = %v, want %v", cfg.Profile.StoreFakeIP, item.storeFakeIP)
				}
				if cfg.General.UnifiedDelay != item.unified {
					t.Errorf("unified-delay = %v, want %v", cfg.General.UnifiedDelay, item.unified)
				}
			})
		}
	}
}

func TestRawProfileKeepsDefaultsForKeysTheDocumentOmits(t *testing.T) {
	base, err := config.UnmarshalRawConfig([]byte("mode: rule\n"))
	if err != nil {
		t.Fatal(err)
	}
	withProfile, err := config.UnmarshalRawConfig([]byte("profile:\n  store-fake-ip: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if withProfile.Profile.StoreSelected != base.Profile.StoreSelected {
		t.Fatalf("store-selected default lost: %v != %v",
			withProfile.Profile.StoreSelected, base.Profile.StoreSelected)
	}
}

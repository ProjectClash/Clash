package clash

import (
	"encoding/json"
	"os"
	"path/filepath"

	C "github.com/ProjectClash/Clash/constant"
	"strings"
	"testing"
)

func noticeContaining(t *testing.T, r planResult, needle string) string {
	t.Helper()
	for _, notice := range r.Notices {
		if strings.Contains(notice, needle) {
			return notice
		}
	}
	return ""
}

func mustNotRefuse(t *testing.T, r planResult, what string) {
	t.Helper()
	if len(r.Errors) != 0 {
		t.Fatalf("%s refused the whole configuration: %+v", what, r.Errors)
	}
}

func TestPlanFileProviderIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  local: {type: file, path: ./nodes.yaml}
`)
	mustNotRefuse(t, r, "a file proxy-provider")
	if noticeContaining(t, r, "proxy-providers.local") == "" {
		t.Fatalf("no notice named the file provider: %+v", r.Notices)
	}
	for _, provider := range r.Providers {
		if provider.Name == "local" {
			t.Fatalf("a file provider must not enter the download plan: %+v", provider)
		}
	}
}

func TestPlanUnusableProviderURLIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
rule-providers:
  broken: {type: http, behavior: domain, url: "not a url"}
`)
	mustNotRefuse(t, r, "a malformed provider url")
	if noticeContaining(t, r, "rule-providers.broken") == "" {
		t.Fatalf("no notice named the provider: %+v", r.Notices)
	}
	for _, provider := range r.Providers {
		if provider.Name == "broken" {
			t.Fatalf("an unfetchable provider must not enter the download plan: %+v", provider)
		}
	}
}

func TestPlanNegativeSizeLimitFallsBackInsteadOfRefusing(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, size-limit: -1}
`)
	mustNotRefuse(t, r, "a negative size-limit")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if r.Providers[0].MaximumBytes != int64(maximumProviderResourceBytes) {
		t.Fatalf("size-limit did not fall back to the default: %d", r.Providers[0].MaximumBytes)
	}
	if noticeContaining(t, r, "size-limit") == "" {
		t.Fatalf("no notice for the defaulted size-limit: %+v", r.Notices)
	}
}

func TestPlanNegativeIntervalFallsBackInsteadOfRefusing(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, interval: -5}
`)
	mustNotRefuse(t, r, "a negative interval")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if r.Providers[0].UpdateIntervalSeconds != 0 {
		t.Fatalf("interval did not fall back to zero: %d", r.Providers[0].UpdateIntervalSeconds)
	}
	if noticeContaining(t, r, "interval") == "" {
		t.Fatalf("no notice for the defaulted interval: %+v", r.Notices)
	}
}

func TestPlanForbiddenHeaderIsDroppedNotRefused(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p:
    type: http
    url: https://example.com/p.yaml
    header:
      Host: [example.org]
      X-Kept: [yes]
`)
	mustNotRefuse(t, r, "a transport-controlled header")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if _, present := r.Providers[0].Headers["Host"]; present {
		t.Fatalf("Host survived into the plan: %+v", r.Providers[0].Headers)
	}
	if _, present := r.Providers[0].Headers["X-Kept"]; !present {
		t.Fatalf("the untouched header was lost with the dropped one: %+v", r.Providers[0].Headers)
	}
	if noticeContaining(t, r, "header") == "" {
		t.Fatalf("no notice for the dropped header: %+v", r.Notices)
	}
}

func TestPlanNestedDNSFragmentIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
proxies:
  - name: wg
    type: wireguard
    server: 10.0.0.1
    port: 51820
    private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    ip: 10.0.0.2/32
    remote-dns-resolve: true
    dns: ["1.1.1.1#other"]
`)
	mustNotRefuse(t, r, "a nested dns fragment")
	if noticeContaining(t, r, "dns") == "" {
		t.Fatalf("no notice for the inert fragment: %+v", r.Notices)
	}
}

func mustSurviveActivation(t *testing.T, name, configYAML string) {
	t.Helper()
	r := planOf(t, configYAML)
	if len(r.Errors) != 0 {
		t.Fatalf("%s: the plan refused it, so this gate does not apply: %+v", name, r.Errors)
	}

	dir := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	previousBreadcrumb := breadcrumbDirectory
	breadcrumbDirectory = dir
	previousRecording := breadcrumbRecording.Load()
	t.Cleanup(func() {
		breadcrumbDirectory = previousBreadcrumb
		setStartupBreadcrumbRecording(previousRecording)
	})
	paths := map[string]string{}
	for _, provider := range r.Providers {
		target := filepath.Join(dir, provider.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(target, []byte("proxies: []\npayload: []\n"), 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		paths[provider.ResourceKey] = target
		paths[provider.Name] = target
	}
	for _, geo := range r.Geodata {
		target := filepath.Join(dir, geo.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		source := filepath.Join(bundledGeoDataDir, geo.Path)
		payload, err := os.ReadFile(source)
		if err != nil {
			t.Skipf("%s: this case needs %s and this tree has no copy of it", name, geo.Path)
		}
		if err := os.WriteFile(target, payload, 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	resourceMap, err := json.Marshal(map[string]any{"providerPaths": paths})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}

	finalized, err := FinalizeForIOS(configYAML, string(resourceMap))
	if err != nil {
		t.Fatalf("%s: the plan tolerated it but FinalizeForIOS refused it: %v", name, err)
	}

	if _, _, err := parseConfigForIOSRuntime(finalized.Value, true, "gate"); err != nil {
		t.Fatalf("%s: the plan tolerated it and Finalize accepted it, but the activation path "+
			"refused it: %v\n\nA notice that says the configuration still starts must be true at "+
			"Start, not merely at Finalize.", name, err)
	}
}

func TestEveryToleratedInputSurvivesActivation(t *testing.T) {
	for name, configYAML := range map[string]string{
		"file provider": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  local: {type: file, path: ./nodes.yaml}
`,
		"negative size-limit": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, size-limit: -1}
`,
		"negative interval": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, interval: -5}
`,
		"transport-controlled header": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p:
    type: http
    url: https://example.com/p.yaml
    header:
      Host: [example.org]
      X-Kept: [yes]
`,
		"fake-ip-filter entry named system": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['223.5.5.5']
  fake-ip-filter: ['system', '+.lan']
`,
		"fallback-filter domain starting with system:": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['223.5.5.5']
  fallback: ['8.8.8.8']
  fallback-filter:
    domain: ['system:8080']
`,
		"dns.listen literally system": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['223.5.5.5']
  listen: 'system'
`,
		"system and dhcp in real resolver fields": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['system', '223.5.5.5']
  fallback: ['dhcp://en0']
`,
		"malformed provider url": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
rule-providers:
  broken: {type: http, behavior: domain, url: "not a url"}
`,
		"non-ipcidr route-address-set": `
rule-providers:
  domains: {type: inline, behavior: domain, payload: [example.com]}
tun:
  enable: true
  route-address-set: [domains]
`,
		"undefined route-address-set": `
tun:
  enable: true
  route-address-set: [nope]
`,
		"nested dns fragment": `
proxies:
  - name: wg
    type: wireguard
    server: 203.0.113.1
    port: 2408
    ip: 192.0.2.2
    private-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    public-key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			mustSurviveActivation(t, name, configYAML)
		})
	}
}

func TestHttpProviderWithNoUrlSurvivesActivation(t *testing.T) {
	for name, configYAML := range map[string]string{
		"rule provider, url absent": `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
rule-providers:
  r: {type: http, behavior: domain, format: yaml, path: ./r.yaml}
`,
		"proxy provider, url empty": `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: "", path: ./p.yaml}
`,
	} {
		t.Run(name, func(t *testing.T) { mustSurviveActivation(t, name, configYAML) })
	}
}

var (
	clientTreeRoot         = filepath.Join("..", "..", "apple", "Clash"+"Client")
	bundledGeoDataDir      = filepath.Join(clientTreeRoot, "Resources", "Bundled"+"GeoData")
	realSubscriptionCorpus = filepath.Join(clientTreeRoot, "Tests", "Fixtures", "config-corpus")
)

func TestARouteSetTheAppHasNoBytesForSurvivesActivation(t *testing.T) {
	const configYAML = `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
rule-providers:
  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/cn_ip.mrs}
tun:
  route-exclude-address-set: [cn_ip]
`
	finalized, err := FinalizeForIOS(configYAML, `{}`)
	if err != nil {
		t.Fatalf("Finalize refused a route set the App has no bytes for: %v", err)
	}
	if _, _, err := parseConfigForIOSRuntime(finalized.Value, true, "gate"); err != nil {
		t.Fatalf("Finalize accepted it, but the activation path refused it: %v", err)
	}
}

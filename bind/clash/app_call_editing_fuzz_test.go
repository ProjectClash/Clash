package clash

import (
	"path/filepath"
	"strings"
	"testing"
)

const editingDraftBase = `mixed-port: 7890
mode: rule
proxies:
  - name: a
    type: ss
    server: 192.0.2.1
    port: 8388
    cipher: aes-128-gcm
    password: p
  - name: b
    type: vmess
    server: 192.0.2.2
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
proxy-providers:
  remote:
    type: http
    url: https://example.invalid/sub
    path: ./providers/remote.yaml
    interval: 3600
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
rule-providers:
  ads:
    type: http
    behavior: domain
    url: https://example.invalid/ads.yaml
    path: ./ruleset/ads.yaml
    interval: 86400
proxy-groups:
  - name: Proxy
    type: select
    proxies: [auto, a, b, DIRECT]
    use: [remote]
  - name: auto
    type: url-test
    proxies: [a, b]
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: fallback
    type: fallback
    proxies: [Proxy, auto]
rules:
  - RULE-SET,ads,REJECT
  - DOMAIN-SUFFIX,example.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
`

func editingDrafts() []string {
	drafts := []string{
		"",
		"proxies:",
		"proxies: []\nproxy-groups: []\nrules: []\n",
		"proxies: ~\nproxy-groups: ~\n",
		"proxy-groups: x\n",
		"proxy-groups: {a: 1}\n",
		"proxy-groups:\n  - name: G\n",
		"proxy-groups:\n  - name: G\n    type: select\n",
		"proxy-groups:\n  - name: G\n    type: select\n    proxies: [missing]\n",
		"proxy-groups:\n  - name: G\n    type: select\n    proxies: [G]\n",
		"proxy-groups:\n  - name: G\n    type: url-test\n    proxies: []\n",
		"proxy-groups:\n  - name: G\n    type: select\n    use: [nope]\n",
		"proxy-groups:\n  - {name: G, type: select, proxies: [H]}\n  - {name: H, type: select, proxies: [G]}\n",
		"proxy-groups:\n  - name:\n    type:\n    proxies:\n",
		"proxy-groups:\n  - [1, 2]\n",
		"proxy-groups:\n  - name: G\n    type: select\n    proxies: {a: b}\n",
		"proxy-providers: []\n",
		"proxy-providers: x\n",
		"proxy-providers:\n  p:\n",
		"proxy-providers:\n  p:\n    type: file\n",
		"proxy-providers:\n  p:\n    type: http\n",
		"proxy-providers:\n  p:\n    type: inline\n    payload: x\n",
		"proxy-providers:\n  p:\n    type: 7\n    path: []\n",
		"rule-providers:\n  r:\n",
		"rule-providers:\n  r:\n    type: http\n    behavior: nope\n",
		"rule-providers: [1]\n",
		"rules: x\n",
		"rules:\n  - \n  - MATCH\n  - RULE-SET\n  - RULE-SET,\n  - AND,((\n",
		"proxies:\n  - name: a\n",
		"proxies:\n  - name: a\n    type: ss\n",
		"proxies:\n  - name: a\n    type: ss\n    port: x\n",
		"proxies:\n  - null\n  - 1\n  - [a]\n",
		"proxies:\n  - {name: a, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n  - {name: a, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n",
		"dns: x\ntun: 1\nsniffer: []\nhosts: [1]\n",
		"proxies: &a [*a]\n",
		"{",
		"- a\n- b\n",
		"\x00\xff",
	}
	lines := strings.SplitAfter(editingDraftBase, "\n")
	for i := range lines {
		prefix := strings.Join(lines[:i], "")
		drafts = append(drafts, prefix)
		if half := len(lines[i]) / 2; half > 0 {
			drafts = append(drafts, prefix+lines[i][:half])
		}
		drafts = append(drafts, prefix+strings.Join(lines[i+1:], ""))
	}
	return drafts
}

var editingOverrides = []string{
	"",
	"{",
	"null",
	"[]",
	`{"patch":null}`,
	`{"patch":{"proxies":[]}}`,
	`{"patch":{"proxy-groups":"x"}}`,
	`{"patch":{"proxy-groups":[{"name":"G"}]},"appendRules":["MATCH,G"]}`,
	`{"appendRules":[""],"prependRules":true}`,
	`{"patch":{"rules":{"a":1}},"appendRules":["MATCH,DIRECT"]}`,
}

func setupForEditingFuzz(t testing.TB) {
	base := t.TempDir()
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
}

func assertNoRecoveredPanic(t testing.TB, entry, draft string, err error) {
	if err != nil && strings.Contains(err.Error(), "internal error:") {
		t.Errorf("%s panicked on an editing draft: %v\n--- draft ---\n%s", entry, err, draft)
	}
}

func exerciseAppEntries(t testing.TB, draft, override string) {
	merged := draft
	box, err := MergeOverrideForIOS(draft, override)
	assertNoRecoveredPanic(t, "MergeOverrideForIOS", draft+"\n--- override ---\n"+override, err)
	if err == nil && box != nil {
		merged = box.Value
	}
	for _, profile := range []string{"", RuntimeProfileMacOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		_, err = PlanResourcesForProfile(merged, profile)
		assertNoRecoveredPanic(t, "PlanResourcesForProfile/"+profile, merged, err)
		_, err = ConfigDeviationsJSON(merged, profile)
		assertNoRecoveredPanic(t, "ConfigDeviationsJSON/"+profile, merged, err)
	}
	for _, resourceMap := range []string{"", "{", `{"proxy-providers":{"remote":"missing.yaml"}}`} {
		_, err = FinalizeForIOS(merged, resourceMap)
		assertNoRecoveredPanic(t, "FinalizeForIOS", merged+"\n--- map ---\n"+resourceMap, err)
		_, err = ProxyCatalogForIOS(merged, resourceMap, `{"Proxy":"missing","G":"a"}`)
		assertNoRecoveredPanic(t, "ProxyCatalogForIOS", merged+"\n--- map ---\n"+resourceMap, err)
	}
}

func TestAppEntriesSurviveEditingDrafts(t *testing.T) {
	if testing.Short() {
		t.Skip("walks a few hundred drafts through five entries")
	}
	setupForEditingFuzz(t)
	drafts := editingDrafts()
	for _, draft := range drafts {
		exerciseAppEntries(t, draft, "")
	}
	for _, override := range editingOverrides {
		exerciseAppEntries(t, editingDraftBase, override)
		exerciseAppEntries(t, "proxies:\n", override)
	}
}

func FuzzAppEntriesOnEditingDrafts(f *testing.F) {
	for _, draft := range editingDrafts() {
		f.Add(draft, "")
	}
	for _, override := range editingOverrides {
		f.Add(editingDraftBase, override)
	}
	setupForEditingFuzz(f)
	f.Fuzz(func(t *testing.T, draft, override string) {
		exerciseAppEntries(t, draft, override)
	})
}

func TestAppEntriesConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the editing drafts from several goroutines")
	}
	setupForEditingFuzz(t)
	drafts := editingDrafts()
	done := make(chan struct{})
	for worker := 0; worker < 6; worker++ {
		go func(worker int) {
			defer func() { done <- struct{}{} }()
			for i := worker; i < len(drafts); i += 6 {
				exerciseAppEntries(t, drafts[i], editingOverrides[i%len(editingOverrides)])
				_ = CheckConfig(drafts[i])
				_ = ValidateConfigShape(drafts[i])
				_, _ = InvalidDomainPatternsJSON(drafts[i], "")
				_, _ = RuleProviderCatalogForIOS(drafts[i], "", false)
				_, _ = PlatformConfigIntentJSON(drafts[i])
				_, _ = YamlToJSON(drafts[i])
				_ = GeoIPCountryLines(drafts[i])
				_ = GeodataModeEnabled(drafts[i])
			}
		}(worker)
	}
	for worker := 0; worker < 6; worker++ {
		<-done
	}
}

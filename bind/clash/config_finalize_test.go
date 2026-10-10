package clash

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"go.yaml.in/yaml/v3"
)

func TestFinalizeRewritesHTTPProviderToFile(t *testing.T) {
	y := "rule-providers:\n  rule1:\n    type: http\n    url: https://e/r.yaml\n    behavior: classical\n"
	m := `{"providerPaths":{"rule1":"/data/providers/rule1.yaml"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "type: file") || !strings.Contains(got, "/data/providers/rule1.yaml") {
		t.Fatalf("not rewritten to file:\n%s", got)
	}
	definition := finalizedProviderDefinition(t, got, "rule-providers", "rule1")
	if _, kept := definition["url"]; kept {
		t.Fatalf("url should be dropped from the definition upstream reads:\n%s", got)
	}
	if spec, ok := decodeProviderRefreshMarker(definition[providerRefreshField]); !ok || spec.URL != "https://e/r.yaml" {
		t.Fatalf("the refresh marker does not carry the url:\n%s", got)
	}
}

func finalizedProviderDefinition(t *testing.T, finalized, section, name string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized), &root); err != nil {
		t.Fatal(err)
	}
	providers, _ := root[section].(map[string]any)
	definition, _ := providers[name].(map[string]any)
	if definition == nil {
		t.Fatalf("no %s %q in:\n%s", section, name, finalized)
	}
	return definition
}

func TestFinalizeNamespacesSameNamedProxyAndRuleProviders(t *testing.T) {
	y := `
proxy-providers:
  shared: {type: http, url: https://example.com/proxies.yaml}
rule-providers:
  shared: {type: http, behavior: domain, url: https://example.com/rules.yaml}
`
	resourceMap := `{"providerPaths":{"proxy:shared":"/published/proxy.yaml","rule:shared":"/published/rule.yaml"}}`
	out, err := FinalizeForIOS(y, resourceMap)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Proxy map[string]struct {
			Path string `yaml:"path"`
		} `yaml:"proxy-providers"`
		Rule map[string]struct {
			Path string `yaml:"path"`
		} `yaml:"rule-providers"`
	}
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	if document.Proxy["shared"].Path != "/published/proxy.yaml" || document.Rule["shared"].Path != "/published/rule.yaml" {
		t.Fatalf("namespaced paths were crossed: %+v / %+v", document.Proxy, document.Rule)
	}
}

func TestFinalizeRejectsAmbiguousLegacyProviderKey(t *testing.T) {
	y := `
proxy-providers:
  shared: {type: http, url: https://example.com/proxies.yaml}
rule-providers:
  shared: {type: http, behavior: domain, url: https://example.com/rules.yaml}
`
	_, err := FinalizeForIOS(y, `{"providerPaths":{"shared":"/published/shared.yaml"}}`)
	if err == nil || !strings.Contains(err.Error(), "schema-v2") {
		t.Fatalf("ambiguous legacy key was accepted: %v", err)
	}
}

func TestFinalizeMovesRemoteFieldsIntoTheRefreshMarkerAndKeepsRuntimePolicy(t *testing.T) {
	y := `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    interval: 3600
    size-limit: 10240
    proxy: DIRECT
    age-secret-key: AGE-SECRET-KEY-PRIVATE
    header:
      Authorization: [Bearer private-token]
    filter: keep
    dialer-proxy: relay
    health-check: {enable: true, url: https://example.com/generate_204}
    override: {udp: true}
rule-providers:
  remote:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    interval: 3600
    size-limit: 10240
    proxy: DIRECT
    header:
      Authorization: [Bearer private-rule-token]
`
	out, err := FinalizeForIOS(y, `{"providerPaths":{"proxy:remote":"/published/proxies.yaml","rule:remote":"/published/rules.yaml"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		definition := document[section].(map[string]any)["remote"].(map[string]any)
		withoutMarker := map[string]any{}
		for key, value := range definition {
			if key != providerRefreshField {
				withoutMarker[key] = value
			}
		}
		rendered, _ := yaml.Marshal(withoutMarker)
		for _, secret := range []string{"AGE-SECRET-KEY-PRIVATE", "private-token", "private-rule-token"} {
			if strings.Contains(string(rendered), secret) {
				t.Fatalf("%s: %q outside the refresh marker:\n%s", section, secret, rendered)
			}
		}
		if _, ok := decodeProviderRefreshMarker(definition[providerRefreshField]); !ok {
			t.Fatalf("%s: no refresh marker", section)
		}
	}
	providers := document["proxy-providers"].(map[string]any)
	provider := providers["remote"].(map[string]any)
	for _, removed := range []string{"url", "interval", "size-limit", "proxy", "age-secret-key", "header"} {
		if _, exists := provider[removed]; exists {
			t.Errorf("remote-only field %q survived: %+v", removed, provider)
		}
	}
	for _, kept := range []string{"filter", "dialer-proxy", "health-check", "override"} {
		if _, exists := provider[kept]; !exists {
			t.Errorf("runtime field %q was removed: %+v", kept, provider)
		}
	}
	ruleProviders := document["rule-providers"].(map[string]any)
	ruleProvider := ruleProviders["remote"].(map[string]any)
	for _, removed := range []string{"url", "interval", "size-limit", "proxy", "header"} {
		if _, exists := ruleProvider[removed]; exists {
			t.Errorf("rule remote-only field %q survived: %+v", removed, ruleProvider)
		}
	}
	if ruleProvider["behavior"] != "domain" {
		t.Errorf("rule runtime behavior was removed: %+v", ruleProvider)
	}
}

func TestFinalizeHandsAProxyBoundProviderToTheTunnelsRefresher(t *testing.T) {
	y := "proxy-providers:\n  air:\n    type: http\n    url: https://example.com/air.yaml\n    proxy: HK\n    interval: 3600\n"
	out, err := FinalizeForIOS(y, `{"providerPaths":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	provider := finalizedProviderDefinition(t, out.Value, "proxy-providers", "air")
	if provider["type"] != "file" || provider["path"] != unseededProviderPath("proxy", "air") {
		t.Fatalf("a provider with no seed becomes a file provider at its unseeded path: %+v", provider)
	}
	for _, removed := range []string{"url", "proxy", "interval"} {
		if _, kept := provider[removed]; kept {
			t.Fatalf("%s stayed on the definition upstream reads: %+v", removed, provider)
		}
	}
	spec, ok := decodeProviderRefreshMarker(provider[providerRefreshField])
	if !ok || spec.URL != "https://example.com/air.yaml" || spec.Proxy != "HK" || spec.Interval != time.Hour {
		t.Fatalf("the marker must carry what the refresher fetches with: %+v", spec)
	}
}

func TestFinalizePreservesUnsupportedTunIntentForPreflight(t *testing.T) {
	y := "tun:\n  auto-redirect: true\n  stack: gvisor\n"
	out, err := FinalizeForIOS(y, "{}")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "auto-redirect: true") {
		t.Fatalf("unsupported route intent was silently discarded:\n%s", got)
	}
	if !strings.Contains(got, "stack: gvisor") {
		t.Fatalf("unrelated key lost:\n%s", got)
	}
}

func TestFinalizeExpandsRouteAddressSet(t *testing.T) {
	dir := t.TempDir()
	setFile := filepath.Join(dir, "cn.yaml")
	if err := os.WriteFile(setFile, []byte("payload:\n  - 1.0.0.0/24\n  - 2.0.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	y := "rule-providers:\n  cn:\n    type: http\n    behavior: ipcidr\n    url: https://e/cn.yaml\n" +
		"tun:\n  route-address-set:\n    - cn\n"
	m := `{"providerPaths":{"cn":"` + setFile + `"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if strings.Contains(got, "route-address-set") {
		t.Fatalf("route-address-set not consumed:\n%s", got)
	}
	if !strings.Contains(got, "1.0.0.0/24") || !strings.Contains(got, "2.0.0.0/16") {
		t.Fatalf("CIDRs not expanded into route-address:\n%s", got)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(got), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["cn"].(map[string]any)
	if safe, exists := provider[providerSideUpdateSafeWrittenField].(bool); !exists || safe {
		t.Fatalf("platform route provider was not marked side-update unsafe: %+v", provider)
	}
}

func TestFinalizeMarksOrdinaryRuleProviderSideUpdateSafe(t *testing.T) {
	y := "rule-providers:\n  ordinary:\n    type: http\n    behavior: domain\n    url: https://e/rules.yaml\n"
	out, err := FinalizeForIOS(y, `{"providerPaths":{"ordinary":"/published/rules.yaml"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["ordinary"].(map[string]any)
	if safe, exists := provider[providerSideUpdateSafeWrittenField].(bool); !exists || !safe {
		t.Fatalf("ordinary rule provider was not marked side-update safe: %+v", provider)
	}
}

func TestInertRouteReferencesKeepOrdinaryRuleSideUpdates(t *testing.T) {
	for _, behavior := range []string{"domain", "classical"} {
		for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
			t.Run(behavior+"/"+field, func(t *testing.T) {
				input := "rule-providers:\n  ordinary:\n    type: http\n    behavior: " + behavior +
					"\n    url: https://rules.example.test/rules.yaml\ntun:\n  " + field + ": [ordinary]\n"
				out, err := FinalizeForIOS(input, `{}`)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]any
				if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
					t.Fatal(err)
				}
				provider := document["rule-providers"].(map[string]any)["ordinary"].(map[string]any)
				if safe, _ := provider[providerSideUpdateSafeWrittenField].(bool); !safe {
					t.Fatal("a rule set that contributes no platform routes must remain eligible for background rule updates")
				}
				if _, exists := document["tun"].(map[string]any)[field]; exists {
					t.Fatal("inert route reference survived finalization")
				}
			})
		}
	}
}

func TestFinalizeReadsCandidateButWritesPublishedProviderPath(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".tmp-revision", "providers", "cn.yaml")
	if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging, []byte("payload:\n  - 10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(dir, "revision", "providers", "cn.yaml")
	y := "rule-providers:\n  cn:\n    type: http\n    behavior: ipcidr\n    url: https://e/cn.yaml\n" +
		"tun:\n  route-address-set:\n    - cn\n"
	m := `{"providerPaths":{"cn":"` + published + `"},"providerReadPaths":{"cn":"` + staging + `"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(out.Value, published) || strings.Contains(out.Value, staging) {
		t.Fatalf("final YAML leaked staging path:\n%s", out.Value)
	}
	if !strings.Contains(out.Value, "10.0.0.0/8") {
		t.Fatalf("candidate CIDR was not expanded:\n%s", out.Value)
	}
}

func TestFinalizeSkipsMissingRouteSetCandidate(t *testing.T) {
	y := "tun:\n  route-address-set:\n    - missing\n"
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("an undefined route-address-set provider is inert upstream, not fatal: %v", err)
	}
	if strings.Contains(out.Value, "missing") {
		t.Fatalf("the skipped set still reached the core:\n%s", out.Value)
	}
}

func TestFinalizeSkipsARouteSetTheAppHasNoBytesFor(t *testing.T) {
	y := `
rule-providers:
  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/cn_ip.mrs, interval: 86400}
tun:
  route-exclude-address-set: [cn_ip]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("a route set the App has no bytes for is inert, not fatal: %v", err)
	}
	for _, key := range []string{"route-exclude-address-set", "route-exclude-address"} {
		if strings.Contains(out.Value, key) {
			t.Fatalf("%s reached the core although nothing could be expanded:\n%s", key, out.Value)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["cn_ip"].(map[string]any)
	spec, ok := decodeProviderRefreshMarker(provider[providerRefreshField])
	if provider["type"] != "file" || !ok || spec.URL != "https://example.com/cn_ip.mrs" {
		t.Fatalf("the provider goes to the tunnel's refresher so the core loads its rules half, got %+v", provider)
	}
}

func TestFinalizeStillRefusesAMappedRouteSetFileThatIsNotThere(t *testing.T) {
	y := `
rule-providers:
  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/cn_ip.mrs}
tun:
  route-exclude-address-set: [cn_ip]
`
	_, err := FinalizeForIOS(y, `{"providerPaths":{"cn_ip":"`+filepath.Join(t.TempDir(), "never-written.mrs")+`"}}`)
	if err == nil || !strings.Contains(err.Error(), "read route-exclude-address-set provider") {
		t.Fatalf("a mapped path nobody wrote must still refuse, got %v", err)
	}
}

func TestFinalizeSkipsNonIPCidrRouteSet(t *testing.T) {
	y := `
rule-providers:
  domains: {type: inline, behavior: domain, payload: [example.com]}
tun:
  route-address-set: [domains]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("a non-ipcidr route-address-set is inert upstream, not fatal: %v", err)
	}
	if strings.Contains(out.Value, "route-address-set") {
		t.Fatalf("the skipped set still reached the core:\n%s", out.Value)
	}
}

func TestFinalizeExpandsInlineRouteSet(t *testing.T) {
	y := `
rule-providers:
  private:
    type: inline
    behavior: ipcidr
    payload:
      - 10.0.0.1/8
      - 10.0.0.0/8
tun:
  route-address-set: [private]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Tun struct {
			RouteAddress []string `yaml:"route-address"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Tun.RouteAddress) != 1 || document.Tun.RouteAddress[0] != "10.0.0.0/8" {
		t.Fatalf("inline prefixes were not canonicalized/deduplicated:\n%s", out.Value)
	}
}

func TestFinalizeExpandsTextAndMRSRouteSets(t *testing.T) {
	directory := t.TempDir()
	textPath := filepath.Join(directory, "text.txt")
	if err := os.WriteFile(textPath, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mrs bytes.Buffer
	if err := ruleprovider.ConvertToMrs([]byte("2001:db8::/32\n"), P.IPCIDR, P.TextRule, &mrs); err != nil {
		t.Fatal(err)
	}
	mrsPath := filepath.Join(directory, "set.mrs")
	if err := os.WriteFile(mrsPath, mrs.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	y := `
rule-providers:
  text-set: {type: http, behavior: ipcidr, format: text, url: https://example.com/text}
  mrs-set: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/mrs}
tun:
  route-address-set: [text-set, mrs-set]
`
	resourceMap := `{"providerPaths":{"text-set":"` + textPath + `","mrs-set":"` + mrsPath + `"}}`
	out, err := FinalizeForIOS(y, resourceMap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Value, "192.0.2.0/24") || !strings.Contains(out.Value, "2001:db8::/32") {
		t.Fatalf("text/MRS prefixes were not expanded:\n%s", out.Value)
	}
}

func TestFinalizeRejectsUnsafeOrInvalidRouteSet(t *testing.T) {
	directory := t.TempDir()
	y := `
rule-providers:
  set: {type: http, behavior: ipcidr, format: yaml, url: https://example.com/set}
tun:
  route-address-set: [set]
`
	t.Run("invalid CIDR", func(t *testing.T) {
		path := filepath.Join(directory, "invalid.yaml")
		if err := os.WriteFile(path, []byte("payload: [not-a-prefix]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+path+`"}}`); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("invalid CIDR was accepted: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "target.yaml")
		if err := os.WriteFile(target, []byte("payload: [10.0.0.0/8]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link.yaml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+link+`"}}`); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink was accepted: %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(directory, "oversized.yaml")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(maximumProviderResourceBytes) + 1); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+path+`"}}`); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("oversized provider was accepted: %v", err)
		}
	})
	t.Run("unsafe MRS length", func(t *testing.T) {
		path := filepath.Join(directory, "unsafe.mrs")
		decoded := buildDecodedMRSTestPayload(t, P.IPCIDR, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		})
		if err := os.WriteFile(path, compressMRSTestPayload(t, decoded), 0o600); err != nil {
			t.Fatal(err)
		}
		mrsYAML := `
rule-providers:
  set: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/set}
tun:
  route-address-set: [set]
`
		var panicValue any
		var err error
		func() {
			defer func() { panicValue = recover() }()
			_, err = FinalizeForIOS(mrsYAML, `{"providerPaths":{"set":"`+path+`"}}`)
		}()
		if panicValue != nil {
			t.Fatalf("unsafe route-set MRS panicked: %v", panicValue)
		}
		if err == nil || !strings.Contains(err.Error(), "MRS") {
			t.Fatalf("unsafe route-set MRS error = %v", err)
		}
	})
}

func TestFinalizeWritesTheSideUpdateMarkerTheExtensionReads(t *testing.T) {
	if providerSideUpdateSafeWrittenField != "x-clash-side-update-safe" {
		t.Fatalf("finalize writes %q; a Extension reads only x-clash-side-update-safe", providerSideUpdateSafeWrittenField)
	}
	root := map[string]any{"rule-providers": map[string]any{
		"ads": map[string]any{"type": "file", "behavior": "domain", "path": "./ads.yaml"},
	}}
	annotateRuleProviderSideUpdateSafety(root, nil)
	definition := root["rule-providers"].(map[string]any)["ads"].(map[string]any)
	if safe, ok := definition["x-clash-side-update-safe"].(bool); !ok || !safe {
		t.Fatalf("a Extension would read this provider as unsafe: %+v", definition)
	}
	if _, ok := definition[providerSideUpdateSafeField]; ok && providerSideUpdateSafeField != providerSideUpdateSafeWrittenField {
		t.Fatalf("finalize wrote the new key too; one marker per definition: %+v", definition)
	}
}

func TestFinalizeReplacesAnySideUpdateMarkerTheSourceCarried(t *testing.T) {
	root := map[string]any{"rule-providers": map[string]any{
		"ads": map[string]any{
			"type": "file", "behavior": "domain", "path": "./ads.yaml",
			"x-clash-side-update-safe": false,
		},
	}}
	annotateRuleProviderSideUpdateSafety(root, nil)
	definition := root["rule-providers"].(map[string]any)["ads"].(map[string]any)
	if !providerSideUpdateSafe(definition) {
		t.Fatalf("an ordinary provider reads as unsafe after finalize: %+v", definition)
	}
	if _, ok := definition["x-clash-side-update-safe"]; ok && providerSideUpdateSafeWrittenField != "x-clash-side-update-safe" {
		t.Fatalf("the source's new-key marker survived beside the written one: %+v", definition)
	}
}

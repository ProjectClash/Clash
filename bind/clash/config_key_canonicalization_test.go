package clash

import (
	"go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func canonicalizedRawConfig(t *testing.T, content string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	canonicalizeProviderDefinitionKeys(raw)
	return raw
}

func TestProviderDefinitionKeysAreCanonicalizedBeforeEveryGuard(t *testing.T) {
	raw := canonicalizedRawConfig(t, `
proxy-providers:
  air:
    Type: file
    Path: ./nodes.yaml
rule-providers:
  ads:
    TYPE: file
    PATH: ./ads.yaml
    Behavior: classical
    Format: yaml
`)
	for _, subject := range []struct {
		kind       string
		definition map[string]any
	}{
		{"proxy-provider", raw.ProxyProvider["air"]},
		{"rule-provider", raw.RuleProvider["ads"]},
	} {
		if _, ok := subject.definition["type"]; !ok {
			t.Fatalf("%s: type key not canonicalized; every literal-lowercase guard in this fork misses it: %v",
				subject.kind, subject.definition)
		}
		if _, ok := subject.definition["path"]; !ok {
			t.Fatalf("%s: path key not canonicalized: %v", subject.kind, subject.definition)
		}
		for key := range subject.definition {
			if key != strings.ToLower(key) {
				t.Fatalf("%s: mixed-case key %q survived canonicalization: %v", subject.kind, key, subject.definition)
			}
		}
	}
	if behavior := raw.RuleProvider["ads"]["behavior"]; behavior != "classical" {
		t.Fatalf("canonicalization lost a value: behavior=%v", behavior)
	}
}

func TestRemoteProviderIsAcceptedWhateverTheKeyCase(t *testing.T) {
	for _, spelling := range []string{"type", "Type", "TYPE", "tYpE"} {
		content := "proxy-providers:\n  air:\n    " + spelling + ": http\n    url: http://example.com/n.yaml\n    path: ./n.yaml\n"
		raw, err := config.UnmarshalRawConfig([]byte(content))
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", spelling, err)
		}
		canonicalizeProviderDefinitionKeys(raw)
		if err := validateRawProvidersForIOS("proxy-provider", raw.ProxyProvider); err != nil {
			t.Fatalf("%s: a remote provider was refused: %v", spelling, err)
		}
		if _, ok := raw.ProxyProvider["air"]["type"]; !ok {
			t.Fatalf("%s: canonicalization did not lower the type key", spelling)
		}
	}
}

func TestStagingSeesAFileProviderWhateverTheKeyCase(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(C.Path.HomeDir(), "nodes.yaml")
	if err := os.WriteFile(source,
		[]byte("proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 443\n    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := config.UnmarshalRawConfig([]byte(
		"proxy-providers:\n  air:\n    Type: file\n    Path: " + source + "\n"))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	canonicalizeProviderDefinitionKeys(raw)

	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if runtime == nil {
		t.Fatal("a mixed-case file provider was skipped by staging; its payload reaches the core unsanitized")
	}
	defer runtime.close()

	if _, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string)); err != nil {
		t.Fatal(err)
	}
	if entry, staged := runtime.entries[providerRuntimeKey("proxy", "air")]; !staged || entry.runtimePath == "" {
		t.Fatal("staging made no entry for the mixed-case file provider")
	}
	if raw.ProxyProvider["air"]["path"].(string) == source {
		t.Fatal("the definition still names the published source, not the staged copy")
	}
	if !strings.HasPrefix(raw.ProxyProvider["air"]["path"].(string), home) {
		t.Fatal("the definition does not point at the staged copy")
	}
}

func TestFinalizeRewritesARemoteProviderWhateverTheKeyCase(t *testing.T) {
	merged := "proxy-providers:\n  air:\n    Type: http\n    URL: http://example.com/nodes.yaml\n" +
		"rules:\n  - MATCH,DIRECT\n"
	resourceMap := `{"providerPaths":{"proxy:air":"/tmp/clash-finalize-air.yaml"}}`

	box, err := FinalizeForIOS(merged, resourceMap)
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	finalized := box.Value
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized), &root); err != nil {
		t.Fatal(err)
	}
	air := root["proxy-providers"].(map[string]any)["air"].(map[string]any)
	if _, kept := air["url"]; kept {
		t.Fatalf("a mixed-case remote provider kept its url on the definition upstream reads:\n%s", finalized)
	}
	if spec, ok := decodeProviderRefreshMarker(air[providerRefreshField]); !ok || spec.URL != "http://example.com/nodes.yaml" {
		t.Fatalf("the refresh marker does not carry the url:\n%s", finalized)
	}
	if !strings.Contains(finalized, "type: file") {
		t.Fatalf("the provider was not rewritten to a file provider:\n%s", finalized)
	}
}

func TestCanonicalizationKeepsAnExistingLowercaseKey(t *testing.T) {
	raw := canonicalizedRawConfig(t, `
proxy-providers:
  air:
    type: file
    Type: http
    path: ./real.yaml
`)
	if got := raw.ProxyProvider["air"]["type"]; got != "file" {
		t.Fatalf("a mixed-case duplicate overwrote the canonical key: type=%v", got)
	}
}

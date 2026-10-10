package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stagedManifestPath(t *testing.T, home string) string {
	t.Helper()
	return filepath.Join(home, providerRuntimeDirectoryName, providerRuntimeManifestName)
}

func readStagedManifest(t *testing.T, home string) *stagedProviderManifest {
	t.Helper()
	payload, err := os.ReadFile(stagedManifestPath(t, home))
	if err != nil {
		t.Fatal(err)
	}
	manifest := &stagedProviderManifest{}
	if err := json.Unmarshal(payload, manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeStagedManifest(t *testing.T, home string, manifest *stagedProviderManifest) {
	t.Helper()
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedManifestPath(t, home), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stageOnce(t *testing.T, source string, compile bool) string {
	t.Helper()
	raw := stagingRawWithProviderPath(t, "rule", source)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), compile)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	path := raw.RuleProvider["probe"]["path"].(string)
	runtime.close()
	return path
}

func TestStagedFileRewriteIsRejected(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(home, "rules.yaml")
	original := "payload:\n  - DOMAIN,example.com\n"
	if err := os.WriteFile(source, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedPath := stageOnce(t, source, false)

	poisoned := "payload:\n  - DOMAIN,attacker.io\n"
	poisoned = poisoned + strings.Repeat(" ", len(original)-len(poisoned))
	if len(poisoned) != len(original) {
		t.Fatalf("test invariant: lengths differ (%d vs %d)", len(poisoned), len(original))
	}
	replacement := stagedPath + ".attacker"
	if err := os.WriteFile(replacement, []byte(poisoned), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, stagedPath); err != nil {
		t.Fatal(err)
	}
	if published, err := os.ReadFile(source); err != nil || string(published) != original {
		t.Fatalf("test invariant: the published source must be untouched (%v, %q)", err, published)
	}

	raw := stagingRawWithProviderPath(t, "rule", source)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("stage after tampering: %v", err)
	}
	defer runtime.close()

	restaged, err := os.ReadFile(raw.RuleProvider["probe"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(restaged) != original {
		t.Fatalf("the tampered staged file was served instead of being rebuilt from the published source:\n%q", restaged)
	}
}

func TestManifestCompiledBehaviorIsWhitelisted(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(home, "rules.txt")
	if err := os.WriteFile(source, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := stagingRawWithProviderPath(t, "rule", source)
	raw.RuleProvider["probe"]["behavior"] = "domain"
	raw.RuleProvider["probe"]["format"] = "text"
	published, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()

	manifest := readStagedManifest(t, home)
	key := providerRuntimeKey("rule", "probe")
	record := manifest.Entries[key]
	record.CompiledBehavior = "not-a-behavior"
	manifest.Entries[key] = record
	writeStagedManifest(t, home, manifest)

	next := stagingRawWithProviderPath(t, "rule", source)
	next.RuleProvider["probe"]["behavior"] = "domain"
	next.RuleProvider["probe"]["format"] = "text"
	runtime, err := stageProviderRuntime(next, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("stage with a poisoned manifest must not fail the start: %v", err)
	}
	defer runtime.close()

	if behavior := next.RuleProvider["probe"]["behavior"]; behavior == "not-a-behavior" {
		t.Fatal("an arbitrary behavior from the manifest reached the definition; ParseRawConfig would refuse the whole configuration on every start")
	}
}

func TestOversizedManifestIsRefusedNotLoaded(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(home, "rules.yaml")
	if err := os.WriteFile(source, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stageOnce(t, source, false)

	var builder strings.Builder
	builder.WriteString(`{"schema":1,"logic":3,"core":"x","policy":"y","entries":{},"pad":"`)
	builder.WriteString(strings.Repeat("A", 8<<20))
	builder.WriteString(`"}`)
	if err := os.WriteFile(stagedManifestPath(t, home), []byte(builder.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	loaded := loadStagedProviderManifest(filepath.Join(home, providerRuntimeDirectoryName), policy)
	if len(loaded.Entries) != 0 {
		t.Fatal("an oversized manifest was parsed; it must be refused and the start must restage from source")
	}
}

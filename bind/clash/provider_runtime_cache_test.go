package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

const cacheTestProxyPayload = "proxies:\n" +
	"  - name: a\n" +
	"    type: ss\n" +
	"    server: 1.2.3.4\n" +
	"    port: 443\n" +
	"    cipher: aes-128-gcm\n" +
	"    password: x\n"

const cacheTestRulePayload = "payload:\n" +
	"  - DOMAIN-SUFFIX,example.com\n"

func cacheTestSources(t *testing.T) (string, string) {
	t.Helper()
	dir := C.Path.HomeDir()
	proxyPath := filepath.Join(dir, "proxy.yaml")
	rulePath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(proxyPath, []byte(cacheTestProxyPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, []byte(cacheTestRulePayload), 0o600); err != nil {
		t.Fatal(err)
	}
	return proxyPath, rulePath
}

func cacheTestRaw(proxyPath, rulePath string) *config.RawConfig {
	raw := &config.RawConfig{}
	if proxyPath != "" {
		raw.ProxyProvider = map[string]map[string]any{
			"air": {"type": "file", "path": proxyPath, "format": "yaml"},
		}
	}
	if rulePath != "" {
		raw.RuleProvider = map[string]map[string]any{
			"ads": {
				"type": "file", "path": rulePath,
				"behavior": "classical", "format": "yaml",
				providerSideUpdateSafeField: true,
			},
		}
	}
	return raw
}

func stagedInode(t *testing.T, path string) (uint64, int64) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat staged file: %v", err)
	}
	return info.Sys().(*syscall.Stat_t).Ino, info.ModTime().UnixNano()
}

func readManifest(t *testing.T, home string) map[string]json.RawMessage {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(
		home, providerRuntimeDirectoryName, providerRuntimeManifestName))
	if err != nil {
		t.Fatalf("read staged manifest: %v", err)
	}
	var document struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode staged manifest: %v", err)
	}
	return document.Entries
}

func TestStagedProviderRuntimeIsReusedAcrossStarts(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	proxyPath, rulePath := cacheTestSources(t)
	policy := currentRuntimePolicy(true)

	first, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false)
	if err != nil {
		t.Fatalf("first stage: %v", err)
	}
	stagedProxy := first.entries[providerRuntimeKey("proxy", "air")].runtimePath
	stagedRule := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	proxyInode, proxyMtime := stagedInode(t, stagedProxy)

	second, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false)
	if err != nil {
		t.Fatalf("second stage: %v", err)
	}
	if got := second.entries[providerRuntimeKey("proxy", "air")].runtimePath; got != stagedProxy {
		t.Fatalf("reuse changed the staged path: %q != %q", got, stagedProxy)
	}
	inode, mtime := stagedInode(t, stagedProxy)
	if inode != proxyInode || mtime != proxyMtime {
		t.Fatalf("unchanged source was restaged: inode %d->%d mtime %d->%d",
			proxyInode, inode, proxyMtime, mtime)
	}
	staged, err := os.ReadFile(stagedProxy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged, []byte(cacheTestProxyPayload)) {
		t.Fatal("staged bytes stopped matching the published source")
	}

	second.close()
	if _, err := os.Lstat(stagedProxy); err != nil {
		t.Fatalf("close() deleted the staged runtime: %v", err)
	}
	third, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false)
	if err != nil {
		t.Fatalf("stage after close: %v", err)
	}
	inode, mtime = stagedInode(t, third.entries[providerRuntimeKey("proxy", "air")].runtimePath)
	if inode != proxyInode || mtime != proxyMtime {
		t.Fatal("staging after close() rebuilt an unchanged provider")
	}

	grown := cacheTestProxyPayload + "  - name: b\n    type: ss\n" +
		"    server: 5.6.7.8\n    port: 443\n    cipher: aes-128-gcm\n    password: y\n"
	if err := os.WriteFile(proxyPath, []byte(grown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false); err != nil {
		t.Fatalf("stage after source change: %v", err)
	}
	staged, err = os.ReadFile(stagedProxy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged, []byte(grown)) {
		t.Fatal("a changed source must be restaged, not served from the cache")
	}

	mrsRaw := cacheTestRaw(proxyPath, rulePath)
	mrsRaw.RuleProvider["ads"]["behavior"] = "domain"
	mrsRaw.RuleProvider["ads"]["format"] = "mrs"
	if _, err := stageProviderRuntime(mrsRaw, policy, false); err != nil {
		t.Fatalf("stage after schema change: %v", err)
	}
	entries := readManifest(t, home)
	record, exists := entries[providerRuntimeKey("rule", "ads")]
	if !exists {
		t.Fatal("manifest lost the rule provider entry")
	}
	if !bytes.Contains(record, []byte(`"behavior":"domain"`)) {
		t.Fatalf("schema change must miss the cache and re-record: %s", record)
	}
	if !bytes.Contains(record, []byte(`"unreadableWarn"`)) ||
		bytes.Contains(record, []byte(`"unreadableWarn":""`)) {
		t.Fatalf("failed preparation must record its verdict for replay: %s", record)
	}
	_ = stagedRule
}

func TestStagedProviderRuntimeSweepsWhatTheConfigurationDropped(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	proxyPath, rulePath := cacheTestSources(t)
	policy := currentRuntimePolicy(true)

	parent := filepath.Join(home, providerRuntimeDirectoryName)
	legacy := filepath.Join(parent, "999999-legacy")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "x.provider"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false)
	if err != nil {
		t.Fatalf("first stage: %v", err)
	}
	stagedRule := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatal("staging must sweep the retired per-start directories")
	}

	if _, err := stageProviderRuntime(cacheTestRaw(proxyPath, ""), policy, false); err != nil {
		t.Fatalf("stage without the rule provider: %v", err)
	}
	if _, err := os.Lstat(stagedRule); err != nil {
		t.Fatalf("a dropped provider whose source is still published must keep its staging: %v", err)
	}
	if err := os.Remove(rulePath); err != nil {
		t.Fatal(err)
	}
	if _, err := stageProviderRuntime(cacheTestRaw(proxyPath, ""), policy, false); err != nil {
		t.Fatalf("stage after the source went: %v", err)
	}
	if _, err := os.Lstat(stagedRule); !os.IsNotExist(err) {
		t.Fatal("a provider the configuration dropped must be swept once its source is gone")
	}
	entries := readManifest(t, home)
	if _, exists := entries[providerRuntimeKey("rule", "ads")]; exists {
		t.Fatal("the manifest must drop the swept provider")
	}
	if _, exists := entries[providerRuntimeKey("proxy", "air")]; !exists {
		t.Fatal("the surviving provider must stay in the manifest")
	}
}

func TestSideUpdateInvalidatesTheStagedRecord(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	proxyPath, rulePath := cacheTestSources(t)
	policy := currentRuntimePolicy(true)

	first, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	proxyStaged := first.entries[providerRuntimeKey("proxy", "air")].runtimePath

	invalidateStagedProviderRecord(filepath.Base(proxyStaged))
	manifest := loadStagedProviderManifest(filepath.Join(home, providerRuntimeDirectoryName), policy)
	if record, exists := manifest.Entries[providerRuntimeKey("proxy", "air")]; !exists || record.ContentSHA256 != "" {
		t.Fatalf("invalidation must keep the record and stop it matching: %+v %v", record, exists)
	}
	if record := manifest.Entries[providerRuntimeKey("rule", "ads")]; record.ContentSHA256 == "" {
		t.Fatal("invalidation must only touch its own record")
	}

	if _, err := stageProviderRuntime(cacheTestRaw(proxyPath, rulePath), policy, false); err != nil {
		t.Fatalf("stage after invalidation: %v", err)
	}
	entries := readManifest(t, home)
	if _, exists := entries[providerRuntimeKey("proxy", "air")]; !exists {
		t.Fatal("the next staging must rebuild the invalidated record")
	}
	manifest = loadStagedProviderManifest(filepath.Join(home, providerRuntimeDirectoryName), policy)
	if manifest.Entries[providerRuntimeKey("proxy", "air")].ContentSHA256 == "" {
		t.Fatal("the rebuilt record must match again")
	}
}

func TestSideUpdateOfTheRunningVersionSurvivesACandidate(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	write := func(revision, payload string) string {
		dir := filepath.Join(home, "published", revision, "providers")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "p.yaml")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	running := write("r1", cacheTestProxyPayload)
	candidate := write("r2", cacheTestProxyPayload+"  - name: b\n    type: ss\n    server: 5.6.7.8\n    port: 443\n    cipher: aes-128-gcm\n    password: y\n")

	staged, err := stageProviderRuntime(cacheTestRaw(running, ""), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	runningFile := staged.entries[providerRuntimeKey("proxy", "air")].runtimePath
	if err := writeRuntimeProviderFile(runningFile, []byte(cacheTestProxyPayload)); err != nil {
		t.Fatal(err)
	}
	invalidateStagedProviderRecord(filepath.Base(runningFile))

	next, err := stageProviderRuntime(cacheTestRaw(candidate, ""), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(runningFile); err != nil {
		t.Fatalf("staging a candidate swept the running version's side-updated file: %v", err)
	}
	candidateFile := next.entries[providerRuntimeKey("proxy", "air")].runtimePath

	invalidateStagedProviderRecord(filepath.Base(runningFile))
	manifest := loadStagedProviderManifest(filepath.Join(home, providerRuntimeDirectoryName), policy)
	record := manifest.Entries[providerRuntimeKey("proxy", "air")]
	if record.File != filepath.Base(candidateFile) || record.ContentSHA256 == "" {
		t.Fatalf("a side update of one version touched another's record: %+v", record)
	}
}

func TestProvidersLoadBeforeTheListenersAttach(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "ordered-proxies.yaml")
	if err := os.WriteFile(published, []byte("proxies:\n  - {name: node, type: direct}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  ordered:
    type: file
    path: %q
proxy-groups:
  - name: Ordered
    type: select
    use: [ordered]
rules:
  - MATCH,Ordered
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	trace := StartupPhaseTrace()
	last := func(mark string) int {
		index := strings.LastIndex(trace, mark)
		if index < 0 {
			t.Fatalf("phase trace never recorded %q:\n%s", mark, trace)
		}
		return index
	}
	if last("apply:rule-providers-loaded") > last("apply:listeners") {
		t.Fatal("the listeners attached before the providers finished loading")
	}
	if last("apply:proxy-providers-loaded") > last("apply:tun") {
		t.Fatal("the tun attached before the providers finished loading")
	}
}

func TestStagedProviderRuntimeKeepsEachVersionsProduct(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	write := func(revision, payload string) string {
		dir := filepath.Join(home, "published", revision, "providers")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "rules.yaml")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	older := write("r1", cacheTestRulePayload)
	newer := write("r2", "payload:\n  - DOMAIN-SUFFIX,example.org\n")

	first, err := stageProviderRuntime(cacheTestRaw("", older), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	olderStaged := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	olderInode, _ := stagedInode(t, olderStaged)

	second, err := stageProviderRuntime(cacheTestRaw("", newer), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	newerStaged := second.entries[providerRuntimeKey("rule", "ads")].runtimePath
	if newerStaged == olderStaged {
		t.Fatal("two versions of one provider must not share a staged file")
	}
	content, err := os.ReadFile(olderStaged)
	if err != nil || !strings.Contains(string(content), "example.com") {
		t.Fatalf("staging the newer version touched the older one's product: %q %v", content, err)
	}

	third, err := stageProviderRuntime(cacheTestRaw("", older), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if again := third.entries[providerRuntimeKey("rule", "ads")].runtimePath; again != olderStaged {
		t.Fatalf("going back to the older version staged %s, want %s", again, olderStaged)
	}
	if inode, _ := stagedInode(t, olderStaged); inode != olderInode {
		t.Fatal("going back to the older version must reuse its product, not restage it")
	}
	if _, err := os.Lstat(newerStaged); err != nil {
		t.Fatalf("and the newer version's product must survive the switch back: %v", err)
	}
}

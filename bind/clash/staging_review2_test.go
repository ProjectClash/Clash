package clash

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func TestRefusedReloadKeepsTheRunningTunnelRanges(t *testing.T) {
	svc := startedServiceForOutcome(t)
	running := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/16")}
	setConfiguredTunnelPrefixes(running)
	t.Cleanup(func() { setConfiguredTunnelPrefixes(nil); reloadTestAfterParse = nil })
	reloadTestAfterParse = func() {
		setConfiguredTunnelPrefixes([]netip.Prefix{netip.MustParsePrefix("198.19.0.1/16")})
	}
	if outcome := svc.ReloadClassified("mode: [broken"); outcome.ErrorClass != CoreOutcomeConfig {
		t.Fatalf("candidate must be refused as config: %q %q", outcome.ErrorClass, outcome.Message)
	}
	if got := currentTunnelPrefixes(); !samePrefixes(got, running) {
		t.Fatalf("tunnel ranges after a refused reload = %v, want the running %v", got, running)
	}
	if outcome := svc.ReloadClassified(helloYAML + "\n"); outcome.ErrorClass != "" {
		t.Fatalf("reload: %q %q", outcome.ErrorClass, outcome.Message)
	}
	if got := currentTunnelPrefixes(); samePrefixes(got, running) {
		t.Fatal("an applied reload must keep the ranges its parse recorded")
	}
}

func TestStagingSchemaErrorIsConfig(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "rules.yaml", "payload:\n  - DOMAIN,example.com\n")
	raw := stagingRawWithProviderPath(t, "rule", source)
	for _, definition := range raw.RuleProvider {
		definition["behavior"] = "nope"
	}
	_, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err == nil || stagingFailureIsEnvironmental(err) {
		t.Fatalf("an unknown behavior must be a config refusal, got %v", err)
	}
}

func stageRevision(t *testing.T, home, revision, payload string) string {
	t.Helper()
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

func TestStagingWithoutTheLockStagesPrivately(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	older := stageRevision(t, home, "r1", cacheTestRulePayload)
	first, err := stageProviderRuntime(cacheTestRaw("", older), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	olderStaged := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	shared := filepath.Dir(olderStaged)
	parent := filepath.Join(home, providerRuntimeDirectoryName)
	manifestBefore, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(shared, "foreign.provider")
	if err := os.WriteFile(foreign, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sharedBefore, _ := os.ReadDir(shared)

	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	defer unlock()
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait })

	newer := stageRevision(t, home, "r2", "payload:\n  - DOMAIN,example.org\n")
	private, err := stageProviderRuntime(cacheTestRaw("", newer), policy, false)
	if err != nil {
		t.Fatalf("staging without the lock must still stage: %v", err)
	}
	privatePath := private.entries[providerRuntimeKey("rule", "ads")].runtimePath
	if !private.private || strings.HasPrefix(privatePath, shared+string(filepath.Separator)) {
		t.Fatalf("staging without the lock wrote into the shared directory: %s", privatePath)
	}
	if content, err := os.ReadFile(privatePath); err != nil || !strings.Contains(string(content), "example.org") {
		t.Fatalf("private staging is not the candidate's: %q %v", content, err)
	}
	manifestAfter, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil || string(manifestAfter) != string(manifestBefore) {
		t.Fatalf("staging without the lock rewrote the manifest (err %v)", err)
	}
	sharedAfter, _ := os.ReadDir(shared)
	if len(sharedAfter) != len(sharedBefore) {
		t.Fatalf("staging without the lock changed the shared directory: %d -> %d entries", len(sharedBefore), len(sharedAfter))
	}
	privateDirectory := private.directory
	private.close()
	if _, err := os.Lstat(privateDirectory); !os.IsNotExist(err) {
		t.Fatal("a private staging must go when its runtime closes")
	}
}

func TestAbandonedPrivateStagingIsRemoved(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	root := filepath.Join(home, providerRuntimePrivateDirectoryName)
	live := filepath.Join(root, fmt.Sprintf("%d-live", os.Getpid()))
	dead := filepath.Join(root, "999999999-dead")
	for _, dir := range []string{live, dead} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := stageRevision(t, home, "r1", cacheTestRulePayload)
	if _, err := stageProviderRuntime(cacheTestRaw("", source), currentRuntimePolicy(true), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(live); err != nil {
		t.Fatalf("a live process's private staging was removed: %v", err)
	}
	if _, err := os.Lstat(dead); !os.IsNotExist(err) {
		t.Fatal("a gone process's private staging must be removed")
	}
}

func TestManifestOverTheLimitKeepsOtherVersionsFiles(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	running := stageRevision(t, home, "r1", cacheTestRulePayload)
	first, err := stageProviderRuntime(cacheTestRaw("", running), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	runningStaged := first.entries[providerRuntimeKey("rule", "ads")].runtimePath

	candidate := stageRevision(t, home, "r2", "payload:\n  - DOMAIN,example.org\n")
	if _, err := stageProviderRuntime(cacheTestRaw("", candidate), policy, false); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(home, providerRuntimeDirectoryName)
	full, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil {
		t.Fatal(err)
	}
	manifest := loadStagedProviderManifest(parent, policy)
	if len(manifest.Retained) == 0 {
		t.Fatal("the running version must be retained beside the candidate")
	}
	previous := maximumStagedManifestBytes
	maximumStagedManifestBytes = int64(len(full)) - 1
	t.Cleanup(func() { maximumStagedManifestBytes = previous })
	saveStagedProviderManifest(parent, manifest)
	compacted, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil || int64(len(compacted)) > maximumStagedManifestBytes {
		t.Fatalf("the saved manifest must fit its limit: %d bytes, %v", len(compacted), err)
	}
	reloaded := loadStagedProviderManifest(parent, policy)
	if len(reloaded.Retained) == 0 {
		t.Fatal("over the limit the other version must be compacted, not dropped")
	}

	for round := 0; round < 2; round++ {
		if _, err := stageProviderRuntime(cacheTestRaw("", candidate), policy, false); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(runningStaged); err != nil {
			t.Fatalf("round %d: the running version's file was swept after the manifest went over its limit: %v", round, err)
		}
	}
}

func TestFailedStagingSweepsWhatItWrote(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	good := stageRevision(t, home, "r1", cacheTestRulePayload)
	first, err := stageProviderRuntime(cacheTestRaw("", good), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	kept := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	staged := filepath.Dir(kept)

	failing := stageRevision(t, home, "r2", "payload:\n  - DOMAIN,example.org\n")
	raw := cacheTestRaw("", failing)
	raw.RuleProvider["zzz"] = map[string]any{"type": "file", "path": "", "behavior": "domain", "format": "yaml"}
	if _, err := stageProviderRuntime(raw, policy, false); err == nil {
		t.Fatal("an empty provider path must fail the staging")
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Join(staged, entry.Name()) != kept {
			t.Fatalf("a failed staging left %s behind", entry.Name())
		}
	}
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestManifestStillOverTheLimitFailsTheStaging(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	running := stageRevision(t, home, "r1", cacheTestRulePayload)
	first, err := stageProviderRuntime(cacheTestRaw("", running), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	runningStaged := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	parent := filepath.Join(home, providerRuntimeDirectoryName)
	before, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil {
		t.Fatal(err)
	}
	previous := maximumStagedManifestBytes
	maximumStagedManifestBytes = int64(len(before))
	t.Cleanup(func() { maximumStagedManifestBytes = previous })

	candidate := stageRevision(t, home, "r2", "payload:\n  - DOMAIN,example.org\n")
	_, err = stageProviderRuntime(cacheTestRaw("", candidate), policy, false)
	if err == nil || coreOutcomeOf(err).ErrorClass != CoreOutcomeUnknown {
		t.Fatalf("a manifest that cannot be recorded must fail the staging as unknown, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil || string(after) != string(before) {
		t.Fatalf("a manifest over the limit must not replace the previous one (err %v)", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(runningStaged))
	if len(entries) != 1 {
		t.Fatalf("the failed staging must leave only the running version's file, found %d entries", len(entries))
	}
}

func TestFailedStagingWithAnUnreadableManifestRemovesOnlyItsOwnFiles(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	policy := currentRuntimePolicy(true)
	running := stageRevision(t, home, "r1", cacheTestRulePayload)
	first, err := stageProviderRuntime(cacheTestRaw("", running), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	runningStaged := first.entries[providerRuntimeKey("rule", "ads")].runtimePath
	parent := filepath.Join(home, providerRuntimeDirectoryName)
	if err := os.WriteFile(filepath.Join(parent, providerRuntimeManifestName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := stageRevision(t, home, "r2", "payload:\n  - DOMAIN,example.org\n")
	raw := cacheTestRaw("", candidate)
	raw.RuleProvider["zzz"] = map[string]any{"type": "file", "path": "", "behavior": "domain", "format": "yaml"}
	if _, err := stageProviderRuntime(raw, policy, false); err == nil {
		t.Fatal("an empty provider path must fail the staging")
	}
	if _, err := os.Lstat(runningStaged); err != nil {
		t.Fatalf("a failed staging removed another version's product: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(runningStaged))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Join(filepath.Dir(runningStaged), entry.Name()) != runningStaged {
			t.Fatalf("a failed staging left %s behind", entry.Name())
		}
	}
}

func TestSideUpdateWithoutTheLockWritesNothing(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "store", "published", "providers")
	if err := os.MkdirAll(published, 0o700); err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.Join(published, "proxy.yaml")
	original := []byte("proxies:\n  - {name: Original, type: direct}\n")
	if err := os.WriteFile(proxyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	config := "mode: rule\ndns:\n  enable: true\n  nameserver: [8.8.8.8]\nproxy-providers:\n  controlled-proxy:\n    type: file\n    path: " +
		strconv.Quote(proxyPath) + "\nproxy-groups:\n  - {name: Controlled, type: select, use: [controlled-proxy]}\nrules:\n  - MATCH,DIRECT\n"
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	runtimePath := service.providerRuntime.entries[providerRuntimeKey("proxy", "controlled-proxy")].runtimePath

	unlock, locked := lockStagedProviderRuntime(filepath.Dir(filepath.Dir(runtimePath)))
	if !locked {
		t.Fatal("test could not take the lock")
	}
	defer unlock()
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait })

	err = service.sideUpdateProvider("proxy", "controlled-proxy", []byte("proxies:\n  - {name: Updated, type: direct}\n"), "")
	if err == nil || !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatalf("a side update without the staging lock must be deferred, got %v", err)
	}
	content, readErr := os.ReadFile(runtimePath)
	if readErr != nil || string(content) != string(original) {
		t.Fatalf("a refused side update changed the staged file: %q %v", content, readErr)
	}
}

func TestPublishPastTheLockFails(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	source := stageRevision(t, C.Path.HomeDir(), "r1", cacheTestRulePayload)
	config := "rule-providers:\n  ads:\n    type: file\n    behavior: classical\n    format: yaml\n    path: " + strconv.Quote(source) + "\nrules:\n  - RULE-SET,ads,DIRECT\n  - MATCH,DIRECT\n"
	parent := stagedProviderParentDirectory()
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait })
	err := StageProvidersForPublish(config, "", true)
	unlock()
	if err == nil {
		t.Fatal("a publish past the lock's wait published nothing and must say so")
	}
	if err := StageProvidersForPublish(config, "", true); err != nil {
		t.Fatalf("with the lock free the publish must succeed: %v", err)
	}
}

func TestPrivateStagingUsesTheSharedCompiledProduct(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "rules.yaml", "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,example.org\n")
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	published, err := stageProviderRuntime(stagingRawWithProviderPath(t, "rule", source), policy, true)
	if err != nil {
		t.Fatal(err)
	}
	var sharedPath string
	for _, entry := range published.entries {
		sharedPath = entry.runtimePath
	}
	if !strings.HasSuffix(sharedPath, providerRuntimeIndexStubSuffix) {
		t.Fatalf("the App's publish must have compiled the set: %s", sharedPath)
	}

	parent := filepath.Join(home, providerRuntimeDirectoryName)
	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	defer unlock()
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait })

	private, err := stageProviderRuntime(stagingRawWithProviderPath(t, "rule", source), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	defer private.close()
	var privatePath string
	for _, entry := range private.entries {
		privatePath = entry.runtimePath
	}
	if !private.private || !strings.HasSuffix(privatePath, providerRuntimeIndexStubSuffix) {
		t.Fatalf("a private pass must use the compiled product, got %s (private %v)", privatePath, private.private)
	}
	sharedInfo, err := os.Stat(sharedPath)
	if err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil || !os.SameFile(sharedInfo, privateInfo) {
		t.Fatalf("the private hit must be a link to the shared product (err %v)", err)
	}
	mappedName := strings.TrimSuffix(filepath.Base(privatePath), providerRuntimeIndexStubSuffix) + providerRuntimeMappedDomainSuffix
	sharedSet, err1 := os.Stat(filepath.Join(filepath.Dir(sharedPath), mappedName))
	privateSet, err2 := os.Stat(filepath.Join(filepath.Dir(privatePath), mappedName))
	if err1 != nil || err2 != nil || !os.SameFile(sharedSet, privateSet) {
		t.Fatalf("the private pass did not link the mapped set its stub names (%v, %v)", err1, err2)
	}

}

func TestAbandonedPrivateStagingIgnoresALinkedRoot(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "important.txt")
	if err := os.WriteFile(victim, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, providerRuntimePrivateDirectoryName)); err != nil {
		t.Fatal(err)
	}
	removeAbandonedPrivateStaging()
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("removal followed a linked root: %v", err)
	}
}

func TestReloadPanicAfterApplyKeepsThePrivateStaging(t *testing.T) {
	svc := startedServiceForOutcome(t)
	source := stageRevision(t, C.Path.HomeDir(), "r1", cacheTestRulePayload)
	config := helloYAML + "\nrule-providers:\n  ads:\n    type: file\n    behavior: classical\n    format: yaml\n    path: " + strconv.Quote(source) + "\n"
	parent := stagedProviderParentDirectory()
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	defer unlock()
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait; reloadTestPanicAfterApplyBegins.Store(false) })
	reloadTestPanicAfterApplyBegins.Store(true)

	if outcome := svc.ReloadClassified(config); outcome.ErrorClass != CoreOutcomeUnknown {
		t.Fatalf("a panic after applying began must be unknown: %q %q", outcome.ErrorClass, outcome.Message)
	}
	privateRoot := filepath.Join(C.Path.HomeDir(), providerRuntimePrivateDirectoryName)
	entries, err := os.ReadDir(privateRoot)
	if err != nil || len(entries) == 0 {
		t.Fatalf("the candidate's private staging must survive a panic after applying began (err %v)", err)
	}
	reloadTestPanicAfterApplyBegins.Store(false)
	unlock()
	if outcome := svc.ReloadClassified(helloYAML + "\n"); outcome.ErrorClass != "" {
		t.Fatalf("reload: %q %q", outcome.ErrorClass, outcome.Message)
	}
	entries, _ = os.ReadDir(privateRoot)
	if len(entries) != 0 {
		t.Fatalf("a committed reload must reclaim a private staging kept after a panic; %d left", len(entries))
	}
}

func TestCloseReclaimsAPrivateStagingKeptAfterAPanic(t *testing.T) {
	svc := startedServiceForOutcome(t)
	source := stageRevision(t, C.Path.HomeDir(), "r1", cacheTestRulePayload)
	config := helloYAML + "\nrule-providers:\n  ads:\n    type: file\n    behavior: classical\n    format: yaml\n    path: " + strconv.Quote(source) + "\n"
	parent := stagedProviderParentDirectory()
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait; reloadTestPanicAfterApplyBegins.Store(false) })
	reloadTestPanicAfterApplyBegins.Store(true)
	_ = svc.ReloadClassified(config)
	reloadTestPanicAfterApplyBegins.Store(false)
	unlock()
	privateRoot := filepath.Join(C.Path.HomeDir(), providerRuntimePrivateDirectoryName)
	if entries, _ := os.ReadDir(privateRoot); len(entries) == 0 {
		t.Fatal("the panic must have left a private staging")
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(privateRoot); len(entries) != 0 {
		t.Fatalf("Close must reclaim a private staging kept after a panic; %d left", len(entries))
	}
}

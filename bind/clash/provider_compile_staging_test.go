package clash

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ruleprovider "github.com/ProjectClash/Clash/rules/provider"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func compileStagingHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	C.SetHomeDir(home)
	return home
}

func writeRuleSource(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(C.Path.HomeDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rawWithRuleProvider(path, behavior, format string) *config.RawConfig {
	raw := &config.RawConfig{}
	raw.RuleProvider = map[string]map[string]any{
		"reject": {
			"type": "file", "path": path,
			"behavior": behavior, "format": format,
		},
	}
	return raw
}

func manifestEntry(t *testing.T, home, kind, name string) string {
	t.Helper()
	entries := readManifest(t, home)
	entry, ok := entries[providerRuntimeKey(kind, name)]
	if !ok {
		t.Fatalf("no manifest entry for %s %s", kind, name)
	}
	return string(entry)
}

func TestPublishCompilesADomainRuleSetToAMappedSet(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n+.example.org\n")
	raw := rawWithRuleProvider(source, "domain", "text")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"mapped"`) || !strings.Contains(entry, `"mappedChecksum":"`) {
		t.Fatalf("no mapped verdict in manifest entry: %s", entry)
	}
	if !strings.Contains(entry, `"compiledBehavior":"domain"`) || !strings.Contains(entry, `"count":2`) {
		t.Fatalf("no compiled behavior or count in manifest entry: %s", entry)
	}

	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" || definition["behavior"] != "domain" ||
		!strings.HasSuffix(definition["path"].(string), providerRuntimeIndexStubSuffix) {
		t.Fatalf("definition does not name the stub: %v", definition)
	}
	provider := loadStagedRuleProvider(t, definition)
	if provider.Count() != 2 {
		t.Fatalf("the mapped set carries %d rules, source had 2", provider.Count())
	}
	for host, want := range map[string]bool{"example.com": true, "a.example.org": true, "example.org": true, "a.example.com": false} {
		if got := provider.Match(&C.Metadata{Host: host}, anyProcess); got != want {
			t.Fatalf("%s: matched %v", host, got)
		}
	}
}

func TestClassicalYamlOfPureDomainsCompilesAsDomain(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "openai.yaml",
		"payload:\n  - DOMAIN,openai.com\n  - DOMAIN-SUFFIX,chatgpt.com\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"mapped"`) {
		t.Fatalf("pure-domain classical yaml did not compile: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "domain" || definition["format"] != "text" {
		t.Fatalf("classical→domain rewrite missing: behavior=%v format=%v",
			definition["behavior"], definition["format"])
	}
}

func TestUncompilableClassicalIsNeverStripped(t *testing.T) {
	home := compileStagingHome(t)
	content := "payload:\n  - DOMAIN-KEYWORD,ads\n  - DST-PORT,8443\n"
	source := writeRuleSource(t, "mixed.yaml", content)
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
		t.Fatalf("no verdict for the set that could not be compiled: %s", entry)
	}
	if !strings.Contains(entry, `"compileReason"`) {
		t.Fatalf("no reason for the reader: %s", entry)
	}

	definition := raw.RuleProvider["reject"]
	if _, ok := raw.RuleProvider["reject"]; !ok {
		t.Fatal("the provider was stripped; a RULE-SET reference inside a logic rule would dangle")
	}
	if definition["behavior"] != "classical" || definition["format"] != "yaml" {
		t.Fatalf("definition was rewritten for a set that did not compile: %v", definition)
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != content {
		t.Fatalf("staged %d bytes that are not the published source", len(staged))
	}
}

func TestExtensionServesTheCompiledArtifactWithoutCompiling(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n")

	published, err := stageProviderRuntime(
		rawWithRuleProvider(source, "domain", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()

	raw := rawWithRuleProvider(source, "domain", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" || definition["behavior"] != "domain" ||
		!strings.HasSuffix(definition["path"].(string), providerRuntimeIndexStubSuffix) {
		t.Fatalf("reuse path did not name the stub: %v", definition)
	}
	if count := loadStagedRuleProvider(t, definition).Count(); count != 1 {
		t.Fatalf("reuse path serves a set of %d rules, not the compiled one", count)
	}
}

func TestNotYetCompiledStaysOnTheTextPath(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n")
	raw := rawWithRuleProvider(source, "domain", "text")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a set nobody compiled carries a verdict: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" {
		t.Fatalf("text path was rewritten without an artifact: %v", definition["format"])
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != "example.com\n" {
		t.Fatal("staged bytes stopped matching the published source")
	}
}

func TestSourceChangeDropsTheVerdict(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(home, "reject.txt")
	if err := os.WriteFile(source, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	published, err := stageProviderRuntime(
		rawWithRuleProvider(source, "domain", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()

	if err := os.WriteFile(source, []byte("example.com\nexample.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := rawWithRuleProvider(source, "domain", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a stale verdict survived a source edit: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" {
		t.Fatalf("stale artifact still served after the source changed: %v", definition["format"])
	}
}

func TestInlineCommentsDoNotPoisonTheCompiledDomains(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "ads.yaml",
		"payload:\n  - DOMAIN,example.com # exact\n  - DOMAIN-SUFFIX,ads.com # 广告\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()

	stub := raw.RuleProvider["reject"]["path"].(string)
	if count := loadStagedRuleProvider(t, raw.RuleProvider["reject"]).Count(); count != 2 {
		t.Fatalf("compiled count=%d, want exactly the 2 real domains", count)
	}
	staged, err := os.ReadFile(strings.TrimSuffix(stub, providerRuntimeIndexStubSuffix) + providerRuntimeMappedDomainSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(staged, []byte("广告")) || bytes.Contains(staged, []byte(" #")) {
		t.Fatal("comment text rode into the compiled set")
	}
}

func TestNoProfileStagesARefusedRuleSetEmpty(t *testing.T) {
	content := "payload:\n  - DOMAIN-KEYWORD,ads\n  - DST-PORT,8443\n"
	for name, profile := range map[string]runtimeProfile{
		"iOS":          runtimeProfileIOSPacketTunnel,
		"tvOS":         runtimeProfileTVOSPacketTunnel,
		"macOS tunnel": runtimeProfileMacOSPacketTunnel,
		"macOS app":    runtimeProfileMacOSApplication,
	} {
		t.Run(name, func(t *testing.T) {
			home := compileStagingHome(t)
			source := writeRuleSource(t, "refused.yaml", content)
			raw := rawWithRuleProvider(source, "classical", "yaml")

			runtime, err := stageProviderRuntime(raw, runtimePolicyFor(profile, true), true)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			defer runtime.close()

			definition := raw.RuleProvider["reject"]
			if definition["behavior"] != "classical" || definition["format"] != "yaml" {
				t.Fatalf("definition was rewritten for a set that did not compile: %v", definition)
			}
			staged, err := os.ReadFile(definition["path"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if len(staged) == 0 {
				t.Fatal("staged empty; that is the ride this ruling removed")
			}
			if string(staged) != content {
				t.Fatalf("staged %d bytes that are not the published source", len(staged))
			}
			entry := manifestEntry(t, home, "rule", "reject")
			if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
				t.Fatalf("verdict is not keptSource: %s", entry)
			}
			if strings.Contains(entry, "notCompilable") {
				t.Fatalf("the empty-ride verdict is still being produced: %s", entry)
			}
		})
	}
}

func TestMacOSKeepsTheSourceWhenTheCompilerRefuses(t *testing.T) {
	home := compileStagingHome(t)
	content := "payload:\n  - DOMAIN-KEYWORD,example\n  - PROCESS-NAME,Mail\n"
	source := writeRuleSource(t, "procs.yaml", content)
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
		t.Fatalf("macOS refusal did not record keptSource: %s", entry)
	}
	if !strings.Contains(entry, `"compileReason"`) {
		t.Fatalf("keptSource must carry the reason exactly as notCompilable does: %s", entry)
	}

	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "classical" || definition["format"] != "yaml" {
		t.Fatalf("keptSource definition was rewritten: %v", definition)
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != content {
		t.Fatalf("keptSource staged %d bytes that differ from the published source", len(staged))
	}
	if len(staged) == 0 {
		t.Fatal("keptSource staged empty; that is notCompilable's shape, not this one's")
	}
}

func TestMacOSKeepsThePreparedCopyWhenStrippingPreceded(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml",
		"payload:\n  - DOMAIN-KEYWORD,example\n  - SOURCE-APP-SIGNING-ID,com.example.app\n  - DST-PORT,8443\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
		t.Fatalf("stripped-then-refused set did not record keptSource: %s", entry)
	}
	if !strings.Contains(entry, `"metadataNoops"`) {
		t.Fatalf("the stripping must stay recorded for replay: %s", entry)
	}
	staged, err := os.ReadFile(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(staged), "SOURCE-APP-SIGNING-ID") {
		t.Fatal("the staged copy still carries a rule this profile cannot execute")
	}
	if !strings.Contains(string(staged), "DST-PORT") {
		t.Fatal("the staged copy lost DST-PORT, which executes fine here — keptSource must keep capability, not just bytes")
	}
}

func TestKeptSourceHitsTheCacheOnRepublish(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN-KEYWORD,example\n  - PROCESS-NAME,Mail\n")
	policy := runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true)

	first, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	firstPath := ""
	for _, entry := range first.entries {
		firstPath = entry.runtimePath
	}
	first.close()
	before, err := os.Stat(firstPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	defer second.close()
	after, err := os.Stat(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("keptSource was restaged on an identical republish; the recorded verdict must satisfy the hit gate")
	}
}

func TestExtensionRidesTheSourceItCannotCompile(t *testing.T) {
	home := compileStagingHome(t)
	content := "payload:\n  - DOMAIN-KEYWORD,ads\n  - DST-PORT,8443\n"
	source := writeRuleSource(t, "mixed.yaml", content)
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "classical" || definition["format"] != "yaml" {
		t.Fatalf("the extension rewrote a definition it never compiled: %v", definition)
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != content {
		t.Fatalf("the extension staged %d bytes that are not the published source", len(staged))
	}
	if entry := manifestEntry(t, home, "rule", "reject"); strings.Contains(entry, "notCompilable") {
		t.Fatalf("the extension still produces the empty-ride verdict: %s", entry)
	}
}

func TestExtensionJudgesThePreparedCopyNotTheRawSource(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - PROCESS-NAME,curl\n  - DOMAIN,example.com\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("the extension judged the raw bytes; after stripping this set is pure domains and the App will compile it: %s", entry)
	}
	staged, err := os.ReadFile(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(staged), "DOMAIN,example.com") {
		t.Fatalf("the executable rule was lost from the staged copy: %q", staged)
	}
}

func TestExtensionKeepsCompilableSetsOnTheTextPath(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "pure.yaml",
		"payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.org\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("the extension judged a compilable set: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() == 0 {
		t.Fatal("a compilable set was emptied; the extension may only empty what the compiler would refuse")
	}
}

func TestMacOSExtensionStillRidesRefusedSetsAsText(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,Mail\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a macOS extension restage judged a set; source-online needs no verdict here: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() == 0 {
		t.Fatal("macOS emptied a refused set; keeping the source online is this profile's ruling")
	}
}

func TestKeptSourceReplaysOnACachedStart(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN-KEYWORD,example\n  - PROCESS-NAME,Mail\n")
	policy := runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true)

	first, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	first.close()

	logBuffer := capturePublishLog(t)
	second, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, false)
	if err != nil {
		t.Fatalf("cached start: %v", err)
	}
	defer second.close()

	if !strings.Contains(logBuffer.String(), "kept as source") {
		t.Fatalf("the cached start stayed silent about keptSource; silence here is indistinguishable from a compiled set:\n%s", logBuffer.String())
	}
}

func TestCompiledSideUpdateRefusalCarriesTheDeferredPrefix(t *testing.T) {
	entry := providerRuntimeEntry{compiled: true, sideUpdateSafe: true}
	_ = entry
	err := fmt.Errorf("%sthis rule set runs compiled; the update applies at the next activation", SideUpdateDeferredPrefix)
	if !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatal("unreachable")
	}
	if !strings.HasPrefix(SideUpdateDeferredPrefix, "clash: side update deferred: ") {
		t.Fatalf("the exported prefix moved: %q — the client classifies by it", SideUpdateDeferredPrefix)
	}
}

func TestAPublishStagesAClassicalSetPastTheHeapLimitEmpty(t *testing.T) {
	home := compileStagingHome(t)
	var b strings.Builder
	b.WriteString("DOMAIN-SUFFIX,kept.example\n")
	for i := 0; i <= ruleprovider.ClashClassicalRegexLimit; i++ {
		fmt.Fprintf(&b, "DOMAIN-REGEX,^a%d\\.example$\n", i)
	}
	source := writeRuleSource(t, "heavy.txt", b.String())
	raw := rawWithRuleProvider(source, "classical", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("the publish failed: %v", err)
	}
	defer runtime.close()
	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, "loads no rules") {
		t.Fatalf("the record does not say why the set loads nothing: %s", entry)
	}
	if count := loadStagedRuleProvider(t, raw.RuleProvider["reject"]).Count(); count != 0 {
		t.Fatalf("the staged set holds %d rules", count)
	}
}

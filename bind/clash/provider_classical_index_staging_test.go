package clash

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules"
	RB "github.com/ProjectClash/Clash/rules/bundle"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
)

const indexedClassicalText = "DOMAIN-SUFFIX,example.com\nDOMAIN,a.example.org\nDOMAIN-KEYWORD,ads\n" +
	"IP-CIDR,10.0.0.0/8,no-resolve\nAND,((DOMAIN,b.example.net),(DST-PORT,443))\n"

func indexedClassicalSource(format string) string {
	if format == "text" {
		return indexedClassicalText
	}
	yaml := "payload:\n"
	for _, line := range strings.Split(strings.TrimSpace(indexedClassicalText), "\n") {
		yaml += "  - '" + line + "'\n"
	}
	return yaml
}

type stagedRecordView struct {
	File           string `json:"file"`
	Count          int    `json:"count"`
	CompileVerdict string `json:"compileVerdict"`
	IndexJudged    bool   `json:"indexJudged"`
}

func stagedRuleRecord(t *testing.T, home string) stagedRecordView {
	t.Helper()
	var record stagedRecordView
	if err := json.Unmarshal([]byte(manifestEntry(t, home, "rule", "reject")), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func loadStagedRuleProvider(t *testing.T, definition map[string]any) P.RuleProvider {
	t.Helper()
	provider, err := ruleprovider.ParseRuleProvider("reject", definition, rules.ParseRule, RB.MakeBundleFile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.(detachedRuleLoader).LoadDetached(payload, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})
	return provider
}

var anyProcess = C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}

func answersTheIndexedSet(t *testing.T, provider P.RuleProvider) {
	t.Helper()
	if provider.Count() != 5 {
		t.Fatalf("%d rules loaded, the set holds 5", provider.Count())
	}
	for _, probe := range []struct {
		metadata C.Metadata
		want     bool
	}{
		{C.Metadata{Host: "www.example.com"}, true},
		{C.Metadata{Host: "a.example.org"}, true},
		{C.Metadata{Host: "x.a.example.org"}, false},
		{C.Metadata{Host: "cdn.ads.test"}, true},
		{C.Metadata{DstIP: netip.MustParseAddr("10.1.2.3")}, true},
		{C.Metadata{Host: "b.example.net", DstPort: 443}, true},
		{C.Metadata{Host: "b.example.net", DstPort: 80}, false},
		{C.Metadata{Host: "nomatch.invalid"}, false},
	} {
		metadata := probe.metadata
		if got := provider.Match(&metadata, anyProcess); got != probe.want {
			t.Errorf("%+v: matched %v", probe.metadata, got)
		}
	}
}

func TestPublishIndexesAClassicalSetThatHoldsNames(t *testing.T) {
	for _, format := range []string{"text", "yaml"} {
		t.Run(format, func(t *testing.T) {
			home := compileStagingHome(t)
			content := indexedClassicalSource(format)
			source := writeRuleSource(t, "mixed."+format, content)
			raw := rawWithRuleProvider(source, "classical", format)
			runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.close()

			record := stagedRuleRecord(t, home)
			if record.CompileVerdict != compileVerdictIndexed || record.Count != 5 ||
				!strings.HasSuffix(record.File, providerRuntimeIndexStubSuffix) {
				t.Fatalf("record %+v", record)
			}
			definition := raw.RuleProvider["reject"]
			if definition["behavior"] != "classical" || definition["format"] != format {
				t.Fatalf("the definition changed: %v", definition)
			}
			stubPath := definition["path"].(string)
			if filepath.Base(stubPath) != record.File {
				t.Fatalf("the definition names %s, the record %s", stubPath, record.File)
			}
			textPath := strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix)
			if text, err := os.ReadFile(textPath); err != nil || string(text) != content {
				t.Fatalf("the text staging beside the stub is not the published source (%v)", err)
			}
			stub, err := os.ReadFile(stubPath)
			if err != nil || !strings.Contains(string(stub), ruleprovider.ClashClassicalIndexStubType+",") ||
				strings.Count(string(stub), ruleprovider.ClashClassicalIndexStubType) != 1 {
				t.Fatalf("stub %q (%v)", stub, err)
			}
			if !runtime.entries[providerRuntimeKey("rule", "reject")].compiled {
				t.Error("a side update would be served to an indexed set as text")
			}
			answersTheIndexedSet(t, loadStagedRuleProvider(t, definition))
			if err := os.Remove(textPath); err != nil {
				t.Fatal(err)
			}
			answersTheIndexedSet(t, loadStagedRuleProvider(t, definition))
		})
	}
}

func TestExtensionServesTheIndexWithoutCompiling(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml", indexedClassicalSource("yaml"))
	published, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	published.close()

	raw := rawWithRuleProvider(source, "classical", "yaml")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()
	record := stagedRuleRecord(t, home)
	if record.CompileVerdict != compileVerdictIndexed || filepath.Base(raw.RuleProvider["reject"]["path"].(string)) != record.File {
		t.Fatalf("the extension did not serve the index: %+v, path %v", record, raw.RuleProvider["reject"]["path"])
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestAnIndexedRecordWithoutItsIndexIsStagedAgain(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	published, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	stubPath := raw.RuleProvider["reject"]["path"].(string)
	published.close()
	if err := os.Remove(strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix) + providerRuntimeIndexSuffix); err != nil {
		t.Fatal(err)
	}

	raw = rawWithRuleProvider(source, "classical", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	if path := raw.RuleProvider["reject"]["path"].(string); strings.HasSuffix(path, providerRuntimeIndexStubSuffix) {
		t.Fatalf("a stub without its index was served: %s", path)
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
	runtime.close()

	raw = rawWithRuleProvider(source, "classical", "text")
	again, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer again.close()
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictIndexed {
		t.Fatalf("the next publish did not index the set again: %+v", record)
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestAKeptSourceRecordFromBeforeTheIndexIsJudgedOnce(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	published, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	stubPath := raw.RuleProvider["reject"]["path"].(string)
	textPath := strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix)
	published.close()

	manifestPath := filepath.Join(home, providerRuntimeDirectoryName, providerRuntimeManifestName)
	var manifest stagedProviderManifest
	payload, err := os.ReadFile(manifestPath)
	if err != nil || json.Unmarshal(payload, &manifest) != nil {
		t.Fatalf("manifest: %v", err)
	}
	text, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	key := providerRuntimeKey("rule", "reject")
	record := manifest.Entries[key]
	record.CompileVerdict = compileVerdictKeptSource
	record.File = filepath.Base(textPath)
	record.StagedSize = int64(len(text))
	record.ContentSHA256 = stagedFileDigest(text)
	record.IndexJudged = false
	manifest.Entries[key] = record
	if payload, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stubPath, textPath + providerRuntimeIndexSuffix} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	raw = rawWithRuleProvider(source, "classical", "text")
	extension, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	if path := raw.RuleProvider["reject"]["path"].(string); path != textPath {
		t.Fatalf("the extension did not serve the kept-source record: %s", path)
	}
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictKeptSource {
		t.Fatalf("the extension restaged the record: %+v", record)
	}
	extension.close()

	raw = rawWithRuleProvider(source, "classical", "text")
	publish, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer publish.close()
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictIndexed {
		t.Fatalf("the publish did not judge the kept-source record for an index: %+v", record)
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestASetWithoutNamesIsJudgedForAnIndexOnce(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "nameless.txt", "DOMAIN-KEYWORD,ads\nDST-PORT,8443\n")
	first, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	first.close()
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictKeptSource || !record.IndexJudged {
		t.Fatalf("record %+v", record)
	}
	logged := capturePublishLog(t)
	second, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if strings.Contains(logged.String(), "rides as text on this profile") || !strings.Contains(logged.String(), "kept as source, every rule loads") {
		t.Fatalf("the second publish staged the set again:\n%s", logged.String())
	}
}

func TestSweepKeepsAnIndexWithItsStubAndText(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	runtime.close()
	stubPath := raw.RuleProvider["reject"]["path"].(string)
	textPath := strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix)
	directory := filepath.Dir(stubPath)
	stray := filepath.Join(directory, strings.Repeat("0", 64)+".provider"+providerRuntimeIndexSuffix)
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sweepStagedProviderRuntime(filepath.Dir(directory), directory, map[string]struct{}{filepath.Base(stubPath): {}})
	for _, path := range []string{stubPath, textPath, textPath + providerRuntimeIndexSuffix} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("the sweep took %s: %v", filepath.Base(path), err)
		}
	}
	if _, err := os.Lstat(stray); !os.IsNotExist(err) {
		t.Error("the sweep kept an index no staging names")
	}
}

func TestAPrivatePassServesTheIndexFromItsOwnDirectory(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	published, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	published.close()

	parent := filepath.Join(home, providerRuntimeDirectoryName)
	unlock, locked := lockStagedProviderRuntime(parent)
	if !locked {
		t.Fatal("test could not take the lock")
	}
	defer unlock()
	previousWait := stagingLockWait
	stagingLockWait = 100 * time.Millisecond
	t.Cleanup(func() { stagingLockWait = previousWait })

	raw := rawWithRuleProvider(source, "classical", "text")
	private, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	defer private.close()
	path := raw.RuleProvider["reject"]["path"].(string)
	if !private.private || filepath.Dir(path) != private.directory || !strings.HasSuffix(path, providerRuntimeIndexStubSuffix) {
		t.Fatalf("the private pass did not serve the index from its directory: %s", path)
	}
	shared := filepath.Join(parent, providerRuntimeStagedDirectoryName)
	files, _ := os.ReadDir(shared)
	for _, file := range files {
		_ = os.Remove(filepath.Join(shared, file.Name()))
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestAnIndexedSetsSideUpdateWaitsForTheNextActivation(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	raw.RuleProvider["reject"][providerSideUpdateSafeField] = true
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()
	stubPath := runtime.entries[providerRuntimeKey("rule", "reject")].runtimePath
	before, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatal(err)
	}
	service := &BoxService{running: true, providerRuntime: runtime}
	err = service.sideUpdateProvider("rule", "reject", []byte("DOMAIN,new.example\n"), "")
	if err == nil || !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatalf("the side update was not deferred: %v", err)
	}
	if after, err := os.ReadFile(stubPath); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the stub was written (%v)", err)
	}
}

func TestTheMacKeepsProcessRulesInAnIndexedSet(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.txt",
		"DOMAIN,example.com\nPROCESS-NAME,Telegram\nAND,((PROCESS-NAME,Mail),(DOMAIN-SUFFIX,example.org))\n")
	raw := rawWithRuleProvider(source, "classical", "text")
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictIndexed || record.Count != 3 {
		t.Fatalf("record %+v", record)
	}
	provider := loadStagedRuleProvider(t, raw.RuleProvider["reject"])
	if provider.Count() != 3 {
		t.Fatalf("%d rules loaded", provider.Count())
	}
	for _, probe := range []struct {
		metadata C.Metadata
		want     bool
	}{
		{C.Metadata{Host: "x.test", Process: "Telegram"}, true},
		{C.Metadata{Host: "x.example.org", Process: "Mail"}, true},
		{C.Metadata{Host: "x.example.org", Process: "Safari"}, false},
		{C.Metadata{Host: "example.com"}, true},
	} {
		metadata := probe.metadata
		if got := provider.Match(&metadata, anyProcess); got != probe.want {
			t.Errorf("%+v: matched %v", probe.metadata, got)
		}
	}
}

func TestAnIndexIsCompiledFromThePreparedCopy(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml",
		"payload:\n  - DOMAIN,example.com\n  - SOURCE-APP-SIGNING-ID,com.example.app\n  - IP-CIDR,10.0.0.0/8\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()
	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"indexed"`) || !strings.Contains(entry, `"metadataNoops"`) || !strings.Contains(entry, `"count":2`) {
		t.Fatalf("entry %s", entry)
	}
	stubPath := raw.RuleProvider["reject"]["path"].(string)
	text, err := os.ReadFile(strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix))
	if err != nil || strings.Contains(string(text), "SOURCE-APP-SIGNING-ID") || !strings.Contains(string(text), "IP-CIDR") {
		t.Fatalf("the text staging is not the prepared copy: %q (%v)", text, err)
	}
	index, err := os.ReadFile(strings.TrimSuffix(stubPath, providerRuntimeIndexStubSuffix) + providerRuntimeIndexSuffix)
	if err != nil || bytes.Contains(index, []byte("SOURCE-APP-SIGNING-ID")) {
		t.Fatalf("the index carries a stripped rule (%v)", err)
	}
	provider := loadStagedRuleProvider(t, raw.RuleProvider["reject"])
	if provider.Count() != 2 {
		t.Fatalf("%d rules loaded", provider.Count())
	}
	for _, probe := range []C.Metadata{{Host: "example.com"}, {DstIP: netip.MustParseAddr("10.9.9.9")}} {
		metadata := probe
		if !provider.Match(&metadata, anyProcess) {
			t.Errorf("%+v did not match", probe)
		}
	}
}

func TestAnIndexedRecordIsServedOnlyWithItsOwnIndex(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	published, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := strings.TrimSuffix(raw.RuleProvider["reject"]["path"].(string), providerRuntimeIndexStubSuffix) + providerRuntimeIndexSuffix
	published.close()
	foreign, err := ruleprovider.ClashCompileClassicalIndex([]string{"DOMAIN,foreign.zzq", "DOMAIN-KEYWORD,foreign"}, rules.ParseRule)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeProviderFile(indexPath, foreign.Bytes); err != nil {
		t.Fatal(err)
	}

	raw = rawWithRuleProvider(source, "classical", "text")
	extension, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	if path := raw.RuleProvider["reject"]["path"].(string); strings.HasSuffix(path, providerRuntimeIndexStubSuffix) {
		t.Fatalf("a stub was served beside another set's index: %s", path)
	}
	provider := loadStagedRuleProvider(t, raw.RuleProvider["reject"])
	answersTheIndexedSet(t, provider)
	if provider.Match(&C.Metadata{Host: "foreign.zzq"}, anyProcess) {
		t.Error("another set's rules were loaded")
	}
	extension.close()

	raw = rawWithRuleProvider(source, "classical", "text")
	publish, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer publish.close()
	if record := stagedRuleRecord(t, home); record.CompileVerdict != compileVerdictIndexed {
		t.Fatalf("the publish did not compile the set again: %+v", record)
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestAChangedIndexIsCompiledAgainByThePublish(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "mixed.txt", indexedClassicalText)
	raw := rawWithRuleProvider(source, "classical", "text")
	published, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := strings.TrimSuffix(raw.RuleProvider["reject"]["path"].(string), providerRuntimeIndexStubSuffix) + providerRuntimeIndexSuffix
	published.close()
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 0x10
	if err := writeRuntimeProviderFile(indexPath, data); err != nil {
		t.Fatal(err)
	}

	raw = rawWithRuleProvider(source, "classical", "text")
	extension, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
	extension.close()

	raw = rawWithRuleProvider(source, "classical", "text")
	publish, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer publish.close()
	if _, ok := ruleprovider.ClashClassicalIndexChecksumOf(indexPath, true); !ok {
		t.Fatal("the publish served the changed index instead of compiling the set again")
	}
	answersTheIndexedSet(t, loadStagedRuleProvider(t, raw.RuleProvider["reject"]))
}

func TestALinkNamedLikeAStubIsNotOne(t *testing.T) {
	home := compileStagingHome(t)
	payload := filepath.Join(home, "untrusted.txt")
	link := filepath.Join(home, "untrusted"+providerRuntimeIndexStubSuffix)
	if err := os.WriteFile(payload, []byte(ruleprovider.ClashClassicalIndexStub("absent.idx", 0, "not-staged.txt", P.TextRule)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "not-staged.txt"), []byte("DOMAIN,not-staged.zzq\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(payload, link); err != nil {
		t.Fatal(err)
	}
	raw := rawWithRuleProvider(link, "classical", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		defer runtime.close()
	}
	provider := loadStagedRuleProvider(t, raw.RuleProvider["reject"])
	if provider.Match(&C.Metadata{Host: "not-staged.zzq"}, anyProcess) || provider.Count() != 0 {
		t.Errorf("the linked stub was honoured: %d rules", provider.Count())
	}
}

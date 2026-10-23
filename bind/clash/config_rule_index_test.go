package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/clashsum"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
	"go.yaml.in/yaml/v3"
)

func ruleIndexTestDocument(rules int) string {
	var b strings.Builder
	b.WriteString("mode: rule\nproxies:\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "  - {name: \"N %d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: Proxy, type: select, proxies: [\"N 0\", \"N 1\", DIRECT]}\n")
	b.WriteString("sub-rules:\n  s1:\n    - DOMAIN-SUFFIX,sub.example,Proxy\n    - MATCH,DIRECT\n")
	b.WriteString("rules:\n")
	for i := 0; i < rules; i++ {
		switch i % 6 {
		case 0:
			fmt.Fprintf(&b, "  - DOMAIN,d%d.example.com,Proxy\n", i)
		case 1:
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,s%d.example.org,N %d\n", i, i%20)
		case 2:
			fmt.Fprintf(&b, "  - DOMAIN-KEYWORD,k%d,REJECT\n", i)
		case 3:
			fmt.Fprintf(&b, "  - IP-CIDR,10.%d.%d.0/24,DIRECT,no-resolve\n", (i/256)%256, i%256)
		case 4:
			fmt.Fprintf(&b, "  - 'DST-PORT,%d,Proxy'\n", 1000+i%50000)
		case 5:
			b.WriteString("  - SUB-RULE,(NETWORK,tcp),s1\n")
		}
	}
	b.WriteString("  - MATCH,Proxy\n")
	return b.String()
}

func finalizeWithRuleIndex(t *testing.T, document, dir string) (string, map[string]any) {
	t.Helper()
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized.Value), &root); err != nil {
		t.Fatal(err)
	}
	return finalized.Value, root
}

func TestFinalizeCompilesTheRulesIntoAnIndex(t *testing.T) {
	dir := t.TempDir()
	document := ruleIndexTestDocument(3000)
	published, root := finalizeWithRuleIndex(t, document, dir)
	if _, ok := root["rules"]; ok {
		t.Fatal("the published configuration still writes its rules")
	}
	reference, _ := root["x-clash-rule-index"].(map[string]any)
	path, _ := reference["path"].(string)
	if path == "" || filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), ruleIndexPrefix) {
		t.Fatalf("no index named in %s: %+v", dir, reference)
	}
	if len(published) > 20000 {
		t.Fatalf("the published configuration is %d bytes", len(published))
	}
	fromIndex, err := parseAfterLookups(published)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := parseAfterLookups(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fromIndex.RuleTable.(*clashindex.Table); !ok || fromIndex.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("%T of %d rules, want the index of %d", fromIndex.RuleTable, fromIndex.RuleTable.Len(), inline.RuleTable.Len())
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), fromIndex.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Fatalf("rule %d: inline %s,%s,%s; published %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
	}
	for _, host := range []string{"d6.example.com", "x.s7.example.org", "ak14z", "nothing.example"} {
		m1 := &C.Metadata{Host: host, NetWork: C.TCP, DstPort: 443}
		m2 := *m1
		var first1, first2 int
		inline.RuleTable.Walk(m1, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { first1 = i; return true })
		fromIndex.RuleTable.Walk(&m2, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { first2 = i; return true })
		if first1 != first2 {
			t.Fatalf("%s: inline rule %d, published %d", host, first1, first2)
		}
	}
	before, _ := os.Stat(path)
	proof := path + clashsum.ProofSuffix
	proofBefore, err := os.Stat(proof)
	if err != nil {
		t.Fatalf("no proof beside the index: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	again, _ := finalizeWithRuleIndex(t, document, dir)
	if again != published {
		t.Fatal("publishing the same rules again named another index")
	}
	if after, _ := os.Stat(proof); !after.ModTime().Equal(proofBefore.ModTime()) {
		t.Fatal("an index marked a moment ago was marked again")
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("a use set the index's own time")
	}
	earlier := time.Now().Add(-nodeLibraryMarkEvery - time.Second)
	for _, file := range []string{path, proof} {
		if err := os.Chtimes(file, earlier, earlier); err != nil {
			t.Fatal(err)
		}
	}
	if again, _ = finalizeWithRuleIndex(t, document, dir); again != published {
		t.Fatal("publishing the same rules again named another index")
	}
	if after, _ := os.Stat(proof); !after.ModTime().After(earlier.Add(time.Second)) {
		t.Fatal("an index used again is not marked used")
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(earlier.Truncate(time.Microsecond)) && !after.ModTime().Equal(earlier) {
		t.Fatalf("a use set the index's own time: %v, written %v", after.ModTime(), earlier)
	}
	republished, _ := finalizeWithRuleIndex(t, published, dir)
	if !strings.Contains(republished, filepath.Base(path)) {
		t.Fatal("a published configuration published again lost its index")
	}
}

func TestFinalizeRefusesARuleAsTheTunnelWould(t *testing.T) {
	for _, bad := range []string{"DOMAIN,a.example,Nowhere", "IP-CIDR,10.0.0.0/33,DIRECT", "RULE-SET,none,DIRECT", "SUB-RULE,(NETWORK,tcp),none"} {
		document := strings.Replace(ruleIndexTestDocument(30), "  - MATCH,Proxy\n", "  - "+bad+"\n  - MATCH,Proxy\n", 1)
		_, want := config.Parse([]byte(document))
		resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir()})
		_, got := FinalizeForIOS(document, string(resources))
		if want == nil || got == nil || !strings.Contains(got.Error(), strings.TrimPrefix(want.Error(), "clash: ")) {
			t.Errorf("%s: Finalize %v, Parse %v", bad, got, want)
		}
	}
}

func TestARuleIndexStaysWhileTheAppKeepsItAndGoesAfter(t *testing.T) {
	dir := t.TempDir()
	_, root := finalizeWithRuleIndex(t, ruleIndexTestDocument(60), dir)
	kept := root["x-clash-rule-index"].(map[string]any)["path"].(string)
	_, other := finalizeWithRuleIndex(t, ruleIndexTestDocument(61), dir)
	stale := other["x-clash-rule-index"].(map[string]any)["path"].(string)
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{kept, stale, kept + clashsum.ProofSuffix, stale + clashsum.ProofSuffix} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := PruneRuleIndexesKeeping(dir, `["`+kept+`"]`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("the index kept was removed")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("an index no configuration keeps stayed")
	}
	if _, err := os.Stat(stale + clashsum.ProofSuffix); err == nil {
		t.Fatal("an index removed left its proof")
	}
	if _, err := os.Stat(kept + clashsum.ProofSuffix); err != nil {
		t.Fatal("the index kept lost its proof")
	}
	libraries, _ := filepath.Glob(filepath.Join(dir, nodeLibraryPrefix+"*"))
	if len(libraries) == 0 {
		t.Fatal("no node library written beside the index")
	}
	for _, library := range libraries {
		_ = os.Chtimes(library, old, old)
	}
	if err := PruneNodeLibraries(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("a node prune removed a rule index")
	}
}

func TestAPublishedConfigurationWhoseIndexIsGoneIsRefused(t *testing.T) {
	dir := t.TempDir()
	published, root := finalizeWithRuleIndex(t, ruleIndexTestDocument(60), dir)
	path := root["x-clash-rule-index"].(map[string]any)["path"].(string)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir})
	if _, err := FinalizeForIOS(published, string(resources)); err == nil || !strings.Contains(err.Error(), "x-clash-rule-index") {
		t.Fatalf("a published configuration without its index published: %v", err)
	}
	if _, err := parseAfterLookups(published); err == nil || !strings.Contains(err.Error(), RuleIndexUnavailablePrefix) {
		t.Fatalf("the tunnel's start: %v", err)
	}
	carried := ruleIndexTestDocument(10) + "x-clash-rule-index: {path: /nowhere, sha256: " + strings.Repeat("0", 64) + "}\n"
	if _, root := finalizeWithRuleIndex(t, carried, dir); root["x-clash-rule-index"].(map[string]any)["path"] == "/nowhere" {
		t.Fatal("a reference the document carried was kept")
	}
}

func TestAnIndexOfTheRightNameButOtherRulesIsNotUsed(t *testing.T) {
	dir := t.TempDir()
	docA := "rules:\n  - DOMAIN,a.example,REJECT\n  - DOMAIN,b.example,DIRECT\n"
	docB := "rules:\n  - DOMAIN,c.example,REJECT\n  - DOMAIN,b.example,DIRECT\n"
	_, rootA := finalizeWithRuleIndex(t, docA, dir)
	_, rootB := finalizeWithRuleIndex(t, docB, dir)
	pathA := rootA["x-clash-rule-index"].(map[string]any)["path"].(string)
	pathB := rootB["x-clash-rule-index"].(map[string]any)["path"].(string)
	data, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathA, data, 0o600); err != nil {
		t.Fatal(err)
	}
	again, _ := finalizeWithRuleIndex(t, docA, dir)
	cfg, err := parseAfterLookups(again)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.RuleTable.At(0).Payload(); got != "a.example" {
		t.Fatalf("rule 0 is %s", got)
	}
}

func TestARepublishChecksTheRulesTheIndexKeepsAsLines(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir})
	published, err := FinalizeForIOS("proxies:\n  - {name: N, type: direct}\nrules:\n  - MATCH,N\n", string(resources))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(published.Value), &root); err != nil {
		t.Fatal(err)
	}
	delete(root, "proxies")
	text, _ := yaml.Marshal(root)
	_, want := config.Parse(text)
	_, got := FinalizeForIOS(string(text), string(resources))
	if want == nil || got == nil {
		t.Fatalf("Finalize %v, Parse %v", got, want)
	}
}

func TestFinalizeReadsTheRulesAsTheTunnelDoes(t *testing.T) {
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir()})
	numeric := "sub-rules:\n  123:\n    - MATCH,DIRECT\nrules:\n  - SUB-RULE,(NETWORK,tcp),123\n"
	if _, err := config.Parse([]byte(numeric)); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeForIOS(numeric, string(resources)); err != nil {
		t.Fatalf("a sub-rule set named by a number: %v", err)
	}
	number := "rules: [123]\n"
	_, want := config.Parse([]byte(number))
	_, got := FinalizeForIOS(number, string(resources))
	if want == nil || got == nil || !strings.Contains(got.Error(), "rules[0] [123] error: format invalid") {
		t.Fatalf("a rule written as a number: Finalize %v, Parse %v", got, want)
	}
}

func TestThePipelineReadsAnIndexsRulesAsInline(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir()})
	publish := func(source string) string {
		finalized, err := FinalizeForIOS(source, string(resources))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(finalized.Value, "x-clash-rule-index") || strings.Contains(finalized.Value, "UID,") {
			t.Fatalf("not published as an index without its UID rules:\n%s", finalized.Value)
		}
		return finalized.Value
	}
	geo := "rules:\n  - DOMAIN,a.example,DIRECT\n  - AND,((GEOSITE,cn),(NETWORK,tcp)),DIRECT\n  - IP-ASN,13335,DIRECT,no-resolve\n  - MATCH,DIRECT\n"
	if a, b := requiredGeodata(decodeConfigText(geo).raw), requiredGeodata(decodeConfigText(publish(geo)).raw); a != b || !a.geoSite || !a.asn {
		t.Errorf("geodata: inline %+v, published %+v", a, b)
	}
	source := "proxies:\n  - {name: P, type: direct}\n" +
		"rules:\n  - DOMAIN,a.example,P\n  - UID,501,DIRECT\n  - DST-PORT,8443,DIRECT\n  - PROCESS-NAME,curl,P\n  - AND,((UID,0),(DOMAIN,b.example)),P\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,P\n"
	published := publish(source)
	inline := decodeConfigText(source)
	published0 := decodeConfigText(published)
	policy := currentRuntimePolicy(true)
	inlineRows, err := inline.deviationRows(policy)
	if err != nil {
		t.Fatal(err)
	}
	publishedRows, err := published0.deviationRows(policy)
	if err != nil {
		t.Fatal(err)
	}
	ruleRows := func(rows []configDeviation) (out []string) {
		for _, row := range rows {
			if strings.HasPrefix(row.Field, "rules") {
				out = append(out, row.Field+"|"+row.RuleKind+"|"+row.Given)
			}
		}
		return out
	}
	if a, b := ruleRows(inlineRows), ruleRows(publishedRows); fmt.Sprint(a) != fmt.Sprint(b) || len(a) == 0 {
		t.Errorf("deviation rows about rules:\n inline    %v\n published %v", a, b)
	}
	capability := policy.processMetadata()
	stripped := decodeConfigText(source).raw
	stripUnconstructibleUIDRules(stripped)
	if a, b := summarizeMetadataRuleOccurrences(stripped, capability), summarizeMetadataRuleOccurrences(published0.raw, capability); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("owner-metadata notices: inline %v, published %v", a, b)
	}
	inlineCfg, err := parseConfigForIOS(source, true)
	if err != nil {
		t.Fatal(err)
	}
	publishedCfg, err := parseConfigForIOS(published, true)
	if err != nil {
		t.Fatal(err)
	}
	types := func(table C.RuleTable) (out []string) {
		for i := 0; i < table.Len(); i++ {
			out = append(out, table.At(i).RuleType().String()+","+table.At(i).Payload())
		}
		return out
	}
	if a, b := types(inlineCfg.RuleTable), types(publishedCfg.RuleTable); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("rules started:\n inline    %v\n published %v", a, b)
	}
	if a, b := ruleCountOf(inline.raw), ruleCountOf(published0.raw); a != b {
		t.Errorf("rules written: inline %d, published %d", a, b)
	}
}

func TestRulesThatReadGeodataPublishBeforeItIsStaged(t *testing.T) {
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir()})
	doc := "rules:\n  - GEOSITE,cn,DIRECT\n  - OR,((GEOIP,CN),(DOMAIN,a.example)),DIRECT\n  - DOMAIN,b.example,DIRECT\n  - MATCH,DIRECT\n"
	finalized, err := FinalizeForIOS(doc, string(resources))
	if err != nil || !strings.Contains(finalized.Value, "x-clash-rule-index") {
		t.Fatalf("%v", err)
	}
	if _, err := FinalizeForIOS(strings.Replace(doc, "GEOSITE,cn,DIRECT", "GEOSITE,cn,Nowhere", 1), string(resources)); err == nil || !strings.Contains(err.Error(), "rules[0] [GEOSITE,cn,Nowhere] error: proxy [Nowhere] not found") {
		t.Fatalf("a missing target: %v", err)
	}
}

func TestARuleIndexIsCompiledForItsTunnelsProfile(t *testing.T) {
	document := "proxies:\n  - {name: P, type: direct}\nrules:\n  - UID,501,P\n  - DOMAIN,a.example,P\n  - MATCH,DIRECT\n"
	finalize := func(profile string) (string, error) {
		resources := map[string]any{"ruleIndexDirectory": t.TempDir()}
		if profile != "" {
			resources["runtimeProfile"] = profile
		}
		encoded, _ := json.Marshal(resources)
		finalized, err := FinalizeForIOS(document, string(encoded))
		if err != nil {
			return "", err
		}
		return finalized.Value, nil
	}
	setupMu.Lock()
	wasDone := setupDone
	setupDone = false
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		setupDone = wasDone
		setupMu.Unlock()
	})
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	if _, err := finalize(""); err == nil || !strings.Contains(err.Error(), "runtimeProfile") {
		t.Fatalf("a Finalize before Setup naming no profile: %v", err)
	}
	for profile, removed := range map[string]bool{
		RuntimeProfileIOSPacketTunnel:   true,
		RuntimeProfileTVOSPacketTunnel:  true,
		RuntimeProfileMacOSPacketTunnel: false,
		RuntimeProfileMacOSApplication:  false,
	} {
		published, err := finalize(profile)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		var root struct {
			Reference config.ClashRuleIndexRef `yaml:"x-clash-rule-index"`
		}
		if err := yaml.Unmarshal([]byte(published), &root); err != nil {
			t.Fatal(err)
		}
		if got := len(root.Reference.UIDRemoved) == 1 && root.Reference.UIDRemoved[0] == 0; got != removed {
			t.Errorf("%s: UID rules removed %v (%v), want %v", profile, got, root.Reference.UIDRemoved, removed)
		}
	}
	if _, err := finalize("watchosPacketTunnel"); err == nil {
		t.Error("a profile there is none of was taken")
	}
	setupMu.Lock()
	setupDone = true
	setupMu.Unlock()
	withRuntimeProfile(t, runtimeProfileMacOSApplication)
	published, err := finalize("")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(published, "uid-removed") {
		t.Errorf("the Mac App's own profile removed its tunnel's UID rules:\n%s", published)
	}
}

func TestARepublishCompilesAgainAnIndexThatIsNotTheCompilers(t *testing.T) {
	dir := t.TempDir()
	source := "rules:\n  - DOMAIN-KEYWORD,ads,REJECT\n  - MATCH,DIRECT\n"
	_, root := finalizeWithRuleIndex(t, source, dir)
	path := root["x-clash-rule-index"].(map[string]any)["path"].(string)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), original...)
	lengths := binary.LittleEndian.Uint32(data[56+8*7:])
	binary.LittleEndian.PutUint32(data[lengths:], 4)
	sum := sha256.Sum256(data[:len(data)-32])
	copy(data[len(data)-32:], sum[:])
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	published, _ := finalizeWithRuleIndex(t, source, dir)
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, original) {
		t.Fatalf("the index was not compiled again: %v", err)
	}
	cfg, err := parseAfterLookups(published)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuleTable.Walk(&C.Metadata{Host: "ads.example"}, C.RuleMatchHelper{}, nil, func(_ int, _ C.Rule, target string) bool {
		if target != "REJECT" {
			t.Errorf("ads.example went %s", target)
		}
		return true
	})
}

func TestAPublishedConfigurationIsNotHashedAgain(t *testing.T) {
	dir := t.TempDir()
	document := ruleIndexTestDocument(3000)
	published, _ := finalizeWithRuleIndex(t, document, dir)
	time.Sleep(300 * time.Millisecond)
	finalizeWithRuleIndex(t, document, dir)
	source := filepath.Join(t.TempDir(), "published.yaml")
	if err := os.WriteFile(source, []byte(published), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		step func() error
	}{
		{"published again", func() error { finalizeWithRuleIndex(t, document, dir); return nil }},
		{"the published text published again", func() error { finalizeWithRuleIndex(t, published, dir); return nil }},
		{"planned", func() error {
			_, err := PlanResourcesForProfileAtPath(source, RuntimeProfileIOSPacketTunnel)
			return err
		}},
		{"its catalog opened", func() error {
			catalog, err := OpenRuleCatalogForPublishedAtPath(source)
			if err == nil {
				catalog.Close()
			}
			return err
		}},
	}
	for _, s := range steps {
		before := clashsum.Hashed()
		if err := s.step(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if hashes := clashsum.Hashed() - before; hashes != 0 {
			t.Errorf("%s: hashed %d times, want none", s.name, hashes)
		}
	}
}

func TestATunnelStartedAfterAPublishReadsTheIndexAndLibraryOnce(t *testing.T) {
	dir := t.TempDir()
	published, root := finalizeWithRuleIndex(t, ruleIndexTestDocument(3000), dir)
	if _, ok := root["x-clash-node-library"]; !ok {
		t.Fatal("no node library published")
	}
	text := filepath.Join(t.TempDir(), "published.yaml")
	if err := os.WriteFile(text, []byte(published), 0o600); err != nil {
		t.Fatal(err)
	}
	start := func() string {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestATunnelStartCountsItsHashes$", "-test.v", "-test.count=1")
		command.Env = append(os.Environ(), tunnelStartHashesEnvironmentKey+"="+text)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "--- PASS: TestATunnelStartCountsItsHashes") {
			t.Fatalf("the tunnel's child failed (%v):\n%s", err, output)
		}
		for _, line := range strings.Split(string(output), "\n") {
			if _, counted, ok := strings.Cut(line, "hashed: "); ok {
				return strings.TrimSpace(counted)
			}
		}
		t.Fatalf("the tunnel's child said nothing:\n%s", output)
		return ""
	}
	if got := start(); got != "0 0" {
		t.Fatalf("a tunnel started on a published configuration hashed its files (start, reload): %s, want 0 0", got)
	}
	proofs, _ := filepath.Glob(filepath.Join(dir, "*"+clashsum.ProofSuffix))
	if len(proofs) != 2 {
		t.Fatalf("proofs beside the index and the library: %v", proofs)
	}
	for _, proof := range proofs {
		if err := os.Remove(proof); err != nil {
			t.Fatal(err)
		}
	}
	if got := start(); got == "0 0" {
		t.Fatal("without the proofs the tunnel's start hashed nothing: the count does not see the hashes")
	}
}

const tunnelStartHashesEnvironmentKey = "CLASH_TEST_TUNNEL_START_HASHES"

func TestATunnelStartCountsItsHashes(t *testing.T) {
	path := os.Getenv(tunnelStartHashesEnvironmentKey)
	if path == "" {
		t.Skip("run by TestATunnelStartedAfterAPublishReadsTheIndexAndLibraryOnce")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	config.ClashRuleIndexesVerified.Store(true)
	var counts []string
	for range 2 {
		before := clashsum.Hashed()
		if _, err := parseAfterLookups(string(text)); err != nil {
			t.Fatal(err)
		}
		counts = append(counts, fmt.Sprint(clashsum.Hashed()-before))
	}
	t.Logf("hashed: %s", strings.Join(counts, " "))
}

func TestAPublishShortOfMemoryCompilesItsIndexAfterItsLibrary(t *testing.T) {
	document := ruleIndexTestDocument(300)
	beside, _ := finalizeWithRuleIndex(t, document, t.TempDir())
	saved := finalizeAvailableMemory
	readings := 0
	finalizeAvailableMemory = func() int64 { readings++; return 64 << 20 }
	t.Cleanup(func() { finalizeAvailableMemory = saved })
	after, _ := finalizeWithRuleIndex(t, document, t.TempDir())
	if readings == 0 {
		t.Fatal("the publish did not ask how much memory is left")
	}
	strip := func(text string) string {
		return regexp.MustCompile(`(path|sha256): \S+`).ReplaceAllString(text, "$1: x")
	}
	if strip(beside) != strip(after) {
		t.Fatalf("compiled after the library:\n%s\nbeside it:\n%s", after, beside)
	}
}

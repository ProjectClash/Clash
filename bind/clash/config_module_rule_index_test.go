package clash

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

const (
	moduleRulesBeforeIndexKey = "rules-before"
	moduleRulesAfterIndexKey  = "rules-after"
)

func moduleShapedRules(t *testing.T, n int) []string {
	t.Helper()
	if path := os.Getenv("CLASH_MODULE_RULES_FILE"); path != "" {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var rules []string
		for _, line := range strings.Split(string(text), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				rules = append(rules, line)
			}
		}
		return rules
	}
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	tlds := []string{"com", "net", "cn", "org", "top", "com.cn"}
	state := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	rules := make([]string, 0, n)
	seen := make(map[string]bool, n)
	for len(rules) < n {
		label := make([]byte, 4+next()%9)
		for i := range label {
			label[i] = letters[next()%uint64(len(letters))]
		}
		domain := string(label) + "." + tlds[next()%uint64(len(tlds))]
		if seen[domain] {
			continue
		}
		seen[domain] = true
		kind := "DOMAIN-SUFFIX"
		if len(rules)%200 == 199 {
			kind = "DOMAIN"
		}
		rules = append(rules, kind+","+domain+",DIRECT")
	}
	return rules
}

func moduleRuleIndexOf(t *testing.T, root map[string]any, key string) (string, os.FileInfo) {
	t.Helper()
	reference, _ := root["x-clash-rule-index"].(map[string]any)
	named, _ := reference[key].(map[string]any)
	path, _ := named["path"].(string)
	sum, _ := named["sha256"].(string)
	if decoded, err := hex.DecodeString(sum); path == "" || err != nil || len(decoded) != 32 {
		keys := make([]string, 0, len(reference))
		for name := range reference {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		t.Fatalf("the reference names no index of a module's rules at %s; it names %v", key, keys)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the index of a module's rules at %s is not there: %v", key, err)
	}
	return path, info
}

func goHeldBytes() uint64 {
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64() - sample[1].Value.Uint64()
}

func startedCoreCost(t *testing.T, published string) (kept, peak uint64) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	platform := &fdPlatform{recordingPlatform: recordingPlatform{lines: make(chan string, 4096), underNetworkExtension: true}, fd: int32(fds[0])}
	go func() {
		for range platform.lines {
		}
	}()
	svc, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	heapBefore := liveHeapAfterCollections()
	debug.FreeOSMemory()
	heldBefore := goHeldBytes()
	var most uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			if held := goHeldBytes(); held > most {
				most = held
			}
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	if err := svc.Start(published); err != nil {
		close(stop)
		<-sampled
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(2 * time.Second)
	close(stop)
	<-sampled
	kept = liveHeapAfterCollections() - heapBefore
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	liveHeapAfterCollections()
	debug.FreeOSMemory()
	if most > heldBefore {
		peak = most - heldBefore
	}
	return kept, peak
}

const moduleRuleBudget = 3 << 20

const moduleRuleBudgetDocument = "mode: rule\nlog-level: info\n" +
	"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: ['223.5.5.5']\n" +
	"tun:\n  enable: true\n  stack: mips\n" +
	"proxies:\n  - {name: P, type: direct}\n" +
	"proxy-groups:\n  - {name: Proxy, type: select, proxies: [P, DIRECT]}\n" +
	"rules:\n  - DOMAIN-SUFFIX,google.com,Proxy\n  - MATCH,Proxy\n"

func TestAModulesHundredThousandRulesAddAtMostThreeMiBToAStartedCore(t *testing.T) {
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-module-index-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	dir := filepath.Join(base, "index")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	module := moduleShapedRules(t, 110_241)
	plain, _ := finalizeWithRulesBefore(t, moduleRuleBudgetDocument, indexResources(dir), nil, nil)
	withModule, _ := finalizeWithRulesBefore(t, moduleRuleBudgetDocument, indexResources(dir), module, nil)

	plainKept, plainPeak := startedCoreCost(t, plain.Text)
	moduleKept, modulePeak := startedCoreCost(t, withModule.Text)
	over := func(a, b uint64) int64 { return int64(a) - int64(b) }
	t.Logf("a started core: %d KiB kept, %d KiB at most without the module; %d KiB kept, %d KiB at most with its %d rules (published text %d KiB)",
		plainKept>>10, plainPeak>>10, moduleKept>>10, modulePeak>>10, len(module), len(withModule.Text)>>10)
	if d := over(moduleKept, plainKept); d > moduleRuleBudget {
		t.Errorf("a module's %d rules keep %d KiB more of a started core's heap, over the %d KiB they may: they are parsed onto it, not mapped from an index",
			len(module), d>>10, moduleRuleBudget>>10)
	}
	if d := over(modulePeak, plainPeak); d > moduleRuleBudget {
		t.Errorf("a module's %d rules take a starting core %d KiB higher, over the %d KiB they may: a phone's tunnel ends at 50 MiB",
			len(module), d>>10, moduleRuleBudget>>10)
	}
}

var (
	moduleOrderBefore = []string{
		"DOMAIN-SUFFIX,Shared.Example,REJECT",
		"DOMAIN-KEYWORD,kwmod,REJECT",
		`DOMAIN-REGEX,^re[0-9]+\.mod\.example$,REJECT`,
		"PROCESS-NAME,Telegram,DIRECT",
		"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		"IP-CIDR,192.0.2.0/24,REJECT,no-resolve",
	}
	moduleOrderAfter = []string{
		"DOMAIN-SUFFIX,body.example,REJECT",
		"DOMAIN-SUFFIX,Late.Example,REJECT",
		"DOMAIN-KEYWORD,kwlate,REJECT",
		"MATCH,DIRECT",
	}
)

var moduleOrderOwn = []string{
	"DOMAIN,www.shared.example,P",
	"DOMAIN,body.example,P",
	"DOMAIN-KEYWORD,kwbody,P",
}

const moduleOrderSourceRules = 3

func moduleOrderDocument(rules []string) string {
	document := "proxies:\n  - {name: P, type: direct}\nrules:\n"
	for _, line := range rules {
		document += "  - '" + strings.ReplaceAll(line, "'", "''") + "'\n"
	}
	return document
}

func moduleOrderRules(t *testing.T) (before, after []string) {
	t.Helper()
	before = append(append([]string{}, moduleOrderBefore...), moduleShapedRules(t, 3000)...)
	return before, moduleOrderAfter
}

func TestAModulesRulesBeforeAndAfterAreIndexedAndWalkedFirstMatchWinning(t *testing.T) {
	dir := t.TempDir()
	before, after := moduleOrderRules(t)
	answer, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, after)

	ownPath, _ := rulesBeforeOf(t, root)
	beforePath, _ := moduleRuleIndexOf(t, root, moduleRulesBeforeIndexKey)
	afterPath, _ := moduleRuleIndexOf(t, root, moduleRulesAfterIndexKey)
	if beforePath == ownPath || afterPath == ownPath || beforePath == afterPath {
		t.Fatalf("the configuration's index %s, the rules before's %s, the rules after's %s: want three files", ownPath, beforePath, afterPath)
	}
	reference := root["x-clash-rule-index"].(map[string]any)
	if reference["prepend"] != nil || reference["append"] != nil {
		t.Fatalf("the reference still writes a module's rules out: prepend %d, append %d", len(rulesBeforeOfList(reference["prepend"])), len(rulesBeforeOfList(reference["append"])))
	}
	if strings.Contains(answer.Text, "kwmod") || strings.Contains(answer.Text, "kwlate") || strings.Contains(answer.Text, strings.Split(before[len(before)-1], ",")[1]) {
		t.Fatalf("the published text carries a module's rules (%d bytes)", len(answer.Text))
	}

	published, err := parseAfterLookups(answer.Text)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append(append([]string{}, before...), moduleOrderOwn...), after...)
	inline, err := parseAfterLookups(moduleOrderDocument(all))
	if err != nil {
		t.Fatal(err)
	}
	if published.RuleTable.Len() != inline.RuleTable.Len() || inline.RuleTable.Len() != len(all) {
		t.Fatalf("published %d rules, inline %d, written %d", published.RuleTable.Len(), inline.RuleTable.Len(), len(all))
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), published.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Fatalf("rule %d: inline %s,%s,%s; published %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
	}
	k, n := len(before), moduleOrderSourceRules
	moduleDomain := strings.Split(before[len(moduleOrderBefore)+100], ",")[1]
	for _, c := range []struct {
		name string
		m    C.Metadata
		want int
	}{
		{"a rule before wins over the configuration's", C.Metadata{Host: "www.shared.example", NetWork: C.TCP, DstPort: 443}, 0},
		{"a keyword before", C.Metadata{Host: "a.kwmod.example", NetWork: C.TCP, DstPort: 443}, 1},
		{"a regex before", C.Metadata{Host: "re12.mod.example", NetWork: C.TCP, DstPort: 443}, 2},
		{"a process before", C.Metadata{Host: "x.nothing.example", NetWork: C.TCP, DstPort: 443, Process: "Telegram"}, 3},
		{"a logic rule before", C.Metadata{Host: "q.nothing.example", NetWork: C.UDP, DstPort: 443}, 4},
		{"an IP-CIDR before", C.Metadata{DstIP: netip.MustParseAddr("192.0.2.7"), NetWork: C.TCP, DstPort: 443}, 5},
		{"one of the module's hundred-thousand", C.Metadata{Host: "cdn." + moduleDomain, NetWork: C.TCP, DstPort: 443}, len(moduleOrderBefore) + 100},
		{"the configuration's wins over a rule after", C.Metadata{Host: "body.example", NetWork: C.TCP, DstPort: 443}, k + 1},
		{"the configuration's keyword", C.Metadata{Host: "kwbody.example", NetWork: C.TCP, DstPort: 443}, k + 2},
		{"a rule after", C.Metadata{Host: "x.late.example", NetWork: C.TCP, DstPort: 443}, k + n + 1},
		{"a keyword after", C.Metadata{Host: "kwlate.example", NetWork: C.TCP, DstPort: 443}, k + n + 2},
		{"the last rule after", C.Metadata{Host: "nothing.example", NetWork: C.TCP, DstPort: 443}, k + n + 3},
	} {
		first := func(table C.RuleTable) int {
			m := c.m
			at := -1
			table.Walk(&m, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { at = i; return true })
			return at
		}
		if got, inlineGot := first(published.RuleTable), first(inline.RuleTable); got != c.want || inlineGot != c.want {
			t.Errorf("%s: published rule %d, inline %d, want %d", c.name, got, inlineGot, c.want)
		}
	}
}

func rulesBeforeOfList(value any) []any {
	list, _ := value.([]any)
	return list
}

func TestTheRulesPageAndTheMatchReadAModulesIndexedRulesAsWritten(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	before, after := moduleOrderRules(t)
	answer, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, after)
	moduleRuleIndexOf(t, root, moduleRulesBeforeIndexKey)
	moduleRuleIndexOf(t, root, moduleRulesAfterIndexKey)
	path := filepath.Join(dir, "published.yaml")
	if err := os.WriteFile(path, []byte(answer.Text), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	k, n := len(before), moduleOrderSourceRules
	if catalog.Prepended() != int32(k) || catalog.Appended() != int32(len(after)) || catalog.Total() != int32(k+n+len(after)) {
		t.Fatalf("prepended %d, appended %d, total %d; want %d, %d, %d", catalog.Prepended(), catalog.Appended(), catalog.Total(), k, len(after), k+n+len(after))
	}
	var summary ruleSummary
	if err := json.Unmarshal([]byte(catalog.SummaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Prepended != k || summary.Appended != len(after) || summary.ByType["DOMAIN-KEYWORD"] != 3 || summary.ByType["PROCESS-NAME"] != 1 {
		t.Fatalf("summary %+v", summary)
	}
	page := func(offset, limit int, query, target string) []rulePageEntry {
		var p struct {
			Rules []rulePageEntry `json:"rules"`
		}
		if err := json.Unmarshal([]byte(catalog.PageJSON(int32(offset), int32(limit), query, target, "")), &p); err != nil {
			t.Fatal(err)
		}
		return p.Rules
	}
	for _, c := range []struct {
		offset int
		lines  []string
	}{{0, before}, {k + n, after}} {
		var got []rulePageEntry
		for len(got) < len(c.lines) {
			next := page(c.offset+len(got), min(500, len(c.lines)-len(got)), "", "")
			if len(next) == 0 {
				break
			}
			got = append(got, next...)
		}
		if len(got) != len(c.lines) {
			t.Fatalf("a page of %d at %d: %d rules", len(c.lines), c.offset, len(got))
		}
		for j, line := range c.lines {
			tp, target, _, _ := ruleTypeAndTarget(line)
			want := rulePageEntry{Index: c.offset + j, Text: line, Rule: line, Type: tp, Target: target}
			if got[j] != want {
				t.Fatalf("rule %d on the rules page: %+v, want %+v", c.offset+j, got[j], want)
			}
		}
	}
	if got := page(0, 10, "shared.example", ""); len(got) != 2 || got[0].Text != before[0] || got[1].Index != k {
		t.Fatalf("searching shared.example: %+v", got)
	}

	match := func(published, query string) matchRuleResult {
		t.Helper()
		box, err := MatchRuleForIOS(published, "", query)
		if err != nil {
			t.Fatal(err)
		}
		var got matchRuleResult
		if err := json.Unmarshal([]byte(box.Value), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	moduleDomain := strings.Split(before[len(moduleOrderBefore)+7], ",")[1]
	if got := match(answer.Text, `{"host":"a.kwmod.example","port":443,"network":"tcp"}`); !got.Matched || got.Rule != before[1] || got.Index == nil || *got.Index != 1 {
		t.Fatalf("a keyword before: %+v", got)
	}
	if got := match(answer.Text, `{"host":"body.example","port":443,"network":"tcp"}`); !got.Undecided || got.Rule != before[3] || got.Index == nil || *got.Index != 3 || got.Reason != "needsProcess" {
		t.Fatalf("past the process rule before: %+v, want undecided at it", got)
	}
	withoutProcess := append(append([]string{}, before[:3]...), before[4:]...)
	plain, plainRoot := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), withoutProcess, after)
	moduleRuleIndexOf(t, plainRoot, moduleRulesBeforeIndexKey)
	k = len(withoutProcess)
	for query, want := range map[string]struct {
		rule  string
		index int
	}{
		`{"host":"www.shared.example","port":443,"network":"tcp"}`:                {withoutProcess[0], 0},
		`{"host":"re7.mod.example","port":443,"network":"tcp"}`:                   {withoutProcess[2], 2},
		`{"host":"q.nothing.example","port":443,"network":"udp"}`:                 {withoutProcess[3], 3},
		`{"ip":"192.0.2.7","port":443,"network":"tcp"}`:                           {withoutProcess[4], 4},
		fmt.Sprintf(`{"host":"cdn.%s","port":443,"network":"tcp"}`, moduleDomain): {before[len(moduleOrderBefore)+7], len(moduleOrderBefore) - 1 + 7},
		`{"host":"body.example","port":443,"network":"tcp"}`:                      {"DOMAIN,body.example,P", k + 1},
		`{"host":"kwbody.example","port":443,"network":"tcp"}`:                    {"DOMAIN-KEYWORD,kwbody,P", k + 2},
		`{"host":"x.late.example","port":443,"network":"tcp"}`:                    {after[1], k + n + 1},
		`{"host":"nothing.example","port":443,"network":"tcp"}`:                   {after[3], k + n + 3},
	} {
		if got := match(plain.Text, query); !got.Matched || got.Rule != want.rule || got.Index == nil || *got.Index != want.index {
			t.Fatalf("%s: %+v, want rule %q at %d", query, got, want.rule, want.index)
		}
	}
}

func TestAModulesIndexIsKeyedByItsRulesAndTheConfigurationsOwnIsNeverCompiledForIt(t *testing.T) {
	dir := t.TempDir()
	document := ruleIndexTestDocument(3000)
	v1 := moduleShapedRules(t, 5000)
	v2 := append(append([]string{}, v1...), "DOMAIN-SUFFIX,added-in-v2.example,DIRECT")
	tail := []string{"DOMAIN-SUFFIX,late.example,REJECT"}

	first, root := finalizeWithRulesAround(t, document, indexResources(dir), v1, tail)
	own, _ := rulesBeforeOf(t, root)
	ownInfo, err := os.Stat(own)
	if err != nil {
		t.Fatal(err)
	}
	beforePath, beforeInfo := moduleRuleIndexOf(t, root, moduleRulesBeforeIndexKey)
	afterPath, afterInfo := moduleRuleIndexOf(t, root, moduleRulesAfterIndexKey)
	sameOwn := func(step string, root map[string]any) {
		t.Helper()
		path, _ := rulesBeforeOf(t, root)
		info, err := os.Stat(path)
		if path != own || err != nil || !os.SameFile(info, ownInfo) || !info.ModTime().Equal(ownInfo.ModTime()) {
			t.Fatalf("%s: the configuration's index %s (%v), want %s as it was: compiled again", step, path, err, own)
		}
	}

	_, again := finalizeWithRulesAround(t, document, indexResources(dir), v1, tail)
	sameOwn("the same module again", again)
	if path, info := moduleRuleIndexOf(t, again, moduleRulesBeforeIndexKey); path != beforePath || !os.SameFile(info, beforeInfo) || !info.ModTime().Equal(beforeInfo.ModTime()) {
		t.Fatalf("the same rules before again: %s, want %s as it was", path, beforePath)
	}
	if path, info := moduleRuleIndexOf(t, again, moduleRulesAfterIndexKey); path != afterPath || !os.SameFile(info, afterInfo) {
		t.Fatalf("the same rules after again: %s, want %s as it was", path, afterPath)
	}

	_, updated := finalizeWithRulesAround(t, document, indexResources(dir), v2, tail)
	sameOwn("the module updated", updated)
	if path, _ := moduleRuleIndexOf(t, updated, moduleRulesBeforeIndexKey); path == beforePath {
		t.Fatalf("other rules before named the same index %s", path)
	}
	if path, info := moduleRuleIndexOf(t, updated, moduleRulesAfterIndexKey); path != afterPath || !os.SameFile(info, afterInfo) {
		t.Fatalf("the rules after, unchanged, named %s, want %s as it was", path, afterPath)
	}

	_, off := finalizeWithRulesAround(t, document, indexResources(dir), []string{}, []string{})
	sameOwn("the module off", off)
	if reference := off["x-clash-rule-index"].(map[string]any); reference[moduleRulesBeforeIndexKey] != nil || reference[moduleRulesAfterIndexKey] != nil {
		t.Fatalf("with no rules before or after the reference names %+v", reference)
	}
	_, on := finalizeWithRulesAround(t, document, indexResources(dir), v1, tail)
	sameOwn("the module on again", on)
	if path, _ := moduleRuleIndexOf(t, on, moduleRulesBeforeIndexKey); path != beforePath {
		t.Fatalf("the first rules before again named %s, want %s", path, beforePath)
	}

	_, kept := finalizeWithRulesAround(t, first.Text, indexResources(dir), nil, nil)
	sameOwn("published again naming none", kept)
	if path, _ := moduleRuleIndexOf(t, kept, moduleRulesBeforeIndexKey); path != beforePath {
		t.Fatalf("published again naming none: %s, want %s", path, beforePath)
	}
	if path, _ := moduleRuleIndexOf(t, kept, moduleRulesAfterIndexKey); path != afterPath {
		t.Fatalf("published again naming none: %s, want %s", path, afterPath)
	}
}

func TestAConfigurationPublishedWithAModulesRulesAsLinesStillRuns(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	before, after := moduleOrderRules(t)
	before = before[:len(moduleOrderBefore)+20]
	_, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), nil, nil)
	reference := root["x-clash-rule-index"].(map[string]any)
	reference["prepend"] = anyStrings(before)
	reference["append"] = anyStrings(after)
	encoded, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	old := string(encoded)

	published, err := parseAfterLookups(old)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := parseAfterLookups(moduleOrderDocument(append(append(append([]string{}, before...), moduleOrderOwn...), after...)))
	if err != nil {
		t.Fatal(err)
	}
	if published.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("published %d rules, inline %d", published.RuleTable.Len(), inline.RuleTable.Len())
	}
	for _, m := range []C.Metadata{
		{Host: "www.shared.example", NetWork: C.TCP, DstPort: 443},
		{Host: "body.example", NetWork: C.TCP, DstPort: 443},
		{Host: "x.late.example", NetWork: C.TCP, DstPort: 443},
		{Host: "nothing.example", NetWork: C.TCP, DstPort: 443},
	} {
		first := func(table C.RuleTable) int {
			m := m
			at := -1
			table.Walk(&m, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { at = i; return true })
			return at
		}
		if a, b := first(published.RuleTable), first(inline.RuleTable); a != b {
			t.Fatalf("%s: published rule %d, inline %d", m.Host, a, b)
		}
	}
	path := filepath.Join(dir, "old.yaml")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := OpenRuleCatalogForPublishedAtPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Prepended() != int32(len(before)) || catalog.Appended() != int32(len(after)) {
		t.Fatalf("prepended %d, appended %d; want %d, %d", catalog.Prepended(), catalog.Appended(), len(before), len(after))
	}
	catalog.Close()
	if got := runMatch(t, old, "", `{"host":"a.kwmod.example","port":443,"network":"tcp"}`); !got.Matched || got.Rule != before[1] {
		t.Fatalf("the offline match of a rule written before: %+v", got)
	}

	_, kept := finalizeWithRulesAround(t, old, indexResources(dir), nil, nil)
	keptReference := kept["x-clash-rule-index"].(map[string]any)
	if keptReference[moduleRulesBeforeIndexKey] != nil || len(rulesAroundOf(t, keptReference, "prepend", moduleRulesBeforeIndexKey)) != len(before) {
		t.Fatalf("published again naming none: %+v", keptReference)
	}
	_, replaced := finalizeWithRulesAround(t, old, indexResources(dir), before, after)
	replacedReference := replaced["x-clash-rule-index"].(map[string]any)
	if replacedReference["prepend"] != nil || replacedReference["append"] != nil {
		t.Fatalf("published again with rules: the lines stayed: %+v", replacedReference)
	}
	moduleRuleIndexOf(t, replaced, moduleRulesBeforeIndexKey)
	moduleRuleIndexOf(t, replaced, moduleRulesAfterIndexKey)
}

func TestTheConfigurationsOwnIndexIsTheFirstPathItsReferenceWrites(t *testing.T) {
	dir := t.TempDir()
	before, after := moduleOrderRules(t)
	answer, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, after)
	own, _ := rulesBeforeOf(t, root)
	block := strings.SplitN(answer.Text, "\nx-clash-rule-index:\n", 2)
	if len(block) != 2 {
		t.Fatalf("no x-clash-rule-index block in the published text")
	}
	for _, line := range strings.Split(block[1], "\n") {
		if !strings.HasPrefix(line, " ") {
			break
		}
		if field := strings.TrimSpace(line); strings.HasPrefix(field, "path: ") {
			if got := strings.Trim(strings.TrimPrefix(field, "path: "), `'"`); got != own {
				t.Fatalf("the first path the reference writes is %s, want the configuration's own %s", got, own)
			}
			return
		}
	}
	t.Fatal("the reference writes no path")
}

func TestAModulesLastIndexIsPrunedOnceNoConfigurationNamesIt(t *testing.T) {
	dir := t.TempDir()
	v1 := moduleShapedRules(t, 3000)
	v2 := append(append([]string{}, v1...), "DOMAIN-SUFFIX,added-in-v2.example,DIRECT")
	_, first := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), v1, nil)
	old, _ := moduleRuleIndexOf(t, first, moduleRulesBeforeIndexKey)
	_, updated := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), v2, nil)
	own, _ := rulesBeforeOf(t, updated)
	current, _ := moduleRuleIndexOf(t, updated, moduleRulesBeforeIndexKey)

	keep, _ := json.Marshal([]string{own, current})
	if err := PruneRuleIndexesKeeping(dir, string(keep)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("the last index went within the grace: %v", err)
	}
	past := time.Now().Add(-nodeLibraryGrace - time.Minute)
	for _, file := range []string{old, old + ".proof"} {
		if err := os.Chtimes(file, past, past); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := PruneRuleIndexesKeeping(dir, string(keep)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("the last index of the module, past the grace and named by nothing kept, is still there (%v)", err)
	}
	if _, err := os.Stat(old + ".proof"); !os.IsNotExist(err) {
		t.Fatalf("its proof is still there (%v)", err)
	}
	for _, path := range []string{own, current} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("an index kept went: %v", err)
		}
	}
}

func TestEveryReaderOfAPublishWhoseModuleIndexIsGoneSaysSo(t *testing.T) {
	setupForMatch(t)
	for _, key := range []string{moduleRulesBeforeIndexKey, moduleRulesAfterIndexKey} {
		dir := t.TempDir()
		before, after := moduleOrderRules(t)
		answer, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, after)
		path, _ := moduleRuleIndexOf(t, root, key)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		published := answer.Text
		const gone = "the rule index is not here"
		doc, err := NewConfigDocument(published)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := doc.ProjectionJSON("merged", `["ruleFacts"]`); err == nil || !strings.Contains(err.Error(), gone) {
			t.Errorf("%s gone, the projection: %v", key, err)
		}
		doc.Close()
		if _, err := ConfigDeviationsJSON(published, RuntimeProfileIOSPacketTunnel); err == nil || !strings.Contains(err.Error(), gone) {
			t.Errorf("%s gone, the deviations: %v", key, err)
		}
		if _, err := PlanResourcesForProfile(published, RuntimeProfileIOSPacketTunnel); err == nil || !strings.Contains(err.Error(), gone) {
			t.Errorf("%s gone, the plan: %v", key, err)
		}
		if _, err := MatchRuleForIOS(published, "", `{"host":"example.test"}`); err == nil || !strings.Contains(err.Error(), gone) {
			t.Errorf("%s gone, the offline match: %v", key, err)
		}
		if _, err := parseAfterLookups(published); err == nil || !strings.Contains(err.Error(), gone) {
			t.Errorf("%s gone, the tunnel's parse: %v", key, err)
		}
	}
}

func TestAModuleIndexNamedWithoutItsChecksumIsRefusedAlike(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	before, _ := moduleOrderRules(t)
	_, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, nil)
	reference := root["x-clash-rule-index"].(map[string]any)
	delete(reference[moduleRulesBeforeIndexKey].(map[string]any), "sha256")
	encoded, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	const refused = "a path and a SHA-256 are required"
	if _, err := parseAfterLookups(string(encoded)); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("the tunnel's parse: %v", err)
	}
	if _, err := MatchRuleForIOS(string(encoded), "", `{"host":"example.test"}`); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("the offline match: %v", err)
	}
}

func TestAModulesRulesAreRefusedAtTheFirstRefusedInOrder(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  string
	}{
		{[]string{"DOMAIN,a.example,NoSuchProxy", "UID,501,DIRECT"}, "rules[0] [DOMAIN,a.example,NoSuchProxy]"},
		{[]string{"DOMAIN,a.example,DIRECT", "UID,501,DIRECT", "DOMAIN,b.example,NoSuchProxy"}, "rules[1] [UID,501,DIRECT] error: a UID rule cannot go before"},
	} {
		_, err := finalizeWithRulesBeforeError(moduleOrderDocument(moduleOrderOwn), indexResources(t.TempDir()), c.lines, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.lines, err, c.want)
		}
	}
}

func TestAReferenceNamingAModulesIndexWithoutItsOwnIsRefused(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	before, _ := moduleOrderRules(t)
	_, root := finalizeWithRulesAround(t, moduleOrderDocument(moduleOrderOwn), indexResources(dir), before, nil)
	reference := root["x-clash-rule-index"].(map[string]any)
	delete(reference, "path")
	delete(reference, "sha256")
	encoded, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	const refused = "a path and a SHA-256 are required"
	if _, err := parseAfterLookups(string(encoded)); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("the tunnel's parse: %v", err)
	}
	if _, err := MatchRuleForIOS(string(encoded), "", `{"host":"example.test"}`); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("the offline match: %v", err)
	}
	doc, err := NewConfigDocument(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()
	if _, err := doc.ProjectionJSON("merged", `["ruleFacts"]`); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("the projection: %v", err)
	}
}

func TestAPublishRefusesTheConfigurationsOwnRuleBeforeARuleAfterIt(t *testing.T) {
	own := append(append([]string{}, moduleOrderOwn...), "DOMAIN,own.example,NoSuchOwnProxy")
	_, err := finalizeWithRulesBeforeError(moduleOrderDocument(own), indexResources(t.TempDir()), nil,
		map[string]any{"appendRules": []string{"DOMAIN,after.example,NoSuchAfterProxy"}})
	if err == nil || !strings.Contains(err.Error(), "NoSuchOwnProxy") {
		t.Fatalf("%v, want the configuration's own rule refused", err)
	}
}

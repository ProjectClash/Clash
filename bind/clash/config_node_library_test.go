package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"

	"golang.org/x/sys/unix"
)

func libraryTestDocument(nodes int) string {
	var b strings.Builder
	b.WriteString("mode: rule\nproxies:\n")
	for i := 0; i < nodes; i++ {
		if i == nodes/2 {
			b.WriteString(testMeshNode)
		}
		fmt.Fprintf(&b, "  - {name: \"N %d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: all, type: select, include-all-proxies: true}\nrules:\n  - MATCH,all\n")
	return b.String()
}

func TestFinalizeWritesTheNodesToALibrary(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := libraryTestDocument(50)
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized.Value), &root); err != nil {
		t.Fatal(err)
	}
	reference, _ := root["x-clash-node-library"].(map[string]any)
	path, _ := reference["path"].(string)
	if path == "" || filepath.Dir(path) != dir {
		t.Fatalf("no library named in %s: %+v", dir, reference)
	}
	kept, _ := root["proxies"].([]any)
	if len(kept) != testMeshNodes || (testMeshNodes == 1 && kept[0].(map[string]any)["name"] != "mesh") {
		t.Fatalf("the proxies a library cannot hold stay inline: %+v", kept)
	}
	if strings.Count(finalized.Value, "n1.example.net") != 0 {
		t.Fatal("a node a library holds is still in the published text")
	}
	fromLibrary, err := parseAfterLookups(finalized.Value)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := parseAfterLookups(document)
	if err != nil {
		t.Fatal(err)
	}
	libraryHolds := func(name string) bool {
		if _, ok := fromLibrary.Proxies[name]; ok {
			return true
		}
		_, ok := fromLibrary.ProxyLibrary.Lookup(name)
		return ok
	}
	for name := range inline.Proxies {
		if !libraryHolds(name) {
			t.Fatalf("%q is missing from the library's configuration", name)
		}
	}
	if got := len(fromLibrary.Proxies) + fromLibrary.ProxyLibrary.Len(); got != len(inline.Proxies) {
		t.Fatalf("%d proxies from the library, %d inline", got, len(inline.Proxies))
	}
	members := func(cfg *config.Config) string {
		encoded, _ := json.Marshal(cfg.Proxies["all"])
		var group struct{ All []string }
		_ = json.Unmarshal(encoded, &group)
		return strings.Join(group.All, ",")
	}
	if got, want := members(fromLibrary), members(inline); got != want {
		t.Fatalf("members out of order:\n got  %.300s\n want %.300s", got, want)
	}
	again, err := FinalizeForIOS(document, string(resources))
	if err != nil || again.Value != finalized.Value {
		t.Fatalf("publishing the same nodes again named another library: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files in the library directory", len(entries))
	}
}

func TestFinalizeRefusesANodeUpstreamRefuses(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := "proxies:\n  - {name: ok, type: ss, server: a.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n  - {name: bad, type: ss, server: b.example.net, port: 8388, cipher: not-a-cipher, password: p}\nrules: [MATCH,DIRECT]\n"
	_, libraryErr := FinalizeForIOS(document, string(resources))
	_, parseErr := parseAfterLookups(document)
	if libraryErr == nil || parseErr == nil || !strings.Contains(libraryErr.Error(), parseErr.Error()) {
		t.Fatalf("publish refused with %v; upstream's parse with %v", libraryErr, parseErr)
	}
}

func TestFinalizeBuildsNoNodeForALibraryAlreadyBuilt(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := libraryTestDocument(20)
	first, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	built := 0
	restore := adapter.CountBuilds(func() { built++ })
	again, err := FinalizeForIOS(document, string(resources))
	restore()
	if err != nil || again.Value != first.Value || built != 0 {
		t.Fatalf("publishing again built %d nodes: %v", built, err)
	}
	var root struct {
		Library struct{ Path string } `yaml:"x-clash-node-library"`
	}
	_ = yaml.Unmarshal([]byte(first.Value), &root)
	data, _ := os.ReadFile(root.Library.Path)
	data[len(data)/2] ^= 1
	_ = os.WriteFile(root.Library.Path, data, 0o600)
	built = 0
	restore = adapter.CountBuilds(func() { built++ })
	repaired, err := FinalizeForIOS(document, string(resources))
	restore()
	if err != nil || built != 20 {
		t.Fatalf("a damaged library: built %d nodes: %v", built, err)
	}
	if _, err := parseAfterLookups(repaired.Value); err != nil {
		t.Fatal(err)
	}
}

func TestPruneNodeLibrariesKeepsTheOneNamed(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"nodes-a.library", "nodes-b.library", "other.txt"} {
		agedFile(t, filepath.Join(dir, name), time.Hour)
	}
	if err := PruneNodeLibraries(dir, filepath.Join(dir, "nodes-b.library")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, ",") != "nodes-b.library,other.txt" {
		t.Fatalf("left %v", names)
	}
	if err := PruneNodeLibraries(filepath.Join(dir, "absent"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestTheLibraryReferenceIsFinalizesOwn(t *testing.T) {
	document := "x-clash-node-library: {path: /etc/hosts, sha256: 00}\nproxies:\n  - {name: a, type: ss, server: a.example.net, port: 8388, cipher: aes-128-gcm, password: p}\nrules: [MATCH,DIRECT]\n"
	finalized, err := FinalizeForIOS(document, "{}")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(finalized.Value, "x-clash-node-library") {
		t.Fatalf("a document's reference was published:\n%s", finalized.Value)
	}
	for _, field := range buildFieldCatalog() {
		if strings.HasPrefix(field.Path, "x-clash-") {
			t.Fatalf("the editor offers %s", field.Path)
		}
	}
	if _, known := mihomoConfigurationKeys.get()["x-clash-node-library"]; known {
		t.Fatal("an import counts the reference as upstream's key")
	}
}

func TestFinalizeCompactsALongMembersList(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "  - {name: \"N %d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: inner, type: select, proxies: [DIRECT]}\n  - name: auto\n    type: url-test\n    proxies: [inner")
	for _, i := range append(append(rangeInts(0, 40), 77, 50), rangeInts(60, 70)...) {
		fmt.Fprintf(&b, ", \"N %d\"", i)
	}
	b.WriteString(", DIRECT]\nrules:\n  - MATCH,auto\n")
	document := b.String()
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(finalized.Value, "N 20") || !strings.Contains(finalized.Value, "x-clash-members") {
		t.Fatalf("the list was not compacted:\n%s", finalized.Value)
	}
	members := func(text string) string {
		cfg, err := parseAfterLookups(text)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(cfg.Proxies["auto"])
		var group struct{ All []string }
		_ = json.Unmarshal(encoded, &group)
		return strings.Join(group.All, ",")
	}
	if got, want := members(finalized.Value), members(document); got != want {
		t.Fatalf("members\n got  %s\n want %s", got, want)
	}
}

func rangeInts(from, to int) []int {
	var out []int
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

func TestAStartWithoutItsLibrarySaysSoAndAPublishMends(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := libraryTestDocument(10)
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
	if _, err := parseAfterLookups(finalized.Value); err == nil || !strings.Contains(err.Error(), NodeLibraryUnavailablePrefix) {
		t.Fatalf("a missing library: %v", err)
	}
	again, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatalf("publishing again: %v", err)
	}
	if _, err := parseAfterLookups(again.Value); err != nil {
		t.Fatalf("the published configuration does not start: %v", err)
	}
}

func TestFinalizeComputesAFilteredIncludeAllGroupsMembers(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "  - {name: \"%s %d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", []string{"HK", "JP", "US"}[i%3], i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: asia, type: select, include-all: true, filter: \"HK`JP|HK\"}\n  - {name: every, type: select, include-all-proxies: true}\nrules:\n  - MATCH,asia\n")
	document := b.String()
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-member-group: asia") || strings.Contains(finalized.Value, "HK 3") {
		t.Fatalf("the group's members were not computed:\n%s", finalized.Value)
	}
	members := func(text, group string) string {
		cfg, err := parseAfterLookups(text)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(cfg.Proxies[group])
		var g struct{ All []string }
		_ = json.Unmarshal(encoded, &g)
		return strings.Join(g.All, ",")
	}
	for _, group := range []string{"asia", "every"} {
		if got, want := members(finalized.Value, group), members(document, group); got != want || got == "" {
			t.Fatalf("%s:\n got  %.300s\n want %.300s", group, got, want)
		}
	}
}

func TestFinalizeDropsGroupMemberFieldsTheDocumentBrings(t *testing.T) {
	document := "proxies:\n  - {name: a, type: ss, server: a.example.net, port: 8388, cipher: aes-128-gcm, password: p}\nproxy-groups:\n  - {name: g, type: select, proxies: [a], x-clash-member-group: g, x-clash-members: [{from: 0, to: 9}]}\nrules:\n  - MATCH,g\n"
	for _, resources := range []map[string]any{{}, {"nodeLibraryDirectory": t.TempDir()}} {
		encoded, _ := json.Marshal(resources)
		finalized, err := FinalizeForIOS(document, string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(finalized.Value, "x-clash-member") {
			t.Fatalf("%v kept the document's member fields:\n%s", resources, finalized.Value)
		}
		if _, err := parseAfterLookups(finalized.Value); err != nil {
			t.Fatalf("%v: %v", resources, err)
		}
	}
}

func TestANodeNamedWithANumberIsTheSameNodeFromTheLibrary(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n  - {name: 1, type: ss, server: one.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n  - {name: 2024, type: ss, server: zero.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n")
	var members []string
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "  - {name: \"n%02d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
		members = append(members, fmt.Sprintf("n%02d", i))
	}
	fmt.Fprintf(&b, "proxy-groups:\n  - {name: picked, type: include-all-filter-placeholder}\n  - {name: long, type: select, proxies: [1, %s]}\nrules:\n  - MATCH,long\n", strings.Join(members, ", "))
	document := strings.Replace(b.String(), "{name: picked, type: include-all-filter-placeholder}", `{name: picked, type: select, include-all: true, filter: "^n0[0-2]$|^1$|^2024$"}`, 1)
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	membersOf := func(text, group string) string {
		cfg, err := parseAfterLookups(text)
		if err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		encoded, _ := json.Marshal(cfg.Proxies[group])
		var g struct{ All []string }
		_ = json.Unmarshal(encoded, &g)
		return strings.Join(g.All, ",")
	}
	for _, group := range []string{"picked", "long"} {
		if got, want := membersOf(finalized.Value, group), membersOf(document, group); got != want || got == "" {
			t.Fatalf("%s:\n got  %s\n want %s", group, got, want)
		}
	}
}

func TestAPublishedConfigurationPublishedAgainKeepsItsNodes(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := libraryTestDocument(40)
	first, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	again, err := FinalizeForIOS(first.Value, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseAfterLookups(again.Value)
	if err != nil || cfg.ProxyLibrary == nil || cfg.ProxyLibrary.Len() != 40 {
		t.Fatalf("published again: %v", err)
	}
	libraries, _ := filepath.Glob(filepath.Join(dir, nodeLibraryPrefix+"*"+nodeLibrarySuffix))
	for _, library := range libraries {
		_ = os.Remove(library)
	}
	if _, err := FinalizeForIOS(first.Value, string(resources)); err == nil {
		t.Fatal("a published configuration whose library is gone was published without its nodes")
	}
}

func TestPruningKeepsWhatIsInUse(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, age time.Duration) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		_ = os.Chtimes(path, at, at)
		return path
	}
	keep := write(nodeLibraryPrefix+"keep"+nodeLibrarySuffix, time.Hour)
	old := write(nodeLibraryPrefix+"old"+nodeLibrarySuffix, time.Hour)
	recentCatalog := write(nodeLibraryPrefix+"precent"+nodeLibrarySuffix, time.Hour)
	recentStub := write(nodeLibraryPrefix+"precent"+providerRuntimeIndexStubSuffix, time.Hour)
	staleCatalog := write(nodeLibraryPrefix+"pstale"+nodeLibrarySuffix, 8*24*time.Hour)
	other := write("unrelated.txt", 30*24*time.Hour)
	if err := PruneNodeLibraries(dir, keep); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{keep: true, old: false, recentCatalog: true, recentStub: true, staleCatalog: false, other: true} {
		if got := regularFileExists(path); got != want {
			t.Fatalf("%s: there %v, want %v", filepath.Base(path), got, want)
		}
	}
}

func TestPruningKeepsEveryLibraryNamed(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a", "b", "c"} {
		path := filepath.Join(dir, nodeLibraryPrefix+name+nodeLibrarySuffix)
		agedFile(t, path, time.Hour)
		paths = append(paths, path)
	}
	keep, _ := json.Marshal([]string{paths[0], paths[2]})
	if err := PruneNodeLibrariesKeeping(dir, string(keep)); err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(paths[0]) || regularFileExists(paths[1]) || !regularFileExists(paths[2]) {
		t.Fatal("pruning kept another set than the one named")
	}
	if err := PruneNodeLibrariesKeeping(dir, "not json"); err == nil {
		t.Fatal("a list that does not decode pruned anyway")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	keep, _ = json.Marshal([]string{filepath.Join(link, filepath.Base(paths[0]))})
	if err := PruneNodeLibrariesKeeping(dir, string(keep)); err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(paths[0]) || regularFileExists(paths[2]) {
		t.Fatal("a library named through a link to its directory was not kept, or another was")
	}
	target := filepath.Join(t.TempDir(), "retained.library")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, nodeLibraryPrefix+"linked"+nodeLibrarySuffix)
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	keep, _ = json.Marshal([]string{paths[0], linked})
	if err := PruneNodeLibrariesKeeping(dir, string(keep)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(linked); err != nil || !regularFileExists(paths[0]) {
		t.Fatalf("a kept library that is a link was removed (%v)", err)
	}
}

func agedFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestPruningLeavesALibraryWrittenOrUsedLately(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := "proxies:\n  - {name: a, type: ss, server: 198.51.100.1, port: 8388, cipher: aes-128-gcm, password: p}\nrules:\n  - MATCH,a\n"
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	libraries, _ := filepath.Glob(filepath.Join(dir, nodeLibraryPrefix+"*"+nodeLibrarySuffix))
	if len(libraries) != 1 {
		t.Fatalf("libraries = %v", libraries)
	}
	library := libraries[0]
	age := func(d time.Duration) {
		at := time.Now().Add(-d)
		if err := os.Chtimes(library, at, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := PruneNodeLibraries(dir, ""); err != nil || !regularFileExists(library) {
		t.Fatalf("a library written a moment ago was pruned (%v)", err)
	}
	for _, again := range []string{document, finalized.Value} {
		age(time.Hour)
		if _, err := FinalizeForIOS(again, string(resources)); err != nil {
			t.Fatal(err)
		}
		if err := PruneNodeLibraries(dir, ""); err != nil || !regularFileExists(library) {
			t.Fatalf("a library a publish named again was pruned (%v)", err)
		}
	}
	age(nodeLibraryGrace + time.Minute)
	if err := PruneNodeLibraries(dir, ""); err != nil || regularFileExists(library) {
		t.Fatalf("a library unused for longer than the grace was kept (%v)", err)
	}
}

func TestPruningReadsALinkedLibrarysTimeFromItsFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "used.library")
	agedFile(t, target, 0)
	link := filepath.Join(dir, nodeLibraryPrefix+"linked"+nodeLibrarySuffix)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := unix.Lutimes(link, []unix.Timeval{unix.NsecToTimeval(old.UnixNano()), unix.NsecToTimeval(old.UnixNano())}); err != nil {
		t.Fatal(err)
	}
	if err := PruneNodeLibraries(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("a link to a library used a moment ago was pruned (%v)", err)
	}
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatal(err)
	}
	if err := PruneNodeLibraries(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); err == nil {
		t.Fatal("a link to a library unused for an hour was kept")
	}
}

func TestANodeNamedWithAnotherCaseIsTheSameNodeFromTheLibrary(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n  - {Name: up, type: ss, server: up.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "  - {name: \"n%02d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: picked, type: select, include-all: true, filter: \"^up$|^n0[0-1]$\"}\nrules:\n  - MATCH,picked\n")
	document := b.String()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	membersOf := func(text string) string {
		cfg, err := parseAfterLookups(text)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(cfg.Proxies["picked"])
		var g struct{ All []string }
		_ = json.Unmarshal(encoded, &g)
		return strings.Join(g.All, ",")
	}
	if got, want := membersOf(finalized.Value), membersOf(document); got != want || !strings.Contains(want, "up") {
		t.Fatalf("members:\n got  %s\n want %s", got, want)
	}
}

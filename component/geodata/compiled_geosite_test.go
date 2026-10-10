package geodata

import (
	"os"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata/compiled"
	"github.com/ProjectClash/Clash/component/geodata/router"
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
)

func stageCompiledHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	ClearGeoSiteCache()
	t.Cleanup(ClearGeoSiteCache)
	return CompiledGeoSiteDir()
}

func writeCompiledCategory(t *testing.T, directory, category string, domains ...string) {
	t.Helper()
	tree := trie.New[struct{}]()
	for _, domain := range domains {
		if err := tree.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := compiled.Store(directory, category, tree.NewDomainSet(), len(domains), nil); err != nil {
		t.Fatal(err)
	}
}

func TestCompiledCategoryIsPreferredOverSource(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "compiled-preference-probe")
	writeCompiledCategory(t, directory, "prefer-cn", "+.example.com")

	matcher, err := LoadGeoSiteMatcher("prefer-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Fatalf("source was decoded %d times despite a compiled artifact", *reads)
	}
	if !matcher.ApplyDomain("www.example.com") {
		t.Fatal("the compiled category does not answer for what it holds")
	}
}

func TestCompiledOnlyRuntimeDegradesInsteadOfDecoding(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "compiled-only-probe")
	previous := CompiledGeoSiteOnly()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(previous) })

	matcher, err := LoadGeoSiteMatcher("absent-cn")
	if err != nil {
		t.Fatalf("a missing compiled category refused to load: %v", err)
	}
	if *reads != 0 {
		t.Fatalf("a compiled-only runtime decoded source %d times", *reads)
	}
	if matcher == nil {
		t.Fatal("no matcher was returned")
	}
	if matcher.ApplyDomain("www.example.com") {
		t.Fatal("a category that was never loaded matched a domain")
	}
	if matcher.Count() != 0 {
		t.Fatalf("count = %d, want 0 for a category that did not load", matcher.Count())
	}
}

func TestUnconstrainedRuntimeStillDecodesSource(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "unconstrained-probe")
	SetCompiledGeoSiteOnly(false)

	if _, err := LoadGeoSiteMatcher("decoded-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("source reads = %d, want 1", *reads)
	}
}

func TestCompileGeoSiteWritesAnArtifactTheLoaderThenUses(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "compile-probe")
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("compile-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("compiling read source %d times, want 1", *reads)
	}
	path, err := compiled.Path(directory, "compile-cn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("compiling left no artifact: %v", err)
	}

	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	before := *reads
	matcher, err := LoadGeoSiteMatcher("compile-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != before {
		t.Fatal("the constrained runtime decoded source despite the artifact")
	}
	if !matcher.ApplyDomain("host0.example.com") {
		t.Fatal("the compiled artifact does not answer for what the source held")
	}
}

func TestCompilingIgnoresAnEmptyMatcherLeftByAConstrainedPreflight(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "poisoned-cache-probe")

	SetCompiledGeoSiteOnly(true)
	preflight, err := LoadGeoSiteMatcher("poisoned-cn")
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Count() != 0 || *reads != 0 {
		t.Fatalf("the preflight did not degrade: count=%d reads=%d", preflight.Count(), *reads)
	}

	SetCompiledGeoSiteOnly(false)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	if err := CompileGeoSite("poisoned-cn"); err != nil {
		t.Fatalf("compiling refused after a constrained preflight: %v", err)
	}
	if *reads != 1 {
		t.Fatalf("compiling read source %d times, want 1 — it used the cached empty matcher", *reads)
	}

	_, count, _, err := compiled.Load(directory, "poisoned-cn")
	if err != nil {
		t.Fatalf("no artifact was written: %v", err)
	}
	if count == 0 {
		t.Fatal("an empty artifact was written, which the tunnel would trust")
	}
}

func TestNegatedCategoryReadsTheArtifactItCompiled(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "negation-probe")
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("!negated-cn"); err != nil {
		t.Fatal(err)
	}

	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	before := *reads
	matcher, err := LoadGeoSiteMatcher("!negated-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != before {
		t.Fatal("the constrained runtime decoded source despite the artifact")
	}
	if matcher.ApplyDomain("host0.example.com") {
		t.Fatal("a domain inside the negated category matched")
	}
	if !matcher.ApplyDomain("unrelated.example.net") {
		t.Fatal("a domain outside the negated category did not match")
	}
}

func TestAttributedCategoryReadsTheArtifactItCompiled(t *testing.T) {
	stageCompiledHome(t)
	reads := 0
	boolAttr := func(key string) *router.Domain_Attribute {
		return &router.Domain_Attribute{
			Key:        key,
			TypedValue: &router.Domain_Attribute_BoolValue{BoolValue: true},
		}
	}
	domains := []*router.Domain{
		{Type: router.Domain_Domain, Value: "plain.example.com"},
		{Type: router.Domain_Domain, Value: "ads-only.example.com",
			Attribute: []*router.Domain_Attribute{boolAttr("ads")}},
		{Type: router.Domain_Domain, Value: "ads-apple.example.com",
			Attribute: []*router.Domain_Attribute{boolAttr("ads"), boolAttr("apple")}},
	}
	RegisterGeoDataLoaderImplementationCreator("attribute-probe", func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
	})
	previousLoader := geoLoaderName
	SetLoader("attribute-probe")
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		delete(loaders, "attribute-probe")
	})
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("attr-cn@ads@apple"); err != nil {
		t.Fatal(err)
	}

	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	matcher, err := LoadGeoSiteMatcher("attr-cn@ads@apple")
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.ApplyDomain("ads-apple.example.com") {
		t.Fatal("the entry carrying both attributes did not match")
	}
	if matcher.ApplyDomain("ads-only.example.com") {
		t.Fatal("an entry missing one requested attribute matched")
	}
	if matcher.ApplyDomain("plain.example.com") {
		t.Fatal("an unattributed entry matched")
	}
}

func TestResidualEntriesSurviveCompilation(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := 0
	domains := []*router.Domain{
		{Type: router.Domain_Domain, Value: "example.com"},
		{Type: router.Domain_Full, Value: "exact.example.org"},
		{Type: router.Domain_Regex, Value: `^intranet\..*\.corp$`},
		{Type: router.Domain_Plain, Value: "keyword-bit"},
	}
	RegisterGeoDataLoaderImplementationCreator("residual-probe", func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
	})
	previousLoader := geoLoaderName
	SetLoader("residual-probe")
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		delete(loaders, "residual-probe")
	})
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("residual-cn"); err != nil {
		t.Fatal(err)
	}
	_, count, residual, err := compiled.Load(directory, "residual-cn")
	if err != nil {
		t.Fatal(err)
	}
	if count != len(domains) {
		t.Fatalf("count = %d, want %d", count, len(domains))
	}
	if len(residual) != 2 {
		t.Fatalf("residual = %+v, want the regex and the keyword", residual)
	}

	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	matcher, err := LoadGeoSiteMatcher("residual-cn")
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range []string{
		"www.example.com", "exact.example.org",
		"intranet.finance.corp", "host-keyword-bit.example.net",
	} {
		if !matcher.ApplyDomain(hit) {
			t.Fatalf("the compiled category no longer matches %q", hit)
		}
	}
	if matcher.ApplyDomain("unrelated.example.net") {
		t.Fatal("the compiled category matches something the source did not")
	}
}

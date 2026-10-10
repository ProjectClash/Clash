package clash

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func mustOpen(t *testing.T, yamlText string) *ConfigDocument {
	t.Helper()
	doc, err := NewConfigDocument(yamlText)
	if err != nil {
		t.Fatalf("fixture does not open: %v", err)
	}
	t.Cleanup(doc.Close)
	return doc
}

func TestCatalogCarriesDeclarationsWithoutExpanding(t *testing.T) {
	doc := mustOpen(t, `
proxies:
  - {name: A, type: socks5, server: e.test, port: 1080}
proxy-groups:
  - {name: G, type: select, proxies: [A]}
  - {name: Auto, type: url-test, use: [Sub], include-all: true, filter: "HK"}
proxy-providers:
  Sub: {type: http, url: "https://unreachable.invalid/s.yaml", path: ./s.yaml}
`)
	got, err := buildConfigProjection(doc, "source", []string{projectionPackageCatalog})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if got.DocumentKind != "source" {
		t.Fatalf("kind not embedded: %+v", got)
	}
	if len(got.Catalog.Proxies) != 1 || got.Catalog.Proxies[0].Name != "A" {
		t.Fatalf("declared proxies wrong: %+v", got.Catalog.Proxies)
	}
	auto := got.Catalog.Groups[1]
	if auto.Name != "Auto" || len(auto.Use) != 1 || auto.Use[0] != "Sub" ||
		!auto.IncludeAll || auto.Filter != "HK" {
		t.Fatalf("declared group knobs lost: %+v", auto)
	}
	if len(auto.Proxies) != 0 {
		t.Fatalf("membership was expanded; it must stay as declared (empty): %+v", auto.Proxies)
	}
}

func TestUnrequestedPackagesAreAbsent(t *testing.T) {
	doc := mustOpen(t, "proxies: []\n")
	got, err := buildConfigProjection(doc, "source", []string{projectionPackageCatalog})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if got.Resources != nil || got.RuleFacts != nil || got.Scalars != nil {
		t.Fatalf("packages nobody asked for were produced: %+v", got)
	}
}

func TestNoProxiesSectionYieldsAnEmptyCatalogNotAnError(t *testing.T) {
	doc := mustOpen(t, "rules:\n  - MATCH,DIRECT\n")
	got, err := buildConfigProjection(doc, "source", []string{projectionPackageCatalog})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if got.Catalog == nil || len(got.Catalog.Proxies) != 0 {
		t.Fatalf("want present-and-empty catalog, got %+v", got.Catalog)
	}
}

func TestAClosedDocumentRefusesToProject(t *testing.T) {
	doc := mustOpen(t, "proxies: []\n")
	doc.Close()
	if _, err := buildConfigProjection(doc, "source", []string{projectionPackageCatalog}); err == nil {
		t.Fatal("a closed document served a projection")
	}
}

func TestProjectingNeverTouchesADeclaredProviderURL(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	doc := mustOpen(t, fmt.Sprintf(`
proxies:
  - {name: Local, type: socks5, server: e.test, port: 1080}
proxy-providers:
  Sub: {type: http, url: "%s/sub.yaml", path: ./sub.yaml}
rule-providers:
  Ads: {type: http, behavior: domain, url: "%s/ads.yaml", path: ./ads.yaml}
`, server.URL, server.URL))
	got, err := buildConfigProjection(doc, projectionKindSource,
		[]string{projectionPackageCatalog, projectionPackageResources})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("projection fetched a provider %d time(s); it must never perform I/O", n)
	}
	if len(got.Resources.ProxyProviders) != 1 || got.Resources.ProxyProviders[0].Name != "Sub" {
		t.Fatalf("declared provider not reported: %+v", got.Resources)
	}
	if got.Resources.RuleProviders[0].Behavior != "domain" {
		t.Fatalf("rule provider behavior lost: %+v", got.Resources.RuleProviders)
	}
	if len(got.Catalog.Proxies) != 1 || got.Catalog.Proxies[0].Name != "Local" {
		t.Fatalf("catalog must hold only declared nodes: %+v", got.Catalog.Proxies)
	}
}

func TestScalarsReportAbsenceNotDefaults(t *testing.T) {
	doc := mustOpen(t, "proxies: []\n")
	got, err := buildConfigProjection(doc, projectionKindSource, []string{projectionPackageScalars})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if got.Scalars.Mode != nil {
		t.Fatalf("mode was never declared yet reads %q (RawConfig default leaking)", *got.Scalars.Mode)
	}
	if got.Scalars.DNSEnable != nil || got.Scalars.GlobalUA != nil {
		t.Fatalf("undeclared scalars must be absent: %+v", got.Scalars)
	}
}

func TestProjectionIsDeterministic(t *testing.T) {
	doc := mustOpen(t, `
proxy-providers:
  Z: {type: http, url: "https://unreachable.invalid/z.yaml", path: ./z.yaml}
  A: {type: http, url: "https://unreachable.invalid/a.yaml", path: ./a.yaml}
  M: {type: http, url: "https://unreachable.invalid/m.yaml", path: ./m.yaml}
`)
	first, err := buildConfigProjection(doc, projectionKindSource, []string{projectionPackageResources})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := buildConfigProjection(doc, projectionKindSource, []string{projectionPackageResources})
		if err != nil {
			t.Fatalf("build failed on run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("projection differs between calls on run %d", i)
		}
	}
	if first.Resources.ProxyProviders[0].Name != "A" {
		t.Fatalf("providers must be sorted by name: %+v", first.Resources.ProxyProviders)
	}
}

func TestOneShotMatchesTheHandleRoute(t *testing.T) {
	yamlText := `
proxies:
  - {name: Local, type: socks5, server: e.test, port: 1080}
proxy-groups:
  - {name: G, type: select, proxies: [Local]}
proxy-providers:
  Sub: {type: http, url: "https://unreachable.invalid/s.yaml", path: ./s.yaml}
rule-providers:
  Ads: {type: http, behavior: domain, url: "https://unreachable.invalid/a.yaml", path: ./a.yaml}
rules:
  - RULE-SET,Ads,REJECT
  - MATCH,G
`
	packages := `["catalog","resources","ruleFacts","scalars"]`
	oneShot, err := ConfigProjectionJSON(yamlText, projectionKindSource, packages)
	if err != nil {
		t.Fatalf("one-shot failed: %v", err)
	}
	doc := mustOpen(t, yamlText)
	viaHandle, err := doc.ProjectionJSON(projectionKindSource, packages)
	if err != nil {
		t.Fatalf("handle route failed: %v", err)
	}
	if oneShot.Value != viaHandle.Value {
		t.Fatalf("two doors disagree:\n one-shot = %s\n handle   = %s",
			oneShot.Value, viaHandle.Value)
	}
}

func TestProjectionAgreesWithTheRuntimesWeakTyping(t *testing.T) {
	doc := mustOpen(t, `
mode: global
global-ua: 123
dns: {enable: yes, nameserver: ["1.1.1.1"]}
proxies:
  - {name: A, type: socks5, server: e.test, port: 1080}
proxy-groups:
  - {name: G, type: url-test, include-all: 1, use: [123]}
`)
	got, err := buildConfigProjection(doc, projectionKindSource,
		[]string{projectionPackageCatalog, projectionPackageScalars})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	group := got.Catalog.Groups[0]
	if !group.IncludeAll {
		t.Fatal("include-all: 1 is true to the runtime; the projection said false")
	}
	if len(group.Use) != 1 || group.Use[0] != "123" {
		t.Fatalf("a numeric use member is the string \"123\" to the runtime, got %+v", group.Use)
	}
	if got.Scalars.Mode == nil || *got.Scalars.Mode != "global" {
		t.Fatalf("declared mode lost: %+v", got.Scalars.Mode)
	}
	if got.Scalars.GlobalUA == nil || *got.Scalars.GlobalUA != "123" {
		t.Fatalf("global-ua: 123 is \"123\" to the runtime, got %+v", got.Scalars.GlobalUA)
	}
	if got.Scalars.DNSEnable == nil || !*got.Scalars.DNSEnable {
		t.Fatalf("dns.enable: yes is true to the runtime, got %+v", got.Scalars.DNSEnable)
	}
}

func TestNeitherPublicDoorTouchesADeclaredProviderURL(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()
	yamlText := fmt.Sprintf(`
proxy-providers:
  Sub: {type: http, url: "%s/sub.yaml", path: ./sub.yaml}
`, server.URL)
	packages := `["resources"]`

	doc := mustOpen(t, yamlText)
	if _, err := doc.ProjectionJSON(projectionKindSource, packages); err != nil {
		t.Fatalf("handle door failed: %v", err)
	}
	if _, err := ConfigProjectionJSON(yamlText, projectionKindSource, packages); err != nil {
		t.Fatalf("one-shot door failed: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a public door fetched a declared provider %d time(s)", n)
	}
}

func TestProjectionJSONIsActuallyCompact(t *testing.T) {
	doc := mustOpen(t, "proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\n")
	box, err := doc.ProjectionJSON(projectionKindSource, `["catalog"]`)
	if err != nil {
		t.Fatalf("projection failed: %v", err)
	}
	if strings.ContainsAny(box.Value, "\n\t") {
		t.Fatal("projection JSON is indented; one compact document is the contract")
	}
}

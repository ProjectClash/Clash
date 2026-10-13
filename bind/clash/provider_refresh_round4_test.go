package clash

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func seedThroughTheTelevision(t *testing.T, fixture *refreshFixture, service *BoxService, body string, fetchedAt int64) string {
	t.Helper()
	seedFile := filepath.Join(fixture.home, fmt.Sprintf("seed-%d", time.Now().UnixNano()))
	if err := os.WriteFile(seedFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	description := map[string]any{"sourceSHA256": payloadSHA256([]byte(body)), "payload": "source"}
	if fetchedAt > 0 {
		description["fetchedAt"] = fetchedAt
	}
	encoded, _ := json.Marshal(description)
	return SeedProviderFileJSON(fixture.options.kind, "refreshed", seedFile, string(encoded), service.runningConfigurationSHA256(), 0)
}

func TestASeedThatWillNotBuildLeavesWhatWaits(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy",
		published: "proxies:\n  - {name: A, type: direct}\n", served: "proxies:\n  - {name: B1, type: direct}\n  - {name: B2, type: direct}\n",
		fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	waiting := fixture.waitForResult(providerRefreshPendingApp)
	available.Store(1 << 32)
	_ = seedThroughTheTelevision(t, fixture, service, "proxies: []\n", time.Now().Add(-time.Hour).Unix())
	if _, entry := fixture.state(); entry.PendingSHA256 != waiting.PendingSHA256 || entry.Result != providerRefreshPendingApp {
		t.Fatalf("a seed that failed to build took what waits: %+v", entry)
	}
}

func TestASeedWithNoConfirmationLeavesAWaitingFirstLoad(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "new.example\nmore.example\n"})
	service := fixture.start()
	waiting := fixture.waitForResult(providerRefreshPendingApp)
	available.Store(1 << 32)
	answer := seedThroughTheTelevision(t, fixture, service, "seed.example\n", 0)
	if !strings.Contains(answer, `"result":"updated"`) || liveRuleCount() != 1 {
		t.Fatalf("the seed did not run: %s", answer)
	}
	if _, entry := fixture.state(); entry.PendingSHA256 != waiting.PendingSHA256 || entry.Result != providerRefreshPendingApp {
		t.Fatalf("a seed with no confirmation settled what waits: %+v", entry)
	}
}

func TestTheAwaitedPayloadKeepsItsLaterConfirmation(t *testing.T) {
	adjustableBuildMemory(t, 1<<20)
	served := "new.example\nmore.example\n"
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: served, compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	waiting := fixture.waitForResult(providerRefreshPendingApp)
	adjustableBuildMemory(t, 1<<32)
	if answer := seedThroughTheTelevision(t, fixture, service, served, waiting.PendingCheckedAt-10); !strings.Contains(answer, `"result":"updated"`) {
		t.Fatalf("the awaited payload: %s", answer)
	}
	if _, entry := fixture.state(); entry.LastCheckedAt < waiting.PendingCheckedAt {
		t.Fatalf("its confirmation moved back: %d < %d", entry.LastCheckedAt, waiting.PendingCheckedAt)
	}
	if answer := seedThroughTheTelevision(t, fixture, service, "between.example\n", waiting.PendingCheckedAt-5); !strings.Contains(answer, "older") {
		t.Fatalf("a seed confirmed before what runs was taken: %s", answer)
	}
}

func TestAReloadOfTheSameAgeSeedRunsItAgain(t *testing.T) {
	setup := testOptions(t)
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	providerCache.useHome(setup.WorkingPath)
	secret, _, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(setup.WorkingPath, "store", "nodes")
	_ = os.MkdirAll(filepath.Dir(seedFile), 0o700)
	_ = os.WriteFile(seedFile, []byte("proxies:\n  - {name: B, type: direct}\n"), 0o600)
	fetchedAt := time.Now().Add(-time.Hour).Unix()
	document := fmt.Sprintf("proxy-providers:\n  nodes: {type: http, url: https://nodes.example/sub, interval: 0, age-secret-key: %s}\nrules:\n  - MATCH,DIRECT\n", secret)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths": map[string]string{"proxy:nodes": seedFile}, "providerFetchedAt": map[string]int64{"proxy:nodes": fetchedAt},
	})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() *providerRefreshTarget {
		raw, err := config.UnmarshalRawConfig([]byte(finalized.Value))
		if err != nil {
			t.Fatal(err)
		}
		canonicalizeProviderDefinitionKeys(raw)
		return prepareProviderRefreshForTunnel(raw, currentRuntimePolicy(false)).targets[0]
	}
	target := prepare()
	identity, _ := providerSeedIdentity(seedFile)
	generation := "g"
	directory := providerCache.productDirectory(target.requestKey, target.productKey, generation)
	_ = os.MkdirAll(directory, 0o700)
	_ = os.WriteFile(filepath.Join(directory, "payload"), []byte("proxies:\n  - {name: A, type: direct}\n"), 0o600)
	providerCache.update(target.requestKey, func(entry *providerCacheEntry) {
		entry.SourceSHA256, entry.LastCheckedAt = "cipher", fetchedAt-3600
		entry.SeedCheckedAt, entry.SeedIdentity = fetchedAt, identity
		entry.Products = map[string]*providerCacheProduct{target.productKey: {Variant: "proxy", Entry: "payload", Files: []string{"payload"}, Generation: generation, SourceSHA256: "cipher"}}
	})
	if again := prepare(); again.pending == nil || again.product != nil {
		t.Fatalf("the Reload served the older cache instead of the seed")
	}
	providerCache.update(target.requestKey, func(entry *providerCacheEntry) { entry.LastCheckedAt = fetchedAt + 60 })
	if later := prepare(); later.product == nil {
		t.Fatalf("the server's newer copy was not served")
	}
}

func TestARouteSetStopsWaitingWhenTheServerGoesBack(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr",
		published: "192.0.2.0/24\n", served: "198.51.100.0/24\n203.0.113.0/24\n", routes: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	fixture.serve(http.StatusOK, "192.0.2.0/24\n")
	if result, _ := service.refreshNow("rule", "refreshed"); result.Result != providerRefreshUnchanged {
		t.Fatalf("the server went back: %+v", result)
	}
	if _, entry := fixture.state(); entry.Result != providerRefreshUnchanged || entry.PendingReason != "" {
		t.Fatalf("the App is still asked to publish: %+v", entry)
	}
}

func TestTheCatalogFindsAClassicalSetsCompiledProduct(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "classical",
		published: "DOMAIN-SUFFIX,a.example\n", served: "DOMAIN-SUFFIX,a.example\nDOMAIN-SUFFIX,b.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForEntry("the refresh's own result", func(e *providerCacheEntry) bool {
		return e.Result == providerRefreshUpdated && e.CountAfter == 2
	})
	product, _ := liveProduct(t, fixture, service)
	if product.Variant != "compiled" || !strings.EqualFold(product.Behavior, "domain") {
		t.Skipf("fixture: the classical set did not compile to a domain set (%s %s)", product.Variant, product.Behavior)
	}
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"rule:refreshed": fixture.seedPath},
		"providerFetchedAt": map[string]int64{"rule:refreshed": time.Now().Add(-2 * time.Hour).Unix()},
	})
	got, _ := catalogRuleProvidersCompiling(t, fixture.document(), string(resources), false)
	if count := got["refreshed"]["ruleCount"]; count != float64(2) {
		t.Fatalf("the catalog counts %v; the tunnel runs 2", count)
	}
}

func TestTheCatalogDecryptsTheCacheWhenTheSeedIsGone(t *testing.T) {
	setup := testOptions(t)
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	secret, public, _ := age.GenX25519KeyPair()
	cipher, _ := age.EncryptBytes([]byte("proxies:\n  - {name: A1, type: socks5, server: 192.0.2.1, port: 1080}\n"), public)
	providerCache.useHome(setup.WorkingPath)
	spec := &providerRefreshSpec{URL: "https://nodes.example/sub", AgeKey: secret}
	requestKey := spec.requestKey("proxy")
	_ = os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700)
	_ = os.WriteFile(providerCache.sourcePath(requestKey), cipher, 0o600)
	providerCache.update(requestKey, func(entry *providerCacheEntry) {
		entry.Kind, entry.SourceSHA256, entry.LastCheckedAt = "proxy", payloadSHA256(cipher), time.Now().Unix()
	})
	document := fmt.Sprintf(`proxy-providers:
  nodes: {type: http, url: https://nodes.example/sub, age-secret-key: %s}
proxy-groups:
  - {name: G, type: select, use: [nodes]}
rules:
  - MATCH,DIRECT
`, secret)
	resources, _ := json.Marshal(map[string]any{"providerPaths": map[string]string{"proxy:nodes": filepath.Join(setup.WorkingPath, "gone")}})
	view := catalogFor(t, document, string(resources), nil)
	if all, _ := view.Proxies["G"]["all"].([]any); len(all) != 1 || all[0] != "A1" {
		t.Fatalf("the catalog did not read the encrypted source: %v", view.Proxies["G"])
	}
}

func TestTheAwaitedPayloadIsKnownByItsBytes(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<20)
	served := "new.example\nmore.example\n"
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: served, compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	waiting := fixture.waitForResult(providerRefreshPendingApp)
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	providerCache.update(requestKey, func(entry *providerCacheEntry) { entry.LastCheckedAt = waiting.PendingCheckedAt - 5 })
	available.Store(1 << 32)
	seedFile := filepath.Join(fixture.home, "seed-unnamed")
	_ = os.WriteFile(seedFile, []byte(served), 0o600)
	description, _ := json.Marshal(map[string]any{"fetchedAt": waiting.PendingCheckedAt - 10, "payload": "source"})
	if answer := SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256(), 0); !strings.Contains(answer, `"result":"updated"`) {
		t.Fatalf("the awaited payload, unnamed: %s", answer)
	}
}

func TestASeedTakenAtStartRecordsItsCount(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy",
		published: "proxies:\n  - {name: A, type: direct}\n  - {name: B, type: direct}\n", served: "proxies:\n  - {name: A, type: direct}\n  - {name: B, type: direct}\n",
		fetchedAgo: time.Minute, interval: 86400})
	fixture.start()
	var entry *providerCacheEntry
	fixture.waitFor("the record", func() bool {
		_, entry = fixture.state()
		return entry != nil && entry.SourceSHA256 != ""
	})
	if entry.CountAfter != 2 || liveProxyCount() != 2 {
		t.Fatalf("the seed's count: %+v, %d live", entry, liveProxyCount())
	}
}

func TestASeedsCountComesFromTheNameThatRunsIt(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "unused.example\n", interval: 86400})
	seed := filepath.Join(fixture.home, "store", "payloads", "b")
	_ = os.MkdirAll(filepath.Dir(seed), 0o700)
	_ = os.WriteFile(seed, []byte("x.example\ny.example\n"), 0o600)
	document := fmt.Sprintf(`mode: rule
dns: {enable: true, nameserver: [8.8.8.8]}
rule-providers:
  a: {type: http, behavior: classical, format: text, url: %[1]s/rules.txt, interval: 86400}
  b: {type: http, behavior: domain, format: text, url: %[1]s/rules.txt, interval: 86400}
rules:
  - RULE-SET,a,DIRECT
  - RULE-SET,b,DIRECT
  - MATCH,DIRECT
`, fixture.server.URL)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"rule:b": seed},
		"providerFetchedAt": map[string]int64{"rule:b": time.Now().Add(-time.Minute).Unix()},
	})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	fixture.finalized = finalized.Value
	service := fixture.start()
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	var entry *providerCacheEntry
	fixture.waitFor("the record", func() bool {
		entry = providerCache.get(requestKey)
		return entry != nil && entry.SourceSHA256 != ""
	})
	if entry.CountAfter != 2 || liveRuleCountOf("b") != 2 {
		t.Fatalf("the count is not the seed's: %+v, b runs %d", entry, liveRuleCountOf("b"))
	}
}

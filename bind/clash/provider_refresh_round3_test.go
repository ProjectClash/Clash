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
)

func TestNamesOfOneRequestReadTheWinningSeedsCompiledProduct(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "unused.example\n", interval: 86400})
	directory := filepath.Join(fixture.home, "store", "payloads")
	_ = os.MkdirAll(directory, 0o700)
	older, newer := filepath.Join(directory, "older"), filepath.Join(directory, "newer")
	_ = os.WriteFile(older, []byte("old.example\n"), 0o600)
	_ = os.WriteFile(newer, []byte("new.example\nnewer.example\n"), 0o600)
	document := fmt.Sprintf(`mode: rule
dns: {enable: true, nameserver: [8.8.8.8]}
rule-providers:
  a: {type: http, behavior: domain, format: text, url: %[1]s/rules.txt, interval: 86400}
  b: {type: http, behavior: domain, format: text, url: %[1]s/rules.txt, interval: 86400}
rules:
  - RULE-SET,a,DIRECT
  - RULE-SET,b,DIRECT
  - MATCH,DIRECT
`, fixture.server.URL)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"rule:a": older, "rule:b": newer},
		"providerFetchedAt": map[string]int64{"rule:a": time.Now().Add(-3 * time.Hour).Unix(), "rule:b": time.Now().Add(-time.Hour).Unix()},
	})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(finalized.Value))
	if err != nil {
		t.Fatal(err)
	}
	canonicalizeProviderDefinitionKeys(raw)
	policy := currentRuntimePolicy(false)
	normalizeRawConfigForApple(raw, policy)
	runtime, err := stageProviderRuntime(raw, policy, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime.close()
	fixture.finalized = finalized.Value
	service := fixture.start()
	if a, b := liveRuleCountOf("a"), liveRuleCountOf("b"); a != 2 || b != 2 {
		t.Fatalf("both names run the newer seed: a=%d b=%d", a, b)
	}
	if _, staged := service.providerRuntime.entries[providerRuntimeKey("rule", "a")]; staged {
		t.Fatalf("the start staged the newer seed under the other name")
	}
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	var entry *providerCacheEntry
	fixture.waitFor("the record", func() bool {
		entry = providerCache.get(requestKey)
		return entry != nil && len(entry.Products) == 1
	})
	for _, product := range entry.Products {
		if product.Variant != "compiled" {
			t.Fatalf("the product is %s, not the App's compile", product.Variant)
		}
	}
}

func TestASeedOlderThanAWaitingFirstLoadDoesNotDisplaceIt(t *testing.T) {
	adjustableBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "new.example\nmore.example\n"})
	service := fixture.start()
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.SourceSHA256 != "" || entry.PendingSHA256 == "" {
		t.Fatalf("fixture: %+v", entry)
	}
	body := []byte("old.example\n")
	seedFile := filepath.Join(fixture.home, "seed-older")
	_ = os.WriteFile(seedFile, body, 0o600)
	description, _ := json.Marshal(map[string]any{"fetchedAt": time.Now().Add(-time.Hour).Unix(), "sourceSHA256": payloadSHA256(body), "payload": "source"})
	_ = SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256())
	if _, after := fixture.state(); after.PendingSHA256 != entry.PendingSHA256 || after.PendingCheckedAt != entry.PendingCheckedAt {
		t.Fatalf("what waits changed: %+v -> %+v", entry, after)
	}
}

func TestANewerWaitingPayloadIsNotDisplacedByARebuild(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<32)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "a1.example\na2.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	_, product := liveProduct(t, fixture, service)
	available.Store(1 << 20)
	fixture.serve(http.StatusOK, "b1.example\nb2.example\nb3.example\n")
	if result, _ := service.refreshNow("rule", "refreshed"); result.Result != providerRefreshPendingApp {
		t.Fatalf("fixture: %+v", result)
	}
	_, waiting := fixture.state()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Dir(product))
	fixture.start()
	time.Sleep(300 * time.Millisecond)
	if _, after := fixture.state(); after.PendingSHA256 != waiting.PendingSHA256 || after.PendingCheckedAt < waiting.PendingCheckedAt {
		t.Fatalf("the newer waiting payload was displaced: %+v -> %+v", waiting, after)
	}
}

func TestAnAgeSeedsConfirmationCountsThoughItIsNotRecorded(t *testing.T) {
	providerCache.useHome(t.TempDir())
	spec := &providerRefreshSpec{URL: "https://nodes.example/sub", AgeKey: "AGE-SECRET-KEY-1EXAMPLE"}
	confirmed := time.Now().Add(-time.Hour)
	target := &providerRefreshTarget{kind: "proxy", name: "nodes", spec: spec, requestKey: spec.requestKey("proxy"), productKey: "p",
		pending: &providerCacheImport{product: &providerCacheProduct{Variant: "proxy"}, fromSeed: true, older: true, serverFirst: true, fetchedAt: confirmed}}
	providerCache.update(target.requestKey, func(entry *providerCacheEntry) {
		entry.SourceSHA256, entry.LastCheckedAt = "cipher", time.Now().Add(-3*time.Hour).Unix()
	})
	commitProviderRefreshPlan(&providerRefreshPlan{targets: []*providerRefreshTarget{target}})
	if got := runningConfirmation(providerCache.get(target.requestKey)); got != confirmed.Unix() {
		t.Fatalf("the seed's confirmation is %d, want %d", got, confirmed.Unix())
	}
}

func TestTheCatalogDecryptsTheCachesAgeSource(t *testing.T) {
	setup := testOptions(t)
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	secret, public, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := age.EncryptBytes([]byte("proxies:\n  - {name: A1, type: socks5, server: 192.0.2.1, port: 1080}\n"), public)
	if err != nil {
		t.Fatal(err)
	}
	providerCache.useHome(setup.WorkingPath)
	spec := &providerRefreshSpec{URL: "https://nodes.example/sub", AgeKey: secret}
	requestKey := spec.requestKey("proxy")
	if err := os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerCache.sourcePath(requestKey), cipher, 0o600); err != nil {
		t.Fatal(err)
	}
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
	view := catalogFor(t, document, "{}", nil)
	if all, _ := view.Proxies["G"]["all"].([]any); len(all) != 1 || all[0] != "A1" {
		t.Fatalf("the catalog did not read the encrypted source: %v", view.Proxies["G"])
	}
}

func TestTheAwaitedPayloadIsTakenWhateverItsConfirmation(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<20)
	served := "new.example\nmore.example\n"
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: served, compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	waiting := fixture.waitForResult(providerRefreshPendingApp)
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	appFetched := waiting.PendingCheckedAt - 10
	providerCache.update(requestKey, func(entry *providerCacheEntry) { entry.LastCheckedAt = waiting.PendingCheckedAt - 5 })
	seed := func() string {
		seedFile := filepath.Join(fixture.home, "seed-awaited")
		_ = os.WriteFile(seedFile, []byte(served), 0o600)
		description, _ := json.Marshal(map[string]any{"fetchedAt": appFetched, "sourceSHA256": payloadSHA256([]byte(served)), "payload": "source"})
		return SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256())
	}
	if answer := seed(); !strings.Contains(answer, `"result":"pendingApp"`) {
		t.Fatalf("the awaited payload with no room: %s", answer)
	}
	if _, entry := fixture.state(); entry.PendingCheckedAt != waiting.PendingCheckedAt {
		t.Fatalf("the wait's confirmation moved back: %d -> %d", waiting.PendingCheckedAt, entry.PendingCheckedAt)
	}
	available.Store(1 << 32)
	if answer := seed(); !strings.Contains(answer, `"result":"updated"`) || liveRuleCount() != 2 {
		t.Fatalf("the awaited payload was refused: %s", answer)
	}
	if _, entry := fixture.state(); entry.PendingSHA256 != "" {
		t.Fatalf("what waited is still waiting: %+v", entry)
	}
}

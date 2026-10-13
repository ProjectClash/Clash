package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func adjustableBuildMemory(t *testing.T, initial int64) *atomic.Int64 {
	t.Helper()
	var available atomic.Int64
	available.Store(initial)
	buildMemoryReader.Lock()
	read, zero := buildMemoryReader.read, buildMemoryReader.zeroIsExhausted
	buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = func() int64 { return available.Load() }, true
	buildMemoryReader.Unlock()
	t.Cleanup(func() {
		buildMemoryReader.Lock()
		buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = read, zero
		buildMemoryReader.Unlock()
	})
	return &available
}

func liveRuleCountOf(name string) int {
	provider, ok := tunnel.RuleProviders()[name]
	if !ok {
		return -1
	}
	return provider.Count()
}

func TestNamesOfOneRequestRunTheNewestSeedWithItsOwnConfirmation(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "unused.example\n", interval: 86400})
	directory := filepath.Join(fixture.home, "store", "payloads")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	older, newer := filepath.Join(directory, "older"), filepath.Join(directory, "newer")
	_ = os.WriteFile(older, []byte("old.example\n"), 0o600)
	_ = os.WriteFile(newer, []byte("new.example\nnewer.example\n"), 0o600)
	olderAt, newerAt := time.Now().Add(-3*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
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
		"providerFetchedAt": map[string]int64{"rule:a": olderAt, "rule:b": newerAt},
	})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	fixture.finalized = finalized.Value
	service := fixture.start()
	if a, b := liveRuleCountOf("a"), liveRuleCountOf("b"); a != 2 || b != 2 {
		t.Fatalf("both names run the newer seed: a=%d b=%d", a, b)
	}
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	var entry *providerCacheEntry
	fixture.waitFor("the record", func() bool {
		entry = providerCache.get(requestKey)
		return entry != nil && entry.SourceSHA256 != ""
	})
	if entry.SourceSHA256 != payloadSHA256([]byte("new.example\nnewer.example\n")) || entry.LastCheckedAt != newerAt {
		t.Fatalf("the record pairs content and confirmation wrongly: %+v", entry)
	}
}

func TestAFailedDownloadKeepsAMemoryWait(t *testing.T) {
	available := adjustableBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	fixture.mu.Lock()
	fixture.etag = `"v2"`
	fixture.mu.Unlock()
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	fixture.mu.Lock()
	fixture.etag, fixture.status = "", http.StatusInternalServerError
	fixture.mu.Unlock()
	if result, _ := service.refreshNow("rule", "refreshed"); result.Result != providerRefreshFailed {
		t.Fatalf("the failed download: %+v", result)
	}
	if _, entry := fixture.state(); entry.Result != providerRefreshPendingApp || entry.PendingReason != providerRefreshPendingMemory || entry.Error == "" {
		t.Fatalf("after a failed download: %+v", entry)
	}
	fixture.mu.Lock()
	fixture.etag, fixture.status = `"v2"`, http.StatusOK
	fixture.mu.Unlock()
	available.Store(1 << 32)
	if result, _ := service.refreshNow("rule", "refreshed"); result.Result != providerRefreshUpdated || liveRuleCount() != 2 {
		t.Fatalf("with room the kept payload builds: %+v, %d rules", result, liveRuleCount())
	}
}

func TestASeedOlderThanWhatWaitsDoesNotDisplaceIt(t *testing.T) {
	adjustableBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	body := []byte("old.example\n")
	seedFile := filepath.Join(fixture.home, "seed-between")
	_ = os.WriteFile(seedFile, body, 0o600)
	description, _ := json.Marshal(map[string]any{"fetchedAt": time.Now().Add(-time.Hour).Unix(), "sourceSHA256": payloadSHA256(body), "payload": "source"})
	answer := SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256(), 0)
	var result providerRefreshResult
	if err := json.Unmarshal([]byte(answer), &result); err != nil || result.Result != providerRefreshUnchanged {
		t.Fatalf("a seed of what runs: %s", answer)
	}
	_, entry := fixture.state()
	if entry.PendingSHA256 == "" || !regularFileExists(providerCache.pendingPath(service.providerRuntime.refresh.targets[0].requestKey)) {
		t.Fatalf("what waits is gone: %+v", entry)
	}
	if entry.Result != providerRefreshPendingApp || entry.PendingReason != providerRefreshPendingMemory {
		t.Fatalf("the App no longer sees what waits for it: %+v", entry)
	}
}

func TestACacheRebuildThatFailsAsksTheServer(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", served: "a.example\n"})
	service := fixture.start()
	fixture.waitFor("the first load", func() bool { return liveRuleCount() == 1 })
	fixture.waitForResult(providerRefreshUpdated)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	if err := ruleprovider.ConvertToMrs([]byte("b.example\nc.example\n"), P.Domain, P.TextRule, &artifact); err != nil {
		t.Fatal(err)
	}
	fixture.serve(http.StatusOK, artifact.String())
	fixture.options.format = "mrs"
	fixture.finalize()
	requests := fixture.requests.Load()
	fixture.start()
	fixture.waitFor("the MRS from the server", func() bool { return liveRuleCount() == 2 })
	if fixture.requests.Load() == requests {
		t.Fatalf("the server was not asked")
	}
}

func TestARebuildAfterAKillKeepsThatPayloadRefused(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	killer := "k1.example\nk2.example\nk3.example\n"
	providerCache.writeInflightMarker(providerBuildInflight{RequestKey: requestKey, PayloadSHA256: payloadSHA256([]byte(killer)), PID: os.Getpid() + 1, Committing: true})
	fixture.start()
	fixture.waitFor("the rebuild", func() bool { return liveRuleCount() == 2 })
	fixture.waitFor("the rebuild on record", func() bool {
		entry := providerCache.get(requestKey)
		return entry != nil && len(entry.Products) > 0
	})
	if entry := providerCache.get(requestKey); entry.KilledSHA256 != payloadSHA256([]byte(killer)) {
		t.Fatalf("the rebuild lifted the refusal: %+v", entry)
	}
	fixture.serve(http.StatusOK, killer)
	if result, _ := fixture.service.refreshNow("rule", "refreshed"); result.Result != providerRefreshPendingApp || result.PendingReason != providerRefreshPendingKilled {
		t.Fatalf("the payload that killed the tunnel was built again: %+v", result)
	}
}

func TestACompiledSeedIsJudgedByItsWindow(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "a.example\n", served: "a.example\n", compile: true, fetchedAgo: time.Second, interval: 86400})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "compiled" {
		t.Fatalf("fixture: the set does not run compiled (%s)", product.Variant)
	}
	adjustableBuildMemory(t, 8<<20)
	source := []byte("x.example\ny.example\n")
	var artifact bytes.Buffer
	if err := ruleprovider.ConvertToMrs(source, P.Domain, P.TextRule, &artifact); err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(fixture.home, "seed-mrs")
	_ = os.WriteFile(seedFile, artifact.Bytes(), 0o600)
	description, _ := json.Marshal(map[string]any{"fetchedAt": time.Now().Add(time.Second).Unix(), "sourceSHA256": payloadSHA256(source), "payload": "mrs"})
	answer := SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256(), 0)
	if !strings.Contains(answer, `"result":"updated"`) || liveRuleCount() != 2 {
		t.Fatalf("an MRS with a 1 MiB window fits in 8 MiB: %s", answer)
	}
}

func TestTheCatalogReadsTheCachesNewerContent(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", fetchedAgo: 2 * time.Hour})
	fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"rule:refreshed": fixture.seedPath},
		"providerFetchedAt": map[string]int64{"rule:refreshed": time.Now().Add(-2 * time.Hour).Unix()},
	})
	got, _ := catalogRuleProvidersCompiling(t, fixture.document(), string(resources), false)
	if count := got["refreshed"]["ruleCount"]; count != float64(2) {
		t.Fatalf("the catalog counts %v; the tunnel runs the cache's 2", count)
	}
}

func TestATelevisionUpdateTimesOutWhileTheServiceIsBusy(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	service := fixture.start()
	service.mu.Lock()
	started := time.Now()
	answer := UpdateProviderJSON("rule", "refreshed", 100)
	waited := time.Since(started)
	service.mu.Unlock()
	if waited > 2*time.Second || !strings.Contains(answer, "busy") {
		t.Fatalf("waited %v for %s", waited, answer)
	}
}

func TestAShortenedIntervalTakesEffectAtTheNextStart(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "a.example\n", served: "a.example\n", fetchedAgo: 2 * time.Hour, interval: 86400})
	service := fixture.start()
	fixture.waitFor("the schedule on record", func() bool {
		_, entry := fixture.state()
		return entry != nil && entry.NextDueAt > time.Now().Add(time.Hour).Unix()
	})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	requests := fixture.requests.Load()
	fixture.options.interval = 3600
	fixture.finalize()
	fixture.start()
	fixture.waitFor("the check the shorter interval makes due", func() bool { return fixture.requests.Load() > requests })
}

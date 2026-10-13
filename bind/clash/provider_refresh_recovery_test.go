package clash

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestACacheNewerThanTheSeedWithNoProductIsRebuiltByTheRefresherNotByTheStart(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	_, product := liveProduct(t, fixture, service)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(product)); err != nil {
		t.Fatal(err)
	}
	requests := fixture.requests.Load()
	fixture.start()
	fixture.waitFor("the rebuild", func() bool { return liveRuleCount() == 2 })
	time.Sleep(200 * time.Millisecond)
	if fixture.requests.Load() != requests {
		t.Fatalf("the rebuild asked the server; the cache held the content")
	}
}

func TestTheStartDoesNotParseTheCachesSourceWhenTheRebuildHasNoRoom(t *testing.T) {
	var available atomic.Int64
	available.Store(1 << 32)
	buildMemoryReader.Lock()
	read, zero := buildMemoryReader.read, buildMemoryReader.zeroIsExhausted
	buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = func() int64 { return available.Load() }, true
	buildMemoryReader.Unlock()
	t.Cleanup(func() {
		buildMemoryReader.Lock()
		buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = read, zero
		buildMemoryReader.Unlock()
	})
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	_, product := liveProduct(t, fixture, service)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(product)); err != nil {
		t.Fatal(err)
	}
	available.Store(1 << 20)
	fixture.start()
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("the start staged the cache's source: %d rules", count)
	}
	if entry := fixture.waitForResult(providerRefreshPendingApp); entry.PendingReason != providerRefreshPendingMemory {
		t.Fatalf("the rebuild waits for headroom: %+v", entry)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("a rebuild with no room changed what runs: %d rules", count)
	}
	available.Store(1 << 32)
	if result, err := fixture.service.refreshNow("rule", "refreshed"); err != nil || result.Result != providerRefreshUpdated || liveRuleCount() != 2 {
		t.Fatalf("with room it builds: %+v (%v), %d rules", result, err, liveRuleCount())
	}
}

func TestAFormatLeftOutIsYAMLForTheProductKey(t *testing.T) {
	policy := currentRuntimePolicy(false)
	if providerProductKey("rule", "domain", "", "", policy) != providerProductKey("rule", "Domain", " YAML ", "", policy) {
		t.Fatalf("a format left out is upstream's yaml")
	}
	if providerProductKey("rule", "domain", "text", "", policy) == providerProductKey("rule", "domain", "yaml", "", policy) {
		t.Fatalf("text and yaml are different products")
	}
}

func TestARouteSetWithNothingLoadedLoadsItsRulesAndItsRoutesWaitForTheApp(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr",
		served: "198.51.100.0/24\n203.0.113.0/24\n", routes: true})
	fixture.start()
	fixture.waitFor("the rules half", func() bool { return liveRuleCount() == 2 })
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.PendingReason != providerRefreshPendingRoutes || entry.CountAfter != 2 {
		t.Fatalf("the routes wait for the App: %+v", entry)
	}
}

func TestAKillWhileAProductWasReplacedServesNoneOfItAndAnAbandonedBuildIsNoKill(t *testing.T) {
	providerCache.useHome(t.TempDir())
	product := &providerCacheProduct{Variant: "text", Entry: "payload", Files: []string{"payload"}, Generation: "g", SourceSHA256: "old"}
	for _, key := range []string{"committing", "abandoned"} {
		providerCache.update(key, func(entry *providerCacheEntry) {
			entry.SourceSHA256 = "old"
			entry.Products = map[string]*providerCacheProduct{"p": product}
		})
	}
	providerCache.writeInflightMarker(providerBuildInflight{RequestKey: "committing", PayloadSHA256: "new", PID: os.Getpid() + 1, Committing: true})
	providerCache.consumeInflight()
	if entry := providerCache.get("committing"); len(entry.Products) != 0 || entry.KilledSHA256 != "new" || entry.PendingReason != providerRefreshPendingKilled {
		t.Fatalf("a kill mid-commit: %+v", entry)
	}
	providerCache.writeInflightMarker(providerBuildInflight{RequestKey: "abandoned", PayloadSHA256: "new", PID: os.Getpid()})
	providerCache.abandonInflight()
	payload, _ := os.ReadFile(filepath.Join(providerCache.rootDirectory(), providerRefreshInflightFileName))
	var marker providerBuildInflight
	_ = json.Unmarshal(payload, &marker)
	marker.PID = os.Getpid() + 1
	providerCache.writeInflightMarker(marker)
	providerCache.consumeInflight()
	if entry := providerCache.get("abandoned"); entry.KilledSHA256 != "" || entry.Products["p"] == nil {
		t.Fatalf("an abandoned build is no kill: %+v", entry)
	}
	if _, err := os.Stat(filepath.Join(providerCache.rootDirectory(), providerRefreshInflightFileName)); !os.IsNotExist(err) {
		t.Fatalf("the marker stays: %v", err)
	}
}

func TestARunningRequestKeepsItsCacheWhenTheStateIsLost(t *testing.T) {
	providerCache.useHome(t.TempDir())
	for _, key := range []string{"running", "orphan"} {
		if err := os.MkdirAll(providerCache.requestDirectory(key), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	providerCache.prune(map[string]bool{"running": true})
	if _, err := os.Stat(providerCache.requestDirectory("running")); err != nil {
		t.Fatalf("the running request's cache went: %v", err)
	}
	if _, err := os.Stat(providerCache.requestDirectory("orphan")); !os.IsNotExist(err) {
		t.Fatalf("an orphan stays: %v", err)
	}
	providerCache.setRunning("config", map[string]string{"rule:a": "running"}, nil, nil)
	if entry := providerCache.get("running"); entry == nil || entry.LastReferencedAt == 0 {
		t.Fatalf("a running request is on record from its start: %+v", entry)
	}
}

func TestAPayloadThatWaitedForMemoryIsAskedForWithItsTagAndBuiltWhenThereIsRoom(t *testing.T) {
	var available atomic.Int64
	available.Store(1 << 20)
	buildMemoryReader.Lock()
	read, zero := buildMemoryReader.read, buildMemoryReader.zeroIsExhausted
	buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = func() int64 { return available.Load() }, true
	buildMemoryReader.Unlock()
	t.Cleanup(func() {
		buildMemoryReader.Lock()
		buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = read, zero
		buildMemoryReader.Unlock()
	})
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	fixture.mu.Lock()
	fixture.etag = `"v2"`
	fixture.mu.Unlock()
	service := fixture.start()
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.PendingReason != providerRefreshPendingMemory || entry.PendingETag != `"v2"` {
		t.Fatalf("pending: %+v", entry)
	}
	available.Store(1 << 32)
	result, err := service.refreshNow("rule", "refreshed")
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != providerRefreshUpdated || liveRuleCount() != 2 || fixture.notMod.Load() == 0 {
		t.Fatalf("built from the kept payload after a 304: %+v, %d rules, %d 304s", result, liveRuleCount(), fixture.notMod.Load())
	}
}

func TestATextSetWithNoRulesIsTakenAsEmpty(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "classical",
		published: "DOMAIN,a.example\n", served: "# nothing here\n\n", fetchedAgo: 2 * time.Hour})
	fixture.start()
	var entry *providerCacheEntry
	fixture.waitFor("the empty set", func() bool {
		_, entry = fixture.state()
		return entry != nil && entry.Result == providerRefreshUpdated && entry.CountBefore == 1
	})
	if liveRuleCount() != 0 || entry.CountAfter != 0 {
		t.Fatalf("zero rules: %+v, %d live", entry, liveRuleCount())
	}
}

func TestAProviderWithNoIntervalIsNotAskedAgainOnceLoaded(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "b.example\n", interval: -1})
	fixture.start()
	time.Sleep(300 * time.Millisecond)
	if requests := fixture.requests.Load(); requests != 0 {
		t.Fatalf("interval 0 asked the server %d times", requests)
	}
}

func TestATelevisionReachesTheRefresherInProcess(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	service := fixture.start()
	body := "x.example\ny.example\n"
	seedFile := filepath.Join(fixture.home, "seed-from-the-app")
	if err := os.WriteFile(seedFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	description, _ := json.Marshal(map[string]any{"fetchedAt": time.Now().Add(time.Second).Unix(), "sourceSHA256": payloadSHA256([]byte(body)), "payload": "source"})
	var result providerRefreshResult
	answer := SeedProviderFileJSON("rule", "refreshed", seedFile, string(description), service.runningConfigurationSHA256(), 0)
	if err := json.Unmarshal([]byte(answer), &result); err != nil || result.Result != providerRefreshUpdated || liveRuleCount() != 2 {
		t.Fatalf("SeedProviderFileJSON answered %s", answer)
	}
	if _, err := os.Stat(seedFile); err != nil {
		t.Fatalf("the App's file is the App's: %v", err)
	}
	if names, _ := os.ReadDir(filepath.Join(providerCache.rootDirectory(), providerRefreshIncomingDirectory)); len(names) != 0 {
		t.Fatalf("seed bodies left behind: %d", len(names))
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(outside, []byte(body), 0o600)
	if answer := SeedProviderFileJSON("rule", "refreshed", outside, string(description), "", 0); !strings.Contains(answer, `"error"`) {
		t.Fatalf("a file outside the home is refused: %s", answer)
	}
	fixture.serve(http.StatusOK, "x.example\n")
	if answer := UpdateProviderJSON("rule", "nope", 1000); !strings.Contains(answer, ProviderUpdateUnavailablePrefix) {
		t.Fatalf("an unknown provider is unavailable: %s", answer)
	}
	if answer := UpdateProviderJSON("rule", "refreshed", 10000); !strings.Contains(answer, `"result":"updated"`) || liveRuleCount() != 1 {
		t.Fatalf("UpdateProviderJSON answered %s", answer)
	}
}

package clash

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
	"go.yaml.in/yaml/v3"
)

type refreshFixture struct {
	t         *testing.T
	home      string
	server    *httptest.Server
	mu        sync.Mutex
	body      []byte
	status    int
	etag      string
	userinfo  string
	requests  atomic.Int64
	notMod    atomic.Int64
	finalized string
	options   refreshFixtureOptions
	seedPath  string
	service   *BoxService
}

type refreshFixtureOptions struct {
	kind, behavior, format string
	published              string
	served                 string
	compile                bool
	routes                 bool
	fetchedAgo             time.Duration
	interval               int
}

func newRefreshFixture(t *testing.T, options refreshFixtureOptions) *refreshFixture {
	t.Helper()
	if options.behavior == "" {
		options.behavior = "domain"
	}
	if options.format == "" {
		options.format = "text"
	}
	if options.interval == 0 {
		options.interval = 3600
	}
	if options.interval < 0 {
		options.interval = 0
	}
	settle, backoff, poll := providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll
	firstMin := providerRefreshFirstLoadMinimum
	providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll = 0, 50*time.Millisecond, 20*time.Millisecond
	providerRefreshFirstLoadMinimum = 50 * time.Millisecond
	t.Cleanup(func() {
		providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll = settle, backoff, poll
		providerRefreshFirstLoadMinimum = firstMin
	})
	setup := testOptions(t)
	setup.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	fixture := &refreshFixture{t: t, home: setup.WorkingPath, body: []byte(options.served), status: http.StatusOK, options: options}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if fixture.userinfo != "" {
			w.Header().Set("subscription-userinfo", fixture.userinfo)
		}
		if fixture.etag != "" {
			if r.Header.Get("If-None-Match") == fixture.etag {
				fixture.notMod.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", fixture.etag)
		}
		w.WriteHeader(fixture.status)
		_, _ = w.Write(fixture.body)
	}))
	t.Cleanup(fixture.server.Close)
	fixture.finalize()
	return fixture
}

func (f *refreshFixture) document() string {
	o := f.options
	switch o.kind {
	case "proxy":
		return fmt.Sprintf(`mode: rule
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  refreshed:
    type: http
    url: %s/nodes
    interval: %d
proxy-groups:
  - name: G
    type: select
    use: [refreshed]
rules:
  - MATCH,DIRECT
`, f.server.URL, o.interval)
	default:
		document := fmt.Sprintf(`mode: rule
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  refreshed:
    type: http
    behavior: %s
    format: %s
    url: %s/rules.txt
    interval: %d
rules:
  - RULE-SET,refreshed,DIRECT
  - MATCH,DIRECT
`, o.behavior, o.format, f.server.URL, o.interval)
		if o.routes {
			document = "tun:\n  enable: false\n  route-address-set: [refreshed]\n" + document
		}
		return document
	}
}

func (f *refreshFixture) finalize() {
	f.t.Helper()
	o := f.options
	resourceMap := map[string]any{}
	if o.published != "" {
		directory := filepath.Join(f.home, "store", "payloads")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			f.t.Fatal(err)
		}
		f.seedPath = filepath.Join(directory, fmt.Sprintf("seed-%d", time.Now().UnixNano()))
		if err := os.WriteFile(f.seedPath, []byte(o.published), 0o600); err != nil {
			f.t.Fatal(err)
		}
		key := o.kind + ":refreshed"
		resourceMap["providerPaths"] = map[string]string{key: f.seedPath}
		if o.fetchedAgo != 0 {
			resourceMap["providerFetchedAt"] = map[string]int64{key: time.Now().Add(-o.fetchedAgo).Unix()}
		}
	}
	encoded, _ := json.Marshal(resourceMap)
	finalized, err := FinalizeForIOS(f.document(), string(encoded))
	if err != nil {
		f.t.Fatal(err)
	}
	f.finalized = finalized.Value
	if o.compile && o.published != "" {
		raw, err := config.UnmarshalRawConfig([]byte(f.finalized))
		if err != nil {
			f.t.Fatal(err)
		}
		canonicalizeProviderDefinitionKeys(raw)
		policy := currentRuntimePolicy(false)
		normalizeRawConfigForApple(raw, policy)
		runtime, err := stageProviderRuntime(raw, policy, true)
		if err != nil {
			f.t.Fatal(err)
		}
		runtime.close()
	}
}

func (f *refreshFixture) serve(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, []byte(body)
}

func (f *refreshFixture) start() *BoxService {
	f.t.Helper()
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := service.Start(f.finalized); err != nil {
		f.t.Fatal(err)
	}
	f.service = service
	f.t.Cleanup(func() { _ = service.Close() })
	return service
}

func (f *refreshFixture) state() (*providerCacheStateFile, *providerCacheEntry) {
	payload, err := os.ReadFile(filepath.Join(f.home, ProviderRefreshDirectoryName, ProviderRefreshStateFileName))
	if err != nil {
		return nil, nil
	}
	var state providerCacheStateFile
	if err := json.Unmarshal(payload, &state); err != nil || state.Version != 2 {
		f.t.Fatalf("state file: %v (version %d)", err, state.Version)
	}
	requestKey := state.Running.Providers[f.options.kind+":refreshed"]
	return &state, state.Entries[requestKey]
}

func (f *refreshFixture) waitFor(what string, condition func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("timed out waiting for %s", what)
}

func (f *refreshFixture) waitForResult(result string) *providerCacheEntry {
	f.t.Helper()
	var entry *providerCacheEntry
	f.waitFor("result "+result, func() bool {
		_, entry = f.state()
		return entry != nil && entry.Result == result
	})
	return entry
}

func liveRuleCount() int {
	provider, ok := tunnel.RuleProviders()["refreshed"]
	if !ok {
		return -1
	}
	return provider.Count()
}

func liveProxyCount() int {
	provider, ok := tunnel.Providers()["refreshed"]
	if !ok {
		return -1
	}
	return provider.Count()
}

func withBuildMemory(t *testing.T, available int64) {
	t.Helper()
	buildMemoryReader.Lock()
	read, zero := buildMemoryReader.read, buildMemoryReader.zeroIsExhausted
	buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = func() int64 { return available }, true
	buildMemoryReader.Unlock()
	t.Cleanup(func() {
		buildMemoryReader.Lock()
		buildMemoryReader.read, buildMemoryReader.zeroIsExhausted = read, zero
		buildMemoryReader.Unlock()
	})
}

func liveProduct(t *testing.T, fixture *refreshFixture, service *BoxService) (*providerCacheProduct, string) {
	t.Helper()
	target := service.providerRuntime.refresh.targets[0]
	var entry *providerCacheEntry
	fixture.waitFor("the product on record", func() bool {
		_, entry = fixture.state()
		return entry != nil && entry.Products[target.productKey] != nil
	})
	product := entry.Products[target.productKey]
	return product, filepath.Join(providerCache.productDirectory(target.requestKey, target.productKey, product.Generation), product.Entry)
}

func TestTheTunnelRefreshesACompiledSetAndTheNextStartServesItFromItsCache(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\n+.newer.example\nthird.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "compiled" {
		t.Fatalf("the published seed should run compiled, from the cache: %q", product.Variant)
	}
	fixture.waitFor("the refreshed set to go live", func() bool { return liveRuleCount() == 3 })
	entry := fixture.waitForResult(providerRefreshUpdated)
	if entry.CountBefore != 1 || entry.CountAfter != 3 || entry.LastCheckedAt == 0 || entry.NextDueAt <= time.Now().Unix() {
		t.Fatalf("state entry: %+v", entry)
	}
	_, runtimeFile := liveProduct(t, fixture, service)
	if payload, _ := os.ReadFile(runtimeFile); strings.Contains(string(payload), "new.example") {
		t.Fatalf("a compiled set's product holds text, not MRS")
	}
	before, _ := os.Stat(runtimeFile)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	requests := fixture.requests.Load()
	fixture.start()
	if count := liveRuleCount(); count != 3 {
		t.Fatalf("the restarted tunnel loaded %d rules; the cache's product should be served", count)
	}
	time.Sleep(200 * time.Millisecond)
	if fixture.requests.Load() != requests {
		t.Fatalf("a restart within the interval asked the server again")
	}
	_, restarted := liveProduct(t, fixture, fixture.service)
	if after, err := os.Stat(restarted); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a restart rebuilt a product the cache already holds (%v)", err)
	}
}

func TestANewerSeedWinsAndAnOlderOneDoesNot(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "a.example\n", served: "a.example\nb.example\n", fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	fixture.waitFor("the refresh", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.options.published, fixture.options.fetchedAgo = "older.example\n", 3*time.Hour
	fixture.finalize()
	fixture.start()
	if count := liveRuleCount(); count != 2 {
		t.Fatalf("an older seed went back on the tunnel's later copy: %d rules", count)
	}
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.options.published, fixture.options.fetchedAgo = "x.example\ny.example\nz.example\nw.example\n", -5*time.Second
	fixture.options.interval = 7200
	fixture.finalize()
	fixture.start()
	if count := liveRuleCount(); count != 4 {
		t.Fatalf("a newer seed did not win: %d rules", count)
	}
}

func TestAnUnchangedSetIsNotParsedAndAnETagIsAskedWith(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "", served: "same.example\n", interval: 1})
	fixture.mu.Lock()
	fixture.etag = `"v1"`
	fixture.mu.Unlock()
	fixture.start()
	fixture.waitFor("the first load", func() bool { return liveRuleCount() == 1 })
	fixture.waitFor("a 304", func() bool { return fixture.notMod.Load() > 0 })
	entry := fixture.waitForResult(providerRefreshUnchanged)
	if entry.LastCheckedAt == 0 || entry.LastChangedAt == 0 || entry.LastCheckedAt < entry.LastChangedAt {
		t.Fatalf("a 304 is a confirmation: %+v", entry)
	}
}

func TestAFailedDownloadKeepsTheRulesAndBacksOffAsUpstream(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "kept.example\n", served: "", fetchedAgo: 2 * time.Hour})
	fixture.serve(http.StatusInternalServerError, "nope")
	fixture.start()
	entry := fixture.waitForResult(providerRefreshFailed)
	if !strings.Contains(entry.Error, "500") {
		t.Fatalf("the error is the server's answer, as it came: %q", entry.Error)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("a failed refresh must leave the running set alone: %d rules", count)
	}
	if wait := entry.NextDueAt - time.Now().Unix(); wait > 1 {
		t.Fatalf("the first retry is at twice the minimum backoff, not %d s away", wait)
	}
	fixture.serve(http.StatusOK, "kept.example\nadded.example\n")
	fixture.waitFor("the retry to land", func() bool { return liveRuleCount() == 2 })
}

func TestAPayloadThatDoesNotFitWaitsForTheApp(t *testing.T) {
	withBuildMemory(t, 1<<20)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\nmore.example\n", compile: true, fetchedAgo: 2 * time.Hour})
	fixture.start()
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.PendingReason != providerRefreshPendingMemory {
		t.Fatalf("pending for %q, want memory", entry.PendingReason)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("a refused build must leave the running set alone: %d rules", count)
	}
}

func TestTheTunnelDoesNotBuildAPayloadItDiedBuilding(t *testing.T) {
	served := "new.example\nmore.example\n"
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "old.example\n", served: served, fetchedAgo: 2 * time.Hour})
	raw, _ := config.UnmarshalRawConfig([]byte(fixture.finalized))
	spec, _ := decodeProviderRefreshMarker(raw.RuleProvider["refreshed"][providerRefreshField])
	providerCache.useHome(fixture.home)
	providerCache.writeInflightFor(os.Getpid()+1, spec.requestKey("rule"), payloadSHA256([]byte(served)))
	fixture.start()
	fixture.waitFor("the refresher's check", func() bool { return fixture.requests.Load() > 0 })
	time.Sleep(200 * time.Millisecond)
	pending := fixture.waitForResult(providerRefreshPendingApp)
	if pending.PendingReason != providerRefreshPendingKilled {
		t.Fatalf("pending for %q, want killed", pending.PendingReason)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("the payload the tunnel died on must not be built again: %d rules", count)
	}
	fixture.serve(http.StatusOK, "new.example\nmore.example\nthird.example\n")
	if _, err := fixture.service.refreshNow("rule", "refreshed"); err != nil {
		t.Fatal(err)
	}
	fixture.waitFor("a different payload to go live", func() bool { return liveRuleCount() == 3 })
}

func TestANodeSetRefreshesAndRecordsItsSubscriptionUsage(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy",
		published: "proxies:\n  - {name: A, type: direct}\n",
		served:    "proxies:\n  - {name: A, type: direct}\n  - {name: B, type: direct, interface-name: en0}\n", fetchedAgo: 2 * time.Hour})
	fixture.mu.Lock()
	fixture.userinfo = "upload=1; download=2; total=3; expire=1900000000"
	fixture.mu.Unlock()
	fixture.start()
	fixture.waitFor("the node set to refresh", func() bool { return liveProxyCount() == 2 })
	entry := fixture.waitForResult(providerRefreshUpdated)
	if entry.SubscriptionInfo != "upload=1; download=2; total=3; expire=1900000000" {
		t.Fatalf("the usage the answer carried is not recorded: %+v", entry)
	}
	payload, _ := json.Marshal(tunnel.Providers()["refreshed"])
	if !strings.Contains(string(payload), `"subscriptionInfo"`) {
		t.Fatalf("the running provider does not report the usage: %s", payload)
	}
}

func TestAnIndexedClassicalSetRefreshesAndTheNextStartServesTheNewIndex(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "classical",
		published: "DOMAIN-SUFFIX,old.example\nIP-CIDR,192.0.2.0/24\n",
		served:    "DOMAIN-SUFFIX,new.example\nDOMAIN,exact.example\nIP-CIDR,198.51.100.0/24\n", compile: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "indexed" {
		t.Fatalf("a classical set with names should run indexed: %q", product.Variant)
	}
	fixture.waitFor("the new index to go live", func() bool { return liveRuleCount() == 3 })
	fixture.waitForResult(providerRefreshUpdated)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.start()
	if count := liveRuleCount(); count != 3 {
		t.Fatalf("the restarted tunnel loaded %d rules; the cache's index should be served", count)
	}
}

func TestARouteSetWaitsForTheApp(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr",
		published: "192.0.2.0/24\n", served: "198.51.100.0/24\n203.0.113.0/24\n", routes: true, fetchedAgo: 2 * time.Hour})
	fixture.start()
	if entry := fixture.waitForResult(providerRefreshPendingApp); entry.PendingReason != providerRefreshPendingRoutes {
		t.Fatalf("pending for %q, want routes", entry.PendingReason)
	}
}

func TestAProviderWithNoSeedIsLoadedByTheTunnelAndKeptForTheNextStart(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "", served: "one.example\ntwo.example\n"})
	service := fixture.start()
	fixture.waitFor("the first load", func() bool { return liveRuleCount() == 2 })
	fixture.waitForResult(providerRefreshUpdated)
	_, product := liveProduct(t, fixture, service)
	before, err := os.Stat(product)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	requests := fixture.requests.Load()
	fixture.start()
	if count := liveRuleCount(); count != 2 {
		t.Fatalf("the restarted tunnel loaded %d rules; the first load is in the cache", count)
	}
	_, served := liveProduct(t, fixture, fixture.service)
	if after, err := os.Stat(served); err != nil || served != product || !os.SameFile(before, after) {
		t.Fatalf("the restart rebuilt the cache's product: %s -> %s (%v)", product, served, err)
	}
	time.Sleep(200 * time.Millisecond)
	if fixture.requests.Load() != requests {
		t.Fatalf("a restart within the interval asked the server again")
	}
}

func TestUpstreamsPreviousDownloadSeedsAProviderWithNoSeed(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "", served: "fresh.example\n"})
	fixture.serve(http.StatusInternalServerError, "down")
	legacy := C.Path.GetPathByHash("rules", fixture.server.URL+"/rules.txt")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("old.example\nolder.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.start()
	if count := liveRuleCount(); count != 2 {
		t.Fatalf("the previous download should carry the provider until the server answers: %d rules", count)
	}
}

func TestTheAppCanUpdateAndSeedAProviderThroughTheTunnel(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	service := fixture.start()
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewAPIClientWithOptions(path, newRecordingClashAPIHandler(), &APIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	fixture.serve(http.StatusOK, "a.example\nb.example\n")
	answer, err := client.UpdateProvider("rule", "refreshed", 10000)
	if err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	var result providerRefreshResult
	if err := json.Unmarshal([]byte(answer), &result); err != nil || result.Result != providerRefreshUpdated || result.CountAfter != 2 {
		t.Fatalf("UpdateProvider answered %s (%v)", answer, err)
	}
	if _, err := client.UpdateProvider("rule", "nope", 1000); err == nil || !strings.HasPrefix(err.Error(), ProviderUpdateUnavailablePrefix) {
		t.Fatalf("an unknown provider is unavailable, which the App acts on: %v", err)
	}

	seed := func(fetchedAt int64, body string) providerRefreshResult {
		description, _ := json.Marshal(map[string]any{"fetchedAt": fetchedAt, "sourceSHA256": payloadSHA256([]byte(body)), "payload": "source"})
		answer, err := client.SeedProvider("rule", "refreshed", []byte(body), string(description), service.runningConfigurationSHA256())
		if err != nil {
			t.Fatalf("SeedProvider: %v", err)
		}
		var result providerRefreshResult
		_ = json.Unmarshal([]byte(answer), &result)
		return result
	}
	if result := seed(time.Now().Add(-time.Hour).Unix(), "x.example\n"); result.Result != providerRefreshUnchanged || liveRuleCount() != 2 {
		t.Fatalf("a seed older than the tunnel's copy must not be taken: %+v", result)
	}
	if result := seed(time.Now().Add(time.Second).Unix(), "x.example\ny.example\nz.example\n"); result.Result != providerRefreshUpdated || liveRuleCount() != 3 {
		t.Fatalf("a newer seed must be taken: %+v", result)
	}
	if err := service.sideUpdateProvider("rule", "refreshed", []byte("q.example\n"), ""); err == nil || !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatalf("a side update of a provider the tunnel refreshes is deferred: %v", err)
	}
}

func TestTheStateNamesTheRunningConfigurationsProviders(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	service := fixture.start()
	state, entry := fixture.state()
	if state == nil || entry == nil || state.Running.ConfigSHA256 != service.runningConfigurationSHA256() {
		t.Fatalf("the running table is not on record when Start returns: %+v", state)
	}
	if entry.Kind != "rule" || entry.URL != fixture.server.URL+"/rules.txt" || entry.Interval != 86400 || entry.SourceSHA256 != payloadSHA256([]byte("a.example\n")) {
		t.Fatalf("state entry: %+v", entry)
	}
}

func TestFinalizeHandsEveryHTTPProviderToTheTunnelWithWhatTheAppKnows(t *testing.T) {
	document := `
rule-providers:
  seeded: {type: HTTP, behavior: domain, url: https://rules.example/a.txt, interval: "86400", header: {Authorization: [Bearer t]}}
  unseeded: {type: http, behavior: domain, url: https://rules.example/b.txt, path: ./custom/b.txt}
  never: {type: http, behavior: domain, url: "file:///etc/passwd"}
proxy-providers:
  nodes: {type: http, url: https://nodes.example/sub, interval: 3600, age-secret-key: AGE-SECRET-KEY-1EXAMPLE}
rules:
  - MATCH,DIRECT
`
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":            map[string]string{"rule:seeded": "/published/a.txt", "proxy:nodes": "/published/n.yaml"},
		"providerFetchedAt":        map[string]int64{"rule:seeded": 1760000000},
		"providerETags":            map[string]string{"rule:seeded": `W/"a"`},
		"providerSubscriptionInfo": map[string]string{"proxy:nodes": "upload=1; download=2; total=3"},
	})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized.Value), &root); err != nil {
		t.Fatal(err)
	}
	rules := root["rule-providers"].(map[string]any)
	seeded := rules["seeded"].(map[string]any)
	spec, ok := decodeProviderRefreshMarker(seeded[providerRefreshField])
	if seeded["type"] != "file" || !ok || spec.Interval != 24*time.Hour || spec.FetchedAt.Unix() != 1760000000 || spec.ETag != `W/"a"` || spec.Header.Get("Authorization") != "Bearer t" {
		t.Fatalf("seeded: %+v / %+v", seeded, spec)
	}
	unseeded := rules["unseeded"].(map[string]any)
	spec, ok = decodeProviderRefreshMarker(unseeded[providerRefreshField])
	if unseeded["type"] != "file" || unseeded["path"] != unseededProviderPath("rule", "unseeded") || !ok || spec.LegacyPath != "./custom/b.txt" || spec.Interval != 0 {
		t.Fatalf("unseeded: %+v / %+v", unseeded, spec)
	}
	if never := rules["never"].(map[string]any); never["type"] != "http" || never[providerRefreshField] != nil {
		t.Fatalf("a url this build cannot use stays as written: %+v", never)
	}
	nodes := root["proxy-providers"].(map[string]any)["nodes"].(map[string]any)
	spec, ok = decodeProviderRefreshMarker(nodes[providerRefreshField])
	if !ok || spec.AgeKey != "AGE-SECRET-KEY-1EXAMPLE" || spec.SubscriptionInfo != "upload=1; download=2; total=3" {
		t.Fatalf("nodes: %+v", spec)
	}
}

func TestTheCacheForgetsWhatNoConfigurationNamesForAMonth(t *testing.T) {
	setup := testOptions(t)
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	providerCache.useHome(setup.WorkingPath)
	old := time.Now().Add(-31 * 24 * time.Hour).Unix()
	for _, key := range []string{"stale", "running", "recent"} {
		if err := os.MkdirAll(providerCache.requestDirectory(key), 0o700); err != nil {
			t.Fatal(err)
		}
		referenced := old
		if key == "recent" {
			referenced = time.Now().Unix()
		}
		providerCache.update(key, func(entry *providerCacheEntry) { entry.LastReferencedAt = referenced })
	}
	providerCache.prune(map[string]bool{"running": true})
	for key, want := range map[string]bool{"stale": false, "running": true, "recent": true} {
		_, err := os.Stat(providerCache.requestDirectory(key))
		if kept := err == nil && providerCache.get(key) != nil; kept != want {
			t.Fatalf("%s kept=%v, want %v", key, kept, want)
		}
	}
}

func (s *BoxService) refreshNow(kind, name string) (providerRefreshResult, error) {
	s.mu.Lock()
	refresher := s.refresher
	s.mu.Unlock()
	if refresher == nil {
		return providerRefreshResult{}, fmt.Errorf("no refresher")
	}
	reply := make(chan providerRefreshResult, 1)
	refresher.requests <- providerRefreshRequest{kind: kind, name: name, reply: reply}
	return <-reply, nil
}

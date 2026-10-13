package clash

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestTheTunnelLeavesAMappedSetsContentForTheAppWhichCompilesAndSeedsIt(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\n+.newer.example\nthird.example\n", compile: true, mapped: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "mapped" {
		t.Fatalf("the published set should run mapped: %q", product.Variant)
	}
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.PendingReason != providerRefreshPendingRecompile || entry.PendingSHA256 == "" || !regularFileExists(providerCache.pendingPath(service.providerRuntime.refresh.targets[0].requestKey)) {
		t.Fatalf("the new content does not wait for the App: %+v", entry)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("the tunnel changed the set it runs: %d rules", count)
	}

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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var results []pendingCompileResult
	if err := json.Unmarshal([]byte(answer), &results); err != nil || len(results) != 1 || results[0].Name != "refreshed" ||
		results[0].Result != providerRefreshUpdated || results[0].CountAfter != 3 {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	if count := liveRuleCount(); count != 3 {
		t.Fatalf("the seeded set does not run: %d rules", count)
	}
	live := tunnel.RuleProviders()["refreshed"]
	for host, want := range map[string]bool{"a.newer.example": true, "third.example": true, "old.example": false} {
		if got := live.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}); got != want {
			t.Fatalf("%s: matched %v", host, got)
		}
	}
	if _, after := fixture.state(); after.PendingSHA256 != "" || after.PendingReason != "" {
		t.Fatalf("the content no longer waits: %+v", after)
	}
	if product, _ := liveProduct(t, fixture, service); product.Variant != "mapped" || product.Count != 3 {
		t.Fatalf("the product on record: %+v", product)
	}
	if answer, _ := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel); answer != "[]" {
		t.Fatalf("a second call compiled %s", answer)
	}
	if _, err := client.CompilePendingProviders(fixture.finalized+"\n# another\n", RuntimeProfileIOSPacketTunnel); err == nil || !strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("another configuration was compiled for the tunnel: %v", err)
	}
}

func TestTheTunnelLeavesAClassicalSetsContentForTheAppWhichIndexesAndSeedsIt(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "classical",
		published: "DOMAIN-SUFFIX,old.example\nIP-CIDR,10.0.0.0/8\n",
		served:    "DOMAIN-SUFFIX,new.example\nDOMAIN,exact.example\nIP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR,198.51.100.0/24,no-resolve\n",
		compile:   true, mapped: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "indexed" {
		t.Fatalf("the published set should run indexed: %q", product.Variant)
	}
	entry := fixture.waitForResult(providerRefreshPendingApp)
	if entry.PendingReason != providerRefreshPendingRecompile || liveRuleCount() != 2 {
		t.Fatalf("the new content does not wait for the App: %+v, %d rules", entry, liveRuleCount())
	}
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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var results []pendingCompileResult
	if err := json.Unmarshal([]byte(answer), &results); err != nil || len(results) != 1 || results[0].Result != providerRefreshUpdated || results[0].CountAfter != 4 {
		t.Fatalf("the App's index answered %s (%v)", answer, err)
	}
	live := tunnel.RuleProviders()["refreshed"]
	for _, probe := range []struct {
		meta C.Metadata
		want bool
	}{
		{C.Metadata{Host: "a.new.example"}, true},
		{C.Metadata{Host: "exact.example"}, true},
		{C.Metadata{Host: "a.old.example"}, false},
		{C.Metadata{DstIP: netip.MustParseAddr("198.51.100.7")}, true},
		{C.Metadata{DstIP: netip.MustParseAddr("10.1.1.1")}, false},
	} {
		meta := probe.meta
		if got := live.Match(&meta, C.RuleMatchHelper{}); got != probe.want {
			t.Fatalf("%+v: matched %v", probe.meta, got)
		}
	}
	if _, after := fixture.state(); after.PendingSHA256 != "" {
		t.Fatalf("the content still waits: %+v", after)
	}
}

func TestAMillionLineSetGoesThroughTheAppToTheTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("a million lines")
	}
	var b strings.Builder
	for i := 0; i < 1000000; i++ {
		fmt.Fprintf(&b, "d%07d.example\n", i)
	}
	served := b.String()
	if len(served) <= maximumProviderResourceBytes {
		t.Fatalf("the fixture is %d bytes, not past the tunnel's ceiling", len(served))
	}
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: served, compile: true, mapped: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "mapped" {
		t.Fatalf("the published set should run mapped: %q", product.Variant)
	}
	if entry := fixture.waitForResult(providerRefreshPendingApp); entry.PendingSHA256 == "" {
		t.Fatalf("the download does not wait for the App: %+v", entry)
	}
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
	asAppProcess(t)
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var results []pendingCompileResult
	if err := json.Unmarshal([]byte(answer), &results); err != nil || len(results) != 1 || results[0].Result != providerRefreshUpdated || results[0].CountAfter != 1000000 {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	live := tunnel.RuleProviders()["refreshed"]
	if !live.Match(&C.Metadata{Host: "d0999999.example"}, C.RuleMatchHelper{}) || live.Match(&C.Metadata{Host: "old.example"}, C.RuleMatchHelper{}) {
		t.Fatal("the mapped million-line set does not answer")
	}
}

func subscriptionPayload(prefix string, n int) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - {name: \"%s %d\", type: ss, server: %s%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", prefix, i, strings.ToLower(prefix), i)
	}
	return b.String()
}

func TestTheTunnelLeavesASubscriptionsContentForTheAppWhichWritesItsLibrary(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy",
		published: subscriptionPayload("Old", 3), served: subscriptionPayload("New", 7), compile: true, mapped: true, fetchedAgo: 2 * time.Hour})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "library" {
		t.Fatalf("the published subscription should run from a library: %q", product.Variant)
	}
	if count := liveProxyCount(); count != 3 {
		t.Fatalf("%d nodes from the library", count)
	}
	if list := tunnel.Providers()["refreshed"].ProxyList(); !adapter.IsLibraryNode(list.At(0)) {
		t.Fatalf("the subscription's nodes are not the library's slots (%T)", list.At(0))
	}
	if entry := fixture.waitForResult(providerRefreshPendingApp); entry.PendingReason != providerRefreshPendingRecompile {
		t.Fatalf("the new content does not wait for the App: %+v", entry)
	}
	if count := liveProxyCount(); count != 3 {
		t.Fatalf("the tunnel changed the nodes it runs: %d", count)
	}
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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var results []pendingCompileResult
	if err := json.Unmarshal([]byte(answer), &results); err != nil || len(results) != 1 || results[0].Kind != "proxy" ||
		results[0].Result != providerRefreshUpdated || results[0].CountAfter != 7 {
		t.Fatalf("the App's library answered %s (%v)", answer, err)
	}
	list := tunnel.Providers()["refreshed"].ProxyList()
	if list.Len() != 7 || list.At(6).Name() != "New 6" || !adapter.IsLibraryNode(list.At(6)) {
		t.Fatalf("the seeded library does not run: %d nodes", list.Len())
	}
}

func TestTheTelevisionsAppCompilesTheWaitingSetToAFileTheExtensionSeedsFrom(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule",
		published: "old.example\n", served: "new.example\n+.newer.example\nthird.example\n", compile: true, mapped: true, fetchedAgo: 2 * time.Hour})
	fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	parent := filepath.Join(C.Path.HomeDir(), ProviderRefreshDirectoryName, pendingSeedDirectoryName)
	stale, recent := filepath.Join(parent, "old", "rule-0.seed"), filepath.Join(parent, "recent", "rule-0.seed")
	for _, path := range []string{stale, recent} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("left"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(filepath.Dir(stale), old, old)

	answer, err := PreparePendingProviderSeeds(fixture.finalized, RuntimeProfileTVOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var entries []pendingSeedFile
	if err := json.Unmarshal([]byte(answer), &entries); err != nil || len(entries) != 1 || entries[0].Name != "refreshed" || entries[0].PayloadPath == "" || entries[0].Error != "" {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	if regularFileExists(stale) || !regularFileExists(recent) {
		t.Fatal("an old call's files stayed, or a recent call's went: a hand-off may still read them")
	}
	if filepath.Dir(filepath.Dir(entries[0].PayloadPath)) != parent {
		t.Fatalf("the seed is not in a directory of its own call: %s", entries[0].PayloadPath)
	}
	if count := liveRuleCount(); count != 1 {
		t.Fatalf("preparing seeded the tunnel: %d rules", count)
	}
	e := entries[0]
	var reply providerRefreshResult
	if err := json.Unmarshal([]byte(SeedProviderFileJSON(e.Kind, e.Name, e.PayloadPath, e.Seed, e.ExpectedConfigSHA256, 0)), &reply); err != nil || reply.Result != providerRefreshUpdated || reply.CountAfter != 3 {
		t.Fatalf("the extension's seed answered %+v (%v)", reply, err)
	}
	if count := liveRuleCount(); count != 3 {
		t.Fatalf("the seeded set does not run: %d rules", count)
	}
	if answer, _ := PreparePendingProviderSeeds(fixture.finalized, RuntimeProfileTVOSPacketTunnel); answer != "[]" {
		t.Fatalf("a second call compiled %s", answer)
	}
}

func TestASetThePublishBroughtNothingOfWaitsForTheAppToMapIt(t *testing.T) {
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	for _, c := range []struct {
		kind, behavior, format, served, variant string
		count                                   int
	}{
		{"rule", "domain", "text", "a.example\n+.b.example\nc.example\n", "mapped", 3},
		{"rule", "ipcidr", "text", "10.0.0.0/8\n192.168.1.0/24\n", "mapped", 2},
		{"rule", "domain", "yaml", "payload:\n  - a.example\n  - '+.b.example'\n", "mapped", 2},
		{"rule", "classical", "text", "DOMAIN,a.example\nIP-CIDR,10.0.0.0/8,no-resolve\nDOMAIN-KEYWORD,kw\n", "indexed", 3},
		{"proxy", "", "", subscriptionPayload("n", 4), "library", 0},
	} {
		t.Run(c.kind+"-"+c.behavior+"-"+c.format, func(t *testing.T) {
			fixture := newRefreshFixture(t, refreshFixtureOptions{kind: c.kind, behavior: c.behavior, format: c.format, published: "", served: padding + c.served, mapped: true})
			service := fixture.start()
			entry := fixture.waitForResult(providerRefreshPendingApp)
			if entry.PendingReason != providerRefreshPendingRecompile || entry.PendingSHA256 == "" {
				t.Fatalf("the content does not wait for the App: %+v", entry)
			}
			if state := readProviderCacheState(C.Path.HomeDir()); state == nil || state.Running.Variants[c.kind+":refreshed"] != c.variant {
				t.Fatalf("the running form on record: %+v", state)
			}
			if c.kind == "rule" && liveRuleCount() != 0 {
				t.Fatalf("the tunnel built the set: %d rules", liveRuleCount())
			}
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
			answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
			var results []pendingCompileResult
			if err != nil || json.Unmarshal([]byte(answer), &results) != nil || len(results) != 1 || results[0].Result != providerRefreshUpdated {
				t.Fatalf("the App's compile answered %s (%v)", answer, err)
			}
			if product, _ := liveProduct(t, fixture, service); product.Variant != c.variant {
				t.Fatalf("the product on record: %+v", product)
			}
			if c.kind == "rule" {
				if count := liveRuleCount(); count != c.count {
					t.Fatalf("the seeded set does not run: %d rules", count)
				}
				return
			}
			if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 4 {
				t.Fatalf("the subscription's nodes do not run: %v", ok)
			}
		})
	}
}

func TestASubscriptionNoLibraryHoldsIsBuiltByTheTunnelWhenTheAppSendsIt(t *testing.T) {
	if testMeshNodes == 0 {
		t.Skip("no mesh node in this build")
	}
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	served := padding + subscriptionPayload("n", 3) + testMeshNode
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: "", served: served, mapped: true})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	var results []pendingCompileResult
	if err != nil || json.Unmarshal([]byte(answer), &results) != nil || len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	if product, _ := liveProduct(t, fixture, service); product.Variant != "proxy" {
		t.Fatalf("the product on record: %+v", product)
	}
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 4 {
		t.Fatalf("the subscription's nodes do not run: %v", ok)
	}
}

func TestTheAppPublishesAMillionLineSetTheTunnelRunsMapped(t *testing.T) {
	if testing.Short() {
		t.Skip("a million lines")
	}
	for _, c := range []struct {
		behavior, variant, hit, miss string
		line                         func(i int) string
	}{
		{"domain", "mapped", "d0999999.example", "old.example", func(i int) string { return fmt.Sprintf("d%07d.example", i) }},
		{"classical", "indexed", "c0999999.example", "d1.example", func(i int) string {
			if i%2 == 1 {
				return fmt.Sprintf("DOMAIN-SUFFIX,c%07d.example", i)
			}
			return fmt.Sprintf("IP-CIDR,11.%d.%d.%d/32,no-resolve", (i>>16)&255, (i>>8)&255, i&255)
		}},
	} {
		t.Run(c.behavior, func(t *testing.T) {
			var b strings.Builder
			for i := 0; i < 1000000; i++ {
				b.WriteString(c.line(i))
				b.WriteByte('\n')
			}
			if b.Len() <= maximumProviderResourceBytes {
				t.Fatalf("the fixture is %d bytes, not past the tunnel's ceiling", b.Len())
			}
			asAppProcess(t)
			fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: c.behavior,
				published: b.String(), served: b.String(), compile: true, mapped: true, fetchedAgo: time.Minute, interval: 86400})
			service := fixture.start()
			if product, _ := liveProduct(t, fixture, service); product.Variant != c.variant {
				t.Fatalf("the published set runs %q", product.Variant)
			}
			if count := liveRuleCount(); count != 1000000 {
				t.Fatalf("the set holds %d rules", count)
			}
			live := tunnel.RuleProviders()["refreshed"]
			if !live.Match(&C.Metadata{Host: c.hit}, C.RuleMatchHelper{}) || live.Match(&C.Metadata{Host: c.miss}, C.RuleMatchHelper{}) {
				t.Fatal("the set does not answer")
			}
		})
	}
}

func TestAClassicalSetOfIPRangesAloneIsIndexed(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, "IP-CIDR,10.%d.%d.0/24,no-resolve\n", (i>>8)&255, i&255)
	}
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "classical",
		published: b.String(), served: b.String(), compile: true, mapped: true, fetchedAgo: time.Minute, interval: 86400})
	service := fixture.start()
	if product, _ := liveProduct(t, fixture, service); product.Variant != "indexed" {
		t.Fatalf("the set runs %q", product.Variant)
	}
	if count := liveRuleCount(); count != 3000 {
		t.Fatalf("the set holds %d rules", count)
	}
	live := tunnel.RuleProviders()["refreshed"]
	if !live.Match(&C.Metadata{DstIP: netip.MustParseAddr("10.11.183.9")}, C.RuleMatchHelper{}) || live.Match(&C.Metadata{DstIP: netip.MustParseAddr("10.200.0.1")}, C.RuleMatchHelper{}) {
		t.Fatal("the indexed ranges do not answer")
	}
}

func TestTwoSubscriptionsOfOneURLKeepTheirOwnSelections(t *testing.T) {
	payload := "proxies:\n"
	for _, name := range []string{"US 1", "US 2", "JP 1", "JP 2", "JP 3"} {
		payload += fmt.Sprintf("  - {name: %q, type: socks5, server: s.example.net, port: 1080}\n", name)
	}
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: "", served: payload, mapped: true, interval: 86400})
	seed := filepath.Join(fixture.home, "store", "seed-shared")
	if err := os.MkdirAll(filepath.Dir(seed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seed, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`mode: rule
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  us:
    type: http
    url: %[1]s/nodes
    interval: 86400
    filter: "US"
  jp:
    type: http
    url: %[1]s/nodes
    interval: 86400
    filter: "JP"
proxy-groups:
  - {name: G, type: select, use: [us, jp]}
rules:
  - MATCH,DIRECT
`, fixture.server.URL)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"proxy:us": seed, "proxy:jp": seed},
		"providerFetchedAt": map[string]int64{"proxy:us": time.Now().Add(-time.Minute).Unix(), "proxy:jp": time.Now().Add(-time.Minute).Unix()},
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
	fixture.start()
	names := func(provider string) string {
		list := tunnel.Providers()[provider].ProxyList()
		var out []string
		for i := 0; i < list.Len(); i++ {
			out = append(out, list.At(i).Name())
		}
		return strings.Join(out, ",")
	}
	if us, jp := names("us"), names("jp"); us != "US 1,US 2" || jp != "JP 1,JP 2,JP 3" {
		t.Fatalf("us runs %q, jp runs %q", us, jp)
	}

	updated := strings.ReplaceAll(payload, "JP 3", "US 3")
	fixture.serve(http.StatusOK, updated)
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
	if answer, err := client.UpdateProvider("proxy", "us", 10000); err != nil || !strings.Contains(answer, providerRefreshPendingApp) {
		t.Fatalf("the update answered %s (%v)", answer, err)
	}
	state := readProviderCacheState(fixture.home)
	requestKey := state.Running.Providers["proxy:us"]
	raw, _ = config.UnmarshalRawConfig([]byte(fixture.finalized))
	canonicalizeProviderDefinitionKeys(raw)
	seedJSON, set, err := compilePendingSubscription(fixture.home, requestKey, "us", state.Entries[requestKey], raw.ProxyProvider["us"])
	if err != nil {
		t.Fatal(err)
	}
	if answer, err := client.SeedProvider("proxy", "us", set, seedJSON, state.Running.ConfigSHA256); err != nil || !strings.Contains(answer, providerRefreshUpdated) {
		t.Fatalf("seeding one form answered %s (%v)", answer, err)
	}
	_ = fixture.service.Close()
	fixture.start()
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	if us, jp := names("us"), names("jp"); us != "US 1,US 2,US 3" || jp != "JP 1,JP 2,JP 3" {
		t.Fatalf("after a restart between the forms us runs %q, jp runs %q", us, jp)
	}
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	var results []pendingCompileResult
	if err != nil || json.Unmarshal([]byte(answer), &results) != nil || len(results) != 1 || results[0].Name != "jp" || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile of the other form answered %s (%v)", answer, err)
	}
	if us, jp := names("us"), names("jp"); us != "US 1,US 2,US 3" || jp != "JP 1,JP 2" {
		t.Fatalf("after the update us runs %q, jp runs %q", us, jp)
	}
	catalog, err := OpenNodeCatalogForIOS(document, string(resources), "{}")
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	for provider, want := range map[string]string{"us": "US 1,US 2,US 3", "jp": "JP 1,JP 2"} {
		var page struct{ Proxies []struct{ Name string } }
		_ = json.Unmarshal([]byte(catalog.ProviderNodesJSON(provider, 0, 0)), &page)
		var got []string
		for _, node := range page.Proxies {
			got = append(got, node.Name)
		}
		if strings.Join(got, ",") != want {
			t.Fatalf("the catalog shows %s as %q, the tunnel runs %q", provider, strings.Join(got, ","), want)
		}
	}
	state = readProviderCacheState(fixture.home)
	entry := state.Entries[state.Running.Providers["proxy:us"]]
	if entry.PendingSHA256 != "" || len(entry.Products) != 2 {
		t.Fatalf("the record after both forms: pending %q, %d products", entry.PendingSHA256, len(entry.Products))
	}
	if again, _ := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel); again != "[]" {
		t.Fatalf("a second compile answered %s", again)
	}
}

func TestAnEncryptedSubscriptionsUpdateIsCompiledByTheApp(t *testing.T) {
	secret, public, _ := age.GenX25519KeyPair()
	cipher, _ := age.EncryptBytes([]byte(subscriptionPayload("New", 3)), public)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: "", served: string(cipher), mapped: true, interval: 86400})
	seed := filepath.Join(fixture.home, "store", "seed-plain")
	_ = os.MkdirAll(filepath.Dir(seed), 0o700)
	if err := os.WriteFile(seed, []byte(subscriptionPayload("Old", 2)), 0o600); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf("mode: rule\ndns:\n  enable: true\n  nameserver: [8.8.8.8]\nproxy-providers:\n  refreshed:\n    type: http\n    url: %s/nodes\n    interval: 86400\n    age-secret-key: %s\nproxy-groups:\n  - {name: G, type: select, use: [refreshed]}\nrules:\n  - MATCH,DIRECT\n", fixture.server.URL, secret)
	resources, _ := json.Marshal(map[string]any{
		"providerPaths":     map[string]string{"proxy:refreshed": seed},
		"providerFetchedAt": map[string]int64{"proxy:refreshed": time.Now().Add(-2 * time.Hour).Unix()},
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
	fixture.start()
	if live := tunnel.Providers()["refreshed"]; live.Count() != 2 {
		t.Fatalf("the published subscription holds %d nodes", live.Count())
	}
	fixture.waitForResult(providerRefreshPendingApp)
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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	var results []pendingCompileResult
	if err != nil || json.Unmarshal([]byte(answer), &results) != nil || len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	list := tunnel.Providers()["refreshed"].ProxyList()
	if list.Len() != 3 || list.At(0).Name() != "New 0" {
		t.Fatalf("the subscription runs %d nodes", list.Len())
	}
}

func TestAFormIsSkippedOnlyWhileItsProductsFilesAreThere(t *testing.T) {
	home := t.TempDir()
	definition := map[string]any{"behavior": "domain", "format": "text"}
	product := &providerCacheProduct{Variant: "mapped", Entry: "payload.stub", Files: []string{"payload.stub", "set.mapped"}, SourceSHA256: "new", Generation: "g1", SourceForm: catalogForm("domain", "text")}
	entry := &providerCacheEntry{Kind: "rule", PendingSHA256: "new", Products: map[string]*providerCacheProduct{"p1": product}}
	directory := providerProductDirectory(home, "r1", "p1", "g1")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range product.Files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !runsWaitingContent(home, "r1", entry, "rule", "set", definition) {
		t.Fatal("a form running the waiting content, its files there, was not skipped")
	}
	if err := os.Remove(filepath.Join(directory, "set.mapped")); err != nil {
		t.Fatal(err)
	}
	if runsWaitingContent(home, "r1", entry, "rule", "set", definition) {
		t.Fatal("a form whose product's files are gone was skipped")
	}
}

func TestAnUnlabelledProductIsTakenOnlyWhenItSelectsNothing(t *testing.T) {
	home := t.TempDir()
	form := catalogForm("", "")
	product := func(key, variant, selection string) *providerCacheProduct {
		p := &providerCacheProduct{Variant: variant, Entry: "payload", Files: []string{"payload"}, SourceSHA256: "s", Generation: "g", SourceForm: form, Selection: selection}
		directory := providerProductDirectory(home, "r", key, "g")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "payload"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	entry := func(products map[string]*providerCacheProduct) *providerCacheEntry {
		return &providerCacheEntry{Kind: "proxy", SourceSHA256: "s", Products: products}
	}
	if got, _ := cachedProviderProduct(home, "r", entry(map[string]*providerCacheProduct{"lib": product("lib", "library", "")}), form, "us"); got != nil {
		t.Fatalf("an unlabelled library was taken for us: %+v", got)
	}
	set := entry(map[string]*providerCacheProduct{"a-set": product("a-set", "proxy", "")})
	for _, name := range []string{"us", "jp"} {
		if got, _ := cachedProviderProduct(home, "r", set, form, name); got == nil || got.Variant != "proxy" {
			t.Fatalf("the unlabelled node set was not taken for %s: %+v", name, got)
		}
	}
	both := entry(map[string]*providerCacheProduct{"a-set": product("a-set", "proxy", ""), "jp": product("jp", "library", "jp")})
	if got, _ := cachedProviderProduct(home, "r", both, form, "jp"); got == nil || got.Selection != "jp" {
		t.Fatalf("jp's own library: %+v", got)
	}
	if got, _ := cachedProviderProduct(home, "r", both, form, "us"); got == nil || got.Variant != "proxy" {
		t.Fatalf("us beside jp's library: %+v", got)
	}
}

func largeDomainText(prefix string) (string, int) {
	var large strings.Builder
	for i := 0; large.Len() <= startTextSeedLimit; i++ {
		fmt.Fprintf(&large, "%s%d.example\n", prefix, i)
	}
	return large.String(), strings.Count(large.String(), "\n")
}

func compilePendingNow(t *testing.T, fixture *refreshFixture) []pendingCompileResult {
	t.Helper()
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
	answer, err := client.CompilePendingProviders(fixture.finalized, RuntimeProfileIOSPacketTunnel)
	var results []pendingCompileResult
	if err != nil || json.Unmarshal([]byte(answer), &results) != nil {
		t.Fatalf("the App's compile answered %s (%v)", answer, err)
	}
	return results
}

func TestALargeSetThePublishBroughtUncompiledWaitsForTheApp(t *testing.T) {
	large, count := largeDomainText("d")
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: large, served: "", mapped: true, fetchedAgo: time.Minute})
	fixture.serve(http.StatusServiceUnavailable, "")
	fixture.start()
	if n := liveRuleCount(); n != 0 {
		t.Fatalf("the tunnel parsed the uncompiled set at start: %d rules", n)
	}
	staged, _ := filepath.Glob(filepath.Join(fixture.home, "*", "*refreshed*"))
	for _, path := range staged {
		if info, err := os.Stat(path); err == nil && info.Size() > startTextSeedLimit {
			t.Fatalf("the staging copied the seed: %s", path)
		}
	}
	_, entry := fixture.state()
	if entry == nil || entry.PendingSHA256 == "" || entry.Result != providerRefreshPendingApp || entry.PendingReason != providerRefreshPendingRecompile {
		t.Fatalf("the seed does not wait for the App: %+v", entry)
	}
	results := compilePendingNow(t, fixture)
	if len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	if n := liveRuleCount(); n != count {
		t.Fatalf("the compiled set runs %d rules, want %d", n, count)
	}
}

func TestANewerUncompiledSeedWaitsBesideTheMappedProduct(t *testing.T) {
	small := "a.example\n+.b.example\nc.example\n"
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: "", served: padding + small, mapped: true, interval: -1})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the first compile: %+v", results)
	}
	if n := liveRuleCount(); n != 3 {
		t.Fatalf("the mapped set runs %d rules", n)
	}
	large, count := largeDomainText("n")
	time.Sleep(2 * time.Second)
	fixture.options.published, fixture.options.fetchedAgo = large, time.Millisecond
	fixture.finalize()
	if err := service.Reload(fixture.finalized); err != nil {
		t.Fatal(err)
	}
	if n := liveRuleCount(); n != 3 {
		t.Fatalf("after the reload the set runs %d rules, want the mapped product's 3", n)
	}
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the newer seed does not wait for the App: %+v", entry)
	}
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the second compile: %+v", results)
	}
	if n := liveRuleCount(); n != count {
		t.Fatalf("the newer set runs %d rules, want %d", n, count)
	}
}

func TestALargeLocalSetTheAppHasNotCompiledStartsEmpty(t *testing.T) {
	setup := testOptions(t)
	setup.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	large, _ := largeDomainText("l")
	if err := os.WriteFile(filepath.Join(setup.WorkingPath, "local.txt"), []byte(large), 0o600); err != nil {
		t.Fatal(err)
	}
	finalized, err := FinalizeForIOS("mode: rule\nrule-providers:\n  local:\n    type: file\n    behavior: domain\n    format: text\n    path: ./local.txt\nrules:\n  - RULE-SET,local,DIRECT\n  - MATCH,DIRECT\n", "{}")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(finalized.Value); err != nil {
		t.Fatal(err)
	}
	if n := liveRuleCountOf("local"); n != 0 {
		t.Fatalf("the local set was parsed at start: %d rules", n)
	}
}

func TestASmallSetThePublishBroughtUncompiledRunsAsItCame(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: "a.example\n+.b.example\nc.example\n", served: "a.example\n+.b.example\nc.example\n", mapped: true, fetchedAgo: time.Minute})
	fixture.start()
	if n := liveRuleCount(); n != 3 {
		t.Fatalf("the small set runs %d rules", n)
	}
}

func TestALargeSubscriptionTheAppHasNotCompiledWaitsForTheApp(t *testing.T) {
	nodes := 1
	for len(subscriptionPayload("n", nodes)) <= startTextSeedLimit {
		nodes *= 2
	}
	payload := subscriptionPayload("n", nodes)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: payload, served: "", mapped: true, fetchedAgo: time.Minute})
	fixture.serve(http.StatusServiceUnavailable, "")
	fixture.start()
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 0 {
		t.Fatalf("the subscription was built at start: %v", ok)
	}
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the seed does not wait for the App: %+v", entry)
	}
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != nodes {
		t.Fatalf("the library's nodes do not run: %v", ok)
	}
}

func TestASeedPastTheReadCeilingWaitsForTheAppAndTheStartGoesOn(t *testing.T) {
	var large strings.Builder
	for i := 0; large.Len() <= maximumProviderResourceBytes+1<<20; i++ {
		fmt.Fprintf(&large, "c%d.example\n", i)
	}
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: large.String(), served: "", mapped: true, fetchedAgo: time.Minute})
	fixture.serve(http.StatusServiceUnavailable, "")
	fixture.start()
	if n := liveRuleCount(); n != 0 {
		t.Fatalf("the set was read at start: %d rules", n)
	}
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the seed does not wait for the App: %+v", entry)
	}
}

func TestACompiledRecordWhoseFileIsGoneDoesNotReadTheSource(t *testing.T) {
	large, count := largeDomainText("g")
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: large, served: "", mapped: true, compile: true, fetchedAgo: time.Minute})
	fixture.serve(http.StatusServiceUnavailable, "")
	compiled, _ := filepath.Glob(filepath.Join(fixture.home, providerRuntimeDirectoryName, "staged", "*"+providerRuntimeMappedDomainSuffix))
	if len(compiled) == 0 {
		t.Fatal("fixture: the App's publish compiled nothing")
	}
	for _, path := range compiled {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	fixture.start()
	if n := liveRuleCount(); n != 0 {
		t.Fatalf("the source was read at start: %d rules", n)
	}
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the seed does not wait for the App: %+v", entry)
	}
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	if n := liveRuleCount(); n != count {
		t.Fatalf("the compiled set runs %d rules, want %d", n, count)
	}
}

func TestAnOlderSeedDoesNotWaitForTheApp(t *testing.T) {
	home := t.TempDir()
	previous := providerCache.homeDirectory()
	providerCache.useHome(home)
	t.Cleanup(func() { providerCache.useHome(previous) })
	seed := filepath.Join(home, "seed")
	if err := os.WriteFile(seed, []byte("older.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	providerCache.update("r", func(cached *providerCacheEntry) {
		cached.Kind, cached.SourceSHA256, cached.LastCheckedAt = "rule", "newer", now
	})
	target := &providerRefreshTarget{kind: "rule", name: "set", requestKey: "r", spec: &providerRefreshSpec{URL: "http://example.invalid/set"}}
	commitSeedForTheApp(target, &providerCacheImport{waitsForApp: true, seedPath: seed, fetchedAt: time.Unix(now-3600, 0)}, now)
	if entry := providerCache.get("r"); entry == nil || entry.PendingSHA256 != "" {
		t.Fatalf("an older seed waits for the App: %+v", entry)
	}
	commitSeedForTheApp(target, &providerCacheImport{waitsForApp: true, seedPath: seed, fetchedAt: time.Unix(now+60, 0)}, now)
	if entry := providerCache.get("r"); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("a newer seed does not wait for the App: %+v", entry)
	}
}

func TestALargeProductNotInTheAppsFormIsNotServed(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, size int) {
		if err := os.WriteFile(filepath.Join(directory, name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("large", startTextSeedLimit+1)
	write("small", 100)
	target := &providerRefreshTarget{kind: "rule", sourceBehavior: "domain", sourceFormat: "text", sideUpdateSafe: true}
	for _, c := range []struct {
		variant, entry string
		want           bool
	}{
		{"text", "large", true},
		{"compiled", "large", true},
		{"mapped", "large", false},
		{"text", "small", false},
	} {
		if got := productParsedTooLarge(target, &providerCacheProduct{Variant: c.variant, Entry: c.entry}, directory); got != c.want {
			t.Fatalf("%s %s: %v", c.variant, c.entry, got)
		}
	}
}

func TestTheRunningTableNamesEachProvidersProductKey(t *testing.T) {
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: "", served: padding + "a.example\n", mapped: true})
	fixture.start()
	entry := fixture.waitForResult(providerRefreshPendingApp)
	state, _ := fixture.state()
	key := state.Running.ProductKeys["rule:refreshed"]
	if key == "" {
		t.Fatalf("no product key on record: %+v", state.Running)
	}
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	_, entry = fixture.state()
	if product := entry.Products[key]; product == nil || product.Variant != "mapped" {
		t.Fatalf("the product under the running key: %+v (products %v)", product, entry.Products)
	}
}

func TestASetOfWhichNothingRunsRunsItsFirstSmallContentAsText(t *testing.T) {
	t.Run("subscription", func(t *testing.T) {
		fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", served: subscriptionPayload("N", 7), mapped: true})
		fixture.start()
		entry := fixture.waitForResult(providerRefreshUpdated)
		if entry.PendingSHA256 != "" {
			t.Fatalf("the content runs and waits too: %+v", entry)
		}
		if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 7 {
			t.Fatalf("the subscription does not run its 7 nodes: %v", ok)
		}
	})
	t.Run("rule set", func(t *testing.T) {
		fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", served: "a.example\n+.b.example\nc.example\n", mapped: true})
		fixture.start()
		fixture.waitForResult(providerRefreshUpdated)
		if n := liveRuleCount(); n != 3 {
			t.Fatalf("the set runs %d rules, want 3", n)
		}
	})
	t.Run("yaml rule set waits", func(t *testing.T) {
		fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr", format: "yaml", served: "payload:\n  - 10.0.0.0/8\n", mapped: true})
		fixture.start()
		fixture.waitForResult(providerRefreshPendingApp)
	})
}

func TestAStopgapRunsUntilTheAppsCompileReplacesIt(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", served: subscriptionPayload("N", 6), mapped: true})
	service := fixture.start()
	fixture.waitForResult(providerRefreshUpdated)
	if state := readProviderCacheState(C.Path.HomeDir()); state == nil || state.Running.Variants["proxy:refreshed"] != "library" {
		t.Fatalf("the form on record for a stopgap: %+v", state)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.serve(http.StatusServiceUnavailable, "")
	service = fixture.start()
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 6 {
		t.Fatalf("after a restart the stopgap does not run its 6 nodes: %v", ok)
	}
	large := subscriptionPayload("L", 1)
	for len(large) <= startTextSeedLimit {
		large = subscriptionPayload("L", 2*strings.Count(large, "name:"))
	}
	nodes := strings.Count(large, "name:")
	fixture.serve(http.StatusOK, large)
	if answer := UpdateProviderJSON("proxy", "refreshed", 15000); !strings.Contains(answer, providerRefreshPendingApp) || !strings.Contains(answer, providerRefreshPendingRecompile) {
		t.Fatalf("content past the limit beside a stopgap: %s", answer)
	}
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 6 {
		t.Fatalf("the stopgap does not run while the content waits: %v", ok)
	}
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != nodes {
		t.Fatalf("the App's library does not run: %v", ok)
	}
	if product, _ := liveProduct(t, fixture, service); product.Variant != "library" || product.Stopgap {
		t.Fatalf("the product on record after the App's compile: %+v", product)
	}
}

func TestASmallPayloadWaitingRunsWhenNothingElseDoesAndTheDownloadFails(t *testing.T) {
	payload := subscriptionPayload("N", 5)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", served: "", mapped: true})
	fixture.serve(http.StatusServiceUnavailable, "")
	var spec *providerRefreshSpec
	raw, err := config.UnmarshalRawConfig([]byte(fixture.finalized))
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range raw.ProxyProvider {
		spec, _ = decodeProviderRefreshMarker(definition[providerRefreshField])
	}
	if spec == nil {
		t.Fatal("the published definition carries no refresh marker")
	}
	providerCache.useHome(fixture.home)
	requestKey := spec.requestKey("proxy")
	if err := os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerCache.pendingPath(requestKey), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	providerCache.update(requestKey, func(entry *providerCacheEntry) {
		entry.Kind, entry.URL = "proxy", spec.URL
		entry.PendingSHA256, entry.PendingWait, entry.PendingCheckedAt = payloadSHA256([]byte(payload)), providerRefreshPendingRecompile, time.Now().Add(-time.Minute).Unix()
		entry.Result, entry.PendingReason = providerRefreshPendingApp, providerRefreshPendingRecompile
	})
	fixture.start()
	fixture.waitFor("the waiting payload to run", func() bool {
		live, ok := tunnel.Providers()["refreshed"]
		return ok && live.Count() == 5
	})
	fixture.waitForEntry("the payload that ran no longer waits", func(entry *providerCacheEntry) bool {
		return entry.PendingSHA256 == "" && entry.Result == providerRefreshUpdated
	})
}

func TestASmallSourceTheCacheKeepsRunsWhenNothingElseDoes(t *testing.T) {
	payload := subscriptionPayload("S", 9)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", served: "", mapped: true})
	fixture.serve(http.StatusServiceUnavailable, "")
	var spec *providerRefreshSpec
	raw, err := config.UnmarshalRawConfig([]byte(fixture.finalized))
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range raw.ProxyProvider {
		spec, _ = decodeProviderRefreshMarker(definition[providerRefreshField])
	}
	if spec == nil {
		t.Fatal("the published definition carries no refresh marker")
	}
	providerCache.useHome(fixture.home)
	requestKey := spec.requestKey("proxy")
	if err := os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerCache.sourcePath(requestKey), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	providerCache.update(requestKey, func(entry *providerCacheEntry) {
		entry.Kind, entry.URL = "proxy", spec.URL
		entry.SourceSHA256, entry.SourceBytes = payloadSHA256([]byte(payload)), int64(len(payload))
		entry.LastCheckedAt, entry.Result = time.Now().Add(-time.Minute).Unix(), providerRefreshUpdated
	})
	fixture.start()
	fixture.waitFor("the cached source to run", func() bool {
		live, ok := tunnel.Providers()["refreshed"]
		return ok && live.Count() == 9
	})
	if requests := fixture.requests.Load(); requests != 0 {
		t.Logf("the server was asked %d times", requests)
	}
	fixture.waitForEntry("the source runs and waits for nothing", func(entry *providerCacheEntry) bool {
		return entry.PendingSHA256 == "" && entry.Result == providerRefreshUpdated
	})
}

func TestWhatTheTunnelBuildsOfASetNoLibraryHoldsIsNoStopgap(t *testing.T) {
	target := &providerRefreshTarget{kind: "proxy", builtHere: true, sideUpdateSafe: true,
		product: &providerCacheProduct{Variant: "proxy", Entry: awaitedEntry, Files: []string{awaitedEntry}, Stopgap: true}}
	if product := (&providerRefresher{}).productFor(target); product.Stopgap || product.Variant != "proxy" {
		t.Fatalf("the product the tunnel builds: %+v", product)
	}
}

func TestAStopgapRunsBesideALargeSeedThatWaits(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", served: "a.example\n+.b.example\nc.example\n", mapped: true, interval: -1})
	service := fixture.start()
	fixture.waitForResult(providerRefreshUpdated)
	if n := liveRuleCount(); n != 3 {
		t.Fatalf("the stopgap runs %d rules", n)
	}
	large, _ := largeDomainText("g")
	time.Sleep(2 * time.Second)
	fixture.options.published, fixture.options.fetchedAgo = large, time.Millisecond
	fixture.finalize()
	if err := service.Reload(fixture.finalized); err != nil {
		t.Fatal(err)
	}
	if n := liveRuleCount(); n != 3 {
		t.Fatalf("beside the large seed the set runs %d rules, want the stopgap's 3", n)
	}
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the large seed does not wait for the App: %+v", entry)
	}
}

func TestALargeSeedBesideACacheWithNoProductStarts(t *testing.T) {
	large, _ := largeDomainText("q")
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "domain", format: "text", published: large, served: "", mapped: true, fetchedAgo: time.Millisecond})
	fixture.serve(http.StatusServiceUnavailable, "")
	var spec *providerRefreshSpec
	raw, err := config.UnmarshalRawConfig([]byte(fixture.finalized))
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range raw.RuleProvider {
		spec, _ = decodeProviderRefreshMarker(definition[providerRefreshField])
	}
	if spec == nil {
		t.Fatal("the published definition carries no refresh marker")
	}
	providerCache.useHome(fixture.home)
	requestKey := spec.requestKey("rule")
	source := "old.example\n"
	if err := os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerCache.sourcePath(requestKey), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	providerCache.update(requestKey, func(entry *providerCacheEntry) {
		entry.Kind, entry.URL = "rule", spec.URL
		entry.SourceSHA256, entry.SourceBytes = payloadSHA256([]byte(source)), int64(len(source))
		entry.LastCheckedAt, entry.Result = time.Now().Add(-time.Hour).Unix(), providerRefreshUpdated
	})
	fixture.start()
	if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 == "" {
		t.Fatalf("the large seed does not wait for the App: %+v", entry)
	}
}

func TestASubscriptionNoLibraryHoldsRunsAgainAfterARestart(t *testing.T) {
	if testMeshNodes == 0 {
		t.Skip("no mesh node in this build")
	}
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	served := padding + subscriptionPayload("n", 3) + testMeshNode
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: "", served: served, mapped: true})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	if product, _ := liveProduct(t, fixture, service); product.Variant != "proxy" || !product.BuiltHere || product.Stopgap {
		t.Fatalf("the product the tunnel built: %+v", product)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.serve(http.StatusServiceUnavailable, "")
	fixture.start()
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 4 {
		t.Fatalf("after a restart the subscription does not run its 4 nodes: %v", ok)
	}
}

func TestALargeSeedBesideASubscriptionNoLibraryHoldsIsBuiltHere(t *testing.T) {
	if testMeshNodes == 0 {
		t.Skip("no mesh node in this build")
	}
	padding := strings.Repeat("# padding past the start path's text limit\n", startTextSeedLimit/40+1)
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: "", served: padding + subscriptionPayload("n", 3) + testMeshNode, mapped: true, interval: -1})
	service := fixture.start()
	fixture.waitForResult(providerRefreshPendingApp)
	if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
		t.Fatalf("the App's compile: %+v", results)
	}
	newer := padding + subscriptionPayload("m", 5) + testMeshNode
	time.Sleep(2 * time.Second)
	fixture.options.published, fixture.options.fetchedAgo = newer, time.Millisecond
	fixture.finalize()
	fixture.serve(http.StatusOK, newer)
	if err := service.Reload(fixture.finalized); err != nil {
		t.Fatal(err)
	}
	if answer := UpdateProviderJSON("proxy", "refreshed", 15000); !strings.Contains(answer, providerRefreshUpdated) {
		t.Fatalf("the check beside a subscription no library holds: %s", answer)
	}
	if live, ok := tunnel.Providers()["refreshed"]; !ok || live.Count() != 6 {
		t.Fatalf("the newer subscription does not run: %v", ok)
	}
}

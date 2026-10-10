package clash

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type coreOwnedRouteFixture struct {
	*refreshFixture
	document, legacy string
}

func newCoreOwnedRouteFixture(t *testing.T, served string) *coreOwnedRouteFixture {
	t.Helper()
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr", served: served})
	cachePath := filepath.Join("tv-rule-cache", "cn_ip.txt")
	document := fmt.Sprintf(`mode: rule
tun:
  enable: false
  route-address-set: [refreshed]
dns: {enable: true, nameserver: [8.8.8.8]}
rule-providers:
  refreshed: {type: http, behavior: ipcidr, format: text, url: %s/rules.txt, interval: 3600, path: %s, proxy: DIRECT}
rules:
  - RULE-SET,refreshed,DIRECT
  - MATCH,DIRECT
`, fixture.server.URL, cachePath)
	return &coreOwnedRouteFixture{refreshFixture: fixture, document: document, legacy: filepath.Join(fixture.home, cachePath)}
}

func (f *coreOwnedRouteFixture) publish(adopt bool) {
	f.t.Helper()
	resources := "{}"
	if adopt {
		bytes, err := os.ReadFile(f.legacy)
		if err != nil {
			f.t.Fatal(err)
		}
		copyPath := filepath.Join(f.home, "store", "revision", fmt.Sprintf("cn_ip-%d", time.Now().UnixNano()))
		_ = os.MkdirAll(filepath.Dir(copyPath), 0o700)
		if err := os.WriteFile(copyPath, bytes, 0o600); err != nil {
			f.t.Fatal(err)
		}
		info, _ := os.Stat(f.legacy)
		encoded, _ := json.Marshal(map[string]any{
			"providerPaths":     map[string]string{"rule:refreshed": copyPath},
			"providerFetchedAt": map[string]int64{"rule:refreshed": info.ModTime().Unix()},
		})
		resources = string(encoded)
	}
	finalized, err := FinalizeForIOS(f.document, resources)
	if err != nil {
		f.t.Fatal(err)
	}
	f.finalized = finalized.Value
}

func (f *coreOwnedRouteFixture) firstLoad() *BoxService {
	f.t.Helper()
	f.publish(false)
	service := f.start()
	f.waitFor("the rules half", func() bool { return liveRuleCount() >= 1 })
	if entry := f.waitForResult(providerRefreshPendingApp); entry.PendingReason != providerRefreshPendingRoutes {
		f.t.Fatalf("the routes wait for the App: %+v", entry)
	}
	return service
}

func TestACoreOwnedRouteSetsBytesReachTheAppAndItsRepublishEndsTheWait(t *testing.T) {
	served := "198.51.100.0/24\n203.0.113.0/24\n"
	fixture := newCoreOwnedRouteFixture(t, served)
	service := fixture.firstLoad()
	if got, err := os.ReadFile(fixture.legacy); err != nil || string(got) != served {
		t.Fatalf("the App's route cache holds %q (%v), want what the server served", got, err)
	}
	_ = service.Close()
	fixture.publish(true)
	service = fixture.start()
	var after *providerCacheEntry
	fixture.waitFor("the wait ended", func() bool {
		_, after = fixture.state()
		return after != nil && after.Result != providerRefreshPendingApp
	})
	if after.RoutesAwaitSHA256 != "" || liveRuleCount() != 2 {
		t.Fatalf("the republish did not end the wait for routes: %+v, %d rules", after, liveRuleCount())
	}
	newer := "192.0.2.0/24\n"
	fixture.serve(http.StatusOK, newer)
	if result, _ := service.refreshNow("rule", "refreshed"); result.PendingReason != providerRefreshPendingRoutes {
		t.Fatalf("new routes wait for the App: %+v", result)
	}
	if got, _ := os.ReadFile(fixture.legacy); string(got) != newer {
		t.Fatalf("the App's route cache holds %q, want the waiting payload", got)
	}
	_ = service.Close()
	fixture.publish(true)
	fixture.start()
	fixture.waitFor("the second wait ended", func() bool {
		_, after = fixture.state()
		return after != nil && after.Result != providerRefreshPendingApp && after.SourceSHA256 == payloadSHA256([]byte(newer))
	})
	if liveRuleCount() != 1 {
		t.Fatalf("the newer routes' rules do not run: %d", liveRuleCount())
	}
}

func TestARestartDoesNotEndTheWaitForRoutes(t *testing.T) {
	fixture := newCoreOwnedRouteFixture(t, "198.51.100.0/24\n203.0.113.0/24\n")
	service := fixture.firstLoad()
	_ = service.Close()
	fixture.start()
	time.Sleep(200 * time.Millisecond)
	if _, entry := fixture.state(); entry.Result != providerRefreshPendingApp || entry.PendingReason != providerRefreshPendingRoutes || entry.RoutesAwaitSHA256 == "" {
		t.Fatalf("a restart ended the wait for routes: %+v", entry)
	}
}

func TestARestartDoesNotLoadAWaitingPayload(t *testing.T) {
	fixture := newCoreOwnedRouteFixture(t, "198.51.100.0/24\n203.0.113.0/24\n")
	service := fixture.firstLoad()
	_ = service.Close()
	fixture.publish(true)
	service = fixture.start()
	fixture.waitFor("the wait ended", func() bool {
		_, entry := fixture.state()
		return entry != nil && entry.Result != providerRefreshPendingApp
	})
	fixture.serve(http.StatusOK, "192.0.2.0/24\n")
	if result, _ := service.refreshNow("rule", "refreshed"); result.PendingReason != providerRefreshPendingRoutes {
		t.Fatalf("fixture: %+v", result)
	}
	_ = service.Close()
	fixture.publish(false)
	fixture.start()
	if count := liveRuleCount(); count != 2 {
		t.Fatalf("the waiting payload was loaded at start: %d rules", count)
	}
	if _, entry := fixture.state(); entry.PendingSHA256 == "" {
		t.Fatalf("the waiting payload stopped waiting: %+v", entry)
	}
}

func TestTheMirrorStaysInsideTheHome(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "source")
	_ = os.WriteFile(source, []byte("192.0.2.0/24\n"), 0o600)
	refresher := &providerRefresher{home: home}
	_ = os.MkdirAll(filepath.Join(home, "kept"), 0o700)
	if err := os.Symlink(filepath.Join(home, "kept"), filepath.Join(home, "dirlink")); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []string{"link/sub/x.txt", ".", "provider-refresh/state.json", "provider-runtime/x",
		"provider-runtime-private/x", "internal-diagnostics/x", "dirlink", "../escape.txt"} {
		task := &providerRefreshTask{spec: &providerRefreshSpec{LegacyPath: legacy}, targets: []*providerRefreshTarget{{name: "x"}}}
		refresher.mirrorToLegacy(task, source)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("the mirror made %d entries outside the home", len(entries))
	}
	if info, err := os.Lstat(filepath.Join(home, "dirlink")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the mirror replaced a link: %v", err)
	}
	for _, refused := range []string{"provider-refresh", "provider-runtime", "provider-runtime-private", "internal-diagnostics"} {
		if _, err := os.Stat(filepath.Join(home, refused)); !os.IsNotExist(err) {
			t.Fatalf("the mirror wrote into %s", refused)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(home), "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("the mirror wrote outside the home")
	}
	task := &providerRefreshTask{spec: &providerRefreshSpec{LegacyPath: "tv-rule-cache/a.txt"}, targets: []*providerRefreshTarget{{name: "x"}}}
	refresher.mirrorToLegacy(task, source)
	if got, _ := os.ReadFile(filepath.Join(home, "tv-rule-cache", "a.txt")); string(got) != "192.0.2.0/24\n" {
		t.Fatalf("the mirror did not write inside the home: %q", got)
	}
}

func TestARestartNeitherParsesTheMirrorNorAsksTheServer(t *testing.T) {
	fixture := newCoreOwnedRouteFixture(t, "198.51.100.0/24\n203.0.113.0/24\n")
	service := fixture.firstLoad()
	requestKey := service.providerRuntime.refresh.targets[0].requestKey
	_ = service.Close()
	requests := fixture.requests.Load()
	fixture.start()
	time.Sleep(200 * time.Millisecond)
	if fixture.requests.Load() != requests {
		t.Fatalf("a restart within the interval asked the server")
	}
	_ = fixture.service.Close()
	_ = os.RemoveAll(filepath.Join(providerCache.requestDirectory(requestKey), "products"))
	adjustableBuildMemory(t, 1<<20)
	fixture.start()
	if count := liveRuleCount(); count != 0 {
		t.Fatalf("the start parsed the tunnel's own copy: %d rules", count)
	}
}

func TestAStartRestoresTheCopyAtTheDefinitionsPath(t *testing.T) {
	served := "198.51.100.0/24\n203.0.113.0/24\n"
	fixture := newCoreOwnedRouteFixture(t, served)
	service := fixture.firstLoad()
	_ = service.Close()
	if err := os.Remove(fixture.legacy); err != nil {
		t.Fatal(err)
	}
	requests := fixture.requests.Load()
	fixture.start()
	fixture.waitFor("the copy back", func() bool {
		got, err := os.ReadFile(fixture.legacy)
		return err == nil && string(got) == served
	})
	if fixture.requests.Load() != requests {
		t.Fatalf("restoring the copy asked the server")
	}
}

func TestTheMirrorSeesThroughTheHomesLink(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(real, "source")
	_ = os.WriteFile(source, []byte("192.0.2.0/24\n"), 0o600)
	for _, c := range []struct{ home, legacy string }{
		{link, filepath.Join(real, "tv-rule-cache", "a.txt")},
		{real, filepath.Join(link, "tv-rule-cache", "b.txt")},
	} {
		refresher := &providerRefresher{home: c.home}
		task := &providerRefreshTask{spec: &providerRefreshSpec{LegacyPath: c.legacy}, targets: []*providerRefreshTarget{{name: "x"}}}
		refresher.mirrorToLegacy(task, source)
		if got, _ := os.ReadFile(c.legacy); string(got) != "192.0.2.0/24\n" {
			t.Fatalf("home %s, path %s: not written", c.home, c.legacy)
		}
	}
}

func TestAWithdrawnPayloadTakesItsCopyBack(t *testing.T) {
	served := "198.51.100.0/24\n203.0.113.0/24\n"
	fixture := newCoreOwnedRouteFixture(t, served)
	service := fixture.firstLoad()
	_ = service.Close()
	fixture.publish(true)
	service = fixture.start()
	fixture.waitFor("the wait ended", func() bool {
		_, entry := fixture.state()
		return entry != nil && entry.Result != providerRefreshPendingApp
	})
	fixture.serve(http.StatusOK, "192.0.2.0/24\n")
	if result, _ := service.refreshNow("rule", "refreshed"); result.PendingReason != providerRefreshPendingRoutes {
		t.Fatalf("fixture: %+v", result)
	}
	fixture.serve(http.StatusOK, served)
	if result, _ := service.refreshNow("rule", "refreshed"); result.Result != providerRefreshUnchanged {
		t.Fatalf("the server went back: %+v", result)
	}
	if got, _ := os.ReadFile(fixture.legacy); string(got) != served {
		t.Fatalf("the copy holds %q, want what runs", got)
	}
}

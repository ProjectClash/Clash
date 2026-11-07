package clash

import (
	"bytes"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestAnMrsSetAnEarlierKernelParkedRunsAfterTheUpgrade(t *testing.T) {
	for _, reply := range []string{"same bytes", "not modified"} {
		t.Run(reply, func(t *testing.T) {
			var mrs bytes.Buffer
			if err := ruleprovider.ConvertToMrs([]byte("a.example\nb.example\nc.example\n"), P.Domain, P.TextRule, &mrs); err != nil {
				t.Fatalf("ConvertToMrs: %v", err)
			}
			payload := mrs.Bytes()
			fixture := newRefreshFixture(t, refreshFixtureOptions{
				kind: "rule", behavior: "domain", format: "mrs",
				published: "", served: string(payload), compile: true, mapped: true,
			})
			if reply == "not modified" {
				fixture.serve(http.StatusNotModified, "")
			}

			raw, err := config.UnmarshalRawConfig([]byte(fixture.finalized))
			if err != nil {
				t.Fatal(err)
			}
			var spec *providerRefreshSpec
			for _, definition := range raw.RuleProvider {
				spec, _ = decodeProviderRefreshMarker(definition[providerRefreshField])
			}
			if spec == nil {
				t.Fatal("the published definition carries no refresh marker")
			}
			providerCache.useHome(fixture.home)
			requestKey := spec.requestKey("rule")
			if err := os.MkdirAll(providerCache.requestDirectory(requestKey), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(providerCache.pendingPath(requestKey), payload, 0o600); err != nil {
				t.Fatal(err)
			}
			providerCache.update(requestKey, func(entry *providerCacheEntry) {
				entry.Kind, entry.URL = "rule", spec.URL
				entry.PendingSHA256, entry.PendingETag = payloadSHA256(payload), `"earlier"`
				entry.PendingWait, entry.PendingCheckedAt = providerRefreshPendingRecompile, time.Now().Add(-time.Hour).Unix()
				entry.Result, entry.PendingReason = providerRefreshPendingApp, providerRefreshPendingRecompile
			})

			fixture.start()
			fixture.waitFor("the parked set to run", func() bool {
				live, ok := tunnel.RuleProviders()["refreshed"]
				return ok && live.Count() == 3
			})
			entry := fixture.waitForEntry("the set no longer waits", func(e *providerCacheEntry) bool {
				return e.Result != providerRefreshPendingApp
			})
			if entry.PendingSHA256 != "" {
				t.Fatalf("the payload still waits for the App (%s)", entry.PendingWait)
			}
		})
	}
}

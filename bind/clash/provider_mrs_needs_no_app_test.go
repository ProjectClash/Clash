package clash

import (
	"bytes"
	"testing"

	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
)

func TestAnMrsSetTheAppNeverBroughtRunsWithoutIt(t *testing.T) {
	for _, c := range []struct {
		behavior, format string
		served           string
		wantRules        int
		wantResult       string
		wantVariant      string
	}{
		{behavior: "domain", format: "mrs", served: "a.example\nb.example\nc.example\n",
			wantRules: 3, wantResult: providerRefreshUpdated, wantVariant: "mrs"},
		{behavior: "ipcidr", format: "mrs", served: "203.0.113.0/24\n198.51.100.0/24\n",
			wantRules: 2, wantResult: providerRefreshUpdated, wantVariant: "mrs"},
		{behavior: "domain", format: "yaml", served: "payload:\n  - a.example\n  - b.example\n",
			wantRules: 2, wantResult: providerRefreshUpdated, wantVariant: "mapped"},
	} {
		t.Run(c.behavior+"/"+c.format, func(t *testing.T) {
			served := c.served
			if c.format == "mrs" {
				behavior := P.Domain
				if c.behavior == "ipcidr" {
					behavior = P.IPCIDR
				}
				var mrs bytes.Buffer
				if err := ruleprovider.ConvertToMrs([]byte(c.served), behavior, P.TextRule, &mrs); err != nil {
					t.Fatalf("ConvertToMrs: %v", err)
				}
				served = mrs.String()
			}
			fixture := newRefreshFixture(t, refreshFixtureOptions{
				kind: "rule", behavior: c.behavior, format: c.format,
				published: "", served: served, compile: true, mapped: true,
			})
			fixture.start()
			entry := fixture.waitForEntry("a settled refresh result", func(e *providerCacheEntry) bool {
				return e.Result != "" && e.Result != providerRefreshScheduled
			})
			if entry.Result != c.wantResult {
				t.Fatalf("the refresh says %q (wait %q), want %q", entry.Result, entry.PendingWait, c.wantResult)
			}
			if live := liveRuleCount(); live != c.wantRules {
				t.Fatalf("the tunnel runs %d of the set's %d rules", live, c.wantRules)
			}
			if entry.CountAfter != c.wantRules {
				t.Fatalf("the page is told %d rules; the tunnel runs %d", entry.CountAfter, c.wantRules)
			}
			state, _ := fixture.state()
			if state == nil {
				t.Fatal("no state file")
			}
			if variant := state.Running.Variants["rule:refreshed"]; variant != c.wantVariant {
				t.Fatalf("the set runs as %q, want %q", variant, c.wantVariant)
			}
		})
	}
}

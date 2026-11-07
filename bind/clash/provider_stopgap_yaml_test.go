package clash

import (
	"strings"
	"testing"
)

func TestAYamlSetWhoseFormatIsLeftOutRunsAsAStopgap(t *testing.T) {
	for _, c := range []struct {
		name, behavior, served string
		rules                  int
		omit                   bool
	}{
		{"domain explicit", "domain", "payload:\n  - a.example\n  - '+.b.example'\n", 2, false},
		{"domain omitted", "domain", "payload:\n  - a.example\n  - '+.b.example'\n", 2, true},
		{"classical omitted", "classical", "payload:\n  - DOMAIN,a.example\n  - DOMAIN-SUFFIX,b.example\n  - IP-CIDR,10.0.0.0/8\n", 3, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: c.behavior, format: "yaml", served: c.served, mapped: true})
			if c.omit {
				document := fixture.document()
				stripped := strings.Replace(document, "    format: yaml\n", "", 1)
				if stripped == document {
					t.Fatal("format line not found")
				}
				finalized, err := FinalizeForIOS(stripped, "{}")
				if err != nil {
					t.Fatal(err)
				}
				fixture.finalized = finalized.Value
			}
			fixture.start()
			entry := fixture.waitForEntry("a settled refresh result", func(e *providerCacheEntry) bool {
				return e.Result != "" && e.Result != providerRefreshScheduled
			})
			if n := liveRuleCount(); n != c.rules {
				t.Fatalf("the set runs %d rules, want %d (result %q)", n, c.rules, entry.Result)
			}
		})
	}
}

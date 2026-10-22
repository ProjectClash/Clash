package clash

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestTheAppCompilesTheWaitingContentOfASetPublishedAsMRSOrYAML(t *testing.T) {
	mrs := func(t *testing.T, lines string) string {
		t.Helper()
		var artifact bytes.Buffer
		if err := ruleprovider.ConvertToMrs([]byte(lines), P.IPCIDR, P.TextRule, &artifact); err != nil {
			t.Fatal(err)
		}
		return artifact.String()
	}
	for _, source := range []struct{ format, published, served string }{
		{"mrs", mrs(t, "10.0.0.0/8\n"), mrs(t, "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n")},
		{"yaml", "payload:\n  - 10.0.0.0/8\n", "payload:\n  - 10.0.0.0/8\n  - 172.16.0.0/12\n  - 192.168.0.0/16\n"},
	} {
		t.Run(source.format, func(t *testing.T) {
			fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", behavior: "ipcidr", format: source.format,
				published: source.published, served: source.served, compile: true, mapped: true, fetchedAgo: 2 * time.Hour})
			service := fixture.start()
			if product, _ := liveProduct(t, fixture, service); product.Variant != "mapped" {
				t.Fatalf("the published set should run mapped: %q", product.Variant)
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
			if err != nil {
				t.Fatal(err)
			}
			var results []pendingCompileResult
			if err := json.Unmarshal([]byte(answer), &results); err != nil || len(results) != 1 ||
				results[0].Result != providerRefreshUpdated || results[0].CountAfter != 3 {
				t.Fatalf("the App's compile answered %s (%v)", answer, err)
			}
			live := tunnel.RuleProviders()["refreshed"]
			if !live.Match(&C.Metadata{DstIP: netip.MustParseAddr("192.168.1.1")}, C.RuleMatchHelper{}) {
				t.Fatal("the seeded set does not run")
			}
			if _, after := fixture.state(); after.PendingSHA256 != "" {
				t.Fatalf("the content still waits: %+v", after)
			}
		})
	}
}

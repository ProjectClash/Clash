package clash

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestTheAppReadsTheDelaysOverItsSocket(t *testing.T) {
	const one = "proxies:\n  - {name: \"N 1\", type: socks5, server: 127.0.0.1, port: 1}\n"
	const two = one + "  - {name: \"N 2\", type: socks5, server: 127.0.0.1, port: 1}\n"
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", published: one, served: one, fetchedAgo: time.Second, interval: 86400})
	fixture.start()
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

	type document struct {
		Revision string
		Groups   map[string]struct{ Now *string }
		Proxies  map[string]json.RawMessage
	}
	read := func() document {
		t.Helper()
		answer, err := client.GetProxyDelays()
		if err != nil {
			t.Fatalf("GetProxyDelays: %v", err)
		}
		var decoded document
		if err := json.Unmarshal([]byte(answer), &decoded); err != nil {
			t.Fatalf("%v: %s", err, answer)
		}
		return decoded
	}
	first := read()
	if g := first.Groups["G"]; g.Now == nil || *g.Now != "N 1" || first.Revision == "" {
		t.Fatalf("the group's selection: %+v", first)
	}
	if again := read(); again.Revision != first.Revision {
		t.Fatalf("nothing changed and the revision did: %s, %s", first.Revision, again.Revision)
	}
	fixture.serve(http.StatusOK, two)
	if err := client.UpdateProxyProvider("refreshed"); err != nil || liveProxyCount() != 2 {
		t.Fatalf("update: %v, %d nodes", err, liveProxyCount())
	}
	if after := read(); after.Revision == first.Revision {
		t.Fatalf("a provider's new nodes kept the revision %s", after.Revision)
	}
}

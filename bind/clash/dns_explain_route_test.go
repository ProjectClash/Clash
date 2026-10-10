package clash

import (
	"encoding/json"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
	"github.com/metacubex/http/httptest"
)

func decodeExplain(t *testing.T, target string) (map[string]any, int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	serveDNSExplain(recorder, httptest.NewRequest("GET", target, nil))
	var body map[string]any
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("response is not JSON: %s", recorder.Body.String())
		}
	}
	return body, recorder.Code
}

func TestExplainRouteRejectsAMissingDomain(t *testing.T) {
	_, status := decodeExplain(t, "/clash/v1/dns/explain")
	if status == 200 {
		t.Fatal("a request with no domain was accepted; there is nothing to explain")
	}
}

func TestExplainRouteSaysWhenDNSIsNotRunning(t *testing.T) {
	previous := resolver.DefaultResolver
	resolver.DefaultResolver = nil
	t.Cleanup(func() { resolver.DefaultResolver = previous })

	_, status := decodeExplain(t, "/clash/v1/dns/explain?domain=example.com")
	if status == 200 {
		t.Fatal("explained a name while no resolver exists; an empty explanation would read " +
			"as 'nothing matched' rather than 'DNS is off'")
	}
}

func TestExplainRouteAcceptsWhatExecutorAssigns(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })

	resolver.DefaultResolver = dns.NewResolver(dns.Config{
		Main: []dns.NameServer{{Net: "", Addr: "223.5.5.5:53"}},
	})

	body, status := decodeExplain(t, "/clash/v1/dns/explain?domain=example.com")
	if status != 200 {
		t.Fatalf("a running core was told its DNS is not running: status %d, body %v",
			status, body)
	}
	candidates, _ := body["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatalf("explained a name with no candidate resolvers: %v", body)
	}
}

func TestExplainRouteDefaultsToNoProbe(t *testing.T) {
	if probeRequested(httptest.NewRequest("GET", "/x?domain=a.com", nil)) {
		t.Fatal("probe defaulted to on")
	}
	if !probeRequested(httptest.NewRequest("GET", "/x?domain=a.com&probe=1", nil)) {
		t.Fatal("probe=1 was not honoured")
	}
	if probeRequested(httptest.NewRequest("GET", "/x?domain=a.com&probe=0", nil)) {
		t.Fatal("probe=0 was treated as on")
	}
}

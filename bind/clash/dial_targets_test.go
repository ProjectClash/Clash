package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const dialTargetsProviderPayload = `proxies:
  - {name: fromProvider, type: socks5, server: 10.0.0.2, port: 1081}
`

const dialTargetsYAML = `
mode: rule
log-level: info
proxies:
  - {name: declared, type: socks5, server: 10.0.0.1, port: 1080}
  - {name: chained, type: socks5, server: 10.0.0.3, port: 1082, dialer-proxy: declared}
proxy-providers:
  air:
    type: file
    path: ./nodes.yaml
    health-check: {enable: false, url: "http://captive.apple.com", interval: 600}
proxy-groups:
  - {name: Top, type: select, use: [air], proxies: [declared, chained, DIRECT]}
rules:
  - MATCH,Top
`

func startDialTargetsCore(t *testing.T) {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(options.WorkingPath, "nodes.yaml")
	if err := os.WriteFile(payload, []byte(dialTargetsProviderPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(dialTargetsYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func decodeDialTargets(t *testing.T, payload string) map[string]map[string]any {
	t.Helper()
	var decoded struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, payload)
	}
	byName := map[string]map[string]any{}
	for _, target := range decoded.Targets {
		name, _ := target["name"].(string)
		byName[name] = target
	}
	return byName
}

func TestDialTargetsNamesEveryNodeIncludingAProvidersOwn(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())

	declared, ok := targets["declared"]
	if !ok {
		t.Fatalf("the `proxies:` section's node is missing:\n%s", DialTargetsJSON())
	}
	if declared["addr"] != "10.0.0.1:1080" {
		t.Fatalf("declared addr = %v, want 10.0.0.1:1080", declared["addr"])
	}
	if declared["host"] != "10.0.0.1" {
		t.Fatalf("declared host = %v, want 10.0.0.1", declared["host"])
	}
	if declared["port"] != float64(1080) {
		t.Fatalf("declared port = %v, want 1080", declared["port"])
	}
	if declared["type"] != "Socks5" {
		t.Fatalf("declared type = %v, want the adapter's own type string", declared["type"])
	}
	if provider, present := declared["provider"]; present {
		t.Fatalf("a node from `proxies:` has no provider, got %v", provider)
	}

	fromProvider, ok := targets["fromProvider"]
	if !ok {
		t.Fatalf("the provider's own node is missing -- tunnel.Proxies() alone does not hold it:\n%s", DialTargetsJSON())
	}
	if fromProvider["addr"] != "10.0.0.2:1081" {
		t.Fatalf("provider node addr = %v, want 10.0.0.2:1081", fromProvider["addr"])
	}
	if fromProvider["provider"] != "air" {
		t.Fatalf("provider node provider = %v, want air", fromProvider["provider"])
	}
}

func TestADialerProxyNodeSaysSoOnItsOwnRow(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())

	chained, ok := targets["chained"]
	if !ok {
		t.Fatalf("missing chained node:\n%s", DialTargetsJSON())
	}
	if chained["dialerProxy"] != "declared" {
		t.Fatalf("dialerProxy = %v, want declared", chained["dialerProxy"])
	}
	if declared := targets["declared"]; declared["dialerProxy"] != nil {
		t.Fatalf("a node with no dialer-proxy must not carry the key, got %v", declared["dialerProxy"])
	}
}

func TestDialTargetsLeavesOutWhatHasNoAddressToDial(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())
	for _, name := range []string{"Top", "DIRECT", "REJECT", "GLOBAL"} {
		if _, present := targets[name]; present {
			t.Fatalf("%q has no address of its own and must not be a dial target:\n%s", name, DialTargetsJSON())
		}
	}
}

func TestDialTargetsAreInAStableOrder(t *testing.T) {
	startDialTargetsCore(t)
	first := DialTargetsJSON()
	for attempt := 0; attempt < 8; attempt++ {
		if again := DialTargetsJSON(); again != first {
			t.Fatalf("order is not stable:\n%s\n%s", first, again)
		}
	}
}

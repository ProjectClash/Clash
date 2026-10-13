package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func TestOutboundEndpointKindsMatchSwiftIDsWithoutLeakingEndpoints(t *testing.T) {
	proxies := map[string]C.Proxy{}
	for _, mapping := range []map[string]any{
		{"name": "Host Node", "type": "vless", "server": "secret.example.test", "port": 443, "uuid": "0123abcd-4567-89ef-0123-456789abcdef"},
		{"name": "IPv4 Node", "type": "socks5", "server": "192.0.2.1", "port": 1080},
		{"name": "IPv6 Node", "type": "hysteria2", "server": "2001:db8::1", "port": 443, "password": "private-credential"},
		{"name": "Shadowsocks Node", "type": "ss", "server": "198.51.100.7", "port": 8388, "cipher": "aes-128-gcm", "password": "private-credential"},
	} {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			t.Fatal(err)
		}
		proxies[proxy.Name()] = proxy
	}
	proxies["DIRECT"] = adapter.NewProxy(nil)
	got, unnamed := outboundEndpointKinds(proxies, nil)
	if unnamed != 0 {
		t.Fatalf("unnamed = %d, want 0", unnamed)
	}
	want := map[string]string{
		anonymizedNodeID("Host Node", "VLESS"):              "hostname",
		anonymizedNodeID("IPv4 Node", "socks5"):             "ipv4",
		anonymizedNodeID("IPv6 Node", "hysteria2"):          "ipv6",
		anonymizedNodeID("Shadowsocks Node", "Shadowsocks"): "ipv4",
	}
	if len(got) != len(want) {
		t.Fatalf("endpoint kinds = %#v, want %#v", got, want)
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Fatalf("endpoint kind %s = %q, want %q", id, got[id], kind)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Host Node", "secret.example.test", "192.0.2.1", "private-credential", "0123abcd"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, encoded)
		}
	}
}

func libraryConfigForEndpointKinds(t *testing.T, nodes int) *config.Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "  - {name: \"n%d\", type: ss, server: 198.51.100.%d, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i%250+1)
	}
	b.WriteString("proxy-groups:\n  - {name: pick, type: select, include-all: true}\nrules:\n  - MATCH,pick\n")
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(b.String(), string(resources))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseAfterLookups(finalized.Value)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyLibrary == nil || cfg.ProxyLibrary.Len() != nodes {
		t.Fatalf("library = %v, want %d nodes", cfg.ProxyLibrary, nodes)
	}
	return cfg
}

func TestEndpointKindsNameALibrarysNodes(t *testing.T) {
	cfg := libraryConfigForEndpointKinds(t, 5)
	kinds, unnamed := outboundEndpointKinds(cfg.Proxies, cfg.ProxyLibrary)
	if unnamed != 0 || len(kinds) != 5 {
		t.Fatalf("kinds = %v, unnamed = %d; want 5 named", kinds, unnamed)
	}
	for i := 0; i < 5; i++ {
		if got := kinds[anonymizedNodeID(fmt.Sprintf("n%d", i), "Shadowsocks")]; got != "ipv4" {
			t.Fatalf("n%d = %q, want ipv4", i, got)
		}
	}
}

func TestEndpointKindsPastTheLimitAreCountedNotNamed(t *testing.T) {
	cfg := libraryConfigForEndpointKinds(t, endpointKindsNodeLimit+1)
	kinds, unnamed := outboundEndpointKinds(cfg.Proxies, cfg.ProxyLibrary)
	if len(kinds) != 0 || unnamed != endpointKindsNodeLimit+1 {
		t.Fatalf("kinds = %d named, unnamed = %d; want none named, %d unnamed", len(kinds), unnamed, endpointKindsNodeLimit+1)
	}
	if allocs := testing.AllocsPerRun(20, func() { outboundEndpointKinds(cfg.Proxies, cfg.ProxyLibrary) }); allocs > 2 {
		t.Fatalf("a read past the limit allocated %.0f times, want at most 2", allocs)
	}
}

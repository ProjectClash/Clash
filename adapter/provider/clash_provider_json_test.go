package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/resource"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestAProviderWrittenAPieceAtATimeIsItsJSON(t *testing.T) {
	dir := t.TempDir()
	payload := providerLibraryPayload(40)
	library, count, err := ClashCompileProviderLibrary("lib", map[string]any{"type": "file", "path": "unused"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "lib.cnl"), library, 0o600)
	stub := filepath.Join(dir, "lib.provider.stub")
	_ = os.WriteFile(stub, []byte(ClashNodeLibraryStub("lib.cnl", [sha256.Size]byte(library[len(library)-sha256.Size:]), count)+"\n"), 0o600)
	plain := filepath.Join(dir, "plain.yaml")
	_ = os.WriteFile(plain, payload, 0o600)
	empty := filepath.Join(dir, "empty.yaml")
	_ = os.WriteFile(empty, []byte("proxies: []\n"), 0o600)

	parser, err := NewProxiesParser("p", nil, "", "", "", "", overrideSchema{}, "")
	if err != nil {
		t.Fatal(err)
	}
	set := func(name, path string) *ProxySetProvider {
		vehicle := resource.NewFileVehicle(path)
		p, err := NewProxySetProvider(name, 0, nil, clashProviderListParser(vehicle, nil, parser), vehicle, NewHealthCheck(nil, "https://www.gstatic.com/generate_204", 5000, 0, true, nil))
		if err != nil {
			t.Fatal(err)
		}
		_ = p.Initial()
		return p
	}
	var maps []map[string]any
	for i := 0; i < 3; i++ {
		maps = append(maps, map[string]any{"name": "i" + string(rune('a'+i)), "type": "socks5", "server": "i.example.net", "port": 1080})
	}
	inline, err := NewInlineProvider("inline", maps, parser, NewHealthCheck(nil, "", 5000, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	compatible, err := NewCompatibleProvider("compatible", inline.Proxies(), NewHealthCheck(nil, "", 5000, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	for name, provider := range map[string]P.ProxyProvider{"library": set("lib", stub), "slice": set("plain", plain), "empty": set("empty", empty), "inline": inline, "compatible": compatible} {
		want, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		ok, err := ClashWriteProviderJSON(&got, provider)
		if !ok || err != nil || got.String() != string(want) {
			t.Fatalf("%s: ok %v err %v\n got  %.300s\n want %.300s", name, ok, err, got.String(), want)
		}
		summary := ClashProviderSummary(provider)
		var full map[string]any
		_ = json.Unmarshal(want, &full)
		nodes, _ := full["proxies"].([]any)
		if summary["total"] != len(nodes) || summary["name"] != full["name"] || summary["proxies"] != nil || summary["alive"] != 0 || summary["dead"] != 0 {
			t.Fatalf("%s: summary %v", name, summary)
		}
	}
}

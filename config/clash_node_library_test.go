package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"go.yaml.in/yaml/v3"
)

func libraryTestProxies(n int) []map[string]any {
	var out []map[string]any
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			out = append(out, map[string]any{"name": fmt.Sprintf("SS %d", i), "type": "ss", "server": fmt.Sprintf("s%d.example.net", i), "port": 8388, "cipher": "aes-128-gcm", "password": "p", "udp": true})
		case 1:
			out = append(out, map[string]any{"name": fmt.Sprintf("Trojan %d", i), "type": "trojan", "server": fmt.Sprintf("t%d.example.net", i), "port": 443, "password": "p", "sni": "t.example.net"})
		default:
			out = append(out, map[string]any{"name": fmt.Sprintf("HY2 <%d>", i), "type": "hysteria2", "server": fmt.Sprintf("h%d.example.net", i), "port": 443, "password": "p", "dialer-proxy": "SS 0"})
		}
	}
	return out
}

func writeLibrary(t *testing.T, dir string, proxies []map[string]any) (string, string) {
	t.Helper()
	writer := outbound.NewNodeLibraryWriter("")
	for _, mapping := range proxies {
		built, config, err := adapter.BuildLibraryNode(mapping)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Add(built, config); err != nil {
			t.Fatal(err)
		}
		_ = built.Close()
	}
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nodes.library")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	whole := buffer.Bytes()
	sum := sha256.Sum256(whole[:len(whole)-sha256.Size])
	if !bytes.Equal(sum[:], whole[len(whole)-sha256.Size:]) {
		t.Fatal("the library's trailer is not its checksum")
	}
	return path, hex.EncodeToString(sum[:])
}

func everyProxy(cfg *Config) map[string]C.Proxy {
	all := make(map[string]C.Proxy, len(cfg.Proxies))
	for name, proxy := range cfg.Proxies {
		all[name] = proxy
	}
	if cfg.ProxyLibrary != nil {
		for i := 0; i < cfg.ProxyLibrary.Len(); i++ {
			node := cfg.ProxyLibrary.At(i)
			all[node.Name()] = node
		}
	}
	return all
}

func proxiesJSONOf(t *testing.T, proxies map[string]C.Proxy) string {
	t.Helper()
	out, err := json.Marshal(proxies)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, proxy := range decoded {
		delete(proxy, "id")
	}
	out, _ = json.Marshal(decoded)
	return string(out)
}

const libraryTestGroups = `proxy-groups:
  - {name: all, type: select, include-all-proxies: true}
  - {name: trojans, type: select, include-all-proxies: true, filter: "Trojan"}
  - {name: auto, type: url-test, proxies: ["SS 0", "Trojan 1"], lazy: true}
rules:
  - MATCH,all
`

func TestALibrarysNodesParseAsTheSameNodesInline(t *testing.T) {
	proxies := libraryTestProxies(60)
	inlineYAML, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		t.Fatal(err)
	}
	inline, err := Parse([]byte(string(inlineYAML) + libraryTestGroups))
	if err != nil {
		t.Fatal(err)
	}
	path, sum := writeLibrary(t, t.TempDir(), proxies)
	libraryText := fmt.Sprintf("x-clash-node-library: {path: %q, sha256: %s}\n", path, sum) + libraryTestGroups
	built := 0
	restore := adapter.CountBuilds(func() { built++ })
	library, err := Parse([]byte(libraryText))
	restore()
	if err != nil {
		t.Fatal(err)
	}
	if built != 0 {
		t.Fatalf("parsing a library built %d nodes", built)
	}
	if library.ProxyLibrary == nil || library.ProxyLibrary.Len() != len(proxies) {
		t.Fatal("the library's nodes are not the configuration's")
	}
	for name := range library.Proxies {
		if _, ok := library.ProxyLibrary.Lookup(name); ok {
			t.Fatalf("%q is in the map as well as the library", name)
		}
	}
	if got, want := proxiesJSONOf(t, everyProxy(library)), proxiesJSONOf(t, inline.Proxies); got != want {
		at := 0
		for at < len(got) && at < len(want) && got[at] == want[at] {
			at++
		}
		window := func(text string) string {
			from, to := at-200, at+200
			if from < 0 {
				from = 0
			}
			if to > len(text) {
				to = len(text)
			}
			return text[from:to]
		}
		t.Fatalf("library JSON differs from inline at %d:\n got  %s\n want %s", at, window(got), window(want))
	}
}

func TestALibraryTheConfigurationDoesNotNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	path, sum := writeLibrary(t, dir, libraryTestProxies(5))
	wrong := strings.Repeat("0", 64)
	for _, text := range []string{
		fmt.Sprintf("x-clash-node-library: {path: %q, sha256: %s}\nrules: [MATCH,DIRECT]\n", path, wrong),
		fmt.Sprintf("x-clash-node-library: {path: %q, sha256: %s}\nrules: [MATCH,DIRECT]\n", filepath.Join(dir, "absent"), sum),
		fmt.Sprintf("x-clash-node-library: {path: %q}\nrules: [MATCH,DIRECT]\n", path),
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Fatalf("parsed %s", text)
		}
	}
}

func TestALibrarysProxiesAreWrittenAsTheWholeTable(t *testing.T) {
	proxies := libraryTestProxies(3000)
	path, sum := writeLibrary(t, t.TempDir(), proxies)
	inlineNode := "proxies:\n  - {name: \"M inline\", type: ss, server: m.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n"
	text := fmt.Sprintf("x-clash-node-library: {path: %q, sha256: %s, inline-at: [7]}\n", path, sum) + inlineNode + libraryTestGroups
	cfg, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	whole, err := adapter.AppendProxiesJSON(nil, everyProxy(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var streamed bytes.Buffer
	if err := adapter.WriteProxiesJSON(&streamed, cfg.Proxies, cfg.ProxyLibrary); err != nil {
		t.Fatal(err)
	}
	if streamed.String() != string(whole) {
		t.Fatalf("streamed %d bytes, the table is %d", streamed.Len(), len(whole))
	}
	global, _ := json.Marshal(cfg.Proxies["GLOBAL"])
	var g struct{ All []string }
	_ = json.Unmarshal(global, &g)
	if len(g.All) < 10 || g.All[2+7] != "M inline" {
		t.Fatalf("GLOBAL: %v", g.All[:10])
	}
}

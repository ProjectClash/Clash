package provider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
)

func providerLibraryPayload(n int) []byte {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "  - {name: \"HK %d\", type: ss, server: s%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
		case 1:
			fmt.Fprintf(&b, "  - {name: \"JP %d\", type: trojan, server: t%d.example.net, port: 443, password: p, sni: t.example.net}\n", i, i)
		default:
			fmt.Fprintf(&b, "  - {name: \"US %d\", type: vmess, server: v%d.example.net, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, alterId: 0, cipher: auto}\n", i, i)
		}
	}
	return []byte(b.String())
}

func jsonWithoutIDs(t *testing.T, list C.ProxyList) string {
	t.Helper()
	var out []map[string]any
	for i := 0; i < list.Len(); i++ {
		encoded, err := list.At(i).MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		_ = json.Unmarshal(encoded, &decoded)
		delete(decoded, "id")
		out = append(out, decoded)
	}
	encoded, _ := json.Marshal(out)
	return string(encoded)
}

func TestASubscriptionsLibraryHoldsTheNodesItsParserMakes(t *testing.T) {
	definition := map[string]any{"type": "file", "path": "unused", "filter": "HK|JP", "exclude-filter": "JP 1$", "exclude-type": "vmess",
		"dialer-proxy": "front", "override": map[string]any{"udp": true, "additional-prefix": "[s] "}}
	payload := providerLibraryPayload(90)
	library, count, err := ClashCompileProviderLibrary("sub", definition, payload)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "sub.cnl"), library, 0o600)
	stub := filepath.Join(dir, "sub.provider.stub")
	_ = os.WriteFile(stub, []byte(ClashNodeLibraryStub("sub.cnl", [sha256.Size]byte(library[len(library)-sha256.Size:]), count)+"\n"), 0o600)

	parser, err := NewProxiesParser("sub", nil, "HK|JP", "JP 1$", "vmess", "front", overrideSchema{UDP: boolPointer(true), AdditionalPrefix: stringPointer("[s] ")}, "")
	if err != nil {
		t.Fatal(err)
	}
	listParser := clashProviderListParser(resource.NewFileVehicle(stub), nil, parser)
	stubBytes, _ := os.ReadFile(stub)
	fromLibrary, err := listParser(stubBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, isSlice := fromLibrary.(C.ProxySlice); isSlice || fromLibrary.Len() != count {
		t.Fatalf("the stub was not read as a library (%T, %d of %d)", fromLibrary, fromLibrary.Len(), count)
	}
	parsed, err := parser(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := jsonWithoutIDs(t, fromLibrary), jsonWithoutIDs(t, C.ProxySlice(parsed)); got != want {
		t.Fatalf("library nodes differ from parsed:\n got  %.400s\n want %.400s", got, want)
	}
	if _, err := clashProviderListParser(resource.NewFileVehicle(filepath.Join(dir, "plain.yaml")), nil, parser)(stubBytes); err == nil {
		t.Fatal("a stub was honoured outside a stub file")
	}
	bad := []byte("proxies:\n  - {name: \"HK bad\", type: ss, server: b.example.net, port: 8388, cipher: nope, password: p}\n")
	_, _, compileErr := ClashCompileProviderLibrary("sub", map[string]any{"type": "file", "path": "unused"}, bad)
	plain, _ := NewProxiesParser("sub", nil, "", "", "", "", overrideSchema{}, "")
	_, parseErr := plain(bad)
	if compileErr == nil || parseErr == nil || compileErr.Error() != parseErr.Error() {
		t.Fatalf("compile refused with %v; the parser with %v", compileErr, parseErr)
	}
}

func boolPointer(v bool) *bool       { return &v }
func stringPointer(v string) *string { return &v }

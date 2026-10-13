package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderAgeSecretKeysAreReadWithoutTheProxies(t *testing.T) {
	document := `proxies:
  - {name: a, type: socks5, server: a.example.net, port: 1080}
  - {name: b, type: socks5, server: b.example.net, port: 1080}
proxy-providers:
  sealed:
    type: http
    url: http://127.0.0.1:1/a
    age-secret-key: AGE-SECRET-KEY-1ONE
  upper:
    Type: HTTP
    url: http://127.0.0.1:1/b
    Age-Secret-Key: AGE-SECRET-KEY-1TWO
  local:
    type: file
    path: ./x.yaml
    age-secret-key: AGE-SECRET-KEY-1FILE
  open:
    type: http
    url: http://127.0.0.1:1/c
rules:
  - MATCH,DIRECT
`
	got, err := ProviderAgeSecretKeysJSON(document)
	if err != nil || got != `{"proxy:sealed":"AGE-SECRET-KEY-1ONE","proxy:upper":"AGE-SECRET-KEY-1TWO"}` {
		t.Fatalf("keys %s (%v)", got, err)
	}
	if got, err := ProviderAgeSecretKeysJSON("proxies:\n  - {name: a, type: socks5, server: a.example.net, port: 1080}\n"); err != nil || got != "{}" {
		t.Fatalf("no providers: %s (%v)", got, err)
	}
	if _, err := ProviderAgeSecretKeysJSON("proxies: [\n"); err == nil {
		t.Fatal("a text that does not parse answered keys")
	}
}

func TestTheOrderReferenceOrdersAPublishWithALibraryWithoutItsNodes(t *testing.T) {
	reference := `mode: rule
dns:
  nameserver: [8.8.8.8]
  enable: true
  ipv6: false
proxies:
  - {name: a, type: socks5, server: a.example.net, port: 1080}
  - {name: b, type: socks5, server: b.example.net, port: 1080}
proxy-groups:
  - {type: select, name: G, proxies: [a, b]}
rules:
  - MATCH,G
`
	sorted := `dns:
  enable: true
  ipv6: false
  nameserver: [8.8.8.8]
mode: rule
proxies:
  - {name: a, port: 1080, server: a.example.net, type: socks5}
  - {name: b, port: 1080, server: b.example.net, type: socks5}
proxy-groups:
  - {name: G, proxies: [a, b], type: select}
rules:
  - MATCH,G
`
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	options, _ := json.Marshal(map[string]any{"orderReference": reference})
	box, err := FinalizeForIOSWithOptions(sorted, string(resources), string(options))
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Text string }
	if json.Unmarshal([]byte(box.Value), &out) != nil || out.Text == "" {
		out.Text = box.Value
	}
	dns := strings.Index(out.Text, "nameserver:") < strings.Index(out.Text, "enable:") && strings.Index(out.Text, "enable:") < strings.Index(out.Text, "ipv6:")
	group := strings.Contains(out.Text, "type: select") && strings.Index(out.Text, "type: select") < strings.Index(out.Text, "name: G")
	if !dns || !group || strings.Index(out.Text, "mode:") > strings.Index(out.Text, "dns:") {
		t.Fatalf("the published text is not in the reader's order:\n%s", out.Text)
	}
}

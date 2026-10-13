package clash

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPolicyNamesAreReadWithoutTheNodes(t *testing.T) {
	text := `mode: rule
proxies:
  - {name: a, type: socks5, server: a.example.net, port: 1080}
  - {name: 1234, type: socks5, server: b.example.net, port: 1080}
  - name: "c d"
    type: ss
    server: c.example.net
    port: 8388
    cipher: aes-128-gcm
    password: p
proxy-providers:
  zeta: {type: http, url: "http://127.0.0.1:1/z"}
  alpha: {type: http, url: "http://127.0.0.1:1/a"}
proxy-groups:
  - {name: Second, type: select, proxies: [a]}
  - {name: First, type: select, use: [alpha]}
rules:
  - DOMAIN,x.example,Second
  - MATCH,First
`
	got, err := PolicyNamesJSON(text)
	want := `{"proxies":["a","1234","c d"],"groups":["Second","First"],"providers":["alpha","zeta"]}`
	if err != nil || got != want {
		t.Fatalf("names %s (%v), want %s", got, err, want)
	}
	if got, err := PolicyNamesJSON("mode: rule\n"); err != nil || got != `{"proxies":[],"groups":[],"providers":[]}` {
		t.Fatalf("none: %s (%v)", got, err)
	}
	if _, err := PolicyNamesJSON("proxies: [\n"); err == nil {
		t.Fatal("a text that does not parse answered names")
	}
}

func TestPolicyNamesAreTheNamesTheParseGives(t *testing.T) {
	for label, text := range map[string]string{
		"case":                    "proxies: [{Name: n, type: socks5, server: 127.0.0.1, port: 1080}]\nproxy-groups: [{name: g, type: select, proxies: [n]}]\nrules: [\"MATCH,g\"]\n",
		"merge":                   "x-base: &base {name: m, type: socks5, server: 127.0.0.1, port: 1080}\nproxies:\n  - {<<: *base}\nrules: [\"MATCH,m\"]\n",
		"merged name over a case": "x-b: &b {name: B, type: socks5, server: 127.0.0.1, port: 1}\nproxies:\n  - {<<: *b, Name: titled}\nrules:\n  - MATCH,B\n",
		"quoted past the margin":  "proxies:\n  - {name: real, type: socks5, server: a.example.net, port: 1080}\nnote: \"x\nrules:\n  - MATCH,real # \"\nproxy-groups:\n  - {name: g, type: select, proxies: [real]} # \"\n",
		"aliased name key":        "x: &k name\nproxies: [{*k : n, type: socks5, server: 127.0.0.1, port: 1080}]\nrules: [\"MATCH,n\"]\n",
		"flow past the margin":    "proxies:\n  - {name: real, type: socks5, server: a.example.net, port: 1080}\nnote: {a: plain \"text, b: \"x}\nrules:\n  - MATCH,real # \"}\nproxy-groups:\n  - {name: g, type: select, proxies: [real]} # \"}\n",
		"anchor":                  "x: &n old\nrule-providers:\n  r: {type: inline, behavior: domain, payload: [&n example.com]}\nproxies:\n  - {name: *n, type: socks5, server: 127.0.0.1, port: 1080}\nrules: [\"MATCH,example.com\"]\n",
	} {
		cfg, err := parseAfterLookups(text)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		answer, err := PolicyNamesJSON(text)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var names struct{ Proxies, Groups []string }
		if err := json.Unmarshal([]byte(answer), &names); err != nil {
			t.Fatal(err)
		}
		for _, name := range append(names.Proxies, names.Groups...) {
			if _, ok := cfg.Proxies[name]; !ok {
				t.Fatalf("%s: %q is not a name the parse gives (%s)", label, name, answer)
			}
		}
		for name, proxy := range cfg.Proxies {
			if slices.Contains(builtinProxyNames[:], name) || name == "GLOBAL" || name == "DNS" {
				continue
			}
			if !slices.Contains(names.Proxies, name) && !slices.Contains(names.Groups, name) {
				t.Fatalf("%s: the parse names %q (%s), the answer does not: %s", label, name, proxy.Type(), answer)
			}
		}
	}
	phantom := "proxies:\n  - {name: real, type: socks5, server: a.example.net, port: 1080}\nrules:\n  - \"DOMAIN,x,real\nproxy-groups:\n  - {name: g, type: select, proxies: [real]}\"\n"
	if answer, err := PolicyNamesJSON(phantom); err != nil || strings.Contains(answer, `"g"`) {
		t.Fatalf("a group inside a quoted rule was named: %s (%v)", answer, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = PolicyNamesJSON("proxies: [&a {<<: [*a, *a]}]\n")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a merge that names itself kept the read going")
	}
	if answer, err := YamlToJSONOmitting("keep: 1\nrules: *missing\n", `["rules"]`); err == nil {
		t.Fatalf("an alias to no anchor in a section cut was hidden: %s", answer.Value)
	}
	text := "x: &n old\nrule-providers:\n  r: {type: inline, behavior: domain, payload: [&n example.com]}\nproxies:\n  - {name: *n, type: socks5, server: 127.0.0.1, port: 1080}\n"
	answer, err := YamlToJSONOmitting(text, `["rule-providers"]`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer.Value, `"name":"example.com"`) || strings.Contains(answer.Value, "rule-providers") {
		t.Fatalf("omitting the section changed what the anchor names: %s", answer.Value)
	}
}

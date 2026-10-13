package clash

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestYamlToJSONOmittingLeavesOutTheSectionsNamed(t *testing.T) {
	for name, text := range map[string]string{
		"plain": `mode: rule
dns:
  nameserver-policy:
    "+.b.example": 1.1.1.1
    "+.a.example": 8.8.8.8
proxies:
- {name: a, type: socks5, server: a.example.net, port: 1080}
# a comment at the margin inside the section
- name: b
  type: socks5
  server: b.example.net
  port: 1080
proxy-groups:
  - {name: G, type: select, proxies: [a, b]}
rules:
  - MATCH,G
x-tail: 1
`,
		"quoted key": "\"proxies\":\n  - {name: a, type: socks5, server: a.example.net, port: 1080}\nmode: rule\nrules: [MATCH,DIRECT]\n",
		"anchor used elsewhere": `proxies:
  - &a {name: a, type: socks5, server: a.example.net, port: 1080}
x-copy: *a
mode: rule
rules: [MATCH,DIRECT]
`,
		"document start": "---\nmode: rule\nproxies: []\nrules: [MATCH,DIRECT]\n",
		"complex key":    "mode: rule\nproxies: []\n? dns\n: {enable: true}\nrules: [MATCH,DIRECT]\n",
	} {
		whole, err := YamlToJSON(text)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		omitted, err := YamlToJSONOmitting(text, `["proxies","rules"]`)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want, got map[string]any
		_ = json.Unmarshal([]byte(whole.Value), &want)
		_ = json.Unmarshal([]byte(omitted.Value), &got)
		delete(want, "proxies")
		delete(want, "rules")
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s:\n got  %s\n want %v", name, omitted.Value, want)
		}
		if _, has := got["proxies"]; has {
			t.Fatalf("%s: a section named is in %s", name, omitted.Value)
		}
	}
	text := "mode: rule\nproxies: []\ndns:\n  nameserver-policy:\n    \"+.b.example\": 1.1.1.1\n    \"+.a.example\": 8.8.8.8\n"
	omitted, _ := YamlToJSONOmitting(text, `["proxies"]`)
	if strings.Index(omitted.Value, "+.b.example") > strings.Index(omitted.Value, "+.a.example") || strings.Index(omitted.Value, "mode") > strings.Index(omitted.Value, "dns") {
		t.Fatalf("the order changed: %s", omitted.Value)
	}
	if _, err := YamlToJSONOmitting("mode: [\n", `["proxies"]`); err == nil {
		t.Fatal("a text that does not parse answered")
	}
}

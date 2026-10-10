package clash

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEditYAMLWritesEmojiAsTheyAre(t *testing.T) {
	text := "proxy-groups:\n  - name: 🚀 Proxy\n    type: select\n    proxies:\n      - DIRECT\nrules:\n  - MATCH,🚀 Proxy\n"
	mustEdit(t, text, `["proxy-groups",0,"name"]`, "set", `"🚀 Proxy 2"`,
		strings.Replace(text, "  - name: 🚀 Proxy\n", "  - name: 🚀 Proxy 2\n", 1))
	inserted := runYAMLEdit(t, text, `["proxy-groups",1]`, "insert", `{"name":"🇭🇰 香港","type":"select","proxies":["DIRECT"]}`)
	if !inserted.OK || !strings.Contains(inserted.Text, "  - name: 🇭🇰 香港\n") || strings.Contains(inserted.Text, `\U000`) {
		t.Errorf("%+v", inserted)
	}
	for value, want := range map[string]string{
		`"🚀: x"`:             `  - name: '🚀: x'` + "\n",
		`"🚀"`:              "  - name: 🚀\n",
		`"true 🇯🇵"`:          "  - name: true 🇯🇵\n",
		`"line 🚀\nline two"`: "  - name: |-\n      line 🚀\n      line two\n",
	} {
		out := runYAMLEdit(t, text, `["proxy-groups",0,"name"]`, "set", value)
		if !out.OK || !strings.Contains(out.Text, want) || strings.Contains(out.Text, `\U000`) {
			t.Errorf("%s: %+v", value, out)
		}
	}
	out := runYAMLEdit(t, "dns:\n  enable: true\n", `["dns","nameserver-policy"]`, "insert", `{"🚀.example": "1.1.1.1"}`)
	if !out.OK || !strings.Contains(out.Text, "🚀.example: 1.1.1.1") {
		t.Errorf("%+v", out)
	}
}

func TestFormatConfigAndKeyOrderWriteEmojiAsTheyAre(t *testing.T) {
	text := "proxies:\n  - name: 🇺🇸 US # 🚀 comment\n    type: socks5\n    server: 192.0.2.1\n    port: 1080\nproxy-groups:\n  - {name: 🚀 Proxy, type: select, proxies: [🇺🇸 US]}\n"
	box, err := FormatConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(box.Value, `\U000`) || !strings.Contains(box.Value, "name: 🇺🇸 US # 🚀 comment") || !strings.Contains(box.Value, "🚀 Proxy") {
		t.Errorf("FormatConfig:\n%s", box.Value)
	}
	var before, after any
	if yaml.Unmarshal([]byte(text), &before) != nil || yaml.Unmarshal([]byte(box.Value), &after) != nil || !yamlValuesEqual(before, after) {
		t.Errorf("FormatConfig changed the document:\n%s", box.Value)
	}
	merged := restoreSourceKeyOrder(text, "proxy-groups:\n  - {name: 🚀 Proxy, type: select, proxies: [🇺🇸 US]}\nproxies:\n  - {name: 🇺🇸 US, type: socks5, server: 192.0.2.1, port: 1080}\n")
	if strings.Contains(merged, `\U000`) || !strings.Contains(merged, "🚀 Proxy") || strings.Index(merged, "proxies:") > strings.Index(merged, "proxy-groups:") {
		t.Errorf("restoreSourceKeyOrder:\n%s", merged)
	}
}

func yamlValuesEqual(a, b any) bool {
	left, _ := yaml.Marshal(normalizeYAMLValue(a))
	right, _ := yaml.Marshal(normalizeYAMLValue(b))
	return string(left) == string(right)
}

package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const yamlEditFixture = `# my config
mode: rule   # routing mode
log-level: info

dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - "https://doh.pub/dns-query"

proxies:
  - name: a   # first
    type: ss
    server: 192.0.2.1
    port: 8388
  - {name: b, type: direct}

rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  # keep this comment
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
`

type yamlEditOutcome struct {
	OK      bool   `json:"ok"`
	Text    string `json:"text"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func runYAMLEdit(t *testing.T, original, path, op, value string) yamlEditOutcome {
	t.Helper()
	box, err := EditYAMLForIOS(original, path, op, value)
	if err != nil {
		t.Fatalf("EditYAMLForIOS: %v", err)
	}
	var out yamlEditOutcome
	if err := json.Unmarshal([]byte(box.Value), &out); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, box.Value)
	}
	return out
}

func mustEdit(t *testing.T, original, path, op, value, want string) {
	t.Helper()
	out := runYAMLEdit(t, original, path, op, value)
	if !out.OK {
		t.Fatalf("%s %s refused: %s %s", op, path, out.Code, out.Message)
	}
	if out.Text != want {
		t.Fatalf("%s %s:\n--- got ---\n%s\n--- want ---\n%s", op, path, out.Text, want)
	}
}

func TestEditYAMLSetScalarKeepsEverythingElse(t *testing.T) {
	mustEdit(t, yamlEditFixture, `["mode"]`, "set", `"global"`,
		strings.Replace(yamlEditFixture, "mode: rule   # routing mode", "mode: global   # routing mode", 1))
	mustEdit(t, yamlEditFixture, `["dns","enable"]`, "set", `false`,
		strings.Replace(yamlEditFixture, "  enable: true", "  enable: false", 1))
	mustEdit(t, yamlEditFixture, `["proxies",0,"port"]`, "set", `443`,
		strings.Replace(yamlEditFixture, "    port: 8388", "    port: 443", 1))
}

func TestEditYAMLSequenceItems(t *testing.T) {
	mustEdit(t, yamlEditFixture, `["rules",1]`, "set", `"GEOIP,US,Proxy"`,
		strings.Replace(yamlEditFixture, "  - GEOIP,CN,DIRECT", "  - GEOIP,US,Proxy", 1))
	mustEdit(t, yamlEditFixture, `["rules",0]`, "insert", `"DOMAIN,a.com,DIRECT"`,
		strings.Replace(yamlEditFixture, "rules:\n", "rules:\n  - DOMAIN,a.com,DIRECT\n", 1))
	mustEdit(t, yamlEditFixture, `["rules",3]`, "insert", `"DOMAIN,z.com,DIRECT"`,
		strings.Replace(yamlEditFixture, "  - MATCH,Proxy\n", "  - MATCH,Proxy\n  - DOMAIN,z.com,DIRECT\n", 1))
	mustEdit(t, yamlEditFixture, `["rules",1]`, "delete", ``,
		strings.Replace(yamlEditFixture, "  - GEOIP,CN,DIRECT\n", "", 1))
	mustEdit(t, yamlEditFixture, `["rules",2]`, "move", `0`,
		strings.Replace(strings.Replace(yamlEditFixture, "  - MATCH,Proxy\n", "", 1),
			"rules:\n", "rules:\n  - MATCH,Proxy\n", 1))
}

func TestEditYAMLMappingItemsAndNewKeys(t *testing.T) {
	mustEdit(t, yamlEditFixture, `["proxies",0]`, "set", `{"name":"a","type":"direct"}`,
		strings.Replace(yamlEditFixture, "  - name: a   # first\n    type: ss\n    server: 192.0.2.1\n    port: 8388\n",
			"  - name: a\n    type: direct\n", 1))
	mustEdit(t, yamlEditFixture, `["dns","ipv6"]`, "insert", `false`,
		strings.Replace(yamlEditFixture, "    - \"https://doh.pub/dns-query\"\n", "    - \"https://doh.pub/dns-query\"\n  ipv6: false\n", 1))
	mustEdit(t, yamlEditFixture, `["dns","nameserver"]`, "set", `["1.1.1.1"]`,
		strings.Replace(yamlEditFixture, "  nameserver:\n    - 223.5.5.5\n    - \"https://doh.pub/dns-query\"\n",
			"  nameserver:\n    - 1.1.1.1\n", 1))
	mustEdit(t, yamlEditFixture, `["log-level"]`, "delete", ``,
		strings.Replace(yamlEditFixture, "log-level: info\n", "", 1))
}

func TestEditYAMLDeletingTheLastItemLeavesAnEmptyList(t *testing.T) {
	original := "rules:\n  - MATCH,DIRECT\nmode: rule\n"
	mustEdit(t, original, `["rules",0]`, "delete", ``, "rules: []\nmode: rule\n")
}

func TestEditYAMLRefusesWhatItCannotDoSafely(t *testing.T) {
	cases := []struct {
		name, original, path, op, value, code string
	}{
		{"anchor", "base: &b {a: 1}\nuse: *b\n", `["base","a"]`, "set", `2`, "anchor"},
		{"merge", "base: &b {a: 1}\nuse:\n  <<: *b\n  c: 2\n", `["use","c"]`, "set", `3`, "anchor"},
		{"multi-document", "a: 1\n---\nb: 2\n", `["a"]`, "set", `2`, "multiDocument"},
		{"encrypted", "age-encryption.org/v1\n-> X25519 abc\n", `["a"]`, "set", `2`, "encrypted"},
		{"not found", yamlEditFixture, `["rules",9]`, "set", `"x"`, "notFound"},
		{"no such key", yamlEditFixture, `["nope","x"]`, "set", `1`, "notFound"},
		{"type mismatch", yamlEditFixture, `["mode",0]`, "set", `1`, "typeMismatch"},
		{"flow list", yamlEditFixture, `["proxies",1,"type"]`, "set", `"ss"`, "unsupportedStyle"},
		{"bad op", yamlEditFixture, `["mode"]`, "transmogrify", `"x"`, "invalidRequest"},
		{"bad value", yamlEditFixture, `["mode"]`, "set", `{`, "invalidRequest"},
	}
	for _, c := range cases {
		out := runYAMLEdit(t, c.original, c.path, c.op, c.value)
		if out.OK || out.Code != c.code {
			t.Errorf("%s: ok=%v code=%q message=%q, want refusal %q", c.name, out.OK, out.Code, out.Message, c.code)
		}
	}
}

func TestEditYAMLResultAlwaysParsesToTheIntendedDocument(t *testing.T) {
	for _, c := range []struct{ path, op, value string }{
		{`["mode"]`, "set", `"direct"`},
		{`["rules",0]`, "delete", ``},
		{`["rules",1]`, "move", `2`},
		{`["proxies",0,"server"]`, "set", `"198.51.100.7"`},
		{`["dns","nameserver",1]`, "set", `"tls://1.1.1.1"`},
		{`["new-key"]`, "insert", `{"a":[1,2]}`},
	} {
		out := runYAMLEdit(t, yamlEditFixture, c.path, c.op, c.value)
		if !out.OK {
			t.Errorf("%s %s refused: %s %s", c.op, c.path, out.Code, out.Message)
			continue
		}
		if !strings.Contains(out.Text, "# keep this comment") || !strings.HasPrefix(out.Text, "# my config\n") {
			t.Errorf("%s %s lost a comment:\n%s", c.op, c.path, out.Text)
		}
	}
}

func TestEditYAMLEdgeCases(t *testing.T) {
	cjk := "代理组:\n  名字: 香港节点   # 注释\n"
	mustEdit(t, cjk, `["代理组","名字"]`, "set", `"日本节点"`, "代理组:\n  名字: 日本节点   # 注释\n")
	quoted := "\"weird key\": 1\nb: 2\n"
	mustEdit(t, quoted, `["weird key"]`, "set", `3`, "\"weird key\": 3\nb: 2\n")
	flow := "tun:\n  dns-hijack: [any:53]\n  stack: gvisor\n"
	mustEdit(t, flow, `["tun","dns-hijack"]`, "set", `["tcp://any:53"]`,
		"tun:\n  dns-hijack:\n    - tcp://any:53\n  stack: gvisor\n")
	block := "script:\n  code: |\n    line one\n    line two\nmode: rule\n"
	mustEdit(t, block, `["script","code"]`, "set", `"x"`, "script:\n  code: x\nmode: rule\n")
	items := "rules:\n  - A,1,X\n  - B,2,Y   # b\n  - C,3,Z\n"
	mustEdit(t, items, `["rules",2]`, "move", `0`, "rules:\n  - C,3,Z\n  - A,1,X\n  - B,2,Y   # b\n")
	empty := "dns: {}\nmode: rule\n"
	mustEdit(t, empty, `["dns","enable"]`, "insert", `true`, "dns:\n  enable: true\nmode: rule\n")
	flat := "rules:\n- A,1,X\n- B,2,Y\n"
	mustEdit(t, flat, `["rules",1]`, "insert", `"C,3,Z"`, "rules:\n- A,1,X\n- C,3,Z\n- B,2,Y\n")
}

func TestEditYAMLReviewCases(t *testing.T) {
	mustEdit(t, "x: 0\n", `["x"]`, "set", `9007199254740993`, "x: 9007199254740993\n")
	if out := runYAMLEdit(t, "x: 0\n", `["x"]`, "set", `123456789012345678901234567890`); out.OK || out.Code != "invalidRequest" {
		t.Errorf("an integer past 64 bits: ok=%v code=%q", out.OK, out.Code)
	}
	mustEdit(t, "name: don't # keep\n", `["name"]`, "set", `"new"`, "name: new # keep\n")
	mustEdit(t, `a: "say \"hi\"" # keep`+"\n", `["a"]`, "set", `1`, "a: 1 # keep\n")
	mustEdit(t, "a: 'it''s' # keep\n", `["a"]`, "set", `1`, "a: 1 # keep\n")
	mustEdit(t, "rules:\n  # keep this explanation\n  - MATCH,DIRECT\nmode: rule\n", `["rules",0]`, "delete", ``,
		"rules: []\n  # keep this explanation\nmode: rule\n")
	mustEdit(t, "script: |\n  # actual scalar content\nmode: rule\n", `["script"]`, "set", `"x"`, "script: x\nmode: rule\n")
}

func TestYAMLOutlineCountsBlockScalarContent(t *testing.T) {
	outline, err := yamlOutline("script: |\n  # actual scalar content\nmode: rule\n")
	if err != nil {
		t.Fatal(err)
	}
	if outline.Sections[0].Key != "script" || outline.Sections[0].End != 2 {
		t.Fatalf("script section: %+v", outline.Sections[0])
	}
}

func TestEditYAMLSelfCheckRefusesAWrongSurgery(t *testing.T) {
	for name, fault := range map[string]func(string) string{
		"another value changed": func(text string) string { return strings.Replace(text, "log-level: info", "log-level: debug", 1) },
		"a key lost":            func(text string) string { return strings.Replace(text, "log-level: info\n", "", 1) },
		"does not parse":        func(text string) string { return text + "\t: [\n" },
		"target not changed":    func(text string) string { return strings.Replace(text, "mode: global", "mode: rule", 1) },
	} {
		yamlEditSurgeryFault = fault
		out := runYAMLEdit(t, yamlEditFixture, `["mode"]`, "set", `"global"`)
		yamlEditSurgeryFault = nil
		if out.OK || out.Code != "unsafeEdit" {
			t.Errorf("%s: ok=%v code=%q, want unsafeEdit", name, out.OK, out.Code)
		}
	}
	if out := runYAMLEdit(t, yamlEditFixture, `["mode"]`, "set", `"global"`); !out.OK {
		t.Fatalf("control: the same edit without a fault succeeds: %+v", out)
	}
}

func TestEditYAMLFableReviewCases(t *testing.T) {
	mustEdit(t, "s:\n  c: |\n    one\n    # two\nm: r\n", `["s","c"]`, "set", `"x"`, "s:\n  c: x\nm: r\n")
	mustEdit(t, "s:\n  c: |\n    one\n    # two\n  d: 1\nm: r\n", `["s","c"]`, "delete", ``, "s:\n  d: 1\nm: r\n")
	for _, original := range []string{"k: \"abc\n  # def\"\nm: r\n", "k: \"abc\n# def\"\nm: r\n", "a:\n  k: \"abc\n  # def\"\n  m: r\n", "k: 'abc\n# def'\nm: r\n"} {
		path := `["k"]`
		if strings.HasPrefix(original, "a:") {
			path = `["a","k"]`
		}
		if out := runYAMLEdit(t, original, path, "set", `"new"`); out.OK || out.Code != "unsupportedStyle" {
			t.Errorf("%q: ok=%v code=%q text=%q, want unsupportedStyle", original, out.OK, out.Code, out.Text)
		}
	}
	mustEdit(t, "name: John's proxy   # main\n", `["name"]`, "set", `"other"`, "name: other   # main\n")
	mustEdit(t, `k: "a \" # b" # c`+"\n", `["k"]`, "set", `"x"`, "k: x # c\n")
}

func TestEditYAMLReviewTwoCases(t *testing.T) {
	mustEdit(t, "mixed-port: 7890\n  # or 7891\nmode: rule\n", `["mixed-port"]`, "set", `7891`, "mixed-port: 7891\n  # or 7891\nmode: rule\n")
	mustEdit(t, "rules:\n  - A\n    # about A\n  - B\n", `["rules",0]`, "set", `"C"`, "rules:\n  - C\n    # about A\n  - B\n")
	mustEdit(t, "rules:\n  - A\n    # keep\nmode: rule\n", `["rules",0]`, "delete", ``, "rules: []\n    # keep\nmode: rule\n")
	mustEdit(t, "items:\n  - name: x\n    script: |\n      # content\n  - name: y\n", `["items",0]`, "delete", ``, "items:\n  - name: y\n")
	mustEdit(t, "k: foo,'bar # keep\n", `["k"]`, "set", `"new"`, "k: new # keep\n")
	mustEdit(t, "k: a['b # keep\n", `["k"]`, "set", `"new"`, "k: new # keep\n")
	mustEdit(t, `k: {"a":"x # y"} # keep`+"\n", `["k"]`, "set", `"new"`, "k: new # keep\n")
	for _, path := range []string{`["rules",0.5]`, `["rules",1e10]`} {
		if out := runYAMLEdit(t, "rules:\n  - A\n  - B\n", path, "move", `1`); out.OK || out.Code != "invalidRequest" {
			t.Errorf("%s: ok=%v code=%q, want invalidRequest", path, out.OK, out.Code)
		}
	}
}

func TestEditYAMLReviewThreeCases(t *testing.T) {
	for _, c := range []struct{ original, path, op, value string }{
		{"k: \"abc\n# def\"\nm: r\n", `["k"]`, "delete", ``},
		{"a:\n  k: \"abc\n  # def\"\n  m: r\n", `["a","k"]`, "delete", ``},
		{"rules:\n  - \"abc\n  # def\"\n  - B\n", `["rules",0]`, "set", `"C"`},
		{"rules:\n  - \"abc\n  # def\"\n  - B\n", `["rules",0]`, "delete", ``},
		{"rules:\n  - \"abc\n  # def\"\nmode: rule\n", `["rules",0]`, "delete", ``},
	} {
		if out := runYAMLEdit(t, c.original, c.path, c.op, c.value); out.OK {
			t.Errorf("%s %s on %q returned %q", c.op, c.path, c.original, out.Text)
		}
	}
	mustEdit(t, "k: [foo:'bar] # keep\n", `["k"]`, "set", `"new"`, "k: new # keep\n")
	mustEdit(t, "items:\n  - name: x\n    script: |\n      body\n    # keep\n  - name: y\n", `["items",0]`, "delete", ``,
		"items:\n    # keep\n  - name: y\n")
	for _, path := range []string{`["rules",1.0000000000000001]`, `["rules",1e-400]`, `["rules",1.0]`} {
		if out := runYAMLEdit(t, "rules:\n  - A\n  - B\n", path, "set", `"C"`); out.OK || out.Code != "invalidRequest" {
			t.Errorf("%s: ok=%v code=%q", path, out.OK, out.Code)
		}
	}
}

func TestEditYAMLReviewFourCases(t *testing.T) {
	mustEdit(t, "k: 1 # keep  \n", `["k"]`, "set", `2`, "k: 2 # keep  \n")
	mustEdit(t, "k: v # c\t\n", `["k"]`, "set", `"w"`, "k: w # c\t\n")
	mustEdit(t, "rules:\n  - name: n   # c  \n", `["rules",0,"name"]`, "set", `"m"`, "rules:\n  - name: m   # c  \n")
	mustEdit(t, "rules:\n  - A # keep\n  - B\n", `["rules",0]`, "set", `"C"`, "rules:\n  - C # keep\n  - B\n")
	mustEdit(t, "items:\n  - name: first\n    script: |\n      body\n     # keep\n  - name: second\n", `["items",0]`, "delete", ``,
		"items:\n     # keep\n  - name: second\n")
	mustEdit(t, "proxies:\n  - name: \"a\"\n    type: direct\n", `["proxies",0,"type"]`, "set", `"reject"`,
		"proxies:\n  - name: \"a\"\n    type: reject\n")
	mustEdit(t, "items:\n  - tags: [a]\n    script: |\n      body\n  - name: second\n", `["items",0]`, "delete", ``,
		"items:\n  - name: second\n")
	mustEdit(t, "%TAG !e! tag:example.com,2026:\n---\nk: !e!thing [a, b]\nm: r\n", `["m"]`, "set", `"s"`,
		"%TAG !e! tag:example.com,2026:\n---\nk: !e!thing [a, b]\nm: s\n")
	if out := runYAMLEdit(t, "mode: rule\n", `["mode"] garbage`, "set", `"global"`); out.OK || out.Code != "invalidRequest" {
		t.Errorf("trailing path data: ok=%v code=%q", out.OK, out.Code)
	}
}

func TestEditYAMLReviewFiveCases(t *testing.T) {
	mustEdit(t, "s: |2\n     deep first\n  # content at col 3\nm: r\n", `["s"]`, "set", `"x"`, "s: x\nm: r\n")
	mustEdit(t, "items:\n  - script: |2\n        body\n      # content\n  - name: second\n", `["items",0]`, "delete", ``, "items:\n  - name: second\n")
	mustEdit(t, "script: |2\n # keep\nmode: rule\n", `["script"]`, "set", `"x"`, "script: x\n # keep\nmode: rule\n")
	mustEdit(t, "rules:\n  - \"A\"# keep\n", `["rules",0]`, "set", `"C"`, "rules:\n  - C # keep\n")
	mustEdit(t, "k: \"A\"# keep\n", `["k"]`, "set", `"C"`, "k: C # keep\n")
	mustEdit(t, "rules:\n  - A # keep\n  - B\n", `["rules",0]`, "set", `{"a":1}`, "rules:\n  - a: 1 # keep\n  - B\n")
	if out := runYAMLEdit(t, "%TAG !e! tag:example.com,2026:\n---\nk: !e!thing \"abc\n# def\"\nm: r\n", `["k"]`, "delete", ``); out.OK {
		t.Errorf("a tagged quoted continuation was cut: %q", out.Text)
	}
	mustEdit(t, "items:\n  - tags: [a]\n    script: |\n      body", `["items",0,"tags"]`, "set", `["b"]`,
		"items:\n  - tags:\n      - b\n    script: |\n      body")
	if _, err := yamlOutline("k: \"abc\n# def\"\nm: r\n"); err == nil {
		t.Errorf("the outline reported a quoted continuation as one line")
	}
}

func TestEditYAMLReviewSixCases(t *testing.T) {
	mustEdit(t, "s: !!str |2\n # keep\nm: r\n", `["s"]`, "delete", ``, " # keep\nm: r\n")
	mustEdit(t, "s: !!str |2\n     deep\n  # content\nm: r\n", `["s"]`, "delete", ``, "m: r\n")
	mustEdit(t, "items:\n  - tags: [a]\n    script: |+\n      body\n\n  - name: second\n", `["items",0]`, "delete", ``, "items:\n  - name: second\n")
	outline, err := yamlOutline("items:\n  - tags: [a]\n    script: |+\n      body\n\n  - name: second\n")
	if err != nil || outline.Sections[0].Items[0].End != 5 {
		t.Errorf("keep-chomping item range: %+v %v", outline, err)
	}
	for _, original := range []string{"k: &a \"abc\n# def\"\nm: r\n", "k: &a [\"abc\n# def\"]\nm: r\n"} {
		if _, err := yamlOutline(original); err == nil {
			t.Errorf("outline of %q reported a truncated range", original)
		}
	}
	mustEdit(t, "\ufeff%TAG !e! tag:example.com,2026:\n---\nitems:\n  - tag: !e!thing [a]\n    name: old\n# keep\nmode: rule\n",
		`["items",0,"name"]`, "set", `"new"`,
		"\ufeff%TAG !e! tag:example.com,2026:\n---\nitems:\n  - tag: !e!thing [a]\n    name: new\n# keep\nmode: rule\n")
}

func TestEditYAMLReviewSevenCases(t *testing.T) {
	mustEdit(t, "s:\n  c: |+\n    body\n  # note about d\n\n  d: 1\n", `["s","c"]`, "delete", ``, "s:\n  # note about d\n\n  d: 1\n")
	mustEdit(t, "script: |+\n  body\n# section comment\n\nmode: rule\n", `["script"]`, "delete", ``, "# section comment\n\nmode: rule\n")
	outline, err := yamlOutline("script: |+\n  body\n# section comment\n\nmode: rule\n")
	if err != nil || outline.Sections[0].End != 2 {
		t.Errorf("script range: %+v %v", outline, err)
	}
	mustEdit(t, "l:\n  - |+\n    A\n  # about B\n\n  - B\n", `["l",0]`, "delete", ``, "l:\n  # about B\n\n  - B\n")
	mustEdit(t, "script: |+\n  body\n\n\nmode: rule\n", `["script"]`, "delete", ``, "mode: rule\n")
}

func TestCompileCheckPlacesGroupDuplicates(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "proxy-groups:\n", "proxy-groups:\n  - {name: a, type: select, proxies: [DIRECT]}\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section == "" {
		t.Errorf("a group named like a node: %+v", answer)
	}
}

func TestEditYAMLCodexReviewSevenCases(t *testing.T) {
	mustEdit(t, "s: |+\n  body\n\n# keep\n\nm: r\n", `["s"]`, "delete", ``, "# keep\n\nm: r\n")
	mustEdit(t, "s: !foo+bar |-\n  body\n\nm: r\n", `["s"]`, "delete", ``, "\nm: r\n")
	if out := runYAMLEdit(t, "s: !!str\n  |4\n   # keep\nm: r\n", `["s"]`, "delete", ``); out.OK {
		t.Errorf("a split block scalar header was edited: %q", out.Text)
	}
}

func TestCompileCheckCodexReviewSevenCases(t *testing.T) {
	setupForEditingFuzz(t)
	crafted := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: 'group[0]: Proxy: proxy Proxy not found', type: direct}\n  - {name: 'group[0]: Proxy: proxy Proxy not found', type: direct}\n", 1)
	answer := runCompileCheck(t, crafted)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxies" || answer.Errors[0].Index == nil || *answer.Errors[0].Index != 1 {
		t.Errorf("crafted duplicate: %+v", answer)
	}
	provider := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: 'provider victim error', type: direct}\n  - {name: 'provider victim error', type: direct}\n", 1)
	if answer := runCompileCheck(t, provider); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxies" {
		t.Errorf("duplicate named like a provider sentence: %+v", answer)
	}
	bogus := strings.Replace(compileCheckBase, "    type: select\n", "    type: \"bogus is the duplicate name\"\n", 1)
	if answer := runCompileCheck(t, bogus); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxy-groups" {
		t.Errorf("group type error: %+v", answer)
	}
}

func TestEditYAMLBlockScalarEndsAtTheFirstShallowerLine(t *testing.T) {
	mustEdit(t, "s: |+\n  body\n\n# outside\n  # also outside\n\nm: r\n", `["s"]`, "delete", ``, "# outside\n  # also outside\n\nm: r\n")
}

func TestEditYAMLReviewNineCases(t *testing.T) {
	for _, original := range []string{"? s\n: |2\n  body\nm: r\n", "l:\n  - ? s\n    : |2\n      body\nm: r\n"} {
		path := `["s"]`
		if strings.HasPrefix(original, "l:") {
			path = `["l",0,"s"]`
		}
		if out := runYAMLEdit(t, original, path, "delete", ``); out.OK || out.Code != "unsupportedStyle" {
			t.Errorf("explicit key %q: ok=%v code=%q", original, out.OK, out.Code)
		}
	}
	mustEdit(t, "s: |\n  \u00a0\n    deeper\n  body\nm: r\n", `["s"]`, "delete", ``, "m: r\n")
}

func TestEditYAMLRefusesUnicodeLineSeparators(t *testing.T) {
	for _, original := range []string{"l:\n  - A\n\u0085# keep\n", "k: 1\n\u2028# keep\n", "k: 1\n\u2029m: 2\n"} {
		if out := runYAMLEdit(t, original, `["k"]`, "set", `2`); out.OK || out.Code != "unsupportedStyle" {
			t.Errorf("%q: ok=%v code=%q", original, out.OK, out.Code)
		}
	}
	if _, err := yamlOutline("l:\n  - A\n\u0085# keep\n"); err == nil {
		t.Errorf("outline of a NEL text")
	}
}

func TestEditorExportsAnswerTextWithUnicodeLineSeparators(t *testing.T) {
	original := "k: \"a b\"\nm: r\nz: 1\n"
	if out := runYAMLEdit(t, original, `["m"]`, "set", `"s"`); out.OK || out.Code != "unsupportedStyle" {
		t.Errorf("ok=%v code=%q message=%q", out.OK, out.Code, out.Message)
	}
	if box, err := YAMLOutlineForIOS(original); err == nil && !strings.Contains(box.Value, "unsupportedStyle") {
		t.Errorf("outline: %s", box.Value)
	}
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "mode: rule\n", "mode: rule\nx-note: \"a b\"\n", 1)
	document = strings.Replace(document, "  - MATCH,DIRECT\n", "  - DOMAIN,b.com,Nowhere\n", 1)
	box, err := CompileCheckForIOS(document, "")
	if err != nil || !strings.Contains(box.Value, "Nowhere") {
		t.Errorf("compile check: %v %v", box, err)
	}
}

func TestEditYAMLRefusesDocumentEndMarker(t *testing.T) {
	for _, original := range []string{"a: 1\nb: 2\n...\n", "a: 1\n... # end\n# tail\n"} {
		if out := runYAMLEdit(t, original, `["a"]`, "set", `3`); out.OK || out.Code != "unsupportedStyle" {
			t.Errorf("%q: ok=%v code=%q", original, out.OK, out.Code)
		}
	}
	mustEdit(t, "s: |\n  ...\nm: r\n", `["m"]`, "set", `"x"`, "s: |\n  ...\nm: x\n")
}

func TestEditYAMLCodexReviewElevenCases(t *testing.T) {
	mustEdit(t, "\ufeffk:\nm: r\n", `["k"]`, "set", `2`, "\ufeffk: 2\nm: r\n")
	mustEdit(t, "\ufeffk: |\n  body\nm: r\n", `["k"]`, "delete", ``, "\ufeffm: r\n")
	mustEdit(t, "\ufeffk: 1   # c\nm: r\n", `["k"]`, "set", `2`, "\ufeffk: 2   # c\nm: r\n")
	mustEdit(t, "a: 1\nb: 2\n", `["b"]`, "delete", ``, "a: 1\n")
	if out := runYAMLEdit(t, "a: 1\nb: 2\n... # end\n# tail\n", `["b"]`, "delete", ``); out.OK {
		t.Errorf("a document-end marker was deleted with b: %q", out.Text)
	}
	setupForEditingFuzz(t)
	for _, document := range []string{"mode: rule\u2029\u2029bad: @\n", "mode: rule\u0085\u0085bad: @\n"} {
		answer := runCompileCheck(t, document)
		if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Line != 0 {
			t.Errorf("%q: %+v", document, answer)
		}
	}
}

func TestEditYAMLCodexReviewTwelveCases(t *testing.T) {
	if out := runYAMLEdit(t, "a: 1\n\ufeff# keep\nb: 2\n", `["a"]`, "delete", ``); out.OK || out.Code != "unsupportedStyle" {
		t.Errorf("a mid-text BOM: ok=%v code=%q", out.OK, out.Code)
	}
	mustEdit(t, "s: |2\n  body\n    \nm: r\n", `["s"]`, "delete", ``, "m: r\n")
	outline, err := yamlOutline("s: |2\n  body\n    \nm: r\n")
	if err != nil || outline.Sections[0].End != 3 {
		t.Errorf("white-space content range: %+v %v", outline, err)
	}
	if out := runYAMLEdit(t, "a: 1\n?\n  s\n: 2\nm: r\n", `["m"]`, "set", `"x"`); out.OK || out.Code != "unsupportedStyle" {
		t.Errorf("an explicit key on its own line: ok=%v code=%q", out.OK, out.Code)
	}
	mustEdit(t, "\"a:b\": 1\nm: r\n", `["m"]`, "set", `"x"`, "\"a:b\": 1\nm: x\n")
}

func TestEditYAMLExplicitKeyFoundByItsIndicator(t *testing.T) {
	for _, original := range []string{"?\n  s # : keep\n: 2\nm: r\n", "? # why\n  s\n: 2\nm: r\n", "l:\n  - ?\n    s\n    : 2\n"} {
		if out := runYAMLEdit(t, original, `["m"]`, "set", `"x"`); out.OK {
			t.Errorf("%q was edited: %q", original, out.Text)
		}
	}
	mustEdit(t, "a: what?\nb: 1\n", `["b"]`, "set", `2`, "a: what?\nb: 2\n")
	mustEdit(t, "a:\n  - x\n# note?\nb: 1\n", `["b"]`, "set", `2`, "a:\n  - x\n# note?\nb: 2\n")
}

func TestEditYAMLBlockScalarQuestionMarkIsContent(t *testing.T) {
	mustEdit(t, "s: |\n  ?\nb: 1\n", `["b"]`, "set", `2`, "s: |\n  ?\nb: 2\n")
	mustEdit(t, "s: >\n  - ?\nb: 1\n", `["b"]`, "set", `2`, "s: >\n  - ?\nb: 2\n")
	mustEdit(t, "a:\n  s: |\n    ?\n  t: 1\n", `["a","t"]`, "set", `2`, "a:\n  s: |\n    ?\n  t: 2\n")
	original := "l:\n  - ?\n      s\n    : 2\n"
	if out := runYAMLEdit(t, original, `["l",0,"s"]`, "set", `3`); out.OK || out.Code != "unsupportedStyle" {
		t.Errorf("an explicit key in a list: ok=%v code=%q message=%q", out.OK, out.Code, out.Message)
	}
}

func TestEditYAMLQuestionMarkInsideValuesIsNotAnIndicator(t *testing.T) {
	mustEdit(t, "a: what\n  ?\nb: 1\n", `["b"]`, "set", `2`, "a: what\n  ?\nb: 2\n")
	mustEdit(t, "a: \"what\n? # text\"\nb: 1\n", `["b"]`, "set", `2`, "a: \"what\n? # text\"\nb: 2\n")
	mustEdit(t, "a: [\"what\n? # text\"]\nb: 1\n", `["b"]`, "set", `2`, "a: [\"what\n? # text\"]\nb: 2\n")
	for _, original := range []string{"\"a:b\": 1\nm: r\n", "'it''s': 1\nm: r\n", "\"k\\\"q\" : 1\nm: r\n", "&x k: 1\nm: r\n", "!!str k: 1\nm: r\n", "k\t: 1\nm: r\n"} {
		out := runYAMLEdit(t, original, `["m"]`, "set", `"x"`)
		if !out.OK {
			t.Errorf("%q refused: %s %s", original, out.Code, out.Message)
		}
	}
}

func TestEditYAMLAnchorNameEndsBeforeTheColon(t *testing.T) {
	mustEdit(t, "!!str &a: 1\nm: r\n", `["m"]`, "set", `"x"`, "!!str &a: 1\nm: x\n")
	mustEdit(t, "&a-b_1 k: 1\nm: r\n", `["m"]`, "set", `"x"`, "&a-b_1 k: 1\nm: x\n")
}

func TestEditYAMLChainedEditsMatchFreshEdits(t *testing.T) {
	var b strings.Builder
	b.WriteString("# head\nmode: rule\ndns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\nproxies:\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "  - {name: \"n%d\", type: direct}\n", i)
	}
	b.WriteString("rules:\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "  - DOMAIN,s%d.test,DIRECT   # r%d\n", i, i)
	}
	steps := []struct{ path, op, value string }{
		{`["rules",3]`, "set", `"DOMAIN,a.test,DIRECT"`},
		{`["rules",0]`, "insert", `"MATCH,DIRECT"`},
		{`["rules",10]`, "move", `2`},
		{`["rules",59]`, "delete", ``},
		{`["dns","nameserver",0]`, "set", `"8.8.8.8"`},
		{`["dns","ipv6"]`, "insert", `false`},
		{`["proxies",3]`, "set", `{"name":"x","type":"direct"}`},
		{`["mode"]`, "set", `"global"`},
		{`["new-key"]`, "insert", `{"a":[1,2]}`},
		{`["new-key"]`, "delete", ``},
		{`["rules",999]`, "set", `"x"`},
	}
	chained := b.String()
	fresh := chained
	for _, step := range steps {
		gotChained, errChained := editYAML(chained, step.path, step.op, step.value)
		rememberParsedYAML(nil)
		gotFresh, errFresh := editYAML(fresh, step.path, step.op, step.value)
		rememberParsedYAML(nil)
		if (errChained == nil) != (errFresh == nil) || gotChained != gotFresh {
			t.Fatalf("%s %s: chained %q %v, fresh %q %v", step.op, step.path, gotChained, errChained, gotFresh, errFresh)
		}
		if errChained == nil {
			if _, err := editYAML(gotChained, `["mode"]`, "set", `"rule"`); err != nil {
				t.Fatal(err)
			}
			chained, _ = editYAML(gotChained, `["mode"]`, "set", `"rule"`)
			fresh = chained
		}
	}
}

func TestEditYAMLConcurrentEditsOfOneText(t *testing.T) {
	original := yamlEditFixture
	want, err := editYAML(original, `["rules",1]`, "set", `"GEOIP,US,Proxy"`)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if got, err := editYAML(original, `["rules",1]`, "set", `"GEOIP,US,Proxy"`); err != nil || got != want {
					t.Errorf("%v %q", err, got)
					return
				}
				if next, err := editYAML(want, `["mode"]`, "set", `"global"`); err != nil || !strings.Contains(next, "mode: global") {
					t.Errorf("%v %q", err, next)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEditYAMLNarrowedSelfCheckSeesTheChangedLines(t *testing.T) {
	for _, c := range []struct {
		name, original, path, op, value string
		fault                           func(string) string
	}{
		{"inserted value", "mode: rule\nlog-level: info\n", `["log-level"]`, "insertBefore", `{"key":"x","value":1}`,
			func(text string) string { return strings.Replace(text, "x: 1", "x: 2", 1) }},
		{"renamed value", "mode: rule\nlog-level: info\n", `["mode"]`, "rename", `"m"`,
			func(text string) string { return strings.Replace(text, "m: rule", "m: global", 1) }},
		{"residue in the previous entry", "proxies:\n  - a\nrules:\n  - MATCH,DIRECT\n", `["rules"]`, "delete", ``,
			func(text string) string { return text + "  - MATCH,DIRECT\n" }},
	} {
		yamlEditSurgeryFault = c.fault
		out := runYAMLEdit(t, c.original, c.path, c.op, c.value)
		yamlEditSurgeryFault = nil
		if out.OK || out.Code != "unsafeEdit" {
			t.Errorf("%s: %+v, want unsafeEdit", c.name, out)
		}
		if control := runYAMLEdit(t, c.original, c.path, c.op, c.value); !control.OK {
			t.Errorf("%s control: %+v", c.name, control)
		}
	}
}

func TestEditYAMLCacheLetsGoOfTheTreeWhenIdle(t *testing.T) {
	previous := parsedYAMLCacheIdle
	parsedYAMLCacheIdle = 20 * time.Millisecond
	defer func() { parsedYAMLCacheIdle = previous }()
	if out := runYAMLEdit(t, yamlEditFixture, `["mode"]`, "set", `"global"`); !out.OK {
		t.Fatalf("%+v", out)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		parsedYAMLCacheMu.Lock()
		cache, timer := parsedYAMLCache, parsedYAMLCacheTimer
		parsedYAMLCacheMu.Unlock()
		if cache == nil && timer == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still held: cache %v, timer %v", cache != nil, timer != nil)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEditYAMLNarrowedSelfCheckRefusesDuplicatedKeys(t *testing.T) {
	yamlEditSurgeryFault = func(string) string { return "b: 1\nb: 1\n" }
	out := runYAMLEdit(t, "a: 1\nb: 1\n", `["a"]`, "set", `2`)
	yamlEditSurgeryFault = nil
	if out.OK || out.Code != "unsafeEdit" {
		t.Errorf("%+v", out)
	}
}

func TestEditYAMLInsertFillsAnEmptySection(t *testing.T) {
	group := `{"name":"G","type":"select","proxies":["DIRECT"]}`
	want := "  - name: G\n    type: select\n    proxies:\n      - DIRECT\n"
	mustEdit(t, "mode: rule\nproxy-groups:\nrules: []\n", `["proxy-groups",0]`, "insert", group,
		"mode: rule\nproxy-groups:\n"+want+"rules: []\n")
	mustEdit(t, "proxy-groups: ~ # none yet\n", `["proxy-groups",0]`, "insert", group, "proxy-groups: # none yet\n"+want)
	mustEdit(t, "dns:\n", `["dns","enable"]`, "insert", `true`, "dns:\n  enable: true\n")
	if out := runYAMLEdit(t, "proxy-groups:\n", `["proxy-groups",1]`, "insert", group); out.OK {
		t.Errorf("index 1 of an empty section: %+v", out)
	}
}

func TestEditYAMLInsertBuildsAMissingSection(t *testing.T) {
	original := "mode: rule # keep\nproxies:\n  - {name: a, type: direct}\n"
	for _, c := range []struct{ path, value, want string }{
		{`["proxy-groups",0]`, `{"name":"G","type":"select","proxies":["a"]}`, "proxy-groups:\n"},
		{`["rule-providers","ads"]`, `{"type":"inline","behavior":"domain","payload":["a.test"]}`, "rule-providers:\n"},
		{`["sub-rules","s1"]`, `["MATCH,DIRECT"]`, "sub-rules:\n"},
	} {
		out := runYAMLEdit(t, original, c.path, "insert", c.value)
		if !out.OK || !strings.HasPrefix(out.Text, original) || !strings.Contains(out.Text, c.want) {
			t.Errorf("%s: %+v", c.path, out)
		}
	}
	if out := runYAMLEdit(t, original, `["proxy-groups",1]`, "insert", `{"name":"G"}`); out.OK || out.Code != "notFound" {
		t.Errorf("index 1 of a missing section: %+v", out)
	}
	if out := runYAMLEdit(t, original, `["proxies",1]`, "insert", `{"name":"b","type":"direct"}`); !out.OK || strings.Count(out.Text, "proxies:") != 1 {
		t.Errorf("existing section: %+v", out)
	}
}

func TestEditYAMLWritesKeysInTheRequestsOrder(t *testing.T) {
	original := "mode: rule\nproxies:\n  - {name: a, type: direct}\nlog-level: info\n"
	value := `{"name":"b","type":"ss","server":"192.0.2.1","port":443,"cipher":"aes-128-gcm","password":"0123","udp":true}`
	want := "  - name: b\n    type: ss\n    server: 192.0.2.1\n    port: 443\n    cipher: aes-128-gcm\n    password: \"0123\"\n    udp: true\n"
	for _, c := range []struct{ path, op, value string }{
		{`["proxies",1]`, "insert", value},
	} {
		if out := runYAMLEdit(t, original, c.path, c.op, c.value); !out.OK || !strings.Contains(out.Text, want) {
			t.Errorf("%s %s: %+v", c.op, c.path, out)
		}
	}
	if out := runYAMLEdit(t, original, `["proxies",0]`, "set", value); !out.OK || !strings.Contains(out.Text, want) {
		t.Errorf("set: %+v", out)
	}
	if out := runYAMLEdit(t, original, `["log-level"]`, "insertBefore", `{"key":"dns","value":{"enable":true,"nameserver":["1.1.1.1"],"ipv6":false}}`); !out.OK ||
		!strings.Contains(out.Text, "dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n  ipv6: false\nlog-level: info\n") {
		t.Errorf("insertBefore: %+v", out)
	}
	if out := runYAMLEdit(t, "mode: rule\n", `["proxy-groups",0]`, "insert", `{"name":"G","type":"select","proxies":["b","a"]}`); !out.OK ||
		!strings.HasSuffix(out.Text, "proxy-groups:\n  - name: G\n    type: select\n    proxies:\n      - b\n      - a\n") {
		t.Errorf("new section: %+v", out)
	}
}

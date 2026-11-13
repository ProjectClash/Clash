package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const flowSubscription = `# subscription
mixed-port: 7890
proxies:
  - {name: 🇭🇰 HK 中转 ⚡️, server: hk.example.com, port: 443, type: trojan, password: "pa,ss", udp: true, sni: www.example.com, skip-cert-verify: true}
  - {name: 🇯🇵 日本 02, server: jp.example.com, port: 8388, type: ss, cipher: chacha20-ietf-poly1305, password: 'it''s', udp: true}
  - {name: 🇹🇼 TW ⚡️〽️, dialer-proxy: 🇭🇰 HK 中转 ⚡️, type: vless, server: 198.51.100.20, port: 443, uuid: 00000000-0000-4000-8000-000000000001, network: grpc, tls: true, flow: "", client-fingerprint: firefox, servername: www.example.org, grpc-opts: {grpc-service-name: grpc}, reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: ""}, ip-version: ipv4-prefer, tfo: false, udp: true}
  - name: block
    type: direct
proxy-groups:
  - {name: PROXY, type: select, proxies: [🇭🇰 HK 中转 ⚡️, 🇯🇵 日本 02, 🇹🇼 TW ⚡️〽️]}
rules:
  - MATCH,PROXY
`

func lineOf(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line starts with %q in:\n%s", prefix, text)
	return ""
}

func mustEditLine(t *testing.T, path, op, value, prefix, want string) string {
	t.Helper()
	out := runYAMLEdit(t, flowSubscription, path, op, value)
	if !out.OK {
		t.Fatalf("%s %s refused: %s %s", op, path, out.Code, out.Message)
	}
	before := lineOf(t, flowSubscription, prefix)
	if got := strings.Replace(flowSubscription, before, want, 1); out.Text != got {
		t.Fatalf("%s %s:\n--- got ---\n%s\n--- want ---\n%s", op, path, out.Text, got)
	}
	return out.Text
}

func TestAFlowNodeGetsItsDialerProxySetAddedAndTakenAway(t *testing.T) {
	mustEditLine(t, `["proxies",1,"dialer-proxy"]`, "insert", `"🇭🇰 HK 中转 ⚡️"`, "  - {name: 🇯🇵",
		`  - {name: 🇯🇵 日本 02, server: jp.example.com, port: 8388, type: ss, cipher: chacha20-ietf-poly1305, password: 'it''s', udp: true, dialer-proxy: 🇭🇰 HK 中转 ⚡️}`)
	long := lineOf(t, flowSubscription, "  - {name: 🇹🇼")
	mustEditLine(t, `["proxies",2,"dialer-proxy"]`, "set", `"🇯🇵 日本 02"`, "  - {name: 🇹🇼",
		strings.Replace(long, "dialer-proxy: 🇭🇰 HK 中转 ⚡️,", "dialer-proxy: 🇯🇵 日本 02,", 1))
	mustEditLine(t, `["proxies",2,"dialer-proxy"]`, "delete", ``, "  - {name: 🇹🇼",
		strings.Replace(long, " dialer-proxy: 🇭🇰 HK 中转 ⚡️,", "", 1))
	trojan := lineOf(t, flowSubscription, "  - {name: 🇭🇰")
	mustEditLine(t, `["proxies",0,"skip-cert-verify"]`, "delete", ``, "  - {name: 🇭🇰",
		strings.Replace(trojan, ", skip-cert-verify: true}", "}", 1))
	mustEditLine(t, `["proxies",0,"name"]`, "delete", ``, "  - {name: 🇭🇰",
		strings.Replace(trojan, "{name: 🇭🇰 HK 中转 ⚡️, ", "{", 1))
}

func TestAValueInAFlowNodeIsWrittenSoItReadsBackTheSame(t *testing.T) {
	for _, value := range []string{
		"🇭🇰 HK 中转 ⚡️", "a,b", "[x]", "{y}", "k: v", "x #y", `say "hi"`, "it's", "#first", "*star", "&amp",
		"!bang", "- dash", "? q", "@at", "`tick`", "%pct", "|pipe", ">gt", "", " lead", "trail ", "123", "true",
		"null", "~", "0x1F", "1e3", "🇯🇵 东京, 01: \"VIP\" #1", strings.Repeat("长名字 ", 40),
	} {
		valueJSON := jsonString(t, value)
		out := runYAMLEdit(t, flowSubscription, `["proxies",1,"dialer-proxy"]`, "insert", valueJSON)
		if !out.OK {
			t.Errorf("insert %q refused: %s %s", value, out.Code, out.Message)
			continue
		}
		line := lineOf(t, out.Text, "  - {name: 🇯🇵")
		if !strings.HasPrefix(line, "  - {name: 🇯🇵 日本 02, server: jp.example.com, port: 8388, type: ss, cipher: chacha20-ietf-poly1305, password: 'it''s', udp: true, dialer-proxy: ") ||
			!strings.HasSuffix(line, "}") {
			t.Errorf("insert %q wrote the line %q", value, line)
		}
		var read struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(out.Text), &read); err != nil || read.Proxies[1]["dialer-proxy"] != value {
			t.Errorf("insert %q reads back as %#v (%v)", value, read.Proxies[1]["dialer-proxy"], err)
		}
		if strings.Count(out.Text, "\n") != strings.Count(flowSubscription, "\n") {
			t.Errorf("insert %q changed the number of lines", value)
		}
	}
}

func TestFieldsNestedInAFlowNodeAreEditedInPlace(t *testing.T) {
	long := lineOf(t, flowSubscription, "  - {name: 🇹🇼")
	mustEditLine(t, `["proxies",2,"reality-opts","short-id"]`, "set", `"6ba85179"`, "  - {name: 🇹🇼",
		strings.Replace(long, `short-id: ""}`, `short-id: 6ba85179}`, 1))
	mustEditLine(t, `["proxies",2,"reality-opts","short-id"]`, "set", `"12345678"`, "  - {name: 🇹🇼",
		strings.Replace(long, `short-id: ""}`, `short-id: "12345678"}`, 1))
	mustEditLine(t, `["proxies",2,"grpc-opts","grpc-service-name"]`, "set", `"svc,2"`, "  - {name: 🇹🇼",
		strings.Replace(long, "{grpc-service-name: grpc}", `{grpc-service-name: 'svc,2'}`, 1))
	mustEditLine(t, `["proxies",2,"grpc-opts","ping-interval"]`, "insert", `30`, "  - {name: 🇹🇼",
		strings.Replace(long, "{grpc-service-name: grpc}", "{grpc-service-name: grpc, ping-interval: 30}", 1))
	mustEditLine(t, `["proxies",2,"alpn"]`, "insert", `["h2","http/1.1"]`, "  - {name: 🇹🇼",
		strings.Replace(long, "udp: true}", "udp: true, alpn: [h2, http/1.1]}", 1))
	mustEditLine(t, `["proxies",2,"reality-opts"]`, "set", `{"public-key":"BBBB","short-id":"0a"}`, "  - {name: 🇹🇼",
		strings.Replace(long, `{public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: ""}`, `{public-key: BBBB, short-id: 0a}`, 1))
	group := lineOf(t, flowSubscription, "  - {name: PROXY")
	mustEditLine(t, `["proxy-groups",0,"proxies",1]`, "delete", ``, "  - {name: PROXY",
		strings.Replace(group, "🇭🇰 HK 中转 ⚡️, 🇯🇵 日本 02, ", "🇭🇰 HK 中转 ⚡️, ", 1))
	mustEditLine(t, `["proxy-groups",0,"proxies",0]`, "insert", `"DIRECT"`, "  - {name: PROXY",
		strings.Replace(group, "proxies: [🇭🇰", "proxies: [DIRECT, 🇭🇰", 1))
}

func TestTheNodePagesStepsOnAFlowNode(t *testing.T) {
	text := flowSubscription
	for _, step := range []struct{ path, op, value string }{
		{`["proxies",0,"dialer-proxy"]`, "insert", `"🇯🇵 日本 02"`},
		{`["proxies",0,"port"]`, "set", `8443`},
		{`["proxies",0,"udp"]`, "delete", ``},
		{`["proxies",0,"sni"]`, "set", `"cdn.example.com"`},
	} {
		out := runYAMLEdit(t, text, step.path, step.op, step.value)
		if !out.OK {
			t.Fatalf("%s %s refused: %s %s", step.op, step.path, out.Code, out.Message)
		}
		text = out.Text
	}
	want := strings.Replace(flowSubscription,
		`  - {name: 🇭🇰 HK 中转 ⚡️, server: hk.example.com, port: 443, type: trojan, password: "pa,ss", udp: true, sni: www.example.com, skip-cert-verify: true}`,
		`  - {name: 🇭🇰 HK 中转 ⚡️, server: hk.example.com, port: 8443, type: trojan, password: "pa,ss", sni: cdn.example.com, skip-cert-verify: true, dialer-proxy: 🇯🇵 日本 02}`, 1)
	if text != want {
		t.Fatalf("--- got ---\n%s\n--- want ---\n%s", text, want)
	}
}

func TestAFlowNodeOverSeveralLines(t *testing.T) {
	original := "proxies:\n  - {name: a,\n     type: ss, server: s.example.com,\n     port: 1}\nmode: rule\n"
	mustEdit(t, original, `["proxies",0,"dialer-proxy"]`, "insert", `"b"`,
		"proxies:\n  - {name: a,\n     type: ss, server: s.example.com,\n     port: 1,\n     dialer-proxy: b}\nmode: rule\n")
	mustEdit(t, original, `["proxies",0,"type"]`, "delete", ``,
		"proxies:\n  - {name: a,\n     server: s.example.com,\n     port: 1}\nmode: rule\n")
	mustEdit(t, original, `["proxies",0,"port"]`, "delete", ``,
		"proxies:\n  - {name: a,\n     type: ss, server: s.example.com}\nmode: rule\n")
	mustEdit(t, "x:\n  - {a: 1, }\n", `["x",0,"a"]`, "delete", ``, "x:\n  - {}\n")
	commented := "proxies:\n  - {name: a,  # first\n     type: ss, port: 1}\n"
	mustEdit(t, commented, `["proxies",0,"type"]`, "set", `"vmess"`, "proxies:\n  - {name: a,  # first\n     type: vmess, port: 1}\n")
	mustEdit(t, commented, `["proxies",0,"name"]`, "set", `"b"`, "proxies:\n  - {name: b,  # first\n     type: ss, port: 1}\n")
}

func TestAFlowNodeRefusesWhatItCannotDoInPlace(t *testing.T) {
	for _, c := range []struct{ name, original, path, op, value, code string }{
		{"rename", flowSubscription, `["proxies",0,"sni"]`, "rename", `"servername"`, "unsupportedStyle"},
		{"insertBefore", flowSubscription, `["proxies",0,"sni"]`, "insertBefore", `{"key":"k","value":1}`, "unsupportedStyle"},
		{"move", "x:\n  - {a: [1, 2, 3]}\n", `["x",0,"a",0]`, "move", `2`, "unsupportedStyle"},
		{"anchor", "x:\n  - {a: &v 1, b: *v}\n", `["x",0,"a"]`, "set", `2`, "anchor"},
		{"merge", "base: &b {p: 1}\nx:\n  - {<<: *b, a: 1}\n", `["x",0,"a"]`, "set", `2`, "anchor"},
		{"a field with no value", "x:\n  - {a, b: 1}\n", `["x",0,"b"]`, "set", `2`, "unsupportedStyle"},
		{"existing key", flowSubscription, `["proxies",0,"sni"]`, "insert", `"x"`, "invalidRequest"},
		{"no such key", flowSubscription, `["proxies",0,"nope"]`, "set", `"x"`, "notFound"},
		{"insert beside a comment", "p:\n  - {\n      a: 1  # about a\n    }\n", `["p",0,"b"]`, "insert", `2`, "unsupportedStyle"},
		{"insert before a head comment", "p: [\n  # about x\n  x,\n  y\n]\n", `["p",0]`, "insert", `"n"`, "unsupportedStyle"},
		{"delete under a head comment", "p:\n  - {\n      a: 1,\n      # about b\n      b: 2,\n      c: 3\n    }\n", `["p",0,"b"]`, "delete", ``, "unsupportedStyle"},
		{"delete a value holding a comment", "p:\n  - {a: [1, # keep?\n       2], b: 3}\n", `["p",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"set a value holding a comment", "p:\n  - {a: [1, # keep?\n       2], b: 3}\n", `["p",0,"a"]`, "set", `5`, "unsupportedStyle"},
		{"a comment right after a bracket", "p:\n  - [# c\n    1]\n", `["p",0,0]`, "insert", `2`, "unsupportedStyle"},
		{"an explicit key on the line before", "p:\n  - { ?\n      a : 1, b: 2 }\n", `["p",0,"b"]`, "set", `3`, "unsupportedStyle"},
		{"a comment after a closing quote", "x:\n  - {a: \"v\"# c1\n     , b: 2}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after a closing bracket", "x:\n  - {a: [1]# c1\n , b: 2}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after a closing brace", "x:\n  - {a: {k: 1}# c1\n , b: 2}\n", `["x",0,"b"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after a JSON key", "x:\n  - {\"a\":# c1\n 1, b: 2}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after a quote in a plain value", "x:\n  - {a: Bob 's, # c1\n     b: 'z'}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"set a list holding a comment", "x:\n  - {a: [it 's, # c1\n     'z'], b: 1}\n", `["x",0,"a"]`, "set", `5`, "unsupportedStyle"},
		{"?a", "x:\n  - {?a: 1, b: 2}\n", `["x",0,"b"]`, "delete", ``, "unsupportedStyle"},
		{",?a", "x:\n  - {b: 2,?a: 1, c: 3}\n", `["x",0,"c"]`, "set", `4`, "unsupportedStyle"},
		{"?\"a\"", "x:\n  - {?\"a\": 1, b: 2}\n", `["x",0,"b"]`, "set", `3`, "unsupportedStyle"},
		{"a comment inside a nested list", "p:\n  - {a: [\n # C\nx], b: 1}\n", `["p",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"set a nested list holding a comment", "p:\n  - {a: [\n # C\nx], b: 1}\n", `["p",0,"a"]`, "set", `9`, "unsupportedStyle"},
		{"a comment inside an empty mapping", "x:\n  - {a: 1, e: {\n # C\n}, f: []}\n", `["x",0,"e"]`, "delete", ``, "unsupportedStyle"},
		{"set an item holding a comment", "p: [x, [\n # C\n], z]\n", `["p",1]`, "set", `9`, "unsupportedStyle"},
		{"insert into an empty list with a comment", "p:\n  - [\n    # c\n  ]\n", `["p",0,0]`, "insert", `1`, "unsupportedStyle"},
		{"a comment after a key's colon", "proxies:\n  - {name: a, type: vless, grpc-opts: # service\n      {grpc-service-name: g}, udp: true}\n", `["proxies",0,"grpc-opts"]`, "delete", ``, "unsupportedStyle"},
		{"set a tagged scalar with a comment", "p:\n  - {a: !!str # c\n      x, b: 2}\n", `["p",0,"a"]`, "set", `"y"`, "unsupportedStyle"},
		{"set a tagged list with a comment", "p:\n  - {a: !!seq # c\n      [1], b: 2}\n", `["p",0,"a"]`, "set", `5`, "unsupportedStyle"},
		{"? and a comment before the key", "p: {? # q\n a: 1, b: 2}\n", `["p","b"]`, "set", `3`, "unsupportedStyle"},
		{"the last entry's comment", "x:\n  - {\n    a: 1, # about a\n    b: 2  # about b\n  }\n", `["x",0,"b"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after the last item", "p: [\n  x, # keep x\n  y # about y\n]\n", `["p",1]`, "delete", ``, "unsupportedStyle"},
		{"a comment line between entries", "x:\n  - {a: 1,\n     # c1\n     b: 2}\n", `["x",0,"b"]`, "delete", ``, "unsupportedStyle"},
		{"a comment after the entry", "x:\n  - {a: 1, # c1\n     b: 2}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"the only entry's comment", "x:\n  - {a: 1 # c1\n    }\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
		{"explicit key", "x:\n  - {? a : 1, b: 2}\n", `["x",0,"a"]`, "delete", ``, "unsupportedStyle"},
	} {
		out := runYAMLEdit(t, c.original, c.path, c.op, c.value)
		if out.OK || out.Code != c.code {
			t.Errorf("%s: ok=%v code=%q message=%q, want refusal %q", c.name, out.OK, out.Code, out.Message, c.code)
		}
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestAValueWithAUnicodeLineSeparatorIsWrittenEscaped(t *testing.T) {
	for _, value := range []string{"\u2028", "ab\u2029cd", "x\u0085y"} {
		out := runYAMLEdit(t, "p:\n  - {a: 1}\n", `["p",0,"a"]`, "set", jsonString(t, value))
		if !out.OK {
			t.Fatalf("%q refused: %s %s", value, out.Code, out.Message)
		}
		if strings.ContainsAny(out.Text, "\u0085\u2028\u2029") {
			t.Fatalf("%q written raw:\n%s", value, out.Text)
		}
		var read struct {
			P []map[string]string `yaml:"p"`
		}
		if err := yaml.Unmarshal([]byte(out.Text), &read); err != nil || len(read.P) != 1 || read.P[0]["a"] != value {
			t.Fatalf("%q reads back as %+v (%v) from:\n%s", value, read, err, out.Text)
		}
		if again := runYAMLEdit(t, out.Text, `["p",0,"b"]`, "insert", `2`); !again.OK {
			t.Fatalf("after %q the next edit is refused: %s %s", value, again.Code, again.Message)
		}
	}
}

func TestAnEmptyFlowListItemIsFilledInPlace(t *testing.T) {
	mustEdit(t, "proxies:\n  - {}\nmode: rule\n", `["proxies",0,"name"]`, "insert", `"a"`, "proxies:\n  - {name: a}\nmode: rule\n")
	mustEdit(t, "p:\n  - []\n", `["p",0,0]`, "insert", `1`, "p:\n  - [1]\n")
}

func TestAFlowNodeEndingFarBelowItsStart(t *testing.T) {
	original := "a: 1\nproxies:\n  - {name: a,\n     type: ss,\n     server: s.example.com,\n     port: 1,\n     cipher: none,\n     password: p,\n     udp: true}\nmode: rule\n"
	mustEdit(t, original, `["proxies",0,"dialer-proxy"]`, "insert", `"b"`, strings.Replace(original, "udp: true}", "udp: true,\n     dialer-proxy: b}", 1))
	mustEdit(t, original, `["proxies",0,"udp"]`, "delete", ``, strings.Replace(original, ",\n     udp: true}", "}", 1))
}

func TestATaggedFlowCollectionIsEditedInPlace(t *testing.T) {
	mustEdit(t, "p:\n  - name: x\n    opts: !!map {a: 1}\n", `["p",0,"opts","a"]`, "set", `4`, "p:\n  - name: x\n    opts: !!map {a: 4}\n")
}

func TestAFlowEditStopsAtTheLineItsCollectionClosesOn(t *testing.T) {
	original := "p: {a: 1,\n  b: 2,\n  c: 3}\nq: 1\nr: [x, y]\n"
	mustEdit(t, original, `["p","b"]`, "set", `5`, strings.Replace(original, "b: 2", "b: 5", 1))
	mustEdit(t, original, `["p","d"]`, "insert", `4`, strings.Replace(original, "c: 3}", "c: 3,\n  d: 4}", 1))
}

func TestFlowValuesThatOnlyLookLikeCommentsAreEdited(t *testing.T) {
	mustEdit(t, "x:\n  - {\"name\":\"HK #1\",\"type\":\"ss\"}\n", `["x",0,"udp"]`, "insert", `true`,
		"x:\n  - {\"name\":\"HK #1\",\"type\":\"ss\", udp: true}\n")
	mustEdit(t, "x: {a: Bob 's, b: 1}\n", `["x","b"]`, "set", `5`, "x: {a: Bob 's, b: 5}\n")
	mustEdit(t, "x: {a: 1, b: \"x\"# c\n}\n", `["x","a"]`, "set", `5`, "x: {a: 5, b: \"x\"# c\n}\n")
	mustEdit(t, "x:\n  - {a: 1, b: 2} # note\n", `["x",0,"c"]`, "insert", `3`, "x:\n  - {a: 1, b: 2, c: 3} # note\n")
	mustEdit(t, "p:\n  - {name: \"HK [#1]\", type: ss}\n", `["p",0,"dialer-proxy"]`, "insert", `"x"`,
		"p:\n  - {name: \"HK [#1]\", type: ss, dialer-proxy: x}\n")
	mustEdit(t, "p:\n  - {password: 'ab{#cd', type: ss}\n", `["p",0,"udp"]`, "insert", `true`,
		"p:\n  - {password: 'ab{#cd', type: ss, udp: true}\n")
	mustEdit(t, "p:\n  - {name: a, server: fe80::}\n", `["p",0,"udp"]`, "insert", `true`, "p:\n  - {name: a, server: fe80::, udp: true}\n")
	mustEdit(t, "p:\n  - {name: a, password: abc:, port: 1}\n", `["p",0,"password"]`, "set", `"xyz"`, "p:\n  - {name: a, password: xyz, port: 1}\n")
	mustEdit(t, "p:\n  - {name: a, server: fe80::, port: 1}\n", `["p",0,"port"]`, "delete", ``, "p:\n  - {name: a, server: fe80::}\n")
	mustEdit(t, "x: {a: \"x\"#c\n , b: 2}\n", `["x","a"]`, "set", `"y"`, "x: {a: y #c\n , b: 2}\n")
}

func TestTheJSONFallbackKeepsHTMLCharacters(t *testing.T) {
	out := runYAMLEdit(t, "p:\n  - {name: a}\n", `["p",0,"name"]`, "set", jsonString(t, "a\u2028<b>&c"))
	if !out.OK || !strings.Contains(out.Text, `"a\u2028<b>&c"`) {
		t.Fatalf("ok=%v %s %s:\n%s", out.OK, out.Code, out.Message, out.Text)
	}
}

func TestAOneLineFlowListOfThousandsOfNodesIsEditedQuickly(t *testing.T) {
	var nodes []string
	for i := 0; i < 3000; i++ {
		nodes = append(nodes, fmt.Sprintf("{name: 节点 %d, type: ss, server: s%d.example.com, port: %d, cipher: aes-128-gcm, password: p%d}", i, i, 10000+i, i))
	}
	original := "proxies: [" + strings.Join(nodes, ", ") + "]\nmode: rule\n"
	start := time.Now()
	out := runYAMLEdit(t, original, `["proxies",2999,"dialer-proxy"]`, "insert", `"中转"`)
	elapsed := time.Since(start)
	if !out.OK || !strings.Contains(out.Text, "password: p2999, dialer-proxy: 中转}]") {
		t.Fatalf("ok=%v %s %s", out.OK, out.Code, out.Message)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("one edit in a 3000-node one-line list took %s", elapsed)
	}
	t.Logf("one edit in a %d KB one-line list: %s", len(original)>>10, elapsed.Round(time.Millisecond))
}

func TestAnEntryALineCollectionKeepsItsShape(t *testing.T) {
	mustEdit(t, "p: {\n  a: 1,\n  b: 2\n}\n", `["p","c"]`, "insert", `3`, "p: {\n  a: 1,\n  b: 2,\n  c: 3\n}\n")
	mustEdit(t, "p: [\n  x,\n  y\n]\n", `["p",0]`, "insert", `"n"`, "p: [\n  n,\n  x,\n  y\n]\n")
	mustEdit(t, "p: {\n  a: 1,\n  b: 2\n}\n", `["p","a"]`, "delete", ``, "p: {\n  b: 2\n}\n")
	mustEdit(t, "p: {a: 1,\n  b: 2}\n", `["p","a"]`, "delete", ``, "p: {\n  b: 2}\n")
	mustEdit(t, "p: {x: 0, a: 1,\n  b: 2}\n", `["p","a"]`, "delete", ``, "p: {x: 0,\n  b: 2}\n")
	mustEdit(t, "p: {\n  a: 1\n}\n", `["p","a"]`, "delete", ``, "p: {\n}\n")
	mustEdit(t, "p: {\n  a: 1,\n}\n", `["p","a"]`, "delete", ``, "p: {\n}\n")
	mustEdit(t, "p: {\n  a: 1,\n  b: 2\n}\n", `["p","b"]`, "delete", ``, "p: {\n  a: 1\n}\n")
	mustEdit(t, "p: {a: 1, b: 2}\n", `["p","c"]`, "insert", `3`, "p: {a: 1, b: 2, c: 3}\n")
}

func TestACommentOutsideTheEditedContainerStaysAndTheEditIsMade(t *testing.T) {
	mustEdit(t, "p: {x: [1, # c\n 2], y: {k: 1}}\n", `["p","y","j"]`, "insert", `2`, "p: {x: [1, # c\n 2], y: {k: 1, j: 2}}\n")
	mustEdit(t, "p: {x: [1, # c\n 2], y: {k: 1, j: 2}}\n", `["p","y","j"]`, "delete", ``, "p: {x: [1, # c\n 2], y: {k: 1}}\n")
}

func TestAnEditThatJoinsOrSplitsLinesKeepsCommentsWhereTheyAre(t *testing.T) {
	for _, c := range []struct{ name, original, path, op, value string }{
		{"delete the last item, a comment after the bracket", "p: [\n  1,\n  2]  # about two\n", `["p",1]`, "delete", ``},
		{"delete the last field, a comment after the brace", "p: {a: x,\n  b: 1}  # about b\n", `["p","b"]`, "delete", ``},
		{"delete in a nested list, the outer comment after it", "p: {x: [\n  1,\n  2], # c about two\n  y: 2}\n", `["p","x",1]`, "delete", ``},
		{"insert after a last item alone on its line, a comment after it", "p: [\n  1,\n  2]  # about two\n", `["p",2]`, "insert", `3`},
		{"insert in a nested list, the outer comment after it", "p: {x: [\n  1,\n  2], # c\n  y: 2}\n", `["p","x",2]`, "insert", `3`},
	} {
		out := runYAMLEdit(t, c.original, c.path, c.op, c.value)
		if out.OK || out.Code != "unsupportedStyle" {
			t.Errorf("%s: ok=%v code=%q, want unsupportedStyle; text:\n%s", c.name, out.OK, out.Code, out.Text)
		}
	}
	mustEdit(t, "p: {x: [\n  1,\n  2], # c\n  y: 2}\n", `["p","x",0]`, "delete", ``, "p: {x: [\n  2], # c\n  y: 2}\n")
	mustEdit(t, "p: {\n  a: 1 }\n", `["p","a"]`, "delete", ``, "p: {\n}\n")
	mustEdit(t, "p: {\n  a: 1\n  , b: 2\n}\n", `["p","a"]`, "delete", ``, "p: {\n  b: 2\n}\n")
}

package yaml

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)


var clashProxies = ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]interface{}(nil))}

type clashConfig struct {
	Mode    string                   `yaml:"mode"`
	Proxies []map[string]interface{} `yaml:"proxies"`
	Groups  []map[string]interface{} `yaml:"proxy-groups"`
	Rules   []string                 `yaml:"rules"`
	X3      interface{}              `yaml:"x3"`
}

type clashProbe struct {
	Mode *string `yaml:"mode"`
}

type clashArray struct {
	Proxies [2]map[string]interface{} `yaml:"proxies"`
}

type clashPointer struct {
	Proxies *[]map[string]interface{} `yaml:"proxies"`
}

type clashMismatch struct {
	Proxies map[string]interface{} `yaml:"proxies"`
}

var clashTargets = []func() interface{}{
	func() interface{} { return &clashConfig{Mode: "rule", Proxies: []map[string]interface{}{}} },
	func() interface{} { return &map[string]interface{}{} },
	func() interface{} { var m map[string]interface{}; return &m },
	func() interface{} { var v interface{}; return &v },
	func() interface{} { return &clashProbe{} },
	func() interface{} { return &clashArray{} },
	func() interface{} { return &clashPointer{} },
	func() interface{} { return &clashMismatch{} },
	func() interface{} { return &[]interface{}{} },
}

func clashItems(n int, item func(i int) string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(item(i))
	}
	return b.String()
}

func clashBomb() string {
	return "x0: &x0 [a, a, a, a, a, a, a, a, a, a]\n" +
		"x1: &x1 [*x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0]\n" +
		"x2: &x2 [*x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1]\n" +
		"x3: [*x2, *x2, *x2, *x2, *x2]\n"
}

var clashDocuments = map[string]string{
	"empty":                      "",
	"comment":                    "# nothing\n",
	"block":                      "mode: global\nproxies:\n  - name: a\n    type: ss\n    port: 443\n    tags: [x, y]\n    opts: {k: v, 2: two}\n  - name: b\n    type: http\n    port: \"80\"\nrules:\n  - MATCH,a\n",
	"flow":                       "proxies: [{name: a, type: ss}, {name: b, n: 1.5, t: true, z: ~}]\n",
	"empty list":                 "proxies: []\n",
	"null list":                  "proxies: ~\n",
	"inline merge":               "proxies:\n  - {<<: {type: ss, port: 1}, name: a, port: 2}\n  - {<<: [{a: 1}, {b: 2}], name: b}\n",
	"anchored item used outside": "proxies:\n  - &a {name: a, type: ss}\nproxy-groups:\n  - {name: G, proxies: [a], node: *a}\n",
	"merge with alias":           "x: &n {type: ss, port: 1}\nproxies:\n  - {<<: *n, name: a}\n  - {name: b}\n",
	"alias item":                 "x: &n {name: a}\nproxies:\n  - *n\n",
	"alias inside item":          "x: &v [1, 2]\nproxies:\n  - {name: a, list: *v}\n",
	"aliased list":               "x: &l\n  - {name: a}\nproxies: *l\n",
	"anchored list":              "proxies: &l\n  - {name: a}\nproxy-groups: *l\n",
	"tagged list":                "proxies: !!seq\n  - {name: a}\n",
	"custom tag list":            "proxies: !mine\n  - {name: a}\n",
	"quoted key":                 "\"proxies\":\n  - {name: a}\n",
	"tagged key":                 "!!str proxies:\n  - {name: a}\n",
	"binary key":                 "!!binary cHJveGllcw==:\n  - {name: a}\n",
	"twice":                      "proxies:\n  - {name: a}\nproxies:\n  - {name: b}\n",
	"anchored root":              "&root\nproxies:\n  - {name: a}\nself: *root\n",
	"root list":                  "- proxies:\n    - {name: a}\n",
	"nested key":                 "outer:\n  proxies:\n    - {name: a}\n",
	"scalar item":                "proxies:\n  - name-only\n",
	"null item":                  "proxies:\n  - ~\n  - {name: a}\n",
	"list item":                  "proxies:\n  - [a, b]\n",
	"int key":                    "proxies:\n  - {1: a, name: b}\n",
	"duplicate key in item":      "proxies:\n  - {name: a, name: b}\n",
	"bad binary":                 "proxies:\n  - {name: !!binary '%%%'}\n",
	"complex key":                "proxies:\n  - ? [a]\n    : b\n",
	"syntax in list":             "proxies:\n  - {name: a\n  - {name: b}\n",
	"syntax after list":          "proxies:\n  - {name: a}\nrules: [\n",
	"unknown anchor":             "proxies:\n  - {name: a}\nx: *nowhere\n",
	"type error after list":      "proxies:\n  - {name: a}\nmode: [1]\n",
	"two documents":              "proxies:\n  - {name: a}\n---\nproxies:\n  - {name: b}\n",
	"comments":                   "# head\nproxies: # line\n  # item head\n  - {name: a} # item line\n  # foot\nmode: rule\n",
	"bomb first":                 clashBomb() + "proxies:\n" + clashItems(10, func(i int) string { return fmt.Sprintf("  - {name: n%d}\n", i) }),
	"bomb after a long list":     "proxies:\n" + clashItems(2000, func(i int) string { return fmt.Sprintf("  - {name: n%d, type: ss, server: s%d, port: %d}\n", i, i, i) }) + clashBomb(),
	"bomb after a short list":    "proxies:\n" + clashItems(20, func(i int) string { return fmt.Sprintf("  - {name: n%d, type: ss}\n", i) }) + clashBomb(),
}

func TestClashUnmarshalIsUnmarshal(t *testing.T) {
	for name, document := range clashDocuments {
		t.Run(name, func(t *testing.T) {
			for _, target := range clashTargets {
				want, got := target(), target()
				wantErr := Unmarshal([]byte(document), want)
				gotErr := ClashUnmarshal([]byte(document), got, clashProxies, func(decode func(interface{}) error) {
					for _, readTarget := range clashTargets {
						fromRead, fromText := readTarget(), readTarget()
						readErr, textErr := decode(fromRead), Unmarshal([]byte(document), fromText)
						if fmt.Sprint(readErr) != fmt.Sprint(textErr) {
							t.Errorf("read into %T: error %v, Unmarshal's %v", fromRead, readErr, textErr)
						}
						if !reflect.DeepEqual(fromRead, fromText) {
							t.Errorf("read into %T: %#v, Unmarshal's %#v", fromRead, fromRead, fromText)
						}
					}
				})
				if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Errorf("into %T: error %v, Unmarshal's %v", got, gotErr, wantErr)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("into %T: %#v, Unmarshal's %#v", got, got, want)
				}
			}
		})
	}
}

func clashRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "was decoded item by item")
}

func TestClashUnmarshalStreamsOnlyWhereNothingCanTell(t *testing.T) {
	streams := map[string]bool{
		"block": true, "flow": true, "empty list": true, "inline merge": true,
		"anchored item used outside": true, "quoted key": true, "tagged key": true, "twice": true,
		"comments": true, "bomb first": true, "bomb after a long list": true, "bomb after a short list": true,
		"syntax after list": false, "unknown anchor": false, "type error after list": true, "two documents": true,
		"int key": false, "null item": false, "scalar item": false, "list item": false,
		"merge with alias": false, "alias item": false, "alias inside item": false, "aliased list": false,
		"anchored list": false, "tagged list": false, "custom tag list": false, "binary key": false,
		"anchored root": false, "root list": false, "nested key": false, "duplicate key in item": false,
		"bad binary": false, "complex key": false, "syntax in list": false, "null list": false,
	}
	for name, want := range streams {
		document, ok := clashDocuments[name]
		if !ok {
			t.Fatalf("no document %q", name)
		}
		node, err := clashParse([]byte(document), clashProxies)
		streamed := err == nil && clashStreamedSequence(node) != nil
		if streamed != want {
			t.Errorf("%s: streamed %v, want %v (parse error %v)", name, streamed, want, err)
		}
	}
}

func clashStreamedSequence(n *Node) *Node {
	if n == nil {
		return nil
	}
	if n.clash != nil {
		return n
	}
	for _, child := range n.Content {
		if found := clashStreamedSequence(child); found != nil {
			return found
		}
	}
	return nil
}

func clashCountNodes(n *Node) int {
	if n == nil {
		return 0
	}
	count := 1
	for _, child := range n.Content {
		count += clashCountNodes(child)
	}
	return count
}

func TestClashUnmarshalKeepsNoItemNodes(t *testing.T) {
	document := "mode: rule\nproxies:\n" + clashItems(5000, func(i int) string {
		return fmt.Sprintf("  - {name: n%d, type: ss, server: s%d, port: %d, opts: {a: 1, b: [x, y]}}\n", i, i, i)
	}) + "rules:\n  - MATCH,DIRECT\n"
	node, err := clashParse([]byte(document), clashProxies)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := clashParse([]byte(document), ClashSequence{})
	if err != nil {
		t.Fatal(err)
	}
	kept, whole := clashCountNodes(node), clashCountNodes(plain)
	t.Logf("nodes kept: %d streamed, %d parsed whole", kept, whole)
	if kept > 16 {
		t.Fatalf("the streamed parse kept %d nodes (the whole parse %d)", kept, whole)
	}
	if seq := clashStreamedSequence(node); seq == nil || seq.clash.items.Len() != 5000 || len(seq.Content) != 0 {
		t.Fatal("the sequence was not streamed into 5,000 items")
	}
	var config clashConfig
	if err := ClashUnmarshal([]byte(document), &config, clashProxies, nil); err != nil {
		t.Fatal(err)
	}
	if len(config.Proxies) != 5000 || config.Proxies[4999]["name"] != "n4999" {
		t.Fatalf("decoded %d proxies", len(config.Proxies))
	}
}

func TestClashUnmarshalRefusesWhatCannotTakeTheItems(t *testing.T) {
	document := "proxies:\n  - {name: a}\n"
	var asNode struct {
		Proxies Node `yaml:"proxies"`
	}
	if err := ClashUnmarshal([]byte(document), &asNode, clashProxies, nil); !clashRefusal(err) {
		t.Fatalf("decoding into a Node: %v", err)
	}
	var asUnmarshaler struct {
		Proxies clashUnmarshaler `yaml:"proxies"`
	}
	if err := ClashUnmarshal([]byte(document), &asUnmarshaler, clashProxies, nil); !clashRefusal(err) {
		t.Fatalf("decoding into an Unmarshaler: %v", err)
	}
	var whole clashWhole
	if err := ClashUnmarshal([]byte(document), &whole, clashProxies, nil); err != nil {
		t.Fatal(err)
	}
	if len(whole.config.Proxies) != 1 || whole.config.Proxies[0]["name"] != "a" {
		t.Fatalf("the Unmarshaler decoded %#v", whole.config.Proxies)
	}
	if _, err := Marshal(whole.node); err == nil || !strings.Contains(err.Error(), "holds no nodes to encode") {
		t.Fatalf("encoding the streamed parse: %v", err)
	}
}

func TestClashUnmarshalRefusesItemsThatTakeNodes(t *testing.T) {
	document := "rules:\n  - 'DOMAIN,a.example,DIRECT' # one\n  - MATCH,DIRECT\n"
	rules := ClashSequence{Key: "rules", Item: reflect.TypeOf("")}
	var plain struct {
		Rules []Node `yaml:"rules"`
	}
	if err := Unmarshal([]byte(document), &plain); err != nil || plain.Rules[0].Style != SingleQuotedStyle || plain.Rules[0].LineComment != "# one" {
		t.Fatalf("Unmarshal: %v %#v", err, plain.Rules)
	}
	var nodes struct {
		Rules []Node `yaml:"rules"`
	}
	if err := ClashUnmarshal([]byte(document), &nodes, rules, nil); !clashRefusal(err) {
		t.Fatalf("decoding into []Node: %v", err)
	}
	var pointers struct {
		Rules []*Node `yaml:"rules"`
	}
	if err := ClashUnmarshal([]byte(document), &pointers, rules, nil); !clashRefusal(err) {
		t.Fatalf("decoding into []*Node: %v", err)
	}
	var unmarshalers struct {
		Rules []clashUnmarshaler `yaml:"rules"`
	}
	if err := ClashUnmarshal([]byte(document), &unmarshalers, rules, nil); !clashRefusal(err) {
		t.Fatalf("decoding into []Unmarshaler: %v", err)
	}
	type named string
	var strings2 struct {
		Rules []named `yaml:"rules"`
	}
	if err := ClashUnmarshal([]byte(document), &strings2, rules, nil); err != nil || len(strings2.Rules) != 2 || strings2.Rules[0] != "DOMAIN,a.example,DIRECT" {
		t.Fatalf("decoding into []named: %v %v", err, strings2.Rules)
	}
}

type clashUnmarshaler struct{}

func (*clashUnmarshaler) UnmarshalYAML(*Node) error { return nil }

type clashWhole struct {
	node   *Node
	config clashConfig
}

func (w *clashWhole) UnmarshalYAML(n *Node) error {
	w.node = n
	return n.Decode(&w.config)
}

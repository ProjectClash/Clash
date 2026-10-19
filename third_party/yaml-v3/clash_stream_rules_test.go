package yaml

import (
	"fmt"
	"reflect"
	"testing"
)


var clashRules = ClashSequence{Key: "rules", Item: reflect.TypeOf("")}

var clashRuleDocuments = map[string]string{
	"plain":            "rules:\n  - DOMAIN,a.example,DIRECT\n  - MATCH,DIRECT\n",
	"quoted":           "rules:\n  - 'DOMAIN,a,b'\n  - \"DOMAIN-KEYWORD,\\u0041,b\"\n",
	"flow":             "rules: [DOMAIN,a,b, 'MATCH,c']\n",
	"comments":         "rules: # line\n  # head\n  - DOMAIN,a,b # tail\n  # foot\nmode: rule\n",
	"folded plain":     "rules:\n  - DOMAIN,a,\n    b\n",
	"int item":         "rules:\n  - DOMAIN,a,b\n  - 123\n",
	"bool item":        "rules:\n  - true\n",
	"null item":        "rules:\n  - DOMAIN,a,b\n  -\n",
	"tagged item":      "rules:\n  - !!str 1\n",
	"custom tag item":  "rules:\n  - !rule DOMAIN,a,b\n",
	"list item":        "rules:\n  - [a, b]\n",
	"map item":         "rules:\n  - {a: b}\n",
	"anchored item":    "rules:\n  - &r DOMAIN,a,b\nx: *r\n",
	"alias item":       "x: &r DOMAIN,a,b\nrules:\n  - *r\n",
	"anchored list":    "rules: &l\n  - DOMAIN,a,b\nx: *l\n",
	"with proxies":     "proxies:\n  - {name: a, type: ss}\nrules:\n  - MATCH,a\n",
	"proxies after":    "rules:\n  - MATCH,a\nproxies:\n  - {name: a, type: ss}\n",
	"twice":            "rules:\n  - a\nrules:\n  - b\n",
	"empty":            "rules: []\n",
	"null":             "rules: ~\n",
	"long":             "rules:\n" + clashItems(3000, func(i int) string { return fmt.Sprintf("  - DOMAIN,n%d.example,P%d\n", i, i%7) }),
	"long then bomb":   "rules:\n" + clashItems(3000, func(i int) string { return fmt.Sprintf("  - DOMAIN,n%d.example,P\n", i) }) + clashBomb(),
	"bomb then rules":  clashBomb() + "rules:\n  - DOMAIN,a,b\n",
	"syntax in list":   "rules:\n  - 'DOMAIN,a\n  - b\n",
	"type after list":  "rules:\n  - a\nmode: [1]\n",
	"two documents":    "rules:\n  - a\n---\nrules:\n  - b\n",
	"sub-rules nested": "sub-rules:\n  s:\n    - DOMAIN,a,b\nrules:\n  - SUB-RULE,(NETWORK,tcp),s\n",
}

func TestClashParseDocumentStreamsRulesAsUnmarshalDecodesThem(t *testing.T) {
	documents := map[string]string{}
	for name, document := range clashDocuments {
		documents["proxies: "+name] = document
	}
	for name, document := range clashRuleDocuments {
		documents["rules: "+name] = document
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			node, parseErr := ClashParseDocument([]byte(document), clashProxies, clashRules)
			for _, target := range clashTargets {
				want, got := target(), target()
				wantErr := Unmarshal([]byte(document), want)
				var gotErr error
				if parseErr != nil {
					gotErr = parseErr
				} else if node != nil {
					gotErr = node.Decode(got)
				}
				if parseErr == nil && node == nil {
					gotErr = nil
				}
				if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Errorf("into %T: error %v, Unmarshal's %v", got, gotErr, wantErr)
				}
				if gotErr == nil && !reflect.DeepEqual(got, want) {
					t.Errorf("into %T: %#v, Unmarshal's %#v", got, got, want)
				}
			}
		})
	}
}

func TestClashParseDocumentKeepsNoNodesOfTheRules(t *testing.T) {
	document, err := ClashParseDocument([]byte(clashRuleDocuments["long"]), clashProxies, clashRules)
	if err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	if root.Content[0].Value != "rules" || len(root.Content[1].Content) != 0 || root.Content[1].clash == nil {
		t.Fatalf("the rules kept %d nodes", len(root.Content[1].Content))
	}
	for _, name := range []string{"int item", "alias item", "anchored item", "custom tag item"} {
		document, err := ClashParseDocument([]byte(clashRuleDocuments[name]), clashRules)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i+1 < len(document.Content[0].Content); i += 2 {
			if document.Content[0].Content[i].Value == "rules" && document.Content[0].Content[i+1].clash != nil {
				t.Errorf("%s: streamed", name)
			}
		}
	}
}

func TestClashUnmarshalSequencesIsUnmarshal(t *testing.T) {
	documents := map[string]string{}
	for name, document := range clashDocuments {
		documents["proxies: "+name] = document
	}
	for name, document := range clashRuleDocuments {
		documents["rules: "+name] = document
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			for _, target := range clashTargets {
				want, got := target(), target()
				wantErr := Unmarshal([]byte(document), want)
				gotErr := ClashUnmarshalSequences([]byte(document), got, func(decode func(interface{}) error) {
					for _, readTarget := range clashTargets {
						fromRead, fromText := readTarget(), readTarget()
						readErr, textErr := decode(fromRead), Unmarshal([]byte(document), fromText)
						if fmt.Sprint(readErr) != fmt.Sprint(textErr) || !reflect.DeepEqual(fromRead, fromText) {
							t.Errorf("read into %T: %v %#v, Unmarshal's %v %#v", fromRead, readErr, fromRead, textErr, fromText)
						}
					}
				}, clashProxies, clashRules)
				if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
					t.Errorf("into %T: %v %#v, Unmarshal's %v %#v", got, gotErr, got, wantErr, want)
				}
			}
		})
	}
}

type clashNamedString string

type clashNamedMap map[string]interface{}

func TestStreamedRulesDecodeIntoEveryShapeAsUnmarshal(t *testing.T) {
	shapes := []func() interface{}{
		func() interface{} { return &struct{ Rules []interface{} }{} },
		func() interface{} { return &struct{ Rules []*string }{} },
		func() interface{} { return &struct{ Rules []clashNamedString }{} },
		func() interface{} { return &struct{ Rules []int }{} },
		func() interface{} { return &struct{ Rules [2]string }{} },
		func() interface{} { return &struct{ Rules *[]string }{} },
		func() interface{} { return &struct{ Rules map[string]string }{} },
		func() interface{} { return &struct{ Rules string }{} },
		func() interface{} { return &struct{ Rules interface{} }{} },
		func() interface{} { m := clashNamedMap{}; return &m },
	}
	for _, document := range []string{"rules: [MATCH,DIRECT]\n", "rules:\n  - DOMAIN,a,b\n  - '12'\n", "rules: [1, 2]\n"} {
		for _, shape := range shapes {
			want, got := shape(), shape()
			wantErr := Unmarshal([]byte(document), want)
			node, err := ClashParseDocument([]byte(document), clashRules)
			if err != nil {
				t.Fatal(err)
			}
			gotErr := node.Decode(got)
			if fmt.Sprint(wantErr) != fmt.Sprint(gotErr) || !reflect.DeepEqual(want, got) {
				t.Errorf("%q into %T: %v %#v, Unmarshal's %v %#v", document, got, gotErr, got, wantErr, want)
			}
		}
	}
}

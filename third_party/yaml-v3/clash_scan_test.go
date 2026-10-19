package yaml

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestClashScanSequenceReadsTheRulesAsUnmarshal(t *testing.T) {
	documents := map[string]string{
		"block":    "mode: rule\nproxies:\n  - {name: a, type: ss}\nrules:\n  - DOMAIN,a.example,DIRECT\n  - 'DOMAIN,b,c'\n  - \"DOMAIN-KEYWORD,\\u0041,d\"\n  - MATCH,中文策略\nx: 1\n",
		"flow":     "rules: [DOMAIN,a,b, 'MATCH,c']\n",
		"comments": "rules: # c\n  # head\n  - DOMAIN,a,b # tail\n  # foot\n  - MATCH,x\n",
		"folded":   "rules:\n  - DOMAIN,a,\n    b\n  - MATCH,y\n",
		"unicode":  "名字: 值\nrules:\n  - DOMAIN,例子.中国,节点选择\n  - DOMAIN-SUFFIX,🇬🇧.uk,🇬🇧 英国\n",
		"nested":   "proxy-groups:\n  - {name: g, proxies: [a, b]}\nsub-rules:\n  s: [MATCH,a]\nrules:\n  - SUB-RULE,(NETWORK,tcp),s\n",
		"empty":    "rules: []\n",
		"null":     "rules:\nmode: x\n",
		"absent":   "mode: rule\n",
		"long":     "rules:\n" + clashItems(2000, func(i int) string { return fmt.Sprintf("  - DOMAIN,n%d.例子,P%d\n", i, i%7) }),
		"indented": "rules:\n    -   DOMAIN,a,b\n    -   MATCH,c\n",
		"literal":  "rules:\n  - |\n    DOMAIN,a,b\n",
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			var want struct {
				Rules []string `yaml:"rules"`
			}
			if err := Unmarshal([]byte(document), &want); err != nil {
				t.Fatal(err)
			}
			var got []string
			in := []byte(document)
			scan, ok := ClashScanSequence(in, "rules", func(item ClashItem) bool {
				got = append(got, string(item.Value))
				raw := string(in[item.Start:item.End])
				switch item.Style {
				case ClashPlain:
					if strings.Join(strings.Fields(raw), " ") != strings.Join(strings.Fields(string(item.Value)), " ") {
						t.Errorf("plain %q written as %q", item.Value, raw)
					}
				case ClashSingleQuoted, ClashDoubleQuoted:
					if raw[0] != raw[len(raw)-1] || (raw[0] != '\'' && raw[0] != '"') {
						t.Errorf("quoted %q written as %q", item.Value, raw)
					}
				}
				return true
			})
			if !ok {
				t.Fatalf("not scanned")
			}
			if !reflect.DeepEqual(got, want.Rules) && !(len(got) == 0 && len(want.Rules) == 0) {
				t.Fatalf("scanned %q, Unmarshal %q", got, want.Rules)
			}
			if scan.Found != (len(want.Rules) > 0 || name == "empty") {
				t.Fatalf("found %v", scan.Found)
			}
		})
	}
	for _, refused := range []string{"rules:\n  - &a DOMAIN,a,b\n", "x: &r DOMAIN,a,b\nrules:\n  - *r\n", "rules:\n  - !!str DOMAIN,a,b\n", "rules:\n  - [a]\n", "rules: &l\n  - a\n", "'rules':\n  - a\n", "rules:\n  - a\nrules:\n  - b\n", "mode: a\nrules: [b]\nmode: c\n", "- a\n", "rules:\n  - 'a\n"} {
		if _, ok := ClashScanSequence([]byte(refused), "rules", func(ClashItem) bool { return true }); ok {
			t.Errorf("scanned %q", refused)
		}
	}
}

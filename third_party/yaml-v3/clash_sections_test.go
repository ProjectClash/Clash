package yaml

import (
	"strings"
	"testing"
)

func TestClashTopLevelSectionsAreWhereTheParserReadsThem(t *testing.T) {
	for _, c := range []struct {
		label, text string
		keys        []string
		anchored    []bool
	}{
		{"plain", "a: 1\nb:\n  - x\n# note\nc: {d: 2}\n", []string{"a", "b", "c"}, []bool{false, false, false}},
		{"quoted past the margin", "note: \"x\nrules:\n  - MATCH # \"\ng: 1\n", []string{"note", "g"}, []bool{false, false}},
		{"flow past the margin", "note: {a: plain \"text, b: \"x}\nrules:\n  - MATCH # \"}\ng: 1\n", []string{"note", "g"}, []bool{false, false}},
		{"anchors", "x: &n old\nr: [&m y]\np: *n\n", []string{"x", "r", "p"}, []bool{true, true, false}},
		{"wide characters", "名前: 値\nb: 1\n", []string{"名前", "b"}, []bool{false, false}},
		{"quoted keys", "\"a b\": 1\n'c': 2\n", []string{"a b", "c"}, []bool{false, false}},
	} {
		sections, ok := ClashTopLevelSections([]byte(c.text))
		if !ok || len(sections) != len(c.keys) {
			t.Fatalf("%s: %v %v", c.label, sections, ok)
		}
		for i, section := range sections {
			if section.Key != c.keys[i] || section.Anchored != c.anchored[i] {
				t.Fatalf("%s: section %d = %+v, want %s anchored %v", c.label, i, section, c.keys[i], c.anchored[i])
			}
			at := c.text[section.Start:]
			if !strings.HasPrefix(at, section.Key) && !strings.HasPrefix(at[1:], section.Key) {
				t.Fatalf("%s: section %q starts at %q", c.label, section.Key, at)
			}
		}
	}
	for label, text := range map[string]string{
		"flow top":                      "{a: 1, b: 2}\n",
		"two documents":                 "a: 1\n---\nb: 2\n",
		"sequence top":                  "- a\n- b\n",
		"alias key":                     "x: &k name\n*k : 1\n",
		"collection key":                "? [a, b]\n: 1\n",
		"anchored top":                  "--- &t\na: 1\n",
		"explicit key":                  "keep: 1\n? rules\n: []\n",
		"explicit key on the next line": "keep: 1\n?\n  rules\n: []\n",
		"every key explicit":            "?\n  a\n: 1\n?\n  rules\n: 2\n",
		"key written twice":             "keep: 1\nrules: []\nrules: []\n",
		"quoted and plain the same":     "keep: 1\nrules: []\n\"rules\": []\n",
		"key not a string":              "keep: 1\n1: []\n",
		"empty key":                     "keep: 1\n: []\n",
		"merge at the top":              "x-base: &base {rules: [MATCH]}\n<<: *base\nproxies: []\n",
		"tagged merge":                  "x-base: &base {rules: [MATCH]}\n!!merge a: *base\nproxies: []\n",
		"utf-16":                        "\xff\xfea\x00:\x00 \x001\x00\n\x00",
		"bad":                           "a: [1\n",
		"byte order mark":               "\xef\xbb\xbfa: 1\n",
	} {
		if sections, ok := ClashTopLevelSections([]byte(text)); ok {
			t.Fatalf("%s: read as sections %+v", label, sections)
		}
	}
}

func TestClashTopLevelSectionsNameTheSectionsWithAnAlias(t *testing.T) {
	sections, ok := ClashTopLevelSections([]byte("keep: 1\nrules: *missing\nlist: [a, *b]\nplain: [a]\n"))
	if !ok || len(sections) != 4 {
		t.Fatalf("%+v %v", sections, ok)
	}
	for i, want := range []bool{false, true, true, false} {
		if sections[i].Aliased != want {
			t.Fatalf("section %s aliased %v, want %v", sections[i].Key, sections[i].Aliased, want)
		}
	}
}

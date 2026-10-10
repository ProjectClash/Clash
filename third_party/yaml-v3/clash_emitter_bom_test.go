package yaml

import "testing"

func TestIsBomAtReadsItsIndex(t *testing.T) {
	bom := "\xef\xbb\xbf"
	for _, c := range []struct {
		value string
		index int
		want  bool
	}{
		{bom + "a", 0, true},
		{bom + "a", 3, false},
		{"a" + bom, 1, true},
		{"a" + bom, 0, false},
		{"a\xef\xbb", 1, false},
	} {
		if got := is_bom_at([]byte(c.value), c.index); got != c.want {
			t.Errorf("is_bom_at(%q, %d) = %v", c.value, c.index, got)
		}
	}
}

func TestABOMLedScalarEscapesOnlyWhatNeedsIt(t *testing.T) {
	for _, c := range []struct {
		value    string
		asKey    bool
		upstream string
		want     string
	}{
		{"\ufeff ", false, "k: \"\\uFEFF\\x20\"\n", "k: \"\\uFEFF \"\n"},
		{"\ufeff\ue000", false, "k: \"\\uFEFF\\uE000\"\n", "k: \"\\uFEFF\ue000\"\n"},
		{"\ufeffx", true, "\"\\uFEFF\\x78\": v\n", "\"\\uFEFFx\": v\n"},
		{"a\ufeffb", false, "k: \"a\\uFEFFb\"\n", "k: \"a\\uFEFFb\"\n"},
		{"\ufeff\ufeff", false, "k: \"\\uFEFF\\uFEFF\"\n", "k: \"\\uFEFF\\uFEFF\"\n"},
		{"x\ufeff", true, "\"x\\uFEFF\": v\n", "\"x\\uFEFF\": v\n"},
	} {
		document := map[string]string{"k": c.value}
		if c.asKey {
			document = map[string]string{c.value: "v"}
		}
		out, err := Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != c.want {
			t.Errorf("%q: written %q, want %q", c.value, out, c.want)
		}
		if c.value[:3] != "\xef\xbb\xbf" && c.want != c.upstream {
			t.Errorf("%q: a scalar without a leading BOM is written differently from upstream", c.value)
		}
		for _, text := range []string{c.upstream, c.want} {
			var back map[string]string
			if err := Unmarshal([]byte(text), &back); err != nil {
				t.Fatalf("%q does not read: %v", text, err)
			}
			for key, value := range back {
				if (c.asKey && key != c.value) || (!c.asKey && value != c.value) {
					t.Errorf("%q reads back as %q: %q", text, key, value)
				}
			}
		}
	}
}

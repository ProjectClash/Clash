package clash

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGeoSiteCategoriesInFindsBothSpellings(t *testing.T) {
	for name, testCase := range map[string]struct {
		content string
		want    []string
	}{
		"dns policy names several at once": {
			content: "dns:\n  nameserver-policy:\n    \"geosite:cn,apple,private\": [223.5.5.5]\n",
			want:    []string{"cn", "apple", "private"},
		},
		"a rule names one and then a target": {
			content: "rules:\n  - GEOSITE,cn,DIRECT\n  - GEOSITE,youtube,PROXY\n",
			want:    []string{"cn", "youtube"},
		},
		"negation and attributes stay attached": {
			content: "rules:\n  - GEOSITE,geolocation-!cn,PROXY\n  - GEOSITE,cn@ads,REJECT\n",
			want:    []string{"geolocation-!cn", "cn@ads"},
		},
		"case does not matter": {
			content: "rules:\n  - GeoSite,CN,DIRECT\n",
			want:    []string{"cn"},
		},
		"the same category twice is one job": {
			content: "rules:\n  - GEOSITE,cn,DIRECT\ndns:\n  nameserver-policy:\n    \"geosite:cn\": [1.1.1.1]\n",
			want:    []string{"cn"},
		},
		"a longer word is not a reference": {
			content: "rules:\n  - DOMAIN,notgeosite:cn.example.com,DIRECT\n  - DOMAIN-SUFFIX,mygeosite,DIRECT\n",
			want:    nil,
		},
		"geoip is a different loader": {
			content: "rules:\n  - GEOIP,CN,DIRECT\n",
			want:    nil,
		},
		"nothing at all": {
			content: "rules: []\n",
			want:    nil,
		},
		"a rule may breathe after its commas": {
			content: "rules:\n  - GEOSITE, cn, DIRECT\n",
			want:    []string{"cn"},
		},
		"a policy key may breathe after its commas": {
			content: "dns:\n  nameserver-policy:\n    \"geosite:cn, apple\": [1.1.1.1]\n",
			want:    []string{"cn", "apple"},
		},
		"the fallback filter names bare categories": {
			content: "dns:\n  fallback-filter:\n    geoip: true\n    geosite:\n      - cn\n      - gfw\n",
			want:    []string{"cn", "gfw"},
		},
		"an inline fallback filter list": {
			content: "dns:\n  fallback-filter:\n    geosite: [cn]\n",
			want:    []string{"cn"},
		},
		"prose around a reference is not a category": {
			content: "# the geosite:cn database is documented elsewhere\n",
			want:    nil,
		},
		"a rule may breathe before its comma too": {
			content: "rules:\n  - GEOSITE , cn, DIRECT\n",
			want:    []string{"cn"},
		},
		"a logic rule wraps a reference in parentheses": {
			content: "rules:\n  - AND,((GEOSITE,cn),(DST-PORT,443)),DIRECT\n",
			want:    []string{"cn"},
		},
		"nested logic keeps every reference": {
			content: "rules:\n  - OR,((GEOSITE,apple),(NOT,((GEOSITE,cn)))),PROXY\n",
			want:    []string{"apple", "cn"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := GeoSiteCategoriesIn(testCase.content)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("categories = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

func TestGeoSiteCategoriesInStaysLinearOnRepeatedMarkers(t *testing.T) {
	line := strings.Repeat("geosite,cn,", 32*1024)
	start := time.Now()
	got := GeoSiteCategoriesIn(line)
	elapsed := time.Since(start)
	if !reflect.DeepEqual(got, []string{"cn"}) {
		t.Fatalf("categories = %#v, want [cn]", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("scanning %d bytes of repeated markers took %v", len(line), elapsed)
	}
}

func TestGeoSiteCategoriesInReadsClassicalProviderPayloads(t *testing.T) {
	text := "DOMAIN-SUFFIX,example.com\nGEOSITE,cn\n"
	if got := GeoSiteCategoriesIn(text); !reflect.DeepEqual(got, []string{"cn"}) {
		t.Fatalf("text payload categories = %#v, want [cn]", got)
	}
	yamlPayload := "payload:\n  - GEOSITE,apple\n  - DOMAIN,x.com\n"
	if got := GeoSiteCategoriesIn(yamlPayload); !reflect.DeepEqual(got, []string{"apple"}) {
		t.Fatalf("yaml payload categories = %#v, want [apple]", got)
	}
}

func TestGeoSiteCategoriesInDoesNotCollectRuleTargets(t *testing.T) {
	got := GeoSiteCategoriesIn("rules:\n  - GEOSITE,cn,节点选择\n  - GEOSITE,apple,DIRECT\n")
	want := []string{"cn", "apple"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("categories = %#v, want %#v", got, want)
	}
}

func TestGeoxURLGeositeIsAURLNotACategory(t *testing.T) {
	unquoted := `
geox-url:
  geosite: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
  geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat
rules:
  - GEOSITE,cn,DIRECT
dns:
  nameserver-policy:
    "geosite:gfw": ["8.8.8.8"]
`
	got := GeoSiteCategoriesIn(unquoted)
	for _, name := range got {
		if name == "https" || name == "http" {
			t.Fatalf("a URL scheme was collected as a category: %v", got)
		}
	}
	want := map[string]bool{"cn": false, "gfw": false}
	for _, name := range got {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("real category %q lost while excluding the URL: %v", name, got)
		}
	}
}

func TestQuotingStyleDoesNotChangeTheCategorySet(t *testing.T) {
	shapes := map[string]string{
		"unquoted":      "geox-url:\n  geosite: https://e.test/geosite.dat\nrules:\n  - GEOSITE,cn,DIRECT\n",
		"double quoted": "geox-url:\n  geosite: \"https://e.test/geosite.dat\"\nrules:\n  - GEOSITE,cn,DIRECT\n",
		"single quoted": "geox-url:\n  geosite: 'https://e.test/geosite.dat'\nrules:\n  - GEOSITE,cn,DIRECT\n",
	}
	var first []string
	var firstName string
	for name, doc := range shapes {
		got := GeoSiteCategoriesIn(doc)
		if first == nil {
			first, firstName = got, name
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("%s yields %v but %s yields %v", name, got, firstName, first)
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("%s yields %v but %s yields %v", name, got, firstName, first)
			}
		}
	}
	if len(first) != 1 || first[0] != "cn" {
		t.Fatalf("want exactly [cn], got %v", first)
	}
}

func TestUnquotedPolicyKeyStillCollects(t *testing.T) {
	doc := "dns:\n  nameserver-policy:\n    geosite:cn: [\"223.5.5.5\"]\n"
	got := GeoSiteCategoriesIn(doc)
	if len(got) != 1 || got[0] != "cn" {
		t.Fatalf("unquoted policy key lost: %v", got)
	}
}

func TestGeoIPTwinStaysInertOnGeoxURL(t *testing.T) {
	doc := "geox-url:\n  geoip: https://e.test/geoip.dat\n"
	if got := GeoIPCountriesIn(doc); len(got) != 0 {
		t.Fatalf("geoip scanner collected from a URL: %v", got)
	}
}

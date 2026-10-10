package clash

import (
	"slices"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata"
)

func countriesIn(t *testing.T, content string) []string {
	t.Helper()
	found := GeoIPCountriesIn(content)
	slices.Sort(found)
	return found
}

func TestGeoIPCountriesInReadsBothRuleSpellings(t *testing.T) {
	found := countriesIn(t, `rules:
  - GEOIP,cn,DIRECT
  - GEOIP,us,PROXY,no-resolve
  - SRC-GEOIP,jp,DIRECT
  - GEOIP, hk ,DIRECT
`)
	for _, want := range []string{"cn", "us", "jp", "hk"} {
		if !slices.Contains(found, want) {
			t.Fatalf("missed %q in %v", want, found)
		}
	}
}

func TestGeoIPCountriesInDoesNotReadTheFallbackFilterBoolean(t *testing.T) {
	found := countriesIn(t, `dns:
  fallback-filter:
    geoip: true
    geoip-code: CN
`)
	if slices.Contains(found, "true") {
		t.Fatalf("read the fallback-filter boolean as a country code: %v", found)
	}
	if !slices.Contains(found, "cn") {
		t.Fatalf("missed the fallback-filter geoip-code: %v", found)
	}
}

func TestGeoIPCountriesInHandlesNegationAndLogicRules(t *testing.T) {
	found := countriesIn(t, `rules:
  - GEOIP,!cn,PROXY
  - AND,((GEOIP,us),(DST-PORT,443)),DIRECT
`)
	if slices.Contains(found, "!cn") {
		t.Fatalf("collected a negated name that no lookup uses: %v", found)
	}
	for _, want := range []string{"cn", "us"} {
		if !slices.Contains(found, want) {
			t.Fatalf("missed %q in %v", want, found)
		}
	}
}

func TestGeoIPCountriesInSkipsLan(t *testing.T) {
	if found := countriesIn(t, "rules:\n  - GEOIP,lan,DIRECT\n"); slices.Contains(found, "lan") {
		t.Fatalf("collected lan, which never loads a matcher: %v", found)
	}
}

func TestGeoIPCountriesInIgnoresProseAndLongerWords(t *testing.T) {
	found := countriesIn(t, `# the geoip database is large
# notgeoip,zz,DIRECT
rules:
  - GEOSITE,cn,DIRECT
`)
	if len(found) != 0 {
		t.Fatalf("collected %v from a configuration naming no GEOIP rule", found)
	}
}

func TestPrepareGeoIPCacheReportsWhenNothingIsNamed(t *testing.T) {
	summary, err := PrepareGeoIPCache("rules:\n  - MATCH,DIRECT\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "no countries") {
		t.Fatalf("summary does not say nothing was named: %q", summary)
	}
}

func TestGeoIPCountriesInReadsRuleProviderPayloads(t *testing.T) {
	classical := "payload:\n  - GEOIP,jp,PROXY\n  - DOMAIN-SUFFIX,example.com,DIRECT\n"
	if found := countriesIn(t, classical); !slices.Contains(found, "jp") {
		t.Fatalf("a classical payload's GEOIP rule was not seen: %v", found)
	}
	text := "GEOIP,kr,PROXY\nDOMAIN-SUFFIX,a.b,DIRECT\n"
	if found := countriesIn(t, text); !slices.Contains(found, "kr") {
		t.Fatalf("a text payload's GEOIP rule was not seen: %v", found)
	}
	noResolve := "payload:\n  - GEOIP,sg,DIRECT,no-resolve\n"
	if found := countriesIn(t, noResolve); !slices.Contains(found, "sg") {
		t.Fatalf("a no-resolve payload rule was not seen: %v", found)
	}
}

func TestTheLineFormsCarryWhatTheSliceFormsFound(t *testing.T) {
	const config = `rules:
  - GEOIP,cn,DIRECT
  - GEOIP,jp,PROXY
  - GEOSITE,private,DIRECT
`
	countries := GeoIPCountryLines(config)
	for _, want := range GeoIPCountriesIn(config) {
		if !slices.Contains(strings.Split(countries, "\n"), want) {
			t.Fatalf("the line form dropped %q that the slice form found: %q", want, countries)
		}
	}
	categories := GeoSiteCategoryLines(config)
	for _, want := range GeoSiteCategoriesIn(config) {
		if !slices.Contains(strings.Split(categories, "\n"), want) {
			t.Fatalf("the line form dropped %q that the slice form found: %q", want, categories)
		}
	}
	if got := GeoIPCountryLines("rules:\n  - MATCH,DIRECT\n"); got != "" {
		t.Fatalf("a configuration naming no country produced %q, not an empty string", got)
	}
}

func TestGeodataModeEnabledReadsTheKeyThePlanReads(t *testing.T) {
	previous := geodata.GeodataMode()
	geodata.SetGeodataMode(false)
	t.Cleanup(func() { geodata.SetGeodataMode(previous) })

	for content, want := range map[string]bool{
		"geodata-mode: true\nrules:\n  - MATCH,DIRECT\n":  true,
		"geodata-mode: false\nrules:\n  - MATCH,DIRECT\n": false,
		"rules:\n  - MATCH,DIRECT\n":                      false,
		"":                                                false,
		"geodata-mode: [\n":                               false,
	} {
		if got := GeodataModeEnabled(content); got != want {
			t.Fatalf("GeodataModeEnabled(%q) = %v, want %v", content, got, want)
		}
	}
}

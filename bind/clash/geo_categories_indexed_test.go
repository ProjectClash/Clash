package clash

import (
	"encoding/json"
	"slices"
	"testing"
)

const geoIndexedDocument = "rules:\n  - GEOSITE,cn,DIRECT\n  - GEOIP,cn,DIRECT,no-resolve\n  - SRC-GEOIP,jp,DIRECT\n  - MATCH,DIRECT\n"

func TestTheGeoCategoriesOfIndexedRulesAreFound(t *testing.T) {
	setupForMatch(t)
	published, root := finalizeWithRuleIndex(t, geoIndexedDocument, t.TempDir())
	if _, ok := root["rules"]; ok {
		t.Fatal("the published configuration still writes its rules; this test is about one that does not")
	}
	if got := GeoSiteCategoriesIn(published); !slices.Contains(got, "cn") {
		t.Errorf("GeoSite categories %q, want cn", got)
	}
	if got := GeoIPCountriesIn(published); !slices.Contains(got, "cn") || !slices.Contains(got, "jp") {
		t.Errorf("GeoIP countries %q, want cn and jp", got)
	}
}

func TestFinalizeAnswersTheGeoCategoriesOfIndexedRules(t *testing.T) {
	setupForMatch(t)
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir})
	options, _ := json.Marshal(map[string]any{"targetProfile": RuntimeProfileIOSPacketTunnel, "geoCategories": true})
	box, err := FinalizeForIOSWithOptions(geoIndexedDocument, string(resources), string(options))
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Text      string    `json:"text"`
		Sites     *[]string `json:"geositeCategories"`
		Countries *[]string `json:"geoipCountries"`
	}
	if err := json.Unmarshal([]byte(box.Value), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Sites == nil || !slices.Contains(*answer.Sites, "cn") {
		t.Errorf("geositeCategories %v, want cn", answer.Sites)
	}
	if answer.Countries == nil || !slices.Contains(*answer.Countries, "cn") {
		t.Errorf("geoipCountries %v, want cn", answer.Countries)
	}
}

func TestADocumentThatWritesItsRulesIsReadFromItsText(t *testing.T) {
	if got := indexedRuleLinesIn("x-clash-rule-index: {path: /nowhere, sha256: x}\nrules:\n  - GEOSITE,us,DIRECT\n", nil); got != "" {
		t.Fatalf("index lines read for a document that writes its rules: %q", got)
	}
	if got := GeoSiteCategoriesIn("rules:\n  - GEOSITE,us,DIRECT\n"); !slices.Equal(got, []string{"us"}) {
		t.Fatalf("GeoSite categories %q, want [us]", got)
	}
}

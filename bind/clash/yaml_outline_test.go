package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestYAMLOutlineGivesSectionsAndItemsTheirLines(t *testing.T) {
	box, err := YAMLOutlineForIOS(yamlEditFixture)
	if err != nil {
		t.Fatal(err)
	}
	var outline struct {
		OK       bool `json:"ok"`
		Sections []struct {
			Key   string `json:"key"`
			Kind  string `json:"kind"`
			Start int    `json:"start"`
			End   int    `json:"end"`
			Items []struct {
				Key   string `json:"key"`
				Start int    `json:"start"`
				End   int    `json:"end"`
			} `json:"items"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(box.Value), &outline); err != nil || !outline.OK {
		t.Fatalf("outline: %v %s", err, box.Value)
	}
	byKey := map[string]int{}
	for i, section := range outline.Sections {
		byKey[section.Key] = i
	}
	mode := outline.Sections[byKey["mode"]]
	if mode.Start != 2 || mode.End != 2 || mode.Kind != "scalar" {
		t.Fatalf("mode = %+v", mode)
	}
	rules := outline.Sections[byKey["rules"]]
	if rules.Kind != "sequence" || rules.Start != 18 || rules.End != 22 || len(rules.Items) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules.Items[1].Start != 21 || rules.Items[1].End != 21 {
		t.Fatalf("the second rule sits after the comment, on line 21: %+v", rules.Items[1])
	}
	proxies := outline.Sections[byKey["proxies"]]
	if len(proxies.Items) != 2 || proxies.Items[0].Start != 12 || proxies.Items[0].End != 15 {
		t.Fatalf("proxies = %+v", proxies)
	}
	dns := outline.Sections[byKey["dns"]]
	if dns.Kind != "mapping" || len(dns.Items) != 2 || dns.Items[1].Key != "nameserver" || dns.Items[1].End != 9 {
		t.Fatalf("dns = %+v", dns)
	}
}

func TestYAMLOutlineRefusesWhatItCannotRead(t *testing.T) {
	box, err := YAMLOutlineForIOS("a: 1\n---\nb: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	var out yamlEditOutcome
	_ = json.Unmarshal([]byte(box.Value), &out)
	if out.OK || out.Code != "multiDocument" {
		t.Fatalf("got %+v", out)
	}
}

const templatedYAML = `mixed-port: 7890
p: &p {type: select, proxies: [DIRECT]}
proxy-groups:
  - name: Templated
    <<: *p
  - name: Plain
    type: select
    proxies: [DIRECT]
# ---- rules ----
rules:
  - MATCH,DIRECT
`

func TestYAMLOutlineOfATemplatedConfiguration(t *testing.T) {
	answer, err := yamlOutline(templatedYAML)
	if err != nil || !answer.OK {
		t.Fatalf("%+v %v", answer, err)
	}
	var keys []string
	for _, section := range answer.Sections {
		keys = append(keys, section.Key)
	}
	if strings.Join(keys, ",") != "mixed-port,p,proxy-groups,rules" || len(answer.Sections[3].Items) != 1 {
		t.Fatalf("%+v", answer)
	}
	if groups := answer.Sections[2]; groups.Start != 3 || groups.End != 8 || len(groups.Items) != 2 || groups.Items[1].Start != 6 || groups.Items[1].End != 8 {
		t.Errorf("proxy-groups: %+v", groups)
	}
}

func TestEditYAMLAnEntryAwayFromTheAnchorsOfItsSection(t *testing.T) {
	mustEdit(t, templatedYAML, `["proxy-groups",1,"name"]`, "set", `"Renamed"`,
		strings.Replace(templatedYAML, "  - name: Plain\n", "  - name: Renamed\n", 1))
	if out := runYAMLEdit(t, templatedYAML, `["proxy-groups",0,"name"]`, "set", `"Renamed"`); out.OK || out.Code != "anchor" {
		t.Errorf("%+v", out)
	}
	runOn := "p: &p {type: select}\nproxy-groups:\n  - name: T\n    <<: *p\n  - name: \"a\n# b\"\n    type: select\n# after\nrules: []\n"
	mustEdit(t, runOn, `["proxy-groups",1,"type"]`, "set", `"url-test"`, strings.Replace(runOn, "type: select\n# after", "type: url-test\n# after", 1))
	mustEdit(t, runOn, `["rules"]`, "set", `["MATCH,DIRECT"]`, strings.Replace(runOn, "rules: []\n", "rules:\n  - MATCH,DIRECT\n", 1))
}

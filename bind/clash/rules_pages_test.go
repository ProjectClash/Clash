package clash

import (
	"bytes"
	"encoding/json"
	"testing"

	mhttp "github.com/metacubex/http"
	"github.com/metacubex/http/httptest"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
	RW "github.com/ProjectClash/Clash/rules/wrapper"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestTheRulesAreReadAPageAtATimeAndByWhatMatched(t *testing.T) {
	lines := []string{"DOMAIN,a.example,DIRECT", "DOMAIN-SUFFIX,b.example,REJECT", "DST-PORT,8443,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "MATCH,DIRECT"}
	parse := func(line string) C.Rule {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	var list C.RuleList
	compiler := clashindex.NewCompiler()
	for _, line := range lines {
		rule := parse(line)
		list = append(list, RW.NewRuleWrapper(rule))
		if err := compiler.Add(line, rule); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if _, _, err := compiler.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	index, err := clashindex.Decode(buffer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var others []C.Rule
	index.Others(func(_ int, line string) bool { others = append(others, RW.NewRuleWrapper(parse(line))); return true })
	table, err := index.Table(others)
	if err != nil {
		t.Fatal(err)
	}
	previous := tunnel.RuleTable()
	t.Cleanup(func() {
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), previous, nil, map[string]P.RuleProvider{})
	})
	for _, rules := range []C.RuleTable{list, table} {
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), rules, nil, map[string]P.RuleProvider{})
		for _, m := range []C.Metadata{{Host: "x.b.example", DstPort: 443}, {Host: "other", DstPort: 8443}} {
			m := m
			rules.Walk(&m, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
		}
		var page struct {
			Total, Offset int
			Noted         *int
			Rules         []struct {
				Index int
				Type  string
				Extra struct{ HitCount uint64 }
			}
		}
		if err := json.Unmarshal([]byte(RulesPageJSON(1, 2, "")), &page); err != nil || page.Total != 5 || page.Offset != 1 || len(page.Rules) != 2 || page.Rules[0].Index != 1 || page.Rules[0].Extra.HitCount != 1 || page.Noted != nil {
			t.Fatalf("%T page: %v %+v", rules, err, page)
		}
		if err := json.Unmarshal([]byte(RulesPageJSON(9, 2, "")), &page); err != nil || page.Offset != 5 || len(page.Rules) != 0 {
			t.Fatalf("%T past the end: %v %+v", rules, err, page)
		}
		if err := json.Unmarshal([]byte(RuleHitsJSON(0, 0)), &page); err != nil || page.Noted == nil || *page.Noted != 2 || len(page.Rules) != 2 || page.Rules[0].Index != 1 || page.Rules[1].Index != 2 {
			t.Fatalf("%T hits: %v %+v", rules, err, page)
		}
		var typed struct {
			Total, Offset int
			Matched       *int
			Rules         []struct{ Index int }
			Error         string
		}
		check := func(answer string, wantMatched int, wantIndexes ...int) {
			t.Helper()
			typed.Matched, typed.Rules = nil, nil
			if err := json.Unmarshal([]byte(answer), &typed); err != nil || typed.Matched == nil || *typed.Matched != wantMatched || len(typed.Rules) != len(wantIndexes) {
				t.Fatalf("%T typed page: %v %s", rules, err, answer)
			}
			for k, i := range wantIndexes {
				if typed.Rules[k].Index != i {
					t.Fatalf("%T typed page: %s", rules, answer)
				}
			}
		}
		check(RulesPageJSON(0, 0, `["DOMAIN-SUFFIX","ip-cidr"]`), 2, 1, 3)
		check(RulesPageJSON(1, 1, `["DOMAIN-SUFFIX","IP-CIDR"]`), 2, 3)
		check(RulesPageJSON(0, 0, `["GEOIP"]`), 0)
		if err := json.Unmarshal([]byte(RulesPageJSON(0, 0, `DOMAIN`)), &typed); err != nil || typed.Error == "" {
			t.Fatalf("%T a types list that does not read: %+v", rules, typed)
		}
		recorder := httptest.NewRecorder()
		serveRulesAnswer(func(offset, limit int, types string) string {
			return rulesPageJSON(offset, limit, typesOfList(types))
		})(recorder, httptest.NewRequest(mhttp.MethodGet, "/clash/v1/rules-page?types=dst-port,MATCH", nil))
		check(recorder.Body.String(), 2, 2, 4)
	}
}

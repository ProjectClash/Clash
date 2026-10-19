package route

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
	RW "github.com/ProjectClash/Clash/rules/wrapper"
	"github.com/ProjectClash/Clash/tunnel"
)


var rulesJSONTestLines = []string{
	"DOMAIN,www.example.com,DIRECT",
	"DOMAIN-SUFFIX,example.org,REJECT",
	"DOMAIN-KEYWORD,<ads&>,REJECT",
	"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
	"IP-CIDR6,2001:db8::/32,REJECT",
	"DST-PORT,8443,DIRECT",
	"AND,((NETWORK,udp),(DOMAIN-SUFFIX,quic.example)),REJECT",
	"MATCH,DIRECT",
}

func rulesJSONTables(t *testing.T) (C.RuleList, *clashindex.Table) {
	t.Helper()
	var list C.RuleList
	compiler := clashindex.NewCompiler()
	parse := func(line string) C.Rule {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	for _, line := range rulesJSONTestLines {
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
	index.Others(func(_ int, line string) bool {
		others = append(others, RW.NewRuleWrapper(parse(line)))
		return true
	})
	table, err := index.Table(others)
	if err != nil {
		t.Fatal(err)
	}
	return list, table
}

func readRules(t *testing.T, table C.RuleTable) string {
	t.Helper()
	previous := tunnel.RuleTable()
	tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), table, nil, map[string]P.RuleProvider{})
	defer tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), previous, nil, map[string]P.RuleProvider{})
	recorder := httptest.NewRecorder()
	getRules(recorder, httptest.NewRequest(http.MethodGet, "/rules", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	return recorder.Body.String()
}

var timesInJSON = regexp.MustCompile(`"(hitAt|missAt)":"[^"]*"`)

func TestTheRulesOfACompiledTableAreTheBytesOfTheSlice(t *testing.T) {
	list, table := rulesJSONTables(t)
	want, got := readRules(t, list), readRules(t, table)
	if want != got {
		t.Fatalf("slice:\n%s\ncompiled:\n%s", want, got)
	}
	if !strings.HasSuffix(got, "]}\n") || !strings.Contains(got, `\u003cads\u0026\u003e`) {
		t.Fatalf("not render.JSON's bytes: %s", got)
	}
	for _, host := range []string{"www.example.com", "a.example.org", "x<ads&>y.net", "other.net"} {
		for _, rules := range []C.RuleTable{list, table} {
			m := &C.Metadata{Host: host, NetWork: C.TCP, DstPort: 443}
			rules.Walk(m, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
		}
	}
	for _, rules := range []C.RuleTable{list, table} {
		previous := tunnel.RuleTable()
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), rules, nil, map[string]P.RuleProvider{})
		recorder := httptest.NewRecorder()
		disableRules(recorder, httptest.NewRequest(http.MethodPatch, "/rules/disable", strings.NewReader(`{"1":true,"5":true,"99":true}`)))
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), previous, nil, map[string]P.RuleProvider{})
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("disable: %d", recorder.Code)
		}
	}
	m := &C.Metadata{Host: "a.example.org", NetWork: C.TCP, DstPort: 8443, DstIP: netip.MustParseAddr("192.0.2.1")}
	for _, rules := range []C.RuleTable{list, table} {
		copy := *m
		rules.Walk(&copy, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
	}
	raw := readRules(t, table)
	want = timesInJSON.ReplaceAllString(readRules(t, list), `"$1":"T"`)
	got = timesInJSON.ReplaceAllString(raw, `"$1":"T"`)
	if want != got {
		t.Fatalf("after the same flows:\nslice:\n%s\ncompiled:\n%s", want, got)
	}
	var decoded struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil || len(decoded.Rules) != len(rulesJSONTestLines) || !decoded.Rules[1].Extra.Disabled || decoded.Rules[0].Extra.HitCount != 1 {
		t.Fatalf("%v %+v", err, decoded)
	}
}

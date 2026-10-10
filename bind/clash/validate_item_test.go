package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

const validateContext = `{"proxies":["a","b"],"groups":["Proxy"],"proxyProviders":["sub"],"ruleProviders":["ads"],"subRules":["s1"]}`

func validateItem(t *testing.T, kind, item, context string) validateItemResult {
	t.Helper()
	box, err := ValidateItemForIOS(kind, item, context)
	if err != nil {
		t.Fatalf("%s %s: %v", kind, item, err)
	}
	var result validateItemResult
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func quoted(line string) string {
	encoded, _ := json.Marshal(line)
	return string(encoded)
}

func TestValidateRuleItem(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{"DOMAIN-SUFFIX,example.com,Proxy", ""},
		{"MATCH,DIRECT", ""},
		{"RULE-SET,ads,REJECT", ""},
		{"GEOIP,CN,DIRECT,no-resolve", ""},
		{"GEOSITE,no-such-code,Proxy", ""},
		{"AND,((GEOIP,CN),(NETWORK,tcp)),a", ""},
		{"SUB-RULE,(NETWORK,tcp),s1", ""},
		{"DOMAIN,example.com", "rules[0] [DOMAIN,example.com] error: format invalid"},
		{"DOMAIN,example.com,Nope", "rules[0] [DOMAIN,example.com,Nope] error: proxy [Nope] not found"},
		{"SUB-RULE,(NETWORK,tcp),s2", "rules[0] [SUB-RULE,(NETWORK,tcp),s2] error: sub-rule [s2] not found"},
		{"RULE-SET,nope,Proxy", "rules[0] [RULE-SET,nope,Proxy] error: rule set [nope] not found"},
		{"AND,((RULE-SET,nope),(NETWORK,tcp)),Proxy", "rule set [nope] not found"},
		{"IP-CIDR,300.0.0.0/8,Proxy", "rules[0] [IP-CIDR,300.0.0.0/8,Proxy] error: "},
		{"NOPE,x,Proxy", "unsupported rule type: NOPE"},
		{"AND,NETWORK,Proxy", "payload format error"},
	} {
		result := validateItem(t, "rule", quoted(c.line), validateContext)
		if c.want == "" {
			if !result.OK {
				t.Errorf("%s: %+v", c.line, result)
			}
		} else if result.OK || !strings.Contains(result.Message, c.want) {
			t.Errorf("%s: %+v, want %q", c.line, result, c.want)
		}
	}
	placed := validateItem(t, "rule", quoted("DOMAIN,x,Nope"), `{"section":"sub-rules[s1]","index":3}`)
	if placed.Message != "sub-rules[s1][3] [DOMAIN,x,Nope] error: proxy [Nope] not found" {
		t.Errorf("%+v", placed)
	}
}

func TestValidateProxyItem(t *testing.T) {
	good := `{"name":"c","type":"ss","server":"192.0.2.1","port":8388,"cipher":"aes-128-gcm","password":"p"}`
	if result := validateItem(t, "proxy", good, validateContext); !result.OK {
		t.Fatalf("%+v", result)
	}
	for _, c := range []struct{ item, want string }{
		{strings.Replace(good, `"aes-128-gcm"`, `"rot13"`, 1), "rot13"},
		{strings.Replace(good, `"name":"c"`, `"name":"a"`, 1), "proxy a is the duplicate name"},
		{strings.Replace(good, `"name":"c"`, `"name":"DIRECT"`, 1), "proxy DIRECT is the duplicate name"},
		{strings.Replace(good, `"name":"c"`, `"name":"Proxy"`, 1), "proxy group Proxy: the duplicate name"},
		{`{"name":"c","type":"nope"}`, "nope"},
	} {
		if result := validateItem(t, "proxy", c.item, validateContext); result.OK || !strings.Contains(result.Message, c.want) {
			t.Errorf("%s: %+v, want %q", c.item, result, c.want)
		}
	}
}

func TestValidateGroupItem(t *testing.T) {
	for _, item := range []string{
		`{"name":"G","type":"select","proxies":["a","Proxy","DIRECT"]}`,
		`{"name":"G","type":"url-test","use":["sub"],"interval":300}`,
		`{"name":"G","type":"select","include-all":true,"filter":"^a"}`,
		`{"name":"G","type":"fallback","proxies":["b"],"empty-fallback":"a"}`,
	} {
		if result := validateItem(t, "proxyGroup", item, validateContext); !result.OK {
			t.Errorf("%s: %+v", item, result)
		}
	}
	for _, c := range []struct{ item, want string }{
		{`{"name":"G","type":"select","proxies":["nope"]}`, "G: 'nope' not found"},
		{`{"name":"G","type":"select","use":["nope"]}`, "G: 'nope' not found"},
		{`{"name":"G","type":"select","use":["Proxy"]}`, "can't contains in `use`"},
		{`{"name":"G","type":"select"}`, "G: `use` or `proxies` missing"},
		{`{"name":"G","type":"relay","proxies":["a"]}`, "relay type was removed"},
		{`{"name":"G","type":"nope","proxies":["a"]}`, "unsupported type: nope"},
		{`{"type":"select","proxies":["a"]}`, "format error"},
		{`{"name":"G","type":"select","proxies":["a"],"empty-fallback":"Proxy"}`, "empty fallback proxy 'Proxy' not found"},
		{`{"name":"G","type":"select","include-all":true,"filter":"("}`, "("},
		{`{"name":"G","type":"select","proxies":["a"],"filter":"("}`, "("},
		{`{"name":"Proxy","type":"select","proxies":["a"]}`, "Proxy"},
		{`{"name":"a","type":"select","proxies":["b"]}`, "proxy group a: the duplicate name"},
		{`{"name":"sub","type":"select","proxies":["b"]}`, "sub"},
		{`{"name":"G","type":"select","proxies":["a"],"expected-status":"x"}`, "G: "},
	} {
		if result := validateItem(t, "proxyGroup", c.item, validateContext); result.OK || !strings.Contains(result.Message, c.want) {
			t.Errorf("%s: %+v, want %q", c.item, result, c.want)
		}
	}
}

func TestValidateItemRejectsBadRequests(t *testing.T) {
	for _, c := range [][3]string{
		{"widget", `"x"`, ""},
		{"rule", `{"x":1}`, ""},
		{"proxy", `"x"`, ""},
		{"rule", `"MATCH,DIRECT"`, "{"},
	} {
		if _, err := ValidateItemForIOS(c[0], c[1], c[2]); err == nil {
			t.Errorf("%v: no error", c)
		}
	}
}

func TestValidateProxyItemChecksTheDecodedName(t *testing.T) {
	if result := validateItem(t, "proxy", `{"Name":"DIRECT","type":"direct"}`, "{}"); result.OK || !strings.Contains(result.Message, "proxy DIRECT is the duplicate name") {
		t.Errorf("%+v", result)
	}
}

func TestValidateProxyItemCodexRound2(t *testing.T) {
	if result := validateItem(t, "proxy", `{"name":"p","type":"trojan","server":"192.0.2.1","port":443,"Password":"secret"}`, "{}"); !result.OK {
		t.Errorf("Password: %+v", result)
	}
	dialer := `{"name":"p","type":"socks5","server":"192.0.2.1","port":1080,"dialer-proxy":"missing"}`
	if result := validateItem(t, "proxy", dialer, "{}"); result.OK || result.Message != "proxy [p] dialer-proxy [missing] not found" {
		t.Errorf("dialer-proxy: %+v", result)
	}
	if result := validateItem(t, "proxy", dialer, `{"groups":["missing"]}`); !result.OK {
		t.Errorf("dialer-proxy naming a group: %+v", result)
	}
}

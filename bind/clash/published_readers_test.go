package clash

import (
	"encoding/json"
	"testing"
)

func TestTheAppsReadersReadAPublishWhoseIndexedRulesNameARuleSet(t *testing.T) {
	setupForMatch(t)
	source := `mode: rule
proxies:
  - {name: HK, type: ss, server: hk.example.net, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK, DIRECT]}
rule-providers:
  Apple: {type: inline, behavior: domain, payload: [apple.test, '+.apple.test']}
rules:
  - RULE-SET,Apple,DIRECT
  - DOMAIN-SUFFIX,hk.test,HK
  - DOMAIN,proxy.test,Proxy
  - AND,((DOMAIN-SUFFIX,sub.test),(DST-PORT,443)),REJECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,Proxy
`
	dir := t.TempDir()
	published, root := finalizeWithRuleIndex(t, source, dir)
	if _, indexed := root["x-clash-rule-index"]; !indexed {
		t.Fatalf("not published to an index:\n%s", published)
	}
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})

	catalog, err := OpenNodeCatalogForIOS(published, string(resources), "")
	if err != nil {
		t.Fatalf("node catalog: %v", err)
	}
	catalog.Close()
	if _, err := ProxyCatalogForIOS(published, string(resources), ""); err != nil {
		t.Fatalf("proxy catalog: %v", err)
	}
	if _, err := RuleProviderCatalogForIOS(published, string(resources), false); err != nil {
		t.Fatalf("rule-set catalog: %v", err)
	}

	for _, query := range []string{
		`{"host":"www.apple.test","port":443,"network":"tcp"}`,
		`{"host":"a.hk.test","port":443,"network":"tcp"}`,
		`{"host":"proxy.test","port":80,"network":"tcp"}`,
		`{"host":"x.sub.test","port":443,"network":"tcp"}`,
		`{"ip":"10.1.2.3","port":53,"network":"udp"}`,
		`{"host":"other.test","port":443,"network":"tcp"}`,
	} {
		written, indexed := runMatch(t, source, "", query), runMatch(t, published, "", query)
		if written.Matched != indexed.Matched || written.Undecided != indexed.Undecided || written.Policy != indexed.Policy || written.Reason != indexed.Reason ||
			(written.Index == nil) != (indexed.Index == nil) || (written.Index != nil && *written.Index != *indexed.Index) {
			t.Errorf("%s: as written %+v, published %+v", query, written, indexed)
		}
	}
}

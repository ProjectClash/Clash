package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func setupForMatch(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	return base
}

func runMatch(t *testing.T, document, resources, query string) matchRuleResult {
	t.Helper()
	box, err := MatchRuleForIOS(document, resources, query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	var result matchRuleResult
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMatchRuleWalksRulesAsTheTunnel(t *testing.T) {
	base := setupForMatch(t)
	working := filepath.Join(base, "working")
	if err := os.MkdirAll(filepath.Join(working, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(working, "rules", "classical.yaml"), []byte("payload:\n  - DOMAIN-KEYWORD,tracker\n  - DST-PORT,6881\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cached := filepath.Join(working, "cached-cn.yaml")
	if err := os.WriteFile(cached, []byte("payload:\n  - '+.cn.test'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	document := `mode: rule
rule-providers:
  ads: {type: inline, behavior: domain, payload: [ads.test, '+.ads.test']}
  classical: {type: file, behavior: classical, path: ./rules/classical.yaml}
  cn: {type: http, behavior: domain, url: https://example.com/cn.yaml}
  remote: {type: http, behavior: domain, url: https://example.com/remote.yaml}
proxy-groups:
  - {name: Proxy, type: select, proxies: [DIRECT]}
sub-rules:
  s1:
    - DST-PORT,8443,PASS-RULE
    - NETWORK,udp,REJECT
    - MATCH,Proxy
rules:
  - DOMAIN,pass.test,PASS
  - RULE-SET,ads,REJECT
  - RULE-SET,classical,REJECT-DROP
  - RULE-SET,cn,DIRECT
  - AND,((DOMAIN-SUFFIX,sub.test),(DST-PORT,443)),REJECT
  - SUB-RULE,(DOMAIN-SUFFIX,sub.test),s1
  - DOMAIN-SUFFIX,pass.test,Proxy
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - RULE-SET,remote,REJECT
  - IP-CIDR,192.0.2.0/24,Proxy
  - GEOIP,CN,DIRECT
  - PROCESS-NAME,curl,REJECT
  - MATCH,Proxy
`
	resources := `{"providerPaths":{"rule:cn":"` + cached + `"}}`
	for _, c := range []struct {
		query     string
		matched   bool
		index     int
		policy    string
		undecided string
	}{
		{`{"host":"x.ads.test"}`, true, 1, "REJECT", ""},
		{`{"host":"pass.test"}`, true, 6, "Proxy", ""},
		{`{"host":"my-tracker.example"}`, true, 2, "REJECT-DROP", ""},
		{`{"host":"a.example","port":6881}`, true, 2, "REJECT-DROP", ""},
		{`{"host":"www.cn.test"}`, true, 3, "DIRECT", ""},
		{`{"host":"a.sub.test","port":443}`, true, 4, "REJECT", ""},
		{`{"host":"a.sub.test","port":8443}`, true, 5, "Proxy", ""},
		{`{"host":"a.sub.test","port":80,"network":"udp"}`, true, 5, "REJECT", ""},
		{`{"host":"a.sub.test","port":80}`, true, 5, "Proxy", ""},
		{`{"ip":"10.1.2.3"}`, true, 7, "DIRECT", ""},
		{`{"host":"10.1.2.3"}`, true, 7, "DIRECT", ""},
		{`{"host":"other.example"}`, false, 8, "", "ruleSetUnavailable"},
	} {
		result := runMatch(t, document, resources, c.query)
		if c.undecided != "" {
			if !result.Undecided || result.Reason != c.undecided || *result.Index != c.index {
				t.Errorf("%s: %+v, want undecided %s at %d", c.query, result, c.undecided, c.index)
			}
			continue
		}
		if result.Matched != c.matched || result.Index == nil || *result.Index != c.index || result.Policy != c.policy {
			t.Errorf("%s: %+v, want %d %s", c.query, result, c.index, c.policy)
		}
	}
}

func TestMatchRuleStopsWhereTheTunnelWouldNeedMore(t *testing.T) {
	setupForMatch(t)
	document := "rules:\n  - IP-CIDR,192.0.2.0/24,Proxy\n  - GEOIP,CN,DIRECT\n  - PROCESS-NAME,curl,REJECT\n  - MATCH,Proxy\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [DIRECT]}\n"
	for _, c := range []struct {
		query, reason string
		index         int
	}{
		{`{"host":"a.example"}`, "needsIP", 0},
		{`{"host":"a.example","ip":"198.51.100.1"}`, "geodataUnavailable", 1},
	} {
		result := runMatch(t, document, "", c.query)
		if !result.Undecided || result.Reason != c.reason || *result.Index != c.index {
			t.Errorf("%s: %+v", c.query, result)
		}
	}
	if result := runMatch(t, document, "", `{"host":"a.example","ip":"192.0.2.9"}`); !result.Matched || result.Policy != "Proxy" {
		t.Errorf("%+v", result)
	}
	noGeo := "rules:\n  - PROCESS-NAME,curl,REJECT\n  - MATCH,DIRECT\n"
	if result := runMatch(t, noGeo, "", `{"host":"a.example"}`); !result.Undecided || result.Reason != "needsProcess" {
		t.Errorf("%+v", result)
	}
	if result := runMatch(t, "rules:\n  - DOMAIN,x.test,REJECT\n", "", `{"host":"a.example"}`); result.Matched || result.Policy != "DIRECT" || result.Index != nil {
		t.Errorf("no rule matched goes DIRECT: %+v", result)
	}
}

func TestMatchRuleRejectsBadQueries(t *testing.T) {
	setupForMatch(t)
	for _, query := range []string{`{}`, `{"host":"a","network":"icmp"}`, `{"ip":"nope"}`, `nope`} {
		if _, err := MatchRuleForIOS("rules: []\n", "", query); err == nil {
			t.Errorf("%s: no error", query)
		}
	}
}

func TestMatchRuleFableRound1(t *testing.T) {
	base := setupForMatch(t)
	circle := "rules:\n  - SUB-RULE,(NETWORK,tcp),a\nsub-rules:\n  a:\n    - SUB-RULE,(NETWORK,tcp),a\n"
	if _, err := MatchRuleForIOS(circle, "", `{"host":"a.example"}`); err == nil || !strings.Contains(err.Error(), "circular references") {
		t.Errorf("circle: %v", err)
	}
	missing := "rules:\n  - SUB-RULE,(NETWORK,tcp),a\nsub-rules:\n  a:\n    - SUB-RULE,(NETWORK,tcp),b\n"
	if _, err := MatchRuleForIOS(missing, "", `{"host":"a.example"}`); err == nil || !strings.Contains(err.Error(), "[b] not found") {
		t.Errorf("missing: %v", err)
	}
	document := "hosts:\n  mapped.test: 192.168.9.9\nrules:\n  - IN-TYPE,INNER,REJECT\n  - GEOIP,LAN,DIRECT\n  - IN-TYPE,TUN,REJECT-DROP\n"
	if result := runMatch(t, document, "", `{"ip":"192.168.1.5"}`); !result.Matched || *result.Index != 1 {
		t.Errorf("lan: %+v", result)
	}
	if result := runMatch(t, document, "", `{"ip":"8.8.8.8"}`); !result.Matched || *result.Index != 2 {
		t.Errorf("tun: %+v", result)
	}
	if result := runMatch(t, document, "", `{"host":"mapped.test"}`); !result.Matched || *result.Index != 1 {
		t.Errorf("hosts: %+v", result)
	}
	if result := runMatch(t, "rules:\n  - IN-NAME,mixed,REJECT\n", "", `{"host":"a.example"}`); !result.Undecided || result.Reason != "needsInbound" {
		t.Errorf("inbound: %+v", result)
	}
	if filepath.Dir(C.Path.MMDB()) != filepath.Join(base, "working") {
		t.Fatalf("the database is read from %s", C.Path.MMDB())
	}
	if err := os.WriteFile(C.Path.MMDB(), []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result := runMatch(t, "rules:\n  - GEOIP,CN,DIRECT\n", "", `{"ip":"1.2.3.4"}`); !result.Undecided || result.Reason != "geodataUnavailable" {
		t.Errorf("corrupt mmdb: %+v", result)
	}
}

func TestMatchRuleFableRound2(t *testing.T) {
	setupForMatch(t)
	document := `hosts:
  alias.test: real.test
  real.test: 192.168.9.9
  dual.test: [2001:db8::1, 10.0.0.1]
proxy-groups:
  - {name: Proxy, type: select, proxies: [DIRECT]}
rules:
  - IP-CIDR,192.168.0.0/16,REJECT,no-resolve
  - IP-CIDR6,2001:db8::/32,REJECT-DROP
  - GEOIP,LAN,DIRECT
  - MATCH,Proxy
`
	for _, c := range []struct {
		query string
		index int
	}{
		{`{"host":"alias.test"}`, 0},
		{`{"host":"real.test","ip":"8.8.8.8"}`, 0},
		{`{"host":"localhost"}`, 2},
		{`{"host":"dual.test"}`, 1},
	} {
		if result := runMatch(t, document, "", c.query); !result.Matched || *result.Index != c.index {
			t.Errorf("%s: %+v, want %d", c.query, result, c.index)
		}
	}
	for name, bad := range map[string]string{
		"unknown target":   "rules:\n  - DOMAIN,x.test,Nope\n",
		"missing sub-rule": "rules:\n  - SUB-RULE,(NETWORK,tcp),missing\n  - MATCH,DIRECT\n",
		"hosts circle":     "hosts:\n  a.test: b.test\n  b.test: a.test\nrules:\n  - IP-CIDR,0.0.0.0/0,DIRECT\n",
		"refused DSCP":     "rules:\n  - DSCP,abc,DIRECT\n",
	} {
		if _, err := MatchRuleForIOS(bad, "", `{"host":"a.test"}`); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := MatchRuleForIOS("rules:\n  - DOMAIN,x.test,Nope\n", "", `{"host":"a.test"}`); err == nil || err.Error() != "rules[0] [DOMAIN,x.test,Nope] error: proxy [Nope] not found" {
		t.Errorf("the core's sentence: %v", err)
	}
	empty := "sub-rules:\n  empty: []\n  outer:\n    - SUB-RULE,(NETWORK,tcp),empty\nrules:\n  - SUB-RULE,(NETWORK,tcp),outer\n  - MATCH,DIRECT\n"
	if result := runMatch(t, empty, "", `{"host":"a.test"}`); !result.Matched || *result.Index != 1 {
		t.Errorf("empty sub-rule: %+v", result)
	}
	off := "find-process-mode: off\nrules:\n  - PROCESS-NAME,curl,REJECT\n  - MATCH,DIRECT\n"
	if result := runMatch(t, off, "", `{"host":"a.example"}`); !result.Matched || *result.Index != 1 {
		t.Errorf("find-process-mode off: %+v", result)
	}
	loop := "rule-providers:\n  loop:\n    type: inline\n    behavior: classical\n    payload:\n      - AND,((RULE-SET,loop),(NETWORK,tcp))\nrules:\n  - RULE-SET,loop,DIRECT\n"
	if result := runMatch(t, loop, "", `{"host":"example.com"}`); !result.Undecided || result.Reason != "ruleSetLoop" {
		t.Errorf("rule set loop: %+v", result)
	}
}

func TestMatchRuleCodexRound2(t *testing.T) {
	setupForMatch(t)
	for name, bad := range map[string]string{
		"self-mapped host":           "hosts:\n  a.test: a.test\nrules:\n  - MATCH,DIRECT\n",
		"refused line after a match": "rules:\n  - MATCH,DIRECT\n  - SUB-RULE,(NETWORK,tcp),missing\n",
		"undefined rule set":         "rules:\n  - RULE-SET,missing,REJECT\n  - MATCH,DIRECT\n",
		"undefined nested rule set":  "rules:\n  - AND,((RULE-SET,missing),(NETWORK,tcp)),REJECT\n  - MATCH,DIRECT\n",
	} {
		if _, err := MatchRuleForIOS(bad, "", `{"host":"a.test"}`); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := MatchRuleForIOS("rules:\n  - RULE-SET,missing,REJECT\n", "", `{"host":"a.test"}`); err == nil ||
		err.Error() != "rules[0] [RULE-SET,missing,REJECT] error: rule set [missing] not found" {
		t.Errorf("the core's sentence: %v", err)
	}
	numeric := "proxies:\n  - {name: 123, type: direct}\nrules:\n  - MATCH,123\n"
	if result := runMatch(t, numeric, "", `{"host":"a.test"}`); !result.Matched || result.Policy != "123" {
		t.Errorf("numeric name: %+v", result)
	}
}

func TestMatchRuleCodexRound3(t *testing.T) {
	base := setupForMatch(t)
	for i := 0; i < 20; i++ {
		if _, err := MatchRuleForIOS("hosts:\n  a.test: a.test\n  b.test: a.test\nrules:\n  - MATCH,DIRECT\n", "", `{"host":"b.test"}`); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("circle: %v", err)
		}
	}
	for _, hosts := range []string{"'+.example.test': example.test", "'*.example.test': www.example.test"} {
		if _, err := MatchRuleForIOS("hosts:\n  "+hosts+"\nrules:\n  - MATCH,DIRECT\n", "", `{"host":"www.example.test"}`); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Errorf("%s: %v", hosts, err)
		}
	}
	if result := runMatch(t, "proxies:\n  - {name: 1.5, type: direct}\nrules:\n  - MATCH,1.5E+00\n", "", `{"host":"a.test"}`); !result.Matched {
		t.Errorf("float name: %+v", result)
	}
	working := filepath.Join(base, "working")
	path := filepath.Join(working, "broken.mrs")
	if err := os.WriteFile(path, []byte("not a rule set"), 0o644); err != nil {
		t.Fatal(err)
	}
	document := "rule-providers:\n  broken: {type: file, behavior: domain, format: mrs, path: ./broken.mrs}\nrules:\n  - RULE-SET,broken,REJECT\n  - MATCH,DIRECT\n"
	_ = runMatch(t, document, "", `{"host":"a.test"}`)
	if data, _ := os.ReadFile(path); string(data) != "not a rule set" {
		t.Errorf("the reader's file changed: %q", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(working, ".match-rule-*")); len(leftovers) != 0 {
		t.Errorf("copies left behind: %v", leftovers)
	}
}

func TestMatchRuleRefusesARuleSetOutsideTheHomeDirectory(t *testing.T) {
	setupForMatch(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("a.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := MatchRuleForIOS("rule-providers:\n  away: {type: file, behavior: domain, path: "+outside+"}\nrules:\n  - RULE-SET,away,REJECT\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
	if err == nil || !strings.Contains(err.Error(), "path is not subpath of home directory") {
		t.Fatalf("a rule set outside the home directory was not refused: %v", err)
	}
	_, err = MatchRuleForIOS("rule-providers:\n  away: {type: file, behavior: domain, path: ../outside.yaml}\nrules:\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
	want := "parse rule provider away error: " + C.Path.ErrNotSafePath(C.Path.Resolve("../outside.yaml")).Error()
	if err == nil || err.Error() != want {
		t.Fatalf("relative escape: %v, want %s", err, want)
	}
	if err := os.Symlink(outside, filepath.Join(C.Path.HomeDir(), "linked.txt")); err != nil {
		t.Fatal(err)
	}
	_, err = MatchRuleForIOS("rule-providers:\n  away: {type: file, behavior: domain, path: ./linked.txt}\nrules:\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
	if err == nil || !strings.Contains(err.Error(), "path is not subpath of home directory") {
		t.Fatalf("a link out of the home directory was not refused: %v", err)
	}
	result := runMatch(t, "rule-providers:\n  later: {type: file, behavior: domain, path: ./rules/later.txt}\nrules:\n  - RULE-SET,later,REJECT\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
	if !result.Undecided || result.Reason != "ruleSetUnavailable" {
		t.Fatalf("a missing directory under home: %+v", result)
	}
}

func TestMatchRuleCodexRound4(t *testing.T) {
	base := setupForMatch(t)
	within := func(name string, call func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { defer close(done); call() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not return", name)
		}
	}
	within("/dev/zero", func() {
		_, err := MatchRuleForIOS("rule-providers:\n  stuck: {type: file, behavior: domain, path: /dev/zero}\nrules:\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
		if err == nil || !strings.Contains(err.Error(), "path is not subpath of home directory") {
			t.Errorf("/dev/zero: %v", err)
		}
	})
	fifo := filepath.Join(base, "working", "rules.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	within("FIFO", func() {
		result := runMatch(t, "rule-providers:\n  pipe: {type: file, behavior: domain, path: ./rules.fifo}\nrules:\n  - RULE-SET,pipe,REJECT\n  - MATCH,DIRECT\n", "", `{"host":"a.test"}`)
		if !result.Undecided || result.Reason != "ruleSetUnavailable" {
			t.Errorf("FIFO: %+v", result)
		}
	})
	var document strings.Builder
	document.WriteString("sub-rules:\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&document, "  s%d:\n    - SUB-RULE,(NETWORK,udp),s%d\n    - SUB-RULE,(NETWORK,udp),s%d\n", i, i+1, i+1)
	}
	document.WriteString("  s40: []\nrules:\n  - MATCH,DIRECT\n")
	within("doubled sub-rules", func() {
		if result := runMatch(t, document.String(), "", `{"host":"a.test"}`); !result.Matched {
			t.Errorf("doubled sub-rules: %+v", result)
		}
	})
}

package clash

import (
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type compileCheckAnswer struct {
	OK     bool `json:"ok"`
	Errors []struct {
		Message string `json:"message"`
		Section string `json:"section"`
		Index   *int   `json:"index"`
		Line    int    `json:"line"`
	} `json:"errors"`
}

func runCompileCheck(t *testing.T, document string) compileCheckAnswer {
	t.Helper()
	box, err := CompileCheckForIOS(document, "")
	if err != nil {
		t.Fatalf("CompileCheckForIOS: %v", err)
	}
	var answer compileCheckAnswer
	if err := json.Unmarshal([]byte(box.Value), &answer); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, box.Value)
	}
	return answer
}

const compileCheckBase = `mode: rule
dns:
  enable: true
  nameserver: [223.5.5.5]
proxies:
  - {name: a, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - name: Proxy
    type: select
    proxies: [a, DIRECT]
rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - MATCH,DIRECT
`

func TestCompileCheckPassesAGoodConfiguration(t *testing.T) {
	setupForEditingFuzz(t)
	answer := runCompileCheck(t, compileCheckBase)
	if !answer.OK || len(answer.Errors) != 0 {
		t.Fatalf("a good configuration must pass: %+v", answer)
	}
}

func TestCompileCheckPlacesARuleError(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "  - MATCH,DIRECT\n", "  - DOMAIN,b.com,Nowhere\n  - MATCH,DIRECT\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 {
		t.Fatalf("a rule naming a missing policy must fail: %+v", answer)
	}
	e := answer.Errors[0]
	if !strings.Contains(e.Message, "Nowhere") || e.Section != "rules" || e.Index == nil || *e.Index != 1 || e.Line != 13 {
		t.Fatalf("error = %+v, want rules[1] on line 13 with the core's words", e)
	}
}

func TestCompileCheckPlacesAGroupError(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "proxies: [a, DIRECT]", "proxies: [a, missing]", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxy-groups" {
		t.Fatalf("a group naming a missing member must fail in proxy-groups: %+v", answer)
	}
	if answer.Errors[0].Line != 8 {
		t.Fatalf("line = %d, want 8", answer.Errors[0].Line)
	}
}

func TestCompileCheckReportsASyntaxErrorWithItsLine(t *testing.T) {
	setupForEditingFuzz(t)
	answer := runCompileCheck(t, "mode: rule\nrules:\n  - [unclosed\n")
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Line == 0 {
		t.Fatalf("a syntax error must carry its line: %+v", answer)
	}
}

func TestCompileCheckReportsOnlyTheReadersLineNumbers(t *testing.T) {
	setupForEditingFuzz(t)
	answer := runCompileCheck(t, "port: nope\nmode: rule\n")
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Line != 1 || !strings.Contains(answer.Errors[0].Message, "line 1: ") {
		t.Fatalf("a line of the re-encoded copy was reported: %+v", answer)
	}
	answer = runCompileCheck(t, "mode: rule\nrules: [\n")
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Line == 0 {
		t.Fatalf("a syntax error in the reader's text lost its line: %+v", answer)
	}
}

func TestCompileCheckClosesTheNodesProvidersBuilt(t *testing.T) {
	setupForEditingFuzz(t)
	document := compileCheckBase + `proxy-providers:
  inline-wg:
    type: inline
    payload:
      - {name: wg, type: wireguard, server: 192.0.2.1, port: 51820, ip: 10.0.0.2/32, workers: 4,
         private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
`
	settle := func() int {
		time.Sleep(200 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	if answer := runCompileCheck(t, document); !answer.OK {
		t.Fatalf("the document must compile: %+v", answer)
	}
	before := settle()
	for i := 0; i < 5; i++ {
		runCompileCheck(t, document)
	}
	if after := settle(); after > before+4 {
		t.Fatalf("goroutines %d before, %d after five checks", before, after)
	}
}

func TestCompileCheckPlacesARuleAfterARemovedUIDRule(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "rules:\n", "rules:\n  - UID,1000,DIRECT\n  - DOMAIN,b.com,Nowhere\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 {
		t.Fatalf("the rule targets a missing proxy: %+v", answer)
	}
	e := answer.Errors[0]
	if e.Section != "rules" || e.Index == nil || *e.Index != 1 || e.Line != 13 {
		t.Fatalf("placed at %s[%v] line %d, want rules[1] line 13: %s", e.Section, e.Index, e.Line, e.Message)
	}
}

func TestCompileCheckPlacesASubRuleErrorInSubRules(t *testing.T) {
	setupForEditingFuzz(t)
	document := compileCheckBase + "sub-rules:\n  s1:\n    - DOMAIN,b.com,Nowhere\n"
	document = strings.Replace(document, "  - MATCH,DIRECT\n", "  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,DIRECT\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "sub-rules" {
		t.Fatalf("a sub-rule error belongs to sub-rules: %+v", answer)
	}
}

func TestCompileCheckThatFailsLeavesNoNodeRunning(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "  - MATCH,DIRECT\n", "  - DOMAIN,b.com,Nowhere\n", 1) + `proxy-providers:
  inline-wg:
    type: inline
    payload:
      - {name: wg, type: wireguard, server: 192.0.2.1, port: 51820, ip: 10.0.0.2/32, workers: 4,
         private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
`
	settle := func() int {
		time.Sleep(300 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	before := settle()
	if answer := runCompileCheck(t, document); answer.OK {
		t.Fatalf("the rule names a missing proxy: %+v", answer)
	}
	for i := 0; i < 4; i++ {
		runCompileCheck(t, document)
	}
	if after := settle(); after > before+4 {
		t.Fatalf("goroutines %d before, %d after five failed checks", before, after)
	}
}

func TestCompileCheckPlacesAGroupErrorByName(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "proxy-groups:\n", "proxy-groups:\n  - {name: A, type: select, proxies: [B]}\n  - {name: B, type: select, proxies: [missing]}\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 {
		t.Fatalf("B names a missing proxy: %+v", answer)
	}
	e := answer.Errors[0]
	if e.Section != "proxy-groups" || e.Index == nil || *e.Index != 1 {
		t.Fatalf("placed at %s[%v], want proxy-groups[1] (B): %s", e.Section, e.Index, e.Message)
	}
}

func TestCompileCheckPlacesEverySubRuleSentence(t *testing.T) {
	setupForEditingFuzz(t)
	for name, document := range map[string]string{
		"cjk name": strings.Replace(compileCheckBase+"sub-rules:\n  中文:\n    - DOMAIN,b.com,Nowhere\n", "  - MATCH,DIRECT\n", "  - SUB-RULE,(NETWORK,tcp),中文\n  - MATCH,DIRECT\n", 1),
		"circular": strings.Replace(compileCheckBase+"sub-rules:\n  s1:\n    - SUB-RULE,(NETWORK,tcp),s2\n  s2:\n    - SUB-RULE,(NETWORK,udp),s1\n", "  - MATCH,DIRECT\n", "  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,DIRECT\n", 1),
	} {
		answer := runCompileCheck(t, document)
		if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "sub-rules" {
			t.Errorf("%s: %+v", name, answer)
		}
	}
}

func TestCompileCheckReviewThreePlacement(t *testing.T) {
	setupForEditingFuzz(t)
	duplicate := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: sub-rule-a, type: direct}\n  - {name: sub-rule-a, type: direct}\n", 1)
	if answer := runCompileCheck(t, duplicate); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section == "sub-rules" {
		t.Errorf("a duplicate node named sub-rule-a: %+v", answer)
	}
	colon := strings.Replace(compileCheckBase, "proxy-groups:\n", "proxy-groups:\n  - {name: A, type: select, proxies: [DIRECT]}\n  - {name: \"A: B\", type: select, proxies: [missing]}\n", 1)
	answer := runCompileCheck(t, colon)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Index == nil || *answer.Errors[0].Index != 1 {
		t.Fatalf("group \"A: B\" is proxy-groups[1]: %+v", answer)
	}
}

func TestCompileCheckReviewFourCases(t *testing.T) {
	setupForEditingFuzz(t)
	duplicate := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: 'sub-rules[s]', type: direct}\n  - {name: 'sub-rules[s]', type: direct}\n", 1)
	if answer := runCompileCheck(t, duplicate); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section == "sub-rules" {
		t.Errorf("a duplicate node named sub-rules[s]: %+v", answer)
	}
	smux := compileCheckBase + `proxy-providers:
  inline-wg:
    type: inline
    payload:
      - {name: wg, type: wireguard, server: 192.0.2.1, port: 51820, ip: 10.0.0.2/32, workers: 4, smux: {enabled: []},
         private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
`
	settle := func() int {
		time.Sleep(300 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 0; i < 5; i++ {
		runCompileCheck(t, smux)
	}
	if after := settle(); after > before+4 {
		t.Fatalf("goroutines %d before, %d after five checks with an smux block that does not decode", before, after)
	}
}

func TestCompileCheckReviewFiveCases(t *testing.T) {
	setupForEditingFuzz(t)
	for _, name := range []string{"x: sub-rules[s]", "x: rules[0]", "x: proxy group[0]: fake"} {
		duplicate := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: '"+name+"', type: direct}\n  - {name: '"+name+"', type: direct}\n", 1)
		answer := runCompileCheck(t, duplicate)
		if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section == "sub-rules" || answer.Errors[0].Section == "rules" || answer.Errors[0].Section == "proxy-groups" {
			t.Errorf("%q: %+v", name, answer)
		}
	}
}

func TestCompileCheckReviewSixCases(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: 'group[0]: Proxy: fake', type: direct}\n  - {name: 'group[0]: Proxy: fake', type: direct}\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section == "proxy-groups" {
		t.Errorf("%+v", answer)
	}
}

func TestCompileCheckPlacesTheRefusedGroup(t *testing.T) {
	setupForEditingFuzz(t)
	likeNode := strings.Replace(compileCheckBase, "proxy-groups:\n", "proxy-groups:\n  - {name: a, type: select, proxies: [DIRECT]}\n", 1)
	if answer := runCompileCheck(t, likeNode); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxy-groups" || answer.Errors[0].Index == nil || *answer.Errors[0].Index != 0 {
		t.Errorf("a group named like a node: %+v", answer)
	}
	twice := strings.Replace(compileCheckBase, "proxy-groups:\n", "proxy-groups:\n  - {name: HK 01, type: select, proxies: [DIRECT]}\n  - {name: HK 01, type: select, proxies: [DIRECT]}\n", 1)
	if answer := runCompileCheck(t, twice); answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxy-groups" || answer.Errors[0].Index == nil || *answer.Errors[0].Index != 1 {
		t.Errorf("two groups named HK 01: %+v", answer)
	}
}

func TestCompileCheckPlacesABuiltinNameAtItsFirstOccurrence(t *testing.T) {
	setupForEditingFuzz(t)
	document := strings.Replace(compileCheckBase, "proxies:\n", "proxies:\n  - {name: DIRECT, type: direct}\n  - {name: DIRECT, type: direct}\n", 1)
	answer := runCompileCheck(t, document)
	if answer.OK || len(answer.Errors) != 1 || answer.Errors[0].Section != "proxies" || answer.Errors[0].Index == nil || *answer.Errors[0].Index != 0 {
		t.Errorf("%+v", answer)
	}
}

func TestCompileCheckLeavesNoCopyLineInTheMessage(t *testing.T) {
	setupConfigPipelineTest(t)
	text := "mode: rule\ntun:\n  mtu: nope\ntuic-server:\n  users:\n    0x10: alice\n    \"16\": bob\n"
	box, err := CompileCheckForIOS(text, "")
	if err != nil {
		t.Fatal(err)
	}
	var result compileCheckResult
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil || result.OK || len(result.Errors) != 1 {
		t.Fatalf("%s", box.Value)
	}
	problem := result.Errors[0]
	if problem.Line != 3 || !strings.Contains(problem.Message, "line 3: cannot unmarshal") ||
		!strings.Contains(problem.Message, `mapping key "16" already defined`) || strings.Contains(problem.Message, "at line") {
		t.Errorf("%+v", problem)
	}
	broken := "tun:\n  mtu: nope\nmode: rule\nport: |\n  bad\n"
	box, _ = CompileCheckForIOS(broken, "")
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil || len(result.Errors) != 1 ||
		!strings.Contains(result.Errors[0].Message, "line 2: cannot unmarshal !!str `nope`") || result.Errors[0].Line == 0 {
		t.Errorf("%s", box.Value)
	}
	box, _ = CompileCheckForIOS("rules: |\n  MATCH,x\ntun:\n  mtu: nope\nmode: rule\n", "")
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil || len(result.Errors) != 1 ||
		!strings.Contains(result.Errors[0].Message, "line 4: cannot unmarshal !!str `nope`") {
		t.Errorf("%s", box.Value)
	}
	quoted := "mode: rule\nport: line 9\n"
	box, _ = CompileCheckForIOS(quoted, "")
	if err := json.Unmarshal([]byte(box.Value), &result); err != nil || len(result.Errors) != 1 || result.Errors[0].Line != 2 ||
		!strings.Contains(result.Errors[0].Message, "`line 9`") {
		t.Errorf("%s", box.Value)
	}
}

func TestCompileCheckNamesTheReadersLine(t *testing.T) {
	setupConfigPipelineTest(t)
	for _, c := range []struct {
		name, text string
		line       int
	}{
		{"flow provider", "rules:\n  - MATCH,DIRECT\nmode: rule\nproxy-providers:\n  Subscribe: [url: http://example.invalid/sub, interval: 3600]\n", 5},
		{"after comments", "# one\n# two\nmode: rule\ndns:\n  enable: true\n  ipv6: maybe\n", 6},
		{"merged", "base: &base\n  ipv6: maybe\ndns:\n  <<: *base\n  enable: true\n", 2},
		{"refused map", "port:\n  z: 1\n  a: 2\nmode: rule\n", 2},
		{"refused list item", "mode: rule\nport:\n  - 1\n", 3},
		{"flow opener", "mode: rule\nproxy-providers:\n  Sub:\n    [\n      url: http://x/sub, interval: 3600\n    ]\n", 4},
		{"nested list", "mode: rule\ndns:\n  nameserver:\n    [\n      [1.1.1.1]\n    ]\n", 0},
		{"top-level value", "mode: rule\nauthentication: {}\n", 2},
	} {
		box, err := CompileCheckForIOS(c.text, "")
		if err != nil {
			t.Fatal(err)
		}
		var result compileCheckResult
		if err := json.Unmarshal([]byte(box.Value), &result); err != nil || result.OK || len(result.Errors) != 1 {
			t.Fatalf("%s: %s", c.name, box.Value)
		}
		problem := result.Errors[0]
		named := compileYAMLLine.get().FindAllStringSubmatch(problem.Message, -1)
		if c.line == 0 {
			if len(named) != 0 || problem.Line != 0 {
				t.Errorf("%s: %+v", c.name, problem)
			}
			continue
		}
		if len(named) == 0 || problem.Line != c.line {
			t.Errorf("%s: %+v", c.name, problem)
		}
		for _, match := range named {
			if match[1] != strconv.Itoa(c.line) {
				t.Errorf("%s: names line %s: %q", c.name, match[1], problem.Message)
			}
		}
	}
}

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
)


const ruleIndexTestHead = `proxies:
  - {name: HK, type: ss, server: hk.example.net, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK, DIRECT]}
sub-rules:
  s1:
    - DOMAIN-SUFFIX,sub.example,Proxy
    - MATCH,DIRECT
`

var ruleIndexTestRules = []string{
	"DOMAIN,www.example.com,Proxy",
	"DOMAIN-SUFFIX,Example.org,DIRECT",
	"DOMAIN-KEYWORD,ads,REJECT",
	"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
	"IP-CIDR6,2001:db8::/32,Proxy",
	"DST-PORT,8443,HK",
	"AND,((NETWORK,udp),(DOMAIN-SUFFIX,quic.example)),REJECT",
	"SUB-RULE,(NETWORK,tcp),s1",
	"MATCH,Proxy",
}

func compileRuleIndex(t *testing.T, dir string, lines []string, hasTarget func(string) bool) (string, string) {
	t.Helper()
	compiler := NewClashRuleIndexCompiler(hasTarget, func(string) bool { return false }, map[string][]C.Rule{"s1": nil})
	for _, line := range lines {
		if err := compiler.Add(line); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	_, sum, err := compiler.Write(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rules.index")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(sum[:])
}

func knownTarget(name string) bool {
	switch name {
	case "HK", "Proxy", "DIRECT", "REJECT":
		return true
	}
	return false
}

func indexedConfiguration(path, sum string) string {
	return ruleIndexTestHead + "x-clash-rule-index: {path: " + path + ", sha256: " + sum + "}\n"
}

func TestAnIndexsRulesParseAsTheSameRulesInline(t *testing.T) {
	inline, err := Parse([]byte(ruleIndexTestHead + "rules:\n  - " + strings.Join(ruleIndexTestRules, "\n  - ") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	path, sum := compileRuleIndex(t, t.TempDir(), ruleIndexTestRules, knownTarget)
	indexed, err := Parse([]byte(indexedConfiguration(path, sum)))
	if err != nil {
		t.Fatal(err)
	}
	if indexed.Rules != nil {
		t.Fatalf("an indexed configuration holds %d rule objects", len(indexed.Rules))
	}
	if _, ok := indexed.RuleTable.(*clashindex.Table); !ok {
		t.Fatalf("the rules are a %T, not the index", indexed.RuleTable)
	}
	if indexed.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("%d rules, want %d", indexed.RuleTable.Len(), inline.RuleTable.Len())
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), indexed.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Errorf("rule %d: inline %s,%s,%s; indexed %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
		if _, wrapped := a.(C.RuleWrapper); wrapped {
			_, mapped := indexed.RuleTable.(C.RuleTableStatistics).Statistics(i)
			if _, other := b.(C.RuleWrapper); !mapped && !other {
				t.Errorf("rule %d keeps no statistics", i)
			}
		}
	}
}

func TestAStartWhoseIndexIsNotRightSaysToPublishAgain(t *testing.T) {
	dir := t.TempDir()
	path, sum := compileRuleIndex(t, dir, ruleIndexTestRules, knownTarget)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	damaged := filepath.Join(dir, "damaged.index")
	data[100] ^= 1
	if err := os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	other, otherSum := compileRuleIndex(t, t.TempDir(), []string{"DOMAIN,a.example,Gone", "MATCH,DIRECT"}, func(name string) bool { return name == "Gone" || knownTarget(name) })
	for name, text := range map[string]string{
		"missing":       indexedConfiguration(filepath.Join(dir, "none.index"), sum),
		"damaged":       indexedConfiguration(damaged, sum),
		"another's sum": indexedConfiguration(path, strings.Repeat("0", 64)),
		"stale targets": indexedConfiguration(other, otherSum),
	} {
		_, err := Parse([]byte(text))
		if !errors.Is(err, ErrRuleIndexUnavailable) {
			t.Errorf("%s: %v, want ErrRuleIndexUnavailable", name, err)
		}
	}
	if _, err := Parse([]byte(indexedConfiguration(path, sum) + "rules:\n  - MATCH,DIRECT\n")); err == nil || errors.Is(err, ErrRuleIndexUnavailable) {
		t.Errorf("rules beside an index: %v", err)
	}
	if _, err := Parse([]byte(ruleIndexTestHead + "x-clash-rule-index: {path: " + path + "}\n")); err == nil {
		t.Error("an index without its checksum parsed")
	}
}

func TestTheIndexCompilerRefusesALineAsParseDoes(t *testing.T) {
	for _, line := range []string{"DOMAIN,a.example,Nowhere", "IP-CIDR,not-a-range,DIRECT", "DOMAIN,a.example", "RULE-SET,none,DIRECT", "SUB-RULE,(NETWORK,tcp),nope"} {
		lines := []string{"DOMAIN,first.example,DIRECT", line, "MATCH,DIRECT"}
		_, want := Parse([]byte(ruleIndexTestHead + "rules:\n  - " + strings.Join(lines, "\n  - ") + "\n"))
		if want == nil {
			t.Fatalf("%s parsed inline", line)
		}
		compiler := NewClashRuleIndexCompiler(knownTarget, func(string) bool { return false }, map[string][]C.Rule{"s1": nil})
		var got error
		for _, l := range lines {
			if got = compiler.Add(l); got != nil {
				break
			}
		}
		if got == nil || got.Error() != want.Error() {
			t.Errorf("%s: compiler %v, Parse %v", line, got, want)
		}
	}
}

func TestTheIndexCompilerRefusesAGeodataLineAsTheTunnelWould(t *testing.T) {
	for _, line := range []string{
		"AND,((GEOIP,CN),(RULE-SET,nope)),DIRECT",
		"AND,((GEOSITE,cn),(DOMAIN-REGEX,[)),DIRECT",
		"OR,((GEOIP,CN),(IP-CIDR,10.0.0.0/33)),DIRECT",
		"AND,((GEOIP,CN),(SUB-RULE,(NETWORK,tcp),none)),DIRECT",
		"AND,((DST-PORT,notaport),(GEOIP,LAN)),DIRECT",
		"DOMAIN-REGEX,(GEOIP,foo,DIRECT",
		"IP-CIDR,(GEOIP,DIRECT",
		"GEOIP,CN,Nowhere",
	} {
		compiler := NewClashRuleIndexCompiler(knownTarget, func(string) bool { return false }, map[string][]C.Rule{"s1": nil})
		if err := compiler.Add(line); err == nil {
			t.Errorf("%s published", line)
		}
	}
	for _, line := range []string{"GEOIP,CN,DIRECT", "GEOSITE,cn,Proxy", "AND,((GEOSITE,cn),(NETWORK,tcp)),REJECT", "NOT,((GEOIP,LAN,no-resolve)),HK"} {
		compiler := NewClashRuleIndexCompiler(knownTarget, func(string) bool { return false }, map[string][]C.Rule{"s1": nil})
		if err := compiler.Add(line); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

func TestAParseOutsideTheTunnelProvesTheIndex(t *testing.T) {
	if ClashRuleIndexesVerified.Load() {
		t.Fatal("this process is marked as a tunnel's")
	}
	dir := t.TempDir()
	path, _ := compileRuleIndex(t, dir, []string{"DOMAIN,a.example,DIRECT", "DOMAIN,b.example,REJECT", "MATCH,Proxy"}, knownTarget)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const sectionsAt = 8 + 4*4 + 32
	le := func(at int) uint32 {
		return uint32(data[at]) | uint32(data[at+1])<<8 | uint32(data[at+2])<<16 | uint32(data[at+3])<<24
	}
	put := func(at int, v uint32) {
		data[at], data[at+1], data[at+2], data[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	exact := int(le(sectionsAt + 8*4))
	slots := int(le(exact))
	keys := exact + 12 + 4*slots
	first, second := le(keys+8), le(keys+12+8)
	put(keys+8, second)
	put(keys+12+8, first)
	sum := sha256.Sum256(data[:len(data)-32])
	copy(data[len(data)-32:], sum[:])
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(indexedConfiguration(path, hex.EncodeToString(sum[:])))); err == nil {
		t.Fatal("an index whose keys name each other's rules parsed")
	}
}

func TestTheShapeCheckJudgesAliasesAsUnmarshalDoes(t *testing.T) {
	doc := "rules:\n" + strings.Repeat("  - MATCH,DIRECT\n", 10000) + `rule-providers:
  p:
    type: inline
    behavior: domain
    payload: [example.test]
    x0: &x0 [a, a, a, a, a, a, a, a, a, a]
    x1: &x1 [*x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0, *x0]
    x2: &x2 [*x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1, *x1]
    x3: [*x2, *x2, *x2, *x2, *x2]
`
	_, want := UnmarshalRawConfig([]byte(doc))
	if got := ClashCheckRawConfig([]byte(doc)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("check %v, UnmarshalRawConfig %v", got, want)
	}
}


var rulesBeforeTheIndex = []string{
	"DOMAIN-SUFFIX,example.com,REJECT",
	"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
}

func indexedConfigurationWithRulesBefore(path, sum string, before []string) string {
	return ruleIndexTestHead + "x-clash-rule-index:\n  path: " + path + "\n  sha256: " + sum +
		"\n  prepend:\n    - " + strings.Join(before, "\n    - ") + "\n"
}

func TestTheRulesBeforeAnIndexParseAsTheSameRulesInlineAndGoFirst(t *testing.T) {
	inline, err := Parse([]byte(ruleIndexTestHead + "rules:\n  - " + strings.Join(append(append([]string{}, rulesBeforeTheIndex...), ruleIndexTestRules...), "\n  - ") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	path, sum := compileRuleIndex(t, t.TempDir(), ruleIndexTestRules, knownTarget)
	indexed, err := Parse([]byte(indexedConfigurationWithRulesBefore(path, sum, rulesBeforeTheIndex)))
	if err != nil {
		t.Fatal(err)
	}
	table, ok := indexed.RuleTable.(*C.ClashRulesBefore)
	if !ok {
		t.Fatalf("the rules are a %T, not the rules before the index", indexed.RuleTable)
	}
	if _, ok := table.Rest.(*clashindex.Table); !ok || len(table.Before) != len(rulesBeforeTheIndex) {
		t.Fatalf("%d rules before a %T, want %d before the index", len(table.Before), table.Rest, len(rulesBeforeTheIndex))
	}
	if indexed.RuleTable.Len() != inline.RuleTable.Len() {
		t.Fatalf("%d rules, want %d", indexed.RuleTable.Len(), inline.RuleTable.Len())
	}
	for i := 0; i < inline.RuleTable.Len(); i++ {
		a, b := inline.RuleTable.At(i), indexed.RuleTable.At(i)
		if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
			t.Errorf("rule %d: inline %s,%s,%s; indexed %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
		}
	}
	for i := range rulesBeforeTheIndex {
		if _, wrapped := indexed.RuleTable.At(i).(C.RuleWrapper); !wrapped {
			t.Errorf("rule %d before the index keeps no statistics", i)
		}
	}
	at, adapter := -1, ""
	indexed.RuleTable.Walk(&C.Metadata{Host: "www.example.com", NetWork: C.TCP, DstPort: 443}, C.RuleMatchHelper{}, nil,
		func(i int, _ C.Rule, a string) bool { at, adapter = i, a; return true })
	if at != 0 || adapter != "REJECT" {
		t.Fatalf("www.example.com stopped at rule %d (%s), want the first rule before the index (REJECT)", at, adapter)
	}
	indexed.RuleTable.Walk(&C.Metadata{Host: "www.example.org", NetWork: C.TCP, DstPort: 80}, C.RuleMatchHelper{}, nil,
		func(i int, _ C.Rule, a string) bool { at, adapter = i, a; return true })
	if at != 3 || adapter != "DIRECT" {
		t.Fatalf("www.example.org stopped at rule %d (%s), want the index's rule 1 at 3 (DIRECT)", at, adapter)
	}
}

func TestARuleBeforeAnIndexIsRefusedAsParseRefusesItAtItsPlace(t *testing.T) {
	path, sum := compileRuleIndex(t, t.TempDir(), ruleIndexTestRules, knownTarget)
	_, err := Parse([]byte(indexedConfigurationWithRulesBefore(path, sum, []string{"DOMAIN,a.example,REJECT", "DOMAIN,b.example,Nowhere"})))
	if err == nil || !strings.Contains(err.Error(), "rules[1] [DOMAIN,b.example,Nowhere] error: proxy [Nowhere] not found") {
		t.Fatalf("a rule before the index naming no policy: %v", err)
	}
	other, otherSum := compileRuleIndex(t, t.TempDir(), []string{"DOMAIN,a.example,Gone", "MATCH,DIRECT"}, func(name string) bool { return name == "Gone" || knownTarget(name) })
	_, err = Parse([]byte(indexedConfigurationWithRulesBefore(other, otherSum, rulesBeforeTheIndex)))
	if !errors.Is(err, ErrRuleIndexUnavailable) || !strings.Contains(err.Error(), "rule 2 names [Gone]") {
		t.Fatalf("an index naming a group that is gone, after two rules: %v, want ErrRuleIndexUnavailable at rule 2", err)
	}
}

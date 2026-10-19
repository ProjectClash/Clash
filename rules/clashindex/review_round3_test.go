package clashindex_test

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
)


func TestARuleDisabledDuringItsOwnResolveStillDecides(t *testing.T) {
	setDisabled := func(rules C.RuleTable, i int, disabled bool) {
		if table, ok := rules.(*clashindex.Table); ok {
			table.SetDisabled(i, disabled)
		} else {
			rules.At(i).(C.RuleWrapper).SetDisabled(disabled)
		}
	}
	for _, first := range []string{"IP-CIDR,5.6.7.0/24,A", "IP-CIDR,9.9.9.0/24,A"} {
		c := &corpus{lines: []string{first, "IP-CIDR,5.6.7.0/24,B,no-resolve", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
		table, _ := c.compile(t, true)
		list := C.RuleList(c.parse(t, true))
		var decided [2]string
		for k, rules := range []C.RuleTable{list, table} {
			setDisabled(rules, 0, true)
			setDisabled(rules, 0, false)
			m := &C.Metadata{Host: "x.example"}
			helper := C.RuleMatchHelper{ResolveIP: func() {
				if !m.DstIP.IsValid() {
					setDisabled(rules, 0, true)
					m.DstIP = netip.MustParseAddr("5.6.7.8")
				}
			}}
			rules.Walk(m, helper, nil, func(i int, _ C.Rule, adapter string) bool {
				decided[k] = string(rune('0'+i)) + ":" + adapter
				return true
			})
		}
		if decided[0] != decided[1] {
			t.Errorf("%s: the loop decided %s, the table %s", first, decided[0], decided[1])
		}
		got, _ := table.Statistics(0)
		want := list[0].(C.RuleWrapper)
		if got.HitCount != want.HitCount() || got.MissCount != want.MissCount() || got.Disabled != want.IsDisabled() {
			t.Errorf("%s: %+v, the wrapper hits %d misses %d disabled %v", first, got, want.HitCount(), want.MissCount(), want.IsDisabled())
		}
	}
}

func TestAnIndexWithADomainNotInLowerCaseIsRefused(t *testing.T) {
	for _, line := range []string{"DOMAIN,example.com,REJECT", "DOMAIN-SUFFIX,example.com,REJECT", "DOMAIN-KEYWORD,example,REJECT"} {
		c := &corpus{lines: []string{line, "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
		_, data := c.compile(t, true)
		payload := strings.Split(line, ",")[1]
		pool, n := section(data, 3)
		at := strings.Index(string(data[pool:pool+n]), payload)
		if at < 0 {
			t.Fatalf("%s: no payload in the pool", line)
		}
		letters := 0
		for _, ch := range payload {
			if ch != '.' {
				letters++
			}
		}
		refusedForCase := false
		for variant := 1; variant < 1<<letters && !refusedForCase; variant++ {
			upper := []byte(payload)
			bit := 0
			for i, ch := range upper {
				if ch == '.' {
					continue
				}
				if variant&(1<<bit) != 0 {
					upper[i] = ch - 'a' + 'A'
				}
				bit++
			}
			wrong := append([]byte(nil), data...)
			copy(wrong[pool+at:], upper)
			resum(wrong)
			_, err := clashindex.Decode(wrong)
			if err == nil {
				t.Fatalf("%s: %s decoded", line, upper)
			}
			refusedForCase = strings.Contains(err.Error(), "lower case")
		}
		if !refusedForCase {
			t.Errorf("%s: no variant reached the lower-case check", line)
		}
	}
}

func TestARulePastTheLastIsNoRuleOnceRulesWereDisabled(t *testing.T) {
	c := &corpus{lines: []string{"DOMAIN,a.example,REJECT", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	path := t.TempDir() + "/x.index"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := clashindex.Open(path, [32]byte(data[len(data)-32:]))
	if err != nil {
		t.Fatal(err)
	}
	var others []C.Rule
	index.Others(func(int, string) bool {
		others = append(others, c.parse(t, true)[1])
		return true
	})
	table, err := index.Table(others)
	if err != nil {
		t.Fatal(err)
	}
	table.SetDisabled(0, true)
	table.SetDisabled(0, false)
	exact, _ := section(data, 4)
	slots := int(binary.LittleEndian.Uint32(data[exact:]))
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, int64(exact+12+4*slots+8)); err != nil {
		t.Fatal(err)
	}
	file.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a walk panicked: %v", r)
		}
	}()
	table.Walk(&C.Metadata{Host: "a.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return false })
	table.Statistics(0)
	table.Noted(func(int) bool { return true })
}

func TestATableOfAnIndexChangedUnderItsMappingIsRefused(t *testing.T) {
	c := &corpus{lines: []string{"DOMAIN,a.example,REJECT", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	path := t.TempDir() + "/x.index"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := clashindex.Open(path, [32]byte(data[len(data)-32:]))
	if err != nil {
		t.Fatal(err)
	}
	parsed := c.parse(t, true)
	var others []C.Rule
	index.Others(func(i int, _ string) bool {
		others = append(others, parsed[i])
		return true
	})
	rules, _ := section(data, 2)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0}, int64(rules)); err != nil {
		t.Fatal(err)
	}
	file.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("building the table panicked: %v", r)
		}
	}()
	if _, err := index.Table(others); err == nil {
		t.Fatal("a table of a changed mapping was built")
	}
}

func TestAnIndexReadsItsRulesBackAsLines(t *testing.T) {
	lines := []string{
		"DOMAIN,Www.Example.com,A",
		"domain-suffix,example.org,DIRECT",
		"DOMAIN-KEYWORD,ads,REJECT",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR6,2001:db8::/32,A",
		"IP-CIDR,2001:db9::/32,B",
		"DST-PORT,443,A",
		"MATCH,DIRECT",
	}
	want := []struct {
		line   string
		mapped bool
	}{
		{"DOMAIN,www.example.com,A", true},
		{"DOMAIN-SUFFIX,example.org,DIRECT", true},
		{"DOMAIN-KEYWORD,ads,REJECT", true},
		{"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", true},
		{"IP-CIDR6,2001:db8::/32,A", true},
		{"IP-CIDR,2001:db9::/32,B", true},
		{"DST-PORT,443,A", false},
		{"MATCH,DIRECT", false},
	}
	c := &corpus{lines: lines, subRules: map[string][]C.Rule{}}
	table, _ := c.compile(t, true)
	x := table.Index()
	for i, w := range want {
		line, mapped, ok := x.Written(i)
		if !ok || line != w.line || mapped != w.mapped {
			t.Errorf("rule %d: %q mapped %v ok %v, want %q mapped %v", i, line, mapped, ok, w.line, w.mapped)
		}
		tp, target, ok := x.MappedTypeAndTarget(i)
		if ok != w.mapped {
			t.Errorf("rule %d: MappedTypeAndTarget ok %v", i, ok)
		}
		if ok {
			fields := strings.Split(w.line, ",")
			if tp != fields[0] || target != fields[2] {
				t.Errorf("rule %d: %s %s, want %s %s", i, tp, target, fields[0], fields[2])
			}
		}
	}
	if _, _, ok := x.Written(len(lines)); ok {
		t.Error("a rule past the last read")
	}
}

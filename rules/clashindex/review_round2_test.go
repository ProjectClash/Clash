package clashindex_test

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
)


func TestAnIndexChangedInPlaceIsNotTheOneOpened(t *testing.T) {
	c := &corpus{lines: []string{"DOMAIN,a.example,REJECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	sum := [32]byte(data[len(data)-32:])
	for _, open := range []func(string, [32]byte) (*clashindex.Index, error){clashindex.Open, clashindex.OpenVerified} {
		path := t.TempDir() + "/x.index"
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := open(path, sum); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := append([]byte(nil), data...)
		rules, _ := section(changed, 2)
		binary.LittleEndian.PutUint32(changed[rules+4:], 0xffffffff)
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(changed, 0); err != nil {
			t.Fatal(err)
		}
		file.Close()
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		if _, err := open(path, sum); err == nil {
			t.Error("a file changed in place opened as the one named")
		}
	}
}

func TestAnIndexWhoseDerivedSectionsAreNotItsRulesIsRefused(t *testing.T) {
	c := &corpus{lines: []string{"DOMAIN-KEYWORD,abc,DIRECT", "DOMAIN-KEYWORD,abcdef,REJECT", "DOMAIN,a.example,REJECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	if _, err := clashindex.Decode(data); err != nil {
		t.Fatal(err)
	}
	lengths, n := section(data, 7)
	if n != 8 {
		t.Fatalf("keyword lengths are %d bytes", n)
	}
	for _, l := range []uint32{2, 5} {
		wrong := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(wrong[lengths:], l)
		resum(wrong)
		if _, err := clashindex.Decode(wrong); err == nil {
			t.Errorf("keyword length %d decoded", l)
		}
	}
	targets, _ := section(data, 0)
	wrong := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(wrong[targets+12+8:], 2)
	resum(wrong)
	if _, err := clashindex.Decode(wrong); err == nil {
		t.Error("a target whose first rule is not the first naming it decoded")
	}
}

func TestAWalkCountsTheRulesItChangesOnItsWay(t *testing.T) {
	compare := func(t *testing.T, c *corpus, rule int, prepare func(rules C.RuleTable), walk func(rules C.RuleTable)) {
		t.Helper()
		table, _ := c.compile(t, true)
		list := C.RuleList(c.parse(t, true))
		for _, rules := range []C.RuleTable{list, table} {
			if prepare != nil {
				prepare(rules)
			}
			walk(rules)
		}
		got, _ := table.Statistics(rule)
		want := list[rule].(C.RuleWrapper)
		if got.MissCount != want.MissCount() || got.HitCount != want.HitCount() || got.Disabled != want.IsDisabled() {
			t.Fatalf("rule %d: %+v, the wrapper hits %d misses %d disabled %v", rule, got, want.HitCount(), want.MissCount(), want.IsDisabled())
		}
	}
	setDisabled := func(rules C.RuleTable, i int, disabled bool) {
		if table, ok := rules.(*clashindex.Table); ok {
			table.SetDisabled(i, disabled)
		} else {
			rules.At(i).(C.RuleWrapper).SetDisabled(disabled)
		}
	}
	t.Run("disabled ahead by a yield", func(t *testing.T) {
		for _, lines := range [][]string{
			{"MATCH,DIRECT", "DOMAIN,miss.example,DIRECT", "MATCH,DIRECT"},
			{"DOMAIN-SUFFIX,x.example,A", "DOMAIN,other.example,B", "MATCH,DIRECT"},
		} {
			c := &corpus{lines: lines, subRules: map[string][]C.Rule{}}
			compare(t, c, 1, nil, func(rules C.RuleTable) {
				rules.Walk(&C.Metadata{Host: "a.x.example"}, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool {
					if i == 0 {
						setDisabled(rules, 1, true)
						return false
					}
					return true
				})
			})
		}
	})
	t.Run("disabled by the resolve after the walk tested it", func(t *testing.T) {
		c := &corpus{lines: []string{"DOMAIN,miss.example,DIRECT", "IP-CIDR,10.0.0.0/8,REJECT", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
		track := func(rules C.RuleTable) { setDisabled(rules, 0, true); setDisabled(rules, 0, false) }
		compare(t, c, 0, track, func(rules C.RuleTable) {
			m := &C.Metadata{Host: "other.example"}
			resolved := false
			helper := C.RuleMatchHelper{ResolveIP: func() {
				if !resolved {
					resolved = true
					setDisabled(rules, 0, true)
					m.DstIP = netip.MustParseAddr("192.0.2.1")
				}
			}}
			rules.Walk(m, helper, nil, func(int, C.Rule, string) bool { return true })
		})
	})
}

func TestPastTheBoundsMissesAreLeftOutNotWrong(t *testing.T) {
	run := func(t *testing.T, n int, act func(rules C.RuleTable, i int)) {
		c := &corpus{subRules: map[string][]C.Rule{}}
		for i := 0; i < n; i++ {
			c.lines = append(c.lines, "DOMAIN,r"+strconv.Itoa(i)+".example,DIRECT")
		}
		c.lines = append(c.lines, "MATCH,DIRECT")
		table, _ := c.compile(t, true)
		list := C.RuleList(c.parse(t, true))
		for _, rules := range []C.RuleTable{list, table} {
			for i := 0; i < n; i++ {
				act(rules, i)
			}
			for k := 0; k < 10; k++ {
				rules.Walk(&C.Metadata{Host: "other.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
			}
		}
		if table.DroppedStatistics() == 0 {
			t.Fatal("nothing left out past the bound")
		}
		disabled := 0
		for i := 0; i < n; i++ {
			got, _ := table.Statistics(i)
			want := list[i].(C.RuleWrapper)
			if got.MissCount != want.MissCount() && got.MissCount != 0 {
				t.Fatalf("rule %d: %d misses, the wrapper %d", i, got.MissCount, want.MissCount())
			}
			if got.HitCount != want.HitCount() || got.Disabled != want.IsDisabled() {
				t.Fatalf("rule %d: %+v, the wrapper hits %d disabled %v", i, got, want.HitCount(), want.IsDisabled())
			}
			if want.IsDisabled() {
				disabled++
			}
		}
		noted := 0
		table.Noted(func(i int) bool {
			if list[i].(C.RuleWrapper).IsDisabled() || list[i].(C.RuleWrapper).HitCount() > 0 {
				noted++
			}
			return true
		})
		if disabled > 0 && noted < disabled {
			t.Fatalf("%d of %d disabled rules noted", noted, disabled)
		}
	}
	t.Run("passed over", func(t *testing.T) {
		run(t, 5000, func(rules C.RuleTable, i int) {
			rules.Walk(&C.Metadata{Host: "r" + strconv.Itoa(i) + ".example"}, C.RuleMatchHelper{}, nil, func(at int, _ C.Rule, _ string) bool { return at != i })
		})
	})
	t.Run("disabled", func(t *testing.T) {
		run(t, 70000, func(rules C.RuleTable, i int) {
			if i%50 == 0 {
				rules.Walk(&C.Metadata{Host: "other.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
			}
			if table, ok := rules.(*clashindex.Table); ok {
				table.SetDisabled(i, true)
			} else {
				rules.At(i).(C.RuleWrapper).SetDisabled(true)
			}
		})
	})
}

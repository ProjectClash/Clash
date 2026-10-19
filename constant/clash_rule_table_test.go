package constant

import (
	"reflect"
	"testing"
	"time"
)

type hostRule struct {
	host, adapter string
	hits          uint64
	disabled      bool
}

func (r *hostRule) RuleType() RuleType      { return Domain }
func (r *hostRule) Adapter() string         { return r.adapter }
func (r *hostRule) Payload() string         { return r.host }
func (r *hostRule) ProviderNames() []string { return nil }
func (r *hostRule) SetDisabled(v bool)      { r.disabled = v }
func (r *hostRule) IsDisabled() bool        { return r.disabled }
func (r *hostRule) HitCount() uint64        { return r.hits }
func (r *hostRule) HitAt() time.Time        { return time.Time{} }
func (r *hostRule) MissCount() uint64       { return 0 }
func (r *hostRule) MissAt() time.Time       { return time.Time{} }
func (r *hostRule) Unwrap() Rule            { return r }
func (r *hostRule) Match(m *Metadata, _ RuleMatchHelper) (bool, string) {
	if !r.disabled && m.Host == r.host {
		r.hits++
		return true, r.adapter
	}
	return false, ""
}

type statisticsTable struct {
	RuleList
	disabled map[int]bool
}

func (t *statisticsTable) Statistics(i int) (RuleStatistics, bool) {
	return RuleStatistics{Disabled: t.disabled[i], HitCount: uint64(100 + i)}, true
}

func (t *statisticsTable) SetDisabled(i int, disabled bool) bool {
	t.disabled[i] = disabled
	return true
}

func (t *statisticsTable) RangeStatistics(f func(int, RuleStatistics, bool) bool) {
	for i := range t.RuleList {
		s, ok := t.Statistics(i)
		if !f(i, s, ok) {
			return
		}
	}
}

func (t *statisticsTable) Noted(f func(int) bool) {
	for i := range t.RuleList {
		if t.disabled[i] && !f(i) {
			return
		}
	}
}

func rulesBeforeForTest() (*ClashRulesBefore, []*hostRule, *statisticsTable) {
	before := []*hostRule{{host: "ad.example", adapter: "REJECT"}, {host: "tracker.example", adapter: "REJECT"}}
	rest := &statisticsTable{RuleList: RuleList{
		&hostRule{host: "a.example", adapter: "DIRECT"},
		&hostRule{host: "ad.example", adapter: "Proxy"},
		&hostRule{host: "b.example", adapter: "Proxy"},
	}, disabled: map[int]bool{}}
	return &ClashRulesBefore{Before: RuleList{before[0], before[1]}, Rest: rest}, before, rest
}

func walkOf(table RuleTable, host string) (tested []int, at int, adapter string) {
	at = -1
	table.Walk(&Metadata{Host: host}, RuleMatchHelper{}, func(i int, _ Rule) { tested = append(tested, i) },
		func(i int, _ Rule, a string) bool { at, adapter = i, a; return true })
	return
}

func TestTheRulesBeforeATableAreItsFirstRules(t *testing.T) {
	table, before, _ := rulesBeforeForTest()
	if table.Len() != 5 {
		t.Fatalf("Len = %d, want 5", table.Len())
	}
	for i, want := range []string{"ad.example", "tracker.example", "a.example", "ad.example", "b.example"} {
		if got := table.At(i).Payload(); got != want {
			t.Fatalf("At(%d) = %s, want %s", i, got, want)
		}
	}
	tested, at, adapter := walkOf(table, "ad.example")
	if !reflect.DeepEqual(tested, []int{0}) || at != 0 || adapter != "REJECT" {
		t.Fatalf("a flow the first rule matches: tested %v, stopped at %d (%s); want [0], 0 (REJECT)", tested, at, adapter)
	}
	if before[0].hits != 1 {
		t.Fatalf("the rule that matched counts %d hits, want 1", before[0].hits)
	}
	tested, at, adapter = walkOf(table, "b.example")
	if !reflect.DeepEqual(tested, []int{0, 1, 2, 3, 4}) || at != 4 || adapter != "Proxy" {
		t.Fatalf("a flow the rest decides: tested %v, stopped at %d (%s); want [0 1 2 3 4], 4 (Proxy)", tested, at, adapter)
	}
	tested, at, _ = walkOf(table, "none.example")
	if len(tested) != 5 || at != -1 {
		t.Fatalf("a flow no rule matches: tested %v, stopped at %d; want all five, none", tested, at)
	}
	before[0].SetDisabled(true)
	if _, at, adapter = walkOf(table, "ad.example"); at != 3 || adapter != "Proxy" {
		t.Fatalf("the first rule disabled: stopped at %d (%s), want 3 (Proxy)", at, adapter)
	}
}

func TestTheRulesBeforeATableKeepTheirOwnStatisticsAndTheTableItsAtItsPlaces(t *testing.T) {
	table, before, rest := rulesBeforeForTest()
	if _, ok := table.Statistics(1); ok {
		t.Fatal("a rule before the table keeps its own statistics; Statistics(1) answered the table's")
	}
	if s, ok := table.Statistics(3); !ok || s.HitCount != 101 {
		t.Fatalf("Statistics(3) = %+v, %v; want the table's rule 1 (101 hits)", s, ok)
	}
	if table.SetDisabled(0, true) {
		t.Fatal("SetDisabled(0) took a rule before the table; its object takes it")
	}
	if !table.SetDisabled(4, true) || !rest.disabled[2] {
		t.Fatal("SetDisabled(4) did not disable the table's rule 2")
	}
	before[1].hits = 1
	var noted []int
	table.Noted(func(i int) bool { noted = append(noted, i); return true })
	if !reflect.DeepEqual(noted, []int{1, 4}) {
		t.Fatalf("Noted = %v, want [1 4]", noted)
	}
	var ranged []int
	table.RangeStatistics(func(i int, s RuleStatistics, ok bool) bool {
		if ok {
			ranged = append(ranged, i*1000+int(s.HitCount))
		} else {
			ranged = append(ranged, -i)
		}
		return true
	})
	if !reflect.DeepEqual(ranged, []int{0, -1, 2100, 3101, 4102}) {
		t.Fatalf("RangeStatistics = %v, want the two before as their own, then the table's at 2..4", ranged)
	}
}

func TestATableWithNoRulesBeforeItIsTheTable(t *testing.T) {
	_, _, rest := rulesBeforeForTest()
	if table := ClashWithRulesBefore(nil, nil, rest); table != RuleTable(rest) {
		t.Fatalf("no rules before: %T, want the table itself", table)
	}
	if table := ClashWithRulesBefore(RuleList{&hostRule{host: "x"}}, []string{"DOMAIN,x,DIRECT"}, rest); table.Len() != 4 {
		t.Fatalf("one rule before: Len = %d, want 4", table.Len())
	}
}

func TestARuleBeforeThatMatchesButIsPassedOverHandsTheFlowToTheTable(t *testing.T) {
	table, _, _ := rulesBeforeForTest()
	var yielded []int
	at := -1
	table.Walk(&Metadata{Host: "ad.example"}, RuleMatchHelper{}, nil, func(i int, _ Rule, adapter string) bool {
		yielded = append(yielded, i)
		if adapter == "REJECT" {
			return false
		}
		at = i
		return true
	})
	if !reflect.DeepEqual(yielded, []int{0, 3}) || at != 3 {
		t.Fatalf("yielded %v, stopped at %d; want [0 3], 3", yielded, at)
	}
}

func TestRulesBeforeATableThatKeepsNoStatisticsReadTheirObjects(t *testing.T) {
	before := &hostRule{host: "ad.example", adapter: "REJECT", hits: 1}
	rest := RuleList{&hostRule{host: "a.example", adapter: "DIRECT"}, &hostRule{host: "b.example", adapter: "DIRECT", hits: 2}}
	table := &ClashRulesBefore{Before: RuleList{before}, Rest: rest}
	if _, ok := table.Statistics(2); ok || table.SetDisabled(2, true) {
		t.Fatal("a slice keeps no statistics of its own; its objects do")
	}
	var noted, ranged []int
	table.Noted(func(i int) bool { noted = append(noted, i); return true })
	table.RangeStatistics(func(i int, _ RuleStatistics, ok bool) bool {
		if !ok {
			ranged = append(ranged, i)
		}
		return true
	})
	if !reflect.DeepEqual(noted, []int{0, 2}) || !reflect.DeepEqual(ranged, []int{0, 1, 2}) {
		t.Fatalf("noted %v, ranged %v; want [0 2] and [0 1 2]", noted, ranged)
	}
}

type matchAllRule struct{ hostRule }

func (r *matchAllRule) RuleType() RuleType { return MATCH }
func (r *matchAllRule) Match(*Metadata, RuleMatchHelper) (bool, string) {
	r.hits++
	return true, r.adapter
}

func TestTheRulesAfterATableAreReachedOnlyWhenItsOwnDecideNothing(t *testing.T) {
	appended := &matchAllRule{hostRule{adapter: "Appended"}}
	table := ClashWithRulesAround(RuleList{&hostRule{host: "ad.example", adapter: "REJECT"}}, nil,
		RuleList{&hostRule{host: "a.example", adapter: "Own"}}, RuleList{appended}, nil)
	var yields []string
	table.Walk(&Metadata{Host: "a.example"}, RuleMatchHelper{}, nil, func(i int, _ Rule, adapter string) bool {
		yields = append(yields, adapter)
		return true
	})
	if !reflect.DeepEqual(yields, []string{"Own"}) || appended.hits != 0 {
		t.Fatalf("yield called with %v and the appended rule tested %d times, want only [Own] and none", yields, appended.hits)
	}
	at := -1
	table.Walk(&Metadata{Host: "elsewhere.example"}, RuleMatchHelper{}, nil, func(i int, _ Rule, adapter string) bool {
		at = i
		return true
	})
	if at != 2 {
		t.Fatalf("a flow nothing of the configuration's matches stopped at %d, want the appended rule at 2", at)
	}
}

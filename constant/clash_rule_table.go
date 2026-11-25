package constant

import "time"


type RuleTable interface {
	Len() int
	At(i int) Rule
	Walk(metadata *Metadata, helper RuleMatchHelper, before func(index int, rule Rule), yield func(index int, rule Rule, adapter string) bool)
}

type RuleList []Rule

func (l RuleList) Len() int      { return len(l) }
func (l RuleList) At(i int) Rule { return l[i] }

func (l RuleList) Walk(metadata *Metadata, helper RuleMatchHelper, before func(int, Rule), yield func(int, Rule, string) bool) {
	for index, rule := range l {
		if before != nil {
			before(index, rule)
		}
		if matched, adapter := rule.Match(metadata, helper); matched && yield(index, rule, adapter) {
			return
		}
	}
}

type RuleStatistics struct {
	Disabled  bool
	HitCount  uint64
	HitAt     time.Time
	MissCount uint64
	MissAt    time.Time
}

type RuleTableStatistics interface {
	Statistics(i int) (RuleStatistics, bool)
	SetDisabled(i int, disabled bool) bool
}

type IndexedRule struct {
	Rule
	Index int
}

func RuleIndexOf(rule Rule) (int, bool) {
	if indexed, ok := rule.(*IndexedRule); ok {
		return indexed.Index, true
	}
	return 0, false
}

type ClashRulesBefore struct {
	Before RuleTable
	Lines []string
	Rest  RuleTable
	After RuleTable
	AfterLines []string
}

var (
	_ RuleTable           = (*ClashRulesBefore)(nil)
	_ RuleTableStatistics = (*ClashRulesBefore)(nil)
)

func ClashWithRulesBefore(before RuleList, lines []string, rest RuleTable) RuleTable {
	return ClashWithRulesAround(before, lines, rest, nil, nil)
}

func ClashWithRulesAround(before RuleTable, lines []string, rest RuleTable, after RuleTable, afterLines []string) RuleTable {
	if lenOf(before) == 0 && lenOf(after) == 0 {
		return rest
	}
	if before == nil {
		before = RuleList(nil)
	}
	if after == nil {
		after = RuleList(nil)
	}
	return &ClashRulesBefore{Before: before, Lines: lines, Rest: rest, After: after, AfterLines: afterLines}
}

func lenOf(table RuleTable) int {
	if table == nil {
		return 0
	}
	return table.Len()
}

func (t *ClashRulesBefore) BeforeLen() int { return lenOf(t.Before) }

func (t *ClashRulesBefore) AfterLen() int { return lenOf(t.After) }

func (t *ClashRulesBefore) Len() int { return lenOf(t.Before) + t.Rest.Len() + lenOf(t.After) }

func (t *ClashRulesBefore) FirstAfter() int { return lenOf(t.Before) + t.Rest.Len() }

func (t *ClashRulesBefore) segments() [3]struct {
	table RuleTable
	first int
} {
	return [3]struct {
		table RuleTable
		first int
	}{{t.Before, 0}, {t.Rest, lenOf(t.Before)}, {t.After, t.FirstAfter()}}
}

func (t *ClashRulesBefore) segmentOf(i int) (RuleTable, int) {
	if k := lenOf(t.Before); i < k {
		return t.Before, i
	}
	if first := t.FirstAfter(); i >= first {
		return t.After, i - first
	}
	return t.Rest, i - lenOf(t.Before)
}

func (t *ClashRulesBefore) At(i int) Rule {
	table, j := t.segmentOf(i)
	return table.At(j)
}

func (t *ClashRulesBefore) AdapterAt(i int) string {
	table, j := t.segmentOf(i)
	if namer, ok := table.(interface{ AdapterAt(int) string }); ok {
		return namer.AdapterAt(j)
	}
	return table.At(j).Adapter()
}

func (t *ClashRulesBefore) ClashNamedOnly(i int) bool {
	table, j := t.segmentOf(i)
	named, ok := table.(interface{ ClashNamedOnly(int) bool })
	return ok && named.ClashNamedOnly(j)
}

func (t *ClashRulesBefore) Walk(metadata *Metadata, helper RuleMatchHelper, before func(int, Rule), yield func(int, Rule, string) bool) {
	for _, segment := range t.segments() {
		if lenOf(segment.table) == 0 {
			continue
		}
		k := segment.first
		var shifted func(int, Rule)
		if before != nil {
			shifted = func(i int, rule Rule) { before(k+i, rule) }
		}
		stopped := false
		segment.table.Walk(metadata, helper, shifted, func(i int, rule Rule, adapter string) bool {
			stopped = yield(k+i, rule, adapter)
			return stopped
		})
		if stopped {
			return
		}
	}
}

func (t *ClashRulesBefore) Statistics(i int) (RuleStatistics, bool) {
	if table, j := t.segmentOf(i); table != nil {
		if s, ok := table.(RuleTableStatistics); ok {
			return s.Statistics(j)
		}
	}
	return RuleStatistics{}, false
}

func (t *ClashRulesBefore) SetDisabled(i int, disabled bool) bool {
	if table, j := t.segmentOf(i); table != nil {
		if s, ok := table.(RuleTableStatistics); ok {
			return s.SetDisabled(j, disabled)
		}
	}
	return false
}

func (t *ClashRulesBefore) RangeStatistics(f func(i int, statistics RuleStatistics, ok bool) bool) {
	for _, segment := range t.segments() {
		k := segment.first
		if ranged, ok := segment.table.(interface {
			RangeStatistics(func(int, RuleStatistics, bool) bool)
		}); ok {
			going := true
			ranged.RangeStatistics(func(i int, s RuleStatistics, ok bool) bool {
				going = f(k+i, s, ok)
				return going
			})
			if !going {
				return
			}
			continue
		}
		for i := 0; i < lenOf(segment.table); i++ {
			if !f(k+i, RuleStatistics{}, false) {
				return
			}
		}
	}
}

func (t *ClashRulesBefore) Noted(f func(i int) bool) {
	for _, segment := range t.segments() {
		k := segment.first
		if noted, ok := segment.table.(interface{ Noted(func(int) bool) }); ok {
			going := true
			noted.Noted(func(i int) bool {
				going = f(k + i)
				return going
			})
			if !going {
				return
			}
			continue
		}
		for i := 0; i < lenOf(segment.table); i++ {
			if w, ok := segment.table.At(i).(RuleWrapper); ok && (w.HitCount() > 0 || w.IsDisabled()) && !f(k+i) {
				return
			}
		}
	}
}

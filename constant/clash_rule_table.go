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
	Before RuleList
	Lines []string
	Rest  RuleTable
	After RuleList
	AfterLines []string
}

var (
	_ RuleTable           = (*ClashRulesBefore)(nil)
	_ RuleTableStatistics = (*ClashRulesBefore)(nil)
)

func ClashWithRulesBefore(before RuleList, lines []string, rest RuleTable) RuleTable {
	return ClashWithRulesAround(before, lines, rest, nil, nil)
}

func ClashWithRulesAround(before RuleList, lines []string, rest RuleTable, after RuleList, afterLines []string) RuleTable {
	if len(before) == 0 && len(after) == 0 {
		return rest
	}
	return &ClashRulesBefore{Before: before, Lines: lines, Rest: rest, After: after, AfterLines: afterLines}
}

func (t *ClashRulesBefore) Len() int { return len(t.Before) + t.Rest.Len() + len(t.After) }

func (t *ClashRulesBefore) FirstAfter() int { return len(t.Before) + t.Rest.Len() }

func (t *ClashRulesBefore) At(i int) Rule {
	if i < len(t.Before) {
		return t.Before[i]
	}
	if first := t.FirstAfter(); i >= first {
		return t.After[i-first]
	}
	return t.Rest.At(i - len(t.Before))
}

func (t *ClashRulesBefore) Walk(metadata *Metadata, helper RuleMatchHelper, before func(int, Rule), yield func(int, Rule, string) bool) {
	stopped := false
	t.Before.Walk(metadata, helper, before, func(i int, rule Rule, adapter string) bool {
		stopped = yield(i, rule, adapter)
		return stopped
	})
	if stopped {
		return
	}
	k := len(t.Before)
	var shifted func(int, Rule)
	if before != nil {
		shifted = func(i int, rule Rule) { before(k+i, rule) }
	}
	t.Rest.Walk(metadata, helper, shifted, func(i int, rule Rule, adapter string) bool {
		stopped = yield(k+i, rule, adapter)
		return stopped
	})
	if stopped || len(t.After) == 0 {
		return
	}
	first := t.FirstAfter()
	var shiftedAfter func(int, Rule)
	if before != nil {
		shiftedAfter = func(i int, rule Rule) { before(first+i, rule) }
	}
	t.After.Walk(metadata, helper, shiftedAfter, func(i int, rule Rule, adapter string) bool { return yield(first+i, rule, adapter) })
}

func (t *ClashRulesBefore) Statistics(i int) (RuleStatistics, bool) {
	if s, ok := t.Rest.(RuleTableStatistics); ok && i >= len(t.Before) && i < t.FirstAfter() {
		return s.Statistics(i - len(t.Before))
	}
	return RuleStatistics{}, false
}

func (t *ClashRulesBefore) SetDisabled(i int, disabled bool) bool {
	if s, ok := t.Rest.(RuleTableStatistics); ok && i >= len(t.Before) && i < t.FirstAfter() {
		return s.SetDisabled(i-len(t.Before), disabled)
	}
	return false
}

func (t *ClashRulesBefore) RangeStatistics(f func(i int, statistics RuleStatistics, ok bool) bool) {
	for i := range t.Before {
		if !f(i, RuleStatistics{}, false) {
			return
		}
	}
	k := len(t.Before)
	if ranged, ok := t.Rest.(interface {
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
	} else {
		for i := 0; i < t.Rest.Len(); i++ {
			if !f(k+i, RuleStatistics{}, false) {
				return
			}
		}
	}
	first := t.FirstAfter()
	for i := range t.After {
		if !f(first+i, RuleStatistics{}, false) {
			return
		}
	}
}

func (t *ClashRulesBefore) Noted(f func(i int) bool) {
	for i, rule := range t.Before {
		if w, ok := rule.(RuleWrapper); ok && (w.HitCount() > 0 || w.IsDisabled()) && !f(i) {
			return
		}
	}
	k := len(t.Before)
	if noted, ok := t.Rest.(interface{ Noted(func(int) bool) }); ok {
		going := true
		noted.Noted(func(i int) bool {
			going = f(k + i)
			return going
		})
		if !going {
			return
		}
	} else {
		for i := 0; i < t.Rest.Len(); i++ {
			if w, ok := t.Rest.At(i).(RuleWrapper); ok && (w.HitCount() > 0 || w.IsDisabled()) && !f(k+i) {
				return
			}
		}
	}
	first := t.FirstAfter()
	for i, rule := range t.After {
		if w, ok := rule.(RuleWrapper); ok && (w.HitCount() > 0 || w.IsDisabled()) && !f(first+i) {
			return
		}
	}
}

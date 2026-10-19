package clashindex

import (
	"errors"
	"sort"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)

type Table struct {
	x      *Index
	others []other
	stats  statistics
}

type other struct {
	index uint32
	rule  C.Rule
}

var (
	_ C.RuleTable           = (*Table)(nil)
	_ C.RuleTableStatistics = (*Table)(nil)
)

func (x *Index) Table(others []C.Rule) (*Table, error) {
	if len(others) != x.others {
		return nil, errors.New("not the index's other rules")
	}
	t := &Table{x: x, others: make([]other, 0, len(others))}
	more := false
	x.Others(func(index int, _ string) bool {
		if len(t.others) == len(others) {
			more = true
			return false
		}
		t.others = append(t.others, other{index: uint32(index), rule: others[len(t.others)]})
		return true
	})
	if more || len(t.others) != len(others) {
		return nil, errors.New("not the index's other rules: the file changed under its mapping")
	}
	t.stats.init(x.count)
	return t, nil
}

func (t *Table) Index() *Index { return t.x }

func (t *Table) Len() int { return t.x.count }

func (t *Table) At(i int) C.Rule {
	kind, _, _, _, _ := t.x.entry(i)
	if kind == kindOther {
		k := sort.Search(len(t.others), func(k int) bool { return int(t.others[k].index) >= i })
		if k < len(t.others) && int(t.others[k].index) == i {
			return t.others[k].rule
		}
	}
	if rule, ok := t.x.mappedAt(i); ok {
		return rule
	}
	return &unreadable{}
}

func (x *Index) mappedAt(i int) (C.Rule, bool) {
	kind, flags, id, payload, ok := x.entry(i)
	if !ok {
		return nil, false
	}
	target, ok := x.target(id)
	if !ok {
		return nil, false
	}
	switch kind {
	case kindDomain:
		return RC.NewDomain(string(payload), target), true
	case kindSuffix:
		return RC.NewDomainSuffix(string(payload), target), true
	case kindKeyword:
		return RC.NewDomainKeyword(string(payload), target), true
	case kindIP:
		rule, err := RC.NewIPCIDR(string(payload), target, RC.WithIPCIDRNoResolve(flags&flagNoResolve != 0))
		return rule, err == nil
	}
	return nil, false
}

type unreadable struct{ RC.Base }

func (*unreadable) RuleType() C.RuleType                                { return C.MATCH }
func (*unreadable) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) { return false, "" }
func (*unreadable) Adapter() string                                     { return "" }
func (*unreadable) Payload() string                                     { return "" }

func (t *Table) Walk(metadata *C.Metadata, helper C.RuleMatchHelper, before func(int, C.Rule), yield func(int, C.Rule, string) bool) {
	x := t.x
	var hostBuffer, ipBuffer [16]cursor
	var matchedBuffer, passedBuffer [4]uint32
	var w walkState
	t.stats.begin(&w)
	host := x.hostCursors(metadata.RuleHost(), hostBuffer[:0])
	ip := x.ipCursors(metadata.DstIP, 0, ipBuffer[:0])
	matched, passed := matchedBuffer[:0], passedBuffer[:0]
	resolver := 0
	resolvers := x.resolverCount()
	stop, stoppedAt := uint32(x.count), int64(0)
	o := 0
	for {
		next, from := uint32(noRule), 0
		if o < len(t.others) {
			next, from = t.others[o].index, 1
		}
		h, hostNext := smallest(host)
		if hostNext < next {
			next, from = hostNext, 2
		}
		p, ipNext := smallest(ip)
		if ipNext < next {
			next, from = ipNext, 3
		}
		if resolver < resolvers {
			if at := x.resolver(resolver); at <= next {
				resolver++
				if t.stats.disabled(at) {
					continue
				}
				resolver = resolvers
				if at > 0 {
					t.stats.pass(&w, at-1, false)
				}
				w.enabled = at
				known := metadata.DstIP
				if helper.ResolveIP != nil {
					helper.ResolveIP()
				}
				if metadata.DstIP != known {
					ip = x.ipCursors(metadata.DstIP, at, ip[:0])
				}
				continue
			}
		}
		if next == noRule {
			break
		}
		if from == 1 {
			t.stats.pass(&w, next, false)
			rule := t.others[o].rule
			o++
			if before != nil {
				before(int(next), rule)
			}
			known := metadata.DstIP
			match, adapter := rule.Match(metadata, helper)
			if metadata.DstIP != known {
				ip = x.ipCursors(metadata.DstIP, next+1, ip[:0])
				resolver = resolvers
			}
			if match && yield(int(next), rule, adapter) {
				stop, stoppedAt = next, time.Now().UnixNano()
				break
			}
			continue
		}
		if from == 2 {
			host[h].advance()
		} else {
			ip[p].advance()
		}
		t.stats.pass(&w, next, true)
		if t.stats.disabledFor(&w, next) {
			w.matched(next, true)
			continue
		}
		w.matched(next, false)
		rule, ok := x.mappedAt(int(next))
		if !ok {
			continue
		}
		at := t.stats.hit(next)
		matched = append(matched, next)
		if yield(int(next), rule, rule.Adapter()) {
			stop, stoppedAt = next, at
			break
		}
		passed = append(passed, next)
	}
	if stop == uint32(x.count) {
		stoppedAt = time.Now().UnixNano()
	}
	t.stats.record(&w, stop, stoppedAt, matched, passed)
}

func (t *Table) Statistics(i int) (C.RuleStatistics, bool) {
	if kind, _, _, _, ok := t.x.entry(i); !ok || kind == kindOther {
		return C.RuleStatistics{}, false
	}
	return t.stats.of(uint32(i)), true
}

func (t *Table) RangeStatistics(f func(i int, statistics C.RuleStatistics, ok bool) bool) {
	t.stats.each(func(i uint32, s C.RuleStatistics) bool {
		if kind, _, _, _, ok := t.x.entry(int(i)); !ok || kind == kindOther {
			return f(int(i), C.RuleStatistics{}, false)
		}
		return f(int(i), s, true)
	})
}

func (t *Table) SetDisabled(i int, disabled bool) bool {
	if i < 0 || i >= t.x.count {
		return false
	}
	if kind, _, _, _, ok := t.x.entry(i); !ok || kind == kindOther {
		return false
	}
	t.stats.setDisabled(uint32(i), disabled)
	return true
}

func (t *Table) Noted(f func(i int) bool) {
	mapped := t.stats.noted()
	o := 0
	for _, rule := range mapped {
		for ; o < len(t.others) && t.others[o].index < rule; o++ {
			if otherNoted(t.others[o].rule) && !f(int(t.others[o].index)) {
				return
			}
		}
		if !f(int(rule)) {
			return
		}
	}
	for ; o < len(t.others); o++ {
		if otherNoted(t.others[o].rule) && !f(int(t.others[o].index)) {
			return
		}
	}
}

func otherNoted(rule C.Rule) bool {
	w, ok := rule.(C.RuleWrapper)
	return ok && (w.HitCount() > 0 || w.IsDisabled())
}

func (t *Table) DroppedStatistics() uint64 { return t.stats.droppedRecords() }

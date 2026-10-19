package clashindex

import (
	"math/bits"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type statistics struct {
	count uint32

	mu      sync.Mutex
	stops   ruleCounts
	hits    ruleCounts
	tracked map[uint32]*trackedRecord
	seq     uint64
	dropped uint64

	passedTracked, disabledTracked int
	unpublished                    []uint32

	lost atomic.Pointer[[]atomic.Uint64]

	trackedNow atomic.Pointer[trackedList]

	off atomic.Pointer[[]atomic.Uint64]
}

const (
	statisticsCapacity = 1 << 16
	trackedCapacity    = 1 << 12
	disabledCapacity   = 1 << 16
)

type trackedRecord struct {
	baseMisses uint64
	baseAt     int64
	misses     uint64
	at         int64
	seq        uint64
}

type trackedList struct {
	rules []uint32
	extra []uint32
	seq   uint64
}

const extraCapacity = 256

type walkState struct {
	start   uint64
	tracked *trackedList
	next    int
	extra   int
	upTo    uint32
	misses  []trackedMiss
	checked []uint32
	enabled uint32
	buffer  [4]trackedMiss
}

type trackedMiss struct {
	rule uint32
	at   int64
}

func (s *statistics) init(count int) {
	s.count = uint32(count)
	s.stops.init()
	s.hits.init()
	s.tracked = map[uint32]*trackedRecord{}
	s.trackedNow.Store(&trackedList{})
}

func (s *statistics) disabled(rule uint32) bool { return bit(&s.off, rule) }

func (s *statistics) begin(w *walkState) {
	w.tracked = s.trackedNow.Load()
	w.start = w.tracked.seq
	w.misses = w.buffer[:0]
	w.enabled = noRule
}

func (s *statistics) disabledFor(w *walkState, rule uint32) bool {
	return rule != w.enabled && s.disabled(rule)
}

func (s *statistics) pass(w *walkState, index uint32, match bool) {
	if now := s.trackedNow.Load(); now != w.tracked {
		w.tracked = now
		w.next = sort.Search(len(now.rules), func(k int) bool { return now.rules[k] >= w.upTo })
		w.extra = sort.Search(len(now.extra), func(k int) bool { return now.extra[k] >= w.upTo })
	}
	for {
		rule, ok := w.head()
		if !ok || rule > index {
			break
		}
		if rule == index && match {
			break
		}
		w.advance()
		if w.tracked.seq != w.start {
			w.checked = append(w.checked, rule)
		}
		if !s.disabledFor(w, rule) {
			w.misses = append(w.misses, trackedMiss{rule, time.Now().UnixNano()})
		}
	}
	if match {
		w.upTo = index
	} else {
		w.upTo = index + 1
	}
}

func (w *walkState) matched(index uint32, disabled bool) {
	if rule, ok := w.head(); ok && rule == index {
		w.advance()
	}
	if disabled {
		w.checked = append(w.checked, index)
	}
	w.upTo = index + 1
}

func (w *walkState) head() (uint32, bool) {
	l := w.tracked
	if w.next < len(l.rules) && (w.extra >= len(l.extra) || l.rules[w.next] < l.extra[w.extra]) {
		return l.rules[w.next], true
	}
	if w.extra < len(l.extra) {
		return l.extra[w.extra], true
	}
	return 0, false
}

func (w *walkState) advance() {
	l := w.tracked
	if w.next < len(l.rules) && (w.extra >= len(l.extra) || l.rules[w.next] < l.extra[w.extra]) {
		w.next++
	} else {
		w.extra++
	}
}

func (s *statistics) hit(rule uint32) int64 {
	now := time.Now().UnixNano()
	s.mu.Lock()
	if !s.hits.add(rule, now) {
		s.dropped++
	}
	s.mu.Unlock()
	return now
}

func (s *statistics) record(w *walkState, stop uint32, stoppedAt int64, matched, passed []uint32) {
	if stop == s.count {
		s.pass(w, stop, false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, miss := range w.misses {
		if t := s.tracked[miss.rule]; t != nil {
			t.misses++
			if miss.at > t.at {
				t.at = miss.at
			}
		}
	}
	if s.seq > w.start {
		for rule, t := range s.tracked {
			if t.seq > w.start && rule < stop && !contains(matched, rule) && !contains(w.checked, rule) {
				t.misses++
				if stoppedAt > t.at {
					t.at = stoppedAt
				}
			}
		}
	}
	if len(passed) > 0 {
		for _, rule := range passed {
			s.track(rule, false)
		}
		s.publishTracked()
	}
	if !s.stops.add(stop, stoppedAt) {
		s.dropped++
	}
}

func contains(rules []uint32, rule uint32) bool {
	k := sort.Search(len(rules), func(k int) bool { return rules[k] >= rule })
	return k < len(rules) && rules[k] == rule
}

func (s *statistics) track(rule uint32, disabling bool) *trackedRecord {
	if t := s.tracked[rule]; t != nil {
		return t
	}
	if bit(&s.lost, rule) {
		return nil
	}
	if disabling && s.disabledTracked >= disabledCapacity || !disabling && s.passedTracked >= trackedCapacity {
		s.dropped++
		setBit(&s.lost, s.count, rule, true)
		return nil
	}
	if disabling {
		s.disabledTracked++
	} else {
		s.passedTracked++
	}
	t := &trackedRecord{}
	s.stops.each(func(stop uint32, count uint64, last int64) {
		if stop > rule {
			t.baseMisses += count
			if last > t.baseAt {
				t.baseAt = last
			}
		}
	})
	s.seq++
	t.seq = s.seq
	s.tracked[rule] = t
	s.unpublished = append(s.unpublished, rule)
	return t
}

func (s *statistics) publishTracked() {
	last := s.trackedNow.Load()
	if last.seq == s.seq {
		return
	}
	added := s.unpublished
	s.unpublished = nil
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	next := &trackedList{rules: last.rules, extra: merged(last.extra, added), seq: s.seq}
	if len(next.extra) > extraCapacity {
		next.rules, next.extra = merged(last.rules, next.extra), nil
	}
	s.trackedNow.Store(next)
}

func merged(a, b []uint32) []uint32 {
	out := make([]uint32, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0] < b[0] {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return append(append(out, a...), b...)
}

func (s *statistics) setDisabled(rule uint32, disabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.track(rule, true)
	s.publishTracked()
	setBit(&s.off, s.count, rule, disabled)
}

func bit(bits *atomic.Pointer[[]atomic.Uint64], rule uint32) bool {
	words := bits.Load()
	return words != nil && int(rule/64) < len(*words) && (*words)[rule/64].Load()&(1<<(rule%64)) != 0
}

func setBit(bits *atomic.Pointer[[]atomic.Uint64], count, rule uint32, on bool) {
	if rule >= count {
		return
	}
	words := bits.Load()
	if words == nil {
		if !on {
			return
		}
		w := make([]atomic.Uint64, (count+63)/64)
		words = &w
		bits.Store(words)
	}
	if on {
		(*words)[rule/64].Or(1 << (rule % 64))
	} else {
		(*words)[rule/64].And(^(uint64(1) << (rule % 64)))
	}
}

func (s *statistics) of(rule uint32) C.RuleStatistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tracked[rule]; t != nil {
		return s.fromTracked(rule, t)
	}
	if bit(&s.lost, rule) {
		return s.statisticsOf(rule, 0, 0)
	}
	var misses uint64
	var at int64
	s.stops.each(func(stop uint32, count uint64, last int64) {
		if stop > rule {
			misses += count
			if last > at {
				at = last
			}
		}
	})
	return s.statisticsOf(rule, misses, at)
}

func (s *statistics) fromTracked(rule uint32, t *trackedRecord) C.RuleStatistics {
	at := t.baseAt
	if t.at > at {
		at = t.at
	}
	return s.statisticsOf(rule, t.baseMisses+t.misses, at)
}

func (s *statistics) statisticsOf(rule uint32, misses uint64, missAt int64) C.RuleStatistics {
	st := C.RuleStatistics{Disabled: s.disabled(rule), MissCount: misses, MissAt: time.Unix(0, missAt), HitAt: time.Unix(0, 0)}
	if count, at, ok := s.hits.get(rule); ok {
		st.HitCount, st.HitAt = count, time.Unix(0, at)
	}
	return st
}

func (s *statistics) each(f func(rule uint32, statistics C.RuleStatistics) bool) {
	type stop struct {
		at    uint32
		count uint64
		last  int64
	}
	type special struct {
		statistics C.RuleStatistics
		tracked    bool
		hits       bool
	}
	s.mu.Lock()
	stops := make([]stop, 0, s.stops.len())
	var total uint64
	s.stops.each(func(at uint32, count uint64, last int64) {
		stops = append(stops, stop{at, count, last})
		total += count
	})
	specials := make(map[uint32]special, len(s.tracked)+s.hits.len())
	for rule, t := range s.tracked {
		specials[rule] = special{statistics: s.fromTracked(rule, t), tracked: true}
	}
	s.hits.each(func(rule uint32, count uint64, at int64) {
		sp := specials[rule]
		sp.statistics.HitCount, sp.statistics.HitAt, sp.hits = count, time.Unix(0, at), true
		specials[rule] = sp
	})
	s.mu.Unlock()

	sort.Slice(stops, func(i, j int) bool { return stops[i].at < stops[j].at })
	lastAfter := make([]int64, len(stops)+1)
	for k := len(stops) - 1; k >= 0; k-- {
		lastAfter[k] = lastAfter[k+1]
		if stops[k].last > lastAfter[k] {
			lastAfter[k] = stops[k].last
		}
	}
	k := 0
	var upTo uint64
	for rule := uint32(0); rule < s.count; rule++ {
		for k < len(stops) && stops[k].at <= rule {
			upTo += stops[k].count
			k++
		}
		st := C.RuleStatistics{MissCount: total - upTo, MissAt: time.Unix(0, lastAfter[k]), HitAt: time.Unix(0, 0), Disabled: s.disabled(rule)}
		if bit(&s.lost, rule) {
			st.MissCount, st.MissAt = 0, time.Unix(0, 0)
		}
		if sp, ok := specials[rule]; ok {
			if sp.tracked {
				st.MissCount, st.MissAt = sp.statistics.MissCount, sp.statistics.MissAt
			}
			if sp.hits {
				st.HitCount, st.HitAt = sp.statistics.HitCount, sp.statistics.HitAt
			}
		}
		if !f(rule, st) {
			return
		}
	}
}

func (s *statistics) noted() []uint32 {
	s.mu.Lock()
	out := make([]uint32, 0, s.hits.len()+s.disabledTracked)
	s.hits.each(func(rule uint32, _ uint64, _ int64) { out = append(out, rule) })
	if off := s.off.Load(); off != nil {
		for k := range *off {
			for word := (*off)[k].Load(); word != 0; word &= word - 1 {
				rule := uint32(64*k + bits.TrailingZeros64(word))
				if _, _, hit := s.hits.get(rule); !hit {
					out = append(out, rule)
				}
			}
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *statistics) droppedRecords() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

type ruleCounts struct {
	keys   []uint32
	counts []uint64
	times  []int64
	used   int
}

func (c *ruleCounts) init() {
	c.keys, c.counts, c.times, c.used = make([]uint32, 16), make([]uint64, 16), make([]int64, 16), 0
}

func (c *ruleCounts) slot(rule uint32) int {
	mask := uint32(len(c.keys) - 1)
	h := (rule * 0x9e3779b1) & mask
	for c.keys[h] != 0 && c.keys[h] != rule+1 {
		h = (h + 1) & mask
	}
	return int(h)
}

func (c *ruleCounts) add(rule uint32, at int64) bool {
	h := c.slot(rule)
	if c.keys[h] == 0 {
		if c.used >= statisticsCapacity {
			return false
		}
		if 4*(c.used+1) > 3*len(c.keys) {
			c.grow()
			h = c.slot(rule)
		}
		c.keys[h] = rule + 1
		c.used++
	}
	c.counts[h]++
	if at > c.times[h] {
		c.times[h] = at
	}
	return true
}

func (c *ruleCounts) grow() {
	keys, counts, times := c.keys, c.counts, c.times
	c.keys, c.counts, c.times = make([]uint32, 2*len(keys)), make([]uint64, 2*len(keys)), make([]int64, 2*len(keys))
	for i, k := range keys {
		if k != 0 {
			h := c.slot(k - 1)
			c.keys[h], c.counts[h], c.times[h] = k, counts[i], times[i]
		}
	}
}

func (c *ruleCounts) get(rule uint32) (uint64, int64, bool) {
	h := c.slot(rule)
	if c.keys[h] == 0 {
		return 0, 0, false
	}
	return c.counts[h], c.times[h], true
}

func (c *ruleCounts) len() int { return c.used }

func (c *ruleCounts) each(f func(rule uint32, count uint64, at int64)) {
	for i, k := range c.keys {
		if k != 0 {
			f(k-1, c.counts[i], c.times[i])
		}
	}
}

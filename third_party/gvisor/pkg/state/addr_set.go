package state

import (
	"bytes"
	"context"
	"fmt"
)

const addrtrackGaps = 0

var _ = uint8(addrtrackGaps << 7)

type addrdynamicGap [addrtrackGaps]uintptr

func (d *addrdynamicGap) Get() uintptr {
	return d[:][0]
}

func (d *addrdynamicGap) Set(v uintptr) {
	d[:][0] = v
}

const (
	addrminDegree = 10

	addrmaxDegree = 2 * addrminDegree
)

type addrSet struct {
	root addrnode `state:".([]addrFlatSegment)"`
}

func (s *addrSet) IsEmpty() bool {
	return s.root.nrSegments == 0
}

func (s *addrSet) IsEmptyRange(r addrRange) bool {
	switch {
	case r.Length() < 0:
		panic(fmt.Sprintf("invalid range %v", r))
	case r.Length() == 0:
		return true
	}
	_, gap := s.Find(r.Start)
	if !gap.Ok() {
		return false
	}
	return r.End <= gap.End()
}

func (s *addrSet) Span() uintptr {
	var sz uintptr
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		sz += seg.Range().Length()
	}
	return sz
}

func (s *addrSet) SpanRange(r addrRange) uintptr {
	switch {
	case r.Length() < 0:
		panic(fmt.Sprintf("invalid range %v", r))
	case r.Length() == 0:
		return 0
	}
	var sz uintptr
	for seg := s.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		sz += seg.Range().Intersect(r).Length()
	}
	return sz
}

func (s *addrSet) FirstSegment() addrIterator {
	if s.root.nrSegments == 0 {
		return addrIterator{}
	}
	return s.root.firstSegment()
}

func (s *addrSet) LastSegment() addrIterator {
	if s.root.nrSegments == 0 {
		return addrIterator{}
	}
	return s.root.lastSegment()
}

func (s *addrSet) FirstGap() addrGapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[0]
	}
	return addrGapIterator{n, 0}
}

func (s *addrSet) LastGap() addrGapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return addrGapIterator{n, n.nrSegments}
}

func (s *addrSet) Find(key uintptr) (addrIterator, addrGapIterator) {
	n := &s.root
	for {

		lower := 0
		upper := n.nrSegments
		for lower < upper {
			i := lower + (upper-lower)/2
			if r := n.keys[i]; key < r.End {
				if key >= r.Start {
					return addrIterator{n, i}, addrGapIterator{}
				}
				upper = i
			} else {
				lower = i + 1
			}
		}
		i := lower
		if !n.hasChildren {
			return addrIterator{}, addrGapIterator{n, i}
		}
		n = n.children[i]
	}
}

func (s *addrSet) FindSegment(key uintptr) addrIterator {
	seg, _ := s.Find(key)
	return seg
}

func (s *addrSet) LowerBoundSegment(min uintptr) addrIterator {
	seg, gap := s.Find(min)
	if seg.Ok() {
		return seg
	}
	return gap.NextSegment()
}

func (s *addrSet) UpperBoundSegment(max uintptr) addrIterator {
	seg, gap := s.Find(max)
	if seg.Ok() {
		return seg
	}
	return gap.PrevSegment()
}

func (s *addrSet) FindGap(key uintptr) addrGapIterator {
	_, gap := s.Find(key)
	return gap
}

func (s *addrSet) LowerBoundGap(min uintptr) addrGapIterator {
	seg, gap := s.Find(min)
	if gap.Ok() {
		return gap
	}
	return seg.NextGap()
}

func (s *addrSet) UpperBoundGap(max uintptr) addrGapIterator {
	seg, gap := s.Find(max)
	if gap.Ok() {
		return gap
	}
	return seg.PrevGap()
}

func (s *addrSet) FirstLargeEnoughGap(minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.FirstGap()
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.NextLargeEnoughGap(minSize)
}

func (s *addrSet) LastLargeEnoughGap(minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.LastGap()
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.PrevLargeEnoughGap(minSize)
}

func (s *addrSet) LowerBoundLargeEnoughGap(min, minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.LowerBoundGap(min)
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.NextLargeEnoughGap(minSize)
}

func (s *addrSet) UpperBoundLargeEnoughGap(max, minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.UpperBoundGap(max)
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.PrevLargeEnoughGap(minSize)
}

func (s *addrSet) Insert(gap addrGapIterator, r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	prev, next := gap.PrevSegment(), gap.NextSegment()
	if prev.Ok() && prev.End() > r.Start {
		panic(fmt.Sprintf("new segment %v overlaps predecessor %v", r, prev.Range()))
	}
	if next.Ok() && next.Start() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps successor %v", r, next.Range()))
	}
	if prev.Ok() && prev.End() == r.Start {
		if mval, ok := (addrSetFunctions{}).Merge(prev.Range(), prev.Value(), r, val); ok {
			shrinkMaxGap := addrtrackGaps != 0 && gap.Range().Length() == gap.node.maxGap.Get()
			prev.SetEndUnchecked(r.End)
			prev.SetValue(mval)
			if shrinkMaxGap {
				gap.node.updateMaxGapLeaf()
			}
			if next.Ok() && next.Start() == r.End {
				val = mval
				if mval, ok := (addrSetFunctions{}).Merge(prev.Range(), val, next.Range(), next.Value()); ok {
					prev.SetEndUnchecked(next.End())
					prev.SetValue(mval)
					return s.Remove(next).PrevSegment()
				}
			}
			return prev
		}
	}
	if next.Ok() && next.Start() == r.End {
		if mval, ok := (addrSetFunctions{}).Merge(r, val, next.Range(), next.Value()); ok {
			shrinkMaxGap := addrtrackGaps != 0 && gap.Range().Length() == gap.node.maxGap.Get()
			next.SetStartUnchecked(r.Start)
			next.SetValue(mval)
			if shrinkMaxGap {
				gap.node.updateMaxGapLeaf()
			}
			return next
		}
	}

	return s.InsertWithoutMergingUnchecked(gap, r, val)
}

func (s *addrSet) InsertWithoutMerging(gap addrGapIterator, r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	if gr := gap.Range(); !gr.IsSupersetOf(r) {
		panic(fmt.Sprintf("cannot insert segment range %v into gap range %v", r, gr))
	}
	return s.InsertWithoutMergingUnchecked(gap, r, val)
}

func (s *addrSet) InsertWithoutMergingUnchecked(gap addrGapIterator, r addrRange, val *objectEncodeState) addrIterator {
	gap = gap.node.rebalanceBeforeInsert(gap)
	splitMaxGap := addrtrackGaps != 0 && (gap.node.nrSegments == 0 || gap.Range().Length() == gap.node.maxGap.Get())
	copy(gap.node.keys[gap.index+1:], gap.node.keys[gap.index:gap.node.nrSegments])
	copy(gap.node.values[gap.index+1:], gap.node.values[gap.index:gap.node.nrSegments])
	gap.node.keys[gap.index] = r
	gap.node.values[gap.index] = val
	gap.node.nrSegments++
	if splitMaxGap {
		gap.node.updateMaxGapLeaf()
	}
	return addrIterator(gap)
}

func (s *addrSet) InsertRange(r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, seg.Range()))
	}
	if gap.End() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, gap.NextSegment().Range()))
	}
	return s.Insert(gap, r, val)
}

func (s *addrSet) InsertWithoutMergingRange(r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, seg.Range()))
	}
	if gap.End() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, gap.NextSegment().Range()))
	}
	return s.InsertWithoutMerging(gap, r, val)
}

func (s *addrSet) TryInsertRange(r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		return addrIterator{}
	}
	if gap.End() < r.End {
		return addrIterator{}
	}
	return s.Insert(gap, r, val)
}

func (s *addrSet) TryInsertWithoutMergingRange(r addrRange, val *objectEncodeState) addrIterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		return addrIterator{}
	}
	if gap.End() < r.End {
		return addrIterator{}
	}
	return s.InsertWithoutMerging(gap, r, val)
}

func (s *addrSet) Remove(seg addrIterator) addrGapIterator {

	if seg.node.hasChildren {

		victim := seg.PrevSegment()

		seg.SetRangeUnchecked(victim.Range())
		seg.SetValue(victim.Value())

		nextAdjacentNode := seg.NextSegment().node
		if addrtrackGaps != 0 {
			nextAdjacentNode.updateMaxGapLeaf()
		}
		return s.Remove(victim).NextGap()
	}
	copy(seg.node.keys[seg.index:], seg.node.keys[seg.index+1:seg.node.nrSegments])
	copy(seg.node.values[seg.index:], seg.node.values[seg.index+1:seg.node.nrSegments])
	addrSetFunctions{}.ClearValue(&seg.node.values[seg.node.nrSegments-1])
	seg.node.nrSegments--
	if addrtrackGaps != 0 {
		seg.node.updateMaxGapLeaf()
	}
	return seg.node.rebalanceAfterRemove(addrGapIterator(seg))
}

func (s *addrSet) RemoveAll() {
	s.root = addrnode{}
}

func (s *addrSet) RemoveRange(r addrRange) addrGapIterator {
	return s.RemoveRangeWith(r, nil)
}

func (s *addrSet) RemoveFullRange(r addrRange) addrGapIterator {
	return s.RemoveFullRangeWith(r, nil)
}

func (s *addrSet) RemoveRangeWith(r addrRange, f func(seg addrIterator)) addrGapIterator {
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		seg = s.Isolate(seg, r)
		if f != nil {
			f(seg)
		}
		gap = s.Remove(seg)
	}
	for seg = gap.NextSegment(); seg.Ok() && seg.Start() < r.End; seg = gap.NextSegment() {
		seg = s.SplitAfter(seg, r.End)
		if f != nil {
			f(seg)
		}
		gap = s.Remove(seg)
	}
	return gap
}

func (s *addrSet) RemoveFullRangeWith(r addrRange, f func(seg addrIterator)) addrGapIterator {
	seg := s.FindSegment(r.Start)
	if !seg.Ok() {
		panic(fmt.Sprintf("missing segment at %v", r.Start))
	}
	seg = s.SplitBefore(seg, r.Start)
	for {
		seg = s.SplitAfter(seg, r.End)
		if f != nil {
			f(seg)
		}
		end := seg.End()
		gap := s.Remove(seg)
		if r.End <= end {
			return gap
		}
		seg = gap.NextSegment()
		if !seg.Ok() || seg.Start() != end {
			panic(fmt.Sprintf("missing segment at %v", end))
		}
	}
}

func (s *addrSet) MoveFrom(s2 *addrSet) {
	*s = *s2
	for _, child := range s.root.children {
		if child == nil {
			break
		}
		child.parent = &s.root
	}
	s2.RemoveAll()
}

func (s *addrSet) Merge(first, second addrIterator) addrIterator {
	if first.NextSegment() != second {
		panic(fmt.Sprintf("attempt to merge non-neighboring segments %v, %v", first.Range(), second.Range()))
	}
	return s.MergeUnchecked(first, second)
}

func (s *addrSet) MergeUnchecked(first, second addrIterator) addrIterator {
	if first.End() == second.Start() {
		if mval, ok := (addrSetFunctions{}).Merge(first.Range(), first.Value(), second.Range(), second.Value()); ok {

			first.SetEndUnchecked(second.End())
			first.SetValue(mval)

			return s.Remove(second).PrevSegment()
		}
	}
	return addrIterator{}
}

func (s *addrSet) MergePrev(seg addrIterator) addrIterator {
	if prev := seg.PrevSegment(); prev.Ok() {
		if mseg := s.MergeUnchecked(prev, seg); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

func (s *addrSet) MergeNext(seg addrIterator) addrIterator {
	if next := seg.NextSegment(); next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

func (s *addrSet) Unisolate(seg addrIterator) addrIterator {
	if prev := seg.PrevSegment(); prev.Ok() {
		if mseg := s.MergeUnchecked(prev, seg); mseg.Ok() {
			seg = mseg
		}
	}
	if next := seg.NextSegment(); next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

func (s *addrSet) MergeAll() {
	seg := s.FirstSegment()
	if !seg.Ok() {
		return
	}
	next := seg.NextSegment()
	for next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg, next = mseg, mseg.NextSegment()
		} else {
			seg, next = next, next.NextSegment()
		}
	}
}

func (s *addrSet) MergeInsideRange(r addrRange) {
	seg := s.LowerBoundSegment(r.Start)
	if !seg.Ok() {
		return
	}
	next := seg.NextSegment()
	for next.Ok() && next.Start() < r.End {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg, next = mseg, mseg.NextSegment()
		} else {
			seg, next = next, next.NextSegment()
		}
	}
}

func (s *addrSet) MergeOutsideRange(r addrRange) {
	first := s.FindSegment(r.Start)
	if first.Ok() {
		if prev := first.PrevSegment(); prev.Ok() {
			s.Merge(prev, first)
		}
	}
	last := s.FindSegment(r.End - 1)
	if last.Ok() {
		if next := last.NextSegment(); next.Ok() {
			s.Merge(last, next)
		}
	}
}

func (s *addrSet) Split(seg addrIterator, split uintptr) (addrIterator, addrIterator) {
	if !seg.Range().CanSplitAt(split) {
		panic(fmt.Sprintf("can't split %v at %v", seg.Range(), split))
	}
	return s.SplitUnchecked(seg, split)
}

func (s *addrSet) SplitUnchecked(seg addrIterator, split uintptr) (addrIterator, addrIterator) {
	val1, val2 := (addrSetFunctions{}).Split(seg.Range(), seg.Value(), split)
	end2 := seg.End()
	seg.SetEndUnchecked(split)
	seg.SetValue(val1)
	seg2 := s.InsertWithoutMergingUnchecked(seg.NextGap(), addrRange{split, end2}, val2)

	return seg2.PrevSegment(), seg2
}

func (s *addrSet) SplitBefore(seg addrIterator, start uintptr) addrIterator {
	if seg.Range().CanSplitAt(start) {
		_, seg = s.SplitUnchecked(seg, start)
	}
	return seg
}

func (s *addrSet) SplitAfter(seg addrIterator, end uintptr) addrIterator {
	if seg.Range().CanSplitAt(end) {
		seg, _ = s.SplitUnchecked(seg, end)
	}
	return seg
}

func (s *addrSet) Isolate(seg addrIterator, r addrRange) addrIterator {
	if seg.Range().CanSplitAt(r.Start) {
		_, seg = s.SplitUnchecked(seg, r.Start)
	}
	if seg.Range().CanSplitAt(r.End) {
		seg, _ = s.SplitUnchecked(seg, r.End)
	}
	return seg
}

func (s *addrSet) LowerBoundSegmentSplitBefore(min uintptr) addrIterator {
	seg, gap := s.Find(min)
	if seg.Ok() {
		return s.SplitBefore(seg, min)
	}
	return gap.NextSegment()
}

func (s *addrSet) UpperBoundSegmentSplitAfter(max uintptr) addrIterator {
	seg, gap := s.Find(max)
	if seg.Ok() {
		return s.SplitAfter(seg, max)
	}
	return gap.PrevSegment()
}

func (s *addrSet) VisitRange(r addrRange, f func(seg addrIterator) bool) {
	for seg := s.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		if !f(seg) {
			return
		}
	}
}

func (s *addrSet) VisitFullRange(r addrRange, f func(seg addrIterator) bool) {
	pos := r.Start
	seg := s.FindSegment(r.Start)
	for {
		if !seg.Ok() {
			panic(fmt.Sprintf("missing segment at %v", pos))
		}
		if !f(seg) {
			return
		}
		pos = seg.End()
		if r.End <= pos {
			return
		}
		seg, _ = seg.NextNonEmpty()
	}
}

func (s *addrSet) MutateRange(r addrRange, f func(seg addrIterator) bool) {
	seg := s.LowerBoundSegmentSplitBefore(r.Start)
	for seg.Ok() && seg.Start() < r.End {
		seg = s.SplitAfter(seg, r.End)
		cont := f(seg)
		seg = s.MergePrev(seg)
		if !cont {
			s.MergeNext(seg)
			return
		}
		seg = seg.NextSegment()
	}
	if seg.Ok() {
		s.MergePrev(seg)
	}
}

func (s *addrSet) MutateFullRange(r addrRange, f func(seg addrIterator) bool) {
	seg := s.FindSegment(r.Start)
	if !seg.Ok() {
		panic(fmt.Sprintf("missing segment at %v", r.Start))
	}
	seg = s.SplitBefore(seg, r.Start)
	for {
		seg = s.SplitAfter(seg, r.End)
		cont := f(seg)
		end := seg.End()
		seg = s.MergePrev(seg)
		if !cont || r.End <= end {
			s.MergeNext(seg)
			return
		}
		seg = seg.NextSegment()
		if !seg.Ok() || seg.Start() != end {
			panic(fmt.Sprintf("missing segment at %v", end))
		}
	}
}

type addrnode struct {
	nrSegments int

	parent *addrnode

	parentIndex int

	hasChildren bool

	maxGap addrdynamicGap

	keys     [addrmaxDegree - 1]addrRange
	values   [addrmaxDegree - 1]*objectEncodeState
	children [addrmaxDegree]*addrnode
}

func (n *addrnode) firstSegment() addrIterator {
	for n.hasChildren {
		n = n.children[0]
	}
	return addrIterator{n, 0}
}

func (n *addrnode) lastSegment() addrIterator {
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return addrIterator{n, n.nrSegments - 1}
}

func (n *addrnode) prevSibling() *addrnode {
	if n.parent == nil || n.parentIndex == 0 {
		return nil
	}
	return n.parent.children[n.parentIndex-1]
}

func (n *addrnode) nextSibling() *addrnode {
	if n.parent == nil || n.parentIndex == n.parent.nrSegments {
		return nil
	}
	return n.parent.children[n.parentIndex+1]
}

func (n *addrnode) rebalanceBeforeInsert(gap addrGapIterator) addrGapIterator {
	if n.nrSegments < addrmaxDegree-1 {
		return gap
	}
	if n.parent != nil {
		gap = n.parent.rebalanceBeforeInsert(gap)
	}
	if n.parent == nil {

		left := &addrnode{
			nrSegments:  addrminDegree - 1,
			parent:      n,
			parentIndex: 0,
			hasChildren: n.hasChildren,
		}
		right := &addrnode{
			nrSegments:  addrminDegree - 1,
			parent:      n,
			parentIndex: 1,
			hasChildren: n.hasChildren,
		}
		copy(left.keys[:addrminDegree-1], n.keys[:addrminDegree-1])
		copy(left.values[:addrminDegree-1], n.values[:addrminDegree-1])
		copy(right.keys[:addrminDegree-1], n.keys[addrminDegree:])
		copy(right.values[:addrminDegree-1], n.values[addrminDegree:])
		n.keys[0], n.values[0] = n.keys[addrminDegree-1], n.values[addrminDegree-1]
		addrzeroValueSlice(n.values[1:])
		if n.hasChildren {
			copy(left.children[:addrminDegree], n.children[:addrminDegree])
			copy(right.children[:addrminDegree], n.children[addrminDegree:])
			addrzeroNodeSlice(n.children[2:])
			for i := 0; i < addrminDegree; i++ {
				left.children[i].parent = left
				left.children[i].parentIndex = i
				right.children[i].parent = right
				right.children[i].parentIndex = i
			}
		}
		n.nrSegments = 1
		n.hasChildren = true
		n.children[0] = left
		n.children[1] = right

		if addrtrackGaps != 0 {
			left.updateMaxGapLocal()
			right.updateMaxGapLocal()
		}
		if gap.node != n {
			return gap
		}
		if gap.index < addrminDegree {
			return addrGapIterator{left, gap.index}
		}
		return addrGapIterator{right, gap.index - addrminDegree}
	}

	copy(n.parent.keys[n.parentIndex+1:], n.parent.keys[n.parentIndex:n.parent.nrSegments])
	copy(n.parent.values[n.parentIndex+1:], n.parent.values[n.parentIndex:n.parent.nrSegments])
	n.parent.keys[n.parentIndex], n.parent.values[n.parentIndex] = n.keys[addrminDegree-1], n.values[addrminDegree-1]
	copy(n.parent.children[n.parentIndex+2:], n.parent.children[n.parentIndex+1:n.parent.nrSegments+1])
	for i := n.parentIndex + 2; i < n.parent.nrSegments+2; i++ {
		n.parent.children[i].parentIndex = i
	}
	sibling := &addrnode{
		nrSegments:  addrminDegree - 1,
		parent:      n.parent,
		parentIndex: n.parentIndex + 1,
		hasChildren: n.hasChildren,
	}
	n.parent.children[n.parentIndex+1] = sibling
	n.parent.nrSegments++
	copy(sibling.keys[:addrminDegree-1], n.keys[addrminDegree:])
	copy(sibling.values[:addrminDegree-1], n.values[addrminDegree:])
	addrzeroValueSlice(n.values[addrminDegree-1:])
	if n.hasChildren {
		copy(sibling.children[:addrminDegree], n.children[addrminDegree:])
		addrzeroNodeSlice(n.children[addrminDegree:])
		for i := 0; i < addrminDegree; i++ {
			sibling.children[i].parent = sibling
			sibling.children[i].parentIndex = i
		}
	}
	n.nrSegments = addrminDegree - 1

	if addrtrackGaps != 0 {
		n.updateMaxGapLocal()
		sibling.updateMaxGapLocal()
	}

	if gap.node != n {
		return gap
	}
	if gap.index < addrminDegree {
		return gap
	}
	return addrGapIterator{sibling, gap.index - addrminDegree}
}

func (n *addrnode) rebalanceAfterRemove(gap addrGapIterator) addrGapIterator {
	for {
		if n.nrSegments >= addrminDegree-1 {
			return gap
		}
		if n.parent == nil {

			return gap
		}

		if sibling := n.prevSibling(); sibling != nil && sibling.nrSegments >= addrminDegree {
			copy(n.keys[1:], n.keys[:n.nrSegments])
			copy(n.values[1:], n.values[:n.nrSegments])
			n.keys[0] = n.parent.keys[n.parentIndex-1]
			n.values[0] = n.parent.values[n.parentIndex-1]
			n.parent.keys[n.parentIndex-1] = sibling.keys[sibling.nrSegments-1]
			n.parent.values[n.parentIndex-1] = sibling.values[sibling.nrSegments-1]
			addrSetFunctions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
			if n.hasChildren {
				copy(n.children[1:], n.children[:n.nrSegments+1])
				n.children[0] = sibling.children[sibling.nrSegments]
				sibling.children[sibling.nrSegments] = nil
				n.children[0].parent = n
				n.children[0].parentIndex = 0
				for i := 1; i < n.nrSegments+2; i++ {
					n.children[i].parentIndex = i
				}
			}
			n.nrSegments++
			sibling.nrSegments--

			if addrtrackGaps != 0 {
				n.updateMaxGapLocal()
				sibling.updateMaxGapLocal()
			}
			if gap.node == sibling && gap.index == sibling.nrSegments {
				return addrGapIterator{n, 0}
			}
			if gap.node == n {
				return addrGapIterator{n, gap.index + 1}
			}
			return gap
		}
		if sibling := n.nextSibling(); sibling != nil && sibling.nrSegments >= addrminDegree {
			n.keys[n.nrSegments] = n.parent.keys[n.parentIndex]
			n.values[n.nrSegments] = n.parent.values[n.parentIndex]
			n.parent.keys[n.parentIndex] = sibling.keys[0]
			n.parent.values[n.parentIndex] = sibling.values[0]
			copy(sibling.keys[:sibling.nrSegments-1], sibling.keys[1:])
			copy(sibling.values[:sibling.nrSegments-1], sibling.values[1:])
			addrSetFunctions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
			if n.hasChildren {
				n.children[n.nrSegments+1] = sibling.children[0]
				copy(sibling.children[:sibling.nrSegments], sibling.children[1:])
				sibling.children[sibling.nrSegments] = nil
				n.children[n.nrSegments+1].parent = n
				n.children[n.nrSegments+1].parentIndex = n.nrSegments + 1
				for i := 0; i < sibling.nrSegments; i++ {
					sibling.children[i].parentIndex = i
				}
			}
			n.nrSegments++
			sibling.nrSegments--

			if addrtrackGaps != 0 {
				n.updateMaxGapLocal()
				sibling.updateMaxGapLocal()
			}
			if gap.node == sibling {
				if gap.index == 0 {
					return addrGapIterator{n, n.nrSegments}
				}
				return addrGapIterator{sibling, gap.index - 1}
			}
			return gap
		}

		p := n.parent
		if p.nrSegments == 1 {

			left, right := p.children[0], p.children[1]
			p.nrSegments = left.nrSegments + right.nrSegments + 1
			p.hasChildren = left.hasChildren
			p.keys[left.nrSegments] = p.keys[0]
			p.values[left.nrSegments] = p.values[0]
			copy(p.keys[:left.nrSegments], left.keys[:left.nrSegments])
			copy(p.values[:left.nrSegments], left.values[:left.nrSegments])
			copy(p.keys[left.nrSegments+1:], right.keys[:right.nrSegments])
			copy(p.values[left.nrSegments+1:], right.values[:right.nrSegments])
			if left.hasChildren {
				copy(p.children[:left.nrSegments+1], left.children[:left.nrSegments+1])
				copy(p.children[left.nrSegments+1:], right.children[:right.nrSegments+1])
				for i := 0; i < p.nrSegments+1; i++ {
					p.children[i].parent = p
					p.children[i].parentIndex = i
				}
			} else {
				p.children[0] = nil
				p.children[1] = nil
			}

			if gap.node == left {
				return addrGapIterator{p, gap.index}
			}
			if gap.node == right {
				return addrGapIterator{p, gap.index + left.nrSegments + 1}
			}
			return gap
		}
		var left, right *addrnode
		if n.parentIndex > 0 {
			left = n.prevSibling()
			right = n
		} else {
			left = n
			right = n.nextSibling()
		}

		if gap.node == right {
			gap = addrGapIterator{left, gap.index + left.nrSegments + 1}
		}
		left.keys[left.nrSegments] = p.keys[left.parentIndex]
		left.values[left.nrSegments] = p.values[left.parentIndex]
		copy(left.keys[left.nrSegments+1:], right.keys[:right.nrSegments])
		copy(left.values[left.nrSegments+1:], right.values[:right.nrSegments])
		if left.hasChildren {
			copy(left.children[left.nrSegments+1:], right.children[:right.nrSegments+1])
			for i := left.nrSegments + 1; i < left.nrSegments+right.nrSegments+2; i++ {
				left.children[i].parent = left
				left.children[i].parentIndex = i
			}
		}
		left.nrSegments += right.nrSegments + 1
		copy(p.keys[left.parentIndex:], p.keys[left.parentIndex+1:p.nrSegments])
		copy(p.values[left.parentIndex:], p.values[left.parentIndex+1:p.nrSegments])
		addrSetFunctions{}.ClearValue(&p.values[p.nrSegments-1])
		copy(p.children[left.parentIndex+1:], p.children[left.parentIndex+2:p.nrSegments+1])
		for i := 0; i < p.nrSegments; i++ {
			p.children[i].parentIndex = i
		}
		p.children[p.nrSegments] = nil
		p.nrSegments--

		if addrtrackGaps != 0 {
			left.updateMaxGapLocal()
		}

		n = p
	}
}

func (n *addrnode) updateMaxGapLeaf() {
	if n.hasChildren {
		panic(fmt.Sprintf("updateMaxGapLeaf should always be called on leaf node: %v", n))
	}
	max := n.calculateMaxGapLeaf()
	if max == n.maxGap.Get() {

		return
	}
	oldMax := n.maxGap.Get()
	n.maxGap.Set(max)
	if max > oldMax {

		for p := n.parent; p != nil; p = p.parent {
			if p.maxGap.Get() >= max {

				break
			}

			p.maxGap.Set(max)
		}
		return
	}

	for p := n.parent; p != nil; p = p.parent {
		if p.maxGap.Get() > oldMax {

			break
		}

		parentNewMax := p.calculateMaxGapInternal()
		if p.maxGap.Get() == parentNewMax {

			break
		}

		p.maxGap.Set(parentNewMax)
	}
}

func (n *addrnode) updateMaxGapLocal() {
	if !n.hasChildren {

		n.maxGap.Set(n.calculateMaxGapLeaf())
	} else {

		n.maxGap.Set(n.calculateMaxGapInternal())
	}
}

func (n *addrnode) calculateMaxGapLeaf() uintptr {
	max := addrGapIterator{n, 0}.Range().Length()
	for i := 1; i <= n.nrSegments; i++ {
		if current := (addrGapIterator{n, i}).Range().Length(); current > max {
			max = current
		}
	}
	return max
}

func (n *addrnode) calculateMaxGapInternal() uintptr {
	max := n.children[0].maxGap.Get()
	for i := 1; i <= n.nrSegments; i++ {
		if current := n.children[i].maxGap.Get(); current > max {
			max = current
		}
	}
	return max
}

func (n *addrnode) searchFirstLargeEnoughGap(minSize uintptr) addrGapIterator {
	if n.maxGap.Get() < minSize {
		return addrGapIterator{}
	}
	if n.hasChildren {
		for i := 0; i <= n.nrSegments; i++ {
			if largeEnoughGap := n.children[i].searchFirstLargeEnoughGap(minSize); largeEnoughGap.Ok() {
				return largeEnoughGap
			}
		}
	} else {
		for i := 0; i <= n.nrSegments; i++ {
			currentGap := addrGapIterator{n, i}
			if currentGap.Range().Length() >= minSize {
				return currentGap
			}
		}
	}
	panic(fmt.Sprintf("invalid maxGap in %v", n))
}

func (n *addrnode) searchLastLargeEnoughGap(minSize uintptr) addrGapIterator {
	if n.maxGap.Get() < minSize {
		return addrGapIterator{}
	}
	if n.hasChildren {
		for i := n.nrSegments; i >= 0; i-- {
			if largeEnoughGap := n.children[i].searchLastLargeEnoughGap(minSize); largeEnoughGap.Ok() {
				return largeEnoughGap
			}
		}
	} else {
		for i := n.nrSegments; i >= 0; i-- {
			currentGap := addrGapIterator{n, i}
			if currentGap.Range().Length() >= minSize {
				return currentGap
			}
		}
	}
	panic(fmt.Sprintf("invalid maxGap in %v", n))
}

type addrIterator struct {
	node *addrnode

	index int
}

func (seg addrIterator) Ok() bool {
	return seg.node != nil
}

func (seg addrIterator) Range() addrRange {
	return seg.node.keys[seg.index]
}

func (seg addrIterator) Start() uintptr {
	return seg.node.keys[seg.index].Start
}

func (seg addrIterator) End() uintptr {
	return seg.node.keys[seg.index].End
}

func (seg addrIterator) SetRangeUnchecked(r addrRange) {
	seg.node.keys[seg.index] = r
}

func (seg addrIterator) SetRange(r addrRange) {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	if prev := seg.PrevSegment(); prev.Ok() && r.Start < prev.End() {
		panic(fmt.Sprintf("new segment range %v overlaps segment range %v", r, prev.Range()))
	}
	if next := seg.NextSegment(); next.Ok() && r.End > next.Start() {
		panic(fmt.Sprintf("new segment range %v overlaps segment range %v", r, next.Range()))
	}
	seg.SetRangeUnchecked(r)
}

func (seg addrIterator) SetStartUnchecked(start uintptr) {
	seg.node.keys[seg.index].Start = start
}

func (seg addrIterator) SetStart(start uintptr) {
	if start >= seg.End() {
		panic(fmt.Sprintf("new start %v would invalidate segment range %v", start, seg.Range()))
	}
	if prev := seg.PrevSegment(); prev.Ok() && start < prev.End() {
		panic(fmt.Sprintf("new start %v would cause segment range %v to overlap segment range %v", start, seg.Range(), prev.Range()))
	}
	seg.SetStartUnchecked(start)
}

func (seg addrIterator) SetEndUnchecked(end uintptr) {
	seg.node.keys[seg.index].End = end
}

func (seg addrIterator) SetEnd(end uintptr) {
	if end <= seg.Start() {
		panic(fmt.Sprintf("new end %v would invalidate segment range %v", end, seg.Range()))
	}
	if next := seg.NextSegment(); next.Ok() && end > next.Start() {
		panic(fmt.Sprintf("new end %v would cause segment range %v to overlap segment range %v", end, seg.Range(), next.Range()))
	}
	seg.SetEndUnchecked(end)
}

func (seg addrIterator) Value() *objectEncodeState {
	return seg.node.values[seg.index]
}

func (seg addrIterator) ValuePtr() **objectEncodeState {
	return &seg.node.values[seg.index]
}

func (seg addrIterator) SetValue(val *objectEncodeState) {
	seg.node.values[seg.index] = val
}

func (seg addrIterator) PrevSegment() addrIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index].lastSegment()
	}
	if seg.index > 0 {
		return addrIterator{seg.node, seg.index - 1}
	}
	if seg.node.parent == nil {
		return addrIterator{}
	}
	return addrsegmentBeforePosition(seg.node.parent, seg.node.parentIndex)
}

func (seg addrIterator) NextSegment() addrIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment()
	}
	if seg.index < seg.node.nrSegments-1 {
		return addrIterator{seg.node, seg.index + 1}
	}
	if seg.node.parent == nil {
		return addrIterator{}
	}
	return addrsegmentAfterPosition(seg.node.parent, seg.node.parentIndex)
}

func (seg addrIterator) PrevGap() addrGapIterator {
	if seg.node.hasChildren {

		return seg.node.children[seg.index].lastSegment().NextGap()
	}
	return addrGapIterator(seg)
}

func (seg addrIterator) NextGap() addrGapIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment().PrevGap()
	}
	return addrGapIterator{seg.node, seg.index + 1}
}

func (seg addrIterator) PrevNonEmpty() (addrIterator, addrGapIterator) {
	if prev := seg.PrevSegment(); prev.Ok() && prev.End() == seg.Start() {
		return prev, addrGapIterator{}
	}
	return addrIterator{}, seg.PrevGap()
}

func (seg addrIterator) NextNonEmpty() (addrIterator, addrGapIterator) {
	if next := seg.NextSegment(); next.Ok() && next.Start() == seg.End() {
		return next, addrGapIterator{}
	}
	return addrIterator{}, seg.NextGap()
}

type addrGapIterator struct {
	node  *addrnode
	index int
}

func (gap addrGapIterator) Ok() bool {
	return gap.node != nil
}

func (gap addrGapIterator) Range() addrRange {
	return addrRange{gap.Start(), gap.End()}
}

func (gap addrGapIterator) Start() uintptr {
	if ps := gap.PrevSegment(); ps.Ok() {
		return ps.End()
	}
	return addrSetFunctions{}.MinKey()
}

func (gap addrGapIterator) End() uintptr {
	if ns := gap.NextSegment(); ns.Ok() {
		return ns.Start()
	}
	return addrSetFunctions{}.MaxKey()
}

func (gap addrGapIterator) IsEmpty() bool {
	return gap.Range().Length() == 0
}

func (gap addrGapIterator) PrevSegment() addrIterator {
	return addrsegmentBeforePosition(gap.node, gap.index)
}

func (gap addrGapIterator) NextSegment() addrIterator {
	return addrsegmentAfterPosition(gap.node, gap.index)
}

func (gap addrGapIterator) PrevGap() addrGapIterator {
	seg := gap.PrevSegment()
	if !seg.Ok() {
		return addrGapIterator{}
	}
	return seg.PrevGap()
}

func (gap addrGapIterator) NextGap() addrGapIterator {
	seg := gap.NextSegment()
	if !seg.Ok() {
		return addrGapIterator{}
	}
	return seg.NextGap()
}

func (gap addrGapIterator) NextLargeEnoughGap(minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	if gap.node != nil && gap.node.hasChildren && gap.index == gap.node.nrSegments {

		gap.node = gap.NextSegment().node
		gap.index = 0
		return gap.nextLargeEnoughGapHelper(minSize)
	}
	return gap.nextLargeEnoughGapHelper(minSize)
}

func (gap addrGapIterator) nextLargeEnoughGapHelper(minSize uintptr) addrGapIterator {
	for {

		for gap.node != nil &&
			(gap.node.maxGap.Get() < minSize || (!gap.node.hasChildren && gap.index == gap.node.nrSegments)) {
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}

		if gap.node == nil {
			return addrGapIterator{}
		}

		gap.index++
		for gap.index <= gap.node.nrSegments {
			if gap.node.hasChildren {
				if largeEnoughGap := gap.node.children[gap.index].searchFirstLargeEnoughGap(minSize); largeEnoughGap.Ok() {
					return largeEnoughGap
				}
			} else {
				if gap.Range().Length() >= minSize {
					return gap
				}
			}
			gap.index++
		}
		gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		if gap.node != nil && gap.index == gap.node.nrSegments {

			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
	}
}

func (gap addrGapIterator) PrevLargeEnoughGap(minSize uintptr) addrGapIterator {
	if addrtrackGaps != 1 {
		panic("set is not tracking gaps")
	}
	if gap.node != nil && gap.node.hasChildren && gap.index == 0 {

		gap.node = gap.PrevSegment().node
		gap.index = gap.node.nrSegments
		return gap.prevLargeEnoughGapHelper(minSize)
	}
	return gap.prevLargeEnoughGapHelper(minSize)
}

func (gap addrGapIterator) prevLargeEnoughGapHelper(minSize uintptr) addrGapIterator {
	for {

		for gap.node != nil &&
			(gap.node.maxGap.Get() < minSize || (!gap.node.hasChildren && gap.index == 0)) {
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}

		if gap.node == nil {
			return addrGapIterator{}
		}

		gap.index--
		for gap.index >= 0 {
			if gap.node.hasChildren {
				if largeEnoughGap := gap.node.children[gap.index].searchLastLargeEnoughGap(minSize); largeEnoughGap.Ok() {
					return largeEnoughGap
				}
			} else {
				if gap.Range().Length() >= minSize {
					return gap
				}
			}
			gap.index--
		}
		gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		if gap.node != nil && gap.index == 0 {

			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
	}
}

func addrsegmentBeforePosition(n *addrnode, i int) addrIterator {
	for i == 0 {
		if n.parent == nil {
			return addrIterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return addrIterator{n, i - 1}
}

func addrsegmentAfterPosition(n *addrnode, i int) addrIterator {
	for i == n.nrSegments {
		if n.parent == nil {
			return addrIterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return addrIterator{n, i}
}

func addrzeroValueSlice(slice []*objectEncodeState) {

	for i := range slice {
		addrSetFunctions{}.ClearValue(&slice[i])
	}
}

func addrzeroNodeSlice(slice []*addrnode) {
	for i := range slice {
		slice[i] = nil
	}
}

func (s *addrSet) String() string {
	return s.root.String()
}

func (n *addrnode) String() string {
	var buf bytes.Buffer
	n.writeDebugString(&buf, "")
	return buf.String()
}

func (n *addrnode) writeDebugString(buf *bytes.Buffer, prefix string) {
	if n.hasChildren != (n.nrSegments > 0 && n.children[0] != nil) {
		buf.WriteString(prefix)
		fmt.Fprintf(buf, "WARNING: inconsistent value of hasChildren: got %v, want %v\n", n.hasChildren, !n.hasChildren)
	}
	for i := 0; i < n.nrSegments; i++ {
		if child := n.children[i]; child != nil {
			cprefix := fmt.Sprintf("%s- % 3d ", prefix, i)
			if child.parent != n || child.parentIndex != i {
				buf.WriteString(cprefix)
				fmt.Fprintf(buf, "WARNING: inconsistent linkage to parent: got (%p, %d), want (%p, %d)\n", child.parent, child.parentIndex, n, i)
			}
			child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, i))
		}
		buf.WriteString(prefix)
		if n.hasChildren {
			if addrtrackGaps != 0 {
				fmt.Fprintf(buf, "- % 3d: %v => %v, maxGap: %d\n", i, n.keys[i], n.values[i], n.maxGap.Get())
			} else {
				fmt.Fprintf(buf, "- % 3d: %v => %v\n", i, n.keys[i], n.values[i])
			}
		} else {
			fmt.Fprintf(buf, "- % 3d: %v => %v\n", i, n.keys[i], n.values[i])
		}
	}
	if child := n.children[n.nrSegments]; child != nil {
		child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, n.nrSegments))
	}
}

type addrFlatSegment struct {
	Start uintptr
	End   uintptr
	Value *objectEncodeState
}

func (s *addrSet) ExportSlice() []addrFlatSegment {
	var fs []addrFlatSegment
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		fs = append(fs, addrFlatSegment{
			Start: seg.Start(),
			End:   seg.End(),
			Value: seg.Value(),
		})
	}
	return fs
}

func (s *addrSet) ImportSlice(fs []addrFlatSegment) error {
	if !s.IsEmpty() {
		return fmt.Errorf("cannot import into non-empty set %v", s)
	}
	gap := s.FirstGap()
	for i := range fs {
		f := &fs[i]
		r := addrRange{f.Start, f.End}
		if !gap.Range().IsSupersetOf(r) {
			return fmt.Errorf("segment overlaps a preceding segment or is incorrectly sorted: %v => %v", r, f.Value)
		}
		gap = s.InsertWithoutMerging(gap, r, f.Value).NextGap()
	}
	return nil
}

func (s *addrSet) segmentTestCheck(expectedSegments int, segFunc func(int, addrRange, *objectEncodeState) error) error {
	havePrev := false
	prev := uintptr(0)
	nrSegments := 0
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		next := seg.Start()
		if havePrev && prev >= next {
			return fmt.Errorf("incorrect order: key %d (segment %d) >= key %d (segment %d)", prev, nrSegments-1, next, nrSegments)
		}
		if segFunc != nil {
			if err := segFunc(nrSegments, seg.Range(), seg.Value()); err != nil {
				return err
			}
		}
		prev = next
		havePrev = true
		nrSegments++
	}
	if nrSegments != expectedSegments {
		return fmt.Errorf("incorrect number of segments: got %d, wanted %d", nrSegments, expectedSegments)
	}
	return nil
}

func (s *addrSet) countSegments() (segments int) {
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		segments++
	}
	return segments
}
func (s *addrSet) saveRoot() []addrFlatSegment {
	fs := s.ExportSlice()

	fs = fs[:len(fs):len(fs)]
	return fs
}

func (s *addrSet) loadRoot(_ context.Context, fs []addrFlatSegment) {
	if err := s.ImportSlice(fs); err != nil {
		panic(err)
	}
}

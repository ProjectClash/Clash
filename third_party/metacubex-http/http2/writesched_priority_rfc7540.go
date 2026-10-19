// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"fmt"
	"math"
	"sort"
)

const priorityDefaultWeightRFC7540 = 15

type PriorityWriteSchedulerConfig struct {
	MaxClosedNodesInTree int

	MaxIdleNodesInTree int

	ThrottleOutOfOrderWrites bool
}

func NewPriorityWriteScheduler(cfg *PriorityWriteSchedulerConfig) WriteScheduler {
	if cfg == nil {
		cfg = &PriorityWriteSchedulerConfig{
			MaxClosedNodesInTree:     10,
			MaxIdleNodesInTree:       10,
			ThrottleOutOfOrderWrites: false,
		}
	}

	ws := &priorityWriteSchedulerRFC7540{
		nodes:                make(map[uint32]*priorityNodeRFC7540),
		maxClosedNodesInTree: cfg.MaxClosedNodesInTree,
		maxIdleNodesInTree:   cfg.MaxIdleNodesInTree,
		enableWriteThrottle:  cfg.ThrottleOutOfOrderWrites,
	}
	ws.nodes[0] = &ws.root
	if cfg.ThrottleOutOfOrderWrites {
		ws.writeThrottleLimit = 1024
	} else {
		ws.writeThrottleLimit = math.MaxInt32
	}
	return ws
}

type priorityNodeStateRFC7540 int

const (
	priorityNodeOpenRFC7540 priorityNodeStateRFC7540 = iota
	priorityNodeClosedRFC7540
	priorityNodeIdleRFC7540
)

type priorityNodeRFC7540 struct {
	q            writeQueue
	id           uint32
	weight       uint8
	state        priorityNodeStateRFC7540
	bytes        int64
	subtreeBytes int64

	parent     *priorityNodeRFC7540
	kids       *priorityNodeRFC7540
	prev, next *priorityNodeRFC7540
}

func (n *priorityNodeRFC7540) setParent(parent *priorityNodeRFC7540) {
	if n == parent {
		panic("setParent to self")
	}
	if n.parent == parent {
		return
	}
	if parent := n.parent; parent != nil {
		if n.prev == nil {
			parent.kids = n.next
		} else {
			n.prev.next = n.next
		}
		if n.next != nil {
			n.next.prev = n.prev
		}
	}
	n.parent = parent
	if parent == nil {
		n.next = nil
		n.prev = nil
	} else {
		n.next = parent.kids
		n.prev = nil
		if n.next != nil {
			n.next.prev = n
		}
		parent.kids = n
	}
}

func (n *priorityNodeRFC7540) addBytes(b int64) {
	n.bytes += b
	for ; n != nil; n = n.parent {
		n.subtreeBytes += b
	}
}

func (n *priorityNodeRFC7540) walkReadyInOrder(openParent bool, tmp *[]*priorityNodeRFC7540, f func(*priorityNodeRFC7540, bool) bool) bool {
	if !n.q.empty() && f(n, openParent) {
		return true
	}
	if n.kids == nil {
		return false
	}

	if n.id != 0 {
		openParent = openParent || (n.state == priorityNodeOpenRFC7540)
	}

	w := n.kids.weight
	needSort := false
	for k := n.kids.next; k != nil; k = k.next {
		if k.weight != w {
			needSort = true
			break
		}
	}
	if !needSort {
		for k := n.kids; k != nil; k = k.next {
			if k.walkReadyInOrder(openParent, tmp, f) {
				return true
			}
		}
		return false
	}

	*tmp = (*tmp)[:0]
	for n.kids != nil {
		*tmp = append(*tmp, n.kids)
		n.kids.setParent(nil)
	}
	sort.Sort(sortPriorityNodeSiblingsRFC7540(*tmp))
	for i := len(*tmp) - 1; i >= 0; i-- {
		(*tmp)[i].setParent(n)
	}
	for k := n.kids; k != nil; k = k.next {
		if k.walkReadyInOrder(openParent, tmp, f) {
			return true
		}
	}
	return false
}

type sortPriorityNodeSiblingsRFC7540 []*priorityNodeRFC7540

func (z sortPriorityNodeSiblingsRFC7540) Len() int      { return len(z) }
func (z sortPriorityNodeSiblingsRFC7540) Swap(i, k int) { z[i], z[k] = z[k], z[i] }
func (z sortPriorityNodeSiblingsRFC7540) Less(i, k int) bool {
	wi, bi := float64(z[i].weight)+1, float64(z[i].subtreeBytes)
	wk, bk := float64(z[k].weight)+1, float64(z[k].subtreeBytes)
	if bi == 0 && bk == 0 {
		return wi >= wk
	}
	if bk == 0 {
		return false
	}
	return bi/bk <= wi/wk
}

type priorityWriteSchedulerRFC7540 struct {
	root priorityNodeRFC7540

	nodes map[uint32]*priorityNodeRFC7540

	maxID uint32

	closedNodes, idleNodes []*priorityNodeRFC7540

	maxClosedNodesInTree int
	maxIdleNodesInTree   int
	writeThrottleLimit   int32
	enableWriteThrottle  bool

	tmp []*priorityNodeRFC7540

	queuePool writeQueuePool
}

func (ws *priorityWriteSchedulerRFC7540) OpenStream(streamID uint32, options OpenStreamOptions) {
	if curr := ws.nodes[streamID]; curr != nil {
		if curr.state != priorityNodeIdleRFC7540 {
			panic(fmt.Sprintf("stream %d already opened", streamID))
		}
		curr.state = priorityNodeOpenRFC7540
		return
	}

	parent := ws.nodes[options.PusherID]
	if parent == nil {
		parent = &ws.root
	}
	n := &priorityNodeRFC7540{
		q:      *ws.queuePool.get(),
		id:     streamID,
		weight: priorityDefaultWeightRFC7540,
		state:  priorityNodeOpenRFC7540,
	}
	n.setParent(parent)
	ws.nodes[streamID] = n
	if streamID > ws.maxID {
		ws.maxID = streamID
	}
}

func (ws *priorityWriteSchedulerRFC7540) CloseStream(streamID uint32) {
	if streamID == 0 {
		panic("violation of WriteScheduler interface: cannot close stream 0")
	}
	if ws.nodes[streamID] == nil {
		panic(fmt.Sprintf("violation of WriteScheduler interface: unknown stream %d", streamID))
	}
	if ws.nodes[streamID].state != priorityNodeOpenRFC7540 {
		panic(fmt.Sprintf("violation of WriteScheduler interface: stream %d already closed", streamID))
	}

	n := ws.nodes[streamID]
	n.state = priorityNodeClosedRFC7540
	n.addBytes(-n.bytes)

	q := n.q
	ws.queuePool.put(&q)
	if ws.maxClosedNodesInTree > 0 {
		ws.addClosedOrIdleNode(&ws.closedNodes, ws.maxClosedNodesInTree, n)
	} else {
		ws.removeNode(n)
	}
}

func (ws *priorityWriteSchedulerRFC7540) AdjustStream(streamID uint32, priority PriorityParam) {
	if streamID == 0 {
		panic("adjustPriority on root")
	}

	n := ws.nodes[streamID]
	if n == nil {
		if streamID <= ws.maxID || ws.maxIdleNodesInTree == 0 {
			return
		}
		ws.maxID = streamID
		n = &priorityNodeRFC7540{
			q:      *ws.queuePool.get(),
			id:     streamID,
			weight: priorityDefaultWeightRFC7540,
			state:  priorityNodeIdleRFC7540,
		}
		n.setParent(&ws.root)
		ws.nodes[streamID] = n
		ws.addClosedOrIdleNode(&ws.idleNodes, ws.maxIdleNodesInTree, n)
	}

	parent := ws.nodes[priority.StreamDep]
	if parent == nil {
		n.setParent(&ws.root)
		n.weight = priorityDefaultWeightRFC7540
		return
	}

	if n == parent {
		return
	}

	for x := parent.parent; x != nil; x = x.parent {
		if x == n {
			parent.setParent(n.parent)
			break
		}
	}

	if priority.Exclusive {
		k := parent.kids
		for k != nil {
			next := k.next
			if k != n {
				k.setParent(n)
			}
			k = next
		}
	}

	n.setParent(parent)
	n.weight = priority.Weight
}

func (ws *priorityWriteSchedulerRFC7540) Push(wr FrameWriteRequest) {
	var n *priorityNodeRFC7540
	if wr.isControl() {
		n = &ws.root
	} else {
		id := wr.StreamID()
		n = ws.nodes[id]
		if n == nil {
			if wr.DataSize() > 0 {
				panic("add DATA on non-open stream")
			}
			n = &ws.root
		}
	}
	n.q.push(wr)
}

func (ws *priorityWriteSchedulerRFC7540) Pop() (wr FrameWriteRequest, ok bool) {
	ws.root.walkReadyInOrder(false, &ws.tmp, func(n *priorityNodeRFC7540, openParent bool) bool {
		limit := int32(math.MaxInt32)
		if openParent {
			limit = ws.writeThrottleLimit
		}
		wr, ok = n.q.consume(limit)
		if !ok {
			return false
		}
		n.addBytes(int64(wr.DataSize()))
		if openParent {
			ws.writeThrottleLimit += 1024
			if ws.writeThrottleLimit < 0 {
				ws.writeThrottleLimit = math.MaxInt32
			}
		} else if ws.enableWriteThrottle {
			ws.writeThrottleLimit = 1024
		}
		return true
	})
	return wr, ok
}

func (ws *priorityWriteSchedulerRFC7540) addClosedOrIdleNode(list *[]*priorityNodeRFC7540, maxSize int, n *priorityNodeRFC7540) {
	if maxSize == 0 {
		return
	}
	if len(*list) == maxSize {
		ws.removeNode((*list)[0])
		x := (*list)[1:]
		copy(*list, x)
		*list = (*list)[:len(x)]
	}
	*list = append(*list, n)
}

func (ws *priorityWriteSchedulerRFC7540) removeNode(n *priorityNodeRFC7540) {
	for n.kids != nil {
		n.kids.setParent(n.parent)
	}
	n.setParent(nil)
	delete(ws.nodes, n.id)
}

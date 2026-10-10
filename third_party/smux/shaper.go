// MIT License
//
// Copyright (c) 2016-2017 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package smux

import (
	"container/heap"
	"container/list"
	"sync"
)

func _itimediff(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

type shaperHeap []writeRequest

func (h shaperHeap) Len() int { return len(h) }

func (h shaperHeap) Less(i, j int) bool {
	if h[i].class != h[j].class {
		return h[i].class < h[j].class
	}
	return _itimediff(h[j].seq, h[i].seq) > 0
}

func (h shaperHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *shaperHeap) Push(x any)   { *h = append(*h, x.(writeRequest)) }

func (h *shaperHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = writeRequest{}
	*h = old[0 : n-1]
	return x
}

type shaperQueue struct {
	streams map[uint32]*shaperHeap
	rrList  *list.List
	next    *list.Element
	count   int
	mu      sync.Mutex
}

func NewShaperQueue() *shaperQueue {
	return &shaperQueue{
		streams: make(map[uint32]*shaperHeap),
		rrList:  list.New(),
	}
}

func (sq *shaperQueue) Push(req writeRequest) {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	sid := req.frame.sid
	if _, ok := sq.streams[sid]; !ok {
		sq.streams[sid] = new(shaperHeap)
		elem := sq.rrList.PushBack(sid)
		if sq.next == nil {
			sq.next = elem
		}
	}

	h := sq.streams[sid]
	heap.Push(h, req)
	sq.count++
}

func (sq *shaperQueue) Pop() (req writeRequest, ok bool) {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	if sq.next == nil || sq.count == 0 {
		return writeRequest{}, false
	}

	start := sq.next
	current := start

	for {
		sid := current.Value.(uint32)
		h := sq.streams[sid]

		if h.Len() > 0 {
			req := heap.Pop(h).(writeRequest)
			sq.count--

			next := current.Next()
			if next == nil {
				next = sq.rrList.Front()
			}
			sq.next = next

			if h.Len() == 0 {
				delete(sq.streams, sid)
				sq.rrList.Remove(current)
				if sq.rrList.Len() == 0 {
					sq.next = nil
				}
			}
			return req, true
		}

		current = current.Next()
		if current == nil {
			current = sq.rrList.Front()
		}
		if current == start {
			break
		}
	}

	return writeRequest{}, false
}

func (sq *shaperQueue) IsEmpty() bool {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	return sq.count == 0
}

func (sq *shaperQueue) Len() int {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	return sq.count
}

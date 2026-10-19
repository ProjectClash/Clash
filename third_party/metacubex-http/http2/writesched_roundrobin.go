// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"fmt"
	"math"
)

type roundRobinWriteScheduler struct {
	control writeQueue

	streams map[uint32]*writeQueue

	head *writeQueue

	queuePool writeQueuePool
}

func newRoundRobinWriteScheduler() WriteScheduler {
	ws := &roundRobinWriteScheduler{
		streams: make(map[uint32]*writeQueue),
	}
	return ws
}

func (ws *roundRobinWriteScheduler) OpenStream(streamID uint32, options OpenStreamOptions) {
	if ws.streams[streamID] != nil {
		panic(fmt.Errorf("stream %d already opened", streamID))
	}
	q := ws.queuePool.get()
	ws.streams[streamID] = q
	if ws.head == nil {
		ws.head = q
		q.next = q
		q.prev = q
	} else {
		q.prev = ws.head.prev
		q.next = ws.head
		q.prev.next = q
		q.next.prev = q
	}
}

func (ws *roundRobinWriteScheduler) CloseStream(streamID uint32) {
	q := ws.streams[streamID]
	if q == nil {
		return
	}
	if q.next == q {
		ws.head = nil
	} else {
		q.prev.next = q.next
		q.next.prev = q.prev
		if ws.head == q {
			ws.head = q.next
		}
	}
	delete(ws.streams, streamID)
	ws.queuePool.put(q)
}

func (ws *roundRobinWriteScheduler) AdjustStream(streamID uint32, priority PriorityParam) {}

func (ws *roundRobinWriteScheduler) Push(wr FrameWriteRequest) {
	if wr.isControl() {
		ws.control.push(wr)
		return
	}
	q := ws.streams[wr.StreamID()]
	if q == nil {
		if wr.DataSize() > 0 {
			panic("add DATA on non-open stream")
		}
		ws.control.push(wr)
		return
	}
	q.push(wr)
}

func (ws *roundRobinWriteScheduler) Pop() (FrameWriteRequest, bool) {
	if !ws.control.empty() {
		return ws.control.shift(), true
	}
	if ws.head == nil {
		return FrameWriteRequest{}, false
	}
	q := ws.head
	for {
		if wr, ok := q.consume(math.MaxInt32); ok {
			ws.head = q.next
			return wr, true
		}
		q = q.next
		if q == ws.head {
			break
		}
	}
	return FrameWriteRequest{}, false
}

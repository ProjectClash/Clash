// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"fmt"
	"math"
)

type streamMetadata struct {
	location *writeQueue
	priority PriorityParam
}

type priorityWriteSchedulerRFC9218 struct {
	control writeQueue

	heads [8][2]*writeQueue

	streams map[uint32]streamMetadata

	queuePool writeQueuePool

	prioritizeIncremental bool
}

func newPriorityWriteSchedulerRFC9218() WriteScheduler {
	ws := &priorityWriteSchedulerRFC9218{
		streams: make(map[uint32]streamMetadata),
	}
	return ws
}

func (ws *priorityWriteSchedulerRFC9218) OpenStream(streamID uint32, opt OpenStreamOptions) {
	if ws.streams[streamID].location != nil {
		panic(fmt.Errorf("stream %d already opened", streamID))
	}
	q := ws.queuePool.get()
	ws.streams[streamID] = streamMetadata{
		location: q,
		priority: opt.priority,
	}

	u, i := opt.priority.urgency, opt.priority.incremental
	if ws.heads[u][i] == nil {
		ws.heads[u][i] = q
		q.next = q
		q.prev = q
	} else {
		q.prev = ws.heads[u][i].prev
		q.next = ws.heads[u][i]
		q.prev.next = q
		q.next.prev = q
	}
}

func (ws *priorityWriteSchedulerRFC9218) CloseStream(streamID uint32) {
	metadata := ws.streams[streamID]
	q, u, i := metadata.location, metadata.priority.urgency, metadata.priority.incremental
	if q == nil {
		return
	}
	if q.next == q {
		ws.heads[u][i] = nil
	} else {
		q.prev.next = q.next
		q.next.prev = q.prev
		if ws.heads[u][i] == q {
			ws.heads[u][i] = q.next
		}
	}
	delete(ws.streams, streamID)
	ws.queuePool.put(q)
}

func (ws *priorityWriteSchedulerRFC9218) AdjustStream(streamID uint32, priority PriorityParam) {
	metadata := ws.streams[streamID]
	q, u, i := metadata.location, metadata.priority.urgency, metadata.priority.incremental
	if q == nil {
		return
	}

	if q.next == q {
		ws.heads[u][i] = nil
	} else {
		q.prev.next = q.next
		q.next.prev = q.prev
		if ws.heads[u][i] == q {
			ws.heads[u][i] = q.next
		}
	}

	u, i = priority.urgency, priority.incremental
	if ws.heads[u][i] == nil {
		ws.heads[u][i] = q
		q.next = q
		q.prev = q
	} else {
		q.prev = ws.heads[u][i].prev
		q.next = ws.heads[u][i]
		q.prev.next = q
		q.next.prev = q
	}

	ws.streams[streamID] = streamMetadata{
		location: q,
		priority: priority,
	}
}

func (ws *priorityWriteSchedulerRFC9218) Push(wr FrameWriteRequest) {
	if wr.isControl() {
		ws.control.push(wr)
		return
	}
	q := ws.streams[wr.StreamID()].location
	if q == nil {
		if wr.DataSize() > 0 {
			panic("add DATA on non-open stream")
		}
		ws.control.push(wr)
		return
	}
	q.push(wr)
}

func (ws *priorityWriteSchedulerRFC9218) Pop() (FrameWriteRequest, bool) {
	if !ws.control.empty() {
		return ws.control.shift(), true
	}

	ws.prioritizeIncremental = !ws.prioritizeIncremental

	for u := range ws.heads {
		for i := range ws.heads[u] {
			if ws.prioritizeIncremental {
				i = (i + 1) % 2
			}
			q := ws.heads[u][i]
			if q == nil {
				continue
			}
			for {
				if wr, ok := q.consume(math.MaxInt32); ok {
					if i == 1 {
						ws.heads[u][i] = q.next
					} else {
						ws.heads[u][i] = q
					}
					return wr, true
				}
				q = q.next
				if q == ws.heads[u][i] {
					break
				}
			}

		}
	}
	return FrameWriteRequest{}, false
}

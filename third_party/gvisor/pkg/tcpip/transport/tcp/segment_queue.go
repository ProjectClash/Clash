// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

type segmentQueue struct {
	mu     segmentQueueMutex `state:"nosave"`
	list   segmentList       `state:"wait"`
	ep     *Endpoint
	frozen bool
}

func (q *segmentQueue) emptyLocked() bool {
	return q.list.Empty()
}

func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.emptyLocked()
}

func (q *segmentQueue) enqueue(s *segment) bool {
	bufSz := q.ep.ops.GetReceiveBufferSize()
	used := q.ep.receiveMemUsed()

	q.mu.Lock()
	defer q.mu.Unlock()

	allow := (used <= int(bufSz) || s.payloadSize() == 0) && !q.frozen

	if allow {
		s.IncRef()
		q.list.PushBack(s)
		s.setOwner(q.ep, recvQ)
	}

	return allow
}

func (q *segmentQueue) dequeue() *segment {
	q.mu.Lock()
	defer q.mu.Unlock()

	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
	}

	return s
}

func (q *segmentQueue) freeze() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.frozen = true
}

func (q *segmentQueue) thaw() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.frozen = false
}

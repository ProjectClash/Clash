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

package waiter

import (
	"github.com/metacubex/gvisor/pkg/sync"
)

type EventMask uint64

const (
	EventIn       EventMask = 0x01
	EventPri      EventMask = 0x02
	EventOut      EventMask = 0x04
	EventErr      EventMask = 0x08
	EventHUp      EventMask = 0x10
	EventRdNorm   EventMask = 0x0040
	EventWrNorm   EventMask = 0x0100
	EventInternal EventMask = 0x1000
	EventRdHUp    EventMask = 0x2000

	AllEvents      EventMask = 0x1f | EventRdNorm | EventWrNorm | EventRdHUp
	ReadableEvents EventMask = EventIn | EventRdNorm
	WritableEvents EventMask = EventOut | EventWrNorm
)

func EventMaskFromLinux(e uint32) EventMask {
	return EventMask(e) & AllEvents
}

func (e EventMask) ToLinux() uint32 {
	return uint32(e)
}

type Waitable interface {
	Readiness(mask EventMask) EventMask

	EventRegister(e *Entry) error

	EventUnregister(e *Entry)
}

type EventListener interface {
	NotifyEvent(mask EventMask)
}

type Entry struct {
	waiterEntry

	eventListener EventListener

	mask EventMask
}

func (e *Entry) Init(eventListener EventListener, mask EventMask) {
	e.eventListener = eventListener
	e.mask = mask
}

func (e *Entry) SetQueuedMask(q *Queue, mask EventMask) {
	q.mu.Lock()
	e.mask = mask
	q.mu.Unlock()
}

func (e *Entry) Mask() EventMask {
	return e.mask
}

func (e *Entry) NotifyEvent(mask EventMask) {
	if m := mask & e.mask; m != 0 {
		e.eventListener.NotifyEvent(m)
	}
}

type ChannelNotifier chan struct{}

func (c ChannelNotifier) NotifyEvent(EventMask) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func NewChannelEntry(mask EventMask) (e Entry, ch chan struct{}) {
	ch = make(chan struct{}, 1)
	e.Init(ChannelNotifier(ch), mask)
	return e, ch
}

type functionNotifier func(EventMask)

func (f functionNotifier) NotifyEvent(mask EventMask) {
	f(mask)
}

func NewFunctionEntry(mask EventMask, fn func(EventMask)) (e Entry) {
	e.Init(functionNotifier(fn), mask)
	return e
}

type NoopListener struct{}

func (NoopListener) NotifyEvent(mask EventMask) {}

type Queue struct {
	list waiterList
	mu   sync.RWMutex `state:"nosave"`
}

func (q *Queue) EventRegister(e *Entry) {
	q.mu.Lock()
	q.list.PushBack(e)
	q.mu.Unlock()
}

func (q *Queue) EventUnregister(e *Entry) {
	q.mu.Lock()
	q.list.Remove(e)
	q.mu.Unlock()
}

func (q *Queue) Notify(mask EventMask) {
	q.mu.RLock()
	for e := q.list.Front(); e != nil; e = e.Next() {
		m := mask & e.mask
		if m == 0 {
			continue
		}
		e.eventListener.NotifyEvent(m)
	}
	q.mu.RUnlock()
}

func (q *Queue) Events() EventMask {
	q.mu.RLock()
	defer q.mu.RUnlock()
	ret := EventMask(0)
	for e := q.list.Front(); e != nil; e = e.Next() {
		ret |= e.mask
	}
	return ret
}

func (q *Queue) IsEmpty() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.list.Front() == nil
}

type NeverReady struct {
}

func (*NeverReady) Readiness(EventMask) EventMask {
	return 0
}

func (*NeverReady) EventRegister(*Entry) error {
	return nil
}

func (*NeverReady) EventUnregister(*Entry) {
}

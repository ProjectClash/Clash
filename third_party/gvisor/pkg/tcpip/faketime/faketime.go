// Copyright 2020 The gVisor Authors.
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

package faketime

import (
	"container/heap"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

type NullClock struct{}

var _ tcpip.Clock = (*NullClock)(nil)

func (*NullClock) Now() time.Time {
	return time.Time{}
}

func (*NullClock) NowMonotonic() tcpip.MonotonicTime {
	return tcpip.MonotonicTime{}
}

type nullTimer struct{}

var _ tcpip.Timer = (*nullTimer)(nil)

func (*nullTimer) Stop() bool {
	return true
}

func (*nullTimer) Reset(time.Duration) {}

func (*NullClock) AfterFunc(time.Duration, func()) tcpip.Timer {
	return &nullTimer{}
}

type notificationChannels struct {
	mu struct {
		sync.Mutex

		ch []<-chan struct{}
	}
}

func (n *notificationChannels) add(ch <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mu.ch = append(n.mu.ch, ch)
}

func (n *notificationChannels) wait() {
	for {
		n.mu.Lock()
		ch := n.mu.ch
		n.mu.ch = nil
		n.mu.Unlock()

		if len(ch) == 0 {
			break
		}

		for _, c := range ch {
			<-c
		}
	}
}

type manualClockMutex struct {
	sync.RWMutex

	now time.Time

	times timeHeap

	timers map[time.Time]map[*manualTimer]struct{}
}

type ManualClock struct {
	runningTimers notificationChannels

	mu manualClockMutex
}

func NewManualClock() *ManualClock {
	c := &ManualClock{}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.mu.now = time.Unix(0, 0)
	c.mu.timers = make(map[time.Time]map[*manualTimer]struct{})

	return c
}

var _ tcpip.Clock = (*ManualClock)(nil)

func (mc *ManualClock) Now() time.Time {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.mu.now
}

func (mc *ManualClock) NowMonotonic() tcpip.MonotonicTime {
	var mt tcpip.MonotonicTime
	return mt.Add(mc.Now().Sub(time.Unix(0, 0)))
}

func (mc *ManualClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	mt := &manualTimer{
		clock: mc,
		f:     f,
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	mc.resetTimerLocked(mt, d)
	return mt
}

func (mc *ManualClock) resetTimerLocked(mt *manualTimer, d time.Duration) {
	if !mt.mu.firesAt.IsZero() {
		panic("tried to reset an active timer")
	}

	t := mc.mu.now.Add(d)

	if !mc.mu.now.Before(t) {
		ch := make(chan struct{})
		mc.runningTimers.add(ch)

		go func() {
			defer close(ch)

			mt.f()
		}()

		return
	}

	mt.mu.firesAt = t

	timers, ok := mc.mu.timers[t]
	if !ok {
		timers = make(map[*manualTimer]struct{})
		mc.mu.timers[t] = timers
		heap.Push(&mc.mu.times, t)
	}

	timers[mt] = struct{}{}
}

func (mc *ManualClock) stopTimerLocked(mt *manualTimer) {
	t := mt.mu.firesAt
	mt.mu.firesAt = time.Time{}

	if t.IsZero() {
		panic("tried to stop an inactive timer")
	}

	timers, ok := mc.mu.timers[t]
	if !ok {
		err := fmt.Sprintf("tried to stop an active timer but the clock does not have anything scheduled for the timer @ t = %s %p\nScheduled timers @:", t.UTC(), mt)
		for t := range mc.mu.timers {
			err += fmt.Sprintf("%s\n", t.UTC())
		}
		panic(err)
	}

	if _, ok := timers[mt]; !ok {
		panic(fmt.Sprintf("did not have an entry in timers for an active timer @ t = %s", t.UTC()))
	}

	delete(timers, mt)

	if len(timers) == 0 {
		delete(mc.mu.timers, t)
	}
}

func (mc *ManualClock) RunImmediatelyScheduledJobs() {
	mc.Advance(0)
}

func (mc *ManualClock) Advance(d time.Duration) {
	mc.runningTimers.wait()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	until := mc.mu.now.Add(d)
	for mc.mu.times.Len() > 0 {
		t := heap.Pop(&mc.mu.times).(time.Time)
		if t.After(until) {
			heap.Push(&mc.mu.times, t)
			break
		}

		timers := mc.mu.timers[t]
		delete(mc.mu.timers, t)

		mc.mu.now = t

		for mt := range timers {
			mt.mu.Lock()
			mt.mu.firesAt = time.Time{}
			mt.mu.Unlock()
		}

		mc.mu.Unlock()

		for mt := range timers {
			mt.f()
		}

		mc.runningTimers.wait()
		mc.mu.Lock()
	}

	mc.mu.now = until
}

func (mc *ManualClock) resetTimer(mt *manualTimer, d time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	if !mt.mu.firesAt.IsZero() {
		mc.stopTimerLocked(mt)
	}

	mc.resetTimerLocked(mt, d)
}

func (mc *ManualClock) stopTimer(mt *manualTimer) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	if mt.mu.firesAt.IsZero() {
		return false
	}

	mc.stopTimerLocked(mt)
	return true
}

type manualTimerMu struct {
	sync.Mutex

	firesAt time.Time
}

type manualTimer struct {
	clock *ManualClock
	f     func()
	mu    manualTimerMu
}

var _ tcpip.Timer = (*manualTimer)(nil)

func (mt *manualTimer) Reset(d time.Duration) {
	mt.clock.resetTimer(mt, d)
}

func (mt *manualTimer) Stop() bool {
	return mt.clock.stopTimer(mt)
}

type timeHeap []time.Time

var _ heap.Interface = (*timeHeap)(nil)

func (h timeHeap) Len() int {
	return len(h)
}

func (h timeHeap) Less(i, j int) bool {
	return h[i].Before(h[j])
}

func (h timeHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *timeHeap) Push(x any) {
	*h = append(*h, x.(time.Time))
}

func (h *timeHeap) Pop() any {
	last := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return last
}

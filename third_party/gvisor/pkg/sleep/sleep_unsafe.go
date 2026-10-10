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

package sleep

import (
	"context"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/sync"
)

const (
	preparingG = 1
)

var (
	assertedSleeper Sleeper
)

type Sleeper struct {
	_ sync.NoCopy

	sharedList unsafe.Pointer `state:".(*Waker)"`

	localList *Waker

	allWakers *Waker

	waitingG uintptr `state:"zero"`
}

func (s *Sleeper) saveSharedList() *Waker {
	return (*Waker)(atomic.LoadPointer(&s.sharedList))
}

func (s *Sleeper) loadSharedList(_ context.Context, w *Waker) {
	atomic.StorePointer(&s.sharedList, unsafe.Pointer(w))
}

func (s *Sleeper) AddWaker(w *Waker) {
	if w.allWakersNext != nil {
		panic("waker has non-nil allWakersNext; owned by another sleeper?")
	}
	if w.next != nil {
		panic("waker has non-nil next; queued in another sleeper?")
	}

	w.allWakersNext = s.allWakers
	s.allWakers = w

	for {
		p := (*Sleeper)(atomic.LoadPointer(&w.s))
		if p == &assertedSleeper {
			s.enqueueAssertedWaker(w, true)
			return
		}

		if atomic.CompareAndSwapPointer(&w.s, usleeper(p), usleeper(s)) {
			return
		}
	}
}

// nextWaker returns the next waker in the notification list, blocking if
// needed. The parameter wakepOrSleep indicates that if the operation does not
// block, then we will need to explicitly wake a runtime P.
//
// Precondition: wakepOrSleep may be true iff block is true.
//
//go:nosplit
func (s *Sleeper) nextWaker(block, wakepOrSleep bool) *Waker {
	if s.localList == nil {
		for atomic.LoadPointer(&s.sharedList) == nil {
			if !block {
				return nil
			}

			atomic.StoreUintptr(&s.waitingG, preparingG)

			if atomic.LoadPointer(&s.sharedList) != nil {
				atomic.StoreUintptr(&s.waitingG, 0)
				break
			}

			wakepOrSleep = false

			const traceEvGoBlockSelect = 24
			const waitReasonSelect = 9
			sync.Gopark(commitSleep, unsafe.Pointer(&s.waitingG), sync.WaitReasonSelect, sync.TraceBlockSelect, 0)
		}

		v := (*Waker)(atomic.SwapPointer(&s.sharedList, nil))
		for v != nil {
			cur := v
			v = v.next

			cur.next = s.localList
			s.localList = cur
		}
	}

	w := s.localList
	s.localList = w.next

	if wakepOrSleep {
		sync.Wakep()
	}

	return w
}

// commitSleep signals to wakers that the given g is now sleeping. Wakers can
// then fetch it and wake it.
//
// The commit may fail if wakers have been asserted after our last check, in
// which case they will have set s.waitingG to zero.
//
//go:norace
//go:nosplit
func commitSleep(g uintptr, waitingG unsafe.Pointer) bool {
	return sync.RaceUncheckedAtomicCompareAndSwapUintptr((*uintptr)(waitingG), preparingG, g)
}

// fetch is the backing implementation for Fetch and AssertAndFetch.
//
// Preconditions are the same as nextWaker.
//
//go:nosplit
func (s *Sleeper) fetch(block, wakepOrSleep bool) *Waker {
	for {
		w := s.nextWaker(block, wakepOrSleep)
		if w == nil {
			return nil
		}

		old := (*Sleeper)(atomic.SwapPointer(&w.s, usleeper(s)))
		if old == &assertedSleeper {
			return w
		}
	}
}

func (s *Sleeper) Fetch(block bool) *Waker {
	return s.fetch(block, false)
}

// AssertAndFetch asserts the given waker and fetches the next wake-up notification.
// Note that this will always be blocking, since there is no value in joining a
// non-blocking operation.
//
// N.B. Like Fetch, this method is *not* thread-safe. This will also yield the current
// P to the next goroutine, avoiding associated scheduled overhead.
//
// +checkescape:all
//
//go:nosplit
func (s *Sleeper) AssertAndFetch(n *Waker) *Waker {
	n.assert(false)
	return s.fetch(true, true)
}

func (s *Sleeper) Done() {
	for w := s.allWakers; w != nil; w = s.allWakers {
		next := w.allWakersNext
		if atomic.CompareAndSwapPointer(&w.s, usleeper(s), nil) {
			w.allWakersNext = nil
			w.next = nil
			s.allWakers = next
			continue
		}

		if w := s.nextWaker(true, false); w != nil {
			prev := &s.allWakers
			for *prev != w {
				prev = &((*prev).allWakersNext)
			}
			*prev = (*prev).allWakersNext
			w.allWakersNext = nil
			w.next = nil
		}
	}
}

// enqueueAssertedWaker enqueues an asserted waker to the "ready" circular list
// of wakers that want to notify the sleeper.
//
//go:nosplit
func (s *Sleeper) enqueueAssertedWaker(w *Waker, wakep bool) {
	for {
		v := (*Waker)(atomic.LoadPointer(&s.sharedList))
		w.next = v
		if atomic.CompareAndSwapPointer(&s.sharedList, uwaker(v), uwaker(w)) {
			break
		}
	}

	if atomic.LoadUintptr(&s.waitingG) == 0 {
		return
	}

	switch g := atomic.SwapUintptr(&s.waitingG, 0); g {
	case 0, preparingG:
	default:
		sync.Goready(g, 0, wakep)
	}
}

type Waker struct {
	_ sync.NoCopy

	s unsafe.Pointer `state:".(wakerState)"`

	next *Waker

	allWakersNext *Waker
}

type wakerState struct {
	asserted bool
	other    *Sleeper
}

func (w *Waker) saveS() wakerState {
	s := (*Sleeper)(atomic.LoadPointer(&w.s))
	if s == &assertedSleeper {
		return wakerState{asserted: true}
	}
	return wakerState{other: s}
}

func (w *Waker) loadS(_ context.Context, ws wakerState) {
	if ws.asserted {
		atomic.StorePointer(&w.s, unsafe.Pointer(&assertedSleeper))
	} else {
		atomic.StorePointer(&w.s, unsafe.Pointer(ws.other))
	}
}

// assert is the implementation for Assert.
//
//go:nosplit
func (w *Waker) assert(wakep bool) {
	if atomic.LoadPointer(&w.s) == usleeper(&assertedSleeper) {
		return
	}

	switch s := (*Sleeper)(atomic.SwapPointer(&w.s, usleeper(&assertedSleeper))); s {
	case nil:
	case &assertedSleeper:
	default:
		s.enqueueAssertedWaker(w, wakep)
	}
}

func (w *Waker) Assert() {
	w.assert(true)
}

func (w *Waker) Clear() bool {
	if atomic.LoadPointer(&w.s) != usleeper(&assertedSleeper) {
		return false
	}

	return atomic.CompareAndSwapPointer(&w.s, usleeper(&assertedSleeper), nil)
}

func (w *Waker) IsAsserted() bool {
	return (*Sleeper)(atomic.LoadPointer(&w.s)) == &assertedSleeper
}

func usleeper(s *Sleeper) unsafe.Pointer {
	return unsafe.Pointer(s)
}

func uwaker(w *Waker) unsafe.Pointer {
	return unsafe.Pointer(w)
}

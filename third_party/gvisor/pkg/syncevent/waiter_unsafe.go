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

package syncevent

import (
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/sync"
)

type Waiter struct {
	r Receiver

	g uintptr `state:"zerovalue"`
}

const preparingG = 1

func (w *Waiter) Init() {
	w.r.Init(w)
}

func (w *Waiter) Receiver() *Receiver {
	return &w.r
}

func (w *Waiter) Pending() Set {
	return w.r.Pending()
}

func (w *Waiter) Wait() Set {
	return w.WaitFor(AllEvents)
}

func (w *Waiter) WaitFor(es Set) Set {
	for {
		if p := w.r.Pending(); p&es != NoEvents {
			return p
		}

		atomic.StoreUintptr(&w.g, preparingG)

		if p := w.r.Pending(); p&es != NoEvents {
			atomic.StoreUintptr(&w.g, 0)
			return p
		}

		sync.Gopark(waiterCommit, unsafe.Pointer(&w.g), sync.WaitReasonSelect, sync.TraceBlockSelect, 0)
	}
}

//go:norace
//go:nosplit
func waiterCommit(g uintptr, wg unsafe.Pointer) bool {
	return sync.RaceUncheckedAtomicCompareAndSwapUintptr((*uintptr)(wg), preparingG, g)
}

func (w *Waiter) Ack(es Set) {
	w.r.Ack(es)
}

func (w *Waiter) WaitAndAckAll() Set {
	if w.r.Pending() != NoEvents {
		if p := w.r.PendingAndAckAll(); p != NoEvents {
			return p
		}
	}

	for {
		atomic.StoreUintptr(&w.g, preparingG)

		if w.r.Pending() != NoEvents {
			if p := w.r.PendingAndAckAll(); p != NoEvents {
				atomic.StoreUintptr(&w.g, 0)
				return p
			}
		}

		sync.Gopark(waiterCommit, unsafe.Pointer(&w.g), sync.WaitReasonSelect, sync.TraceBlockSelect, 0)

		if p := w.r.PendingAndAckAll(); p != NoEvents {
			return p
		}
	}
}

func (w *Waiter) Notify(es Set) {
	w.r.Notify(es)
}

func (w *Waiter) NotifyPending() {
	if atomic.LoadUintptr(&w.g) == 0 {
		return
	}
	if g := atomic.SwapUintptr(&w.g, 0); g > preparingG {
		sync.Goready(g, 0, true)
	}
}

var waiterPool = sync.Pool{
	New: func() any {
		w := &Waiter{}
		w.Init()
		return w
	},
}

func GetWaiter() *Waiter {
	return waiterPool.Get().(*Waiter)
}

func PutWaiter(w *Waiter) {
	waiterPool.Put(w)
}

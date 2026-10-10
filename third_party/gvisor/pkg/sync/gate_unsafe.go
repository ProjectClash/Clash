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

package sync

import (
	"fmt"
	"math"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/gohacks"
)

type Gate struct {
	userCount int32
	closingG  uintptr
}

const preparingG = 1

func (g *Gate) Enter() bool {
	if atomic.AddInt32(&g.userCount, 1) > 0 {
		return true
	}
	g.leaveAfterFailedEnter()
	return false
}

// leaveAfterFailedEnter is identical to Leave, but is marked noinline to
// prevent it from being inlined into Enter, since as of this writing inlining
// Leave into Enter prevents Enter from being inlined into its callers.
//
//go:noinline
func (g *Gate) leaveAfterFailedEnter() {
	if atomic.AddInt32(&g.userCount, -1) == math.MinInt32 {
		g.leaveClosed()
	}
}

func (g *Gate) Leave() {
	if atomic.AddInt32(&g.userCount, -1) == math.MinInt32 {
		g.leaveClosed()
	}
}

func (g *Gate) leaveClosed() {
	if atomic.LoadUintptr(&g.closingG) == 0 {
		return
	}
	if cG := atomic.SwapUintptr(&g.closingG, 0); cG > preparingG {
		goready(cG, 0)
	}
}

func (g *Gate) Close() {
	if atomic.LoadInt32(&g.userCount) == math.MinInt32 {
		return
	}
	if v := atomic.AddInt32(&g.userCount, math.MinInt32); v == math.MinInt32 {
		return
	} else if v >= 0 {
		panic("concurrent Close of sync.Gate")
	}

	if cG := atomic.SwapUintptr(&g.closingG, preparingG); cG != 0 {
		panic(fmt.Sprintf("invalid sync.Gate.closingG during Close: %#x", cG))
	}
	if atomic.LoadInt32(&g.userCount) == math.MinInt32 {
		return
	}
	gopark(gateCommit, gohacks.Noescape(unsafe.Pointer(&g.closingG)), WaitReasonSemacquire, TraceBlockSync, 0)
	RaceAcquire(unsafe.Pointer(&g.closingG))
}

//go:norace
//go:nosplit
func gateCommit(g uintptr, closingG unsafe.Pointer) bool {
	return RaceUncheckedAtomicCompareAndSwapUintptr((*uintptr)(closingG), preparingG, g)
}

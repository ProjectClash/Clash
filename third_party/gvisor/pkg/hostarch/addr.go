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

package hostarch

import (
	"fmt"
)

type Addr uintptr

func (v Addr) AddLength(length uint64) (end Addr, ok bool) {
	end = v + Addr(length)
	ok = end >= v && (addrAtLeast64b || length <= uint64(^Addr(0)))
	return
}

func (v Addr) RoundDown() Addr {
	return PageRoundDown(v)
}

func (v Addr) RoundUp() (Addr, bool) {
	return PageRoundUp(v)
}

func (v Addr) MustRoundUp() Addr {
	return MustPageRoundUp(v)
}

func (v Addr) HugeRoundDown() Addr {
	return HugePageRoundDown(v)
}

func (v Addr) HugeRoundUp() (Addr, bool) {
	return HugePageRoundUp(v)
}

func (v Addr) MustHugeRoundUp() Addr {
	return MustHugePageRoundUp(v)
}

func (v Addr) PageOffset() uint64 {
	return uint64(PageOffset(v))
}

func (v Addr) IsPageAligned() bool {
	return IsPageAligned(v)
}

func (v Addr) HugePageOffset() uint64 {
	return uint64(HugePageOffset(v))
}

func (v Addr) IsHugePageAligned() bool {
	return IsHugePageAligned(v)
}


func (v Addr) ToRange(length uint64) (AddrRange, bool) {
	end, ok := v.AddLength(length)
	return AddrRange{v, end}, ok
}

// MustToRange is equivalent to ToRange, but panics if the end of the range
// wraps around.
//
//go:nosplit
func (v Addr) MustToRange(length uint64) AddrRange {
	ar, ok := v.ToRange(length)
	if !ok {
		panic("hostarch.Addr.ToRange() wraps")
	}
	return ar
}

func (ar AddrRange) IsPageAligned() bool {
	return ar.Start.IsPageAligned() && ar.End.IsPageAligned()
}

func (ar AddrRange) IsHugePageAligned() bool {
	return ar.Start.IsHugePageAligned() && ar.End.IsHugePageAligned()
}

func (ar AddrRange) String() string {
	return fmt.Sprintf("[%#x, %#x)", ar.Start, ar.End)
}

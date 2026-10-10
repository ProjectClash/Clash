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
	"bytes"
	"fmt"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/gohacks"
)

type AddrRangeSeq struct {
	data   unsafe.Pointer
	length int
	offset Addr
	limit  Addr
}

func AddrRangeSeqOf(ar AddrRange) AddrRangeSeq {
	return AddrRangeSeq{
		length: 1,
		offset: ar.Start,
		limit:  ar.Length(),
	}
}

func AddrRangeSeqFromSlice(slice []AddrRange) AddrRangeSeq {
	var limit int64
	for _, ar := range slice {
		len64 := int64(ar.Length())
		if len64 < 0 {
			panic(fmt.Sprintf("Length of AddrRange %v overflows int64", ar))
		}
		sum := limit + len64
		if sum < limit {
			panic(fmt.Sprintf("Total length of AddrRanges %v overflows int64", slice))
		}
		limit = sum
	}
	return addrRangeSeqFromSliceLimited(slice, limit)
}

func addrRangeSeqFromSliceLimited(slice []AddrRange, limit int64) AddrRangeSeq {
	switch len(slice) {
	case 0:
		return AddrRangeSeq{}
	case 1:
		return AddrRangeSeq{
			length: 1,
			offset: slice[0].Start,
			limit:  Addr(limit),
		}
	default:
		return AddrRangeSeq{
			data:   unsafe.Pointer(&slice[0]),
			length: len(slice),
			limit:  Addr(limit),
		}
	}
}

func (ars AddrRangeSeq) IsEmpty() bool {
	return ars.length == 0
}

func (ars AddrRangeSeq) NumRanges() int {
	return ars.length
}

func (ars AddrRangeSeq) NumBytes() int64 {
	return int64(ars.limit)
}

func (ars AddrRangeSeq) Head() AddrRange {
	if ars.length == 0 {
		panic("empty AddrRangeSeq")
	}
	if ars.length == 1 {
		return AddrRange{ars.offset, ars.offset + ars.limit}
	}
	ar := *(*AddrRange)(ars.data)
	ar.Start += ars.offset
	if ar.Length() > ars.limit {
		ar.End = ar.Start + ars.limit
	}
	return ar
}

func (ars AddrRangeSeq) Tail() AddrRangeSeq {
	if ars.length == 0 {
		panic("empty AddrRangeSeq")
	}
	if ars.length == 1 {
		return AddrRangeSeq{}
	}
	return ars.externalTail()
}

func (ars AddrRangeSeq) externalTail() AddrRangeSeq {
	data := (*AddrRange)(ars.data)
	headLen := data.Length() - ars.offset
	var tailLimit int64
	if ars.limit > headLen {
		tailLimit = int64(ars.limit - headLen)
	}
	extSlice := gohacks.Slice(data, ars.length)
	return addrRangeSeqFromSliceLimited(extSlice[1:], tailLimit)
}

func (ars AddrRangeSeq) DropFirst(n int) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return ars.DropFirst64(int64(n))
}

func (ars AddrRangeSeq) DropFirst64(n int64) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	if Addr(n) > ars.limit {
		return AddrRangeSeq{}
	}
	switch ars.length {
	case 0:
		return AddrRangeSeq{}
	case 1:
		if ars.limit == 0 {
			return AddrRangeSeq{}
		}
	default:
		if rawHeadLen := (*AddrRange)(ars.data).Length(); ars.offset == rawHeadLen {
			ars = ars.externalTail()
		}
	}
	for n != 0 {
		var headLen Addr
		if ars.length == 1 {
			headLen = ars.limit
		} else {
			headLen = (*AddrRange)(ars.data).Length() - ars.offset
		}
		if Addr(n) < headLen {
			ars.offset += Addr(n)
			ars.limit -= Addr(n)
			return ars
		}
		n -= int64(headLen)
		ars = ars.Tail()
	}
	return ars
}

func (ars AddrRangeSeq) TakeFirst(n int) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	return ars.TakeFirst64(int64(n))
}

func (ars AddrRangeSeq) TakeFirst64(n int64) AddrRangeSeq {
	if n < 0 {
		panic(fmt.Sprintf("invalid n: %d", n))
	}
	if ars.limit > Addr(n) {
		ars.limit = Addr(n)
	}
	return ars
}

func (ars AddrRangeSeq) String() string {
	var buf bytes.Buffer
	buf.WriteByte('[')
	var sep string
	for !ars.IsEmpty() {
		buf.WriteString(sep)
		sep = " "
		buf.WriteString(ars.Head().String())
		ars = ars.Tail()
	}
	buf.WriteByte(']')
	return buf.String()
}

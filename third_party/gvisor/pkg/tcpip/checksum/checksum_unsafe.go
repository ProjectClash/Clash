// Copyright 2023 The gVisor Authors.
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

package checksum

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

func calculateChecksum(buf []byte, odd bool, initial uint16) (uint16, bool) {
	acc := uint64(initial)

	if odd {
		acc += uint64(buf[0])
		buf = buf[1:]
	}
	odd = len(buf)&1 != 0

	if len(buf) < 8 {
		if len(buf) >= 4 {
			acc += (uint64(buf[0]) << 8) + uint64(buf[1])
			acc += (uint64(buf[2]) << 8) + uint64(buf[3])
			buf = buf[4:]
		}
		if len(buf) >= 2 {
			acc += (uint64(buf[0]) << 8) + uint64(buf[1])
			buf = buf[2:]
		}
		if len(buf) >= 1 {
			acc += uint64(buf[0]) << 8
		}
		return reduce(acc), odd
	}

	acc = uint64(bswapIfLittleEndian32(uint32(acc)))

	bswapped := false
	if sliceAddr(buf)&1 != 0 {
		acc = uint64(bits.ReverseBytes32(uint32(acc)))
		bswapped = true
		acc += uint64(bswapIfLittleEndian16(uint16(buf[0])))
		buf = buf[1:]
	}
	if sliceAddr(buf)&2 != 0 {
		acc += uint64(*(*uint16)(unsafe.Pointer(&buf[0])))
		buf = buf[2:]
	}
	if sliceAddr(buf)&4 != 0 {
		acc += uint64(*(*uint32)(unsafe.Pointer(&buf[0])))
		buf = buf[4:]
	}

	for len(buf) >= 64 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[16])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[24])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[32])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[40])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[48])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[56])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[64:]
	}

	if len(buf) >= 32 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[16])), carry)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[24])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[32:]
	}
	if len(buf) >= 16 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[8])), carry)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[16:]
	}
	if len(buf) >= 8 {
		var carry uint64
		acc, carry = bits.Add64(acc, *(*uint64)(unsafe.Pointer(&buf[0])), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[8:]
	}
	if len(buf) >= 4 {
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(*(*uint32)(unsafe.Pointer(&buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[4:]
	}
	if len(buf) >= 2 {
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(*(*uint16)(unsafe.Pointer(&buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
		buf = buf[2:]
	}
	if len(buf) >= 1 {
		var carry uint64
		acc, carry = bits.Add64(acc, uint64(bswapIfBigEndian16(uint16(buf[0]))), 0)
		acc, _ = bits.Add64(acc, 0, carry)
	}

	acc16 := bswapIfLittleEndian16(reduce(acc))
	if bswapped {
		acc16 = bits.ReverseBytes16(acc16)
	}
	return acc16, odd
}

func reduce(acc uint64) uint16 {
	acc = (acc >> 32) + (acc & 0xffff_ffff)
	acc32 := uint32(acc>>32 + acc)
	acc32 = (acc32 >> 16) + (acc32 & 0xffff)
	return uint16(acc32>>16 + acc32)
}

func bswapIfLittleEndian32(val uint32) uint32 {
	return binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&val))[:])
}

func bswapIfLittleEndian16(val uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&val))[:])
}

func bswapIfBigEndian16(val uint16) uint16 {
	return binary.LittleEndian.Uint16((*[2]byte)(unsafe.Pointer(&val))[:])
}

func sliceAddr(buf []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
}

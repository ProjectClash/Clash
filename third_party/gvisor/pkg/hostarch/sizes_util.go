// Copyright 2022 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package hostarch

const (
	PageMask      = PageSize - 1
	HugePageMask  = HugePageSize - 1
	CacheLineMask = CacheLineSize - 1
	JumboPageMask = ^uintptr(JumboPageSize - 1)
)

type bytecount interface {
	~uint | ~uint32 | ~uint64 | ~uintptr
}

type hugebytecount interface {
	~uint | ~uint32 | ~uint64 | ~uintptr
}

func PageRoundDown[T bytecount](x T) T {
	return x &^ PageMask
}

func PageRoundUp[T bytecount](x T) (val T, ok bool) {
	val = PageRoundDown(x + PageMask)
	ok = val >= x
	return
}

func MustPageRoundUp[T bytecount](x T) T {
	val, ok := PageRoundUp(x)
	if !ok {
		panic("PageRoundUp overflows")
	}
	return val
}

func PageOffset[T bytecount](x T) T {
	return x & PageMask
}

func IsPageAligned[T bytecount](x T) bool {
	return PageOffset(x) == 0
}

func ToPagesRoundUp[T bytecount](x T) (T, bool) {
	y := x + PageMask
	if y < x {
		return x, false
	}
	return y / PageSize, true
}

func HugePageRoundDown[T hugebytecount](x T) T {
	return x &^ HugePageMask
}

func HugePageRoundUp[T hugebytecount](x T) (val T, ok bool) {
	val = HugePageRoundDown(x + HugePageMask)
	ok = val >= x
	return
}

func MustHugePageRoundUp[T hugebytecount](x T) T {
	val, ok := HugePageRoundUp(x)
	if !ok {
		panic("HugePageRoundUp overflows")
	}
	return val
}

func HugePageOffset[T hugebytecount](x T) T {
	return x & HugePageMask
}

func IsHugePageAligned[T hugebytecount](x T) bool {
	return HugePageOffset(x) == 0
}

func CacheLineRoundDown[T bytecount](x T) T {
	return x &^ CacheLineMask
}

func CacheLineRoundUp[T bytecount](x T) (val T, ok bool) {
	val = CacheLineRoundDown(x + CacheLineMask)
	ok = val >= x
	return
}

func MustCacheLineRoundUp[T bytecount](x T) T {
	val, ok := CacheLineRoundUp(x)
	if !ok {
		panic("CacheLineRoundUp overflows")
	}
	return val
}

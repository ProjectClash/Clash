// Copyright 2021 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package hostarch

import (
	"fmt"
	"unsafe"
)

func EndianString() string {
	value := uint32(0x01020304)
	bytes := *(*[4]byte)(unsafe.Pointer(&value))
	switch bytes {
	case [4]byte{0x01, 0x02, 0x03, 0x04}:
		return "big"
	case [4]byte{0x04, 0x03, 0x02, 0x01}:
		return "little"
	default:
		panic(fmt.Sprintf("unknown endianness: [01 02 03 04] => % x", bytes))
	}
}

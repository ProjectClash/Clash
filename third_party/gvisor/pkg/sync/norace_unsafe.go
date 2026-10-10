// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build !race
// +build !race

package sync

import (
	"sync/atomic"
	"unsafe"
)

const RaceEnabled = false

func RaceDisable() {
}

func RaceEnable() {
}

func RaceAcquire(addr unsafe.Pointer) {
}

func RaceRelease(addr unsafe.Pointer) {
}

func RaceReleaseMerge(addr unsafe.Pointer) {
}

func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool {
	return atomic.CompareAndSwapUintptr(ptr, old, new)
}

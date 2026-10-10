// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build race
// +build race

package sync

import (
	"runtime"
	"unsafe"
)

const RaceEnabled = true

func RaceDisable() {
	runtime.RaceDisable()
}

func RaceEnable() {
	runtime.RaceEnable()
}

func RaceAcquire(addr unsafe.Pointer) {
	runtime.RaceAcquire(addr)
}

func RaceRelease(addr unsafe.Pointer) {
	runtime.RaceRelease(addr)
}

func RaceReleaseMerge(addr unsafe.Pointer) {
	runtime.RaceReleaseMerge(addr)
}

func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool

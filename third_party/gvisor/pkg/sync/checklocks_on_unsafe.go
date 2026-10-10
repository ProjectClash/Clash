// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build checklocks
// +build checklocks

package sync

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/goid"
)

type gLocks struct {
	locksHeld []unsafe.Pointer
}

var locksHeld sync.Map

func getGLocks() *gLocks {
	id := goid.Get()

	var locks *gLocks
	if l, ok := locksHeld.Load(id); ok {
		locks = l.(*gLocks)
	} else {
		locks = &gLocks{
			locksHeld: make([]unsafe.Pointer, 0, 8),
		}
		locksHeld.Store(id, locks)
	}

	return locks
}

func noteLock(l unsafe.Pointer) {
	locks := getGLocks()

	for _, lock := range locks.locksHeld {
		if lock == l {
			panic(fmt.Sprintf("Deadlock on goroutine %d! Double lock of %p: %+v", goid.Get(), l, locks))
		}
	}

	locks.locksHeld = append(locks.locksHeld, l)
}

func noteUnlock(l unsafe.Pointer) {
	locks := getGLocks()

	if len(locks.locksHeld) == 0 {
		panic(fmt.Sprintf("Unlock of %p on goroutine %d without any locks held! All locks:\n%s", l, goid.Get(), dumpLocks()))
	}

	length := len(locks.locksHeld)
	for i := length - 1; i >= 0; i-- {
		if l == locks.locksHeld[i] {
			copy(locks.locksHeld[i:length-1], locks.locksHeld[i+1:length])
			locks.locksHeld[length-1] = nil
			locks.locksHeld = locks.locksHeld[:length-1]
			return
		}
	}

	panic(fmt.Sprintf("Unlock of %p on goroutine %d without matching lock! All locks:\n%s", l, goid.Get(), dumpLocks()))
}

func dumpLocks() string {
	var s strings.Builder
	locksHeld.Range(func(key, value any) bool {
		goid := key.(int64)
		locks := value.(*gLocks)


		fmt.Fprintf(&s, "goroutine %d:\n", goid)
		if len(locks.locksHeld) == 0 {
			fmt.Fprintf(&s, "\t<none>\n")
		}
		for _, lock := range locks.locksHeld {
			fmt.Fprintf(&s, "\t%p\n", lock)
		}
		fmt.Fprintf(&s, "\n")

		return true
	})

	return s.String()
}

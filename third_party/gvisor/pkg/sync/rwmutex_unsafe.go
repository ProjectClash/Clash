// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.


package sync

import (
	"sync/atomic"
	"unsafe"
)

type CrossGoroutineRWMutex struct {
	w           CrossGoroutineMutex
	writerSem   uint32
	readerSem   uint32
	readerCount int32
	readerWait  int32
}

const rwmutexMaxReaders = 1 << 30

func (rw *CrossGoroutineRWMutex) TryRLock() bool {
	if RaceEnabled {
		RaceDisable()
	}
	for {
		rc := atomic.LoadInt32(&rw.readerCount)
		if rc < 0 {
			if RaceEnabled {
				RaceEnable()
			}
			return false
		}
		if !atomic.CompareAndSwapInt32(&rw.readerCount, rc, rc+1) {
			continue
		}
		if RaceEnabled {
			RaceEnable()
			RaceAcquire(unsafe.Pointer(&rw.readerSem))
		}
		return true
	}
}

func (rw *CrossGoroutineRWMutex) RLock() {
	if RaceEnabled {
		RaceDisable()
	}
	if atomic.AddInt32(&rw.readerCount, 1) < 0 {
		semacquire(&rw.readerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.readerSem))
	}
}

func (rw *CrossGoroutineRWMutex) RUnlock() {
	if RaceEnabled {
		RaceReleaseMerge(unsafe.Pointer(&rw.writerSem))
		RaceDisable()
	}
	if r := atomic.AddInt32(&rw.readerCount, -1); r < 0 {
		if r+1 == 0 || r+1 == -rwmutexMaxReaders {
			panic("RUnlock of unlocked RWMutex")
		}
		if atomic.AddInt32(&rw.readerWait, -1) == 0 {
			semrelease(&rw.writerSem, false, 0)
		}
	}
	if RaceEnabled {
		RaceEnable()
	}
}

func (rw *CrossGoroutineRWMutex) TryLock() bool {
	if RaceEnabled {
		RaceDisable()
	}
	if !rw.w.TryLock() {
		if RaceEnabled {
			RaceEnable()
		}
		return false
	}
	if !atomic.CompareAndSwapInt32(&rw.readerCount, 0, -rwmutexMaxReaders) {
		rw.w.Unlock()
		if RaceEnabled {
			RaceEnable()
		}
		return false
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.writerSem))
	}
	return true
}

func (rw *CrossGoroutineRWMutex) Lock() {
	if RaceEnabled {
		RaceDisable()
	}
	rw.w.Lock()
	r := atomic.AddInt32(&rw.readerCount, -rwmutexMaxReaders) + rwmutexMaxReaders
	if r != 0 && atomic.AddInt32(&rw.readerWait, r) != 0 {
		semacquire(&rw.writerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.writerSem))
	}
}

func (rw *CrossGoroutineRWMutex) Unlock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.writerSem))
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders)
	if r >= rwmutexMaxReaders {
		panic("Unlock of unlocked RWMutex")
	}
	for i := 0; i < int(r); i++ {
		semrelease(&rw.readerSem, false, 0)
	}
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}

func (rw *CrossGoroutineRWMutex) DowngradeLock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders+1)
	if r >= rwmutexMaxReaders+1 {
		panic("DowngradeLock of unlocked RWMutex")
	}
	for i := 1; i < int(r); i++ {
		semrelease(&rw.readerSem, false, 0)
	}
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}

type RWMutex struct {
	m CrossGoroutineRWMutex
}

func (rw *RWMutex) TryRLock() bool {
	noteLock(unsafe.Pointer(rw))
	locked := rw.m.TryRLock()
	if !locked {
		noteUnlock(unsafe.Pointer(rw))
	}
	return locked
}

func (rw *RWMutex) RLock() {
	noteLock(unsafe.Pointer(rw))
	rw.m.RLock()
}

func (rw *RWMutex) RUnlock() {
	rw.m.RUnlock()
	noteUnlock(unsafe.Pointer(rw))
}

func (rw *RWMutex) TryLock() bool {
	noteLock(unsafe.Pointer(rw))
	locked := rw.m.TryLock()
	if !locked {
		noteUnlock(unsafe.Pointer(rw))
	}
	return locked
}

func (rw *RWMutex) Lock() {
	noteLock(unsafe.Pointer(rw))
	rw.m.Lock()
}

func (rw *RWMutex) Unlock() {
	rw.m.Unlock()
	noteUnlock(unsafe.Pointer(rw))
}

func (rw *RWMutex) DowngradeLock() {
	rw.m.DowngradeLock()
}

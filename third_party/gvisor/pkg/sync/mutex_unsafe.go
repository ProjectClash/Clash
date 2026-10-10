// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package sync

import (
	"sync"
	"unsafe"
)

type CrossGoroutineMutex struct {
	m sync.Mutex
}

func (m *CrossGoroutineMutex) Lock() {
	m.m.Lock()
}

func (m *CrossGoroutineMutex) Unlock() {
	m.m.Unlock()
}

func (m *CrossGoroutineMutex) TryLock() bool {
	return m.m.TryLock()
}

type Mutex struct {
	m CrossGoroutineMutex
}

func (m *Mutex) Lock() {
	noteLock(unsafe.Pointer(m))
	m.m.Lock()
}

func (m *Mutex) Unlock() {
	noteUnlock(unsafe.Pointer(m))
	m.m.Unlock()
}

func (m *Mutex) TryLock() bool {
	noteLock(unsafe.Pointer(m))
	locked := m.m.TryLock()
	if !locked {
		noteUnlock(unsafe.Pointer(m))
	}
	return locked
}

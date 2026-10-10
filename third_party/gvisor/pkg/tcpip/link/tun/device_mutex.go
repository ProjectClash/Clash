package tun

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type deviceRWMutex struct {
	mu sync.RWMutex
}

var devicelockNames []string

type devicelockNameIndex int

const ()

func (m *deviceRWMutex) Lock() {
	locking.AddGLock(deviceprefixIndex, -1)
	m.mu.Lock()
}

func (m *deviceRWMutex) NestedLock(i devicelockNameIndex) {
	locking.AddGLock(deviceprefixIndex, int(i))
	m.mu.Lock()
}

func (m *deviceRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(deviceprefixIndex, -1)
}

func (m *deviceRWMutex) NestedUnlock(i devicelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(deviceprefixIndex, int(i))
}

func (m *deviceRWMutex) RLock() {
	locking.AddGLock(deviceprefixIndex, -1)
	m.mu.RLock()
}

func (m *deviceRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(deviceprefixIndex, -1)
}

func (m *deviceRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *deviceRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *deviceRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var deviceprefixIndex *locking.MutexClass

func deviceinitLockNames() {}

func init() {
	deviceinitLockNames()
	deviceprefixIndex = locking.NewMutexClass(reflect.TypeOf((*deviceRWMutex)(nil)).Elem(), devicelockNames)
}

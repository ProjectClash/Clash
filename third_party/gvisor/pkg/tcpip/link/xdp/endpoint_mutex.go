package xdp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type endpointRWMutex struct {
	mu sync.RWMutex
}

var endpointlockNames []string

type endpointlockNameIndex int

const ()

func (m *endpointRWMutex) Lock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.Lock()
}

func (m *endpointRWMutex) NestedLock(i endpointlockNameIndex) {
	locking.AddGLock(endpointprefixIndex, int(i))
	m.mu.Lock()
}

func (m *endpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(endpointprefixIndex, -1)
}

func (m *endpointRWMutex) NestedUnlock(i endpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(endpointprefixIndex, int(i))
}

func (m *endpointRWMutex) RLock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.RLock()
}

func (m *endpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(endpointprefixIndex, -1)
}

func (m *endpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *endpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *endpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var endpointprefixIndex *locking.MutexClass

func endpointinitLockNames() {}

func init() {
	endpointinitLockNames()
	endpointprefixIndex = locking.NewMutexClass(reflect.TypeOf((*endpointRWMutex)(nil)).Elem(), endpointlockNames)
}

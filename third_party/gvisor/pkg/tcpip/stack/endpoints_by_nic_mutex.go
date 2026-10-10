package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type endpointsByNICRWMutex struct {
	mu sync.RWMutex
}

var endpointsByNIClockNames []string

type endpointsByNIClockNameIndex int

const ()

func (m *endpointsByNICRWMutex) Lock() {
	locking.AddGLock(endpointsByNICprefixIndex, -1)
	m.mu.Lock()
}

func (m *endpointsByNICRWMutex) NestedLock(i endpointsByNIClockNameIndex) {
	locking.AddGLock(endpointsByNICprefixIndex, int(i))
	m.mu.Lock()
}

func (m *endpointsByNICRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(endpointsByNICprefixIndex, -1)
}

func (m *endpointsByNICRWMutex) NestedUnlock(i endpointsByNIClockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(endpointsByNICprefixIndex, int(i))
}

func (m *endpointsByNICRWMutex) RLock() {
	locking.AddGLock(endpointsByNICprefixIndex, -1)
	m.mu.RLock()
}

func (m *endpointsByNICRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(endpointsByNICprefixIndex, -1)
}

func (m *endpointsByNICRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *endpointsByNICRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *endpointsByNICRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var endpointsByNICprefixIndex *locking.MutexClass

func endpointsByNICinitLockNames() {}

func init() {
	endpointsByNICinitLockNames()
	endpointsByNICprefixIndex = locking.NewMutexClass(reflect.TypeOf((*endpointsByNICRWMutex)(nil)).Elem(), endpointsByNIClockNames)
}

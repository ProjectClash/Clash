package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type addressStateRWMutex struct {
	mu sync.RWMutex
}

var addressStatelockNames []string

type addressStatelockNameIndex int

const ()

func (m *addressStateRWMutex) Lock() {
	locking.AddGLock(addressStateprefixIndex, -1)
	m.mu.Lock()
}

func (m *addressStateRWMutex) NestedLock(i addressStatelockNameIndex) {
	locking.AddGLock(addressStateprefixIndex, int(i))
	m.mu.Lock()
}

func (m *addressStateRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(addressStateprefixIndex, -1)
}

func (m *addressStateRWMutex) NestedUnlock(i addressStatelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(addressStateprefixIndex, int(i))
}

func (m *addressStateRWMutex) RLock() {
	locking.AddGLock(addressStateprefixIndex, -1)
	m.mu.RLock()
}

func (m *addressStateRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(addressStateprefixIndex, -1)
}

func (m *addressStateRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *addressStateRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *addressStateRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var addressStateprefixIndex *locking.MutexClass

func addressStateinitLockNames() {}

func init() {
	addressStateinitLockNames()
	addressStateprefixIndex = locking.NewMutexClass(reflect.TypeOf((*addressStateRWMutex)(nil)).Elem(), addressStatelockNames)
}

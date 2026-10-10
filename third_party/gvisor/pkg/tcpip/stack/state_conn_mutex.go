package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type stateConnRWMutex struct {
	mu sync.RWMutex
}

var stateConnlockNames []string

type stateConnlockNameIndex int

const ()

func (m *stateConnRWMutex) Lock() {
	locking.AddGLock(stateConnprefixIndex, -1)
	m.mu.Lock()
}

func (m *stateConnRWMutex) NestedLock(i stateConnlockNameIndex) {
	locking.AddGLock(stateConnprefixIndex, int(i))
	m.mu.Lock()
}

func (m *stateConnRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(stateConnprefixIndex, -1)
}

func (m *stateConnRWMutex) NestedUnlock(i stateConnlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(stateConnprefixIndex, int(i))
}

func (m *stateConnRWMutex) RLock() {
	locking.AddGLock(stateConnprefixIndex, -1)
	m.mu.RLock()
}

func (m *stateConnRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(stateConnprefixIndex, -1)
}

func (m *stateConnRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *stateConnRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *stateConnRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var stateConnprefixIndex *locking.MutexClass

func stateConninitLockNames() {}

func init() {
	stateConninitLockNames()
	stateConnprefixIndex = locking.NewMutexClass(reflect.TypeOf((*stateConnRWMutex)(nil)).Elem(), stateConnlockNames)
}

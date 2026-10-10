package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type stackRWMutex struct {
	mu sync.RWMutex
}

var stacklockNames []string

type stacklockNameIndex int

const ()

func (m *stackRWMutex) Lock() {
	locking.AddGLock(stackprefixIndex, -1)
	m.mu.Lock()
}

func (m *stackRWMutex) NestedLock(i stacklockNameIndex) {
	locking.AddGLock(stackprefixIndex, int(i))
	m.mu.Lock()
}

func (m *stackRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(stackprefixIndex, -1)
}

func (m *stackRWMutex) NestedUnlock(i stacklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(stackprefixIndex, int(i))
}

func (m *stackRWMutex) RLock() {
	locking.AddGLock(stackprefixIndex, -1)
	m.mu.RLock()
}

func (m *stackRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(stackprefixIndex, -1)
}

func (m *stackRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *stackRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *stackRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var stackprefixIndex *locking.MutexClass

func stackinitLockNames() {}

func init() {
	stackinitLockNames()
	stackprefixIndex = locking.NewMutexClass(reflect.TypeOf((*stackRWMutex)(nil)).Elem(), stacklockNames)
}

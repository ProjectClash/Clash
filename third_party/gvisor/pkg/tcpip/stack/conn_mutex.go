package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type connRWMutex struct {
	mu sync.RWMutex
}

var connlockNames []string

type connlockNameIndex int

const ()

func (m *connRWMutex) Lock() {
	locking.AddGLock(connprefixIndex, -1)
	m.mu.Lock()
}

func (m *connRWMutex) NestedLock(i connlockNameIndex) {
	locking.AddGLock(connprefixIndex, int(i))
	m.mu.Lock()
}

func (m *connRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(connprefixIndex, -1)
}

func (m *connRWMutex) NestedUnlock(i connlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(connprefixIndex, int(i))
}

func (m *connRWMutex) RLock() {
	locking.AddGLock(connprefixIndex, -1)
	m.mu.RLock()
}

func (m *connRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(connprefixIndex, -1)
}

func (m *connRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *connRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *connRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var connprefixIndex *locking.MutexClass

func conninitLockNames() {}

func init() {
	conninitLockNames()
	connprefixIndex = locking.NewMutexClass(reflect.TypeOf((*connRWMutex)(nil)).Elem(), connlockNames)
}

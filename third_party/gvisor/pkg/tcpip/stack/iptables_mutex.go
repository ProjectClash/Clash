package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type ipTablesRWMutex struct {
	mu sync.RWMutex
}

var ipTableslockNames []string

type ipTableslockNameIndex int

const ()

func (m *ipTablesRWMutex) Lock() {
	locking.AddGLock(ipTablesprefixIndex, -1)
	m.mu.Lock()
}

func (m *ipTablesRWMutex) NestedLock(i ipTableslockNameIndex) {
	locking.AddGLock(ipTablesprefixIndex, int(i))
	m.mu.Lock()
}

func (m *ipTablesRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(ipTablesprefixIndex, -1)
}

func (m *ipTablesRWMutex) NestedUnlock(i ipTableslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(ipTablesprefixIndex, int(i))
}

func (m *ipTablesRWMutex) RLock() {
	locking.AddGLock(ipTablesprefixIndex, -1)
	m.mu.RLock()
}

func (m *ipTablesRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(ipTablesprefixIndex, -1)
}

func (m *ipTablesRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *ipTablesRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *ipTablesRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var ipTablesprefixIndex *locking.MutexClass

func ipTablesinitLockNames() {}

func init() {
	ipTablesinitLockNames()
	ipTablesprefixIndex = locking.NewMutexClass(reflect.TypeOf((*ipTablesRWMutex)(nil)).Elem(), ipTableslockNames)
}

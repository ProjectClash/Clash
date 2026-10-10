package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type dispatcherMutex struct {
	mu sync.Mutex
}

var dispatcherprefixIndex *locking.MutexClass

var dispatcherlockNames []string

type dispatcherlockNameIndex int

const ()

func (m *dispatcherMutex) Lock() {
	locking.AddGLock(dispatcherprefixIndex, -1)
	m.mu.Lock()
}

func (m *dispatcherMutex) NestedLock(i dispatcherlockNameIndex) {
	locking.AddGLock(dispatcherprefixIndex, int(i))
	m.mu.Lock()
}

func (m *dispatcherMutex) Unlock() {
	locking.DelGLock(dispatcherprefixIndex, -1)
	m.mu.Unlock()
}

func (m *dispatcherMutex) NestedUnlock(i dispatcherlockNameIndex) {
	locking.DelGLock(dispatcherprefixIndex, int(i))
	m.mu.Unlock()
}

func dispatcherinitLockNames() {}

func init() {
	dispatcherinitLockNames()
	dispatcherprefixIndex = locking.NewMutexClass(reflect.TypeOf((*dispatcherMutex)(nil)).Elem(), dispatcherlockNames)
}

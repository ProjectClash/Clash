package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type multiPortEndpointRWMutex struct {
	mu sync.RWMutex
}

var multiPortEndpointlockNames []string

type multiPortEndpointlockNameIndex int

const ()

func (m *multiPortEndpointRWMutex) Lock() {
	locking.AddGLock(multiPortEndpointprefixIndex, -1)
	m.mu.Lock()
}

func (m *multiPortEndpointRWMutex) NestedLock(i multiPortEndpointlockNameIndex) {
	locking.AddGLock(multiPortEndpointprefixIndex, int(i))
	m.mu.Lock()
}

func (m *multiPortEndpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(multiPortEndpointprefixIndex, -1)
}

func (m *multiPortEndpointRWMutex) NestedUnlock(i multiPortEndpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(multiPortEndpointprefixIndex, int(i))
}

func (m *multiPortEndpointRWMutex) RLock() {
	locking.AddGLock(multiPortEndpointprefixIndex, -1)
	m.mu.RLock()
}

func (m *multiPortEndpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(multiPortEndpointprefixIndex, -1)
}

func (m *multiPortEndpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *multiPortEndpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *multiPortEndpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var multiPortEndpointprefixIndex *locking.MutexClass

func multiPortEndpointinitLockNames() {}

func init() {
	multiPortEndpointinitLockNames()
	multiPortEndpointprefixIndex = locking.NewMutexClass(reflect.TypeOf((*multiPortEndpointRWMutex)(nil)).Elem(), multiPortEndpointlockNames)
}

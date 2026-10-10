package fdbased

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type injectableEndpointRWMutex struct {
	mu sync.RWMutex
}

var injectableEndpointlockNames []string

type injectableEndpointlockNameIndex int

const ()

func (m *injectableEndpointRWMutex) Lock() {
	locking.AddGLock(injectableEndpointprefixIndex, -1)
	m.mu.Lock()
}

func (m *injectableEndpointRWMutex) NestedLock(i injectableEndpointlockNameIndex) {
	locking.AddGLock(injectableEndpointprefixIndex, int(i))
	m.mu.Lock()
}

func (m *injectableEndpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(injectableEndpointprefixIndex, -1)
}

func (m *injectableEndpointRWMutex) NestedUnlock(i injectableEndpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(injectableEndpointprefixIndex, int(i))
}

func (m *injectableEndpointRWMutex) RLock() {
	locking.AddGLock(injectableEndpointprefixIndex, -1)
	m.mu.RLock()
}

func (m *injectableEndpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(injectableEndpointprefixIndex, -1)
}

func (m *injectableEndpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *injectableEndpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *injectableEndpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var injectableEndpointprefixIndex *locking.MutexClass

func injectableEndpointinitLockNames() {}

func init() {
	injectableEndpointinitLockNames()
	injectableEndpointprefixIndex = locking.NewMutexClass(reflect.TypeOf((*injectableEndpointRWMutex)(nil)).Elem(), injectableEndpointlockNames)
}

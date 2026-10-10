package sharedmem

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type serverEndpointRWMutex struct {
	mu sync.RWMutex
}

var serverEndpointlockNames []string

type serverEndpointlockNameIndex int

const ()

func (m *serverEndpointRWMutex) Lock() {
	locking.AddGLock(serverEndpointprefixIndex, -1)
	m.mu.Lock()
}

func (m *serverEndpointRWMutex) NestedLock(i serverEndpointlockNameIndex) {
	locking.AddGLock(serverEndpointprefixIndex, int(i))
	m.mu.Lock()
}

func (m *serverEndpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(serverEndpointprefixIndex, -1)
}

func (m *serverEndpointRWMutex) NestedUnlock(i serverEndpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(serverEndpointprefixIndex, int(i))
}

func (m *serverEndpointRWMutex) RLock() {
	locking.AddGLock(serverEndpointprefixIndex, -1)
	m.mu.RLock()
}

func (m *serverEndpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(serverEndpointprefixIndex, -1)
}

func (m *serverEndpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *serverEndpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *serverEndpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var serverEndpointprefixIndex *locking.MutexClass

func serverEndpointinitLockNames() {}

func init() {
	serverEndpointinitLockNames()
	serverEndpointprefixIndex = locking.NewMutexClass(reflect.TypeOf((*serverEndpointRWMutex)(nil)).Elem(), serverEndpointlockNames)
}

package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type transportEndpointsRWMutex struct {
	mu sync.RWMutex
}

var transportEndpointslockNames []string

type transportEndpointslockNameIndex int

const ()

func (m *transportEndpointsRWMutex) Lock() {
	locking.AddGLock(transportEndpointsprefixIndex, -1)
	m.mu.Lock()
}

func (m *transportEndpointsRWMutex) NestedLock(i transportEndpointslockNameIndex) {
	locking.AddGLock(transportEndpointsprefixIndex, int(i))
	m.mu.Lock()
}

func (m *transportEndpointsRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(transportEndpointsprefixIndex, -1)
}

func (m *transportEndpointsRWMutex) NestedUnlock(i transportEndpointslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(transportEndpointsprefixIndex, int(i))
}

func (m *transportEndpointsRWMutex) RLock() {
	locking.AddGLock(transportEndpointsprefixIndex, -1)
	m.mu.RLock()
}

func (m *transportEndpointsRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(transportEndpointsprefixIndex, -1)
}

func (m *transportEndpointsRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *transportEndpointsRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *transportEndpointsRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var transportEndpointsprefixIndex *locking.MutexClass

func transportEndpointsinitLockNames() {}

func init() {
	transportEndpointsinitLockNames()
	transportEndpointsprefixIndex = locking.NewMutexClass(reflect.TypeOf((*transportEndpointsRWMutex)(nil)).Elem(), transportEndpointslockNames)
}

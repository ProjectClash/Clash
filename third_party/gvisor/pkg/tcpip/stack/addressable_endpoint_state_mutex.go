package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type addressableEndpointStateRWMutex struct {
	mu sync.RWMutex
}

var addressableEndpointStatelockNames []string

type addressableEndpointStatelockNameIndex int

const ()

func (m *addressableEndpointStateRWMutex) Lock() {
	locking.AddGLock(addressableEndpointStateprefixIndex, -1)
	m.mu.Lock()
}

func (m *addressableEndpointStateRWMutex) NestedLock(i addressableEndpointStatelockNameIndex) {
	locking.AddGLock(addressableEndpointStateprefixIndex, int(i))
	m.mu.Lock()
}

func (m *addressableEndpointStateRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, -1)
}

func (m *addressableEndpointStateRWMutex) NestedUnlock(i addressableEndpointStatelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, int(i))
}

func (m *addressableEndpointStateRWMutex) RLock() {
	locking.AddGLock(addressableEndpointStateprefixIndex, -1)
	m.mu.RLock()
}

func (m *addressableEndpointStateRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, -1)
}

func (m *addressableEndpointStateRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *addressableEndpointStateRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *addressableEndpointStateRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var addressableEndpointStateprefixIndex *locking.MutexClass

func addressableEndpointStateinitLockNames() {}

func init() {
	addressableEndpointStateinitLockNames()
	addressableEndpointStateprefixIndex = locking.NewMutexClass(reflect.TypeOf((*addressableEndpointStateRWMutex)(nil)).Elem(), addressableEndpointStatelockNames)
}

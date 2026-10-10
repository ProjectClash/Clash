package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type cleanupEndpointsMutex struct {
	mu sync.Mutex
}

var cleanupEndpointsprefixIndex *locking.MutexClass

var cleanupEndpointslockNames []string

type cleanupEndpointslockNameIndex int

const ()

func (m *cleanupEndpointsMutex) Lock() {
	locking.AddGLock(cleanupEndpointsprefixIndex, -1)
	m.mu.Lock()
}

func (m *cleanupEndpointsMutex) NestedLock(i cleanupEndpointslockNameIndex) {
	locking.AddGLock(cleanupEndpointsprefixIndex, int(i))
	m.mu.Lock()
}

func (m *cleanupEndpointsMutex) Unlock() {
	locking.DelGLock(cleanupEndpointsprefixIndex, -1)
	m.mu.Unlock()
}

func (m *cleanupEndpointsMutex) NestedUnlock(i cleanupEndpointslockNameIndex) {
	locking.DelGLock(cleanupEndpointsprefixIndex, int(i))
	m.mu.Unlock()
}

func cleanupEndpointsinitLockNames() {}

func init() {
	cleanupEndpointsinitLockNames()
	cleanupEndpointsprefixIndex = locking.NewMutexClass(reflect.TypeOf((*cleanupEndpointsMutex)(nil)).Elem(), cleanupEndpointslockNames)
}

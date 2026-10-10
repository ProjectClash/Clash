package tun

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type endpointMutex struct {
	mu sync.Mutex
}

var endpointprefixIndex *locking.MutexClass

var endpointlockNames []string

type endpointlockNameIndex int

const ()

func (m *endpointMutex) Lock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.Lock()
}

func (m *endpointMutex) NestedLock(i endpointlockNameIndex) {
	locking.AddGLock(endpointprefixIndex, int(i))
	m.mu.Lock()
}

func (m *endpointMutex) Unlock() {
	locking.DelGLock(endpointprefixIndex, -1)
	m.mu.Unlock()
}

func (m *endpointMutex) NestedUnlock(i endpointlockNameIndex) {
	locking.DelGLock(endpointprefixIndex, int(i))
	m.mu.Unlock()
}

func endpointinitLockNames() {}

func init() {
	endpointinitLockNames()
	endpointprefixIndex = locking.NewMutexClass(reflect.TypeOf((*endpointMutex)(nil)).Elem(), endpointlockNames)
}

package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type protocolRWMutex struct {
	mu sync.RWMutex
}

var protocollockNames []string

type protocollockNameIndex int

const ()

func (m *protocolRWMutex) Lock() {
	locking.AddGLock(protocolprefixIndex, -1)
	m.mu.Lock()
}

func (m *protocolRWMutex) NestedLock(i protocollockNameIndex) {
	locking.AddGLock(protocolprefixIndex, int(i))
	m.mu.Lock()
}

func (m *protocolRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(protocolprefixIndex, -1)
}

func (m *protocolRWMutex) NestedUnlock(i protocollockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(protocolprefixIndex, int(i))
}

func (m *protocolRWMutex) RLock() {
	locking.AddGLock(protocolprefixIndex, -1)
	m.mu.RLock()
}

func (m *protocolRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(protocolprefixIndex, -1)
}

func (m *protocolRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *protocolRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *protocolRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var protocolprefixIndex *locking.MutexClass

func protocolinitLockNames() {}

func init() {
	protocolinitLockNames()
	protocolprefixIndex = locking.NewMutexClass(reflect.TypeOf((*protocolRWMutex)(nil)).Elem(), protocollockNames)
}

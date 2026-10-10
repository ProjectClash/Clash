package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type bridgeRWMutex struct {
	mu sync.RWMutex
}

var bridgelockNames []string

type bridgelockNameIndex int

const ()

func (m *bridgeRWMutex) Lock() {
	locking.AddGLock(bridgeprefixIndex, -1)
	m.mu.Lock()
}

func (m *bridgeRWMutex) NestedLock(i bridgelockNameIndex) {
	locking.AddGLock(bridgeprefixIndex, int(i))
	m.mu.Lock()
}

func (m *bridgeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(bridgeprefixIndex, -1)
}

func (m *bridgeRWMutex) NestedUnlock(i bridgelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(bridgeprefixIndex, int(i))
}

func (m *bridgeRWMutex) RLock() {
	locking.AddGLock(bridgeprefixIndex, -1)
	m.mu.RLock()
}

func (m *bridgeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(bridgeprefixIndex, -1)
}

func (m *bridgeRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *bridgeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *bridgeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var bridgeprefixIndex *locking.MutexClass

func bridgeinitLockNames() {}

func init() {
	bridgeinitLockNames()
	bridgeprefixIndex = locking.NewMutexClass(reflect.TypeOf((*bridgeRWMutex)(nil)).Elem(), bridgelockNames)
}

package channel

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type queueRWMutex struct {
	mu sync.RWMutex
}

var queuelockNames []string

type queuelockNameIndex int

const ()

func (m *queueRWMutex) Lock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.Lock()
}

func (m *queueRWMutex) NestedLock(i queuelockNameIndex) {
	locking.AddGLock(queueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *queueRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(queueprefixIndex, -1)
}

func (m *queueRWMutex) NestedUnlock(i queuelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(queueprefixIndex, int(i))
}

func (m *queueRWMutex) RLock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.RLock()
}

func (m *queueRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(queueprefixIndex, -1)
}

func (m *queueRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *queueRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *queueRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var queueprefixIndex *locking.MutexClass

func queueinitLockNames() {}

func init() {
	queueinitLockNames()
	queueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*queueRWMutex)(nil)).Elem(), queuelockNames)
}

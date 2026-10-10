package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type nicRWMutex struct {
	mu sync.RWMutex
}

var niclockNames []string

type niclockNameIndex int

const ()

func (m *nicRWMutex) Lock() {
	locking.AddGLock(nicprefixIndex, -1)
	m.mu.Lock()
}

func (m *nicRWMutex) NestedLock(i niclockNameIndex) {
	locking.AddGLock(nicprefixIndex, int(i))
	m.mu.Lock()
}

func (m *nicRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(nicprefixIndex, -1)
}

func (m *nicRWMutex) NestedUnlock(i niclockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(nicprefixIndex, int(i))
}

func (m *nicRWMutex) RLock() {
	locking.AddGLock(nicprefixIndex, -1)
	m.mu.RLock()
}

func (m *nicRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(nicprefixIndex, -1)
}

func (m *nicRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *nicRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *nicRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var nicprefixIndex *locking.MutexClass

func nicinitLockNames() {}

func init() {
	nicinitLockNames()
	nicprefixIndex = locking.NewMutexClass(reflect.TypeOf((*nicRWMutex)(nil)).Elem(), niclockNames)
}

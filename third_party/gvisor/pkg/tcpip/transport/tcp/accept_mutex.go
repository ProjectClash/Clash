package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type acceptMutex struct {
	mu sync.Mutex
}

var acceptprefixIndex *locking.MutexClass

var acceptlockNames []string

type acceptlockNameIndex int

const ()

func (m *acceptMutex) Lock() {
	locking.AddGLock(acceptprefixIndex, -1)
	m.mu.Lock()
}

func (m *acceptMutex) NestedLock(i acceptlockNameIndex) {
	locking.AddGLock(acceptprefixIndex, int(i))
	m.mu.Lock()
}

func (m *acceptMutex) Unlock() {
	locking.DelGLock(acceptprefixIndex, -1)
	m.mu.Unlock()
}

func (m *acceptMutex) NestedUnlock(i acceptlockNameIndex) {
	locking.DelGLock(acceptprefixIndex, int(i))
	m.mu.Unlock()
}

func acceptinitLockNames() {}

func init() {
	acceptinitLockNames()
	acceptprefixIndex = locking.NewMutexClass(reflect.TypeOf((*acceptMutex)(nil)).Elem(), acceptlockNames)
}

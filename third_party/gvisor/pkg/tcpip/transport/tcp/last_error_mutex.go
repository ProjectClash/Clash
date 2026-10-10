package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type lastErrorMutex struct {
	mu sync.Mutex
}

var lastErrorprefixIndex *locking.MutexClass

var lastErrorlockNames []string

type lastErrorlockNameIndex int

const ()

func (m *lastErrorMutex) Lock() {
	locking.AddGLock(lastErrorprefixIndex, -1)
	m.mu.Lock()
}

func (m *lastErrorMutex) NestedLock(i lastErrorlockNameIndex) {
	locking.AddGLock(lastErrorprefixIndex, int(i))
	m.mu.Lock()
}

func (m *lastErrorMutex) Unlock() {
	locking.DelGLock(lastErrorprefixIndex, -1)
	m.mu.Unlock()
}

func (m *lastErrorMutex) NestedUnlock(i lastErrorlockNameIndex) {
	locking.DelGLock(lastErrorprefixIndex, int(i))
	m.mu.Unlock()
}

func lastErrorinitLockNames() {}

func init() {
	lastErrorinitLockNames()
	lastErrorprefixIndex = locking.NewMutexClass(reflect.TypeOf((*lastErrorMutex)(nil)).Elem(), lastErrorlockNames)
}

package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type keepaliveMutex struct {
	mu sync.Mutex
}

var keepaliveprefixIndex *locking.MutexClass

var keepalivelockNames []string

type keepalivelockNameIndex int

const ()

func (m *keepaliveMutex) Lock() {
	locking.AddGLock(keepaliveprefixIndex, -1)
	m.mu.Lock()
}

func (m *keepaliveMutex) NestedLock(i keepalivelockNameIndex) {
	locking.AddGLock(keepaliveprefixIndex, int(i))
	m.mu.Lock()
}

func (m *keepaliveMutex) Unlock() {
	locking.DelGLock(keepaliveprefixIndex, -1)
	m.mu.Unlock()
}

func (m *keepaliveMutex) NestedUnlock(i keepalivelockNameIndex) {
	locking.DelGLock(keepaliveprefixIndex, int(i))
	m.mu.Unlock()
}

func keepaliveinitLockNames() {}

func init() {
	keepaliveinitLockNames()
	keepaliveprefixIndex = locking.NewMutexClass(reflect.TypeOf((*keepaliveMutex)(nil)).Elem(), keepalivelockNames)
}

package tbf

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type queueMutex struct {
	mu sync.Mutex
}

var queueprefixIndex *locking.MutexClass

var queuelockNames []string

type queuelockNameIndex int

const ()

func (m *queueMutex) Lock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.Lock()
}

func (m *queueMutex) NestedLock(i queuelockNameIndex) {
	locking.AddGLock(queueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *queueMutex) Unlock() {
	locking.DelGLock(queueprefixIndex, -1)
	m.mu.Unlock()
}

func (m *queueMutex) NestedUnlock(i queuelockNameIndex) {
	locking.DelGLock(queueprefixIndex, int(i))
	m.mu.Unlock()
}

func queueinitLockNames() {}

func init() {
	queueinitLockNames()
	queueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*queueMutex)(nil)).Elem(), queuelockNames)
}

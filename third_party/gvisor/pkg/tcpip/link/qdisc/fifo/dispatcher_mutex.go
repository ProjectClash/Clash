package fifo

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type queueDispatcherMutex struct {
	mu sync.Mutex
}

var queueDispatcherprefixIndex *locking.MutexClass

var queueDispatcherlockNames []string

type queueDispatcherlockNameIndex int

const ()

func (m *queueDispatcherMutex) Lock() {
	locking.AddGLock(queueDispatcherprefixIndex, -1)
	m.mu.Lock()
}

func (m *queueDispatcherMutex) NestedLock(i queueDispatcherlockNameIndex) {
	locking.AddGLock(queueDispatcherprefixIndex, int(i))
	m.mu.Lock()
}

func (m *queueDispatcherMutex) Unlock() {
	locking.DelGLock(queueDispatcherprefixIndex, -1)
	m.mu.Unlock()
}

func (m *queueDispatcherMutex) NestedUnlock(i queueDispatcherlockNameIndex) {
	locking.DelGLock(queueDispatcherprefixIndex, int(i))
	m.mu.Unlock()
}

func queueDispatcherinitLockNames() {}

func init() {
	queueDispatcherinitLockNames()
	queueDispatcherprefixIndex = locking.NewMutexClass(reflect.TypeOf((*queueDispatcherMutex)(nil)).Elem(), queueDispatcherlockNames)
}

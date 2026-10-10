package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type rcvQueueMutex struct {
	mu sync.Mutex
}

var rcvQueueprefixIndex *locking.MutexClass

var rcvQueuelockNames []string

type rcvQueuelockNameIndex int

const ()

func (m *rcvQueueMutex) Lock() {
	locking.AddGLock(rcvQueueprefixIndex, -1)
	m.mu.Lock()
}

func (m *rcvQueueMutex) NestedLock(i rcvQueuelockNameIndex) {
	locking.AddGLock(rcvQueueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *rcvQueueMutex) Unlock() {
	locking.DelGLock(rcvQueueprefixIndex, -1)
	m.mu.Unlock()
}

func (m *rcvQueueMutex) NestedUnlock(i rcvQueuelockNameIndex) {
	locking.DelGLock(rcvQueueprefixIndex, int(i))
	m.mu.Unlock()
}

func rcvQueueinitLockNames() {}

func init() {
	rcvQueueinitLockNames()
	rcvQueueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*rcvQueueMutex)(nil)).Elem(), rcvQueuelockNames)
}

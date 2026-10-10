package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type epQueueMutex struct {
	mu sync.Mutex
}

var epQueueprefixIndex *locking.MutexClass

var epQueuelockNames []string

type epQueuelockNameIndex int

const ()

func (m *epQueueMutex) Lock() {
	locking.AddGLock(epQueueprefixIndex, -1)
	m.mu.Lock()
}

func (m *epQueueMutex) NestedLock(i epQueuelockNameIndex) {
	locking.AddGLock(epQueueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *epQueueMutex) Unlock() {
	locking.DelGLock(epQueueprefixIndex, -1)
	m.mu.Unlock()
}

func (m *epQueueMutex) NestedUnlock(i epQueuelockNameIndex) {
	locking.DelGLock(epQueueprefixIndex, int(i))
	m.mu.Unlock()
}

func epQueueinitLockNames() {}

func init() {
	epQueueinitLockNames()
	epQueueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*epQueueMutex)(nil)).Elem(), epQueuelockNames)
}

package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type sndQueueMutex struct {
	mu sync.Mutex
}

var sndQueueprefixIndex *locking.MutexClass

var sndQueuelockNames []string

type sndQueuelockNameIndex int

const ()

func (m *sndQueueMutex) Lock() {
	locking.AddGLock(sndQueueprefixIndex, -1)
	m.mu.Lock()
}

func (m *sndQueueMutex) NestedLock(i sndQueuelockNameIndex) {
	locking.AddGLock(sndQueueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *sndQueueMutex) Unlock() {
	locking.DelGLock(sndQueueprefixIndex, -1)
	m.mu.Unlock()
}

func (m *sndQueueMutex) NestedUnlock(i sndQueuelockNameIndex) {
	locking.DelGLock(sndQueueprefixIndex, int(i))
	m.mu.Unlock()
}

func sndQueueinitLockNames() {}

func init() {
	sndQueueinitLockNames()
	sndQueueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*sndQueueMutex)(nil)).Elem(), sndQueuelockNames)
}

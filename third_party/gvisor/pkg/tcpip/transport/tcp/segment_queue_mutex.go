package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type segmentQueueMutex struct {
	mu sync.Mutex
}

var segmentQueueprefixIndex *locking.MutexClass

var segmentQueuelockNames []string

type segmentQueuelockNameIndex int

const ()

func (m *segmentQueueMutex) Lock() {
	locking.AddGLock(segmentQueueprefixIndex, -1)
	m.mu.Lock()
}

func (m *segmentQueueMutex) NestedLock(i segmentQueuelockNameIndex) {
	locking.AddGLock(segmentQueueprefixIndex, int(i))
	m.mu.Lock()
}

func (m *segmentQueueMutex) Unlock() {
	locking.DelGLock(segmentQueueprefixIndex, -1)
	m.mu.Unlock()
}

func (m *segmentQueueMutex) NestedUnlock(i segmentQueuelockNameIndex) {
	locking.DelGLock(segmentQueueprefixIndex, int(i))
	m.mu.Unlock()
}

func segmentQueueinitLockNames() {}

func init() {
	segmentQueueinitLockNames()
	segmentQueueprefixIndex = locking.NewMutexClass(reflect.TypeOf((*segmentQueueMutex)(nil)).Elem(), segmentQueuelockNames)
}

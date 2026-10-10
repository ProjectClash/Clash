package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type forwarderMutex struct {
	mu sync.Mutex
}

var forwarderprefixIndex *locking.MutexClass

var forwarderlockNames []string

type forwarderlockNameIndex int

const ()

func (m *forwarderMutex) Lock() {
	locking.AddGLock(forwarderprefixIndex, -1)
	m.mu.Lock()
}

func (m *forwarderMutex) NestedLock(i forwarderlockNameIndex) {
	locking.AddGLock(forwarderprefixIndex, int(i))
	m.mu.Lock()
}

func (m *forwarderMutex) Unlock() {
	locking.DelGLock(forwarderprefixIndex, -1)
	m.mu.Unlock()
}

func (m *forwarderMutex) NestedUnlock(i forwarderlockNameIndex) {
	locking.DelGLock(forwarderprefixIndex, int(i))
	m.mu.Unlock()
}

func forwarderinitLockNames() {}

func init() {
	forwarderinitLockNames()
	forwarderprefixIndex = locking.NewMutexClass(reflect.TypeOf((*forwarderMutex)(nil)).Elem(), forwarderlockNames)
}

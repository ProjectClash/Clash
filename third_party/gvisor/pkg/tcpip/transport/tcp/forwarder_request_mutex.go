package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type forwarderRequestMutex struct {
	mu sync.Mutex
}

var forwarderRequestprefixIndex *locking.MutexClass

var forwarderRequestlockNames []string

type forwarderRequestlockNameIndex int

const ()

func (m *forwarderRequestMutex) Lock() {
	locking.AddGLock(forwarderRequestprefixIndex, -1)
	m.mu.Lock()
}

func (m *forwarderRequestMutex) NestedLock(i forwarderRequestlockNameIndex) {
	locking.AddGLock(forwarderRequestprefixIndex, int(i))
	m.mu.Lock()
}

func (m *forwarderRequestMutex) Unlock() {
	locking.DelGLock(forwarderRequestprefixIndex, -1)
	m.mu.Unlock()
}

func (m *forwarderRequestMutex) NestedUnlock(i forwarderRequestlockNameIndex) {
	locking.DelGLock(forwarderRequestprefixIndex, int(i))
	m.mu.Unlock()
}

func forwarderRequestinitLockNames() {}

func init() {
	forwarderRequestinitLockNames()
	forwarderRequestprefixIndex = locking.NewMutexClass(reflect.TypeOf((*forwarderRequestMutex)(nil)).Elem(), forwarderRequestlockNames)
}

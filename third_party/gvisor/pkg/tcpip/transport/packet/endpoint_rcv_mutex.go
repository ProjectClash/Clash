package packet

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type rcvMutex struct {
	mu sync.Mutex
}

var rcvprefixIndex *locking.MutexClass

var rcvlockNames []string

type rcvlockNameIndex int

const ()

func (m *rcvMutex) Lock() {
	locking.AddGLock(rcvprefixIndex, -1)
	m.mu.Lock()
}

func (m *rcvMutex) NestedLock(i rcvlockNameIndex) {
	locking.AddGLock(rcvprefixIndex, int(i))
	m.mu.Lock()
}

func (m *rcvMutex) Unlock() {
	locking.DelGLock(rcvprefixIndex, -1)
	m.mu.Unlock()
}

func (m *rcvMutex) NestedUnlock(i rcvlockNameIndex) {
	locking.DelGLock(rcvprefixIndex, int(i))
	m.mu.Unlock()
}

func rcvinitLockNames() {}

func init() {
	rcvinitLockNames()
	rcvprefixIndex = locking.NewMutexClass(reflect.TypeOf((*rcvMutex)(nil)).Elem(), rcvlockNames)
}

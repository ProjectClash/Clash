package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type rttMutex struct {
	mu sync.Mutex
}

var rttprefixIndex *locking.MutexClass

var rttlockNames []string

type rttlockNameIndex int

const ()

func (m *rttMutex) Lock() {
	locking.AddGLock(rttprefixIndex, -1)
	m.mu.Lock()
}

func (m *rttMutex) NestedLock(i rttlockNameIndex) {
	locking.AddGLock(rttprefixIndex, int(i))
	m.mu.Lock()
}

func (m *rttMutex) Unlock() {
	locking.DelGLock(rttprefixIndex, -1)
	m.mu.Unlock()
}

func (m *rttMutex) NestedUnlock(i rttlockNameIndex) {
	locking.DelGLock(rttprefixIndex, int(i))
	m.mu.Unlock()
}

func rttinitLockNames() {}

func init() {
	rttinitLockNames()
	rttprefixIndex = locking.NewMutexClass(reflect.TypeOf((*rttMutex)(nil)).Elem(), rttlockNames)
}

package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type hasherMutex struct {
	mu sync.Mutex
}

var hasherprefixIndex *locking.MutexClass

var hasherlockNames []string

type hasherlockNameIndex int

const ()

func (m *hasherMutex) Lock() {
	locking.AddGLock(hasherprefixIndex, -1)
	m.mu.Lock()
}

func (m *hasherMutex) NestedLock(i hasherlockNameIndex) {
	locking.AddGLock(hasherprefixIndex, int(i))
	m.mu.Lock()
}

func (m *hasherMutex) Unlock() {
	locking.DelGLock(hasherprefixIndex, -1)
	m.mu.Unlock()
}

func (m *hasherMutex) NestedUnlock(i hasherlockNameIndex) {
	locking.DelGLock(hasherprefixIndex, int(i))
	m.mu.Unlock()
}

func hasherinitLockNames() {}

func init() {
	hasherinitLockNames()
	hasherprefixIndex = locking.NewMutexClass(reflect.TypeOf((*hasherMutex)(nil)).Elem(), hasherlockNames)
}

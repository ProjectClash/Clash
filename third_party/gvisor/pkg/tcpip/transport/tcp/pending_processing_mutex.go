package tcp

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type pendingProcessingMutex struct {
	mu sync.Mutex
}

var pendingProcessingprefixIndex *locking.MutexClass

var pendingProcessinglockNames []string

type pendingProcessinglockNameIndex int

const ()

func (m *pendingProcessingMutex) Lock() {
	locking.AddGLock(pendingProcessingprefixIndex, -1)
	m.mu.Lock()
}

func (m *pendingProcessingMutex) NestedLock(i pendingProcessinglockNameIndex) {
	locking.AddGLock(pendingProcessingprefixIndex, int(i))
	m.mu.Lock()
}

func (m *pendingProcessingMutex) Unlock() {
	locking.DelGLock(pendingProcessingprefixIndex, -1)
	m.mu.Unlock()
}

func (m *pendingProcessingMutex) NestedUnlock(i pendingProcessinglockNameIndex) {
	locking.DelGLock(pendingProcessingprefixIndex, int(i))
	m.mu.Unlock()
}

func pendingProcessinginitLockNames() {}

func init() {
	pendingProcessinginitLockNames()
	pendingProcessingprefixIndex = locking.NewMutexClass(reflect.TypeOf((*pendingProcessingMutex)(nil)).Elem(), pendingProcessinglockNames)
}

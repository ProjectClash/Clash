package gomaxprocs

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type gomaxprocsMutex struct {
	mu sync.Mutex
}

var gomaxprocsprefixIndex *locking.MutexClass

var gomaxprocslockNames []string

type gomaxprocslockNameIndex int

const ()

func (m *gomaxprocsMutex) Lock() {
	locking.AddGLock(gomaxprocsprefixIndex, -1)
	m.mu.Lock()
}

func (m *gomaxprocsMutex) NestedLock(i gomaxprocslockNameIndex) {
	locking.AddGLock(gomaxprocsprefixIndex, int(i))
	m.mu.Lock()
}

func (m *gomaxprocsMutex) Unlock() {
	locking.DelGLock(gomaxprocsprefixIndex, -1)
	m.mu.Unlock()
}

func (m *gomaxprocsMutex) NestedUnlock(i gomaxprocslockNameIndex) {
	locking.DelGLock(gomaxprocsprefixIndex, int(i))
	m.mu.Unlock()
}

func gomaxprocsinitLockNames() {}

func init() {
	gomaxprocsinitLockNames()
	gomaxprocsprefixIndex = locking.NewMutexClass(reflect.TypeOf((*gomaxprocsMutex)(nil)).Elem(), gomaxprocslockNames)
}

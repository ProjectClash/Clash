package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type bucketRWMutex struct {
	mu sync.RWMutex
}

var bucketlockNames []string

type bucketlockNameIndex int

const (
	bucketLockOthertuple = bucketlockNameIndex(0)
)
const ()

func (m *bucketRWMutex) Lock() {
	locking.AddGLock(bucketprefixIndex, -1)
	m.mu.Lock()
}

func (m *bucketRWMutex) NestedLock(i bucketlockNameIndex) {
	locking.AddGLock(bucketprefixIndex, int(i))
	m.mu.Lock()
}

func (m *bucketRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(bucketprefixIndex, -1)
}

func (m *bucketRWMutex) NestedUnlock(i bucketlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(bucketprefixIndex, int(i))
}

func (m *bucketRWMutex) RLock() {
	locking.AddGLock(bucketprefixIndex, -1)
	m.mu.RLock()
}

func (m *bucketRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(bucketprefixIndex, -1)
}

func (m *bucketRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *bucketRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *bucketRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var bucketprefixIndex *locking.MutexClass

func bucketinitLockNames() { bucketlockNames = []string{"otherTuple"} }

func init() {
	bucketinitLockNames()
	bucketprefixIndex = locking.NewMutexClass(reflect.TypeOf((*bucketRWMutex)(nil)).Elem(), bucketlockNames)
}

package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type neighborEntryRWMutex struct {
	mu sync.RWMutex
}

var neighborEntrylockNames []string

type neighborEntrylockNameIndex int

const ()

func (m *neighborEntryRWMutex) Lock() {
	locking.AddGLock(neighborEntryprefixIndex, -1)
	m.mu.Lock()
}

func (m *neighborEntryRWMutex) NestedLock(i neighborEntrylockNameIndex) {
	locking.AddGLock(neighborEntryprefixIndex, int(i))
	m.mu.Lock()
}

func (m *neighborEntryRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(neighborEntryprefixIndex, -1)
}

func (m *neighborEntryRWMutex) NestedUnlock(i neighborEntrylockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(neighborEntryprefixIndex, int(i))
}

func (m *neighborEntryRWMutex) RLock() {
	locking.AddGLock(neighborEntryprefixIndex, -1)
	m.mu.RLock()
}

func (m *neighborEntryRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(neighborEntryprefixIndex, -1)
}

func (m *neighborEntryRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *neighborEntryRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *neighborEntryRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var neighborEntryprefixIndex *locking.MutexClass

func neighborEntryinitLockNames() {}

func init() {
	neighborEntryinitLockNames()
	neighborEntryprefixIndex = locking.NewMutexClass(reflect.TypeOf((*neighborEntryRWMutex)(nil)).Elem(), neighborEntrylockNames)
}

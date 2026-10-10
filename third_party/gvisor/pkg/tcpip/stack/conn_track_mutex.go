package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type connTrackRWMutex struct {
	mu sync.RWMutex
}

var connTracklockNames []string

type connTracklockNameIndex int

const ()

func (m *connTrackRWMutex) Lock() {
	locking.AddGLock(connTrackprefixIndex, -1)
	m.mu.Lock()
}

func (m *connTrackRWMutex) NestedLock(i connTracklockNameIndex) {
	locking.AddGLock(connTrackprefixIndex, int(i))
	m.mu.Lock()
}

func (m *connTrackRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(connTrackprefixIndex, -1)
}

func (m *connTrackRWMutex) NestedUnlock(i connTracklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(connTrackprefixIndex, int(i))
}

func (m *connTrackRWMutex) RLock() {
	locking.AddGLock(connTrackprefixIndex, -1)
	m.mu.RLock()
}

func (m *connTrackRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(connTrackprefixIndex, -1)
}

func (m *connTrackRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *connTrackRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *connTrackRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var connTrackprefixIndex *locking.MutexClass

func connTrackinitLockNames() {}

func init() {
	connTrackinitLockNames()
	connTrackprefixIndex = locking.NewMutexClass(reflect.TypeOf((*connTrackRWMutex)(nil)).Elem(), connTracklockNames)
}

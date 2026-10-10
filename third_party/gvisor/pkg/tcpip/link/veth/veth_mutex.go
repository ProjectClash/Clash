package veth

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type vethRWMutex struct {
	mu sync.RWMutex
}

var vethlockNames []string

type vethlockNameIndex int

const ()

func (m *vethRWMutex) Lock() {
	locking.AddGLock(vethprefixIndex, -1)
	m.mu.Lock()
}

func (m *vethRWMutex) NestedLock(i vethlockNameIndex) {
	locking.AddGLock(vethprefixIndex, int(i))
	m.mu.Lock()
}

func (m *vethRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(vethprefixIndex, -1)
}

func (m *vethRWMutex) NestedUnlock(i vethlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(vethprefixIndex, int(i))
}

func (m *vethRWMutex) RLock() {
	locking.AddGLock(vethprefixIndex, -1)
	m.mu.RLock()
}

func (m *vethRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(vethprefixIndex, -1)
}

func (m *vethRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *vethRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *vethRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var vethprefixIndex *locking.MutexClass

func vethinitLockNames() {}

func init() {
	vethinitLockNames()
	vethprefixIndex = locking.NewMutexClass(reflect.TypeOf((*vethRWMutex)(nil)).Elem(), vethlockNames)
}

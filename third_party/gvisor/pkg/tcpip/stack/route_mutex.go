package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type routeRWMutex struct {
	mu sync.RWMutex
}

var routelockNames []string

type routelockNameIndex int

const ()

func (m *routeRWMutex) Lock() {
	locking.AddGLock(routeprefixIndex, -1)
	m.mu.Lock()
}

func (m *routeRWMutex) NestedLock(i routelockNameIndex) {
	locking.AddGLock(routeprefixIndex, int(i))
	m.mu.Lock()
}

func (m *routeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(routeprefixIndex, -1)
}

func (m *routeRWMutex) NestedUnlock(i routelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(routeprefixIndex, int(i))
}

func (m *routeRWMutex) RLock() {
	locking.AddGLock(routeprefixIndex, -1)
	m.mu.RLock()
}

func (m *routeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(routeprefixIndex, -1)
}

func (m *routeRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *routeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *routeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var routeprefixIndex *locking.MutexClass

func routeinitLockNames() {}

func init() {
	routeinitLockNames()
	routeprefixIndex = locking.NewMutexClass(reflect.TypeOf((*routeRWMutex)(nil)).Elem(), routelockNames)
}

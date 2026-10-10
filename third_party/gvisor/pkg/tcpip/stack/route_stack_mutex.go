package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type routeStackRWMutex struct {
	mu sync.RWMutex
}

var routeStacklockNames []string

type routeStacklockNameIndex int

const ()

func (m *routeStackRWMutex) Lock() {
	locking.AddGLock(routeStackprefixIndex, -1)
	m.mu.Lock()
}

func (m *routeStackRWMutex) NestedLock(i routeStacklockNameIndex) {
	locking.AddGLock(routeStackprefixIndex, int(i))
	m.mu.Lock()
}

func (m *routeStackRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(routeStackprefixIndex, -1)
}

func (m *routeStackRWMutex) NestedUnlock(i routeStacklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(routeStackprefixIndex, int(i))
}

func (m *routeStackRWMutex) RLock() {
	locking.AddGLock(routeStackprefixIndex, -1)
	m.mu.RLock()
}

func (m *routeStackRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(routeStackprefixIndex, -1)
}

func (m *routeStackRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *routeStackRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *routeStackRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var routeStackprefixIndex *locking.MutexClass

func routeStackinitLockNames() {}

func init() {
	routeStackinitLockNames()
	routeStackprefixIndex = locking.NewMutexClass(reflect.TypeOf((*routeStackRWMutex)(nil)).Elem(), routeStacklockNames)
}

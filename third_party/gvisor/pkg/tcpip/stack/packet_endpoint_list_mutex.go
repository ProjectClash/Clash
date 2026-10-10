package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type packetEndpointListRWMutex struct {
	mu sync.RWMutex
}

var packetEndpointListlockNames []string

type packetEndpointListlockNameIndex int

const ()

func (m *packetEndpointListRWMutex) Lock() {
	locking.AddGLock(packetEndpointListprefixIndex, -1)
	m.mu.Lock()
}

func (m *packetEndpointListRWMutex) NestedLock(i packetEndpointListlockNameIndex) {
	locking.AddGLock(packetEndpointListprefixIndex, int(i))
	m.mu.Lock()
}

func (m *packetEndpointListRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetEndpointListprefixIndex, -1)
}

func (m *packetEndpointListRWMutex) NestedUnlock(i packetEndpointListlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetEndpointListprefixIndex, int(i))
}

func (m *packetEndpointListRWMutex) RLock() {
	locking.AddGLock(packetEndpointListprefixIndex, -1)
	m.mu.RLock()
}

func (m *packetEndpointListRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetEndpointListprefixIndex, -1)
}

func (m *packetEndpointListRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *packetEndpointListRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *packetEndpointListRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetEndpointListprefixIndex *locking.MutexClass

func packetEndpointListinitLockNames() {}

func init() {
	packetEndpointListinitLockNames()
	packetEndpointListprefixIndex = locking.NewMutexClass(reflect.TypeOf((*packetEndpointListRWMutex)(nil)).Elem(), packetEndpointListlockNames)
}

package packet

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type packetMmapRWMutex struct {
	mu sync.RWMutex
}

var packetMmaplockNames []string

type packetMmaplockNameIndex int

const ()

func (m *packetMmapRWMutex) Lock() {
	locking.AddGLock(packetMmapprefixIndex, -1)
	m.mu.Lock()
}

func (m *packetMmapRWMutex) NestedLock(i packetMmaplockNameIndex) {
	locking.AddGLock(packetMmapprefixIndex, int(i))
	m.mu.Lock()
}

func (m *packetMmapRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetMmapprefixIndex, -1)
}

func (m *packetMmapRWMutex) NestedUnlock(i packetMmaplockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetMmapprefixIndex, int(i))
}

func (m *packetMmapRWMutex) RLock() {
	locking.AddGLock(packetMmapprefixIndex, -1)
	m.mu.RLock()
}

func (m *packetMmapRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetMmapprefixIndex, -1)
}

func (m *packetMmapRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *packetMmapRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *packetMmapRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetMmapprefixIndex *locking.MutexClass

func packetMmapinitLockNames() {}

func init() {
	packetMmapinitLockNames()
	packetMmapprefixIndex = locking.NewMutexClass(reflect.TypeOf((*packetMmapRWMutex)(nil)).Elem(), packetMmaplockNames)
}

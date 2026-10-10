package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type packetEPsRWMutex struct {
	mu sync.RWMutex
}

var packetEPslockNames []string

type packetEPslockNameIndex int

const ()

func (m *packetEPsRWMutex) Lock() {
	locking.AddGLock(packetEPsprefixIndex, -1)
	m.mu.Lock()
}

func (m *packetEPsRWMutex) NestedLock(i packetEPslockNameIndex) {
	locking.AddGLock(packetEPsprefixIndex, int(i))
	m.mu.Lock()
}

func (m *packetEPsRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetEPsprefixIndex, -1)
}

func (m *packetEPsRWMutex) NestedUnlock(i packetEPslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetEPsprefixIndex, int(i))
}

func (m *packetEPsRWMutex) RLock() {
	locking.AddGLock(packetEPsprefixIndex, -1)
	m.mu.RLock()
}

func (m *packetEPsRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetEPsprefixIndex, -1)
}

func (m *packetEPsRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *packetEPsRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *packetEPsRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetEPsprefixIndex *locking.MutexClass

func packetEPsinitLockNames() {}

func init() {
	packetEPsinitLockNames()
	packetEPsprefixIndex = locking.NewMutexClass(reflect.TypeOf((*packetEPsRWMutex)(nil)).Elem(), packetEPslockNames)
}

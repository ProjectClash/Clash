package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type packetsPendingLinkResolutionMutex struct {
	mu sync.Mutex
}

var packetsPendingLinkResolutionprefixIndex *locking.MutexClass

var packetsPendingLinkResolutionlockNames []string

type packetsPendingLinkResolutionlockNameIndex int

const ()

func (m *packetsPendingLinkResolutionMutex) Lock() {
	locking.AddGLock(packetsPendingLinkResolutionprefixIndex, -1)
	m.mu.Lock()
}

func (m *packetsPendingLinkResolutionMutex) NestedLock(i packetsPendingLinkResolutionlockNameIndex) {
	locking.AddGLock(packetsPendingLinkResolutionprefixIndex, int(i))
	m.mu.Lock()
}

func (m *packetsPendingLinkResolutionMutex) Unlock() {
	locking.DelGLock(packetsPendingLinkResolutionprefixIndex, -1)
	m.mu.Unlock()
}

func (m *packetsPendingLinkResolutionMutex) NestedUnlock(i packetsPendingLinkResolutionlockNameIndex) {
	locking.DelGLock(packetsPendingLinkResolutionprefixIndex, int(i))
	m.mu.Unlock()
}

func packetsPendingLinkResolutioninitLockNames() {}

func init() {
	packetsPendingLinkResolutioninitLockNames()
	packetsPendingLinkResolutionprefixIndex = locking.NewMutexClass(reflect.TypeOf((*packetsPendingLinkResolutionMutex)(nil)).Elem(), packetsPendingLinkResolutionlockNames)
}

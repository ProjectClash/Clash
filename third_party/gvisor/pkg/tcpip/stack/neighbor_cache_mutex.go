package stack

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type neighborCacheRWMutex struct {
	mu sync.RWMutex
}

var neighborCachelockNames []string

type neighborCachelockNameIndex int

const ()

func (m *neighborCacheRWMutex) Lock() {
	locking.AddGLock(neighborCacheprefixIndex, -1)
	m.mu.Lock()
}

func (m *neighborCacheRWMutex) NestedLock(i neighborCachelockNameIndex) {
	locking.AddGLock(neighborCacheprefixIndex, int(i))
	m.mu.Lock()
}

func (m *neighborCacheRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(neighborCacheprefixIndex, -1)
}

func (m *neighborCacheRWMutex) NestedUnlock(i neighborCachelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(neighborCacheprefixIndex, int(i))
}

func (m *neighborCacheRWMutex) RLock() {
	locking.AddGLock(neighborCacheprefixIndex, -1)
	m.mu.RLock()
}

func (m *neighborCacheRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(neighborCacheprefixIndex, -1)
}

func (m *neighborCacheRWMutex) RLockBypass() {
	m.mu.RLock()
}

func (m *neighborCacheRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

func (m *neighborCacheRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var neighborCacheprefixIndex *locking.MutexClass

func neighborCacheinitLockNames() {}

func init() {
	neighborCacheinitLockNames()
	neighborCacheprefixIndex = locking.NewMutexClass(reflect.TypeOf((*neighborCacheRWMutex)(nil)).Elem(), neighborCachelockNames)
}

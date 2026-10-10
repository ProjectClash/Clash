package fdbased

import (
	"reflect"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/sync/locking"
)

type processorMutex struct {
	mu sync.Mutex
}

var processorprefixIndex *locking.MutexClass

var processorlockNames []string

type processorlockNameIndex int

const ()

func (m *processorMutex) Lock() {
	locking.AddGLock(processorprefixIndex, -1)
	m.mu.Lock()
}

func (m *processorMutex) NestedLock(i processorlockNameIndex) {
	locking.AddGLock(processorprefixIndex, int(i))
	m.mu.Lock()
}

func (m *processorMutex) Unlock() {
	locking.DelGLock(processorprefixIndex, -1)
	m.mu.Unlock()
}

func (m *processorMutex) NestedUnlock(i processorlockNameIndex) {
	locking.DelGLock(processorprefixIndex, int(i))
	m.mu.Unlock()
}

func processorinitLockNames() {}

func init() {
	processorinitLockNames()
	processorprefixIndex = locking.NewMutexClass(reflect.TypeOf((*processorMutex)(nil)).Elem(), processorlockNames)
}

package locking

import (
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/gohacks"
	"github.com/metacubex/gvisor/pkg/sync"
)

const (
	goroutineLocksShardOrder = 0
)

type goroutineLocksHasher struct {
	goroutineLocksdefaultHasher
}

type goroutineLocksdefaultHasher struct {
	fn   func(unsafe.Pointer, uintptr) uintptr
	seed uintptr
}

func (h *goroutineLocksdefaultHasher) Init() {
	h.fn = sync.MapKeyHasher(map[int64]*goroutineLocks(nil))
	h.seed = sync.RandUintptr()
}

func (h *goroutineLocksdefaultHasher) Hash(key int64) uintptr {
	return h.fn(gohacks.Noescape(unsafe.Pointer(&key)), h.seed)
}

var goroutineLockshasher goroutineLocksHasher

func init() {
	goroutineLockshasher.Init()
}

type goroutineLocksAtomicPtrMap struct {
	shards [1 << goroutineLocksShardOrder]goroutineLocksapmShard
}

func (m *goroutineLocksAtomicPtrMap) shard(hash uintptr) *goroutineLocksapmShard {
	const indexLSB = unsafe.Sizeof(uintptr(0))*8 - goroutineLocksShardOrder
	index := hash >> indexLSB
	return (*goroutineLocksapmShard)(unsafe.Pointer(uintptr(unsafe.Pointer(&m.shards)) + (index * unsafe.Sizeof(goroutineLocksapmShard{}))))
}

type goroutineLocksapmShard struct {
	goroutineLocksapmShardMutationData
	_ [goroutineLocksapmShardMutationDataPadding]byte
	goroutineLocksapmShardLookupData
	_ [goroutineLocksapmShardLookupDataPadding]byte
}

type goroutineLocksapmShardMutationData struct {
	dirtyMu  sync.Mutex
	dirty    uintptr
	count    uintptr
	rehashMu sync.Mutex
}

type goroutineLocksapmShardLookupData struct {
	seq   sync.SeqCount
	slots unsafe.Pointer
	mask  uintptr
}

const (
	goroutineLockscacheLineBytes = 64
	goroutineLocksapmEnablePadding = (goroutineLocksShardOrder + 63) >> 6
	goroutineLocksapmShardMutationDataRequiredPadding = goroutineLockscacheLineBytes - (((unsafe.Sizeof(goroutineLocksapmShardMutationData{}) - 1) % goroutineLockscacheLineBytes) + 1)
	goroutineLocksapmShardMutationDataPadding         = goroutineLocksapmEnablePadding * goroutineLocksapmShardMutationDataRequiredPadding
	goroutineLocksapmShardLookupDataRequiredPadding   = goroutineLockscacheLineBytes - (((unsafe.Sizeof(goroutineLocksapmShardLookupData{}) - 1) % goroutineLockscacheLineBytes) + 1)
	goroutineLocksapmShardLookupDataPadding           = goroutineLocksapmEnablePadding * goroutineLocksapmShardLookupDataRequiredPadding

	goroutineLocksapmRehashThresholdNum    = 2
	goroutineLocksapmRehashThresholdDen    = 3
	goroutineLocksapmExpansionThresholdNum = 1
	goroutineLocksapmExpansionThresholdDen = 6
)

type goroutineLocksapmSlot struct {
	val unsafe.Pointer
	key int64
}

func goroutineLocksapmSlotAt(slots unsafe.Pointer, pos uintptr) *goroutineLocksapmSlot {
	return (*goroutineLocksapmSlot)(unsafe.Pointer(uintptr(slots) + pos*unsafe.Sizeof(goroutineLocksapmSlot{})))
}

var goroutineLockstombstoneObj byte

func goroutineLockstombstone() unsafe.Pointer {
	return unsafe.Pointer(&goroutineLockstombstoneObj)
}

var goroutineLocksevacuatedObj byte

func goroutineLocksevacuated() unsafe.Pointer {
	return unsafe.Pointer(&goroutineLocksevacuatedObj)
}

func (m *goroutineLocksAtomicPtrMap) Load(key int64) *goroutineLocks {
	hash := goroutineLockshasher.Hash(key)
	shard := m.shard(hash)

retry:
	epoch := shard.seq.BeginRead()
	slots := atomic.LoadPointer(&shard.slots)
	mask := atomic.LoadUintptr(&shard.mask)
	if !shard.seq.ReadOk(epoch) {
		goto retry
	}
	if slots == nil {
		return nil
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := goroutineLocksapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {

			return nil
		}
		if slotVal == goroutineLocksevacuated() {

			goto retry
		}
		if slot.key == key {
			if slotVal == goroutineLockstombstone() {
				return nil
			}
			return (*goroutineLocks)(slotVal)
		}
		i = (i + inc) & mask
		inc++
	}
}

func (m *goroutineLocksAtomicPtrMap) Store(key int64, val *goroutineLocks) {
	m.maybeCompareAndSwap(key, false, nil, val)
}

func (m *goroutineLocksAtomicPtrMap) Swap(key int64, val *goroutineLocks) *goroutineLocks {
	return m.maybeCompareAndSwap(key, false, nil, val)
}

func (m *goroutineLocksAtomicPtrMap) CompareAndSwap(key int64, oldVal, newVal *goroutineLocks) *goroutineLocks {
	return m.maybeCompareAndSwap(key, true, oldVal, newVal)
}

func (m *goroutineLocksAtomicPtrMap) maybeCompareAndSwap(key int64, compare bool, typedOldVal, typedNewVal *goroutineLocks) *goroutineLocks {
	hash := goroutineLockshasher.Hash(key)
	shard := m.shard(hash)
	oldVal := goroutineLockstombstone()
	if typedOldVal != nil {
		oldVal = unsafe.Pointer(typedOldVal)
	}
	newVal := goroutineLockstombstone()
	if typedNewVal != nil {
		newVal = unsafe.Pointer(typedNewVal)
	}

retry:
	epoch := shard.seq.BeginRead()
	slots := atomic.LoadPointer(&shard.slots)
	mask := atomic.LoadUintptr(&shard.mask)
	if !shard.seq.ReadOk(epoch) {
		goto retry
	}
	if slots == nil {
		if (compare && oldVal != goroutineLockstombstone()) || newVal == goroutineLockstombstone() {
			return nil
		}

		shard.rehash(nil)
		goto retry
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := goroutineLocksapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			if (compare && oldVal != goroutineLockstombstone()) || newVal == goroutineLockstombstone() {
				return nil
			}

			shard.dirtyMu.Lock()
			slotVal = atomic.LoadPointer(&slot.val)
			if slotVal == nil {

				if dirty, capacity := shard.dirty+1, mask+1; dirty*goroutineLocksapmRehashThresholdDen >= capacity*goroutineLocksapmRehashThresholdNum {
					shard.dirtyMu.Unlock()
					shard.rehash(slots)
					goto retry
				}
				slot.key = key
				atomic.StorePointer(&slot.val, newVal)
				shard.dirty++
				atomic.AddUintptr(&shard.count, 1)
				shard.dirtyMu.Unlock()
				return nil
			}

			shard.dirtyMu.Unlock()
		}
		if slotVal == goroutineLocksevacuated() {

			goto retry
		}
		if slot.key == key {

			for {
				if (compare && oldVal != slotVal) || newVal == slotVal {
					if slotVal == goroutineLockstombstone() {
						return nil
					}
					return (*goroutineLocks)(slotVal)
				}
				if atomic.CompareAndSwapPointer(&slot.val, slotVal, newVal) {
					if slotVal == goroutineLockstombstone() {
						atomic.AddUintptr(&shard.count, 1)
						return nil
					}
					if newVal == goroutineLockstombstone() {
						atomic.AddUintptr(&shard.count, ^uintptr(0))
					}
					return (*goroutineLocks)(slotVal)
				}
				slotVal = atomic.LoadPointer(&slot.val)
				if slotVal == goroutineLocksevacuated() {
					goto retry
				}
			}
		}

		i = (i + inc) & mask
		inc++
	}
}

// rehash is marked nosplit to avoid preemption during table copying.
//
//go:nosplit
func (shard *goroutineLocksapmShard) rehash(oldSlots unsafe.Pointer) {
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()

	if shard.slots != oldSlots {

		return
	}

	newSize := uintptr(8)
	if oldSlots != nil {
		oldSize := shard.mask + 1
		newSize = oldSize
		if count := atomic.LoadUintptr(&shard.count) + 1; count*goroutineLocksapmExpansionThresholdDen > oldSize*goroutineLocksapmExpansionThresholdNum {
			newSize *= 2
		}
	}

	newSlotsSlice := make([]goroutineLocksapmSlot, newSize)
	newSlots := unsafe.Pointer(&newSlotsSlice[0])
	newMask := newSize - 1

	shard.dirtyMu.Lock()
	shard.seq.BeginWrite()

	if oldSlots != nil {
		realCount := uintptr(0)

		oldMask := shard.mask
		for i := uintptr(0); i <= oldMask; i++ {
			oldSlot := goroutineLocksapmSlotAt(oldSlots, i)
			val := atomic.SwapPointer(&oldSlot.val, goroutineLocksevacuated())
			if val == nil || val == goroutineLockstombstone() {
				continue
			}
			hash := goroutineLockshasher.Hash(oldSlot.key)
			j := hash & newMask
			inc := uintptr(1)
			for {
				newSlot := goroutineLocksapmSlotAt(newSlots, j)
				if newSlot.val == nil {
					newSlot.val = val
					newSlot.key = oldSlot.key
					break
				}
				j = (j + inc) & newMask
				inc++
			}
			realCount++
		}

		shard.dirty = realCount
	}

	atomic.StorePointer(&shard.slots, newSlots)
	atomic.StoreUintptr(&shard.mask, newMask)

	shard.seq.EndWrite()
	shard.dirtyMu.Unlock()
}

func (m *goroutineLocksAtomicPtrMap) Range(f func(key int64, val *goroutineLocks) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]
		if !shard.doRange(f) {
			return
		}
	}
}

func (shard *goroutineLocksapmShard) doRange(f func(key int64, val *goroutineLocks) bool) bool {

	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()
	slots := shard.slots
	if slots == nil {
		return true
	}
	mask := shard.mask
	for i := uintptr(0); i <= mask; i++ {
		slot := goroutineLocksapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil || slotVal == goroutineLockstombstone() {
			continue
		}
		if !f(slot.key, (*goroutineLocks)(slotVal)) {
			return false
		}
	}
	return true
}

func (m *goroutineLocksAtomicPtrMap) RangeRepeatable(f func(key int64, val *goroutineLocks) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]

	retry:
		epoch := shard.seq.BeginRead()
		slots := atomic.LoadPointer(&shard.slots)
		mask := atomic.LoadUintptr(&shard.mask)
		if !shard.seq.ReadOk(epoch) {
			goto retry
		}
		if slots == nil {
			continue
		}

		for i := uintptr(0); i <= mask; i++ {
			slot := goroutineLocksapmSlotAt(slots, i)
			slotVal := atomic.LoadPointer(&slot.val)
			if slotVal == goroutineLocksevacuated() {
				goto retry
			}
			if slotVal == nil || slotVal == goroutineLockstombstone() {
				continue
			}
			if !f(slot.key, (*goroutineLocks)(slotVal)) {
				return
			}
		}
	}
}

package locking

import (
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/gohacks"
	"github.com/metacubex/gvisor/pkg/sync"
)

const (
	ancestorsShardOrder = 0
)

type ancestorsHasher struct {
	ancestorsdefaultHasher
}

type ancestorsdefaultHasher struct {
	fn   func(unsafe.Pointer, uintptr) uintptr
	seed uintptr
}

func (h *ancestorsdefaultHasher) Init() {
	h.fn = sync.MapKeyHasher(map[*MutexClass]*string(nil))
	h.seed = sync.RandUintptr()
}

func (h *ancestorsdefaultHasher) Hash(key *MutexClass) uintptr {
	return h.fn(gohacks.Noescape(unsafe.Pointer(&key)), h.seed)
}

var ancestorshasher ancestorsHasher

func init() {
	ancestorshasher.Init()
}

type ancestorsAtomicPtrMap struct {
	shards [1 << ancestorsShardOrder]ancestorsapmShard
}

func (m *ancestorsAtomicPtrMap) shard(hash uintptr) *ancestorsapmShard {
	const indexLSB = unsafe.Sizeof(uintptr(0))*8 - ancestorsShardOrder
	index := hash >> indexLSB
	return (*ancestorsapmShard)(unsafe.Pointer(uintptr(unsafe.Pointer(&m.shards)) + (index * unsafe.Sizeof(ancestorsapmShard{}))))
}

type ancestorsapmShard struct {
	ancestorsapmShardMutationData
	_ [ancestorsapmShardMutationDataPadding]byte
	ancestorsapmShardLookupData
	_ [ancestorsapmShardLookupDataPadding]byte
}

type ancestorsapmShardMutationData struct {
	dirtyMu  sync.Mutex
	dirty    uintptr
	count    uintptr
	rehashMu sync.Mutex
}

type ancestorsapmShardLookupData struct {
	seq   sync.SeqCount
	slots unsafe.Pointer
	mask  uintptr
}

const (
	ancestorscacheLineBytes = 64
	ancestorsapmEnablePadding = (ancestorsShardOrder + 63) >> 6
	ancestorsapmShardMutationDataRequiredPadding = ancestorscacheLineBytes - (((unsafe.Sizeof(ancestorsapmShardMutationData{}) - 1) % ancestorscacheLineBytes) + 1)
	ancestorsapmShardMutationDataPadding         = ancestorsapmEnablePadding * ancestorsapmShardMutationDataRequiredPadding
	ancestorsapmShardLookupDataRequiredPadding   = ancestorscacheLineBytes - (((unsafe.Sizeof(ancestorsapmShardLookupData{}) - 1) % ancestorscacheLineBytes) + 1)
	ancestorsapmShardLookupDataPadding           = ancestorsapmEnablePadding * ancestorsapmShardLookupDataRequiredPadding

	ancestorsapmRehashThresholdNum    = 2
	ancestorsapmRehashThresholdDen    = 3
	ancestorsapmExpansionThresholdNum = 1
	ancestorsapmExpansionThresholdDen = 6
)

type ancestorsapmSlot struct {
	val unsafe.Pointer
	key *MutexClass
}

func ancestorsapmSlotAt(slots unsafe.Pointer, pos uintptr) *ancestorsapmSlot {
	return (*ancestorsapmSlot)(unsafe.Pointer(uintptr(slots) + pos*unsafe.Sizeof(ancestorsapmSlot{})))
}

var ancestorstombstoneObj byte

func ancestorstombstone() unsafe.Pointer {
	return unsafe.Pointer(&ancestorstombstoneObj)
}

var ancestorsevacuatedObj byte

func ancestorsevacuated() unsafe.Pointer {
	return unsafe.Pointer(&ancestorsevacuatedObj)
}

func (m *ancestorsAtomicPtrMap) Load(key *MutexClass) *string {
	hash := ancestorshasher.Hash(key)
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
		slot := ancestorsapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {

			return nil
		}
		if slotVal == ancestorsevacuated() {

			goto retry
		}
		if slot.key == key {
			if slotVal == ancestorstombstone() {
				return nil
			}
			return (*string)(slotVal)
		}
		i = (i + inc) & mask
		inc++
	}
}

func (m *ancestorsAtomicPtrMap) Store(key *MutexClass, val *string) {
	m.maybeCompareAndSwap(key, false, nil, val)
}

func (m *ancestorsAtomicPtrMap) Swap(key *MutexClass, val *string) *string {
	return m.maybeCompareAndSwap(key, false, nil, val)
}

func (m *ancestorsAtomicPtrMap) CompareAndSwap(key *MutexClass, oldVal, newVal *string) *string {
	return m.maybeCompareAndSwap(key, true, oldVal, newVal)
}

func (m *ancestorsAtomicPtrMap) maybeCompareAndSwap(key *MutexClass, compare bool, typedOldVal, typedNewVal *string) *string {
	hash := ancestorshasher.Hash(key)
	shard := m.shard(hash)
	oldVal := ancestorstombstone()
	if typedOldVal != nil {
		oldVal = unsafe.Pointer(typedOldVal)
	}
	newVal := ancestorstombstone()
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
		if (compare && oldVal != ancestorstombstone()) || newVal == ancestorstombstone() {
			return nil
		}

		shard.rehash(nil)
		goto retry
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := ancestorsapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			if (compare && oldVal != ancestorstombstone()) || newVal == ancestorstombstone() {
				return nil
			}

			shard.dirtyMu.Lock()
			slotVal = atomic.LoadPointer(&slot.val)
			if slotVal == nil {

				if dirty, capacity := shard.dirty+1, mask+1; dirty*ancestorsapmRehashThresholdDen >= capacity*ancestorsapmRehashThresholdNum {
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
		if slotVal == ancestorsevacuated() {

			goto retry
		}
		if slot.key == key {

			for {
				if (compare && oldVal != slotVal) || newVal == slotVal {
					if slotVal == ancestorstombstone() {
						return nil
					}
					return (*string)(slotVal)
				}
				if atomic.CompareAndSwapPointer(&slot.val, slotVal, newVal) {
					if slotVal == ancestorstombstone() {
						atomic.AddUintptr(&shard.count, 1)
						return nil
					}
					if newVal == ancestorstombstone() {
						atomic.AddUintptr(&shard.count, ^uintptr(0))
					}
					return (*string)(slotVal)
				}
				slotVal = atomic.LoadPointer(&slot.val)
				if slotVal == ancestorsevacuated() {
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
func (shard *ancestorsapmShard) rehash(oldSlots unsafe.Pointer) {
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()

	if shard.slots != oldSlots {

		return
	}

	newSize := uintptr(8)
	if oldSlots != nil {
		oldSize := shard.mask + 1
		newSize = oldSize
		if count := atomic.LoadUintptr(&shard.count) + 1; count*ancestorsapmExpansionThresholdDen > oldSize*ancestorsapmExpansionThresholdNum {
			newSize *= 2
		}
	}

	newSlotsSlice := make([]ancestorsapmSlot, newSize)
	newSlots := unsafe.Pointer(&newSlotsSlice[0])
	newMask := newSize - 1

	shard.dirtyMu.Lock()
	shard.seq.BeginWrite()

	if oldSlots != nil {
		realCount := uintptr(0)

		oldMask := shard.mask
		for i := uintptr(0); i <= oldMask; i++ {
			oldSlot := ancestorsapmSlotAt(oldSlots, i)
			val := atomic.SwapPointer(&oldSlot.val, ancestorsevacuated())
			if val == nil || val == ancestorstombstone() {
				continue
			}
			hash := ancestorshasher.Hash(oldSlot.key)
			j := hash & newMask
			inc := uintptr(1)
			for {
				newSlot := ancestorsapmSlotAt(newSlots, j)
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

func (m *ancestorsAtomicPtrMap) Range(f func(key *MutexClass, val *string) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]
		if !shard.doRange(f) {
			return
		}
	}
}

func (shard *ancestorsapmShard) doRange(f func(key *MutexClass, val *string) bool) bool {

	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()
	slots := shard.slots
	if slots == nil {
		return true
	}
	mask := shard.mask
	for i := uintptr(0); i <= mask; i++ {
		slot := ancestorsapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil || slotVal == ancestorstombstone() {
			continue
		}
		if !f(slot.key, (*string)(slotVal)) {
			return false
		}
	}
	return true
}

func (m *ancestorsAtomicPtrMap) RangeRepeatable(f func(key *MutexClass, val *string) bool) {
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
			slot := ancestorsapmSlotAt(slots, i)
			slotVal := atomic.LoadPointer(&slot.val)
			if slotVal == ancestorsevacuated() {
				goto retry
			}
			if slotVal == nil || slotVal == ancestorstombstone() {
				continue
			}
			if !f(slot.key, (*string)(slotVal)) {
				return
			}
		}
	}
}

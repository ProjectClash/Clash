//go:build darwin

package tun

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func goRegionRecycleDrainForTest(t *testing.T) {
	t.Helper()
	drain := func() {
		goRegionRecycle.access.Lock()
		defer goRegionRecycle.access.Unlock()
		for size, bases := range goRegionRecycle.free {
			for _, base := range bases {
				if err := unix.Munmap(unsafe.Slice(base, size)); err != nil {
					_ = unix.MunmapPtr(unsafe.Pointer(base), uintptr(size))
				}
			}
		}
		goRegionRecycle.free = nil
		goRegionRecycle.held = 0
		goRegionRecycle.regions = 0
		goRegionRecycle.notKept = 0
	}
	limit := goRegionRecycleLimit
	drain()
	t.Cleanup(func() {
		drain()
		goRegionRecycleLimit = limit
	})
}

func regionStillReserved(t *testing.T, base *byte, size int) bool {
	t.Helper()
	_, _, errno := unix.Syscall(unix.SYS_MSYNC, uintptr(unsafe.Pointer(base)), uintptr(size), uintptr(unix.MS_ASYNC))
	switch errno {
	case 0:
		return true
	case unix.ENOMEM:
		return false
	default:
		t.Fatalf("msync: %v", errno)
		return false
	}
}

func allZero(memory []byte) bool {
	for _, b := range memory {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestARegionGivenBackKeepsItsAddressAndComesBackZeroed(t *testing.T) {
	goRegionRecycleDrainForTest(t)
	size := 4 * goPageSize
	memory := goRegionMap(size)
	for i := range memory {
		memory[i] = 0xab
	}
	base := unsafe.SliceData(memory)
	goRegionUnmap(memory)
	if !regionStillReserved(t, base, size) {
		t.Fatal("the region's address was given back")
	}
	again := goRegionMap(size)
	if unsafe.SliceData(again) != base || len(again) != size {
		t.Fatalf("the next region is %p (%d bytes), not the one given back at %p", unsafe.SliceData(again), len(again), base)
	}
	if !allZero(again) {
		t.Fatal("a recycled region came back with the old contents")
	}
	goRegionUnmap(again)
}

func TestTheRecycleTableKeepsAtMostItsLimit(t *testing.T) {
	goRegionRecycleDrainForTest(t)
	size := 2 * goPageSize
	goRegionRecycleLimit = 2 * size
	regions := [][]byte{goRegionMap(size), goRegionMap(size), goRegionMap(size)}
	for _, region := range regions {
		goRegionUnmap(region)
	}
	goRegionRecycle.access.Lock()
	held, kept := goRegionRecycle.held, len(goRegionRecycle.free[size])
	goRegionRecycle.access.Unlock()
	if held != 2*size || kept != 2 {
		t.Fatalf("the table holds %d bytes in %d region(s), want %d in 2", held, kept, 2*size)
	}
	if regions, bytes, past := GoRegionsKept(); regions != 2 || bytes != int64(2*size) || past != 1 {
		t.Fatalf("GoRegionsKept says %d region(s), %d bytes, %d not kept; want 2, %d, 1", regions, bytes, past, 2*size)
	}
}

func TestAClosedPoolsChunkIsTheNextPoolsChunk(t *testing.T) {
	goRegionRecycleDrainForTest(t)
	first := newGoSlabPool(nil, 8)
	slab := first.acquire()
	base := uintptr(unsafe.Pointer(slab))
	first.release(slab)
	first.close()
	if !regionStillReserved(t, (*byte)(unsafe.Pointer(slab)), goSlabChunkSize) {
		t.Fatal("the closed pool's chunk was unmapped")
	}
	second := newGoSlabPool(nil, 8)
	defer second.close()
	again := second.acquire()
	defer second.release(again)
	if got := uintptr(unsafe.Pointer(again)); got != base {
		t.Fatalf("the next pool's first slab is at %#x, not in the chunk the closed pool left at %#x", got, base)
	}
	if !allZero(again[:]) {
		t.Fatal("the next pool's slab came with the closed pool's data")
	}
}

func TestReadSlotsReconfiguredKeepTheirRegionsAddress(t *testing.T) {
	goRegionRecycleDrainForTest(t)
	var slots goReadSlots
	slots.configure(4, goPageSize)
	slots.slot(0)
	base := unsafe.SliceData(slots.region)
	size := len(slots.region)
	slots.configure(8, goPageSize)
	if !regionStillReserved(t, base, size) {
		t.Fatal("the read slots' old region was unmapped")
	}
	slots.configure(4, goPageSize)
	slots.slot(0)
	if unsafe.SliceData(slots.region) != base {
		t.Fatalf("the read slots took a new region at %p, not the one they gave back at %p", unsafe.SliceData(slots.region), base)
	}
	slots.release()
}

func TestTheOldestKeptRegionIsTakenFirst(t *testing.T) {
	goRegionRecycleDrainForTest(t)
	size := 2 * goPageSize
	first, second := goRegionMap(size), goRegionMap(size)
	goRegionUnmap(first)
	goRegionUnmap(second)
	again := goRegionMap(size)
	if unsafe.SliceData(again) != unsafe.SliceData(first) {
		t.Fatalf("took %p, not the region given back first (%p)", unsafe.SliceData(again), unsafe.SliceData(first))
	}
	goRegionUnmap(again)
}

//go:build darwin || linux

package tun

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)


var goRegionRecycleLimit = 1 << 30

var goRegionRecycle struct {
	access  sync.Mutex
	free    map[int][]*byte
	held    int
	regions int
	notKept uint64
}

func GoRegionsKept() (regions int, bytes int64, notKept uint64) {
	goRegionRecycle.access.Lock()
	defer goRegionRecycle.access.Unlock()
	return goRegionRecycle.regions, int64(goRegionRecycle.held), goRegionRecycle.notKept
}

func goRegionRecycled(size int) []byte {
	goRegionRecycle.access.Lock()
	kept := goRegionRecycle.free[size]
	if len(kept) == 0 {
		goRegionRecycle.access.Unlock()
		return nil
	}
	base := kept[0]
	kept[0] = nil
	if len(kept) == 1 {
		delete(goRegionRecycle.free, size)
	} else {
		goRegionRecycle.free[size] = kept[1:]
	}
	goRegionRecycle.held -= size
	goRegionRecycle.regions--
	goRegionRecycle.access.Unlock()
	if _, err := unix.MmapPtr(-1, 0, unsafe.Pointer(base), uintptr(size), unix.PROT_READ|unix.PROT_WRITE, goRegionMapFlags|unix.MAP_FIXED); err != nil {
		goRegionRecycle.access.Lock()
		goRegionRecycle.notKept++
		goRegionRecycle.access.Unlock()
		return nil
	}
	return unsafe.Slice(base, size)
}

func goRegionKeep(memory []byte) bool {
	size := len(memory)
	base := unsafe.SliceData(memory)
	goRegionRecycle.access.Lock()
	if goRegionRecycle.held+size > goRegionRecycleLimit {
		goRegionRecycle.notKept++
		goRegionRecycle.access.Unlock()
		return false
	}
	goRegionRecycle.held += size
	goRegionRecycle.regions++
	goRegionRecycle.access.Unlock()
	_, err := unix.MmapPtr(-1, 0, unsafe.Pointer(base), uintptr(size), unix.PROT_NONE, goRegionMapFlags|unix.MAP_FIXED)
	goRegionRecycle.access.Lock()
	defer goRegionRecycle.access.Unlock()
	if err != nil {
		goRegionRecycle.held -= size
		goRegionRecycle.regions--
		goRegionRecycle.notKept++
		return false
	}
	if goRegionRecycle.free == nil {
		goRegionRecycle.free = make(map[int][]*byte)
	}
	goRegionRecycle.free[size] = append(goRegionRecycle.free[size], base)
	return true
}

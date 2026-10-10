//go:build race && arm64

package sync

import (
	stdsync "sync"
	"sync/atomic"
	"testing"
)

func TestRaceUncheckedCompareAndSwapUintptr(t *testing.T) {
	for _, start := range []uintptr{0, 7, uintptr(1) << 63, ^uintptr(0)} {
		value := start
		next := start ^ 0x1357
		if !RaceUncheckedAtomicCompareAndSwapUintptr(&value, start, next) || value != next {
			t.Fatalf("CAS(%x -> %x) left %x", start, next, value)
		}
		if RaceUncheckedAtomicCompareAndSwapUintptr(&value, start, start+1) || value != next {
			t.Fatalf("failed comparison changed %x to %x", next, value)
		}
	}
}

func TestRaceUncheckedCompareAndSwapUintptrContended(t *testing.T) {
	var value uintptr
	var wg stdsync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				for {
					old := atomic.LoadUintptr(&value)
					if RaceUncheckedAtomicCompareAndSwapUintptr(&value, old, old+1) {
						break
					}
				}
			}
		}()
	}
	wg.Wait()
	if value != 40000 {
		t.Fatalf("lost atomic increments: %d", value)
	}
}

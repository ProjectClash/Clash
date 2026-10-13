//go:build !clash_internal

package clash

import (
	"runtime"
	"sync"
	"testing"
)

func TestAReleaseBuildDoesNotSampleTheHeap(t *testing.T) {
	if memProfileRateAtInit != 0 {
		t.Fatalf("MemProfileRate = %d after initialisation, want 0 in a release build", memProfileRateAtInit)
	}
}

func TestTheFirstConfigurationDecidesHeapSampling(t *testing.T) {
	previousRate, previousOnce := runtime.MemProfileRate, heapSamplingDecided
	defer func() { runtime.MemProfileRate, heapSamplingDecided = previousRate, previousOnce }()

	runtime.MemProfileRate, heapSamplingDecided = 0, new(sync.Once)
	memoryProfilingForDebug(true)
	if runtime.MemProfileRate != defaultMemProfileRate {
		t.Fatalf("MemProfileRate = %d after a debug first configuration", runtime.MemProfileRate)
	}
	memoryProfilingForDebug(false)
	if runtime.MemProfileRate != defaultMemProfileRate {
		t.Fatal("a later configuration wrote the rate again")
	}

	runtime.MemProfileRate, heapSamplingDecided = 0, new(sync.Once)
	memoryProfilingForDebug(false)
	memoryProfilingForDebug(true)
	if runtime.MemProfileRate != 0 {
		t.Fatal("a later debug configuration started sampling mid-run")
	}
}

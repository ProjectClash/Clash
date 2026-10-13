//go:build !clash_internal

package clash

import (
	"runtime"
	"sync"
)

func init() {
	runtime.MemProfileRate = 0
	memProfileRateAtInit = runtime.MemProfileRate
}

const defaultMemProfileRate = 512 * 1024

var memProfileRateAtInit int

var heapSamplingDecided = new(sync.Once)

func memoryProfilingForDebug(debug bool) {
	heapSamplingDecided.Do(func() {
		if debug {
			runtime.MemProfileRate = defaultMemProfileRate
		}
	})
}

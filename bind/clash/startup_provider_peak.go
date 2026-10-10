package clash

import (
	"sync"
	"sync/atomic"
	"time"
)

const providerPeakSampleInterval = time.Millisecond

var footprintForSampling = MemoryFootprint

type providerPeakSampler struct {
	name string
	peak atomic.Int64
	stop chan struct{}
	done chan struct{}
}

var (
	providerPeakMu     sync.Mutex
	providerPeakActive *providerPeakSampler
)

func startProviderPeakSampling(name string) {
	providerPeakMu.Lock()
	defer providerPeakMu.Unlock()
	stopActiveProviderPeakLocked()

	sampler := &providerPeakSampler{
		name: name,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	sampler.peak.Store(footprintForSampling())
	providerPeakActive = sampler

	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(providerPeakSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sampler.stop:
				return
			case <-ticker.C:
				if current := footprintForSampling(); current > sampler.peak.Load() {
					sampler.peak.Store(current)
				}
			}
		}
	}()
}

func stopProviderPeakSampling(name string) int64 {
	providerPeakMu.Lock()
	sampler := providerPeakActive
	if sampler == nil || sampler.name != name {
		providerPeakMu.Unlock()
		return 0
	}
	providerPeakActive = nil
	providerPeakMu.Unlock()

	close(sampler.stop)
	<-sampler.done
	peak := sampler.peak.Load()
	if final := footprintForSampling(); final > peak {
		peak = final
	}
	return peak
}

func stopAnyProviderPeakSampling() {
	providerPeakMu.Lock()
	defer providerPeakMu.Unlock()
	stopActiveProviderPeakLocked()
}

func stopActiveProviderPeakLocked() {
	if providerPeakActive == nil {
		return
	}
	sampler := providerPeakActive
	providerPeakActive = nil
	close(sampler.stop)
	<-sampler.done
}

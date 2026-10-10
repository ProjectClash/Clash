package clash

import (
	"runtime"
	"runtime/debug"
	runtimemetrics "runtime/metrics"
	"sync/atomic"

	"github.com/ProjectClash/Clash/log"
)

type runtimeMemorySnapshot struct {
	availableBytes          int64
	physicalBytes           int64
	goResidentBytes         uint64
	nonGoPhysicalEstimate   int64
	heapAllocBytes          uint64
	heapInuseBytes          uint64
	stackInuseBytes         uint64
	gcCount                 uint32
	gcPauseTotalNanoseconds uint64
}

var memoryPressureEventCount atomic.Uint64

func armMemoryPressureMonitorForRuntime(profile runtimeProfile, appOnly bool, arm func()) {
	if appOnly || profile == runtimeProfileMacOSApplication {
		return
	}
	arm()
}

func currentRuntimeMemorySnapshot() runtimeMemorySnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	samples := []runtimemetrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	runtimemetrics.Read(samples)
	var total, released uint64
	if samples[0].Value.Kind() == runtimemetrics.KindUint64 {
		total = samples[0].Value.Uint64()
	}
	if samples[1].Value.Kind() == runtimemetrics.KindUint64 {
		released = samples[1].Value.Uint64()
	}
	resident := total
	if released <= total {
		resident = total - released
	}
	physical := MemoryFootprint()
	nonGo := int64(-1)
	if physical >= 0 {
		nonGo = physical
		if resident <= uint64(physical) {
			nonGo = physical - int64(resident)
		} else {
			nonGo = 0
		}
	}
	return runtimeMemorySnapshot{
		availableBytes:          availableMemory(),
		physicalBytes:           physical,
		goResidentBytes:         resident,
		nonGoPhysicalEstimate:   nonGo,
		heapAllocBytes:          stats.HeapAlloc,
		heapInuseBytes:          stats.HeapInuse,
		stackInuseBytes:         stats.StackInuse,
		gcCount:                 stats.NumGC,
		gcPauseTotalNanoseconds: stats.PauseTotalNs,
	}
}

func handleMemoryPressure() {
	handleMemoryPressureWith(MemoryFootprint(), runtimeSetupSnapshot().softMemoryLimit)
}

func handleMemoryPressureWith(footprint, softLimit int64) {
	memoryPressureEventCount.Add(1)
	refreshStartupBreadcrumbFootprint()
	if err := RecordMemoryPressureEvidence(); err != nil {
		log.Warnln("[Memory] persist pressure evidence: %v", err)
	}
	log.Warnln(
		"[Memory] critical pressure: releasing memory (footprint=%d softLimit=%d); "+
			"the notification never closes connections — the threshold machine decides that",
		footprint, softLimit)

	notifyPressureThreshold()

	debug.FreeOSMemory()
}

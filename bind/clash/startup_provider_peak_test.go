package clash

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/hub/executor"
)

type fakeFootprintCurve struct {
	values []int64
	calls  atomic.Int64
	served chan struct{}
	once   atomic.Bool
}

func (c *fakeFootprintCurve) next() int64 {
	n := c.calls.Add(1)
	if int(n) >= len(c.values) && c.once.CompareAndSwap(false, true) {
		close(c.served)
	}
	index := int(n) - 1
	if index >= len(c.values) {
		index = len(c.values) - 1
	}
	return c.values[index]
}

func installFootprintCurve(t *testing.T, values ...int64) *fakeFootprintCurve {
	t.Helper()
	curve := &fakeFootprintCurve{values: values, served: make(chan struct{})}
	previous := footprintForSampling
	footprintForSampling = curve.next
	t.Cleanup(func() { footprintForSampling = previous })
	return curve
}

func phaseTraceTail(from int) []string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	if from > len(phaseTrace) {
		return nil
	}
	return append([]string(nil), phaseTrace[from:]...)
}

func phaseTraceLength() int {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return len(phaseTrace)
}

func TestTheProvidersPeakTravelsOnItsClosingLine(t *testing.T) {
	breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	curve := installFootprintCurve(t,
		20<<20, 31<<20, 44<<20, 48<<20, 33<<20, 26<<20)
	t.Cleanup(armStartupProbes())

	start := phaseTraceLength()
	executor.StartupProbe("rule-provider-begin:reject")

	select {
	case <-curve.served:
	case <-time.After(3 * time.Second):
		t.Fatalf("the sampler asked for the footprint %d time(s) in three seconds; it is not sampling", curve.calls.Load())
	}
	executor.StartupProbe("rule-provider:reject")

	var closing string
	for _, line := range phaseTraceTail(start) {
		if strings.Contains(line, "apply:rule-provider:reject") {
			closing = line
		}
	}
	if closing == "" {
		t.Fatal("no closing line for the provider")
	}
	if !strings.Contains(closing, "peak=48.0MiB") {
		t.Fatalf("the closing line does not carry the build's high-water mark: %q", closing)
	}
}

func TestTheOpeningLineCarriesNoPeak(t *testing.T) {
	breadcrumbHome(t)
	installFootprintCurve(t, 20<<20, 21<<20)
	t.Cleanup(armStartupProbes())

	start := phaseTraceLength()
	executor.StartupProbe("rule-provider-begin:reject")

	for _, line := range phaseTraceTail(start) {
		if strings.Contains(line, "rule-provider-begin:reject") && strings.Contains(line, "peak=") {
			t.Fatalf("the opening line claims a peak before anything was built: %q", line)
		}
	}
}

func TestDisarmingStopsASamplerThatNeverGotItsClosingProbe(t *testing.T) {
	breadcrumbHome(t)
	curve := installFootprintCurve(t, 20<<20, 21<<20, 22<<20)

	disarm := armStartupProbes()
	executor.StartupProbe("rule-provider-begin:direct")
	select {
	case <-curve.served:
	case <-time.After(3 * time.Second):
		t.Fatal("sampler never ran")
	}
	disarm()

	settled := curve.calls.Load()
	time.Sleep(50 * time.Millisecond)
	if grew := curve.calls.Load() - settled; grew > 1 {
		t.Fatalf("the sampler kept running after disarm: %d more samples", grew)
	}
}

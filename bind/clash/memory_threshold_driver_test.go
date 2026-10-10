package clash

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type pressureProbeTracker struct {
	statistic.Tracker
	id     string
	closed atomic.Int64
}

func (p *pressureProbeTracker) Close() error { p.closed.Add(1); return nil }
func (p *pressureProbeTracker) ID() string   { return p.id }

func joinPressureProbe(t *testing.T, id string) *pressureProbeTracker {
	t.Helper()
	probe := &pressureProbeTracker{id: id}
	statistic.DefaultManager.Join(probe)
	t.Cleanup(func() { statistic.DefaultManager.Leave(probe) })
	return probe
}

func withThresholdMachine(t *testing.T, mode thresholdMode, limit uint64, sample pressureSample, shed bool) *pressureMachine {
	t.Helper()

	machine := newPressureMachine(mode, limit)
	pressureThresholdMu.Lock()
	if pressureThresholdStop != nil {
		close(pressureThresholdStop)
		pressureThresholdStop = nil
	}
	priorMachine := pressureThresholdMachine
	priorSample := pressureThresholdSample
	priorShed := pressureThresholdShedEnabled.Load()
	pressureThresholdMachine = machine
	pressureThresholdSample = func() pressureSample { return sample }
	pressureThresholdShedEnabled.Store(shed)
	pressureThresholdMu.Unlock()

	t.Cleanup(func() {
		pressureThresholdMu.Lock()
		pressureThresholdMachine = priorMachine
		pressureThresholdSample = priorSample
		pressureThresholdMu.Unlock()
		pressureThresholdShedEnabled.Store(priorShed)
	})
	return machine
}

func setPressureSampleForTest(sample func() pressureSample) {
	pressureThresholdMu.Lock()
	pressureThresholdSample = sample
	pressureThresholdMu.Unlock()
}

func TestReportOnlyRecordsTheTriggerAndKeepsConnections(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), false)
	probe := joinPressureProbe(t, "pressure-threshold-report-only")

	beforeTriggers := pressureThresholdTriggerCount.Load()
	beforeSheds := pressureThresholdShedCount.Load()

	interval := stepPressureThreshold(machine)

	if got := pressureThresholdTriggerCount.Load() - beforeTriggers; got != 1 {
		t.Fatalf("trigger count rose by %d, want 1; without the count a report-only run produces "+
			"no evidence at all", got)
	}
	if got := pressureThresholdShedCount.Load() - beforeSheds; got != 0 {
		t.Fatalf("shed count rose by %d in report-only mode", got)
	}
	if closed := probe.closed.Load(); closed != 0 {
		t.Fatalf("report-only mode closed %d connection(s)", closed)
	}
	if interval != pressureMinInterval {
		t.Fatalf("interval after a trigger = %v, want the fast rate", interval)
	}
}

func TestEnablingShedActuallyClosesConnections(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), true)
	probe := joinPressureProbe(t, "pressure-threshold-shed-on")

	beforeSheds := pressureThresholdShedCount.Load()
	stepPressureThreshold(machine)

	if got := pressureThresholdShedCount.Load() - beforeSheds; got != 1 {
		t.Fatalf("shed count rose by %d, want 1", got)
	}
	if closed := probe.closed.Load(); closed != 1 {
		t.Fatalf("the probe was closed %d time(s), want 1. If this is 0 the action is wired to "+
			"nothing and the whole option is decoration", closed)
	}
}

func TestSustainedEpisodeShedsOnceNotPerPoll(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), true)
	probe := joinPressureProbe(t, "pressure-threshold-sustained")

	for i := 0; i < 8; i++ {
		stepPressureThreshold(machine)
	}

	if closed := probe.closed.Load(); closed != 1 {
		t.Fatalf("eight polls of a sustained episode closed the probe %d time(s), want 1; the "+
			"trigger has to be the edge into the state, not the state", closed)
	}
}

func TestPredictedTriggersAreCountedSeparately(t *testing.T) {
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(20<<20), false)

	beforePredicted := pressureThresholdPredictedCount.Load()

	machine.notifyPressure()
	stepPressureThreshold(machine)

	setPressureSampleForTest(func() pressureSample {
		machine.baselineAt = time.Now().Add(-pressureMinInterval)
		return atUsage(44 << 20)
	})
	stepPressureThreshold(machine)

	if got := pressureThresholdPredictedCount.Load() - beforePredicted; got != 1 {
		t.Fatalf("predicted count rose by %d, want 1", got)
	}
}

func TestNotifyPressureWithNoMachineIsSafe(t *testing.T) {
	pressureThresholdMu.Lock()
	priorMachine, priorWake := pressureThresholdMachine, pressureThresholdWake
	pressureThresholdMachine, pressureThresholdWake = nil, nil
	pressureThresholdMu.Unlock()
	t.Cleanup(func() {
		pressureThresholdMu.Lock()
		pressureThresholdMachine, pressureThresholdWake = priorMachine, priorWake
		pressureThresholdMu.Unlock()
	})

	notifyPressureThreshold()
}

func TestDiagnosticsExposeTheEvidence(t *testing.T) {
	report := pressureThresholdDiagnostics()
	for _, key := range []string{
		"memoryThresholdState",
		"memoryThresholdTriggerCount",
		"memoryThresholdPredictedCount",
		"memoryThresholdShedCount",
		"memoryThresholdShedEnabled",
	} {
		if _, present := report[key]; !present {
			t.Fatalf("diagnostics omit %q; a report-only run would produce no readable evidence", key)
		}
	}
}

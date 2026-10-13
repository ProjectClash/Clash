package clash

import (
	"fmt"
	"sync"
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
		pressureSessionPacer.setActive(false)
		pressureRoundHold.set(false)
		pressureShedLayerGauge.Store(0)
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

func withShedEffects(t *testing.T, usage uint64, freePer uint64, probes []*pressureProbeTracker) (frees *atomic.Int64) {
	t.Helper()
	var mu sync.Mutex
	current := usage
	frees = new(atomic.Int64)
	priorCandidates, priorClose, priorFree, priorSettle, priorReset := pressureShedCandidates, pressureShedClose, pressureShedFree, pressureShedSettle, pressureShedResetNode
	pressureShedResetNode = func(string) {}
	setPressureSampleForTest(func() pressureSample {
		mu.Lock()
		defer mu.Unlock()
		return atUsage(current)
	})
	pressureShedCandidates = func() []shedCandidate {
		var out []shedCandidate
		for i, probe := range probes {
			if probe.closed.Load() == 0 {
				out = append(out, shedCandidate{shedView: shedView{id: probe.id, tracker: probe}, weight: int64(len(probes)-i) << 20})
			}
		}
		return out
	}
	pressureShedClose = func(c shedCandidate) {
		_ = c.tracker.Close()
		mu.Lock()
		current -= freePer
		mu.Unlock()
	}
	pressureShedFree = func() { frees.Add(1) }
	pressureShedSettle = time.Millisecond
	t.Cleanup(func() {
		pressureShedCandidates, pressureShedClose, pressureShedFree, pressureShedSettle, pressureShedResetNode = priorCandidates, priorClose, priorFree, priorSettle, priorReset
	})
	return frees
}

func pressureProbes(t *testing.T, n int) []*pressureProbeTracker {
	t.Helper()
	probes := make([]*pressureProbeTracker, n)
	for i := range probes {
		probes[i] = &pressureProbeTracker{id: fmt.Sprintf("probe-%02d", i)}
	}
	return probes
}

func TestLayerThreeClosesTheHeaviestNotEverything(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(thresholds.trigger+1), true)
	probes := pressureProbes(t, 40)
	withShedEffects(t, thresholds.trigger+1<<20, 512<<10, probes)

	beforeSheds, beforeClosed := pressureThresholdShedCount.Load(), pressureShedClosedTotal.Load()
	stepPressureThreshold(machine)

	closed := 0
	for i, probe := range probes {
		if probe.closed.Load() > 0 {
			closed++
			if i >= shedBatch {
				t.Fatalf("closed %s, which was not among the heaviest", probe.id)
			}
		}
	}
	if closed != shedBatch {
		t.Fatalf("closed %d of 40; one batch of %d brings 46 MiB back under 45 at 0.5 MiB each", closed, shedBatch)
	}
	if got := pressureThresholdShedCount.Load() - beforeSheds; got != 1 {
		t.Fatalf("shed count rose by %d, want 1", got)
	}
	if got := pressureShedClosedTotal.Load() - beforeClosed; got != uint64(shedBatch) {
		t.Fatalf("closed total rose by %d, want %d", got, shedBatch)
	}
}

func TestASustainedEpisodeDoesNotCloseEverything(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(thresholds.trigger+1), true)
	probes := pressureProbes(t, 40)
	withShedEffects(t, thresholds.trigger+1<<20, 0, probes)

	for i := 0; i < 8; i++ {
		stepPressureThreshold(machine)
	}
	closed := 0
	for _, probe := range probes {
		closed += int(probe.closed.Load())
	}
	if closed != shedBatch {
		t.Fatalf("eight polls closed %d connection(s), want one batch of %d: a batch that frees nothing "+
			"ends the episode and the next one waits out its cooldown", closed, shedBatch)
	}
}

func TestLayersOneAndTwoDriveTheHoldAndThePacer(t *testing.T) {
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(20<<20), true)
	frees := withShedEffects(t, 41<<20, 0, nil)
	t.Cleanup(func() { pressureSessionPacer.setActive(false); pressureRoundHold.set(false) })

	interval := stepPressureThreshold(machine)
	if !pressureSessionPacer.active.Load() {
		t.Fatal("41 MiB did not start pacing")
	}
	pressureRoundHold.mu.Lock()
	held := pressureRoundHold.held
	pressureRoundHold.mu.Unlock()
	if !held {
		t.Fatal("41 MiB did not hold new background rounds")
	}
	if frees.Load() != 1 {
		t.Fatalf("entering layer 1 released memory %d times, want 1", frees.Load())
	}
	if interval > pressureArmedInterval {
		t.Fatalf("pacing polls every %v; waiting sessions need a poll at least every %v", interval, pressureArmedInterval)
	}
	if pressureShedLayerGauge.Load() != 2 {
		t.Fatalf("layer gauge %d, want 2", pressureShedLayerGauge.Load())
	}

	setPressureSampleForTest(func() pressureSample { return atUsage(32 << 20) })
	for i := 0; i < 6; i++ {
		interval = stepPressureThreshold(machine)
	}
	if pressureSessionPacer.active.Load() {
		t.Fatal("32 MiB left pacing on")
	}
	if interval > pressureArmedInterval {
		t.Fatalf("layer 1 polls every %v; crossing into layer 2 must be seen within %v", interval, pressureArmedInterval)
	}

	setPressureSampleForTest(func() pressureSample { return atUsage(20 << 20) })
	stepPressureThreshold(machine)
	if pressureSessionPacer.active.Load() {
		t.Fatal("20 MiB left pacing on")
	}
	pressureRoundHold.mu.Lock()
	held = pressureRoundHold.held
	pressureRoundHold.mu.Unlock()
	if held || pressureShedLayerGauge.Load() != 0 {
		t.Fatal("20 MiB left layer 1 on")
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
		"memoryLayer",
		"memoryReleaseCount",
		"memoryPacedSessions",
		"memoryRoundHolds",
		"memoryShedEpisodes",
		"memoryShedClosedTotal",
	} {
		if _, present := report[key]; !present {
			t.Fatalf("diagnostics omit %q; a report-only run would produce no readable evidence", key)
		}
	}
}

func TestAReleaseThatGetsUnderTheLineClosesNothing(t *testing.T) {
	for _, predicted := range []bool{false, true} {
		machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(20<<20), true)
		probes := pressureProbes(t, 10)
		withShedEffects(t, 0, 0, probes)
		var released atomic.Bool
		pressureShedFree = func() { released.Store(true) }
		setPressureSampleForTest(func() pressureSample {
			if released.Load() {
				return atUsage(20 << 20)
			}
			if predicted {
				return atUsage(44 << 20)
			}
			return atUsage(46 << 20)
		})
		if predicted {
			machine.notifyPressure()
			stepPressureThreshold(machine)
			machine.baselineAt = time.Now().Add(-pressureMinInterval)
			machine.baseline = atUsage(20 << 20)
			released.Store(false)
		}
		stepPressureThreshold(machine)
		for _, probe := range probes {
			if probe.closed.Load() != 0 {
				t.Fatalf("predicted=%v: %s was closed although a release took the footprint to 20 MiB", predicted, probe.id)
			}
		}
		if !released.Load() {
			t.Fatalf("predicted=%v: nothing was released", predicted)
		}
	}
}

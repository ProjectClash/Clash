package clash

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

var (
	pressureThresholdStartMu sync.Mutex

	pressureThresholdMu      sync.Mutex
	pressureThresholdMachine *pressureMachine
	pressureThresholdWake    chan struct{}
	pressureThresholdStop    chan struct{}
	pressureThresholdExited  chan struct{}

	pressureThresholdShedEnabled atomic.Bool

	pressureThresholdTriggerCount   atomic.Uint64
	pressureThresholdPredictedCount atomic.Uint64
	pressureThresholdShedCount      atomic.Uint64
	pressureThresholdStateGauge     atomic.Uint32
	pressureShedLayerGauge          atomic.Uint32
	pressureShedClosedTotal         atomic.Uint64
	pressureShedEpisodeCount        atomic.Uint64
	pressureReleaseCount            atomic.Uint64

	pressureThresholdSample = livePressureSample
	pressureShedCandidates  = func() []shedCandidate { return rankShedCandidates(liveShedViews(), liveNodeTypes()) }
	pressureShedClose       = closeShedCandidate
	pressureShedResetNode   = resetNodeSessions
	pressureShedFree        = FreeMemory
	pressureShedSettle      = shedSettle

	pressureSessionPacer = newSessionPacer()
	pressureRoundHold    = newRoundHold()
)

func livePressureSample() pressureSample {
	sample := pressureSample{}
	if footprint := MemoryFootprint(); footprint > 0 {
		sample.usage = uint64(footprint)
	}
	if available := availableMemory(); available > 0 {
		sample.available = uint64(available)
		sample.availableKnown = true
	}
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		sample.connections++
		return true
	})
	return sample
}

func closeShedCandidate(candidate shedCandidate) {
	if candidate.tracker == nil {
		return
	}
	stalled := ""
	if candidate.stalled() {
		stalled = ", its app stopped reading"
	}
	metadata := candidate.tracker.Info().Metadata
	log.Infoln("[Memory] layer 3: closing %s %s --> %s via %s (about %d KiB%s)",
		candidate.network, metadata.SourceDetail(), metadata.RemoteAddress(), candidate.node, candidate.weight>>10, stalled)
	if closer, ok := candidate.tracker.(statistic.InboundCloser); ok {
		_ = closer.CloseInbound()
	}
	_ = candidate.tracker.Close()
}

func resetNodeSessions(node string) {
	var adapters []C.ProxyAdapter
	named := providerNodesNamed(node)
	if proxy, ok := lookupRunningProxy(node); ok {
		named = append([]C.Proxy{proxy}, named...)
	}
	for _, proxy := range named {
		if held := adapter.HeldProxy(proxy); held != nil {
			adapters = append(adapters, held.Adapter())
		}
	}
	reset := resetSessionsOf(adapters)
	log.Warnln("[Memory] layer 3: node %s was wedged by flows its apps stopped reading; reset its session (%d)", node, reset)
}

func installShedHooks(armed bool) {
	pressureSessionPacer.setActive(false)
	pressureRoundHold.set(false)
	pressureShedLayerGauge.Store(0)
	if !armed {
		tunnel.SetNewSessionGate(nil)
		provider.SetBackgroundRoundHold(nil)
		return
	}
	tunnel.SetNewSessionGate(pressureSessionPacer.wait)
	provider.SetBackgroundRoundHold(pressureRoundHold.wait)
}

func startPressureThresholdMonitor(softLimit int64, shedEnabled bool) {
	pressureThresholdStartMu.Lock()
	defer pressureThresholdStartMu.Unlock()

	pressureThresholdMu.Lock()
	priorStop, priorExited := pressureThresholdStop, pressureThresholdExited
	pressureThresholdMu.Unlock()
	if priorStop != nil {
		close(priorStop)
		<-priorExited
	}
	pressureThresholdMu.Lock()
	mode := resolveThresholdMode(softLimit, availableMemory())
	limit := uint64(0)
	if softLimit > 0 {
		limit = uint64(softLimit)
	}
	pressureThresholdMachine = newPressureMachine(mode, limit)
	pressureThresholdWake = make(chan struct{}, 1)
	pressureThresholdStop = make(chan struct{})
	pressureThresholdExited = make(chan struct{})
	wake, stop, machine, exited := pressureThresholdWake, pressureThresholdStop, pressureThresholdMachine, pressureThresholdExited
	pressureThresholdShedEnabled.Store(shedEnabled)
	pressureThresholdMu.Unlock()

	installShedHooks(mode != thresholdModeNone)
	if mode == thresholdModeNone {
		close(pressureThresholdExited)
		log.Infoln("[Memory] threshold monitor idle: neither a soft limit nor an available-memory reading")
		return
	}
	log.Infoln("[Memory] threshold monitor armed (mode=%s limit=%d shed=%v)", mode, limit, shedEnabled)

	go runPressureThresholdLoop(machine, wake, stop, exited)
}

func runPressureThresholdLoop(machine *pressureMachine, wake <-chan struct{}, stop <-chan struct{}, exited chan<- struct{}) {
	defer close(exited)
	timer := time.NewTimer(pressureMaxInterval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-wake:
		case <-timer.C:
		}
		interval := stepPressureThresholdUntil(machine, stop)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(interval)
	}
}

func stepPressureThreshold(machine *pressureMachine) time.Duration {
	return stepPressureThresholdUntil(machine, nil)
}

func stepPressureThresholdUntil(machine *pressureMachine, stop <-chan struct{}) time.Duration {
	pressureThresholdMu.Lock()
	sample := pressureThresholdSample()
	now := time.Now()
	decision := machine.step(sample, now)
	var lines shedLines
	var step shedStep
	if machine.mode != thresholdModeNone {
		lines = computeShedLines(machine.mode, machine.limit)
		step = machine.ladder.step(lines, sample, decision.predicted, now)
	}
	pressureThresholdMu.Unlock()

	pressureThresholdStateGauge.Store(uint32(decision.state))
	if decision.triggered {
		pressureThresholdTriggerCount.Add(1)
		if decision.predicted {
			pressureThresholdPredictedCount.Add(1)
		}
	}
	applyShedLayers(step, sample)

	if step.shed {
		result := runShedLayer(lines, sample, decision.predicted, step.mayClose, stop)
		pressureThresholdMu.Lock()
		machine.ladder.episodeDone(result, time.Now())
		pressureThresholdMu.Unlock()
	}

	interval := decision.interval
	if (step.release || step.pace) && interval > pressureArmedInterval {
		interval = pressureArmedInterval
	}
	return interval
}

func applyShedLayers(step shedStep, sample pressureSample) {
	if step.releaseChanged {
		pressureRoundHold.set(step.release)
		if step.release {
			log.Infoln("[Memory] layer 1 on at footprint %d MiB: releasing memory, new background test rounds wait", sample.usage>>20)
		} else {
			log.Infoln("[Memory] layer 1 off at footprint %d MiB", sample.usage>>20)
		}
	}
	if step.paceChanged {
		pressureSessionPacer.setActive(step.pace)
		if step.pace {
			log.Warnln("[Memory] layer 2 on at footprint %d MiB: new connections are paced at %d/s, none refused", sample.usage>>20, shedPaceRate)
		} else {
			log.Infoln("[Memory] layer 2 off at footprint %d MiB", sample.usage>>20)
		}
	}
	switch {
	case step.pace:
		pressureShedLayerGauge.Store(2)
	case step.release:
		pressureShedLayerGauge.Store(1)
	default:
		pressureShedLayerGauge.Store(0)
	}
	if step.freeMemory && !step.shed {
		pressureReleaseCount.Add(1)
		pressureShedFree()
	}
}

func runShedLayer(lines shedLines, sample pressureSample, predicted, mayClose bool, stop <-chan struct{}) shedEpisodeResult {
	pressureShedEpisodeCount.Add(1)
	if !pressureThresholdShedEnabled.Load() {
		log.Warnln("[Memory] layer 3 due at footprint %d MiB (report only, predicted=%v): connections kept", sample.usage>>20, predicted)
		pressureShedFree()
		return shedEpisodeResult{reason: shedReasonReportOnly}
	}
	result := runShedEpisode(lines, shedEpisodeDeps{
		sample: func() pressureSample {
			pressureThresholdMu.Lock()
			defer pressureThresholdMu.Unlock()
			return pressureThresholdSample()
		},
		candidates: pressureShedCandidates,
		closeOne:   pressureShedClose,
		resetNode:  pressureShedResetNode,
		free:       pressureShedFree,
		settle: func(time.Duration) bool {
			timer := time.NewTimer(pressureShedSettle)
			defer timer.Stop()
			select {
			case <-timer.C:
				return true
			case <-stop:
				return false
			}
		},
	}, mayClose)
	if result.closed > 0 {
		pressureThresholdShedCount.Add(1)
		pressureShedClosedTotal.Add(uint64(result.closed))
	}
	if result.reason == shedReasonReleased {
		log.Debugln("[Memory] layer 3 due at footprint %d MiB (predicted=%v): %s", sample.usage>>20, predicted, result.reason)
		return result
	}
	log.Warnln("[Memory] layer 3 at footprint %d MiB (predicted=%v): closed %d of %d connection(s), footprint %+.1f MiB after the opening release; %s",
		sample.usage>>20, predicted, result.closed, result.present, -float64(result.freed)/(1<<20), result.reason)
	return result
}

func notifyPressureThreshold() {
	pressureThresholdMu.Lock()
	machine, wake := pressureThresholdMachine, pressureThresholdWake
	if machine != nil {
		machine.notifyPressure()
	}
	pressureThresholdMu.Unlock()

	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func pressureThresholdDiagnostics() map[string]any {
	return map[string]any{
		"memoryThresholdState":          pressureState(pressureThresholdStateGauge.Load()).String(),
		"memoryThresholdTriggerCount":   pressureThresholdTriggerCount.Load(),
		"memoryThresholdPredictedCount": pressureThresholdPredictedCount.Load(),
		"memoryThresholdShedCount":      pressureThresholdShedCount.Load(),
		"memoryThresholdShedEnabled":    pressureThresholdShedEnabled.Load(),
		"memoryLayer":                   pressureShedLayerGauge.Load(),
		"memoryReleaseCount":            pressureReleaseCount.Load(),
		"memoryPaceActivations":         pressureSessionPacer.activations.Load(),
		"memoryPacedSessions":           pressureSessionPacer.paced.Load(),
		"memoryPacedMilliseconds":       pressureSessionPacer.pacedNanos.Load() / uint64(time.Millisecond),
		"memoryPacedAtMaxWait":          pressureSessionPacer.reachedMax.Load(),
		"memoryRoundHolds":              pressureRoundHold.holds.Load(),
		"memoryRoundHoldsExpired":       pressureRoundHold.expired.Load(),
		"memoryShedEpisodes":            pressureShedEpisodeCount.Load(),
		"memoryShedClosedTotal":         pressureShedClosedTotal.Load(),
	}
}

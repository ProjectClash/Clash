package clash

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/log"
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

	pressureThresholdSample = livePressureSample
	pressureThresholdShed   = closeTrackedConnectionsForPressure
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
	return sample
}

func closeTrackedConnectionsForPressure() int {
	closed := 0
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		_ = tracker.Close()
		closed++
		return true
	})
	return closed
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
		interval := stepPressureThreshold(machine)
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
	pressureThresholdMu.Lock()
	decision := machine.step(pressureThresholdSample(), time.Now())
	pressureThresholdMu.Unlock()

	pressureThresholdStateGauge.Store(uint32(decision.state))
	if !decision.triggered {
		return decision.interval
	}

	pressureThresholdTriggerCount.Add(1)
	if decision.predicted {
		pressureThresholdPredictedCount.Add(1)
	}

	if !pressureThresholdShedEnabled.Load() {
		log.Warnln(
			"[Memory] threshold %s (report only, predicted=%v): connections kept. This is the "+
				"count that decides whether shedding is worth enabling",
			decision.state, decision.predicted)
		return decision.interval
	}

	closed := pressureThresholdShed()
	pressureThresholdShedCount.Add(1)
	log.Warnln("[Memory] threshold %s (predicted=%v): closed %d tracked connection(s)",
		decision.state, decision.predicted, closed)
	return decision.interval
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
	}
}

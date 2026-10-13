package clash

import (
	"fmt"
	"time"
)

const (
	pressureMinInterval   = 100 * time.Millisecond
	pressureArmedInterval = time.Second
	pressureMaxInterval   = 10 * time.Second

	pressureSafetyMargin = 5 * 1024 * 1024

	pressureAvailableMarginMin = 32 * 1024 * 1024
	pressureAvailableMarginMax = 128 * 1024 * 1024
)

type pressureState uint8

const (
	pressureStateNormal pressureState = iota
	pressureStateArmed
	pressureStateTriggered
)

func (s pressureState) String() string {
	switch s {
	case pressureStateNormal:
		return "normal"
	case pressureStateArmed:
		return "armed"
	case pressureStateTriggered:
		return "triggered"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

type thresholdMode uint8

const (
	thresholdModeNone thresholdMode = iota
	thresholdModeLimit
	thresholdModeAvailable
)

func (m thresholdMode) String() string {
	switch m {
	case thresholdModeLimit:
		return "limit"
	case thresholdModeAvailable:
		return "available"
	default:
		return "none"
	}
}

type pressureSample struct {
	usage          uint64
	available      uint64
	availableKnown bool
	connections    int
}

type pressureThresholds struct {
	trigger uint64
	armed   uint64
	resume  uint64
}

func resolveThresholdMode(softLimit int64, available int64) thresholdMode {
	if softLimit > 0 {
		return thresholdModeLimit
	}
	if available > 0 {
		return thresholdModeAvailable
	}
	return thresholdModeNone
}

func computeLimitThresholds(limit, safetyMargin uint64) pressureThresholds {
	triggerMargin := min(safetyMargin, limit)
	armedMargin := min(triggerMargin*2, limit)
	resumeMargin := min(triggerMargin*4, limit)
	return pressureThresholds{
		trigger: limit - triggerMargin,
		armed:   limit - armedMargin,
		resume:  limit - resumeMargin,
	}
}

func computeAvailableThresholds(sample pressureSample) pressureThresholds {
	var triggerMargin uint64
	switch {
	case sample.usage == 0:
		triggerMargin = pressureAvailableMarginMin
	default:
		triggerMargin = max(pressureAvailableMarginMin, min(sample.usage/4, pressureAvailableMarginMax))
	}
	return pressureThresholds{
		trigger: triggerMargin,
		armed:   triggerMargin * 2,
		resume:  triggerMargin * 4,
	}
}

func nextPressureState(current pressureState, shouldTrigger, shouldArm, shouldStayTriggered bool) pressureState {
	if current == pressureStateTriggered {
		if shouldStayTriggered {
			return pressureStateTriggered
		}
		return pressureStateNormal
	}
	if shouldTrigger {
		return pressureStateTriggered
	}
	if shouldArm {
		return pressureStateArmed
	}
	return pressureStateNormal
}

type pressureMachine struct {
	mode  thresholdMode
	limit uint64

	state            pressureState
	currentInterval  time.Duration
	forceMinInterval bool

	triggeredExitFloor uint64

	pendingBaseline bool
	baseline        pressureSample
	baselineAt      time.Time

	ladder shedLadder
}

type pressureDecision struct {
	state     pressureState
	interval  time.Duration
	triggered bool
	predicted bool
}

func newPressureMachine(mode thresholdMode, limit uint64) *pressureMachine {
	return &pressureMachine{mode: mode, limit: limit}
}

func (m *pressureMachine) notifyPressure() {
	m.forceMinInterval = true
	m.pendingBaseline = true
}

func (m *pressureMachine) step(sample pressureSample, now time.Time) pressureDecision {
	if m.mode == thresholdModeNone {
		return pressureDecision{state: pressureStateNormal, interval: pressureMaxInterval}
	}

	if m.pendingBaseline {
		m.baseline = sample
		m.baselineAt = now
		m.pendingBaseline = false
	}

	previous := m.state
	m.state = m.nextState(sample)
	if m.state == pressureStateNormal {
		m.forceMinInterval = false
		if !m.baselineAt.IsZero() && now.Sub(m.baselineAt) > pressureMaxInterval {
			m.baselineAt = time.Time{}
		}
	}

	decision := pressureDecision{
		triggered: previous != pressureStateTriggered && m.state == pressureStateTriggered,
	}
	if decision.triggered {
		m.triggeredExitFloor = 0
	}

	if !decision.triggered && m.state != pressureStateTriggered && m.mode == thresholdModeLimit && m.limit > 0 &&
		!m.baselineAt.IsZero() && sample.usage > m.baseline.usage && sample.usage < m.limit {
		elapsed := now.Sub(m.baselineAt)
		if elapsed >= pressureMinInterval/2 {
			growth := sample.usage - m.baseline.usage
			ratePerSecond := float64(growth) / elapsed.Seconds()
			if ratePerSecond > 0 {
				headroom := m.limit - sample.usage
				secondsUntilLimit := float64(headroom) / ratePerSecond
				if secondsUntilLimit < pressureMinInterval.Seconds() {
					m.state = pressureStateTriggered
					decision.triggered = true
					decision.predicted = true
					m.triggeredExitFloor = sample.usage
				}
			}
		}
	}

	decision.state = m.state
	decision.interval = m.intervalForState()
	return decision
}

func (m *pressureMachine) nextState(sample pressureSample) pressureState {
	switch m.mode {
	case thresholdModeLimit:
		thresholds := computeLimitThresholds(m.limit, pressureSafetyMargin)
		stayFloor := thresholds.resume
		if m.state == pressureStateTriggered && m.triggeredExitFloor > 0 && m.triggeredExitFloor < stayFloor {
			stayFloor = m.triggeredExitFloor
		}
		return nextPressureState(m.state,
			sample.usage >= thresholds.trigger,
			sample.usage >= thresholds.armed,
			sample.usage >= stayFloor,
		)
	case thresholdModeAvailable:
		if !sample.availableKnown {
			return pressureStateNormal
		}
		thresholds := computeAvailableThresholds(sample)
		return nextPressureState(m.state,
			sample.available <= thresholds.trigger,
			sample.available <= thresholds.armed,
			sample.available <= thresholds.resume,
		)
	default:
		return pressureStateNormal
	}
}

func (m *pressureMachine) intervalForState() time.Duration {
	switch {
	case m.forceMinInterval || m.state == pressureStateTriggered:
		m.currentInterval = pressureMinInterval
	case m.state == pressureStateArmed:
		m.currentInterval = pressureArmedInterval
	default:
		if m.currentInterval == 0 {
			m.currentInterval = pressureMaxInterval
		} else {
			m.currentInterval = min(m.currentInterval*2, pressureMaxInterval)
		}
	}
	return m.currentInterval
}

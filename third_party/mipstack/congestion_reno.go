package mipstack

import "math"

const renoRecoveryCheckpointValid = uint64(1) << 63

type renoCongestionControl struct {
	credit float64
	recoveryCheckpoint uint64
}

func newRenoCongestionControl() *renoCongestionControl {
	return &renoCongestionControl{}
}

func (r *renoCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventACK:
		event.State.CongestionWindow = r.increaseOnACK(
			event.State.CongestionWindow,
			event.Acknowledged,
			event.State.MaximumSegmentSize,
			event.State.BytesInFlight,
			event.State.SlowStartThreshold,
		)
	case CongestionEventLoss:
		event.State.SlowStartThreshold = r.reduceOnLoss(event.State.BytesInFlight, event.State.MaximumSegmentSize)
	case CongestionEventECN:
		threshold := r.reduceOnECN(event.State.BytesInFlight, event.State.MaximumSegmentSize)
		event.State.SlowStartThreshold = threshold
		event.State.CongestionWindow = threshold
	case CongestionEventTimeout:
		event.State.SlowStartThreshold = r.reduceOnTimeout(event.State.BytesInFlight, event.State.MaximumSegmentSize)
	case CongestionEventRecovery:
		switch event.Recovery.Stage {
		case CongestionRecoveryCheckpoint:
			r.recoveryCheckpoint = math.Float64bits(r.credit) | renoRecoveryCheckpointValid
		case CongestionRecoveryUndo:
			if r.recoveryCheckpoint&renoRecoveryCheckpointValid != 0 {
				r.credit = math.Float64frombits(r.recoveryCheckpoint &^ renoRecoveryCheckpointValid)
			}
			r.recoveryCheckpoint = 0
		}
	case CongestionEventMTUChanged:
		r.credit = 0
		r.recoveryCheckpoint = 0
	}
}

func (r *renoCongestionControl) reduceOnLoss(flight uint32, mss int) uint32 {
	r.credit = 0
	return congestionThreshold(flight, mss, 1, 2)
}

func (r *renoCongestionControl) reduceOnECN(flight uint32, mss int) uint32 {
	r.credit = 0
	return congestionThresholdWithFloor(flight, mss, 1, 2, 1)
}

func (r *renoCongestionControl) reduceOnTimeout(flight uint32, mss int) uint32 {
	r.credit = 0
	return congestionThreshold(flight, mss, 1, 2)
}

func (r *renoCongestionControl) increaseOnACK(window, acknowledged uint32, mss int, flight, slowStartThreshold uint32) uint32 {
	if !congestionWindowLimited(window, flight, mss) {
		return window
	}
	window, acknowledged = applySlowStart(window, acknowledged, slowStartThreshold)
	if acknowledged == 0 {
		return window
	}
	return applyCongestionIncrease(window, &r.credit, additiveIncrease(window, acknowledged, mss))
}

func applySlowStart(window, acknowledged, slowStartThreshold uint32) (uint32, uint32) {
	if window >= slowStartThreshold {
		return window, acknowledged
	}
	growth := acknowledged
	if available := slowStartThreshold - window; growth > available {
		growth = available
	}
	return growCongestionWindow(window, growth), acknowledged - growth
}

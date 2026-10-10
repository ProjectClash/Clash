package mipstack

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

const (
	bbrBandwidthWindow = 10
	bbrFullBandwidthRounds = 3
	bbrMinRTTWindow = 10 * time.Second
	bbrProbeRTTDuration = 200 * time.Millisecond
	bbrStartupPacingGain = 739.0 / 256
	bbrDrainPacingGain = 88.0 / 256
	bbrCongestionWindowGain = 2.0
	bbrFullBandwidthGrowth = 1.25
	bbrMinimumCongestionMSS = 4
	bbrInitialCongestionMSS = 10
	bbrPacingMargin = 0.99
	bbrCycleRandomIncrement = uint64(0x9e3779b97f4a7c15)
	bbrLongTermMinimumRounds = 4
	bbrLongTermMaximumRounds = 4 * bbrLongTermMinimumRounds
	bbrLongTermUseRounds = 48
	bbrLongTermLossRatio = 50.0 / 256
	bbrLongTermBandwidthRatio = 1.0 / 8
	bbrLongTermBandwidthDifference = (4000.0 / 8) / bbrPacingMargin
	bbrExtraACKedWindow = 5
	bbrExtraACKedMaximumInterval = 100 * time.Millisecond
	bbrPacingLowRateThreshold = 1_200_000 / 8
	bbrSendQuantumByteTarget = 65535
	bbrMaximumSendSegments = 127
	bbrMaximumUserspaceQuanta = 4
)

var bbrCycleRandomSequence atomic.Uint64

var bbrProbeBandwidthGains = [...]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

func bbrSendQuantum(rate float64, mss int) int {
	if rate <= 0 || mss < 1 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return 0
	}
	minimumSegments := 1
	if rate >= bbrPacingLowRateThreshold {
		minimumSegments = 2
	}
	targetBytes := rate / 1024
	if targetBytes > bbrSendQuantumByteTarget {
		targetBytes = bbrSendQuantumByteTarget
	}
	segments := int(targetBytes / float64(mss))
	if segments < minimumSegments {
		segments = minimumSegments
	}
	if segments > bbrMaximumSendSegments {
		segments = bbrMaximumSendSegments
	}
	return segments * mss
}

func bbrSendQuantumDuration(rate float64, mss int) time.Duration {
	quantum := bbrSendQuantum(rate, mss)
	return pacingDuration(quantum, rate)
}

func bbrUserspacePacingBudget(rate float64, mss int) int {
	quantum := bbrSendQuantum(rate, mss)
	if quantum == 0 {
		return 0
	}
	targetValue := math.Ceil(rate * tcpUserspacePacingBatch.Seconds())
	if targetValue <= float64(quantum) {
		return quantum
	}
	maximum := quantum * bbrMaximumUserspaceQuanta
	if targetValue >= float64(maximum) {
		return maximum
	}
	target := int(targetValue)
	quanta := (target + quantum - 1) / quantum
	return quanta * quantum
}

type bbrMode uint8

const (
	bbrStartup bbrMode = iota
	bbrDrain
	bbrProbeBandwidth
	bbrProbeRTT
)

func (m bbrMode) String() string {
	switch m {
	case bbrStartup:
		return "STARTUP"
	case bbrDrain:
		return "DRAIN"
	case bbrProbeBandwidth:
		return "PROBE_BW"
	case bbrProbeRTT:
		return "PROBE_RTT"
	default:
		return ""
	}
}

type bbrBandwidthSample struct {
	rate  float64
	round uint32
}

type bbrBandwidthFilter struct {
	samples [3]bbrBandwidthSample
}

func (f *bbrBandwidthFilter) reset(round uint32, rate float64) float64 {
	sample := bbrBandwidthSample{rate: rate, round: round}
	f.samples[0], f.samples[1], f.samples[2] = sample, sample, sample
	return rate
}

func (f *bbrBandwidthFilter) update(window, round uint32, rate float64) float64 {
	sample := bbrBandwidthSample{rate: rate, round: round}
	if sample.rate >= f.samples[0].rate || sample.round-f.samples[2].round > window {
		return f.reset(round, rate)
	}
	if sample.rate >= f.samples[1].rate {
		f.samples[1], f.samples[2] = sample, sample
	} else if sample.rate >= f.samples[2].rate {
		f.samples[2] = sample
	}
	delta := sample.round - f.samples[0].round
	if delta > window {
		f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], sample
		if sample.round-f.samples[0].round > window {
			f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], sample
		}
	} else if f.samples[1].round == f.samples[0].round && delta > window/4 {
		f.samples[1], f.samples[2] = sample, sample
	} else if f.samples[2].round == f.samples[1].round && delta > window/2 {
		f.samples[2] = sample
	}
	return f.samples[0].rate
}

type bbrCongestionControl struct {
	mode                 bbrMode
	roundStart           bool
	fullRounds           uint8
	fullBandwidthReached bool
	probeRound           bool
	applicationLimited   bool
	schedulerLimited     bool
	requestAppLimited    bool
	extraACKedIndex      uint8
	extraACKedRounds     uint8
	longTermSampling     bool
	longTermUseBandwidth bool
	longTermRounds       uint8
	idleRestart          bool
	hasSeenRTT           bool
	recovery             bool
	lossRecovery         bool
	packetConservation   bool

	roundCount         uint32
	nextRoundDelivered uint32
	cycleStamp         tcpDeliveryTimestamp
	priorWindow        uint32
	deliveredStamp     tcpDeliveryTimestamp
	extraACKed         [2]uint32

	bandwidthFilter        bbrBandwidthFilter
	bandwidth              float64
	minimumRTT             time.Duration
	minimumRTTStamp        time.Time
	cycleIndex             int
	fullBandwidth          float64
	cycleRandom            uint64
	probeDone              time.Time
	delivered              uint64
	totalLost              uint64
	schedulerLimitedEvents uint64
	ackEpochStamp          time.Time
	ackEpochBytes          uint64
	longTermBandwidth      float64
	longTermLastDelivered  uint64
	longTermLastLost       uint64
	longTermLastStamp      time.Time
	pacingRate             float64
	maximumPacingRate      uint64
	nextSend               time.Time
	pacingWakeDeadline     time.Time
	pacingBurstRemaining   int
}

func newBBRCongestionControl() *bbrCongestionControl {
	return &bbrCongestionControl{}
}

func (b *bbrCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventInitialize:
		b.syncDeliveryState(event.State)
		b.maximumPacingRate = event.State.MaximumPacingRate
		if event.State.MinimumRTT > 0 {
			b.minimumRTT = event.State.MinimumRTT
			b.minimumRTTStamp = event.Time
		}
		b.initializePacingRate(event.State.CongestionWindow, event.State.SmoothedRTT)
	case CongestionEventACK:
		b.syncDeliveryState(event.State)
		b.requestAppLimited = false
		sample := event.RateSample
		if sample == nil {
			return
		}
		if sample.ackStamp != 0 {
			b.deliveredStamp = sample.ackStamp
		} else if !event.Time.IsZero() {
			b.deliveredStamp = tcpDeliveryTimestampAt(monotonicStamp(event.Time.UnixNano()) + 1)
		}
		var threshold uint32
		event.State.CongestionWindow, threshold = b.onRateSample(event.State.CongestionWindow, event.State.MaximumSegmentSize, sample)
		if threshold != 0 {
			event.State.SlowStartThreshold = threshold
		}
		event.MarkApplicationLimited = b.requestAppLimited
	case CongestionEventLoss, CongestionEventECN:
		b.saveWindow(event.State.CongestionWindow)
	case CongestionEventTimeout:
		b.delivered = event.State.DeliveredBytes
		b.totalLost = event.State.LostBytes
		b.saveWindow(event.State.CongestionWindow)
		b.recovery = false
		b.lossRecovery = true
		b.packetConservation = false
		b.fullBandwidth = 0
		b.roundStart = true
		sample := tcpDeliveryRateSample{losses: 1, ackTime: event.Time}
		b.updateLongTermBandwidth(&sample)
	case CongestionEventPacketSent:
		b.applicationLimited = event.State.ApplicationLimited
		event.State.CongestionWindow = b.onDeliverySend(event.Time, event.OutstandingBytes, event.State.CongestionWindow)
		b.consumePacingBurst(event.PacketBytes)
		b.advancePacing(event.PacketBytes, event.State.MaximumSegmentSize, event.Time)
	case CongestionEventPacketRetransmitted:
		b.advanceRetransmissionPacing(event.PacketBytes, event.State.MaximumSegmentSize, event.Time)
	case CongestionEventRecovery:
		b.handleRecoveryEvent(event)
	case CongestionEventPacing:
		b.handlePacingEvent(event)
	case CongestionEventMTUChanged:
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
		b.pacingBurstRemaining = 0
	case CongestionEventDiagnostics:
		b.syncDeliveryState(event.State)
		event.Diagnostics = CongestionDiagnostics{
			DeliveryRate:           congestionRateValue(b.effectiveBandwidth()),
			PacingRate:             congestionRateValue(b.effectivePacingRate()),
			State:                  b.mode.String(),
			ApplicationLimited:     b.applicationLimited,
			SchedulerLimited:       b.schedulerLimited,
			SchedulerLimitedEvents: b.schedulerLimitedEvents,
		}
	}
}

func (b *bbrCongestionControl) syncDeliveryState(state *CongestionState) {
	b.delivered = state.DeliveredBytes
	b.totalLost = state.LostBytes
	b.applicationLimited = state.ApplicationLimited
	b.schedulerLimited = state.SchedulerLimited
	b.schedulerLimitedEvents = state.SchedulerLimitedEvents
}

func (b *bbrCongestionControl) handleRecoveryEvent(event *CongestionEvent) {
	switch event.Recovery.Stage {
	case CongestionRecoverySelectFlight:
		event.Recovery.Flight = event.Recovery.OrdinaryFlight
	case CongestionRecoveryEnter:
		window := event.Recovery.Flight
		if minimum := uint32(bbrMinimumCongestionMSS * event.State.MaximumSegmentSize); window < minimum {
			window = minimum
		}
		event.State.CongestionWindow = window
	case CongestionRecoveryPRR, CongestionRecoveryExit, CongestionRecoveryPartialACK, CongestionRecoveryDuplicateACK:
		event.State.CongestionWindow = event.Recovery.PreviousWindow
	case CongestionRecoveryUndo:
		b.undoRecovery(event.Time)
		if event.State.CongestionWindow < b.priorWindow {
			event.State.CongestionWindow = b.priorWindow
		}
	}
}

func (b *bbrCongestionControl) handlePacingEvent(event *CongestionEvent) {
	switch event.Pacing.Operation {
	case CongestionPacingQuery:
		if event.Pacing.TransmittedSegments >= tcpPacingInitialBurst {
			event.Pacing.Delay, event.Pacing.MarkSchedulerLimited = b.pacingDelay(event.Time, event.Pacing.Bytes, event.State.MaximumSegmentSize, event.State.BytesInFlight)
		}
	case CongestionPacingWake:
		event.Pacing.MarkSchedulerLimited = b.consumePacingWake(event.Time, event.State.BytesInFlight)
	case CongestionPacingCancel:
		b.pacingWakeDeadline = time.Time{}
	case CongestionPacingPolicyChanged:
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
		b.pacingBurstRemaining = 0
		b.maximumPacingRate = event.State.MaximumPacingRate
	}
}

func (b *bbrCongestionControl) onRateSample(window uint32, mss int, sample *tcpDeliveryRateSample) (uint32, uint32) {
	b.updateBandwidth(sample)
	b.updateACKAggregation(sample, window, mss)
	b.updateCycle(sample, mss)
	b.checkFullBandwidth(sample)
	threshold := b.checkDrain(sample, mss)
	window = b.updateMinimumRTT(window, sample, mss)
	if sample.delivered != 0 {
		b.idleRestart = false
	}
	b.setPacingRate(window, sample.smoothedRTT)
	window = b.setCongestionWindow(window, sample, mss)
	return window, threshold
}

func (b *bbrCongestionControl) updateBandwidth(sample *tcpDeliveryRateSample) {
	b.roundStart = false
	if !sample.valid {
		return
	}
	if tcpDeliveryAfterEqual(sample.priorDelivered, b.nextRoundDelivered) {
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
		b.roundCount++
		b.roundStart = true
		b.packetConservation = false
	}
	b.updateLongTermBandwidth(sample)
	rate := float64(sample.delivered) / sample.interval.Seconds()
	if sample.locallyLimited() && rate < b.bandwidth {
		return
	}
	b.bandwidth = b.bandwidthFilter.update(bbrBandwidthWindow, b.roundCount, rate)
}

func (b *bbrCongestionControl) updateACKAggregation(sample *tcpDeliveryRateSample, window uint32, mss int) {
	if !sample.valid || sample.acked == 0 || mss < 1 {
		return
	}
	if b.roundStart {
		b.extraACKedRounds++
		if b.extraACKedRounds >= bbrExtraACKedWindow {
			b.extraACKedRounds = 0
			b.extraACKedIndex ^= 1
			b.extraACKed[b.extraACKedIndex] = 0
		}
	}
	if sample.schedulerLimited {
		b.ackEpochStamp = sample.ackTime
		b.ackEpochBytes = 0
		return
	}
	if b.ackEpochStamp.IsZero() {
		b.ackEpochStamp = sample.ackTime
	}
	elapsed := sample.ackTime.Sub(b.ackEpochStamp)
	if elapsed < 0 {
		elapsed = 0
	}
	expected := uint64(b.effectiveBandwidth() * elapsed.Seconds())
	maximumEpochBytes := uint64(1<<20) * uint64(mss)
	if b.ackEpochBytes <= expected || b.ackEpochBytes+uint64(sample.acked) >= maximumEpochBytes {
		b.ackEpochBytes = 0
		b.ackEpochStamp = sample.ackTime
		expected = 0
	}
	b.ackEpochBytes += uint64(sample.acked)
	if b.ackEpochBytes >= maximumEpochBytes {
		b.ackEpochBytes = maximumEpochBytes - 1
	}
	extra := b.ackEpochBytes - expected
	if extra > uint64(window) {
		extra = uint64(window)
	}
	if extra > uint64(^uint32(0)) {
		extra = uint64(^uint32(0))
	}
	if uint32(extra) > b.extraACKed[b.extraACKedIndex] {
		b.extraACKed[b.extraACKedIndex] = uint32(extra)
	}
}

func (b *bbrCongestionControl) checkFullBandwidth(sample *tcpDeliveryRateSample) {
	if b.fullBandwidthReached || !b.roundStart || sample.applicationLimited {
		return
	}
	if b.bandwidth >= b.fullBandwidth*bbrFullBandwidthGrowth {
		b.fullBandwidth = b.bandwidth
		b.fullRounds = 0
		return
	}
	b.fullRounds++
	b.fullBandwidthReached = b.fullRounds >= bbrFullBandwidthRounds
}

func (b *bbrCongestionControl) checkDrain(sample *tcpDeliveryRateSample, mss int) uint32 {
	enteredDrain := false
	var gain float64
	if b.mode == bbrStartup && b.fullBandwidthReached {
		gain = b.pacingGain()
		b.mode = bbrDrain
		enteredDrain = true
	} else if b.mode != bbrDrain {
		return 0
	} else {
		gain = b.pacingGain()
	}
	drainTarget := b.quantizeWindowAt(b.modelWindowForBandwidth(b.bandwidth, 1, mss), mss, false)
	var threshold uint32
	if enteredDrain {
		threshold = uint32(drainTarget)
	}
	inflight := b.packetsInNetwork(sample.inFlight, sample.ackTime, mss, gain)
	if b.mode == bbrDrain && uint64(inflight) <= drainTarget {
		b.resetProbeBandwidth(sample.ackTime)
	}
	return threshold
}

func (b *bbrCongestionControl) updateCycle(sample *tcpDeliveryRateSample, mss int) {
	if b.mode != bbrProbeBandwidth || b.minimumRTT <= 0 || b.cycleStamp == 0 || b.deliveredStamp == 0 {
		return
	}
	fullLength := tcpDeliveryTimestampDuration(b.deliveredStamp, b.cycleStamp) > b.minimumRTT
	gain := b.pacingGain()
	advance := fullLength
	switch {
	case gain > 1:
		advance = fullLength && (sample.losses != 0 || uint64(b.packetsInNetwork(sample.priorInFlight, sample.ackTime, mss, gain)) >= b.inflightTarget(gain, mss))
	case gain < 1:
		advance = fullLength || uint64(b.packetsInNetwork(sample.priorInFlight, sample.ackTime, mss, gain)) <= b.inflightTarget(1, mss)
	}
	if advance {
		b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBandwidthGains)
		b.cycleStamp = b.deliveredStamp
	}
}

func (b *bbrCongestionControl) updateMinimumRTT(window uint32, sample *tcpDeliveryRateSample, mss int) uint32 {
	expired := b.minimumRTT != 0 && sample.ackTime.Sub(b.minimumRTTStamp) > bbrMinRTTWindow
	if sample.rtt > 0 && (b.minimumRTT == 0 || sample.rtt < b.minimumRTT || expired && !sample.ackDelayed) {
		b.minimumRTT = sample.rtt
		b.minimumRTTStamp = sample.ackTime
	}
	if expired && !b.idleRestart && b.mode != bbrProbeRTT {
		b.mode = bbrProbeRTT
		if sample.recovery {
			if window > b.priorWindow {
				b.priorWindow = window
			}
		} else {
			b.priorWindow = window
		}
		b.probeDone = time.Time{}
		b.probeRound = false
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
	}
	if b.mode != bbrProbeRTT {
		return window
	}
	b.requestAppLimited = true
	minimumFlight := uint32(bbrMinimumCongestionMSS * mss)
	if b.probeDone.IsZero() && sample.inFlight <= minimumFlight {
		b.probeDone = sample.ackTime.Add(bbrProbeRTTDuration)
		b.probeRound = false
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
	} else if !b.probeDone.IsZero() && b.roundStart {
		b.probeRound = true
	}
	if !b.probeDone.IsZero() && b.probeRound && !sample.ackTime.Before(b.probeDone) {
		b.minimumRTTStamp = sample.ackTime
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.resetMode(sample.ackTime)
	}
	return window
}

func (b *bbrCongestionControl) setCongestionWindow(window uint32, sample *tcpDeliveryRateSample, mss int) uint32 {
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	if sample.acked == 0 {
		if b.mode == bbrProbeRTT && window > minimum {
			return minimum
		}
		return window
	}
	if sample.losses != 0 {
		losses := sample.losses
		if losses >= uint64(window) {
			window = uint32(mss)
		} else {
			window -= uint32(losses)
		}
	}
	if b.lossRecovery && !sample.recovery {
		b.lossRecovery = false
		if window < b.priorWindow {
			window = b.priorWindow
		}
	}
	switch {
	case sample.fastRecovery && !b.recovery:
		b.recovery = true
		b.packetConservation = true
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
		window = growCongestionWindow(sample.inFlight, sample.acked)
	case !sample.fastRecovery && b.recovery:
		b.recovery = false
		b.packetConservation = false
		if window < b.priorWindow {
			window = b.priorWindow
		}
	}
	if b.packetConservation {
		conserved := growCongestionWindow(sample.inFlight, sample.acked)
		if window < conserved {
			window = conserved
		}
		if window < minimum {
			window = minimum
		}
		if b.mode == bbrProbeRTT && window > minimum {
			window = minimum
		}
		return window
	}
	if b.mode == bbrProbeRTT {
		if window > minimum {
			return minimum
		}
		return window
	}
	target := b.modelWindow(b.congestionWindowGain(), mss)
	if b.fullBandwidthReached {
		extra := uint64(b.extraACKed[0])
		if uint64(b.extraACKed[1]) > extra {
			extra = uint64(b.extraACKed[1])
		}
		maximumExtra := uint64(b.effectiveBandwidth() * bbrExtraACKedMaximumInterval.Seconds())
		if extra > maximumExtra {
			extra = maximumExtra
		}
		target += extra
	}
	target = b.quantizeWindow(target, mss)
	if b.fullBandwidthReached {
		grown := growCongestionWindow(window, sample.acked)
		if uint64(grown) > target {
			window = uint32(target)
		} else {
			window = grown
		}
	} else if uint64(window) < target || b.delivered < uint64(bbrInitialCongestionMSS*mss) {
		window = growCongestionWindow(window, sample.acked)
	}
	if window < minimum {
		window = minimum
	}
	return window
}

func (b *bbrCongestionControl) modelWindow(gain float64, mss int) uint64 {
	return b.modelWindowForBandwidth(b.effectiveBandwidth(), gain, mss)
}

func (b *bbrCongestionControl) modelWindowForBandwidth(bandwidth, gain float64, mss int) uint64 {
	if mss < 1 {
		return 0
	}
	if b.minimumRTT <= 0 {
		return uint64(bbrInitialCongestionMSS * mss)
	}
	if bandwidth <= 0 || gain <= 0 {
		return 0
	}
	value := math.Ceil(bandwidth * b.minimumRTT.Seconds() * gain)
	if value >= float64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return uint64(value)
}

func (b *bbrCongestionControl) quantizeWindow(target uint64, mss int) uint64 {
	probeHigh := b.mode == bbrProbeBandwidth && b.cycleIndex == 0
	return b.quantizeWindowAt(target, mss, probeHigh)
}

func (b *bbrCongestionControl) quantizeWindowAt(target uint64, mss int, probeHigh bool) uint64 {
	if mss < 1 {
		return 0
	}
	quantum := bbrSendQuantum(b.effectivePacingRate(), mss)
	if quantum < mss {
		quantum = mss
	}
	target += uint64(3 * quantum)
	segments := (target + uint64(mss) - 1) / uint64(mss)
	if segments&1 != 0 {
		segments++
	}
	target = segments * uint64(mss)
	if probeHigh {
		target += uint64(2 * mss)
	}
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if target < minimum {
		target = minimum
	}
	if target > uint64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return target
}

func (b *bbrCongestionControl) inflightTarget(gain float64, mss int) uint64 {
	return b.quantizeWindow(b.modelWindow(gain, mss), mss)
}

func (b *bbrCongestionControl) packetsInNetwork(inflight uint32, now time.Time, mss int, gain float64) uint32 {
	value := uint64(inflight)
	if gain > 1 {
		value += uint64(bbrSendQuantum(b.effectivePacingRate(), mss))
	}
	if now.Before(b.nextSend) && b.effectiveBandwidth() > 0 {
		delivered := uint64(b.effectiveBandwidth() * b.nextSend.Sub(now).Seconds())
		if delivered >= value {
			return 0
		}
		value -= delivered
	}
	if value > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func (b *bbrCongestionControl) effectiveBandwidth() float64 {
	if b.longTermUseBandwidth {
		return b.longTermBandwidth
	}
	return b.bandwidth
}

func (b *bbrCongestionControl) updateLongTermBandwidth(sample *tcpDeliveryRateSample) {
	if b.longTermUseBandwidth {
		if b.mode == bbrProbeBandwidth && b.roundStart {
			b.longTermRounds++
			if b.longTermRounds >= bbrLongTermUseRounds {
				b.resetLongTermBandwidth(sample.ackTime)
				b.resetProbeBandwidth(sample.ackTime)
			}
		}
		return
	}
	if !b.longTermSampling {
		if sample.losses == 0 {
			return
		}
		b.resetLongTermInterval(sample.ackTime)
		b.longTermSampling = true
	}
	if sample.locallyLimited() {
		b.resetLongTermBandwidth(sample.ackTime)
		return
	}
	if b.roundStart {
		b.longTermRounds++
	}
	if b.longTermRounds < bbrLongTermMinimumRounds {
		return
	}
	if b.longTermRounds > bbrLongTermMaximumRounds {
		b.resetLongTermBandwidth(sample.ackTime)
		return
	}
	if sample.losses == 0 {
		return
	}
	delivered := b.delivered - b.longTermLastDelivered
	lost := b.totalLost - b.longTermLastLost
	if delivered == 0 || float64(lost)/float64(delivered) < bbrLongTermLossRatio {
		return
	}
	interval := sample.ackTime.Sub(b.longTermLastStamp)
	if interval < time.Millisecond {
		return
	}
	rate := float64(delivered) / interval.Seconds()
	if b.longTermBandwidth != 0 {
		difference := math.Abs(rate - b.longTermBandwidth)
		if difference <= b.longTermBandwidth*bbrLongTermBandwidthRatio || difference <= bbrLongTermBandwidthDifference {
			b.longTermBandwidth = (b.longTermBandwidth + rate) / 2
			b.longTermUseBandwidth = true
			b.longTermRounds = 0
			return
		}
	}
	b.longTermBandwidth = rate
	b.resetLongTermInterval(sample.ackTime)
}

func (b *bbrCongestionControl) resetLongTermInterval(now time.Time) {
	b.longTermLastStamp = now
	b.longTermLastDelivered = b.delivered
	b.longTermLastLost = b.totalLost
	b.longTermRounds = 0
}

func (b *bbrCongestionControl) resetLongTermBandwidth(now time.Time) {
	b.longTermBandwidth = 0
	b.longTermUseBandwidth = false
	b.longTermSampling = false
	b.resetLongTermInterval(now)
}

func (b *bbrCongestionControl) undoRecovery(now time.Time) {
	b.fullBandwidth = 0
	b.fullRounds = 0
	b.recovery = false
	b.lossRecovery = false
	b.packetConservation = false
	b.resetLongTermBandwidth(now)
}

func (b *bbrCongestionControl) saveWindow(window uint32) {
	if !b.recovery && !b.lossRecovery && b.mode != bbrProbeRTT {
		b.priorWindow = window
		return
	}
	if window > b.priorWindow {
		b.priorWindow = window
	}
}

func (b *bbrCongestionControl) onDeliverySend(now time.Time, packetsOut, window uint32) uint32 {
	if packetsOut == 0 {
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
		b.pacingBurstRemaining = 0
		if b.applicationLimited {
			b.idleRestart = true
			if b.mode == bbrProbeBandwidth && b.bandwidth > 0 {
				b.pacingRate = b.effectiveBandwidth() * bbrPacingMargin
			}
		}
	}
	if packetsOut == 0 && b.idleRestart {
		b.ackEpochStamp = now
		b.ackEpochBytes = 0
	}
	if packetsOut == 0 && b.idleRestart && b.mode == bbrProbeRTT && !b.probeDone.IsZero() && !now.Before(b.probeDone) {
		b.minimumRTTStamp = now
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.resetMode(now)
	}
	return window
}

func (s *tcpDeliveryRateSample) locallyLimited() bool {
	return s.applicationLimited || s.schedulerLimited
}

func (b *bbrCongestionControl) resetMode(now time.Time) {
	if b.fullBandwidthReached {
		b.resetProbeBandwidth(now)
	} else {
		b.mode = bbrStartup
	}
}

func (b *bbrCongestionControl) resetProbeBandwidth(now time.Time) {
	b.mode = bbrProbeBandwidth
	b.cycleIndex = b.initialCycle(now)
	b.cycleStamp = b.deliveredStamp
}

func (b *bbrCongestionControl) nextCycleRandom(now time.Time) uint64 {
	if b.cycleRandom == 0 {
		b.cycleRandom = uint64(now.UnixNano()) ^ bbrCycleRandomSequence.Add(bbrCycleRandomIncrement)
	}
	b.cycleRandom += bbrCycleRandomIncrement
	value := b.cycleRandom
	value = (value ^ value>>30) * 0xbf58476d1ce4e5b9
	value = (value ^ value>>27) * 0x94d049bb133111eb
	return value ^ value>>31
}

func (b *bbrCongestionControl) initialCycle(now time.Time) int {
	const choices = uint64(len(bbrProbeBandwidthGains) - 1)
	const rejection = (^choices + 1) % choices
	for {
		choice, remainder := bits.Mul64(b.nextCycleRandom(now), choices)
		if remainder >= rejection {
			return (len(bbrProbeBandwidthGains) - int(choice)) % len(bbrProbeBandwidthGains)
		}
	}
}

func (b *bbrCongestionControl) pacingGain() float64 {
	switch b.mode {
	case bbrStartup:
		return bbrStartupPacingGain
	case bbrDrain:
		return bbrDrainPacingGain
	case bbrProbeBandwidth:
		if b.longTermUseBandwidth {
			return 1
		}
		return bbrProbeBandwidthGains[b.cycleIndex]
	default:
		return 1
	}
}

func (b *bbrCongestionControl) congestionWindowGain() float64 {
	if b.mode == bbrStartup || b.mode == bbrDrain {
		return bbrStartupPacingGain
	}
	if b.mode == bbrProbeRTT {
		return 1
	}
	return bbrCongestionWindowGain
}

func (b *bbrCongestionControl) initializePacingRate(window uint32, smoothedRTT time.Duration) {
	roundTrip := smoothedRTT
	if roundTrip <= 0 {
		roundTrip = time.Millisecond
	} else {
		b.hasSeenRTT = true
	}
	b.pacingRate = float64(window) / roundTrip.Seconds() * bbrStartupPacingGain * bbrPacingMargin
}

func (b *bbrCongestionControl) setPacingRate(window uint32, smoothedRTT time.Duration) {
	if !b.hasSeenRTT && smoothedRTT > 0 {
		b.initializePacingRate(window, smoothedRTT)
	}
	bw := b.effectiveBandwidth()
	if bw <= 0 {
		return
	}
	rate := bw * b.pacingGain() * bbrPacingMargin
	if b.pacingRate == 0 || b.fullBandwidthReached || rate > b.pacingRate {
		b.pacingRate = rate
	}
}

func (b *bbrCongestionControl) pacingDelay(now time.Time, bytes, mss int, flight uint32) (time.Duration, bool) {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return 0, false
	}
	schedulerLimited := b.consumePacingWake(now, flight)
	if b.pacingBurstRemaining >= bytes {
		return 0, schedulerLimited
	}
	budget := bbrUserspacePacingBudget(rate, mss)
	if !b.nextSend.IsZero() && now.Before(b.nextSend) {
		allowance := pacingDuration(budget, rate)
		deadline := b.nextSend.Add(-allowance)
		if now.Before(deadline) {
			b.pacingWakeDeadline = deadline
			return deadline.Sub(now), schedulerLimited
		}
	}
	if b.nextSend.IsZero() {
		b.nextSend = now
	}
	b.pacingBurstRemaining = budget
	return 0, schedulerLimited
}

func (b *bbrCongestionControl) consumePacingWake(now time.Time, flight uint32) bool {
	if b.pacingWakeDeadline.IsZero() {
		return false
	}
	deadline := b.pacingWakeDeadline
	b.pacingWakeDeadline = time.Time{}
	if flight != 0 && now.Sub(deadline) > tcpUserspaceSchedulingTolerance {
		return true
	}
	return false
}

func (b *bbrCongestionControl) effectivePacingRate() float64 {
	rate := b.pacingRate
	if b.maximumPacingRate != 0 && rate > float64(b.maximumPacingRate) {
		return float64(b.maximumPacingRate)
	}
	return rate
}

func (b *bbrCongestionControl) consumePacingBurst(bytes int) {
	if bytes <= 0 || b.pacingBurstRemaining <= 0 {
		return
	}
	b.pacingBurstRemaining -= bytes
	if b.pacingBurstRemaining < 0 {
		b.pacingBurstRemaining = 0
	}
}

func (b *bbrCongestionControl) advancePacing(bytes, mss int, now time.Time) {
	b.advancePacingAt(bytes, mss, now, true)
}

func (b *bbrCongestionControl) advanceRetransmissionPacing(bytes, mss int, now time.Time) {
	b.pacingWakeDeadline = time.Time{}
	b.consumePacingBurst(bytes)
	b.advancePacingAt(bytes, mss, now, false)
}

func (b *bbrCongestionControl) advancePacingAt(bytes, mss int, now time.Time, catchUp bool) {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return
	}
	delay := pacingDuration(bytes, rate)
	maximumDebt := bbrSendQuantumDuration(rate, mss)
	base := pacingScheduleBase(b.nextSend, now, maximumDebt, catchUp)
	b.nextSend = base.Add(delay)
}

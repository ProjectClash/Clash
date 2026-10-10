package mipstack

import "time"

type tcpDeliveryTimestamp uint32

func tcpDeliveryTimestampAt(stamp monotonicStamp) tcpDeliveryTimestamp {
	if stamp == 0 {
		return 0
	}
	value := tcpDeliveryTimestamp((uint64(stamp)-1)/uint64(time.Microsecond)) + 1
	if value == 0 {
		return 1
	}
	return value
}

func tcpDeliveryTimestampDuration(later, earlier tcpDeliveryTimestamp) time.Duration {
	if later == 0 || earlier == 0 {
		return 0
	}
	delta := uint32(later - earlier)
	if delta == 0 {
		return 0
	}
	return time.Duration(delta) * time.Microsecond
}

const (
	tcpDeliveryApplicationLimited = uint32(1) << 31
	tcpDeliveryDeliveredMask = tcpDeliveryApplicationLimited - 1
)

type tcpDeliverySnapshot struct {
	firstSent      tcpDeliveryTimestamp
	deliveredStamp tcpDeliveryTimestamp
	deliveredFlags uint32
}

func (s tcpDeliverySnapshot) delivered() uint32 { return s.deliveredFlags & tcpDeliveryDeliveredMask }

func (s tcpDeliverySnapshot) applicationLimited() bool {
	return s.deliveredFlags&tcpDeliveryApplicationLimited != 0
}

func tcpDeliveryAfterEqual(value, reference uint32) bool {
	delta := (value - reference) & tcpDeliveryDeliveredMask
	return delta == 0 || delta < tcpDeliveryApplicationLimited/2
}

type CongestionRateSample struct {
	priorDelivered      uint32
	priorDeliveredTotal uint64
	delivered           uint32
	acked               uint32
	losses              uint64
	priorInFlight       uint32
	inFlight            uint32
	interval            time.Duration
	rtt                 time.Duration
	smoothedRTT         time.Duration
	ackTime             time.Time
	ackStamp            tcpDeliveryTimestamp
	lastSent            monotonicStamp
	lastEnd, lastOrder  uint32
	applicationLimited  bool
	schedulerLimited    bool
	retransmitted       bool
	recovery            bool
	fastRecovery        bool
	ackDelayed          bool
	tailLossProbeACK    bool
	valid               bool
	packetState         uint64
	firstSent           tcpDeliveryTimestamp
	priorStamp          tcpDeliveryTimestamp
}

type tcpDeliveryRateSample = CongestionRateSample

func (s *CongestionRateSample) PriorDeliveredBytes() uint64 { return s.priorDeliveredTotal }

func (s *CongestionRateSample) DeliveredBytes() uint32 { return s.delivered }

func (s *CongestionRateSample) AcknowledgedBytes() uint32 { return s.acked }

func (s *CongestionRateSample) LostBytes() uint64 { return s.losses }

func (s *CongestionRateSample) PriorBytesInFlight() uint32 { return s.priorInFlight }

func (s *CongestionRateSample) BytesInFlight() uint32 { return s.inFlight }

func (s *CongestionRateSample) Interval() time.Duration { return s.interval }

func (s *CongestionRateSample) RTT() time.Duration { return s.rtt }

func (s *CongestionRateSample) SmoothedRTT() time.Duration { return s.smoothedRTT }

func (s *CongestionRateSample) ACKTime() time.Time { return s.ackTime }

func (s *CongestionRateSample) ApplicationLimited() bool { return s.applicationLimited }

func (s *CongestionRateSample) SchedulerLimited() bool { return s.schedulerLimited }

func (s *CongestionRateSample) Retransmitted() bool { return s.retransmitted }

func (s *CongestionRateSample) InRecovery() bool { return s.recovery }

func (s *CongestionRateSample) InFastRecovery() bool { return s.fastRecovery }

func (s *CongestionRateSample) ACKDelayed() bool { return s.ackDelayed }

func (s *CongestionRateSample) TailLossProbeACK() bool { return s.tailLossProbeACK }

func (s *CongestionRateSample) Valid() bool { return s.valid }

func (s *CongestionRateSample) PacketState() uint64 { return s.packetState }

type tcpDeliveryRateEstimator struct {
	delivered               uint64
	deliveredStamp          tcpDeliveryTimestamp
	firstSent               tcpDeliveryTimestamp
	applicationLimitedUntil uint64
	schedulerLimitedUntil   uint64
	schedulerLimitedEvents  uint64
	totalLost               uint64
	sampledLost             uint64
}

func (d *tcpDeliveryRateEstimator) initializeDelivery(_ time.Time, _ time.Duration, stamp monotonicStamp) {
	d.restartFlight(stamp)
}

func (s *tcpDeliveryRateSample) observe(segment sentTCPSegment) {
	snapshot := segment.delivery
	if snapshot.deliveredStamp == 0 {
		return
	}
	sent := segment.hostQueue.queuedAt
	if s.priorStamp != 0 && (sent < s.lastSent || sent == s.lastSent && !tcpClockTieTransmissionAfter(segment.transmissionOrder, segment.end, s.lastOrder, s.lastEnd)) {
		return
	}
	s.priorDelivered = snapshot.delivered()
	s.priorStamp = snapshot.deliveredStamp
	s.firstSent = snapshot.firstSent
	s.lastSent = sent
	s.lastEnd = segment.end
	s.lastOrder = segment.transmissionOrder
	s.applicationLimited = snapshot.applicationLimited()
	s.schedulerLimited = segment.state.has(sentTCPSegmentDeliverySchedulerLimited)
	s.retransmitted = segment.isRetransmitted()
	s.packetState = segment.congestionPacketState
}

func (d *tcpDeliveryRateEstimator) finishRateSample(sample *tcpDeliveryRateSample, acknowledged uint32, priorInFlight, inFlight uint32, now time.Time, nowStamp monotonicStamp, minimumRTT, smoothedRTT, sampleRTT time.Duration) {
	sample.acked = acknowledged
	sample.priorInFlight = priorInFlight
	sample.inFlight = inFlight
	sample.ackTime = now
	sample.rtt = sampleRTT
	sample.smoothedRTT = smoothedRTT
	sample.losses = d.totalLost - d.sampledLost
	d.sampledLost = d.totalLost
	if acknowledged != 0 {
		d.delivered += uint64(acknowledged)
		d.deliveredStamp = tcpDeliveryTimestampAt(nowStamp)
	}
	sample.ackStamp = d.deliveredStamp
	if d.applicationLimitedUntil != 0 && d.delivered > d.applicationLimitedUntil {
		d.applicationLimitedUntil = 0
	}
	if d.schedulerLimitedUntil != 0 && d.delivered > d.schedulerLimitedUntil {
		d.schedulerLimitedUntil = 0
	}
	if sample.priorStamp == 0 {
		return
	}
	compactNow := tcpDeliveryTimestampAt(nowStamp)
	compactSent := tcpDeliveryTimestampAt(sample.lastSent)
	d.firstSent = compactSent
	if !sample.retransmitted {
		if selectedRTT := tcpDeliveryTimestampDuration(compactNow, compactSent); selectedRTT > 0 {
			sample.rtt = selectedRTT
		}
	}
	sample.delivered = (uint32(d.delivered) - sample.priorDelivered) & tcpDeliveryDeliveredMask
	sample.priorDeliveredTotal = d.delivered - uint64(sample.delivered)
	sendInterval := tcpDeliveryTimestampDuration(compactSent, sample.firstSent)
	ackInterval := tcpDeliveryTimestampDuration(compactNow, sample.priorStamp)
	if ackInterval > sendInterval {
		sendInterval = ackInterval
	}
	if sendInterval <= 0 || minimumRTT > 0 && sendInterval < minimumRTT {
		return
	}
	sample.interval = sendInterval
	sample.valid = true
}

func (d *tcpDeliveryRateEstimator) noteLoss(bytes uint32) {
	d.totalLost += uint64(bytes)
}

func (d *tcpDeliveryRateEstimator) recordLoss(bytes uint32, duringACK bool) {
	d.noteLoss(bytes)
	if !duringACK {
		d.sampledLost = d.totalLost
	}
}

func (d *tcpDeliveryRateEstimator) markApplicationLimited(flight uint32) {
	limit := d.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	d.applicationLimitedUntil = limit
}

func (d *tcpDeliveryRateEstimator) markSchedulerLimited(flight uint32) {
	limit := d.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	if limit > d.schedulerLimitedUntil {
		d.schedulerLimitedUntil = limit
	}
	d.schedulerLimitedEvents++
}

func (d *tcpDeliveryRateEstimator) schedulerLimited() bool {
	return d.schedulerLimitedUntil != 0
}

func (d *tcpDeliveryRateEstimator) restartFlight(stamp monotonicStamp) {
	compactStamp := tcpDeliveryTimestampAt(stamp)
	d.firstSent = compactStamp
	d.deliveredStamp = compactStamp
}

func (d *tcpDeliveryRateEstimator) snapshot() tcpDeliverySnapshot {
	deliveredFlags := uint32(d.delivered) & tcpDeliveryDeliveredMask
	if d.applicationLimitedUntil != 0 {
		deliveredFlags |= tcpDeliveryApplicationLimited
	}
	return tcpDeliverySnapshot{firstSent: d.firstSent, deliveredStamp: d.deliveredStamp, deliveredFlags: deliveredFlags}
}

func (d *tcpDeliveryRateEstimator) onDeliveryDataSent(_, _ int, _ time.Time, stamp monotonicStamp, packetsOut, window uint32) (tcpDeliverySnapshot, uint32) {
	if packetsOut == 0 {
		d.restartFlight(stamp)
	}
	return d.snapshot(), window
}

func (d *tcpDeliveryRateEstimator) onDeliveryRetransmit(_, _ int, _ time.Time, stamp monotonicStamp, packetsOut uint32) tcpDeliverySnapshot {
	if packetsOut == 0 {
		d.restartFlight(stamp)
	}
	return d.snapshot()
}

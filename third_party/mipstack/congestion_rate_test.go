package mipstack

import (
	"testing"
	"time"
)

func TestTCPDeliveryRateSampleUsesLongerPipelinePhase(t *testing.T) {
	stamp := func(value time.Duration) monotonicStamp { return monotonicStamp(value) + 1 }
	estimator := tcpDeliveryRateEstimator{
		deliveredStamp: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)),
		firstSent:      tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)),
	}
	segment := sentTCPSegment{
		sequence: 1, end: 1001, state: sentTCPSegmentTransmitted,
		hostQueue: packetQueueTicket{queuedAt: stamp(20 * time.Millisecond)},
		delivery:  tcpDeliverySnapshot{firstSent: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)), deliveredStamp: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond))},
	}
	var sample tcpDeliveryRateSample
	sample.observe(segment)
	estimator.finishRateSample(&sample, 1000, 1000, 0, time.Unix(100, 0), stamp(25*time.Millisecond), time.Millisecond, time.Millisecond, time.Millisecond)
	if !sample.valid || sample.interval != 15*time.Millisecond || sample.delivered != 1000 {
		t.Fatalf("delivery sample = valid %t interval %v delivered %d", sample.valid, sample.interval, sample.delivered)
	}
	if estimator.firstSent != tcpDeliveryTimestampAt(stamp(20*time.Millisecond)) {
		t.Fatalf("next send-phase boundary = %d, want %d", estimator.firstSent, tcpDeliveryTimestampAt(stamp(20*time.Millisecond)))
	}
}

func TestTCPDeliveryRateSampleUsesClockTieTransmissionOrder(t *testing.T) {
	stamp := monotonicStamp(time.Second) + 1
	earlier := sentTCPSegment{
		end:               300,
		hostQueue:         packetQueueTicket{queuedAt: stamp},
		transmissionOrder: 1,
		delivery:          tcpDeliverySnapshot{firstSent: 1, deliveredStamp: 1, deliveredFlags: 100},
	}
	later := sentTCPSegment{
		end:               200,
		hostQueue:         packetQueueTicket{queuedAt: stamp},
		transmissionOrder: 2,
		delivery:          tcpDeliverySnapshot{firstSent: 2, deliveredStamp: 2, deliveredFlags: 200},
	}
	var sample tcpDeliveryRateSample
	sample.observe(earlier)
	sample.observe(later)
	sample.observe(earlier)
	if sample.priorDelivered != 200 || sample.lastSent != stamp || sample.lastEnd != 200 || sample.lastOrder != 2 {
		t.Fatalf("clock-tied delivery selection = delivered %d sent %d end %d order %d", sample.priorDelivered, sample.lastSent, sample.lastEnd, sample.lastOrder)
	}
}

func TestTCPDeliveryRateSampleRejectsSACKReneging(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	sample := tcpDeliveryRateSample{
		priorStamp: 1,
		firstSent:  1,
		lastSent:   monotonicStamp(2*time.Millisecond) + 1,
	}
	controller.finishDeliveryRateSample(&sample, 1000, 1000, 0, time.Unix(100, 0), monotonicStamp(3*time.Millisecond)+1, 0, time.Millisecond, 0, true)
	if sample.delivered != 1000 || sample.interval == 0 {
		t.Fatalf("reneging sample accounting = delivered %d interval %v", sample.delivered, sample.interval)
	}
	if sample.valid {
		t.Fatal("SACK reneging produced a valid delivery-rate sample")
	}
}

func TestTCPDeliveryTimestampWrapsAcrossUint32(t *testing.T) {
	earlier := tcpDeliveryTimestamp(^uint32(0) - 5)
	later := tcpDeliveryTimestamp(5)
	if interval := tcpDeliveryTimestampDuration(later, earlier); interval != 11*time.Microsecond {
		t.Fatalf("wrapped delivery interval = %v, want 11us", interval)
	}
}

func TestTCPDeliveryCounterWrapsAcross31Bits(t *testing.T) {
	earlier := tcpDeliveryDeliveredMask - 5
	later := uint32(5)
	if !tcpDeliveryAfterEqual(later, earlier) {
		t.Fatal("wrapped delivered counter was ordered before its reference")
	}
	if tcpDeliveryAfterEqual(earlier, later) {
		t.Fatal("reverse wrapped delivered counter comparison was accepted")
	}
	estimator := tcpDeliveryRateEstimator{delivered: uint64(tcpDeliveryApplicationLimited) + 5}
	sample := tcpDeliveryRateSample{
		priorDelivered: earlier,
		priorStamp:     1,
		firstSent:      1,
		lastSent:       monotonicStamp(time.Microsecond) + 1,
	}
	estimator.finishRateSample(&sample, 0, 0, 0, time.Unix(100, 0), monotonicStamp(2*time.Microsecond)+1, 0, 0, 0)
	if sample.delivered != 11 || !sample.valid {
		t.Fatalf("wrapped delivered sample = %d, valid %t; want 11, true", sample.delivered, sample.valid)
	}
	if prior := sample.PriorDeliveredBytes(); prior != uint64(tcpDeliveryApplicationLimited)-6 {
		t.Fatalf("public prior delivered bytes = %d, want %d", prior, uint64(tcpDeliveryApplicationLimited)-6)
	}
}

func TestTCPDeliverySnapshotPacksApplicationLimit(t *testing.T) {
	estimator := tcpDeliveryRateEstimator{delivered: 1234, applicationLimitedUntil: 2000}
	snapshot := estimator.snapshot()
	if snapshot.delivered() != 1234 || !snapshot.applicationLimited() {
		t.Fatalf("packed snapshot = delivered %d limited %t", snapshot.delivered(), snapshot.applicationLimited())
	}
	estimator.applicationLimitedUntil = 0
	snapshot = estimator.snapshot()
	if snapshot.applicationLimited() {
		t.Fatal("unlimited snapshot retained application-limited flag")
	}
}

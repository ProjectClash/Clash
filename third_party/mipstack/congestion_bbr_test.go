package mipstack

import (
	"sync"
	"testing"
	"time"
)

func bbrState(t testing.TB, controller *tcpCongestionController) *bbrCongestionControl {
	t.Helper()
	bbr, ok := controller.algorithm.(*bbrCongestionControl)
	if !ok {
		t.Fatalf("controller implementation = %T, want BBR", controller.algorithm)
	}
	return bbr
}

func bbrSample(sample tcpDeliveryRateSample) *tcpDeliveryRateSample {
	return &sample
}

func TestBBRCongestionControl(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, 2*mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, true)
	if bbrState(t, &controller).bandwidth != 20000 {
		t.Fatalf("BBR initial bandwidth = %v, want 20000", bbrState(t, &controller).bandwidth)
	}
	_, _ = controller.onDataSend(mss, mss, start, 1, 0, window, 0, 0, 0)
	if delay := controller.pacingDelay(start, mss, window, 0, mss, 100*time.Millisecond, ^uint32(0)); delay >= 100*time.Millisecond {
		t.Fatalf("BBR startup pacing delay = %v, want less than 100ms", delay)
	}
	for round := 0; round < 4; round++ {
		window = controller.onACK(window, mss, mss, start.Add(time.Duration(round+1)*100*time.Millisecond), 100*time.Millisecond, 100*time.Millisecond, window, false)
	}
	if bbrState(t, &controller).mode == bbrStartup {
		t.Fatal("BBR remained in Startup after a sustained bandwidth plateau")
	}
	bbrState(t, &controller).mode = bbrProbeBandwidth
	bbrState(t, &controller).minimumRTTStamp = start.Add(-bbrMinRTTWindow - time.Nanosecond)
	window = controller.onACK(window, mss, mss, start.Add(time.Second), 100*time.Millisecond, 100*time.Millisecond, mss, false)
	if bbrState(t, &controller).mode != bbrProbeRTT || window != bbrMinimumCongestionMSS*mss {
		t.Fatalf("BBR ProbeRTT state/window = %v/%d", bbrState(t, &controller).mode, window)
	}
}

func TestBBRACKUsesDeliveryMonotonicStamp(t *testing.T) {
	bbr := newBBRCongestionControl()
	sample := tcpDeliveryRateSample{ackStamp: 123, ackTime: time.Unix(100, 0)}
	state := CongestionState{CongestionWindow: 10_000, SlowStartThreshold: 20_000, MaximumSegmentSize: 1000}
	bbr.HandleCongestionEvent(&CongestionEvent{
		Type: CongestionEventACK, Time: time.Unix(1_000_000, 0), State: &state, RateSample: &sample,
	})
	if bbr.deliveredStamp != sample.ackStamp {
		t.Fatalf("BBR delivery stamp = %d, want sampler stamp %d", bbr.deliveredStamp, sample.ackStamp)
	}
}

func TestBBRApplicationLimitedRoundsDoNotEndStartup(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{bandwidth: 100000, fullBandwidth: 100000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	now := time.Unix(100, 0)
	for round := 0; round < bbrFullBandwidthRounds+2; round++ {
		bbr.delivered += mss
		sample := tcpDeliveryRateSample{priorDelivered: uint32(bbr.delivered - mss), delivered: mss, acked: mss, interval: 10 * time.Millisecond, ackTime: now.Add(time.Duration(round) * 10 * time.Millisecond), applicationLimited: true, valid: true}
		_, _ = bbr.onRateSample(10*mss, mss, bbrSample(sample))
	}
	if bbr.mode != bbrStartup || bbr.fullRounds != 0 {
		t.Fatalf("application-limited BBR state = mode %v full rounds %d", bbr.mode, bbr.fullRounds)
	}
}

func TestBBRIgnoresLowApplicationLimitedBandwidthSamples(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{delivered: 1000, interval: 10 * time.Millisecond, ackTime: start, applicationLimited: true, valid: true}))
	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("low app-limited sample changed BBR model: bandwidth=%v", bbr.bandwidth)
	}
	bbr = bbrCongestionControl{bandwidth: 100_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{delivered: 2000, interval: 10 * time.Millisecond, ackTime: start, applicationLimited: true, valid: true}))
	if bbr.bandwidth != 200_000 {
		t.Fatalf("high app-limited sample was ignored: bandwidth=%v", bbr.bandwidth)
	}
}

func TestBBRApplicationLimitedSamplesDoNotExpireBandwidth(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	for round := 0; round < 2*bbrBandwidthWindow; round++ {
		bbr.delivered += mss
		bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{
			priorDelivered: uint32(bbr.delivered - mss), delivered: mss,
			interval: 10 * time.Millisecond, ackTime: start.Add(time.Duration(round) * time.Millisecond),
			applicationLimited: true, valid: true,
		}))

	}
	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("app-limited rounds expired BBR bandwidth: %v", bbr.bandwidth)
	}
	bbr.delivered += mss
	bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{
		priorDelivered: uint32(bbr.delivered - mss), delivered: mss,
		interval: 10 * time.Millisecond, ackTime: start.Add(time.Second), valid: true,
	}))

	if bbr.bandwidth != 100_000 {
		t.Fatalf("first usable sample after stale rounds retained bandwidth: %v", bbr.bandwidth)
	}
}

func TestBBRAcceptsLowSampleWhilePacingLimited(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{delivered: 1000, interval: 10 * time.Millisecond, ackTime: start, valid: true}))
	if bbr.bandwidthFilter.samples[0].rate == 0 {
		t.Fatal("pacing-limited BBR delivery sample was treated as application-limited")
	}
}

func TestBBRACKAggregationTracksExcessDelivery(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 100_000}
	bbr.updateACKAggregation(bbrSample(tcpDeliveryRateSample{acked: 5000, delivered: 5000, interval: 10 * time.Millisecond, ackTime: start, valid: true}), 10_000, 1000)
	if bbr.extraACKed[0] != 5000 {
		t.Fatalf("extra ACKed = %d, want 5000", bbr.extraACKed[0])
	}
	bbr.updateACKAggregation(bbrSample(tcpDeliveryRateSample{acked: 1000, delivered: 1000, interval: 10 * time.Millisecond, ackTime: start.Add(50 * time.Millisecond), valid: true}), 10_000, 1000)
	if bbr.ackEpochBytes != 1000 {
		t.Fatalf("slow ACK epoch retained %d bytes, want reset to 1000", bbr.ackEpochBytes)
	}
}

func TestBBRACKAggregationEpochSaturates(t *testing.T) {
	const mss = 48
	maximum := uint32((1 << 20) * mss)
	bbr := bbrCongestionControl{bandwidth: 1}
	bbr.updateACKAggregation(bbrSample(tcpDeliveryRateSample{
		acked: maximum, delivered: maximum, interval: time.Second,
		ackTime: time.Unix(100, 0), valid: true,
	}),

		maximum, mss)

	if want := uint64(maximum) - 1; bbr.ackEpochBytes != want {
		t.Fatalf("ACK epoch bytes = %d, want %d", bbr.ackEpochBytes, want)
	}
}

func TestBBRProbeBandwidthWaitsForInflightOrLoss(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	cycleStamp := tcpDeliveryTimestampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 0, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + tcpDeliveryTimestamp(20*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond, bandwidth: 1_000_000, pacingRate: 1_000_000,
	}
	sample := tcpDeliveryRateSample{ackTime: now, priorInFlight: mss, valid: true}
	bbr.updateCycle(bbrSample(sample), mss)
	if bbr.cycleIndex != 0 {
		t.Fatalf("underfilled probe advanced to phase %d", bbr.cycleIndex)
	}
	sample.losses = mss
	bbr.updateCycle(bbrSample(sample), mss)
	if bbr.cycleIndex != 1 {
		t.Fatalf("loss-limited probe phase = %d, want 1", bbr.cycleIndex)
	}
}

func TestBBRProbeBandwidthUsesDeliveryClock(t *testing.T) {
	const mss = 1000
	cycleStamp := tcpDeliveryTimestampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 2, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + tcpDeliveryTimestamp(5*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond,
	}
	bbr.updateCycle(bbrSample(tcpDeliveryRateSample{ackTime: time.Unix(100, 0)}), mss)
	if bbr.cycleIndex != 2 {
		t.Fatalf("zero-delivery ACK advanced ProbeBW phase to %d", bbr.cycleIndex)
	}
	bbr.deliveredStamp = cycleStamp + tcpDeliveryTimestamp(20*time.Millisecond/time.Microsecond)
	bbr.updateCycle(bbrSample(tcpDeliveryRateSample{ackTime: time.Unix(100, 0)}), mss)
	if bbr.cycleIndex != 3 {
		t.Fatalf("delivery clock did not advance ProbeBW phase: %d", bbr.cycleIndex)
	}
}

func TestBBRLongTermPolicerDetection(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{delivered: 1000, totalLost: 300}
	bbr.updateLongTermBandwidth(bbrSample(tcpDeliveryRateSample{losses: 300, ackTime: start}))
	for interval := 1; interval <= 2; interval++ {
		bbr.longTermRounds = bbrLongTermMinimumRounds
		bbr.delivered += 10_000
		bbr.totalLost += 3000
		bbr.updateLongTermBandwidth(bbrSample(tcpDeliveryRateSample{losses: 3000, ackTime: start.Add(time.Duration(interval) * time.Second)}))
	}
	if !bbr.longTermUseBandwidth || bbr.longTermBandwidth != 10_000 {
		t.Fatalf("policer model = use %t rate %v", bbr.longTermUseBandwidth, bbr.longTermBandwidth)
	}
}

func TestBBRPolicerSamplingProcessesFirstLossRound(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{delivered: 1000, totalLost: 300, roundStart: true}
	bbr.updateLongTermBandwidth(bbrSample(tcpDeliveryRateSample{losses: 300, ackTime: start}))
	if !bbr.longTermSampling || bbr.longTermRounds != 1 {
		t.Fatalf("first-loss sampling state = active %t, rounds %d", bbr.longTermSampling, bbr.longTermRounds)
	}

	bbr = bbrCongestionControl{delivered: 1000, totalLost: 300, roundStart: true}
	bbr.updateLongTermBandwidth(bbrSample(tcpDeliveryRateSample{losses: 300, ackTime: start, schedulerLimited: true}))
	if bbr.longTermSampling || bbr.longTermRounds != 0 || bbr.longTermBandwidth != 0 {
		t.Fatalf("locally limited first-loss sample retained policer state: %+v", bbr)
	}
}

func TestBBRPolicerGainOnlyOverridesProbeBandwidth(t *testing.T) {
	bbr := bbrCongestionControl{longTermUseBandwidth: true}
	if gain := bbr.pacingGain(); gain != bbrStartupPacingGain {
		t.Fatalf("policed Startup gain = %v, want %v", gain, bbrStartupPacingGain)
	}
	bbr.mode = bbrDrain
	if gain := bbr.pacingGain(); gain != bbrDrainPacingGain {
		t.Fatalf("policed Drain gain = %v, want %v", gain, bbrDrainPacingGain)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.cycleIndex = 0
	if gain := bbr.pacingGain(); gain != 1 {
		t.Fatalf("policed ProbeBW gain = %v, want 1", gain)
	}
}

func TestBBRPacingRateOnlyFallsAfterStartup(t *testing.T) {
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.setPacingRate(0, 0)
	initial := bbr.pacingRate
	bbr.bandwidth = 500_000
	bbr.setPacingRate(0, 0)
	if bbr.pacingRate != initial {
		t.Fatalf("Startup pacing rate fell from %v to %v", initial, bbr.pacingRate)
	}
	bbr.fullBandwidthReached = true
	bbr.setPacingRate(0, 0)
	if bbr.pacingRate >= initial {
		t.Fatalf("full-pipe pacing rate remained %v, initial %v", bbr.pacingRate, initial)
	}
}

func TestBBRInitialPacingUsesWindowAndSRTT(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{bandwidth: 20_000}
	bbr.setPacingRate(10*mss, time.Millisecond)
	want := float64(10*mss) / time.Millisecond.Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != want || !bbr.hasSeenRTT {
		t.Fatalf("initial BBR pacing = %v seen %t, want %v/true", bbr.pacingRate, bbr.hasSeenRTT, want)
	}
	bbr.bandwidth = 1000
	bbr.setPacingRate(10*mss, time.Millisecond)
	if bbr.pacingRate != want {
		t.Fatalf("Startup lowered initialized pacing rate to %v", bbr.pacingRate)
	}
}

func TestBBRInitialPacingUsesNominalRTTUntilMeasured(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{}
	bbr.initializePacingRate(10*mss, 0)
	want := float64(10*mss) / time.Millisecond.Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != want || bbr.hasSeenRTT {
		t.Fatalf("nominal BBR pacing = %v seen %t, want %v/false", bbr.pacingRate, bbr.hasSeenRTT, want)
	}
	bbr.setPacingRate(10*mss, 10*time.Millisecond)
	realWant := float64(10*mss) / (10 * time.Millisecond).Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != realWant || !bbr.hasSeenRTT {
		t.Fatalf("measured BBR pacing = %v seen %t, want %v/true", bbr.pacingRate, bbr.hasSeenRTT, realWant)
	}
}

func TestBBRInitialPacingQuantumAllowsTenSegments(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).pacingRate = 10_000
	for segment := 0; segment < tcpPacingInitialBurst; segment++ {
		if delay := controller.pacingDelay(start, mss, 10*mss, uint32(segment*mss), mss, 100*time.Millisecond, ^uint32(0)); delay != 0 {
			t.Fatalf("initial segment %d pacing delay = %v", segment+1, delay)
		}
		flight := uint32(segment * mss)
		_, _ = controller.onDataSend(mss, mss, start, monotonicStamp(segment+1), flight, 10*mss, flight, 0, 0)
	}
	if delay := controller.pacingDelay(start, mss, 10*mss, 10*mss, mss, 100*time.Millisecond, ^uint32(0)); delay <= 0 {
		t.Fatalf("post-initial-quantum pacing delay = %v", delay)
	}
}

func TestBBRPacedBatchBoundsFutureCredit(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.initialize(start, 0, time.Millisecond, 100*mss, 100*mss, mss, 1)
	controller.pacingSegments = tcpPacingInitialBurst
	bbrState(t, &controller).pacingRate = 1_000_000
	bbrState(t, &controller).nextSend = start
	budget := bbrUserspacePacingBudget(bbrState(t, &controller).pacingRate, mss)
	for sent := 0; sent < 2*budget; sent += mss {
		if delay := controller.pacingDelay(start, mss, 100*mss, uint32(sent+mss), mss, time.Millisecond, 100*mss); delay != 0 {
			t.Fatalf("paced byte %d delayed by %v before credit exhaustion", sent, delay)
		}
		flight := uint32(sent + mss)
		_, _ = controller.onDataSend(mss, mss, start, monotonicStamp(sent+1), flight, 100*mss, flight, 0, 0)
	}
	if delay := controller.pacingDelay(start, mss, 100*mss, uint32(2*budget), mss, time.Millisecond, 100*mss); delay <= 0 {
		t.Fatalf("sender released more than one future %d-byte pacing group", budget)
	}
}

func TestBBRProbeRTTDoesNotRetainOldRoundTarget(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).mode = bbrProbeBandwidth
	bbrState(t, &controller).bandwidth = 10 * 1024 * 1024
	bbrState(t, &controller).bandwidthFilter.reset(0, bbrState(t, &controller).bandwidth)
	bbrState(t, &controller).minimumRTT = 10 * time.Millisecond
	bbrState(t, &controller).minimumRTTStamp = time.Unix(1, 0)
	start := time.Unix(100, 0)
	window := uint32(1024 * 1024)
	window = controller.onACK(window, mss, mss, start, 10*time.Millisecond, 10*time.Millisecond, window, false)
	if bbrState(t, &controller).mode != bbrProbeRTT {
		t.Fatalf("ProbeRTT entry mode = %v", bbrState(t, &controller).mode)
	}
	flight := uint32(1024 * 1024)
	now := start
	for bbrState(t, &controller).probeDone.IsZero() && flight > 0 {
		now = now.Add(time.Millisecond)
		acknowledged := uint32(mss)
		if acknowledged > flight {
			acknowledged = flight
		}
		window = controller.onACK(window, acknowledged, mss, now, 10*time.Millisecond, 10*time.Millisecond, flight, false)
		flight -= acknowledged
	}
	if bbrState(t, &controller).probeDone.IsZero() {
		t.Fatal("ProbeRTT did not begin after draining the entry flight")
	}
}

func TestBBRPacingDelaySaturates(t *testing.T) {
	controller := bbrCongestionControl{pacingRate: 1e-20}
	start := time.Unix(100, 0)
	_ = controller.onDeliverySend(start, 1, 1)
	controller.consumePacingBurst(1)
	controller.advancePacing(1, 1, start)
	if controller.nextSend.Before(start) {
		t.Fatalf("overflowed BBR pacing deadline = %v", controller.nextSend)
	}
}

func TestBBRLateWakeRetainsBoundedPacingDebt(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000, pacingRate: 1_000_000,
		minimumRTT: 100 * time.Millisecond, minimumRTTStamp: now, nextSend: start,
	}
	for segment := 0; segment < 2; segment++ {
		bbr.advancePacing(mss, mss, now)
	}
	if bbr.nextSend != now {
		t.Fatalf("late BBR catch-up = next %v, want %v", bbr.nextSend, now)
	}
	bbr.advancePacing(mss, mss, now)
	if bbr.nextSend != now.Add(time.Millisecond) {
		t.Fatalf("post-catch-up BBR deadline = %v, want %v", bbr.nextSend, now.Add(time.Millisecond))
	}
}

func TestBBRLatePacingWakeMarksDeliverySampleSchedulerLimited(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.initialize(start, 0, 10*time.Millisecond, 20*mss, 20*mss, mss, 1)
	bbr := bbrState(t, &controller)
	bbr.pacingRate = 1_000_000
	bbr.nextSend = start.Add(10 * time.Millisecond)
	controller.delivery.delivered = 1000
	controller.pacingSegments = tcpPacingInitialBurst
	if delay := controller.pacingDelay(start, mss, 20*mss, 10*mss, mss, 10*time.Millisecond, 20*mss); delay != 8*time.Millisecond {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	if delay := controller.pacingDelay(start.Add(10*time.Millisecond), mss, 20*mss, 10*mss, mss, 10*time.Millisecond, 20*mss); delay != 0 {
		t.Fatalf("late-wake pacing delay = %v", delay)
	}
	if !controller.schedulerLimited() || controller.delivery.schedulerLimitedUntil != 11_000 || controller.delivery.schedulerLimitedEvents != 1 {
		t.Fatalf("late-wake state = scheduler %t boundary %d events %d", controller.schedulerLimited(), controller.delivery.schedulerLimitedUntil, controller.delivery.schedulerLimitedEvents)
	}
	controller.markApplicationLimited(mss)
	if controller.delivery.applicationLimitedUntil != 2_000 {
		t.Fatalf("refreshed application-limit boundary = %d, want 2000", controller.delivery.applicationLimitedUntil)
	}
}

func TestBBRSchedulerLimitUsesUserspaceWakeDeadline(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	nextSend := start.Add(10 * time.Millisecond)
	deadline := nextSend.Add(-2 * time.Millisecond)

	early := bbrCongestionControl{delivered: 1000, pacingRate: 1_000_000, nextSend: nextSend}
	if delay, limited := early.pacingDelay(start, mss, mss, 10*mss); delay != 8*time.Millisecond || limited {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	if delay, limited := early.pacingDelay(deadline.Add(-time.Microsecond), mss, mss, 10*mss); delay != time.Microsecond || limited {
		t.Fatalf("pre-deadline pacing delay = %v, want 1us", delay)
	}

	late := bbrCongestionControl{delivered: 1000, pacingRate: 1_000_000, nextSend: nextSend}
	if delay, limited := late.pacingDelay(start, mss, mss, 10*mss); delay != 8*time.Millisecond || limited {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	now := deadline.Add(tcpUserspaceSchedulingTolerance + time.Microsecond)
	if !now.Before(nextSend) {
		t.Fatal("test wake must remain earlier than the pacing clock")
	}
	if delay, limited := late.pacingDelay(now, mss, mss, 10*mss); delay != 0 || !limited {
		t.Fatalf("late userspace wake delay = %v, want 0", delay)
	}

	unarmed := bbrCongestionControl{delivered: 1000, pacingRate: 1_000_000, nextSend: nextSend}
	if delay, limited := unarmed.pacingDelay(now, mss, mss, 10*mss); delay != 0 || limited {
		t.Fatalf("unarmed pacing delay = %v, want 0", delay)
	}
}

func TestBBRSchedulerLimitedSampleCannotLowerBandwidthModel(t *testing.T) {
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrSample(tcpDeliveryRateSample{
		priorDelivered: 1, delivered: 1000, interval: 2 * time.Millisecond,
		ackTime: time.Unix(100, 0), schedulerLimited: true, valid: true,
	}))

	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("scheduler-limited sample lowered bandwidth to %v", bbr.bandwidth)
	}
}

func TestBBRSchedulerLimitedSampleDoesNotCreateACKAggregation(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{
		bandwidth: 1_000_000, ackEpochStamp: start, ackEpochBytes: 1000,
		extraACKed: [2]uint32{200, 100},
	}
	bbr.updateACKAggregation(bbrSample(tcpDeliveryRateSample{
		acked: 10_000, ackTime: start.Add(time.Millisecond),
		schedulerLimited: true, valid: true,
	}),

		100_000, 1000)

	if bbr.ackEpochStamp != start.Add(time.Millisecond) || bbr.ackEpochBytes != 0 {
		t.Fatalf("scheduler-limited ACK epoch = %v/%d", bbr.ackEpochStamp, bbr.ackEpochBytes)
	}
	if bbr.extraACKed != [2]uint32{200, 100} {
		t.Fatalf("scheduler-limited ACK changed aggregation history: %v", bbr.extraACKed)
	}

	bbr.roundStart = true
	bbr.extraACKedRounds = bbrExtraACKedWindow - 1
	bbr.updateACKAggregation(bbrSample(tcpDeliveryRateSample{
		acked: 10_000, ackTime: start.Add(2 * time.Millisecond),
		schedulerLimited: true, valid: true,
	}),

		100_000, 1000)

	if bbr.extraACKedRounds != 0 || bbr.extraACKedIndex != 1 || bbr.extraACKed != [2]uint32{200, 0} {
		t.Fatalf("scheduler-limited round did not age aggregation history: rounds %d, index %d, values %v", bbr.extraACKedRounds, bbr.extraACKedIndex, bbr.extraACKed)
	}
}

func TestBBRSchedulerLimitedRoundsCanEndStartup(t *testing.T) {
	bbr := bbrCongestionControl{
		mode: bbrStartup, bandwidth: 1_000_000,
		fullBandwidth: 1_000_000,
	}
	for round := 0; round < bbrFullBandwidthRounds; round++ {
		bbr.roundStart = true
		bbr.checkFullBandwidth(bbrSample(tcpDeliveryRateSample{
			delivered: 1000, interval: time.Millisecond,
			schedulerLimited: true, valid: true,
		}))

	}
	if !bbr.fullBandwidthReached {
		t.Fatal("BBR stayed in Startup under persistent scheduler limitation")
	}
}

func TestBBRPacingTimerConsumesWakeWhenSendIsBlocked(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{delivered: 1000, pacingWakeDeadline: start}
	if !bbr.consumePacingWake(start.Add(tcpUserspaceSchedulingTolerance+time.Microsecond), 10_000) || !bbr.pacingWakeDeadline.IsZero() {
		t.Fatalf("consumed pacing wake = deadline %v", bbr.pacingWakeDeadline)
	}
	if bbr.consumePacingWake(start.Add(time.Second), 10_000) {
		t.Fatal("one pacing wake was counted twice")
	}
}

func TestBBRPacingWakeCanBeRepurposedWithoutSchedulerSample(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).pacingWakeDeadline = time.Unix(100, 0)
	controller.cancelPacingWake()
	controller.onPacingWake(time.Unix(101, 0), 10_000)
	if !bbrState(t, &controller).pacingWakeDeadline.IsZero() || controller.schedulerLimited() || controller.delivery.schedulerLimitedEvents != 0 {
		t.Fatalf("cancelled pacing wake = deadline %v, limited %t, events %d", bbrState(t, &controller).pacingWakeDeadline, controller.schedulerLimited(), controller.delivery.schedulerLimitedEvents)
	}
}

func TestBBRRetransmissionDoesNotCatchUpPacingDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000, pacingRate: 1_000_000, nextSend: start}
	bbr.advanceRetransmissionPacing(1000, 1000, now)
	if bbr.nextSend != now.Add(time.Millisecond) {
		t.Fatalf("retransmission BBR pacing = next %v", bbr.nextSend)
	}
}

func TestBBRStartupSampleCanGrowPastInitialFlight(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, 2*mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, true)
	initialBandwidth := bbrState(t, &controller).bandwidth
	window = controller.onACK(window, 8*mss, mss, start.Add(25*time.Millisecond), 100*time.Millisecond, 0, window, true)
	if bbrState(t, &controller).bandwidth <= initialBandwidth {
		t.Fatalf("BBR bandwidth = %v, want growth above bootstrap %v", bbrState(t, &controller).bandwidth, initialBandwidth)
	}
}

func TestBBRWaitsForValidRTTBeforeSampling(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 0, 0, window, true)
	if bbrState(t, &controller).bandwidth != 0 {
		t.Fatalf("BBR sampled without an RTT: bandwidth=%v", bbrState(t, &controller).bandwidth)
	}
	controller.onACK(window, mss, mss, start.Add(time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, window, true)
	if bbrState(t, &controller).bandwidth == 0 {
		t.Fatal("BBR did not bootstrap from the first valid RTT")
	}
}

func TestBBRStartupIgnoresRoundsWithoutBandwidthSamples(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 0, 100*time.Millisecond, window, true)
	for round := 0; round < bbrFullBandwidthRounds+1; round++ {
		window = controller.onACK(window, mss, mss, start, 0, 0, window, false)
	}
	if bbrState(t, &controller).fullRounds != 0 || bbrState(t, &controller).mode != bbrStartup {
		t.Fatalf("BBR counted sampleless rounds: fullRounds=%d mode=%v", bbrState(t, &controller).fullRounds, bbrState(t, &controller).mode)
	}
}

func TestBBRStartupPublishesDrainThreshold(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).fullBandwidthReached = true
	bbrState(t, &controller).bandwidth = 1_000_000
	bbrState(t, &controller).minimumRTT = 10 * time.Millisecond
	bbrState(t, &controller).minimumRTTStamp = time.Unix(100, 0)
	want := uint32(bbrState(t, &controller).quantizeWindowAt(bbrState(t, &controller).modelWindowForBandwidth(bbrState(t, &controller).bandwidth, 1, mss), mss, false))
	sample := tcpDeliveryRateSample{
		priorInFlight: 100 * mss, inFlight: 100 * mss, ackTime: time.Unix(100, 0),
	}
	window, threshold := controller.onDeliveryRateSample(100*mss, ^uint32(0), mss, 0, &sample)
	if bbrState(t, &controller).mode != bbrDrain || window != 100*mss || threshold != want {
		t.Fatalf("BBR drain publication = mode %v window %d threshold %d, want DRAIN/%d/%d", bbrState(t, &controller).mode, window, threshold, 100*mss, want)
	}
}

func TestBBRStartupProbeRTTDoesNotPublishDrainThreshold(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).minimumRTT = 10 * time.Millisecond
	bbrState(t, &controller).minimumRTTStamp = time.Unix(100, 0)
	sample := tcpDeliveryRateSample{
		ackTime: time.Unix(100, 0).Add(bbrMinRTTWindow + time.Second),
	}
	_, threshold := controller.onDeliveryRateSample(10*mss, ^uint32(0), mss, 0, &sample)
	if bbrState(t, &controller).mode != bbrProbeRTT || threshold != 0 {
		t.Fatalf("Startup ProbeRTT = mode %v threshold %d", bbrState(t, &controller).mode, threshold)
	}
}

func TestBBRDrainUsesMinimumWindowFloor(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).mode = bbrDrain
	bbrState(t, &controller).bandwidth = 1000
	bbrState(t, &controller).minimumRTT = time.Millisecond
	start := time.Unix(100, 0)
	bbrState(t, &controller).minimumRTTStamp = start
	controller.onACK(10*mss, mss, mss, start, time.Millisecond, time.Millisecond, bbrMinimumCongestionMSS*mss, false)
	if bbrState(t, &controller).mode != bbrProbeBandwidth {
		t.Fatalf("low-BDP BBR remained in Drain: mode=%v", bbrState(t, &controller).mode)
	}
}

func TestBBRExpiredMinimumRTTCanIncrease(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	bbrState(t, &controller).minimumRTT = 10 * time.Millisecond
	bbrState(t, &controller).minimumRTTStamp = start.Add(-bbrMinRTTWindow - time.Nanosecond)
	bbrState(t, &controller).bandwidth = 100000
	controller.onACK(10*mss, mss, mss, start, 30*time.Millisecond, 30*time.Millisecond, 2*mss, false)
	if bbrState(t, &controller).minimumRTT != 30*time.Millisecond || bbrState(t, &controller).mode != bbrProbeRTT {
		t.Fatalf("expired min RTT/mode = %v/%v, want 30ms/ProbeRTT", bbrState(t, &controller).minimumRTT, bbrState(t, &controller).mode)
	}
	if bbrState(t, &controller).probeDone.IsZero() {
		t.Fatal("ProbeRTT did not start after flight reached its floor")
	}
}

func TestBBRExpiredMinimumRTTIgnoresDelayedACK(t *testing.T) {
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, minimumRTT: 10 * time.Millisecond,
		minimumRTTStamp: time.Unix(100, 0), idleRestart: true,
	}
	now := bbr.minimumRTTStamp.Add(bbrMinRTTWindow + time.Nanosecond)
	window := bbr.updateMinimumRTT(10_000, bbrSample(tcpDeliveryRateSample{ackTime: now, rtt: 30 * time.Millisecond, ackDelayed: true}), 1000)
	if bbr.minimumRTT != 10*time.Millisecond || window != 10_000 {
		t.Fatalf("delayed ACK replaced expired min RTT: min %v window %d", bbr.minimumRTT, window)
	}
	bbr.updateMinimumRTT(window, bbrSample(tcpDeliveryRateSample{ackTime: now, rtt: 5 * time.Millisecond, ackDelayed: true}), 1000)
	if bbr.minimumRTT != 5*time.Millisecond {
		t.Fatalf("lower delayed-ACK RTT was ignored: min %v", bbr.minimumRTT)
	}
}

func TestBBRIdleRestartResetsSamplingInterval(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	now := time.Unix(150, 0)
	controller.initialize(now, 0, 0, 10_000, 10_000, 1000, 1)
	bbrState(t, &controller).bandwidth = 100000
	bbrState(t, &controller).pacingRate = 100000
	controller.delivery.firstSent = 10
	controller.delivery.deliveredStamp = 10
	bbrState(t, &controller).nextSend = time.Unix(200, 0)
	stamp := monotonicStamp(20*time.Microsecond) + 1
	snapshot, _ := controller.onDataSend(1000, 1000, now, stamp, 0, 10_000, 0, 0, 0)
	if snapshot.firstSent != tcpDeliveryTimestampAt(stamp) || snapshot.deliveredStamp != tcpDeliveryTimestampAt(stamp) || bbrState(t, &controller).nextSend.Before(now) || !bbrState(t, &controller).idleRestart {
		t.Fatalf("BBR idle restart state = first %d delivered %d next %v", snapshot.firstSent, snapshot.deliveredStamp, bbrState(t, &controller).nextSend)
	}
	if bbrState(t, &controller).ackEpochStamp != now || bbrState(t, &controller).ackEpochBytes != 0 {
		t.Fatalf("BBR idle ACK epoch = %v/%d, want %v/0", bbrState(t, &controller).ackEpochStamp, bbrState(t, &controller).ackEpochBytes, now)
	}
}

func TestBBRIdleRestartUsesNeutralPacingAndSkipsProbeRTT(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	controller.initialize(start, 10*time.Millisecond, 10*time.Millisecond, 10*mss, 10*mss, mss, 1)
	bbrState(t, &controller).mode = bbrProbeBandwidth
	bbrState(t, &controller).cycleIndex = 0
	bbrState(t, &controller).bandwidth = 100000
	bbrState(t, &controller).pacingRate = 100000
	bbrState(t, &controller).minimumRTT = 10 * time.Millisecond
	bbrState(t, &controller).minimumRTTStamp = start.Add(-bbrMinRTTWindow)
	_, _ = controller.onDataSend(mss, mss, start, 1, 0, 10*mss, 0, 0, 0)
	if gain := bbrState(t, &controller).pacingGain(); gain != bbrProbeBandwidthGains[0] {
		t.Fatalf("BBR idle restart saved pacing gain = %v, want %v", gain, bbrProbeBandwidthGains[0])
	}
	if bbrState(t, &controller).pacingRate != bbrState(t, &controller).bandwidth*bbrPacingMargin {
		t.Fatalf("BBR idle restart pacing rate = %v, want %v", bbrState(t, &controller).pacingRate, bbrState(t, &controller).bandwidth*bbrPacingMargin)
	}
	controller.onACK(10*mss, mss, mss, start.Add(10*time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, mss, false)
	if bbrState(t, &controller).mode == bbrProbeRTT || bbrState(t, &controller).idleRestart {
		t.Fatalf("BBR idle restart mode/flag = %v/%v", bbrState(t, &controller).mode, bbrState(t, &controller).idleRestart)
	}
}

func TestBBRIdleRestartRetainsProbeBandwidthPhase(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	cycleStamp := tcpDeliveryTimestampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 0, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + tcpDeliveryTimestamp(20*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond, minimumRTTStamp: start,
		bandwidth: 1_000_000, pacingRate: 1_000_000, idleRestart: true,
	}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	sample := tcpDeliveryRateSample{
		priorDelivered: 1, delivered: mss, acked: mss,
		priorInFlight: mss, inFlight: 0, interval: 10 * time.Millisecond,
		rtt: 10 * time.Millisecond, smoothedRTT: 10 * time.Millisecond,
		ackTime: start, applicationLimited: true, valid: true,
	}
	bbr.delivered = mss + 1
	_, _ = bbr.onRateSample(10*mss, mss, bbrSample(sample))
	if bbr.cycleIndex != 0 {
		t.Fatalf("idle restart advanced underfilled high-gain phase to %d", bbr.cycleIndex)
	}
	if bbr.idleRestart {
		t.Fatal("delivery ACK retained idle-restart state")
	}
}

func TestBBRIdleRestartCompletesProbeRTT(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := bbrCongestionControl{
		mode: bbrProbeRTT, fullBandwidthReached: true, priorWindow: 20 * mss,
		applicationLimited: true,
		probeDone:          now.Add(-time.Millisecond),
		bandwidth:          1_000_000, pacingRate: 1_000_000,
	}
	window := bbr.onDeliverySend(now, 0, bbrMinimumCongestionMSS*mss)
	if bbr.mode != bbrProbeBandwidth || window != 20*mss || bbr.minimumRTTStamp != now {
		t.Fatalf("idle ProbeRTT exit = mode %v window %d stamp %v", bbr.mode, window, bbr.minimumRTTStamp)
	}
}

func TestBBRPacketConservationEndsAfterOneRound(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, bandwidth: 1_000_000, minimumRTT: 10 * time.Millisecond,
		minimumRTTStamp: time.Unix(100, 0), fullBandwidthReached: true, priorWindow: 20 * mss,
	}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.delivered = 2 * mss
	start := time.Unix(100, 0)
	sample := tcpDeliveryRateSample{
		priorDelivered: 0, delivered: 2 * mss, acked: 2 * mss,
		priorInFlight: 10 * mss, inFlight: 8 * mss, interval: 10 * time.Millisecond,
		rtt: 10 * time.Millisecond, ackTime: start, fastRecovery: true, recovery: true, valid: true,
	}
	window, _ := bbr.onRateSample(20*mss, mss, bbrSample(sample))
	if !bbr.recovery || !bbr.packetConservation || window != 10*mss {
		t.Fatalf("BBR recovery entry = recovery %t conservation %t window %d", bbr.recovery, bbr.packetConservation, window)
	}
	bbr.delivered += 2 * mss
	sample.priorDelivered = uint32(bbr.delivered - 2*mss)
	sample.inFlight = 6 * mss
	sample.ackTime = start.Add(10 * time.Millisecond)
	window, _ = bbr.onRateSample(window, mss, bbrSample(sample))
	if bbr.packetConservation {
		t.Fatal("BBR retained packet conservation after a packet-timed round")
	}
	sample.fastRecovery = false
	sample.recovery = false
	sample.acked = mss
	sample.delivered = mss
	sample.inFlight = 5 * mss
	sample.ackTime = start.Add(20 * time.Millisecond)
	window, _ = bbr.onRateSample(window, mss, bbrSample(sample))
	if bbr.recovery || window != 21*mss {
		t.Fatalf("BBR recovery exit = recovery %t window %d, want false/%d", bbr.recovery, window, 21*mss)
	}
}

func TestBBRZeroDeliveryLossSampleDefersPacketConservation(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{priorWindow: 20 * mss}
	window, _ := bbr.onRateSample(20*mss, mss, bbrSample(tcpDeliveryRateSample{
		losses: mss, priorInFlight: 10 * mss, inFlight: 9 * mss,
		ackTime: time.Unix(100, 0), recovery: true, fastRecovery: true,
	}))

	if bbr.recovery || bbr.packetConservation || window != 20*mss {
		t.Fatalf("zero-delivery loss sample recovery = %t/%t window %d", bbr.recovery, bbr.packetConservation, window)
	}
}

func TestBBRLossSamplingSeparatesACKAndTimerEvents(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.noteLoss(1000, false)
	var sample tcpDeliveryRateSample
	controller.finishDeliveryRateSample(&sample, 0, 0, 0, time.Unix(100, 0), 1, 0, 0, 0, false)
	if sample.losses != 0 {
		t.Fatalf("timer loss repeated on ACK as %d bytes", sample.losses)
	}
	controller.noteLoss(500, true)
	controller.finishDeliveryRateSample(&sample, 0, 0, 0, time.Unix(101, 0), 2, 0, 0, 0, false)
	if sample.losses != 500 {
		t.Fatalf("ACK loss sample = %d, want 500", sample.losses)
	}
}

func TestBBRTimeoutRestoresWindowOnlyAfterLossRecovery(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	bbrState(t, &controller).recovery = true
	bbrState(t, &controller).packetConservation = true
	bbrState(t, &controller).fullBandwidth = 1_000_000
	bbrState(t, &controller).fullRounds = 2
	now := time.Unix(100, 0)
	const slowStartThreshold = 15 * mss
	if threshold := controller.onTimeout(20*mss, 10*mss, slowStartThreshold, mss, now); threshold != slowStartThreshold {
		t.Fatalf("BBR timeout threshold = %d, want %d", threshold, slowStartThreshold)
	}
	if bbrState(t, &controller).recovery || !bbrState(t, &controller).lossRecovery || bbrState(t, &controller).packetConservation || bbrState(t, &controller).fullBandwidth != 0 || !bbrState(t, &controller).roundStart || !bbrState(t, &controller).longTermSampling {
		t.Fatalf("BBR timeout state = recovery %t loss %t conservation %t full_bw %v round %t policer %t", bbrState(t, &controller).recovery, bbrState(t, &controller).lossRecovery, bbrState(t, &controller).packetConservation, bbrState(t, &controller).fullBandwidth, bbrState(t, &controller).roundStart, bbrState(t, &controller).longTermSampling)
	}
	sample := tcpDeliveryRateSample{acked: mss, delivered: mss, recovery: true, ackTime: now.Add(time.Millisecond)}
	if window := bbrState(t, &controller).setCongestionWindow(mss, bbrSample(sample), mss); window != bbrMinimumCongestionMSS*mss || !bbrState(t, &controller).lossRecovery {
		t.Fatalf("BBR active loss window/state = %d/%t", window, bbrState(t, &controller).lossRecovery)
	}
	sample.recovery = false
	if window := bbrState(t, &controller).setCongestionWindow(mss, bbrSample(sample), mss); window != 21*mss || bbrState(t, &controller).lossRecovery {
		t.Fatalf("BBR completed loss window/state = %d/%t, want %d/false", window, bbrState(t, &controller).lossRecovery, 21*mss)
	}
}

func TestBBRSpuriousRecoveryUndoRetainsDeliveryAccounting(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.delivery.delivered = 1000
	controller.syncDeliveryState()
	var undo tcpRecoveryUndo
	undo.begin(false, 2000, 20_000, 20_000, 10_000, &controller, rttEstimator{})
	controller.delivery.delivered = 5000
	controller.syncDeliveryState()
	bbrState(t, &controller).delivered = 5000
	bbrState(t, &controller).bandwidth = 1_000_000
	bbrState(t, &controller).fullBandwidth = 1_000_000
	bbrState(t, &controller).fullRounds = 2
	bbrState(t, &controller).longTermSampling = true
	bbrState(t, &controller).recovery = true
	bbrState(t, &controller).packetConservation = true
	_, _ = undo.restore(1000, 10_000, 1000, 1000, &controller, time.Unix(100, 0), CongestionPhaseOpen)
	if bbrState(t, &controller).delivered != 5000 || bbrState(t, &controller).bandwidth != 1_000_000 {
		t.Fatalf("BBR undo rewound delivery model: delivered %d bandwidth %v", bbrState(t, &controller).delivered, bbrState(t, &controller).bandwidth)
	}
	if bbrState(t, &controller).fullBandwidth != 0 || bbrState(t, &controller).fullRounds != 0 || bbrState(t, &controller).longTermSampling || bbrState(t, &controller).recovery || bbrState(t, &controller).lossRecovery || bbrState(t, &controller).packetConservation {
		t.Fatalf("BBR undo state = full %v/%d policer %t recovery %t/%t/%t", bbrState(t, &controller).fullBandwidth, bbrState(t, &controller).fullRounds, bbrState(t, &controller).longTermSampling, bbrState(t, &controller).recovery, bbrState(t, &controller).lossRecovery, bbrState(t, &controller).packetConservation)
	}
}

func TestBBRSaveWindowReplacesStaleOpenState(t *testing.T) {
	bbr := bbrCongestionControl{priorWindow: 20_000}
	bbr.saveWindow(10_000)
	if bbr.priorWindow != 10_000 {
		t.Fatalf("open-state prior window = %d, want 10000", bbr.priorWindow)
	}
	bbr.recovery = true
	bbr.saveWindow(8_000)
	bbr.saveWindow(12_000)
	if bbr.priorWindow != 12_000 {
		t.Fatalf("recovery prior window = %d, want 12000", bbr.priorWindow)
	}
}

func TestBBRInitialCycleUsesLinuxPhaseSet(t *testing.T) {
	controller := bbrCongestionControl{cycleRandom: 1}
	counts := [len(bbrProbeBandwidthGains)]int{}
	now := time.Unix(100, 0)
	for sample := 0; sample < 4096; sample++ {
		controller.resetProbeBandwidth(now)
		if controller.cycleIndex < 0 || controller.cycleIndex >= len(counts) {
			t.Fatalf("ProbeBW cycle = %d", controller.cycleIndex)
		}
		counts[controller.cycleIndex]++
	}
	if counts[1] != 0 {
		t.Fatalf("ProbeBW initialized in drain phase %d times", counts[1])
	}
	for phase, count := range counts {
		if phase != 1 && count == 0 {
			t.Fatalf("ProbeBW phase %d was never selected: %v", phase, counts)
		}
	}
}

func TestBBRCycleRandomIsControllerLocal(t *testing.T) {
	first := bbrCongestionControl{cycleRandom: 1}
	second := bbrCongestionControl{cycleRandom: 2}
	now := time.Unix(100, 0)
	equal := true
	for sample := 0; sample < 16; sample++ {
		if first.nextCycleRandom(now) != second.nextCycleRandom(now) {
			equal = false
		}
	}
	if equal {
		t.Fatal("independent BBR controllers produced identical random streams")
	}
}

func TestBBRCycleRandomConcurrentInitialization(t *testing.T) {
	const controllers = 256
	start := make(chan struct{})
	cycles := make(chan int, controllers)
	var workers sync.WaitGroup
	workers.Add(controllers)
	for index := 0; index < controllers; index++ {
		go func() {
			defer workers.Done()
			<-start
			controller := bbrCongestionControl{}
			controller.resetProbeBandwidth(time.Unix(100, 0))
			cycles <- controller.cycleIndex
		}()
	}
	close(start)
	workers.Wait()
	close(cycles)
	for cycle := range cycles {
		if cycle < 0 || cycle >= len(bbrProbeBandwidthGains) || cycle == 1 {
			t.Fatalf("concurrent ProbeBW cycle = %d", cycle)
		}
	}
}

func BenchmarkBBRResetProbeBandwidth(b *testing.B) {
	controller := newBBRCongestionControl()
	now := time.Unix(100, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		controller.resetProbeBandwidth(now)
	}
	if controller.cycleIndex < 0 {
		b.Fatal("invalid ProbeBW cycle")
	}
}

func BenchmarkBBRInitializeProbeBandwidth(b *testing.B) {
	now := time.Unix(100, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		controller := bbrCongestionControl{}
		controller.resetProbeBandwidth(now)
		if controller.cycleIndex < 0 {
			b.Fatal("invalid ProbeBW cycle")
		}
	}
}

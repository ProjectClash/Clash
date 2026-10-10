package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestBuiltInCongestionControllerLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout assertion")
	}
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Reno", unsafe.Sizeof(renoCongestionControl{}), 16},
		{"CUBIC", unsafe.Sizeof(cubicCongestionControl{}), 256},
		{"BBR", unsafe.Sizeof(bbrCongestionControl{}), 360},
		{"BBRv3", unsafe.Sizeof(bbr3CongestionControl{}), 400},
	}
	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("%s controller size = %d, want %d; reassess the lossy-connection allocation class", test.name, test.got, test.want)
		}
	}
}

type testPacedCongestionControl struct {
	dataEvents  int
	pacedSends  int
	retransmits int
}

func (c *testPacedCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventPacketSent:
		c.dataEvents++
		c.pacedSends++
	case CongestionEventPacketRetransmitted:
		c.retransmits++
	case CongestionEventPacing:
		if event.Pacing.Operation == CongestionPacingQuery {
			event.Pacing.Delay = 7 * time.Millisecond
		}
	}
}

type testDeliveryCongestionControl struct {
	rateSamples int
}

func (c *testDeliveryCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventACK {
		c.rateSamples++
		event.State.CongestionWindow++
	}
}

func TestCongestionControllerComposesPacingWithoutDeliverySampling(t *testing.T) {
	implementation := &testPacedCongestionControl{}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name:     "test-paced",
		New:      func(CongestionControlContext) CongestionController { return implementation },
		Features: CongestionControlFeatureCustomPacing | CongestionControlFeatureTransmissionEvents,
	})
	if controller.usesDeliveryRate() || !controller.customPacing() {
		t.Fatalf("capabilities = delivery %t custom pacing %t", controller.usesDeliveryRate(), controller.customPacing())
	}
	if delay := controller.pacingDelay(time.Unix(100, 0), 1000, 10_000, 0, 1000, time.Millisecond, 20_000); delay != 7*time.Millisecond {
		t.Fatalf("custom pacing delay = %v, want 7ms", delay)
	}
	_, _ = controller.onDataSend(1000, 1000, time.Unix(100, 0), 1, 0, 10_000, 0, time.Millisecond, 20_000)
	_ = controller.onRetransmit(1000, 1000, time.Unix(100, 0), 1, 10_000, 0, 1000, time.Millisecond, 20_000)
	if implementation.dataEvents != 1 || implementation.pacedSends != 1 || implementation.retransmits != 1 {
		t.Fatalf("pacing callbacks = event %d send %d retransmit %d, want 1/1/1", implementation.dataEvents, implementation.pacedSends, implementation.retransmits)
	}
}

func TestCongestionControllerComposesDeliverySamplingWithCommonPacing(t *testing.T) {
	implementation := &testDeliveryCongestionControl{}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "test-delivery",
		New:  func(CongestionControlContext) CongestionController { return implementation }, Features: CongestionControlFeatureDeliveryRate,
	})
	if !controller.usesDeliveryRate() || controller.customPacing() {
		t.Fatalf("capabilities = delivery %t custom pacing %t", controller.usesDeliveryRate(), controller.customPacing())
	}
	controller.initialize(time.Unix(100, 0), 0, time.Millisecond, 10_000, 20_000, 1000, 1)
	snapshot, window := controller.onDataSend(1000, 1000, time.Unix(100, 0), 2, 0, 10_000, 0, time.Millisecond, 20_000)
	if snapshot.deliveredStamp == 0 || window != 10_000 || controller.pacingSegments != 1 {
		t.Fatalf("delivery send = stamp %d window %d pacing segments %d", snapshot.deliveredStamp, window, controller.pacingSegments)
	}
	sample := tcpDeliveryRateSample{}
	window, _ = controller.onDeliveryRateSample(window, 20_000, 1000, 0, &sample)
	if window != 10_001 || implementation.rateSamples != 1 || controller.sendBufferMultiplier() != 0 {
		t.Fatalf("delivery update = window %d samples %d buffer multiplier %d", window, implementation.rateSamples, controller.sendBufferMultiplier())
	}
}

func TestCongestionControllerFactoryProvidesIndependentImplementations(t *testing.T) {
	tests := []struct {
		name               string
		deliveryRate       bool
		transmissionEvents bool
		customPacing       bool
		customRecovery     bool
		lossEvents         bool
		sendBufferMultiple uint32
	}{
		{name: CongestionControlReno},
		{name: CongestionControlCUBIC, transmissionEvents: true},
		{name: CongestionControlBBR, deliveryRate: true, transmissionEvents: true, customPacing: true, customRecovery: true, sendBufferMultiple: 3},
		{name: CongestionControlBBR3, deliveryRate: true, transmissionEvents: true, customPacing: true, customRecovery: true, lossEvents: true, sendBufferMultiple: 3},
	}
	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			controller := newTCPCongestionController(test.name)
			if controller.algorithmName() != test.name || controller.usesDeliveryRate() != test.deliveryRate {
				t.Fatalf("controller = %q delivery %t, want %q/%t", controller.algorithmName(), controller.usesDeliveryRate(), test.name, test.deliveryRate)
			}
			if controller.usesTransmissionEvents() != test.transmissionEvents || controller.customPacing() != test.customPacing || controller.customRecovery() != test.customRecovery {
				t.Fatalf("controller features = transmission %t pacing %t recovery %t", controller.usesTransmissionEvents(), controller.customPacing(), controller.customRecovery())
			}
			if controller.usesLossEvents() != test.lossEvents {
				t.Fatalf("controller loss events = %t, want %t", controller.usesLossEvents(), test.lossEvents)
			}
			if multiplier := controller.sendBufferMultiplier(); multiplier != test.sendBufferMultiple {
				t.Fatalf("send-buffer multiplier = %d, want %d", multiplier, test.sendBufferMultiple)
			}
			second := newTCPCongestionController(test.name)
			if second.algorithmName() != test.name || second.algorithm == controller.algorithm {
				t.Fatalf("second controller = %q/%T, original %T", second.algorithmName(), second.algorithm, controller.algorithm)
			}
		})
	}
}

func TestHyStartPlusPlusDelayAndCSS(t *testing.T) {
	var state tcpHyStart
	state.start(1000)
	for sample := 0; sample < hyStartMinimumRTTSamples; sample++ {
		state.onACK(900, 2000, 1000, 20*time.Millisecond)
	}
	state.onACK(1000, 2000, 1000, 25*time.Millisecond)
	for sample := 1; sample < hyStartMinimumRTTSamples; sample++ {
		growth, completed := state.onACK(1100, 2000, 1000, 25*time.Millisecond)
		if completed {
			t.Fatal("HyStart++ completed before CSS")
		}
		if sample == hyStartMinimumRTTSamples-1 && (growth != 250 || !state.css || state.cssRounds != 1) {
			t.Fatalf("CSS entry growth/state = %d/%t/%d, want 250/true/1", growth, state.css, state.cssRounds)
		}
	}
	for round := 2; round <= hyStartCSSRounds; round++ {
		state.onACK(state.windowEnd, state.windowEnd+1000, 1000, 25*time.Millisecond)
	}
	if _, completed := state.onACK(state.windowEnd, state.windowEnd+1000, 1000, 25*time.Millisecond); !completed || !state.done {
		t.Fatal("HyStart++ did not leave CSS after five rounds")
	}
}

func TestHyStartPlusPlusRejectsJitterAndUserPause(t *testing.T) {
	state := tcpHyStart{
		windowEnd: 2000, lastRoundMinRTT: 20 * time.Millisecond,
		currentMinRTT: 25 * time.Millisecond, samples: hyStartMinimumRTTSamples - 1,
	}
	state.onACK(1500, 3000, 1000, 25*time.Millisecond)
	if !state.css {
		t.Fatal("delay increase did not enter CSS")
	}
	for sample := 0; sample < hyStartMinimumRTTSamples; sample++ {
		state.onACK(1600, 3000, 1000, 19*time.Millisecond)
	}
	if state.css || state.done {
		t.Fatal("lower CSS RTT did not resume ordinary slow start")
	}
	state.restartRound(4000)
	if state.lastRoundMinRTT != 0 || state.currentMinRTT != 0 || state.samples != 0 {
		t.Fatal("idle restart retained stale HyStart++ measurements")
	}
	state.disable()
	if growth, completed := state.onACK(4000, 5000, 1000, time.Second); growth != 1000 || completed {
		t.Fatalf("disabled HyStart++ result = %d/%t", growth, completed)
	}
}

func TestWindowPacingUsesLinuxRates(t *testing.T) {
	const (
		mss    = 1000
		window = uint32(10 * mss)
	)
	start := time.Unix(100, 0)
	slowStart := newTCPCongestionController(CongestionControlReno)
	slowStart.pacingSegments = tcpPacingInitialBurst - 1
	slowStart.pacingNext = start
	_, _ = slowStart.onDataSend(mss, mss, start, 0, window, window, window, 100*time.Millisecond, ^uint32(0))
	slowInterval := slowStart.pacingNext.Sub(start)

	avoidance := newTCPCongestionController(CongestionControlCUBIC)
	avoidance.pacingSegments = tcpPacingInitialBurst - 1
	avoidance.pacingNext = start
	_, _ = avoidance.onDataSend(mss, mss, start, 0, window, window, window, 100*time.Millisecond, window)
	avoidanceInterval := avoidance.pacingNext.Sub(start)

	if slowInterval < 4999*time.Microsecond || slowInterval > 5001*time.Microsecond {
		t.Fatalf("slow-start pacing interval = %v, want 5ms", slowInterval)
	}
	if avoidanceInterval < 8332*time.Microsecond || avoidanceInterval > 8334*time.Microsecond {
		t.Fatalf("congestion-avoidance pacing interval = %v, want approximately 8.333ms", avoidanceInterval)
	}
}

func TestMaximumPacingRateLimitsEveryController(t *testing.T) {
	const (
		mss   = 1000
		limit = uint64(50_000)
	)
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		controller := newTCPCongestionController(algorithm)
		controller.setMaximumPacingRate(limit)
		controller.initialize(time.Unix(99, 0), 0, time.Millisecond, 10*mss, 20*mss, mss, 1)
		if algorithm == CongestionControlBBR {
			bbrState(t, &controller).pacingRate = 1_000_000
			if rate := bbrState(t, &controller).effectivePacingRate(); rate != float64(limit) {
				t.Fatalf("%s limited pacing rate = %v, want %d", algorithm, rate, limit)
			}
			if bbrState(t, &controller).pacingBurstRemaining != 0 {
				t.Fatal("new pacing ceiling retained credit granted at the old rate")
			}
			controller.setMaximumPacingRate(0)
			if rate := bbrState(t, &controller).effectivePacingRate(); rate != 1_000_000 {
				t.Fatalf("%s restored pacing rate = %v, want 1000000", algorithm, rate)
			}
			continue
		}
		if algorithm == CongestionControlBBR3 {
			state := controller.algorithm.(*bbr3CongestionControl)
			state.pacingRate = 1_000_000
			if rate := state.effectivePacingRate(); rate != float64(limit) {
				t.Fatalf("%s limited pacing rate = %v, want %d", algorithm, rate, limit)
			}
			controller.setMaximumPacingRate(0)
			if rate := state.effectivePacingRate(); rate != 1_000_000 {
				t.Fatalf("%s restored pacing rate = %v, want 1000000", algorithm, rate)
			}
			continue
		}
		controller.pacingSegments = tcpPacingInitialBurst - 1
		_, _ = controller.onDataSend(mss, mss, time.Unix(100, 0), 0, 10*mss, 10*mss, 10*mss, time.Millisecond, 10*mss)
		if effective := controller.limitPacingRate(controller.pacingRate); effective != float64(limit) || controller.pacingRate <= effective {
			t.Fatalf("%s pacing model/effective rate = %v/%v, want model above %d and effective at limit", algorithm, controller.pacingRate, effective, limit)
		}
		controller.setMaximumPacingRate(0)
		if effective := controller.limitPacingRate(controller.pacingRate); effective != controller.pacingRate || effective <= float64(limit) {
			t.Fatalf("%s pacing rate did not recover immediately: model/effective %v/%v", algorithm, controller.pacingRate, effective)
		}
	}
}

func TestMaximumPacingRateChangeInvalidatesPacingSchedule(t *testing.T) {
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.initialize(start, 0, time.Millisecond, 10_000, 20_000, 1000, 1)
	controller.pacingNext = start.Add(time.Second)
	bbrState(t, &controller).nextSend = start.Add(2 * time.Second)
	bbrState(t, &controller).pacingWakeDeadline = start.Add(1500 * time.Millisecond)
	bbrState(t, &controller).pacingBurstRemaining = 32 * 1024
	bbrState(t, &controller).pacingRate = 1_000_000

	if !controller.setMaximumPacingRate(50_000) {
		t.Fatal("new pacing ceiling was not reported as a policy change")
	}
	if !controller.pacingNext.IsZero() || !bbrState(t, &controller).nextSend.IsZero() || !bbrState(t, &controller).pacingWakeDeadline.IsZero() || bbrState(t, &controller).pacingBurstRemaining != 0 {
		t.Fatalf("stale pacing state = window %v, BBR %v, wake %v, credit %d", controller.pacingNext, bbrState(t, &controller).nextSend, bbrState(t, &controller).pacingWakeDeadline, bbrState(t, &controller).pacingBurstRemaining)
	}
	if bbrState(t, &controller).pacingRate != 1_000_000 {
		t.Fatalf("model pacing rate = %v, want 1000000", bbrState(t, &controller).pacingRate)
	}
	if controller.setMaximumPacingRate(50_000) {
		t.Fatal("unchanged pacing ceiling was reported as a policy change")
	}
	if !controller.setMaximumPacingRate(0) || bbrState(t, &controller).effectivePacingRate() != 1_000_000 {
		t.Fatalf("removing ceiling did not immediately restore model rate: %v", bbrState(t, &controller).effectivePacingRate())
	}
}

func TestWindowPacingDefersAfterInitialBurst(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	start := time.Unix(100, 0)
	for segment := 0; segment < tcpPacingInitialBurst+4; segment++ {
		flight := uint32(segment * mss)
		_, _ = controller.onDataSend(mss, mss, start, 0, flight, 10*mss, flight, 100*time.Millisecond, ^uint32(0))
	}
	if delay := controller.pacingDelay(start, mss, 10*mss, 10*mss, mss, 100*time.Millisecond, ^uint32(0)); delay <= 0 {
		t.Fatal("window-based pacer did not defer after its initial burst")
	}
}

func TestPacingScheduleRetainsBoundedLateDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	base := pacingScheduleBase(start, now, 2*time.Millisecond, true)
	if base != now.Add(-2*time.Millisecond) {
		t.Fatalf("late pacing base = %v", base)
	}
	base = pacingScheduleBase(start, now, time.Millisecond, false)
	if base != now {
		t.Fatalf("retransmission pacing base = %v, want now", base)
	}
	base = pacingScheduleBase(now.Add(time.Millisecond), now, time.Millisecond, true)
	if base != now.Add(time.Millisecond) {
		t.Fatalf("early pacing base = %v", base)
	}
}

func TestBBRSendQuantumMatchesLinuxPolicy(t *testing.T) {
	const mss = 1000
	if quantum := bbrSendQuantum(100_000, mss); quantum != mss {
		t.Fatalf("low-rate send quantum = %d, want %d", quantum, mss)
	}
	if quantum := bbrSendQuantum(200_000, mss); quantum != 2*mss {
		t.Fatalf("normal-rate send quantum = %d, want %d", quantum, 2*mss)
	}
	if quantum := bbrSendQuantum(1024*100_000, mss); quantum != bbrSendQuantumByteTarget/mss*mss {
		t.Fatalf("high-rate send quantum = %d, want %d", quantum, bbrSendQuantumByteTarget/mss*mss)
	}
	if quantum := bbrSendQuantum(1024*100_000, 100); quantum != bbrMaximumSendSegments*100 {
		t.Fatalf("small-MSS send quantum = %d, want %d", quantum, bbrMaximumSendSegments*100)
	}
	if quantum := bbrSendQuantum(1024*100_000, 40_000); quantum != 80_000 {
		t.Fatalf("large-MSS send quantum = %d, want Linux's two-segment minimum", quantum)
	}
	if quantum := bbrSendQuantum(math.MaxFloat64, mss); quantum != bbrSendQuantumByteTarget/mss*mss {
		t.Fatalf("extreme-rate send quantum = %d, want %d", quantum, bbrSendQuantumByteTarget/mss*mss)
	}
	if duration := bbrSendQuantumDuration(1024*1024*1024, mss); duration < 60*time.Microsecond || duration > 61*time.Microsecond {
		t.Fatalf("high-rate send-quantum duration = %v, want approximately 60us", duration)
	}
	if budget := bbrUserspacePacingBudget(math.MaxFloat64, mss); budget != bbrMaximumUserspaceQuanta*(bbrSendQuantumByteTarget/mss*mss) {
		t.Fatalf("extreme-rate userspace budget = %d", budget)
	}
	if duration := bbrSendQuantumDuration(math.MaxFloat64, mss); duration != time.Nanosecond {
		t.Fatalf("extreme-rate quantum duration = %v, want 1ns", duration)
	}
	if duration := pacingDuration(1, math.SmallestNonzeroFloat64); duration != time.Duration(1<<63-1) {
		t.Fatalf("tiny-rate pacing duration = %v, want saturation", duration)
	}
}

func TestBBRGainsAndUnknownRTTWindowMatchLinux(t *testing.T) {
	if bbrStartupPacingGain != 739.0/256 || bbrDrainPacingGain != 88.0/256 {
		t.Fatalf("BBR fixed-point gains = %v/%v", bbrStartupPacingGain, bbrDrainPacingGain)
	}
	const mss = 1000
	bbr := bbrCongestionControl{mode: bbrStartup}
	if target := bbr.inflightTarget(bbrStartupPacingGain, mss); target != 14*mss {
		t.Fatalf("BBR target without RTT = %d, want %d", target, 14*mss)
	}
}

func TestECNCongestionWindowCanReachOneSegment(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(string(algorithm), func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			if threshold, window := controller.onECN(mss, mss, 0, mss, time.Time{}); threshold != mss || window != mss {
				t.Fatalf("one-segment ECN threshold/window = %d/%d, want %d/%d", threshold, window, mss, mss)
			}
			controller = newTCPCongestionController(algorithm)
			if threshold, _ := controller.onCongestion(mss, mss, 0, mss, time.Time{}); threshold != 2*mss {
				t.Fatalf("one-segment loss threshold = %d, want %d", threshold, 2*mss)
			}
		})
	}
}

func TestBBRECNPreservesModelWindowAndThreshold(t *testing.T) {
	const (
		mss       = 1000
		window    = uint32(20 * mss)
		threshold = uint32(200 * mss)
	)
	controller := newTCPCongestionController(CongestionControlBBR)
	gotThreshold, gotWindow := controller.onECN(window, 10*mss, threshold, mss, time.Time{})
	if gotThreshold != threshold || gotWindow != window {
		t.Fatalf("BBR ECN threshold/window = %d/%d, want %d/%d", gotThreshold, gotWindow, threshold, window)
	}
	if bbrState(t, &controller).priorWindow != window {
		t.Fatalf("BBR ECN saved window = %d, want %d", bbrState(t, &controller).priorWindow, window)
	}
}

func TestTCPRestartWindowAfterIdle(t *testing.T) {
	const mss = 1200
	initial := initialTCPWindow(mss)
	if got := tcpRestartWindow(100*mss, mss, 1100*time.Millisecond, time.Second); got != 50*mss {
		t.Fatalf("one-RTO idle window = %d, want %d", got, 50*mss)
	}
	if got := tcpRestartWindow(100*mss, mss, 10*time.Second, time.Second); got != initial {
		t.Fatalf("long-idle window = %d, want restart window %d", got, initial)
	}
	if got := tcpRestartWindow(2*mss, mss, 10*time.Second, time.Second); got != 2*mss {
		t.Fatalf("small idle window = %d, want unchanged %d", got, 2*mss)
	}
}

func TestTCPCongestionWindowValidation(t *testing.T) {
	const mss = 1000
	state := tcpEstablishedState{
		peerMSS: mss, peerWindow: 100 * mss,
		congestionWindow: 100 * mss, slowStartThreshold: 20 * mss,
		cwndUsageStamp: 1, rtt: newRTTEstimator(time.Second),
		controller: newTCPCongestionController(CongestionControlCUBIC),
	}
	state.controller.state.Phase = CongestionPhaseOpen
	state.validateCongestionWindow(monotonicStamp(time.Second)+1, 0, false)
	if state.congestionWindow != 55*mss {
		t.Fatalf("application-limited window = %d, want %d", state.congestionWindow, 55*mss)
	}
	if state.slowStartThreshold != 75*mss {
		t.Fatalf("application-limited threshold = %d, want %d", state.slowStartThreshold, 75*mss)
	}
	state.congestionWindow = 100 * mss
	state.cwndUsageStamp = 1
	state.sendNext = 10 * mss
	state.validateCongestionWindow(monotonicStamp(time.Second)+1, 10*mss, false)
	if state.congestionWindow != 100*mss {
		t.Fatalf("congestion-limited window = %d, want unchanged", state.congestionWindow)
	}

	bbr := state
	bbr.controller = newTCPCongestionController(CongestionControlBBR)
	bbr.controller.state.Phase = CongestionPhaseOpen
	bbr.sendNext = 0
	bbr.congestionWindow = 100 * mss
	bbr.cwndUsageStamp = 1
	bbr.validateCongestionWindow(monotonicStamp(time.Second)+1, 0, false)
	if bbr.congestionWindow != 100*mss {
		t.Fatalf("custom-validation window = %d, want unchanged", bbr.congestionWindow)
	}

	bufferLimited := state
	bufferLimited.sendNext = 0
	bufferLimited.congestionWindow = 100 * mss
	bufferLimited.cwndUsageStamp = 1
	bufferLimited.cwndUsed = 10 * mss
	bufferLimited.validateCongestionWindow(monotonicStamp(time.Second)+1, 0, true)
	if bufferLimited.congestionWindow != 100*mss {
		t.Fatalf("send-buffer-limited window = %d, want unchanged", bufferLimited.congestionWindow)
	}
	if bufferLimited.cwndUsed != 0 || bufferLimited.cwndUsageStamp != monotonicStamp(time.Second)+1 {
		t.Fatalf("send-buffer-limited observation = (%d, %d), want reset at current time", bufferLimited.cwndUsed, bufferLimited.cwndUsageStamp)
	}
}

func TestBBRSpuriousRecoveryRestoresPriorWindow(t *testing.T) {
	const (
		mss         = 1000
		priorWindow = 20 * mss
	)
	for _, algorithm := range []string{CongestionControlBBR, CongestionControlBBR3} {
		t.Run(algorithm, func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			now := time.Unix(100, 0)
			_, _ = controller.initialize(now, 10*time.Millisecond, 20*time.Millisecond, priorWindow, ^uint32(0)>>1, mss, 1)
			threshold := controller.onTimeout(priorWindow, priorWindow, ^uint32(0)>>1, mss, now)
			window, _ := controller.undoRecovery(now.Add(time.Second), uint32(mss), 5*mss, threshold, 5*mss, mss, CongestionPhaseOpen)
			if window != priorWindow {
				t.Fatalf("spurious-recovery window = %d, want prior window %d", window, priorWindow)
			}
		})
	}
}

func TestSlowStartReturnsExcessACKCreditToCongestionAvoidance(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(string(algorithm), func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			const window = uint32(9 * mss)
			grown, _ := controller.onACKWithThreshold(window, 2*mss, 0, mss, time.Unix(100, 0), 20*time.Millisecond, 0, 0, window, 10*mss, false)
			if grown < 10*mss || grown >= 11*mss {
				t.Fatalf("boundary ACK window = %d, want [10000, 11000)", grown)
			}
		})
	}
}

func TestTCPSelectableCongestionControls(t *testing.T) {
	for index, algorithm := range []string{CongestionControlCUBIC, CongestionControlReno, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(string(algorithm), func(t *testing.T) {
			local := netip.AddrFrom4([4]byte{192, 0, 2, byte(50 + index*2)})
			remote := netip.AddrFrom4([4]byte{192, 0, 2, byte(51 + index*2)})
			link, stack := newTestStack(t, local, remote)
			defer stack.Close()
			link.mu.Lock()
			link.echoTCP = true
			link.mu.Unlock()
			if err := stack.UpdateConfig(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
				TCP:            TCPSocketDefaults{CongestionControl: algorithm},
			}); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, uint16(8100+index)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			writeAndReadTCPEcho(t, connection, make([]byte, 64*1024))
		})
	}
}

func TestTCPBBRPartialCumulativeACKProducesRateSample(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.88")
	remote := netip.MustParseAddr("192.0.2.89")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.partialTCPACK = 500
	link.delayTCPACK = 5 * time.Millisecond
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8288))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		info := tcpConnection.Info()
		return info.BytesAcknowledged == 500 && info.DeliveryRate != 0
	})
}

func TestTCPControllerChangePreservesCongestionState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.58")
	remote := netip.MustParseAddr("192.0.2.59")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8150))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	writeAndReadTCPEcho(t, connection, make([]byte, 512*1024))
	tcpConnection := connection.(*TCPConn)
	before := tcpConnection.Info()
	if before.CongestionWindow <= initialTCPWindow(before.MaximumSegmentSize) {
		t.Fatalf("pre-change congestion window = %d, did not grow beyond initial window", before.CongestionWindow)
	}
	if err = tcpConnection.SetCongestionControl(CongestionControlBBR); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return tcpConnection.Info().CongestionControl == CongestionControlBBR
	})
	after := tcpConnection.Info()
	if after.CongestionWindow != before.CongestionWindow || after.SlowStartThreshold != before.SlowStartThreshold {
		t.Fatalf("controller change altered cwnd/ssthresh = %d/%d, want %d/%d", after.CongestionWindow, after.SlowStartThreshold, before.CongestionWindow, before.SlowStartThreshold)
	}
}

func TestTCPSelectableCongestionControlsRecoverMultipleLosses(t *testing.T) {
	for index, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(string(algorithm), func(t *testing.T) {
			local := netip.AddrFrom4([4]byte{192, 0, 2, byte(70 + index*2)})
			remote := netip.AddrFrom4([4]byte{192, 0, 2, byte(71 + index*2)})
			link, stack := newTestStack(t, local, remote)
			defer stack.Close()
			link.mu.Lock()
			link.echoTCP = true
			link.sackTCP = true
			link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
			link.mu.Unlock()
			if err := stack.UpdateConfig(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
				TCP:            TCPSocketDefaults{CongestionControl: algorithm},
			}); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, uint16(8200+index)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
			writeAndReadTCPEcho(t, connection, make([]byte, 64*1024))
			if recoveries := stack.Stats().TCPSACKRetransmissions; recoveries < 2 {
				t.Fatalf("SACK retransmissions = %d, want at least 2", recoveries)
			}
			if algorithm == CongestionControlBBR || algorithm == CongestionControlBBR3 {
				info := connection.(*TCPConn).Info()
				if info.CongestionWindow >= tcpMaximumScaledWindow {
					t.Fatalf("BBR recovery window = %d after ssthresh %d", info.CongestionWindow, info.SlowStartThreshold)
				}
			}
		})
	}
}

func TestBBRTailLossRecoveryRetainsModelWindow(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.78")
	remote := netip.MustParseAddr("192.0.2.79")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8278))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte("warmup"))
	if info := connection.(*TCPConn).Info(); info.RTT <= 0 {
		t.Fatal("warmup did not establish an RTT sample")
	}
	link.mu.Lock()
	link.holdTCPACKs = 10
	link.dropTCPOrdinals = map[int]bool{4: true}
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x5a}, 3*1280))
	link.mu.Lock()
	link.holdTCPACKs = 0
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("advance past tail"))
	info := connection.(*TCPConn).Info()
	if probes := stack.Stats().TCPTailLossProbes; probes == 0 {
		t.Fatalf("BBR tail loss did not exercise a tail-loss probe: info=%+v stats=%+v", info, stack.Stats())
	}
	if info.CongestionWindow >= tcpMaximumScaledWindow {
		t.Fatalf("BBR tail-loss window = %d after ssthresh %d", info.CongestionWindow, info.SlowStartThreshold)
	}
}

func TestTCPAlgorithmsUnderCombinedImpairment(t *testing.T) {
	condition := testLinkCondition{
		Latency: 5 * time.Millisecond, Jitter: 2 * time.Millisecond,
		LossRate: 0.02, BurstEnterRate: 0.01, BurstExitRate: 0.5,
		DuplicateRate: 0.05, Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
	}
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(string(algorithm), func(t *testing.T) {
			client, server, link := newTestTCPConnectionPair(t, algorithm, testLinkConditions{
				Seed: 3779, ClientToPeer: condition, PeerToClient: condition,
			})
			started := time.Now()
			transferTestTCPPayload(t, client, server, 128*1024, 20*time.Second)
			stats := link.Stats(0)
			info := client.Info()
			t.Logf("transfer=%v link=%+v rtt=%v retransmissions=%d cwnd=%d scheduler-limited=%d", time.Since(started), stats, info.RTT, info.Retransmissions, info.CongestionWindow, info.SchedulerLimitedEvents)
			if stats.RandomDrops == 0 || stats.Duplicates == 0 {
				t.Fatalf("combined impairment was not exercised: %+v", stats)
			}
		})
	}
}

func TestTCPAlgorithmsShareBottleneckWithoutStarvation(t *testing.T) {
	const flows, payloadSize = 8, 128 * 1024
	condition := testLinkCondition{
		Latency: 8 * time.Millisecond, Jitter: time.Millisecond,
		Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
	}
	fairCompletion := time.Duration(payloadSize*flows) * time.Second / time.Duration(condition.Bandwidth)
	maximumCompletion := 4*fairCompletion + 250*time.Millisecond
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(string(algorithm), func(t *testing.T) {
			clientAddress := netip.MustParseAddr("192.0.2.231")
			serverAddress := netip.MustParseAddr("192.0.2.232")
			clientStack, serverStack, link := newTestImpairedStackPair(t, algorithm, testLinkConditions{
				Seed: 9341, ClientToPeer: condition, PeerToClient: condition,
			}, clientAddress, serverAddress)
			listener, err := serverStack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
			clients := make([]*TCPConn, flows)
			servers := make([]*TCPConn, flows)
			for flow := 0; flow < flows; flow++ {
				accepted := make(chan net.Conn, 1)
				acceptError := make(chan error, 1)
				go func() {
					connection, acceptErr := listener.Accept()
					if acceptErr != nil {
						acceptError <- acceptErr
						return
					}
					accepted <- connection
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				connection, dialErr := clientStack.DialTCP(ctx, "tcp4", netip.AddrPort{}, endpoint)
				cancel()
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				clients[flow] = connection.(*TCPConn)
				select {
				case connection := <-accepted:
					servers[flow] = connection.(*TCPConn)
				case acceptErr := <-acceptError:
					t.Fatal(acceptErr)
				case <-time.After(10 * time.Second):
					t.Fatal("timed out accepting bottleneck test flow")
				}
			}
			type flowResult struct {
				flow     int
				duration time.Duration
				err      error
			}
			start := make(chan struct{})
			results := make(chan flowResult, flows)
			for flow := 0; flow < flows; flow++ {
				go func(flow int) {
					<-start
					started := time.Now()
					err := exchangeTestTCPPayload(clients[flow], servers[flow], payloadSize, 20*time.Second, uint32(flow+1))
					results <- flowResult{flow: flow, duration: time.Since(started), err: err}
				}(flow)
			}
			close(start)
			durations := make([]time.Duration, flows)
			minimum, maximum := time.Duration(0), time.Duration(0)
			for flow := 0; flow < flows; flow++ {
				result := <-results
				if result.err != nil {
					t.Fatal(result.err)
				}
				if minimum == 0 || result.duration < minimum {
					minimum = result.duration
				}
				if result.duration > maximum {
					maximum = result.duration
				}
				durations[result.flow] = result.duration
			}
			stats := link.Stats(0)
			t.Logf("flows=%d min=%v max=%v link=%+v", flows, minimum, maximum, stats)
			if stats.QueueDrops == 0 {
				t.Fatalf("bottleneck queue did not drop a packet: %+v", stats)
			}
			if maximum > maximumCompletion {
				for flow := 0; flow < flows; flow++ {
					t.Logf("flow=%d duration=%v info=%+v", flow, durations[flow], clients[flow].Info())
				}
				t.Fatalf("flow completion spread %v..%v exceeds fair-share limit %v", minimum, maximum, maximumCompletion)
			}
			for flow := 0; flow < flows; flow++ {
				_ = clients[flow].Close()
				_ = servers[flow].Close()
			}
		})
	}
}

func TestTCPAlgorithmsUnderSustainedSchedulerPressure(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)
	stop := make(chan struct{})
	var workers sync.WaitGroup
	var work, workSink atomic.Uint64
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(seed uint64) {
			defer workers.Done()
			value := seed
			for {
				for iteration := 0; iteration < 1<<16; iteration++ {
					value = value*6364136223846793005 + 1442695040888963407
				}
				workSink.Store(value)
				work.Add(1)
				select {
				case <-stop:
					return
				default:
				}
			}
		}(uint64(worker + 1))
	}
	defer func() {
		close(stop)
		workers.Wait()
	}()
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(string(algorithm), func(t *testing.T) {
			client, server, _ := newTestTCPConnectionPair(t, algorithm, testLinkConditions{
				Seed:         6113,
				ClientToPeer: testLinkCondition{Latency: 3 * time.Millisecond, Jitter: time.Millisecond, LossRate: 0.01},
				PeerToClient: testLinkCondition{Latency: 3 * time.Millisecond, Jitter: time.Millisecond, LossRate: 0.01},
			})
			transferTestTCPPayload(t, client, server, 128*1024, 20*time.Second)
			info := client.Info()
			t.Logf("scheduler pressure work=%d rtt=%v retransmissions=%d cwnd=%d scheduler-limited=%d", work.Load(), info.RTT, info.Retransmissions, info.CongestionWindow, info.SchedulerLimitedEvents)
			if (algorithm == CongestionControlBBR || algorithm == CongestionControlBBR3) && info.SchedulerLimitedEvents == 0 {
				t.Fatal("BBR did not observe scheduler pressure")
			}
		})
	}
	if work.Load() == 0 {
		t.Fatal("CPU pressure workers did not run")
	}
}

func TestBBRModeString(t *testing.T) {
	tests := []struct {
		mode bbrMode
		name string
	}{
		{bbrStartup, "STARTUP"},
		{bbrDrain, "DRAIN"},
		{bbrProbeBandwidth, "PROBE_BW"},
		{bbrProbeRTT, "PROBE_RTT"},
		{bbrMode(255), ""},
	}
	for _, test := range tests {
		if name := test.mode.String(); name != test.name {
			t.Errorf("bbrMode(%d).String() = %q, want %q", test.mode, name, test.name)
		}
	}
}

type testDeviceBottleneck struct {
	client *Stack
	server *Stack
	done   sync.WaitGroup
}

func newTestDeviceBottleneck(t testing.TB, algorithm string, bytesPerSecond int, fair bool) (*Stack, *Stack) {
	t.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.241")
	serverAddress := netip.MustParseAddr("192.0.2.242")
	newStack := func(address netip.Addr) *Stack {
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(address, 32)},
			MTU:            1400,
			TCP:            TCPSocketDefaults{CongestionControl: algorithm},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !fair {
			stack.outbound.initFIFO(outboundPacketQueue, stack.timestampEpoch)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		return stack
	}
	link := &testDeviceBottleneck{client: newStack(clientAddress), server: newStack(serverAddress)}
	link.done.Add(2)
	go link.pump(link.client, link.server, bytesPerSecond)
	go link.pump(link.server, link.client, 0)
	t.Cleanup(func() {
		_ = link.client.Close()
		_ = link.server.Close()
		link.done.Wait()
	})
	return link.client, link.server
}

func (l *testDeviceBottleneck) pump(source, target *Stack, bytesPerSecond int) {
	defer l.done.Done()
	const batchSize = 32
	buffers := make([][]byte, batchSize)
	for index := range buffers {
		buffers[index] = make([]byte, 65535)
	}
	sizes := make([]int, batchSize)
	next := time.Time{}
	for {
		count, err := source.Read(buffers, sizes, 0)
		if err != nil {
			return
		}
		if bytesPerSecond > 0 {
			bytes := 0
			for index := 0; index < count; index++ {
				bytes += sizes[index]
			}
			now := time.Now()
			if next.Before(now) {
				next = now
			}
			next = next.Add(time.Duration(bytes) * time.Second / time.Duration(bytesPerSecond))
			if delay := time.Until(next); delay > 0 {
				time.Sleep(delay)
			}
		}
		for index := 0; index < count; index++ {
			if _, err = target.Write(buffers[index:index+1], 0); err != nil {
				return
			}
		}
	}
}

func openTestDeviceBottleneckTCPFlows(t testing.TB, client, server *Stack, flows int) ([]*TCPConn, []*TCPConn) {
	t.Helper()
	serverAddress := server.LocalAddresses()[0]
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clients := make([]*TCPConn, flows)
	servers := make([]*TCPConn, flows)
	for flow := 0; flow < flows; flow++ {
		accepted := make(chan net.Conn, 1)
		acceptError := make(chan error, 1)
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				acceptError <- acceptErr
				return
			}
			accepted <- connection
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		connection, dialErr := client.DialTCP(ctx, "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
		cancel()
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clients[flow] = connection.(*TCPConn)
		select {
		case connection := <-accepted:
			servers[flow] = connection.(*TCPConn)
		case acceptErr := <-acceptError:
			t.Fatal(acceptErr)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out accepting device-bottleneck flow")
		}
	}
	t.Cleanup(func() {
		for index := range clients {
			_ = clients[index].Close()
			_ = servers[index].Close()
		}
	})
	return clients, servers
}

func testJainCompletionFairness(payloadBytes int, durations []time.Duration) float64 {
	var sum, squares float64
	for _, duration := range durations {
		rate := float64(payloadBytes) / duration.Seconds()
		sum += rate
		squares += rate * rate
	}
	if squares == 0 {
		return 0
	}
	return sum * sum / (float64(len(durations)) * squares)
}

func TestTCPAlgorithmsShareDeviceBottleneck(t *testing.T) {
	const flows, payloadBytes = 8, 128 * 1024
	for _, scheduler := range []struct {
		name string
		fair bool
	}{{name: "fifo"}, {name: "drr", fair: true}} {
		for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
			t.Run(scheduler.name+"/"+string(algorithm), func(t *testing.T) {
				client, server := newTestDeviceBottleneck(t, algorithm, 4*1024*1024, scheduler.fair)
				clients, servers := openTestDeviceBottleneckTCPFlows(t, client, server, flows)
				start := make(chan struct{})
				durations := make([]time.Duration, flows)
				errorsCh := make(chan error, flows)
				var workers sync.WaitGroup
				for flow := 0; flow < flows; flow++ {
					workers.Add(1)
					go func(flow int) {
						defer workers.Done()
						<-start
						started := time.Now()
						err := exchangeTestTCPPayload(clients[flow], servers[flow], payloadBytes, 10*time.Second, uint32(flow+1))
						durations[flow] = time.Since(started)
						errorsCh <- err
					}(flow)
				}
				close(start)
				workers.Wait()
				close(errorsCh)
				for err := range errorsCh {
					if err != nil {
						t.Fatal(err)
					}
				}
				sorted := append([]time.Duration(nil), durations...)
				sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
				fairness := testJainCompletionFairness(payloadBytes, durations)
				ratio := float64(sorted[len(sorted)-1]) / float64(sorted[0])
				t.Logf("device bottleneck fairness=%.4f ratio=%.3f min=%v median=%v max=%v", fairness, ratio, sorted[0], sorted[len(sorted)/2], sorted[len(sorted)-1])
				if math.IsNaN(fairness) || fairness < 0.5 {
					t.Fatalf("device-bottleneck fairness = %f", fairness)
				}
				if scheduler.fair && fairness < 0.995 {
					t.Fatalf("DRR fairness regression: fairness=%.4f ratio=%.3f", fairness, ratio)
				}
			})
		}
	}
}

func testUDPLatencyDuringTCPDeviceBottleneck(t *testing.T, algorithm string, fair bool) []time.Duration {
	t.Helper()
	client, server := newTestDeviceBottleneck(t, algorithm, 4*1024*1024, fair)
	clients, servers := openTestDeviceBottleneckTCPFlows(t, client, server, 4)
	serverAddress := server.LocalAddresses()[0]
	listener, err := server.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err = listener.(*UDPConn).SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, 64)
		for {
			n, address, readErr := listener.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			for {
				if _, writeErr := listener.WriteTo(buffer[:n], address); writeErr == nil {
					break
				} else if !errors.Is(writeErr, syscall.ENOBUFS) {
					return
				}
				select {
				case <-listener.(*UDPConn).closed:
					return
				case <-time.After(time.Millisecond):
				}
			}
		}
	}()
	udpConnection, err := client.DialUDP(context.Background(), "udp4", netip.AddrPort{}, listener.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.(*UDPConn).SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = udpConnection.Close()
		_ = listener.Close()
		<-echoDone
	})
	start := make(chan struct{})
	bulkErrors := make(chan error, len(clients))
	for flow := range clients {
		go func(flow int) {
			<-start
			bulkErrors <- exchangeTestTCPPayload(clients[flow], servers[flow], 512*1024, 15*time.Second, uint32(flow+100))
		}(flow)
	}
	close(start)
	time.Sleep(20 * time.Millisecond)
	latencies := make([]time.Duration, 0, 32)
	request := make([]byte, 8)
	response := make([]byte, len(request))
	for sequence := 0; sequence < 32; sequence++ {
		binary.BigEndian.PutUint64(request, uint64(sequence))
		started := time.Now()
		admissionDeadline := started.Add(5 * time.Second)
		for {
			if _, err = udpConnection.Write(request); err == nil {
				break
			}
			if !errors.Is(err, syscall.ENOBUFS) {
				t.Fatal(err)
			}
			if time.Now().After(admissionDeadline) {
				t.Fatal("UDP bottleneck packet could not acquire device admission")
			}
			time.Sleep(time.Millisecond)
		}
		_ = udpConnection.SetReadDeadline(started.Add(5 * time.Second))
		if _, err = io.ReadFull(udpConnection, response); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint64(response) != uint64(sequence) {
			t.Fatal("UDP bottleneck response mismatch")
		}
		latencies = append(latencies, time.Since(started))
	}
	for range clients {
		if err = <-bulkErrors; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies
}

func TestUDPLatencyDuringTCPDeviceBottleneck(t *testing.T) {
	for _, scheduler := range []struct {
		name string
		fair bool
	}{{name: "fifo"}, {name: "drr", fair: true}} {
		for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
			t.Run(scheduler.name+"/"+string(algorithm), func(t *testing.T) {
				latencies := testUDPLatencyDuringTCPDeviceBottleneck(t, algorithm, scheduler.fair)
				t.Logf("UDP latency min=%v median=%v p95=%v max=%v", latencies[0], latencies[len(latencies)/2], latencies[len(latencies)*95/100], latencies[len(latencies)-1])
			})
		}
	}
}

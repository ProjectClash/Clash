package mipstack

import (
	"testing"
	"time"
)

func cubicState(t testing.TB, controller *tcpCongestionController) *cubicCongestionControl {
	t.Helper()
	cubic, ok := controller.algorithm.(*cubicCongestionControl)
	if !ok {
		t.Fatalf("controller implementation = %T, want CUBIC", controller.algorithm)
	}
	return cubic
}

func TestCUBICCongestionControl(t *testing.T) {
	const mss = 1200
	controller := newTCPCongestionController(CongestionControlCUBIC)
	if threshold, _ := controller.onCongestion(12000, 9000, 0, mss, time.Time{}); threshold != 8400 {
		t.Fatalf("CUBIC threshold = %d, want 8400", threshold)
	}
	start := time.Unix(100, 0)
	window := uint32(8400)
	first := controller.onACK(window, mss, mss, start, 20*time.Millisecond, 20*time.Millisecond, window, false)
	if first <= window {
		t.Fatalf("CUBIC first window = %d, want > %d", first, window)
	}
	later := controller.onACK(first, 10*mss, mss, start.Add(3*time.Second), 20*time.Millisecond, 20*time.Millisecond, first, false)
	if later <= first {
		t.Fatalf("CUBIC later window = %d, want > %d", later, first)
	}
}

func TestCUBICFastConvergenceComparesAdjustedMaximum(t *testing.T) {
	const mss = 1000
	var cubic cubicCongestionControl
	cubic.onCongestion(100*mss, mss)
	if cubic.lastMaximum != 100 {
		t.Fatalf("first congestion Wmax=%v, want 100", cubic.lastMaximum)
	}
	cubic.onCongestion(80*mss, mss)
	if cubic.lastMaximum != 68 {
		t.Fatalf("second congestion Wmax=%v, want 68", cubic.lastMaximum)
	}
	cubic.onCongestion(70*mss, mss)
	if cubic.lastMaximum != 70 {
		t.Fatalf("third congestion Wmax=%v, want 70", cubic.lastMaximum)
	}
}

func TestCUBICRecoveryCheckpointDoesNotAllocate(t *testing.T) {
	cubic := newCUBICCongestionControl()
	if allocations := testing.AllocsPerRun(1000, cubic.saveRecoveryCheckpoint); allocations != 0 {
		t.Fatalf("CUBIC recovery checkpoint allocations = %v, want 0", allocations)
	}
}

func TestCUBICRenoFriendlyAlpha(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	window, _ := controller.onCongestion(100*mss, 100*mss, 0, mss, time.Unix(99, 0))
	initial := window
	start := time.Unix(100, 0)
	for acknowledged := uint32(0); acknowledged < initial; acknowledged += mss {
		window = controller.onACK(window, mss, mss, start, 0, 0, window, false)
	}
	growth := window - initial
	if growth < 500 || growth > 560 {
		t.Fatalf("CUBIC Reno-friendly growth = %d, want approximately 9/17 MSS", growth)
	}
}

func TestCUBICFirstLossFreeEpochUsesRenoAlpha(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	_, _ = controller.onACKWithThreshold(8*mss, 8*mss, 16*mss, mss, start, 20*time.Millisecond, 20*time.Millisecond, 0, 16*mss, 12*mss, false)
	cubic := cubicState(t, &controller)
	if cubic.priorWindow != 12 || cubic.estimate != 12+4.0/12 {
		t.Fatalf("first congestion-avoidance epoch = prior %f estimate %f, want 12 and %f", cubic.priorWindow, cubic.estimate, 12+4.0/12)
	}
}

func TestCUBICCurveWindowVectors(t *testing.T) {
	start := time.Unix(100, 0)
	for _, test := range []struct {
		elapsed, rtt time.Duration
		window       uint32
		credit       float64
	}{
		{0, 0, 9066, 2.0 / 3},
		{500 * time.Millisecond, 0, 9105, 5.0 / 9},
		{time.Second, 0, 9111, 1.0 / 9},
		{1500 * time.Millisecond, 0, 9116, 2.0 / 3},
		{2 * time.Second, 0, 9155, 5.0 / 9},
		{0, 250 * time.Millisecond, 9092, 13.0 / 36},
		{500 * time.Millisecond, 100 * time.Millisecond, 9108, 4.0 / 15},
		{time.Second, 100 * time.Millisecond, 9111, 7.0 / 45},
	} {
		cubic := cubicCongestionControl{epochStart: start, origin: 10, k: 1, estimate: 9, priorWindow: 20}
		window := cubic.onACK(9000, 1000, 1000, start.Add(test.elapsed), test.rtt)
		delta := cubic.credit - test.credit
		if window != test.window || delta < -1e-8 || delta > 1e-8 {
			t.Fatalf("elapsed %v RTT %v = window %d credit %.12f, want %d %.12f", test.elapsed, test.rtt, window, cubic.credit, test.window, test.credit)
		}
	}
}

func BenchmarkCUBICCongestionAvoidance(b *testing.B) {
	start := time.Unix(100, 0)
	now := start.Add(500 * time.Millisecond)
	cubic := cubicCongestionControl{epochStart: start, origin: 10, k: 1, priorWindow: 20}
	var window uint32
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		cubic.estimate, cubic.credit = 9, 0
		window = cubic.onACK(9000, 1000, 1000, now, 100*time.Millisecond)
	}
	b.StopTimer()
	if window != 9108 {
		b.Fatalf("congestion-avoidance window = %d, want 9108", window)
	}
}

func TestCUBICEpochExcludesApplicationIdleTime(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	_, _ = controller.onDataSend(mss, mss, start, 0, 0, window, 0, 0, 20*time.Millisecond, ^uint32(0))
	window = controller.onACK(window, mss, mss, start.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	epoch := cubicState(t, &controller).epochStart
	resume := start.Add(time.Hour)
	_, _ = controller.onDataSend(mss, mss, resume, 0, 0, window, 0, 0, 20*time.Millisecond, ^uint32(0))
	if got := cubicState(t, &controller).epochStart; !got.Equal(resume) {
		t.Fatalf("CUBIC epoch after idle = %v (previous %v), want resume time %v", got, epoch, resume)
	}
	before := window
	window = controller.onACK(window, mss, mss, resume.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	if window-before >= uint32(mss) {
		t.Fatalf("CUBIC grew by %d immediately after idle, want less than one MSS", window-before)
	}
}

func TestCUBICIdleRestartClampsApplicationLimitedEpoch(t *testing.T) {
	start := time.Unix(100, 0)
	for _, flight := range []uint32{0, 1000} {
		cubic := cubicCongestionControl{epochStart: start.Add(time.Millisecond), lastSend: start, applicationLimited: start, priorWindow: 20, estimate: 1, origin: 10}
		resume := start.Add(time.Hour)
		cubic.onSend(resume, flight)
		if !cubic.epochStart.Equal(resume) || !cubic.applicationLimited.IsZero() {
			t.Fatalf("restart with flight %d = epoch %v limited %v, want %v and cleared limit", flight, cubic.epochStart, cubic.applicationLimited, resume)
		}
		window := cubic.onACK(10_000, 1000, 1000, resume.Add(-time.Second), 20*time.Millisecond)
		if window != 10_000 || cubic.credit <= 0 || !cubic.epochStart.Equal(resume) {
			t.Fatalf("queued ACK = cwnd %d credit %f epoch %v, want 10000, positive curve credit and %v", window, cubic.credit, cubic.epochStart, resume)
		}
	}
}

func TestCUBICSendStartUsesTransmissionFlight(t *testing.T) {
	start := time.Unix(100, 0)
	resume := start.Add(time.Second)
	for _, test := range []struct {
		name       string
		packetsOut uint32
		flight     uint32
		epoch      time.Time
	}{
		{name: "live copies", packetsOut: 1000, flight: 1000, epoch: start},
		{name: "lost copies", packetsOut: 1000, epoch: resume},
		{name: "idle", epoch: resume},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := newTCPCongestionController(CongestionControlCUBIC)
			cubic := cubicState(t, &controller)
			cubic.epochStart, cubic.lastSend = start, start
			_, _ = controller.onDataSend(1000, 1000, resume, 0, test.packetsOut, 10_000, test.packetsOut, test.flight, 20*time.Millisecond, 10_000)
			if !cubic.epochStart.Equal(test.epoch) || !cubic.lastSend.Equal(resume) {
				t.Fatalf("send start = epoch %v last send %v, want %v and %v", cubic.epochStart, cubic.lastSend, test.epoch, resume)
			}
		})
	}
}

func TestCUBICCapsTargetAndKeepsFriendlyEstimateSeparate(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlCUBIC)
	*cubicState(t, &controller) = cubicCongestionControl{
		epochStart: start, lastMaximum: 10, priorWindow: 20, estimate: 1,
		origin: 10,
	}
	const window = uint32(10 * mss)
	grown := controller.onACK(window, mss, mss, start.Add(time.Minute), time.Second, 0, window, false)
	if increase := grown - window; increase > mss/2 {
		t.Fatalf("CUBIC target-cap increase = %d, want <= %d", increase, mss/2)
	}
	if cubicState(t, &controller).estimate >= float64(grown)/mss {
		t.Fatalf("friendly estimate %f was incorrectly folded into CUBIC window %d", cubicState(t, &controller).estimate, grown)
	}
}

func TestCUBICTimeoutStartsNextEpochAtKZero(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	_, _ = controller.onCongestion(100*mss, 100*mss, 0, mss, time.Time{})
	if threshold := controller.onTimeout(70*mss, 60*mss, 0, mss, time.Unix(100, 0)); threshold != 49*mss {
		t.Fatalf("CUBIC timeout threshold = %d, want %d", threshold, 49*mss)
	}
	start := time.Unix(100, 0)
	window := uint32(49 * mss)
	_ = controller.onACK(window, mss, mss, start, 20*time.Millisecond, 0, window, false)
	if cubicState(t, &controller).k != 0 || cubicState(t, &controller).lastMaximum != 49 || cubicState(t, &controller).origin != 49 {
		t.Fatalf("CUBIC post-timeout epoch = K %f Wmax %f origin %f", cubicState(t, &controller).k, cubicState(t, &controller).lastMaximum, cubicState(t, &controller).origin)
	}
	if cubicState(t, &controller).priorWindow != 70 {
		t.Fatalf("CUBIC post-timeout cwnd_prior = %f, want 70", cubicState(t, &controller).priorWindow)
	}
	before := cubicState(t, &controller).estimate
	_ = controller.onACK(window, mss, mss, start.Add(time.Millisecond), 20*time.Millisecond, 0, window, false)
	if increase := cubicState(t, &controller).estimate - before; increase >= 1.0/float64(window/mss) {
		t.Fatalf("CUBIC post-timeout W_est increase = %f, switched to alpha=1 before cwnd_prior", increase)
	}
}

func TestCUBICEpochExcludesNonIdleApplicationLimit(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 20*time.Millisecond, 0, window, false)
	epoch := cubicState(t, &controller).epochStart
	limitedAt := start.Add(time.Second)
	if got := controller.onACK(window, mss, mss, limitedAt, 20*time.Millisecond, 0, 2*mss, false); got != window {
		t.Fatalf("application-limited CUBIC window = %d, want %d", got, window)
	}
	resume := start.Add(time.Hour)
	_, _ = controller.onDataSend(mss, mss, resume, 0, mss, window, mss, mss, 20*time.Millisecond, ^uint32(0))
	if shift := cubicState(t, &controller).epochStart.Sub(epoch); shift != resume.Sub(limitedAt) {
		t.Fatalf("application-limited epoch shift = %v, want %v", shift, resume.Sub(limitedAt))
	}
}

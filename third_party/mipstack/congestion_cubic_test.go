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
	window := uint32(100 * mss)
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

func TestCUBICEpochExcludesApplicationIdleTime(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	_, _ = controller.onDataSend(mss, mss, start, 0, 0, window, 0, 20*time.Millisecond, ^uint32(0))
	window = controller.onACK(window, mss, mss, start.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	epoch := cubicState(t, &controller).epochStart
	resume := start.Add(time.Hour)
	_, _ = controller.onDataSend(mss, mss, resume, 0, 0, window, 0, 20*time.Millisecond, ^uint32(0))
	if shift := cubicState(t, &controller).epochStart.Sub(epoch); shift != resume.Sub(start) {
		t.Fatalf("CUBIC epoch shift = %v, want idle interval %v", shift, resume.Sub(start))
	}
	before := window
	window = controller.onACK(window, mss, mss, resume.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	if window-before >= uint32(mss) {
		t.Fatalf("CUBIC grew by %d immediately after idle, want less than one MSS", window-before)
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
	_, _ = controller.onDataSend(mss, mss, resume, 0, mss, window, mss, 20*time.Millisecond, ^uint32(0))
	if shift := cubicState(t, &controller).epochStart.Sub(epoch); shift != resume.Sub(limitedAt) {
		t.Fatalf("application-limited epoch shift = %v, want %v", shift, resume.Sub(limitedAt))
	}
}

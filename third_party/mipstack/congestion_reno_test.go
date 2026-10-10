package mipstack

import (
	"testing"
	"time"
)

func TestRenoCongestionControl(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	if threshold, _ := controller.onCongestion(12000, 9000, 0, mss, time.Time{}); threshold != 4500 {
		t.Fatalf("Reno threshold = %d, want 4500", threshold)
	}
	window := uint32(10000)
	if grown := controller.onACK(window, 2*mss, mss, time.Time{}, 0, 0, window, true); grown != 12000 {
		t.Fatalf("Reno slow-start window = %d, want 12000", grown)
	}
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, window, false); grown != 10100 {
		t.Fatalf("Reno avoidance window = %d, want 10100", grown)
	}
}

func TestRenoCongestionAvoidanceRetainsFractionalCredit(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	window := uint32(10 * 1024 * 1024)
	initial := window
	for acknowledged := uint32(0); acknowledged < initial; acknowledged += mss {
		window = controller.onACK(window, mss, mss, time.Time{}, 0, 0, window, false)
	}
	growth := window - initial
	if growth < 900 || growth > 1100 {
		t.Fatalf("Reno growth over one window = %d, want approximately one MSS", growth)
	}
}

func TestRenoRecoveryCheckpointRetainsZeroCredit(t *testing.T) {
	reno := newRenoCongestionControl()
	checkpoint := CongestionEvent{Type: CongestionEventRecovery, Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint}}
	undo := CongestionEvent{Type: CongestionEventRecovery, Recovery: CongestionRecovery{Stage: CongestionRecoveryUndo}}
	reno.HandleCongestionEvent(&checkpoint)
	reno.credit = 0.75
	reno.HandleCongestionEvent(&undo)
	if reno.credit != 0 || reno.recoveryCheckpoint != 0 {
		t.Fatalf("Reno zero-credit undo = credit %v checkpoint %#x", reno.credit, reno.recoveryCheckpoint)
	}
	reno.credit = 0.25
	reno.HandleCongestionEvent(&undo)
	if reno.credit != 0.25 {
		t.Fatalf("repeated Reno undo restored a stale checkpoint: credit %v", reno.credit)
	}
}

func TestRenoDoesNotGrowWhenApplicationLimited(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	const window = uint32(10 * mss)
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, 2*mss, false); grown != window {
		t.Fatalf("application-limited Reno window = %d, want %d", grown, window)
	}
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, window-mss, false); grown <= window {
		t.Fatalf("packet-granularity cwnd-limited Reno window = %d, want > %d", grown, window)
	}
}

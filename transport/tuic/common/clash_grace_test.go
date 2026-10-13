package common

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type graceHeld struct{ payload [1 << 20]byte }

func TestAGraceTimerHoldsItsConnectionWeakly(t *testing.T) {
	held := &graceHeld{}
	collected := make(chan struct{})
	runtime.AddCleanup(held, func(chan struct{}) { close(collected) }, collected)
	var ran atomic.Int32
	var sawNil atomic.Bool
	began := time.Now()
	AfterGrace(300*time.Millisecond, held, func(conn *graceHeld) {
		ran.Add(1)
		sawNil.Store(conn == nil)
	})
	held = nil
	deadline := time.After(250 * time.Millisecond)
	for collecting := true; collecting; {
		runtime.GC()
		select {
		case <-collected:
			collecting = false
		case <-deadline:
			t.Fatal("the grace timer kept its connection reachable")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(time.Until(began.Add(500 * time.Millisecond)))
	if ran.Load() != 1 || !sawNil.Load() {
		t.Fatalf("ran %d, nil %v: the timer runs, without the connection", ran.Load(), sawNil.Load())
	}
}

func TestAGraceTimerHandsOverALiveConnection(t *testing.T) {
	held := &graceHeld{}
	got := make(chan *graceHeld, 1)
	AfterGrace(20*time.Millisecond, held, func(conn *graceHeld) { got <- conn })
	if conn := <-got; conn != held {
		t.Fatal("a live connection was not handed over")
	}
	runtime.KeepAlive(held)
}

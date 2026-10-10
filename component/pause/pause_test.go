package pause

import (
	"sync/atomic"
	"testing"
	"time"
)


func TestRegisteredTickerStopsWhilePausedAndResumesOnWake(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	unregister := RegisterTicker(ticker, interval, nil)
	defer unregister()

	time.Sleep(6 * interval)
	running := ticks.Load()
	if running == 0 {
		t.Fatal("the ticker never fired before pausing, so this test cannot observe it stopping")
	}

	DevicePause()
	defer DeviceWake()

	time.Sleep(2 * interval)
	atPause := ticks.Load()

	time.Sleep(10 * interval)
	if paused := ticks.Load(); paused != atPause {
		t.Fatalf("the ticker fired %d more time(s) while the device was paused; each of those is "+
			"a round of URL tests, and on Apple one trustd round trip per handshake",
			paused-atPause)
	}
	if !IsDevicePaused() {
		t.Fatal("IsDevicePaused is false during a pause")
	}

	DeviceWake()
	time.Sleep(6 * interval)
	if resumed := ticks.Load(); resumed <= atPause {
		t.Fatalf("the ticker did not resume after wake: %d ticks, still at the paused count %d. "+
			"A pause that never ends would silently disable health checking for the whole session",
			resumed, atPause)
	}
	if IsDevicePaused() {
		t.Fatal("IsDevicePaused is still true after DeviceWake")
	}
}

func TestUnregisterStopsTrackingTheTicker(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	unregister := RegisterTicker(ticker, interval, nil)
	unregister()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	DevicePause()
	defer DeviceWake()

	time.Sleep(2 * interval)
	atPause := ticks.Load()
	time.Sleep(8 * interval)

	if paused := ticks.Load(); paused == atPause {
		t.Fatal("an unregistered ticker was still stopped by DevicePause, so the callback is " +
			"still in the process-wide list; every configuration reload would leak one")
	}
}

func TestResumeCallbackRunsBeforeTheTickerRestarts(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var resumed atomic.Bool
	unregister := RegisterTicker(ticker, interval, func() { resumed.Store(true) })
	defer unregister()

	DevicePause()
	if resumed.Load() {
		t.Fatal("the resume callback ran on pause")
	}

	DeviceWake()
	if !resumed.Load() {
		t.Fatal("the resume callback did not run on wake")
	}
}

func TestRegisteringWhileAlreadyPausedStopsImmediately(t *testing.T) {
	const interval = 10 * time.Millisecond

	DevicePause()
	defer DeviceWake()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unregister := RegisterTicker(ticker, interval, nil)
	defer unregister()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	time.Sleep(8 * interval)
	if got := ticks.Load(); got != 0 {
		t.Fatalf("a ticker registered during a pause fired %d time(s); a reload while the device "+
			"sleeps would restart the very traffic the pause exists to stop", got)
	}
}

func TestBothPausesAreVisibleIndependently(t *testing.T) {
	t.Cleanup(func() {
		DeviceWake()
		NetworkWake()
	})
	DeviceWake()
	NetworkWake()
	if IsDevicePaused() || IsNetworkPaused() {
		t.Fatal("precondition: nothing paused")
	}

	DevicePause()
	if !IsDevicePaused() || IsNetworkPaused() {
		t.Fatal("a device pause must not read as a network pause")
	}

	NetworkPause()
	if !IsDevicePaused() || !IsNetworkPaused() {
		t.Fatal("both pauses must be in force")
	}
	NetworkWake()
	if !IsDevicePaused() {
		t.Fatal("a network wake must not lift the device pause -- this is the overnight case")
	}
	if IsNetworkPaused() {
		t.Fatal("the network pause must be lifted")
	}

	DeviceWake()
	if IsDevicePaused() || IsNetworkPaused() {
		t.Fatal("both must be clear once the device wakes")
	}
}

func TestPauseCallsAreIdempotent(t *testing.T) {
	t.Cleanup(func() {
		DeviceWake()
		NetworkWake()
	})
	NetworkWake()
	for range [3]struct{}{} {
		NetworkPause()
	}
	if !IsNetworkPaused() {
		t.Fatal("repeated pauses must leave it paused")
	}
	for range [3]struct{}{} {
		NetworkWake()
	}
	if IsNetworkPaused() {
		t.Fatal("repeated wakes must leave it awake")
	}
}

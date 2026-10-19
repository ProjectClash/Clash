package pause

import (
	"testing"
	"time"
)

func TestANetworkWakeWhileTheDeviceSleepsKeepsTheTickerStopped(t *testing.T) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	stop, _ := RegisterTickerResumingOnDeviceWake(ticker, func() time.Duration { return 50 * time.Millisecond }, nil)
	defer stop()
	t.Cleanup(func() { NetworkWake(); DeviceWake() })
	DevicePause()
	NetworkPause()
	NetworkWake()
	ticks := 0
	deadline := time.After(500 * time.Millisecond)
	for waiting := true; waiting; {
		select {
		case <-ticker.C:
			ticks++
		case <-deadline:
			waiting = false
		}
	}
	if ticks != 0 {
		t.Fatalf("%d ticks in 0.5 s with the device paused", ticks)
	}
}

func TestATickRacingAWakeLeavesTheTickerRunning(t *testing.T) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	stop, tick := RegisterTickerResumingOnDeviceWake(ticker, func() time.Duration { return 30 * time.Millisecond }, nil)
	defer stop()
	t.Cleanup(DeviceWake)
	for i := 0; i < 500; i++ {
		DevicePause()
		done := make(chan struct{})
		go func() { tick(30 * time.Millisecond); close(done) }()
		DeviceWake()
		<-done
	}
	select {
	case <-ticker.C:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("awake, and the ticker does not tick")
	}
}

func TestTickRacingPausesIsRaceFree(t *testing.T) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	stop, tick := RegisterTickerResumingOnDeviceWake(ticker, func() time.Duration { return time.Hour }, nil)
	defer stop()
	t.Cleanup(DeviceWake)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			tick(time.Hour)
		}
	}()
	for i := 0; i < 300; i++ {
		DevicePause()
		DeviceWake()
	}
	<-done
}

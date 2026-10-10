package clash

import (
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/pause"
)

func TestCloseWakesTheDeviceItPaused(t *testing.T) {
	for _, profile := range []runtimeProfile{runtimeProfileMacOSPacketTunnel, runtimeProfileIOSPacketTunnel} {
		t.Run(profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, profile)
			leaveAwake(t)

			service := &BoxService{}
			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device")
			}

			if err := service.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if pause.IsDevicePaused() {
				t.Fatal("the device is still reported paused after Close; a service started in " +
					"this window would inherit a pause it never asked for")
			}
		})
	}
}

func TestCloseNeverWakesAPauseThisServiceDidNotMake(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	leaveAwake(t)

	pause.DevicePause()

	service := &BoxService{}
	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !pause.IsDevicePaused() {
		t.Fatal("Close woke a pause this service never made; a sibling service still holding " +
			"the pause would have its health checks resumed out from under it")
	}
}

func TestCloseStopsTheEndPauseTimerBeforeItCanFireAgainstAClosedService(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if service.endPauseTimer == nil {
		t.Fatal("no end-pause timer was armed on iOS")
	}

	service.endPauseMu.Lock()
	service.endPauseTimer.Reset(50 * time.Millisecond)
	service.endPauseMu.Unlock()

	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pause.DevicePause()
	time.Sleep(300 * time.Millisecond)
	if !pause.IsDevicePaused() {
		t.Fatal("something woke the device after Close -- the end-pause timer from the closed " +
			"service was not stopped and fired against a service that no longer exists")
	}
}

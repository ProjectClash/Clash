package clash

import (
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/pause"
)

func withRuntimeProfile(t *testing.T, profile runtimeProfile) {
	t.Helper()
	original := currentRuntimeProfile()
	setupRuntimeProfile.Store(uint32(profile))
	t.Cleanup(func() { setupRuntimeProfile.Store(uint32(original)) })
}

func leaveAwake(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		pause.DeviceWake()
		if pause.IsDevicePaused() {
			t.Error("the device is still paused after cleanup; later tests will misbehave")
		}
	})
}

func TestPauseAndWakeDriveTheDevicePauseManager(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		profile       runtimeProfile
		wakeResumes   bool
		armsExpiry    bool
		whyWakeResume string
	}{
		{
			name:          "macOS packet tunnel",
			profile:       runtimeProfileMacOSPacketTunnel,
			wakeResumes:   true,
			armsExpiry:    false,
			whyWakeResume: "a delivered wake resumes, and this profile never armed a backstop to fall back on",
		},
		{
			name:          "iOS packet tunnel",
			profile:       runtimeProfileIOSPacketTunnel,
			wakeResumes:   true,
			armsExpiry:    true,
			whyWakeResume: "a delivered wake resumes here too; the timer is only the backstop for one that never arrives",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			withRuntimeProfile(t, testCase.profile)
			leaveAwake(t)

			service := &BoxService{}

			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device; every registered ticker keeps running")
			}
			if service.pauseCount.Load() != 1 {
				t.Fatalf("pauseCount = %d, want 1", service.pauseCount.Load())
			}

			armed := service.endPauseTimer != nil
			if armed != testCase.armsExpiry {
				t.Fatalf("end-pause timer armed = %v, want %v", armed, testCase.armsExpiry)
			}

			service.Wake()
			if service.wakeCount.Load() != 1 {
				t.Fatalf("wakeCount = %d, want 1", service.wakeCount.Load())
			}
			if resumed := !pause.IsDevicePaused(); resumed != testCase.wakeResumes {
				t.Fatalf("Wake resumed the device = %v, want %v — %s",
					resumed, testCase.wakeResumes, testCase.whyWakeResume)
			}
		})
	}
}

func TestIOSEndPauseTimerActuallyFires(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if !pause.IsDevicePaused() {
		t.Fatal("Pause did not pause the device")
	}
	if service.endPauseTimer == nil {
		t.Fatal("no end-pause timer was armed on iOS")
	}

	service.endPauseMu.Lock()
	service.endPauseTimer.Reset(50 * time.Millisecond)
	service.endPauseMu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pause.IsDevicePaused() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the end-pause timer fired without waking the device; on iOS nothing else resumes " +
		"it, so health checking would stay off for the rest of the session")
}

func TestRepeatedSleepExtendsTheWindow(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	first := service.endPauseTimer

	service.Pause()
	if service.endPauseTimer != first {
		t.Fatal("a second sleep replaced the timer instead of resetting it; upstream resets, and " +
			"replacing leaks the old one")
	}
	if !pause.IsDevicePaused() {
		t.Fatal("a second sleep left the device awake")
	}
	if service.pauseCount.Load() != 2 {
		t.Fatalf("pauseCount = %d, want 2", service.pauseCount.Load())
	}
}

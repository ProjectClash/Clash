package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/component/pause"
)

func TestWakeResumesHealthChecksOnEveryProfileIncludingIOS(t *testing.T) {
	for _, profile := range []runtimeProfile{
		runtimeProfileIOSPacketTunnel,
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		t.Run(profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, profile)
			leaveAwake(t)

			service := &BoxService{}
			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device")
			}

			service.Wake()

			if pause.IsDevicePaused() {
				t.Error("Wake left the device paused; health checks stay stopped until a timer " +
					"expires, so the next check lands a full interval after that")
			}
		})
	}
}

func TestIOSStillArmsTheBackstopTimerAfterWakeResumes(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if service.endPauseTimer == nil {
		t.Fatal("the backstop timer must still be armed on iOS")
	}
	service.Wake()
	if pause.IsDevicePaused() {
		t.Fatal("Wake must resume regardless of the backstop")
	}
}

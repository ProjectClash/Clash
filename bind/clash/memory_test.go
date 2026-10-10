package clash

import (
	"os"
	"testing"

	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type fakeTracker struct {
	statistic.Tracker
	closed bool
}

func (f *fakeTracker) ID() string   { return "clash-test-tracker" }
func (f *fakeTracker) Close() error { f.closed = true; return nil }

func TestHandleMemoryPressureRecordsEvidenceAndKeepsConnections(t *testing.T) {
	const softLimit = 50 << 20
	path := setupOOMEvidenceTest(t)
	startPressureThresholdMonitor(0, pressureThresholdShedEnabled.Load())
	before := memoryPressureEventCount.Load()

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	handleMemoryPressureWith(39_580_000, softLimit)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pressure evidence was not persisted: %v", err)
	}
	if tracker.closed {
		t.Fatal("closed a live connection from the pressure NOTIFICATION; sing-box does not " +
			"shed there either. Shedding belongs to the threshold machine, on its own " +
			"measurements — never to the OS notification")
	}
	if got := memoryPressureEventCount.Load(); got != before+1 {
		t.Fatalf("memory pressure event count = %d, want %d", got, before+1)
	}
}

func TestStartMemoryPressureMonitorIsSafe(t *testing.T) {
	startMemoryPressureMonitor()
	startMemoryPressureMonitor()
}

func TestArmMemoryPressureMonitorForNetworkExtensionProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profile  runtimeProfile
		appOnly  bool
		wantArms int
	}{
		{name: "iOS packet tunnel without a budget", profile: runtimeProfileIOSPacketTunnel, wantArms: 1},
		{name: "macOS packet tunnel without a budget", profile: runtimeProfileMacOSPacketTunnel, wantArms: 1},
		{name: "macOS containing application", profile: runtimeProfileMacOSApplication},
		{name: "app-only preflight", profile: runtimeProfileIOSPacketTunnel, appOnly: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arms := 0
			armMemoryPressureMonitorForRuntime(test.profile, test.appOnly, func() {
				arms++
			})
			if arms != test.wantArms {
				t.Fatalf("memory pressure monitor arms = %d, want %d", arms, test.wantArms)
			}
		})
	}
}

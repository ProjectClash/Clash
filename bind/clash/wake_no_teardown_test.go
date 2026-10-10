package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func TestWakeKeepsLiveConnections(t *testing.T) {
	service := &BoxService{running: true}

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	before := service.wakeCount.Load()
	service.Wake()

	if tracker.closed {
		t.Fatal("Wake() closed a live connection; a sleep/wake pair is not evidence that the " +
			"connection died, and every app's session pays a TCP connect and a full TLS " +
			"handshake to recover -- one trustd round trip each on iOS")
	}
	if got := service.wakeCount.Load(); got != before+1 {
		t.Fatalf("wakeCount = %d, want %d", got, before+1)
	}
}

func TestPauseKeepsLiveConnections(t *testing.T) {
	service := &BoxService{running: true}

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	before := service.pauseCount.Load()
	service.Pause()

	if tracker.closed {
		t.Fatal("Pause() closed a live connection; the useful action while asleep is shrinking " +
			"the footprint against jetsam, not discarding work")
	}
	if got := service.pauseCount.Load(); got != before+1 {
		t.Fatalf("pauseCount = %d, want %d", got, before+1)
	}
}

func TestCloseAllConnectionsStillWorks(t *testing.T) {
	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	CloseAllConnections()

	if !tracker.closed {
		t.Fatal("CloseAllConnections must still close tracked connections for its real callers")
	}
}

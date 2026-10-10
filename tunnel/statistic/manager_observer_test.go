package statistic

import (
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
)

type observedTracker struct {
	Tracker
	info *TrackerInfo
}

func (t observedTracker) ID() string         { return t.info.UUID.String() }
func (t observedTracker) Info() *TrackerInfo { return t.info }

func TestConnectionObserverSeesEveryJoinAndRealLeave(t *testing.T) {
	manager := NewManagerForTest()
	type seen struct {
		joined  bool
		id      string
		inTable bool
	}
	var got []seen
	manager.SetConnectionObserver(func(joined bool, tracker Tracker) {
		got = append(got, seen{joined, tracker.ID(), manager.Get(tracker.ID()) != nil})
	})

	tracker := observedTracker{info: &TrackerInfo{UUID: utils.NewUUIDV4()}}
	manager.Join(tracker)
	manager.Leave(tracker)
	manager.Leave(tracker)

	want := []seen{{true, tracker.ID(), true}, {false, tracker.ID(), false}}
	if len(got) != len(want) {
		t.Fatalf("observer saw %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("observer saw %+v, want %+v", got, want)
		}
	}

	manager.SetConnectionObserver(nil)
	manager.Join(tracker)
	if len(got) != len(want) {
		t.Fatalf("a removed observer was still called: %+v", got)
	}
}

package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/component/profile"
	"github.com/ProjectClash/Clash/component/profile/cachefile"
)

func TestSelectionChangesReachTheStreamEvenWithStoreSelectedOff(t *testing.T) {
	fired := make(chan string, 4)
	cachefile.SetSelectedObserver(func(group, selected string) { fired <- group + "=" + selected })
	t.Cleanup(func() { cachefile.SetSelectedObserver(nil) })

	previous := profile.StoreSelected.Load()
	profile.StoreSelected.Store(false)
	t.Cleanup(func() { profile.StoreSelected.Store(previous) })

	cachefile.Cache().SetSelected("GLOBAL", "singapore")

	select {
	case got := <-fired:
		if got != "GLOBAL=singapore" {
			t.Fatalf("observer saw %q", got)
		}
	default:
		t.Fatal("a selection change did not reach the observer; with store-selected off the seam " +
			"would be silent exactly when nothing is written down to fall back on")
	}
}

func TestSelectionSnapshotInitializesManualSelections(t *testing.T) {
	switches := currentRuntimeSwitches()
	if switches.Selected == nil {
		t.Fatal("Selected must be an empty map rather than nil: a consumer cannot tell a null " +
			"it did not expect from a core that has nothing selected")
	}

}

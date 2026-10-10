package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter"
)

func pinUnifiedDelayOff(t *testing.T) {
	t.Helper()
	prior := adapter.UnifiedDelay.Swap(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prior) })
}

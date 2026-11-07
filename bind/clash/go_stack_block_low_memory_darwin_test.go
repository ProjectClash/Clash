//go:build darwin && with_low_memory

package clash

import "testing"

func TestTheGoStackReadsLowMemoryBlocksOnAnExtensionWithAJetsamLimit(t *testing.T) {
	if goStreamBlock != 16<<10 {
		t.Fatalf("goStreamBlock is %d KiB on a with_low_memory build, want the 16 KiB every read waiter there takes", goStreamBlock>>10)
	}
}

func TestTheGoStackALowMemoryBuildStartsHoldsGVisorsUDPSessions(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	if entry.options.UDPNATMax != 1024 {
		t.Fatalf("newGoStack gives the stack a UDP session limit of %d on a with_low_memory build, want 1024", entry.options.UDPNATMax)
	}
}

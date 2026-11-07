//go:build darwin && !with_low_memory

package clash

import "testing"

func TestTheGoStackAMacStartsKeepsTheStacksUDPSessionLimit(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	if entry.options.UDPNATMax != 0 {
		t.Fatalf("newGoStack gives a Mac's go stack a UDP session limit of %d, want the stack's own", entry.options.UDPNATMax)
	}
}

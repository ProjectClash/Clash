//go:build with_low_memory

package clash

import "testing"

func TestLowMemoryBuildActive(t *testing.T) {
	if !LowMemoryBuild() {
		t.Fatal("with_low_memory tag set but LowMemoryBuild() = false")
	}
}

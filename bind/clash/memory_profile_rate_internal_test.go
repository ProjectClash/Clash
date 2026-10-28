//go:build clash_internal

package clash

import "testing"

func TestAnInternalBuildKeepsTheGODEBUGsMemProfileRate(t *testing.T) {
	for godebug, chose := range map[string]bool{
		"":                                      false,
		"gctrace=1":                             false,
		"memprofilerate=0":                      true,
		"gctrace=1, memprofilerate=1":           false,
		"gctrace=1,memprofilerate=1":            true,
		"memprofilerate=abc":                    false,
		"adaptivestackstart=0,memprofilerate=0": true,
		"memprofilerates=1":                     false,
	} {
		if got := godebugSetsMemProfileRate(godebug); got != chose {
			t.Errorf("GODEBUG %q: chose a rate %v, want %v", godebug, got, chose)
		}
	}
}

package tun

import (
	"testing"
	"time"
)

func TestABlockedGateIsSampledFastOnlyRightAfterItBlocks(t *testing.T) {
	if got := goDarwinGatePollInterval(true, time.Millisecond); got != goDarwinGatePoll {
		t.Fatalf("a gate blocked 1 ms ago is sampled every %s, want every poll (%s)", got, goDarwinGatePoll)
	}
	if got := goDarwinGatePollInterval(true, 20*time.Millisecond); got != goDarwinGateSample {
		t.Fatalf("a gate blocked 20 ms is sampled every %s, want upstream's %s", got, goDarwinGateSample)
	}
	if got := goDarwinGatePollInterval(false, 0); got != goDarwinGateSample {
		t.Fatalf("an open gate is sampled every %s, want upstream's %s", got, goDarwinGateSample)
	}
}

func TestTheGateProbesAfterTheTimeUpstreamDoesWhateverTheSampleRate(t *testing.T) {
	if goDarwinGateShouldProbe(15 * time.Millisecond) {
		t.Fatal("probed after 15 ms without progress; upstream waits 16")
	}
	if !goDarwinGateShouldProbe(16 * time.Millisecond) {
		t.Fatal("no probe after 16 ms without progress")
	}
}

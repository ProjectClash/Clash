package tun

import "time"

func goDarwinGatePollInterval(blocked bool, blockedFor time.Duration) time.Duration {
	if blocked && blockedFor < goDarwinGateFastWindow {
		return goDarwinGatePoll
	}
	return goDarwinGateSample
}

func goDarwinGateShouldProbe(sinceProgress time.Duration) bool {
	return sinceProgress >= goDarwinGateProbeAfter*goDarwinGateSample
}

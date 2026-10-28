package clash

import (
	"context"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

const (
	sessionIdlePeriod    = 30 * time.Second
	sessionSweepInterval = 10 * time.Second
)

func armSessionRelease() {
	adapter.SetURLTestFinished(releaseAfterProbe)
}

func releaseAfterProbe(ctx context.Context, _ *adapter.Proxy) {
	for _, node := range outbound.ProbeDialed(ctx) {
		outbound.ReleaseProbedSession(node)
	}
}

func sweepIdleSessions(now time.Time, idle time.Duration) int {
	seen := map[C.ProxyAdapter]struct{}{}
	released := 0
	visit := func(proxy C.Proxy) {
		if proxy == nil {
			return
		}
		node := proxy.Adapter()
		if _, dup := seen[node]; dup {
			return
		}
		seen[node] = struct{}{}
		if outbound.ReleaseUserSessionIfIdle(node, now, idle) {
			released++
		}
	}
	rangeHeldProxies(func(proxy C.Proxy) bool { visit(proxy); return true })
	return released
}

func runSessionSweep(ctx context.Context, interval, idle time.Duration, quiet *quietRelease) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			sweepIdleSessions(now, idle)
			refreshNodeCatalog()
			if quiet != nil {
				quiet.observe(now)
			}
		}
	}
}

func (s *BoxService) startSessionSweepLocked() {
	s.stopSessionSweepLocked()
	ctx, cancel := context.WithCancel(context.Background())
	s.sessionSweepCancel = cancel
	var quiet *quietRelease
	if currentRuntimePolicy(s.platform.UnderNetworkExtension()).releaseWhenQuiet {
		quiet = newQuietRelease(time.Now())
	}
	go runSessionSweep(ctx, sessionSweepInterval, sessionIdlePeriod, quiet)
}

func (s *BoxService) stopSessionSweepLocked() {
	if s.sessionSweepCancel != nil {
		s.sessionSweepCancel()
		s.sessionSweepCancel = nil
	}
}

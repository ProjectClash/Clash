package provider

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)

func withRoundHold(t *testing.T, hold func(ctx context.Context) error) {
	t.Helper()
	SetBackgroundRoundHold(hold)
	t.Cleanup(func() { SetBackgroundRoundHold(nil) })
}

func TestAScheduledRoundWaitsForTheHold(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	withRoundHold(t, func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	probe := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	healthCheck := NewHealthCheck([]C.Proxy{probe}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	defer healthCheck.close()

	done := make(chan struct{})
	go func() { healthCheck.checkScheduled(); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("a scheduled round never asked the hold")
	}
	time.Sleep(50 * time.Millisecond)
	if got := probe.probes.Load(); got != 0 {
		t.Fatalf("a held round probed %d node(s)", got)
	}
	close(release)
	<-done
	if got := probe.probes.Load(); got != 1 {
		t.Fatalf("the released round probed %d node(s), want 1", got)
	}
}

func TestAHeldRoundEndsWithItsHealthCheck(t *testing.T) {
	withRoundHold(t, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	probe := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	healthCheck := NewHealthCheck([]C.Proxy{probe}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	done := make(chan struct{})
	go func() { healthCheck.checkScheduled(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	healthCheck.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a held round outlived its health check")
	}
	if got := probe.probes.Load(); got != 0 {
		t.Fatalf("a round held until its provider closed probed %d node(s)", got)
	}
}

func TestAForcedCheckIsNotHeld(t *testing.T) {
	withRoundHold(t, func(ctx context.Context) error {
		t.Error("a forced check asked the background hold")
		return nil
	})
	probe := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	healthCheck := NewHealthCheck([]C.Proxy{probe}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	defer healthCheck.close()
	healthCheck.check()
	if got := probe.probes.Load(); got != 1 {
		t.Fatalf("a forced check probed %d node(s), want 1", got)
	}
}

func TestANetworkChangeRoundWaitsForTheHold(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	withRoundHold(t, func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	probe := &countingProxy{}
	healthCheck := NewHealthCheck([]C.Proxy{probe}, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	defer healthCheck.close()
	provider, err := NewCompatibleProvider("p", []C.Proxy{probe}, healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	provider.HealthCheckAfterNetworkChange()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("a network-change round never asked the hold")
	}
	time.Sleep(50 * time.Millisecond)
	if got := probe.urlTests.Load(); got != 0 {
		t.Fatalf("a held network-change round probed %d node(s)", got)
	}
	close(release)
	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("the released network-change round measured nothing")
	}
}

type slowProxy struct {
	*adapter.Proxy
	inFlight, peak *atomic.Int64
	want           int64
}

func (p slowProxy) URLTest(ctx context.Context, url string, expected utils.IntRanges[uint16]) (uint16, error) {
	n := p.inFlight.Add(1)
	for {
		old := p.peak.Load()
		if n <= old || p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	for deadline := time.Now().Add(2 * time.Second); p.peak.Load() < p.want && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	p.inFlight.Add(-1)
	return 0, nil
}

func TestARoundRunsAtTheConfiguredConcurrency(t *testing.T) {
	for _, c := range []struct {
		limit func() int
		want  int64
	}{
		{nil, 10},
		{func() int { return 3 }, 3},
		{func() int { return 24 }, 24},
		{func() int { return 0 }, 10},
	} {
		SetRoundConcurrency(c.limit)
		var inFlight, peak atomic.Int64
		proxies := make([]C.Proxy, 40)
		for i := range proxies {
			proxies[i] = slowProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), inFlight: &inFlight, peak: &peak, want: c.want}
		}
		healthCheck := NewHealthCheck(proxies, "http://127.0.0.1:1/never", 1, 300, false, nil)
		healthCheck.check()
		healthCheck.close()
		if peak.Load() != c.want {
			t.Fatalf("peak in flight %d, want %d", peak.Load(), c.want)
		}
	}
	SetRoundConcurrency(nil)
}

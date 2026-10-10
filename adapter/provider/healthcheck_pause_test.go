package provider

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
)


func TestHealthCheckRegistersAndReleasesItsPauseCallback(t *testing.T) {
	baseline := pause.Outstanding()

	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 1, true, nil)

	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()

	if !waitFor(func() bool { return pause.Outstanding() == baseline+1 }) {
		t.Fatalf("process() did not register a pause callback: outstanding %d, want %d. "+
			"Without it the ticker keeps firing while the device sleeps",
			pause.Outstanding(), baseline+1)
	}

	healthCheck.close()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("process() did not return after close()")
	}

	if !waitFor(func() bool { return pause.Outstanding() == baseline }) {
		t.Fatalf("the pause callback outlived the health check: outstanding %d, want the baseline "+
			"%d. Each configuration reload would leave one behind for the life of the process",
			pause.Outstanding(), baseline)
	}
}

func TestRepeatedHealthChecksDoNotAccumulateCallbacks(t *testing.T) {
	baseline := pause.Outstanding()

	for round := 0; round < 5; round++ {
		healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 1, true, nil)
		stopped := make(chan struct{})
		go func() {
			healthCheck.process()
			close(stopped)
		}()
		if !waitFor(func() bool { return pause.Outstanding() > baseline }) {
			t.Fatalf("round %d never registered", round)
		}
		healthCheck.close()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d did not stop", round)
		}
	}

	if !waitFor(func() bool { return pause.Outstanding() == baseline }) {
		t.Fatalf("after five create/destroy rounds outstanding is %d, want the baseline %d",
			pause.Outstanding(), baseline)
	}
}

func waitFor(condition func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

type countingProxy struct {
	C.Proxy
	urlTests atomic.Int64
}

func (p *countingProxy) Name() string { return "probe" }
func (p *countingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.urlTests.Add(1)
	return 0, errors.New("probe never dials")
}
func (p *countingProxy) AliveForTestUrl(url string) bool       { return false }
func (p *countingProxy) LastDelayForTestUrl(url string) uint16 { return 0 }

func TestWakeRunsAHealthCheckInsteadOfOnlyRestartingTheClock(t *testing.T) {
	t.Cleanup(pause.DeviceWake)

	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	probe := &countingProxy{}
	healthCheck.setProxies([]C.Proxy{probe})

	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()
	t.Cleanup(func() {
		healthCheck.close()
		<-stopped
	})

	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("process() did not run its initial check; the rest of this test cannot distinguish causes")
	}
	time.Sleep(1200 * time.Millisecond)
	initial := probe.urlTests.Load()

	pause.DevicePause()
	pause.DeviceWake()

	if !waitFor(func() bool { return probe.urlTests.Load() > initial }) {
		t.Fatalf("no health check followed the wake (url tests still %d): with a nil resume the "+
			"ticker is merely Reset, so the next check is a full interval away", probe.urlTests.Load())
	}
}

func TestOvernightNetworkFlapRunsNoHealthCheck(t *testing.T) {
	t.Cleanup(func() {
		pause.DeviceWake()
		pause.NetworkWake()
	})
	pause.DeviceWake()
	pause.NetworkWake()

	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 1, false, nil)
	probe := &countingProxy{}
	healthCheck.setProxies([]C.Proxy{probe})
	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()
	t.Cleanup(func() {
		healthCheck.close()
		<-stopped
	})
	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("the health check must run once when it starts")
	}
	time.Sleep(1200 * time.Millisecond)

	pause.DevicePause()
	time.Sleep(50 * time.Millisecond)
	before := probe.urlTests.Load()

	for range [3]struct{}{} {
		pause.NetworkPause()
		time.Sleep(20 * time.Millisecond)
		pause.NetworkWake()
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(2500 * time.Millisecond)

	if after := probe.urlTests.Load(); after != before {
		t.Fatalf("health checks ran while the device slept: %d -> %d", before, after)
	}

	pause.DeviceWake()
	if !waitFor(func() bool { return probe.urlTests.Load() > before }) {
		t.Fatal("waking the device must produce a check")
	}
}

func TestANetworkReturningRunsNoHealthCheckOfItsOwn(t *testing.T) {
	t.Cleanup(func() {
		pause.DeviceWake()
		pause.NetworkWake()
	})
	pause.DeviceWake()
	pause.NetworkWake()

	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	probe := &countingProxy{}
	healthCheck.setProxies([]C.Proxy{probe})
	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()
	t.Cleanup(func() {
		healthCheck.close()
		<-stopped
	})
	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("the health check must run once when it starts")
	}
	time.Sleep(1200 * time.Millisecond)
	before := probe.urlTests.Load()

	pause.NetworkPause()
	time.Sleep(20 * time.Millisecond)
	pause.NetworkWake()
	time.Sleep(500 * time.Millisecond)

	if after := probe.urlTests.Load(); after != before {
		t.Fatalf("a network returning ran a health check of its own: %d -> %d", before, after)
	}
}

package provider

import (
	"context"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
)

func TestAWakeShortlyAfterARoundRunsNoneAndKeepsTheInterval(t *testing.T) {
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
		t.Fatal("process() did not run its initial check")
	}
	time.Sleep(1200 * time.Millisecond)
	initial := probe.urlTests.Load()
	for i := 0; i < 20; i++ {
		pause.DevicePause()
		pause.DeviceWake()
	}
	time.Sleep(1500 * time.Millisecond)
	if got := probe.urlTests.Load(); got != initial {
		t.Fatalf("20 wakes a second after a round ran %d more tests", got-initial)
	}
	if rest := healthCheck.untilScheduled(); rest <= 0 || rest > healthCheck.interval-time.Second {
		t.Fatalf("the ticker resumes in %v of %v", rest, healthCheck.interval)
	}
}

func TestAScheduledRoundAskedWhileOneIsHeldIsDropped(t *testing.T) {
	release := make(chan struct{})
	SetBackgroundRoundHold(func(ctx context.Context) error { <-release; return nil })
	t.Cleanup(func() { SetBackgroundRoundHold(nil) })
	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	t.Cleanup(healthCheck.close)
	probe := &countingProxy{}
	healthCheck.setProxies([]C.Proxy{probe})
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() { healthCheck.checkScheduled(); done <- struct{}{} }()
	}
	for i := 0; i < 9; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%d rounds queued behind the held one", 9-i)
		}
	}
	close(release)
	<-done
	if !waitFor(func() bool { return probe.urlTests.Load() == 1 }) || probe.urlTests.Load() != 1 {
		t.Fatalf("%d tests ran, want the one round's 1", probe.urlTests.Load())
	}
}

func TestAWakeShortlyBeforeATickShortensThatTickOnly(t *testing.T) {
	t.Cleanup(pause.DeviceWake)
	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 2, false, nil)
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
		t.Fatal("process() did not run its initial check")
	}
	began := time.Unix(0, healthCheck.lastScheduled.Load())
	time.Sleep(time.Until(began.Add(1700 * time.Millisecond)))
	pause.DevicePause()
	pause.DeviceWake()
	before := probe.urlTests.Load()
	time.Sleep(6 * time.Second)
	if rounds := probe.urlTests.Load() - before; rounds > 3 {
		t.Fatalf("%d rounds in three intervals after a wake just before a tick", rounds)
	}
}

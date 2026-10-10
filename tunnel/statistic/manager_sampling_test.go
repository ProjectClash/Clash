package statistic

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
)


func waitUntil(t *testing.T, deadline time.Duration, condition func() bool) bool {
	t.Helper()
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

func TestResumingDoesNotPublishTheIdleAccumulation(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	const idleBytes = 500 << 20
	manager.PushUploaded("direct", idleBytes)
	manager.PushDownloaded("direct", idleBytes)
	time.Sleep(1500 * time.Millisecond)

	if up, down := manager.uploadBlip.Load(), manager.downloadBlip.Load(); up != 0 || down != 0 {
		t.Fatalf("the idle sampler published a rate (up=%d down=%d); it should not have been "+
			"sampling at all", up, down)
	}

	manager.Now()

	if !waitUntil(t, 3*time.Second, func() bool {
		return manager.uploadTemp.Load() == 0
	}) {
		t.Fatalf("the sampler did not clear the idle accumulation: uploadTemp=%d", manager.uploadTemp.Load())
	}

	time.Sleep(2500 * time.Millisecond)
	if up := manager.uploadBlip.Load(); up >= idleBytes {
		t.Fatalf("published %d bytes/s after resuming; the whole idle span was reported as one "+
			"second of traffic, which is the fake spike this design exists to avoid", up)
	}
	if down := manager.downloadBlip.Load(); down >= idleBytes {
		t.Fatalf("published %d bytes/s down after resuming, same fake spike", down)
	}
}

func TestSamplerPublishesRealTrafficWhileBeingRead(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()

	const perSecond = 3 << 20
	published := waitUntil(t, 6*time.Second, func() bool {
		manager.PushUploaded("direct", perSecond/4)
		manager.Now()
		time.Sleep(120 * time.Millisecond)
		return manager.uploadBlip.Load() > 0
	})
	if !published {
		t.Fatal("a sampler being read every 120 ms never published a rate, so reads are not " +
			"keeping it alive and the rate view would sit at zero")
	}
}

func TestSamplerStopsWhenNobodyReads(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()
	manager.PushUploaded("direct", 4<<20)

	if !waitUntil(t, 4*time.Second, func() bool { return manager.uploadBlip.Load() > 0 }) {
		t.Fatal("never published a rate while being read")
	}

	time.Sleep(sampleIdleTimeout + time.Second)
	manager.uploadTemp.Store(0)
	manager.PushUploaded("direct", 7<<20)
	time.Sleep(2 * time.Second)

	if manager.uploadTemp.Load() != 7<<20 {
		t.Fatalf("uploadTemp = %d after the idle timeout, want the pushed 7 MiB left untouched; "+
			"the sampler is still running with no reader", manager.uploadTemp.Load())
	}
}

func TestSnapshotDoesNotWakeTheSampler(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Snapshot()
	manager.PushUploaded("direct", 9<<20)
	time.Sleep(2 * time.Second)

	if got := manager.uploadBlip.Load(); got != 0 {
		t.Fatalf("Snapshot woke the sampler: published %d bytes/s", got)
	}
	if manager.lastReadAt.Load() != 0 {
		t.Fatal("Snapshot recorded a rate read")
	}
}

func newTestManager() *Manager {
	return &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		proxyUploadTemp:    atomic.NewInt64(0),
		proxyDownloadTemp:  atomic.NewInt64(0),
		proxyUploadBlip:    atomic.NewInt64(0),
		proxyDownloadBlip:  atomic.NewInt64(0),
		proxyUploadTotal:   atomic.NewInt64(0),
		proxyDownloadTotal: atomic.NewInt64(0),
		lastReadAt:         atomic.NewInt64(0),
		sampledAt:          atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}
}

func TestMemorySamplingAndCachedSnapshotsAreConcurrent(t *testing.T) {
	manager := newTestManager()
	manager.pid = int32(os.Getpid())
	if manager.Memory() == 0 {
		t.Skip("host RSS sampling unavailable")
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(sample bool) {
			defer workers.Done()
			<-start
			for n := 0; n < 500; n++ {
				if sample {
					manager.Memory()
				} else {
					manager.Snapshot()
				}
			}
		}(worker%2 == 0)
	}
	close(start)
	workers.Wait()
}

func TestMemorySampleIsVisibleInCachedSnapshot(t *testing.T) {
	manager := newTestManager()
	manager.pid = int32(os.Getpid())
	if got := manager.Snapshot().Memory; got != 0 {
		t.Fatalf("unsampled snapshot = %d", got)
	}
	sampled := manager.Memory()
	if sampled == 0 {
		t.Skip("host RSS sampling unavailable")
	}
	if got := manager.Snapshot().Memory; got != sampled {
		t.Fatalf("snapshot=%d, last sample=%d", got, sampled)
	}
}

func TestAStoppedSamplersRateIsNotReadAsCurrent(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()
	if !waitUntil(t, 5*time.Second, func() bool {
		manager.PushUploaded("proxy", 64<<10)
		manager.PushDownloaded("proxy", 128<<10)
		up, down := manager.Now()
		pu, pd := manager.NowTraffic(true)
		return up > 0 && down > 0 && pu > 0 && pd > 0
	}) {
		t.Fatal("the sampler never published a rate while being read")
	}
	lastUp, lastDown, sampledAt, fresh := manager.LastRate()
	if lastUp == 0 || lastDown == 0 || time.Since(sampledAt) > 2*time.Second || !fresh {
		t.Fatalf("a running sampler's last rate is %d/%d sampled %s ago", lastUp, lastDown, time.Since(sampledAt))
	}
	upTotal, downTotal := manager.Total()

	manager.lastReadAt.Store(monoNow() - int64(2*sampleIdleTimeout))
	time.Sleep(1200 * time.Millisecond)
	manager.sampledAt.Store(monoNow() - int64(3*time.Second))

	if up, down, at, fresh := manager.LastRate(); up == 0 || down == 0 || time.Since(at) < RateFreshFor || fresh {
		t.Fatalf("LastRate lost the last measurement or its age: %d/%d sampled %s ago", up, down, time.Since(at))
	}
	if up, down := manager.Now(); up != 0 || down != 0 {
		t.Fatalf("Now() returned a rate nobody measured in the last %s: up=%d down=%d", RateFreshFor, up, down)
	}
	if up, down := manager.NowTraffic(true); up != 0 || down != 0 {
		t.Fatalf("NowTraffic(proxy) returned a stale rate: up=%d down=%d", up, down)
	}
	if up, down := manager.Total(); up != upTotal || down != downTotal {
		t.Fatalf("stopping the sampler changed the totals: %d/%d, were %d/%d", up, down, upTotal, downTotal)
	}
}

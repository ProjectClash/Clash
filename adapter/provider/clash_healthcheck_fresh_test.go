package provider

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)

type recordingProxy struct {
	*adapter.Proxy
	probes atomic.Int64
	gate   chan struct{}

	mu       sync.Mutex
	record   C.DelayHistory
	alive    bool
	expected string
	has      bool
}

func (r *recordingProxy) LastURLTestRecord(url string) (C.DelayHistory, bool, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.record, r.alive, r.expected, r.has
}

func plantHistory(p *recordingProxy, record C.DelayHistory, alive bool) {
	plantHistoryAsked(p, record, alive, "*")
}

func plantHistoryAsked(p *recordingProxy, record C.DelayHistory, alive bool, expected string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record, p.alive, p.expected, p.has = record, alive, expected, true
}

func (r *recordingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	r.probes.Add(1)
	if r.gate != nil {
		<-r.gate
	}
	return r.Proxy.URLTest(ctx, url, expectedStatus)
}

func TestProviderHealthCheckMeasuresANodeMeasuredAliveMomentsAgo(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	justMeasured := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	plantHistory(justMeasured, C.DelayHistory{Time: time.Now().Add(-10 * time.Second), Delay: 42}, true)

	healthCheck := NewHealthCheck([]C.Proxy{justMeasured}, url, 1, 300, true, nil)
	healthCheck.check()

	if got := justMeasured.probes.Load(); got != 1 {
		t.Fatalf("a forced check probed a node measured alive 10s ago %d times, want 1: a failover check that skips it cannot see that it died", got)
	}
}

func TestScheduledRoundMeasuresANodeItMeasuredInItsOwnPreviousRound(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	ownPreviousRound := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	plantHistory(ownPreviousRound, C.DelayHistory{Time: time.Now().Add(-298 * time.Second), Delay: 42}, true)

	healthCheck := NewHealthCheck([]C.Proxy{ownPreviousRound}, url, 1, 300, true, nil)
	healthCheck.checkScheduled()

	if got := ownPreviousRound.probes.Load(); got != 1 {
		t.Fatalf("a node this check measured 298s ago was probed %d times in the next 300s round, want 1: skipping it doubles the user's interval", got)
	}
}

func TestScheduledRoundSkipsANodeASiblingMeasuredAliveSinceTheRoundBegan(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	siblingMeasuredAlive := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	siblingMeasuredDead := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	now := time.Now()
	roundBegan := now.Add(-3 * time.Second)
	plantHistory(siblingMeasuredAlive, C.DelayHistory{Time: now.Add(-1 * time.Second), Delay: 42}, true)
	plantHistory(siblingMeasuredDead, C.DelayHistory{Time: now.Add(-1 * time.Second), Delay: 0}, false)

	healthCheck := NewHealthCheck([]C.Proxy{siblingMeasuredAlive, siblingMeasuredDead}, url, 1000, 300, true, nil)
	healthCheck.scheduledRound(roundBegan)

	if got := siblingMeasuredAlive.probes.Load(); got != 0 {
		t.Fatalf("a node a sibling round measured alive 2s into this round was probed %d times, want 0", got)
	}
	if got := siblingMeasuredDead.probes.Load(); got != 1 {
		t.Fatalf("a node whose newest record is dead was probed %d times, want 1", got)
	}
}

func TestTheTickerLoopRunsTheScheduledRound(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	measuredSince := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	neverMeasured := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	plantHistory(measuredSince, C.DelayHistory{Time: time.Now().Add(time.Hour), Delay: 42}, true)

	healthCheck := NewHealthCheck([]C.Proxy{measuredSince, neverMeasured}, url, 1000, 300, false, nil)
	go healthCheck.process()
	defer healthCheck.close()

	deadline := time.Now().Add(5 * time.Second)
	for neverMeasured.probes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the ticker loop never started its first round")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := measuredSince.probes.Load(); got != 0 {
		t.Fatalf("the ticker loop's first round probed a node measured since it began %d times, want 0", got)
	}
}

func TestScheduledRoundMeasuresANodeASiblingMeasuredUnderAnotherExpectedStatus(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	expects204, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	node := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	now := time.Now()
	plantHistoryAsked(node, C.DelayHistory{Time: now.Add(-1 * time.Second), Delay: 42}, true, "200-299")

	healthCheck := NewHealthCheck([]C.Proxy{node}, url, 1000, 300, true, expects204)
	healthCheck.scheduledRound(now.Add(-3 * time.Second))

	if got := node.probes.Load(); got != 1 {
		t.Fatalf("a check expecting 204 probed a node measured alive under 200-299 %d times, want 1", got)
	}
}

func TestScheduledRoundMeasuresANodeASiblingFoundSlowerThanItsOwnTimeout(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	node := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	now := time.Now()
	plantHistory(node, C.DelayHistory{Time: now.Add(-1 * time.Second), Delay: 2000}, true)

	healthCheck := NewHealthCheck([]C.Proxy{node}, url, 1000, 300, true, nil)
	healthCheck.scheduledRound(now.Add(-3 * time.Second))

	if got := node.probes.Load(); got != 1 {
		t.Fatalf("a check with a 1000ms timeout probed a node a sibling measured at 2000ms %d times, want 1", got)
	}
}

func TestScheduledRoundAsksAgainWhenTheProbeIsAboutToRun(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	gate := make(chan struct{})
	var nodes []C.Proxy
	var slotHolders []*recordingProxy
	for i := 0; i < 10; i++ {
		holder := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), gate: gate}
		slotHolders = append(slotHolders, holder)
		nodes = append(nodes, holder)
	}
	queued := &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	nodes = append(nodes, queued)

	healthCheck := NewHealthCheck(nodes, url, 1000, 300, true, nil)
	began := time.Now()
	roundDone := make(chan struct{})
	go func() {
		defer close(roundDone)
		healthCheck.scheduledRound(began)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		started := int64(0)
		for _, holder := range slotHolders {
			started += holder.probes.Load()
		}
		if started == 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of the ten slot holders started", started)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	plantHistory(queued, C.DelayHistory{Time: time.Now(), Delay: 42}, true)
	close(gate)
	<-roundDone

	if got := queued.probes.Load(); got != 0 {
		t.Fatalf("a node a sibling measured while it waited for a slot was probed %d times, want 0", got)
	}
}

func TestScheduledRoundMeasuresANodeWithNoRecord(t *testing.T) {
	const url = "http://127.0.0.1:1/never"
	plain := &countingOnlyProxy{Proxy: adapter.NewProxy(outbound.NewDirect())}
	healthCheck := NewHealthCheck([]C.Proxy{plain}, url, 1, 300, true, nil)
	healthCheck.scheduledRound(time.Now().Add(-time.Hour))
	if got := plain.probes.Load(); got != 1 {
		t.Fatalf("a node with no record was probed %d times, want 1", got)
	}
}

type countingOnlyProxy struct {
	*adapter.Proxy
	probes atomic.Int64
}

func (r *countingOnlyProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	r.probes.Add(1)
	return r.Proxy.URLTest(ctx, url, expectedStatus)
}

package provider

import (
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func withProbeGoroutineLimit(t *testing.T, n int) {
	t.Helper()
	SetProbeGoroutineLimit(n)
	t.Cleanup(func() { SetProbeGoroutineLimit(0) })
}

func blockedProbes(gate chan struct{}, n int) []*recordingProxy {
	probes := make([]*recordingProxy, n)
	for i := range probes {
		probes[i] = &recordingProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), gate: gate}
	}
	return probes
}

func probesStarted(probes []*recordingProxy) int64 {
	var n int64
	for _, p := range probes {
		n += p.probes.Load()
	}
	return n
}

func TestRoundsTogetherHoldNoMoreProbeGoroutinesThanTheLimit(t *testing.T) {
	withProbeGoroutineLimit(t, 3)
	gate := make(chan struct{})
	var all []*recordingProxy
	var checks sync.WaitGroup
	for i := 0; i < 4; i++ {
		probes := blockedProbes(gate, 5)
		all = append(all, probes...)
		nodes := make([]C.Proxy, len(probes))
		for j, p := range probes {
			nodes[j] = p
		}
		healthCheck := NewHealthCheck(nodes, "http://127.0.0.1:1/never", 1, 300, false, nil)
		defer healthCheck.close()
		checks.Add(1)
		go func() { defer checks.Done(); healthCheck.check() }()
	}
	deadline := time.Now().Add(3 * time.Second)
	for probesStarted(all) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if started, held := probesStarted(all), ProbeGoroutinesHeldForTest(); started != 3 || held != 3 {
		t.Fatalf("four rounds of five held %d places and started %d probes; want the limit, 3", held, started)
	}
	close(gate)
	checks.Wait()
	if started := probesStarted(all); started != 20 {
		t.Fatalf("%d of 20 nodes measured once the probes went through", started)
	}
	if held := ProbeGoroutinesHeldForTest(); held != 0 {
		t.Fatalf("%d places still held after every round ended", held)
	}
}

func TestARoundWaitingForAProbePlaceEndsWithItsHealthCheck(t *testing.T) {
	withProbeGoroutineLimit(t, 1)
	gate := make(chan struct{})
	holder := blockedProbes(gate, 1)
	first := NewHealthCheck([]C.Proxy{holder[0]}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	defer first.close()
	firstDone := make(chan struct{})
	go func() { first.check(); close(firstDone) }()
	defer func() { close(gate); <-firstDone }()
	deadline := time.Now().Add(3 * time.Second)
	for holder[0].probes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	waiting := blockedProbes(gate, 2)
	second := NewHealthCheck([]C.Proxy{waiting[0], waiting[1]}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	done := make(chan struct{})
	go func() { second.check(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	second.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a round waiting for a place outlived its health check")
	}
	if started := probesStarted(waiting); started != 0 {
		t.Fatalf("a round that never got a place probed %d node(s)", started)
	}
}

func TestWithoutALimitProbePlacesAreNotCounted(t *testing.T) {
	SetProbeGoroutineLimit(0)
	before := ProbeGoroutinesHeldForTest()
	release, ok := acquireProbeGoroutine(t.Context())
	if !ok {
		t.Fatal("no limit refused a place")
	}
	if held := ProbeGoroutinesHeldForTest(); held != before {
		t.Fatalf("no limit counted a place: %d held, %d before", held, before)
	}
	release()
}

func TestARoundAtItsOwnLimitHoldsNoSparePlace(t *testing.T) {
	withProbeGoroutineLimit(t, 4)
	SetRoundConcurrency(func() int { return 1 })
	t.Cleanup(func() { SetRoundConcurrency(nil) })
	gate := make(chan struct{})
	var all []*recordingProxy
	var checks sync.WaitGroup
	for i := 0; i < 2; i++ {
		probes := blockedProbes(gate, 3)
		all = append(all, probes...)
		healthCheck := NewHealthCheck([]C.Proxy{probes[0], probes[1], probes[2]}, "http://127.0.0.1:1/never", 1, 300, false, nil)
		defer healthCheck.close()
		checks.Add(1)
		go func() { defer checks.Done(); healthCheck.check() }()
	}
	deadline := time.Now().Add(3 * time.Second)
	for probesStarted(all) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if held := ProbeGoroutinesHeldForTest(); held != 2 {
		t.Fatalf("two rounds limited to one probe each hold %d places, want 2", held)
	}
	close(gate)
	checks.Wait()
	if started := probesStarted(all); started != 6 {
		t.Fatalf("%d of 6 nodes measured", started)
	}
}

func TestRemovingTheLimitLetsTheWaitingRoundsGo(t *testing.T) {
	withProbeGoroutineLimit(t, 1)
	gate := make(chan struct{})
	probes := blockedProbes(gate, 3)
	healthCheck := NewHealthCheck([]C.Proxy{probes[0], probes[1], probes[2]}, "http://127.0.0.1:1/never", 1, 300, false, nil)
	defer healthCheck.close()
	done := make(chan struct{})
	go func() { healthCheck.check(); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for probesStarted(probes) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if started := probesStarted(probes); started != 1 {
		t.Fatalf("a limit of one started %d probes", started)
	}
	SetProbeGoroutineLimit(0)
	deadline = time.Now().Add(3 * time.Second)
	for probesStarted(probes) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if started := probesStarted(probes); started != 3 {
		t.Fatalf("with the limit off %d of 3 probes started", started)
	}
	close(gate)
	<-done
}

func TestAClosedHealthChecksRoundRunsToItsEndOnlyWithoutACap(t *testing.T) {
	t.Cleanup(func() { SetRoundConcurrency(nil); SetProbeGoroutineLimit(0) })
	for _, capped := range []bool{false, true} {
		if capped {
			SetProbeGoroutineLimit(30)
		}
		SetRoundConcurrency(func() int { return 1 })
		gate := make(chan struct{})
		probes := blockedProbes(gate, 4)
		healthCheck := NewHealthCheck([]C.Proxy{probes[0], probes[1], probes[2], probes[3]}, "http://127.0.0.1:1/never", 1, 300, false, nil)
		done := make(chan struct{})
		go func() { healthCheck.check(); close(done) }()
		deadline := time.Now().Add(3 * time.Second)
		for probesStarted(probes) < 1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		healthCheck.close()
		close(gate)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("capped=%v: the closed health check's round did not end", capped)
		}
		started := probesStarted(probes)
		if !capped && started != 4 {
			t.Errorf("with no cap a closed health check's round measured %d of 4 nodes, as upstream's measures all", started)
		}
		if capped && started != 1 {
			t.Errorf("under a cap a closed health check's round started %d probes after the first", started-1)
		}
		SetRoundConcurrency(nil)
		SetProbeGoroutineLimit(0)
	}
}

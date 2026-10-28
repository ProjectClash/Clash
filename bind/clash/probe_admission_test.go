package clash

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/provider"
)

func testAdmissionConfig(interactiveCap, backgroundCap int) probeAdmissionConfig {
	return probeAdmissionConfig{
		interactiveCap: interactiveCap,
		backgroundCap:  func() int { return backgroundCap },
	}
}

func backgroundCtx() context.Context { return adapter.WithBackgroundProbe(context.Background()) }

func admitAsync(slots *probeSlots, ctx context.Context, background bool) (admitted chan func(), deferred chan struct{}) {
	admitted, deferred = make(chan func(), 1), make(chan struct{}, 1)
	go func() {
		end, verdict := slots.admit(ctx, background)
		if verdict == probeDeferred {
			deferred <- struct{}{}
			return
		}
		admitted <- end
	}()
	return admitted, deferred
}

func waitAdmitted(t *testing.T, admitted chan func(), what string) func() {
	t.Helper()
	select {
	case end := <-admitted:
		return end
	case <-time.After(3 * time.Second):
		t.Fatalf("%s was never admitted", what)
		return nil
	}
}

func notAdmitted(t *testing.T, admitted chan func(), what string) {
	t.Helper()
	select {
	case <-admitted:
		t.Fatalf("%s was admitted", what)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestProbeAdmissionShouldArmOnlyForNEOnBudgetedPlatform(t *testing.T) {
	cases := []struct{ budgeted, underNE, want bool }{
		{true, true, true},
		{true, false, false},
		{false, true, false},
		{false, false, false},
	}
	for _, c := range cases {
		if got := probeAdmissionShouldArm(c.budgeted, c.underNE); got != c.want {
			t.Fatalf("shouldArm(%t,%t)=%t want %t", c.budgeted, c.underNE, got, c.want)
		}
	}
}

func TestBackgroundConcurrencyIsTenAtAnySize(t *testing.T) {
	for _, c := range []struct{ nodes, want int }{
		{0, 10}, {3, 10}, {200, 10}, {201, 10}, {2000, 10}, {2001, 10}, {10000, 10}, {100000, 10},
	} {
		if got := probeBackgroundCap(c.nodes); got != c.want {
			t.Fatalf("%d nodes: background cap %d, want %d", c.nodes, got, c.want)
		}
	}
}

func TestBackgroundProbesAreCappedAndAdmittedInOrder(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(16, 3))
	var held []func()
	for i := 0; i < 3; i++ {
		end, verdict := slots.admit(backgroundCtx(), true)
		if verdict != probeAdmitted {
			t.Fatalf("background probe %d was %v", i, verdict)
		}
		held = append(held, end)
	}
	type admitted struct {
		index int
		end   func()
	}
	got := make(chan admitted, 12)
	waitQueued := func(n int) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, _, _, waiting := slots.counts(); waiting == n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d probes never queued", n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	for i := 3; i < 12; i++ {
		go func(i int) {
			end, verdict := slots.admit(backgroundCtx(), true)
			if verdict != probeAdmitted {
				t.Errorf("background probe %d was %v", i, verdict)
				return
			}
			got <- admitted{i, end}
		}(i)
		waitQueued(i - 2)
	}
	for want := 3; want < 12; want++ {
		held[0]()
		held = held[1:]
		next := <-got
		if next.index != want {
			t.Fatalf("probe %d admitted where %d was next in the queue", next.index, want)
		}
		if _, background, _, _ := slots.counts(); background > 3 {
			t.Fatalf("%d background probes in flight under a cap of 3", background)
		}
		held = append(held, next.end)
	}
	for _, end := range held {
		end()
	}
}

func TestInteractiveProbesGoFirst(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(16, 2))
	first, _ := slots.admit(backgroundCtx(), true)
	second, _ := slots.admit(backgroundCtx(), true)
	queuedBackground, _ := admitAsync(slots, backgroundCtx(), true)
	notAdmitted(t, queuedBackground, "a third background probe under a cap of 2")

	interactive, verdict := slots.admit(context.Background(), false)
	if verdict != probeAdmitted {
		t.Fatal("an interactive probe waited behind background probes")
	}
	first()
	notAdmitted(t, queuedBackground, "a background probe while the interactive one fills the shared cap")
	second()
	end := waitAdmitted(t, queuedBackground, "the background probe in the slot the interactive one leaves")
	if _, verdict := slots.admit(context.Background(), false); verdict != probeAdmitted {
		t.Fatal("a second interactive probe waited although its own cap has room")
	}
	end()
	interactive()
}

func TestABackgroundProbeYieldsToAWaitingInteractiveOne(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(1, 10))
	holding, _ := slots.admit(context.Background(), false)
	waitingInteractive, _ := admitAsync(slots, context.Background(), false)
	notAdmitted(t, waitingInteractive, "a second interactive probe under a cap of 1")
	background, _ := admitAsync(slots, backgroundCtx(), true)
	notAdmitted(t, background, "a background probe while an interactive one waits")
	holding()
	end := waitAdmitted(t, waitingInteractive, "the waiting interactive probe")
	waitAdmitted(t, background, "the background probe once nothing interactive waits")()
	end()
}

func TestInteractiveProbesQueueInOrderAtTheirCap(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(2, 10))
	a, _ := slots.admit(context.Background(), false)
	b, _ := slots.admit(context.Background(), false)
	var queued []chan func()
	for i := 0; i < 3; i++ {
		admitted, _ := admitAsync(slots, context.Background(), false)
		queued = append(queued, admitted)
		time.Sleep(2 * time.Millisecond)
	}
	notAdmitted(t, queued[0], "a third interactive probe under a cap of 2")
	a()
	waitAdmitted(t, queued[0], "the first queued probe")()
	notAdmitted(t, queued[2], "the third queued probe before the second")
	b()
	waitAdmitted(t, queued[1], "the second queued probe")()
	waitAdmitted(t, queued[2], "the third queued probe")()
}

func TestADeferredProbeLeavesNothingBehind(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(16, 1))
	holding, _ := slots.admit(backgroundCtx(), true)
	ctx, cancel := context.WithCancel(backgroundCtx())
	_, deferred := admitAsync(slots, ctx, true)
	next, _ := admitAsync(slots, backgroundCtx(), true)
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-deferred:
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled probe never left the queue")
	}
	holding()
	end := waitAdmitted(t, next, "the probe behind the cancelled one")
	if interactive, background, _, waiting := slots.counts(); interactive != 0 || background != 1 || waiting != 0 {
		t.Fatalf("counts after a deferral: interactive=%d background=%d waiting=%d", interactive, background, waiting)
	}
	end()
	end()
	if _, background, _, _ := slots.counts(); background != 0 {
		t.Fatalf("an end called twice gave back two slots: %d in flight", background)
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, verdict := slots.admit(cancelled, false); verdict != probeDeferred {
		t.Fatal("a probe already cancelled was admitted")
	}
}

func TestCancellationRacingAGrantLeaksNoSlot(t *testing.T) {
	slots := newProbeSlots(testAdmissionConfig(16, 1))
	for i := 0; i < 200; i++ {
		holding, _ := slots.admit(backgroundCtx(), true)
		ctx, cancel := context.WithCancel(backgroundCtx())
		done := make(chan func(), 1)
		go func() {
			end, verdict := slots.admit(ctx, true)
			if verdict == probeDeferred {
				end = func() {}
			}
			done <- end
		}()
		time.Sleep(50 * time.Microsecond)
		go cancel()
		holding()
		(<-done)()
		if interactive, background, iw, bw := slots.counts(); interactive+background+iw+bw != 0 {
			t.Fatalf("round %d left in_flight=%d/%d waiting=%d/%d", i, interactive, background, iw, bw)
		}
	}
}

func TestTheNodeCountIsCachedForItsTTL(t *testing.T) {
	reads := 0
	counter := &probeNodeCounter{ttl: 30 * time.Millisecond, read: func() int { reads++; return 5000 }}
	for i := 0; i < 10; i++ {
		if counter.nodes() != 5000 {
			t.Fatal("wrong count")
		}
	}
	if reads != 1 {
		t.Fatalf("counted %d times inside the TTL", reads)
	}
	time.Sleep(40 * time.Millisecond)
	counter.nodes()
	if reads != 2 {
		t.Fatalf("not recounted after the TTL: %d reads", reads)
	}
}

func TestTheHookAdmitsEveryBackgroundProbeAtTheCap(t *testing.T) {
	hook := newProbeAdmissionHook(testAdmissionConfig(16, 4))
	var inFlight, peak atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			end, err := hook(backgroundCtx())
			if err != nil {
				errs <- err
				return
			}
			if n := inFlight.Add(1); n > peak.Load() {
				peak.Store(n)
			}
			time.Sleep(time.Millisecond)
			inFlight.Add(-1)
			end()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(fmt.Errorf("a background probe was not admitted: %w", err))
	}
	if peak.Load() > 4 {
		t.Fatalf("%d in flight under a cap of 4", peak.Load())
	}
}

func TestArmingTheGateSetsTheRoundConcurrency(t *testing.T) {
	t.Cleanup(disarmProbeAdmission)
	armProbeAdmission()
	if got := provider.RoundConcurrencyForTest(); got != probeBackgroundCap(liveNodeCount()) {
		t.Fatalf("an armed gate leaves rounds at %d, want the tier %d", got, probeBackgroundCap(liveNodeCount()))
	}
	disarmProbeAdmission()
	if got := provider.RoundConcurrencyForTest(); got != 10 {
		t.Fatalf("a disarmed gate leaves rounds at %d, want upstream's 10", got)
	}
}

func TestArmingTheGateCapsTheProbeGoroutines(t *testing.T) {
	t.Cleanup(disarmProbeAdmission)
	armProbeAdmission()
	if got, want := provider.ProbeGoroutineLimitForTest(), probeGoroutinesPerBackgroundPlace*probeBackgroundTier; got != want {
		t.Fatalf("an armed gate caps probe goroutines at %d, want %d", got, want)
	}
	disarmProbeAdmission()
	if got := provider.ProbeGoroutineLimitForTest(); got != 0 {
		t.Fatalf("a disarmed gate leaves a cap of %d", got)
	}
}

func TestTheProbeGoroutineCapFollowsTheTierAtEverySize(t *testing.T) {
	for _, nodes := range []int{0, 1, 100, 1000, 2000, 10000, 100000} {
		if got := probeBackgroundCap(nodes); got != probeBackgroundTier {
			t.Fatalf("the tier at %d nodes is %d, not the %d the probe goroutine cap is set from", nodes, got, probeBackgroundTier)
		}
	}
}

func TestAProbeRoundIsSettledOnceItHasEnded(t *testing.T) {
	previous := probeSettleQuiet
	probeSettleQuiet = 80 * time.Millisecond
	t.Cleanup(func() { probeSettleQuiet = previous })
	hook := newProbeAdmissionHook(defaultProbeAdmissionConfig())
	before := probeSettles.Load()
	var ends []func()
	for i := 0; i < probeSettleFloor+1; i++ {
		end, err := hook(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ends = append(ends, end)
	}
	for _, end := range ends[:len(ends)-1] {
		end()
	}
	time.Sleep(200 * time.Millisecond)
	if got := probeSettles.Load() - before; got != 0 {
		t.Fatalf("settled %d times while a probe still ran", got)
	}
	ends[len(ends)-1]()
	ends[len(ends)-1]()
	time.Sleep(300 * time.Millisecond)
	if got := probeSettles.Load() - before; got != 1 {
		t.Fatalf("settled %d times after the round, want 1", got)
	}
	time.Sleep(200 * time.Millisecond)
	if got := probeSettles.Load() - before; got != 1 {
		t.Fatalf("settled %d times with no new round, want 1", got)
	}
	end, _ := hook(context.Background())
	end()
	time.Sleep(300 * time.Millisecond)
	if got := probeSettles.Load() - before; got != 1 {
		t.Fatalf("a single probe was settled after: %d", got)
	}
}

func TestTheProbeGatesCountsAreInTheDiagnostics(t *testing.T) {
	previous := probeAdmissionCounts.Load()
	t.Cleanup(func() { probeAdmissionCounts.Store(previous) })
	counts := func() (int, int, int, int) { return 3, 7, 1, 2 }
	probeAdmissionCounts.Store(&counts)
	service := &BoxService{}
	var diagnostics struct {
		ProbeAdmission map[string]int `json:"probeAdmission"`
	}
	if err := json.Unmarshal([]byte(service.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if got := diagnostics.ProbeAdmission; got["interactiveInFlight"] != 3 || got["backgroundInFlight"] != 7 || got["interactiveWaiting"] != 1 || got["backgroundWaiting"] != 2 {
		t.Fatalf("diagnostics say %v", got)
	}
}

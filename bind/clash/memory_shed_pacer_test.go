package clash

import (
	"context"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func instantPacer() (*sessionPacer, *[]time.Duration) {
	pacer := newSessionPacer()
	clock := time.Unix(1000, 0)
	pacer.now = func() time.Time { return clock }
	var mu sync.Mutex
	var waits []time.Duration
	pacer.timer = func(d time.Duration) (<-chan time.Time, func() bool) {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		fired := make(chan time.Time, 1)
		fired <- clock
		return fired, func() bool { return true }
	}
	return pacer, &waits
}

func TestThePacerIsFreeWhenInactive(t *testing.T) {
	pacer, waits := instantPacer()
	for i := 0; i < 100; i++ {
		pacer.wait(context.Background(), C.TCP)
	}
	if len(*waits) != 0 || pacer.paced.Load() != 0 {
		t.Fatalf("an inactive pacer held %d sessions", len(*waits))
	}
}

func TestThePacerSpacesNewSessions(t *testing.T) {
	pacer, waits := instantPacer()
	pacer.setActive(true)
	for i := 0; i < shedPaceBurst+3; i++ {
		pacer.wait(context.Background(), C.TCP)
	}
	interval := time.Second / shedPaceRate
	want := []time.Duration{interval, 2 * interval, 3 * interval}
	if len(*waits) != len(want) {
		t.Fatalf("waits %v, want the first %d free and then %v", *waits, shedPaceBurst, want)
	}
	for i := range want {
		if (*waits)[i] != want[i] {
			t.Fatalf("waits %v, want %v", *waits, want)
		}
	}
	for i := 0; i < 100; i++ {
		pacer.wait(context.Background(), C.UDP)
	}
	last := (*waits)[len(*waits)-1]
	if last != shedPaceMaxWait {
		t.Fatalf("a deep queue waited %v, want the %v cap", last, shedPaceMaxWait)
	}
	if pacer.reachedMax.Load() == 0 {
		t.Fatal("waits at the cap are not counted")
	}
}

func TestLeavingLayerTwoReleasesTheQueue(t *testing.T) {
	pacer := newSessionPacer()
	pacer.setActive(true)
	for i := 0; i < shedPaceBurst; i++ {
		pacer.wait(context.Background(), C.TCP)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); pacer.wait(context.Background(), C.TCP) }()
	}
	go func() { wg.Wait(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("five sessions past the burst did not wait")
	default:
	}
	pacer.setActive(false)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("leaving layer 2 did not release the queue")
	}

	pacer.setActive(true)
	for i := 0; i < shedPaceBurst; i++ {
		pacer.wait(context.Background(), C.TCP)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	started := time.Now()
	pacer.wait(ctx, C.TCP)
	pacer.wait(ctx, C.TCP)
	if took := time.Since(started); took > time.Second {
		t.Fatalf("a cancelled session waited %v", took)
	}
}

func TestTheRoundHoldReleasesOrExpires(t *testing.T) {
	hold := newRoundHold()
	if err := hold.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hold.holds.Load() != 0 {
		t.Fatal("an idle hold held a round")
	}
	hold.set(true)
	released := make(chan error, 1)
	go func() { released <- hold.wait(context.Background()) }()
	time.Sleep(30 * time.Millisecond)
	select {
	case <-released:
		t.Fatal("a held round went before the layer ended")
	default:
	}
	hold.set(false)
	if err := <-released; err != nil {
		t.Fatal(err)
	}

	hold.set(true)
	hold.maxHold = 30 * time.Millisecond
	if err := hold.wait(context.Background()); err != nil || hold.expired.Load() != 1 {
		t.Fatalf("a round held past maxHold: err=%v expired=%d", err, hold.expired.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hold.maxHold = time.Hour
	if err := hold.wait(ctx); err == nil {
		t.Fatal("a closed health check's round was let go as if released")
	}
}

func TestACappedWaitLeavesNoDebt(t *testing.T) {
	pacer, waits := instantPacer()
	clock := time.Unix(1000, 0)
	pacer.now = func() time.Time { return clock }
	pacer.setActive(true)
	for i := 0; i < 200; i++ {
		pacer.wait(context.Background(), C.TCP)
	}
	clock = clock.Add(shedPaceMaxWait + time.Second)
	*waits = nil
	pacer.wait(context.Background(), C.TCP)
	if len(*waits) > 0 && (*waits)[0] >= time.Second {
		t.Fatalf("a session %v after the burst waited %v; the burst's capped sessions left a debt", shedPaceMaxWait+time.Second, (*waits)[0])
	}
}

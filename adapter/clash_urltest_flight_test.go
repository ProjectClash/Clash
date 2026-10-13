package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

type countingDirect struct {
	*outbound.Direct
	dials atomic.Int64
	hold  chan struct{}
}

func (d *countingDirect) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	d.dials.Add(1)
	select {
	case <-d.hold:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return d.Direct.DialContext(ctx, metadata)
}

func TestConcurrentProbesOfOneNodeShareOneDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	proxy := NewProxy(direct)

	const groups = 5
	var wg sync.WaitGroup
	delays := make([]uint16, groups)
	errs := make([]error, groups)
	for i := 0; i < groups; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(WithBackgroundProbe(context.Background()), 5*time.Second)
			defer cancel()
			delays[i], errs[i] = proxy.URLTest(ctx, server.URL, nil)
		}(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(direct.hold)
	wg.Wait()

	if got := direct.dials.Load(); got != 1 {
		t.Fatalf("five same-instant probes of one node dialed %d times, want 1", got)
	}
	for i := range delays {
		if errs[i] != nil || delays[i] == 0 {
			t.Fatalf("probe %d = (%d, %v): every waiter must receive the shared measurement", i, delays[i], errs[i])
		}
	}
	if h := proxy.DelayHistory(); len(h) != 1 {
		t.Fatalf("one measurement must write one history record, got %d", len(h))
	}
}

func TestForegroundProbeDoesNotShareABackgroundFlight(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	proxy := NewProxy(direct)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(WithBackgroundProbe(context.Background()), 5*time.Second)
		defer cancel()
		_, _ = proxy.URLTest(ctx, server.URL, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = proxy.URLTest(ctx, server.URL, nil)
	}()
	for direct.dials.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(direct.hold)
	wg.Wait()

	if got := direct.dials.Load(); got != 2 {
		t.Fatalf("a foreground probe joined a background flight: %d dials, want 2", got)
	}
}

func TestAWaiterDoesNotInheritItsLeadersCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	proxy := NewProxy(direct)

	leaderCtx, abandonLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = proxy.URLTest(leaderCtx, server.URL, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	var waiterDelay uint16
	var waiterErr error
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		waiterDelay, waiterErr = proxy.URLTest(ctx, server.URL, nil)
	}()
	time.Sleep(50 * time.Millisecond)

	abandonLeader()
	<-leaderDone
	close(direct.hold)
	<-waiterDone

	if waiterErr != nil || waiterDelay == 0 {
		t.Fatalf("the waiter got (%d, %v) after its leader was cancelled; its own context was good, so it must measure the node itself", waiterDelay, waiterErr)
	}
}

type slowFirstDirect struct {
	*outbound.Direct
	dials  atomic.Int64
	unwind time.Duration
}

func (d *slowFirstDirect) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if d.dials.Add(1) == 1 {
		<-ctx.Done()
		time.Sleep(d.unwind)
		return nil, ctx.Err()
	}
	return d.Direct.DialContext(ctx, metadata)
}

func noContentServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestATimedOutProbeHasWrittenItsRecordByTheTimeURLTestReturns(t *testing.T) {
	url := noContentServer(t)
	proxy := NewProxy(&slowFirstDirect{Direct: outbound.NewDirect(), unwind: 100 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := proxy.URLTest(ctx, url, nil); err == nil {
		t.Fatal("the fixture was meant to time out")
	}

	if got := len(proxy.DelayHistory()); got != 1 {
		t.Fatalf("URLTest returned with %d history records; the timeout it just reported is not written yet", got)
	}
	if proxy.AliveForTestUrl(url) {
		t.Fatal("URLTest returned a timeout while the node still reads alive")
	}
}

func TestAMorePatientWaiterDoesNotInheritItsLeadersTimeout(t *testing.T) {
	url := noContentServer(t)
	direct := &slowFirstDirect{Direct: outbound.NewDirect()}
	proxy := NewProxy(direct)

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, _ = proxy.URLTest(ctx, url, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, url, nil)
	<-leaderDone

	if err != nil || delay == 0 {
		t.Fatalf("a waiter with 5s of patience got (%d, %v) from a leader that gave up after 150ms", delay, err)
	}
	if got := direct.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want 2: the leader's, and the patient waiter's own", got)
	}
}

func TestWaitersOfTheSamePatienceShareATimeout(t *testing.T) {
	url := noContentServer(t)
	direct := &slowFirstDirect{Direct: outbound.NewDirect()}
	proxy := NewProxy(direct)

	const patience = 300 * time.Millisecond
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		ctx, cancel := context.WithTimeout(context.Background(), patience)
		defer cancel()
		_, _ = proxy.URLTest(ctx, url, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), patience)
	defer cancel()
	_, err := proxy.URLTest(ctx, url, nil)
	<-leaderDone

	if err == nil {
		t.Fatal("the node hung; the waiter must share the leader's timeout")
	}
	if got := direct.dials.Load(); got != 1 {
		t.Fatalf("%d dials, want 1: a waiter no more patient than its leader does not dial a node that just timed out", got)
	}
}

type selectingDirect struct{ *countingDirect }

func (selectingDirect) Type() C.AdapterType { return C.Selector }

func TestAGroupIsMeasuredThroughWhateverItSelectsNow(t *testing.T) {
	url := noContentServer(t)
	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	proxy := NewProxy(selectingDirect{direct})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = proxy.URLTest(ctx, url, nil)
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(direct.hold)
	wg.Wait()

	if got := direct.dials.Load(); got != 2 {
		t.Fatalf("two tests of one group dialed %d times, want 2", got)
	}
}

func TestATimeoutCarriedToTheProbeKeepsTheFlightsPatienceRules(t *testing.T) {
	for _, c := range []struct {
		name      string
		waiter    time.Duration
		wantDials int64
		wantOK    bool
	}{
		{"as patient", 150 * time.Millisecond, 1, false},
		{"more patient", 5 * time.Second, 2, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			url := noContentServer(t)
			direct := &slowFirstDirect{Direct: outbound.NewDirect()}
			proxy := NewProxy(direct)
			background := WithBackgroundProbe(context.Background())

			leaderDone := make(chan struct{})
			go func() {
				defer close(leaderDone)
				_, _ = proxy.URLTest(WithURLTestTimeout(background, 150*time.Millisecond), url, nil)
			}()
			deadline := time.Now().Add(2 * time.Second)
			for direct.dials.Load() < 1 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}

			delay, err := proxy.URLTest(WithURLTestTimeout(background, c.waiter), url, nil)
			<-leaderDone

			if ok := err == nil && delay > 0; ok != c.wantOK {
				t.Fatalf("waiter with %v measured (%d, %v), want ok=%t", c.waiter, delay, err, c.wantOK)
			}
			if got := direct.dials.Load(); got != c.wantDials {
				t.Fatalf("%d dials, want %d", got, c.wantDials)
			}
		})
	}
}

func TestACoalescedWaiterKeepsItsOwnCarriedTimeout(t *testing.T) {
	asked := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case asked <- struct{}{}:
		default:
		}
		time.Sleep(400 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	SetURLTestAdmission(nil)

	proxy := NewProxy(outbound.NewDirect())
	background := WithBackgroundProbe(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = proxy.URLTest(WithURLTestTimeout(background, 5*time.Second), server.URL, nil)
	}()
	<-asked

	start := time.Now()
	delay, err := proxy.URLTest(WithURLTestTimeout(background, 50*time.Millisecond), server.URL, nil)
	elapsed := time.Since(start)
	<-leaderDone
	if err == nil {
		t.Fatalf("a waiter with a 50ms timeout reported a %dms answer after %v", delay, elapsed)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("a waiter with a 50ms timeout was held %v", elapsed)
	}
}

func TestACoalescedWaitersTimeoutStartsWhenItsLeaderIsAdmitted(t *testing.T) {
	url := noContentServer(t)
	SetURLTestAdmission(func(context.Context) error {
		time.Sleep(300 * time.Millisecond)
		return nil
	})
	defer SetURLTestAdmission(nil)

	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	close(direct.hold)
	proxy := NewProxy(direct)
	background := WithBackgroundProbe(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = proxy.URLTest(WithURLTestTimeout(background, 5*time.Second), url, nil)
	}()
	time.Sleep(50 * time.Millisecond)

	delay, err := proxy.URLTest(WithURLTestTimeout(background, 100*time.Millisecond), url, nil)
	<-leaderDone
	if err != nil || delay == 0 {
		t.Fatalf("a waiter with a 100ms timeout behind a 300ms queue measured (%d, %v): the queue was charged to it", delay, err)
	}
	if got := direct.dials.Load(); got != 1 {
		t.Fatalf("%d dials, want 1 shared", got)
	}
}

func TestAWaitersCarriedTimeoutIsOneBudgetAcrossRetries(t *testing.T) {
	url := noContentServer(t)
	SetURLTestAdmission(nil)
	direct := &countingDirect{Direct: outbound.NewDirect(), hold: make(chan struct{})}
	proxy := NewProxy(direct)
	background := WithBackgroundProbe(context.Background())

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = proxy.URLTest(WithURLTestTimeout(background, 300*time.Millisecond), url, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for direct.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	_, err := proxy.URLTest(WithURLTestTimeout(background, 600*time.Millisecond), url, nil)
	elapsed := time.Since(start)
	<-leaderDone
	if err == nil {
		t.Fatal("a node that never answers passed")
	}
	if elapsed > 800*time.Millisecond {
		t.Fatalf("a 600ms waiter took %v: its retry started a fresh timeout", elapsed)
	}
	if got := direct.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want 2: the leader's and the more patient waiter's own", got)
	}
}

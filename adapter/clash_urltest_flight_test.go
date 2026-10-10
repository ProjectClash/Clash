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

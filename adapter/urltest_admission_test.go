package adapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

func admissionTestProxy(t *testing.T) *Proxy {
	t.Helper()
	h, err := outbound.NewHttp(outbound.HttpOption{
		Name:   "admission-probe",
		Server: "127.0.0.1",
		Port:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewProxy(h)
}

func TestURLTestAdmissionHookRunsWhenSet(t *testing.T) {
	var calls atomic.Int64
	SetURLTestAdmission(func(ctx context.Context) error { calls.Add(1); return nil })
	defer SetURLTestAdmission(nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = admissionTestProxy(t).URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if got := calls.Load(); got != 1 {
		t.Fatalf("armed hook must run once per URL test, got %d", got)
	}
}

func TestURLTestAdmissionNilHookKeepsUpstreamPath(t *testing.T) {
	SetURLTestAdmission(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := admissionTestProxy(t).URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if err == nil {
		t.Fatal("dial against a closed port should fail")
	}
}

func TestURLTestDeferredSkipsBookkeeping(t *testing.T) {
	SetURLTestAdmission(func(ctx context.Context) error { return ErrURLTestDeferred })
	defer SetURLTestAdmission(nil)

	p := admissionTestProxy(t)
	before := p.AliveForTestUrl("https://www.gstatic.com/generate_204")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := p.URLTest(ctx, "https://www.gstatic.com/generate_204", nil)
	if !errors.Is(err, ErrURLTestDeferred) {
		t.Fatalf("deferred probe must surface ErrURLTestDeferred, got %v", err)
	}
	if got := p.AliveForTestUrl("https://www.gstatic.com/generate_204"); got != before {
		t.Fatalf("a deferred probe must not touch alive state: %t -> %t", before, got)
	}
	if h := p.DelayHistory(); len(h) != 0 {
		t.Fatalf("a deferred probe must not write history, got %d records", len(h))
	}
}

func TestBackgroundProbeMarkRoundtrip(t *testing.T) {
	if IsBackgroundProbe(context.Background()) {
		t.Fatal("plain context must not read as background")
	}
	if !IsBackgroundProbe(WithBackgroundProbe(context.Background())) {
		t.Fatal("marked context must read as background")
	}
}

func TestAProbesTimeoutStartsWhenTheGateLetsItThrough(t *testing.T) {
	url := noContentServer(t)
	var queuedOnTheClock atomic.Bool
	SetURLTestAdmission(func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); ok {
			queuedOnTheClock.Store(true)
		}
		time.Sleep(300 * time.Millisecond)
		return nil
	})
	defer SetURLTestAdmission(nil)

	p := NewProxy(outbound.NewDirect())
	ctx := WithURLTestTimeout(WithBackgroundProbe(context.Background()), 100*time.Millisecond)
	delay, err := p.URLTest(ctx, url, nil)
	if err != nil || delay == 0 {
		t.Fatalf("a node that answers at once, queued for 300ms with a 100ms timeout, measured (%d, %v): the queue was charged to the node", delay, err)
	}
	if !p.AliveForTestUrl(url) {
		t.Fatal("the node was recorded dead after a queue it had no part in")
	}
	if queuedOnTheClock.Load() {
		t.Fatal("the probe waited at the gate with its timeout already running")
	}
}

func TestAProbesOwnTimeoutStillBoundsIt(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	SetURLTestAdmission(nil)

	p := NewProxy(outbound.NewDirect())
	start := time.Now()
	_, err := p.URLTest(WithURLTestTimeout(context.Background(), 100*time.Millisecond), server.URL, nil)
	if err == nil {
		t.Fatal("a node that never answers passed")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a 100ms timeout returned after %v", elapsed)
	}
	if len(p.DelayHistory()) != 1 || p.AliveForTestUrl(server.URL) {
		t.Fatalf("a real timeout is a measurement and is recorded: history=%d alive=%t", len(p.DelayHistory()), p.AliveForTestUrl(server.URL))
	}
}

func TestTheGateHearsEachProbeItAdmittedEndOnce(t *testing.T) {
	url := noContentServer(t)
	var admitted, ended atomic.Int64
	defer SetURLTestAdmission(nil)
	SetURLTestGate(func(ctx context.Context) (func(), error) {
		admitted.Add(1)
		return func() { ended.Add(1) }, nil
	})
	p := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.URLTest(ctx, url, nil); err != nil {
		t.Fatal(err)
	}
	if admitted.Load() != 1 || ended.Load() != 1 {
		t.Fatalf("admitted %d ended %d, want 1 and 1", admitted.Load(), ended.Load())
	}

	SetURLTestGate(func(ctx context.Context) (func(), error) {
		return func() { ended.Add(1) }, ErrURLTestDeferred
	})
	_, _ = p.URLTest(ctx, url, nil)
	if ended.Load() != 1 {
		t.Fatalf("a deferred probe's end was reported (ended %d)", ended.Load())
	}
}

func TestAFinishedProbeIsReportedWithItsNode(t *testing.T) {
	url := noContentServer(t)
	var got atomic.Pointer[Proxy]
	SetURLTestFinished(func(_ context.Context, proxy *Proxy) { got.Store(proxy) })
	defer SetURLTestFinished(nil)
	p := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = p.URLTest(ctx, url, nil)
	if got.Load() != p {
		t.Fatal("the finished probe was not reported with its node")
	}
}

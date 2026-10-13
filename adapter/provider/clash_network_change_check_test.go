package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)

func TestANetworkChangeChecksOnlyProvidersInUse(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		url      string
		interval uint
		lazy     bool
		touched  bool
		want     bool
	}{
		{name: "lazy and untouched", url: "http://127.0.0.1:1/never", interval: 3600, lazy: true},
		{name: "lazy and in use", url: "http://127.0.0.1:1/never", interval: 3600, lazy: true, touched: true, want: true},
		{name: "not lazy", url: "http://127.0.0.1:1/never", interval: 3600, want: true},
		{name: "no health check", touched: true, lazy: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			probe := &countingProxy{}
			healthCheck := NewHealthCheck([]C.Proxy{probe}, testCase.url, 1, testCase.interval, testCase.lazy, nil)
			if testCase.touched {
				healthCheck.touch()
			}
			provider, err := NewCompatibleProvider("p", []C.Proxy{probe}, healthCheck)
			if err != nil {
				t.Fatal(err)
			}
			provider.HealthCheckAfterNetworkChange()
			if testCase.want {
				if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
					t.Fatal("a provider in use was not measured after the network changed")
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
			if got := probe.urlTests.Load(); got != 0 {
				t.Fatalf("a provider not in use was measured %d times after the network changed", got)
			}
		})
	}
}

type gatedProxy struct {
	C.Proxy
	started chan struct{}
	release chan struct{}
}

func (p *gatedProxy) Name() string { return "slow" }
func (p *gatedProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-p.release
	return 0, errors.New("probe never dials")
}
func (p *gatedProxy) AliveForTestUrl(string) bool       { return false }
func (p *gatedProxy) LastDelayForTestUrl(string) uint16 { return 0 }

func TestANetworkChangeDoesNotJoinARoundBegunBeforeIt(t *testing.T) {
	fast := &countingProxy{}
	slow := &gatedProxy{started: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { close(slow.release) })
	healthCheck := NewHealthCheck([]C.Proxy{fast, slow}, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	provider, err := NewCompatibleProvider("p", []C.Proxy{fast, slow}, healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	go healthCheck.checkScheduled()
	<-slow.started
	if !waitFor(func() bool { return fast.urlTests.Load() >= 1 }) {
		t.Fatal("the ticker's round did not measure the fast node")
	}
	provider.HealthCheckAfterNetworkChange()
	if !waitFor(func() bool { return fast.urlTests.Load() >= 2 }) {
		t.Fatal("the change's round joined the ticker's round still running from before the change; the fast node was not measured again")
	}
}

type freshAliveProxy struct {
	countingProxy
	expected string
}

func (p *freshAliveProxy) LastURLTestRecord(string) (C.DelayHistory, bool, string, bool) {
	return C.DelayHistory{Time: time.Now().Add(time.Hour), Delay: 10}, true, p.expected, true
}

func TestANetworkChangeMeasuresANodeEvenIfARecordSaysItIsFresh(t *testing.T) {
	probe := &freshAliveProxy{}
	healthCheck := NewHealthCheck([]C.Proxy{probe}, "http://127.0.0.1:1/never", 5000, 3600, false, nil)
	probe.expected = healthCheck.expectedStatus.String()
	if !measuredAliveSince(probe, healthCheck.url, probe.expected, healthCheck.timeout, time.Now()) {
		t.Fatal("precondition: the ticker's shortcut must take this record as fresh")
	}
	provider, err := NewCompatibleProvider("p", []C.Proxy{probe}, healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	provider.HealthCheckAfterNetworkChange()
	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("the change's round took a fresh-looking record as its answer and measured nothing")
	}
}

type inProgressProxy struct {
	*adapter.Proxy
	now, total *atomic.Int64
}

func (p *inProgressProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.now.Add(1)
	p.total.Add(1)
	defer p.now.Add(-1)
	return p.Proxy.URLTest(ctx, url, expectedStatus)
}

func TestNetworkChangesWhileTheGateIsShutKeepOneRound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	open := make(chan struct{})
	adapter.SetURLTestAdmission(func(ctx context.Context) error {
		select {
		case <-open:
			return nil
		case <-ctx.Done():
			return adapter.ErrURLTestDeferred
		}
	})
	defer adapter.SetURLTestAdmission(nil)

	var now, total atomic.Int64
	var nodes []C.Proxy
	for i := 0; i < 20; i++ {
		nodes = append(nodes, &inProgressProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), now: &now, total: &total})
	}
	healthCheck := NewHealthCheck(nodes, server.URL, 1000, 3600, false, nil)
	provider, err := NewCompatibleProvider("p", nodes, healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	for i := 0; i < 20; i++ {
		provider.HealthCheckAfterNetworkChange()
	}
	time.Sleep(300 * time.Millisecond)
	if got := now.Load(); got > 10 {
		t.Fatalf("%d probes held after 20 changes with the gate shut, want one round's 10", got)
	}

	close(open)
	if !waitFor(func() bool { return total.Load() >= 40 && now.Load() == 0 }) {
		t.Fatalf("after the gate opened: %d probes run, %d still held", total.Load(), now.Load())
	}
	time.Sleep(200 * time.Millisecond)
	if got := total.Load(); got != 40 {
		t.Fatalf("%d probes for 20 nodes, want 40: the round held at the gate and one more for the changes during it", got)
	}
}

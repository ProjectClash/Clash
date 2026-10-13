package clash

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
)

func stormProviders(t *testing.T, nodes []C.Proxy, url string) []*provider.CompatibleProvider {
	var providers []*provider.CompatibleProvider
	for i := 0; i < 5; i++ {
		healthCheck := provider.NewHealthCheck(nodes, url, 1000, 300, false, nil)
		p, err := provider.NewCompatibleProvider(fmt.Sprintf("storm-%d", i), nodes, healthCheck)
		if err != nil {
			t.Fatal(err)
		}
		providers = append(providers, p)
	}
	return providers
}

func TestFiveProvidersHealthChecksMeasureEveryNodeThroughTheGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	const capInFlight = 10
	gate := newProbeAdmissionHook(testAdmissionConfig(probeInteractiveCap, capInFlight))
	var deferred, inFlight, peak atomic.Int64
	adapter.SetURLTestGate(func(ctx context.Context) (func(), error) {
		end, err := gate(ctx)
		if err != nil {
			deferred.Add(1)
			return nil, err
		}
		if n := inFlight.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		return func() { inFlight.Add(-1); end() }, nil
	})
	defer adapter.SetURLTestAdmission(nil)

	nodes := make([]C.Proxy, 264)
	for i := range nodes {
		nodes[i] = adapter.NewProxy(outbound.NewDirect())
	}
	providers := stormProviders(t, nodes, server.URL)
	for _, p := range providers {
		defer p.Close()
		if err := p.Initial(); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		unmeasured := 0
		for _, node := range nodes {
			if _, _, _, ok := node.(*adapter.Proxy).LastURLTestRecord(server.URL); !ok {
				unmeasured++
			}
		}
		if unmeasured == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d nodes still unmeasured after 30s (%d deferred)", unmeasured, len(nodes), deferred.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i, node := range nodes {
		record, alive, _, _ := node.(*adapter.Proxy).LastURLTestRecord(server.URL)
		if !alive || record.Delay == 0 {
			t.Fatalf("node %d answers at once and was recorded %v alive=%t", i, record, alive)
		}
	}
	if n := deferred.Load(); n != 0 {
		t.Fatalf("%d health-check probes deferred", n)
	}
	if n := peak.Load(); n > capInFlight {
		t.Fatalf("%d probes in flight under a cap of %d", n, capInFlight)
	}
}

func TestClosingProvidersMidQueueLeavesNoRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	gate := newProbeAdmissionHook(testAdmissionConfig(probeInteractiveCap, 0))
	var entered, returned atomic.Int64
	adapter.SetURLTestGate(func(ctx context.Context) (func(), error) {
		entered.Add(1)
		defer returned.Add(1)
		return gate(ctx)
	})
	defer adapter.SetURLTestAdmission(nil)

	nodes := make([]C.Proxy, 50)
	for i := range nodes {
		nodes[i] = adapter.NewProxy(outbound.NewDirect())
	}
	providers := stormProviders(t, nodes, server.URL)
	for _, p := range providers {
		if err := p.Initial(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for entered.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	for _, p := range providers {
		_ = p.Close()
	}
	var in, out int64
	for time.Now().Before(deadline) {
		in, out = entered.Load(), returned.Load()
		time.Sleep(50 * time.Millisecond)
		if in == out && in == entered.Load() && out == returned.Load() {
			break
		}
	}
	if in != out || in == 0 {
		t.Fatalf("%d probes entered the gate, %d left after the providers closed", in, out)
	}
	for i, node := range nodes {
		if _, _, _, ok := node.(*adapter.Proxy).LastURLTestRecord(server.URL); ok {
			t.Fatalf("node %d has a record from a round that was called off", i)
		}
	}
}

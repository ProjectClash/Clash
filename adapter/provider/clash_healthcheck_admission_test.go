package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

func TestAHealthCheckQueuedAtTheGateIsMeasuredNotTimedOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var queued atomic.Int64
	adapter.SetURLTestAdmission(func(ctx context.Context) error {
		if !adapter.IsBackgroundProbe(ctx) {
			t.Error("a health check's probe arrived at the gate unmarked")
			return nil
		}
		queued.Add(1)
		select {
		case <-time.After(300 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return adapter.ErrURLTestDeferred
		}
	})
	defer adapter.SetURLTestAdmission(nil)

	var nodes []C.Proxy
	for i := 0; i < 3; i++ {
		nodes = append(nodes, adapter.NewProxy(outbound.NewDirect()))
	}
	healthCheck := NewHealthCheck(nodes, server.URL, 100, 300, false, nil)
	defer healthCheck.close()
	healthCheck.check()

	if got := queued.Load(); got != int64(len(nodes)) {
		t.Fatalf("%d of %d probes went through the gate", got, len(nodes))
	}
	for i, node := range nodes {
		record, alive, _, ok := node.(*adapter.Proxy).LastURLTestRecord(server.URL)
		if !ok || !alive || record.Delay == 0 {
			t.Fatalf("node %d after a 300ms queue and a 100ms timeout: record=%v alive=%t ok=%t -- the queue was charged to the node", i, record, alive, ok)
		}
	}
}

func TestADeferredHealthCheckIsLoggedAsNotMeasured(t *testing.T) {
	previousLevel := log.Level()
	log.SetLevel(log.DEBUG)
	defer log.SetLevel(previousLevel)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	adapter.SetURLTestAdmission(func(context.Context) error { return adapter.ErrURLTestDeferred })
	defer adapter.SetURLTestAdmission(nil)

	node := adapter.NewProxy(outbound.NewDirect())
	healthCheck := NewHealthCheck([]C.Proxy{node}, "http://127.0.0.1:1/never", 1000, 300, false, nil)
	defer healthCheck.close()
	healthCheck.check()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-sub:
			line := event.Payload
			if strings.Contains(line, "Health Checked") {
				t.Fatalf("a deferred probe was logged as a result: %s", line)
			}
			if strings.Contains(line, "Health Check deferred") {
				return
			}
		case <-deadline:
			t.Fatal("no not-measured line for a deferred probe")
		}
	}
}

package clash

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

type keepingDirect struct {
	*outbound.Direct
	resets *atomic.Int64
}

func (k keepingDirect) ResetNetwork() { k.resets.Add(1) }

func (k keepingDirect) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(c, k), nil
}

func keepingNode(name string) (*adapter.Proxy, *atomic.Int64) {
	resets := &atomic.Int64{}
	direct := outbound.NewDirectWithOption(outbound.DirectOption{BasicOption: outbound.BasicOption{}, Name: name})
	return adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(keepingDirect{Direct: direct, resets: resets})), resets
}

func noContent(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func armedSessionRelease(t *testing.T) {
	t.Helper()
	armSessionRelease()
	t.Cleanup(func() { adapter.SetURLTestFinished(nil) })
}

func TestAProbedNodeKeepsNoSessionAfterTheProbe(t *testing.T) {
	armedSessionRelease(t)
	url := noContent(t)
	node, resets := keepingNode("probed")
	ctx := adapter.WithURLTestTimeout(adapter.WithBackgroundProbe(context.Background()), 2*time.Second)
	if _, err := node.URLTest(ctx, url, nil); err != nil {
		t.Fatal(err)
	}
	if got := resets.Load(); got != 1 {
		t.Fatalf("the probed node's session was dropped %d times, want once", got)
	}
}

func TestAProbeLeavesTheSessionOfANodeAConnectionIsOpenOn(t *testing.T) {
	armedSessionRelease(t)
	url := noContent(t)
	node, resets := keepingNode("in-use")
	conn, err := node.DialContext(context.Background(), serverTarget(t, url))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := adapter.WithURLTestTimeout(adapter.WithBackgroundProbe(context.Background()), 2*time.Second)
	_, _ = node.URLTest(ctx, url, nil)
	if got := resets.Load(); got != 0 {
		t.Fatalf("a probe dropped the session of a node in use (%d)", got)
	}
}

func serverTarget(t *testing.T, url string) *C.Metadata {
	t.Helper()
	host, portText, _ := net.SplitHostPort(url[len("http://"):])
	port, _ := strconv.Atoi(portText)
	return &C.Metadata{DstIP: netip.MustParseAddr(host), DstPort: uint16(port)}
}

func TestProbingAGroupReleasesTheNodeItDialed(t *testing.T) {
	armedSessionRelease(t)
	url := noContent(t)
	node, resets := keepingNode("leaf")
	members, err := provider.NewCompatibleProvider("members", []C.Proxy{node}, provider.NewHealthCheck([]C.Proxy{node}, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	selector, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: "pick"}, outboundgroup.SelectorOption{}, node, []P.ProxyProvider{members})
	if err != nil {
		t.Fatal(err)
	}
	group := adapter.NewProxy(selector)
	ctx := adapter.WithURLTestTimeout(adapter.WithBackgroundProbe(context.Background()), 2*time.Second)
	if _, err := group.URLTest(ctx, url, nil); err != nil {
		t.Fatal(err)
	}
	if got := resets.Load(); got != 1 {
		t.Fatalf("probing the group dropped the node's session %d times, want once", got)
	}
}

func TestTheSweepReleasesAUserSessionAfterItsIdlePeriod(t *testing.T) {
	url := noContent(t)
	node, resets := keepingNode("used")
	restore := swapTunnelProxies(map[string]C.Proxy{"used": node}, map[string]P.ProxyProvider{})
	defer restore()

	conn, err := node.DialContext(context.Background(), serverTarget(t, url))
	if err != nil {
		t.Fatal(err)
	}
	idle := 20 * time.Second
	if got := sweepIdleSessions(time.Now().Add(time.Hour), idle); got != 0 || resets.Load() != 0 {
		t.Fatalf("the sweep released a session a connection is open on (released %d)", got)
	}
	_ = conn.Close()

	if got := sweepIdleSessions(time.Now(), idle); got != 0 || resets.Load() != 0 {
		t.Fatalf("the sweep released a session just used (released %d)", got)
	}
	if got := sweepIdleSessions(time.Now().Add(idle+time.Second), idle); got != 1 || resets.Load() != 1 {
		t.Fatalf("the sweep released %d sessions idle past their period, want 1", got)
	}
}

func TestTheSessionSweepStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSessionSweep(ctx, 10*time.Millisecond, time.Hour)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the sweep outlived its context")
	}
}

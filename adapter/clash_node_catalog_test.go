package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)


type clashConnectProxy struct {
	host    string
	port    int
	tunnels atomic.Int64
}

func newClashConnectProxy(t testing.TB) *clashConnectProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &clashConnectProxy{host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = listener.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.serve(conn)
			}()
		}
	}()
	return p
}

func (p *clashConnectProxy) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	upstream, err := net.Dial("tcp", request.Host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()
	p.tunnels.Add(1)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func (p *clashConnectProxy) node(name string) map[string]any {
	return map[string]any{"name": name, "type": "http", "server": p.host, "port": p.port}
}

func clashEchoServer(t testing.TB) *C.Metadata {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); _ = conn.Close() }()
		}
	}()
	metadata := &C.Metadata{NetWork: C.TCP}
	if err := metadata.SetRemoteAddress(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func clashCountedBuilds(t testing.TB, wrap func(outbound.ProxyAdapter) (outbound.ProxyAdapter, error)) *atomic.Int64 {
	t.Helper()
	builds := &atomic.Int64{}
	catalogBuildOverride = func(config string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, providerName string) (outbound.ProxyAdapter, error) {
		builds.Add(1)
		built, err := buildCatalogNode(config, dialerForAPI, tunnelForAPI, providerName)
		if err != nil || wrap == nil {
			return built, err
		}
		return wrap(built)
	}
	t.Cleanup(func() { catalogBuildOverride = nil })
	return builds
}

func clashEventually(done func() bool) bool {
	for i := 0; i < 200; i++ {
		if done() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return done()
}

func clashCatalogLimit(t testing.TB, limit int) {
	t.Helper()
	restore := outbound.SetNodeCatalogLimit(limit)
	t.Cleanup(restore)
}

func clashParse(t testing.TB, mapping map[string]any, options ...ProxyOption) *Proxy {
	t.Helper()
	proxy, err := ParseProxy(mapping, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy.(*Proxy)
}

func clashBuilt(proxy C.Proxy) bool {
	_, built := outbound.IsCatalogNode(proxy.Adapter())
	return built
}

func clashDial(t testing.TB, proxy C.Proxy, target *C.Metadata) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, target)
	if err != nil {
		t.Fatalf("dial through %s: %v", proxy.Name(), err)
	}
	return conn
}

func clashSettleHeap() (heap int64, goroutines int) {
	last := -1
	for i := 0; i < 50; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
		now := runtime.NumGoroutine()
		if now == last {
			break
		}
		last = now
	}
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return int64(stats.HeapAlloc), runtime.NumGoroutine()
}

const clashNodeResidentMax = 600

func TestParsedNodesKeepNoOutbound(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		const n = 2000
		dir := ""
		if mapped {
			dir = t.TempDir()
		}
		SetNodeCatalogDirectory(dir)
		proxies := make([]C.Proxy, 0, n)
		heapBefore, goroutinesBefore := clashSettleHeap()
		session := NewNodeCatalogSession()
		for i := 0; i < n; i++ {
			mapping := clashMixedNode(t, i)
			proxy, err := ParseProxy(mapping, WithNodeCatalogSession(session))
			if err != nil {
				t.Fatalf("%v: %v", mapping["name"], err)
			}
			proxies = append(proxies, proxy)
		}
		if err := session.Seal(); err != nil {
			t.Fatal(err)
		}
		heapAfter, goroutinesAfter := clashSettleHeap()
		SetNodeCatalogDirectory("")
		perNode := (heapAfter - heapBefore) / n
		stored, isMapped := session.Stored()
		t.Logf("mapped %v: each parsed node keeps %d B of live heap (records %d B a node, mapped %v); goroutines %d -> %d",
			mapped, perNode, stored/n, isMapped, goroutinesBefore, goroutinesAfter)
		if isMapped != mapped {
			t.Fatalf("records mapped %v, want %v", isMapped, mapped)
		}
		if entries, _ := os.ReadDir(dir); mapped && len(entries) != 0 {
			t.Fatalf("the mapped file is left behind: %v", entries)
		}
		for _, proxy := range proxies {
			if catalog, built := outbound.IsCatalogNode(proxy.Adapter()); !catalog || built {
				t.Fatalf("%s: catalog node %v, built %v; want a catalog node holding nothing built", proxy.Name(), catalog, built)
			}
		}
		if perNode > clashNodeResidentMax {
			t.Errorf("each parsed node keeps %d B; want at most %d", perNode, clashNodeResidentMax)
		}
		if goroutinesAfter > goroutinesBefore {
			t.Errorf("parsing %d nodes left %d goroutines running", n, goroutinesAfter-goroutinesBefore)
		}
		for _, proxy := range proxies {
			_ = proxy.Close()
		}
		runtime.KeepAlive(proxies)
	}
}

var clashProxySink *Proxy

func TestAProxyHoldsNoHistoryUntilItIsMeasured(t *testing.T) {
	adapter := outbound.NewDirect()
	if allocs := testing.AllocsPerRun(100, func() { clashProxySink = NewProxy(adapter) }); allocs != 1 {
		t.Fatalf("NewProxy made %.0f allocations; want the node record alone", allocs)
	}
	proxy := NewProxy(adapter)
	if history := proxy.DelayHistory(); history == nil || len(history) != 0 {
		t.Fatalf("an unmeasured node's history is %#v; want an empty list", history)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	for i := 1; i <= defaultHistoriesNum+2; i++ {
		if _, err := proxy.URLTest(context.Background(), server.URL+"/"+strconv.Itoa(i), nil); err != nil {
			t.Fatal(err)
		}
		want := i
		if want > defaultHistoriesNum {
			want = defaultHistoriesNum
		}
		if got := len(proxy.DelayHistory()); got != want {
			t.Fatalf("after %d measurements the history holds %d records; want %d", i, got, want)
		}
	}
}

func TestACatalogNodeReadsAsTheOutboundItStandsFor(t *testing.T) {
	cases := append(clashMixedNodes(t, 5),
		map[string]any{"name": "ss-smux", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "p", "smux": map[string]any{"enabled": true, "protocol": "h2mux"}},
		map[string]any{"name": "ss-uot", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "p", "udp-over-tcp": true, "dialer-proxy": "other", "interface-name": "en0", "routing-mark": 7, "tfo": true},
		map[string]any{"name": "tuic", "type": "tuic", "server": "127.0.0.1", "port": 9, "uuid": "0123abcd-4567-89ef-0123-456789abcdef", "password": "p", "alpn": []any{"h3"}},
		map[string]any{"name": "socks", "type": "socks5", "server": "127.0.0.1", "port": 9, "udp": true},
		map[string]any{"name": "http", "type": "http", "server": "127.0.0.1", "port": 9},
		map[string]any{"name": "anytls", "type": "anytls", "server": "127.0.0.1", "port": 9, "password": "p", "udp": true},
		map[string]any{"name": "snell", "type": "snell", "server": "127.0.0.1", "port": 9, "psk": "p", "version": 3},
		map[string]any{"name": "wg", "type": "wireguard", "server": "127.0.0.1", "port": 9, "ip": "10.0.0.2", "private-key": "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "public-key": "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "udp": true},
		map[string]any{"name": "direct-node", "type": "direct"},
		map[string]any{"name": "reject-node", "type": "reject"},
	)
	for _, mapping := range cases {
		name := mapping["name"].(string)
		config, ok := encodeNodeConfig(mapping)
		if !ok {
			t.Fatalf("%s: not encoded", name)
		}
		const providerName = "provider"
		built, err := buildCatalogNode(config, nil, nil, providerName)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reference := NewProxy(outbound.NewAutoCloseProxyAdapter(built))
		want, err := reference.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		wantInfo, wantL3 := built.ProxyInfo(), built.IsL3Protocol(&C.Metadata{})
		wantUDP, wantUOT, wantAddr, wantType := built.SupportUDP(), built.SupportUOT(), built.Addr(), built.Type()

		node, ok := outbound.NewSingleCatalogNode(built, config, providerName, nil, nil, buildCatalogNode)
		if !ok {
			t.Fatalf("%s: no catalog node", name)
		}
		proxy := NewProxy(outbound.NewAutoCloseProxyAdapter(node))
		got, err := proxy.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s: JSON\n%s\nwant\n%s", name, got, want)
		}
		if proxy.Name() != name || proxy.Type() != wantType || proxy.Addr() != wantAddr || proxy.SupportUDP() != wantUDP ||
			proxy.SupportUOT() != wantUOT || proxy.ProxyInfo() != wantInfo || proxy.IsL3Protocol(&C.Metadata{}) != wantL3 ||
			proxy.Unwrap(&C.Metadata{}, true) != nil {
			t.Errorf("%s: the catalog node answers differently from its outbound", name)
		}
		if _, built := outbound.IsCatalogNode(proxy.Adapter()); built {
			t.Errorf("%s: reading the node built it", name)
		}
		_ = proxy.Close()
	}
}

func TestParseProxyKeepsCatalogNodes(t *testing.T) {
	for _, mapping := range clashMixedNodes(t, 5) {
		proxy := clashParse(t, mapping)
		if catalog, built := outbound.IsCatalogNode(proxy.Adapter()); !catalog || built {
			t.Errorf("%s: catalog node %v, built %v", proxy.Name(), catalog, built)
		}
	}
}

func TestTheParseRefusesInUpstreamsWords(t *testing.T) {
	cases := []map[string]any{
		{"name": "no type"},
		{"name": "unknown", "type": "nope"},
		{"name": "bad cipher", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "nope", "password": "p"},
		{"name": "bad port", "type": "ss", "server": "127.0.0.1", "port": "x", "cipher": "aes-128-gcm", "password": "p"},
		{"name": "bad smux", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "p", "smux": map[string]any{"enabled": true, "protocol": "nope"}},
		{"name": "bad smux field", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "p", "smux": map[string]any{"enabled": "x"}},
		{"name": "bad reality", "type": "vless", "server": "127.0.0.1", "port": 9, "uuid": "0123abcd-4567-89ef-0123-456789abcdef", "tls": true, "reality-opts": map[string]any{"public-key": "short"}},
		{"name": "bad wireguard", "type": "wireguard", "server": "127.0.0.1", "port": 9, "ip": "10.0.0.2", "private-key": "x", "public-key": "y"},
		{"name": "bad uuid", "type": "vmess", "server": "127.0.0.1", "port": 9, "uuid": "x", "cipher": "auto"},
	}
	for _, mapping := range cases {
		_, catalogErr := ParseProxy(mapping)
		SetNodeCatalog(false)
		_, upstreamErr := ParseProxy(mapping)
		SetNodeCatalog(true)
		if catalogErr == nil || upstreamErr == nil || catalogErr.Error() != upstreamErr.Error() {
			t.Errorf("%v: catalog %v, upstream %v", mapping["name"], catalogErr, upstreamErr)
		}
	}
}

func TestRacingFirstDialsBuildOnce(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	builds := clashCountedBuilds(t, nil)
	proxy := clashParse(t, connect.node("racing"))
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := proxy.DialContext(context.Background(), target)
			if err != nil {
				errs <- err
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("16 racing first dials built the outbound %d times; want once", got)
	}
}

func TestAFailedBuildIsNotKept(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	refusal := errors.New("refused this once")
	var refused atomic.Bool
	builds := clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		if refused.CompareAndSwap(false, true) {
			_ = built.Close()
			return nil, refusal
		}
		return built, nil
	})
	proxy := clashParse(t, connect.node("refused"))
	if _, err := proxy.DialContext(context.Background(), target); !errors.Is(err, refusal) {
		t.Fatalf("the first dial returned %v; want the build's error", err)
	}
	if clashBuilt(proxy) {
		t.Fatal("a failed build was kept")
	}
	_ = clashDial(t, proxy, target).Close()
	if got := builds.Load(); got != 2 {
		t.Fatalf("%d builds; want the failed one and one more", got)
	}
	if !clashBuilt(proxy) {
		t.Fatal("the second build was not kept")
	}
}

func TestTheLeastRecentlyUsedIdleNodeLetsGoOfItsOutbound(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	clashCatalogLimit(t, 2)
	closed := &atomic.Int64{}
	builds := clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashClosingAdapter{ProxyAdapter: built, closed: closed}, nil
	})
	a, b, c := clashParse(t, connect.node("a")), clashParse(t, connect.node("b")), clashParse(t, connect.node("c"))
	for _, proxy := range []*Proxy{a, b, c} {
		_ = clashDial(t, proxy, target).Close()
	}
	if clashBuilt(a) || !clashBuilt(b) || !clashBuilt(c) || outbound.NodeCatalogBuilt() != 2 {
		t.Fatalf("built: a %v b %v c %v (%d); want b and c", clashBuilt(a), clashBuilt(b), clashBuilt(c), outbound.NodeCatalogBuilt())
	}
	if !clashEventually(func() bool { return closed.Load() == 1 }) {
		t.Fatalf("%d outbounds closed; want a's", closed.Load())
	}
	_ = clashDial(t, a, target).Close()
	if builds.Load() != 4 || clashBuilt(b) || !clashBuilt(a) {
		t.Fatalf("builds %d, a %v, b %v; want a rebuilt and b let go", builds.Load(), clashBuilt(a), clashBuilt(b))
	}
}

func TestANodeInUseKeepsItsOutbound(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	clashCatalogLimit(t, 1)
	release := make(chan struct{})
	var holding atomic.Bool
	clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashGatedAdapter{ProxyAdapter: built, gate: release, holding: &holding}, nil
	})
	open, flying, other := clashParse(t, connect.node("open")), clashParse(t, connect.node("flying")), clashParse(t, connect.node("other"))
	conn := clashDial(t, open, target)
	holding.Store(true)
	dialed := make(chan error, 1)
	go func() {
		c, err := flying.DialContext(context.Background(), target)
		if err == nil {
			_ = c.Close()
		}
		dialed <- err
	}()
	for !clashBuilt(flying) {
		time.Sleep(time.Millisecond)
	}
	holding.Store(false)
	_ = clashDial(t, other, target).Close()
	if !clashBuilt(open) || !clashBuilt(flying) {
		t.Fatalf("a node with a connection open (%v) or a dial in flight (%v) let go of its outbound", clashBuilt(open), clashBuilt(flying))
	}
	close(release)
	if err := <-dialed; err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	time.Sleep(10 * time.Millisecond)
	outbound.TrimNodeCatalog()
	if outbound.NodeCatalogBuilt() != 1 || !clashBuilt(other) {
		t.Fatalf("after both went idle %d nodes hold an outbound (other %v); want the most recent alone", outbound.NodeCatalogBuilt(), clashBuilt(other))
	}
}

func TestDialerProxyReachesACatalogNodeByName(t *testing.T) {
	first, second := newClashConnectProxy(t), newClashConnectProxy(t)
	target := clashEchoServer(t)
	tunnel := &clashNamedTunnel{proxies: map[string]C.Proxy{}}
	hop := clashParse(t, first.node("hop"), WithTunnelForAPI(tunnel))
	mapping := second.node("exit")
	mapping["dialer-proxy"] = "hop"
	exit := clashParse(t, mapping, WithTunnelForAPI(tunnel))
	tunnel.proxies["hop"], tunnel.proxies["exit"] = hop, exit
	conn := clashDial(t, exit, target)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("echo through exit over hop: %q, %v", reply, err)
	}
	_ = conn.Close()
	if first.tunnels.Load() != 1 || second.tunnels.Load() != 1 || !clashBuilt(hop) || !clashBuilt(exit) {
		t.Fatalf("tunnels %d/%d, built hop %v exit %v; want the chain through both", first.tunnels.Load(), second.tunnels.Load(), clashBuilt(hop), clashBuilt(exit))
	}
}

func TestMeasuringEveryNodeLeavesTheCatalogWithinItsLimit(t *testing.T) {
	connect := newClashConnectProxy(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	clashCatalogLimit(t, 8)
	const n = 40
	proxies := make([]*Proxy, n)
	for i := range proxies {
		proxies[i] = clashParse(t, connect.node(fmt.Sprint("node-", i)))
	}
	pace := time.NewTicker(25 * time.Millisecond)
	defer pace.Stop()
	slots := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var failures atomic.Int64
	for _, proxy := range proxies {
		<-pace.C
		wg.Add(1)
		slots <- struct{}{}
		go func(proxy *Proxy) {
			defer wg.Done()
			defer func() { <-slots }()
			if _, err := proxy.URLTest(context.Background(), server.URL, nil); err != nil {
				failures.Add(1)
			}
		}(proxy)
	}
	wg.Wait()
	outbound.TrimNodeCatalog()
	if failures.Load() != 0 || connect.tunnels.Load() < n {
		t.Fatalf("%d of %d probes failed, %d tunnels", failures.Load(), n, connect.tunnels.Load())
	}
	if built := outbound.NodeCatalogBuilt(); built > 8 {
		t.Fatalf("%d nodes hold an outbound after the round; want at most the limit, 8", built)
	}
	for _, proxy := range proxies {
		if len(proxy.DelayHistory()) != 1 {
			t.Fatalf("%s: %d records", proxy.Name(), len(proxy.DelayHistory()))
		}
	}
}

func TestAnUnreachableNodeLetsGoOfItsOutbound(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	closed := &atomic.Int64{}
	clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashClosingAdapter{ProxyAdapter: built, closed: closed}, nil
	})
	before := outbound.NodeCatalogBuilt()
	generation := make([]C.Proxy, 8)
	for i := range generation {
		proxy, err := ParseProxy(connect.node(fmt.Sprint("old-", i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = clashDial(t, proxy, target).Close()
		generation[i] = proxy
	}
	if outbound.NodeCatalogBuilt() != before+8 {
		t.Fatalf("%d built", outbound.NodeCatalogBuilt()-before)
	}
	runtime.KeepAlive(generation)
	generation = nil
	for i := 0; i < 100 && (closed.Load() < 8 || outbound.NodeCatalogBuilt() != before); i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() != 8 || outbound.NodeCatalogBuilt() != before {
		t.Fatalf("%d of 8 outbounds of unreachable nodes closed, %d still listed", closed.Load(), outbound.NodeCatalogBuilt()-before)
	}
}

type clashClosingAdapter struct {
	outbound.ProxyAdapter
	closed *atomic.Int64
}

func (a *clashClosingAdapter) Close() error {
	a.closed.Add(1)
	return a.ProxyAdapter.Close()
}

type clashGatedAdapter struct {
	outbound.ProxyAdapter
	gate    chan struct{}
	holding *atomic.Bool
}

func (a *clashGatedAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if a.holding.Load() {
		<-a.gate
	}
	return a.ProxyAdapter.DialContext(ctx, metadata)
}

type clashNamedTunnel struct {
	proxies map[string]C.Proxy
}

func (t *clashNamedTunnel) HandleTCPConn(net.Conn, *C.Metadata)      {}
func (t *clashNamedTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (t *clashNamedTunnel) NatTable() C.NatTable                     { return nil }
func (t *clashNamedTunnel) Proxies() map[string]C.Proxy              { return t.proxies }
func (t *clashNamedTunnel) Providers() map[string]C.ProxyAdapter     { return nil }

func TestAProbeLeavesNoOutboundBehind(t *testing.T) {
	connect := newClashConnectProxy(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	closed := &atomic.Int64{}
	builds := clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashClosingAdapter{ProxyAdapter: built, closed: closed}, nil
	})
	listed, outbounds := outbound.NodeCatalogBuilt(), outbound.NodeCatalogOutbounds()
	proxy := clashParse(t, connect.node("probed"))
	if _, err := proxy.URLTest(context.Background(), server.URL, nil); err != nil {
		t.Fatal(err)
	}
	if !clashEventually(func() bool { return closed.Load() == 1 }) || builds.Load() != 1 {
		t.Fatalf("the probe built %d outbounds and closed %d; want one built for it and closed after it", builds.Load(), closed.Load())
	}
	if clashBuilt(proxy) || outbound.NodeCatalogBuilt() != listed || outbound.NodeCatalogOutbounds() != outbounds {
		t.Fatal("a probe left an outbound behind")
	}
	target := clashEchoServer(t)
	_ = clashDial(t, proxy, target).Close()
	if _, err := proxy.URLTest(context.Background(), server.URL, nil); err != nil {
		t.Fatal(err)
	}
	if builds.Load() != 2 || closed.Load() != 1 || !clashBuilt(proxy) {
		t.Fatalf("builds %d, closed %d, listed %v; want the user's outbound kept and probed", builds.Load(), closed.Load(), clashBuilt(proxy))
	}
}

func TestAUserDialTakesWhatAProbeBuilt(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	release := make(chan struct{})
	var holding atomic.Bool
	builds := clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashGatedAdapter{ProxyAdapter: built, gate: release, holding: &holding}, nil
	})
	proxy := clashParse(t, connect.node("shared-with-probe"))
	holding.Store(true)
	probed := make(chan error, 1)
	go func() {
		c, err := proxy.DialContext(dialer.WithDialKind(context.Background(), dialer.DialKindProbe), target)
		if err == nil {
			_ = c.Close()
		}
		probed <- err
	}()
	for outbound.NodeCatalogOutbounds() == 0 {
		time.Sleep(time.Millisecond)
	}
	holding.Store(false)
	_ = clashDial(t, proxy, target).Close()
	close(release)
	if err := <-probed; err != nil {
		t.Fatal(err)
	}
	if builds.Load() != 1 || !clashBuilt(proxy) {
		t.Fatalf("builds %d, listed %v; want the probe's outbound listed for the user", builds.Load(), clashBuilt(proxy))
	}
}

func TestEqualNodesShareAnOutbound(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	closed := &atomic.Int64{}
	builds := clashCountedBuilds(t, func(built outbound.ProxyAdapter) (outbound.ProxyAdapter, error) {
		return &clashClosingAdapter{ProxyAdapter: built, closed: closed}, nil
	})
	old := clashParse(t, connect.node("unchanged"), WithProviderName("airport"))
	_ = clashDial(t, old, target).Close()
	refreshed := clashParse(t, connect.node("unchanged"), WithProviderName("airport"))
	changed := clashParse(t, connect.node("unchanged"), WithProviderName("another"))
	_ = clashDial(t, refreshed, target).Close()
	if builds.Load() != 1 {
		t.Fatalf("%d builds; want the refreshed node to take the old one's outbound", builds.Load())
	}
	if outbound.ReleaseProbedSession(refreshed.Adapter()) {
		t.Fatal("a shared outbound was released for one of its nodes")
	}
	_ = clashDial(t, changed, target).Close()
	if builds.Load() != 2 {
		t.Fatalf("%d builds; a node of another provider shares nothing", builds.Load())
	}
	_ = old.Close()
	if closed.Load() != 0 || !clashBuilt(refreshed) {
		t.Fatal("closing the old node closed the outbound the refreshed one holds")
	}
	_ = refreshed.Close()
	if closed.Load() != 1 {
		t.Fatalf("%d closed; the last holder closes the outbound", closed.Load())
	}
}

func TestAPinnedNodeStaysListed(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	clashCatalogLimit(t, 1)
	chosen, a, b := clashParse(t, connect.node("chosen")), clashParse(t, connect.node("a")), clashParse(t, connect.node("b"))
	outbound.SetNodeCatalogPins([]C.ProxyAdapter{chosen.Adapter()})
	t.Cleanup(func() { outbound.SetNodeCatalogPins(nil) })
	for _, proxy := range []*Proxy{chosen, a, b} {
		_ = clashDial(t, proxy, target).Close()
	}
	if !clashBuilt(chosen) || clashBuilt(a) || !clashBuilt(b) {
		t.Fatalf("listed: chosen %v a %v b %v; want the pinned one and the latest", clashBuilt(chosen), clashBuilt(a), clashBuilt(b))
	}
	outbound.SetNodeCatalogPins(nil)
	outbound.TrimNodeCatalog()
	if clashBuilt(chosen) || !clashBuilt(b) {
		t.Fatal("an unpinned idle node stayed past the limit")
	}
}

func TestAMappedStoreReadsAsTheHeapStore(t *testing.T) {
	connect := newClashConnectProxy(t)
	target := clashEchoServer(t)
	parse := func(dir string) map[string]C.Proxy {
		SetNodeCatalogDirectory(dir)
		defer SetNodeCatalogDirectory("")
		session := NewNodeCatalogSession()
		proxies := map[string]C.Proxy{}
		for i := 0; i < 20; i++ {
			mapping := clashMixedNode(t, i)
			mapping["interface-name"] = fmt.Sprint("en", i)
			proxies[mapping["name"].(string)] = clashParse(t, mapping, WithProviderName("airport"), WithNodeCatalogSession(session))
		}
		hop := connect.node("hop")
		hop["dialer-proxy"] = "nowhere"
		proxies["hop"] = clashParse(t, hop, WithProviderName("airport"), WithNodeCatalogSession(session))
		proxies["direct"] = clashParse(t, connect.node("direct"), WithProviderName("airport"), WithNodeCatalogSession(session))
		if err := session.Seal(); err != nil {
			t.Fatal(err)
		}
		if _, mapped := session.Stored(); mapped != (dir != "") {
			t.Fatalf("mapped %v", mapped)
		}
		return proxies
	}
	heap, mapped := parse(""), parse(t.TempDir())
	for name, h := range heap {
		m := mapped[name]
		hj, _ := h.MarshalJSON()
		mj, _ := m.MarshalJSON()
		strip := func(b []byte) string {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			delete(v, "id")
			out, _ := json.Marshal(v)
			return string(out)
		}
		if strip(hj) != strip(mj) || h.Addr() != m.Addr() || h.ProxyInfo() != m.ProxyInfo() {
			t.Fatalf("%s reads differently mapped:\n%s\n%s", name, hj, mj)
		}
	}
	_ = clashDial(t, mapped["direct"], target).Close()
	if !clashBuilt(mapped["direct"]) {
		t.Fatal("a node of a mapped store did not build")
	}
}

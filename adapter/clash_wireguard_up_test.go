package adapter

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

type silentDialer struct {
	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func (d *silentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	client, peer := net.Pipe()
	d.conns = append(d.conns, client, peer)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	return client, nil
}

func (d *silentDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (d *silentDialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, c := range d.conns {
		_ = c.Close()
	}
}

func silentHopWireGuard(t *testing.T) C.Proxy {
	t.Helper()
	silent := &silentDialer{}
	node := hopWireGuard(t, silent)
	t.Cleanup(silent.closeAll)
	return node
}

func hopWireGuard(t *testing.T, hopDialer C.Dialer) C.Proxy {
	t.Helper()
	tunnel := &clashNamedTunnel{proxies: map[string]C.Proxy{}}
	hop, err := ParseProxy(map[string]any{
		"name": "hop", "type": "trojan", "server": "203.0.113.1", "port": 443, "password": "p",
		"sni": "hop.example.net", "skip-cert-verify": true, "udp": true,
	}, WithDialerForAPI(hopDialer))
	if err != nil {
		t.Fatal(err)
	}
	tunnel.proxies["hop"] = hop
	const key = "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	node, err := ParseProxy(map[string]any{
		"name": "wg", "type": "wireguard", "server": "203.0.113.2", "port": 51820, "ip": "10.0.0.2",
		"private-key": key, "public-key": key, "udp": true, "dialer-proxy": "hop", "persistent-keepalive": 25,
	}, WithTunnelForAPI(tunnel))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close(); _ = hop.Close() })
	return node
}

type deafDialer struct{ let chan struct{} }

func (d *deafDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	<-d.let
	return nil, net.ErrClosed
}

func (d *deafDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func dialStuck(t *testing.T, node C.Proxy) {
	t.Helper()
	dialed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		conn, err := node.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 80})
		if conn != nil {
			_ = conn.Close()
		}
		dialed <- err
	}()
	select {
	case err := <-dialed:
		if err == nil {
			t.Fatal("the dial succeeded through a hop that never answers")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the dial still waits after 3 s: the device's Up holds it past its deadline")
	}
}

func settlesTo(t *testing.T, baseline int, after string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		buf := make([]byte, 1<<20)
		t.Fatalf("%d goroutines 3 s after %s, %d before the dial:\n%s", got, after, baseline, buf[:runtime.Stack(buf, true)])
	}
}

func within[T any](t *testing.T, limit time.Duration, what string, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	start := time.Now()
	go func() { done <- f() }()
	select {
	case v := <-done:
		t.Logf("%s returned after %v", what, time.Since(start))
		return v
	case <-time.After(limit):
		t.Fatalf("%s still waits after %v", what, limit)
		panic("unreachable")
	}
}

func TestAWireGuardDeviceStuckComingUpHoldsADialOnlyToItsDeadline(t *testing.T) {
	node := silentHopWireGuard(t)
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 80}
	type result struct {
		took time.Duration
		err  error
	}
	dial := func(deadline time.Duration) <-chan result {
		done := make(chan result, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			start := time.Now()
			conn, err := node.DialContext(ctx, metadata)
			if conn != nil {
				_ = conn.Close()
			}
			done <- result{time.Since(start), err}
		}()
		return done
	}
	first := dial(100 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	second := dial(150 * time.Millisecond)
	for name, got := range map[string]<-chan result{"first": first, "second": second} {
		select {
		case r := <-got:
			if r.err == nil {
				t.Fatalf("%s dial succeeded through a hop that never answers", name)
			}
			if r.took > time.Second {
				t.Fatalf("%s dial took %v; want about its own deadline", name, r.took)
			}
			t.Logf("%s dial returned after %v: %v", name, r.took, r.err)
		case <-time.After(3 * time.Second):
			t.Fatalf("%s dial still waits after 3 s: the device's Up holds it past its deadline", name)
		}
	}
}

func TestAReleaseTakesDownAWireGuardDeviceStuckComingUp(t *testing.T) {
	node := silentHopWireGuard(t)
	baseline := runtime.NumGoroutine()
	dialStuck(t, node)
	released := within(t, time.Second, "the release", func() bool {
		return outbound.ReleaseUserSessionIfIdle(node.Adapter(), time.Now().Add(time.Hour), 0)
	})
	if !released {
		t.Fatal("the release declined a device whose bind's dial it could cancel")
	}
	settlesTo(t, baseline, "the release")
}

func TestAWireGuardDeviceStuckOnADialThatIgnoresItsContextBlocksNeitherReleaseNorClose(t *testing.T) {
	deaf := &deafDialer{let: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-deaf.let:
		default:
			close(deaf.let)
		}
	})
	node := hopWireGuard(t, deaf)
	baseline := runtime.NumGoroutine()
	dialStuck(t, node)
	released := within(t, time.Second, "the release", func() bool {
		return outbound.ReleaseUserSessionIfIdle(node.Adapter(), time.Now().Add(time.Hour), 0)
	})
	if released {
		t.Fatal("a device whose Up is still waiting was released")
	}
	dialStuck(t, node)
	within(t, time.Second, "Close", func() error { return node.Close() })
	close(deaf.let)
	settlesTo(t, baseline, "Close and the dial's end")
}

func TestClosingAWireGuardNodeStuckComingUpReturnsAndLeavesNothing(t *testing.T) {
	for _, catalog := range []bool{true, false} {
		name := "catalog"
		if !catalog {
			name = "upstream"
		}
		t.Run(name, func(t *testing.T) {
			previous := SetNodeCatalog(catalog)
			t.Cleanup(func() { SetNodeCatalog(previous) })
			node := silentHopWireGuard(t)
			baseline := runtime.NumGoroutine()
			dialStuck(t, node)
			within(t, time.Second, "Close", func() error { return node.Close() })
			settlesTo(t, baseline, "Close")
		})
	}
}

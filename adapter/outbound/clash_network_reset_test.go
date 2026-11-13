package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/ca"
	C "github.com/ProjectClash/Clash/constant"

	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/tls"
)

func TestAHysteria2ResetDropsItsClientAndTheNextDialBuildsAnother(t *testing.T) {
	builds := 0
	h := &Hysteria2{buildClient: func() (*hysteria2.Client, error) {
		builds++
		return nil, errors.New("no server in a unit test")
	}}
	_, _ = h.lazyClient()
	h.ResetNetwork()
	if _, err := h.lazyClient(); errors.Is(err, errOutboundClosed) {
		t.Fatal("a network reset must not close the node")
	}
	if builds != 2 {
		t.Fatalf("builds=%d, want the client rebuilt after the reset", builds)
	}
}

func TestAClosedHysteria2StaysClosedThroughAReset(t *testing.T) {
	h := &Hysteria2{buildClient: func() (*hysteria2.Client, error) { return nil, nil }}
	_ = h.Close()
	h.ResetNetwork()
	if _, err := h.lazyClient(); !errors.Is(err, errOutboundClosed) {
		t.Fatalf("a closed node reopened by a reset: %v", err)
	}
}

var _ NetworkResetter = (*Hysteria2)(nil)
var _ NetworkResetter = (*Tuic)(nil)
var _ NetworkResetter = (*SingMux)(nil)

type anyTLSSink struct {
	port     int
	accepted atomic.Int64
	closed   atomic.Int64
}

func newAnyTLSSink(t *testing.T) *anyTLSSink {
	t.Helper()
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &anyTLSSink{port: listener.Addr().(*net.TCPAddr).Port}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			sink.accepted.Add(1)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				sink.closed.Add(1)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return sink
}

func anyTLSDialAndClose(t *testing.T, node C.ProxyAdapter) {
	t.Helper()
	conn, err := node.DialContext(context.Background(), &C.Metadata{Host: "example.com", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestAnAnyTLSNodeDropsItsSessionsOnANetworkChangeButNotInTheIdleRelease(t *testing.T) {
	for _, catalog := range []bool{false, true} {
		t.Run(fmt.Sprintf("catalog=%v", catalog), func(t *testing.T) {
			sink := newAnyTLSSink(t)
			option := AnyTLSOption{Name: "anytls", Server: "127.0.0.1", Port: sink.port, Password: "x", SkipCertVerify: true}
			build := func(string, C.Dialer, C.Tunnel, string) (ProxyAdapter, error) {
				node, err := NewAnyTLS(option)
				if err != nil {
					return nil, err
				}
				return node, nil
			}
			parsed, err := build("", nil, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			if catalog {
				var ok bool
				if parsed, ok = NewSingleCatalogNode(parsed, "anytls network reset", "airport", nil, nil, build); !ok {
					t.Fatal("no catalog node")
				}
			}
			node := NewAutoCloseProxyAdapter(parsed)
			t.Cleanup(func() { _ = node.Close() })
			resetter, ok := AsNetworkResetter(node)
			if !ok {
				t.Fatal("an AnyTLS node is not reset on a network change")
			}

			anyTLSDialAndClose(t, node)
			if ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) {
				t.Fatal("the idle session release took an AnyTLS node's sessions")
			}
			anyTLSDialAndClose(t, node)
			if accepted := sink.accepted.Load(); accepted != 1 {
				t.Fatalf("%d sessions for two dials around the idle release, want the pooled one reused", accepted)
			}

			resetter.ResetNetwork()
			deadline := time.Now().Add(2 * time.Second)
			for sink.closed.Load() != 1 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if closed := sink.closed.Load(); closed != 1 {
				t.Fatalf("%d sessions closed after the network reset, want the pooled one", closed)
			}
			anyTLSDialAndClose(t, node)
			if accepted := sink.accepted.Load(); accepted != 2 {
				t.Fatalf("%d sessions after the network reset, want the next dial on a new one", accepted)
			}
		})
	}
}

func TestANetworkResetNeitherBuildsNorReopensAnAnyTLSNode(t *testing.T) {
	node, err := NewAnyTLS(anyTLSOption())
	if err != nil {
		t.Fatal(err)
	}
	resetter, ok := AsNetworkResetter(node)
	if !ok {
		t.Fatal("an AnyTLS node is not reset on a network change")
	}
	resetter.ResetNetwork()
	if node.clientBuilt() {
		t.Fatal("a network reset built the client of a node that never dialed")
	}
	built, err := node.lazyClient()
	if err != nil {
		t.Fatal(err)
	}
	resetter.ResetNetwork()
	if after, err := node.lazyClient(); err != nil || after != built {
		t.Fatalf("the client after a network reset: %p, %v; want the node's own, open", after, err)
	}
	_ = node.Close()
	resetter.ResetNetwork()
	if _, err := node.lazyClient(); !errors.Is(err, errOutboundClosed) || node.clientBuilt() {
		t.Fatalf("a closed node reopened by a network reset: %v", err)
	}
}

type pathResettingOutbound struct{ keepingOutbound }

func (pathResettingOutbound) resetsOnNetworkChangeOnly() bool { return true }

func TestTheIdleReleaseLeavesANodeThatResetsOnlyOnANetworkChange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pathOnly bool
		catalog  bool
	}{
		{"keeping", false, false},
		{"keeping catalog", false, true},
		{"path only", true, false},
		{"path only catalog", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resets := &atomic.Int64{}
			build := func(string, C.Dialer, C.Tunnel, string) (ProxyAdapter, error) {
				keeping := keepingOutbound{Direct: NewDirect(), resets: resets}
				if tc.pathOnly {
					return pathResettingOutbound{keeping}, nil
				}
				return keeping, nil
			}
			parsed, _ := build("", nil, nil, "")
			if tc.catalog {
				var ok bool
				if parsed, ok = NewSingleCatalogNode(parsed, "path reset "+tc.name, "airport", nil, nil, build); !ok {
					t.Fatal("no catalog node")
				}
			}
			node := NewAutoCloseProxyAdapter(parsed)
			t.Cleanup(func() { _ = node.Close() })
			_ = dialed(t, node, context.Background()).Close()
			if released := ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second); released == tc.pathOnly {
				t.Fatalf("released %v after the idle period (resets %d)", released, resets.Load())
			}
			resetter, ok := AsNetworkResetter(node)
			if !ok {
				t.Fatal("a session-keeping node is not reset on a network change")
			}
			before := resets.Load()
			resetter.ResetNetwork()
			if resets.Load() != before+1 {
				t.Fatalf("resets %d after a network reset, want %d", resets.Load(), before+1)
			}
		})
	}
}

func TestAMuxedNodesReleaseLeavesAnOutboundThatResetsOnlyOnANetworkChange(t *testing.T) {
	resets := &atomic.Int64{}
	mux := &SingMux{ProxyAdapter: pathResettingOutbound{keepingOutbound{Direct: NewDirect(), resets: resets}}}
	mux.ReleaseSessions()
	if resets.Load() != 0 {
		t.Fatalf("the mux's idle release reset the outbound underneath %d times", resets.Load())
	}
	mux.ResetNetwork()
	if resets.Load() != 1 {
		t.Fatalf("a network change reset the outbound underneath %d times, want once", resets.Load())
	}
}

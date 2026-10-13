package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	"golang.org/x/net/http2"
)

func TestMasqueFirstDialsBuildOneStack(t *testing.T) {
	_, goroutinesBefore := clashSettle()
	option := clashMasqueOption(t)
	option.Port = clashClosedPort(t, "udp")
	node, err := NewMasque(option)
	if err != nil {
		t.Fatal(err)
	}
	if builds := node.clashStackBuilds(); builds != 0 {
		t.Fatalf("parsing built %d stacks", builds)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var dials sync.WaitGroup
	for i := 0; i < 16; i++ {
		dials.Add(1)
		go func() {
			defer dials.Done()
			if conn, err := node.DialContext(ctx, clashTCPMetadata()); err == nil {
				_ = conn.Close()
			}
		}()
	}
	dials.Wait()
	if builds := node.clashStackBuilds(); builds != 1 {
		t.Fatalf("16 racing first dials built %d stacks, want 1", builds)
	}
	_ = node.Close()
	if _, goroutinesAfter := clashSettle(); goroutinesAfter > goroutinesBefore+2 {
		t.Fatalf("goroutines %d before the node, %d after it closed", goroutinesBefore, goroutinesAfter)
	}
}

func TestMasqueClosedBeforeItsFirstDialBuildsNothing(t *testing.T) {
	node, err := NewMasque(clashMasqueOption(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := node.DialContext(ctx, clashTCPMetadata()); err == nil {
		t.Fatal("a dial after Close must refuse")
	}
	if _, err := node.clashBuildStack(); err != errOutboundClosed {
		t.Fatalf("a build after Close: %v, want errOutboundClosed", err)
	}
	if builds := node.clashStackBuilds(); builds != 0 {
		t.Fatalf("a closed node built %d stacks", builds)
	}
}

func clashMasqueH2Server(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != stdhttp.MethodConnect {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		w.WriteHeader(stdhttp.StatusOK)
		w.(stdhttp.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	})
	var mu sync.Mutex
	var conns []net.Conn
	var serving sync.WaitGroup
	serving.Add(1)
	go func() {
		defer serving.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			serving.Add(1)
			go func() {
				defer serving.Done()
				tlsConn := stdtls.Server(conn, config)
				if err := tlsConn.Handshake(); err != nil {
					_ = conn.Close()
					return
				}
				(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		serving.Wait()
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func clashMasqueH2Node(t *testing.T) *Masque {
	t.Helper()
	option := clashMasqueOption(t)
	option.Network = "h2"
	option.Port = clashMasqueH2Server(t)
	option.SkipCertVerify = true
	node, err := NewMasque(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func clashResolverUDPMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("10.0.0.53"), DstPort: 53}
}

func TestAMasqueNodeKeepsItsStackWhileItsResolverHoldsAConnection(t *testing.T) {
	node := clashMasqueH2Node(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := clashMasqueResolverDialer{node}.ListenPacketContext(ctx, clashResolverUDPMetadata())
	if err != nil {
		t.Fatalf("the resolver dial failed: %v", err)
	}
	if node.ReleaseSessions() || node.clashStack.built.Load() == nil {
		t.Fatal("released the stack under a connection its resolver holds")
	}
	_ = pc.Close()
	if !node.ReleaseSessions() || node.clashStack.built.Load() != nil {
		t.Fatal("the stack stayed after its resolver's connection closed")
	}
}

func TestAMasqueResolverDialDuringAReleaseGetsALiveStack(t *testing.T) {
	node := clashMasqueH2Node(t)
	clashProbeDial(node)
	if node.clashStack.built.Load() == nil || !node.running.Load() {
		t.Fatal("the first dial did not bring the tunnel up")
	}

	type dialed struct {
		pc  C.PacketConn
		err error
	}
	result := make(chan dialed, 1)
	clashMasqueReleaseChecked = func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := clashMasqueResolverDialer{node}.ListenPacketContext(ctx, clashResolverUDPMetadata())
			result <- dialed{pc, err}
		}()
		time.Sleep(100 * time.Millisecond)
	}
	defer func() { clashMasqueReleaseChecked = nil }()
	if !node.ReleaseSessions() {
		t.Fatal("an idle node was not released")
	}

	got := <-result
	if got.err != nil {
		t.Fatalf("the resolver dial failed: %v", got.err)
	}
	defer got.pc.Close()
	if _, err := got.pc.WriteTo([]byte{0}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 53), Port: 53}); err != nil {
		t.Fatalf("the resolver's connection is on a closed stack: %v", err)
	}
	if builds := node.clashStackBuilds(); builds != 2 {
		t.Fatalf("%d stacks built, want 2 (the released one and the resolver's)", builds)
	}
}

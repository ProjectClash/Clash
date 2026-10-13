package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)


const (
	clashParsedNodes       = 8
	clashParsedNodeMaxHeap = 16 << 10
)

func clashSettle() (heap int64, goroutines int) {
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
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return int64(stats.HeapAlloc), runtime.NumGoroutine()
}

func clashParseCost(t *testing.T, build func(i int) (io.Closer, error)) (bytesPerNode int64, goroutinesPerNode float64) {
	t.Helper()
	nodes := make([]io.Closer, 0, clashParsedNodes)
	t.Cleanup(func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	})
	heapBefore, goroutinesBefore := clashSettle()
	for i := 0; i < clashParsedNodes; i++ {
		node, err := build(i)
		if err != nil {
			t.Fatalf("parse node %d: %v", i, err)
		}
		nodes = append(nodes, node)
	}
	heapAfter, goroutinesAfter := clashSettle()
	runtime.KeepAlive(nodes)
	return (heapAfter - heapBefore) / clashParsedNodes, float64(goroutinesAfter-goroutinesBefore) / clashParsedNodes
}

func clashRequireParsedNodesHoldNothing(t *testing.T, protocol string, build func(i int) (io.Closer, error)) {
	t.Helper()
	bytes, goroutines := clashParseCost(t, build)
	t.Logf("%s: each parsed node holds %d bytes of live heap and %.1f goroutines", protocol, bytes, goroutines)
	if bytes > clashParsedNodeMaxHeap {
		t.Errorf("%s: each parsed node holds %d bytes; its protocol state must wait for the first dial", protocol, bytes)
	}
	if goroutines >= 1 {
		t.Errorf("%s: each parsed node runs %.1f goroutines; none may run before the first dial", protocol, goroutines)
	}
}

const clashTestWireGuardKey = "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func clashWireGuardOption() WireGuardOption {
	return WireGuardOption{
		Name: "wg", Ip: "10.0.0.2/32",
		WireGuardPeerOption: WireGuardPeerOption{
			Server: "127.0.0.1", Port: 9, PublicKey: clashTestWireGuardKey,
		},
		PrivateKey: clashTestWireGuardKey,
	}
}

func clashMasqueOption(t *testing.T) MasqueOption {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return MasqueOption{
		Name: "masque", Server: "127.0.0.1", Port: 9, Ip: "10.0.0.2/32",
		PrivateKey: base64.StdEncoding.EncodeToString(private),
		PublicKey:  base64.StdEncoding.EncodeToString(public),
	}
}

func TestParsedWireGuardNodesHoldNoDevice(t *testing.T) {
	clashRequireParsedNodesHoldNothing(t, "wireguard", func(int) (io.Closer, error) {
		return NewWireGuard(clashWireGuardOption())
	})
}

func TestParsedAmneziaWireGuardNodesHoldNoDevice(t *testing.T) {
	clashRequireParsedNodesHoldNothing(t, "amneziawg", func(i int) (io.Closer, error) {
		option := clashWireGuardOption()
		option.AmneziaWGOption = &AmneziaWGOption{JC: 4, JMin: 40, JMax: 70}
		if i%2 == 1 {
			option.AmneziaWGOption.Version = 3
		}
		return NewWireGuard(option)
	})
}

func TestParsedMasqueNodesHoldNoStack(t *testing.T) {
	option := clashMasqueOption(t)
	clashRequireParsedNodesHoldNothing(t, "masque", func(int) (io.Closer, error) {
		return NewMasque(option)
	})
}

func clashClosedPort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		return port
	default:
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		_ = conn.Close()
		return port
	}
}

func clashTCPMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 80}
}

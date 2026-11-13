package inbound_test


import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/inbound"
	"github.com/ProjectClash/Clash/transport/gun"
)

const grpcFlows = 16

func heapOfOpenGRPCFlows(t *testing.T) int64 {
	t.Helper()
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	var (
		heldMu sync.Mutex
		held   []net.Conn
		done   bool
	)
	defer func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		done = true
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		heldMu.Lock()
		if done {
			heldMu.Unlock()
			_ = conn.Close()
			return
		}
		held = append(held, conn)
		heldMu.Unlock()
		if metadata.Host == "warm.grpc.test" {
			_, _ = conn.Write([]byte("ok"))
		}
		_, _ = io.Copy(io.Discard, conn)
	}
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:      inbound.BaseOption{NameStr: "vless_grpc_scratch", Listen: "127.0.0.1", Port: "0"},
		Users:           []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		GrpcServiceName: "GunService",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	addrPort, err := netip.ParseAddrPort(in.Address())
	if err != nil {
		t.Fatal(err)
	}
	out, err := outbound.NewVless(outbound.VlessOption{
		Name: "vless_grpc_scratch", Server: addrPort.Addr().String(), Port: int(addrPort.Port()), UUID: userUUID,
		TLS: true, Fingerprint: tlsFingerprint, Network: "grpc",
		GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "GunService"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	settled := func() uint64 {
		var stats runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	warm, err := out.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "warm.grpc.test", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer warm.Close()
	if _, err := warm.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	_ = warm.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(warm, make([]byte, 2)); err != nil {
		t.Fatalf("the warm flow was not answered: %v", err)
	}
	before := settled()
	streams := gun.StreamsOpen()
	var conns []net.Conn
	for i := 0; i < grpcFlows; i++ {
		conn, err := out.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "grpc.test", DstPort: 443})
		if err != nil {
			t.Fatalf("dial flow %d: %v", i, err)
		}
		conns = append(conns, conn)
		if _, err := conn.Write([]byte("GET")); err != nil {
			t.Fatalf("write flow %d: %v", i, err)
		}
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	if got := gun.StreamsOpen() - streams; got < grpcFlows {
		t.Fatalf("%d gRPC flows counted open for %d dialed", got, grpcFlows)
	}
	time.Sleep(200 * time.Millisecond)
	return (int64(settled()) - int64(before)) / grpcFlows
}

func withStreamingBodyScratchMax(t *testing.T, bytes int) {
	t.Helper()
	before := http.SetHTTP2StreamingBodyScratchMax(bytes)
	t.Cleanup(func() { http.SetHTTP2StreamingBodyScratchMax(before) })
}

func TestAnOpenGRPCFlowHoldsSixtyFourKiBToSendWith(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	withStreamingBodyScratchOnDemand(t, false)
	perFlow := heapOfOpenGRPCFlows(t)
	t.Logf("an open gRPC flow holds %d KiB with the 64 KiB cap", perFlow>>10)
	if perFlow < 0 || perFlow > 160<<10 {
		t.Fatalf("an open gRPC flow that sends nothing holds %d KiB with the 64 KiB cap", perFlow>>10)
	}
	if perFlow < 56<<10 {
		t.Fatalf("an open gRPC flow holds only %d KiB with its 64 KiB buffer kept; the measurement does not see the scratch", perFlow>>10)
	}
}

func TestWithoutTheCapAnOpenGRPCFlowHoldsHalfAMebibyte(t *testing.T) {
	withStreamingBodyScratchMax(t, 0)
	withStreamingBodyScratchOnDemand(t, false)
	perFlow := heapOfOpenGRPCFlows(t)
	t.Logf("an open gRPC flow holds %d KiB without the cap", perFlow>>10)
	if perFlow < 448<<10 {
		t.Fatalf("an open gRPC flow holds only %d KiB without the cap; the measurement does not see the scratch", perFlow>>10)
	}
}

func withStreamingBodyScratchOnDemand(t *testing.T, on bool) {
	t.Helper()
	before := http.SetHTTP2StreamingBodyScratchOnDemand(on)
	t.Cleanup(func() { http.SetHTTP2StreamingBodyScratchOnDemand(before) })
}

func TestAnOpenGRPCFlowWithNothingToSendHoldsNoScratchOnDemand(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	withStreamingBodyScratchOnDemand(t, true)
	perFlow := heapOfOpenGRPCFlows(t)
	t.Logf("an open gRPC flow holds %d KiB with the scratch taken on demand", perFlow>>10)
	if perFlow < 0 || perFlow >= 56<<10 {
		t.Fatalf("an open gRPC flow that sends nothing holds %d KiB with the scratch taken on demand; the 64 KiB buffer is still held", perFlow>>10)
	}
}

func TestAGRPCFlowsUploadArrivesWholeWithTheScratchTakenOnDemand(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	withStreamingBodyScratchOnDemand(t, true)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	tunnel.HandleTCPConnFn = func(conn net.Conn, _ *C.Metadata) {
		defer conn.Close()
		var header [8]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		sum := sha256.New()
		if _, err := io.CopyN(sum, conn, int64(binary.BigEndian.Uint64(header[:]))); err != nil {
			return
		}
		_, _ = conn.Write(sum.Sum(nil))
	}
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:      inbound.BaseOption{NameStr: "vless_grpc_upload", Listen: "127.0.0.1", Port: "0"},
		Users:           []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		GrpcServiceName: "GunService",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	addrPort, err := netip.ParseAddrPort(in.Address())
	if err != nil {
		t.Fatal(err)
	}
	out, err := outbound.NewVless(outbound.VlessOption{
		Name: "vless_grpc_upload", Server: addrPort.Addr().String(), Port: int(addrPort.Port()), UUID: userUUID,
		TLS: true, Fingerprint: tlsFingerprint, Network: "grpc",
		GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "GunService"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	var chunks [][]byte
	want, total := sha256.New(), 0
	for i, size := range []int{1, 2, 3, 65535, 65536, 65537, 1, 200000, 7, 1 << 20, 1} {
		chunk := make([]byte, size)
		for j := range chunk {
			chunk[j] = byte(i*31 + j)
		}
		chunks = append(chunks, chunk)
		want.Write(chunk)
		total += size
	}
	conn, err := out.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "upload.grpc.test", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(total))
	if _, err := conn.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	for i, chunk := range chunks {
		if _, err := conn.Write(chunk); err != nil {
			t.Fatalf("write %d of %d bytes: %v", i, len(chunk), err)
		}
	}
	got := make([]byte, sha256.Size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the tunnel's answer: %v", err)
	}
	if !bytes.Equal(got, want.Sum(nil)) {
		t.Fatalf("the tunnel received other bytes than the %d sent", total)
	}
}

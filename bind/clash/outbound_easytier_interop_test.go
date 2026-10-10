//go:build !no_easytier

package clash

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	C "github.com/ProjectClash/Clash/constant"
	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/easytier/easytier/easytier-go/platform"
	"github.com/easytier/easytier/easytier-go/platform/netstd"
)

func TestControlledEasyTierInterop(t *testing.T) {
	stateDir := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(stateDir)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var before, reference, client runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	sockets := &easyTierReferenceSockets{}
	host, err := corehost.New(ctx, corehost.Options{Platform: platform.Services{Sockets: sockets}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(context.Background())
	config, err := corehost.NewInstanceConfigBuilder("clash-interop").
		NetworkSecret("local-fixture-only").Hostname("reference").
		IPv4(netip.MustParsePrefix("10.144.0.101/24")).
		AddListeners("tcp://127.0.0.1:0").
		P2P(corehost.P2PPolicy{Disable: true}).Encryption(true).Build()
	if err != nil {
		t.Fatal(err)
	}
	server, err := host.CreateInstance(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	if err = server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var listener net.Listener
	for {
		listener, err = server.Listen("tcp4", ":0")
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatal(err)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	defer listener.Close()
	pc, err := server.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	runtime.ReadMemStats(&reference)
	t.Logf("reference startup=%s heap_alloc=%d heap_sys=%d", time.Since(started), reference.HeapAlloc, reference.HeapSys)
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "controlled-easytier", "type": "easytier", "network-name": "clash-interop",
		"network-secret": "local-fixture-only", "hostname": "client", "ipv4": "10.144.0.102/24",
		"peers":       []string{fmt.Sprintf("tcp://127.0.0.1:%d", sockets.listenerPort(t))},
		"no-listener": true, "disable-p2p": true, "enable-encryption": true,
		"state-dir": stateDir, "udp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: netip.MustParseAddr("10.144.0.101"), DstPort: uint16(listener.Addr().(*net.TCPAddr).Port)}
	var conn C.Conn
	for {
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		conn, err = proxy.DialContext(attempt, metadata)
		stop()
		if err == nil {
			break
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("EasyTier TCP: %v (%v)", err, ctx.Err())
		}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("clash-easytier-tcp-"), 4096)
	writeResult := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); writeResult <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TCP payload differs")
	}
	udpMetadata := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstIP: metadata.DstIP, DstPort: uint16(pc.LocalAddr().(*net.UDPAddr).Port)}
	clientPC, err := proxy.ListenPacketContext(ctx, udpMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clientPC.Close()
	if err := clientPC.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(metadata.DstIP, udpMetadata.DstPort))
	udpPayload := bytes.Repeat([]byte("clash-easytier-udp"), 75)
	if _, err := clientPC.WriteTo(udpPayload, destination); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, source, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], udpPayload) || source.String() != destination.String() {
		t.Fatalf("UDP echo mismatch: bytes=%d source=%s", n, source)
	}
	runtime.ReadMemStats(&client)
	t.Logf("pair elapsed=%s heap_alloc_before=%d reference=%d pair=%d heap_sys=%d total_alloc_delta=%d", time.Since(started), before.HeapAlloc, reference.HeapAlloc, client.HeapAlloc, client.HeapSys, client.TotalAlloc-before.TotalAlloc)
}

type easyTierReferenceSockets struct {
	netstd.SocketFactory
	mu   sync.Mutex
	port int
}

func (s *easyTierReferenceSockets) ListenTCP(ctx context.Context, options platform.TCPListenOptions) (net.Listener, error) {
	listener, err := s.SocketFactory.ListenTCP(ctx, options)
	if err == nil && options.Purpose == platform.TCPListenDirect {
		s.mu.Lock()
		s.port = listener.Addr().(*net.TCPAddr).Port
		s.mu.Unlock()
	}
	return listener, err
}

func (s *easyTierReferenceSockets) listenerPort(t *testing.T) int {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.port == 0 {
		t.Fatal("EasyTier reference did not listen")
	}
	return s.port
}

package clash

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"golang.org/x/sys/unix"
)

const (
	heldConnectionCount        = 100
	heldConnectionStacksBudget = 27 << 10
	heldConnectionHeapBudget   = 24 << 10
	heldConnectionChildEnv     = "CLASH_HELD_CONNECTION_BUDGET_CHILD"
	heldConnectionSampleLine   = "HELD-CONNECTION-SAMPLE"
)

type heldConnectionSample struct {
	heap, stacks uint64
	goroutines   int
}

func sampleHeldConnections() heldConnectionSample {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	s := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/memory/classes/heap/stacks:bytes"}}
	metrics.Read(s)
	return heldConnectionSample{s[0].Value.Uint64(), s[1].Value.Uint64(), runtime.NumGoroutine()}
}

func tunPhone(t *testing.T, fd int) outbound.IPStack {
	t.Helper()
	stack, err := newGoIPStack(outbound.GoIPStackOptions{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "phone")
	t.Cleanup(func() { _ = stack.Close(); _ = file.Close() })
	go func() {
		buffers, sizes := [][]byte{make([]byte, 4+65535)}, []int{0}
		for {
			count, err := stack.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			for i := 0; i < count; i++ {
				packet := buffers[i][:4+sizes[i]]
				family := uint32(unix.AF_INET)
				if packet[4]>>4 == 6 {
					family = unix.AF_INET6
				}
				binary.BigEndian.PutUint32(packet, family)
				if _, err := file.Write(packet); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		buffer := make([]byte, 4+65535)
		for {
			size, err := file.Read(buffer)
			if err != nil {
				return
			}
			_, _ = stack.Write([][]byte{buffer[:size]}, 4)
		}
	}()
	return stack
}

func heldConnectionHostAddress() netip.Addr {
	benchmarking := netip.MustParsePrefix("198.18.0.0/15")
	interfaces, _ := net.Interfaces()
	for _, ifc := range interfaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, _ := ifc.Addrs()
		for _, a := range addresses {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLinkLocalUnicast() || benchmarking.Contains(prefix.Addr()) {
				continue
			}
			return prefix.Addr()
		}
	}
	return netip.Addr{}
}

func TestAHeldConnectionStaysWithinItsBudget(t *testing.T) {
	if os.Getenv(heldConnectionChildEnv) == "1" {
		measureHeldConnections(t)
		return
	}
	if heldConnectionHostAddress() == (netip.Addr{}) {
		t.Skip("no IPv4 address on a broadcast interface that is up")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestAHeldConnectionStaysWithinItsBudget$", "-test.count=1", "-test.v")
	child.Env = append(os.Environ(), heldConnectionChildEnv+"=1")
	out, err := child.CombinedOutput()
	var stacks, heap int64
	var goroutines float64
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, heldConnectionSampleLine); i >= 0 {
			_, scanErr := fmt.Sscanf(line[i:], heldConnectionSampleLine+" stacks=%d heap=%d goroutines=%f", &stacks, &heap, &goroutines)
			found = scanErr == nil
		}
	}
	if err != nil || !found {
		t.Fatalf("the measuring process failed (%v):\n%s", err, out)
	}
	t.Logf("a held connection keeps %d B of stacks (budget %d) and %d B of heap (budget %d), %.2f goroutines, both sides",
		stacks, heldConnectionStacksBudget, heap, heldConnectionHeapBudget, goroutines)
	if goroutines < 1.9 {
		t.Fatalf("%.2f goroutines a connection at the sample, want 2: the flows were not all held", goroutines)
	}
	if stacks > heldConnectionStacksBudget {
		t.Errorf("a held connection keeps %d B of goroutine stacks, over its %d B budget: a goroutine that parks for the connection's life is parked deeper than it was -- the flow's preparation frame back under its relay (tunnel/clash_tcp_flow_cleanup.go) puts the forwarder at 16 KiB", stacks, heldConnectionStacksBudget)
	}
	if heap > heldConnectionHeapBudget {
		t.Errorf("a held connection keeps %d B of live heap, over its %d B budget", heap, heldConnectionHeapBudget)
	}
}

func measureHeldConnections(t *testing.T) {
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-held-budget-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	address := heldConnectionHostAddress()
	if !address.IsValid() {
		t.Skip("no IPv4 address on an interface that is up")
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	var held sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			held.Lock()
			accepted = append(accepted, conn)
			held.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		held.Lock()
		for _, conn := range accepted {
			_ = conn.Close()
		}
		held.Unlock()
	})
	config := "mode: rule\nlog-level: info\n" +
		"tun:\n  enable: true\n" +
		"rules:\n  - MATCH,DIRECT\n"
	finalized, err := FinalizeForIOS(config, "{}")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	platform := &fdPlatform{recordingPlatform: recordingPlatform{lines: make(chan string, 4096), underNetworkExtension: true}, fd: int32(fds[0])}
	go func() {
		for range platform.lines {
		}
	}()
	svc, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(finalized.Value); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	phone := tunPhone(t, fds[1])
	time.Sleep(time.Second)

	before := sampleHeldConnections()
	remote := netip.AddrPortFrom(address, uint16(listener.Addr().(*net.TCPAddr).Port))
	conns := make([]net.Conn, 0, heldConnectionCount)
	for i := 0; i < heldConnectionCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := phone.DialTCP(ctx, "tcp4", netip.AddrPort{}, remote)
		cancel()
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if _, err := fmt.Fprintf(conn, "GET /held/%d HTTP/1.1\r\nHost: held\r\n\r\n", i); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	t.Cleanup(func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		held.Lock()
		n := len(accepted)
		held.Unlock()
		if n == heldConnectionCount {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listener holds %d of %d connections", n, heldConnectionCount)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	after := sampleHeldConnections()
	stacks := (int64(after.stacks) - int64(before.stacks)) / heldConnectionCount
	heap := (int64(after.heap) - int64(before.heap)) / heldConnectionCount
	fmt.Printf("%s stacks=%d heap=%d goroutines=%.2f\n", heldConnectionSampleLine, stacks, heap,
		float64(after.goroutines-before.goroutines)/heldConnectionCount)
}

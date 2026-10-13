package outbound

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	amneziav3 "github.com/metacubex/amneziawg-go/device"
	amnezia "github.com/metacubex/amneziawg-go/device_v1"
	"github.com/metacubex/wireguard-go/device"
)


func clashProbeDial(node C.ProxyAdapter) {
	ctx, cancel := context.WithTimeout(probeKind(), 300*time.Millisecond)
	defer cancel()
	if conn, err := node.DialContext(ctx, clashTCPMetadata()); err == nil {
		_ = conn.Close()
	}
}

type clashReleaseCase struct {
	name  string
	parse func(t *testing.T) (ProxyAdapter, func() int)
}

func clashGoroutinesDownTo(want int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		runtime.GC()
		if now := runtime.NumGoroutine(); now <= want || time.Now().After(deadline) {
			return now
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func clashCollected[T any](p *T) <-chan struct{} {
	collected := make(chan struct{})
	runtime.AddCleanup(p, func(c chan struct{}) { close(c) }, collected)
	return collected
}

func clashWatchBuilt(t *testing.T, node ProxyAdapter) []<-chan struct{} {
	t.Helper()
	switch node := node.(type) {
	case *WireGuard:
		built := node.clashDevice.built.Load()
		if built == nil {
			t.Fatal("nothing built")
		}
		watched := []<-chan struct{}{clashCollected(built)}
		switch device := built.device.(type) {
		case *device.Device:
			watched = append(watched, clashCollected(device))
		case *amneziav3.Device:
			watched = append(watched, clashCollected(device))
		case *amnezia.Device:
			watched = append(watched, clashCollected(device))
		default:
			t.Fatalf("unexpected device %T", device)
		}
		return watched
	case *Masque:
		built := node.clashStack.built.Load()
		if built == nil {
			t.Fatal("nothing built")
		}
		return []<-chan struct{}{clashCollected(built)}
	}
	t.Fatalf("unexpected node %T", node)
	return nil
}

func clashReleaseCases() []clashReleaseCase {
	wireGuard := func(amnezia *AmneziaWGOption) func(t *testing.T) (ProxyAdapter, func() int) {
		return func(t *testing.T) (ProxyAdapter, func() int) {
			option := clashWireGuardOption()
			option.Port = clashClosedPort(t, "udp")
			option.AmneziaWGOption = amnezia
			node, err := NewWireGuard(option)
			if err != nil {
				t.Fatal(err)
			}
			return node, node.clashDeviceBuilds
		}
	}
	return []clashReleaseCase{
		{name: "wireguard", parse: wireGuard(nil)},
		{name: "amneziawg", parse: wireGuard(&AmneziaWGOption{JC: 4, JMin: 40, JMax: 70})},
		{name: "amneziawg v3", parse: wireGuard(&AmneziaWGOption{Version: 3, JC: 4, JMin: 40, JMax: 70})},
		{name: "masque", parse: func(t *testing.T) (ProxyAdapter, func() int) {
			option := clashMasqueOption(t)
			option.Port = clashClosedPort(t, "udp")
			node, err := NewMasque(option)
			if err != nil {
				t.Fatal(err)
			}
			return node, node.clashStackBuilds
		}},
	}
}

func TestAReleasedNodeGoesBackToWhatItHeldWhenParsed(t *testing.T) {
	for _, tc := range clashReleaseCases() {
		t.Run(tc.name, func(t *testing.T) {
			inner, builds := tc.parse(t)
			node := NewAutoCloseProxyAdapter(inner)
			defer node.Close()
			heapParsed, goroutinesParsed := clashSettle()
			clashProbeDial(node)
			heapBuilt, goroutinesBuilt := clashSettle()
			if builds() != 1 {
				t.Fatalf("the first dial built %d times", builds())
			}
			watched := clashWatchBuilt(t, inner)
			if !ReleaseProbedSession(node) {
				t.Fatal("a node only a probe dialed, with nothing open, was not released")
			}
			goroutinesReleased := clashGoroutinesDownTo(goroutinesParsed, 3*time.Second)
			heapReleased, _ := clashSettle()
			t.Logf("parsed %d B / %d goroutines; built +%d B / +%d; released +%d B / +%d",
				heapParsed, goroutinesParsed, heapBuilt-heapParsed, goroutinesBuilt-goroutinesParsed,
				heapReleased-heapParsed, goroutinesReleased-goroutinesParsed)
			if goroutinesReleased > goroutinesParsed {
				t.Errorf("%d goroutines after the release, %d when parsed", goroutinesReleased, goroutinesParsed)
			}
			for i, collected := range watched {
				for attempt := 0; ; attempt++ {
					select {
					case <-collected:
					default:
						if attempt < 400 {
							runtime.GC()
							time.Sleep(5 * time.Millisecond)
							continue
						}
						t.Fatalf("what the node built (%d) is still held after the release", i)
					}
					break
				}
			}
			clashProbeDial(node)
			if builds() != 2 {
				t.Fatalf("the dial after the release built %d times in all, want 2", builds())
			}
		})
	}
}

func TestReleasingNodesAreNotNetworkResetters(t *testing.T) {
	for _, tc := range clashReleaseCases() {
		inner, _ := tc.parse(t)
		node := NewAutoCloseProxyAdapter(inner)
		if _, ok := node.(*autoCloseProxyAdapter).ProxyAdapter.(SessionReleaser); !ok {
			t.Errorf("%s does not release its sessions", tc.name)
		}
		if _, ok := AsNetworkResetter(node); ok {
			t.Errorf("%s became a network resetter", tc.name)
		}
		_ = node.Close()
	}
}

func TestReleasesRacingUncountedDialsLeaveNothingBehind(t *testing.T) {
	for _, tc := range clashReleaseCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, goroutinesBefore := clashSettle()
			inner, builds := tc.parse(t)
			if wireGuard, ok := inner.(*WireGuard); ok {
				wireGuard.option.RefreshServerIPInterval = 1
			}
			releaser, ok := inner.(SessionReleaser)
			if !ok {
				t.Fatalf("%s does not release its sessions", tc.name)
			}
			stop := make(chan struct{})
			var racing sync.WaitGroup
			for i := 0; i < 4; i++ {
				racing.Add(1)
				go func() {
					defer racing.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
						if conn, err := inner.DialContext(ctx, clashTCPMetadata()); err == nil {
							_ = conn.Close()
						}
						if pc, err := inner.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: clashTCPMetadata().DstIP, DstPort: 53}); err == nil {
							_ = pc.Close()
						}
						cancel()
					}
				}()
			}
			racing.Add(1)
			go func() {
				defer racing.Done()
				for {
					select {
					case <-stop:
						return
					case <-time.After(20 * time.Millisecond):
						releaser.ReleaseSessions()
					}
				}
			}()
			time.Sleep(1500 * time.Millisecond)
			close(stop)
			racing.Wait()
			t.Logf("%d builds while racing", builds())
			_ = inner.Close()
			releaser.ReleaseSessions()
			if goroutinesAfter := clashGoroutinesDownTo(goroutinesBefore+2, 3*time.Second); goroutinesAfter > goroutinesBefore+2 {
				t.Fatalf("goroutines %d before the node, %d after it closed", goroutinesBefore, goroutinesAfter)
			}
		})
	}
}

func TestAWireGuardReleaseLeavesADeviceBeingConfigured(t *testing.T) {
	option := clashWireGuardOption()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	clashProbeDial(node)
	releaser, ok := any(node).(SessionReleaser)
	if !ok {
		t.Fatal("WireGuard does not release its sessions")
	}
	node.initMutex.Lock()
	released := make(chan struct{})
	go func() {
		releaser.ReleaseSessions()
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		node.initMutex.Unlock()
		t.Fatal("a release waited for a dial configuring the device")
	}
	node.initMutex.Unlock()
	if !node.initOk.Load() {
		t.Fatal("the release dropped a device a dial was configuring")
	}
	releaser.ReleaseSessions()
	if node.initOk.Load() {
		t.Fatal("an idle device was not released")
	}
}

func TestARebuildRightAfterAReleaseWaitsOutTheRehandshakeGap(t *testing.T) {
	option := clashWireGuardOption()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if err := node.clashBuildDevice(); err != nil {
		t.Fatal(err)
	}
	node.ReleaseSessions()
	node.clashDevice.mu.Lock()
	released := node.clashDevice.released
	node.clashDevice.mu.Unlock()
	if err := node.clashBuildDevice(); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(released); waited < clashRehandshakeGap {
		t.Fatalf("a rebuild right after a release came %v after it, want at least %v", waited, clashRehandshakeGap)
	}
	node.ReleaseSessions()
	time.Sleep(clashRehandshakeGap)
	started := time.Now()
	if err := node.clashBuildDevice(); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(started); waited >= clashRehandshakeGap/2 {
		t.Fatalf("a rebuild after the gap waited %v", waited)
	}
	if builds := node.clashDeviceBuilds(); builds != 3 {
		t.Fatalf("%d builds, want 3", builds)
	}
}

func TestAWireGuardNodeKeepsItsDeviceWhileItsResolverHoldsAConnection(t *testing.T) {
	option := clashWireGuardOption()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	clashProbeDial(node)
	resolverDialer := clashResolverDialer{node}
	pc, err := resolverDialer.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("10.0.0.53"), DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	if node.ReleaseSessions() || !node.initOk.Load() {
		t.Fatal("released the device under a connection its resolver holds")
	}
	_ = pc.Close()
	if !node.ReleaseSessions() || node.initOk.Load() {
		t.Fatal("the device stayed after its resolver's connection closed")
	}
}

func TestAResolverDialDuringAReleaseGetsALiveDevice(t *testing.T) {
	option := clashWireGuardOption()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	clashProbeDial(node)

	type dialed struct {
		pc  C.PacketConn
		err error
	}
	result := make(chan dialed, 1)
	clashWireGuardReleaseChecked = func() {
		go func() {
			pc, err := clashResolverDialer{node}.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("10.0.0.53"), DstPort: 53})
			result <- dialed{pc, err}
		}()
		time.Sleep(100 * time.Millisecond)
	}
	defer func() { clashWireGuardReleaseChecked = nil }()
	node.ReleaseSessions()

	got := <-result
	if got.err != nil {
		t.Fatalf("the resolver dial failed: %v", got.err)
	}
	defer got.pc.Close()
	if _, err := got.pc.WriteTo([]byte{0}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 53), Port: 53}); err != nil {
		t.Fatalf("the resolver's connection is on a closed device: %v", err)
	}
}

func TestAMasqueReleaseRetryWaitsForTheCancelledRun(t *testing.T) {
	option := clashMasqueOption(t)
	option.Port = clashClosedPort(t, "udp")
	node, err := NewMasque(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	clashProbeDial(node)
	if node.clashStack.built.Load() == nil {
		t.Skip("the probe dial built no stack (L4 mode or the build failed)")
	}
	node.clashStack.mu.Lock()
	node.clashStack.runCancel = nil
	node.clashStack.mu.Unlock()
	node.running.Store(true)
	if node.ReleaseSessions() || node.clashStack.built.Load() == nil {
		t.Fatal("the stack was closed under a run that has not stopped")
	}
	node.running.Store(false)
	if !node.ReleaseSessions() || node.clashStack.built.Load() != nil {
		t.Fatal("the stack stayed after the run stopped")
	}
}

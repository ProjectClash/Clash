package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func TestWireGuardFirstDialsBuildOneDevice(t *testing.T) {
	_, goroutinesBefore := clashSettle()
	option := clashWireGuardOption()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	if builds := node.clashDeviceBuilds(); builds != 0 {
		t.Fatalf("parsing built %d devices", builds)
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
	if builds := node.clashDeviceBuilds(); builds != 1 {
		t.Fatalf("16 racing first dials built %d devices, want 1", builds)
	}
	udpCtx, udpCancel := context.WithTimeout(context.Background(), time.Second)
	defer udpCancel()
	if pc, err := node.ListenPacketContext(udpCtx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 53}); err != nil {
		t.Fatalf("a packet listen on a built device: %v", err)
	} else {
		_ = pc.Close()
	}
	if builds := node.clashDeviceBuilds(); builds != 1 {
		t.Fatalf("a later packet listen built another device (%d)", builds)
	}
	_ = node.Close()
	if _, goroutinesAfter := clashSettle(); goroutinesAfter > goroutinesBefore+2 {
		t.Fatalf("goroutines %d before the node, %d after it closed", goroutinesBefore, goroutinesAfter)
	}
}

func TestWireGuardClosedBeforeItsFirstDialBuildsNothing(t *testing.T) {
	option := clashWireGuardOption()
	option.Server = "closed-node.invalid"
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := node.DialContext(ctx, clashTCPMetadata()); !errors.Is(err, context.Canceled) {
		t.Fatalf("a dial after Close: %v, want context.Canceled", err)
	}
	if builds := node.clashDeviceBuilds(); builds != 0 {
		t.Fatalf("a closed node built %d devices", builds)
	}
}

func TestWireGuardDialsRacingCloseLeaveNoDevice(t *testing.T) {
	_, goroutinesBefore := clashSettle()
	for round := 0; round < 5; round++ {
		option := clashWireGuardOption()
		option.Port = clashClosedPort(t, "udp")
		node, err := NewWireGuard(option)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		var racing sync.WaitGroup
		for i := 0; i < 4; i++ {
			racing.Add(1)
			go func() {
				defer racing.Done()
				if conn, err := node.DialContext(ctx, clashTCPMetadata()); err == nil {
					_ = conn.Close()
				}
			}()
		}
		racing.Add(1)
		go func() {
			defer racing.Done()
			_ = node.Close()
		}()
		racing.Wait()
		cancel()
		if builds := node.clashDeviceBuilds(); builds > 1 {
			t.Fatalf("round %d: %d devices built", round, builds)
		}
	}
	if _, goroutinesAfter := clashSettle(); goroutinesAfter > goroutinesBefore+2 {
		t.Fatalf("goroutines %d before, %d after five closed nodes", goroutinesBefore, goroutinesAfter)
	}
}

func TestAFailedRebuildAfterAnIdleReleaseIsNotKept(t *testing.T) {
	option := clashWireGuardOption()
	option.MTU = 20
	option.IPStack.Mode = ipStackMips
	node, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if err := node.init0(context.Background()); err == nil {
		t.Fatal("a stack mipstack refuses was built")
	}
	if node.initErr == nil {
		t.Fatal("a node that never built did not keep its failure, as upstream's does")
	}
	node.initErr = nil
	node.clashDevice.mu.Lock()
	node.clashDevice.releases = 1
	node.clashDevice.mu.Unlock()
	if err := node.init0(context.Background()); err == nil {
		t.Fatal("a stack mipstack refuses was built")
	}
	if node.initErr != nil {
		t.Fatalf("a failed rebuild after a release was kept: %v", node.initErr)
	}
}

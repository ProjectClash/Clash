package clash

import (
	"net"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/component/dialer"
)

type hookPlatform struct {
	recordingPlatform
	enabled    bool
	gotFd      int32
	callCount  int
	controlErr error
}

func (p *hookPlatform) UsePlatformAutoDetectInterfaceControl() bool { return p.enabled }
func (p *hookPlatform) AutoDetectInterfaceControl(fd int32) error {
	p.callCount++
	p.gotFd = fd
	return p.controlErr
}

func withPublishedPath(t *testing.T, index int32) {
	t.Helper()
	previous := publishedInterfaceIndex.Load()
	t.Cleanup(func() {
		publishedInterfaceIndex.Store(previous)
		noPathDialsLogged.Store(false)
	})
	publishedInterfaceIndex.Store(index)
}

func TestInstallSocketHook(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	withPublishedPath(t, 5)

	dialer.DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error { return nil }
	installSocketHook(&hookPlatform{enabled: false})
	if dialer.DefaultSocketHook != nil {
		t.Fatal("opt-out must clear DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("a platform that does not bind its sockets must still get the physical-address transform")
	}
	installSocketHook(nil)
	if dialer.DefaultAddressTransform != nil {
		t.Fatal("no platform must clear DefaultAddressTransform")
	}

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("opt-in must install DefaultAddressTransform")
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	if err := dialer.DefaultSocketHook("udp", "1.1.1.1:53", raw); err != nil {
		t.Fatalf("hook returned error: %v", err)
	}
	if platform.callCount != 1 {
		t.Fatalf("AutoDetectControl called %d times, want 1", platform.callCount)
	}
	if platform.gotFd <= 0 {
		t.Fatalf("AutoDetectControl got fd %d, want a valid descriptor", platform.gotFd)
	}
}

func TestSocketHookLeavesLoopbackUnscoped(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	withPublishedPath(t, 5)

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	rawConnOf := func(t *testing.T) syscall.RawConn {
		t.Helper()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatalf("syscall conn: %v", err)
		}
		return raw
	}

	for _, address := range []string{
		"127.0.0.1:1053", "[::1]:53", "localhost:53", listener.Addr().String(),
		"169.254.1.1:53",
		"[fe80::1]:53",
		"224.0.0.251:5353",
		"0.0.0.0:0",
	} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before {
			t.Fatalf("%q was scoped to an interface; upstream leaves a non-global-unicast destination unbound", address)
		}
	}

	for _, address := range []string{"223.5.5.5:53", "[2400:3200::1]:53", "example.com:443"} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before+1 {
			t.Fatalf("%q must still be scoped: callCount %d -> %d", address, before, platform.callCount)
		}
	}

	before := platform.callCount
	if err := dialer.DefaultSocketHook("udp", "", rawConnOf(t)); err != nil {
		t.Fatalf("hook returned an error for an empty address: %v", err)
	}
	if platform.callCount != before+1 {
		t.Fatalf("an address the hook cannot read must stay scoped: callCount %d -> %d", before, platform.callCount)
	}
}

func TestSocketHookDialsUnboundWhenNoPathIsPublished(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	previousIndex := publishedInterfaceIndex.Load()
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
		publishedInterfaceIndex.Store(previousIndex)
		noPathDialsLogged.Store(false)
	})

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()
	rawConnOf := func(t *testing.T) syscall.RawConn {
		t.Helper()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatalf("syscall conn: %v", err)
		}
		return raw
	}

	const routable = "93.184.216.34:443"

	publishedInterfaceIndex.Store(0)
	noPathDialsLogged.Store(false)
	before := platform.callCount
	if err := dialer.DefaultSocketHook("tcp", routable, rawConnOf(t)); err != nil {
		t.Fatalf("with no published path the dial must proceed unbound, got %v", err)
	}
	if platform.callCount != before {
		t.Fatal("with no published path the platform must not be asked to scope the socket")
	}

	publishedInterfaceIndex.Store(7)
	before = platform.callCount
	if err := dialer.DefaultSocketHook("tcp", routable, rawConnOf(t)); err != nil {
		t.Fatalf("with a published path the socket must still be scoped, got %v", err)
	}
	if platform.callCount != before+1 {
		t.Fatal("with a published path the platform must scope the socket")
	}
}

func TestPathMonitorPublishesTheIndexTheHookReads(t *testing.T) {
	previousIndex := publishedInterfaceIndex.Load()
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	flushInterfaceCache = func() {}
	resetResolverConnection = func() {}
	closeTrackedConnections = func() {}
	oldSessions := resetOutboundSessions
	resetOutboundSessions = func() {}
	clearResolverCache = func() {}
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		publishedInterfaceIndex.Store(previousIndex)
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		resetOutboundSessions = oldSessions
		readPhysicalResolvers = previousRead
	})

	updater := &interfaceUpdater{bindDefaultInterface: true}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if got := publishedInterfaceIndex.Load(); got != 5 {
		t.Fatalf("published index = %d, want 5", got)
	}
	updater.UpdateDefaultInterface("", 0, false, false, false, false)
	if got := publishedInterfaceIndex.Load(); got != 0 {
		t.Fatalf("an unsatisfied path must publish index 0, got %d", got)
	}
}

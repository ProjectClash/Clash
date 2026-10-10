package dialer

import (
	"context"
	"net/netip"
	"syscall"
	"testing"
)

func TestListenPacketLeavesALoopbackPeerOutOfTheSocketHook(t *testing.T) {
	orig := DefaultSocketHook
	origScoping := SocketHookScopesInterfaceOnly
	origIface := DefaultInterface.Load()
	t.Cleanup(func() {
		DefaultSocketHook = orig
		SocketHookScopesInterfaceOnly = origScoping
		DefaultInterface.Store(origIface)
	})
	SocketHookScopesInterfaceOnly = true
	DefaultInterface.Store("")

	calls := 0
	DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error {
		calls++
		return nil
	}

	for _, peer := range []string{"127.0.0.1:1053", "[::1]:53", "169.254.1.1:53", "224.0.0.251:5353"} {
		before := calls
		pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort(peer))
		if err != nil {
			t.Fatalf("ListenPacket toward %s: %v", peer, err)
		}
		pc.Close()
		if calls != before {
			t.Errorf("peer %s went through the socket hook; upstream leaves a non-global-unicast peer unscoped", peer)
		}
	}

	before := calls
	pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("223.5.5.5:53"))
	if err != nil {
		t.Fatalf("ListenPacket toward a routable peer: %v", err)
	}
	pc.Close()
	if calls != before+1 {
		t.Errorf("a routable peer must still be scoped by the hook: calls %d -> %d", before, calls)
	}

	before = calls
	pc, err = ListenPacket(context.Background(), "udp", "", netip.AddrPort{})
	if err != nil {
		t.Fatalf("ListenPacket with no peer: %v", err)
	}
	pc.Close()
	if calls != before+1 {
		t.Errorf("a listener with no peer must still be scoped by the hook: calls %d -> %d", before, calls)
	}
}

func TestASocketHookThatDoesNotOnlyScopeStillSeesEveryPeer(t *testing.T) {
	orig := DefaultSocketHook
	origScoping := SocketHookScopesInterfaceOnly
	origIface := DefaultInterface.Load()
	t.Cleanup(func() {
		DefaultSocketHook = orig
		SocketHookScopesInterfaceOnly = origScoping
		DefaultInterface.Store(origIface)
	})
	DefaultInterface.Store("")
	SocketHookScopesInterfaceOnly = false

	calls := 0
	DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error {
		calls++
		return nil
	}

	for _, peer := range []string{"127.0.0.1:1053", "[::1]:53", "169.254.1.1:53", "224.0.0.251:5353"} {
		before := calls
		pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort(peer))
		if err != nil {
			t.Fatalf("ListenPacket toward %s: %v", peer, err)
		}
		pc.Close()
		if calls != before+1 {
			t.Errorf("peer %s skipped a hook that never said it only scopes; the exemption for an "+
				"interface-scoping hook must not reach a hook installed to observe sockets", peer)
		}
	}
}

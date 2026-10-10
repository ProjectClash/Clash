//go:build darwin

package clash

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
)

func hostLANFace(t *testing.T) lanFace {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := candidate.Addrs()
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			return lanFace{name: candidate.Name, index: candidate.Index, addr: prefix.Addr()}
		}
	}
	t.Skip("no up interface with an IPv4 address on this machine")
	return lanFace{}
}

func useLANFacesForTest(t *testing.T, faces func() []lanFace) {
	t.Helper()
	prior, priorEnabled, priorWatcher := currentLANFaces, lanCompanionsEnabled, startLANWatcher
	currentLANFaces, lanCompanionsEnabled = faces, true
	startLANWatcher = func() *os.File { return nil }
	t.Cleanup(func() {
		stopLANTimersForTest()
		currentLANFaces, lanCompanionsEnabled, startLANWatcher = prior, priorEnabled, priorWatcher
	})
}

func TestLANCompanionsAreOffOutsideIOS(t *testing.T) {
	face := hostLANFace(t)
	prior := currentLANFaces
	currentLANFaces = func() []lanFace { return []lanFace{face} }
	t.Cleanup(func() { currentLANFaces = prior })
	if lanCompanionsEnabled {
		t.Skip("this build is the iPhone's")
	}
	installScopeHooksForTest(t)
	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	if merged, ok := listener.(*companionListener); ok && len(merged.lanCompanionsOn(face)) != 0 {
		t.Fatal("a LAN companion on the Mac")
	}
}

func TestASelfConnectionToALANAddressReachesTheLoopbackBoundCompanion(t *testing.T) {
	face := hostLANFace(t)
	companion, err := listenLANCompanion("tcp4", net.JoinHostPort(face.addr.String(), "0"))
	if err != nil {
		t.Fatalf("listenLANCompanion: %v", err)
	}
	defer companion.Close()
	if got := boundInterfaceOf(t, tcpListenerRaw(t, companion), false); got != requireLoopbackIndex(t) {
		t.Fatalf("IP_BOUND_IF = %d, want the loopback interface", got)
	}
	dialAndAccept(t, companion, companion.Addr().String())
}

func TestLANFacesAreTheUpLANInterfacesOtherThanTheDefault(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	given := []interfaceWithAddrs{
		{name: "pdp_ip0", index: 3, flags: up, addrs: []string{"10.1.2.3/32"}},
		{name: "en0", index: 4, flags: up, addrs: []string{"192.168.1.5/24", "fe80::1/64"}},
		{name: "bridge100", index: 9, flags: up, addrs: []string{"172.20.10.1/28", "fd00::1/64"}},
		{name: "en2", index: 5, flags: net.FlagBroadcast, addrs: []string{"192.168.9.9/24"}},
		{name: "utun4", index: 12, flags: up | net.FlagPointToPoint, addrs: []string{"198.18.0.1/16"}},
		{name: "awdl0", index: 7, flags: up, addrs: []string{"169.254.1.1/16"}},
		{name: "lo0", index: 1, flags: up | net.FlagLoopback, addrs: []string{"127.0.0.1/8"}},
	}
	faces := lanFacesOf(given, 4)
	want := map[lanFace]bool{
		{name: "bridge100", index: 9, addr: netip.MustParseAddr("172.20.10.1")}: true,
		{name: "bridge100", index: 9, addr: netip.MustParseAddr("fd00::1")}:     true,
	}
	if len(faces) != len(want) {
		t.Fatalf("faces = %v, want %v", faces, want)
	}
	for _, face := range faces {
		if !want[face] {
			t.Errorf("unexpected face %v", face)
		}
	}
	if faces := lanFacesOf(given, 3); len(faces) != 3 {
		t.Fatalf("with pdp_ip0 the default, faces = %v, want en0 and bridge100", faces)
	}
}

func TestAWildcardListenerGainsACompanionOnEachLANFace(t *testing.T) {
	face := hostLANFace(t)
	useLANFacesForTest(t, func() []lanFace { return []lanFace{face} })
	installScopeHooksForTest(t)

	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	merged, ok := listener.(*companionListener)
	if !ok {
		t.Fatalf("listener is %T, want *companionListener", listener)
	}
	companions := merged.lanCompanionsOn(face)
	if len(companions) != 1 {
		t.Fatalf("%d companions on %s (%v), want 1", len(companions), face.name, face.addr)
	}
	if got := boundInterfaceOf(t, tcpListenerRaw(t, companions[0]), false); got != requireLoopbackIndex(t) {
		t.Fatalf("companion IP_BOUND_IF = %d, want the loopback interface", got)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dialAndAccept(t, listener, net.JoinHostPort(face.addr.String(), port))
}

func TestLANCompanionsFollowTheInterfaces(t *testing.T) {
	face := hostLANFace(t)
	var faces []lanFace
	useLANFacesForTest(t, func() []lanFace { return faces })
	installScopeHooksForTest(t)

	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	merged := listener.(*companionListener)
	if len(merged.lanCompanionsOn(face)) != 0 {
		t.Fatal("a companion before the interface is there")
	}

	faces = []lanFace{face}
	reconcileLANCompanions()
	if len(merged.lanCompanionsOn(face)) != 1 {
		t.Fatalf("no companion on %s after it appeared", face.name)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dialAndAccept(t, listener, net.JoinHostPort(face.addr.String(), port))

	faces = nil
	reconcileLANCompanions()
	if len(merged.lanCompanionsOn(face)) != 0 {
		t.Fatalf("the companions on %s outlived the interface", face.name)
	}
	again, err := net.Listen("tcp4", net.JoinHostPort(face.addr.String(), port))
	if err != nil {
		t.Fatalf("the removed companion still holds %s:%s: %v", face.addr, port, err)
	}
	again.Close()
}

func TestAClosedListenerLeavesTheLANCompanionRegistry(t *testing.T) {
	face := hostLANFace(t)
	useLANFacesForTest(t, func() []lanFace { return []lanFace{face} })
	installScopeHooksForTest(t)

	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	merged := listener.(*companionListener)
	listener.Close()
	lanCompanionRegistry.mu.Lock()
	_, still := lanCompanionRegistry.listeners[merged]
	lanCompanionRegistry.mu.Unlock()
	if still {
		t.Fatal("a closed listener is still reconciled")
	}
}

func TestNoLANCompanionsWhileTheDefaultIsUnknown(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	given := []interfaceWithAddrs{
		{name: "en0", index: 4, flags: up, addrs: []string{"192.168.1.5/24"}},
		{name: "bridge100", index: 9, flags: up, addrs: []string{"172.20.10.1/28"}},
	}
	if faces := lanFacesOf(given, 0); len(faces) != 0 {
		t.Fatalf("faces with no default = %v, want none", faces)
	}
}

type fakeRouteSocket struct {
	reads []func([]byte) (int, error)
}

func (f *fakeRouteSocket) Read(b []byte) (int, error) {
	if len(f.reads) == 0 {
		return 0, os.ErrClosed
	}
	next := f.reads[0]
	f.reads = f.reads[1:]
	return next(b)
}

func TestTheRouteWatcherReadsOnAfterAReadError(t *testing.T) {
	message := func(kind byte) func([]byte) (int, error) {
		return func(b []byte) (int, error) { b[3] = kind; return 4, nil }
	}
	failing := func(err error) func([]byte) (int, error) {
		return func([]byte) (int, error) { return 0, err }
	}
	socket := &fakeRouteSocket{reads: []func([]byte) (int, error){
		failing(syscall.ENOBUFS),
		failing(syscall.EINTR),
		message(byte(syscall.RTM_NEWADDR)),
	}}
	scheduled := 0
	var waited []time.Duration
	done := make(chan struct{})
	go func() {
		pumpRouteMessages(socket, func() { scheduled++ }, func(d time.Duration) { waited = append(waited, d) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher did not end when the socket closed")
	}
	if scheduled != 3 {
		t.Fatalf("scheduled %d reconciles, want 3: the watcher stopped at an error", scheduled)
	}
	if len(waited) != 2 {
		t.Fatalf("waited %v, want a back-off after each of the 2 errors", waited)
	}
}

func TestAnOlderReconcileDoesNotUndoANewerOne(t *testing.T) {
	face := hostLANFace(t)
	var mu sync.Mutex
	calls := 0
	entered, release := make(chan struct{}), make(chan struct{})
	useLANFacesForTest(t, func() []lanFace {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch n {
		case 1:
			return nil
		case 2:
			close(entered)
			<-release
			return nil
		default:
			return []lanFace{face}
		}
	})
	installScopeHooksForTest(t)
	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	merged := listener.(*companionListener)

	older := make(chan struct{})
	go func() { reconcileLANCompanions(); close(older) }()
	<-entered
	newer := make(chan struct{})
	go func() { reconcileLANCompanions(); close(newer) }()
	select {
	case <-newer:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-older
	<-newer
	if len(merged.lanCompanionsOn(face)) != 1 {
		t.Fatal("the older reconcile closed the companion the newer one made")
	}
}

func TestAFailedLANCompanionIsRetried(t *testing.T) {
	face := hostLANFace(t)
	useLANFacesForTest(t, func() []lanFace { return []lanFace{face} })
	installScopeHooksForTest(t)
	priorListen, priorDelay := listenLANCompanion, lanRetryDelay
	var mu sync.Mutex
	failures := 2
	listenLANCompanion = func(network, address string) (net.Listener, error) {
		mu.Lock()
		defer mu.Unlock()
		if failures > 0 {
			failures--
			return nil, syscall.EADDRNOTAVAIL
		}
		return priorListen(network, address)
	}
	lanRetryDelay = func(int) time.Duration { return 10 * time.Millisecond }
	t.Cleanup(func() { listenLANCompanion, lanRetryDelay = priorListen, priorDelay })

	listener, err := inbound.NewListenConfig().Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	merged := listener.(*companionListener)
	deadline := time.Now().Add(2 * time.Second)
	for len(merged.lanCompanionsOn(face)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the companion that failed to bind was never tried again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLANCompanionRetriesAreBounded(t *testing.T) {
	var delays []time.Duration
	for attempt := 0; attempt < 10; attempt++ {
		delay := defaultLANRetryDelay(attempt)
		if delay <= 0 {
			break
		}
		delays = append(delays, delay)
	}
	if len(delays) == 0 || len(delays) > lanRetryAttempts {
		t.Fatalf("retry delays %v, want between 1 and %d", delays, lanRetryAttempts)
	}
}

func TestALANCompanionClosesForTheReasonItHas(t *testing.T) {
	face := lanFace{name: "bridge100", index: 9, addr: netip.MustParseAddr("172.20.10.1")}
	for _, c := range []struct {
		defaultIndex int
		want         string
	}{
		{0, "default interface is not known"},
		{9, "now the default"},
		{4, "gone"},
	} {
		if got := lanCompanionCloseReason(face, c.defaultIndex); !strings.Contains(got, c.want) {
			t.Errorf("default %d: reason %q, want it to say %q", c.defaultIndex, got, c.want)
		}
	}
}

func stopLANTimersForTest() {
	lanCompanionRegistry.mu.Lock()
	defer lanCompanionRegistry.mu.Unlock()
	stopLANTimersLocked()
}

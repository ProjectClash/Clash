package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func withStrategy(t *testing.T, strategy NetworkStrategy, primary, fallback []InterfaceType, interfaces []NetworkInterface) {
	t.Helper()
	previousStrategy := NetworkStrategyValue.Load()
	previousPrimary := NetworkTypeValue.Load()
	previousFallback := FallbackNetworkTypeValue.Load()
	previousProvider := NetworkInterfaceProvider.Load()
	previousFallbackAt := networkLastFallback.Load()
	t.Cleanup(func() {
		NetworkStrategyValue.Store(previousStrategy)
		NetworkTypeValue.Store(previousPrimary)
		FallbackNetworkTypeValue.Store(previousFallback)
		NetworkInterfaceProvider.Store(previousProvider)
		networkLastFallback.Store(previousFallbackAt)
	})
	SetNetworkStrategy(strategy, primary, fallback)
	networkLastFallback.Store(time.Time{})
	if interfaces == nil {
		NetworkInterfaceProvider.Store(nil)
		return
	}
	NetworkInterfaceProvider.Store(func() []NetworkInterface { return interfaces })
}

func names(interfaces []NetworkInterface) []string {
	out := make([]string, 0, len(interfaces))
	for _, candidate := range interfaces {
		out = append(out, candidate.Name)
	}
	return out
}

func equalNames(got []NetworkInterface, want ...string) bool {
	actual := names(got)
	if len(actual) != len(want) {
		return false
	}
	for i := range want {
		if actual[i] != want[i] {
			return false
		}
	}
	return true
}

func sampleInterfaces() []NetworkInterface {
	return []NetworkInterface{
		{Index: 10, Name: "pdp_ip0", Type: InterfaceTypeCellular, Available: true, Metered: true},
		{Index: 4, Name: "en0", Type: InterfaceTypeWIFI, Available: true, Default: true},
		{Index: 1, Name: "lo0", Type: InterfaceTypeLoopback, Available: true},
		{Index: 12, Name: "utun4", Type: InterfaceTypeTunnel, Available: true, OwnTunnel: true},
		{Index: 13, Name: "en1", Type: InterfaceTypeWIFI, Available: false},
	}
}

func TestCandidateInterfacesExcludesOwnTunnelLoopbackAndUnavailable(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, sampleInterfaces())
	primary, fallback := candidateInterfaces()
	if len(fallback) != 0 {
		t.Fatalf("hybrid has no fallback set, got %v", names(fallback))
	}
	if !equalNames(primary, "en0", "pdp_ip0") {
		t.Fatalf("expected the default interface first then cellular, got %v", names(primary))
	}
}

func TestCandidateInterfacesDefaultStrategyTakesOnlyTheDefaultInterface(t *testing.T) {
	withStrategy(t, NetworkStrategyDefault, nil, nil, sampleInterfaces())
	primary, fallback := candidateInterfaces()
	if !equalNames(primary, "en0") || len(fallback) != 0 {
		t.Fatalf("expected en0 alone, got primary=%v fallback=%v", names(primary), names(fallback))
	}
}

func TestCandidateInterfacesWithoutADefaultKeepsEveryUsableInterface(t *testing.T) {
	interfaces := sampleInterfaces()
	interfaces[1].Default = false
	withStrategy(t, NetworkStrategyDefault, nil, nil, interfaces)
	primary, _ := candidateInterfaces()
	if !equalNames(primary, "en0", "pdp_ip0") {
		t.Fatalf("expected every usable interface, got %v", names(primary))
	}
}

func TestCandidateInterfacesFallbackSplitsPrimaryAndRest(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback, []InterfaceType{InterfaceTypeWIFI}, nil, sampleInterfaces())
	primary, fallback := candidateInterfaces()
	if !equalNames(primary, "en0") {
		t.Fatalf("expected wifi as primary, got %v", names(primary))
	}
	if !equalNames(fallback, "pdp_ip0") {
		t.Fatalf("expected cellular as fallback, got %v", names(fallback))
	}
}

func TestCandidateInterfacesFallbackTypeListNarrowsAndDeduplicates(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWIFI},
		[]InterfaceType{InterfaceTypeWIFI, InterfaceTypeCellular},
		sampleInterfaces())
	primary, fallback := candidateInterfaces()
	if !equalNames(primary, "en0") || !equalNames(fallback, "pdp_ip0") {
		t.Fatalf("expected en0 primary and pdp_ip0 fallback, got primary=%v fallback=%v", names(primary), names(fallback))
	}
}

func TestNetworkStrategyInertWithoutAProvider(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, nil)
	if networkStrategyActive() {
		t.Fatal("a strategy with no interface provider must be inert")
	}
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), "127.0.0.1:9", option{})
	if ok || err != nil || conn != nil {
		t.Fatalf("expected the strategy to decline, got ok=%v err=%v", ok, err)
	}
}

func TestNetworkStrategyInertOnDefaultWithoutTypes(t *testing.T) {
	withStrategy(t, NetworkStrategyDefault, nil, nil, sampleInterfaces())
	if networkStrategyActive() {
		t.Fatal("default with no type list must be inert")
	}
}

func TestParseNetworkStrategy(t *testing.T) {
	for input, want := range map[string]NetworkStrategy{
		"":         NetworkStrategyDefault,
		"default":  NetworkStrategyDefault,
		"Fallback": NetworkStrategyFallback,
		" hybrid ": NetworkStrategyHybrid,
	} {
		got, err := ParseNetworkStrategy(input)
		if err != nil || got != want {
			t.Fatalf("ParseNetworkStrategy(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	if _, err := ParseNetworkStrategy("falback"); err == nil {
		t.Fatal("a misspelled strategy must be rejected, not silently ignored")
	}
}

func TestParseInterfaceType(t *testing.T) {
	for input, want := range map[string]InterfaceType{
		"wifi":     InterfaceTypeWIFI,
		"Wi-Fi":    InterfaceTypeWIFI,
		"cellular": InterfaceTypeCellular,
		"ethernet": InterfaceTypeWired,
		"wired":    InterfaceTypeWired,
		"other":    InterfaceTypeOther,
	} {
		got, err := ParseInterfaceType(input)
		if err != nil || got != want {
			t.Fatalf("ParseInterfaceType(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	if _, err := ParseInterfaceType("wlan"); err == nil {
		t.Fatal("an unknown interface type must be rejected")
	}
}

func loopbackListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().String()
}

func TestDialStrategyFallsBackWhenThePrimaryCannotBeUsed(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI},
		[]NetworkInterface{
			{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWired, Available: true, Default: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
		})
	address := loopbackListener(t)
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
	if !ok {
		t.Fatal("the strategy should have owned this dial")
	}
	if err != nil {
		t.Fatalf("the fallback interface should have carried the dial: %v", err)
	}
	_ = conn.Close()
	if time.Since(networkLastFallback.Load()) > time.Minute {
		t.Fatal("a dial only the fallback completed must open the fast-fallback window")
	}
}

func TestDialStrategyReportsWhenNoInterfaceWorks(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, []NetworkInterface{
		{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWIFI, Available: true, Default: true},
		{Index: 21, Name: "clash-no-such-interface-2", Type: InterfaceTypeCellular, Available: true},
	})
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), "127.0.0.1:9", option{})
	if !ok || err == nil {
		t.Fatalf("expected the strategy to own the dial and fail, got ok=%v err=%v conn=%v", ok, err, conn)
	}
}

func TestDialStrategySingleCandidateDialsDirectly(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, []NetworkInterface{
		{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true, Default: true},
	})
	address := loopbackListener(t)
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
	if !ok || err != nil {
		t.Fatalf("expected a completed dial, got ok=%v err=%v", ok, err)
	}
	_ = conn.Close()
	if !networkLastFallback.Load().IsZero() {
		t.Fatal("a dial the only candidate completed is not a fallback win")
	}
}

func TestFastFallbackWindowRemovesTheFallbackDelay(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback, []InterfaceType{InterfaceTypeWIFI}, nil, sampleInterfaces())
	if time.Since(networkLastFallback.Load()) < networkFastFallbackWindow {
		t.Fatal("the window must start closed")
	}
	networkLastFallback.Store(time.Now())
	if time.Since(networkLastFallback.Load()) >= networkFastFallbackWindow {
		t.Fatal("the window must be open right after a fallback win")
	}
	networkLastFallback.Store(time.Now().Add(-networkFastFallbackWindow - time.Second))
	if time.Since(networkLastFallback.Load()) < networkFastFallbackWindow {
		t.Fatal("the window must expire on its own")
	}
}

func TestNetworkStrategyTimingsMatchSingBox(t *testing.T) {
	if networkFallbackDelay != 300*time.Millisecond {
		t.Fatalf("fallback delay is sing's N.DefaultFallbackDelay (300ms), got %v", networkFallbackDelay)
	}
	if networkFastFallbackWindow != 15*time.Second {
		t.Fatalf("fast-fallback window is sing-box's C.TCPTimeout (15s), got %v", networkFastFallbackWindow)
	}
}

type countingListener struct {
	listener net.Listener
	accepted chan net.Conn
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	counting := &countingListener{listener: listener, accepted: make(chan net.Conn, 16)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			counting.accepted <- conn
		}
	}()
	return counting
}

func (c *countingListener) address() string { return c.listener.Addr().String() }

func TestDialStrategyClosesTheLosingConnection(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, []NetworkInterface{
		{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true, Default: true},
		{Index: 1, Name: "lo0", Type: InterfaceTypeCellular, Available: true},
	})
	server := newCountingListener(t)
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), server.address(), option{})
	if !ok || err != nil {
		t.Fatalf("expected a completed dial, got ok=%v err=%v", ok, err)
	}
	defer conn.Close()

	var accepted []net.Conn
	deadline := time.After(3 * time.Second)
	for len(accepted) < 2 {
		select {
		case c := <-server.accepted:
			accepted = append(accepted, c)
		case <-deadline:
			t.Skip("only one racer reached the listener on this host; the close path needs both")
		}
	}
	closedCount := 0
	for _, serverSide := range accepted {
		_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		if _, err := serverSide.Read(buf); err != nil {
			closedCount++
		}
		_ = serverSide.Close()
	}
	if closedCount == 0 {
		t.Fatal("the losing racer's connection was never closed: it leaked")
	}
}

func TestDialStrategyPrimaryFailureBringsTheFallbackForward(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI},
		[]NetworkInterface{
			{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWired, Available: true, Default: true},
			{Index: 21, Name: "clash-no-such-interface-2", Type: InterfaceTypeWired, Available: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
		})
	address := loopbackListener(t)
	start := time.Now()
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
	if !ok || err != nil {
		t.Fatalf("expected the fallback to carry the dial, got ok=%v err=%v", ok, err)
	}
	_ = conn.Close()
	if elapsed := time.Since(start); elapsed >= networkFallbackDelay {
		t.Fatalf("the fallback waited out the full delay (%v) although both primaries had already failed", elapsed)
	}
}

func TestCloseWindowOnLatePrimary(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback, []InterfaceType{InterfaceTypeWIFI}, nil, sampleInterfaces())

	networkLastFallback.Store(time.Now())
	closeWindowOnLatePrimary(true, time.Now())
	if !networkLastFallback.Load().IsZero() {
		t.Fatal("a primary that connected within the fallback delay must close the window")
	}

	opened := time.Now()
	networkLastFallback.Store(opened)
	closeWindowOnLatePrimary(true, time.Now().Add(-networkFallbackDelay-time.Second))
	if !networkLastFallback.Load().Equal(opened) {
		t.Fatal("a primary slower than the fallback delay is not evidence the primary set is carrying")
	}

	networkLastFallback.Store(opened)
	closeWindowOnLatePrimary(false, time.Now())
	if !networkLastFallback.Load().Equal(opened) {
		t.Fatal("a losing FALLBACK connection says nothing about the primary set")
	}
}

func TestFastFallbackWindowClosesWhenThePrimaryIsCarryingAgain(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWIFI},
		[]InterfaceType{InterfaceTypeCellular},
		[]NetworkInterface{
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true, Default: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeCellular, Available: true},
		})
	networkLastFallback.Store(time.Now())
	address := loopbackListener(t)
	for attempt := 0; attempt < 8; attempt++ {
		conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
		if !ok || err != nil {
			t.Fatalf("expected a completed dial, got ok=%v err=%v", ok, err)
		}
		_ = conn.Close()
		if networkLastFallback.Load().IsZero() {
			return
		}
	}
	t.Skip("the primary never lost a race on this host, so the window-closing branch was not reached")
}

func TestDialStrategySingleFallbackCandidateOpensTheWindow(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI},
		[]NetworkInterface{
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
		})
	address := loopbackListener(t)
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
	if !ok || err != nil {
		t.Fatalf("expected a completed dial, got ok=%v err=%v", ok, err)
	}
	_ = conn.Close()
	if time.Since(networkLastFallback.Load()) > time.Minute {
		t.Fatal("a dial only a fallback interface could carry must open the fast-fallback window")
	}
}

func TestDialStrategyReportsEveryInterfacesError(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, []NetworkInterface{
		{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWIFI, Available: true, Default: true},
		{Index: 21, Name: "clash-no-such-interface-2", Type: InterfaceTypeCellular, Available: true},
	})
	_, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), "127.0.0.1:9", option{})
	if !ok || err == nil {
		t.Fatalf("expected a failure, got ok=%v err=%v", ok, err)
	}
	message := err.Error()
	for _, want := range []string{"clash-no-such-interface", "clash-no-such-interface-2"} {
		if !strings.Contains(message, want) {
			t.Fatalf("the error must name every interface that failed; %q is missing from %q", want, message)
		}
	}
}

func TestListenStrategyPacketUsesTheStrategy(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI},
		[]NetworkInterface{
			{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWired, Available: true, Default: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
		})
	conn, ok, err := listenStrategyPacket(context.Background(), "udp4", "0.0.0.0:0", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53), option{})
	if !ok {
		t.Fatal("the strategy should have owned this listen")
	}
	if err != nil {
		t.Fatalf("the fallback interface should have carried the listen: %v", err)
	}
	_ = conn.Close()
}

func TestListenStrategyPacketIsInertWithoutAStrategy(t *testing.T) {
	withStrategy(t, NetworkStrategyDefault, nil, nil, sampleInterfaces())
	conn, ok, err := listenStrategyPacket(context.Background(), "udp4", "0.0.0.0:0", netip.AddrPort{}, option{})
	if ok || err != nil || conn != nil {
		t.Fatalf("expected the strategy to decline, got ok=%v err=%v", ok, err)
	}
}

func TestDialStrategyWithNoPrimaryDoesNotWaitOutTheFallbackDelay(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI, InterfaceTypeCellular},
		[]NetworkInterface{
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeCellular, Available: true},
		})
	primary, fallback := candidateInterfaces()
	if len(primary) != 0 || len(fallback) != 2 {
		t.Fatalf("expected an empty primary set and two fallbacks, got %v / %v", names(primary), names(fallback))
	}
	address := loopbackListener(t)
	start := time.Now()
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4", netip.MustParseAddr("127.0.0.1"), address, option{})
	if !ok || err != nil {
		t.Fatalf("expected a completed dial, got ok=%v err=%v", ok, err)
	}
	_ = conn.Close()
	if elapsed := time.Since(start); elapsed >= networkFallbackDelay {
		t.Fatalf("with no primary there is nothing to wait for, but the dial took %v", elapsed)
	}
}

type recordingNetDialer struct {
	dialed []string
}

func (d *recordingNetDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.dialed = append(d.dialed, address)
	return nil, errors.New("recording dialer does not connect")
}

func (d *recordingNetDialer) ListenPacket(_ context.Context, _, _ string, _ netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("recording dialer does not listen")
}

func TestStrategyDeclinesACustomNetDialer(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, sampleInterfaces())
	custom := &recordingNetDialer{}
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4",
		netip.MustParseAddr("93.184.216.34"), "93.184.216.34:443", option{netDialer: custom})
	if ok {
		t.Fatalf("the strategy must not own a dial through a custom NetDialer; got conn=%v err=%v", conn, err)
	}
	if len(custom.dialed) != 0 {
		t.Fatalf("the strategy must not have dialed anything itself, it dialed %v", custom.dialed)
	}

	if _, ok, _ := listenStrategyPacket(context.Background(), "udp4", "0.0.0.0:0",
		netip.AddrPortFrom(netip.MustParseAddr("93.184.216.34"), 443), option{netDialer: custom}); ok {
		t.Fatal("the strategy must not own a listen for a custom NetDialer either")
	}

	if !strategyOwnsThisSocket(option{}) {
		t.Fatal("no NetDialer means an ordinary physical socket")
	}
	if !strategyOwnsThisSocket(option{netDialer: &net.Dialer{}}) {
		t.Fatal("a plain *net.Dialer is an ordinary physical socket")
	}
}

func TestStrategyDeclinesWhenAnInterfaceIsPinned(t *testing.T) {
	withStrategy(t, NetworkStrategyHybrid, nil, nil, sampleInterfaces())
	if strategyOwnsThisSocket(option{interfaceName: "en0"}) {
		t.Fatal("an explicit interface pin must make the strategy stand down")
	}
	_, ok, _ := dialStrategyContext(context.Background(), "tcp4",
		netip.MustParseAddr("93.184.216.34"), "93.184.216.34:443", option{interfaceName: "en0"})
	if ok {
		t.Fatal("a pinned dial must not be claimed by the strategy")
	}
	_, ok, _ = listenStrategyPacket(context.Background(), "udp4", "0.0.0.0:0",
		netip.AddrPort{}, option{interfaceName: "en0"})
	if ok {
		t.Fatal("a pinned listen must not be claimed by the strategy")
	}
}

func TestStrategyDialDoesNotUseTFO(t *testing.T) {
	withStrategy(t, NetworkStrategyFallback,
		[]InterfaceType{InterfaceTypeWired},
		[]InterfaceType{InterfaceTypeWIFI},
		[]NetworkInterface{
			{Index: 20, Name: "clash-no-such-interface", Type: InterfaceTypeWired, Available: true, Default: true},
			{Index: 1, Name: "lo0", Type: InterfaceTypeWIFI, Available: true},
		})
	address := loopbackListener(t)
	conn, ok, err := dialStrategyContext(context.Background(), "tcp4",
		netip.MustParseAddr("127.0.0.1"), address, option{tfo: true})
	if !ok || err != nil {
		t.Fatalf("expected the fallback to carry the dial, got ok=%v err=%v", ok, err)
	}
	_ = conn.Close()
}

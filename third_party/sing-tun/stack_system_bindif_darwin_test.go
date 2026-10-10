//go:build darwin

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/sys/unix"
)


func withInterfaceTable(t *testing.T, table []net.Interface, addrs map[string][]net.Addr) {
	t.Helper()
	prevEnum, prevAddrs := enumerateInterfaces, interfaceAddresses
	enumerateInterfaces = func() ([]net.Interface, error) { return table, nil }
	interfaceAddresses = func(i *net.Interface) ([]net.Addr, error) { return addrs[i.Name], nil }
	t.Cleanup(func() { enumerateInterfaces, interfaceAddresses = prevEnum, prevAddrs })
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	ipNet.IP = ip
	return ipNet
}

func TestLookupSkipsDownInterfaces(t *testing.T) {
	withInterfaceTable(t,
		[]net.Interface{
			{Index: 5, Name: "utun4", Flags: 0},
			{Index: 9, Name: "utun5", Flags: net.FlagUp},
		},
		map[string][]net.Addr{
			"utun4": {mustCIDR(t, "198.18.0.1/16")},
			"utun5": {mustCIDR(t, "198.18.0.1/16")},
		})
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("fabricated table must not error: %v", err)
	}
	if index != 9 {
		t.Fatalf("the up interface must win over a down one carrying the same address, got index %d", index)
	}
	if carriers != 1 {
		t.Fatalf("a down interface is not a carrier, got %d", carriers)
	}
}

func TestLookupPrefersNewestWhenTwoLiveInterfacesCarryTheAddress(t *testing.T) {
	withInterfaceTable(t,
		[]net.Interface{
			{Index: 4, Name: "utun2", Flags: net.FlagUp},
			{Index: 11, Name: "utun6", Flags: net.FlagUp},
		},
		map[string][]net.Addr{
			"utun2": {mustCIDR(t, "198.18.0.1/16")},
			"utun6": {mustCIDR(t, "198.18.0.1/16")},
		})
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("fabricated table must not error: %v", err)
	}
	if index != 11 {
		t.Fatalf("the newest live carrier must win, got index %d", index)
	}
	if carriers != 2 {
		t.Fatalf("both live carriers must be counted (the caller warns on >1), got %d", carriers)
	}
}

func TestLookupReportsEnumerationFailureAsItself(t *testing.T) {
	prevEnum := enumerateInterfaces
	boom := errors.New("getifaddrs: cannot allocate memory")
	enumerateInterfaces = func() ([]net.Interface, error) { return nil, boom }
	t.Cleanup(func() { enumerateInterfaces = prevEnum })
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if index != -1 || carriers != 0 {
		t.Fatalf("enumeration failure must report -1/0, got %d/%d", index, carriers)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the enumeration error must be preserved, got %v", err)
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the enumeration error must stay retryable, got %v", err)
	}
}

func TestListenWithTunBindBindsWhenAddressResolves(t *testing.T) {
	s := &System{ctx: context.Background(), logger: logger.NOP()}
	ln, err := s.listenWithTunBind(net.ListenConfig{}, "tcp4", "127.0.0.1:0", netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("listen with a resolvable tun address must succeed, got %v", err)
	}
	defer ln.Close()
}

func TestListenWithTunBindFailsRetryablyWhenAddressAbsent(t *testing.T) {
	s := &System{ctx: context.Background(), logger: logger.NOP()}
	ln, err := s.listenWithTunBind(net.ListenConfig{}, "tcp4", "127.0.0.1:0", netip.MustParseAddr("203.0.113.254"))
	if err == nil {
		ln.Close()
		t.Fatal("an absent tun address must not produce an unbound listener -- that is the silent-dead-TCP state")
	}
	if !retryableListenError(err) {
		t.Fatalf("a lookup miss is the same \"address not there yet\" condition the retry loop exists for; got non-retryable %v", err)
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the miss must wrap EADDRNOTAVAIL, got %v", err)
	}
}

func TestBindHookFailsClosedAndRetryablyOnSetsockoptFailure(t *testing.T) {
	hook := bindListenerToInterfaceControl(1<<24, logger.NOP())
	if hook == nil {
		t.Fatal("a non-negative index must yield a hook")
	}
	lc := net.ListenConfig{Control: hook}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatal("a failed setsockopt must fail the listen: an unbound listener is the exact state this file exists to end")
	}
	if !retryableListenError(err) {
		t.Fatalf("a setsockopt failure means the tun changed under us -- it must stay retryable so the next attempt re-resolves, got %v", err)
	}
}

func TestStartRoutesItsListenersThroughTunBind(t *testing.T) {
	withInterfaceTable(t, nil, nil)
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	err := s.start()
	if err == nil {
		t.Fatal("with no interface carrying the tun address, a start() that routes through " +
			"listenWithTunBind cannot succeed; success means the routing was dropped " +
			"(an upstream merge took the whole function) and the bind is gone")
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the failure must be the retryable lookup miss, got %v", err)
	}
	if s.tcpListener != nil {
		t.Fatal("a failed start must not leave a live TCP listener behind")
	}
}

func TestStartClosesV4ListenerWhenV6Fails(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	withInterfaceTable(t,
		[]net.Interface{*lo, {Index: 1 << 24, Name: "utun9", Flags: net.FlagUp}},
		map[string][]net.Addr{
			"lo0":   {mustCIDR(t, "127.0.0.1/8")},
			"utun9": {mustCIDR(t, "2001:db8::1/126")},
		})
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		inet6Address:     netip.MustParseAddr("2001:db8::1"),
		inet6NextAddress: netip.MustParseAddr("2001:db8::2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	start := time.Now()
	err = s.start()
	if err == nil {
		s.Close()
		t.Fatal("the v6 leg's bound-if setsockopt cannot succeed on index 1<<24; start() must fail")
	}
	if errors.Is(err, errTunAddressNotPresent) {
		t.Fatalf("the v6 address IS carried by an up interface here; the failure must be the bind, not a lookup miss: %v", err)
	}
	if s.tcpListener != nil {
		t.Fatal("the v4 listener must be closed when the v6 leg fails, or every failed start leaks a socket and a goroutine")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("start() took %v; the retry loop grew beyond its documented three attempts", elapsed)
	}
}

func TestStartDefersIPv6ForwardingUntilTheTunAddressIsDeclared(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	addrs := map[string][]net.Addr{"lo0": {mustCIDR(t, "127.0.0.1/8")}}
	withInterfaceTable(t, []net.Interface{*lo}, addrs)
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		inet6Address:     netip.MustParseAddr("::1"),
		inet6NextAddress: netip.MustParseAddr("::2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	start := time.Now()
	if err := s.start(); err != nil {
		t.Fatalf("an undeclared IPv6 tun address is `automatic` on an IPv4-only path, not a failure; start() returned %v", err)
	}
	defer s.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("start() spent %v waiting for an address nothing was going to declare", elapsed)
	}
	if s.tcpListener == nil {
		t.Fatal("the v4 forwarder must be listening")
	}
	if s.tcpListener6 != nil || s.tcpPort6 != 0 {
		t.Fatal("the v6 forwarder must be deferred, not listening unbound (the silent-dead-TCP state)")
	}
	if s.ipv6ForwarderListening() {
		t.Fatal("with the address still absent the forwarder must report itself down")
	}

	addrs["lo0"] = append(addrs["lo0"], mustCIDR(t, "::1/128"))
	s.tcp6RetryAt = time.Time{}
	if !s.ipv6ForwarderListening() {
		t.Fatal("once an up interface carries the address, the v6 forwarder must come up on demand")
	}
	if s.tcpListener6 == nil || s.tcpPort6 == 0 {
		t.Fatal("a listening forwarder must have a listener and a port")
	}
	if got := M.SocksaddrFromNet(s.tcpListener6.Addr()); got.Addr != s.inet6Address || got.Port != s.tcpPort6 {
		t.Fatalf("the late listener must sit where the packet rewrite sends flows, got %v", got)
	}
}

func TestDeferredIPv6ForwarderPacesItsLookupsWhileTheAddressStaysAbsent(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	withInterfaceTable(t, []net.Interface{*lo}, map[string][]net.Addr{"lo0": {mustCIDR(t, "127.0.0.1/8")}})
	var lookups int
	prevEnum := enumerateInterfaces
	enumerateInterfaces = func() ([]net.Interface, error) { lookups++; return prevEnum() }
	t.Cleanup(func() { enumerateInterfaces = prevEnum })
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		inet6Address:     netip.MustParseAddr("::1"),
		inet6NextAddress: netip.MustParseAddr("::2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lookups = 0
	for i := 0; i < 50; i++ {
		if s.ipv6ForwarderListening() {
			t.Fatal("the address is absent; the forwarder cannot be up")
		}
	}
	if lookups != 1 {
		t.Fatalf("50 back-to-back checks against an absent address must cost one enumeration, cost %d", lookups)
	}
}

func TestIPv6TCPWaitsForTheDeferredForwarderAndFlowsOnceItListens(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	addrs := map[string][]net.Addr{"lo0": {mustCIDR(t, "127.0.0.1/8")}}
	withInterfaceTable(t, []net.Interface{*lo}, addrs)
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		handler:          &doorHandler{},
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		inet6Address:     netip.MustParseAddr("::1"),
		inet6NextAddress: netip.MustParseAddr("::2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	syn := func() (header.IPv6, header.TCP) {
		packet := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
		ipHdr := header.IPv6(packet)
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     header.TCPMinimumSize,
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           s.inet6Address,
			DstAddr:           netip.MustParseAddr("2001:db8::10"),
		})
		tcpHdr := header.TCP(ipHdr.Payload())
		tcpHdr.Encode(&header.TCPFields{
			SrcPort:    40000,
			DstPort:    443,
			SeqNum:     1,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagSyn,
			WindowSize: 65535,
		})
		return ipHdr, tcpHdr
	}

	ipHdr, tcpHdr := syn()
	writeBack, err := s.processIPv6TCP(ipHdr, tcpHdr)
	if err != nil {
		t.Fatalf("a SYN ahead of the declaration is not an error, got %v", err)
	}
	if writeBack {
		t.Fatal("a SYN ahead of the declaration must be dropped, not rewritten towards a forwarder that is not listening")
	}

	addrs["lo0"] = append(addrs["lo0"], mustCIDR(t, "::1/128"))
	s.tcp6RetryAt = time.Time{}
	ipHdr, tcpHdr = syn()
	writeBack, err = s.processIPv6TCP(ipHdr, tcpHdr)
	if err != nil {
		t.Fatal(err)
	}
	if !writeBack {
		t.Fatal("once the address is declared the SYN must flow")
	}
	if ipHdr.DestinationAddr() != s.inet6Address || tcpHdr.DestinationPort() != s.tcpPort6 || s.tcpPort6 == 0 {
		t.Fatalf("the SYN must be rewritten towards the forwarder, got %v:%d", ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	}
	if ipHdr.SourceAddr() != s.inet6NextAddress {
		t.Fatalf("the SYN's source must be the tun's peer address, got %v", ipHdr.SourceAddr())
	}
}

func TestStartAcrossTheTunIPv6ModesAsTheStackSeesThem(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	cases := []struct {
		name       string
		offersIPv6 bool
		declared   bool
		wantV6Up   bool
	}{
		{"disabled", false, false, false},
		{"enabled", true, true, true},
		{"automatic on a path with IPv6", true, true, true},
		{"automatic on an IPv4-only path", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			carried := []net.Addr{mustCIDR(t, "127.0.0.1/8")}
			if tc.declared {
				carried = append(carried, mustCIDR(t, "::1/128"))
			}
			withInterfaceTable(t, []net.Interface{*lo}, map[string][]net.Addr{"lo0": carried})
			s := &System{
				ctx:              context.Background(),
				logger:           logger.NOP(),
				inet4Address:     netip.MustParseAddr("127.0.0.1"),
				inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
				udpTimeout:       time.Minute,
				icmpTimeout:      time.Minute,
			}
			if tc.offersIPv6 {
				s.inet6Address = netip.MustParseAddr("::1")
				s.inet6NextAddress = netip.MustParseAddr("::2")
			}
			start := time.Now()
			if err := s.start(); err != nil {
				t.Fatalf("start() must succeed in every mode, got %v", err)
			}
			defer s.Close()
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("start() took %v; no mode may ride the retry loop", elapsed)
			}
			if s.tcpListener == nil {
				t.Fatal("the v4 forwarder is up in every mode")
			}
			if up := s.tcpListener6 != nil && s.tcpPort6 != 0; up != tc.wantV6Up {
				t.Fatalf("v6 forwarder up=%v, want %v", up, tc.wantV6Up)
			}
			if s.ipv6ForwarderListening() != tc.wantV6Up {
				t.Fatalf("ipv6ForwarderListening must agree with the listener state (%v)", tc.wantV6Up)
			}
		})
	}
}

package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestRXChecksumOffloadPolicy(t *testing.T) {
	settings := []struct {
		name string
		set  func(*RXChecksumOffload, bool) *RXChecksumOffload
		get  func(RXChecksumOffload) bool
	}{
		{"IPv4Header", (*RXChecksumOffload).SetIPv4Header, RXChecksumOffload.IPv4Header},
		{"TCP", (*RXChecksumOffload).SetTCP, RXChecksumOffload.TCP},
		{"UDP", (*RXChecksumOffload).SetUDP, RXChecksumOffload.UDP},
		{"ICMPv4", (*RXChecksumOffload).SetICMPv4, RXChecksumOffload.ICMPv4},
		{"ICMPv6", (*RXChecksumOffload).SetICMPv6, RXChecksumOffload.ICMPv6},
		{"IGMP", (*RXChecksumOffload).SetIGMP, RXChecksumOffload.IGMP},
	}
	for index, setting := range settings {
		t.Run(setting.name, func(t *testing.T) {
			var offload RXChecksumOffload
			if setting.get(offload) || setting.set(&offload, true) != &offload {
				t.Fatal("zero policy or chained setter is incorrect")
			}
			for other, query := range settings {
				if got := query.get(offload); got != (other == index) {
					t.Fatalf("%s enabled = %t after setting %s", query.name, got, setting.name)
				}
			}
			if setting.set(&offload, false) != &offload || setting.get(offload) {
				t.Fatal("setter did not clear its category")
			}
		})
	}
	config := Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}}
	stack, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	var offload RXChecksumOffload
	offload.SetIPv4Header(true).SetTCP(true).SetUDP(true).SetICMPv4(true).SetICMPv6(true).SetIGMP(true)
	stack.SetRXChecksumOffload(offload)
	offload.SetTCP(false)
	copy := stack.RXChecksumOffload()
	copy.SetUDP(false)
	if err = stack.UpdateConfig(config); err != nil {
		t.Fatal(err)
	}
	for _, setting := range settings {
		if !setting.get(stack.RXChecksumOffload()) {
			t.Fatalf("%s was changed through a copied value or UpdateConfig", setting.name)
		}
	}
}

func TestMTUAndRouteFamilyValidation(t *testing.T) {
	ipv4 := netip.MustParsePrefix("192.0.2.15/32")
	if _, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, MTU: 68}); err != nil {
		t.Fatalf("minimum IPv4 MTU was rejected: %v", err)
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, MTU: 67}); err == nil {
		t.Fatal("IPv4 MTU below 68 was accepted")
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::15/128")}, MTU: 1279}); err == nil {
		t.Fatal("IPv6 MTU below 1280 was accepted")
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.255/24")}}); err == nil {
		t.Fatal("IPv4 subnet broadcast address was accepted as local")
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.255/32"),
		netip.MustParsePrefix("192.0.2.1/24"),
	}}); err == nil {
		t.Fatal("address that is another configured prefix's broadcast was accepted as local")
	}
	if _, err := New(Config{
		LocalAddresses: []netip.Prefix{ipv4},
		Routes:         []Route{{Destination: netip.MustParsePrefix("2001:db8::/32")}},
	}); err == nil {
		t.Fatal("route without a same-family local address was accepted")
	}
	withoutRoutes, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, Routes: []Route{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = withoutRoutes.RouteFor(netip.MustParseAddr("198.51.100.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("explicit empty route table = %v, want ENETUNREACH", err)
	}
	broadcastStack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.15/24")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.255", "255.255.255.255"} {
		destination := netip.MustParseAddr(address)
		if _, routeErr := broadcastStack.RouteFor(destination); !errors.Is(routeErr, syscall.EACCES) {
			t.Fatalf("broadcast route %s = %v, want EACCES", destination, routeErr)
		}
		if source, sourceErr := broadcastStack.sourceForRequested(destination, netip.Addr{}); sourceErr != nil || source != netip.MustParseAddr("192.0.2.15") {
			t.Fatalf("broadcast source %s = %s, %v, want 192.0.2.15", destination, source, sourceErr)
		}
	}
}

func TestAddresslessPromiscuousConfiguration(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty local addresses without promiscuous mode were accepted")
	}
	if _, err := New(Config{Promiscuous: true, MTU: 1279}); err == nil {
		t.Fatal("addressless implicit IPv6 route below the minimum MTU was accepted")
	}
	if _, err := New(Config{
		Promiscuous: true,
		MTU:         1279,
		Routes:      []Route{{Destination: netip.MustParsePrefix("2001:db8::/32")}},
	}); err == nil {
		t.Fatal("addressless explicit IPv6 route below the minimum MTU was accepted")
	}
	if _, err := New(Config{
		Promiscuous: true,
		MTU:         1280,
		Routes: []Route{{
			Destination: netip.MustParsePrefix("198.51.100.0/24"),
			Source:      netip.MustParseAddr("192.0.2.1"),
		}},
	}); err == nil {
		t.Fatal("addressless route with a nonlocal source was accepted")
	}
	if _, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		Promiscuous:    true,
		MTU:            1280,
		Routes:         []Route{{Destination: netip.MustParsePrefix("2001:db8::/32")}},
	}); err != nil {
		t.Fatalf("promiscuous source-less route without a local address in its family: %v", err)
	}
	ipv4Only, err := New(Config{
		Promiscuous: true,
		MTU:         68,
		Routes:      []Route{{Destination: netip.MustParsePrefix("0.0.0.0/0")}},
	})
	if err != nil {
		t.Fatalf("addressless IPv4-only minimum MTU: %v", err)
	}
	_ = ipv4Only.Close()

	stack, err := New(Config{Promiscuous: true, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if addresses := stack.LocalAddresses(); len(addresses) != 0 {
		t.Fatalf("addressless local addresses = %v, want none", addresses)
	}
	for destination, want := range map[netip.Addr]netip.Prefix{
		netip.MustParseAddr("198.51.100.1"): netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParseAddr("2001:db8::1"):  netip.MustParsePrefix("::/0"),
	} {
		route, routeErr := stack.RouteFor(destination)
		if routeErr != nil || route.Destination != want || route.Source.IsValid() {
			t.Fatalf("addressless route for %s = %+v, %v, want source-less %s", destination, route, routeErr, want)
		}
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	families := []struct {
		name, tcp, udp, ip string
		remote             netip.Addr
	}{
		{name: "IPv4", tcp: "tcp4", udp: "udp4", ip: "ip4:99", remote: netip.MustParseAddr("198.51.100.1")},
		{name: "IPv6", tcp: "tcp6", udp: "udp6", ip: "ip6:99", remote: netip.MustParseAddr("2001:db8::1")},
	}
	for _, family := range families {
		check := func(operation string, operationErr error) {
			t.Helper()
			if !errors.Is(operationErr, syscall.EADDRNOTAVAIL) {
				t.Errorf("%s %s = %v, want EADDRNOTAVAIL", family.name, operation, operationErr)
			}
		}
		_, operationErr := stack.ListenTCP(ctx, family.tcp, netip.AddrPort{})
		check("ListenTCP", operationErr)
		_, operationErr = stack.ListenUDP(ctx, family.udp, netip.AddrPort{})
		check("ListenUDP", operationErr)
		_, operationErr = stack.ListenIP(ctx, family.ip, netip.Addr{})
		check("ListenIP", operationErr)
		_, operationErr = stack.DialTCP(ctx, family.tcp, netip.AddrPort{}, netip.AddrPortFrom(family.remote, 80))
		check("DialTCP", operationErr)
		_, operationErr = stack.DialUDP(ctx, family.udp, netip.AddrPort{}, netip.AddrPortFrom(family.remote, 53))
		check("DialUDP", operationErr)
		_, operationErr = stack.DialIP(ctx, family.ip, netip.Addr{}, family.remote)
		check("DialIP", operationErr)
	}
	if err = stack.UpdateConfig(Config{}); err == nil {
		t.Fatal("UpdateConfig disabled promiscuous mode without adding a local address")
	}

	unrouted, err := New(Config{Promiscuous: true, MTU: 68, Routes: []Route{}})
	if err != nil {
		t.Fatal(err)
	}
	defer unrouted.Close()
	if _, err = unrouted.RouteFor(netip.MustParseAddr("198.51.100.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("addressless explicit empty route table = %v, want ENETUNREACH", err)
	}
}

func TestLocalAddressNormalization(t *testing.T) {
	ipv4 := netip.MustParsePrefix("192.0.2.15/32")
	for _, duplicate := range []netip.Prefix{ipv4, netip.MustParsePrefix("2001:db8::15/64")} {
		stack, duplicateErr := New(Config{LocalAddresses: []netip.Prefix{duplicate, duplicate}})
		if duplicateErr != nil {
			t.Fatalf("idempotent duplicate %s prefix was rejected: %v", duplicate.Addr(), duplicateErr)
		}
		if addresses := stack.LocalAddresses(); len(addresses) != 1 || addresses[0] != duplicate.Addr() || len(stack.network.Load().localPrefixes) != 1 {
			t.Fatalf("duplicate %s prefix was not normalized: addresses %v, prefixes %v", duplicate.Addr(), addresses, stack.network.Load().localPrefixes)
		}
	}
	sharedIPv4, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.15/24"),
		netip.MustParsePrefix("192.0.2.15/32"),
	}})
	if err != nil {
		t.Fatalf("IPv4 address with two prefixes was rejected: %v", err)
	}
	if addresses := sharedIPv4.LocalAddresses(); len(addresses) != 1 || addresses[0] != ipv4.Addr() {
		t.Fatalf("shared IPv4 local addresses = %v, want [%s]", addresses, ipv4.Addr())
	}
	sharedIPv6, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.MustParsePrefix("2001:db8::15/64"),
		netip.MustParsePrefix("2001:db8::15/128"),
	}})
	if err != nil {
		t.Fatalf("IPv6 address with two prefixes was rejected: %v", err)
	}
	if addresses := sharedIPv6.LocalAddresses(); len(addresses) != 1 || addresses[0] != netip.MustParseAddr("2001:db8::15") {
		t.Fatalf("shared IPv6 local addresses = %v, want [2001:db8::15]", addresses)
	}
}

func TestIPv4BroadcastPrefixBoundaries(t *testing.T) {
	tests := []struct {
		prefix    string
		address   string
		broadcast bool
	}{
		{prefix: "192.0.2.1/24", address: "192.0.2.255", broadcast: true},
		{prefix: "192.0.2.1/30", address: "192.0.2.3", broadcast: true},
		{prefix: "192.0.2.0/31", address: "192.0.2.1"},
		{prefix: "192.0.2.255/32", address: "192.0.2.255"},
	}
	for _, test := range tests {
		state, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix(test.prefix)}})
		if err != nil {
			t.Fatalf("buildNetworkState(%s): %v", test.prefix, err)
		}
		address := netip.MustParseAddr(test.address)
		if got := state.broadcastDestination(address); got != test.broadcast {
			t.Fatalf("broadcastDestination(%s, %s) = %v, want %v", test.prefix, address, got, test.broadcast)
		}
	}
}

func TestDirectedBroadcastSelectsAddressOnMatchingSubnet(t *testing.T) {
	primary := netip.MustParseAddr("198.51.100.1")
	matching := netip.MustParseAddr("192.0.2.1")
	state, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(primary, 24),
		netip.PrefixFrom(matching, 24),
	}})
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddr("192.0.2.255")
	source, err := state.sourceForNonUnicast(destination, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if source != matching {
		t.Fatalf("directed-broadcast source = %s, want %s", source, matching)
	}
}

func TestInboundIPv4PacketInfoSource(t *testing.T) {
	primary := netip.MustParseAddr("198.51.100.1")
	matching := netip.MustParseAddr("192.0.2.1")
	state, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(primary, 24), netip.PrefixFrom(matching, 24),
	}, Promiscuous: true, Routes: []Route{
		{Destination: netip.MustParsePrefix("198.51.100.0/24"), Source: primary},
		{Destination: netip.MustParsePrefix("203.0.113.0/24"), Source: matching},
		{Destination: netip.MustParsePrefix("0.0.0.0/0")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("198.51.100.9")
	if got := state.inboundIPv4PacketInfoSource(remote, matching); got != matching {
		t.Fatalf("local-unicast packet-info source = %s, want %s", got, matching)
	}
	if got := state.inboundIPv4PacketInfoSource(netip.IPv4Unspecified(), netip.MustParseAddr("192.0.2.255")); got != primary {
		t.Fatalf("directed-broadcast packet-info source = %s, want %s", got, primary)
	}
	if got := state.inboundIPv4PacketInfoSource(netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("239.1.1.1")); got != matching {
		t.Fatalf("multicast packet-info source = %s, want %s", got, matching)
	}
	if got := state.inboundIPv4PacketInfoSource(remote, netip.MustParseAddr("203.0.113.9")); got != primary {
		t.Fatalf("promiscuous packet-info source = %s, want %s", got, primary)
	}

	addressless, err := buildNetworkState(Config{Promiscuous: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := addressless.inboundIPv4PacketInfoSource(remote, netip.MustParseAddr("203.0.113.9")); got.IsValid() {
		t.Fatalf("addressless promiscuous packet-info source = %s, want unspecified", got)
	}
}

func TestPathMTUMinimumPolicy(t *testing.T) {
	local6 := netip.MustParseAddr("2001:db8::1")
	remote6 := netip.MustParseAddr("2001:db8::2")
	stack6, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local6, 128)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if stack6.observePathMTU(remote6, 1200) {
		t.Fatal("IPv6 PTB below the RFC 8201 minimum was accepted")
	}
	if mtu := stack6.mtuFor(remote6); mtu != 1500 {
		t.Fatalf("IPv6 PMTU after subminimum PTB = %d, want 1500", mtu)
	}

	local4 := netip.MustParseAddr("192.0.2.1")
	remote4 := netip.MustParseAddr("192.0.2.2")
	stack4, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if !stack4.observePathMTU(remote4, 40) {
		t.Fatal("legacy IPv4 PTB was not clamped to the minimum datagram size")
	}
	if mtu := stack4.mtuFor(remote4); mtu != 68 {
		t.Fatalf("IPv4 PMTU after subminimum hint = %d, want 68", mtu)
	}
}

func TestPathMTUUsesOneConfigurationSnapshot(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.3")
	remote := netip.MustParseAddr("198.51.100.3")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1200})
	if err != nil {
		t.Fatal(err)
	}

	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	stack.pathMTUMu.Lock()
	result := make(chan int, 1)
	go func() { result <- stack.mtuFor(remote) }()
	runtime.Gosched()
	stack.network.Store(updated)
	stack.pathMTU = make(map[netip.Addr]pathMTUEntry)
	stack.pathMTUMu.Unlock()
	if mtu := <-result; mtu != 1200 {
		t.Fatalf("PMTU spanning a configuration update = %d, want 1200", mtu)
	}
}

func TestUpdateConfigInvalidatesOnlyChangedPathState(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.10")
	second := netip.MustParseAddr("192.0.2.11")
	remote := netip.MustParseAddr("198.51.100.10")
	destination := netip.MustParsePrefix("198.51.100.0/24")
	config := Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)},
		Routes:         []Route{{Destination: destination, Source: first}},
		MTU:            1500,
	}
	stack, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(remote, 1200) {
		t.Fatal("failed to install test PMTU")
	}
	unchanged := config
	unchanged.TCP.DisableNoDelay = true
	if err = stack.UpdateConfig(unchanged); err != nil {
		t.Fatal(err)
	}
	if mtu := stack.mtuFor(remote); mtu != 1200 {
		t.Fatalf("socket-policy update discarded PMTU = %d, want 1200", mtu)
	}
	changed := config
	changed.Routes = []Route{{Destination: destination, Source: second}}
	if err = stack.UpdateConfig(changed); err != nil {
		t.Fatal(err)
	}
	if mtu := stack.mtuFor(remote); mtu != 1500 {
		t.Fatalf("source-route update retained stale PMTU = %d, want 1500", mtu)
	}
}

func TestTCPConnectionLimitConfiguration(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.12")
	if _, err := New(Config{
		LocalAddresses:    []netip.Prefix{netip.PrefixFrom(local, 32)},
		MaxTCPConnections: -1,
	}); err == nil {
		t.Fatal("negative MaxTCPConnections was accepted")
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	stack.mu.Lock()
	for index := 0; index < 16385; index++ {
		key := tcpKey{
			local:  netip.AddrPortFrom(local, uint16(1024+index)),
			remote: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.12"), uint16(index+1)),
		}
		stack.tcp[key] = nil
	}
	available := stack.tcpConnectionAvailableLocked()
	stack.mu.Unlock()
	if !available {
		t.Fatal("zero MaxTCPConnections imposed an implicit limit")
	}
}

func TestCongestionControlConfiguration(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.13/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}})
	if err != nil {
		t.Fatal(err)
	}
	if defaults := stack.network.Load().tcpDefaults; defaults.CongestionControl != "" || defaults.CongestionControlFactory.Name() != CongestionControlCUBIC {
		t.Fatalf("default congestion control = name %q factory %q, want factory %q", defaults.CongestionControl, defaults.CongestionControlFactory.Name(), CongestionControlCUBIC)
	}
	for _, algorithm := range []string{CongestionControlCUBIC, CongestionControlReno, CongestionControlBBR, CongestionControlBBR3} {
		if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local}, TCP: TCPSocketDefaults{CongestionControl: algorithm}}); err != nil {
			t.Fatalf("UpdateConfig(%q): %v", algorithm, err)
		}
		defaults := stack.network.Load().tcpDefaults
		if defaults.CongestionControl != "" || defaults.CongestionControlFactory.Name() != algorithm {
			t.Fatalf("configured congestion control = name %q factory %q, want factory %q", defaults.CongestionControl, defaults.CongestionControlFactory.Name(), algorithm)
		}
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local}, TCP: TCPSocketDefaults{CongestionControl: "invalid"}}); err == nil {
		t.Fatal("invalid congestion control was accepted")
	}
}

func TestCongestionControlConfigurationUpdatesExistingConnections(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.16")
	remote := netip.MustParseAddr("198.51.100.16")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 443))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	defer tcpConnection.Close()
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlReno},
	}); err != nil {
		t.Fatal(err)
	}
	if got := tcpConnection.socketOptions().congestionFactory.Name(); got != CongestionControlReno {
		t.Fatalf("updated connection congestion control = %q, want %q", got, CongestionControlReno)
	}
	if err = tcpConnection.SetCongestionControl(CongestionControlBBR); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlCUBIC},
	}); err != nil {
		t.Fatal(err)
	}
	if got := tcpConnection.socketOptions().congestionFactory.Name(); got != CongestionControlBBR {
		t.Fatalf("per-connection congestion control changed to %q, want %q", got, CongestionControlBBR)
	}
}

func TestTCPSocketDefaultConfiguration(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.130/32")
	invalid := []TCPSocketDefaults{
		{ReceiveBuffer: -1},
		{ReceiveBuffer: 4096, MaximumReceiveBuffer: 2048},
		{SendBuffer: 4096, MaximumSendBuffer: 2048},
		{MaximumReceiveBuffer: int(tcpMaximumScaledWindow) + 1},
		{KeepAliveConfig: KeepAliveConfig{Count: -1}},
		{UserTimeout: -time.Second},
		{FlowLabel: ipv6MaximumFlowLabel + 1},
	}
	for _, defaults := range invalid {
		if _, err := New(Config{LocalAddresses: []netip.Prefix{local}, TCP: defaults}); err == nil {
			t.Fatalf("invalid TCP defaults were accepted: %+v", defaults)
		}
	}

	defaults := TCPSocketDefaults{
		ReceiveBuffer: 128 * 1024, MaximumReceiveBuffer: 2 * 1024 * 1024,
		SendBuffer: 64 * 1024, MaximumSendBuffer: 4 * 1024 * 1024,
		MaximumPacingRate: 12_345_678,
		AcceptQueue:       17, SYNBacklog: 29, KeepAlive: true,
		KeepAliveConfig: KeepAliveConfig{Idle: time.Minute, Interval: 3 * time.Second, Count: 4},
		IdleTimeout:     5 * time.Minute, UserTimeout: 30 * time.Second, DisableNoDelay: true, TrafficClass: 0xab,
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, TCP: defaults})
	if err != nil {
		t.Fatal(err)
	}
	state := stack.network.Load()
	if state.tcpDefaults.TrafficClass != 0xa8 {
		t.Fatalf("normalized traffic class = %#x, want %#x", state.tcpDefaults.TrafficClass, 0xa8)
	}
	connection := newTCPConn(stack, "tcp", tcpKey{}, 1500, tcpSocketOptionSet{})
	if connection.receiveCapacity != defaults.ReceiveBuffer || connection.receiveMaximum != defaults.MaximumReceiveBuffer ||
		connection.sendCapacity != defaults.SendBuffer || connection.sendMaximum != defaults.MaximumSendBuffer ||
		connection.maximumPacingRate != defaults.MaximumPacingRate || connection.noDelay || !connection.keepAlive || connection.userTimeout != defaults.UserTimeout || connection.receiveWindowScale != tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer) {
		t.Fatalf("connection did not inherit TCP defaults: %+v", connection)
	}
	if got := uint8(connection.trafficClass.Load()); got != 0xa8 {
		t.Fatalf("connection traffic class = %#x, want %#x", got, 0xa8)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if cap(listener.(*TCPListener).accept) != defaults.AcceptQueue || listener.(*TCPListener).backlog != defaults.SYNBacklog {
		t.Fatalf("listener queue/backlog = %d/%d, want %d/%d", cap(listener.(*TCPListener).accept), listener.(*TCPListener).backlog, defaults.AcceptQueue, defaults.SYNBacklog)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan struct{})
	go func() {
		_, _ = stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("198.51.100.130:443"))
		close(dialDone)
	}()
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.protocol != ProtocolTCP || packet.trafficClass != 0xa8 {
		t.Fatalf("default TCP SYN traffic class = %#x, want %#x", packet.trafficClass, 0xa8)
	}
	cancel()
	<-dialDone
}

func TestDatagramSocketDefaultConfiguration(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.131/32")
	for _, config := range []Config{
		{LocalAddresses: []netip.Prefix{local}, UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{ReceiveBuffer: -1}}},
		{LocalAddresses: []netip.Prefix{local}, UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{HopLimit: 256}}},
		{LocalAddresses: []netip.Prefix{local}, UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{FlowLabel: ipv6MaximumFlowLabel + 1}}},
		{LocalAddresses: []netip.Prefix{local}, UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{PathMTUDiscovery: PathMTUDiscovery(99)}}},
		{LocalAddresses: []netip.Prefix{local}, IP: IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{HopLimit: -1}}},
		{LocalAddresses: []netip.Prefix{local}, IP: IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{FlowLabel: ipv6MaximumFlowLabel + 1}}},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("invalid datagram defaults were accepted: %+v", config)
		}
	}
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{local},
		UDP:            UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{ReceiveBuffer: 2048, ReceiveErrors: true, HopLimit: 31, TrafficClass: 0xb8, PathMTUDiscovery: PathMTUDiscoveryProbe}},
		IP: IPSocketDefaults{
			DatagramSocketDefaults:  DatagramSocketDefaults{ReceiveBuffer: 4096, ReceiveErrors: true, HopLimit: 29, TrafficClass: 0x2e, PathMTUDiscovery: PathMTUDiscoveryOmit},
			IPHeaderIncludedOnWrite: true, IPHeaderIncludedOnRead: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	udp := newUDPConn(stack, "udp4", 1000, false, local.Addr(), netip.AddrPort{}, datagramSocketOptionSet{})
	if udp.receiveCapacity != 2048 || !udp.receiveErrors || udp.defaultOptions != (ipPacketOptions{hopLimit: 31, trafficClass: 0xb8}) || udp.pathMTUDiscovery != PathMTUDiscoveryProbe {
		t.Fatalf("UDP defaults = %d, %+v, PMTU mode %d", udp.receiveCapacity, udp.defaultOptions, udp.pathMTUDiscovery)
	}
	ip := newIPConn(stack, "ip4:99", 99, local.Addr(), netip.Addr{}, socketOptionSet{})
	if ip.receiveCapacity != 4096 || !ip.receiveErrors || ip.defaultOptions != (ipPacketOptions{hopLimit: 29, trafficClass: 0x2e}) ||
		ip.pathMTUDiscovery != PathMTUDiscoveryOmit || !ip.ipHeaderIncludedOnWrite.Load() || !ip.ipHeaderIncludedOnRead {
		t.Fatalf("IP defaults = %d, %+v, PMTU mode %d", ip.receiveCapacity, ip.defaultOptions, ip.pathMTUDiscovery)
	}
}

func TestExpiredPathMTURemainsActionable(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.14/32")
	remote := netip.MustParseAddr("198.51.100.14")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	stack.pathMTU[remote] = pathMTUEntry{mtu: 1000, updated: time.Now().Add(-pathMTULifetime - time.Second)}
	if expiry, exists := stack.pathMTUExpiry(remote); !exists || !expiry.Before(time.Now()) {
		t.Fatalf("expired PMTU expiry = %v, %v", expiry, exists)
	}
	if mtu := stack.mtuFor(remote); mtu != 1500 {
		t.Fatalf("MTU after expiry = %d, want 1500", mtu)
	}
	if _, exists := stack.pathMTU[remote]; exists {
		t.Fatal("expired PMTU cache entry was not removed")
	}
}

func TestPathMTUCacheBoundAndICMPRefreshPolicy(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.16/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("198.51.100.16")
	updated := time.Now().Add(-time.Minute)
	stack.pathMTU[remote] = pathMTUEntry{mtu: 1000, updated: updated}
	if stack.observePathMTU(remote, 1200) {
		t.Fatal("larger ICMP Packet Too Big value raised the PMTU")
	}
	if entry := stack.pathMTU[remote]; entry.mtu != 1000 || !entry.updated.Equal(updated) {
		t.Fatalf("larger ICMP value refreshed PMTU entry = %+v", entry)
	}
	for index := 0; index <= pathMTUMaximumEntries; index++ {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 1})
		if !stack.confirmPathMTU(address, 1400, nil) {
			t.Fatalf("PMTU confirmation %d was not recorded", index)
		}
	}
	if count := len(stack.pathMTU); count != pathMTUMaximumEntries {
		t.Fatalf("PMTU cache entries = %d, want %d", count, pathMTUMaximumEntries)
	}
}

func TestSmallerConfirmationDoesNotRefreshLargerPathMTU(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.17/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("198.51.100.17")
	updated := time.Now().Add(-time.Minute)
	stack.pathMTU[remote] = pathMTUEntry{mtu: 1400, updated: updated}
	if stack.confirmPathMTU(remote, 1200, nil) {
		t.Fatal("smaller confirmation changed the shared PMTU")
	}
	if entry := stack.pathMTU[remote]; entry.mtu != 1400 || !entry.updated.Equal(updated) {
		t.Fatalf("smaller confirmation refreshed larger PMTU entry = %+v", entry)
	}
}

func TestRoutesAndRFC6724SourceSelection(t *testing.T) {
	ula := netip.MustParseAddr("fd00::10")
	global := netip.MustParseAddr("2001:db8::10")
	ipv4 := netip.MustParseAddr("192.0.2.30")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.PrefixFrom(global, 128),
			netip.PrefixFrom(ula, 128),
			netip.PrefixFrom(ipv4, 32),
		},
		Routes: []Route{
			{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Metric: 20},
			{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Source: global, Metric: 10},
			{Destination: netip.MustParsePrefix("fd00::/8")},
			{Destination: netip.MustParsePrefix("198.51.100.0/24"), Source: ipv4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	route, err := stack.RouteFor(netip.MustParseAddr("2001:db8:1::99"))
	if err != nil {
		t.Fatal(err)
	}
	if route.Metric != 10 || route.Source != global {
		t.Fatalf("selected route = %+v", route)
	}
	if _, err = stack.RouteFor(netip.MustParseAddr("203.0.113.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("route miss = %v, want ENETUNREACH", err)
	}
	if source, err := stack.sourceForRequested(netip.MustParseAddr("fd12::1"), netip.Addr{}); err != nil || source != ula {
		t.Fatalf("ULA source = %v, %v, want %v", source, err, ula)
	}
	if source, err := stack.sourceForRequested(netip.MustParseAddr("2001:db8:1::99"), netip.Addr{}); err != nil || source != global {
		t.Fatalf("global source = %v, %v, want %v", source, err, global)
	}
	if source, err := stack.sourceForRequested(netip.MustParseAddr("198.51.100.99"), netip.Addr{}); err != nil || source != ipv4 {
		t.Fatalf("route-pinned IPv4 source = %v, %v, want %v", source, err, ipv4)
	}
}

func TestRFC6724AddressProperties(t *testing.T) {
	stable := netip.MustParseAddr("2001:db8:10::10")
	temporary := netip.MustParseAddr("2001:db8:10::20")
	deprecated := netip.MustParseAddr("2001:db8:10::30")
	destination := netip.MustParseAddr("2001:db8:10::31")
	base := Config{
		LocalAddresses: []netip.Prefix{
			netip.PrefixFrom(deprecated, 128),
			netip.PrefixFrom(temporary, 128),
			netip.PrefixFrom(stable, 128),
		},
		AddressProperties: map[netip.Addr]AddressProperties{
			deprecated: {Deprecated: true},
			temporary:  {Temporary: true},
		},
	}
	stack, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if source, sourceErr := stack.sourceForRequested(destination, netip.Addr{}); sourceErr != nil || source != stable {
		t.Fatalf("stable source preference = %v, %v, want %v", source, sourceErr, stable)
	}
	preferTemporary := base
	preferTemporary.PreferTemporaryAddresses = true
	temporaryStack, err := New(preferTemporary)
	if err != nil {
		t.Fatal(err)
	}
	if source, sourceErr := temporaryStack.sourceForRequested(destination, netip.Addr{}); sourceErr != nil || source != temporary {
		t.Fatalf("temporary source preference = %v, %v, want %v", source, sourceErr, temporary)
	}
	if source, sourceErr := stack.sourceForRequested(deprecated, netip.Addr{}); sourceErr != nil || source != deprecated {
		t.Fatalf("same deprecated source rule = %v, %v, want %v", source, sourceErr, deprecated)
	}

	base.AddressProperties[stable] = AddressProperties{Deprecated: true}
	if source, sourceErr := stack.sourceForRequested(destination, netip.Addr{}); sourceErr != nil || source != stable {
		t.Fatalf("configuration map mutation changed snapshot source = %v, %v", source, sourceErr)
	}
}

func TestRFC6724SourceScopePreference(t *testing.T) {
	linkLocal := netip.MustParseAddr("fe80::10")
	global := netip.MustParseAddr("2001:db8::10")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(global, 128),
		netip.PrefixFrom(linkLocal, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, destination := range []netip.Addr{
		netip.MustParseAddr("ff01::123"),
		netip.MustParseAddr("ff02::123"),
	} {
		source, sourceErr := stack.sourceForRequested(destination, netip.Addr{})
		if sourceErr != nil || source != linkLocal {
			t.Fatalf("source for %s = %v, %v, want %v", destination, source, sourceErr, linkLocal)
		}
	}

	destination := netip.MustParseAddr("ff0e::123")
	if source, sourceErr := stack.sourceForRequested(destination, netip.Addr{}); sourceErr != nil || source != global {
		t.Fatalf("source for %s = %v, %v, want %v", destination, source, sourceErr, global)
	}

	limited, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(linkLocal, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, destination = range []netip.Addr{
		netip.MustParseAddr("2001:db8:1::123"),
		netip.MustParseAddr("ff0e::123"),
	} {
		source, sourceErr := limited.sourceForRequested(destination, netip.Addr{})
		if sourceErr != nil || source != linkLocal {
			t.Fatalf("insufficient-scope source for %s = %v, %v, want %v", destination, source, sourceErr, linkLocal)
		}
	}
	if _, sourceErr := limited.sourceForRequested(netip.MustParseAddr("ff0e::123"), linkLocal); !errors.Is(sourceErr, syscall.ENETUNREACH) {
		t.Fatalf("explicit insufficient-scope multicast source = %v, want ENETUNREACH", sourceErr)
	}

	siteLocal := netip.MustParseAddr("fec0::10")
	scoped, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(global, 128),
		netip.PrefixFrom(siteLocal, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		destination, source netip.Addr
	}{
		{destination: netip.MustParseAddr("ff05::123"), source: siteLocal},
		{destination: netip.MustParseAddr("ff08::123"), source: global},
	} {
		source, sourceErr := scoped.sourceForRequested(test.destination, netip.Addr{})
		if sourceErr != nil || source != test.source {
			t.Fatalf("source for %s = %v, %v, want %v", test.destination, source, sourceErr, test.source)
		}
	}
}

func TestAddressPropertiesValidation(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.32")
	local6 := netip.MustParseAddr("2001:db8::32")
	base := []netip.Prefix{netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128)}
	for _, properties := range []map[netip.Addr]AddressProperties{
		{netip.MustParseAddr("198.51.100.32"): {Deprecated: true}},
		{local4: {Temporary: true}},
		{netip.IPv6Unspecified(): {Deprecated: true}},
	} {
		if _, err := New(Config{LocalAddresses: base, AddressProperties: properties}); err == nil {
			t.Fatalf("invalid address properties were accepted: %+v", properties)
		}
	}
}

func TestAddressPropertyUpdateInvalidatesPathMTU(t *testing.T) {
	stable := netip.MustParseAddr("2001:db8:20::1")
	temporary := netip.MustParseAddr("2001:db8:20::2")
	remote := netip.MustParseAddr("2001:db8:30::1")
	config := Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(stable, 128), netip.PrefixFrom(temporary, 128)}, MTU: 1500,
		AddressProperties: map[netip.Addr]AddressProperties{temporary: {Temporary: true}}}
	stack, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(remote, 1280) {
		t.Fatal("failed to install test PMTU")
	}
	config.PreferTemporaryAddresses = true
	if err = stack.UpdateConfig(config); err != nil {
		t.Fatal(err)
	}
	if mtu := stack.mtuFor(remote); mtu != 1500 {
		t.Fatalf("source-preference update retained PMTU %d, want 1500", mtu)
	}
}

func TestRFC6724AddressLabels(t *testing.T) {
	for _, test := range []struct {
		address string
		label   uint8
	}{
		{address: "192.0.2.1", label: 4},
		{address: "::1", label: 0},
		{address: "2002::1", label: 2},
		{address: "2001::1", label: 5},
		{address: "fd00::1", label: 13},
		{address: "fec0::1", label: 11},
		{address: "3ffe::1", label: 12},
		{address: "::192.0.2.1", label: 3},
		{address: "2001:db8::1", label: 1},
	} {
		if label := addressLabel(netip.MustParseAddr(test.address)); label != test.label {
			t.Errorf("addressLabel(%s) = %d, want %d", test.address, label, test.label)
		}
	}
}

func TestRFC6724AddressScopes(t *testing.T) {
	for _, test := range []struct {
		address string
		scope   uint8
	}{
		{address: "127.0.0.1", scope: 2},
		{address: "169.254.1.1", scope: 2},
		{address: "10.0.0.1", scope: 14},
		{address: "224.0.0.1", scope: 2},
		{address: "239.1.1.1", scope: 14},
		{address: "239.255.1.1", scope: 3},
		{address: "239.192.1.1", scope: 8},
		{address: "::1", scope: 2},
		{address: "fe80::1", scope: 2},
		{address: "fec0::1", scope: 5},
		{address: "fd00::1", scope: 14},
		{address: "ff01::1", scope: 1},
		{address: "ff04::1", scope: 4},
		{address: "ff05::1", scope: 5},
		{address: "ff08::1", scope: 8},
		{address: "ff0e::1", scope: 14},
	} {
		if scope := addressScope(netip.MustParseAddr(test.address)); scope != test.scope {
			t.Errorf("addressScope(%s) = %d, want %d", test.address, scope, test.scope)
		}
	}
}

func TestIPv4MulticastUsesPrimaryInterfaceAddress(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	primary := netip.MustParseAddr("10.0.0.1")
	secondary := netip.MustParseAddr("192.0.2.1")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(loopback, 8), netip.PrefixFrom(primary, 24), netip.PrefixFrom(secondary, 24),
	}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := stack.sourceForRequested(netip.MustParseAddr("239.192.0.1"), netip.Addr{})
	if err != nil || source != primary {
		t.Fatalf("IPv4 multicast source = %s, %v, want primary %s", source, err, primary)
	}
	source, err = stack.sourceForRequested(netip.MustParseAddr("255.255.255.255"), netip.Addr{})
	if err != nil || source != primary {
		t.Fatalf("limited-broadcast source = %s, %v, want primary %s", source, err, primary)
	}
	if _, err = stack.sourceForRequested(netip.MustParseAddr("127.255.255.255"), netip.Addr{}); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("loopback directed-broadcast route = %v, want ENETUNREACH", err)
	}
	if source, ok := (&multicastState{stack: stack}).reportSource(false); !ok || source != primary {
		t.Fatalf("IGMP report source = %s, %v, want primary %s", source, ok, primary)
	}
}

func TestCommonPrefixBitsRejectsInvalidAddresses(t *testing.T) {
	if bits := commonPrefixBits(netip.Addr{}, netip.Addr{}, 128); bits != 0 {
		t.Fatalf("invalid common-prefix length = %d", bits)
	}
}

func TestRFC6724CommonPrefixUsesSourcePrefixLength(t *testing.T) {
	shortPrefix := netip.MustParseAddr("2001:db8:1234:5678:aaaa::1")
	longPrefix := netip.MustParseAddr("2001:db8:1234:5000::1")
	destination := netip.MustParseAddr("2001:db8:1234:5678:bbbb::1")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(shortPrefix, 48),
		netip.PrefixFrom(longPrefix, 64),
	}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := stack.sourceForRequested(destination, netip.Addr{})
	if err != nil || source != longPrefix {
		t.Fatalf("RFC 6724 prefix-limited source = %v, %v, want %v", source, err, longPrefix)
	}
}

func TestRFC6724CommonPrefixUsesLongestRepeatedAddressPrefix(t *testing.T) {
	for _, test := range []struct {
		name                      string
		other, repeated, target   netip.Addr
		otherBits, short, longest int
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 25, 24, 32},
		{"IPv6", netip.MustParseAddr("2001:db8:1:8000::1"), netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::2"), 64, 32, 128},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, order := range []struct {
				name        string
				first, last int
			}{
				{"short-first", test.short, test.longest},
				{"longest-first", test.longest, test.short},
			} {
				t.Run(order.name, func(t *testing.T) {
					stack, err := New(Config{LocalAddresses: []netip.Prefix{
						netip.PrefixFrom(test.other, test.otherBits),
						netip.PrefixFrom(test.repeated, order.first),
						netip.PrefixFrom(test.repeated, order.last),
					}})
					if err != nil {
						t.Fatal(err)
					}
					source, err := stack.sourceForRequested(test.target, netip.Addr{})
					if err != nil || source != test.repeated {
						t.Fatalf("repeated address longest-prefix source = %v, %v, want %v", source, err, test.repeated)
					}
				})
			}
		})
	}
}

func TestUpdateConfigClosesInvalidBindings(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.40")
	ipv6 := netip.MustParseAddr("2001:db8::40")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(ipv4, 32),
		netip.PrefixFrom(ipv6, 128),
	}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	tcpListener, err := stack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(ipv4, 0))
	if err != nil {
		t.Fatal(err)
	}
	wildcardUDP, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(netip.MustParseAddr("2001:db8::99"), 1280) {
		t.Fatal("failed to install test PMTU")
	}
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(ipv6, 128)},
		MTU:            1400,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err = tcpListener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed TCP binding Accept = %v, want net.ErrClosed", err)
	}
	if _, _, err = wildcardUDP.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed UDP family ReadFrom = %v, want net.ErrClosed", err)
	}
	if _, err = stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0)); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("ListenUDP for removed family = %v, want EADDRNOTAVAIL", err)
	}
	if _, err = stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0)); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("ListenTCP for removed family = %v, want EADDRNOTAVAIL", err)
	}
	if got := stack.mtuFor(netip.MustParseAddr("2001:db8::99")); got != 1400 {
		t.Fatalf("MTU after UpdateConfig = %d, want 1400", got)
	}
	if _, err = stack.RouteFor(netip.MustParseAddr("198.51.100.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("removed IPv4 route = %v, want ENETUNREACH", err)
	}
}

func TestUpdateConfigClosesConnectedUnicastWithoutRoute(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("198.51.100.41")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	udpConnection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 53))
	if err != nil {
		t.Fatal(err)
	}
	ipConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	multicast, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.MustParseAddrPort("224.0.0.251:5353"))
	if err != nil {
		t.Fatal(err)
	}

	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		Routes:         []Route{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = udpConnection.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("connected UDP Read after route removal = %v, want net.ErrClosed", err)
	}
	if _, err = ipConnection.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("connected IP Read after route removal = %v, want net.ErrClosed", err)
	}
	if _, err = multicast.Write([]byte("still attached")); err != nil {
		t.Fatalf("multicast Write without a unicast route = %v", err)
	}
}

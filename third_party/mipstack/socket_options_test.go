package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestSocketOptionCreationPolicyValidation(t *testing.T) {
	keepAlive := KeepAliveConfig{Idle: time.Minute, Interval: time.Second, Count: 3}
	validTCP := []SocketOption{
		SocketOptions.ReadBuffer(4096), SocketOptions.WriteBuffer(8192),
		SocketOptions.KeepAlive(true), SocketOptions.KeepAliveConfig(keepAlive), SocketOptions.NoDelay(false),
		SocketOptions.IdleTimeout(0), SocketOptions.UserTimeout(0),
		SocketOptions.CongestionControl(CongestionControlReno), SocketOptions.MaximumPacingRate(0),
		SocketOptions.TrafficClass(255), SocketOptions.FlowLabel(0),
	}
	if _, err := parseSocketOptions(validTCP, socketOptionTCPDial); err != nil {
		t.Fatal(err)
	}
	validDatagram := []SocketOption{
		SocketOptions.ReadBuffer(1), SocketOptions.ReceiveErrors(true),
		SocketOptions.PathMTUDiscovery(PathMTUDiscoveryProbe), SocketOptions.HopLimit(0),
		SocketOptions.Broadcast(false), SocketOptions.MulticastHopLimit(0), SocketOptions.MulticastLoopback(false),
		SocketOptions.TrafficClass(255), SocketOptions.FlowLabel(0),
	}
	if parsed, err := parseSocketOptions(validDatagram, socketOptionUDPDial); err != nil {
		t.Fatal(err)
	} else if err = parsed.validateFamily(socketOptionUDPDial, true, false); err != nil {
		t.Fatal(err)
	}

	invalid := []struct {
		name   string
		option SocketOption
		use    socketOptionUse
		err    error
	}{
		{name: "read buffer zero", option: SocketOptions.ReadBuffer(0), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "write buffer negative", option: SocketOptions.WriteBuffer(-1), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "traffic class high", option: SocketOptions.TrafficClass(256), use: socketOptionUDPDial, err: syscall.EINVAL},
		{name: "flow label high", option: SocketOptions.FlowLabel(ipv6MaximumFlowLabel + 1), use: socketOptionIPDial, err: syscall.EINVAL},
		{name: "keepalive idle zero", option: SocketOptions.KeepAliveConfig(KeepAliveConfig{Interval: time.Second, Count: 1}), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "idle timeout negative", option: SocketOptions.IdleTimeout(-1), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "user timeout negative", option: SocketOptions.UserTimeout(-1), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "unknown congestion control", option: SocketOptions.CongestionControl("missing"), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "nil congestion factory", option: SocketOptions.CongestionControlFactory(nil), use: socketOptionTCPDial, err: syscall.EINVAL},
		{name: "negative accept queue", option: SocketOptions.AcceptQueue(-1), use: socketOptionTCPListen, err: syscall.EINVAL},
		{name: "negative SYN backlog", option: SocketOptions.SYNBacklog(-1), use: socketOptionTCPListen, err: syscall.EINVAL},
		{name: "unknown PMTU mode", option: SocketOptions.PathMTUDiscovery(PathMTUDiscoveryOmit + 1), use: socketOptionUDPDial, err: syscall.EINVAL},
		{name: "negative hop limit", option: SocketOptions.HopLimit(-1), use: socketOptionIPDial, err: syscall.EINVAL},
		{name: "high multicast hop limit", option: SocketOptions.MulticastHopLimit(256), use: socketOptionUDPListen, err: syscall.EINVAL},
		{name: "negative enabled IPv6 checksum offset", option: SocketOptions.IPv6Checksum(true, -1), use: socketOptionIPDial, err: syscall.EINVAL},
		{name: "odd enabled IPv6 checksum offset", option: SocketOptions.IPv6Checksum(true, 3), use: socketOptionIPDial, err: syscall.EINVAL},
		{name: "TCP option on UDP", option: SocketOptions.NoDelay(true), use: socketOptionUDPDial, err: syscall.ENOPROTOOPT},
		{name: "datagram option on TCP", option: SocketOptions.ReceiveErrors(true), use: socketOptionTCPDial, err: syscall.ENOPROTOOPT},
		{name: "listener option on dial", option: SocketOptions.AcceptQueue(1), use: socketOptionTCPDial, err: syscall.ENOPROTOOPT},
		{name: "write buffer on IP", option: SocketOptions.WriteBuffer(1), use: socketOptionIPDial, err: syscall.ENOPROTOOPT},
		{name: "ICMPv4 filter on UDP", option: SocketOptions.ICMPv4Filter(ICMPv4Filter{}), use: socketOptionUDPDial, err: syscall.ENOPROTOOPT},
		{name: "ICMPv6 filter on TCP", option: SocketOptions.ICMPv6Filter(ICMPv6Filter{}), use: socketOptionTCPDial, err: syscall.ENOPROTOOPT},
		{name: "IPv6 checksum on UDP", option: SocketOptions.IPv6Checksum(false, -1), use: socketOptionUDPDial, err: syscall.ENOPROTOOPT},
		{name: "invalid TCP option on UDP", option: SocketOptions.WriteBuffer(-1), use: socketOptionUDPDial, err: syscall.ENOPROTOOPT},
		{name: "invalid datagram option on TCP", option: SocketOptions.PathMTUDiscovery(PathMTUDiscoveryOmit + 1), use: socketOptionTCPDial, err: syscall.ENOPROTOOPT},
		{name: "invalid listener option on dial", option: SocketOptions.AcceptQueue(-1), use: socketOptionTCPDial, err: syscall.ENOPROTOOPT},
		{name: "invalid raw IP option on UDP", option: SocketOptions.IPv6Checksum(true, -1), use: socketOptionUDPDial, err: syscall.ENOPROTOOPT},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSocketOptions([]SocketOption{test.option}, test.use); !errors.Is(err, test.err) {
				t.Fatalf("parse error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestSocketOptionUnsetRestoresConfiguredPolicy(t *testing.T) {
	parsed, err := parseSocketOptions([]SocketOption{
		SocketOptions.ReadBuffer(1), SocketOptions.UnsetReadBuffer(),
		SocketOptions.WriteBuffer(1), SocketOptions.UnsetWriteBuffer(),
		SocketOptions.KeepAlive(false), SocketOptions.UnsetKeepAlive(),
		SocketOptions.KeepAliveConfig(KeepAliveConfig{Idle: time.Second, Interval: time.Second, Count: 1}), SocketOptions.UnsetKeepAliveConfig(),
		SocketOptions.NoDelay(false), SocketOptions.UnsetNoDelay(),
		SocketOptions.IdleTimeout(time.Second), SocketOptions.UnsetIdleTimeout(),
		SocketOptions.UserTimeout(time.Second), SocketOptions.UnsetUserTimeout(),
		SocketOptions.CongestionControl(CongestionControlReno), SocketOptions.UnsetCongestionControl(),
		SocketOptions.MaximumPacingRate(1), SocketOptions.UnsetMaximumPacingRate(),
		SocketOptions.TrafficClass(1), SocketOptions.UnsetTrafficClass(),
		SocketOptions.FlowLabel(1), SocketOptions.UnsetFlowLabel(),
	}, socketOptionTCPDial)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.tcp != (tcpSocketOptionSet{}) {
		t.Fatalf("unset TCP policy = %+v", parsed.tcp)
	}

	parsed, err = parseSocketOptions([]SocketOption{
		SocketOptions.ReadBuffer(1), SocketOptions.UnsetReadBuffer(),
		SocketOptions.ReceiveErrors(true), SocketOptions.UnsetReceiveErrors(),
		SocketOptions.PathMTUDiscovery(PathMTUDiscoveryDo), SocketOptions.UnsetPathMTUDiscovery(),
		SocketOptions.HopLimit(1), SocketOptions.UnsetHopLimit(),
		SocketOptions.Broadcast(false), SocketOptions.UnsetBroadcast(),
		SocketOptions.MulticastHopLimit(1), SocketOptions.UnsetMulticastHopLimit(),
		SocketOptions.MulticastLoopback(false), SocketOptions.UnsetMulticastLoopback(),
		SocketOptions.TrafficClass(1), SocketOptions.UnsetTrafficClass(),
		SocketOptions.FlowLabel(1), SocketOptions.UnsetFlowLabel(),
	}, socketOptionUDPDial)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.datagram != (datagramSocketOptionSet{}) {
		t.Fatalf("unset datagram policy = %+v", parsed.datagram)
	}

	var ipv4Filter ICMPv4Filter
	ipv4Filter.Block(0)
	var ipv6Filter ICMPv6Filter
	ipv6Filter.Block(129)
	parsed, err = parseSocketOptions([]SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.UnsetIPHeaderIncludedOnWrite(),
		SocketOptions.IPHeaderIncludedOnRead(true), SocketOptions.UnsetIPHeaderIncludedOnRead(),
		SocketOptions.ICMPv4Filter(ipv4Filter), SocketOptions.UnsetICMPv4Filter(),
		SocketOptions.ICMPv6Filter(ipv6Filter), SocketOptions.UnsetICMPv6Filter(),
		SocketOptions.IPv6Checksum(true, 2), SocketOptions.UnsetIPv6Checksum(),
	}, socketOptionIPListen)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ip != (ipSocketOptionSet{}) {
		t.Fatalf("unset raw IP policy = %+v", parsed.ip)
	}
}

func TestTCPCreationOptionsApplyToDialedAndAcceptedConnections(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::230")
	serverAddress := netip.MustParseAddr("2001:db8::231")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	keepAlive := KeepAliveConfig{Idle: 3 * time.Minute, Interval: 7 * time.Second, Count: 4}
	serverOptions := []SocketOption{
		SocketOptions.ReadBuffer(7001), SocketOptions.WriteBuffer(8001),
		SocketOptions.KeepAlive(true), SocketOptions.KeepAliveConfig(keepAlive), SocketOptions.NoDelay(false),
		SocketOptions.IdleTimeout(0), SocketOptions.UserTimeout(0),
		SocketOptions.CongestionControl(CongestionControlReno), SocketOptions.MaximumPacingRate(900001),
		SocketOptions.TrafficClass(0xaf), SocketOptions.FlowLabel(0x12345),
		SocketOptions.AcceptQueue(3), SocketOptions.SYNBacklog(2),
	}
	listener, err := (&ListenConfig{Options: serverOptions}).ListenTCP(context.Background(), server, "tcp6", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if info := listener.(*TCPListener).Info(); info.AcceptQueueCapacity != 3 || info.SYNBacklogCapacity != 2 {
		t.Fatalf("listener creation policy = %+v", info)
	}

	clientKeepAlive := KeepAliveConfig{Idle: 4 * time.Minute, Interval: 9 * time.Second, Count: 5}
	dialer := &Dialer{Options: []SocketOption{
		SocketOptions.ReadBuffer(7002), SocketOptions.WriteBuffer(8002),
		SocketOptions.KeepAlive(true), SocketOptions.KeepAliveConfig(clientKeepAlive), SocketOptions.NoDelay(false),
		SocketOptions.IdleTimeout(0), SocketOptions.UserTimeout(0),
		SocketOptions.CongestionControl(CongestionControlReno), SocketOptions.MaximumPacingRate(900002),
		SocketOptions.TrafficClass(0xab), SocketOptions.FlowLabel(0x23456),
	}}
	dialedNet, err := dialer.DialTCP(context.Background(), client, "tcp6", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	dialed := dialedNet.(*TCPConn)
	defer dialed.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()

	check := func(name string, info TCPConnInfo, receive, send int, keepAliveConfig KeepAliveConfig, pacing uint64, trafficClass uint8, flowLabel uint32) {
		t.Helper()
		if info.ReceiveBufferCapacity != receive || info.MaximumReceiveBuffer != receive ||
			info.SendBufferCapacity != send || info.MaximumSendBuffer != send ||
			!info.KeepAlive || info.KeepAliveConfig != keepAliveConfig || info.NoDelay ||
			info.IdleTimeout != 0 || info.UserTimeout != 0 || info.CongestionControl != CongestionControlReno ||
			info.MaximumPacingRate != pacing || info.TrafficClass != trafficClass || info.FlowLabel != flowLabel {
			t.Fatalf("%s TCP creation policy = %+v", name, info)
		}
	}
	check("dialed", dialed.Info(), 7002, 8002, clientKeepAlive, 900002, 0xa8, 0x23456)
	check("accepted", accepted.(*TCPConn).Info(), 7001, 8001, keepAlive, 900001, 0xac, 0x12345)
}

func TestTCPListenerOverridesOnlyExplicitPolicies(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.232")
	serverAddress := netip.MustParseAddr("192.0.2.233")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReadBuffer(7777), SocketOptions.NoDelay(false),
		SocketOptions.AcceptQueue(2), SocketOptions.SYNBacklog(1),
	}}).ListenTCP(context.Background(), server, "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = server.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)}, MTU: 1400,
		TCP: TCPSocketDefaults{KeepAlive: true, CongestionControl: CongestionControlBBR, MaximumPacingRate: 7654321},
	}); err != nil {
		t.Fatal(err)
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	info := accepted.(*TCPConn).Info()
	if info.ReceiveBufferCapacity != 7777 || info.MaximumReceiveBuffer != 7777 || info.NoDelay ||
		!info.KeepAlive || info.CongestionControl != CongestionControlBBR || info.MaximumPacingRate != 7654321 {
		t.Fatalf("accepted policy after UpdateConfig = %+v", info)
	}
	if listenerInfo := listener.(*TCPListener).Info(); listenerInfo.AcceptQueueCapacity != 2 || listenerInfo.SYNBacklogCapacity != 1 {
		t.Fatalf("listener policy changed with Stack defaults = %+v", listenerInfo)
	}
}

func TestDatagramCreationOptionsAndConfiguredDefaults(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.234")
	local6 := netip.MustParseAddr("2001:db8::234")
	remote6 := netip.MustParseAddr("2001:db8:1::234")
	defaults := DatagramSocketDefaults{
		ReceiveBuffer: 4096, ReceiveErrors: true, PathMTUDiscovery: PathMTUDiscoveryWant,
		HopLimit: 44, MulticastHopLimit: 5, DisableMulticastLoopback: true, DisableBroadcast: true,
		TrafficClass: 0x66, FlowLabel: 0x34567,
	}
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128)}, MTU: 1400,
		UDP: UDPSocketDefaults{DatagramSocketDefaults: defaults}, IP: IPSocketDefaults{DatagramSocketDefaults: defaults},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	unsetPacket, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReceiveErrors(false), SocketOptions.UnsetReceiveErrors(),
		SocketOptions.FlowLabel(0), SocketOptions.UnsetFlowLabel(),
	}}).ListenUDP(context.Background(), stack, "udp6", netip.AddrPortFrom(local6, 0))
	if err != nil {
		t.Fatal(err)
	}
	unsetUDP := unsetPacket.(*UDPConn)
	if info := unsetUDP.Info(); !info.ReceiveErrors || info.FlowLabel != defaults.FlowLabel {
		t.Fatalf("unset UDP policy did not inherit defaults: %+v", info)
	}
	_ = unsetUDP.Close()

	options := []SocketOption{
		SocketOptions.ReadBuffer(1), SocketOptions.ReceiveErrors(false),
		SocketOptions.PathMTUDiscovery(PathMTUDiscoveryProbe), SocketOptions.HopLimit(0),
		SocketOptions.Broadcast(true), SocketOptions.MulticastHopLimit(0), SocketOptions.MulticastLoopback(true),
		SocketOptions.TrafficClass(0), SocketOptions.FlowLabel(0),
	}
	udpNet, err := (&Dialer{Options: options}).DialUDP(context.Background(), stack, "udp6", netip.AddrPort{}, netip.AddrPortFrom(remote6, 5353))
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := udpNet.(*UDPConn)
	defer udpConnection.Close()
	if info := udpConnection.Info(); info.ReceiveQueueCapacity != udpDatagramMetadataSize || info.ReceiveErrors ||
		info.PathMTUDiscovery != PathMTUDiscoveryProbe || info.HopLimit != 0 || !info.Broadcast ||
		info.MulticastHopLimit != 0 || !info.MulticastLoopback || info.TrafficClass != 0 || info.FlowLabel != 0 {
		t.Fatalf("UDP creation policy = %+v", info)
	}

	ipConnection, err := (&ListenConfig{Options: append(options,
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.IPHeaderIncludedOnRead(true),
	)}).ListenIP(context.Background(), stack, "ip6:99", local6)
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	if info := ipConnection.(*IPConn).Info(); info.ReceiveQueueCapacity != ipDatagramMetadataSize || info.ReceiveErrors ||
		info.PathMTUDiscovery != PathMTUDiscoveryProbe || info.HopLimit != 0 || !info.Broadcast ||
		info.MulticastHopLimit != 0 || !info.MulticastLoopback || info.TrafficClass != 0 || info.FlowLabel != 0 ||
		!info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("IP creation policy = %+v", info)
	}
}

func TestIPSocketConfiguredRepresentationDefaults(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.243")
	configuration := Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		IP: IPSocketDefaults{
			IPHeaderIncludedOnWrite: true,
			IPHeaderIncludedOnRead:  true,
		},
	}
	stack, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	inherited, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer inherited.Close()
	if info := inherited.(*IPConn).Info(); !info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("configured IP representation defaults = %+v", info)
	}

	overridden, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(false),
		SocketOptions.IPHeaderIncludedOnRead(false),
	}}).ListenIP(context.Background(), stack, "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer overridden.Close()
	if info := overridden.(*IPConn).Info(); info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("explicit IP representation overrides = %+v", info)
	}

	unset, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(false), SocketOptions.UnsetIPHeaderIncludedOnWrite(),
		SocketOptions.IPHeaderIncludedOnRead(false), SocketOptions.UnsetIPHeaderIncludedOnRead(),
	}}).ListenIP(context.Background(), stack, "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer unset.Close()
	if info := unset.(*IPConn).Info(); !info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("unset IP representation defaults = %+v", info)
	}

	configuration.IP.IPHeaderIncludedOnWrite = false
	configuration.IP.IPHeaderIncludedOnRead = false
	if err = stack.UpdateConfig(configuration); err != nil {
		t.Fatal(err)
	}
	updated, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer updated.Close()
	if info := updated.(*IPConn).Info(); info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("updated IP representation defaults = %+v", info)
	}
	if info := inherited.(*IPConn).Info(); !info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("existing IP socket changed with Config = %+v", info)
	}
}

func TestSocketOptionAddressFamilyValidationDoesNotCreateEndpoint(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.235")
	remote4 := netip.MustParseAddr("198.51.100.235")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	tests := []struct {
		name string
		call func() error
		err  error
	}{
		{name: "TCP IPv4 flow label", err: syscall.EAFNOSUPPORT, call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.FlowLabel(1)}}).DialTCP(context.Background(), stack, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote4, 80))
			return callErr
		}},
		{name: "UDP IPv4 flow label", err: syscall.EAFNOSUPPORT, call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.FlowLabel(1)}}).DialUDP(context.Background(), stack, "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote4, 53))
			return callErr
		}},
		{name: "IP IPv4 flow label", err: syscall.EAFNOSUPPORT, call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.FlowLabel(1)}}).ListenIP(context.Background(), stack, "ip4:99", local4)
			return callErr
		}},
		{name: "UDP IPv4 zero hop limit", err: syscall.EINVAL, call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.HopLimit(0)}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if callErr := test.call(); !errors.Is(callErr, test.err) {
				t.Fatalf("creation error = %v, want %v", callErr, test.err)
			}
			if stats := stack.Stats(); stats.ActiveTCPConnections != 0 || stats.ActiveTCPListeners != 0 || stats.ActiveUDPSockets != 0 || stats.ActiveIPSockets != 0 {
				t.Fatalf("family validation retained endpoint state: %+v", stats)
			}
		})
	}
}

func TestRawIPSocketOptionProtocolValidationDoesNotCreateEndpoint(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.236")
	local6 := netip.MustParseAddr("2001:db8::236")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	tests := []struct {
		name    string
		network string
		local   netip.Addr
		option  SocketOption
		want    error
	}{
		{name: "IPv4 filter on IPv6-only socket", network: "ip6:icmp", local: local6, option: SocketOptions.ICMPv4Filter(ICMPv4Filter{}), want: syscall.EAFNOSUPPORT},
		{name: "IPv4 filter on another protocol", network: "ip4:99", local: local4, option: SocketOptions.ICMPv4Filter(ICMPv4Filter{}), want: syscall.ENOPROTOOPT},
		{name: "IPv6 filter on IPv4-only socket", network: "ip4:58", local: local4, option: SocketOptions.ICMPv6Filter(ICMPv6Filter{}), want: syscall.EAFNOSUPPORT},
		{name: "IPv6 filter on another protocol", network: "ip6:99", local: local6, option: SocketOptions.ICMPv6Filter(ICMPv6Filter{}), want: syscall.ENOPROTOOPT},
		{name: "IPv6 checksum on IPv4-only socket", network: "ip4:99", local: local4, option: SocketOptions.IPv6Checksum(true, 2), want: syscall.EAFNOSUPPORT},
		{name: "enabled checksum on ICMPv6", network: "ip6:ipv6-icmp", local: local6, option: SocketOptions.IPv6Checksum(true, 2), want: syscall.EINVAL},
		{name: "disabled checksum on ICMPv6", network: "ip6:ipv6-icmp", local: local6, option: SocketOptions.IPv6Checksum(false, 0), want: syscall.EINVAL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, callErr := (&ListenConfig{Options: []SocketOption{test.option}}).ListenIP(context.Background(), stack, test.network, test.local)
			if connection != nil || !errors.Is(callErr, test.want) {
				t.Fatalf("ListenIP = %v, %v, want %v", connection, callErr, test.want)
			}
			if active := stack.Stats().ActiveIPSockets; active != 0 {
				t.Fatalf("late raw option validation retained %d endpoint(s)", active)
			}
		})
	}

	var ipv4Filter ICMPv4Filter
	ipv4Filter.Block(0)
	ipv4, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ICMPv4Filter(ipv4Filter),
	}}).ListenIP(context.Background(), stack, "ip4:icmp", local4)
	if err != nil {
		t.Fatal(err)
	}
	if current, filterErr := ipv4.(*IPConn).ICMPv4Filter(); filterErr != nil || !current.WillBlock(0) {
		t.Fatalf("created IPv4 filter = %+v, %v", current, filterErr)
	}
	_ = ipv4.Close()

	var ipv6Filter ICMPv6Filter
	ipv6Filter.Block(129)
	ipv6, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ICMPv6Filter(ipv6Filter),
		SocketOptions.IPv6Checksum(false, 0), SocketOptions.UnsetIPv6Checksum(),
	}}).ListenIP(context.Background(), stack, "ip6:ipv6-icmp", local6)
	if err != nil {
		t.Fatal(err)
	}
	defer ipv6.Close()
	if current, filterErr := ipv6.(*IPConn).ICMPv6Filter(); filterErr != nil || !current.WillBlock(129) {
		t.Fatalf("created IPv6 filter = %+v, %v", current, filterErr)
	}
	if enabled, offset, checksumErr := ipv6.(*IPConn).IPv6Checksum(); checksumErr != nil || !enabled || offset != 2 {
		t.Fatalf("unset ICMPv6 checksum default = %v/%d, %v", enabled, offset, checksumErr)
	}
}

func TestSocketOptionValidationDoesNotCreateEndpoints(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.221")
	remote := netip.MustParseAddr("198.51.100.221")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	tests := []struct {
		name string
		call func() error
	}{
		{name: "TCP listen header included", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
			return callErr
		}},
		{name: "UDP listen receive IP header", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
		{name: "IP listen reuse port", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
			return callErr
		}},
		{name: "nil option", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{nil}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
		{name: "TCP dial header included", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).DialTCP(context.Background(), stack, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 80))
			return callErr
		}},
		{name: "UDP dial reuse address", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.ReuseAddress(true)}}).DialUDP(context.Background(), stack, "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 53))
			return callErr
		}},
		{name: "IP dial reuse port", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.ReusePort(true)}}).DialIP(context.Background(), stack, "ip4:99", netip.Addr{}, remote)
			return callErr
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if callErr := test.call(); !errors.Is(callErr, syscall.ENOPROTOOPT) {
				t.Fatalf("option error = %v, want ENOPROTOOPT", callErr)
			}
			if stats := stack.Stats(); stats.ActiveTCPConnections != 0 || stats.ActiveTCPListeners != 0 || stats.ActiveUDPSockets != 0 || stats.ActiveIPSockets != 0 {
				t.Fatalf("invalid option retained endpoint state: %+v", stats)
			}
		})
	}
}

func TestSocketOptionApplicabilityMatrix(t *testing.T) {
	uses := []struct {
		name string
		use  socketOptionUse
	}{
		{name: "TCP listen", use: socketOptionTCPListen},
		{name: "UDP listen", use: socketOptionUDPListen},
		{name: "IP listen", use: socketOptionIPListen},
		{name: "TCP dial", use: socketOptionTCPDial},
		{name: "UDP dial", use: socketOptionUDPDial},
		{name: "IP dial", use: socketOptionIPDial},
	}
	options := []struct {
		name                     string
		enabled, disabled, unset SocketOption
		valid                    func(socketOptionUse) bool
		setExpected              func(*socketOptionSet, bool)
	}{
		{
			name:        "ReuseAddress",
			enabled:     SocketOptions.ReuseAddress(true),
			disabled:    SocketOptions.ReuseAddress(false),
			unset:       SocketOptions.UnsetReuseAddress(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionTCPListen || use == socketOptionUDPListen },
			setExpected: func(set *socketOptionSet, enabled bool) { set.reuseAddress = enabled },
		},
		{
			name:        "ReusePort",
			enabled:     SocketOptions.ReusePort(true),
			disabled:    SocketOptions.ReusePort(false),
			unset:       SocketOptions.UnsetReusePort(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionTCPListen || use == socketOptionUDPListen },
			setExpected: func(set *socketOptionSet, enabled bool) { set.reusePort = enabled },
		},
		{
			name:     "IPHeaderIncludedOnWrite",
			enabled:  SocketOptions.IPHeaderIncludedOnWrite(true),
			disabled: SocketOptions.IPHeaderIncludedOnWrite(false),
			unset:    SocketOptions.UnsetIPHeaderIncludedOnWrite(),
			valid:    func(use socketOptionUse) bool { return use == socketOptionIPListen || use == socketOptionIPDial },
			setExpected: func(set *socketOptionSet, enabled bool) {
				set.ip.headerIncludedOnWrite = newSocketOptionBoolOverride(enabled)
			},
		},
		{
			name:     "IPHeaderIncludedOnRead",
			enabled:  SocketOptions.IPHeaderIncludedOnRead(true),
			disabled: SocketOptions.IPHeaderIncludedOnRead(false),
			unset:    SocketOptions.UnsetIPHeaderIncludedOnRead(),
			valid:    func(use socketOptionUse) bool { return use == socketOptionIPListen || use == socketOptionIPDial },
			setExpected: func(set *socketOptionSet, enabled bool) {
				set.ip.headerIncludedOnRead = newSocketOptionBoolOverride(enabled)
			},
		},
	}
	for _, option := range options {
		for _, use := range uses {
			variants := []struct {
				name     string
				value    SocketOption
				explicit bool
				enabled  bool
			}{
				{name: "enabled", value: option.enabled, explicit: true, enabled: true},
				{name: "disabled", value: option.disabled, explicit: true},
				{name: "unset", value: option.unset},
			}
			for _, variant := range variants {
				t.Run(option.name+"/"+use.name+"/"+variant.name, func(t *testing.T) {
					got, err := parseSocketOptions([]SocketOption{variant.value}, use.use)
					if !option.valid(use.use) && variant.explicit {
						if !errors.Is(err, syscall.ENOPROTOOPT) || got != (socketOptionSet{}) {
							t.Fatalf("invalid option result = %+v, %v", got, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := socketOptionSet{reuseAddress: use.use == socketOptionTCPListen}
					if variant.explicit {
						option.setExpected(&want, variant.enabled)
					}
					if got != want {
						t.Fatalf("option result = %+v, want %+v", got, want)
					}
				})
			}
		}
	}
}

func TestSocketOptionUnsetAcceptedByEveryOperation(t *testing.T) {
	uses := []struct {
		name string
		use  socketOptionUse
	}{
		{name: "TCP listen", use: socketOptionTCPListen},
		{name: "UDP listen", use: socketOptionUDPListen},
		{name: "IP listen", use: socketOptionIPListen},
		{name: "TCP dial", use: socketOptionTCPDial},
		{name: "UDP dial", use: socketOptionUDPDial},
		{name: "IP dial", use: socketOptionIPDial},
	}
	unsets := []struct {
		name   string
		option SocketOption
	}{
		{name: "ReadBuffer", option: SocketOptions.UnsetReadBuffer()},
		{name: "TrafficClass", option: SocketOptions.UnsetTrafficClass()},
		{name: "FlowLabel", option: SocketOptions.UnsetFlowLabel()},
		{name: "WriteBuffer", option: SocketOptions.UnsetWriteBuffer()},
		{name: "KeepAlive", option: SocketOptions.UnsetKeepAlive()},
		{name: "KeepAliveConfig", option: SocketOptions.UnsetKeepAliveConfig()},
		{name: "NoDelay", option: SocketOptions.UnsetNoDelay()},
		{name: "IdleTimeout", option: SocketOptions.UnsetIdleTimeout()},
		{name: "UserTimeout", option: SocketOptions.UnsetUserTimeout()},
		{name: "CongestionControl", option: SocketOptions.UnsetCongestionControl()},
		{name: "MaximumPacingRate", option: SocketOptions.UnsetMaximumPacingRate()},
		{name: "AcceptQueue", option: SocketOptions.UnsetAcceptQueue()},
		{name: "SYNBacklog", option: SocketOptions.UnsetSYNBacklog()},
		{name: "ReceiveErrors", option: SocketOptions.UnsetReceiveErrors()},
		{name: "PathMTUDiscovery", option: SocketOptions.UnsetPathMTUDiscovery()},
		{name: "HopLimit", option: SocketOptions.UnsetHopLimit()},
		{name: "Broadcast", option: SocketOptions.UnsetBroadcast()},
		{name: "MulticastHopLimit", option: SocketOptions.UnsetMulticastHopLimit()},
		{name: "MulticastLoopback", option: SocketOptions.UnsetMulticastLoopback()},
		{name: "ReuseAddress", option: SocketOptions.UnsetReuseAddress()},
		{name: "ReusePort", option: SocketOptions.UnsetReusePort()},
		{name: "IPHeaderIncludedOnWrite", option: SocketOptions.UnsetIPHeaderIncludedOnWrite()},
		{name: "IPHeaderIncludedOnRead", option: SocketOptions.UnsetIPHeaderIncludedOnRead()},
		{name: "ICMPv4Filter", option: SocketOptions.UnsetICMPv4Filter()},
		{name: "ICMPv6Filter", option: SocketOptions.UnsetICMPv6Filter()},
		{name: "IPv6Checksum", option: SocketOptions.UnsetIPv6Checksum()},
	}
	for _, unset := range unsets {
		for _, use := range uses {
			t.Run(unset.name+"/"+use.name, func(t *testing.T) {
				got, err := parseSocketOptions([]SocketOption{unset.option}, use.use)
				if err != nil {
					t.Fatal(err)
				}
				want := socketOptionSet{reuseAddress: use.use == socketOptionTCPListen}
				if got != want {
					t.Fatalf("unset result = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestSocketOptionUnsetRestoresOperationDefaults(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.220")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	tcpListener, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReuseAddress(false), SocketOptions.UnsetReuseAddress(),
		SocketOptions.ReusePort(true), SocketOptions.UnsetReusePort(),
	}}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if !tcpListener.(*TCPListener).reuseAddress || tcpListener.(*TCPListener).reusePort {
		t.Fatalf("unset TCP reuse policy = address:%v port:%v", tcpListener.(*TCPListener).reuseAddress, tcpListener.(*TCPListener).reusePort)
	}
	_ = tcpListener.Close()

	udpPacket, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReuseAddress(true), SocketOptions.UnsetReuseAddress(),
		SocketOptions.ReusePort(true), SocketOptions.UnsetReusePort(),
	}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := udpPacket.(*UDPConn)
	if udpConnection.reuseAddress || udpConnection.reusePort {
		t.Fatalf("unset UDP reuse policy = address:%v port:%v", udpConnection.reuseAddress, udpConnection.reusePort)
	}
	_ = udpConnection.Close()

	ipConnection, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.UnsetIPHeaderIncludedOnWrite(),
		SocketOptions.IPHeaderIncludedOnRead(true), SocketOptions.UnsetIPHeaderIncludedOnRead(),
	}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	if info := ipConnection.(*IPConn).Info(); info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("unset IP representation policy = %+v", info)
	}
}

func TestSocketOptionDefaultsOrderAndSnapshot(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.222")
	remote := netip.MustParseAddr("198.51.100.222")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	defaultTCP, err := (*ListenConfig)(nil).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultTCP.(*TCPListener).reuseAddress || defaultTCP.(*TCPListener).reusePort {
		t.Fatalf("default TCP reuse policy = address:%v port:%v", defaultTCP.(*TCPListener).reuseAddress, defaultTCP.(*TCPListener).reusePort)
	}
	_ = defaultTCP.Close()

	tcpOptions := []SocketOption{SocketOptions.ReuseAddress(true), SocketOptions.ReuseAddress(false)}
	tcpListener, err := (&ListenConfig{Options: tcpOptions}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if tcpListener.(*TCPListener).reuseAddress {
		t.Fatal("last TCP ReuseAddress option did not win")
	}
	tcpOptions[1] = SocketOptions.ReuseAddress(true)
	if tcpListener.(*TCPListener).reuseAddress {
		t.Fatal("TCP listener retained the caller's option slice")
	}
	_ = tcpListener.Close()

	defaultUDP, err := (*ListenConfig)(nil).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defaultUDPConn := defaultUDP.(*UDPConn)
	if defaultUDPConn.reuseAddress || defaultUDPConn.reusePort {
		t.Fatalf("default UDP reuse policy = address:%v port:%v", defaultUDPConn.reuseAddress, defaultUDPConn.reusePort)
	}
	_ = defaultUDP.Close()

	udpOptions := []SocketOption{SocketOptions.ReuseAddress(false), SocketOptions.ReuseAddress(true)}
	udpPacket, err := (&ListenConfig{Options: udpOptions}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := udpPacket.(*UDPConn)
	if !udpConnection.reuseAddress || udpConnection.reusePort {
		t.Fatalf("ordered UDP reuse policy = address:%v port:%v", udpConnection.reuseAddress, udpConnection.reusePort)
	}
	udpOptions[1] = SocketOptions.ReuseAddress(false)
	if !udpConnection.reuseAddress {
		t.Fatal("UDP socket retained the caller's option slice")
	}
	_ = udpConnection.Close()

	ipOptions := []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(false), SocketOptions.IPHeaderIncludedOnWrite(true),
		SocketOptions.IPHeaderIncludedOnRead(true), SocketOptions.IPHeaderIncludedOnRead(false),
	}
	ipConnection, err := (&ListenConfig{Options: ipOptions}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	if info := ipConnection.(*IPConn).Info(); !info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("ordered IP representation policy = %+v", info)
	}
	ipOptions[1] = SocketOptions.IPHeaderIncludedOnWrite(false)
	if !ipConnection.(*IPConn).Info().IPHeaderIncludedOnWrite {
		t.Fatal("IP socket retained the caller's option slice")
	}
	if err = ipConnection.(*IPConn).SetIPHeaderIncludedOnWrite(false); err != nil || ipConnection.(*IPConn).Info().IPHeaderIncludedOnWrite {
		t.Fatalf("runtime IPHeaderIncludedOnWrite(false) = %+v, %v", ipConnection.(*IPConn).Info(), err)
	}

	dialedNet, err := (&Dialer{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.IPHeaderIncludedOnRead(true),
	}}).DialIP(context.Background(), stack, "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	dialed := dialedNet.(*IPConn)
	defer dialed.Close()
	if info := dialed.Info(); !info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("dialed IP representation policy = %+v", info)
	}
	if _, ok := interface{}(dialed).(net.Conn); !ok {
		t.Fatal("Dialer.DialIP result does not implement net.Conn")
	}
}

func TestIPHeaderIncludedOnWriteSelectsErrorQueueRepresentationAtDelivery(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.229")
	remote := netip.MustParseAddr("198.51.100.229")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.(*IPConn).SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}

	packet := buildIPPacket(local, remote, 99, []byte("quoted-payload"), 7, true)
	parsed, ok := parseIPPacket(packet, false)
	if !ok {
		t.Fatal("failed to parse quoted packet")
	}
	networkError := ICMPError{
		Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 1,
		QuotedSource: local, QuotedTarget: remote, QuotedProtocol: 99,
		QuotedPacket: packet, QuotedPayload: parsed.payload,
	}

	connection.(*IPConn).deliverError(remote, networkError)
	if err = connection.(*IPConn).SetIPHeaderIncludedOnWrite(false); err != nil {
		t.Fatal(err)
	}
	connection.(*IPConn).deliverError(remote, networkError)
	for index, want := range [][]byte{packet, parsed.payload} {
		buffer := make([]byte, len(packet))
		messages := []SocketMessage{{Buffers: [][]byte{buffer}, OOB: make([]byte, 128)}}
		if count, readErr := connection.(*IPConn).ReadBatch(messages, MessageFlagErrorQueue); readErr != nil || count != 1 || !bytes.Equal(buffer[:messages[0].N], want) {
			t.Fatalf("error queue representation %d = count %d payload %x, %v; want %x", index, count, buffer[:messages[0].N], readErr, want)
		}
	}
}

func TestIPHeaderIncludedOnWriteLinuxRepresentation(t *testing.T) {
	t.Run("IPv4 repairs kernel-owned fields and routes by destination argument", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.223")
		routeTarget := netip.MustParseAddr("198.51.100.223")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()

		payload := []byte("header-included-ipv4")
		packet := make([]byte, 24+len(payload))
		packet[0], packet[1], packet[8], packet[9] = 0x46, 0x2e, 37, 99
		binary.BigEndian.PutUint16(packet[2:4], 1)
		binary.BigEndian.PutUint16(packet[10:12], 0xbeef)
		destination := local.As4()
		copy(packet[16:20], destination[:])
		copy(packet[20:24], []byte{1, 1, 0, 0})
		copy(packet[24:], payload)
		original := append([]byte(nil), packet...)
		if n, writeErr := connection.WriteTo(packet, ipNetAddr(routeTarget)); writeErr != nil || n != len(packet) {
			t.Fatalf("header-included IPv4 write = %d, %v", n, writeErr)
		}
		if !bytes.Equal(packet, original) {
			t.Fatal("header-included IPv4 write mutated caller storage")
		}
		output := readOutboundPacket(t, stack)
		if len(output) != len(packet) || output[0] != 0x46 || output[1] != 0x2e || output[8] != 37 || output[9] != 99 ||
			binary.BigEndian.Uint16(output[2:4]) != uint16(len(output)) || binary.BigEndian.Uint16(output[4:6]) == 0 || checksum(output[:24]) != 0 ||
			!bytes.Equal(output[12:16], local.AsSlice()) || !bytes.Equal(output[16:20], local.AsSlice()) ||
			!bytes.Equal(output[20:24], []byte{1, 1, 0, 0}) || !bytes.Equal(output[24:], payload) {
			t.Fatalf("repaired header-included IPv4 packet = %x", output)
		}
		if stack.loopback.len() != 0 {
			t.Fatal("header destination selected loopback instead of the explicit route target")
		}
	})

	t.Run("IPv6 remains byte exact and routes by destination argument", func(t *testing.T) {
		local := netip.MustParseAddr("2001:db8::223")
		routeTarget := netip.MustParseAddr("2001:db8:1::223")
		packetSource := netip.MustParseAddr("2001:db8:ffff::223")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip6:99", netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()

		payload := []byte("header-included-ipv6")
		packet := make([]byte, 40+len(payload))
		packet[0], packet[1], packet[2], packet[3] = 0x6b, 0xa5, 0x43, 0x21
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
		packet[6], packet[7] = 99, 29
		copy(packet[8:24], packetSource.AsSlice())
		copy(packet[24:40], local.AsSlice())
		copy(packet[40:], payload)
		original := append([]byte(nil), packet...)
		if n, writeErr := connection.WriteTo(packet, ipNetAddr(routeTarget)); writeErr != nil || n != len(packet) {
			t.Fatalf("header-included IPv6 write = %d, %v", n, writeErr)
		}
		if !bytes.Equal(packet, original) {
			t.Fatal("header-included IPv6 write mutated caller storage")
		}
		if output := readOutboundPacket(t, stack); !bytes.Equal(output, packet) {
			t.Fatalf("header-included IPv6 output changed:\n got %x\nwant %x", output, packet)
		}
		if stack.loopback.len() != 0 {
			t.Fatal("IPv6 header destination selected loopback instead of the explicit route target")
		}
	})
}

func TestIPReceiveHeaderPreservesCompleteReassembledPacket(t *testing.T) {
	t.Run("IPv4 options", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.224")
		remote := netip.MustParseAddr("198.51.100.224")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, "ip4:99", local)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		packet := buildTestIPv4Options(remote, local, []byte{1, 1, 0, 0})
		packet[9], packet[10], packet[11] = 99, 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:24]))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 256)
		n, source, readErr := connection.ReadFrom(buffer)
		if readErr != nil || source.String() != remote.String() || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("complete IPv4 options read = %d from %v, %v", n, source, readErr)
		}
	})

	t.Run("IPv6 extension header", func(t *testing.T) {
		local := netip.MustParseAddr("2001:db8::224")
		remote := netip.MustParseAddr("2001:db8:1::224")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, "ip6:99", local)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		payload := []byte("extension")
		packet := make([]byte, 48+len(payload))
		packet[0], packet[6], packet[7] = 0x60, 60, 43
		binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
		copy(packet[8:24], remote.AsSlice())
		copy(packet[24:40], local.AsSlice())
		copy(packet[40:48], []byte{99, 0, 1, 0, 0, 0, 0, 0})
		copy(packet[48:], payload)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 256)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("complete IPv6 extension read = %d, %v", n, readErr)
		}
	})

	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		mtu           int
	}{
		{name: "IPv4 fragments", local: netip.MustParseAddr("192.0.2.225"), remote: netip.MustParseAddr("198.51.100.225"), mtu: 600},
		{name: "IPv6 fragments", local: netip.MustParseAddr("2001:db8::225"), remote: netip.MustParseAddr("2001:db8:1::225"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := test.local.BitLen()
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: uint32(test.mtu)})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			network := "ip4:99"
			if test.local.Is6() {
				network = "ip6:99"
			}
			connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, 99, payload, test.mtu, 0x1234)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, 99, payload, test.mtu, 0x12345678, ipPacketOptions{})
			}
			for _, fragment := range fragments {
				if err = writeTestPacket(stack, fragment); err != nil {
					t.Fatal(err)
				}
			}
			buffer := make([]byte, 65535)
			n, _, readErr := connection.ReadFrom(buffer)
			packet, ok := parseIPPacket(buffer[:n], false)
			if readErr != nil || !ok || packet.source != test.remote || packet.target != test.local || packet.protocol != 99 || !bytes.Equal(packet.payload, payload) {
				t.Fatalf("complete reassembled packet = %d bytes, %+v, parsed=%v, error=%v", n, packet, ok, readErr)
			}
		})
	}
}

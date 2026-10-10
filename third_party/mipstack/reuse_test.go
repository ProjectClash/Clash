package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestTCPReusePortFlowSelectionAndRebind(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.31")
	serverAddress := netip.MustParseAddr("192.0.2.32")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	local := netip.AddrPortFrom(serverAddress, 47000)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	first, err := listenConfig.ListenTCP(context.Background(), server, "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := listenConfig.ListenTCP(context.Background(), server, "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = server.ListenTCP(context.Background(), "tcp4", local); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary listener over REUSEPORT group error = %v, want EADDRINUSE", err)
	}

	server.mu.RLock()
	state := server.tcpPassive.(*tcpPassiveState)
	registry := state.reuse.(*tcpReuseRegistry)
	ports := make(map[*TCPListener]uint16)
	for port := uint16(40000); port < 41000 && len(ports) != 2; port++ {
		remote := netip.AddrPortFrom(clientAddress, port)
		ports[registry.listener(local, local, remote)] = port
	}
	server.mu.RUnlock()
	if len(ports) != 2 {
		t.Fatal("could not find stable flows for both TCP REUSEPORT listeners")
	}

	var clients []net.Conn
	var accepted []net.Conn
	for listener, port := range ports {
		connection, dialErr := client.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(clientAddress, port), local)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clients = append(clients, connection)
		if deadlineErr := listener.SetDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
			t.Fatal(deadlineErr)
		}
		serverConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		accepted = append(accepted, serverConnection)
		if serverConnection.RemoteAddr().(*net.TCPAddr).AddrPort().Port() != port {
			t.Fatalf("REUSEPORT listener accepted source %v, want port %d", serverConnection.RemoteAddr(), port)
		}
	}
	defer func() {
		for _, connection := range clients {
			_ = connection.Close()
		}
		for _, connection := range accepted {
			_ = connection.Close()
		}
	}()

	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = server.ListenTCP(context.Background(), "tcp4", local); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("bind while one REUSEPORT listener remains = %v, want EADDRINUSE", err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := server.ListenTCP(context.Background(), "tcp4", local)
	if err != nil {
		t.Fatalf("rebind with accepted connections still active: %v", err)
	}
	_ = rebound.Close()
}

func TestReusablePortZeroAllocatesUniqueEndpoints(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	tcpConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	tcpCursor := stack.nextPort[0]
	firstTCP, err := tcpConfig.ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer firstTCP.Close()
	stack.nextPort[0] = tcpCursor
	secondTCP, err := tcpConfig.ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer secondTCP.Close()
	if firstTCP.Addr().String() == secondTCP.Addr().String() {
		t.Fatalf("SO_REUSEPORT TCP port-zero binds shared %v", firstTCP.Addr())
	}

	udpConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReuseAddress(true)}}
	udpCursor := stack.nextPort[0]
	firstUDP, err := udpConfig.ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer firstUDP.Close()
	stack.nextPort[0] = udpCursor
	secondUDP, err := udpConfig.ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer secondUDP.Close()
	if firstUDP.LocalAddr().String() == secondUDP.LocalAddr().String() {
		t.Fatalf("SO_REUSEADDR UDP port-zero binds shared %v", firstUDP.LocalAddr())
	}
}

func TestUDPReusePortFlowSelectionAndPrecedence(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("198.51.100.41")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	binding := netip.AddrPortFrom(netip.IPv4Unspecified(), 47001)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	firstPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	first := firstPacket.(*UDPConn)
	defer first.Close()
	secondPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	second := secondPacket.(*UDPConn)
	defer second.Close()
	if _, err = stack.ListenUDP(context.Background(), "udp4", binding); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary UDP bind over REUSEPORT group error = %v, want EADDRINUSE", err)
	}

	actualLocal := netip.AddrPortFrom(local, binding.Port())
	stack.mu.RLock()
	registry := stack.udpReuse.(*udpReuseRegistry)
	ports := make(map[*UDPConn]uint16)
	for port := uint16(41000); port < 42000 && len(ports) != 2; port++ {
		peer := netip.AddrPortFrom(remote, port)
		ports[registry.connection(binding, actualLocal, peer)] = port
	}
	stack.mu.RUnlock()
	if len(ports) != 2 {
		t.Fatal("could not find stable flows for both UDP REUSEPORT sockets")
	}
	for connection, port := range ports {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, port, binding.Port(), []byte{byte(port)})); err != nil {
			t.Fatal(err)
		}
		if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		n, source, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || source.(*net.UDPAddr).Port != int(port) {
			t.Fatalf("UDP REUSEPORT read = %d byte from %v, %v, want port %d", n, source, readErr, port)
		}
	}

	exactPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.AddrPortFrom(local, binding.Port()))
	if err != nil {
		t.Fatal(err)
	}
	exact := exactPacket.(*UDPConn)
	defer exact.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 43000, binding.Port(), []byte("exact"))); err != nil {
		t.Fatal(err)
	}
	if err = exact.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, _, err := exact.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "exact" {
		t.Fatalf("exact REUSEPORT binding precedence = %q, %v", buffer[:n], err)
	}
}

func TestUDPReuseOptionCompatibilityAndStablePrecedence(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.42")
	remote := netip.MustParseAddr("198.51.100.42")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	address := []SocketOption{SocketOptions.ReuseAddress(true)}
	port := []SocketOption{SocketOptions.ReusePort(true)}
	both := []SocketOption{SocketOptions.ReuseAddress(true), SocketOptions.ReusePort(true)}
	tests := []struct {
		name          string
		first, second []SocketOption
		wildcard      bool
		want          bool
	}{
		{name: "address with address", first: address, second: address, want: true},
		{name: "address with port", first: address, second: port},
		{name: "address with both", first: address, second: both, want: true},
		{name: "port with address", first: port, second: address},
		{name: "port with port", first: port, second: port, want: true},
		{name: "port with both", first: port, second: both, want: true},
		{name: "both with address", first: both, second: address, want: true},
		{name: "both with port", first: both, second: port, want: true},
		{name: "wildcard address with exact address", first: address, second: address, wildcard: true, want: true},
		{name: "wildcard address with exact port", first: address, second: port, wildcard: true},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			portNumber := uint16(47100 + index)
			firstAddress := local
			if test.wildcard {
				firstAddress = netip.IPv4Unspecified()
			}
			first, listenErr := (&ListenConfig{Options: test.first}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPortFrom(firstAddress, portNumber))
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			defer first.Close()
			second, listenErr := (&ListenConfig{Options: test.second}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPortFrom(local, portNumber))
			if test.want {
				if listenErr != nil {
					t.Fatalf("compatible second bind: %v", listenErr)
				}
				_ = second.Close()
			} else if !errors.Is(listenErr, syscall.EADDRINUSE) {
				t.Fatalf("incompatible second bind = %v, want EADDRINUSE", listenErr)
			}
		})
	}

	listenAddress := ListenConfig{Options: address}
	binding := netip.AddrPortFrom(local, 47120)
	firstPacket, err := listenAddress.ListenUDP(context.Background(), stack, "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	first := firstPacket.(*UDPConn)
	secondPacket, err := listenAddress.ListenUDP(context.Background(), stack, "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	second := secondPacket.(*UDPConn)
	thirdPacket, err := listenAddress.ListenUDP(context.Background(), stack, "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	third := thirdPacket.(*UDPConn)
	defer second.Close()

	deliver := func(want *UDPConn, value byte) {
		t.Helper()
		if err = writeTestPacket(stack, buildTestUDP(remote, local, uint16(48000)+uint16(value), binding.Port(), []byte{value})); err != nil {
			t.Fatal(err)
		}
		for _, connection := range []*UDPConn{first, second, third} {
			entries := connection.Info().ReceiveQueuePackets
			if connection == want {
				if entries != 1 {
					t.Fatalf("latest SO_REUSEADDR socket queued %d packets, want 1", entries)
				}
				buffer := make([]byte, 1)
				if n, _, readErr := connection.ReadFrom(buffer); readErr != nil || n != 1 || buffer[0] != value {
					t.Fatalf("latest SO_REUSEADDR read = %x, %v", buffer[:n], readErr)
				}
			} else if entries != 0 {
				t.Fatalf("older SO_REUSEADDR socket queued %d packets", entries)
			}
		}
	}
	deliver(third, 1)
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	deliver(third, 2)
	if err = third.Close(); err != nil {
		t.Fatal(err)
	}
	deliver(second, 3)
}

func TestTCPReuseAddressDisabledPreventsLiveConnectionRebind(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.43")
	serverAddress := netip.MustParseAddr("192.0.2.44")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	local := netip.AddrPortFrom(serverAddress, 47130)
	config := ListenConfig{Options: []SocketOption{SocketOptions.ReuseAddress(false)}}
	listener, err := config.ListenTCP(context.Background(), server, "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, local)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = server.ListenTCP(context.Background(), "tcp4", local); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("default listener over non-reusable live connection = %v, want EADDRINUSE", err)
	}
}

func TestTCPReusePortOnlyAllowsLiveConnectionRebind(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.45")
	serverAddress := netip.MustParseAddr("192.0.2.46")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	local := netip.AddrPortFrom(serverAddress, 47131)
	config := ListenConfig{Options: []SocketOption{
		SocketOptions.ReuseAddress(false),
		SocketOptions.ReusePort(true),
	}}
	listener, err := config.ListenTCP(context.Background(), server, "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, local)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := config.ListenTCP(context.Background(), server, "tcp4", local)
	if err != nil {
		t.Fatalf("SO_REUSEPORT-only rebind with live accepted connection: %v", err)
	}
	_ = rebound.Close()
}

func TestReusePortRejectsMixedDualStackGroups(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.71")
	local6 := netip.MustParseAddr("2001:db8::71")
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
	wildcard := netip.AddrPortFrom(netip.IPv6Unspecified(), 47003)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	tcp, err := listenConfig.ListenTCP(context.Background(), stack, "tcp", wildcard)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if _, err = listenConfig.ListenTCP(context.Background(), stack, "tcp6", wildcard); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("mixed dual/IPv6-only TCP group error = %v, want EADDRINUSE", err)
	}
	udp, err := listenConfig.ListenUDP(context.Background(), stack, "udp", netip.AddrPortFrom(netip.IPv6Unspecified(), 47004))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err = listenConfig.ListenUDP(context.Background(), stack, "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 47004)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("mixed dual/IPv6-only UDP group error = %v, want EADDRINUSE", err)
	}
}

func TestReusePortConfigInvalidationClosesGroups(t *testing.T) {
	removed := netip.MustParseAddr("192.0.2.81")
	retained := netip.MustParseAddr("192.0.2.82")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(removed, 32), netip.PrefixFrom(retained, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	tcpLocal := netip.AddrPortFrom(removed, 47005)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	tcpFirst, err := listenConfig.ListenTCP(context.Background(), stack, "tcp4", tcpLocal)
	if err != nil {
		t.Fatal(err)
	}
	tcpSecond, err := listenConfig.ListenTCP(context.Background(), stack, "tcp4", tcpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpLocal := netip.AddrPortFrom(removed, 47006)
	udpFirstPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", udpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpSecondPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", udpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpFirst, udpSecond := udpFirstPacket.(*UDPConn), udpSecondPacket.(*UDPConn)
	if stats := stack.Stats(); stats.ActiveTCPListeners != 2 || stats.ActiveUDPSockets != 2 {
		t.Fatalf("active REUSEPORT endpoints before update = %+v", stats)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(retained, 32)}}); err != nil {
		t.Fatal(err)
	}
	for index, listener := range []net.Listener{tcpFirst, tcpSecond} {
		if !listener.(*TCPListener).Info().Closed {
			t.Fatalf("TCP REUSEPORT listener %d remained open", index)
		}
		if _, acceptErr := listener.Accept(); !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("TCP REUSEPORT listener %d Accept = %v, want net.ErrClosed", index, acceptErr)
		}
	}
	for index, connection := range []*UDPConn{udpFirst, udpSecond} {
		if !connection.Info().Closed {
			t.Fatalf("UDP REUSEPORT socket %d remained open", index)
		}
		if _, _, readErr := connection.ReadFrom(make([]byte, 1)); !errors.Is(readErr, net.ErrClosed) {
			t.Fatalf("UDP REUSEPORT socket %d ReadFrom = %v, want net.ErrClosed", index, readErr)
		}
	}
	if stats := stack.Stats(); stats.ActiveTCPListeners != 0 || stats.ActiveUDPSockets != 0 {
		t.Fatalf("active REUSEPORT endpoints after update = %+v", stats)
	}
	stack.mu.RLock()
	defer stack.mu.RUnlock()
	if stack.tcpPassive != nil || stack.udpReuse != nil {
		t.Fatalf("empty REUSEPORT registries retained: tcp=%T udp=%T", stack.tcpPassive, stack.udpReuse)
	}
}

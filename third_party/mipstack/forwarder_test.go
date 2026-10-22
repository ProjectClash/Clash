package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func newForwarderTestStack(t *testing.T, local netip.Addr, promiscuous bool) *Stack {
	t.Helper()
	bits := 32
	if local.Is6() {
		bits = 128
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, Promiscuous: promiscuous, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

func readForwarderTestPacket(t *testing.T, stack *Stack) []byte {
	t.Helper()
	return readOutboundPacket(t, stack)
}

func TestForwarderRegistrationAndCloseLifecycle(t *testing.T) {
	type control interface {
		Close() error
		Done() <-chan struct{}
		Info() ForwarderInfo
	}
	constructors := []struct {
		name string
		new  func(*Stack) (control, error)
	}{
		{name: "TCP", new: func(stack *Stack) (control, error) {
			return NewTCPForwarder(stack, TCPForwarderOptions{}, func(*TCPForwarderRequest) {})
		}},
		{name: "UDP", new: func(stack *Stack) (control, error) {
			return NewUDPForwarder(stack, UDPForwarderOptions{}, func(*UDPForwarderRequest) {})
		}},
		{name: "IP", new: func(stack *Stack) (control, error) {
			return NewIPForwarder(stack, IPForwarderOptions{}, func(*IPForwarderRequest) {})
		}},
		{name: "ICMP", new: func(stack *Stack) (control, error) {
			return NewICMPForwarder(stack, ICMPForwarderOptions{}, func(*ICMPForwarderRequest) {})
		}},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			if _, err := constructor.new(nil); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("constructor with nil stack = %v", err)
			}
			local := netip.MustParseAddr("192.0.2.9")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				t.Fatal(err)
			}
			first, err := constructor.new(stack)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = constructor.new(stack); !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("duplicate constructor = %v", err)
			}
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-first.Done():
			default:
				t.Fatal("Done remained open after Close")
			}
			if info := first.Info(); !info.Closed || info.Pending != 0 {
				t.Fatalf("closed forwarder info = %+v", info)
			}
			if err = first.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("repeated Close = %v", err)
			}
			replacement, err := constructor.new(stack)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			stackResult, forwarderResult := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				stackResult <- stack.Close()
			}()
			go func() {
				<-start
				forwarderResult <- replacement.Close()
			}()
			close(start)
			if err = <-stackResult; err != nil {
				t.Fatalf("concurrent Stack.Close = %v", err)
			}
			if err = <-forwarderResult; err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("concurrent Forwarder.Close = %v", err)
			}
			select {
			case <-replacement.Done():
			default:
				t.Fatal("replacement Done remained open after concurrent Close")
			}
			if _, err = constructor.new(stack); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("constructor on closed stack = %v", err)
			}
		})
	}
	if _, err := NewTCPForwarder(&Stack{}, TCPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("TCP constructor with nil handler = %v", err)
	}
	if _, err := NewUDPForwarder(&Stack{}, UDPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("UDP constructor with nil handler = %v", err)
	}
	if _, err := NewICMPForwarder(&Stack{}, ICMPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ICMP constructor with nil handler = %v", err)
	}
}

func TestTCPForwarderInterceptsNonlocalDestination(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.10")
	serverAddress := netip.MustParseAddr("192.0.2.20")
	intercepted := netip.MustParseAddr("198.51.100.80")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)

	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))

	type acceptResult struct {
		connection *TCPConn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	forwarder, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		flow := request.Flow()
		if flow.Source.Addr() != clientAddress || flow.Destination != netip.AddrPortFrom(intercepted, 8080) {
			t.Errorf("TCP forwarder flow = %+v", flow)
		}
		connection, acceptErr := request.Accept(context.Background())
		accepted <- acceptResult{connection: connection, err: acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(intercepted, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	serverConnection := result.connection
	defer serverConnection.Close()
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if got := serverConnection.LocalAddr().(*net.TCPAddr).AddrPort(); got != netip.AddrPortFrom(intercepted, 8080) {
		t.Fatalf("forwarded TCP local address = %v", got)
	}
	if _, err = listener.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary wildcard listener accepted nonlocal flow: %v", err)
	}
	localClient, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer localClient.Close()
	_ = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second))
	localServer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer localServer.Close()
	if got := localServer.LocalAddr().(*net.TCPAddr).AddrPort().Addr(); got != serverAddress {
		t.Fatalf("ordinary listener local address = %v", got)
	}

	_ = clientConnection.SetDeadline(time.Now().Add(time.Second))
	_ = serverConnection.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientConnection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, err := serverConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "request" {
		t.Fatalf("forwarded TCP request = %q, %v", buffer[:n], err)
	}
	if _, err = serverConnection.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	n, err = clientConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "response" {
		t.Fatalf("forwarded TCP response = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); !info.Closed || info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
		t.Fatalf("TCP forwarder info = %+v", info)
	}
	if err = server.UpdateConfig(Config{Promiscuous: true, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if addresses := server.LocalAddresses(); len(addresses) != 0 {
		t.Fatalf("addressless forwarder local addresses = %v, want none", addresses)
	}
	if _, err = listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ordinary listener survived local-address removal: %v", err)
	}
	if _, err = localServer.Read(buffer); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("ordinary TCP connection survived local-address removal: %v", err)
	}
	_ = clientConnection.SetDeadline(time.Now().Add(time.Second))
	_ = serverConnection.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientConnection.Write([]byte("continued")); err != nil {
		t.Fatal(err)
	}
	n, err = serverConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "continued" {
		t.Fatalf("addressless forwarded TCP request = %q, %v", buffer[:n], err)
	}
	if _, err = serverConnection.Write([]byte("retained")); err != nil {
		t.Fatal(err)
	}
	n, err = clientConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "retained" {
		t.Fatalf("addressless forwarded TCP response = %q, %v", buffer[:n], err)
	}
	if err = server.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = serverConnection.Read(buffer); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("forwarded TCP survived promiscuous disable: %v", err)
	}
}

func TestTCPForwarderTimeWaitReplacesTuple(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.40")
	serverAddress := netip.MustParseAddr("192.0.2.41")
	intercepted := netip.MustParseAddr("198.51.100.40")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)
	accepted := make(chan *TCPConn, 2)
	forwarder, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		if acceptErr == nil {
			accepted <- connection
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	remote := netip.AddrPortFrom(intercepted, 8080)
	first, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := <-accepted
	if firstServer == nil {
		t.Fatal("forwarder did not accept first connection")
	}
	firstClient := first.(*TCPConn)
	if err = firstServer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	oldTimestamp := client.tcpTimestamp()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first forwarded client FIN read = %d, %v", n, readErr)
	}
	if err = firstClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first forwarded server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	waitFor(t, time.Second, func() bool { return server.Stats().ActiveTCPConnections == 1 })
	if state := firstServer.Info().State; state != TCPStateTimeWait {
		t.Fatalf("old forwarded server state = %v, want TIME-WAIT", state)
	}
	oldLocal := first.LocalAddr().(*net.TCPAddr).AddrPort()
	first.Close()
	firstServer.Close()
	waitFor(t, time.Second, func() bool { return tcpSequenceGreater(client.tcpTimestamp(), oldTimestamp) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := client.DialTCP(ctx, "tcp4", oldLocal, remote)
	if err != nil {
		t.Fatalf("same-tuple forwarded DialTCP = %v", err)
	}
	defer second.Close()
	select {
	case secondServer := <-accepted:
		defer secondServer.Close()
		if got := secondServer.LocalAddr().(*net.TCPAddr).AddrPort(); got != remote {
			t.Fatalf("replacement forwarded local address = %v, want %v", got, remote)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarder did not accept replacement connection")
	}
}

func TestTCPForwarderTimeWaitFullKeepsOwner(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.42")
	serverAddress := netip.MustParseAddr("192.0.2.43")
	intercepted := netip.MustParseAddr("198.51.100.42")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)
	type acceptResult struct {
		connection *TCPConn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	blocked := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	var requests atomic.Uint32
	forwarder, err := NewTCPForwarder(server, TCPForwarderOptions{MaxInFlight: 1}, func(request *TCPForwarderRequest) {
		switch requests.Add(1) {
		case 1:
			connection, acceptErr := request.Accept(context.Background())
			accepted <- acceptResult{connection: connection, err: acceptErr}
		case 2:
			close(blocked)
			<-release
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	remote := netip.AddrPortFrom(intercepted, 8080)
	first, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	firstServer := result.connection
	if firstServer == nil {
		t.Fatal("forwarder did not accept first connection")
	}
	firstClient := first.(*TCPConn)
	if err = firstServer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first forwarded client FIN read = %d, %v", n, readErr)
	}
	if err = firstClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first forwarded server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	waitFor(t, time.Second, func() bool { return firstServer.Info().State == TCPStateTimeWait })
	oldLocal := first.LocalAddr().(*net.TCPAddr).AddrPort()
	serverKey := tcpKey{local: remote, remote: oldLocal}
	server.mu.Lock()
	oldOwner := server.tcp[serverKey]
	server.mu.Unlock()
	if oldOwner != firstServer {
		t.Fatal("server did not retain the forwarded TIME-WAIT owner")
	}
	newSequence := uint32(firstClient.icmpSequence.Load()) + 1
	_ = first.Close()
	_ = firstServer.Close()

	blockerPort := oldLocal.Port() + 1
	if blockerPort == 0 {
		blockerPort = oldLocal.Port() - 1
	}
	blocker := buildTestTCP(clientAddress, intercepted, blockerPort, remote.Port(), 1000, 0, TCPFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(server, blocker); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("forwarder handler did not retain the blocker request")
	}
	waitFor(t, time.Second, func() bool { return forwarder.Info().Pending == 1 })
	drops := forwarder.Info().Dropped
	replacement := buildTestTCP(oldLocal.Addr(), remote.Addr(), oldLocal.Port(), remote.Port(), newSequence, 0, TCPFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(server, replacement); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return forwarder.Info().Dropped > drops })
	server.mu.Lock()
	owner := server.tcp[serverKey]
	server.mu.Unlock()
	if owner != oldOwner {
		t.Fatal("full forwarder replaced the TIME-WAIT owner")
	}
	if active := server.Stats().ActiveTCPConnections; active != 1 {
		t.Fatalf("active connections after capacity drop = %d, want 1", active)
	}
	if pending := forwarder.Info().Pending; pending != 1 {
		t.Fatalf("pending requests after capacity drop = %d, want blocker", pending)
	}
	close(release)
	released = true
	waitFor(t, time.Second, func() bool { return forwarder.Info().Pending == 0 })
}

func TestTCPForwarderCoalescesPendingSYNs(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.30")
	remote := netip.MustParseAddr("192.0.2.31")
	target := netip.MustParseAddr("198.51.100.30")
	stack := newForwarderTestStack(t, owned, true)
	entered := make(chan struct{})
	result := make(chan error, 1)
	var calls atomic.Uint32
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{MaxInFlight: 1}, func(request *TCPForwarderRequest) {
		calls.Add(1)
		close(entered)
		<-request.Done()
		_, acceptErr := request.Accept(context.Background())
		result <- acceptErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	syn := buildTestTCP(remote, target, 42000, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)
	var writers sync.WaitGroup
	for index := 0; index < 32; index++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if writeErr := writeTestPacket(stack, syn); writeErr != nil {
				t.Error(writeErr)
			}
		}()
	}
	writers.Wait()
	<-entered
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, target, 42001, 443, 200, 0, TCPFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	info := forwarder.Info()
	if calls.Load() != 1 || info.Requests != 1 || info.Dropped != 1 {
		t.Fatalf("duplicate SYN created %d handlers, info %+v", calls.Load(), info)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("invalidated TCP request Accept = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 2 {
		t.Fatalf("invalidated TCP forwarder info = %+v", info)
	}
}

func TestTCPForwarderCloseSignalsCompletedRequestHandler(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.34")
	remote := netip.MustParseAddr("192.0.2.35")
	target := netip.MustParseAddr("198.51.100.34")
	stack := newForwarderTestStack(t, local, true)
	actionComplete := make(chan struct{})
	handlerComplete := make(chan struct{})
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		if dropErr := request.Drop(); dropErr != nil {
			t.Errorf("Drop TCP request: %v", dropErr)
			return
		}
		close(actionComplete)
		<-request.Done()
		close(handlerComplete)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, target, 50003, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-actionComplete:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not complete its action")
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerComplete:
	case <-time.After(time.Second):
		t.Fatal("completed TCP request did not observe forwarder closure")
	}
}

func TestForwarderAcceptFailureAllowsRetry(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.37")
		remote := netip.MustParseAddr("192.0.2.38")
		target := netip.MustParseAddr("198.51.100.37")
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true,
			Routes: []Route{}, MTU: 1400,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		results := make(chan error, 2)
		var calls atomic.Uint32
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			if calls.Add(1) == 1 {
				_, acceptErr := request.Accept(context.Background())
				results <- acceptErr
				return
			}
			results <- request.Drop()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestTCP(remote, target, 50004, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("first TCP Accept = %v", err)
		}
		if err = stack.UpdateConfig(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
		}); err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; err != nil {
			t.Fatalf("retried TCP request: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("TCP handler calls = %d, want 2", calls.Load())
		}
	})

	t.Run("UDP", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.39")
		remote := netip.MustParseAddr("192.0.2.40")
		target := netip.MustParseAddr("198.51.100.39")
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true,
			Routes: []Route{}, MTU: 1400,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		results := make(chan error, 2)
		var calls atomic.Uint32
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			connection, acceptErr := request.Accept()
			if connection != nil {
				_ = connection.Close()
			}
			calls.Add(1)
			results <- acceptErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestUDP(remote, target, 50005, 53, []byte("query"))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("first UDP Accept = %v", err)
		}
		if err = stack.UpdateConfig(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
		}); err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; err != nil {
			t.Fatalf("retried UDP Accept: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("UDP handler calls = %d, want 2", calls.Load())
		}
	})
}

func TestPromiscuousAdmissionDoesNotImplySourceSpoofing(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.35")
	remote := netip.MustParseAddr("192.0.2.36")
	target := netip.MustParseAddr("198.51.100.35")
	stack := newForwarderTestStack(t, owned, true)
	packets := [][]byte{
		buildTestTCP(remote, target, 42500, 80, 1, 0, TCPFlagSYN, 65535, nil, nil),
		buildTestUDP(remote, target, 42501, 53, []byte("query")),
	}
	icmp := make([]byte, 8)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packets = append(packets, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true))
	for _, packet := range packets {
		if err := writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if entry, ok := waitTestPacketEntry(&stack.outbound, 30*time.Millisecond); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("bare promiscuous admission emitted response %x", response)
	}
	if got := stack.Stats().PromiscuousInboundPackets; got != uint64(len(packets)) {
		t.Fatalf("promiscuous packet count = %d", got)
	}
}

func TestPromiscuousUDPForwarderPacketInfo(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.35")
	remote := netip.MustParseAddr("198.51.100.35")
	target := netip.MustParseAddr("203.0.113.35")
	tests := []struct {
		name       string
		local      netip.Addr
		wantSource netip.Addr
	}{
		{name: "configured source", local: local, wantSource: local},
		{name: "addressless", wantSource: netip.Addr{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stack *Stack
			var err error
			if test.local.IsValid() {
				stack = newForwarderTestStack(t, test.local, true)
			} else {
				stack, err = New(Config{Promiscuous: true, MTU: 1400})
				if err != nil {
					t.Fatal(err)
				}
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
			}
			connections := make(chan *UDPConn, 1)
			handlerErrors := make(chan error, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				connection, listenErr := request.Listen()
				if listenErr != nil {
					handlerErrors <- listenErr
					return
				}
				connections <- connection
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(remote, target, 42501, 53001, []byte("promiscuous"))); err != nil {
				t.Fatal(err)
			}
			var connection *UDPConn
			select {
			case err = <-handlerErrors:
				t.Fatal(err)
			case connection = <-connections:
			}
			defer connection.Close()
			if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			payload, control := make([]byte, 64), make([]byte, 128)
			n, oobn, flags, source, err := connection.ReadMsgUDPAddrPort(payload, control)
			if err != nil || flags != 0 || string(payload[:n]) != "promiscuous" || source != netip.AddrPortFrom(remote, 42501) {
				t.Fatalf("promiscuous ReadMsgUDPAddrPort = %q/%d flags %#x source %s, %v", payload[:n], oobn, flags, source, err)
			}
			var message IPv4ControlMessage
			if err = message.Parse(control[:oobn]); err != nil || message.Dst != target {
				t.Fatalf("promiscuous packet-info = %+v, %v, want destination %s", message, err, target)
			}
			var wantSource [4]byte
			if test.wantSource.IsValid() {
				wantSource = test.wantSource.As4()
			}
			if oobn < 28 || !bytes.Equal(control[20:24], wantSource[:]) || !bytes.Equal(control[24:28], target.AsSlice()) {
				t.Fatalf("promiscuous packet-info fields = %x/%x, want %s/%s", control[20:24], control[24:28], test.wantSource, target)
			}
			if _, err = stack.Write([][]byte{buildTestUDP(remote, target, 42502, 53001, []byte("promiscuous-batch"))}, 0); err != nil {
				t.Fatal(err)
			}
			batch := []SocketMessage{{Buffers: [][]byte{make([]byte, 64)}, OOB: make([]byte, 128)}}
			if count, batchErr := connection.ReadBatch(batch, 0); batchErr != nil || count != 1 || string(batch[0].Buffers[0][:batch[0].N]) != "promiscuous-batch" {
				t.Fatalf("promiscuous ReadBatch = %d/%d, %v", count, batch[0].N, batchErr)
			}
			var batchMessage IPv4ControlMessage
			if err = batchMessage.Parse(batch[0].OOB[:batch[0].NN]); err != nil || batchMessage.Dst != target || !bytes.Equal(batch[0].OOB[20:24], wantSource[:]) || !bytes.Equal(batch[0].OOB[24:28], target.AsSlice()) {
				t.Fatalf("promiscuous batch packet-info = %+v, %v, fields %x/%x", batchMessage, err, batch[0].OOB[20:24], batch[0].OOB[24:28])
			}
		})
	}
}

func TestForwardersHandleLocalTrafficWithoutPromiscuous(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.37")
	remote := netip.MustParseAddr("192.0.2.38")
	stack := newForwarderTestStack(t, local, false)
	tcpHandled, udpHandled, icmpHandled := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	_, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		tcpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		udpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		icmpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, local, 42600, 80, 1, 0, TCPFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 42601, 53, []byte("local"))); err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 20)
	icmp[0] = 13
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, local, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	for name, handled := range map[string]<-chan struct{}{"TCP": tcpHandled, "UDP": udpHandled, "ICMP": icmpHandled} {
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Fatalf("local %s traffic did not reach forwarder", name)
		}
	}
	if got := stack.Stats().PromiscuousInboundPackets; got != 0 {
		t.Fatalf("local forwarder traffic counted as promiscuous = %d", got)
	}
}

func TestUDPForwarderUsesCompleteFlowTuple(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.40")
	firstRemote := netip.MustParseAddr("192.0.2.41")
	secondRemote := netip.MustParseAddr("192.0.2.42")
	target := netip.MustParseAddr("198.51.100.40")
	stack := newForwarderTestStack(t, owned, true)

	ordinary, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	connections := make(chan *UDPConn, 2)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if flow := request.Flow(); flow.Destination != netip.AddrPortFrom(target, 5353) {
			t.Errorf("UDP forwarder flow = %+v", flow)
		}
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept UDP: %v", acceptErr)
			return
		}
		connections <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	firstPacket := buildTestUDP(firstRemote, target, 51001, 5353, []byte("first"))
	if err = writeTestPacket(stack, firstPacket); err != nil {
		t.Fatal(err)
	}
	first := <-connections
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, err := first.Read(buffer)
	if err != nil || string(buffer[:n]) != "first" {
		t.Fatalf("first forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if got := first.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(target, 5353) {
		t.Fatalf("forwarded UDP local address = %v", got)
	}

	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51001, 5353, []byte("again"))); err != nil {
		t.Fatal(err)
	}
	n, err = first.Read(buffer)
	if err != nil || string(buffer[:n]) != "again" {
		t.Fatalf("existing forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51001, 5353, []byte("second"))); err != nil {
		t.Fatal(err)
	}
	second := <-connections
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(time.Second))
	n, err = second.Read(buffer)
	if err != nil || string(buffer[:n]) != "second" {
		t.Fatalf("second forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); info.Requests != 2 || info.Accepted != 2 {
		t.Fatalf("UDP forwarder info = %+v", info)
	}

	_ = ordinary.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err = ordinary.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary wildcard received nonlocal datagram: %v", err)
	}
	_ = ordinary.SetReadDeadline(time.Now().Add(time.Second))
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, owned, 51002, 5353, []byte("ordinary"))); err != nil {
		t.Fatal(err)
	}
	n, _, err = ordinary.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "ordinary" {
		t.Fatalf("ordinary local UDP payload = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); info.Requests != 2 {
		t.Fatalf("local UDP reached forwarder: %+v", info)
	}
	if _, err = first.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != firstRemote || parsed.protocol != ProtocolUDP {
		t.Fatalf("forwarded UDP response = %x", response)
	}
	if gotSource, gotTarget := binary.BigEndian.Uint16(parsed.payload[0:2]), binary.BigEndian.Uint16(parsed.payload[2:4]); gotSource != 5353 || gotTarget != 51001 {
		t.Fatalf("forwarded UDP response ports = %d -> %d", gotSource, gotTarget)
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51001, 5353, []byte("after close"))); err != nil {
		t.Fatal(err)
	}
	n, err = first.Read(buffer)
	if err != nil || string(buffer[:n]) != "after close" {
		t.Fatalf("accepted UDP after forwarder close = %q, %v", buffer[:n], err)
	}
}

func TestUDPForwarderListenUnconnected(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.44")
	firstRemote := netip.MustParseAddr("192.0.2.45")
	secondRemote := netip.MustParseAddr("192.0.2.46")
	target := netip.MustParseAddr("198.51.100.44")
	stack := newForwarderTestStack(t, owned, true)

	connections := make(chan *UDPConn, 1)
	var handlerCalls atomic.Uint32
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		handlerCalls.Add(1)
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen forwarded UDP: %v", listenErr)
			return
		}
		connections <- connection
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51101, 5353, []byte("first"))); err != nil {
		t.Fatal(err)
	}
	connection := <-connections
	defer connection.Close()
	if connection.RemoteAddr() != nil {
		t.Fatalf("listened UDP remote address = %v, want nil", connection.RemoteAddr())
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, source, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "first" || source != netip.AddrPortFrom(firstRemote, 51101) {
		t.Fatalf("first listened UDP datagram = %q from %v, %v", buffer[:n], source, err)
	}

	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51102, 5353, []byte("second"))); err != nil {
		t.Fatal(err)
	}
	n, source, err = connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "second" || source != netip.AddrPortFrom(secondRemote, 51102) {
		t.Fatalf("second listened UDP datagram = %q from %v, %v", buffer[:n], source, err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("UDP listener handler calls = %d, want 1", got)
	}
	if _, err = connection.Write([]byte("missing destination")); err == nil {
		t.Fatal("Write on unconnected forwarded UDP succeeded")
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("reply"), netip.AddrPortFrom(secondRemote, 51102)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != secondRemote || parsed.protocol != ProtocolUDP {
		t.Fatalf("listened UDP response = %x", response)
	}
	if gotSource, gotTarget := binary.BigEndian.Uint16(parsed.payload[0:2]), binary.BigEndian.Uint16(parsed.payload[2:4]); gotSource != 5353 || gotTarget != 51102 {
		t.Fatalf("listened UDP response ports = %d -> %d", gotSource, gotTarget)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
		t.Fatalf("UDP listener forwarder info = %+v", info)
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51101, 5353, []byte("after close"))); err != nil {
		t.Fatal(err)
	}
	n, source, err = connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "after close" || source != netip.AddrPortFrom(firstRemote, 51101) {
		t.Fatalf("listened UDP after forwarder close = %q from %v, %v", buffer[:n], source, err)
	}
}

func TestUDPForwarderListenOwnsLocalBinding(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.47")
	remote := netip.MustParseAddr("192.0.2.48")
	stack := newForwarderTestStack(t, local, false)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen local forwarded UDP: %v", listenErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	localEndpoint := netip.AddrPortFrom(local, 5354)
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 51201, localEndpoint.Port(), []byte("local"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 16)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if n, source, readErr := connection.ReadFromUDPAddrPort(buffer); readErr != nil || string(buffer[:n]) != "local" || source != netip.AddrPortFrom(remote, 51201) {
		t.Fatalf("local listened UDP = %q from %v, %v", buffer[:n], source, readErr)
	}
	if _, err = stack.ListenUDP(context.Background(), "udp4", localEndpoint); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary bind over forwarded UDP listener = %v, want EADDRINUSE", err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	ordinary, err := stack.ListenUDP(context.Background(), "udp4", localEndpoint)
	if err != nil {
		t.Fatalf("ordinary bind after forwarded listener close: %v", err)
	}
	_ = ordinary.Close()
}

func TestUDPForwarderListenConflictsWithAcceptedFlow(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.49")
	firstRemote := netip.MustParseAddr("192.0.2.60")
	secondRemote := netip.MustParseAddr("192.0.2.61")
	target := netip.MustParseAddr("198.51.100.49")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	listenResult := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if request.Flow().Source.Addr() == firstRemote {
			connection, acceptErr := request.Accept()
			if acceptErr == nil {
				accepted <- connection
			}
			return
		}
		_, listenErr := request.Listen()
		listenResult <- listenErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51301, 5355, []byte("flow"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	defer connection.Close()
	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51302, 5355, []byte("listen"))); err != nil {
		t.Fatal(err)
	}
	if err = <-listenResult; !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Listen over accepted UDP flow = %v, want EADDRINUSE", err)
	}
	if info := forwarder.Info(); info.Requests != 2 || info.Accepted != 1 || info.Dropped != 1 || info.Pending != 0 {
		t.Fatalf("conflicting UDP listener forwarder info = %+v", info)
	}
}

func TestUDPForwarderEndpointSurvivesInitialQueueDrop(t *testing.T) {
	actions := []struct {
		name string
		run  func(*UDPForwarderRequest) (*UDPConn, error)
	}{
		{name: "Accept", run: func(request *UDPForwarderRequest) (*UDPConn, error) { return request.Accept() }},
		{name: "Listen", run: func(request *UDPForwarderRequest) (*UDPConn, error) { return request.Listen() }},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.58")
			remote := netip.MustParseAddr("192.0.2.59")
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
				UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{ReceiveBuffer: udpDatagramMetadataSize}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			accepted := make(chan *UDPConn, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				connection, actionErr := action.run(request)
				if actionErr != nil {
					t.Errorf("%s after initial queue drop: %v", action.name, actionErr)
					return
				}
				accepted <- connection
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			large := bytes.Repeat([]byte{0x5a}, 32)
			if err = writeTestPacket(stack, buildTestUDP(remote, local, 51400, 5356, large)); err != nil {
				t.Fatal(err)
			}
			connection := <-accepted
			defer connection.Close()
			if info := connection.Info(); info.PacketsDropped != 1 || info.ReceiveQueuePackets != 0 {
				t.Fatalf("%s initial queue drop info = %+v", action.name, info)
			}
			if err = writeTestPacket(stack, buildTestUDP(remote, local, 51400, 5356, nil)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1)
			n, source, readErr := connection.ReadFromUDPAddrPort(buffer)
			if readErr != nil || n != 0 || source != netip.AddrPortFrom(remote, 51400) {
				t.Fatalf("%s later datagram = %d bytes from %v, %v", action.name, n, source, readErr)
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Dropped != 0 || info.Pending != 0 {
				t.Fatalf("%s forwarder info after queue drop = %+v", action.name, info)
			}
		})
	}
}

func TestPromiscuousUpdateClosesForwardedUDPListener(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.62")
	remote := netip.MustParseAddr("192.0.2.63")
	target := netip.MustParseAddr("198.51.100.62")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen forwarded UDP: %v", listenErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 51401, 5356, []byte("open"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 8)
	if _, _, err = connection.ReadFrom(buffer); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = connection.ReadFrom(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forwarded UDP listener survived promiscuous disable: %v", err)
	}
}

func TestPromiscuousUpdateClosesForwardedUDP(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.50")
	remote := netip.MustParseAddr("192.0.2.51")
	target := netip.MustParseAddr("198.51.100.50")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept UDP: %v", acceptErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52001, 52002, []byte("open"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 8)
	if _, err = connection.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{Promiscuous: true, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52001, 52002, []byte("retained"))); err != nil {
		t.Fatal(err)
	}
	if n, readErr := connection.Read(buffer); readErr != nil || string(buffer[:n]) != "retained" {
		t.Fatalf("addressless forwarded UDP payload = %q, %v", buffer[:n], readErr)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Read(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forwarded UDP survived promiscuous disable: %v", err)
	}
	if stack.Stats().PromiscuousInboundPackets == 0 {
		t.Fatal("promiscuous input was not counted")
	}
}

func TestUDPForwarderPendingConfigInvalidation(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.52")
	remote := netip.MustParseAddr("192.0.2.53")
	target := netip.MustParseAddr("198.51.100.52")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		close(entered)
		<-release
		_, acceptErr := request.Accept()
		result <- acceptErr
	})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeTestPacket(stack, buildTestUDP(remote, target, 52201, 52202, []byte("pending")))
	}()
	<-entered
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-result; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("invalidated UDP request Accept = %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("invalidated UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderReceivesReassembledNonlocalDatagram(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.55")
	remote := netip.MustParseAddr("192.0.2.56")
	target := netip.MustParseAddr("198.51.100.55")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept fragmented UDP: %v", acceptErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1800)
	complete, ok := parseIPPacket(buildTestUDP(remote, target, 52501, 52502, payload), false)
	if !ok {
		t.Fatal("failed to parse complete UDP test packet")
	}
	fragments := buildIPv4Fragments(remote, target, ProtocolUDP, complete.payload, 600, 77)
	for _, fragment := range fragments {
		if err = writeTestPacket(stack, fragment); err != nil {
			t.Fatal(err)
		}
	}
	connection := <-accepted
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	n, err := connection.Read(received)
	if err != nil || n != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("reassembled forwarded UDP = %d bytes, %v", n, err)
	}
}

func TestICMPForwarderRepliesFromOriginalDestination(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.60")
	remote := netip.MustParseAddr("192.0.2.61")
	target := netip.MustParseAddr("198.51.100.60")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		message := request.Message()
		if message.Source != remote || message.Destination != target || message.Type != 8 || message.Code != 0 || !message.IsEchoRequest() {
			t.Errorf("ICMP forwarder message = %+v", message)
			_ = request.Drop()
			return
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("ReplyEcho ICMP: %v", replyErr)
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("second ReplyEcho ICMP: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 12)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 0x5678)
	copy(icmp[8:], "ping")
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != ProtocolICMPv4 || parsed.payload[0] != 0 || !bytes.Equal(parsed.payload[4:], icmp[4:]) || checksum(parsed.payload) != 0 {
		t.Fatalf("forwarded ICMP response = %x", response)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
		t.Fatalf("second forwarded ICMP response = %x", response)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 2 {
		t.Fatalf("ICMP forwarder info = %+v", info)
	}
}

func TestICMPForwarderCloseInvalidatesRunningRequest(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.65")
	remote := netip.MustParseAddr("192.0.2.66")
	target := netip.MustParseAddr("198.51.100.65")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	actionResult := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		close(entered)
		<-release
		actionResult <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 8)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true))
	}()
	<-entered
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); !info.Closed || info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("closed ICMP forwarder info = %+v", info)
	}
	close(release)
	if err = <-actionResult; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("action after ICMP forwarder Close = %v", err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
}

func TestICMPForwarderConfigInvalidatesRunningRequest(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.67")
	remote := netip.MustParseAddr("192.0.2.68")
	target := netip.MustParseAddr("198.51.100.67")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	actionResult := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		close(entered)
		<-release
		actionResult <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 8)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true))
	}()
	<-entered
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("configuration-invalidated ICMP forwarder info = %+v", info)
	}
	close(release)
	if err = <-actionResult; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("action after ICMP configuration invalidation = %v", err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
}

func TestICMPForwarderDetachFailureCleansRequest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.69")
	stack := newForwarderTestStack(t, local, false)
	forwarder := &ICMPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		requests:         make(map[*ICMPForwarderRequest]struct{}),
	}
	forwarder.closed.Store(true)
	request := &ICMPForwarderRequest{
		forwarder: forwarder,
		packet: ipPacket{
			source: netip.MustParseAddr("198.51.100.69"), target: local,
			payload: make([]byte, 8), original: make([]byte, 28),
		},
	}
	forwarder.requests[request] = struct{}{}
	if responder, err := request.Detach(); responder != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Detach on closed ICMP forwarder = %v, %v", responder, err)
	}
	if state := forwarderRequestState(request.state.Load()); state != forwarderRequestDropped {
		t.Fatalf("failed Detach request state = %v, want dropped", state)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("failed Detach forwarder info = %+v", info)
	}
}

func TestIPForwarderDetachFailureCleansRequest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.70")
	stack := newForwarderTestStack(t, local, false)
	forwarder := &IPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		requests:         make(map[*IPForwarderRequest]struct{}),
	}
	forwarder.closed.Store(true)
	request := &IPForwarderRequest{
		forwarder: forwarder,
		packet: ipPacket{
			source: netip.MustParseAddr("198.51.100.70"), target: local,
			protocol: 99, payload: []byte("payload"), original: make([]byte, 27),
		},
	}
	forwarder.requests[request] = struct{}{}
	if responder, err := request.Detach(); responder != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Detach on closed IP forwarder = %v, %v", responder, err)
	}
	if state := forwarderRequestState(request.state.Load()); state != forwarderRequestDropped {
		t.Fatalf("failed Detach request state = %v, want dropped", state)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("failed Detach forwarder info = %+v", info)
	}
}

func TestForwarderRequestReplyAndRejectActions(t *testing.T) {
	t.Run("TCP reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.70")
		remote := netip.MustParseAddr("192.0.2.71")
		target := netip.MustParseAddr("198.51.100.70")
		stack := newForwarderTestStack(t, owned, true)
		repeated := make(chan error, 1)
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			if rejectErr := request.Reject(); rejectErr != nil {
				t.Errorf("Reject TCP: %v", rejectErr)
			}
			_, repeatedErr := request.Accept(context.Background())
			repeated <- repeatedErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestTCP(remote, target, 53001, 443, 99, 0, TCPFlagSYN, 65535, nil, nil)); err != nil {
			t.Fatal(err)
		}
		response := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(response, false)
		if !ok || parsed.source != target || parsed.target != remote || parsed.payload[13] != TCPFlagRST|TCPFlagACK || binary.BigEndian.Uint32(parsed.payload[8:12]) != 100 {
			t.Fatalf("forwarded TCP rejection = %x", response)
		}
		if err = <-repeated; !errors.Is(err, ErrForwarderRequestCompleted) {
			t.Fatalf("repeated TCP action = %v", err)
		}
	})

	t.Run("UDP reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.72")
		remote := netip.MustParseAddr("192.0.2.73")
		target := netip.MustParseAddr("198.51.100.72")
		stack := newForwarderTestStack(t, owned, true)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			if string(request.Payload()) != "query" {
				t.Errorf("UDP request payload = %q", request.Payload())
			}
			if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
				t.Errorf("Reply UDP: %v", replyErr)
			}
			if _, replyErr := request.Reply([]byte("second answer")); replyErr != nil {
				t.Errorf("second Reply UDP: %v", replyErr)
			}
			if dropErr := request.Drop(); dropErr != nil {
				t.Errorf("Drop UDP request after replies: %v", dropErr)
			}
			if _, replyErr := request.Reply([]byte("after drop")); !errors.Is(replyErr, ErrForwarderRequestCompleted) {
				t.Errorf("Reply UDP after Drop: %v", replyErr)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 53003, 53, []byte("query"))); err != nil {
			t.Fatal(err)
		}
		response := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(response, false)
		if !ok || parsed.source != target || parsed.target != remote || binary.BigEndian.Uint16(parsed.payload[0:2]) != 53 || binary.BigEndian.Uint16(parsed.payload[2:4]) != 53003 || string(parsed.payload[udpHeaderSize:]) != "answer" {
			t.Fatalf("forwarded UDP reply = %x", response)
		}
		response = readForwarderTestPacket(t, stack)
		parsed, ok = parseIPPacket(response, false)
		if !ok || string(parsed.payload[udpHeaderSize:]) != "second answer" {
			t.Fatalf("second forwarded UDP reply = %x", response)
		}
		if info := forwarder.Info(); info.Replies != 2 || info.ReplyErrors != 0 || info.Dropped != 1 {
			t.Fatalf("multi-reply UDP forwarder info = %+v", info)
		}
	})

	for _, test := range []struct {
		name                  string
		owned, remote, target netip.Addr
		protocol              byte
		requestType           byte
		responseType          byte
		responseCode          byte
	}{
		{
			name: "ICMPv4 reject", owned: netip.MustParseAddr("192.0.2.74"),
			remote: netip.MustParseAddr("192.0.2.75"), target: netip.MustParseAddr("198.51.100.74"),
			protocol: ProtocolICMPv4, requestType: 8, responseType: 3, responseCode: 13,
		},
		{
			name: "ICMPv6 reject", owned: netip.MustParseAddr("2001:db8::74"),
			remote: netip.MustParseAddr("2001:db8::75"), target: netip.MustParseAddr("2001:db8:1::74"),
			protocol: ProtocolICMPv6, requestType: 128, responseType: 1, responseCode: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, test.owned, true)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) { _ = request.Reject() })
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			icmp := make([]byte, 8)
			icmp[0] = test.requestType
			if test.protocol == ProtocolICMPv4 {
				binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			} else {
				binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(test.remote, test.target, ProtocolICMPv6, icmp))
			}
			if err = writeTestPacket(stack, buildIPPacket(test.remote, test.target, test.protocol, icmp, 1, true)); err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			validChecksum := false
			if ok {
				validChecksum = checksum(parsed.payload) == 0
				if test.protocol == ProtocolICMPv6 {
					validChecksum = transportChecksum(test.target, test.remote, ProtocolICMPv6, parsed.payload) == 0
				}
			}
			if !ok || parsed.source != test.target || parsed.target != test.remote || parsed.payload[0] != test.responseType || parsed.payload[1] != test.responseCode || !validChecksum {
				t.Fatalf("forwarded ICMP rejection = %x", response)
			}
		})
	}
}

func TestUDPForwarderReplyAllowsTerminalActions(t *testing.T) {
	actions := []struct {
		name, request, responder string
	}{
		{name: "Accept", request: "Accept"},
		{name: "Listen", request: "Listen"},
		{name: "Drop", request: "Drop"},
		{name: "Reject", request: "Reject"},
		{name: "Detach/Drop", request: "Detach", responder: "Drop"},
		{name: "Detach/Reject", request: "Detach", responder: "Reject"},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.188")
			remote := netip.MustParseAddr("192.0.2.189")
			target := netip.MustParseAddr("198.51.100.188")
			stack := newForwarderTestStack(t, local, true)
			var connection *UDPConn
			var responder *UDPForwarderResponder
			result := make(chan error, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				if _, replyErr := request.Reply([]byte("request reply")); replyErr != nil {
					result <- fmt.Errorf("Reply: %w", replyErr)
					return
				}
				var actionErr error
				switch action.request {
				case "Accept":
					connection, actionErr = request.Accept()
				case "Listen":
					connection, actionErr = request.Listen()
				case "Detach":
					responder, actionErr = request.Detach()
				case "Drop":
					actionErr = request.Drop()
				case "Reject":
					actionErr = request.Reject()
				}
				if actionErr != nil {
					result <- fmt.Errorf("%s after Reply: %w", action.request, actionErr)
					return
				}
				if _, replyErr := request.Reply([]byte("late")); !errors.Is(replyErr, ErrForwarderRequestCompleted) {
					result <- fmt.Errorf("Reply after %s = %v", action.request, replyErr)
					return
				}
				result <- nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(remote, target, 55188, 53, []byte("query"))); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}

			packet := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != ProtocolUDP || string(parsed.payload[udpHeaderSize:]) != "request reply" {
				t.Fatalf("request Reply output = %x", packet)
			}
			if connection != nil {
				defer connection.Close()
				if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 16)
				if n, readErr := connection.Read(buffer); readErr != nil || string(buffer[:n]) != "query" {
					t.Fatalf("%s initial datagram = %q, %v", action.request, buffer[:n], readErr)
				}
			}

			if responder != nil {
				if _, err = responder.Reply([]byte("responder reply")); err != nil {
					t.Fatalf("responder Reply after request Reply: %v", err)
				}
				packet = readForwarderTestPacket(t, stack)
				parsed, ok = parseIPPacket(packet, false)
				if !ok || string(parsed.payload[udpHeaderSize:]) != "responder reply" {
					t.Fatalf("responder Reply output = %x", packet)
				}
				switch action.responder {
				case "Drop":
					err = responder.Drop()
				case "Reject":
					err = responder.Reject()
				}
				if err != nil {
					t.Fatalf("responder %s after replies: %v", action.responder, err)
				}
				if _, err = responder.Reply([]byte("late")); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("responder Reply after %s = %v", action.responder, err)
				}
			}

			if action.request == "Reject" || action.responder == "Reject" {
				packet = readForwarderTestPacket(t, stack)
				parsed, ok = parseIPPacket(packet, false)
				if !ok || parsed.protocol != ProtocolICMPv4 || parsed.payload[0] != 3 || parsed.payload[1] != 3 {
					t.Fatalf("UDP rejection after Reply = %x", packet)
				}
			}
			info := forwarder.Info()
			wantReplies := uint64(1)
			if responder != nil {
				wantReplies = 2
			}
			wantAccepted, wantDropped, wantRejected := uint64(0), uint64(0), uint64(0)
			switch {
			case action.request == "Accept" || action.request == "Listen":
				wantAccepted = 1
			case action.request == "Drop" || action.responder == "Drop":
				wantDropped = 1
			case action.request == "Reject" || action.responder == "Reject":
				wantRejected = 1
			}
			if info.Pending != 0 || info.Requests != 1 || info.Accepted != wantAccepted || info.Replies != wantReplies ||
				info.ReplyErrors != 0 || info.Dropped != wantDropped || info.Rejected != wantRejected {
				t.Fatalf("%s diagnostics = %+v", action.name, info)
			}
		})
	}
}

func TestIPAndICMPForwarderReplyAllowsTerminalActions(t *testing.T) {
	for _, protocol := range []string{"IP", "ICMP"} {
		for _, action := range []string{"Drop", "Reject", "Detach/Drop", "Detach/Reject"} {
			t.Run(protocol+"/"+action, func(t *testing.T) {
				local := netip.MustParseAddr("192.0.2.190")
				remote := netip.MustParseAddr("192.0.2.191")
				target := netip.MustParseAddr("198.51.100.190")
				stack := newForwarderTestStack(t, local, true)
				result := make(chan error, 1)
				var responderReply func() error
				var responderFinish func() error
				var responderReplyAfterFinish func() error
				var forwarder interface {
					Close() error
					Info() ForwarderInfo
				}
				var err error
				if protocol == "IP" {
					forwarder, err = NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
						if replyErr := request.Reply([]byte("request reply")); replyErr != nil {
							result <- fmt.Errorf("Reply: %w", replyErr)
							return
						}
						var actionErr error
						switch action {
						case "Drop":
							actionErr = request.Drop()
						case "Reject":
							actionErr = request.Reject()
						default:
							responder, detachErr := request.Detach()
							actionErr = detachErr
							if detachErr == nil {
								responderReply = func() error { return responder.Reply([]byte("responder reply")) }
								responderReplyAfterFinish = func() error { return responder.Reply([]byte("late")) }
								switch action {
								case "Detach/Drop":
									responderFinish = responder.Drop
								case "Detach/Reject":
									responderFinish = responder.Reject
								}
							}
						}
						if actionErr != nil {
							result <- fmt.Errorf("%s after Reply: %w", action, actionErr)
							return
						}
						if replyErr := request.Reply([]byte("late")); !errors.Is(replyErr, ErrForwarderRequestCompleted) {
							result <- fmt.Errorf("Reply after %s = %v", action, replyErr)
							return
						}
						result <- nil
					})
				} else {
					forwarder, err = NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
						if replyErr := request.ReplyEcho(); replyErr != nil {
							result <- fmt.Errorf("ReplyEcho: %w", replyErr)
							return
						}
						var actionErr error
						switch action {
						case "Drop":
							actionErr = request.Drop()
						case "Reject":
							actionErr = request.Reject()
						default:
							responder, detachErr := request.Detach()
							actionErr = detachErr
							if detachErr == nil {
								responderReply = responder.ReplyEcho
								responderReplyAfterFinish = responder.ReplyEcho
								switch action {
								case "Detach/Drop":
									responderFinish = responder.Drop
								case "Detach/Reject":
									responderFinish = responder.Reject
								}
							}
						}
						if actionErr != nil {
							result <- fmt.Errorf("%s after Reply: %w", action, actionErr)
							return
						}
						if replyErr := request.ReplyEcho(); !errors.Is(replyErr, ErrForwarderRequestCompleted) {
							result <- fmt.Errorf("ReplyEcho after %s = %v", action, replyErr)
							return
						}
						result <- nil
					})
				}
				if err != nil {
					t.Fatal(err)
				}
				defer forwarder.Close()
				var input []byte
				if protocol == "IP" {
					input = buildIPPacket(remote, target, 99, []byte("request"), 1, true)
				} else {
					message := []byte{8, 0, 0, 0, 1, 2, 3, 4}
					binary.BigEndian.PutUint16(message[2:4], checksum(message))
					input = buildIPPacket(remote, target, ProtocolICMPv4, message, 1, true)
				}
				if err = writeTestPacket(stack, input); err != nil {
					t.Fatal(err)
				}
				if err = <-result; err != nil {
					t.Fatal(err)
				}

				packet := readForwarderTestPacket(t, stack)
				parsed, ok := parseIPPacket(packet, false)
				if !ok || parsed.source != target || parsed.target != remote {
					t.Fatalf("request Reply output = %x", packet)
				}
				if protocol == "IP" {
					if parsed.protocol != 99 || string(parsed.payload) != "request reply" {
						t.Fatalf("IP request Reply output = %+v", parsed)
					}
				} else if parsed.protocol != ProtocolICMPv4 || parsed.payload[0] != 0 {
					t.Fatalf("ICMP request Reply output = %+v", parsed)
				}

				if responderReply != nil {
					if err = responderReply(); err != nil {
						t.Fatalf("responder Reply after request Reply: %v", err)
					}
					packet = readForwarderTestPacket(t, stack)
					parsed, ok = parseIPPacket(packet, false)
					if !ok || parsed.source != target || parsed.target != remote {
						t.Fatalf("responder Reply output = %x", packet)
					}
					if err = responderFinish(); err != nil {
						t.Fatalf("responder %s after replies: %v", action, err)
					}
					if err = responderReplyAfterFinish(); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("responder Reply after %s = %v", action, err)
					}
				}
				if action == "Reject" || action == "Detach/Reject" {
					packet = readForwarderTestPacket(t, stack)
					parsed, ok = parseIPPacket(packet, false)
					if !ok || parsed.protocol != ProtocolICMPv4 {
						t.Fatalf("%s rejection after Reply = %x", protocol, packet)
					}
				}
				info := forwarder.Info()
				wantReplies := uint64(1)
				if responderReply != nil {
					wantReplies = 2
				}
				wantDropped, wantRejected := uint64(0), uint64(0)
				if action == "Drop" || action == "Detach/Drop" {
					wantDropped = 1
				} else if action == "Reject" || action == "Detach/Reject" {
					wantRejected = 1
				}
				if info.Pending != 0 || info.Requests != 1 || info.Replies != wantReplies || info.ReplyErrors != 0 ||
					info.Dropped != wantDropped || info.Rejected != wantRejected {
					t.Fatalf("%s/%s diagnostics = %+v", protocol, action, info)
				}
			})
		}
	}
}

func TestUDPForwarderRequestConcurrentReplyAndTerminalAction(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.192")
	remote := netip.MustParseAddr("192.0.2.193")
	target := netip.MustParseAddr("198.51.100.192")
	stack := newForwarderTestStack(t, local, true)
	type result struct {
		replies int
		err     error
	}
	results := make(chan result, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		const attempts = 32
		start := make(chan struct{})
		errorsCh := make(chan error, attempts)
		for index := 0; index < attempts; index++ {
			go func(index int) {
				<-start
				_, replyErr := request.Reply([]byte{byte(index)})
				errorsCh <- replyErr
			}(index)
		}
		dropped := make(chan error, 1)
		go func() {
			<-start
			dropped <- request.Drop()
		}()
		close(start)
		succeeded := 0
		for index := 0; index < attempts; index++ {
			replyErr := <-errorsCh
			if replyErr == nil {
				succeeded++
			} else if !errors.Is(replyErr, ErrForwarderRequestCompleted) {
				results <- result{err: fmt.Errorf("concurrent Reply: %w", replyErr)}
				return
			}
		}
		if dropErr := <-dropped; dropErr != nil {
			results <- result{err: fmt.Errorf("concurrent Drop: %w", dropErr)}
			return
		}
		if _, replyErr := request.Reply([]byte("late")); !errors.Is(replyErr, ErrForwarderRequestCompleted) {
			results <- result{err: fmt.Errorf("Reply after Drop = %v", replyErr)}
			return
		}
		results <- result{replies: succeeded}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55192, 53, []byte("race"))); err != nil {
		t.Fatal(err)
	}
	got := <-results
	if got.err != nil {
		t.Fatal(got.err)
	}
	queued := 0
	for stack.outbound.len() != 0 {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			break
		}
		packet := consumeTestPacket(&stack.outbound, entry)
		parsed, valid := parseIPPacket(packet, false)
		if !valid || parsed.source != target || parsed.target != remote || parsed.protocol != ProtocolUDP || len(parsed.payload) != udpHeaderSize+1 {
			t.Fatalf("concurrent Reply output = %x", packet)
		}
		queued++
	}
	if queued != got.replies {
		t.Fatalf("concurrent Reply queued %d packets for %d successes", queued, got.replies)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Requests != 1 || info.Replies != uint64(got.replies) ||
		info.ReplyErrors != 0 || info.Dropped != 1 || info.Rejected != 0 {
		t.Fatalf("concurrent request diagnostics = %+v, replies=%d", info, got.replies)
	}
}

func TestForwarderOutputActionsDoNotBlockOnFullQueue(t *testing.T) {
	awaitBestEffort := func(t *testing.T, stack *Stack, packet []byte, result <-chan error) {
		t.Helper()
		writeResult := make(chan error, 1)
		go func() { writeResult <- writeTestPacket(stack, packet) }()
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		actionResult := result
		for actionResult != nil || writeResult != nil {
			select {
			case err := <-actionResult:
				if err != nil {
					t.Fatalf("full-queue best-effort action = %v", err)
				}
				actionResult = nil
			case err := <-writeResult:
				if err != nil {
					t.Fatalf("full-queue Stack.Write error = %v", err)
				}
				writeResult = nil
			case <-timer.C:
				if actionResult != nil && writeResult != nil {
					t.Fatal("full-queue action and Stack.Write blocked")
				}
				if actionResult != nil {
					t.Fatal("full-queue action blocked")
				}
				t.Fatal("full-queue Stack.Write blocked")
			}
		}
		if got := stack.Stats().OutboundQueueDrops; got != 1 {
			t.Fatalf("full-queue best-effort action counted %d outbound queue drops, want 1", got)
		}
	}

	t.Run("TCP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.100")
		remote := netip.MustParseAddr("192.0.2.101")
		target := netip.MustParseAddr("198.51.100.100")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestTCP(remote, target, 55001, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)
		awaitBestEffort(t, stack, packet, result)
		if info := forwarder.Info(); info.Pending != 0 || info.Rejected != 1 {
			t.Fatalf("full-queue TCP forwarder info = %+v", info)
		}
	})

	t.Run("UDP Reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.102")
		remote := netip.MustParseAddr("192.0.2.103")
		target := netip.MustParseAddr("198.51.100.102")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			_, replyErr := request.Reply([]byte("answer"))
			result <- replyErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestUDP(remote, target, 55002, 53, []byte("query"))
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("UDP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.104")
		remote := netip.MustParseAddr("192.0.2.105")
		target := netip.MustParseAddr("198.51.100.104")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestUDP(remote, target, 55003, 5353, []byte("reject"))
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("IP Reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.110")
		remote := netip.MustParseAddr("192.0.2.111")
		target := netip.MustParseAddr("198.51.100.110")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
			result <- request.Reply([]byte("answer"))
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildIPPacket(remote, target, 253, []byte("query"), 1, true)
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("IP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.112")
		remote := netip.MustParseAddr("192.0.2.113")
		target := netip.MustParseAddr("198.51.100.112")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildIPPacket(remote, target, 252, []byte("reject"), 1, true)
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("ICMP Reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.106")
		remote := netip.MustParseAddr("192.0.2.107")
		target := netip.MustParseAddr("198.51.100.106")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			reply := append([]byte(nil), request.Message().Payload...)
			reply[0] = 0
			result <- request.Reply(reply)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		packet := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("ICMP ReplyEcho", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.114")
		remote := netip.MustParseAddr("192.0.2.115")
		target := netip.MustParseAddr("198.51.100.114")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			result <- request.ReplyEcho()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = ICMPv4TypeEchoRequest
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		packet := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
		awaitBestEffort(t, stack, packet, result)
	})

	t.Run("ICMP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.108")
		remote := netip.MustParseAddr("192.0.2.109")
		target := netip.MustParseAddr("198.51.100.108")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		packet := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
		awaitBestEffort(t, stack, packet, result)
	})
}

func TestTCPForwarderAcceptResumesAfterFullPacketQueue(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.116")
	remote := netip.MustParseAddr("192.0.2.117")
	target := netip.MustParseAddr("198.51.100.116")
	stack := newForwarderTestStack(t, owned, true)
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	type acceptResult struct {
		connection *TCPConn
		err        error
	}
	result := make(chan acceptResult, 1)
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		result <- acceptResult{connection: connection, err: acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	local := netip.AddrPortFrom(target, 443)
	peer := netip.AddrPortFrom(remote, 55007)
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeTestPacket(stack, buildTestTCP(remote, target, peer.Port(), local.Port(), 100, 0, TCPFlagSYN, 65535, nil, nil))
	}()
	select {
	case err = <-writeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stack.Write blocked in TCP forwarder")
	}
	key := tcpKey{local: local, remote: peer}
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.RLock()
		connection = stack.tcp[key]
		stack.mu.RUnlock()
		return connection != nil
	})
	infoResult := make(chan TCPConnInfo, 1)
	go func() { infoResult <- connection.Info() }()
	select {
	case info := <-infoResult:
		if info.State != TCPStateSYNReceived || info.Retransmissions != 0 {
			t.Fatalf("full-queue forwarded handshake info = %+v", info)
		}
	case <-time.After(time.Second):
		t.Fatal("full-queue forwarded handshake blocked diagnostics")
	}

	var synACK ipPacket
	for attempts := cap(stack.outbound.free) + 1; attempts != 0; attempts-- {
		packet := readOutboundPacket(t, stack)
		parsed, valid := parseIPPacket(packet, false)
		if valid && parsed.protocol == ProtocolTCP && len(parsed.payload) >= tcpHeaderSize && parsed.payload[13]&byte(TCPFlagSYN|TCPFlagACK) == byte(TCPFlagSYN|TCPFlagACK) {
			synACK = parsed
			break
		}
	}
	if synACK.original == nil {
		t.Fatal("forwarded SYN-ACK was not published after device capacity returned")
	}
	serverSequence := binary.BigEndian.Uint32(synACK.payload[4:8])
	ack := buildTestTCP(remote, target, peer.Port(), local.Port(), 101, serverSequence+1, TCPFlagACK, 65535, nil, nil)
	if err = writeTestPacket(stack, ack); err != nil {
		t.Fatal(err)
	}
	select {
	case accepted := <-result:
		if accepted.err != nil || accepted.connection != connection {
			t.Fatalf("forwarded Accept after capacity returned = %p, %v; want %p, nil", accepted.connection, accepted.err, connection)
		}
		_ = accepted.connection.SetLinger(0)
		_ = accepted.connection.Close()
	case <-time.After(time.Second):
		t.Fatal("forwarded Accept did not complete after device capacity returned")
	}
}

func TestUDPForwarderFragmentedReplyIsBestEffort(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.110")
	remote := netip.MustParseAddr("192.0.2.111")
	target := netip.MustParseAddr("198.51.100.110")
	stack := newForwarderTestStack(t, owned, true)
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	entry, ok := stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("filled packet queue could not be dequeued")
	}
	stack.outbound.release(entry)
	before := stack.outbound.len()
	result := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.Reply(bytes.Repeat([]byte{0x5a}, 1800))
		result <- replyErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55004, 5353, []byte("fragment"))); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatalf("fragmented Reply with one slot = %v", err)
	}
	if got := stack.outbound.len(); got != before+1 {
		t.Fatalf("best-effort fragmented UDP reply changed queue depth from %d to %d, want %d", before, got, before+1)
	}
}

func TestUDPForwarderFragmentedReply(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.114")
	serverAddress := netip.MustParseAddr("192.0.2.115")
	target := netip.MustParseAddr("198.51.100.114")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)
	payload := bytes.Repeat([]byte{0x6b}, 1800)
	replyResult := make(chan error, 1)
	forwarder, err := NewUDPForwarder(server, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.Reply(payload)
		replyResult <- replyErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	connection, err := client.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(target, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("fragmented reply")); err != nil {
		t.Fatal(err)
	}
	if err = <-replyResult; err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	n, err := connection.Read(received)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(received[:n], payload) {
		t.Fatalf("fragmented UDP Reply length=%d want=%d", n, len(payload))
	}
}

func TestUDPForwarderReplyUsesSocketDefaults(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::108")
	remote := netip.MustParseAddr("2001:db8::109")
	target := netip.MustParseAddr("2001:db8:1::108")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, Promiscuous: true, MTU: 1400,
		UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{HopLimit: 37, TrafficClass: 0x2e, FlowLabel: 0x54321}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
			t.Errorf("Reply UDP with configured defaults: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52900, 53, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != ProtocolUDP {
		t.Fatalf("configured UDP forwarder response = %x", response)
	}
	if parsed.hopLimit != 37 || parsed.trafficClass != 0x2e || parsed.flowLabel != 0x54321 {
		t.Fatalf("configured UDP output fields = hop %d, class %#x, label %#x", parsed.hopLimit, parsed.trafficClass, parsed.flowLabel)
	}
}

func TestUDPForwarderReplyUsesAutomaticFlowLabel(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::110")
	remote := netip.MustParseAddr("2001:db8::111")
	target := netip.MustParseAddr("2001:db8:1::110")
	stack := newForwarderTestStack(t, local, true)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
			t.Errorf("Reply UDP with automatic flow label: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	const sourcePort, targetPort = 52901, 53
	if err = writeTestPacket(stack, buildTestUDP(remote, target, sourcePort, targetPort, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok {
		t.Fatalf("automatic-label UDP forwarder response = %x", response)
	}
	want := stack.automaticTransportFlowLabel(target, remote, ProtocolUDP, targetPort, sourcePort)
	if parsed.flowLabel != want {
		t.Fatalf("automatic UDP flow label = %#x, want %#x", parsed.flowLabel, want)
	}
}

func TestUDPForwarderDetachedReply(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.116")
	remote := netip.MustParseAddr("192.0.2.117")
	target := netip.MustParseAddr("198.51.100.116")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	packet := buildTestUDP(remote, target, 55007, 53, []byte("async query"))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	for index := range packet {
		packet[index] = 0
	}
	if got := responder.Flow(); got != (ForwarderFlow{Source: netip.AddrPortFrom(remote, 55007), Destination: netip.AddrPortFrom(target, 53)}) {
		t.Fatalf("detached UDP flow = %+v", got)
	}
	if got := string(responder.Payload()); got != "async query" {
		t.Fatalf("detached UDP payload = %q", got)
	}
	if info := forwarder.Info(); info.Pending != 0 {
		t.Fatalf("detached UDP forwarder info = %+v", info)
	}
	result := make(chan error, 1)
	go func() {
		_, replyErr := responder.Reply([]byte("async answer"))
		result <- replyErr
	}()
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != remote || string(parsed.payload[udpHeaderSize:]) != "async answer" {
		t.Fatalf("detached UDP response = %x", response)
	}
	if _, err = responder.Reply([]byte("second answer")); err != nil {
		t.Fatal(err)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || string(parsed.payload[udpHeaderSize:]) != "second answer" {
		t.Fatalf("second detached UDP response = %x", response)
	}
	if err = responder.Drop(); err != nil {
		t.Fatalf("Drop detached UDP responder after replies = %v", err)
	}
	if err = responder.RestrictToReplies(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("RestrictToReplies after Drop = %v", err)
	}
	if got := string(responder.Payload()); got != "async query" {
		t.Fatalf("failed restriction changed UDP payload = %q", got)
	}
	if err = responder.Reject(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reject dropped detached UDP responder = %v", err)
	}
	if _, err = responder.Reply([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply closed detached UDP responder = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Replies != 2 || info.Dropped != 1 {
		t.Fatalf("completed detached UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderReplyFrom(t *testing.T) {
	for _, test := range []struct {
		name           string
		local, remote  netip.Addr
		target, source netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.146"), netip.MustParseAddr("192.0.2.147"), netip.MustParseAddr("198.51.100.146"), netip.MustParseAddr("203.0.113.146")},
		{"IPv6", netip.MustParseAddr("2001:db8::146"), netip.MustParseAddr("2001:db8::147"), netip.MustParseAddr("2001:db8:1::146"), netip.MustParseAddr("2001:db8:2::146")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, test.local, true)
			const remotePort, targetPort, sourcePort = 55146, 53, 0
			results := make(chan error, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				for _, invalid := range []netip.AddrPort{
					{},
					netip.MustParseAddrPort("[2001:db8::1]:1"),
				} {
					if test.local.Is6() {
						if invalid.IsValid() {
							invalid = netip.MustParseAddrPort("192.0.2.1:1")
						}
					}
					if _, replyErr := request.ReplyFrom([]byte("invalid"), invalid); !errors.Is(replyErr, syscall.EINVAL) {
						results <- replyErr
						return
					}
				}
				_, replyErr := request.ReplyFrom([]byte("selected"), netip.AddrPortFrom(test.source, sourcePort))
				results <- replyErr
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(test.remote, test.target, remotePort, targetPort, []byte("query"))); err != nil {
				t.Fatal(err)
			}
			if err = <-results; err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.source != test.source || parsed.target != test.remote || parsed.protocol != ProtocolUDP ||
				binary.BigEndian.Uint16(parsed.payload[:2]) != sourcePort || binary.BigEndian.Uint16(parsed.payload[2:4]) != remotePort ||
				string(parsed.payload[udpHeaderSize:]) != "selected" || transportChecksum(parsed.source, parsed.target, ProtocolUDP, parsed.payload) != 0 {
				t.Fatalf("ReplyFrom output = %x", response)
			}
			if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 2 || info.Dropped != 0 {
				t.Fatalf("ReplyFrom diagnostics = %+v", info)
			}
		})
	}
}

func TestUDPForwarderReplyFromPreservesConfiguredBroadcastSource(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.146")
	remote := netip.MustParseAddr("198.51.100.147")
	target := netip.MustParseAddr("203.0.113.146")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)},
		Promiscuous:    true,
		MTU:            1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	result := make(chan [2]error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.ReplyFrom([]byte("answer"), netip.AddrPortFrom(broadcast, 53))
		result <- [2]error{replyErr, request.Drop()}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55146, 53, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	resultErrors := <-result
	if resultErrors[0] != nil {
		t.Fatalf("configured-broadcast ReplyFrom = %v", resultErrors[0])
	}
	if resultErrors[1] != nil {
		t.Fatalf("Drop after configured-broadcast ReplyFrom = %v", resultErrors[1])
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != broadcast || parsed.target != remote || string(parsed.payload[udpHeaderSize:]) != "answer" {
		t.Fatalf("configured-broadcast ReplyFrom output = %x", response)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 1 {
		t.Fatalf("configured-broadcast ReplyFrom diagnostics = %+v", info)
	}
}

func TestICMPForwarderReplyIPPacketPreservesConfiguredBroadcastSource(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.150")
	remote := netip.MustParseAddr("198.51.100.151")
	target := netip.MustParseAddr("203.0.113.150")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)},
		Promiscuous:    true,
		MTU:            1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	result := make(chan [2]error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		reply := makeForwarderICMPEchoReplyPacket(broadcast, remote, []byte("answer"))
		result <- [2]error{request.ReplyIPPacket(reply), request.Drop()}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 8+len("query"))
	icmp[0] = 8
	copy(icmp[8:], "query")
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	resultErrors := <-result
	if resultErrors[0] != nil {
		t.Fatalf("configured-broadcast ReplyIPPacket = %v", resultErrors[0])
	}
	if resultErrors[1] != nil {
		t.Fatalf("Drop after configured-broadcast ReplyIPPacket = %v", resultErrors[1])
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != broadcast || parsed.target != remote || string(parsed.payload[8:]) != "answer" {
		t.Fatalf("configured-broadcast ReplyIPPacket output = %x", response)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 1 {
		t.Fatalf("configured-broadcast ReplyIPPacket diagnostics = %+v", info)
	}
}

func TestUDPForwarderReplyFromPreservesSpecialSources(t *testing.T) {
	for _, test := range []struct {
		name                          string
		local, remote, target, source netip.Addr
	}{
		{"IPv4 configured unicast", netip.MustParseAddr("192.0.2.178"), netip.MustParseAddr("192.0.2.179"), netip.MustParseAddr("198.51.100.178"), netip.MustParseAddr("192.0.2.178")},
		{"IPv4 unspecified", netip.MustParseAddr("192.0.2.180"), netip.MustParseAddr("192.0.2.181"), netip.MustParseAddr("198.51.100.180"), netip.IPv4Unspecified()},
		{"IPv4 multicast", netip.MustParseAddr("192.0.2.182"), netip.MustParseAddr("192.0.2.183"), netip.MustParseAddr("198.51.100.182"), netip.MustParseAddr("224.0.0.1")},
		{"IPv4 loopback", netip.MustParseAddr("192.0.2.184"), netip.MustParseAddr("192.0.2.185"), netip.MustParseAddr("198.51.100.184"), netip.MustParseAddr("127.0.0.1")},
		{"IPv4 limited broadcast", netip.MustParseAddr("192.0.2.186"), netip.MustParseAddr("192.0.2.187"), netip.MustParseAddr("198.51.100.186"), netip.MustParseAddr("255.255.255.255")},
		{"IPv6 configured unicast", netip.MustParseAddr("2001:db8::178"), netip.MustParseAddr("2001:db8::179"), netip.MustParseAddr("2001:db8:1::178"), netip.MustParseAddr("2001:db8::178")},
		{"IPv6 unspecified", netip.MustParseAddr("2001:db8::180"), netip.MustParseAddr("2001:db8::181"), netip.MustParseAddr("2001:db8:1::180"), netip.IPv6Unspecified()},
		{"IPv6 multicast", netip.MustParseAddr("2001:db8::182"), netip.MustParseAddr("2001:db8::183"), netip.MustParseAddr("2001:db8:1::182"), netip.MustParseAddr("ff02::1")},
		{"IPv6 loopback", netip.MustParseAddr("2001:db8::184"), netip.MustParseAddr("2001:db8::185"), netip.MustParseAddr("2001:db8:1::184"), netip.IPv6Loopback()},
		{"IPv6 zoned link-local", netip.MustParseAddr("2001:db8::186"), netip.MustParseAddr("2001:db8::187"), netip.MustParseAddr("2001:db8:1::186"), netip.MustParseAddr("fe80::1").WithZone("test")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, test.local, true)
			result := make(chan [2]error, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				_, replyErr := request.ReplyFrom([]byte("answer"), netip.AddrPortFrom(test.source, 53))
				result <- [2]error{replyErr, request.Drop()}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(test.remote, test.target, 55180, 53, []byte("query"))); err != nil {
				t.Fatal(err)
			}
			for index, actionErr := range <-result {
				if actionErr != nil {
					t.Fatalf("action %d = %v", index, actionErr)
				}
			}
			packet := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.source != test.source.WithZone("").Unmap() || parsed.target != test.remote || string(parsed.payload[udpHeaderSize:]) != "answer" {
				t.Fatalf("special-source ReplyFrom output = %x", packet)
			}
			if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 1 {
				t.Fatalf("special-source ReplyFrom diagnostics = %+v", info)
			}
		})
	}
}

func TestUDPForwarderReplyFromLoopback(t *testing.T) {
	for _, test := range []struct {
		name, network string
		address       netip.Addr
	}{
		{"IPv4", "udp4", netip.MustParseAddr("127.0.0.1")},
		{"IPv6", "udp6", netip.IPv6Loopback()},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.address.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.address, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()

			const clientPort, targetPort = 55146, 55147
			result := make(chan error, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				if flow := request.Flow(); !flow.Source.Addr().IsLoopback() || flow.Destination != netip.AddrPortFrom(test.address, targetPort) {
					result <- fmt.Errorf("loopback flow = %+v", flow)
					return
				}
				_, replyErr := request.ReplyFrom([]byte("answer"), request.Flow().Destination)
				result <- replyErr
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()

			client, err := stack.DialUDP(context.Background(), test.network, netip.AddrPortFrom(test.address, clientPort), netip.AddrPortFrom(test.address, targetPort))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = client.Write([]byte("query")); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 16)
			n, err := client.Read(buffer)
			if err != nil || string(buffer[:n]) != "answer" {
				t.Fatalf("loopback ReplyFrom = %q, %v", buffer[:n], err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 0 {
				t.Fatalf("loopback ReplyFrom diagnostics = %+v", info)
			}
		})
	}
}

func TestUDPForwarderReplyPreservesLoopbackSourceForRemotePeer(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	remote := netip.MustParseAddr("192.0.2.147")
	stack := newForwarderTestStack(t, local, false)
	result := make(chan [3]error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.Reply([]byte("answer"))
		_, replyFromErr := request.ReplyFrom([]byte("answer"), request.Flow().Destination)
		result <- [3]error{replyErr, replyFromErr, request.Drop()}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 55148, 53, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	resultErrors := <-result
	for index, replyErr := range resultErrors[:2] {
		if replyErr != nil {
			t.Fatalf("loopback source reply %d = %v", index, replyErr)
		}
	}
	if resultErrors[2] != nil {
		t.Fatalf("Drop after static loopback failures = %v", resultErrors[2])
	}
	for index := 0; index < 2; index++ {
		packet := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.source != local || parsed.target != remote || string(parsed.payload[udpHeaderSize:]) != "answer" {
			t.Fatalf("loopback source reply %d output = %x", index, packet)
		}
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 2 || info.ReplyErrors != 0 || info.Dropped != 1 {
		t.Fatalf("loopback source diagnostics = %+v", info)
	}
}

func TestUDPForwarderDetachedReplyFromConcurrent(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.148")
	remote := netip.MustParseAddr("192.0.2.149")
	target := netip.MustParseAddr("198.51.100.148")
	stack := newForwarderTestStack(t, local, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55148, 53, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	sources := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.148:1001"),
		netip.MustParseAddrPort("203.0.113.149:1002"),
	}
	errorsCh := make(chan error, len(sources))
	for index, source := range sources {
		go func(index int, source netip.AddrPort) {
			_, replyErr := responder.ReplyFrom([]byte{byte(index)}, source)
			errorsCh <- replyErr
		}(index, source)
	}
	for range sources {
		if err = <-errorsCh; err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[netip.AddrPort]byte, len(sources))
	for range sources {
		parsed, ok := parseIPPacket(readForwarderTestPacket(t, stack), false)
		if !ok || parsed.protocol != ProtocolUDP || parsed.target != remote || len(parsed.payload) != udpHeaderSize+1 {
			t.Fatalf("detached ReplyFrom output = %+v", parsed)
		}
		seen[netip.AddrPortFrom(parsed.source, binary.BigEndian.Uint16(parsed.payload[:2]))] = parsed.payload[udpHeaderSize]
	}
	for index, source := range sources {
		if seen[source] != byte(index) {
			t.Fatalf("detached ReplyFrom source %v payload = %d, want %d", source, seen[source], index)
		}
	}
}

func TestUDPForwarderDetachedTerminalActions(t *testing.T) {
	for _, action := range []string{"Drop", "Reject"} {
		t.Run(action, func(t *testing.T) {
			owned := netip.MustParseAddr("192.0.2.120")
			remote := netip.MustParseAddr("192.0.2.121")
			target := netip.MustParseAddr("198.51.100.120")
			stack := newForwarderTestStack(t, owned, true)
			detached := make(chan *UDPForwarderResponder, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				responder, detachErr := request.Detach()
				if detachErr != nil {
					t.Errorf("Detach UDP: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(remote, target, 55008, 53, []byte("terminal"))); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			if action == "Drop" {
				err = responder.Drop()
			} else {
				err = responder.Reject()
			}
			if err != nil {
				t.Fatalf("%s detached UDP: %v", action, err)
			}
			info := forwarder.Info()
			if action == "Drop" {
				if info.Dropped != 1 || info.Rejected != 0 {
					t.Fatalf("dropped detached UDP info = %+v", info)
				}
				if packet, ok := stack.outbound.tryDequeue(); ok {
					stack.outbound.release(packet)
					t.Fatal("detached UDP Drop emitted a packet")
				}
			} else {
				if info.Dropped != 0 || info.Rejected != 1 {
					t.Fatalf("rejected detached UDP info = %+v", info)
				}
				response := readForwarderTestPacket(t, stack)
				parsed, ok := parseIPPacket(response, false)
				if !ok || parsed.protocol != ProtocolICMPv4 || parsed.payload[0] != 3 || parsed.payload[1] != 3 {
					t.Fatalf("detached UDP rejection = %x", response)
				}
			}
		})
	}
}

func TestICMPForwarderDetachedReply(t *testing.T) {
	for _, offload := range []bool{false, true} {
		t.Run(fmt.Sprintf("header-offload-%t", offload), func(t *testing.T) {
			owned := netip.MustParseAddr("192.0.2.118")
			remote := netip.MustParseAddr("192.0.2.119")
			target := netip.MustParseAddr("198.51.100.118")
			stack := newForwarderTestStack(t, owned, true)
			var policy RXChecksumOffload
			policy.SetIPv4Header(offload)
			stack.SetRXChecksumOffload(policy)
			detached := make(chan *ICMPForwarderResponder, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				responder, detachErr := request.Detach()
				if detachErr != nil {
					t.Errorf("Detach ICMP: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			echo := ICMPMessage{Source: remote, Destination: target}
			if err = echo.SetEchoRequest(0, 0, []byte("ping")); err != nil {
				t.Fatal(err)
			}
			icmp, err := echo.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			packet := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
			badHeader := append([]byte(nil), packet...)
			badHeader[10] ^= 1
			if offload {
				packet = badHeader
			} else {
				if err = writeTestPacket(stack, badHeader); err != nil {
					t.Fatal(err)
				}
				select {
				case <-detached:
					t.Fatal("invalid IPv4 header reached the forwarder without offload")
				default:
				}
			}
			before := append([]byte(nil), packet...)
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			var responder *ICMPForwarderResponder
			select {
			case responder = <-detached:
			default:
				t.Fatal("synchronous ICMP handler did not detach the accepted request")
			}
			for index := range packet {
				packet[index] = 0
			}
			message := responder.Message()
			if message.Source != remote || message.Destination != target || message.Type != 8 || message.Code != 0 || string(message.Payload[8:]) != "ping" {
				t.Fatalf("detached ICMP message = %+v", message)
			}
			fullPacket := responder.IPPacket()
			if !bytes.Equal(fullPacket, before) || len(message.Payload) == 0 || &message.Payload[0] != &fullPacket[20] {
				t.Fatal("detached ICMP packet and message do not share one owned snapshot")
			}
			if _, parseErr := ParseIPPacket(fullPacket); (parseErr != nil) != offload {
				t.Fatalf("public snapshot checksum validation with offload %t = %v", offload, parseErr)
			}
			result := make(chan error, 1)
			go func() { result <- responder.ReplyEcho() }()
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.source != target || parsed.target != remote || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
				t.Fatalf("detached ICMP response = %x", response)
			}
			if err = responder.ReplyEcho(); err != nil {
				t.Fatal(err)
			}
			response = readForwarderTestPacket(t, stack)
			parsed, ok = parseIPPacket(response, false)
			if !ok || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
				t.Fatalf("second detached ICMP response = %x", response)
			}
			if info := forwarder.Info(); info.Pending != 0 || info.Replies != 2 {
				t.Fatalf("completed detached ICMP forwarder info = %+v", info)
			}
		})
	}
}

func TestICMPForwarderIPPacketRequestLifetime(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.150")
	remote := netip.MustParseAddr("192.0.2.151")
	target := netip.MustParseAddr("198.51.100.150")
	stack := newForwarderTestStack(t, local, true)
	result := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		message := request.Message()
		packet := request.IPPacket()
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.source != remote || parsed.target != target || len(message.Payload) == 0 || &message.Payload[0] != &parsed.payload[0] {
			result <- syscall.EINVAL
			return
		}
		result <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := []byte{13, 0, 0, 0, 1, 2, 3, 4}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}

func makeForwarderICMPErrorPacket(source, target netip.Addr, quoted []byte) []byte {
	icmp := make([]byte, 8+len(quoted))
	copy(icmp[8:], quoted)
	protocol := byte(ProtocolICMPv6)
	if source.Is4() {
		protocol = ProtocolICMPv4
		icmp[0], icmp[1] = 3, 1
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	} else {
		icmp[0] = 1
		binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(source, target, protocol, icmp))
	}
	return buildIPPacket(source, target, protocol, icmp, 0, false)
}

func makeForwarderICMPEchoReplyPacket(source, target netip.Addr, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	copy(icmp[8:], payload)
	protocol := byte(ProtocolICMPv6)
	icmp[0] = 129
	if source.Is4() {
		protocol = ProtocolICMPv4
		icmp[0] = 0
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	} else {
		binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(source, target, protocol, icmp))
	}
	return buildIPPacket(source, target, protocol, icmp, 0, false)
}

func prependIPv6AtomicFragment(packet []byte, identification uint32) []byte {
	result := make([]byte, len(packet)+8)
	copy(result[:40], packet[:40])
	result[6] = 44
	result[40] = packet[6]
	result[41] = 0xa5
	binary.BigEndian.PutUint16(result[42:44], 6)
	binary.BigEndian.PutUint32(result[44:48], identification)
	copy(result[48:], packet[40:])
	binary.BigEndian.PutUint16(result[4:6], uint16(len(result)-40))
	return result
}

func makeNoncanonicalIPv6AtomicFragmentPacket(packet []byte, identification uint32) []byte {
	result := make([]byte, len(packet)+24)
	copy(result[:40], packet[:40])
	result[6] = 60
	result[40] = 44
	result[48] = 43
	result[49] = 0xa5
	binary.BigEndian.PutUint16(result[50:52], 6)
	binary.BigEndian.PutUint32(result[52:56], identification)
	result[56] = ProtocolICMPv6
	copy(result[64:], packet[40:])
	binary.BigEndian.PutUint16(result[4:6], uint16(len(result)-40))
	return result
}

func TestICMPForwarderReplyIPPacketKnownAnswers(t *testing.T) {
	tests := []struct {
		name        string
		destination netip.Addr
		input       string
		want        string
		ipv4DF      bool
	}{
		{
			name:        "IPv4 options",
			destination: netip.MustParseAddr("192.0.2.10"),
			input: "462e0001123440002501aabbc633640ac000020a00aabbcc" +
				"000012340001000201020304",
			want: "462e0024123440002501562fc633640ac000020a00000000" +
				"0000fbf60001000201020304",
			ipv4DF: true,
		},
		{
			name:        "IPv6 atomic Fragment",
			destination: netip.MustParseAddr("2001:db8::a"),
			input: "62e0000000012c2520010db800010000000000000000000a20010db800000000000000000000000a" +
				"3aa5000612345678810012340001000201020304",
			want: "62e0000000142c2520010db800010000000000000000000a20010db800000000000000000000000a" +
				"3a0000001234567881001f290001000201020304",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := mustCodecVector(t, test.input)
			before := append([]byte(nil), input...)
			reply, err := prepareICMPForwarderIPPacket(input, test.destination)
			want := mustCodecVector(t, test.want)
			if err != nil || !bytes.Equal(reply.packet, want) || reply.ipv4DF != test.ipv4DF {
				t.Fatalf("ReplyIPPacket normalization = DF %t error %v\n got %x\nwant %x",
					reply.ipv4DF, err, reply.packet, want)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("ReplyIPPacket normalization modified caller storage")
			}
			parsed, ok := parseIPPacket(reply.packet, false)
			if !ok || parsed.parameterError || parsed.target != test.destination || parsed.protocol != ProtocolICMPv4 && parsed.protocol != ProtocolICMPv6 {
				t.Fatalf("normalized ReplyIPPacket metadata = %+v, valid %t", parsed, ok)
			}
			if parsed.source.Is4() {
				headerLength := int(reply.packet[0]&0xf) * 4
				if referenceChecksum(reply.packet[:headerLength]) != 0 || referenceChecksum(parsed.payload) != 0 {
					t.Fatal("normalized IPv4 ReplyIPPacket checksums are invalid")
				}
			} else if referenceTransportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
				t.Fatal("normalized IPv6 ReplyIPPacket checksum is invalid")
			}
		})
	}
}

func TestICMPForwarderReplyIPPacketNormalization(t *testing.T) {
	for _, test := range []struct {
		name                  string
		local, remote, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.152"), netip.MustParseAddr("192.0.2.153"), netip.MustParseAddr("198.51.100.152")},
		{"IPv6", netip.MustParseAddr("2001:db8::152"), netip.MustParseAddr("2001:db8::153"), netip.MustParseAddr("2001:db8:1::152")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, test.local, true)
			results := make(chan error, 1)
			var callerPacket []byte
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				quoted := append([]byte(nil), request.IPPacket()...)
				callerPacket = makeForwarderICMPErrorPacket(test.target, test.remote, quoted)
				headerSize := 40
				if test.remote.Is4() {
					headerSize = 20
					callerPacket[1], callerPacket[8] = 0x2e, 37
					binary.BigEndian.PutUint16(callerPacket[2:4], 1)
					callerPacket[10], callerPacket[11] = 0x12, 0x34
				} else {
					callerPacket[0], callerPacket[1], callerPacket[7] = 0x62, 0xe0, 37
					binary.BigEndian.PutUint16(callerPacket[4:6], 1)
				}
				callerPacket[headerSize+2], callerPacket[headerSize+3] = 0x12, 0x34
				copy(callerPacket[len(callerPacket)-len(quoted):], quoted)
				replyErr := request.ReplyIPPacket(callerPacket)
				for index := range callerPacket {
					callerPacket[index] = 0xa5
				}
				results <- replyErr
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			requestICMP := []byte{13, 0, 0, 0, 1, 2, 3, 4}
			protocol := byte(ProtocolICMPv6)
			if test.remote.Is4() {
				protocol = ProtocolICMPv4
				binary.BigEndian.PutUint16(requestICMP[2:4], checksum(requestICMP))
			} else {
				binary.BigEndian.PutUint16(requestICMP[2:4], transportChecksum(test.remote, test.target, protocol, requestICMP))
			}
			requestPacket := buildIPPacket(test.remote, test.target, protocol, requestICMP, 1, true)
			if err = writeTestPacket(stack, requestPacket); err != nil {
				t.Fatal(err)
			}
			if err = <-results; err != nil {
				t.Fatal(err)
			}
			output := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(output, false)
			if !ok || parsed.source != test.target || parsed.target != test.remote || !bytes.Equal(parsed.payload[8:], requestPacket) {
				t.Fatalf("ReplyIPPacket output = %x", output)
			}
			if parsed.source.Is4() {
				if parsed.hopLimit != 37 || parsed.trafficClass != 0x2e || checksum(parsed.payload) != 0 || binary.BigEndian.Uint16(output[4:6]) == 0 {
					t.Fatalf("normalized IPv4 ReplyIPPacket = %x", output)
				}
			} else if parsed.hopLimit != 37 || parsed.trafficClass != 0x2e || transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
				t.Fatalf("normalized IPv6 ReplyIPPacket = %x", output)
			}
			if bytes.Contains(output, bytes.Repeat([]byte{0xa5}, 16)) {
				t.Fatal("ReplyIPPacket retained caller storage")
			}
		})
	}
}

func TestICMPForwarderReplyIPPacketValidationAllowsLaterAction(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.154")
	remote := netip.MustParseAddr("192.0.2.155")
	target := netip.MustParseAddr("198.51.100.154")
	stack := newForwarderTestStack(t, local, true)
	result := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		invalid := [][]byte{
			nil,
			make([]byte, 19),
			buildIPPacket(target, netip.MustParseAddr("192.0.2.156"), ProtocolICMPv4, make([]byte, 8), 0, false),
			buildIPPacket(target, remote, ProtocolUDP, make([]byte, 8), 0, false),
		}
		for _, packet := range invalid {
			if replyErr := request.ReplyIPPacket(packet); !errors.Is(replyErr, syscall.EINVAL) {
				result <- replyErr
				return
			}
		}
		if replyErr := request.ReplyIPPacket(makeForwarderICMPEchoReplyPacket(netip.MustParseAddr("127.0.0.1"), remote, nil)); replyErr != nil {
			result <- replyErr
			return
		}
		result <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := []byte{13, 0, 0, 0, 1, 2, 3, 4}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != netip.MustParseAddr("127.0.0.1") || parsed.target != remote {
		t.Fatalf("loopback-source ReplyIPPacket output = %x", response)
	}
	if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 4 || info.Dropped != 1 {
		t.Fatalf("ReplyIPPacket validation diagnostics = %+v", info)
	}
}

func TestICMPForwarderReplyIPPacketFragmentation(t *testing.T) {
	for _, test := range []struct {
		name                  string
		local, remote, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.156"), netip.MustParseAddr("192.0.2.157"), netip.MustParseAddr("198.51.100.156")},
		{"IPv6", netip.MustParseAddr("2001:db8::156"), netip.MustParseAddr("2001:db8::157"), netip.MustParseAddr("2001:db8:1::156")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, test.local, true)
			result := make(chan error, 1)
			quoted := bytes.Repeat([]byte{0x5a}, 2500)
			var fittingFlow, terminalFlow outputFlowKey
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				reply := makeForwarderICMPErrorPacket(test.target, test.remote, quoted)
				payloadOffset := 20
				protocol := byte(ProtocolICMPv4)
				if test.remote.Is4() {
					options := []byte{7, 7, 8, 0, 0, 0, 0, 148, 4, 0, 0, 0}
					headerSize := 20 + len(options)
					withOptions := make([]byte, headerSize+len(reply)-20)
					copy(withOptions[:20], reply[:20])
					copy(withOptions[20:headerSize], options)
					copy(withOptions[headerSize:], reply[20:])
					withOptions[0] = 0x40 | byte(headerSize/4)
					reply = withOptions
					payloadOffset = headerSize
				} else {
					reply[40] = 129
					extension := []byte{ProtocolICMPv6, 0, 0, 0, 0, 0, 0, 0}
					reply[6] = 60
					reply = append(append(reply[:40:40], extension...), reply[40:]...)
					payloadOffset = 48
					protocol = ProtocolICMPv6
				}
				fittingFlow = outputHashedFlowKey(outputPacketFlowHash(stack.outbound.scheduler.secret, reply))
				selector := outputTransportSelector(protocol, reply[payloadOffset:])
				terminalFlow = outputHashedFlowKey(outputIPFlowHash(stack.outbound.scheduler.secret, test.target, test.remote, protocol, 0, selector))
				result <- request.ReplyIPPacket(reply)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			request := []byte{13, 0, 0, 0, 1, 2, 3, 4}
			protocol := byte(ProtocolICMPv6)
			if test.remote.Is4() {
				protocol = ProtocolICMPv4
				binary.BigEndian.PutUint16(request[2:4], checksum(request))
			} else {
				binary.BigEndian.PutUint16(request[2:4], transportChecksum(test.remote, test.target, protocol, request))
			}
			if err = writeTestPacket(stack, buildIPPacket(test.remote, test.target, protocol, request, 1, true)); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			if fittingFlow != terminalFlow {
				t.Fatalf("fitting ReplyIPPacket flow = %+v, want terminal flow %+v", fittingFlow, terminalFlow)
			}
			stack.outbound.scheduler.mu.Lock()
			queued := stack.outbound.scheduler.flows[terminalFlow]
			stack.outbound.scheduler.mu.Unlock()
			if queued == nil || queued.head < 0 {
				t.Fatal("source-fragmented ReplyIPPacket was not assigned to its fitting terminal flow")
			}
			var reassembled []byte
			fragments := 0
			for stack.outbound.len() != 0 {
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					break
				}
				packet := consumeTestPacket(&stack.outbound, entry)
				fragments++
				if test.remote.Is4() && fragments > 1 {
					headerSize := int(packet[0]&0x0f) * 4
					for _, option := range packet[20:27] {
						if option != 1 {
							t.Fatalf("non-copied IPv4 option survived later fragment: %x", packet[20:headerSize])
						}
					}
					if !bytes.Equal(packet[27:31], []byte{148, 4, 0, 0}) {
						t.Fatalf("copied IPv4 option missing from later fragment: %x", packet[20:headerSize])
					}
				}
				if completed := stack.reassemblePacket(packet, time.Now()); completed != nil {
					reassembled = completed
				}
			}
			if fragments < 2 || len(reassembled) == 0 {
				t.Fatalf("ReplyIPPacket fragments = %d, reassembled=%d", fragments, len(reassembled))
			}
			parsed, ok := parseIPPacket(reassembled, false)
			if !ok || parsed.source != test.target || parsed.target != test.remote || !bytes.Equal(parsed.payload[8:], quoted) {
				t.Fatalf("reassembled ReplyIPPacket = %x", reassembled)
			}
		})
	}
}

func TestICMPForwarderReplyIPPacketIPv6AtomicFragment(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::160")
	remote := netip.MustParseAddr("2001:db8::161")
	target := netip.MustParseAddr("2001:db8:1::160")
	for _, test := range []struct {
		name           string
		payloadSize    int
		noncanonical   bool
		identification uint32
	}{
		{name: "fitting", payloadSize: 32, identification: 0x12345678},
		{name: "refragment noncanonical zero ID", payloadSize: 2500, noncanonical: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, local, true)
			payload := bytes.Repeat([]byte{0x6d}, test.payloadSize)
			reply := makeForwarderICMPEchoReplyPacket(target, remote, payload)
			if test.noncanonical {
				reply = makeNoncanonicalIPv6AtomicFragmentPacket(reply, test.identification)
			} else {
				reply = prependIPv6AtomicFragment(reply, test.identification)
			}
			result := make(chan error, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				result <- request.ReplyIPPacket(reply)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			request := []byte{128, 0, 0, 0, 1, 2, 3, 4}
			binary.BigEndian.PutUint16(request[2:4], transportChecksum(remote, target, ProtocolICMPv6, request))
			if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv6, request, 1, true)); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			if !test.noncanonical {
				selector := outputTransportSelector(ProtocolICMPv6, reply[48:])
				want := outputHashedFlowKey(outputIPFlowHash(stack.outbound.scheduler.secret, target, remote, ProtocolICMPv6, 0, selector))
				stack.outbound.scheduler.mu.Lock()
				queued := stack.outbound.scheduler.flows[want]
				stack.outbound.scheduler.mu.Unlock()
				if queued == nil || queued.head < 0 {
					t.Fatal("fitting ReplyIPPacket was not assigned to its terminal ICMP flow")
				}
				output := readForwarderTestPacket(t, stack)
				if output[6] != 44 || output[40] != ProtocolICMPv6 || output[41] != 0 || binary.BigEndian.Uint16(output[42:44]) != 0 || binary.BigEndian.Uint32(output[44:48]) != test.identification {
					t.Fatalf("fitting atomic Fragment header = %x", output[40:48])
				}
				parsed, ok := parseIPPacket(output, false)
				if !ok || !bytes.Equal(parsed.payload[8:], payload) || transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
					t.Fatalf("fitting atomic ReplyIPPacket = %x", output)
				}
				return
			}
			fragments := 0
			var reassembled []byte
			for stack.outbound.len() != 0 {
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					break
				}
				fragment := consumeTestPacket(&stack.outbound, entry)
				fragments++
				if fragment[6] != 60 || fragment[40] != 43 || fragment[48] != 44 || fragment[56] != ProtocolICMPv6 || binary.BigEndian.Uint32(fragment[60:64]) != test.identification {
					t.Fatalf("refragmented IPv6 chain = %x", fragment[:64])
				}
				if completed := stack.reassemblePacket(fragment, time.Now()); completed != nil {
					reassembled = completed
				}
			}
			if fragments < 2 || len(reassembled) == 0 {
				t.Fatalf("atomic refragmentation produced %d fragments and %d reassembled bytes", fragments, len(reassembled))
			}
			parsed, ok := parseIPPacket(reassembled, false)
			if !ok || !bytes.Equal(parsed.payload[8:], payload) || transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
				t.Fatalf("reassembled atomic ReplyIPPacket = %x", reassembled)
			}
		})
	}
}

func TestICMPForwarderReplyIPPacketIPv6StaticValidation(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::162")
	remote := netip.MustParseAddr("2001:db8::163")
	target := netip.MustParseAddr("2001:db8:1::162")
	stack := newForwarderTestStack(t, local, true)
	result := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		oversizedError := makeForwarderICMPErrorPacket(target, remote, make([]byte, ipv6MinimumMTU-47))
		if replyErr := request.ReplyIPPacket(oversizedError); !errors.Is(replyErr, syscall.EMSGSIZE) {
			result <- replyErr
			return
		}
		duplicate := makeForwarderICMPEchoReplyPacket(target, remote, nil)
		duplicate = prependIPv6AtomicFragment(prependIPv6AtomicFragment(duplicate, 1), 2)
		if replyErr := request.ReplyIPPacket(duplicate); !errors.Is(replyErr, syscall.EINVAL) {
			result <- replyErr
			return
		}
		loopback := makeForwarderICMPEchoReplyPacket(netip.IPv6Loopback(), remote, nil)
		if replyErr := request.ReplyIPPacket(loopback); replyErr != nil {
			result <- replyErr
			return
		}
		result <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	request := []byte{128, 0, 0, 0, 1, 2, 3, 4}
	binary.BigEndian.PutUint16(request[2:4], transportChecksum(remote, target, ProtocolICMPv6, request))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv6, request, 1, true)); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != netip.IPv6Loopback() || parsed.target != remote {
		t.Fatalf("IPv6 loopback-source ReplyIPPacket output = %x", response)
	}
	if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 2 || info.Dropped != 1 {
		t.Fatalf("IPv6 static ReplyIPPacket diagnostics = %+v", info)
	}
}

func TestICMPForwarderReplyRejectsOversizedIPv6Error(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::172")
	remote := netip.MustParseAddr("2001:db8::173")
	target := netip.MustParseAddr("2001:db8:1::172")
	for _, detached := range []bool{false, true} {
		name := "callback"
		if detached {
			name = "detached"
		}
		t.Run(name, func(t *testing.T) {
			stack := newForwarderTestStack(t, local, true)
			result := make(chan error, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				oversized := make([]byte, ipv6MinimumMTU-39)
				oversized[0] = 1
				if !detached {
					if replyErr := request.Reply(oversized); !errors.Is(replyErr, syscall.EMSGSIZE) {
						result <- replyErr
						return
					}
					result <- request.Drop()
					return
				}
				responder, detachErr := request.Detach()
				if detachErr != nil {
					result <- detachErr
					return
				}
				if replyErr := responder.Reply(oversized); !errors.Is(replyErr, syscall.EMSGSIZE) {
					result <- replyErr
					return
				}
				result <- responder.Drop()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			request := []byte{128, 0, 0, 0, 1, 2, 3, 4}
			binary.BigEndian.PutUint16(request[2:4], transportChecksum(remote, target, ProtocolICMPv6, request))
			if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv6, request, 1, true)); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			if info := forwarder.Info(); info.Replies != 0 || info.ReplyErrors != 1 || info.Dropped != 1 {
				t.Fatalf("oversized ICMPv6 error diagnostics = %+v", info)
			}
		})
	}
}

func TestICMPForwarderReplyIPPacketDFAndBestEffortQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.158")
	remote := netip.MustParseAddr("192.0.2.159")
	target := netip.MustParseAddr("198.51.100.158")
	for _, test := range []struct {
		name        string
		fill        bool
		want        error
		queued      int
		wantReplies uint64
	}{
		{"DF", false, syscall.EMSGSIZE, 0, 0},
		{"queue", true, nil, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, local, true)
			if test.fill {
				fillTestPacketQueue(t, &stack.outbound, []byte{0})
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					t.Fatal("filled queue could not release one slot")
				}
				stack.outbound.release(entry)
			}
			before := stack.outbound.len()
			result := make(chan error, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				reply := makeForwarderICMPErrorPacket(target, remote, bytes.Repeat([]byte{0x6b}, 2500))
				if !test.fill {
					binary.BigEndian.PutUint16(reply[6:8], 0x4000)
				}
				result <- request.ReplyIPPacket(reply)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			request := []byte{13, 0, 0, 0, 1, 2, 3, 4}
			binary.BigEndian.PutUint16(request[2:4], checksum(request))
			packet := buildIPPacket(remote, target, ProtocolICMPv4, request, 1, true)
			writeResult := make(chan error, 1)
			go func() { writeResult <- writeTestPacket(stack, packet) }()
			select {
			case err = <-result:
				if !errors.Is(err, test.want) {
					t.Fatalf("ReplyIPPacket = %v, want %v", err, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("ReplyIPPacket blocked")
			}
			select {
			case err = <-writeResult:
				if err != nil {
					t.Fatalf("Stack.Write after ReplyIPPacket = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Stack.Write blocked in ICMP forwarder")
			}
			if got := stack.outbound.len(); got != before+test.queued {
				t.Fatalf("ReplyIPPacket changed queue length %d -> %d, want %d", before, got, before+test.queued)
			}
			if info := forwarder.Info(); info.Replies != test.wantReplies || info.ReplyErrors != 1-test.wantReplies || info.Dropped != 0 {
				t.Fatalf("dynamic ReplyIPPacket diagnostics = %+v", info)
			}
		})
	}
}

func FuzzICMPForwarderReplyIPPacket(f *testing.F) {
	v4Source := netip.MustParseAddr("198.51.100.190")
	v4Target := netip.MustParseAddr("192.0.2.190")
	v6Source := netip.MustParseAddr("2001:db8:1::190")
	v6Target := netip.MustParseAddr("2001:db8::190")
	f.Add(makeForwarderICMPEchoReplyPacket(v4Source, v4Target, []byte("IPv4")), false)
	f.Add(makeForwarderICMPEchoReplyPacket(v6Source, v6Target, []byte("IPv6")), true)
	f.Add(prependIPv6AtomicFragment(makeForwarderICMPEchoReplyPacket(v6Source, v6Target, nil), 190), true)
	f.Fuzz(func(t *testing.T, input []byte, ipv6 bool) {
		if len(input) > 65575 {
			input = input[:65575]
		}
		original := append([]byte(nil), input...)
		destination := v4Target
		protocol := byte(ProtocolICMPv4)
		if ipv6 {
			destination = v6Target
			protocol = ProtocolICMPv6
		}
		reply, err := prepareICMPForwarderIPPacket(input, destination)
		if !bytes.Equal(input, original) {
			t.Fatal("ReplyIPPacket validation modified caller storage")
		}
		if err != nil {
			return
		}
		parsed, ok := parseIPPacket(reply.packet, false)
		if !ok || parsed.parameterError || parsed.target != destination || parsed.protocol != protocol || len(parsed.payload) < 8 {
			t.Fatalf("accepted ReplyIPPacket is not parseable: %+v, valid=%t", parsed, ok)
		}
		if parsed.source.Is4() {
			if checksum(parsed.payload) != 0 || checksum(reply.packet[:int(reply.packet[0]&0x0f)*4]) != 0 {
				t.Fatal("accepted IPv4 ReplyIPPacket has an invalid checksum")
			}
		} else if transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
			t.Fatal("accepted IPv6 ReplyIPPacket has an invalid checksum")
		}
	})
}

func FuzzICMPForwarderReplyIPPacketFragmentation(f *testing.F) {
	v4Source := netip.MustParseAddr("198.51.100.191")
	v4Target := netip.MustParseAddr("192.0.2.191")
	v6Source := netip.MustParseAddr("2001:db8:1::191")
	v6Target := netip.MustParseAddr("2001:db8::191")
	v4WithOptions := makeForwarderICMPErrorPacket(v4Source, v4Target, bytes.Repeat([]byte{0x41}, 1800))
	options := []byte{7, 7, 8, 0, 0, 0, 0, 148, 4, 0, 0, 0}
	headerSize := 20 + len(options)
	v4OptionPacket := make([]byte, headerSize+len(v4WithOptions)-20)
	copy(v4OptionPacket[:20], v4WithOptions[:20])
	copy(v4OptionPacket[20:headerSize], options)
	copy(v4OptionPacket[headerSize:], v4WithOptions[20:])
	v4OptionPacket[0] = 0x40 | byte(headerSize/4)
	binary.BigEndian.PutUint16(v4OptionPacket[2:4], uint16(len(v4OptionPacket)))
	v4OptionPacket[10], v4OptionPacket[11] = 0, 0
	binary.BigEndian.PutUint16(v4OptionPacket[10:12], checksum(v4OptionPacket[:headerSize]))
	v6WithExtension := makeForwarderICMPEchoReplyPacket(v6Source, v6Target, bytes.Repeat([]byte{0x42}, 1800))
	extension := []byte{ProtocolICMPv6, 0, 0, 0, 0, 0, 0, 0}
	v6WithExtension[6] = 60
	v6WithExtension = append(append(v6WithExtension[:40:40], extension...), v6WithExtension[40:]...)
	binary.BigEndian.PutUint16(v6WithExtension[4:6], uint16(len(v6WithExtension)-40))
	f.Add(makeForwarderICMPEchoReplyPacket(v4Source, v4Target, []byte("IPv4")), false, uint16(1500), false)
	f.Add(v4OptionPacket, false, uint16(600), true)
	f.Add(makeForwarderICMPEchoReplyPacket(v6Source, v6Target, []byte("IPv6")), true, uint16(1500), false)
	f.Add(v6WithExtension, true, uint16(1280), true)
	f.Add(makeNoncanonicalIPv6AtomicFragmentPacket(makeForwarderICMPEchoReplyPacket(v6Source, v6Target, bytes.Repeat([]byte{0x43}, 1800)), 191), true, uint16(1280), false)
	f.Fuzz(func(t *testing.T, input []byte, ipv6 bool, mtuSeed uint16, reverse bool) {
		if len(input) > 65575 {
			input = input[:65575]
		}
		destination := v4Target
		if ipv6 {
			destination = v6Target
		}
		reply, err := prepareICMPForwarderIPPacket(input, destination)
		if err != nil {
			return
		}
		expectedSource := reply.parsed.source
		expectedTarget := reply.parsed.target
		expectedProtocol := reply.parsed.protocol
		expectedPayload := append([]byte(nil), reply.parsed.payload...)
		mtu := 68 + int(mtuSeed)%1433
		bits := 32
		if ipv6 {
			mtu = ipv6MinimumMTU + int(mtuSeed)%(1501-ipv6MinimumMTU)
			bits = 128
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(destination, bits)}, MTU: 1500})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		packets, err := stack.icmpForwarderIPPackets(reply, mtu)
		if err != nil {
			if len(reply.packet) <= mtu {
				t.Fatalf("fitting ReplyIPPacket failed at MTU %d: %v", mtu, err)
			}
			return
		}
		if len(packets) == 0 {
			t.Fatal("ReplyIPPacket fragmentation returned no packets")
		}
		var completed []byte
		if len(packets) == 1 {
			completed = packets[0]
		} else {
			now := time.Unix(400, 0)
			for step := range packets {
				index := step
				if reverse {
					index = len(packets) - 1 - step
				}
				packet := packets[index]
				if len(packet) > mtu {
					t.Fatalf("ReplyIPPacket fragment %d has %d bytes, want at most MTU %d", index, len(packet), mtu)
				}
				if output := stack.reassemblePacket(packet, now); output != nil {
					completed = output
				}
				checkFragmentFuzzResources(t, stack)
			}
			if len(completed) == 0 {
				t.Fatalf("ReplyIPPacket emitted %d fragments but did not reassemble", len(packets))
			}
		}
		parsed, ok := parseIPPacket(completed, false)
		if !ok || parsed.parameterError || parsed.source != expectedSource || parsed.target != expectedTarget ||
			parsed.protocol != expectedProtocol || !bytes.Equal(parsed.payload, expectedPayload) {
			t.Fatalf("ReplyIPPacket reassembly = valid %t %s -> %s protocol %d payload %d, want %s -> %s protocol %d payload %d",
				ok, parsed.source, parsed.target, parsed.protocol, len(parsed.payload), expectedSource, expectedTarget, expectedProtocol, len(expectedPayload))
		}
		if parsed.source.Is4() {
			if checksum(parsed.payload) != 0 {
				t.Fatal("reassembled IPv4 ReplyIPPacket has an invalid ICMP checksum")
			}
		} else if transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0 {
			t.Fatal("reassembled IPv6 ReplyIPPacket has an invalid ICMP checksum")
		}
	})
}

func TestForwarderFailedRequestReplyAllowsTerminalAction(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.168")
	remote := netip.MustParseAddr("192.0.2.169")
	target := netip.MustParseAddr("198.51.100.168")
	for _, test := range []struct {
		name     string
		register func(*Stack, chan<- error) (interface{ Close() error }, error)
		packet   []byte
	}{
		{
			name: "UDP",
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
					if _, err := request.Reply(make([]byte, 65508)); !errors.Is(err, syscall.EMSGSIZE) {
						result <- err
						return
					}
					result <- request.Drop()
				})
			},
			packet: buildTestUDP(remote, target, 55168, 53, []byte("request")),
		},
		{
			name: "IP",
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
					if err := request.Reply(make([]byte, 65516)); !errors.Is(err, syscall.EMSGSIZE) {
						result <- err
						return
					}
					result <- request.Drop()
				})
			},
			packet: buildIPPacket(remote, target, 99, []byte("request"), 1, true),
		},
		{
			name: "ICMP",
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
					if err := request.Reply(make([]byte, 65516)); !errors.Is(err, syscall.EMSGSIZE) {
						result <- err
						return
					}
					result <- request.Drop()
				})
			},
			packet: func() []byte {
				icmp := []byte{13, 0, 0, 0, 1, 2, 3, 4}
				binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
				return buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, local, true)
			result := make(chan error, 1)
			forwarder, err := test.register(stack, result)
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, test.packet); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			type informer interface{ Info() ForwarderInfo }
			info := forwarder.(informer).Info()
			if info.Replies != 0 || info.ReplyErrors != 1 || info.Dropped != 1 {
				t.Fatalf("oversized request Reply diagnostics = %+v", info)
			}
		})
	}
}

func TestForwarderFailedResponderReplyAllowsTerminalAction(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.170")
	remote := netip.MustParseAddr("192.0.2.171")
	target := netip.MustParseAddr("198.51.100.170")
	type detachedReply struct {
		reply func() error
		drop  func() error
	}
	for _, test := range []struct {
		name     string
		register func(*Stack, chan<- detachedReply) (interface {
			Close() error
			Info() ForwarderInfo
		}, error)
		packet []byte
	}{
		{
			name: "UDP",
			register: func(stack *Stack, result chan<- detachedReply) (interface {
				Close() error
				Info() ForwarderInfo
			}, error) {
				return NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
					responder, err := request.Detach()
					if err != nil {
						t.Errorf("Detach UDP: %v", err)
						return
					}
					result <- detachedReply{
						reply: func() error { _, err = responder.Reply(make([]byte, 65508)); return err },
						drop:  responder.Drop,
					}
				})
			},
			packet: buildTestUDP(remote, target, 55170, 53, []byte("request")),
		},
		{
			name: "IP",
			register: func(stack *Stack, result chan<- detachedReply) (interface {
				Close() error
				Info() ForwarderInfo
			}, error) {
				return NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
					responder, err := request.Detach()
					if err != nil {
						t.Errorf("Detach IP: %v", err)
						return
					}
					result <- detachedReply{
						reply: func() error { return responder.Reply(make([]byte, 65516)) },
						drop:  responder.Drop,
					}
				})
			},
			packet: buildIPPacket(remote, target, 99, []byte("request"), 1, true),
		},
		{
			name: "ICMP",
			register: func(stack *Stack, result chan<- detachedReply) (interface {
				Close() error
				Info() ForwarderInfo
			}, error) {
				return NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
					responder, err := request.Detach()
					if err != nil {
						t.Errorf("Detach ICMP: %v", err)
						return
					}
					result <- detachedReply{
						reply: func() error { return responder.Reply(make([]byte, 65516)) },
						drop:  responder.Drop,
					}
				})
			},
			packet: func() []byte {
				icmp := []byte{13, 0, 0, 0, 1, 2, 3, 4}
				binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
				return buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newForwarderTestStack(t, local, true)
			result := make(chan detachedReply, 1)
			forwarder, err := test.register(stack, result)
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, test.packet); err != nil {
				t.Fatal(err)
			}
			responder := <-result
			if err = responder.reply(); !errors.Is(err, syscall.EMSGSIZE) {
				t.Fatalf("oversized responder Reply = %v", err)
			}
			if err = responder.drop(); err != nil {
				t.Fatalf("Drop after oversized responder Reply = %v", err)
			}
			if info := forwarder.Info(); info.Replies != 0 || info.ReplyErrors != 1 || info.Dropped != 1 {
				t.Fatalf("oversized responder Reply diagnostics = %+v", info)
			}
		})
	}
}

func TestICMPForwarderDetachedTerminalActions(t *testing.T) {
	for _, action := range []string{"Drop", "Reject"} {
		t.Run(action, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.122")
			remote := netip.MustParseAddr("192.0.2.123")
			target := netip.MustParseAddr("198.51.100.122")
			stack := newForwarderTestStack(t, local, true)
			detached := make(chan *ICMPForwarderResponder, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				responder, detachErr := request.Detach()
				if detachErr != nil {
					t.Errorf("Detach ICMP: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			icmp := make([]byte, 8)
			icmp[0] = 13
			binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			if action == "Drop" {
				err = responder.Drop()
			} else {
				err = responder.Reject()
			}
			if err != nil {
				t.Fatalf("%s detached ICMP: %v", action, err)
			}
			info := forwarder.Info()
			if action == "Drop" {
				if info.Dropped != 1 || info.Rejected != 0 {
					t.Fatalf("dropped detached ICMP info = %+v", info)
				}
			} else {
				if info.Dropped != 0 || info.Rejected != 1 {
					t.Fatalf("rejected detached ICMP info = %+v", info)
				}
				response := readForwarderTestPacket(t, stack)
				parsed, ok := parseIPPacket(response, false)
				if !ok || parsed.payload[0] != 3 || parsed.payload[1] != 13 {
					t.Fatalf("detached ICMP rejection = %x", response)
				}
			}
			if err = forwarder.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-responder.Done():
			default:
				t.Fatal("detached ICMP responder Done remained open")
			}
		})
	}
}

func TestICMPForwarderDetachedRejectUsesIndependentQuote(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.164")
	remote := netip.MustParseAddr("192.0.2.165")
	target := netip.MustParseAddr("198.51.100.164")
	stack := newForwarderTestStack(t, local, true)
	detached := make(chan *ICMPForwarderResponder, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach ICMP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := []byte{8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	requestPacket := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
	wantQuote := append([]byte(nil), requestPacket[:28]...)
	if err = writeTestPacket(stack, requestPacket); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	for index := range responder.IPPacket() {
		responder.IPPacket()[index] = 0xa5
	}
	if err = responder.Reject(); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv4 || parsed.payload[0] != 3 || parsed.payload[1] != 13 || checksum(parsed.payload) != 0 || !bytes.Equal(parsed.payload[8:], wantQuote) {
		t.Fatalf("detached rejection did not preserve its independent quote: %x", response)
	}
}

func TestUDPForwarderDetachedReplyCanRetry(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.132")
	remote := netip.MustParseAddr("192.0.2.133")
	target := netip.MustParseAddr("198.51.100.132")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55302, 53, []byte("retry"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	held := make([]uint16, 0, cap(stack.outbound.free))
	defer func() {
		for _, slot := range held {
			stack.outbound.releaseReserved(slot)
		}
	}()
	for {
		slot, reserved := stack.outbound.tryReserve()
		if !reserved {
			break
		}
		held = append(held, slot)
	}
	if len(held) != cap(stack.outbound.free) {
		t.Fatalf("held output slots = %d, want %d", len(held), cap(stack.outbound.free))
	}
	replyResult := make(chan error, 1)
	go func() {
		_, replyErr := responder.Reply([]byte("answer"))
		replyResult <- replyErr
	}()
	select {
	case err = <-replyResult:
		if err != nil {
			t.Fatalf("full-queue detached UDP Reply = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("full-queue detached UDP Reply blocked")
	}
	if stats := stack.Stats(); stats.OutboundPackets != 0 || stats.OutboundQueueDrops != 1 {
		t.Fatalf("unreclaimable detached UDP Reply statistics = %+v", stats)
	}
	for _, slot := range held {
		stack.outbound.releaseReserved(slot)
	}
	held = nil
	if _, err = responder.Reply([]byte("answer")); err != nil {
		t.Fatalf("retry detached UDP Reply: %v", err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || string(parsed.payload[udpHeaderSize:]) != "answer" {
		t.Fatalf("retried detached UDP response = %x", response)
	}
	if err = responder.Drop(); err != nil {
		t.Fatalf("Drop detached UDP responder after retry = %v", err)
	}
	if _, err = responder.Reply([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply after detached UDP Drop = %v", err)
	}
	if info := forwarder.Info(); info.Replies != 2 || info.ReplyErrors != 0 || info.Dropped != 1 {
		t.Fatalf("retried detached UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderBestEffortReplyCanPrecedeAccept(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.134")
	remote := netip.MustParseAddr("192.0.2.135")
	target := netip.MustParseAddr("198.51.100.134")
	stack := newForwarderTestStack(t, owned, true)
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	results := make(chan [3]error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, firstErr := request.Reply([]byte("answer"))
		connection, acceptErr := request.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		for {
			entry, ok := stack.outbound.tryDequeue()
			if !ok {
				break
			}
			consumeTestPacket(&stack.outbound, entry)
		}
		_, retryErr := request.Reply([]byte("answer"))
		results <- [3]error{firstErr, acceptErr, retryErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55303, 53, []byte("retry"))); err != nil {
		t.Fatal(err)
	}
	result := <-results
	if result[0] != nil {
		t.Fatalf("full-queue request Reply = %v", result[0])
	}
	if result[1] != nil {
		t.Fatalf("Accept request after failed Reply = %v", result[1])
	}
	if !errors.Is(result[2], ErrForwarderRequestCompleted) {
		t.Fatalf("Reply request after Accept = %v", result[2])
	}
	if info := forwarder.Info(); info.Accepted != 1 || info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 0 {
		t.Fatalf("best-effort request UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderDetachedResponderIsCallerOwned(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.124")
	remote := netip.MustParseAddr("192.0.2.125")
	target := netip.MustParseAddr("198.51.100.124")
	stack := newForwarderTestStack(t, owned, true)
	responders := make(chan *UDPForwarderResponder, 300)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		responders <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < cap(responders); index++ {
		packet := buildTestUDP(remote, target, uint16(55000+index), 53, []byte("query"))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Requests != uint64(cap(responders)) || info.Dropped != 0 {
		t.Fatalf("caller-owned UDP forwarder info = %+v", info)
	}
	responder := <-responders
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = responder.Reply([]byte("late")); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("config-invalidated UDP responder action = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 0 || info.ReplyErrors != 1 {
		t.Fatalf("invalidated UDP forwarder info = %+v", info)
	}
	for len(responders) != 0 {
		if dropErr := (<-responders).Drop(); dropErr != nil {
			t.Fatal(dropErr)
		}
	}
	if info := forwarder.Info(); info.Dropped != uint64(cap(responders)-1) {
		t.Fatalf("completed caller-owned UDP forwarder info = %+v", info)
	}
}

func TestDetachedForwarderResponderRevalidatesLifecycle(t *testing.T) {
	t.Run("UDP forwarder close", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.126")
		remote := netip.MustParseAddr("192.0.2.127")
		target := netip.MustParseAddr("198.51.100.126")
		stack := newForwarderTestStack(t, owned, true)
		detached := make(chan *UDPForwarderResponder, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			responder, detachErr := request.Detach()
			if detachErr != nil {
				t.Errorf("Detach UDP: %v", detachErr)
				return
			}
			detached <- responder
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 55300, 53, []byte("close"))); err != nil {
			t.Fatal(err)
		}
		responder := <-detached
		if err = forwarder.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-forwarder.Done():
		default:
			t.Fatal("UDP forwarder Done remained open after Close")
		}
		select {
		case <-responder.Done():
		default:
			t.Fatal("UDP responder Done remained open after forwarder Close")
		}
		if _, err = responder.ReplyFrom([]byte("invalid"), netip.AddrPort{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("invalid detached UDP ReplyFrom after forwarder Close = %v", err)
		}
		if _, err = responder.Reply([]byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("detached UDP Reply after Close = %v", err)
		}
		if err = responder.Drop(); err != nil {
			t.Fatalf("Drop detached UDP responder after failed replies = %v", err)
		}
		if err = responder.Drop(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Drop detached UDP responder = %v", err)
		}
		if info := forwarder.Info(); !info.Closed || info.Pending != 0 || info.Dropped != 1 || info.ReplyErrors != 2 {
			t.Fatalf("closed detached UDP forwarder info = %+v", info)
		}
	})

	t.Run("ICMP configuration removal", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.128")
		remote := netip.MustParseAddr("192.0.2.129")
		target := netip.MustParseAddr("198.51.100.128")
		stack := newForwarderTestStack(t, owned, true)
		detached := make(chan *ICMPForwarderResponder, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			responder, detachErr := request.Detach()
			if detachErr != nil {
				t.Errorf("Detach ICMP: %v", detachErr)
				return
			}
			detached <- responder
		})
		if err != nil {
			t.Fatal(err)
		}
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
			t.Fatal(err)
		}
		responder := <-detached
		if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
			t.Fatal(err)
		}
		if err = responder.Reply(icmp); !errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Fatalf("detached ICMP Reply after configuration removal = %v", err)
		}
		if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 0 || info.ReplyErrors != 1 {
			t.Fatalf("invalidated detached ICMP forwarder info = %+v", info)
		}
	})
}

func TestDetachedForwarderResponderConcurrentAction(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.130")
	remote := netip.MustParseAddr("192.0.2.131")
	target := netip.MustParseAddr("198.51.100.130")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55301, 53, []byte("race"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	results := make(chan error, 32)
	for index := 0; index < cap(results); index++ {
		go func() { results <- responder.Drop() }()
	}
	succeeded := 0
	for index := 0; index < cap(results); index++ {
		actionErr := <-results
		if actionErr == nil {
			succeeded++
		} else if !errors.Is(actionErr, net.ErrClosed) {
			t.Fatalf("concurrent detached action = %v", actionErr)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent detached actions = %d", succeeded)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("concurrent detached UDP forwarder info = %+v", info)
	}
}

func TestDetachedForwarderResponderConcurrentReplyAndDrop(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.136")
	remote := netip.MustParseAddr("192.0.2.137")
	target := netip.MustParseAddr("198.51.100.136")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55304, 53, []byte("race"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	const replies = 32
	start := make(chan struct{})
	results := make(chan error, replies)
	for index := 0; index < replies; index++ {
		go func() {
			<-start
			_, replyErr := responder.Reply([]byte("answer"))
			results <- replyErr
		}()
	}
	dropped := make(chan error, 1)
	go func() {
		<-start
		dropped <- responder.Drop()
	}()
	close(start)
	if err = <-dropped; err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for index := 0; index < replies; index++ {
		replyErr := <-results
		if replyErr == nil {
			succeeded++
		} else if !errors.Is(replyErr, net.ErrClosed) {
			t.Fatalf("concurrent detached Reply = %v", replyErr)
		}
	}
	if _, err = responder.Reply([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply after concurrent Drop = %v", err)
	}
	if info := forwarder.Info(); info.Replies != uint64(succeeded) || info.Dropped != 1 {
		t.Fatalf("concurrent Reply forwarder info = %+v, succeeded=%d", info, succeeded)
	}
}

func TestICMPForwarderResponderConcurrentReplyIPPacketAndDrop(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.166")
	remote := netip.MustParseAddr("192.0.2.167")
	target := netip.MustParseAddr("198.51.100.166")
	stack := newForwarderTestStack(t, local, true)
	detached := make(chan *ICMPForwarderResponder, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach ICMP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	request := []byte{8, 0, 0, 0, 1, 2, 3, 4}
	binary.BigEndian.PutUint16(request[2:4], checksum(request))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, request, 1, true)); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	reply := makeForwarderICMPEchoReplyPacket(target, remote, []byte("concurrent"))
	const attempts = 32
	start := make(chan struct{})
	results := make(chan error, attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			<-start
			results <- responder.ReplyIPPacket(reply)
		}()
	}
	dropped := make(chan error, 1)
	go func() {
		<-start
		dropped <- responder.Drop()
	}()
	close(start)
	if err = <-dropped; err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for index := 0; index < attempts; index++ {
		replyErr := <-results
		if replyErr == nil {
			succeeded++
		} else if !errors.Is(replyErr, net.ErrClosed) {
			t.Fatalf("concurrent ReplyIPPacket = %v", replyErr)
		}
	}
	if err = responder.ReplyIPPacket(reply); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReplyIPPacket after Drop = %v", err)
	}
	queued := 0
	for stack.outbound.len() != 0 {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			break
		}
		packet := consumeTestPacket(&stack.outbound, entry)
		parsed, valid := parseIPPacket(packet, false)
		if !valid || parsed.source != target || parsed.target != remote || string(parsed.payload[8:]) != "concurrent" {
			t.Fatalf("concurrent ReplyIPPacket output = %x", packet)
		}
		queued++
	}
	if queued != succeeded {
		t.Fatalf("concurrent ReplyIPPacket queued %d packets for %d successes", queued, succeeded)
	}
	info := forwarder.Info()
	if info.Replies != uint64(succeeded) || info.ReplyErrors != 0 || info.Dropped != 1 {
		t.Fatalf("concurrent ReplyIPPacket diagnostics = %+v, succeeded=%d", info, succeeded)
	}
}

func TestAutomaticControlResponsesDoNotBlockOnFullQueue(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP"} {
		t.Run(protocol, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.112")
			remote := netip.MustParseAddr("192.0.2.113")
			stack := newForwarderTestStack(t, local, false)
			fillTestPacketQueue(t, &stack.outbound, []byte{0})
			var packet []byte
			if protocol == "TCP" {
				packet = buildTestTCP(remote, local, 55005, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)
			} else {
				packet = buildTestUDP(remote, local, 55006, 5353, []byte("unhandled"))
			}
			done := make(chan error, 1)
			go func() { done <- writeTestPacket(stack, packet) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("automatic %s response returned input error: %v", protocol, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("automatic %s response blocked Stack.Write", protocol)
			}
		})
	}
}

func TestIPForwarderReplyAndMetadata(t *testing.T) {
	for _, test := range []struct {
		name          string
		owned, remote netip.Addr
		target        netip.Addr
	}{
		{name: "IPv4", owned: netip.MustParseAddr("192.0.2.114"), remote: netip.MustParseAddr("198.51.100.114"), target: netip.MustParseAddr("203.0.113.114")},
		{name: "IPv6", owned: netip.MustParseAddr("2001:db8::114"), remote: netip.MustParseAddr("2001:db8:1::114"), target: netip.MustParseAddr("2001:db8:2::114")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.owned, test.owned.BitLen())},
				Promiscuous:    true,
				IP: IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{
					HopLimit: 41, TrafficClass: 0x2e, FlowLabel: 0x34567,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			var observed IPForwarderMessage
			forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
				observed = request.Message()
				if replyErr := request.Reply([]byte("first")); replyErr != nil {
					t.Errorf("first IP Reply: %v", replyErr)
				}
				if replyErr := request.Reply([]byte("second")); replyErr != nil {
					t.Errorf("second IP Reply: %v", replyErr)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			options := ipPacketOptions{hopLimit: 37, trafficClass: 0xb8, flowLabel: 0x12345, flowLabelSet: true}
			packet := buildIPPacketWithOptions(test.remote, test.target, 99, []byte("request"), 7, true, options)
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			wantFlowLabel := uint32(0)
			if test.remote.Is6() {
				wantFlowLabel = 0x12345
			}
			if observed.Source != test.remote || observed.Destination != test.target || observed.Protocol != 99 ||
				observed.HopLimit != 37 || observed.TrafficClass != 0xb8 || observed.FlowLabel != wantFlowLabel || string(observed.Payload) != "request" {
				t.Fatalf("forwarded IP message = %+v", observed)
			}
			for _, payload := range []string{"first", "second"} {
				response := readForwarderTestPacket(t, stack)
				parsed, ok := parseIPPacket(response, false)
				if !ok || parsed.source != test.target || parsed.target != test.remote || parsed.protocol != 99 || string(parsed.payload) != payload {
					t.Fatalf("forwarded IP reply = %+v payload %q", parsed, parsed.payload)
				}
				wantReplyFlowLabel := uint32(0)
				if test.remote.Is6() {
					wantReplyFlowLabel = 0x34567
				}
				if parsed.hopLimit != 41 || parsed.trafficClass != 0x2e || parsed.flowLabel != wantReplyFlowLabel {
					t.Fatalf("configured IP reply fields = hop %d, class %#x, label %#x", parsed.hopLimit, parsed.trafficClass, parsed.flowLabel)
				}
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Replies != 2 || info.Dropped != 0 || info.Pending != 0 {
				t.Fatalf("IP forwarder diagnostics = %+v", info)
			}
		})
	}
}

func TestForwarderRepliesUseDatagramPathMTUDefaults(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.119")
	remote := netip.MustParseAddr("198.51.100.119")
	target := netip.MustParseAddr("203.0.113.119")
	for _, test := range []struct {
		name     string
		register func(*Stack, chan<- error) (interface{ Close() error }, error)
		packet   func() []byte
	}{
		{
			name: "UDP",
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
					_, err := request.Reply(make([]byte, 1100))
					result <- err
				})
			},
			packet: func() []byte { return buildTestUDP(remote, target, 53000, 53, []byte("query")) },
		},
		{
			name: "IP",
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
					result <- request.Reply(make([]byte, 1100))
				})
			},
			packet: func() []byte { return buildIPPacket(remote, target, 99, []byte("request"), 1, true) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
				UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{PathMTUDiscovery: PathMTUDiscoveryDo}},
				IP:  IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{PathMTUDiscovery: PathMTUDiscoveryDo}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if !stack.observePathMTU(remote, 1000) {
				t.Fatal("failed to install forwarder PMTU")
			}
			result := make(chan error, 1)
			forwarder, err := test.register(stack, result)
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, test.packet()); err != nil {
				t.Fatal(err)
			}
			if replyErr := <-result; !errors.Is(replyErr, syscall.EMSGSIZE) {
				t.Fatalf("oversized forwarder Reply = %v, want EMSGSIZE", replyErr)
			}
			if entry, queued := stack.outbound.tryDequeue(); queued {
				stack.outbound.release(entry)
				t.Fatal("failed PMTU-limited forwarder Reply queued output")
			}
		})
	}
}

func TestForwarderRejectRequiresReturnRoute(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.120")
	remote := netip.MustParseAddr("198.51.100.120")
	for _, test := range []struct {
		name     string
		exhaust  func(*Stack)
		register func(*Stack, chan<- error) (interface{ Close() error }, error)
		packet   func() []byte
	}{
		{
			name: "TCP",
			exhaust: func(stack *Stack) {
				stack.controlMu.Lock()
				stack.controlLimiters[controlResponseTCPReset] = tokenBucket{updated: time.Now().Add(time.Hour)}
				stack.controlMu.Unlock()
			},
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
					result <- request.Reject()
				})
			},
			packet: func() []byte {
				return buildTestTCP(remote, local, 53001, 443, 1, 0, TCPFlagSYN, 65535, nil, nil)
			},
		},
		{
			name: "UDP",
			exhaust: func(stack *Stack) {
				stack.controlMu.Lock()
				table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
				future := time.Now().Add(time.Hour)
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{updated: future}
				stack.controlMu.Unlock()
			},
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
					result <- request.Reject()
				})
			},
			packet: func() []byte { return buildTestUDP(remote, local, 53002, 53, []byte("query")) },
		},
		{
			name: "IP",
			exhaust: func(stack *Stack) {
				stack.controlMu.Lock()
				table := stack.icmpErrorLimiterTableLocked(icmpErrorResponseParameterProblem)
				future := time.Now().Add(time.Hour)
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{updated: future}
				stack.controlMu.Unlock()
			},
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
					result <- request.Reject()
				})
			},
			packet: func() []byte { return buildIPPacket(remote, local, 99, []byte("request"), 1, true) },
		},
		{
			name: "ICMP",
			exhaust: func(stack *Stack) {
				stack.controlMu.Lock()
				table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
				future := time.Now().Add(time.Hour)
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{updated: future}
				stack.controlMu.Unlock()
			},
			register: func(stack *Stack, result chan<- error) (interface{ Close() error }, error) {
				return NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
					result <- request.Reject()
				})
			},
			packet: func() []byte {
				message := make([]byte, 8)
				message[0] = 42
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
				return buildIPPacket(remote, local, ProtocolICMPv4, message, 1, true)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Routes: []Route{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			test.exhaust(stack)
			result := make(chan error, 1)
			forwarder, err := test.register(stack, result)
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, test.packet()); err != nil {
				t.Fatal(err)
			}
			if rejectErr := <-result; !errors.Is(rejectErr, syscall.ENETUNREACH) {
				t.Fatalf("Reject without a return route = %v, want ENETUNREACH", rejectErr)
			}
			if entry, queued := stack.outbound.tryDequeue(); queued {
				stack.outbound.release(entry)
				t.Fatal("Reject without a return route queued output")
			}
		})
	}
}

func TestIPForwarderRawSocketPriorityAndProtocolScope(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.115")
	remote := netip.MustParseAddr("198.51.100.115")
	stack := newForwarderTestStack(t, local, false)
	var calls atomic.Int32
	forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		calls.Add(1)
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	raw, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("raw"), 1, true)); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 3)
	if n, _, readErr := raw.ReadFrom(buffer); readErr != nil || n != 3 || string(buffer) != "raw" {
		t.Fatalf("raw priority read = %d, %v, %q", n, readErr, buffer)
	}
	for _, packet := range [][]byte{
		buildTestUDP(remote, local, 50000, 50001, []byte("udp")),
	} {
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("IP forwarder received %d raw or built-in packets", got)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 59, nil, 2, true)); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("IP forwarder received %d IPv4 protocol 59 packets, want 1", got)
	}

	local6 := netip.MustParseAddr("2001:db8::115")
	remote6 := netip.MustParseAddr("2001:db8:1::115")
	stack6 := newForwarderTestStack(t, local6, false)
	var calls6 atomic.Int32
	forwarder6, err := NewIPForwarder(stack6, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		calls6.Add(1)
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder6.Close()
	if err = writeTestPacket(stack6, buildIPPacket(remote6, local6, 59, nil, 0, true)); err != nil {
		t.Fatal(err)
	}
	if got := calls6.Load(); got != 0 {
		t.Fatalf("IP forwarder received %d IPv6 No Next Header packets", got)
	}
}

func TestIPForwarderDetachAndReject(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.116")
	remote := netip.MustParseAddr("198.51.100.116")
	stack := newForwarderTestStack(t, local, false)
	responders := make(chan *IPForwarderResponder, 1)
	forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach: %v", detachErr)
		}
		responders <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	packet := buildIPPacket(remote, local, 100, []byte("owned"), 3, true)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	responder := <-responders
	for index := range packet {
		packet[index] = 0
	}
	if message := responder.Message(); string(message.Payload) != "owned" || message.Protocol != 100 {
		t.Fatalf("detached IP snapshot = %+v", message)
	}
	if err = responder.Reply([]byte("async")); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != local || parsed.target != remote || parsed.protocol != 100 || string(parsed.payload) != "async" {
		t.Fatalf("detached IP reply = %+v", parsed)
	}
	if err = responder.Drop(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Reply(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply after Drop = %v", err)
	}

	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	rejectForwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		if rejectErr := request.Reject(); rejectErr != nil {
			t.Errorf("Reject: %v", rejectErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rejectForwarder.Close()
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 101, []byte("reject"), 4, true)); err != nil {
		t.Fatal(err)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv4 || len(parsed.payload) < 2 || parsed.payload[0] != 3 || parsed.payload[1] != 2 {
		t.Fatalf("IP forwarder rejection = %+v", parsed)
	}
}

func TestIPForwarderConfigInvalidatesRunningRequest(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.117")
	remote := netip.MustParseAddr("198.51.100.117")
	target := netip.MustParseAddr("203.0.113.117")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	actionResult := make(chan error, 1)
	forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		close(entered)
		<-release
		actionResult <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeTestPacket(stack, buildIPPacket(remote, target, 102, []byte("pending"), 5, true))
	}()
	<-entered
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("configuration-invalidated IP forwarder info = %+v", info)
	}
	close(release)
	if err = <-actionResult; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("action after IP configuration invalidation = %v", err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
}

func TestDetachedIPForwarderResponderRevalidatesConfiguration(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.118")
	remote := netip.MustParseAddr("198.51.100.118")
	target := netip.MustParseAddr("203.0.113.118")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *IPForwarderResponder, 2)
	forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach IP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	for protocol := byte(103); protocol <= 104; protocol++ {
		if err = writeTestPacket(stack, buildIPPacket(remote, target, protocol, []byte("detached"), uint16(protocol), true)); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-detached, <-detached
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if err = first.Reply([]byte("late")); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("configuration-invalidated IP Reply = %v", err)
	}
	if err = second.Reject(); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("configuration-invalidated IP Reject = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Requests != 2 || info.ReplyErrors != 1 || info.Rejected != 1 {
		t.Fatalf("configuration-invalidated IP responder info = %+v", info)
	}
}

func TestICMPv6ForwarderReply(t *testing.T) {
	owned := netip.MustParseAddr("2001:db8::80")
	remote := netip.MustParseAddr("2001:db8::81")
	target := netip.MustParseAddr("2001:db8:1::80")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		if !request.Message().IsEchoRequest() {
			t.Error("ICMPv6 Echo Request was not recognized")
			_ = request.Drop()
			return
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("ReplyEcho ICMPv6: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 12)
	icmp[0] = 128
	copy(icmp[8:], "ping")
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(remote, target, ProtocolICMPv6, icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv6, icmp, 0, true)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.source != target || parsed.target != remote || parsed.payload[0] != 129 || transportChecksum(target, remote, ProtocolICMPv6, parsed.payload) != 0 {
		t.Fatalf("forwarded ICMPv6 reply = %x", response)
	}
}

func TestICMPForwarderReplyEchoRejectsNonEcho(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.82")
	remote := netip.MustParseAddr("192.0.2.83")
	target := netip.MustParseAddr("198.51.100.82")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		if request.Message().IsEchoRequest() {
			t.Error("ICMP Echo Reply was recognized as a request")
		}
		if replyErr := request.ReplyEcho(); !errors.Is(replyErr, syscall.EINVAL) {
			t.Errorf("ReplyEcho non-Echo ICMP = %v", replyErr)
		}
		if dropErr := request.Drop(); dropErr != nil {
			t.Errorf("Drop after invalid ReplyEcho = %v", dropErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 8)
	icmp[0] = 0
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 0 || info.Dropped != 1 {
		t.Fatalf("ICMP forwarder info after invalid ReplyEcho = %+v", info)
	}
}

func TestICMPForwarderMessageIsEchoRequest(t *testing.T) {
	v4Source := netip.MustParseAddr("192.0.2.90")
	v4Target := netip.MustParseAddr("198.51.100.90")
	v6Source := netip.MustParseAddr("2001:db8::90")
	v6Target := netip.MustParseAddr("2001:db8:1::90")
	v4Echo := []byte{8, 0, 0, 0, 0, 1, 0, 2}
	v6Echo := []byte{128, 0, 0, 0, 0, 1, 0, 2}
	tests := []struct {
		name    string
		message ICMPForwarderMessage
		want    bool
	}{
		{name: "IPv4", message: ICMPForwarderMessage{Source: v4Source, Destination: v4Target, Type: 8, Payload: v4Echo}, want: true},
		{name: "IPv4 mapped", message: ICMPForwarderMessage{Source: netip.MustParseAddr("::ffff:192.0.2.90"), Destination: netip.MustParseAddr("::ffff:198.51.100.90"), Type: 8, Payload: v4Echo}, want: true},
		{name: "IPv6", message: ICMPForwarderMessage{Source: v6Source, Destination: v6Target, Type: 128, Payload: v6Echo}, want: true},
		{name: "reply", message: ICMPForwarderMessage{Source: v4Source, Destination: v4Target, Payload: []byte{0, 0, 0, 0, 0, 1, 0, 2}}},
		{name: "nonzero code", message: ICMPForwarderMessage{Source: v4Source, Destination: v4Target, Type: 8, Code: 1, Payload: []byte{8, 1, 0, 0, 0, 1, 0, 2}}},
		{name: "truncated", message: ICMPForwarderMessage{Source: v4Source, Destination: v4Target, Type: 8, Payload: []byte{8, 0}}},
		{name: "cross family", message: ICMPForwarderMessage{Source: v4Source, Destination: v6Target, Type: 8, Payload: v4Echo}},
		{name: "metadata mismatch", message: ICMPForwarderMessage{Source: v4Source, Destination: v4Target, Type: 128, Payload: v4Echo}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.message.IsEchoRequest(); got != test.want {
				t.Fatalf("IsEchoRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestICMPForwarderMessageConversion(t *testing.T) {
	tests := []struct {
		name    string
		message ICMPMessage
	}{
		{
			name: "IPv4 mapped",
			message: ICMPMessage{
				Source: netip.MustParseAddr("::ffff:192.0.2.90"), Destination: netip.MustParseAddr("::ffff:198.51.100.90"),
				Type: 8, Body: []byte{0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'},
			},
		},
		{
			name: "IPv6",
			message: ICMPMessage{
				Source: netip.MustParseAddr("2001:db8::90"), Destination: netip.MustParseAddr("2001:db8:1::90"),
				Type: 128, Body: []byte{0x56, 0x78, 0, 2, 'p', 'i', 'n', 'g'},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := test.message
			forwarded := ICMPForwarderMessage{Payload: make([]byte, 1, 64)}
			backing := &forwarded.Payload[0]
			if err := forwarded.SetICMPMessage(message); err != nil {
				t.Fatalf("SetICMPMessage: %v", err)
			}
			if &forwarded.Payload[0] != backing {
				t.Fatal("SetICMPMessage did not reuse sufficient Payload capacity")
			}
			if forwarded.Source != message.Source.Unmap() || forwarded.Destination != message.Destination.Unmap() ||
				forwarded.Type != message.Type || forwarded.Code != message.Code {
				t.Fatalf("forwarder metadata = %+v, want %+v", forwarded, message)
			}

			decoded, err := forwarded.ICMPMessage()
			if err != nil {
				t.Fatalf("ICMPMessage: %v", err)
			}
			if decoded.Source != message.Source.Unmap() || decoded.Destination != message.Destination.Unmap() ||
				decoded.Type != message.Type || decoded.Code != message.Code || !bytes.Equal(decoded.Body, message.Body) {
				t.Fatalf("decoded message = %+v, want %+v", decoded, message)
			}
			if &decoded.Body[0] != &forwarded.Payload[4] {
				t.Fatal("decoded Body does not alias the forwarder Payload")
			}

			decoded.Body[len(decoded.Body)-1] ^= 0xff
			wantBody := append([]byte(nil), decoded.Body...)
			if _, err = forwarded.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("modified wire checksum error = %v", err)
			}
			if err = forwarded.SetICMPMessage(decoded); err != nil {
				t.Fatalf("in-place SetICMPMessage: %v", err)
			}
			if &forwarded.Payload[0] != backing {
				t.Fatal("in-place SetICMPMessage replaced Payload backing")
			}
			if reparsed, parseErr := forwarded.ICMPMessage(); parseErr != nil || !bytes.Equal(reparsed.Body, wantBody) {
				t.Fatalf("reparse after in-place update: message=%+v error=%v", reparsed, parseErr)
			}
		})
	}
}

func TestICMPForwarderMessageConversionErrors(t *testing.T) {
	valid := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.90"), Destination: netip.MustParseAddr("198.51.100.90"),
		Type: 8, Body: []byte{0, 1, 0, 2},
	}
	forwarded := ICMPForwarderMessage{Payload: make([]byte, 0, 16)}
	if err := forwarded.SetICMPMessage(valid); err != nil {
		t.Fatal(err)
	}

	invalid := valid
	invalid.Destination = netip.MustParseAddr("2001:db8::1")
	wantPayload := append([]byte(nil), forwarded.Payload...)
	wantSource, wantDestination := forwarded.Source, forwarded.Destination
	wantType, wantCode := forwarded.Type, forwarded.Code
	if err := forwarded.SetICMPMessage(invalid); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("cross-family SetICMPMessage error = %v", err)
	}
	if forwarded.Source != wantSource || forwarded.Destination != wantDestination || forwarded.Type != wantType ||
		forwarded.Code != wantCode || !bytes.Equal(forwarded.Payload, wantPayload) {
		t.Fatal("failed SetICMPMessage modified its receiver")
	}
	if err := (*ICMPForwarderMessage)(nil).SetICMPMessage(valid); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetICMPMessage error = %v", err)
	}

	missing := ICMPForwarderMessage{Source: valid.Source, Destination: valid.Destination, Type: valid.Type}
	if _, err := missing.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("missing Payload ICMPMessage error = %v", err)
	}
	mismatch := forwarded
	mismatch.Type++
	if _, err := mismatch.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("metadata mismatch ICMPMessage error = %v", err)
	}
	corrupt := forwarded
	corrupt.Payload = append([]byte(nil), forwarded.Payload...)
	corrupt.Payload[len(corrupt.Payload)-1] ^= 0xff
	if _, err := corrupt.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("checksum mismatch ICMPMessage error = %v", err)
	}
}

func TestICMPReplyEchoLifecycleAndSnapshotValidation(t *testing.T) {
	nonEcho := []byte{0, 0, 0, 0, 0, 1, 0, 2}
	request := &ICMPForwarderRequest{packet: ipPacket{protocol: ProtocolICMPv4, payload: nonEcho}}
	request.state.Store(uint32(forwarderRequestDropped))
	if err := request.ReplyEcho(); !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("ReplyEcho after request completion = %v", err)
	}
	responder := &ICMPForwarderResponder{
		forwarderResponder: forwarderResponder{packet: ipPacket{protocol: ProtocolICMPv4}},
		message: ICMPForwarderMessage{
			Source: netip.MustParseAddr("192.0.2.91"), Destination: netip.MustParseAddr("198.51.100.91"),
			Payload: nonEcho,
		},
	}
	responder.state.Store(uint32(forwarderResponderDropped))
	if err := responder.ReplyEcho(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReplyEcho after responder closure = %v", err)
	}

	local := netip.MustParseAddr("192.0.2.90")
	remote := netip.MustParseAddr("192.0.2.91")
	target := netip.MustParseAddr("198.51.100.90")
	stack := newForwarderTestStack(t, local, true)
	detached := make(chan *ICMPForwarderResponder, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach ICMP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	echo := []byte{8, 0, 0, 0, 0, 1, 0, 2}
	binary.BigEndian.PutUint16(echo[2:4], checksum(echo))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, echo, 1, true)); err != nil {
		t.Fatal(err)
	}
	responder = <-detached
	responder.message.Payload[1] = 1
	if responder.message.IsEchoRequest() {
		t.Fatal("mutated detached message has inconsistent Echo metadata")
	}
	if err := responder.ReplyEcho(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ReplyEcho with inconsistent detached message = %v", err)
	}
	if err = responder.Drop(); err != nil {
		t.Fatalf("Drop after invalid ReplyEcho = %v", err)
	}
}

func TestICMPForwarderRejectsShortReply(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.92")
	remote := netip.MustParseAddr("192.0.2.93")
	target := netip.MustParseAddr("198.51.100.92")
	stack := newForwarderTestStack(t, local, true)
	results := make(chan [4]error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		var replyErrors [4]error
		for index := range replyErrors {
			replyErrors[index] = request.Reply(make([]byte, index+4))
		}
		results <- replyErrors
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := []byte{13, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	for size, replyErr := range <-results {
		if !errors.Is(replyErr, syscall.EINVAL) {
			t.Fatalf("%d-byte ICMP Reply = %v", size+4, replyErr)
		}
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		stack.outbound.release(entry)
		t.Fatal("short ICMP Reply emitted a packet")
	}
	if info := forwarder.Info(); info.Replies != 0 || info.ReplyErrors != 4 || info.Dropped != 0 {
		t.Fatalf("short ICMP Reply diagnostics = %+v", info)
	}
}

func TestUDPForwarderRepliesOnlyResponder(t *testing.T) {
	for _, direct := range []bool{true, false} {
		name := "RestrictToReplies"
		if direct {
			name = "DetachForReplies"
		}
		t.Run(name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.200")
			remote := netip.MustParseAddr("198.51.100.201")
			target := netip.MustParseAddr("203.0.113.200")
			alternate := netip.MustParseAddr("203.0.113.201")
			stack := newForwarderTestStack(t, local, true)
			detached := make(chan *UDPForwarderResponder, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				var responder *UDPForwarderResponder
				var detachErr error
				if direct {
					responder, detachErr = request.DetachForReplies()
				} else {
					responder, detachErr = request.Detach()
				}
				if detachErr != nil {
					t.Errorf("detach UDP replies-only responder: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildTestUDP(remote, target, 56000, 53, []byte("retained query"))); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			var retained []byte
			if !direct {
				retained = responder.Payload()
				if err = responder.RestrictToReplies(); err != nil {
					t.Fatal(err)
				}
				if string(retained) != "retained query" {
					t.Fatalf("previously returned UDP payload = %q", retained)
				}
			}
			if payload := responder.Payload(); payload != nil {
				t.Fatalf("replies-only UDP payload = %q", payload)
			}
			if responder.packet.payload != nil || responder.packet.original != nil {
				t.Fatal("replies-only UDP responder retained packet storage")
			}
			if got := responder.Flow(); got != (ForwarderFlow{Source: netip.AddrPortFrom(remote, 56000), Destination: netip.AddrPortFrom(target, 53)}) {
				t.Fatalf("replies-only UDP flow = %+v", got)
			}
			if _, err = responder.Reply([]byte("default source")); err != nil {
				t.Fatal(err)
			}
			if _, err = responder.ReplyFrom([]byte("selected source"), netip.AddrPortFrom(alternate, 5353)); err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.source != target || parsed.target != remote || string(parsed.payload[udpHeaderSize:]) != "default source" {
				t.Fatalf("replies-only UDP Reply output = %x", response)
			}
			response = readForwarderTestPacket(t, stack)
			parsed, ok = parseIPPacket(response, false)
			if !ok || parsed.source != alternate || parsed.target != remote || binary.BigEndian.Uint16(parsed.payload[:2]) != 5353 || string(parsed.payload[udpHeaderSize:]) != "selected source" {
				t.Fatalf("replies-only UDP ReplyFrom output = %x", response)
			}
			if err = responder.RestrictToReplies(); err != nil {
				t.Fatalf("idempotent UDP RestrictToReplies = %v", err)
			}
			if err = responder.Drop(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("UDP Drop after restriction = %v", err)
			}
			if err = responder.Reject(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("UDP Reject after restriction = %v", err)
			}
			if err = forwarder.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-responder.Done():
			default:
				t.Fatal("replies-only UDP responder Done remained open after forwarder close")
			}
			if _, err = responder.Reply([]byte("closed")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("replies-only UDP Reply after forwarder close = %v", err)
			}
			if info := forwarder.Info(); !info.Closed || info.Pending != 0 || info.Requests != 1 || info.Replies != 2 || info.ReplyErrors != 1 || info.Dropped != 0 || info.Rejected != 0 {
				t.Fatalf("replies-only UDP diagnostics = %+v", info)
			}
		})
	}
}

func TestIPForwarderRepliesOnlyResponder(t *testing.T) {
	for _, direct := range []bool{true, false} {
		name := "RestrictToReplies"
		if direct {
			name = "DetachForReplies"
		}
		t.Run(name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.202")
			remote := netip.MustParseAddr("198.51.100.203")
			target := netip.MustParseAddr("203.0.113.202")
			stack := newForwarderTestStack(t, local, true)
			detached := make(chan *IPForwarderResponder, 1)
			forwarder, err := NewIPForwarder(stack, IPForwarderOptions{}, func(request *IPForwarderRequest) {
				var responder *IPForwarderResponder
				var detachErr error
				if direct {
					responder, detachErr = request.DetachForReplies()
				} else {
					responder, detachErr = request.Detach()
				}
				if detachErr != nil {
					t.Errorf("detach IP replies-only responder: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			if err = writeTestPacket(stack, buildIPPacket(remote, target, 100, []byte("retained payload"), 1, true)); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			var retained []byte
			if !direct {
				retained = responder.Message().Payload
				if err = responder.RestrictToReplies(); err != nil {
					t.Fatal(err)
				}
				if string(retained) != "retained payload" {
					t.Fatalf("previously returned IP payload = %q", retained)
				}
			}
			message := responder.Message()
			if message.Source != remote || message.Destination != target || message.Protocol != 100 || message.Payload != nil {
				t.Fatalf("replies-only IP message = %+v", message)
			}
			if responder.packet.payload != nil || responder.packet.original != nil {
				t.Fatal("replies-only IP responder retained packet storage")
			}
			if err = responder.Reply([]byte("asynchronous reply")); err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != 100 || string(parsed.payload) != "asynchronous reply" {
				t.Fatalf("replies-only IP Reply output = %x", response)
			}
			if err = responder.RestrictToReplies(); err != nil {
				t.Fatalf("idempotent IP RestrictToReplies = %v", err)
			}
			if err = responder.Drop(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("IP Drop after restriction = %v", err)
			}
			if err = responder.Reject(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("IP Reject after restriction = %v", err)
			}
			if info := forwarder.Info(); info.Pending != 0 || info.Requests != 1 || info.Replies != 1 || info.ReplyErrors != 0 || info.Dropped != 0 || info.Rejected != 0 {
				t.Fatalf("replies-only IP diagnostics = %+v", info)
			}
		})
	}
}

func TestICMPForwarderRepliesOnlyResponder(t *testing.T) {
	for _, direct := range []bool{true, false} {
		name := "RestrictToReplies"
		if direct {
			name = "DetachForReplies"
		}
		t.Run(name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.204")
			remote := netip.MustParseAddr("198.51.100.205")
			target := netip.MustParseAddr("203.0.113.204")
			stack := newForwarderTestStack(t, local, true)
			detached := make(chan *ICMPForwarderResponder, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				var responder *ICMPForwarderResponder
				var detachErr error
				if direct {
					responder, detachErr = request.DetachForReplies()
				} else {
					responder, detachErr = request.Detach()
				}
				if detachErr != nil {
					t.Errorf("detach ICMP replies-only responder: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			icmp := []byte{8, 0, 0, 0, 1, 2, 3, 4}
			binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			if err = writeTestPacket(stack, buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			var retainedMessage, retainedPacket []byte
			if !direct {
				retainedMessage = responder.Message().Payload
				retainedPacket = responder.IPPacket()
				if err = responder.RestrictToReplies(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(retainedMessage, icmp) {
					t.Fatalf("previously returned ICMP message = %x", retainedMessage)
				}
				if parsed, ok := parseIPPacket(retainedPacket, false); !ok || !bytes.Equal(parsed.payload, icmp) {
					t.Fatalf("previously returned ICMP packet = %x", retainedPacket)
				}
			}
			message := responder.Message()
			if message.Source != remote || message.Destination != target || message.Type != 8 || message.Code != 0 || message.Payload != nil {
				t.Fatalf("replies-only ICMP message = %+v", message)
			}
			if responder.IPPacket() != nil || responder.packet.payload != nil || responder.packet.original != nil || responder.rejectPacket.original != nil {
				t.Fatal("replies-only ICMP responder retained packet storage")
			}
			reply := []byte{0, 0, 0, 0, 5, 6, 7, 8}
			if err = responder.Reply(reply); err != nil {
				t.Fatal(err)
			}
			response := readForwarderTestPacket(t, stack)
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != ProtocolICMPv4 || !bytes.Equal(parsed.payload[4:], reply[4:]) || checksum(parsed.payload) != 0 {
				t.Fatalf("replies-only ICMP Reply output = %x", response)
			}
			rawReply := makeForwarderICMPEchoReplyPacket(target, remote, []byte("raw reply"))
			if err = responder.ReplyIPPacket(rawReply); err != nil {
				t.Fatal(err)
			}
			response = readForwarderTestPacket(t, stack)
			parsed, ok = parseIPPacket(response, false)
			if !ok || parsed.source != target || parsed.target != remote || string(parsed.payload[8:]) != "raw reply" || checksum(parsed.payload) != 0 {
				t.Fatalf("replies-only ICMP ReplyIPPacket output = %x", response)
			}
			if err = responder.ReplyEcho(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ICMP ReplyEcho after restriction = %v", err)
			}
			if err = responder.RestrictToReplies(); err != nil {
				t.Fatalf("idempotent ICMP RestrictToReplies = %v", err)
			}
			if err = responder.Drop(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ICMP Drop after restriction = %v", err)
			}
			if err = responder.Reject(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ICMP Reject after restriction = %v", err)
			}
			if info := forwarder.Info(); info.Pending != 0 || info.Requests != 1 || info.Replies != 2 || info.ReplyErrors != 0 || info.Dropped != 0 || info.Rejected != 0 {
				t.Fatalf("replies-only ICMP diagnostics = %+v", info)
			}
		})
	}
}

func TestUDPForwardedIPv4ReassemblyTimeout(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.197")
	remote, intercepted := netip.MustParseAddr("198.51.100.197"), netip.MustParseAddr("203.0.113.197")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	var connection *UDPConn
	var acceptErr error
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr = request.Accept(SocketOptions.ReceiveErrors(true))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	payload := mustTestWire((UDPDatagram{Source: netip.AddrPortFrom(remote, 40197), Destination: netip.AddrPortFrom(intercepted, 5353), Payload: []byte("request")}).MarshalBinary())
	if err = writeTestPacket(stack, mustTestWire((IPPacket{Source: remote, Destination: intercepted, Protocol: ProtocolUDP, HopLimit: 64, Payload: payload}).MarshalBinary())); err != nil {
		t.Fatal(err)
	}
	if acceptErr != nil || connection == nil {
		t.Fatalf("forwarded socket = %v, %v", connection, acceptErr)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	quote := readOutboundPacket(t, stack)
	for index, code := range []uint8{ICMPv4TimeExceededCodeFragmentReassembly, ICMPv4TimeExceededCodeTTLInTransit, ICMPv4TimeExceededCodeFragmentReassembly} {
		message, err := (ICMPError{Reporter: remote, Type: ICMPv4TypeTimeExceeded, Code: code, QuotedPacket: quote}).ICMPMessage(intercepted)
		if err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, mustTestWire((IPPacket{Source: remote, Destination: intercepted, Protocol: ProtocolICMPv4, HopLimit: 64, Payload: mustTestWire(message.MarshalBinary())}).MarshalBinary())); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if info := connection.Info(); info.ICMPErrors != 0 || info.ErrorQueueEntries != 0 || info.LastError != nil {
				t.Fatalf("forwarded socket retained a reassembly timeout: %+v", info)
			}
			if n, err := connection.Write([]byte("still writable")); err != nil || n != len("still writable") {
				t.Fatalf("forwarded write after reassembly timeout = %d, %v", n, err)
			}
			_ = readOutboundPacket(t, stack)
		}
	}
	if info := connection.Info(); info.ICMPErrors != 1 || info.ErrorQueueEntries != 1 {
		t.Fatalf("forwarded socket retained something other than the TTL error: %+v", info)
	}
	buffer := make([]byte, 64)
	var networkError ICMPError
	if n, readErr := connection.Read(buffer); n != 0 || !errors.As(readErr, &networkError) || networkError.Code != ICMPv4TimeExceededCodeTTLInTransit {
		t.Fatalf("forwarded pending error = %d, %v", n, readErr)
	}
	if queued, queueErr := connection.ReadError(); queueErr != nil || !errors.As(queued, &networkError) || networkError.Code != ICMPv4TimeExceededCodeTTLInTransit {
		t.Fatalf("forwarded extended error = %v, %v", queued, queueErr)
	}
	if n, readErr := connection.Read(buffer); readErr != nil || !bytes.Equal(buffer[:n], []byte("request")) {
		t.Fatalf("forwarded queued data = %d, %v", n, readErr)
	}
}

func BenchmarkUDPForwarderReply(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.200")
	remote := netip.MustParseAddr("192.0.2.201")
	target := netip.MustParseAddr("198.51.100.200")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	reply := []byte("benchmark answer")
	var replyErr error
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr = request.Reply(reply)
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = forwarder.Close()
		_ = stack.Close()
	})
	packet := buildTestUDP(remote, target, 53000, 53, []byte("benchmark query"))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet) + len(reply)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			b.Fatal(err)
		}
		if replyErr != nil {
			b.Fatal(replyErr)
		}
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			b.Fatal("missing UDP forwarder reply")
		}
		stack.outbound.release(entry)
	}
}

func BenchmarkUDPForwarderReplyFrom(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.204")
	remote := netip.MustParseAddr("192.0.2.205")
	target := netip.MustParseAddr("198.51.100.204")
	selected := netip.MustParseAddrPort("203.0.113.204:5353")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	reply := []byte("benchmark answer")
	var replyErr error
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr = request.ReplyFrom(reply, selected)
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = forwarder.Close()
		_ = stack.Close()
	})
	packet := buildTestUDP(remote, target, 53000, 53, []byte("benchmark query"))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet) + len(reply)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			b.Fatal(err)
		}
		if replyErr != nil {
			b.Fatal(replyErr)
		}
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			b.Fatal("missing UDP forwarder ReplyFrom")
		}
		stack.outbound.release(entry)
	}
}

func BenchmarkICMPForwarderReplyEcho(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.202")
	remote := netip.MustParseAddr("192.0.2.203")
	target := netip.MustParseAddr("198.51.100.202")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	var replyErr error
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		replyErr = request.ReplyEcho()
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = forwarder.Close()
		_ = stack.Close()
	})
	icmp := make([]byte, 40)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 1)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packet := buildIPPacket(remote, target, ProtocolICMPv4, icmp, 1, true)
	b.ReportAllocs()
	b.SetBytes(int64(len(packet) + len(icmp)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			b.Fatal(err)
		}
		if replyErr != nil {
			b.Fatal(replyErr)
		}
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			b.Fatal("missing ICMP forwarder reply")
		}
		stack.outbound.release(entry)
	}
}

func BenchmarkICMPForwarderReplyIPPacket(b *testing.B) {
	for _, size := range []int{256, 4096} {
		b.Run(fmt.Sprintf("IPv4/%d", size), func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.206")
			remote := netip.MustParseAddr("192.0.2.207")
			target := netip.MustParseAddr("198.51.100.206")
			selected := netip.MustParseAddr("203.0.113.206")
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
			})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			icmp := make([]byte, size-20)
			icmp[0] = 0
			binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			reply := buildIPPacket(selected, remote, ProtocolICMPv4, icmp, 1, false)
			requestICMP := []byte{8, 0, 0, 0, 0, 1, 0, 1}
			binary.BigEndian.PutUint16(requestICMP[2:4], checksum(requestICMP))
			packet := buildIPPacket(remote, target, ProtocolICMPv4, requestICMP, 1, true)
			var replyErr error
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				replyErr = request.ReplyIPPacket(reply)
			})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				_ = forwarder.Close()
				_ = stack.Close()
			})
			fragments := 1
			if size > 1400 {
				fragments = (size - 20 + 1375) / 1376
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(packet) + len(reply)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err = stack.Write([][]byte{packet}, 0); err != nil {
					b.Fatal(err)
				}
				if replyErr != nil {
					b.Fatal(replyErr)
				}
				for fragment := 0; fragment < fragments; fragment++ {
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						b.Fatal("missing ICMP forwarder ReplyIPPacket")
					}
					stack.outbound.release(entry)
				}
			}
		})
	}
}

func TestIPv6TransportForwarders(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::90")
	serverAddress := netip.MustParseAddr("2001:db8::91")
	target := netip.MustParseAddr("2001:db8:1::90")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)

	tcpAccepted := make(chan *TCPConn, 1)
	_, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		if acceptErr != nil {
			t.Errorf("Accept IPv6 TCP: %v", acceptErr)
			return
		}
		tcpAccepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTCP, err := client.DialTCP(context.Background(), "tcp6", netip.AddrPort{}, netip.AddrPortFrom(target, 8443))
	if err != nil {
		t.Fatal(err)
	}
	defer clientTCP.Close()
	serverTCP := <-tcpAccepted
	defer serverTCP.Close()
	_ = clientTCP.SetDeadline(time.Now().Add(time.Second))
	_ = serverTCP.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientTCP.Write([]byte("tcp6")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, err := serverTCP.Read(buffer)
	if err != nil || string(buffer[:n]) != "tcp6" {
		t.Fatalf("IPv6 forwarded TCP = %q, %v", buffer[:n], err)
	}

	udpAccepted := make(chan *UDPConn, 1)
	_, err = NewUDPForwarder(server, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept IPv6 UDP: %v", acceptErr)
			return
		}
		udpAccepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	clientUDP, err := client.DialUDP(context.Background(), "udp6", netip.AddrPort{}, netip.AddrPortFrom(target, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	_ = clientUDP.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientUDP.Write([]byte("udp6")); err != nil {
		t.Fatal(err)
	}
	serverUDP := <-udpAccepted
	defer serverUDP.Close()
	_ = serverUDP.SetDeadline(time.Now().Add(time.Second))
	n, err = serverUDP.Read(buffer)
	if err != nil || string(buffer[:n]) != "udp6" {
		t.Fatalf("IPv6 forwarded UDP = %q, %v", buffer[:n], err)
	}
	if _, err = serverUDP.Write([]byte("reply6")); err != nil {
		t.Fatal(err)
	}
	n, err = clientUDP.Read(buffer)
	if err != nil || string(buffer[:n]) != "reply6" {
		t.Fatalf("IPv6 forwarded UDP reply = %q, %v", buffer[:n], err)
	}
}

func TestTCPForwarderCreationOptionsValidateBeforeClaim(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.240")
	serverAddress := netip.MustParseAddr("192.0.2.241")
	target := netip.MustParseAddr("198.51.100.240")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)
	type acceptResult struct {
		connection *TCPConn
		invalid    error
		err        error
	}
	accepted := make(chan acceptResult, 1)
	_, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		_, invalid := request.Accept(context.Background(), SocketOptions.ReceiveErrors(true))
		connection, acceptErr := request.Accept(context.Background(),
			SocketOptions.ReadBuffer(6123), SocketOptions.WriteBuffer(7123),
			SocketOptions.NoDelay(false), SocketOptions.CongestionControl(CongestionControlReno),
			SocketOptions.MaximumPacingRate(8123), SocketOptions.TrafficClass(0xab),
		)
		accepted <- acceptResult{connection: connection, invalid: invalid, err: acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(target, 8443))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	result := <-accepted
	if !errors.Is(result.invalid, syscall.ENOPROTOOPT) {
		t.Fatalf("invalid TCP Forwarder option = %v, want ENOPROTOOPT", result.invalid)
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.connection.Close()
	if info := result.connection.Info(); info.ReceiveBufferCapacity != 6123 || info.MaximumReceiveBuffer != 6123 ||
		info.SendBufferCapacity != 7123 || info.MaximumSendBuffer != 7123 || info.NoDelay ||
		info.CongestionControl != CongestionControlReno || info.MaximumPacingRate != 8123 || info.TrafficClass != 0xa8 {
		t.Fatalf("forwarded TCP creation policy = %+v", info)
	}
}

func TestUDPForwarderCreationOptionsValidateBeforeClaim(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.242")
	remote := netip.MustParseAddr("198.51.100.242")
	target := netip.MustParseAddr("203.0.113.242")
	stack := newForwarderTestStack(t, owned, true)
	type acceptResult struct {
		connection *UDPConn
		invalid    error
		err        error
	}
	accepted := make(chan acceptResult, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, invalid := request.Accept(SocketOptions.FlowLabel(1))
		connection, acceptErr := request.Accept(
			SocketOptions.ReadBuffer(123), SocketOptions.ReceiveErrors(true),
			SocketOptions.PathMTUDiscovery(PathMTUDiscoveryDo), SocketOptions.HopLimit(23),
			SocketOptions.Broadcast(false), SocketOptions.MulticastHopLimit(7), SocketOptions.MulticastLoopback(false),
			SocketOptions.TrafficClass(0x5a),
		)
		accepted <- acceptResult{connection: connection, invalid: invalid, err: acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52000, 5353, []byte("options"))); err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if !errors.Is(result.invalid, syscall.EAFNOSUPPORT) {
		t.Fatalf("invalid UDP Forwarder family option = %v, want EAFNOSUPPORT", result.invalid)
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.connection.Close()
	if info := result.connection.Info(); info.ReceiveQueueCapacity != 123 || !info.ReceiveErrors ||
		info.PathMTUDiscovery != PathMTUDiscoveryDo || info.HopLimit != 23 || info.Broadcast ||
		info.MulticastHopLimit != 7 || info.MulticastLoopback || info.TrafficClass != 0x5a {
		t.Fatalf("forwarded UDP creation policy = %+v", info)
	}
}

func TestUDPForwarderListenCreationOptionsValidateBeforeClaim(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.243")
	remote := netip.MustParseAddr("198.51.100.243")
	target := netip.MustParseAddr("203.0.113.243")
	stack := newForwarderTestStack(t, owned, true)
	type listenResult struct {
		connection *UDPConn
		invalid    error
		err        error
	}
	listened := make(chan listenResult, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, invalid := request.Listen(SocketOptions.ReusePort(true))
		connection, listenErr := request.Listen(SocketOptions.ReadBuffer(321), SocketOptions.ReceiveErrors(true))
		listened <- listenResult{connection: connection, invalid: invalid, err: listenErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52001, 5353, []byte("listen options"))); err != nil {
		t.Fatal(err)
	}
	result := <-listened
	if !errors.Is(result.invalid, syscall.ENOPROTOOPT) {
		t.Fatalf("invalid UDP Forwarder listen option = %v, want ENOPROTOOPT", result.invalid)
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.connection.Close()
	if info := result.connection.Info(); info.RemoteAddress.IsValid() || info.ReceiveQueueCapacity != 321 || !info.ReceiveErrors {
		t.Fatalf("forwarded UDP listener creation policy = %+v", info)
	}
}

func TestTCPForwarderRevalidatesSYNAdmission(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("IPv6-%t", ipv6), func(t *testing.T) {
			local, remote, intercepted := netip.MustParseAddr("192.0.2.247"), netip.MustParseAddr("192.0.2.248"), netip.MustParseAddr("198.51.100.247")
			if ipv6 {
				local, remote, intercepted = netip.MustParseAddr("2001:db8::247"), netip.MustParseAddr("2001:db8::248"), netip.MustParseAddr("2001:db8:1::247")
			}
			stack := newForwarderTestStack(t, local, true)
			requests := make(chan *TCPForwarderRequest, 2)
			forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{MaxInFlight: 1}, func(request *TCPForwarderRequest) {
				requests <- request
				<-request.Done()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			key := tcpKey{local: netip.AddrPortFrom(intercepted, 8080), remote: netip.AddrPortFrom(remote, 5300)}
			segment := tcpSegment{flags: TCPFlagSYN, sequence: 1000}
			previous := stack.network.Load()
			if !previous.acceptsInboundDestination(intercepted) {
				t.Fatal("original network policy did not admit intercepted destination")
			}
			if handled, admitted := forwarder.admitSegment(segment, key); !handled || !admitted {
				t.Fatal("initial request was not admitted")
			}
			var first *TCPForwarderRequest
			select {
			case first = <-requests:
			case <-time.After(time.Second):
				t.Fatal("initial handler did not start")
			}
			if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}, MTU: 1400}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-first.Done():
			default:
				t.Fatal("configuration update retained an invalid pending request")
			}
			if !previous.acceptsInboundDestination(intercepted) {
				t.Fatal("immutable policy snapshot changed")
			}
			if handled, admitted := forwarder.admitSegment(segment, key); !handled || admitted {
				t.Fatalf("stale SYN admission = handled %t, admitted %t", handled, admitted)
			}
			if forwarder.handleTimeWaitSegment(segment, key) {
				t.Fatal("rejected SYN was allowed to replace its TIME-WAIT owner")
			}
			if info := forwarder.Info(); info.Pending != 0 || info.Requests != 1 {
				t.Fatalf("invalid SYN consumed request capacity: %+v", info)
			}
			key.local = netip.AddrPortFrom(local, 8080)
			wire := buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), segment.sequence, 0, TCPFlagSYN, 65535, nil, nil)
			if err = writeTestPacket(stack, wire); err != nil {
				t.Fatal(err)
			}
			select {
			case request := <-requests:
				if request.Flow().Destination != key.local {
					t.Fatalf("accepted destination = %v, want %v", request.Flow().Destination, key.local)
				}
				if err = request.Drop(); err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("valid SYN could not use the released capacity")
			}
		})
	}
}

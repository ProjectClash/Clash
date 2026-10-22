package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSYNCookieBacklogHandshake(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.51")
	remote := netip.MustParseAddr("198.51.100.51")
	initialTCP := TCPSocketDefaults{ReceiveBuffer: 128 * 1024, MaximumReceiveBuffer: 2 * 1024 * 1024}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, TCP: initialTCP})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 47002))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for index := 0; index < tcpSYNBacklog; index++ {
		connection := &TCPConn{}
		if !listener.(*TCPListener).trackHandshake(connection) {
			t.Fatalf("failed to fill SYN backlog at %d", index)
		}
	}
	defer func() {
		listener.(*TCPListener).mu.Lock()
		listener.(*TCPListener).pending = make(map[*TCPConn]struct{})
		listener.(*TCPListener).handshaking = make(map[*TCPConn]struct{})
		listener.(*TCPListener).mu.Unlock()
	}()

	clientSequence := uint32(0x12345678)
	clientTimestamp := uint32(1000)
	options := []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 5}
	options = append(options, tcpTimestampOptions(clientTimestamp, 0)...)
	syn := buildTestTCP(remote, local, 43001, 47002, clientSequence, 0, TCPFlagSYN|TCPFlagECE|TCPFlagCWR, 4096, options, nil)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie response: %x", response)
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if tcp[13] != TCPFlagSYN|TCPFlagACK|TCPFlagECE || binary.BigEndian.Uint32(tcp[8:12]) != clientSequence+1 {
		t.Fatalf("SYN-cookie flags/ack = %#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	_, serverWindowScale, serverWindowScaling, _, _, _ := parseTCPOptions(tcp[tcpHeaderSize:headerSize], 536, 65535)
	if !serverWindowScaling {
		t.Fatal("SYN cookie did not advertise window scaling")
	}
	serverTimestamp, _, timestampPresent := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize])
	if !timestampPresent {
		t.Fatal("SYN cookie did not preserve timestamp negotiation")
	}
	if serverTimestamp&1 == 0 {
		t.Fatal("SYN cookie lost ECN timestamp parity")
	}
	stack.mu.RLock()
	connectionsBeforeACK := len(stack.tcp)
	stack.mu.RUnlock()
	if connectionsBeforeACK != 0 {
		t.Fatalf("SYN cookie retained %d connections before final ACK", connectionsBeforeACK)
	}

	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 64 * 1024, MaximumReceiveBuffer: 128 * 1024},
	}); err != nil {
		t.Fatal(err)
	}
	const missingTimestampClientSequence = uint32(0x22345678)
	missingTimestampSYN := buildTestTCP(remote, local, 43002, 47002, missingTimestampClientSequence, 0, TCPFlagSYN|TCPFlagECE|TCPFlagCWR, 4096, options, nil)
	if err = writeTestPacket(stack, missingTimestampSYN); err != nil {
		t.Fatal(err)
	}
	missingTimestampResponse := readOutboundPacket(t, stack)
	missingParsed, ok := parseIPPacket(missingTimestampResponse, false)
	if !ok || missingParsed.protocol != ProtocolTCP || len(missingParsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid missing-timestamp SYN-cookie response: %x", missingTimestampResponse)
	}
	missingServerSequence := binary.BigEndian.Uint32(missingParsed.payload[4:8])
	missingTimestampACK := buildTestTCP(remote, local, 43002, 47002, missingTimestampClientSequence+1, missingServerSequence+1, TCPFlagACK, 1234, nil, nil)
	if err = writeTestPacket(stack, missingTimestampACK); err != nil {
		t.Fatal(err)
	}
	if err = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	missingConnection, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept without cookie timestamp: %v", err)
	}
	missingConnectionTCP := missingConnection.(*TCPConn)
	if missingConnectionTCP.peerTimestamp || missingConnectionTCP.peerECN || missingConnectionTCP.recentTimestamp != 0 ||
		missingConnectionTCP.peerSACK || missingConnectionTCP.peerWindowScaling || missingConnectionTCP.peerWindowScale != 0 ||
		missingConnectionTCP.receiveWindowScale != 0 {
		t.Fatalf("missing-timestamp cookie options = MSS:%d SACK:%v TS:%v/%d ECN:%v scale:%d/%d/%v", missingConnectionTCP.peerMSS,
			missingConnectionTCP.peerSACK, missingConnectionTCP.peerTimestamp, missingConnectionTCP.recentTimestamp,
			missingConnectionTCP.peerECN, missingConnectionTCP.peerWindowScale, missingConnectionTCP.receiveWindowScale,
			missingConnectionTCP.peerWindowScaling)
	}
	_ = missingConnection.Close()
	_ = readOutboundPacket(t, stack)

	ackOptions := tcpTimestampOptions(clientTimestamp+1, serverTimestamp)
	forgedACK := buildTestTCP(remote, local, 43001, 47002, clientSequence+1, serverSequence+2, TCPFlagACK, 1234, ackOptions, nil)
	if err = writeTestPacket(stack, forgedACK); err != nil {
		t.Fatal(err)
	}
	reset := readOutboundPacket(t, stack)
	if parsedReset, parsedResetOK := parseIPPacket(reset, false); !parsedResetOK || len(parsedReset.payload) < tcpHeaderSize || parsedReset.payload[13]&TCPFlagRST == 0 {
		t.Fatalf("forged cookie ACK response = %x", reset)
	}
	ack := buildTestTCP(remote, local, 43001, 47002, clientSequence+1, serverSequence+1, TCPFlagACK, 1234, ackOptions, nil)
	if err = writeTestPacket(stack, ack); err != nil {
		t.Fatal(err)
	}
	if err = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	connectionTCP := connection.(*TCPConn)
	defer connection.Close()
	if connectionTCP.peerMSS != 1440 || !connectionTCP.peerWindowScaling || connectionTCP.peerWindowScale != 5 ||
		!connectionTCP.peerSACK || !connectionTCP.peerTimestamp || !connectionTCP.peerECN || connectionTCP.recentTimestamp != clientTimestamp+1 {
		t.Fatalf("restored SYN-cookie options = MSS %d scale %d/%v SACK %v TS %v/%d ECN %v",
			connectionTCP.peerMSS, connectionTCP.peerWindowScale, connectionTCP.peerWindowScaling, connectionTCP.peerSACK,
			connectionTCP.peerTimestamp, connectionTCP.recentTimestamp, connectionTCP.peerECN)
	}
	if connectionTCP.peerWindow != uint32(1234)<<5 {
		t.Fatalf("restored peer window = %d, want %d", connectionTCP.peerWindow, uint32(1234)<<5)
	}
	if connectionTCP.receiveWindowScale != serverWindowScale {
		t.Fatalf("restored local window scale = %d, want advertised %d", connectionTCP.receiveWindowScale, serverWindowScale)
	}
	const zeroEchoClientSequence = uint32(0x32345678)
	zeroEchoSYN := buildTestTCP(remote, local, 43003, 47002, zeroEchoClientSequence, 0, TCPFlagSYN|TCPFlagECE|TCPFlagCWR, 4096, options, nil)
	if err = writeTestPacket(stack, zeroEchoSYN); err != nil {
		t.Fatal(err)
	}
	zeroEchoResponse := readOutboundPacket(t, stack)
	zeroEchoParsed, ok := parseIPPacket(zeroEchoResponse, false)
	if !ok || zeroEchoParsed.protocol != ProtocolTCP || len(zeroEchoParsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid zero-TSecr SYN-cookie response: %x", zeroEchoResponse)
	}
	zeroEchoTCP := zeroEchoParsed.payload
	zeroEchoServerSequence := binary.BigEndian.Uint32(zeroEchoTCP[4:8])
	zeroEchoACK := buildTestTCP(remote, local, 43003, 47002, zeroEchoClientSequence+1, zeroEchoServerSequence+1, TCPFlagACK, 1234, tcpTimestampOptions(clientTimestamp+2, 0), nil)
	if err = writeTestPacket(stack, zeroEchoACK); err != nil {
		t.Fatal(err)
	}
	if err = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	zeroEchoConnection, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept with zero cookie TSecr: %v", err)
	}
	zeroEchoConnectionTCP := zeroEchoConnection.(*TCPConn)
	defer zeroEchoConnection.Close()
	if !zeroEchoConnectionTCP.peerTimestamp || zeroEchoConnectionTCP.recentTimestamp != clientTimestamp+2 ||
		!zeroEchoConnectionTCP.peerECN || !zeroEchoConnectionTCP.peerSACK || !zeroEchoConnectionTCP.peerWindowScaling ||
		zeroEchoConnectionTCP.peerWindowScale != 5 || zeroEchoConnectionTCP.receiveWindowScale != serverWindowScale {
		t.Fatalf("zero-TSecr cookie options = TS:%v/%d ECN:%v SACK:%v scale:%d/%d/%v", zeroEchoConnectionTCP.peerTimestamp,
			zeroEchoConnectionTCP.recentTimestamp, zeroEchoConnectionTCP.peerECN, zeroEchoConnectionTCP.peerSACK,
			zeroEchoConnectionTCP.peerWindowScale, zeroEchoConnectionTCP.receiveWindowScale, zeroEchoConnectionTCP.peerWindowScaling)
	}
	if zeroEchoConnectionTCP.peerWindow != uint32(1234)<<5 {
		t.Fatalf("zero-TSecr peer window = %d, want %d", zeroEchoConnectionTCP.peerWindow, uint32(1234)<<5)
	}
	if connection.RemoteAddr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(remote, 43001) {
		t.Fatalf("cookie connection remote = %v", connection.RemoteAddr())
	}
	info := listener.(*TCPListener).Info()
	if info.SYNsReceived != 3 || info.SYNCookiesSent != 3 || info.SYNCookiesRejected != 1 || info.SYNCookiesAccepted != 3 ||
		info.HandshakeCompletions != 3 || info.AcceptedConnections != 3 || info.AcceptQueuePeak > 1 ||
		info.SYNBacklogConnections != tcpSYNBacklog || info.SYNBacklogPeak != tcpSYNBacklog {
		t.Fatalf("SYN cookie listener diagnostics = %+v", info)
	}
	stats := stack.Stats()
	if stats.TCPSYNCookiesSent != 3 || stats.TCPSYNCookiesRejected != 1 || stats.TCPSYNCookiesAccepted != 3 {
		t.Fatalf("SYN cookie stack diagnostics = %+v", stats)
	}
}

func TestSYNCookieReceiveScaleIsListenerScoped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.54")
	remote := netip.MustParseAddr("198.51.100.54")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 64 * 1024, MaximumReceiveBuffer: 64 * 1024},
		MTU:            1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	factory := SocketOptions
	low, err := (&ListenConfig{Options: []SocketOption{factory.SYNBacklog(1), factory.ReadBuffer(65535)}}).ListenTCP(
		context.Background(), stack, "tcp4", netip.AddrPortFrom(local, 47004))
	if err != nil {
		t.Fatal(err)
	}
	high, err := (&ListenConfig{Options: []SocketOption{factory.SYNBacklog(1), factory.ReadBuffer(2 * 1024 * 1024)}}).ListenTCP(
		context.Background(), stack, "tcp4", netip.AddrPortFrom(local, 47005))
	if err != nil {
		low.Close()
		t.Fatal(err)
	}
	cleanup := func(listener net.Listener) {
		tcpListener := listener.(*TCPListener)
		tcpListener.mu.Lock()
		tcpListener.pending = make(map[*TCPConn]struct{})
		tcpListener.handshaking = make(map[*TCPConn]struct{})
		tcpListener.mu.Unlock()
		_ = listener.Close()
	}
	defer cleanup(low)
	defer cleanup(high)

	type cookieWire struct {
		scale           uint8
		serverTimestamp uint32
		serverSequence  uint32
		scaling         bool
	}
	issueCookie := func(listener net.Listener, localPort, remotePort uint16, clientSequence uint32) cookieWire {
		tcpListener := listener.(*TCPListener)
		if !tcpListener.trackHandshake(&TCPConn{}) {
			t.Fatal("failed to fill listener SYN backlog")
		}
		synOptions := []byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionWindowScale, 3, 7}
		synOptions = append(synOptions, tcpTimestampOptions(1000, 0)...)
		syn := buildTestTCP(remote, local, remotePort, localPort, clientSequence, 0, TCPFlagSYN, 4096, synOptions, nil)
		if err := writeTestPacket(stack, syn); err != nil {
			t.Fatal(err)
		}
		response := readOutboundPacket(t, stack)
		parsed, ok := parseIPPacket(response, false)
		if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
			t.Fatalf("invalid listener-scoped SYN-cookie response: %x", response)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		_, scale, scaling, _, _, _ := parseTCPOptions(parsed.payload[tcpHeaderSize:headerSize], 536, 65535)
		serverTimestamp, _, _ := parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
		return cookieWire{scale: scale, serverTimestamp: serverTimestamp, serverSequence: binary.BigEndian.Uint32(parsed.payload[4:8]), scaling: scaling}
	}

	lowCookie := issueCookie(low, 47004, 43004, 0x11000001)
	highCookie := issueCookie(high, 47005, 43005, 0x22000001)
	if lowCookie.scale != 0 {
		t.Fatalf("low-buffer listener SYN-cookie scale = %d/%v, want 0", lowCookie.scale, lowCookie.scaling)
	}
	wantHighScale := tcpReceiveWindowScaleFor(2 * 1024 * 1024)
	if !highCookie.scaling || highCookie.scale != wantHighScale {
		t.Fatalf("high-buffer listener SYN-cookie scale = %d/%v, want %d/true", highCookie.scale, highCookie.scaling, wantHighScale)
	}
	lowACK := buildTestTCP(remote, local, 43004, 47004, 0x11000002, lowCookie.serverSequence+1, TCPFlagACK, 4096,
		tcpTimestampOptions(1001, lowCookie.serverTimestamp), nil)
	highACK := buildTestTCP(remote, local, 43005, 47005, 0x22000002, highCookie.serverSequence+1, TCPFlagACK, 4096,
		tcpTimestampOptions(1001, highCookie.serverTimestamp), nil)
	if err := writeTestPacket(stack, lowACK); err != nil {
		t.Fatal(err)
	}
	if err := writeTestPacket(stack, highACK); err != nil {
		t.Fatal(err)
	}
	if err := low.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := high.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	lowConnection, err := low.Accept()
	if err != nil {
		t.Fatal(err)
	}
	highConnection, err := high.Accept()
	if err != nil {
		lowConnection.Close()
		t.Fatal(err)
	}
	defer lowConnection.Close()
	defer highConnection.Close()
	if got := lowConnection.(*TCPConn).receiveWindowScale; got != 0 {
		t.Fatalf("low-buffer restored receive scale = %d, want 0", got)
	}
	if got := highConnection.(*TCPConn).receiveWindowScale; got != wantHighScale {
		t.Fatalf("high-buffer restored receive scale = %d, want %d", got, wantHighScale)
	}
}

func TestSYNCookieFastOpenFallsBackToFinalACK(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.53")
	remote := netip.MustParseAddr("198.51.100.53")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 47003))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for index := 0; index < tcpSYNBacklog; index++ {
		if !listener.(*TCPListener).trackHandshake(&TCPConn{}) {
			t.Fatalf("failed to fill SYN backlog at %d", index)
		}
	}
	t.Cleanup(func() {
		listener.(*TCPListener).mu.Lock()
		listener.(*TCPListener).pending = make(map[*TCPConn]struct{})
		listener.(*TCPListener).handshaking = make(map[*TCPConn]struct{})
		listener.(*TCPListener).mu.Unlock()
	})

	const clientSequence = uint32(0x23456789)
	payload := []byte("fast-open request")
	syn := buildTestTCP(remote, local, 43003, 47003, clientSequence, 0, TCPFlagSYN, 65535, nil, payload)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie response: %x", response)
	}
	tcp := parsed.payload
	if tcp[13]&byte(TCPFlagSYN|TCPFlagACK) != byte(TCPFlagSYN|TCPFlagACK) || binary.BigEndian.Uint32(tcp[8:12]) != clientSequence+1 {
		t.Fatalf("SYN-cookie flags/ack = %#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	finalACK := buildTestTCP(remote, local, 43003, 47003, clientSequence+1, serverSequence+1, TCPFlagACK|TCPFlagFIN, 65535, nil, payload)
	if err = writeTestPacket(stack, finalACK); err != nil {
		t.Fatal(err)
	}
	if err = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("retransmitted SYN data = %q, want %q", buffer, payload)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("read after retransmitted FIN = %d, %v, want 0, EOF", n, readErr)
	}
}

func TestSYNCookieListenerCloseResetsPendingConnection(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.52")
	remote := netip.MustParseAddr("198.51.100.52")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	key := tcpKey{
		local:  netip.AddrPortFrom(local, port),
		remote: netip.AddrPortFrom(remote, 43002),
	}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	connection.passive = true
	connection.receiveNext = 0x12345679
	if !listener.(*TCPListener).trackCompleted(connection) {
		t.Fatal("failed to track pending cookie connection")
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	const initialSequence = uint32(0x87654321)
	connection.runPassiveCookie(listener.(*TCPListener), tcpSegment{}, initialSequence)
	packet := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid abort reset: %x", packet)
	}
	tcp := parsed.payload
	if tcp[13] != TCPFlagRST|TCPFlagACK || binary.BigEndian.Uint32(tcp[4:8]) != initialSequence+1 ||
		binary.BigEndian.Uint32(tcp[8:12]) != connection.receiveNext {
		t.Fatalf("abort reset flags/sequence/ack = %#x/%#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]))
	}
}

func TestSYNCookieHonorsConfiguredReceiveWindow(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.61")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 4096, MaximumReceiveBuffer: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	key := tcpKey{local: netip.MustParseAddrPort("192.0.2.61:8080"), remote: netip.MustParseAddrPort("198.51.100.61:40000")}
	syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, nil, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(packet, false)
	if !ok || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie packet: %x", packet)
	}
	if window := binary.BigEndian.Uint16(parsed.payload[14:16]); window != 4096 {
		t.Fatalf("SYN-cookie receive window = %d, want 4096", window)
	}
}

func TestSYNCookieHonorsListenerCreationOptions(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::62")
	remote := netip.MustParseAddr("2001:db8:1::62")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	parsed, err := parseSocketOptions([]SocketOption{
		SocketOptions.ReadBuffer(4321), SocketOptions.TrafficClass(0xaf), SocketOptions.FlowLabel(0x45678),
	}, socketOptionTCPListen)
	if err != nil {
		t.Fatal(err)
	}
	listener := &TCPListener{options: parsed.tcp}
	key := tcpKey{local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 40000)}
	syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, listener, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet := readOutboundPacket(t, stack)
	parsedPacket, ok := parseIPPacket(packet, false)
	if !ok || len(parsedPacket.payload) < tcpHeaderSize {
		t.Fatalf("invalid listener-option SYN-cookie packet: %x", packet)
	}
	if window := binary.BigEndian.Uint16(parsedPacket.payload[14:16]); window != 4321 {
		t.Fatalf("listener-option SYN-cookie receive window = %d, want 4321", window)
	}
	if parsedPacket.trafficClass != 0xac || parsedPacket.flowLabel != 0x45678 {
		t.Fatalf("listener-option SYN-cookie IP policy = class %#x label %#x", parsedPacket.trafficClass, parsedPacket.flowLabel)
	}

	parsed, err = parseSocketOptions([]SocketOption{SocketOptions.FlowLabel(0)}, socketOptionTCPListen)
	if err != nil {
		t.Fatal(err)
	}
	listener.options = parsed.tcp
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, listener, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet = readOutboundPacket(t, stack)
	parsedPacket, ok = parseIPPacket(packet, false)
	if !ok || parsedPacket.flowLabel != 0 {
		t.Fatalf("explicit zero SYN-cookie flow label = %#x, parsed=%v", parsedPacket.flowLabel, ok)
	}
}

func TestSYNCookieValidationIPv4AndIPv6(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, test := range []struct {
		name   string
		local  netip.Addr
		remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.61"), remote: netip.MustParseAddr("198.51.100.61")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::61"), remote: netip.MustParseAddr("2001:db8:1::61")},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &tcpPassiveState{
				cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
			}
			for index := range state.cookieKey {
				state.cookieKey[index] = byte(index + 1)
			}
			key := tcpKey{local: netip.AddrPortFrom(test.local, 443), remote: netip.AddrPortFrom(test.remote, 50000)}
			syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
			syn.setOptions([]byte{2, 4, 0x05, 0xb4, 4, 2})
			_, data := encodeSYNCookieOptions(syn, test.remote)
			cookie := synCookieSequence(state.cookieKey, key, 0, syn.sequence, synCookiePeriodNumber(now, state.cookieEpoch), data, data)
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now, nil); !valid {
				t.Fatal("valid SYN cookie was rejected")
			}
			forged := ack
			forged.acknowledgement ^= 1 << synCookieDataBits
			if _, _, valid, _ := state.validateSYNCookie(key, forged, now, nil); valid {
				t.Fatal("forged SYN cookie was accepted")
			}
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now.Add(2*synCookiePeriod), nil); valid {
				t.Fatal("expired SYN cookie was accepted")
			}
			state.cookieActive = false
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now, nil); valid {
				t.Fatal("cookie ACK was accepted without recent cookie issuance")
			}
		})
	}
}

func TestSYNCookieAcceptsMissingTimestamp(t *testing.T) {
	now := time.Unix(2000002000, 0)
	state := &tcpPassiveState{
		cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
	}
	for index := range state.cookieKey {
		state.cookieKey[index] = byte(index + 1)
	}
	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.72:443"),
		remote: netip.MustParseAddrPort("198.51.100.72:50000"),
	}
	syn := tcpSegment{sequence: 100, flags: TCPFlagSYN | TCPFlagECE | TCPFlagCWR, window: 65535}
	syn.setOptions(tcpTimestampOptions(700, 0))
	_, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	cookie := synCookieSequence(state.cookieKey, key, 0, syn.sequence, period, data, synCookieAuthenticatedData(data, true, true))
	ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
	_, options, valid, attempted := state.validateSYNCookie(key, ack, now, nil)
	if !attempted || !valid {
		t.Fatalf("missing-timestamp cookie validation = valid:%v attempted:%v", valid, attempted)
	}
	if options.timestamp || options.ecn || options.timestampNow != 0 || options.sack || options.windowScaling ||
		options.windowScale != 0 {
		t.Fatalf("missing-timestamp cookie options = timestamp:%v ecn:%v tsval:%d sack:%v scale:%d/%v",
			options.timestamp, options.ecn, options.timestampNow, options.sack, options.windowScale,
			options.windowScaling)
	}
}

func TestSYNCookieZeroTimestampEcho(t *testing.T) {
	now := time.Unix(2000003000, 0)
	for _, withECN := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-ECN", true: "with-ECN"}[withECN], func(t *testing.T) {
			state := &tcpPassiveState{
				cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
			}
			for index := range state.cookieKey {
				state.cookieKey[index] = byte(index + 1)
			}
			key := tcpKey{
				local:  netip.MustParseAddrPort("192.0.2.74:443"),
				remote: netip.MustParseAddrPort("198.51.100.74:50000"),
			}
			flags := byte(TCPFlagSYN)
			if withECN {
				flags |= TCPFlagECE | TCPFlagCWR
			}
			syn := tcpSegment{sequence: 100, flags: flags, window: 65535}
			syn.setOptions(append([]byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionSACKPermitted, 2,
				TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, 7}, tcpTimestampOptions(700, 0)...))
			cookieOptions, data := encodeSYNCookieOptions(syn, key.remote.Addr())
			period := synCookiePeriodNumber(now, state.cookieEpoch)
			cookie := synCookieSequence(state.cookieKey, key, 0, syn.sequence, period, data,
				synCookieAuthenticatedData(data, cookieOptions.timestamp, cookieOptions.ecn))
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
			ack.setOptions(tcpTimestampOptions(701, 0))

			_, options, valid, attempted := state.validateSYNCookie(key, ack, now, nil)
			if !attempted || !valid {
				t.Fatalf("zero-TSecr cookie validation = valid:%v attempted:%v", valid, attempted)
			}
			if !options.timestamp || options.timestampNow != 701 || options.ecn != withECN || !options.sack ||
				!options.windowScaling || options.windowScale != 7 {
				t.Fatalf("zero-TSecr cookie options = timestamp:%v/%d ecn:%v sack:%v scale:%d/%v",
					options.timestamp, options.timestampNow, options.ecn, options.sack,
					options.windowScale, options.windowScaling)
			}
		})
	}
}

func TestSYNCookieTimestampPreservesClockOrder(t *testing.T) {
	for _, test := range []struct {
		raw  uint32
		ecn  bool
		want uint32
	}{
		{raw: 0, want: 0},
		{raw: 1, want: 0},
		{raw: 2, want: 2},
		{raw: 3, want: 2},
		{raw: 0, ecn: true, want: ^uint32(0)},
		{raw: 1, ecn: true, want: 1},
		{raw: 2, ecn: true, want: 1},
		{raw: 3, ecn: true, want: 3},
		{raw: ^uint32(0) - 1, want: ^uint32(0) - 1},
		{raw: ^uint32(0) - 1, ecn: true, want: ^uint32(0) - 2},
		{raw: ^uint32(0), want: ^uint32(0) - 1},
		{raw: ^uint32(0), ecn: true, want: ^uint32(0)},
	} {
		if got := synCookieTimestamp(test.raw, test.ecn); got != test.want || (got&1 != 0) != test.ecn || tcpSequenceGreater(got, test.raw) {
			t.Errorf("synCookieTimestamp(%#x, %t) = %#x, want %#x", test.raw, test.ecn, got, test.want)
		}
		if previous, next := synCookieTimestamp(test.raw, test.ecn), synCookieTimestamp(test.raw+1, test.ecn); tcpSequenceLess(next, previous) {
			t.Errorf("SYN-cookie timestamp moved backward from %#x to %#x at clock %#x, ECN:%t", previous, next, test.raw, test.ecn)
		}
	}
}

func TestSYNCookieWireTimestamp(t *testing.T) {
	for _, family := range []struct{ name, local, remote string }{
		{"IPv4", "192.0.2.75", "198.51.100.75"},
		{"IPv6", "2001:db8::75", "2001:db8:1::75"},
	} {
		t.Run(family.name, func(t *testing.T) {
			local, remote := netip.MustParseAddr(family.local), netip.MustParseAddr(family.remote)
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			key := tcpKey{local: netip.AddrPortFrom(local, 443), remote: netip.AddrPortFrom(remote, 50000)}
			for _, ecn := range []bool{false, true} {
				t.Run(fmt.Sprintf("ECN-%t", ecn), func(t *testing.T) {
					now := time.Now()
					state := &tcpPassiveState{}
					syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
					if ecn {
						syn.flags |= TCPFlagECE | TCPFlagCWR
					}
					options := []byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionSACKPermitted, 2,
						TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, 7}
					syn.setOptions(append(options, tcpTimestampOptions(700, 0)...))
					if err := state.sendSYNCookie(stack, nil, key, syn, now); err != nil {
						t.Fatal(err)
					}
					packet, err := ParseIPPacket(readOutboundPacket(t, stack))
					if err != nil {
						t.Fatal(err)
					}
					wire, err := packet.TCPSegment()
					if err != nil {
						t.Fatal(err)
					}
					value, echo, present := parseTCPTimestamp(wire.Options)
					if !present || (value&1 != 0) != ecn || echo != 700 {
						t.Fatalf("SYN-cookie Timestamp = %d/%d/%t, ECN:%t", value, echo, present, ecn)
					}
					ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: wire.SequenceNumber + 1, flags: TCPFlagACK, window: 4096}
					ack.setOptions(tcpTimestampOptions(701, value))
					_, recovered, valid, attempted := state.validateSYNCookie(key, ack, now, nil)
					if !attempted || !valid || !recovered.timestamp || recovered.ecn != ecn ||
						!recovered.sack || !recovered.windowScaling || recovered.windowScale != 7 {
						t.Fatalf("SYN-cookie recovery = valid:%t attempted:%t options:%+v", valid, attempted, recovered)
					}
					ack.setOptions(tcpTimestampOptions(701, 0))
					_, zeroEcho, valid, _ := state.validateSYNCookie(key, ack, now, nil)
					if !valid || zeroEcho != recovered {
						t.Fatalf("zero-TSecr recovery = valid:%t options:%+v, want %+v", valid, zeroEcho, recovered)
					}
				})
			}
		})
	}
}

func TestSYNCookieWithoutTimestampClearsRecoveredExtensions(t *testing.T) {
	for _, family := range []struct{ name, local, remote string }{
		{"IPv4", "192.0.2.73", "198.51.100.73"},
		{"IPv6", "2001:db8::73", "2001:db8:1::73"},
	} {
		for _, scale := range []byte{0, 7} {
			t.Run(fmt.Sprintf("%s/scale-%d", family.name, scale), func(t *testing.T) {
				local := netip.MustParseAddr(family.local)
				remote := netip.MustParseAddr(family.remote)
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
				if err != nil {
					t.Fatal(err)
				}
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				state := &tcpPassiveState{}
				key := tcpKey{local: netip.AddrPortFrom(local, 443), remote: netip.AddrPortFrom(remote, 50000)}
				syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
				syn.setOptions([]byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionSACKPermitted, 2,
					TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, scale})
				if err = state.sendSYNCookie(stack, nil, key, syn, time.Now()); err != nil {
					t.Fatal(err)
				}
				packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
				if !ok || len(packet.payload) < tcpHeaderSize {
					t.Fatalf("invalid SYN-cookie packet: %+v", packet)
				}
				tcp := packet.payload
				headerSize := int(tcp[12]>>4) * 4
				if headerSize < tcpHeaderSize || headerSize > len(tcp) {
					t.Fatalf("invalid SYN-cookie header size: %d", headerSize)
				}
				_, _, scaling, sack, timestamp, _ := parseTCPOptions(tcp[tcpHeaderSize:headerSize], 536, 65535)
				if scaling || sack || timestamp {
					t.Fatalf("no-timestamp SYN-cookie advertised scale:%v SACK:%v TS:%v; want no extensions", scaling, sack, timestamp)
				}
				ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: binary.BigEndian.Uint32(tcp[4:8]) + 1, flags: TCPFlagACK}
				_, options, valid, attempted := state.validateSYNCookie(key, ack, time.Now(), nil)
				if !attempted || !valid || options.windowScaling || options.sack || options.timestamp || options.mss != 1440 {
					t.Fatalf("no-timestamp SYN-cookie validation = attempted:%v valid:%v options:%+v", attempted, valid, options)
				}
			})
		}
	}
}

func BenchmarkSYNCookieOptionEncoding(b *testing.B) {
	for _, timestamp := range []bool{false, true} {
		b.Run(fmt.Sprintf("timestamp-%v", timestamp), func(b *testing.B) {
			remote := netip.MustParseAddr("198.51.100.73")
			syn := tcpSegment{flags: TCPFlagSYN}
			options := []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7}
			if timestamp {
				options = append(options, tcpTimestampOptions(100, 0)...)
			}
			syn.setOptions(options)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if options, _ := encodeSYNCookieOptions(syn, remote); options.mss == 0 {
					b.Fatal("missing MSS")
				}
			}
		})
	}
}

func TestSYNCookieValidationAcceptsPreviousPeriod(t *testing.T) {
	now := time.Unix(2000001000, 0)
	state := &tcpPassiveState{}
	listener := &TCPListener{closed: make(chan struct{})}
	secret, period, err := state.synCookieKey(now)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(period)
	if got := listener.recordSYNCookieScale(period, 2); got != 2 {
		t.Fatalf("first-period listener scale = %d, want 2", got)
	}
	_, samePeriod, err := state.synCookieKey(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if samePeriod != period {
		t.Fatalf("same-period SYN-cookie period = %d, want %d", samePeriod, period)
	}
	if got := listener.recordSYNCookieScale(samePeriod, 7); got != 2 {
		t.Fatalf("same-period listener scale = %d, want stable 2", got)
	}

	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.70:443"),
		remote: netip.MustParseAddrPort("198.51.100.70:50000"),
	}
	clientSequence := uint32(100)
	syn := tcpSegment{sequence: clientSequence, flags: TCPFlagSYN, window: 65535}
	syn.setOptions(append([]byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionWindowScale, 3, 7}, tcpTimestampOptions(700, 0)...))
	_, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	cookie := synCookieSequence(secret, key, 0, clientSequence, period, data, synCookieAuthenticatedData(data, true, false))
	ack := tcpSegment{sequence: clientSequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK}
	ack.setOptions(tcpTimestampOptions(100, 0))

	next := now.Add(synCookiePeriod)
	_, nextPeriod, err := state.synCookieKey(next)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(nextPeriod)
	if nextPeriod != period+1 {
		t.Fatalf("next-period SYN-cookie period = %d, want %d", nextPeriod, period+1)
	}
	if got := listener.recordSYNCookieScale(nextPeriod, 7); got != 7 {
		t.Fatalf("next-period listener scale = %d, want 7", got)
	}
	_, options, valid, _ := state.validateSYNCookie(key, ack, next, listener)
	if !valid || options.localWindowScale != 2 {
		t.Fatalf("previous-period cookie = valid %t scale %d, want true/2", valid, options.localWindowScale)
	}
}

func TestSYNCookieRejectsReplacedListenerCookie(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.76")
	remote := netip.MustParseAddr("198.51.100.76")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 65535, MaximumReceiveBuffer: 65535},
		MTU:            1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	keeper, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 47007))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keeper.Close() })
	old, err := (&ListenConfig{Options: []SocketOption{SocketOptions.ReadBuffer(65535)}}).ListenTCP(
		context.Background(), stack, "tcp4", netip.AddrPortFrom(local, 47006))
	if err != nil {
		t.Fatal(err)
	}

	state := stack.tcpPassive.(*tcpPassiveState)
	key := tcpKey{local: netip.AddrPortFrom(local, 47006), remote: netip.AddrPortFrom(remote, 50076)}
	syn := tcpSegment{sequence: 0x11000001, flags: TCPFlagSYN, window: 4096}
	syn.setOptions(append([]byte{TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionWindowScale, 3, 7}, tcpTimestampOptions(1000, 0)...))
	issue := func(listener *TCPListener, clientSequence uint32) tcpSegment {
		syn.sequence = clientSequence
		if err := state.sendSYNCookie(stack, listener, key, syn, time.Now()); err != nil {
			t.Fatal(err)
		}
		packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
		if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("invalid listener-replacement SYN-cookie: %+v", packet)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		serverTimestamp, _, present := parseTCPTimestamp(packet.payload[tcpHeaderSize:headerSize])
		if !present {
			t.Fatal("listener-replacement SYN-cookie omitted Timestamp")
		}
		ack := tcpSegment{sequence: clientSequence + 1, acknowledgement: binary.BigEndian.Uint32(packet.payload[4:8]) + 1, flags: TCPFlagACK, window: 4096}
		ack.setOptions(tcpTimestampOptions(clientSequence+1, serverTimestamp))
		return ack
	}

	oldACK := issue(old.(*TCPListener), syn.sequence)
	if _, options, valid, attempted := state.validateSYNCookie(key, oldACK, time.Now(), old.(*TCPListener)); !valid || !attempted || options.localWindowScale != 0 {
		t.Fatalf("old listener cookie = valid:%v attempted:%v scale:%d, want true/true/0", valid, attempted, options.localWindowScale)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := (&ListenConfig{Options: []SocketOption{SocketOptions.ReadBuffer(2 * 1024 * 1024)}}).ListenTCP(
		context.Background(), stack, "tcp4", netip.AddrPortFrom(local, 47006))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	replacementACK := issue(replacement.(*TCPListener), 0x22000001)
	if _, _, valid, attempted := state.validateSYNCookie(key, oldACK, time.Now(), replacement.(*TCPListener)); valid || !attempted {
		t.Fatalf("old cookie after listener replacement = valid:%v attempted:%v, want false/true", valid, attempted)
	}
	_, options, valid, attempted := state.validateSYNCookie(key, replacementACK, time.Now(), replacement.(*TCPListener))
	wantScale := tcpReceiveWindowScaleFor(2 * 1024 * 1024)
	if !valid || !attempted || options.localWindowScale != wantScale {
		t.Fatalf("replacement cookie = valid:%v attempted:%v scale:%d, want true/true/%d", valid, attempted, options.localWindowScale, wantScale)
	}
}

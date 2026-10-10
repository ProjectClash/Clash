package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
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
		zeroEchoConnectionTCP.peerECN || zeroEchoConnectionTCP.peerSACK || !zeroEchoConnectionTCP.peerWindowScaling ||
		zeroEchoConnectionTCP.peerWindowScale != 0 || zeroEchoConnectionTCP.receiveWindowScale != serverWindowScale {
		t.Fatalf("zero-TSecr cookie options = TS:%v/%d ECN:%v SACK:%v scale:%d/%d/%v", zeroEchoConnectionTCP.peerTimestamp,
			zeroEchoConnectionTCP.recentTimestamp, zeroEchoConnectionTCP.peerECN, zeroEchoConnectionTCP.peerSACK,
			zeroEchoConnectionTCP.peerWindowScale, zeroEchoConnectionTCP.receiveWindowScale, zeroEchoConnectionTCP.peerWindowScaling)
	}
	if zeroEchoConnectionTCP.peerWindow != 1234 {
		t.Fatalf("zero-TSecr peer window = %d, want 1234", zeroEchoConnectionTCP.peerWindow)
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
				cookieScaleSet: true, cookieScalePeriod: 0, cookieWindowScale: 4,
			}
			for index := range state.cookieKey {
				state.cookieKey[index] = byte(index + 1)
			}
			key := tcpKey{local: netip.AddrPortFrom(test.local, 443), remote: netip.AddrPortFrom(test.remote, 50000)}
			syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
			syn.setOptions([]byte{2, 4, 0x05, 0xb4, 4, 2})
			_, data := encodeSYNCookieOptions(syn, test.remote)
			cookie := synCookieSequence(state.cookieKey, key, syn.sequence, synCookiePeriodNumber(now, state.cookieEpoch), data, data)
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now); !valid {
				t.Fatal("valid SYN cookie was rejected")
			}
			forged := ack
			forged.acknowledgement ^= 1 << synCookieDataBits
			if _, _, valid, _ := state.validateSYNCookie(key, forged, now); valid {
				t.Fatal("forged SYN cookie was accepted")
			}
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now.Add(2*synCookiePeriod)); valid {
				t.Fatal("expired SYN cookie was accepted")
			}
			state.cookieActive = false
			if _, _, valid, _ := state.validateSYNCookie(key, ack, now); valid {
				t.Fatal("cookie ACK was accepted without recent cookie issuance")
			}
		})
	}
}

func TestSYNCookieAcceptsMissingTimestamp(t *testing.T) {
	now := time.Unix(2000002000, 0)
	state := &tcpPassiveState{
		cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
		cookieScaleSet: true, cookieScalePeriod: 0, cookieWindowScale: 4,
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
	cookie := synCookieSequence(state.cookieKey, key, syn.sequence, period, data, synCookieAuthenticatedData(data, true, true))
	ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
	_, options, valid, attempted := state.validateSYNCookie(key, ack, now)
	if !attempted || !valid {
		t.Fatalf("missing-timestamp cookie validation = valid:%v attempted:%v", valid, attempted)
	}
	if options.timestamp || options.ecn || options.timestampNow != 0 || options.sack || options.windowScaling ||
		options.windowScale != 0 || options.localWindowScale != 0 {
		t.Fatalf("missing-timestamp cookie options = timestamp:%v ecn:%v tsval:%d sack:%v scale:%d/%d/%v",
			options.timestamp, options.ecn, options.timestampNow, options.sack, options.windowScale,
			options.localWindowScale, options.windowScaling)
	}
}

func TestSYNCookieZeroTimestampEcho(t *testing.T) {
	now := time.Unix(2000003000, 0)
	for _, withECN := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-ECN", true: "with-ECN"}[withECN], func(t *testing.T) {
			state := &tcpPassiveState{
				cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
				cookieScaleSet: true, cookieScalePeriod: 0, cookieWindowScale: 4,
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
			cookie := synCookieSequence(state.cookieKey, key, syn.sequence, period, data,
				synCookieAuthenticatedData(data, cookieOptions.timestamp, cookieOptions.ecn))
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
			ack.setOptions(tcpTimestampOptions(701, 0))

			_, options, valid, attempted := state.validateSYNCookie(key, ack, now)
			if !attempted || !valid {
				t.Fatalf("zero-TSecr cookie validation = valid:%v attempted:%v", valid, attempted)
			}
			if !options.timestamp || options.timestampNow != 701 || options.ecn || options.sack ||
				!options.windowScaling || options.windowScale != 0 || options.localWindowScale != 4 {
				t.Fatalf("zero-TSecr cookie options = timestamp:%v/%d ecn:%v sack:%v scale:%d/%d/%v",
					options.timestamp, options.timestampNow, options.ecn, options.sack,
					options.windowScale, options.localWindowScale, options.windowScaling)
			}
		})
	}
}

func TestSYNCookieWithoutTimestampClearsRecoveredExtensions(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.73")
	remote := netip.MustParseAddr("198.51.100.73")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
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
		TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, 7})
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
	if !scaling || !sack || timestamp {
		t.Fatalf("no-timestamp SYN-cookie advertised scale:%v SACK:%v TS:%v; want SACK/window scaling without Timestamp", scaling, sack, timestamp)
	}
	ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: binary.BigEndian.Uint32(tcp[4:8]) + 1, flags: TCPFlagACK}
	_, options, valid, attempted := state.validateSYNCookie(key, ack, time.Now())
	if !attempted || !valid || options.windowScaling || options.sack || options.timestamp || options.mss != 1440 {
		t.Fatalf("no-timestamp SYN-cookie validation = attempted:%v valid:%v options:%+v", attempted, valid, options)
	}
}

func TestSYNCookieWindowScaleRotatesByPeriod(t *testing.T) {
	now := time.Unix(2000001000, 0)
	state := &tcpPassiveState{}
	secret, period, firstScale, err := state.synCookieKey(now, 2)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(period)
	if firstScale != 2 {
		t.Fatalf("first SYN-cookie scale = %d, want 2", firstScale)
	}
	_, samePeriod, stableScale, err := state.synCookieKey(now.Add(time.Second), 7)
	if err != nil {
		t.Fatal(err)
	}
	if samePeriod != period || stableScale != 2 {
		t.Fatalf("same-period SYN-cookie scale = period %d scale %d, want %d/2", samePeriod, stableScale, period)
	}

	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.70:443"),
		remote: netip.MustParseAddrPort("198.51.100.70:50000"),
	}
	clientSequence := uint32(100)
	data := uint32(0)
	cookie := synCookieSequence(secret, key, clientSequence, period, data, synCookieAuthenticatedData(data, true, false))
	ack := tcpSegment{sequence: clientSequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK}
	ack.setOptions(tcpTimestampOptions(100, 0))

	next := now.Add(synCookiePeriod)
	_, nextPeriod, nextScale, err := state.synCookieKey(next, 7)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(nextPeriod)
	if nextPeriod != period+1 || nextScale != 7 {
		t.Fatalf("next-period SYN-cookie scale = period %d scale %d, want %d/7", nextPeriod, nextScale, period+1)
	}
	_, options, valid, _ := state.validateSYNCookie(key, ack, next)
	if !valid || options.localWindowScale != 2 {
		t.Fatalf("previous-period cookie = valid %t scale %d, want true/2", valid, options.localWindowScale)
	}
}

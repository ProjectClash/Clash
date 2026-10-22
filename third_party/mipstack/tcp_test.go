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
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestPublicTCPSegmentCodecKnownAnswers(t *testing.T) {
	tests := []struct {
		name    string
		packet  string
		segment TCPSegment
	}{
		{
			name: "Linux IPv4 SYN",
			packet: "4500003c5053400040066665c0000201c0000202" +
				"b5fa01bbe3655ed100000000a002faf0e3b40000" +
				"020405b40402080ad7fe1368000000000103030a",
			segment: TCPSegment{
				Source: netip.MustParseAddrPort("192.0.2.1:46586"), Destination: netip.MustParseAddrPort("192.0.2.2:443"),
				SequenceNumber: 0xe3655ed1, Flags: TCPFlagSYN, WindowSize: 0xfaf0,
				Options: mustCodecVector(t, "020405b40402080ad7fe1368000000000103030a"),
			},
		},
		{
			name: "IPv6 odd payload",
			packet: "6ab543210025062520010db8000000000000000000000001" +
				"20010db8000000000000000000000002" +
				"5ba020fb01020304a0b0c0d080184567d9560000" +
				"0101080a11223344556677880102030405",
			segment: TCPSegment{
				Source: netip.MustParseAddrPort("[2001:db8::1]:23456"), Destination: netip.MustParseAddrPort("[2001:db8::2]:8443"),
				SequenceNumber: 0x01020304, AcknowledgmentNumber: 0xa0b0c0d0,
				Flags: TCPFlagACK | TCPFlagPSH, WindowSize: 0x4567,
				Options: mustCodecVector(t, "0101080a1122334455667788"), Payload: mustCodecVector(t, "0102030405"),
			},
		},
		{
			name: "IPv4 SACK",
			packet: "45000048999940004006b4dfc6336402c0000201" +
				"01bbb5fa1111111122222222d0101000562e0000" +
				"0101080a01020304050607080101051200001000000020000000300000004000",
			segment: TCPSegment{
				Source: netip.MustParseAddrPort("198.51.100.2:443"), Destination: netip.MustParseAddrPort("192.0.2.1:46586"),
				SequenceNumber: 0x11111111, AcknowledgmentNumber: 0x22222222,
				Flags: TCPFlagACK, WindowSize: 0x1000,
				Options: mustCodecVector(t, "0101080a01020304050607080101051200001000000020000000300000004000"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := ParseIPPacket(mustCodecVector(t, test.packet))
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil {
				t.Fatalf("TCPSegment: %v", err)
			}
			if !equalTCPSegments(segment, test.segment) {
				t.Fatalf("parsed segment = %+v, want %+v", segment, test.segment)
			}
			encoded, err := test.segment.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, packet.Payload) {
				t.Fatalf("MarshalBinary: error=%v\n got %x\nwant %x", err, encoded, packet.Payload)
			}
			assertTCPSegmentWire(t, test.segment, encoded)
		})
	}

	linuxPacket, err := ParseIPPacket(mustCodecVector(t, tests[0].packet))
	if err != nil {
		t.Fatal(err)
	}
	linuxSYN, err := linuxPacket.TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	options, err := linuxSYN.HeaderOptions()
	if err != nil || len(options) != 5 {
		t.Fatalf("Linux SYN options = %+v, %v", options, err)
	}
	if mss, ok := options[0].MaximumSegmentSize(); !ok || mss != 1460 || !options[1].IsSACKPermitted() {
		t.Fatalf("Linux SYN MSS/SACK = %d/%t, SACK=%t", mss, ok, options[1].IsSACKPermitted())
	}
	if value, echo, ok := options[2].Timestamp(); !ok || value != 0xd7fe1368 || echo != 0 {
		t.Fatalf("Linux SYN Timestamp = %#x/%#x/%t", value, echo, ok)
	}
	if scale, ok := options[4].WindowScale(); !ok || scale != 10 || options[3].Kind != TCPHeaderOptionNOP {
		t.Fatalf("Linux SYN NOP/Window Scale = %d/%t, NOP=%d", scale, ok, options[3].Kind)
	}

	sackPacket, err := ParseIPPacket(mustCodecVector(t, tests[2].packet))
	if err != nil {
		t.Fatal(err)
	}
	sackSegment, err := sackPacket.TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	sackOptions, err := sackSegment.HeaderOptions()
	if err != nil || len(sackOptions) != 6 {
		t.Fatalf("SACK options = %+v, %v", sackOptions, err)
	}
	blocks, ok := sackOptions[5].SACKBlocks()
	wantBlocks := []TCPSACKBlock{{LeftEdge: 0x1000, RightEdge: 0x2000}, {LeftEdge: 0x3000, RightEdge: 0x4000}}
	if !ok || !reflect.DeepEqual(blocks, wantBlocks) {
		t.Fatalf("SACK blocks = %+v/%t, want %+v", blocks, ok, wantBlocks)
	}
}

func TestPublicTCPSegmentCodecKnownAnswerMutations(t *testing.T) {
	base := mustCodecVector(t, "4500003c5053400040066665c0000201c0000202"+
		"b5fa01bbe3655ed100000000a002faf0e3b40000020405b40402080ad7fe1368000000000103030a")
	tests := []struct {
		name   string
		mutate func(IPPacket, []byte)
	}{
		{name: "checksum", mutate: func(_ IPPacket, payload []byte) { payload[16] ^= 1 }},
		{name: "short data offset", mutate: func(packet IPPacket, payload []byte) {
			payload[12] = payload[12]&0x0f | 4<<4
			repairReferenceTransportChecksum(packet.Source, packet.Destination, ProtocolTCP, payload, 16)
		}},
		{name: "malformed option length", mutate: func(packet IPPacket, payload []byte) {
			payload[21] = 1
			repairReferenceTransportChecksum(packet.Source, packet.Destination, ProtocolTCP, payload, 16)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := ParseIPPacket(base)
			if err != nil {
				t.Fatal(err)
			}
			payload := append([]byte(nil), packet.Payload...)
			packet.Payload = payload
			test.mutate(packet, payload)
			before := append([]byte(nil), payload...)
			if _, err = packet.TCPSegment(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("TCPSegment error = %v, want EINVAL", err)
			}
			if !bytes.Equal(payload, before) {
				t.Fatal("failed TCP parse modified its input")
			}
		})
	}
}

func FuzzPublicTCPSegmentWireEncoding(f *testing.F) {
	f.Add(false, uint16(12345), uint16(443), uint32(1), uint32(0), uint16(TCPFlagSYN),
		uint16(65535), uint16(0), byte(1), []byte(nil))
	f.Add(true, uint16(8443), uint16(49152), uint32(0xffffffff), uint32(7), uint16(TCPFlagACK|TCPFlagPSH),
		uint16(4096), uint16(0), byte(2), []byte("odd"))
	f.Fuzz(func(t *testing.T, ipv6 bool, sourcePort, destinationPort uint16, sequence, acknowledgement uint32,
		flags, window, urgent uint16, optionForm byte, payload []byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		flags &= TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagPSH | TCPFlagACK | TCPFlagURG | TCPFlagECE | TCPFlagCWR | TCPFlagNS
		segment := TCPSegment{
			Source:         netip.AddrPortFrom(netip.MustParseAddr("192.0.2.102"), sourcePort),
			Destination:    netip.AddrPortFrom(netip.MustParseAddr("198.51.100.102"), destinationPort),
			SequenceNumber: sequence, AcknowledgmentNumber: acknowledgement,
			Flags: flags, WindowSize: window, UrgentPointer: urgent, Payload: payload,
		}
		switch optionForm % 5 {
		case 1:
			segment.Options = []byte{TCPHeaderOptionMSS, 4, byte(window >> 8), byte(window)}
		case 2:
			segment.Options = []byte{TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10,
				byte(sequence >> 24), byte(sequence >> 16), byte(sequence >> 8), byte(sequence),
				byte(acknowledgement >> 24), byte(acknowledgement >> 16), byte(acknowledgement >> 8), byte(acknowledgement)}
		case 3:
			segment.Options = []byte{TCPHeaderOptionEnd, 0xaa, 0xbb, 0xcc}
		case 4:
			segment.Options = []byte{TCPHeaderOptionSACK, 10,
				byte(sequence >> 24), byte(sequence >> 16), byte(sequence >> 8), byte(sequence),
				byte(acknowledgement >> 24), byte(acknowledgement >> 16), byte(acknowledgement >> 8), byte(acknowledgement)}
		}
		if ipv6 {
			segment.Source = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::102"), sourcePort)
			segment.Destination = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::102"), destinationPort)
		}
		wire, err := segment.AppendBinary(nil)
		if err != nil {
			t.Fatalf("AppendBinary: %v", err)
		}
		assertTCPSegmentWire(t, segment, wire)
		packet := IPPacket{Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: wire}
		if _, err = packet.TCPSegment(); err != nil {
			t.Fatalf("TCPSegment(encoded segment): %v", err)
		}
	})
}

func equalTCPSegments(left, right TCPSegment) bool {
	return left.Source == right.Source && left.Destination == right.Destination &&
		left.SequenceNumber == right.SequenceNumber && left.AcknowledgmentNumber == right.AcknowledgmentNumber &&
		left.Flags == right.Flags && left.WindowSize == right.WindowSize && left.UrgentPointer == right.UrgentPointer &&
		bytes.Equal(left.Options, right.Options) && bytes.Equal(left.Payload, right.Payload)
}

func assertTCPSegmentWire(t testing.TB, segment TCPSegment, wire []byte) {
	t.Helper()
	headerSize := tcpHeaderSize + (len(segment.Options)+3)&^3
	if len(wire) != headerSize+len(segment.Payload) || wire[12]>>4 != byte(headerSize/4) || wire[12]&0x0e != 0 {
		t.Fatalf("TCP wire length/data offset/reserved bits = %d/%d/%#x", len(wire), wire[12]>>4, wire[12]&0x0e)
	}
	if binary.BigEndian.Uint16(wire[0:2]) != segment.Source.Port() ||
		binary.BigEndian.Uint16(wire[2:4]) != segment.Destination.Port() ||
		binary.BigEndian.Uint32(wire[4:8]) != segment.SequenceNumber ||
		binary.BigEndian.Uint32(wire[8:12]) != segment.AcknowledgmentNumber ||
		uint16(wire[13])|uint16(wire[12]&1)<<8 != segment.Flags ||
		binary.BigEndian.Uint16(wire[14:16]) != segment.WindowSize ||
		binary.BigEndian.Uint16(wire[18:20]) != segment.UrgentPointer {
		t.Fatalf("TCP fixed fields do not match semantic value: %x", wire[:tcpHeaderSize])
	}
	contentSize := len(segment.Options)
	for offset := 0; offset < len(segment.Options); {
		kind := segment.Options[offset]
		if kind == TCPHeaderOptionEnd {
			contentSize = offset + 1
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
		} else {
			offset += int(segment.Options[offset+1])
		}
	}
	if !bytes.Equal(wire[tcpHeaderSize:tcpHeaderSize+contentSize], segment.Options[:contentSize]) {
		t.Fatalf("TCP options = %x, want prefix %x", wire[tcpHeaderSize:headerSize], segment.Options[:contentSize])
	}
	for _, value := range wire[tcpHeaderSize+contentSize : headerSize] {
		if value != 0 {
			t.Fatalf("TCP option padding is nonzero: %x", wire[tcpHeaderSize:headerSize])
		}
	}
	if !bytes.Equal(wire[headerSize:], segment.Payload) {
		t.Fatalf("TCP payload = %x, want %x", wire[headerSize:], segment.Payload)
	}
	if got := referenceTransportChecksum(segment.Source.Addr(), segment.Destination.Addr(), ProtocolTCP, wire); got != 0 {
		t.Fatalf("TCP reference checksum = %#x, want zero", got)
	}
}

func TestTCPListenerAcceptAndClose(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.1")
	serverAddress := netip.MustParseAddr("192.0.2.2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	serverEndpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	clientConnection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, serverEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	listenerInfo := listener.(*TCPListener).Info()
	if listenerInfo.LocalAddress != serverEndpoint || listenerInfo.Closed || listenerInfo.AcceptQueueConnections != 0 ||
		listenerInfo.SYNBacklogConnections != 0 || listenerInfo.AcceptQueueCapacity == 0 || listenerInfo.SYNBacklogCapacity == 0 ||
		listenerInfo.AcceptQueuePeak > 1 || listenerInfo.SYNBacklogPeak != 1 || listenerInfo.SYNsReceived != 1 ||
		listenerInfo.StatefulHandshakes != 1 || listenerInfo.HandshakeCompletions != 1 || listenerInfo.AcceptedConnections != 1 {
		t.Fatalf("listener diagnostics after Accept = %+v", listenerInfo)
	}
	_ = clientConnection.SetDeadline(time.Now().Add(2 * time.Second))
	_ = serverConnection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = clientConnection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	if _, err = io.ReadFull(serverConnection, buffer[:7]); err != nil || string(buffer[:7]) != "request" {
		t.Fatalf("server Read = %q, %v", buffer[:7], err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if closedInfo := listener.(*TCPListener).Info(); !closedInfo.Closed || closedInfo.AcceptedConnections != 1 ||
		closedInfo.AcceptQueueCapacity != listenerInfo.AcceptQueueCapacity || closedInfo.SYNBacklogCapacity != listenerInfo.SYNBacklogCapacity {
		t.Fatalf("closed listener diagnostics = %+v", closedInfo)
	}
	if _, err = serverConnection.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(clientConnection, buffer); err != nil || string(buffer) != "response" {
		t.Fatalf("client Read = %q, %v", buffer, err)
	}
	if err = listener.Close(); err == nil {
		t.Fatal("second listener Close succeeded")
	} else {
		checkNetOpError(t, err, "close", "tcp")
	}

	deadlineListener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer deadlineListener.Close()
	if err = deadlineListener.(*TCPListener).SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = deadlineListener.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept error = %v, want deadline", err)
	} else {
		checkNetOpError(t, err, "accept", "tcp")
	}
}

func TestTCPDestinationPortZeroUsesProtocolPath(t *testing.T) {
	for _, test := range []struct {
		name           string
		network        string
		client, server netip.Addr
	}{
		{name: "IPv4", network: "tcp4", client: netip.MustParseAddr("192.0.2.232"), server: netip.MustParseAddr("192.0.2.233")},
		{name: "IPv6", network: "tcp6", client: netip.MustParseAddr("2001:db8::232"), server: netip.MustParseAddr("2001:db8::233")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.client, test.server, 1400)
			newStackBridge(t, client, server)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := client.DialTCP(ctx, test.network, netip.AddrPort{}, netip.AddrPortFrom(test.server, 0)); !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("DialTCP to port zero = %v, want ECONNREFUSED", err)
			}
		})
	}
}

func TestTCPListenerCloseReleasesPendingOwnership(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.251/32")}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.251:443"),
		remote: netip.MustParseAddrPort("198.51.100.251:50000"),
	}, 1400, tcpSocketOptionSet{})

	listener := &TCPListener{
		stack: stack, net: "tcp4", local: netip.MustParseAddrPort("192.0.2.251:443"), accept: make(chan *TCPConn, 1024), closed: make(chan struct{}),
		pending: map[*TCPConn]struct{}{connection: {}}, handshaking: map[*TCPConn]struct{}{connection: {}},
	}
	if err = listener.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	listener.accept <- connection
	listener.closeFromStack()
	listener.mu.Lock()
	released := listener.accept == nil && listener.pending == nil && listener.handshaking == nil && listener.deadline.timer == nil
	listener.mu.Unlock()
	if !released {
		t.Fatal("closed listener retained accept or pending connection storage")
	}
	select {
	case <-connection.abortCh:
	default:
		t.Fatal("closed listener did not abort its pending connection")
	}
}

func TestTCPListenerAcceptCloseConcurrent(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		listener := &TCPListener{
			net: "tcp4", local: netip.MustParseAddrPort("192.0.2.251:443"),
			accept: make(chan *TCPConn), closed: make(chan struct{}),
			pending: make(map[*TCPConn]struct{}), handshaking: make(map[*TCPConn]struct{}),
		}
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			_, err := listener.Accept()
			result <- err
		}()
		<-started
		runtime.Gosched()
		listener.closeFromStack()
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept after concurrent Close = %v, want net.ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Accept did not return after concurrent Close")
		}
	}
}

func TestTCPListenerAcceptUnblocksOnPublicClose(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.251/32")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.MustParseAddrPort("192.0.2.251:443"))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("Accept returned before Close: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

func TestStackCloseEventuallyReleasesTCPBuffers(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.252:40000")
	remote := netip.MustParseAddrPort("198.51.100.252:443")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local.Addr(), 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	connection := newTCPConn(stack, "tcp4", tcpKey{local: local, remote: remote}, 1400, tcpSocketOptionSet{})
	payload := make([]byte, 1<<20)
	connection.mu.Lock()
	connection.readBuffer.append(payload)
	connection.sendBuffer.append(payload)
	connection.mu.Unlock()
	if err = connection.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(errors.New("retained network error"))
	stack.tcp[connection.key] = connection
	stack.stats.activeTCPConnections.Add(1)
	go connection.run(1, make(chan error, 1))
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("TCP actor did not terminate after Stack.Close")
	}
	connection.mu.Lock()
	released := connection.readBuffer.size == 0 && connection.readBuffer.chunks == nil &&
		connection.sendBuffer.size == 0 && connection.sendBuffer.chunks == nil && connection.sendBuffer.spare == nil &&
		connection.pending == nil && connection.readDeadline.timer == nil && connection.writeDeadline.timer == nil
	connection.mu.Unlock()
	if !released || connection.inbound.retainedBytes() != 0 {
		t.Fatal("terminated TCP connection retained payload-bearing buffers")
	}
}

func TestTCPListenerCompletedConnectionsLeaveSYNBacklog(t *testing.T) {
	listener := &TCPListener{
		accept: make(chan *TCPConn, 2), closed: make(chan struct{}), backlog: 1,
		pending: make(map[*TCPConn]struct{}), handshaking: make(map[*TCPConn]struct{}),
	}
	first, second := &TCPConn{}, &TCPConn{}
	if !listener.trackHandshake(first) || !listener.enqueue(first) {
		t.Fatal("first handshake did not enter the accept queue")
	}
	info := listener.Info()
	if info.SYNBacklogConnections != 0 || info.AcceptQueueConnections != 1 {
		t.Fatalf("completed handshake queue accounting = %+v", info)
	}
	if !listener.trackHandshake(second) {
		t.Fatal("completed connection continued to consume the SYN backlog")
	}
}

func TestTCPStateString(t *testing.T) {
	tests := []struct {
		state TCPState
		name  string
	}{
		{TCPStateClosed, "CLOSED"},
		{TCPStateSYNReceived, "SYN-RECEIVED"},
		{TCPStateSYNSent, "SYN-SENT"},
		{TCPStateEstablished, "ESTABLISHED"},
		{TCPStateFINWait1, "FIN-WAIT-1"},
		{TCPStateFINWait2, "FIN-WAIT-2"},
		{TCPStateCloseWait, "CLOSE-WAIT"},
		{TCPStateClosing, "CLOSING"},
		{TCPStateLastACK, "LAST-ACK"},
		{TCPStateTimeWait, "TIME-WAIT"},
		{TCPState(255), "CLOSED"},
	}
	for _, test := range tests {
		if name := test.state.String(); name != test.name {
			t.Errorf("TCPState(%d).String() = %q, want %q", test.state, name, test.name)
		}
	}
}

func TestTCPConnectionInfo(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(serverAddress, 45200))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 45200))
	if err != nil {
		t.Fatal(err)
	}
	clientConnection := connection.(*TCPConn)
	serverConnection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()

	payload := []byte("connection diagnostics")
	if _, err = clientConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(serverConnection, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return clientConnection.Info().BytesAcknowledged >= uint64(len(payload)) })
	info := clientConnection.Info()
	if info.State != TCPStateEstablished || info.State.String() != "ESTABLISHED" || info.LocalAddress.Addr() != clientAddress || info.RemoteAddress.Addr() != serverAddress {
		t.Fatalf("connection identity/state = %+v", info)
	}
	if info.CongestionControl != CongestionControlCUBIC || info.RTT <= 0 || info.RetransmissionTimeout <= 0 ||
		info.CongestionWindow == 0 || info.MaximumSegmentSize <= 0 || info.PathMTU != 1400 ||
		!info.WindowScaling || info.ReceiveWindowScale == 0 || !info.SACK || !info.Timestamps || !info.NoDelay ||
		info.KeepAliveConfig.Idle <= 0 || info.KeepAliveConfig.Interval <= 0 || info.KeepAliveConfig.Count <= 0 ||
		info.BytesSent < uint64(len(payload)) {
		t.Fatalf("incomplete live TCP diagnostics: %+v", info)
	}
	const concurrentInfoCalls = 64
	infos := make(chan TCPConnInfo, concurrentInfoCalls)
	for index := 0; index < concurrentInfoCalls; index++ {
		go func() { infos <- clientConnection.Info() }()
	}
	for index := 0; index < concurrentInfoCalls; index++ {
		select {
		case concurrent := <-infos:
			if concurrent.State != TCPStateEstablished || concurrent.LocalAddress != info.LocalAddress || concurrent.RemoteAddress != info.RemoteAddress {
				t.Fatalf("concurrent TCP diagnostics = %+v", concurrent)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent TCP diagnostics blocked")
		}
	}
	if err = clientConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = clientConnection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clientConnection.done:
	case <-time.After(time.Second):
		t.Fatal("abortive close did not terminate TCP actor")
	}
	closed := clientConnection.Info()
	if closed.State != TCPStateClosed || closed.LastError == nil || closed.BytesAcknowledged < uint64(len(payload)) {
		t.Fatalf("final TCP diagnostics = %+v", closed)
	}
}

func TestTCPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::194")
	remote := netip.MustParseAddr("2001:db8::195")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	key := tcpKey{local: netip.AddrPortFrom(local, 40000), remote: netip.AddrPortFrom(remote, 443)}
	connection := newTCPConn(stack, "tcp6", key, 1500, tcpSocketOptionSet{})
	if connection.flowLabel == 0 {
		t.Fatal("automatic TCP flow label is zero")
	}
	if second := newTCPConn(stack, "tcp6", key, 1500, tcpSocketOptionSet{}); second.flowLabel != connection.flowLabel {
		t.Fatalf("automatic TCP flow labels = %#x and %#x", connection.flowLabel, second.flowLabel)
	}
	explicit, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)},
		TCP:            TCPSocketDefaults{FlowLabel: 0x45678},
	})
	if err != nil {
		t.Fatal(err)
	}
	if label := newTCPConn(explicit, "tcp6", key, 1500, tcpSocketOptionSet{}).flowLabel; label != 0x45678 {
		t.Fatalf("configured TCP flow label = %#x, want 0x45678", label)
	}
}

func TestTCPUserTimeoutClosesUnacknowledgedConnection(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.132"), netip.MustParseAddr("192.0.2.133"))
	link.echoTCP = true
	link.dropTCPData = 100
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.133:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(75 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetUserTimeout(-time.Second); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("negative SetUserTimeout = %v, want EINVAL", err)
	}
	if _, err = tcp.Write([]byte("unacknowledged")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("TCP user timeout did not terminate the connection")
	}
	info := tcp.Info()
	if info.UserTimeout != 75*time.Millisecond || !errors.Is(info.LastError, syscall.ETIMEDOUT) {
		t.Fatalf("TCP user-timeout info = %+v", info)
	}
}

func TestTCPUserTimeoutClosesZeroWindowConnection(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.136"), netip.MustParseAddr("192.0.2.137"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.137:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(75 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.useTCPWindow = true
	link.advertisedTCPWindow = 0
	link.mu.Unlock()
	if _, err = tcp.Write([]byte("close the window")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcp.Info().PeerWindow == 0 })
	if _, err = tcp.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatalf("TCP user timeout did not terminate a zero-window connection: %+v", tcp.Info())
	}
	if !errors.Is(tcp.Info().LastError, syscall.ETIMEDOUT) {
		t.Fatalf("zero-window user timeout = %+v", tcp.Info())
	}
}

func TestTCPUserTimeoutPreservesPersistHistory(t *testing.T) {
	const timeout = time.Second
	for _, mode := range []string{"enable after blocking", "disable and enable", "reopen and block again"} {
		t.Run(mode, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.136"), netip.MustParseAddr("192.0.2.137"))
			link.mu.Lock()
			link.echoTCP, link.useTCPWindow = true, true
			link.advertisedTCPWindow = 0
			link.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connection, err := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.137:443"))
			if err != nil {
				t.Fatal(err)
			}
			c := connection.(*TCPConn)
			defer c.Close()
			if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			initial := []byte("close the window")
			if n, err := c.Write(initial); err != nil || n != len(initial) {
				t.Fatalf("initial Write = %d, %v", n, err)
			}
			received := make([]byte, len(initial))
			if _, err := io.ReadFull(c, received); err != nil || !bytes.Equal(received, initial) {
				t.Fatalf("initial echo = %q, %v", received, err)
			}
			waitFor(t, time.Second, func() bool {
				info := c.Info()
				return info.PeerWindow == 0 && info.BytesAcknowledged == uint64(len(initial)) && info.BytesInFlight == 0
			})
			if mode == "disable and enable" {
				if err = c.SetUserTimeout(10 * timeout); err != nil {
					t.Fatal(err)
				}
			}
			blocked := []byte("blocked")
			if n, err := c.Write(blocked); err != nil || n != len(blocked) {
				t.Fatalf("blocked Write = %d, %v", n, err)
			}
			if info := c.Info(); info.PeerWindow != 0 || info.BytesSent != uint64(len(initial)) || info.BytesInFlight != 0 {
				t.Fatalf("connection did not enter pure persist: %+v", info)
			}
			if mode == "disable and enable" {
				if err = c.SetUserTimeout(0); err != nil {
					t.Fatal(err)
				}
				if info := c.Info(); info.UserTimeout != 0 {
					t.Fatalf("user timeout was not disabled: %+v", info)
				}
			}
			select {
			case <-c.done:
				t.Fatalf("persist terminated with user timeout disabled: %+v", c.Info())
			case <-time.After(timeout + timeout/2):
			}

			var restartedAt time.Time
			if mode == "reopen and block again" {
				port := uint16(c.LocalAddr().(*net.TCPAddr).Port)
				link.mu.Lock()
				peer := link.tcp[port]
				sequence, acknowledgement := peer.serverNext, peer.clientNext
				link.advertisedTCPWindow = 65535
				link.mu.Unlock()
				if err = link.deliverTCP(443, port, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				received = make([]byte, len(blocked))
				if _, err := io.ReadFull(c, received); err != nil || !bytes.Equal(received, blocked) {
					t.Fatalf("echo after reopening = %q, %v", received, err)
				}
				waitFor(t, time.Second, func() bool {
					info := c.Info()
					return info.PeerWindow != 0 && info.BytesAcknowledged == uint64(len(initial)+len(blocked)) && info.BytesInFlight == 0
				})
				link.mu.Lock()
				sequence, acknowledgement = peer.serverNext, peer.clientNext
				link.advertisedTCPWindow = 0
				link.mu.Unlock()
				if err = link.deliverTCP(443, port, sequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
					t.Fatal(err)
				}
				waitFor(t, time.Second, func() bool { return c.Info().PeerWindow == 0 })
				restartedAt = time.Now()
				if n, err := c.Write(blocked); err != nil || n != len(blocked) {
					t.Fatalf("Write in the new persist episode = %d, %v", n, err)
				}
				if info := c.Info(); info.BytesSent != uint64(len(initial)+len(blocked)) || info.BytesInFlight != 0 {
					t.Fatalf("new persist episode transmitted data: %+v", info)
				}
			}
			if err = c.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err = c.SetUserTimeout(timeout); err != nil {
				t.Fatal(err)
			}
			_ = c.Info()
			wait := timeout / 2
			if !restartedAt.IsZero() {
				wait = 3 * timeout
			}
			select {
			case <-c.done:
			case <-time.After(wait):
				t.Fatalf("user timeout did not apply to the persist episode: %+v", c.Info())
			}
			if !restartedAt.IsZero() && time.Since(restartedAt) < timeout*3/4 {
				t.Fatalf("new persist episode reused the previous timeout age: %+v", c.Info())
			}
			if info := c.Info(); !errors.Is(info.LastError, syscall.ETIMEDOUT) {
				t.Fatalf("persist user timeout = %+v", info)
			}
		})
	}
}

func TestTCPUserTimeoutDisarmsAfterAcknowledgement(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.138"), netip.MustParseAddr("192.0.2.139"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.139:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("acknowledge")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := io.ReadFull(tcp, buffer[:11]); readErr != nil || string(buffer[:n]) != "acknowledge" {
		t.Fatalf("acknowledged echo = %q, %v", buffer[:n], readErr)
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case <-tcp.done:
		t.Fatalf("acknowledged connection hit user timeout: %+v", tcp.Info())
	default:
	}
	_ = tcp.Close()
}

func TestTCPUserTimeoutOverridesKeepAliveCount(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.140"), netip.MustParseAddr("192.0.2.141"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.141:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetKeepAliveConfig(KeepAliveConfig{Idle: 20 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 1}); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetUserTimeout(150 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetKeepAlive(true); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	started := time.Now()
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("keepalive user timeout did not terminate the connection")
	}
	elapsed := time.Since(started)
	if elapsed < 100*time.Millisecond || !errors.Is(tcp.Info().LastError, syscall.ETIMEDOUT) {
		t.Fatalf("keepalive user timeout after %v: %+v", elapsed, tcp.Info())
	}
}

func TestTCPKeepAliveSocketOptionsPreserveProbeHistory(t *testing.T) {
	config := KeepAliveConfig{Idle: 30 * time.Millisecond, Interval: 500 * time.Millisecond, Count: 1}
	for _, test := range []struct {
		name   string
		update func(*TCPConn) error
	}{
		{name: "no delay", update: func(c *TCPConn) error { return c.SetNoDelay(false) }},
		{name: "idle timeout", update: func(c *TCPConn) error { return c.SetIdleTimeout(10 * time.Second) }},
		{name: "disabled user timeout", update: func(c *TCPConn) error { return c.SetUserTimeout(0) }},
		{name: "enabled user timeout", update: func(c *TCPConn) error { return c.SetUserTimeout(75 * time.Millisecond) }},
		{name: "pacing", update: func(c *TCPConn) error { return c.SetMaximumPacingRate(1024 * 1024) }},
		{name: "congestion control", update: func(c *TCPConn) error { return c.SetCongestionControl(CongestionControlCUBIC) }},
		{name: "keepalive configuration", update: func(c *TCPConn) error { return c.SetKeepAliveConfig(config) }},
		{name: "disable and enable", update: func(c *TCPConn) error {
			if err := c.SetKeepAlive(false); err != nil {
				return err
			}
			if c.Info().KeepAlive {
				return errors.New("keepalive was not disabled")
			}
			return c.SetKeepAlive(true)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack, c := newManuallyPumpedTCPConnection(t)
			defer c.Close()
			if err := c.SetKeepAliveConfig(config); err != nil {
				t.Fatal(err)
			}
			enabledAt := time.Now()
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, 2*time.Second)
			if !available {
				t.Fatal("keepalive probe was not published")
			}
			packet, valid := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
			if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || packet.payload[13] != TCPFlagACK ||
				int(packet.payload[12]>>4)*4 != len(packet.payload) {
				t.Fatalf("first output was not a keepalive probe: %+v", packet)
			}
			port := uint16(c.LocalAddr().(*net.TCPAddr).Port)
			link.mu.Lock()
			peer := link.tcp[port]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			if binary.BigEndian.Uint32(packet.payload[4:8]) != acknowledgement-1 || binary.BigEndian.Uint32(packet.payload[8:12]) != sequence {
				t.Fatalf("keepalive probe did not use SND.NXT-1: %+v", packet)
			}
			if info := c.Info(); info.State != TCPStateEstablished || info.LastError != nil || stack.Stats().TCPKeepAliveProbes != 1 {
				t.Fatalf("keepalive probe history was not published: info=%+v stats=%+v", info, stack.Stats())
			}
			if err := test.update(c); err != nil {
				t.Fatal(err)
			}
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Fatal("socket-option update prevented keepalive termination")
			}
			if elapsed := time.Since(enabledAt); test.name != "disable and enable" && elapsed < config.Interval*3/4 {
				t.Fatalf("socket-option update closed the connection after %v, before the probe interval", elapsed)
			}
			if probes := stack.Stats().TCPKeepAliveProbes; probes != 1 || !errors.Is(c.Info().LastError, syscall.ETIMEDOUT) {
				t.Fatalf("keepalive after option update = %d probes, %+v", probes, c.Info())
			}
		})
	}
}

func TestTCPKeepAliveReenableRestartsIdleTimer(t *testing.T) {
	config := KeepAliveConfig{Idle: 200 * time.Millisecond, Interval: time.Second, Count: 1}
	for _, afterInterval := range []bool{false, true} {
		for _, userTimeout := range []time.Duration{0, 75 * time.Millisecond} {
			t.Run(fmt.Sprintf("after-interval-%v/user-timeout-%v", afterInterval, userTimeout), func(t *testing.T) {
				_, stack, c := newManuallyPumpedTCPConnection(t)
				defer c.Close()
				if err := c.SetKeepAliveConfig(config); err != nil {
					t.Fatal(err)
				}
				if err := c.SetUserTimeout(userTimeout); err != nil {
					t.Fatal(err)
				}
				if err := c.SetKeepAlive(true); err != nil {
					t.Fatal(err)
				}
				entry, available := waitTestPacketEntry(&stack.outbound, 2*time.Second)
				if !available {
					t.Fatal("keepalive probe was not published")
				}
				consumeTestPacket(&stack.outbound, entry)
				if err := c.SetKeepAlive(false); err != nil {
					t.Fatal(err)
				}
				if info := c.Info(); info.KeepAlive || info.State != TCPStateEstablished || stack.Stats().TCPKeepAliveProbes != 1 {
					t.Fatalf("keepalive was not disabled after one probe: info=%+v stats=%+v", info, stack.Stats())
				}
				if afterInterval {
					select {
					case <-c.done:
						t.Fatalf("disabled keepalive terminated the connection: %+v", c.Info())
					case <-time.After(config.Interval + config.Interval/4):
					}
				}
				reenabledAt := time.Now()
				if err := c.SetKeepAlive(true); err != nil {
					t.Fatal(err)
				}
				select {
				case <-c.done:
				case <-time.After(3 * config.Idle):
					t.Fatalf("reenabling keepalive retained the old probe deadline: %+v", c.Info())
				}
				if elapsed := time.Since(reenabledAt); elapsed < config.Idle*3/4 {
					t.Fatalf("reenabling keepalive closed the connection after %v, before Idle", elapsed)
				}
				if probes := stack.Stats().TCPKeepAliveProbes; probes != 1 || !errors.Is(c.Info().LastError, syscall.ETIMEDOUT) {
					t.Fatalf("reenabling keepalive lost probe history: probes=%d info=%+v", probes, c.Info())
				}
			})
		}
	}
}

func TestTCPKeepAliveReenableWithPendingTimer(t *testing.T) {
	config := KeepAliveConfig{Idle: 150 * time.Millisecond, Interval: 500 * time.Millisecond, Count: 1}
	for _, policy := range []string{"probe count", "user timeout", "idle timeout"} {
		t.Run(policy, func(t *testing.T) {
			_, stack, c := newManuallyPumpedTCPConnection(t)
			defer c.Close()
			if err := c.SetKeepAliveConfig(config); err != nil {
				t.Fatal(err)
			}
			if policy == "user timeout" {
				if err := c.SetUserTimeout(50 * time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, 2*time.Second)
			if !available {
				t.Fatal("initial keepalive probe was not published")
			}
			consumeTestPacket(&stack.outbound, entry)
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })

			entered, resume := make(chan struct{}), make(chan struct{})
			var resumed sync.Once
			defer resumed.Do(func() { close(resume) })
			factory, err := NewCongestionControlFactory(CongestionControlDefinition{
				Name: "keepalive-timer-order-test",
				New: func(CongestionControlContext) CongestionController {
					close(entered)
					<-resume
					return newRenoCongestionControl()
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.SetCongestionControlFactory(factory); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("actor did not enter the controller factory")
			}
			if policy == "idle timeout" {
				if err := c.SetIdleTimeout(config.Interval / 2); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(config.Interval + config.Interval/4)
			if err := c.SetKeepAlive(false); err != nil {
				t.Fatal(err)
			}
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			select {
			case <-c.inbound.notify:
			case <-time.After(time.Second):
				t.Fatal("keepalive option notification was not queued")
			}
			resumed.Do(func() { close(resume) })
			if policy == "idle timeout" {
				select {
				case <-c.done:
				case <-time.After(time.Second):
					t.Fatal("keepalive enable postponed the independent idle timeout")
				}
				if !errors.Is(c.Info().LastError, os.ErrDeadlineExceeded) {
					t.Fatalf("idle timeout = %+v", c.Info())
				}
				return
			}
			select {
			case <-c.done:
				t.Fatalf("old keepalive timer closed the reenabled connection: %+v", c.Info())
			case <-time.After(config.Idle / 2):
			}
			if probes := stack.Stats().TCPKeepAliveProbes; probes != 1 {
				t.Fatalf("old timer published another probe: %d", probes)
			}
			restoredAt := time.Now()
			select {
			case c.inbound.notify <- struct{}{}:
			default:
			}
			select {
			case <-c.done:
			case <-time.After(3 * config.Idle):
				t.Fatal("reenabled keepalive did not apply its retained timeout policy")
			}
			if time.Since(restoredAt) < config.Idle*3/4 || stack.Stats().TCPKeepAliveProbes != 1 || !errors.Is(c.Info().LastError, syscall.ETIMEDOUT) {
				t.Fatalf("reenabled keepalive lost its idle delay or probe history: %+v", c.Info())
			}
		})
	}
}

func TestTCPKeepAliveReenableWithReturnedCapacity(t *testing.T) {
	config := KeepAliveConfig{Idle: 200 * time.Millisecond, Interval: 100 * time.Millisecond, Count: 2}
	for _, userTimeout := range []time.Duration{0, 3 * time.Second} {
		t.Run(userTimeout.String(), func(t *testing.T) {
			_, stack, c := newManuallyPumpedTCPConnection(t)
			defer c.Close()
			if err := c.SetKeepAliveConfig(config); err != nil {
				t.Fatal(err)
			}
			if err := c.SetUserTimeout(userTimeout); err != nil {
				t.Fatal(err)
			}
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, 2*time.Second)
			if !available {
				t.Fatal("initial keepalive probe was not published")
			}
			consumeTestPacket(&stack.outbound, entry)
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })
			var held []uint16
			defer func() {
				for _, slot := range held {
					stack.outbound.releaseReserved(slot)
				}
			}()
			for slot, ok := stack.outbound.tryReserve(); ok; slot, ok = stack.outbound.tryReserve() {
				held = append(held, slot)
			}
			if len(held) != cap(stack.outbound.free) {
				t.Fatalf("held output slots = %d, want %d", len(held), cap(stack.outbound.free))
			}
			time.Sleep(config.Interval + config.Interval/2)
			_ = c.Info()
			_ = c.Info()
			reenabledAt := time.Now()
			if err := c.SetKeepAlive(false); err != nil {
				t.Fatal(err)
			}
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			last := len(held) - 1
			stack.outbound.releaseReserved(held[last])
			held = held[:last]
			select {
			case <-c.done:
				t.Fatalf("returned capacity closed the reenabled connection: %+v", c.Info())
			case <-time.After(config.Idle / 2):
			}
			if probes := stack.Stats().TCPKeepAliveProbes; probes != 1 {
				t.Fatalf("returned capacity published a probe before Idle: %d", probes)
			}
			entry, available = waitTestPacketEntry(&stack.outbound, 3*config.Idle)
			if !available {
				t.Fatal("reenabled keepalive did not publish its next probe")
			}
			consumeTestPacket(&stack.outbound, entry)
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 2 })
			if elapsed := time.Since(reenabledAt); elapsed < config.Idle*3/4 {
				t.Fatalf("reenabled probe published after %v, before Idle", elapsed)
			}
		})
	}
}

func TestTCPKeepAliveEnableWake(t *testing.T) {
	for _, current := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v-to-%v", current, enabled), func(t *testing.T) {
				c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				c.keepAlive = current
				if err := c.SetKeepAlive(enabled); err != nil {
					t.Fatal(err)
				}
				want := tcpActorWakeOptions
				if !current && enabled {
					want |= tcpActorWakeKeepAliveEnable
				}
				if got := c.takeActorWake(); got != want || c.keepAlive != enabled {
					t.Fatalf("keepalive wake = %#x, want %#x; enabled = %v", got, want, c.keepAlive)
				}
			})
		}
	}
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	for _, enabled := range []bool{true, false, true} {
		if err := c.SetKeepAlive(enabled); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.takeActorWake(); got != tcpActorWakeOptions|tcpActorWakeKeepAliveEnable || !c.keepAlive {
		t.Fatalf("coalesced keepalive transitions lost enable: flags=%#x enabled=%v", got, c.keepAlive)
	}
	c.userClosed = true
	if err := c.SetKeepAlive(false); !errors.Is(err, net.ErrClosed) || c.takeActorWake() != 0 || !c.keepAlive {
		t.Fatalf("closed connection changed keepalive: enabled=%v error=%v", c.keepAlive, err)
	}
}

func TestTCPKeepAliveUserTimeoutWaitsForProbeInterval(t *testing.T) {
	for _, mode := range []string{"silent peer", "acknowledged probe", "outstanding data"} {
		t.Run(mode, func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			keepAlive := KeepAliveConfig{Idle: 150 * time.Millisecond, Interval: 500 * time.Millisecond, Count: 1}
			if err := connection.SetKeepAliveConfig(keepAlive); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetUserTimeout(100 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
			if !available {
				t.Fatal("initial keepalive probe was not published")
			}
			probeAt := time.Now()
			wire := consumeTestPacket(&stack.outbound, entry)
			packet, valid := parseIPPacket(wire, false)
			if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || int(packet.payload[12]>>4)*4 != len(packet.payload) || packet.payload[13] != TCPFlagACK {
				t.Fatalf("initial output is not a keepalive ACK: %x", wire)
			}
			clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
			link.mu.Lock()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			if binary.BigEndian.Uint32(packet.payload[4:8]) != acknowledgement-1 || binary.BigEndian.Uint32(packet.payload[8:12]) != sequence {
				t.Fatalf("initial output does not use SND.NXT-1: %x", wire)
			}
			select {
			case <-connection.done:
				t.Fatalf("connection closed before the next keepalive check: %+v", connection.Info())
			case <-time.After(keepAlive.Interval / 5):
			}

			if mode == "acknowledged probe" {
				if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				entry, available = waitTestPacketEntry(&stack.outbound, (keepAlive.Idle+keepAlive.Interval)/2)
				if !available {
					t.Fatal("keepalive ACK did not restart the probe series with Idle")
				}
				wire = consumeTestPacket(&stack.outbound, entry)
				packet, valid = parseIPPacket(wire, false)
				if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || int(packet.payload[12]>>4)*4 != len(packet.payload) || packet.payload[13] != TCPFlagACK || binary.BigEndian.Uint32(packet.payload[4:8]) != acknowledgement-1 {
					t.Fatalf("output after keepalive ACK is not a new probe: %x", wire)
				}
				if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				payload := []byte("usable after keepalive ACK")
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				if n, err := connection.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("Write after keepalive ACK = %d, %v", n, err)
				}
				entry, available = waitTestPacketEntry(&stack.outbound, time.Second)
				if !available {
					t.Fatal("application output was not published after keepalive ACK")
				}
				if err := link.handleOutboundPacket(consumeTestPacket(&stack.outbound, entry)); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
					t.Fatalf("echo after keepalive ACK = %q, %v", received, err)
				}
				if info := connection.Info(); info.State != TCPStateEstablished || info.LastError != nil {
					t.Fatalf("acknowledged keepalive connection = %+v", info)
				}
				return
			}

			if mode == "outstanding data" {
				if _, err := connection.Write([]byte("unacknowledged after probe")); err != nil {
					t.Fatal(err)
				}
				entry, available = waitTestPacketEntry(&stack.outbound, time.Second)
				if !available {
					t.Fatal("application output was not published after keepalive probe")
				}
				wire = consumeTestPacket(&stack.outbound, entry)
				packet, valid = parseIPPacket(wire, false)
				if !valid || packet.protocol != ProtocolTCP || len(packet.payload) <= tcpHeaderSize || int(packet.payload[12]>>4)*4 >= len(packet.payload) {
					t.Fatalf("expected outstanding application data, got %x", wire)
				}
				select {
				case <-connection.done:
					t.Fatalf("stale keepalive activity expired a new flight: %+v", connection.Info())
				case <-time.After(25 * time.Millisecond):
				}
			}
			select {
			case <-connection.done:
			case <-time.After(2 * time.Second):
				t.Fatal("unanswered connection did not reach its user timeout")
			}
			if mode == "silent peer" && time.Since(probeAt) < keepAlive.Interval*3/4 {
				t.Fatalf("silent peer closed %v after its first probe, before the next check", time.Since(probeAt))
			}
			if info := connection.Info(); !errors.Is(info.LastError, syscall.ETIMEDOUT) || stack.Stats().TCPKeepAliveProbes != 1 {
				t.Fatalf("keepalive user timeout = info:%+v stats:%+v", info, stack.Stats())
			}
		})
	}
}

func TestTCPFullDuplexSustainedTrafficHasNoLocalDrops(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.142")
	serverAddress := netip.MustParseAddr("192.0.2.143")
	client, server := newStackPair(t, clientAddress, serverAddress, 1500)
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- connection
		_, _ = io.Copy(connection, connection)
	}()
	connection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		t.Fatal("server did not accept stress connection")
	}
	t.Cleanup(func() {
		_ = connection.Close()
		_ = serverConnection.Close()
		_ = listener.Close()
	})
	payload := bytes.Repeat([]byte{0x5c}, 8*1024*1024)
	received := make([]byte, len(payload))
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := connection.Write(payload)
		writeDone <- writeErr
	}()
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("full-duplex stress payload mismatch")
	}
	tcp := connection.(*TCPConn)
	waitFor(t, 2*time.Second, func() bool { return tcp.Info().BytesInFlight == 0 })
	clientStats, serverStats := client.Stats(), server.Stats()
	if clientStats.InboundDroppedPackets != 0 || serverStats.InboundDroppedPackets != 0 {
		t.Fatalf("full-duplex stress diagnostics: client=%+v server=%+v connection=%+v", clientStats, serverStats, tcp.Info())
	}
}

func TestTCPReaderFromWriterToAndMultipathQuery(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.201")
	serverAddress := netip.MustParseAddr("192.0.2.202")
	clientStack, serverStack := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, clientStack, serverStack)
	listener, err := serverStack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 45100))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := clientStack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 45100))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	payload := strings.Repeat("reader-from-writer-to-", 4096)
	n, err := client.(*TCPConn).ReadFrom(strings.NewReader(payload))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("ReadFrom = %d, %v, want %d", n, err, len(payload))
	}
	if err = client.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	n, err = server.(*TCPConn).WriteTo(&received)
	if err != nil || n != int64(len(payload)) || received.String() != payload {
		t.Fatalf("WriteTo = %d bytes, %v, content match = %v", n, err, received.String() == payload)
	}
	if multipath, queryErr := client.(*TCPConn).MultipathTCP(); queryErr != nil || multipath {
		t.Fatalf("MultipathTCP = %v, %v, want false, nil", multipath, queryErr)
	}
}

func TestTCPCloseWriteInterruptsWrites(t *testing.T) {
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.203"), netip.MustParseAddr("2001:db8::203")} {
		for _, mode := range []string{"Write", "ReadFrom", "ReaderData", "ReaderEOF", "ReaderCloseWrite"} {
			t.Run(address.String()+"/"+mode, func(t *testing.T) {
				const capacity = 4096
				stack, err := New(Config{
					LocalAddresses: []netip.Prefix{netip.PrefixFrom(address, address.BitLen())}, MTU: 1500,
					TCP: TCPSocketDefaults{ReceiveBuffer: capacity, MaximumReceiveBuffer: capacity, SendBuffer: capacity, MaximumSendBuffer: capacity},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				network := "tcp4"
				if address.Is6() {
					network = "tcp6"
				}
				listener, err := stack.ListenTCP(context.Background(), network, netip.AddrPortFrom(address, 0))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				client, err := stack.DialTCP(ctx, network, netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				connection := client.(*TCPConn)
				type writeResult struct {
					n   int64
					err error
				}
				written := make(chan writeResult, 1)
				payload := bytes.Repeat([]byte("accepted-prefix-"), capacity)
				expected := payload
				var releaseReader func()
				var readerClosed chan error
				if mode == "Write" || mode == "ReadFrom" {
					go func() {
						if mode == "Write" {
							n, writeErr := connection.Write(payload)
							written <- writeResult{int64(n), writeErr}
						} else {
							n, writeErr := connection.ReadFrom(bytes.NewReader(payload))
							written <- writeResult{n, writeErr}
						}
					}()
					waitFor(t, 2*time.Second, func() bool {
						info := connection.Info()
						connection.mu.Lock()
						waiting := connection.sendBuffer.limited && connection.sendBuffer.size == capacity
						connection.mu.Unlock()
						return waiting && info.PeerWindow == 0
					})
				} else {
					expected = []byte("queued before the external Reader")
					if n, writeErr := connection.Write(expected); writeErr != nil || n != len(expected) {
						t.Fatalf("initial Write = %d, %v", n, writeErr)
					}
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					releaseReader = func() { once.Do(func() { close(release) }) }
					t.Cleanup(releaseReader)
					readerClosed = make(chan error, 1)
					go func() {
						n, readErr := connection.ReadFrom(tcpTestReaderFunc(func(buffer []byte) (int, error) {
							close(entered)
							if mode == "ReaderCloseWrite" {
								readerClosed <- connection.CloseWrite()
								return 0, io.EOF
							}
							<-release
							if mode == "ReaderEOF" {
								return 0, io.EOF
							}
							return copy(buffer, []byte("not accepted after half-close")), io.EOF
						}))
						written <- writeResult{n, readErr}
					}()
					select {
					case <-entered:
					case <-time.After(2 * time.Second):
						t.Fatal("ReadFrom did not enter the external Reader")
					}
				}
				closed := make(chan error, 8)
				for range [8]struct{}{} {
					go func() { closed <- connection.CloseWrite() }()
				}
				for range [8]struct{}{} {
					select {
					case closeErr := <-closed:
						if closeErr != nil {
							t.Fatalf("CloseWrite = %v", closeErr)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("CloseWrite waited for the active write")
					}
				}
				if mode == "ReaderCloseWrite" {
					select {
					case closeErr := <-readerClosed:
						if closeErr != nil {
							t.Fatalf("Reader CloseWrite = %v", closeErr)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("Reader CloseWrite deadlocked")
					}
				}
				readerBlocked := mode == "ReaderData" || mode == "ReaderEOF"
				var result writeResult
				if !readerBlocked {
					select {
					case result = <-written:
					case <-time.After(2 * time.Second):
						t.Fatal("write did not observe the half-close")
					}
				}
				if mode == "Write" || mode == "ReadFrom" {
					if result.n <= 0 || result.n >= int64(len(payload)) || !errors.Is(result.err, net.ErrClosed) {
						t.Fatalf("interrupted %s = %d, %v", mode, result.n, result.err)
					}
					operation := "write"
					if mode == "ReadFrom" {
						operation = "readfrom"
					}
					checkNetOpError(t, result.err, operation, network)
					expected = payload[:int(result.n)]
				}
				_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
				received, readErr := io.ReadAll(server)
				if readErr != nil || !bytes.Equal(received, expected) {
					t.Fatalf("accepted prefix before EOF = %d bytes, %v; want %d matching bytes", len(received), readErr, len(expected))
				}
				if readerBlocked {
					select {
					case result := <-written:
						t.Fatalf("ReadFrom returned before its Reader: %+v", result)
					default:
					}
					releaseReader()
					select {
					case result = <-written:
					case <-time.After(2 * time.Second):
						t.Fatal("ReadFrom did not return after its Reader")
					}
				}
				if mode == "ReaderData" {
					if result.n != 0 || !errors.Is(result.err, net.ErrClosed) {
						t.Fatalf("ReadFrom after Reader data = %d, %v", result.n, result.err)
					}
				} else if mode == "ReaderEOF" || mode == "ReaderCloseWrite" {
					if result.n != 0 || result.err != nil {
						t.Fatalf("ReadFrom after Reader EOF = %d, %v", result.n, result.err)
					}
				}
				if n, writeErr := connection.Write([]byte("late")); n != 0 || !errors.Is(writeErr, net.ErrClosed) {
					t.Fatalf("Write after CloseWrite = %d, %v", n, writeErr)
				}
				response := []byte("receive direction remains open")
				if n, writeErr := server.Write(response); writeErr != nil || n != len(response) {
					t.Fatalf("reverse Write = %d, %v", n, writeErr)
				}
				if err = server.(*TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
				received, readErr = io.ReadAll(connection)
				if readErr != nil || !bytes.Equal(received, response) {
					t.Fatalf("reverse stream before EOF = %q, %v", received, readErr)
				}
			})
		}
	}
}

func TestTCPCloseWriteWithReservedDeviceQueue(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.204"), netip.MustParseAddr("198.51.100.204"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	client, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 45204))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	connection := client.(*TCPConn)
	const capacity = 4096
	_ = connection.SetWriteBuffer(capacity)
	held := make([]uint16, 0, cap(stack.outbound.free))
	t.Cleanup(func() {
		for _, slot := range held {
			stack.outbound.releaseReserved(slot)
		}
	})
	waitFor(t, 2*time.Second, func() bool {
		for len(held) < cap(held) {
			slot, ok := stack.outbound.tryReserve()
			if !ok {
				return false
			}
			held = append(held, slot)
		}
		return true
	})
	type writeResult struct {
		n   int
		err error
	}
	payload := bytes.Repeat([]byte{0x6d}, 64*1024)
	written := make(chan writeResult, 1)
	go func() {
		n, writeErr := connection.Write(payload)
		written <- writeResult{n, writeErr}
	}()
	waitFor(t, 2*time.Second, func() bool {
		connection.mu.Lock()
		defer connection.mu.Unlock()
		return connection.sendBuffer.limited && connection.sendBuffer.size == capacity
	})
	closed := make(chan error, 1)
	go func() { closed <- connection.CloseWrite() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseWrite waited for device capacity")
	}
	select {
	case result := <-written:
		if result.n != capacity || !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("Write with unavailable device capacity = %d, %v", result.n, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer was not woken by CloseWrite")
	}
	for _, slot := range held {
		stack.outbound.releaseReserved(slot)
	}
	held = nil
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	received, err := io.ReadAll(connection)
	if err != nil || !bytes.Equal(received, payload[:capacity]) {
		t.Fatalf("accepted external prefix before EOF = %d bytes, %v", len(received), err)
	}
}

func TestTCPCloseReadWithBlockedReads(t *testing.T) {
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.205"), netip.MustParseAddr("2001:db8::205")} {
		for _, mode := range []string{"Read", "ReadWithBuffer", "WriteTo", "Writer", "TCPWriter"} {
			t.Run(address.String()+"/"+mode, func(t *testing.T) {
				const capacity = 64
				stack, err := New(Config{
					LocalAddresses: []netip.Prefix{netip.PrefixFrom(address, address.BitLen())}, MTU: 1500,
					TCP: TCPSocketDefaults{ReceiveBuffer: capacity, MaximumReceiveBuffer: capacity, SendBuffer: capacity, MaximumSendBuffer: capacity},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				network := "tcp4"
				if address.Is6() {
					network = "tcp6"
				}
				listener, err := stack.ListenTCP(context.Background(), network, netip.AddrPortFrom(address, 0))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				client, err := stack.DialTCP(ctx, network, netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				connection := client.(*TCPConn)
				payload := []byte("consumed before the blocked Writer")
				var destination io.Writer = io.Discard
				var releaseWriter func()
				var entered chan struct{}
				var target, targetPeer *TCPConn
				var targetPrefix []byte
				if mode == "Writer" {
					entered = make(chan struct{})
					release := make(chan struct{})
					var once sync.Once
					releaseWriter = func() { once.Do(func() { close(release) }) }
					t.Cleanup(releaseWriter)
					destination = tcpTestWriterFunc(func(buffer []byte) (int, error) {
						close(entered)
						<-release
						if !bytes.Equal(buffer, payload) {
							t.Errorf("blocked Writer data = %q, want %q", buffer, payload)
						}
						return len(buffer), nil
					})
				} else if mode == "TCPWriter" {
					outgoing, dialErr := stack.DialTCP(ctx, network, netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
					if dialErr != nil {
						t.Fatal(dialErr)
					}
					t.Cleanup(func() { _ = outgoing.Close() })
					incoming, acceptErr := listener.Accept()
					if acceptErr != nil {
						t.Fatal(acceptErr)
					}
					t.Cleanup(func() { _ = incoming.Close() })
					target, targetPeer = outgoing.(*TCPConn), incoming.(*TCPConn)
					targetPrefix = bytes.Repeat([]byte{0x6d}, capacity)
					if n, writeErr := target.Write(targetPrefix); writeErr != nil || n != len(targetPrefix) {
						t.Fatalf("initial target Write = %d, %v", n, writeErr)
					}
					waitFor(t, 2*time.Second, func() bool {
						info := target.Info()
						return info.PeerWindow == 0 && info.SendBufferSize == 0
					})
					if n, writeErr := target.Write(targetPrefix); writeErr != nil || n != len(targetPrefix) {
						t.Fatalf("queued target Write = %d, %v", n, writeErr)
					}
					targetPrefix = bytes.Repeat([]byte{0x6d}, 2*capacity)
					destination = target
				}
				type readResult struct {
					n   int64
					err error
				}
				readDone := make(chan readResult, 1)
				callbackCalled := false
				go func() {
					var n int64
					var readErr error
					switch mode {
					case "Read":
						count, err := connection.Read(make([]byte, 1))
						n, readErr = int64(count), err
					case "ReadWithBuffer":
						count, err := connection.ReadWithBuffer(func(_ int) []byte {
							callbackCalled = true
							return make([]byte, 1)
						})
						n, readErr = int64(count), err
					default:
						n, readErr = connection.WriteTo(destination)
					}
					readDone <- readResult{n, readErr}
				}()
				writerBlocked := mode == "Writer" || mode == "TCPWriter"
				if writerBlocked {
					if n, writeErr := server.Write(payload); writeErr != nil || n != len(payload) {
						t.Fatalf("source Write = %d, %v", n, writeErr)
					}
					if mode == "Writer" {
						select {
						case <-entered:
						case <-time.After(2 * time.Second):
							t.Fatal("WriteTo did not enter the external Writer")
						}
					} else {
						waitFor(t, 2*time.Second, func() bool {
							target.mu.Lock()
							defer target.mu.Unlock()
							return target.sendBuffer.limited && target.sendBuffer.size == target.sendCapacity
						})
					}
				} else {
					waitFor(t, 2*time.Second, func() bool {
						connection.mu.Lock()
						defer connection.mu.Unlock()
						return connection.readNotify != nil && connection.readBuffer.size == 0 && connection.readErr == nil
					})
				}
				select {
				case result := <-readDone:
					t.Fatalf("read returned before half-close: %+v", result)
				default:
				}
				closed := make(chan error, 1)
				go func() { closed <- connection.CloseRead() }()
				select {
				case closeErr := <-closed:
					if closeErr != nil {
						t.Fatalf("CloseRead = %v", closeErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("CloseRead waited for the active read")
				}
				var result readResult
				if !writerBlocked {
					select {
					case result = <-readDone:
					case <-time.After(2 * time.Second):
						t.Fatal("read was not woken by CloseRead")
					}
				}
				response := []byte("send direction remains open")
				if n, writeErr := connection.Write(response); writeErr != nil || n != len(response) {
					t.Fatalf("Write after CloseRead = %d, %v", n, writeErr)
				}
				if err = connection.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
				received, readErr := io.ReadAll(server)
				if readErr != nil || !bytes.Equal(received, response) {
					t.Fatalf("send stream after CloseRead = %q, %v; want %q before EOF", received, readErr, response)
				}
				type targetResult struct {
					payload []byte
					err     error
				}
				var targetRead chan targetResult
				if writerBlocked {
					select {
					case result := <-readDone:
						t.Fatalf("WriteTo returned while its Writer was blocked: %+v", result)
					default:
					}
					if releaseWriter != nil {
						releaseWriter()
					} else {
						targetRead = make(chan targetResult, 1)
						_ = targetPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
						go func() {
							data, err := io.ReadAll(targetPeer)
							targetRead <- targetResult{data, err}
						}()
					}
					select {
					case result = <-readDone:
					case <-time.After(2 * time.Second):
						t.Fatal("WriteTo did not return after its Writer resumed")
					}
				}
				var expectedCount int64
				operation := "read"
				if mode != "Read" && mode != "ReadWithBuffer" {
					operation = "writeto"
				}
				if writerBlocked {
					expectedCount = int64(len(payload))
				}
				if result.n != expectedCount || !errors.Is(result.err, net.ErrClosed) || callbackCalled {
					t.Fatalf("%s after CloseRead = %d, %v, callback called %t; want %d, closed, false", mode, result.n, result.err, callbackCalled, expectedCount)
				}
				checkNetOpError(t, result.err, operation, network)
				if targetRead != nil {
					if err = target.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					select {
					case forwarded := <-targetRead:
						expected := append(targetPrefix, payload...)
						if forwarded.err != nil || !bytes.Equal(forwarded.payload, expected) {
							t.Fatalf("forwarded stream = %q, %v; want %q before EOF", forwarded.payload, forwarded.err, expected)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("target peer did not receive FIN")
					}
				}
			})
		}
	}
}

type tcpTestReaderFunc func([]byte) (int, error)

func (f tcpTestReaderFunc) Read(payload []byte) (int, error) { return f(payload) }

type tcpTestWriterFunc func([]byte) (int, error)

func (f tcpTestWriterFunc) Write(payload []byte) (int, error) { return f(payload) }

func TestTCPWriteToKeepsDirectChunkStableWhileReceiving(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.mu.Lock()
	connection.readBuffer.append([]byte("first"))
	connection.readErr = io.EOF
	connection.mu.Unlock()
	var received bytes.Buffer
	writes := 0
	n, err := connection.WriteTo(tcpTestWriterFunc(func(payload []byte) (int, error) {
		writes++
		if writes == 1 {
			if string(payload) != "first" {
				t.Fatalf("first direct WriteTo chunk = %q", payload)
			}
			second := []byte("second")
			if accepted := connection.appendReadBuffer(second, second, 0, 0); accepted != len(second) {
				t.Fatalf("concurrent receive accepted %d bytes", accepted)
			}
			if string(payload) != "first" {
				t.Fatalf("concurrent receive changed direct WriteTo chunk to %q", payload)
			}
		}
		return received.Write(payload)
	}))
	if err != nil || n != int64(len("firstsecond")) || received.String() != "firstsecond" || writes != 2 {
		t.Fatalf("direct WriteTo = %d, %v, data %q, writes %d", n, err, received.String(), writes)
	}
}

func TestTCPReadBufferAdoptsOwnedPayload(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("data")
	payload = payload[:len(payload):len(payload)]
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("appendReadBuffer accepted %d bytes, want %d", accepted, len(payload))
	}
	if &connection.readBuffer.chunks[0][0] != &payload[0] {
		t.Fatal("empty receive buffer did not adopt actor-owned payload")
	}
	buffer := make([]byte, len(payload))
	if n, err := connection.Read(buffer); err != nil || n != len(payload) || string(buffer) != "data" {
		t.Fatalf("Read = %d, %q, %v; want 4, data, nil", n, buffer, err)
	}
}

func TestTCPReadCrossesReceiveChunks(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	for _, payload := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
			t.Fatalf("accepted %d of %d bytes", accepted, len(payload))
		}
	}
	buffer := make([]byte, len("onetwothree"))
	if n, err := connection.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "onetwothree" {
		t.Fatalf("cross-chunk Read = %d, %v, %q", n, err, buffer)
	}
	if connection.readBuffer.size != 0 || connection.readBuffer.head != 0 || len(connection.readBuffer.chunks) != 0 {
		t.Fatalf("drained receive deque = size %d head %d chunks %d", connection.readBuffer.size, connection.readBuffer.head, len(connection.readBuffer.chunks))
	}
}

func TestTCPReadWithBufferAllocatesOnlyForAvailableData(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	started := make(chan struct{})
	result := make(chan struct {
		n   int
		err error
	}, 1)
	var provided []byte
	var sizeHint int
	callbackCalls := 0
	callbackCalled := make(chan struct{}, 1)
	go func() {
		close(started)
		n, err := connection.ReadWithBuffer(func(hint int) []byte {
			callbackCalls++
			sizeHint = hint
			callbackCalled <- struct{}{}
			provided = make([]byte, 5)
			return provided
		})
		result <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	<-started
	select {
	case <-result:
		t.Fatal("ReadWithBuffer returned before data was available")
	case <-callbackCalled:
		t.Fatal("buffer callback ran before data was available")
	case <-time.After(20 * time.Millisecond):
	}
	if accepted := connection.appendReadBuffer([]byte("hello world"), []byte("hello world"), 0, 0); accepted != len("hello world") {
		t.Fatalf("accepted = %d, want %d", accepted, len("hello world"))
	}
	var readResult struct {
		n   int
		err error
	}
	select {
	case readResult = <-result:
	case <-time.After(time.Second):
		t.Fatal("ReadWithBuffer did not return after data arrived")
	}
	if readResult.n != 5 || readResult.err != nil || callbackCalls != 1 || sizeHint != len("hello world") || string(provided) != "hello" {
		t.Fatalf("ReadWithBuffer = %d, %v, buffer %q, callback calls %d, size hint %d; want 5, nil, hello, 1, %d", readResult.n, readResult.err, provided, callbackCalls, sizeHint, len("hello world"))
	}
	var remaining []byte
	remainingHint := 0
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		remainingHint = hint
		remaining = make([]byte, 6)
		return remaining
	})
	if n != len(remaining) || err != nil || remainingHint != len(remaining) || string(remaining) != " world" {
		t.Fatalf("remaining ReadWithBuffer = %d, %v, %q, size hint %d; want 6, nil, ' world', 6", n, err, remaining, remainingHint)
	}
}

func TestTCPReadWithBufferEmptyBufferDoesNotConsume(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("preserved")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	callbackCalls := 0
	sizeHint := 0
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		callbackCalls++
		sizeHint = hint
		return nil
	})
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) || callbackCalls != 1 || sizeHint != len(payload) {
		t.Fatalf("empty-buffer ReadWithBuffer = %d, %v, callback calls %d, size hint %d; want 0, ErrShortBuffer, 1, %d", n, err, callbackCalls, sizeHint, len(payload))
	}
	buffer := make([]byte, len(payload))
	if n, err = connection.Read(buffer); n != len(buffer) || err != nil || string(buffer) != string(payload) {
		t.Fatalf("data after empty-buffer ReadWithBuffer = %d, %v, %q; want %d, nil, %q", n, err, buffer, len(payload), payload)
	}
}

func TestTCPReadWithBufferReportsFullQueuedSize(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := bytes.Repeat([]byte{'x'}, 64*1024+1)
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	var sizeHint int
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		sizeHint = hint
		return make([]byte, 1)
	})
	if n != 1 || err != nil || sizeHint != len(payload) {
		t.Fatalf("ReadWithBuffer = %d, %v, size hint %d; want 1, nil, %d", n, err, sizeHint, len(payload))
	}
}

func TestTCPReadWithBufferCrossesReceiveChunks(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	for _, payload := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
			t.Fatalf("accepted %d of %d bytes", accepted, len(payload))
		}
	}
	var buffer []byte
	sizeHint := 0
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		sizeHint = hint
		buffer = make([]byte, len("onetwothree"))
		return buffer
	})
	if n != len(buffer) || err != nil || sizeHint != len(buffer) || string(buffer) != "onetwothree" {
		t.Fatalf("cross-chunk ReadWithBuffer = %d, %v, %q, size hint %d; want 11, nil, onetwothree, %d", n, err, buffer, sizeHint, len(buffer))
	}
}

func TestTCPReadWithBufferTerminalStatesDoNotCallCallback(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*TCPConn)
		want  error
	}{
		{name: "EOF", setup: func(c *TCPConn) { c.readErr = io.EOF }, want: io.EOF},
		{name: "reset", setup: func(c *TCPConn) { c.readErr = syscall.ECONNRESET }, want: syscall.ECONNRESET},
		{name: "read closed", setup: func(c *TCPConn) { c.readClosed = true; c.readErr = net.ErrClosed }, want: net.ErrClosed},
		{name: "user closed", setup: func(c *TCPConn) { c.userClosed = true }, want: net.ErrClosed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.mu.Lock()
			test.setup(connection)
			connection.mu.Unlock()
			callbackCalls := 0
			n, err := connection.ReadWithBuffer(func(_ int) []byte {
				callbackCalls++
				return make([]byte, 1)
			})
			if n != 0 || !errors.Is(err, test.want) || callbackCalls != 0 {
				t.Fatalf("ReadWithBuffer = %d, %v, callback calls %d; want 0, %v, 0", n, err, callbackCalls, test.want)
			}
		})
	}
}

func TestTCPReadWithBufferExpiredDeadlineDoesNotCallCallback(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("deadline data")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	if err := connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	n, err := connection.ReadWithBuffer(func(_ int) []byte {
		callbackCalls++
		return make([]byte, 1)
	})
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || callbackCalls != 0 {
		t.Fatalf("expired-deadline ReadWithBuffer = %d, %v, callback calls %d; want 0, deadline, 0", n, err, callbackCalls)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if n, err := connection.Read(buffer); n != len(payload) || err != nil || string(buffer) != string(payload) {
		t.Fatalf("data after expired-deadline ReadWithBuffer = %d, %v, %q; want %d, nil, %q", n, err, buffer, len(payload), payload)
	}
}

func TestTCPReadWithBufferDataPrecedesEOF(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("data")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	connection.mu.Lock()
	connection.readErr = io.EOF
	connection.mu.Unlock()
	callbackCalls := 0
	buffer := []byte(nil)
	sizeHint := 0
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		callbackCalls++
		sizeHint = hint
		buffer = make([]byte, len(payload))
		return buffer
	})
	if n != len(payload) || err != nil || callbackCalls != 1 || sizeHint != len(payload) || string(buffer) != string(payload) {
		t.Fatalf("data ReadWithBuffer = %d, %v, %q, callback calls %d, size hint %d; want %d, nil, %q, 1, %d", n, err, buffer, callbackCalls, sizeHint, len(payload), payload, len(payload))
	}
	if n, err = connection.ReadWithBuffer(func(_ int) []byte {
		callbackCalls++
		return make([]byte, 1)
	}); n != 0 || err != io.EOF || callbackCalls != 1 {
		t.Fatalf("EOF ReadWithBuffer = %d, %v, callback calls %d; want 0, EOF, 1", n, err, callbackCalls)
	}
}

func TestTCPReadWithBufferCallbackRunsOutsideConnectionLock(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("callback")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	buffer := []byte(nil)
	n, err := connection.ReadWithBuffer(func(hint int) []byte {
		if hint != len(payload) {
			t.Fatalf("ReadWithBuffer size hint = %d; want %d", hint, len(payload))
		}
		if deadlineErr := connection.SetReadDeadline(time.Time{}); deadlineErr != nil {
			t.Fatalf("SetReadDeadline in buffer callback = %v", deadlineErr)
		}
		buffer = make([]byte, len(payload))
		return buffer
	})
	if n != len(payload) || err != nil || string(buffer) != string(payload) {
		t.Fatalf("ReadWithBuffer = %d, %v, %q; want %d, nil, %q", n, err, buffer, len(payload), payload)
	}
}

func TestTCPReadWithBufferCallbackCanRaceCloseRead(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("callback close")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("accepted = %d, want %d", accepted, len(payload))
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan struct {
		n        int
		err      error
		provided []byte
		sizeHint int
	}, 1)
	go func() {
		var provided []byte
		sizeHint := 0
		n, err := connection.ReadWithBuffer(func(hint int) []byte {
			sizeHint = hint
			close(entered)
			<-release
			provided = make([]byte, len(payload))
			return provided
		})
		result <- struct {
			n        int
			err      error
			provided []byte
			sizeHint int
		}{n: n, err: err, provided: provided, sizeHint: sizeHint}
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- connection.CloseRead() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("CloseRead during buffer callback = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseRead blocked during buffer callback")
	}
	close(release)
	select {
	case readResult := <-result:
		if readResult.n != 0 || !errors.Is(readResult.err, net.ErrClosed) || readResult.provided == nil || readResult.sizeHint != len(payload) {
			t.Fatalf("ReadWithBuffer after CloseRead = %d, %v, buffer nil=%v, size hint %d; want 0, closed, non-nil buffer, %d", readResult.n, readResult.err, readResult.provided == nil, readResult.sizeHint, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("ReadWithBuffer did not return after CloseRead")
	}
}

func TestTCPReadWithBufferUsesEstablishedReceivePath(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.221")
	serverAddress := netip.MustParseAddr("192.0.2.222")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- connection
	}()
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		t.Fatal("server did not accept connection")
	}
	defer clientConnection.Close()
	defer serverConnection.Close()
	defer listener.Close()
	payload := []byte("established receive path")
	if _, err = clientConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	var buffer []byte
	sizeHint := 0
	n, err := serverConnection.(*TCPConn).ReadWithBuffer(func(hint int) []byte {
		sizeHint = hint
		buffer = make([]byte, len(payload))
		return buffer
	})
	if n != len(payload) || err != nil || sizeHint != len(payload) || string(buffer) != string(payload) {
		t.Fatalf("ReadWithBuffer = %d, %v, %q, size hint %d; want %d, nil, %q, %d", n, err, buffer, sizeHint, len(payload), payload, len(payload))
	}
}

func TestTCPReadWithBufferRejectsNilCallback(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	n, err := connection.ReadWithBuffer(nil)
	if n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil callback ReadWithBuffer = %d, %v; want 0, EINVAL", n, err)
	}
	var operationError *net.OpError
	if !errors.As(err, &operationError) || operationError.Op != "read" || operationError.Net != "tcp4" {
		t.Fatalf("nil callback error = %T %v; want read tcp4 OpError", err, err)
	}
}

func TestTCPWriteToBatchesReceiveChunks(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	const chunks = 40
	chunk := bytes.Repeat([]byte{0x5a}, 1024)
	for index := 0; index < chunks; index++ {
		connection.readBuffer.append(append([]byte(nil), chunk...))
	}
	connection.readErr = io.EOF
	writes := 0
	n, err := connection.WriteTo(tcpTestWriterFunc(func(payload []byte) (int, error) {
		writes++
		if len(payload) > 32*1024 {
			t.Fatalf("WriteTo batch = %d bytes", len(payload))
		}
		return len(payload), nil
	}))
	if err != nil || n != chunks*1024 || writes != 2 {
		t.Fatalf("chunked WriteTo = %d, %v, writes %d; want %d, nil, 2", n, err, writes, chunks*1024)
	}
}

func TestTCPReadDequeReleasesLargeMetadataBurst(t *testing.T) {
	var buffer tcpReadBuffer
	for index := 0; index <= tcpReadChunkRetain; index++ {
		buffer.append([]byte{byte(index)})
	}
	destination := make([]byte, buffer.size)
	if n := buffer.read(destination, len(destination), nil); n != len(destination) {
		t.Fatalf("deque read = %d, want %d", n, len(destination))
	}
	if buffer.chunks != nil {
		t.Fatalf("large drained deque retained capacity %d", cap(buffer.chunks))
	}
}

func TestTCPSegmentQueueReusesOneReceivePayload(t *testing.T) {
	queue := newTCPSegmentQueue()
	first := bytes.Repeat([]byte{0x31}, 1500)
	if !queue.enqueueCopy(tcpSegment{}, first) {
		t.Fatal("first copied segment was rejected")
	}
	segment, ok := queue.dequeue()
	if !ok || !bytes.Equal(segment.payload, first) {
		t.Fatal("first copied segment payload mismatch")
	}
	backing := &segment.payload[0]
	queue.recyclePayload(segment.payload)
	second := bytes.Repeat([]byte{0x52}, 1500)
	if !queue.enqueueCopy(tcpSegment{}, second) {
		t.Fatal("second copied segment was rejected")
	}
	segment, ok = queue.dequeue()
	if !ok || !bytes.Equal(segment.payload, second) || &segment.payload[0] != backing {
		t.Fatal("receive payload backing was not safely reused")
	}
	queue.recyclePayload(segment.payload)
	queue.bytes = tcpInboundByteCapacity
	if allocations := testing.AllocsPerRun(100, func() {
		if queue.enqueueCopy(tcpSegment{}, second[:1]) {
			t.Fatal("full actor queue accepted another payload")
		}
	}); allocations != 0 {
		t.Fatalf("full-queue drop allocations = %v, want 0", allocations)
	}
}

func TestTCPListenerIPv6WildcardAndBinding(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::1")
	serverAddress := netip.MustParseAddr("2001:db8::2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	if _, err = server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, port)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("overlapping ListenTCP error = %v", err)
	} else {
		checkNetOpError(t, err, "listen", "tcp")
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, port))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	if serverConnection.LocalAddr().(*net.TCPAddr).AddrPort().Addr() != serverAddress {
		t.Fatalf("accepted local address = %v, want %v", serverConnection.LocalAddr(), serverAddress)
	}
	if stats := server.Stats(); stats.ActiveTCPListeners != 1 || stats.ActiveTCPConnections != 1 {
		t.Fatalf("passive stats = listeners %d connections %d", stats.ActiveTCPListeners, stats.ActiveTCPConnections)
	}
}

func TestTCPListenerCloseAbortsQueuedConnection(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.1")
	serverAddress := netip.MustParseAddr("192.0.2.2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "accept", "tcp")
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queued connection Read error = %v", err)
	}
}

func TestTCPPassiveCloserSkipsTimeWait(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.181")
	serverAddress := netip.MustParseAddr("192.0.2.182")
	client, server := newStackPair(t, clientAddress, serverAddress, 1500)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		t.Fatal("accept failed")
	}
	defer clientConnection.Close()
	defer serverConnection.Close()
	if err = serverConnection.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = clientConnection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := clientConnection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("client FIN read = %d, %v", n, readErr)
	}
	if err = clientConnection.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = serverConnection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := serverConnection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	if active := server.Stats().ActiveTCPConnections; active != 1 {
		t.Fatalf("active closer connections = %d, want TIME-WAIT actor", active)
	}
}

func TestTCPTimeWaitAcceptsRetransmittedFINWithAdditionalFlags(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.183"), netip.MustParseAddr("192.0.2.184"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	defer connection.Close()
	if err = tcpConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("peer FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 1 })
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	if peer == nil || !peer.finSent {
		link.mu.Unlock()
		t.Fatal("test peer did not complete the active close")
	}
	sequence := peer.serverNext - 1
	acknowledgement := peer.clientNext
	ackCount := link.clientACKs
	link.mu.Unlock()
	stack.controlMu.Lock()
	stack.controlLimiters[controlResponseTCPChallengeACK] = tokenBucket{updated: time.Now().Add(time.Hour)}
	stack.controlMu.Unlock()
	if err = link.deliverTCP(8080, tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK|TCPFlagFIN|TCPFlagPSH, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > ackCount
	})
}

func TestTCPTimeWaitReplacesAcceptedTupleWithFreshTimestamp(t *testing.T) {
	client, server := newStackPair(t, netip.MustParseAddr("192.0.2.185"), netip.MustParseAddr("192.0.2.186"), 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.186"), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote := listener.Addr().(*net.TCPAddr).AddrPort()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	first, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := <-accepted
	if firstServer == nil {
		t.Fatal("first Accept returned no connection")
	}
	firstTCP := firstServer.(*TCPConn)
	firstClient := first.(*TCPConn)
	if err = firstTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first client FIN read = %d, %v", n, readErr)
	}
	if err = firstClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	waitFor(t, time.Second, func() bool { return server.Stats().ActiveTCPConnections == 1 })
	oldLocal := first.LocalAddr().(*net.TCPAddr).AddrPort()
	serverKey := tcpKey{local: remote, remote: oldLocal}
	server.mu.Lock()
	oldServer := server.tcp[serverKey]
	if oldServer == nil || oldServer.recentTimestamp == 0 {
		server.mu.Unlock()
		t.Fatal("server did not retain timestamped TIME-WAIT connection")
	}
	oldTimestamp := oldServer.recentTimestamp
	oldReceiveNext := uint32(firstClient.icmpSequence.Load())
	if oldReceiveNext == 0 {
		t.Fatal("client did not publish the final receive sequence")
	}
	server.mu.Unlock()
	if state := oldServer.Info().State; state != TCPStateTimeWait {
		t.Fatalf("old server state = %v, want TIME-WAIT", state)
	}
	first.Close()
	firstServer.Close()
	for _, options := range [][]byte{tcpTimestampOptions(oldTimestamp-1, 0), tcpTimestampOptions(oldTimestamp, 0), nil} {
		staleSYN := buildTestTCP(oldLocal.Addr(), remote.Addr(), oldLocal.Port(), remote.Port(), oldReceiveNext-1, 0,
			TCPFlagSYN, 65535, options, nil)
		if err = writeTestPacket(server, staleSYN); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Millisecond)
	server.mu.Lock()
	if server.tcp[serverKey] != oldServer {
		server.mu.Unlock()
		t.Fatal("stale or equal timestamp replaced TIME-WAIT connection")
	}
	server.mu.Unlock()
	rst := buildTestTCP(oldLocal.Addr(), remote.Addr(), oldLocal.Port(), remote.Port(), 0, 0, TCPFlagRST|TCPFlagACK, 0, nil, nil)
	if err = writeTestPacket(server, rst); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.tcp[serverKey] == oldServer
	})
	waitFor(t, time.Second, func() bool { return tcpSequenceGreater(client.tcpTimestamp(), oldTimestamp) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := client.DialTCP(ctx, "tcp4", oldLocal, remote)
	if err != nil {
		t.Fatalf("same-tuple DialTCP = %v", err)
	}
	defer second.Close()
	secondServer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer secondServer.Close()
	if got := second.LocalAddr().(*net.TCPAddr).AddrPort(); got != oldLocal {
		t.Fatalf("replacement local address = %v, want %v", got, oldLocal)
	}
	if state := secondServer.(*TCPConn).Info().State; state != TCPStateEstablished {
		t.Fatalf("replacement state = %v, want established", state)
	}
}

func TestTCPTimeWaitReplacementFailureReleasesCandidate(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.189")
	serverAddress := netip.MustParseAddr("192.0.2.190")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote := listener.Addr().(*net.TCPAddr).AddrPort()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	first, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := <-accepted
	if firstServer == nil {
		t.Fatal("first Accept returned no connection")
	}
	firstClient := first.(*TCPConn)
	firstServerTCP := firstServer.(*TCPConn)
	if err = firstServerTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first client FIN read = %d, %v", n, readErr)
	}
	if err = firstClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("first server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	waitFor(t, time.Second, func() bool { return firstServerTCP.Info().State == TCPStateTimeWait })
	oldLocal := first.LocalAddr().(*net.TCPAddr).AddrPort()
	serverKey := tcpKey{local: remote, remote: oldLocal}
	server.mu.Lock()
	oldOwner := server.tcp[serverKey]
	server.mu.Unlock()
	if oldOwner != firstServerTCP {
		t.Fatal("server did not retain the accepted TIME-WAIT owner")
	}
	newSequence := uint32(firstClient.icmpSequence.Load()) + 1
	failures := listener.(*TCPListener).Info().HandshakeFailures
	_ = first.Close()
	_ = firstServer.Close()

	syn := buildTestTCP(oldLocal.Addr(), remote.Addr(), oldLocal.Port(), remote.Port(), newSequence, 0, TCPFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(server, syn); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return listener.(*TCPListener).Info().HandshakeFailures > failures && server.Stats().ActiveTCPConnections == 0
	})
	server.mu.Lock()
	owner := server.tcp[serverKey]
	server.mu.Unlock()
	if owner != nil {
		t.Fatalf("failed replacement retained tuple owner %p", owner)
	}
	listener.(*TCPListener).mu.Lock()
	pending, handshaking := len(listener.(*TCPListener).pending), len(listener.(*TCPListener).handshaking)
	listener.(*TCPListener).mu.Unlock()
	if pending != 0 || handshaking != 0 {
		t.Fatalf("failed replacement listener ownership = (%d pending, %d handshaking), want zero", pending, handshaking)
	}
}

func TestTCPTimeWaitSYNAdmission(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name                string
		peerTimestamp       bool
		recentTimestamp     uint32
		lastTimestampUpdate time.Time
		sequence            uint32
		options             []byte
		replace             bool
	}{
		{name: "new timestamp", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now, sequence: 499, options: tcpTimestampOptions(101, 0), replace: true},
		{name: "equal timestamp and new sequence", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now, sequence: 501, options: tcpTimestampOptions(100, 0), replace: true},
		{name: "older timestamp rejected by paws", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now, sequence: 501, options: tcpTimestampOptions(99, 0)},
		{name: "before paws expiry", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now.Add(-2147*time.Second + time.Nanosecond), sequence: 501, options: tcpTimestampOptions(99, 0)},
		{name: "exact paws expiry and new sequence", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now.Add(-2147 * time.Second), sequence: 501, options: tcpTimestampOptions(99, 0), replace: true},
		{name: "expired paws and old sequence", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now.Add(-40 * time.Minute), sequence: 499, options: tcpTimestampOptions(99, 0)},
		{name: "microsecond clock and new sequence", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now.Add(-40 * time.Minute), sequence: 501, options: tcpTimestampOptions(2_400_000_100, 0), replace: true},
		{name: "microsecond clock and old sequence", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now.Add(-40 * time.Minute), sequence: 499, options: tcpTimestampOptions(2_400_000_100, 0)},
		{name: "new sequence without timestamp", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now, sequence: 501, replace: true},
		{name: "old sequence without timestamp", peerTimestamp: true, recentTimestamp: 100, lastTimestampUpdate: now, sequence: 499},
		{name: "timestamp enables new incarnation", peerTimestamp: false, sequence: 499, options: tcpTimestampOptions(101, 0), replace: true},
		{name: "old sequence and no timestamp", peerTimestamp: false, sequence: 499},
	} {
		t.Run(test.name, func(t *testing.T) {
			replaced := false
			stack := &Stack{tcpTimeWaitReplacer: func(*Stack, *TCPConn, tcpSegment) bool {
				replaced = true
				return true
			}}
			connection := &TCPConn{stack: stack, peerTimestamp: test.peerTimestamp, recentTimestamp: test.recentTimestamp}
			state := &tcpEstablishedState{connection: connection, receiveNext: 500, lastTimestampUpdate: test.lastTimestampUpdate}
			segment := tcpSegment{sequence: test.sequence, flags: TCPFlagSYN, optionLength: uint8(len(test.options))}
			copy(segment.options[:], test.options)
			got := state.handleTimeWaitSegment(segment, now, now)
			if got != test.replace {
				t.Fatalf("TIME-WAIT SYN replacement = %v, want %v", got, test.replace)
			}
			if replaced != test.replace {
				t.Fatalf("replacement callback = %v, want %v", replaced, test.replace)
			}
		})
	}
}

func TestTCPTimeWaitDoesNotLearnTimestampFromOutOfWindow(t *testing.T) {
	now := time.Now()
	stack := &Stack{}
	connection := &TCPConn{stack: stack, peerTimestamp: true, recentTimestamp: 100}
	state := &tcpEstablishedState{
		connection:          connection,
		receiveNext:         500,
		lastACKSent:         500,
		lastTimestampUpdate: now,
	}
	outOfWindow := tcpSegment{sequence: 100, flags: TCPFlagACK, optionLength: 12}
	copy(outOfWindow.options[:], tcpTimestampOptions(200, 0))
	state.handleTimeWaitSegment(outOfWindow, now, now)
	if connection.recentTimestamp != 100 {
		t.Fatalf("out-of-window TS.Recent = %d, want 100", connection.recentTimestamp)
	}
	inWindow := tcpSegment{sequence: 500, flags: TCPFlagACK, optionLength: 12}
	copy(inWindow.options[:], tcpTimestampOptions(200, 0))
	state.handleTimeWaitSegment(inWindow, now, now)
	if connection.recentTimestamp != 200 {
		t.Fatalf("in-window TS.Recent = %d, want 200", connection.recentTimestamp)
	}
}

func TestTCPTimeWaitPAWSExpiry(t *testing.T) {
	now := time.Now()
	connection := &TCPConn{stack: &Stack{}, peerTimestamp: true, recentTimestamp: 100}
	state := &tcpEstablishedState{
		connection:          connection,
		receiveNext:         500,
		lastACKSent:         500,
		lastTimestampUpdate: now,
		receiveWindowState:  newTCPReceiveWindow(500, 4096, false, false, 0),
	}
	for _, step := range []struct {
		name     string
		sequence uint32
		flags    byte
		tsval    uint32
		age      time.Duration
		want     uint32
	}{
		{name: "fresh reference rejects stale ACK", sequence: 500, flags: TCPFlagACK, tsval: 99, age: 2147*time.Second - time.Nanosecond, want: 100},
		{name: "expiry does not bypass sequence gate", sequence: 499, flags: TCPFlagACK, tsval: 2_400_000_100, age: 40 * time.Minute, want: 100},
		{name: "expiry does not bypass control gate", sequence: 500, flags: TCPFlagACK | TCPFlagFIN, tsval: 2_400_000_100, age: 40 * time.Minute, want: 100},
		{name: "exact ACK refreshes expired reference", sequence: 500, flags: TCPFlagACK, tsval: 2_400_000_100, age: 40 * time.Minute, want: 2_400_000_100},
		{name: "refreshed reference rejects old ACK", sequence: 500, flags: TCPFlagACK, tsval: 2_400_000_098, age: 40*time.Minute + time.Second, want: 2_400_000_100},
		{name: "new ACK remains accepted", sequence: 500, flags: TCPFlagACK, tsval: 2_400_000_101, age: 40*time.Minute + 2*time.Second, want: 2_400_000_101},
	} {
		previousTimestamp, previousUpdate := connection.recentTimestamp, state.lastTimestampUpdate
		segment := tcpSegment{sequence: step.sequence, flags: step.flags}
		segment.setOptions(tcpTimestampOptions(step.tsval, 0))
		receivedAt := now.Add(step.age)
		if state.handleTimeWaitSegment(segment, receivedAt, receivedAt) {
			t.Fatalf("%s: TIME-WAIT ACK unexpectedly replaced the tuple", step.name)
		}
		if got := connection.recentTimestamp; got != step.want {
			t.Fatalf("%s: TS.Recent = %d, want %d", step.name, got, step.want)
		}
		wantUpdate := previousUpdate
		if step.want != previousTimestamp {
			wantUpdate = receivedAt
		}
		if !state.lastTimestampUpdate.Equal(wantUpdate) {
			t.Fatalf("%s: reference update time = %v, want %v", step.name, state.lastTimestampUpdate, wantUpdate)
		}
	}
}

func TestTCPTimeWaitLearnsTimestampOnlyFromPureACK(t *testing.T) {
	now := time.Now()
	connection := &TCPConn{stack: &Stack{}, peerTimestamp: true, recentTimestamp: 100}
	state := &tcpEstablishedState{
		connection:          connection,
		receiveNext:         500,
		lastACKSent:         500,
		lastTimestampUpdate: now,
		receiveWindowState:  newTCPReceiveWindow(500, 4096, false, false, 0),
	}
	for _, segment := range []tcpSegment{
		{sequence: 500, flags: TCPFlagACK, payload: []byte("data")},
		{sequence: 500, flags: TCPFlagACK | TCPFlagFIN},
	} {
		segment.setOptions(tcpTimestampOptions(200, 0))
		if state.handleTimeWaitSegment(segment, now, now) {
			t.Fatal("TIME-WAIT payload/control unexpectedly replaced the tuple")
		}
		if connection.recentTimestamp != 100 {
			t.Fatalf("non-pure ACK TS.Recent = %d, want 100", connection.recentTimestamp)
		}
	}
	pureACK := tcpSegment{sequence: 500, flags: TCPFlagACK}
	pureACK.setOptions(tcpTimestampOptions(200, 0))
	if state.handleTimeWaitSegment(pureACK, now, now) {
		t.Fatal("TIME-WAIT pure ACK unexpectedly replaced the tuple")
	}
	if connection.recentTimestamp != 200 {
		t.Fatalf("pure ACK TS.Recent = %d, want 200", connection.recentTimestamp)
	}
}

func TestTCPTimeWaitAcceptsMissingTimestampFIN(t *testing.T) {
	now := time.Now()
	connection := &TCPConn{stack: &Stack{}, peerTimestamp: true, recentTimestamp: 100}
	state := &tcpEstablishedState{
		connection:          connection,
		receiveNext:         501,
		lastACKSent:         501,
		lastTimestampUpdate: now,
	}
	segment := tcpSegment{sequence: 500, flags: TCPFlagACK | TCPFlagFIN}
	if state.handleTimeWaitSegment(segment, now, now) {
		t.Fatal("missing-timestamp FIN unexpectedly replaced TIME-WAIT")
	}
	if !state.retransmit || state.retransmissionKind != tcpRetransmissionClose {
		t.Fatalf("missing-timestamp FIN close timer = retransmit:%v kind:%v", state.retransmit, state.retransmissionKind)
	}
}

func TestTCPTimeWaitTimerRefreshPolicy(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name                string
		segment             tcpSegment
		receivedAt          time.Time
		peerTimestamp       bool
		recentTimestamp     uint32
		lastTimestampUpdate time.Time
		receiveNext         uint32
		replace             bool
		wantReplacement     bool
		wantRefresh         bool
	}{
		{
			name:        "in-window ACK",
			segment:     tcpSegment{sequence: 100, flags: TCPFlagACK},
			receivedAt:  now.Add(-2 * tcpTimeWaitDuration),
			receiveNext: 100,
			wantRefresh: true,
		},
		{
			name:        "out-of-window ACK",
			segment:     tcpSegment{sequence: 99, flags: TCPFlagACK},
			receiveNext: 100,
			wantRefresh: true,
		},
		{
			name:                "PAWS-rejected segment",
			segment:             tcpSegment{sequence: 100, optionLength: 12},
			peerTimestamp:       true,
			recentTimestamp:     100,
			lastTimestampUpdate: now,
			receiveNext:         100,
			wantRefresh:         true,
		},
		{
			name:        "old ACK-less SYN",
			segment:     tcpSegment{sequence: 99, flags: TCPFlagSYN},
			receiveNext: 100,
		},
		{
			name:        "invalid SYN-ACK",
			segment:     tcpSegment{sequence: 99, flags: TCPFlagSYN | TCPFlagACK},
			receiveNext: 100,
			wantRefresh: true,
		},
		{
			name:        "RST",
			segment:     tcpSegment{sequence: 100, flags: TCPFlagRST},
			receiveNext: 100,
		},
		{
			name:        "retransmitted FIN",
			segment:     tcpSegment{sequence: 99, flags: TCPFlagACK | TCPFlagFIN},
			receiveNext: 100,
			wantRefresh: true,
		},
		{
			name:            "successful SYN replacement",
			segment:         tcpSegment{sequence: 101, flags: TCPFlagSYN},
			receiveNext:     100,
			replace:         true,
			wantReplacement: true,
		},
		{
			name:                "PAWS-rejected SYN",
			segment:             tcpSegment{sequence: 99, flags: TCPFlagSYN, optionLength: 12},
			peerTimestamp:       true,
			recentTimestamp:     100,
			lastTimestampUpdate: now,
			receiveNext:         100,
			wantRefresh:         true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := &Stack{}
			if test.replace {
				stack.tcpTimeWaitReplacer = func(*Stack, *TCPConn, tcpSegment) bool { return true }
			}
			connection := &TCPConn{
				stack:           stack,
				peerTimestamp:   test.peerTimestamp,
				recentTimestamp: test.recentTimestamp,
			}
			state := &tcpEstablishedState{
				connection:          connection,
				receiveNext:         test.receiveNext,
				receiveWindowState:  newTCPReceiveWindow(test.receiveNext, 65535, false, false, 0),
				lastTimestampUpdate: test.lastTimestampUpdate,
			}
			if test.peerTimestamp && test.segment.optionLength != 0 {
				copy(test.segment.options[:], tcpTimestampOptions(99, 0))
			}
			deadline := time.Now().Add(-time.Second)
			state.retransmit = true
			state.retransmissionKind = tcpRetransmissionClose
			state.retransmissionDeadline = deadline
			receivedAt := test.receivedAt
			if receivedAt.IsZero() {
				receivedAt = now
			}
			if replaced := state.handleTimeWaitSegment(test.segment, receivedAt, now); replaced != test.wantReplacement {
				t.Fatalf("TIME-WAIT replacement = %v, want %v", replaced, test.wantReplacement)
			}
			if test.wantRefresh {
				if !state.retransmissionDeadline.After(time.Now()) {
					t.Fatalf("TIME-WAIT deadline = %v, want a fresh 2MSL deadline", state.retransmissionDeadline)
				}
			} else if !state.retransmissionDeadline.Equal(deadline) {
				t.Fatalf("TIME-WAIT deadline = %v, want unchanged %v", state.retransmissionDeadline, deadline)
			}
		})
	}
}

func TestTCPTimeWaitKeepsQueuedAcceptOwner(t *testing.T) {
	client, server := newStackPair(t, netip.MustParseAddr("192.0.2.187"), netip.MustParseAddr("192.0.2.188"), 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.188"), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote := listener.Addr().(*net.TCPAddr).AddrPort()
	first, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	firstTCP := first.(*TCPConn)
	oldLocal := first.LocalAddr().(*net.TCPAddr).AddrPort()
	serverKey := tcpKey{local: remote, remote: oldLocal}
	var firstServer *TCPConn
	waitFor(t, time.Second, func() bool {
		server.mu.Lock()
		firstServer = server.tcp[serverKey]
		server.mu.Unlock()
		return firstServer != nil
	})
	waitFor(t, time.Second, func() bool { return firstServer.Info().State == TCPStateEstablished })
	if err = firstServer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("queued first client FIN read = %d, %v", n, readErr)
	}
	if err = firstTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("queued first server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	waitFor(t, time.Second, func() bool { return server.Stats().ActiveTCPConnections == 1 })
	server.mu.Lock()
	if server.tcp[serverKey] != firstServer {
		server.mu.Unlock()
		t.Fatal("queued connection left the TCP map before Accept")
	}
	server.mu.Unlock()
	if state := firstServer.Info().State; state != TCPStateTimeWait {
		t.Fatalf("queued server state = %v, want TIME-WAIT", state)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if replacement, dialErr := client.DialTCP(ctx, "tcp4", oldLocal, remote); replacement != nil || !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("queued tuple reuse = (%v, %v), want context deadline", replacement, dialErr)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.(*TCPConn) != firstServer {
		t.Fatal("Accept returned a replacement instead of the queued connection")
	}
}

func testTCPHandshake(connection *TCPConn, initialSequence uint32) error {
	timer := newOwnedTimer()
	defer timer.close()
	return connection.handshake(initialSequence, timer, nil)
}

func testTCPPassiveHandshake(connection *TCPConn, syn tcpSegment, initialSequence uint32) error {
	timer := newOwnedTimer()
	defer timer.close()
	return connection.passiveHandshake(syn, initialSequence, timer, tcpHandshakeTimestampRange{})
}

func TestTCPActiveHandshakeProcessesSYNACKText(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.69")
	remote := netip.MustParseAddr("198.51.100.69")
	link, stack := newTestStack(t, local, remote)
	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
		result <- dialResult{connection: connection, err: err}
	}()
	var synPacket []byte
	select {
	case synPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for active SYN")
	}
	parsed, ok := parseIPPacket(synPacket, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("active SYN = %x", synPacket)
	}
	tcp := parsed.payload
	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	clientSequence := binary.BigEndian.Uint32(tcp[4:8])
	payload := []byte("syn-ack text")
	response := buildTestTCP(remote, local, 8080, clientPort, 2000, clientSequence+1, TCPFlagSYN|TCPFlagACK|TCPFlagFIN, 65535, nil, payload)
	if err := writeTestPacket(stack, response); err != nil {
		t.Fatal(err)
	}
	var connection net.Conn
	select {
	case opened := <-result:
		if opened.err != nil {
			t.Fatal(opened.err)
		}
		connection = opened.connection
	case <-time.After(time.Second):
		t.Fatal("SYN-ACK text did not complete active open")
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("SYN-ACK text = %q, want %q", received, payload)
	}
	if n, err := connection.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("SYN-ACK FIN read = %d, %v", n, err)
	}
}

func TestTCPActiveHandshakeRejectsInvalidTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.75")
	remote := netip.MustParseAddr("198.51.100.75")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 45000), remote: netip.AddrPortFrom(remote, 8080),
	}, 1400, tcpSocketOptionSet{})
	result := make(chan error, 1)
	go func() { result <- testTCPHandshake(connection, 1000) }()
	select {
	case synPacket := <-link.outbound:
		parsed, ok := parseIPPacket(synPacket, false)
		if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
			t.Fatalf("active SYN = %x", synPacket)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		clientSequence := binary.BigEndian.Uint32(parsed.payload[4:8])
		clientTimestamp, _, timestampPresent := parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
		if !timestampPresent || clientTimestamp == 0 {
			t.Fatal("active SYN did not carry a Timestamp")
		}
		invalid := tcpSegment{sequence: 2000, acknowledgement: clientSequence + 1, flags: TCPFlagSYN | TCPFlagACK, window: 65535}
		invalid.setOptions(tcpTimestampOptions(300, clientTimestamp+1))
		enqueueTCPTestSegment(t, connection, invalid)
		select {
		case err := <-result:
			t.Fatalf("invalid TSecr completed active handshake with %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		valid := tcpSegment{sequence: 2000, acknowledgement: clientSequence + 1, flags: TCPFlagSYN | TCPFlagACK, window: 65535}
		valid.setOptions(tcpTimestampOptions(300, clientTimestamp))
		enqueueTCPTestSegment(t, connection, valid)
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("valid TSecr did not complete active handshake")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for active SYN")
	}
	connection.abortWithoutReset(net.ErrClosed)
}

func TestTCPActiveHandshakeAcceptsZeroTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.76")
	remote := netip.MustParseAddr("198.51.100.76")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 45001), remote: netip.AddrPortFrom(remote, 8080),
	}, 1400, tcpSocketOptionSet{})
	result := make(chan error, 1)
	go func() { result <- testTCPHandshake(connection, 1000) }()
	select {
	case synPacket := <-link.outbound:
		parsed, ok := parseIPPacket(synPacket, false)
		if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
			t.Fatalf("active SYN = %x", synPacket)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		clientSequence := binary.BigEndian.Uint32(parsed.payload[4:8])
		clientTimestamp, _, timestampPresent := parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
		if !timestampPresent || clientTimestamp == 0 {
			t.Fatal("active SYN did not carry a Timestamp")
		}
		zeroEcho := tcpSegment{sequence: 2001, acknowledgement: clientSequence + 1, flags: TCPFlagSYN | TCPFlagACK, window: 65535}
		zeroEcho.setOptions(tcpTimestampOptions(301, 0))
		enqueueTCPTestSegment(t, connection, zeroEcho)
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("zero TSecr did not complete active handshake")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for active SYN")
	}
	connection.abortWithoutReset(net.ErrClosed)
}

func TestTCPPassiveHandshakeProcessesSYNText(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.70")
	remote := netip.MustParseAddr("198.51.100.70")
	link, stack := newTestStack(t, local, remote)
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	localPort := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	const (
		remotePort     = 45000
		remoteSequence = 100
	)
	payload := []byte("syn text")
	syn := buildTestTCP(remote, local, remotePort, localPort, remoteSequence, 0, TCPFlagSYN|TCPFlagFIN, 65535, nil, payload)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	var synACKPacket []byte
	select {
	case synACKPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive SYN-ACK")
	}
	parsed, ok := parseIPPacket(synACKPacket, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("passive SYN-ACK = %x", synACKPacket)
	}
	tcp := parsed.payload
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	if acknowledgement := binary.BigEndian.Uint32(tcp[8:12]); acknowledgement != remoteSequence+1 {
		t.Fatalf("SYN-ACK acknowledgement = %d, want SYN-only %d", acknowledgement, remoteSequence+1)
	}
	finalSequence := uint32(remoteSequence + 1 + len(payload) + 1)
	finalACK := buildTestTCP(remote, local, remotePort, localPort, finalSequence, serverSequence+1, TCPFlagACK, 65535, nil, nil)
	if err = writeTestPacket(stack, finalACK); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("SYN text = %q, want %q", received, payload)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("SYN FIN read = %d, %v", n, readErr)
	}
}

func TestTCPPassiveHandshakeAcceptsMissingTimestamp(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.72")
	remote := netip.MustParseAddr("198.51.100.72")
	link, stack := newTestStack(t, local, remote)
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	localPort := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	const (
		remotePort      = 45002
		remoteSequence  = 100
		remoteTimestamp = 700
	)
	syn := buildTestTCP(remote, local, remotePort, localPort, remoteSequence, 0, TCPFlagSYN, 65535, tcpTimestampOptions(remoteTimestamp, 0), nil)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	var synACK []byte
	select {
	case synACK = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive timestamp SYN-ACK")
	}
	parsed, ok := parseIPPacket(synACK, false)
	if !ok || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("passive timestamp SYN-ACK = %x", synACK)
	}
	serverSequence := binary.BigEndian.Uint32(parsed.payload[4:8])
	finalACK := buildTestTCP(remote, local, remotePort, localPort, remoteSequence+1, serverSequence+1, TCPFlagACK, 65535, nil, nil)
	if err = writeTestPacket(stack, finalACK); err != nil {
		t.Fatal(err)
	}
	if err = listener.(*TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept without final-ACK timestamp: %v", err)
	}
	defer connection.Close()
	if info := connection.(*TCPConn).Info(); info.State != TCPStateEstablished {
		t.Fatalf("accepted connection state = %v, want established", info.State)
	}
}

func TestTCPPassiveHandshakeAcceptsZeroTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.79")
	remote := netip.MustParseAddr("198.51.100.79")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8081), remote: netip.AddrPortFrom(remote, 45001),
	}, 1400, tcpSocketOptionSet{})
	connection.passive = true
	initialSYN := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	initialSYN.setOptions(tcpTimestampOptions(101, 0))
	result := make(chan error, 1)
	go func() { result <- testTCPPassiveHandshake(connection, initialSYN, 1001) }()
	var serverTimestamp uint32
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
			t.Fatalf("passive SYN-ACK = %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		serverTimestamp, _, ok = parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
		if !ok || serverTimestamp == 0 {
			t.Fatal("passive SYN-ACK did not carry a Timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive SYN-ACK")
	}
	finalACK := tcpSegment{sequence: 101, acknowledgement: 1002, flags: TCPFlagACK, window: 65535}
	finalACK.setOptions(tcpTimestampOptions(202, 0))
	enqueueTCPTestSegment(t, connection, finalACK)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("zero TSecr did not complete passive handshake")
	}
	connection.abortWithoutReset(net.ErrClosed)
}

func TestTCPPassiveHandshakeChallengeAndResetResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		segment   tcpSegment
		wantFlags byte
		wantSeq   uint32
		wantACK   uint32
	}{
		{
			name: "in-window RST", segment: tcpSegment{sequence: 102, flags: TCPFlagRST},
			wantFlags: TCPFlagACK, wantSeq: 1001, wantACK: 101,
		},
		{
			name: "unacceptable ACK", segment: tcpSegment{sequence: 101, acknowledgement: 999, flags: TCPFlagACK},
			wantFlags: TCPFlagRST, wantSeq: 999,
		},
		{
			name: "out-of-window sequence", segment: tcpSegment{sequence: 101 + 65535, acknowledgement: 1001, flags: TCPFlagACK},
			wantFlags: TCPFlagACK, wantSeq: 1001, wantACK: 101,
		},
		{
			name: "unexpected SYN", segment: tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagSYN | TCPFlagACK},
			wantFlags: TCPFlagACK, wantSeq: 1001, wantACK: 101,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.71")
			remote := netip.MustParseAddr("198.51.100.71")
			link, stack := newTestStack(t, local, remote)
			connection := newTCPConn(stack, "tcp4", tcpKey{
				local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
			}, 1400, tcpSocketOptionSet{})

			connection.passive = true
			result := make(chan error, 1)
			go func() {
				result <- testTCPPassiveHandshake(connection, tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}, 1000)
			}()
			readPacket := func() []byte {
				select {
				case packet := <-link.outbound:
					return packet
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for passive-handshake response")
					return nil
				}
			}
			_ = readPacket()
			enqueueTCPTestSegment(t, connection, test.segment)
			response := readPacket()
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive-handshake response = %x", response)
			}
			tcp := parsed.payload
			if tcp[13] != test.wantFlags || binary.BigEndian.Uint32(tcp[4:8]) != test.wantSeq || binary.BigEndian.Uint32(tcp[8:12]) != test.wantACK {
				t.Fatalf("passive-handshake TCP response flags=%02x seq=%d ack=%d", tcp[13], binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]))
			}
			connection.abortWithoutReset(net.ErrClosed)
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("passive handshake did not stop")
			}
		})
	}
}

func TestTCPPassiveHandshakeAcceptsOutOfOrderFinalACKData(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.72")
	remote := netip.MustParseAddr("198.51.100.72")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- testTCPPassiveHandshake(connection, tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}, 1000)
	}()
	select {
	case <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SYN-ACK")
	}
	finalACK := tcpSegment{
		sequence: 102, acknowledgement: 1001, flags: TCPFlagACK, window: 65535,
		payload: []byte{0x42},
	}
	enqueueTCPTestSegment(t, connection, finalACK)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("acceptable out-of-order final ACK did not complete handshake")
	}
	select {
	case <-connection.inbound.notify:
		queued, ok := connection.inbound.dequeue()
		if !ok {
			t.Fatal("out-of-order final ACK notification had no segment")
		}
		if queued.sequence != finalACK.sequence || !bytes.Equal(queued.payload, finalACK.payload) {
			t.Fatalf("queued final ACK = seq %d payload %x", queued.sequence, queued.payload)
		}
	default:
		t.Fatal("out-of-order final ACK data was not queued for established processing")
	}
}

func TestTCPPassiveHandshakeECNFallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.73")
	remote := netip.MustParseAddr("198.51.100.73")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- testTCPPassiveHandshake(connection, tcpSegment{
			sequence: 100, flags: TCPFlagSYN | TCPFlagECE | TCPFlagCWR, window: 65535,
		}, 1000)
	}()
	readFlags := func() byte {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet, false)
			if !ok || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive-handshake response = %x", packet)
			}
			return parsed.payload[13]
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for passive-handshake response")
			return 0
		}
	}
	if flags := readFlags(); flags&TCPFlagECE == 0 {
		t.Fatalf("initial ECN SYN-ACK flags = %02x", flags)
	}
	enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535})
	if flags := readFlags(); flags&TCPFlagECE != 0 {
		t.Fatalf("fallback SYN-ACK retained ECE: flags=%02x", flags)
	}
	enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagACK, window: 65535})
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback final ACK did not complete the passive handshake")
	}
	if connection.peerECN {
		t.Fatal("fallback passive connection retained ECN negotiation")
	}
}

func TestTCPPassiveRetransmittedSYNUpdatesTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.77")
	remote := netip.MustParseAddr("198.51.100.77")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	initialSYN := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	initialSYN.setOptions(tcpTimestampOptions(100, 0))
	go func() {
		result <- testTCPPassiveHandshake(connection, initialSYN, 1000)
	}()
	readTimestamp := func() (uint32, uint32) {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet, false)
			if !ok || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive SYN-ACK = %x", packet)
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			value, echo, present := parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
			if !present {
				t.Fatal("passive SYN-ACK omitted negotiated timestamp")
			}
			return value, echo
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for timestamp SYN-ACK")
			return 0, 0
		}
	}
	if _, echo := readTimestamp(); echo != 100 {
		t.Fatalf("initial SYN-ACK TSecr = %d, want 100", echo)
	}
	retransmittedSYN := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	retransmittedSYN.setOptions(tcpTimestampOptions(200, 0))
	enqueueTCPTestSegment(t, connection, retransmittedSYN)
	serverTimestamp, echo := readTimestamp()
	if echo != 200 {
		t.Fatalf("retransmitted SYN-ACK TSecr = %d, want 200", echo)
	}
	finalACK := tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagACK, window: 65535}
	finalACK.setOptions(tcpTimestampOptions(300, serverTimestamp))
	enqueueTCPTestSegment(t, connection, finalACK)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timestamp handshake did not complete")
	}
}

func TestTCPPassiveHandshakeRejectsInvalidTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.78")
	remote := netip.MustParseAddr("198.51.100.78")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400, tcpSocketOptionSet{})
	connection.passive = true
	initialSYN := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	initialSYN.setOptions(tcpTimestampOptions(100, 0))
	result := make(chan error, 1)
	go func() { result <- testTCPPassiveHandshake(connection, initialSYN, 1000) }()
	var serverTimestamp uint32
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
			t.Fatalf("passive SYN-ACK = %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		serverTimestamp, _, ok = parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
		if !ok || serverTimestamp == 0 {
			t.Fatal("passive SYN-ACK did not carry a Timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive SYN-ACK")
	}
	invalid := tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagACK, window: 65535}
	invalid.setOptions(tcpTimestampOptions(300, serverTimestamp+1))
	enqueueTCPTestSegment(t, connection, invalid)
	select {
	case err := <-result:
		t.Fatalf("invalid final-ACK TSecr completed passive handshake with %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	valid := tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagACK, window: 65535}
	valid.setOptions(tcpTimestampOptions(300, serverTimestamp))
	enqueueTCPTestSegment(t, connection, valid)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("valid final-ACK TSecr did not complete passive handshake")
	}
	connection.abortWithoutReset(net.ErrClosed)
}

func TestTCPHandshakeMaintenanceDoesNotConsumeRTOBudget(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.75")
	remote := netip.MustParseAddr("198.51.100.75")
	t.Run("active PMTU updates", func(t *testing.T) {
		link, stack := newTestStack(t, local, remote)
		connection := newTCPConn(stack, "tcp4", tcpKey{
			local: netip.AddrPortFrom(local, 45000), remote: netip.AddrPortFrom(remote, 8080),
		}, 1400, tcpSocketOptionSet{})

		result := make(chan error, 1)
		go func() { result <- testTCPHandshake(connection, 1000) }()
		read := func() byte {
			select {
			case packet := <-link.outbound:
				parsed, ok := parseIPPacket(packet, false)
				if !ok || len(parsed.payload) < tcpHeaderSize {
					t.Fatalf("active-handshake packet = %x", packet)
				}
				return parsed.payload[13]
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for active SYN")
				return 0
			}
		}
		if flags := read(); flags&(TCPFlagECE|TCPFlagCWR) != TCPFlagECE|TCPFlagCWR {
			t.Fatalf("initial SYN flags = %02x", flags)
		}
		for index := 0; index < tcpActiveSYNMaximumAttempts+1; index++ {
			connection.wakeActor(tcpActorWakePathMTU)
			if flags := read(); flags&(TCPFlagECE|TCPFlagCWR) != TCPFlagECE|TCPFlagCWR {
				t.Fatalf("maintenance SYN %d flags = %02x", index, flags)
			}
		}
		if flags := read(); flags&(TCPFlagECE|TCPFlagCWR) != 0 {
			t.Fatalf("RTO fallback SYN flags = %02x", flags)
		}
		enqueueTCPTestSegment(t, connection, tcpSegment{
			sequence: 2000, acknowledgement: 1001, flags: TCPFlagSYN | TCPFlagACK, window: 65535,
		})
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("active handshake did not recover after maintenance retransmissions")
		}
	})

	t.Run("passive duplicate SYNs", func(t *testing.T) {
		link, stack := newTestStack(t, local, remote)
		connection := newTCPConn(stack, "tcp4", tcpKey{
			local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
		}, 1400, tcpSocketOptionSet{})

		connection.passive = true
		syn := tcpSegment{sequence: 100, flags: TCPFlagSYN | TCPFlagECE | TCPFlagCWR, window: 65535}
		result := make(chan error, 1)
		go func() { result <- testTCPPassiveHandshake(connection, syn, 1000) }()
		read := func() {
			select {
			case <-link.outbound:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for passive SYN-ACK")
			}
		}
		read()
		for index := 0; index < tcpPassiveSYNMaximumAttempts+1; index++ {
			enqueueTCPTestSegment(t, connection, syn)
			read()
		}
		read()
		enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 101, acknowledgement: 1001, flags: TCPFlagACK, window: 65535})
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("passive handshake did not recover after duplicate SYNs")
		}
	})
}

func TestTCPStandardOperationErrors(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	if _, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPort{}); err == nil {
		t.Fatal("invalid DialTCP succeeded")
	} else {
		checkNetOpError(t, err, "dial", "tcp")
	}
	if _, err := stack.DialTCP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 80)); err == nil {
		t.Fatal("DialTCP with UDP network succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialTCP unknown network error = %v", err)
		}
	}
	if _, err := stack.DialTCP(context.Background(), "tcp6", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 80)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("DialTCP family mismatch = %v, want EAFNOSUPPORT", err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8088))
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close error = %v", err)
	} else {
		checkNetOpError(t, err, "close", "tcp")
	}
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "read", "tcp")
	}
	if _, err = connection.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "write", "tcp")
	}
	if err = connection.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "set", "tcp")
	}
}

func TestTCPCloseReadKeepsReceiveWindow(t *testing.T) {
	connection := &TCPConn{readNotify: make(chan struct{}), receiveCapacity: tcpReceiveCapacity}
	if err := connection.CloseRead(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("discarded peer data")
	if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != len(payload) {
		t.Fatalf("discarded bytes accepted = %d, want %d", accepted, len(payload))
	}
	if window := connection.receiveWindow(0, true); window == 0 {
		t.Fatal("CloseRead advertised a zero receive window")
	}
	if connection.readBuffer.size != 0 {
		t.Fatal("CloseRead retained discarded peer data")
	}
}

func TestTCPWindowUpdateOrdering(t *testing.T) {
	const scale = uint8(2)
	tests := []struct {
		name                                        string
		ackAdvanced                                 bool
		sequence, lastSequence                      uint32
		advertisedWindow, currentWindow, wantWindow uint32
		want                                        bool
	}{
		{name: "advanced ACK beats old sequence", ackAdvanced: true, sequence: 99, lastSequence: 100, advertisedWindow: 1, currentWindow: 4096, wantWindow: 4, want: true},
		{name: "old sequence", sequence: 99, lastSequence: 100, advertisedWindow: 65535, currentWindow: 4096, want: false},
		{name: "same sequence shrinks nonzero window", sequence: 100, lastSequence: 100, advertisedWindow: 512, currentWindow: 4096, wantWindow: 2048},
		{name: "same sequence grows window", sequence: 100, lastSequence: 100, advertisedWindow: 2048, currentWindow: 4096, wantWindow: 8192, want: true},
		{name: "same sequence closes window", sequence: 100, lastSequence: 100, advertisedWindow: 0, currentWindow: 4096, want: true},
		{name: "new sequence", sequence: 101, lastSequence: 100, advertisedWindow: 1, currentWindow: 4096, wantWindow: 4, want: true},
		{name: "sequence wrap", sequence: 1, lastSequence: ^uint32(0), advertisedWindow: 1, currentWindow: 4096, wantWindow: 4, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			window, got := tcpWindowUpdate(test.ackAdvanced, test.sequence, test.lastSequence, uint16(test.advertisedWindow), scale, test.currentWindow)
			if got != test.want || got && window != test.wantWindow {
				t.Fatalf("tcpWindowUpdate = (%d, %v), want (%d, %v)", window, got, test.wantWindow, test.want)
			}
		})
	}
}

func TestTCPDuplicateACKEvidence(t *testing.T) {
	pure := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 200}
	tests := []struct {
		name                          string
		segment                       tcpSegment
		peerSACK, newSACK, advanced   bool
		previousWindow, currentWindow uint32
		want                          bool
	}{
		{name: "classic pure", segment: pure, previousWindow: 200, currentWindow: 200, want: true},
		{name: "classic cumulative", segment: pure, advanced: true, previousWindow: 200, currentWindow: 200},
		{name: "classic window update", segment: pure, previousWindow: 199, currentWindow: 200},
		{name: "classic data", segment: tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 200, payload: []byte{1}}, previousWindow: 200, currentWindow: 200},
		{name: "classic FIN", segment: tcpSegment{acknowledgement: 100, flags: TCPFlagACK | TCPFlagFIN, window: 200}, previousWindow: 200, currentWindow: 200},
		{name: "SACK pure without new block", segment: pure, peerSACK: true, previousWindow: 200, currentWindow: 200},
		{name: "SACK new block", segment: pure, peerSACK: true, newSACK: true, previousWindow: 200, currentWindow: 200, want: true},
		{name: "SACK cumulative data and window update", segment: tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 200, payload: []byte{1}}, peerSACK: true, newSACK: true, advanced: true, previousWindow: 199, currentWindow: 200, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpDuplicateACKEvidence(test.segment, test.peerSACK, test.newSACK, test.advanced, 100, test.previousWindow, test.currentWindow); got != test.want {
				t.Fatalf("tcpDuplicateACKEvidence = %v, want %v", got, test.want)
			}
		})
	}
}

func TestTCPAcceptableSendSequence(t *testing.T) {
	tests := []struct {
		name                         string
		unacknowledged, next, window uint32
		scale                        uint8
		want                         uint32
	}{
		{name: "open window", unacknowledged: 100, next: 200, window: 200, scale: 2, want: 200},
		{name: "shrunken window", unacknowledged: 100, next: 200, window: 0, scale: 2, want: 100},
		{name: "zero window below scale quantum", unacknowledged: 100, next: 102, window: 0, scale: 8, want: 100},
		{name: "scaling precision", unacknowledged: 100, next: 200, window: 97, scale: 2, want: 200},
		{name: "wrapped open window", unacknowledged: 0xfffffff0, next: 16, window: 64, scale: 0, want: 16},
		{name: "wrapped shrunken window", unacknowledged: 0xfffffff0, next: 16, window: 0, scale: 0, want: 0xfffffff0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpAcceptableSendSequence(test.unacknowledged, test.next, test.window, test.scale); got != test.want {
				t.Fatalf("tcpAcceptableSendSequence(%d, %d, %d, %d) = %d, want %d", test.unacknowledged, test.next, test.window, test.scale, got, test.want)
			}
		})
	}
}

func TestTCPChallengeACKSequence(t *testing.T) {
	segment := tcpSegment{flags: TCPFlagACK, acknowledgement: 150, window: 0}
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 150 {
		t.Fatalf("zero-window challenge sequence = %d, want 150", got)
	}
	segment.window = 20
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 200 {
		t.Fatalf("open-window challenge sequence = %d, want 200", got)
	}
	segment.acknowledgement = 201
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 100 {
		t.Fatalf("invalid-ACK challenge sequence = %d, want 100", got)
	}
	segment.acknowledgement = 150
	segment.flags |= TCPFlagFIN
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 100 {
		t.Fatalf("non-pure challenge sequence = %d, want 100", got)
	}
	segment.payload = tcpZeroWindowProbe[:]
	if got := tcpChallengeACKSequence(segment, 100, 200, 40, 2); got != 140 {
		t.Fatalf("peer-probe challenge sequence = %d, want 140", got)
	}
}

func TestTCPSegmentAcceptability(t *testing.T) {
	if !tcpSegmentAcceptable(100, 0, 100, 0) || tcpSegmentAcceptable(100, 1, 100, 0) {
		t.Fatal("zero-window segment acceptance is incorrect")
	}
	if !tcpSegmentAcceptable(99, 2, 100, 10) {
		t.Fatal("segment overlapping the left window edge was rejected")
	}
	if tcpSegmentAcceptable(110, 1, 100, 10) {
		t.Fatal("segment beyond the right window edge was accepted")
	}
	if !tcpSegmentAcceptable(0xfffffff8, 16, 0, 32) {
		t.Fatal("wrapped segment overlapping the receive window was rejected")
	}
}

func TestTCPResetExceptions(t *testing.T) {
	for _, test := range []struct {
		name                   string
		next, sequence, window uint32
		sack                   bool
		pieces                 []tcpReceivedPiece
		want                   bool
	}{
		{name: "exact is not an exception", next: 100, sequence: 100, window: 64},
		{name: "zero window exact is not an exception", next: 100, sequence: 100},
		{name: "in window nonexact", next: 100, sequence: 101, window: 64},
		{name: "before window", next: 100, sequence: 99, window: 64},
		{name: "window right without SACK", next: 100, sequence: 164, window: 64},
		{name: "empty SACK", next: 100, sequence: 124, window: 64, sack: true},
		{name: "SACK not negotiated", next: 100, sequence: 124, window: 64, pieces: []tcpReceivedPiece{{sequence: 120, payload: []byte("tail")}}},
		{name: "SACK right", next: 100, sequence: 124, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 120, payload: []byte("tail")}}, want: true},
		{name: "SACK exclusive window right", next: 100, sequence: 164, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 160, payload: []byte("tail")}}, want: true},
		{name: "SACK beyond window", next: 100, sequence: 165, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 161, payload: []byte("tail")}}},
		{name: "SACK lower end", next: 100, sequence: 108, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 104, payload: []byte("head")}, {sequence: 120, payload: []byte("tail")}}},
		{name: "SACK highest end", next: 100, sequence: 124, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 104, payload: []byte("head")}, {sequence: 120, payload: []byte("tail")}}, want: true},
		{name: "SACK interior", next: 100, sequence: 123, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 120, payload: []byte("tail")}}},
		{name: "SACK data and FIN", next: 100, sequence: 125, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 120, payload: []byte("tail"), fin: true}}, want: true},
		{name: "SACK FIN only", next: 100, sequence: 121, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 120, fin: true}}, want: true},
		{name: "unconsumed FIN sequence", next: 100, sequence: 120, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 120, fin: true}}},
		{name: "wrapped exact is not an exception", next: 0, sequence: 0, window: 64},
		{name: "wrapped SACK right", next: 0xfffffff0, sequence: 4, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 0, payload: []byte("tail")}}, want: true},
		{name: "wrapped SACK window right", next: 0xfffffff0, sequence: 48, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 44, payload: []byte("tail")}}, want: true},
		{name: "wrapped SACK below next", next: 4, sequence: 0, window: 64, sack: true, pieces: []tcpReceivedPiece{{sequence: 0xfffffffc, payload: []byte("tail")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := tcpEstablishedState{receiveNext: test.next, peerSACK: test.sack, outOfOrder: test.pieces}
			if got := state.acceptsResetException(test.sequence, test.window); got != test.want {
				t.Fatalf("acceptsResetException(%d, %d) = %t, want %t", test.sequence, test.window, got, test.want)
			}
		})
	}
}

func TestTCPResetFINStates(t *testing.T) {
	for _, test := range []struct {
		name  string
		state tcpEstablishedState
		want  bool
	}{
		{name: "established"},
		{name: "close wait", state: tcpEstablishedState{remoteFINReceived: true}, want: true},
		{name: "last ack", state: tcpEstablishedState{remoteFINReceived: true, localFINSent: true}, want: true},
		{name: "closing", state: tcpEstablishedState{remoteFINReceived: true, localFINSent: true, timeWaitRequired: true}, want: true},
		{name: "fin wait 1", state: tcpEstablishedState{localFINSent: true, timeWaitRequired: true}},
		{name: "fin wait 2", state: tcpEstablishedState{localFINSent: true, localFINAcked: true, timeWaitRequired: true}},
		{name: "time wait", state: tcpEstablishedState{remoteFINReceived: true, localFINSent: true, localFINAcked: true, timeWaitArmed: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, next := range []uint32{100, 0} {
				state := test.state
				state.receiveNext = next
				for _, window := range []uint32{0, 64} {
					if got := state.acceptsResetException(next-1, window); got != test.want {
						t.Fatalf("FIN reset at next=%d window=%d = %t, want %t", next, window, got, test.want)
					}
				}
			}
		})
	}
}

func TestTCPResetPreservesZeroWindowAdmission(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("192.0.2.34"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connected, err := (&Dialer{Options: []SocketOption{SocketOptions.ReadBuffer(1)}}).DialTCP(
		ctx, stack, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	connection := connected.(*TCPConn)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	clientPort := connection.key.local.Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.echoTCP = false
	link.mu.Unlock()
	_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte("x"))
	deadline := time.After(time.Second)
	zeroWindow := false
	for !zeroWindow {
		select {
		case wire := <-link.outbound:
			packet, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil {
				t.Fatal(err)
			}
			zeroWindow = segment.Flags == TCPFlagACK && segment.AcknowledgmentNumber == sequence+1 && segment.WindowSize == 0
		case <-deadline:
			t.Fatal("buffered data did not produce a zero-window ACK")
		}
	}
	_ = link.deliverTCP(8080, clientPort, sequence+1, acknowledgement, TCPFlagRST, 0, nil, []byte("diagnostic"))
	_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil)
	select {
	case wire := <-link.outbound:
		packet, err := ParseIPPacket(wire)
		if err != nil {
			t.Fatal(err)
		}
		segment, err := packet.TCPSegment()
		if err != nil || segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence+1 || segment.WindowSize != 0 {
			t.Fatalf("keepalive after diagnostic RST = %+v, %v, want zero-window ACK", segment, err)
		}
	case <-time.After(time.Second):
		t.Fatal("diagnostic RST at zero window prevented the keepalive ACK")
	}
	if info := connection.Info(); info.State != TCPStateEstablished || info.ReceiveBufferSize != 1 || info.ReceiveWindow != 0 {
		t.Fatalf("state after diagnostic RST at zero window = %+v", info)
	}
	_ = link.deliverTCP(8080, clientPort, sequence+1, acknowledgement, TCPFlagRST, 0, nil, nil)
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("empty exact RST at zero window did not terminate the connection")
	}
	var got [1]byte
	if n, err := connection.Read(got[:]); n != 1 || err != nil || got[0] != 'x' {
		t.Fatalf("buffered data after empty RST = %d, %v, %q", n, err, got)
	}
	if n, err := connection.Read(got[:]); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read after empty RST at zero window = %d, %v, want ECONNRESET", n, err)
	}
}

func TestTCPActiveHandshakeReopensScaledZeroWindow(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.35")
	remote := netip.MustParseAddr("192.0.2.36")
	link := &testPacketLink{
		local: local, remote: remote, echoTCP: true,
		outbound: make(chan []byte, 32), tcp: make(map[uint16]*testTCPPeer),
		done: make(chan struct{}),
	}
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		MTU:            1400,
		TCP:            TCPSocketDefaults{ReceiveBuffer: 1, MaximumReceiveBuffer: 2 * 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		t.Fatal(err)
	}
	link.stack = stack
	go link.run()
	t.Cleanup(func() {
		_ = stack.Close()
		<-link.done
	})

	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8035))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	t.Cleanup(func() { _ = connection.Close() })
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		window := link.lastClientWindow
		link.mu.Unlock()
		return window != 0
	})
	if info := tcpConnection.Info(); info.ReceiveWindow == 0 || info.ReceiveWindowScale == 0 {
		t.Fatalf("active handshake receive window = %d, scale = %d; want a quantized non-zero window", info.ReceiveWindow, info.ReceiveWindowScale)
	}

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	if peer == nil {
		link.mu.Unlock()
		t.Fatal("TCP peer state was not created")
	}
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	info := tcpConnection.Info()
	if info.ReceiveWindowScale == 0 {
		t.Fatalf("active handshake receive scale = %d, want non-zero", info.ReceiveWindowScale)
	}
	quantum := 1 << info.ReceiveWindowScale
	firstPayload := bytes.Repeat([]byte{'x'}, quantum)
	link.mu.Lock()
	zeroWindowACKs := link.clientACKs
	link.mu.Unlock()
	if err := link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, firstPayload); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return tcpConnection.Info().ReceiveWindow == 0
	})
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > zeroWindowACKs && link.lastClientWindow == 0
	})
	if buffered := tcpConnection.Info().ReceiveBufferSize; buffered != quantum {
		t.Fatalf("scaled zero-window buffered bytes = %d, want %d", buffered, quantum)
	}
	if err := tcpConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := tcpConnection.Read(firstPayload); n != quantum || err != nil || !bytes.Equal(firstPayload, bytes.Repeat([]byte{'x'}, quantum)) {
		t.Fatalf("data after scaled zero-window admission = %d, %v", n, err)
	}
	link.mu.Lock()
	openedWindowACKs := link.clientACKs
	link.mu.Unlock()
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > openedWindowACKs && link.lastClientWindow != 0
	})
	secondPayload := bytes.Repeat([]byte{'y'}, quantum)
	if err := link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+uint32(quantum), acknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, secondPayload); err != nil {
		t.Fatal(err)
	}
	if n, err := tcpConnection.Read(secondPayload); n != quantum || err != nil || !bytes.Equal(secondPayload, bytes.Repeat([]byte{'y'}, quantum)) {
		t.Fatalf("data after scaled zero-window reopening = %d, %v", n, err)
	}
}

func TestTCPResetAtConsumedFIN(t *testing.T) {
	for _, closingState := range []TCPState{TCPStateCloseWait, TCPStateLastACK, TCPStateClosing} {
		for _, reset := range []struct {
			name    string
			flags   byte
			payload []byte
		}{
			{name: "RST", flags: TCPFlagRST},
			{name: "RST-ACK", flags: TCPFlagRST | TCPFlagACK},
			{name: "diagnostic-payload", flags: TCPFlagRST, payload: []byte("diagnostic")},
		} {
			t.Run(fmt.Sprintf("%s/%s", closingState, reset.name), func(t *testing.T) {
				link, stack, connection := newManuallyPumpedTCPConnection(t)
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				clientPort := connection.key.local.Port()
				peer := link.tcp[clientPort]
				finSequence, acknowledgement := peer.serverNext, peer.clientNext
				if closingState == TCPStateClosing {
					_ = connection.CloseWrite()
					waitFor(t, time.Second, func() bool { return connection.Info().State == TCPStateFINWait1 })
				}
				_ = link.deliverTCP(8080, clientPort, finSequence, acknowledgement, TCPFlagFIN|TCPFlagACK, 65535, nil, nil)
				var buffer [1]byte
				if n, err := connection.Read(buffer[:]); n != 0 || err != io.EOF {
					t.Fatalf("Read after peer FIN = %d, %v, want EOF", n, err)
				}
				if closingState == TCPStateLastACK {
					_ = connection.CloseWrite()
				}
				waitFor(t, time.Second, func() bool { return connection.Info().State == closingState })
				if closingState != TCPStateCloseWait {
					for {
						packet, err := ParseIPPacket(readOutboundPacket(t, stack))
						if err != nil {
							t.Fatal(err)
						}
						segment, err := packet.TCPSegment()
						if err != nil {
							t.Fatal(err)
						}
						if segment.Flags&TCPFlagFIN != 0 {
							break
						}
					}
				}
				_ = link.deliverTCP(8080, clientPort, finSequence, acknowledgement, reset.flags, 0, nil, reset.payload)
				select {
				case <-connection.done:
				case <-time.After(time.Second):
					t.Fatal("reset using the consumed FIN sequence did not terminate the connection")
				}
				if info := connection.Info(); info.State != TCPStateClosed || !errors.Is(info.LastError, syscall.ECONNRESET) {
					t.Fatalf("state after FIN-sequence reset = %+v", info)
				}
			})
		}
	}
}

func TestTCPResetAtSACKRightEdge(t *testing.T) {
	for _, test := range []struct {
		windowEdge bool
		payload    string
	}{{false, ""}, {true, ""}, {false, "diagnostic"}, {true, "diagnostic"}} {
		t.Run(fmt.Sprintf("window-edge-%t/payload-%t", test.windowEdge, test.payload != ""), func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			info := connection.Info()
			if !info.SACK {
				t.Fatal("handshake did not negotiate SACK")
			}
			clientPort := connection.key.local.Port()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			right := sequence + 24
			if test.windowEdge {
				right = sequence + info.ReceiveWindow
			}
			_ = link.deliverTCP(8080, clientPort, right-4, acknowledgement, TCPFlagACK, 65535, nil, []byte("tail"))
			packet, err := ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil {
				t.Fatal(err)
			}
			options, err := segment.HeaderOptions()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, option := range options {
				if blocks, ok := option.SACKBlocks(); ok {
					for _, block := range blocks {
						found = found || block.LeftEdge == right-4 && block.RightEdge == right
					}
				}
			}
			if !found || segment.AcknowledgmentNumber != sequence {
				t.Fatalf("ACK did not advertise retained SACK range [%d,%d): %+v", right-4, right, segment)
			}
			if test.windowEdge && right != sequence+uint32(segment.WindowSize)<<info.ReceiveWindowScale {
				t.Fatal("SACK endpoint no longer coincides with the advertised receive-window edge")
			}
			_ = link.deliverTCP(8080, clientPort, right, acknowledgement, TCPFlagRST|TCPFlagACK, 0, nil, []byte(test.payload))
			if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("Read after SACK-edge reset = %d, %v, want ECONNRESET", n, err)
			}
		})
	}
}

func TestTCPResetUsesNormalizedSACKBoundary(t *testing.T) {
	for _, truncateAtFIN := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncate-at-FIN-%t", truncateAtFIN), func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			clientPort := connection.key.local.Port()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			var wire []byte
			for _, offset := range []uint32{44, 4, 36, 12, 28, 20} {
				_ = link.deliverTCP(8080, clientPort, sequence+offset, acknowledgement, TCPFlagACK, 65535, nil, []byte("data"))
				wire = readOutboundPacket(t, stack)
			}
			packet, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil {
				t.Fatal(err)
			}
			options, err := segment.HeaderOptions()
			if err != nil {
				t.Fatal(err)
			}
			var blocks []TCPSACKBlock
			for _, option := range options {
				if sack, ok := option.SACKBlocks(); ok {
					blocks = sack
				}
			}
			highest := TCPSACKBlock{LeftEdge: sequence + 44, RightEdge: sequence + 48}
			found := false
			for _, block := range blocks {
				found = found || block == highest
			}
			if segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence || len(blocks) != 4 ||
				blocks[0] != (TCPSACKBlock{LeftEdge: sequence + 20, RightEdge: sequence + 24}) || !found {
				t.Fatalf("ACK after reordered ranges = %+v, SACK %+v", segment, blocks)
			}
			right, rejected := highest.RightEdge, sequence+24
			if truncateAtFIN {
				_ = link.deliverTCP(8080, clientPort, sequence+10, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil)
				packet, err = ParseIPPacket(readOutboundPacket(t, stack))
				if err != nil {
					t.Fatal(err)
				}
				segment, err = packet.TCPSegment()
				if err != nil {
					t.Fatal(err)
				}
				options, err = segment.HeaderOptions()
				if err != nil {
					t.Fatal(err)
				}
				blocks = nil
				for _, option := range options {
					if sack, ok := option.SACKBlocks(); ok {
						blocks = sack
					}
				}
				if segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence || len(blocks) != 2 ||
					blocks[0] != (TCPSACKBlock{LeftEdge: sequence + 10, RightEdge: sequence + 11}) ||
					blocks[1] != (TCPSACKBlock{LeftEdge: sequence + 4, RightEdge: sequence + 8}) {
					t.Fatalf("ACK after FIN truncation = %+v, SACK %+v", segment, blocks)
				}
				right, rejected = sequence+11, highest.RightEdge
			}
			_ = link.deliverTCP(8080, clientPort, rejected, acknowledgement, TCPFlagRST, 0, nil, nil)
			packet, err = ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			segment, err = packet.TCPSegment()
			if err != nil || segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence {
				t.Fatalf("reset at nonmaximum or truncated boundary = %+v, %v, want challenge ACK", segment, err)
			}
			_ = link.deliverTCP(8080, clientPort, right, acknowledgement, TCPFlagRST, 0, nil, nil)
			if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("Read after normalized SACK-edge reset = %d, %v, want ECONNRESET", n, err)
			}
		})
	}
}

func TestTCPResetRejectsOtherSACKBoundaries(t *testing.T) {
	for _, offset := range []uint32{8, 23, 25} {
		t.Run(fmt.Sprintf("offset-%d", offset), func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			clientPort := connection.key.local.Port()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			for _, piece := range []struct {
				offset  uint32
				payload string
			}{{4, "head"}, {20, "tail"}} {
				_ = link.deliverTCP(8080, clientPort, sequence+piece.offset, acknowledgement, TCPFlagACK, 65535, nil, []byte(piece.payload))
				_ = readOutboundPacket(t, stack)
			}
			_ = link.deliverTCP(8080, clientPort, sequence+offset, acknowledgement, TCPFlagRST, 0, nil, nil)
			packet, err := ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil || segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence {
				t.Fatalf("nonexact reset response = %+v, %v, want challenge ACK", segment, err)
			}
			payload := bytes.Repeat([]byte{'_'}, 24)
			copy(payload[4:], "head")
			copy(payload[20:], "tail")
			_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("stream after rejected reset = %q, %v, want %q", got, err, payload)
			}
		})
	}
}

func TestTCPResetRequiresRetainedReceiveBoundary(t *testing.T) {
	for _, scenario := range []string{"discarded", "consumed", "DSACK"} {
		t.Run(scenario, func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			clientPort := connection.key.local.Port()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			next := sequence
			wantRetained := int64(0)
			if scenario == "discarded" {
				_ = connection.SetReadBuffer(1)
				wantRetained = 1
			}
			_ = link.deliverTCP(8080, clientPort, sequence+20, acknowledgement, TCPFlagACK, 65535, nil, []byte("tail"))
			_ = readOutboundPacket(t, stack)
			if scenario != "discarded" {
				payload := bytes.Repeat([]byte{'_'}, 32)
				copy(payload[20:], "tail")
				_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, payload)
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("consume retained range = %q, %v", got, err)
				}
				next += uint32(len(payload))
				_ = readOutboundPacket(t, stack)
				if scenario == "DSACK" {
					duplicate := bytes.Repeat([]byte{'d'}, 16)
					copy(duplicate, payload[20:])
					_ = link.deliverTCP(8080, clientPort, sequence+20, acknowledgement, TCPFlagACK, 65535, nil, duplicate)
					var got [4]byte
					if _, err := io.ReadFull(connection, got[:]); err != nil || string(got[:]) != "dddd" {
						t.Fatalf("Read new bytes after duplicate overlap = %q, %v", got, err)
					}
					next += 4
					packet, err := ParseIPPacket(readOutboundPacket(t, stack))
					if err != nil {
						t.Fatal(err)
					}
					segment, err := packet.TCPSegment()
					if err != nil {
						t.Fatal(err)
					}
					options, err := segment.HeaderOptions()
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, option := range options {
						if blocks, ok := option.SACKBlocks(); ok {
							found = len(blocks) != 0 && blocks[0] == (TCPSACKBlock{LeftEdge: sequence + 20, RightEdge: sequence + 32})
						}
					}
					if !found {
						t.Fatal("duplicate data did not produce the expected DSACK")
					}
				}
			}
			if bytes := connection.outOfOrderUnread.Load(); bytes != wantRetained {
				t.Fatalf("retained receive bytes = %d, want %d", bytes, wantRetained)
			}
			right := sequence + 24
			if scenario == "DSACK" {
				right = sequence + 32
			}
			_ = link.deliverTCP(8080, clientPort, right, acknowledgement, TCPFlagRST, 0, nil, nil)
			_ = link.deliverTCP(8080, clientPort, next, acknowledgement, TCPFlagACK, 65535, nil, []byte("x"))
			var got [1]byte
			if n, err := connection.Read(got[:]); n != 1 || err != nil || got[0] != 'x' {
				t.Fatalf("Read after obsolete-boundary reset = %d, %v, %q", n, err, got)
			}
		})
	}
}

func TestTCPResetAtOutOfOrderFIN(t *testing.T) {
	for _, finSequence := range []bool{true, false} {
		t.Run(fmt.Sprintf("FIN-sequence-%t", finSequence), func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			clientPort := connection.key.local.Port()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			_ = link.deliverTCP(8080, clientPort, sequence+4, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil)
			_ = readOutboundPacket(t, stack)
			right := sequence + 5
			if finSequence {
				right--
			}
			_ = link.deliverTCP(8080, clientPort, right, acknowledgement, TCPFlagRST, 0, nil, nil)
			if !finSequence {
				if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("Read after FIN SACK-end reset = %d, %v", n, err)
				}
				return
			}
			packet, err := ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil || segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence {
				t.Fatalf("reset at unconsumed FIN = %+v, %v, want challenge ACK", segment, err)
			}
			_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte("gap!"))
			var got [4]byte
			if _, err := io.ReadFull(connection, got[:]); err != nil || string(got[:]) != "gap!" {
				t.Fatalf("Read after filling FIN gap = %q, %v", got, err)
			}
			if n, err := connection.Read(got[:1]); n != 0 || err != io.EOF {
				t.Fatalf("Read after promoting FIN = %d, %v, want EOF", n, err)
			}
		})
	}
}

func TestTCPResetWithoutSACKNegotiation(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32"))
	link.mu.Lock()
	link.echoTCP, link.timestampTCP = true, true
	link.disableTCPSACK = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	tcpConnection := connection.(*TCPConn)
	if info := tcpConnection.Info(); info.SACK || !info.Timestamps {
		t.Fatalf("handshake options = SACK:%t timestamps:%t", info.SACK, info.Timestamps)
	}
	clientPort := tcpConnection.key.local.Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.echoTCP = false
	link.mu.Unlock()
	_ = link.deliverTCP(8080, clientPort, sequence+20, acknowledgement, TCPFlagACK, 65535, nil, []byte("tail"))
	select {
	case <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("out-of-order data did not elicit an ACK")
	}
	reset := buildTestTCP(link.remote, link.local, 8080, clientPort, sequence+24, acknowledgement, TCPFlagRST, 0, tcpTimestampOptions(0, 0), nil)
	_ = writeTestPacket(stack, reset)
	select {
	case wire := <-link.outbound:
		packet, err := ParseIPPacket(wire)
		if err != nil {
			t.Fatal(err)
		}
		segment, err := packet.TCPSegment()
		if err != nil || segment.Flags != TCPFlagACK || segment.AcknowledgmentNumber != sequence {
			t.Fatalf("unnegotiated SACK-edge reset = %+v, %v, want challenge ACK", segment, err)
		}
	case <-time.After(time.Second):
		t.Fatal("nonexact reset did not elicit a challenge ACK")
	}
	payload := bytes.Repeat([]byte{'_'}, 24)
	copy(payload[20:], "tail")
	_ = link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Read after rejected reset = %q, %v", got, err)
	}
	_ = writeTestPacket(stack, reset)
	if n, err := connection.Read(got[:1]); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read after exact stale-timestamp reset = %d, %v", n, err)
	}
}

func TestTCPResetUsesRetainedSACKWithoutPublishedACK(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	clientPort := connection.key.local.Port()
	peer := link.tcp[clientPort]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	_ = link.deliverTCP(8080, clientPort, sequence+20, acknowledgement, TCPFlagACK, 65535, nil, []byte("tail"))
	waitFor(t, time.Second, func() bool { return connection.outOfOrderUnread.Load() == 4 })
	if bytes := connection.outOfOrderUnread.Load(); bytes != 4 {
		t.Fatalf("retained receive bytes = %d, want 4", bytes)
	}
	if stack.outbound.len() != cap(stack.outbound.free) {
		t.Fatal("output queue unexpectedly allowed a SACK ACK")
	}
	_ = link.deliverTCP(8080, clientPort, sequence+24, acknowledgement, TCPFlagRST, 0, nil, nil)
	if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read after retained-SACK reset with blocked output = %d, %v", n, err)
	}
}

func BenchmarkTCPResetValidation(b *testing.B) {
	for _, count := range []int{0, 1, tcpMaximumOutOfOrder} {
		b.Run(fmt.Sprintf("ranges-%d", count), func(b *testing.B) {
			state := tcpEstablishedState{receiveNext: 100, peerSACK: true}
			for index := 0; index < count; index++ {
				state.outOfOrder = append(state.outOfOrder, tcpReceivedPiece{sequence: 104 + uint32(index)*8, payload: []byte("data")})
			}
			sequence := uint32(101)
			if count != 0 {
				sequence = 108 + uint32(count-1)*8
			}
			accepted := 0
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if state.acceptsResetException(sequence, 65535) {
					accepted++
				}
			}
			b.StopTimer()
			if count != 0 && accepted != b.N || count == 0 && accepted != 0 {
				b.Fatal("unexpected reset admission")
			}
		})
	}
}

func TestTCPKeepAliveAndWindowProbeClassification(t *testing.T) {
	const receiveNext = uint32(100)
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: TCPFlagACK}, 0, receiveNext, 4096) {
		t.Fatal("keepalive probe was not recognized")
	}
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: TCPFlagACK, payload: []byte{0}}, 1, receiveNext, 0) {
		t.Fatal("zero-window probe was not recognized")
	}
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: TCPFlagACK, payload: []byte{0}}, 1, receiveNext, 4096) {
		t.Fatal("one-byte RFC 1122 keepalive was not recognized with an open window")
	}
	if tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: TCPFlagRST | TCPFlagACK}, 0, receiveNext, 4096) {
		t.Fatal("RST was classified as a keepalive probe")
	}
}

func TestTCPWindowScalingRequiresPeerOption(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPWindowScale = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7999))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	link.mu.Lock()
	window := link.lastClientWindow
	link.mu.Unlock()
	if window != 65535 {
		t.Fatalf("unscaled receive window = %d, want 65535", window)
	}
	if connection.(*TCPConn).peerWindowScaling {
		t.Fatal("window scaling was enabled without the peer option")
	}
}

func TestTCPReceiveWindowScaleSupportsAutoTuning(t *testing.T) {
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	_, scale, enabled, _, _, _ := parseTCPOptions(tcpSYNOptions(nil, 1360, windowScale, 1), 536, 1360)
	if !enabled || scale != windowScale {
		t.Fatalf("SYN window scale = %d, enabled=%t; want %d, true", scale, enabled, windowScale)
	}
	connection := &TCPConn{receiveCapacity: tcpReceiveCapacity, receiveWindowScale: windowScale}
	if window, want := connection.receiveWindow(0, true), uint16(int(tcpReceiveCapacity)>>windowScale); window != want {
		t.Fatalf("scaled default receive window = %d, want %d", window, want)
	}
	if maximum := uint64(65535) << windowScale; maximum < tcpMaximumReceiveCapacity {
		t.Fatalf("maximum scaled receive window = %d, want at least %d", maximum, tcpMaximumReceiveCapacity)
	}
	if got := tcpReceiveWindowScaleFor(128 * 1024); got != 2 {
		t.Fatalf("128 KiB receive ceiling selected window scale %d, want 2", got)
	}
}

func TestTCPReceiveWindowPreservesRightEdge(t *testing.T) {
	const receiveNext = uint32(100)
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	window := newTCPReceiveWindow(receiveNext, 65535, true, false, windowScale)
	want := uint16(int(tcpReceiveCapacity) >> windowScale)
	initialRight := window.right
	proposed, proposedRight, _ := window.next(receiveNext, tcpReceiveCapacity, 0)
	if proposed != want {
		t.Fatalf("proposed scaled window = %d, want %d", proposed, want)
	}
	if window.right != initialRight {
		t.Fatalf("window proposal moved right edge from %d to %d", initialRight, window.right)
	}
	window.right = proposedRight
	right := window.right
	got, nextRight, _ := window.next(receiveNext, tcpReceiveCapacity/2, 0)
	if got != want {
		t.Fatalf("window after out-of-order storage = %d, want %d", got, want)
	}
	if nextRight != right {
		t.Fatalf("proposed right edge moved from %d to %d", right, nextRight)
	}
	advanced := receiveNext + 1380
	got, _, _ = window.next(advanced, tcpReceiveCapacity-1380, 0)
	if advertisedRight := advanced + uint32(got)<<windowScale; tcpSequenceLess(advertisedRight+uint32(1<<windowScale)-1, right) {
		t.Fatalf("scaled right edge shrank from %d to %d", right, advertisedRight)
	}
}

func TestTCPBufferAutoTuning(t *testing.T) {
	base := time.Now()
	fast := tcpBufferAutoTune{updated: base}
	if target := fast.target(base.Add(500*time.Microsecond), 100*time.Microsecond, tcpReceiveCapacity, tcpMaximumSendCapacity); target != 0 {
		t.Fatalf("sub-interval auto tuning target = %d, want 0", target)
	}
	if target := fast.target(base.Add(time.Millisecond), 100*time.Microsecond, tcpReceiveCapacity, tcpMaximumSendCapacity); target >= tcpSendCapacity {
		t.Fatalf("scheduler-batched low-RTT target = %d, want below initial send capacity", target)
	}
	receive := &TCPConn{receiveCapacity: tcpReceiveCapacity, receiveAutoTune: true}
	tuner := tcpBufferAutoTune{updated: base}
	receive.applicationReads.Store(tcpReceiveCapacity)
	target := tuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, receive.applicationReads.Load(), tcpMaximumReceiveCapacity)
	if !receive.growReceiveCapacity(target) || receive.receiveCapacity != 2*tcpReceiveCapacity {
		t.Fatalf("receive auto tuning capacity = %d, want %d", receive.receiveCapacity, 2*tcpReceiveCapacity)
	}
	receive.receiveAutoTune = false
	receive.applicationReads.Add(4 * tcpReceiveCapacity)
	target = tuner.target(base.Add(200*time.Millisecond), 100*time.Millisecond, receive.applicationReads.Load(), tcpMaximumReceiveCapacity)
	if receive.growReceiveCapacity(target) || receive.receiveCapacity != 2*tcpReceiveCapacity {
		t.Fatalf("user-locked receive capacity changed to %d", receive.receiveCapacity)
	}
	customMaximum := 32 * 1024 * 1024
	customTuner := tcpBufferAutoTune{updated: base}
	if target = customTuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, uint64(customMaximum), customMaximum); target != customMaximum {
		t.Fatalf("custom automatic maximum target = %d, want %d", target, customMaximum)
	}

	send := &TCPConn{sendCapacity: tcpSendCapacity, sendAutoTune: true, sendChanged: make(chan struct{})}
	sendTuner := tcpBufferAutoTune{updated: base}
	target = sendTuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, 512*1024, tcpMaximumSendCapacity)
	if !send.growSendCapacity(target) || send.sendCapacity != 512*1024 {
		t.Fatalf("first send auto tuning capacity = %d, want %d", send.sendCapacity, 512*1024)
	}
	target = sendTuner.target(base.Add(200*time.Millisecond), 100*time.Millisecond, 1536*1024, tcpMaximumSendCapacity)
	if !send.growSendCapacity(target) || send.sendCapacity != 1024*1024 {
		t.Fatalf("second send auto tuning capacity = %d, want %d", send.sendCapacity, 1024*1024)
	}
	send.sendAutoTune = false
	if send.growSendCapacity(4*1024*1024) || send.sendCapacity != 1024*1024 {
		t.Fatalf("user-locked send capacity changed to %d", send.sendCapacity)
	}
}

func TestTCPMSSChangePreservesCongestionUnits(t *testing.T) {
	if got := tcpCongestionValueForMSS(12_000, 1200, 600, true); got != 6000 {
		t.Fatalf("congestion value after MSS reduction = %d, want 6000", got)
	}
	if got := tcpCongestionValueForMSS(12_000, 600, 1200, true); got != 12_000 {
		t.Fatalf("congestion value after MSS increase = %d, want 12000", got)
	}
	if got := tcpCongestionValueForMSS(500, 1200, 600, true); got != 600 {
		t.Fatalf("congestion window floor after MSS reduction = %d, want 600", got)
	}
	if got := tcpCongestionValueForMSS(500, 1200, 600, false); got != 250 {
		t.Fatalf("threshold after MSS reduction = %d, want 250", got)
	}
}

func TestTCPPLPMTUProbeHeadway(t *testing.T) {
	if got := tcpPLPMTUProbeHeadway(10_000, 1000, 100*time.Millisecond); got != time.Second {
		t.Fatalf("ten-packet PLPMTU headway = %v, want 1s", got)
	}
	if got := tcpPLPMTUProbeHeadway(100_000, 1000, 100*time.Millisecond); got != 10*time.Second {
		t.Fatalf("hundred-packet PLPMTU headway = %v, want 10s", got)
	}
	if got := tcpPLPMTUTimeoutDelay(10 * time.Second); got != 50*time.Second {
		t.Fatalf("timeout PLPMTU delay = %v, want 50s", got)
	}
	now := time.Unix(100, 0)
	probe := tcpPLPMTU{searchLow: 1000, searchHigh: 1500, probeMTU: 1250, active: true, searching: true}
	probe.failed(now, 10*time.Second)
	if probe.searchHigh != 1249 || probe.active || probe.nextProbe != now.Add(10*time.Second) {
		t.Fatalf("failed PLPMTU probe state = %+v", probe)
	}
	probe = tcpPLPMTU{searchLow: 1000, searchHigh: 1500, probeMTU: 1250, active: true, searching: true}
	probe.inconclusive(now, 50*time.Second)
	if probe.searchLow != 1000 || probe.searchHigh != 1500 || probe.active || probe.nextProbe != now.Add(50*time.Second) {
		t.Fatalf("inconclusive PLPMTU probe state = %+v", probe)
	}
	probe.start(1495, 1500, now)
	if probe.searching {
		t.Fatalf("sub-threshold PLPMTU search remained active: %+v", probe)
	}
}

func TestTCPPLPMTURequiresIsolatedLossEvidence(t *testing.T) {
	segments := []sentTCPSegment{
		{sequence: 1000, end: 2200},
		{sequence: 2200, end: 3200, state: sentTCPSegmentSACKed},
		{sequence: 3200, end: 4200, state: sentTCPSegmentSACKed},
	}
	if isolatedPLPMTUProbeLoss(segments, 1000, 4200, 1000) {
		t.Fatal("PLPMTU accepted fewer than DupThresh SACKed ranges")
	}
	segments = append(segments, sentTCPSegment{sequence: 4200, end: 5200, state: sentTCPSegmentSACKed})
	if !isolatedPLPMTUProbeLoss(segments, 1000, 5200, 1000) {
		t.Fatal("PLPMTU rejected an isolated probe with ordinary loss evidence")
	}
	segments[2].state.set(sentTCPSegmentSACKed, false)
	if isolatedPLPMTUProbeLoss(segments, 1000, 5200, 1000) {
		t.Fatal("PLPMTU suppressed congestion with a second hole below HighSACK")
	}
}

func recordTestTCPLosses(outstanding []sentTCPSegment, mss int) uint32 {
	markProvenTCPLosses(outstanding, mss, false)
	var losses uint32
	for index := range outstanding {
		losses += recordTCPSegmentLoss(&outstanding[index])
	}
	return losses
}

func TestTCPProvenLossAccountingUsesTransmissionGenerations(t *testing.T) {
	speculative := sentTCPSegment{sequence: 0, end: 1000, state: sentTCPSegmentTransmitted}
	if loss := recordTCPSegmentLoss(&speculative); loss != 0 || speculative.lossAlreadyReported() {
		t.Fatalf("speculative retransmission loss = %d, reported %t", loss, speculative.lossAlreadyReported())
	}
	segments := []sentTCPSegment{
		{sequence: 0, end: 1000, state: sentTCPSegmentTransmitted},
		{sequence: 1000, end: 2000, state: sentTCPSegmentTransmitted},
		{sequence: 2000, end: 3000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 3000, end: 4000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 4000, end: 5000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
	}
	if losses := recordTestTCPLosses(segments, 1000); losses != 2000 {
		t.Fatalf("initial proven losses = %d, want 2000", losses)
	}
	if losses := recordTestTCPLosses(segments, 1000); losses != 0 {
		t.Fatalf("repeated proven losses = %d", losses)
	}
	segments[0].advanceTransmissionGeneration()
	segments[0].state.set(sentTCPSegmentSACKRetried, true)
	if losses := recordTestTCPLosses(segments, 1000); losses != 0 {
		t.Fatalf("speculative replacement loss = %d", losses)
	}
	segments[0].state.set(sentTCPSegmentRACKLost, true)
	if losses := recordTestTCPLosses(segments, 1000); losses != 1000 {
		t.Fatalf("RACK-proven replacement loss = %d, want 1000", losses)
	}
	segments[0].state |= sentTCPSegmentLossReported
	segments[0].advanceTransmissionGeneration()
	if !segments[0].isTransmitted() || !segments[0].isRetransmitted() || segments[0].lossAlreadyReported() {
		t.Fatalf("replacement generation state = %#x", segments[0].state)
	}
}

func TestTCPRecoveryUndoEvidence(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlCUBIC)
	rtt := rttEstimator{initialized: true, srtt: 100 * time.Millisecond, variation: 20 * time.Millisecond, rto: time.Second}
	eifel := tcpRecoveryUndo{spuriousUndos: 2}
	eifel.begin(true, 4000, 12000, 8000, 10000, &controller, rtt, time.Unix(100, 0))
	if eifel.spuriousUndos != 2 {
		t.Fatalf("recovery restart discarded %d prior spurious undos", eifel.spuriousUndos)
	}
	eifel.recordRetransmission(1000, 2000, 200, false)
	if eifel.detectEifel(199, false, false, 4000) {
		t.Fatal("Eifel accepted an all-data ACK without prior DSACK evidence")
	}
	eifel.eifelChecked = false
	if !eifel.detectEifel(199, false, true, 4000) {
		t.Fatal("Eifel rejected conservative timestamp and prior-DSACK evidence")
	}
	response := eifel.eifelRTOResponse()
	window, threshold := eifel.restore(1000, 6000, 4000, 1000, &controller, time.Unix(100, 0), CongestionPhaseOpen)
	if window != 10000 || threshold != 10000 || controller.algorithmName() != CongestionControlCUBIC {
		t.Fatalf("Eifel restore = cwnd %d ssthresh %d controller %q", window, threshold, controller.algorithmName())
	}
	currentRTT := rttEstimator{initialized: true, srtt: 80 * time.Millisecond, variation: 10 * time.Millisecond, rto: tcpMinimumRTO}
	if response.observe(4000, 300*time.Millisecond, &currentRTT) {
		t.Fatal("Eifel RTO response used an RTT sample that did not cover new data")
	}
	if !response.observe(4001, 300*time.Millisecond, &currentRTT) || currentRTT.srtt != 300*time.Millisecond || currentRTT.variation != 150*time.Millisecond || currentRTT.rto != 900*time.Millisecond {
		t.Fatalf("Eifel RTO response = srtt %v variation %v rto %v", currentRTT.srtt, currentRTT.variation, currentRTT.rto)
	}
	var highThreshold tcpRecoveryUndo
	highThreshold.begin(false, 4000, 12000, 18000, 10000, &controller, rtt, time.Unix(100, 0))
	_, threshold = highThreshold.restore(1000, 6000, 0, 1000, &controller, time.Unix(100, 0), CongestionPhaseOpen)
	if threshold != 18000 {
		t.Fatalf("RFC 4015 pipe_prev = %d, want max(FlightSize, ssthresh) = 18000", threshold)
	}

	var dsack tcpRecoveryUndo
	dsack.begin(false, 5000, 16000, 12000, 14000, &controller, rtt, time.Unix(100, 0))
	dsack.recordRetransmission(1000, 2000, 300, false)
	dsack.recordRetransmission(2000, 3000, 301, false)
	if dsack.observeDSACK(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}, 3000, 1000, false) {
		t.Fatal("DSACK undo completed before every retransmission was duplicated")
	}
	if !dsack.observeDSACK(TCPSACKBlock{LeftEdge: 2000, RightEdge: 3000}, 3000, 1000, false) {
		t.Fatal("DSACK undo did not complete after every retransmission was duplicated")
	}
	timeoutDSACKController := newTCPCongestionController(CongestionControlCUBIC)
	timeoutDSACK := new(tcpRecoveryUndo)
	timeoutDSACK.begin(true, 3000, 12000, 8000, 10000, &timeoutDSACKController, rtt, time.Unix(100, 0))
	timeoutDSACK.recordRetransmission(1000, 2000, 300, false)
	if !timeoutDSACK.observeDSACK(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}, 2000, 1000, false) {
		t.Fatal("DSACK did not prove the timeout retransmission spurious")
	}
	state := tcpEstablishedState{
		connection: &TCPConn{stack: new(Stack)}, controller: timeoutDSACKController,
		undo: timeoutDSACK, peerMSS: 1000, congestionWindow: 1000, slowStartThreshold: 8000,
		outstanding:  []sentTCPSegment{{sequence: 2000, end: 3000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKRetried | sentTCPSegmentOriginalLost | sentTCPSegmentRACKLost | sentTCPSegmentLossReported}},
		haveRACKLoss: true,
	}
	state.controller.state.LostBytes = 1000
	if !state.restoreSpuriousRecovery(time.Unix(100, 0), 1000) {
		t.Fatal("DSACK evidence did not restore timeout recovery")
	}
	if state.eifelRTO == nil {
		t.Fatal("DSACK evidence did not install the RFC 4015 spurious-timeout response")
	}
	if state.haveRACKLoss || state.outstanding[0].state.has(sentTCPSegmentOriginalLost|sentTCPSegmentRACKLost) || !state.outstanding[0].state.has(sentTCPSegmentSACKRetried) || !state.outstanding[0].lossAlreadyReported() || state.controller.state.LostBytes != 1000 || sackRecoveryPipe(state.outstanding, 1000) != 2000 {
		t.Fatalf("timeout undo discarded published flight or loss history: state %#x lost %d Pipe %d", state.outstanding[0].state, state.controller.state.LostBytes, sackRecoveryPipe(state.outstanding, 1000))
	}

	var repeated tcpRecoveryUndo
	repeated.begin(false, 5000, 16000, 12000, 14000, &controller, rtt, time.Unix(100, 0))
	repeated.recordRetransmission(1000, 2000, 300, false)
	repeated.recordRetransmission(1000, 2000, 301, true)
	if repeated.observeDSACK(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}, 2000, 1000, false) {
		t.Fatal("DSACK undid a range retransmitted more than once")
	}
	var repacketized tcpRecoveryUndo
	repacketized.begin(false, 5000, 16000, 12000, 14000, &controller, rtt, time.Unix(100, 0))
	repacketized.recordRetransmission(1000, 2200, 300, false)
	repacketized.recordRetransmission(1000, 2000, 301, true)
	if !repacketized.dsackDisabled {
		t.Fatal("DSACK undo retained a repacketized range retransmitted more than once")
	}

	var emptyScoreboard tcpRecoveryUndo
	emptyScoreboard.begin(false, 5000, 16000, 12000, 14000, &controller, rtt, time.Unix(100, 0))
	emptyScoreboard.recordRetransmission(1000, 2000, 300, false)
	if emptyScoreboard.observeDSACK(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}, 2000, 1000, true) || !emptyScoreboard.dsackDisabled {
		t.Fatal("RFC 3708 empty-scoreboard exception did not disable undo")
	}

	var history tcpRetransmissionHistory
	history.record(1000, 2000)
	if matched, repeatedRange := history.match(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}); !matched || repeatedRange {
		t.Fatalf("single retransmission history match = %t, %t", matched, repeatedRange)
	}
	history.record(1000, 2000)
	if matched, repeatedRange := history.match(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}); !matched || !repeatedRange {
		t.Fatalf("repeated retransmission history match = %t, %t", matched, repeatedRange)
	}
	var overlappingHistory tcpRetransmissionHistory
	overlappingHistory.record(1000, 2200)
	overlappingHistory.record(1000, 2000)
	if matched, repeatedRange := overlappingHistory.match(TCPSACKBlock{LeftEdge: 1000, RightEdge: 2000}); !matched || !repeatedRange {
		t.Fatalf("overlapping retransmission history match = %t, %t", matched, repeatedRange)
	}
}

func TestTCPRecoveryUndoRestoresNestedTransportState(t *testing.T) {
	now := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlCUBIC)
	_, _ = controller.initialize(CongestionPhaseOpen, now, 10*time.Millisecond, 20*time.Millisecond, 20_000, 10_000, 1000, 1)
	controller.setCongestionPhase(CongestionPhaseRecovery, now)
	state := tcpEstablishedState{
		connection: &TCPConn{stack: new(Stack)}, controller: controller,
		peerMSS: 1000, congestionWindow: 10_000, slowStartThreshold: 8000,
		fastRecovery: true, recoveryPoint: 9000,
		prrPriorFlight: 7000, prrDelivered: 2000, prrOut: 1000,
		ecnRecoveryActive: true, ecnRecoveryPoint: 12_000, rtoAttempts: 2,
		undo: new(tcpRecoveryUndo),
	}
	transport := state.recoveryTransportState(false)
	state.undo.begin(false, 9000, state.congestionWindow, state.slowStartThreshold, 7000, &state.controller, newRTTEstimator(20*time.Millisecond), now)
	state.undo.setTransport(transport)
	state.fastRecovery = false
	state.recoveryPoint = 0
	state.prrPriorFlight, state.prrDelivered, state.prrOut = 0, 0, 0
	state.ecnRecoveryActive, state.ecnRecoveryPoint = false, 0
	state.rtoAttempts = 0
	state.controller.setCongestionPhase(CongestionPhaseLoss, now.Add(time.Millisecond))
	if !state.restoreSpuriousRecovery(now.Add(2*time.Millisecond), 1000) {
		t.Fatal("nested recovery was not restored")
	}
	if !state.fastRecovery || state.recoveryPoint != 9000 || state.prrPriorFlight != 7000 || state.prrDelivered != 2000 || state.prrOut != 1000 {
		t.Fatalf("restored fast recovery = active %t point %d PRR %d/%d/%d", state.fastRecovery, state.recoveryPoint, state.prrPriorFlight, state.prrDelivered, state.prrOut)
	}
	if !state.ecnRecoveryActive || state.ecnRecoveryPoint != 12_000 || state.rtoAttempts != 0 {
		t.Fatalf("restored congestion epoch = active %t point %d attempts %d", state.ecnRecoveryActive, state.ecnRecoveryPoint, state.rtoAttempts)
	}
	if phase := state.controller.state.Phase; phase != CongestionPhaseRecovery {
		t.Fatalf("restored congestion phase = %v, want Recovery", phase)
	}
	state.sendUnacknowledged = state.recoveryPoint
	transport = state.recoveryTransportState(false)
	state.undo.begin(false, 12_000, state.congestionWindow, state.slowStartThreshold, 7000, &state.controller, state.rtt, now)
	state.undo.setTransport(transport)
	state.fastRecovery = true
	if !state.restoreSpuriousRecovery(now.Add(3*time.Millisecond), 1000) {
		t.Fatal("completed nested recovery was not undone")
	}
	if state.fastRecovery || state.prrPriorFlight != 0 || state.prrDelivered != 0 || state.prrOut != 0 {
		t.Fatalf("completed prior recovery was resurrected: active %t PRR %d/%d/%d", state.fastRecovery, state.prrPriorFlight, state.prrDelivered, state.prrOut)
	}
	if phase := state.controller.state.Phase; phase != CongestionPhaseOpen {
		t.Fatalf("completed prior recovery phase = %v, want Open", phase)
	}
}

func TestTCPReceiveWindowHandshakeScaling(t *testing.T) {
	const receiveNext = uint32(100)
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	active := newTCPReceiveWindow(receiveNext, 65535, true, true, windowScale)
	if got := active.size(receiveNext); got != uint32(65535)<<windowScale {
		t.Fatalf("active initial receive window = %d", got)
	}
	passive := newTCPReceiveWindow(receiveNext, 65535, true, false, windowScale)
	if got := passive.size(receiveNext); got != 65535 {
		t.Fatalf("passive initial receive window = %d", got)
	}
}

func TestTCPReceiveWindowAvoidsSillyWindowGrowth(t *testing.T) {
	const receiveNext = uint32(100)
	window := newTCPReceiveWindow(receiveNext, 1000, false, false, 0)
	advanced := receiveNext + 1000
	if got, _, _ := window.next(advanced, 499, tcpReceiveWindowIncrease(1000, 600)); got != 0 {
		t.Fatalf("sub-threshold reopened window = %d, want 0", got)
	}
	if got, _, _ := window.next(advanced, 500, tcpReceiveWindowIncrease(1000, 600)); got != 500 {
		t.Fatalf("threshold reopened window = %d, want 500", got)
	}
	maximumInt := int(^uint(0) >> 1)
	if got, want := tcpReceiveWindowIncrease(maximumInt, maximumInt), maximumInt/2+maximumInt%2; got != want {
		t.Fatalf("maximum-capacity threshold = %d, want %d", got, want)
	}
}

func TestTCPReceiveWindowReopensScaledZeroWindow(t *testing.T) {
	const (
		receiveNext = uint32(100)
		mss         = 28
		shift       = uint8(8)
		quantum     = uint32(1) << shift
	)
	window := newTCPReceiveWindow(receiveNext, 0, true, false, shift)
	if got, _, reserve := window.next(receiveNext, mss-1, mss); got != 0 || reserve != 0 {
		t.Fatalf("sub-MSS scaled zero-window proposal = %d/%d, want 0/0", got, reserve)
	}
	got, right, reserve := window.next(receiveNext, mss, mss)
	if got != 1 || right != receiveNext+quantum || reserve != uint16(quantum-uint32(mss)) {
		t.Fatalf("scaled zero-window proposal = %d/%d/%d, want 1/%d/%d", got, right, reserve, receiveNext+quantum, quantum-uint32(mss))
	}
	partial := newTCPReceiveWindow(receiveNext, 0, true, false, shift)
	partial.right = receiveNext + quantum - 1
	got, quantumRight, quantumReserve := partial.next(receiveNext, mss, mss)
	if got != 1 || quantumRight != receiveNext+quantum || quantumReserve != uint16(quantum-uint32(mss)) {
		t.Fatalf("partially consumed scaled zero-window proposal = %d/%d/%d, want 1/%d/%d", got, quantumRight, quantumReserve, receiveNext+quantum, quantum-uint32(mss))
	}
	common := newTCPReceiveWindow(receiveNext, 0, true, false, 5)
	common.right = receiveNext + 31
	got, commonRight, commonReserve := common.next(receiveNext, 1460, 1460)
	if got != 1 || commonRight != receiveNext+32 || commonReserve != 0 {
		t.Fatalf("common-scale zero-window proposal = %d/%d/%d, want 1/%d/0", got, commonRight, commonReserve, receiveNext+32)
	}
	if window.right != receiveNext || window.quantumReserve != 0 {
		t.Fatal("uncommitted scaled zero-window proposal changed state")
	}

	window.right, window.quantumReserve = quantumRight, quantumReserve
	connection := &TCPConn{receiveCapacity: mss}
	payload := make([]byte, quantum)
	next := receiveNext
	pieces := []tcpReceivedPiece(nil)
	bytes := 0
	if delivered, closed := connection.receiveTCPData(receiveNext, payload, false, quantum, quantumReserve, &next, &pieces, &bytes); !delivered || closed {
		t.Fatalf("quantum receive = delivered %t closed %t", delivered, closed)
	}
	if next != receiveNext+quantum || connection.readBuffer.size != int(quantum) {
		t.Fatalf("quantum receive state = next %d buffer %d", next, connection.readBuffer.size)
	}
	if accepted := connection.appendReadBuffer([]byte{1}, []byte{1}, 0, quantumReserve); accepted != 0 {
		t.Fatalf("post-quantum receive accepted %d bytes, want 0", accepted)
	}
	stream := &TCPConn{receiveCapacity: mss}
	streamNext := receiveNext
	var streamPieces []tcpReceivedPiece
	streamBytes := 0
	for index := uint32(0); index < quantum; index++ {
		if delivered, closed := stream.receiveTCPData(streamNext, []byte{byte(index)}, false, quantum-(streamNext-receiveNext), quantumReserve, &streamNext, &streamPieces, &streamBytes); !delivered || closed {
			t.Fatalf("quantum stream packet %d = delivered %t closed %t", index, delivered, closed)
		}
	}
	if streamNext != receiveNext+quantum || stream.readBuffer.size != int(quantum) {
		t.Fatalf("quantum stream state = next %d buffer %d, want %d/%d", streamNext, stream.readBuffer.size, receiveNext+quantum, quantum)
	}
	if delivered, closed := stream.receiveTCPData(streamNext, []byte{1}, false, 0, quantumReserve, &streamNext, &streamPieces, &streamBytes); delivered || closed {
		t.Fatalf("post-quantum stream packet = delivered %t closed %t, want false/false", delivered, closed)
	}
	outOfOrderConnection := &TCPConn{receiveCapacity: mss}
	outOfOrderNext := receiveNext
	var outOfOrder []tcpReceivedPiece
	outOfOrderBytes := 0
	gap := quantum / 2
	if delivered, closed := outOfOrderConnection.receiveTCPData(receiveNext+gap, []byte{1}, false, quantum, quantumReserve, &outOfOrderNext, &outOfOrder, &outOfOrderBytes); delivered || closed {
		t.Fatalf("out-of-order quantum packet = delivered %t closed %t", delivered, closed)
	}
	if delivered, closed := outOfOrderConnection.receiveTCPData(receiveNext, make([]byte, gap), false, quantum, quantumReserve, &outOfOrderNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("gap-filling quantum packet = delivered %t closed %t", delivered, closed)
	}
	if outOfOrderNext != receiveNext+gap+1 || outOfOrderConnection.readBuffer.size != int(gap+1) {
		t.Fatalf("promoted quantum state = next %d buffer %d, want %d/%d", outOfOrderNext, outOfOrderConnection.readBuffer.size, receiveNext+gap+1, gap+1)
	}
	if delivered, closed := outOfOrderConnection.receiveTCPData(outOfOrderNext, make([]byte, quantum-gap-1), false, quantum-(outOfOrderNext-receiveNext), quantumReserve, &outOfOrderNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("remaining quantum packet = delivered %t closed %t", delivered, closed)
	}
	if delivered, closed := outOfOrderConnection.receiveTCPData(outOfOrderNext, []byte{1}, false, 0, quantumReserve, &outOfOrderNext, &outOfOrder, &outOfOrderBytes); delivered || closed {
		t.Fatalf("post-promote quantum packet = delivered %t closed %t", delivered, closed)
	}
	if delivered, closed := outOfOrderConnection.receiveTCPData(outOfOrderNext, nil, true, 0, quantumReserve, &outOfOrderNext, &outOfOrder, &outOfOrderBytes); !delivered || !closed {
		t.Fatalf("zero-window FIN = delivered %t closed %t, want true/true", delivered, closed)
	}
	baselineSize := unsafe.Sizeof(struct {
		right uint32
		shift uint8
	}{})
	if got := unsafe.Sizeof(window); got != baselineSize {
		t.Fatalf("tcpReceiveWindow size = %d, want %d", got, baselineSize)
	}
	maximum := newTCPReceiveWindow(receiveNext, 0, true, false, tcpMaximumWindowScale)
	if got, _, reserve := maximum.next(receiveNext, 1, 1); got != 1 || reserve != uint16((uint32(1)<<tcpMaximumWindowScale)-1) {
		t.Fatalf("maximum-scale reserve = %d/%d, want one quantum/%d", got, reserve, uint16((uint32(1)<<tcpMaximumWindowScale)-1))
	}
}

func TestTCPWindowUpdatePromotesContiguousData(t *testing.T) {
	connection := &TCPConn{
		readNotify:      make(chan struct{}),
		receiveCapacity: 4,
	}
	connection.readBuffer.append([]byte("full"))
	receiveNext := uint32(100)
	outOfOrder := []tcpReceivedPiece{{sequence: receiveNext, payload: []byte("next")}}
	outOfOrderBytes := len(outOfOrder[0].payload)
	buffer := make([]byte, 4)
	if n, err := connection.Read(buffer); err != nil || n != 4 || string(buffer) != "full" {
		t.Fatalf("Read = %d, %v, %q; want 4, nil, full", n, err, buffer)
	}
	if delivered, closed := connection.promoteTCPReceived(0, &receiveNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("promoteTCPReceived = %t, %t; want true, false", delivered, closed)
	}
	if receiveNext != 104 || len(outOfOrder) != 0 || outOfOrderBytes != 0 {
		t.Fatalf("receive state = next %d, pieces %d, bytes %d; want 104, 0, 0", receiveNext, len(outOfOrder), outOfOrderBytes)
	}
	if got := string(testTCPReadBufferBytes(&connection.readBuffer)); got != "next" {
		t.Fatalf("promoted read buffer = %q, want next", got)
	}
}

func TestTCPRejectsOutOfWindowACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7998))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("unacknowledged")); err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		if peer == nil || peer.highestClientEnd == peer.clientNext {
			return false
		}
		link.echoTCP = false
		return true
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	validSequence, acknowledgement := peer.serverNext, peer.highestClientEnd
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), validSequence+tcpReceiveCapacity+1, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	tcpConnection.mu.Lock()
	retained := tcpConnection.sendBuffer.size
	tcpConnection.mu.Unlock()
	if retained == 0 {
		t.Fatal("out-of-window segment acknowledged the send buffer")
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), validSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		tcpConnection.mu.Lock()
		defer tcpConnection.mu.Unlock()
		return tcpConnection.sendBuffer.size == 0
	})
}

func TestTCPOldACKStillDeliversData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, oldACK := peer.serverNext, peer.clientNext-1
	peer.serverNext += 4
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, oldACK, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte("data")); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != "data" {
		t.Fatalf("data with old ACK = %q, %v", buffer, err)
	}
}

func TestTCPTooOldACKDropsData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7996))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, tooOldACK := peer.serverNext, peer.clientNext-5
	peer.serverNext += 4
	baselineACKs := link.clientACKs
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, tooOldACK, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte("data")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > baselineACKs
	})
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buffer := make([]byte, 4)
	if n, readErr := connection.Read(buffer); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("data with too-old ACK = %q, %v, want timeout", buffer[:n], readErr)
	}
}

func TestTCPOldACKUpdatesRecentTimestamp(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.21"), netip.MustParseAddr("192.0.2.22"))
	link.mu.Lock()
	link.echoTCP, link.timestampTCP = true, true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7995))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	c := connection.(*TCPConn)
	link.mu.Lock()
	link.echoTCP = false
	peer := link.tcp[c.key.local.Port()]
	sequence, ack, timestamp := peer.serverNext, peer.clientNext, peer.timestamp+1000
	link.mu.Unlock()
	packet := buildTestTCP(link.remote, link.local, c.key.remote.Port(), c.key.local.Port(), sequence, ack-1, TCPFlagACK|TCPFlagPSH, 0, tcpTimestampOptions(timestamp, 0), []byte("old"))
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var data [3]byte
	if _, err := io.ReadFull(connection, data[:]); err != nil || string(data[:]) != "old" {
		t.Fatalf("old ACK data = %q, %v", data, err)
	}
	if info := c.Info(); info.PeerWindow == 0 {
		t.Fatal("old ACK changed the send window")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case wire := <-link.outbound:
			packet, ok := parseIPPacket(wire, false)
			if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || binary.BigEndian.Uint32(packet.payload[8:12]) != sequence+3 {
				continue
			}
			headerSize := int(packet.payload[12]>>4) * 4
			_, echo, present := parseTCPTimestamp(packet.payload[tcpHeaderSize:headerSize])
			if !present || echo != timestamp {
				t.Fatalf("old ACK timestamp echo = %d, present %t, want %d", echo, present, timestamp)
			}
			return
		case <-deadline.C:
			t.Fatal("no ACK for accepted old-ACK data")
		}
	}
}

func TestTCPOldACKProcessesSelectiveEvidence(t *testing.T) {
	for _, selective := range []bool{false, true} {
		start := time.Now()
		connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
		connection.stack = &Stack{timestampEpoch: start}
		state := tcpEstablishedState{
			connection: connection, controller: newTCPCongestionController(CongestionControlCUBIC),
			peerMSS: 1000, peerSACK: true, peerWindow: 20_000, peerWindowSequence: 100,
			sendUnacknowledged: 2000, sendNext: 5000, bytesAcknowledged: 1000,
			congestionWindow: 10_000, slowStartThreshold: 10_000, rtt: newRTTEstimator(20 * time.Millisecond),
			outstanding: []sentTCPSegment{{sequence: 2000, end: 3000}, {sequence: 3000, end: 4000}, {sequence: 4000, end: 5000}},
			sendTimer:   tcpSendTimerState{baseDeadline: start.Add(time.Second)},
			retransmit:  true, retransmissionDeadline: start.Add(time.Second),
		}
		segment := tcpSegment{sequence: 101, acknowledgement: 1999, flags: TCPFlagACK, window: 0}
		if selective {
			segment.setOptions(testSACKOptions(map[uint32][]byte{4000: make([]byte, 1000)}))
		}
		update := state.processAcknowledgment(&segment, start.Add(time.Millisecond), 0)
		state.updateRetransmissionTimer(update, start.Add(time.Millisecond))
		if state.sendUnacknowledged != 2000 || state.peerWindow != 20_000 || state.peerWindowSequence != 100 || state.bytesAcknowledged != 1000 || state.congestionWindow != 10_000 {
			t.Fatalf("old ACK changed cumulative/window/growth state: UNA %d window %d WL1 %d bytes %d cwnd %d", state.sendUnacknowledged, state.peerWindow, state.peerWindowSequence, state.bytesAcknowledged, state.congestionWindow)
		}
		if !state.sendTimer.baseDeadline.Equal(start.Add(time.Second)) {
			t.Fatalf("old ACK moved RTO fallback to %v", state.sendTimer.baseDeadline)
		}
		if selective {
			if !state.outstanding[2].state.has(sentTCPSegmentSACKed) || state.sackedBytes != 1000 || state.duplicateACKs != 1 || update != tcpRetransmissionReselect {
				t.Fatalf("old ACK SACK state = marks %v bytes %d DupAcks %d timer %d", state.outstanding[2].state, state.sackedBytes, state.duplicateACKs, update)
			}
		} else if state.sackedBytes != 0 || state.duplicateACKs != 0 || update != tcpRetransmissionPreserve {
			t.Fatalf("plain old ACK invented evidence: bytes %d DupAcks %d timer %d", state.sackedBytes, state.duplicateACKs, update)
		}
	}
}

func TestTCPOldACKDSACKBoundsAndUndo(t *testing.T) {
	for _, test := range []struct {
		name    string
		blocks  []TCPSACKBlock
		invalid bool
	}{
		{name: "contained duplicate", blocks: []TCPSACKBlock{{LeftEdge: 4000, RightEdge: 4500}, {LeftEdge: 4000, RightEdge: 6000}}},
		{name: "unsent history", blocks: []TCPSACKBlock{{LeftEdge: 0, RightEdge: 1000}}, invalid: true},
		{name: "contained unsent history", blocks: []TCPSACKBlock{{LeftEdge: 0, RightEdge: 500}, {LeftEdge: 0, RightEdge: 1000}}, invalid: true},
		{name: "containing block beyond send next", blocks: []TCPSACKBlock{{LeftEdge: 4400, RightEdge: 4500}, {LeftEdge: 4300, RightEdge: 6300}}, invalid: true},
	} {
		for _, flags := range []byte{TCPFlagACK, TCPFlagACK | TCPFlagECE} {
			t.Run(fmt.Sprintf("%s/flags-%02x", test.name, flags), func(t *testing.T) {
				now := time.Now()
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{timestampEpoch: now}
				connection.peerECN = true
				state := tcpEstablishedState{
					connection: connection, controller: newTCPCongestionController(CongestionControlCUBIC),
					peerMSS: 1000, peerSACK: true, peerWindow: 20_000,
					sendUnacknowledged: 5000, sendNext: 6000, bytesAcknowledged: 4000,
					congestionWindow: 1000, slowStartThreshold: 2000, fastRecovery: true, recoveryPoint: 6000,
					rtt: newRTTEstimator(20 * time.Millisecond), undo: new(tcpRecoveryUndo),
					outstanding: []sentTCPSegment{{sequence: 5000, end: 6000}},
				}
				state.undo.begin(false, 6000, 10_000, 10_000, 1000, &state.controller, state.rtt, now)
				state.undo.recordRetransmission(4000, 4500, 100, false)
				state.recordRetransmission(4000, 4500)
				var option TCPHeaderOption
				if err := option.SetSACKBlocks(test.blocks); err != nil {
					t.Fatal(err)
				}
				wireSegment := TCPSegment{}
				if err := wireSegment.SetHeaderOptions([]TCPHeaderOption{option}); err != nil {
					t.Fatal(err)
				}
				segment := tcpSegment{sequence: 100, acknowledgement: 4000, flags: flags, window: 65535}
				segment.setOptions(wireSegment.Options)
				state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0)
				if test.invalid {
					if state.seenDSACK || state.dsackUndoDisabled || state.rackReorderingSeen || state.rackReorderingScale != 0 || !state.undo.active || state.undo.dsackDisabled || !state.fastRecovery {
						t.Fatal("invalid old-ACK DSACK changed recovery or reordering state")
					}
				} else if !state.seenDSACK || state.undo.active || state.fastRecovery || state.congestionWindow != 1000 || state.slowStartThreshold != 10_000 {
					t.Fatalf("old ACK failed to undo cumulatively acknowledged duplicate range: DSACK %t active %t recovery %t cwnd %d threshold %d", state.seenDSACK, state.undo.active, state.fastRecovery, state.congestionWindow, state.slowStartThreshold)
				}
			})
		}
	}
}

func TestTCPOldACKECEDoesNotChangeRecovery(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		now := time.Now()
		connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
		connection.stack = &Stack{timestampEpoch: now}
		connection.peerECN = true
		state := tcpEstablishedState{
			connection: connection, controller: newTCPCongestionController(CongestionControlCUBIC),
			peerMSS: 1000, peerWindow: 20_000,
			sendUnacknowledged: 2000, sendNext: 3000, bytesAcknowledged: 1000,
			congestionWindow: 10_000, slowStartThreshold: 10_000,
			rtt: newRTTEstimator(time.Millisecond), undo: new(tcpRecoveryUndo),
			outstanding: []sentTCPSegment{{sequence: 2000, end: 3000}},
		}
		state.undo.begin(timeout, state.sendNext, 10_000, 10_000, 1000, &state.controller, state.rtt, now)
		if timeout {
			state.congestionWindow, state.slowStartThreshold = 1000, 7000
			state.rtoRecovery = true
			state.ecnRecoveryActive, state.ecnRecoveryPoint = true, state.sendNext
			state.frtoState, state.frtoProbeBudget = tcpFRTOProbePending, 2
		}
		window, threshold := state.congestionWindow, state.slowStartThreshold
		frto, budget := state.frtoState, state.frtoProbeBudget
		segment := tcpSegment{sequence: 100, acknowledgement: 1999, flags: TCPFlagACK | TCPFlagECE, window: 65535}
		if update := state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0); update != tcpRetransmissionPreserve {
			t.Fatalf("old ECE timer update = %d, want preserve", update)
		}
		if state.congestionWindow != window || state.slowStartThreshold != threshold || !state.undo.active || state.frtoState != frto || state.frtoProbeBudget != budget || connection.sendCWR {
			t.Fatalf("old ECE changed recovery: timeout %t cwnd %d threshold %d undo %t F-RTO %d budget %d CWR %t", timeout, state.congestionWindow, state.slowStartThreshold, state.undo.active, state.frtoState, state.frtoProbeBudget, connection.sendCWR)
		}
		segment.acknowledgement = state.sendUnacknowledged
		state.processAcknowledgment(&segment, now.Add(2*time.Millisecond), 0)
		if state.undo.active || state.frtoState != tcpFRTOInactive || state.frtoProbeBudget != 0 || !timeout && (!connection.sendCWR || state.congestionWindow != 7000) {
			t.Fatal("current ECE feedback did not apply its congestion response")
		}
	}
}

func TestTCPCWRRecoveryPointTracksACKProgress(t *testing.T) {
	for _, start := range []uint32{2000, 0xfffffe00} {
		for _, recovery := range []string{"ordinary", "undo-before-point", "undo-at-point"} {
			t.Run(fmt.Sprintf("%08x/%s", start, recovery), func(t *testing.T) {
				now := time.Now()
				c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				c.stack = &Stack{timestampEpoch: now}
				c.peerECN = true
				c.sendBuffer.append(make([]byte, 1000))
				state := tcpEstablishedState{
					connection: c, controller: newTCPCongestionController(CongestionControlCUBIC),
					peerMSS: 1000, peerWindow: 20_000, bytesAcknowledged: 1000,
					sendUnacknowledged: start, sendNext: start + 1000,
					congestionWindow: 10_000, slowStartThreshold: 10_000,
					rtt: newRTTEstimator(time.Millisecond),
					outstanding: []sentTCPSegment{{sequence: start, end: start + 1000,
						state:     sentTCPSegmentTransmitted,
						hostQueue: packetQueueTicket{queuedAt: monotonicStampAt(now, now)}}},
				}
				state.controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, 10_000, 10_000, 1000, 1)
				segment := tcpSegment{sequence: 100, acknowledgement: start, flags: TCPFlagACK | TCPFlagECE, window: 20_000}
				state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0)
				if state.controller.state.Phase != CongestionPhaseCWR || !state.ecnRecoveryActive || state.ecnRecoveryPoint != state.sendNext {
					t.Fatal("current ECE did not establish the outstanding CWR recovery point")
				}
				point := state.ecnRecoveryPoint
				if recovery != "ordinary" {
					state.rtoAttempts = 1
					if index := state.prepareRetransmission(0, true, false, true, false, 0, now.Add(2*time.Millisecond)); index != 0 || state.undo == nil || state.undo.transport == nil || state.undo.transport.phase != CongestionPhaseCWR {
						t.Fatal("nested timeout did not retain the active CWR episode")
					}
					if recovery == "undo-before-point" {
						if !state.restoreSpuriousRecovery(now.Add(3*time.Millisecond), 0) || state.controller.state.Phase != CongestionPhaseCWR {
							t.Fatal("undo before the recovery point did not restore CWR")
						}
					}
				}
				if recovery != "undo-at-point" {
					segment.acknowledgement = start - 1
					state.processAcknowledgment(&segment, now.Add(4*time.Millisecond), 0)
					if state.controller.state.Phase != CongestionPhaseCWR || state.ecnRecoveryPoint != point || tcpSequenceLess(point, state.sendUnacknowledged) {
						t.Fatal("old ACK completed or invalidated an active CWR episode")
					}
				}
				segment.acknowledgement, segment.flags = point, TCPFlagACK
				state.processAcknowledgment(&segment, now.Add(5*time.Millisecond), 0)
				if state.sendUnacknowledged != point || state.controller.state.Phase != CongestionPhaseOpen || len(state.outstanding) != 0 {
					t.Fatal("ACK progress retained an already completed CWR episode")
				}
				if recovery == "undo-at-point" && state.undo.active {
					t.Fatal("advancing ACK did not undo the unpublished nested timeout")
				}
			})
		}
	}
}

func TestTCPOldACKOnlyReportsNewDeliveryEvidence(t *testing.T) {
	for _, evidence := range []string{"none", "new-SACK", "RACK"} {
		now := time.Now()
		recorder := new(congestionAPIRecorder)
		controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
			Name: "old-ACK-delivery", Features: CongestionControlFeatureDeliveryRate,
			New: func(CongestionControlContext) CongestionController { return recorder },
		})
		controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, 10_000, 10_000, 1000, 1)
		connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
		connection.stack = &Stack{timestampEpoch: now}
		state := tcpEstablishedState{
			connection: connection, controller: controller, peerMSS: 1000, peerSACK: true, peerWindow: 20_000,
			sendUnacknowledged: 2000, sendNext: 5000, bytesAcknowledged: 1000,
			congestionWindow: 10_000, slowStartThreshold: 10_000, rtt: newRTTEstimator(time.Millisecond),
			outstanding: []sentTCPSegment{{sequence: 2000, end: 3000}, {sequence: 3000, end: 4000}, {sequence: 4000, end: 5000}},
		}
		for index := range state.outstanding {
			snapshot, _ := state.controller.onDataSend(1000, 1000, now, 1, uint32(index*1000), 10_000, 0, 0, time.Millisecond, 10_000)
			state.outstanding[index].delivery = snapshot
			state.outstanding[index].state.set(sentTCPSegmentTransmitted, true)
			state.outstanding[index].hostQueue.queuedAt = 1
		}
		recorder.events = nil
		segment := tcpSegment{sequence: 100, acknowledgement: 1999, flags: TCPFlagACK, window: 65535}
		if evidence == "new-SACK" {
			segment.setOptions(testSACKOptions(map[uint32][]byte{4000: make([]byte, 1000)}))
		} else if evidence == "RACK" {
			state.outstanding[2].state.set(sentTCPSegmentSACKed, true)
			state.outstanding[2].delivery.deliveredStamp = 0
			state.recountSACK()
			state.rackLatestDelivered = tcpRACKSample{sentAt: now.Add(500 * time.Microsecond), end: 5000, rtt: 500 * time.Microsecond}
		}
		update := state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0)
		ackEvents := 0
		for _, event := range recorder.events {
			if event == CongestionEventACK {
				ackEvents++
			}
		}
		if evidence == "new-SACK" {
			if ackEvents != 1 || recorder.rateSample.acked != 1000 || state.controller.state.DeliveredBytes != 1000 {
				t.Fatalf("old SACK delivery = events %d sample %d total %d", ackEvents, recorder.rateSample.acked, state.controller.state.DeliveredBytes)
			}
		} else if evidence == "RACK" {
			if ackEvents != 1 || recorder.rateSample.acked != 0 || recorder.rateSample.losses != 2000 || state.controller.state.DeliveredBytes != 0 || !state.fastRecovery || update != tcpRetransmissionReselect {
				t.Fatalf("old ACK RACK evidence = events %d delivered %d lost %d recovery %t timer %d", ackEvents, recorder.rateSample.acked, recorder.rateSample.losses, state.fastRecovery, update)
			}
		} else if ackEvents != 0 || state.controller.state.DeliveredBytes != 0 {
			t.Fatal("old ACK without evidence generated a congestion-control delivery event")
		}
	}
}

type tcpRecoveryClockRecorder struct {
	events []CongestionEventType
	times  []time.Time
	stages []CongestionRecoveryStage
}

func (r *tcpRecoveryClockRecorder) HandleCongestionEvent(event *CongestionEvent) {
	r.events = append(r.events, event.Type)
	r.times = append(r.times, event.Time)
	if event.Type == CongestionEventRecovery {
		r.stages = append(r.stages, event.Recovery.Stage)
	}
}

func TestTCPRecoveryEventsUseLossObservationTime(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		for _, timerClock := range []bool{false, true} {
			start := time.Now().Add(-time.Hour)
			recorder := new(tcpRecoveryClockRecorder)
			controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
				Name:     "recovery-clock",
				New:      func(CongestionControlContext) CongestionController { return recorder },
				Features: CongestionControlFeatureCustomRecovery | CongestionControlFeatureLossEvents | CongestionControlFeatureTransmissionEvents,
			})
			state := tcpEstablishedState{
				connection: &TCPConn{stack: &Stack{timestampEpoch: start}}, controller: controller,
				peerMSS: 1000, sendUnacknowledged: 1000, sendNext: 2000,
				congestionWindow: 10_000, slowStartThreshold: 10_000, rtt: newRTTEstimator(time.Millisecond),
				outstanding: []sentTCPSegment{{sequence: 1000, end: 2000, state: sentTCPSegmentTransmitted, hostQueue: packetQueueTicket{queuedAt: 1}}},
			}
			observation := start.Add(time.Minute)
			if timerClock {
				observation = time.Time{}
			}
			before := time.Now()
			if index := state.prepareRetransmission(0, timeout, false, true, false, 0, observation); index != 0 {
				t.Fatalf("selected retransmission = %d, want 0", index)
			}
			after := time.Now()
			lossEvent := CongestionEventLoss
			if timeout {
				lossEvent = CongestionEventTimeout
			}
			for _, required := range []CongestionEventType{CongestionEventPacketLost, lossEvent, CongestionEventRecovery} {
				found := false
				for _, event := range recorder.events {
					found = found || event == required
				}
				if !found {
					t.Fatalf("missing event %d in %v", required, recorder.events)
				}
			}
			for _, required := range []CongestionRecoveryStage{CongestionRecoveryCheckpoint, CongestionRecoverySelectFlight, CongestionRecoveryEnter} {
				if timeout && required != CongestionRecoveryCheckpoint {
					continue
				}
				found := false
				for _, stage := range recorder.stages {
					found = found || stage == required
				}
				if !found {
					t.Fatalf("missing recovery stage %d in %v", required, recorder.stages)
				}
			}
			want := observation
			if timerClock {
				want = recorder.times[0]
				if want.Before(before) || want.After(after) {
					t.Fatalf("timer observation = %v, outside %v..%v", want, before, after)
				}
			}
			for index, at := range recorder.times {
				if !at.Equal(want) {
					t.Fatalf("event %d at %v, want observation %v", recorder.events[index], at, want)
				}
			}
		}
	}
}

func TestTCPNonCurrentACKPreservesLivenessAndCWR(t *testing.T) {
	for _, kind := range []string{"future-ACK", "too-old-ACK", "no-ACK", "SYN", "inexact-RST", "old-ACK"} {
		t.Run(kind, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.25"), netip.MustParseAddr("192.0.2.26"))
			link.mu.Lock()
			link.echoTCP, link.ecnTCP = true, true
			link.mu.Unlock()
			connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7994))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			c := connection.(*TCPConn)
			if kind == "old-ACK" {
				if _, err := c.Write([]byte("h")); err != nil {
					t.Fatal(err)
				}
				var echoed [1]byte
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(c, echoed[:]); err != nil || echoed[0] != 'h' {
					t.Fatalf("ACK history echo = %q, %v", echoed, err)
				}
				waitFor(t, time.Second, func() bool { return c.Info().BytesAcknowledged == 1 })
			}
			link.mu.Lock()
			link.echoTCP = false
			peer := link.tcp[c.key.local.Port()]
			sequence, ack := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			wire := buildTestTCP(link.remote, link.local, c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK, 65535, nil, []byte("e"))
			setPacketECN(wire, 3)
			if err := writeTestPacket(stack, wire); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			var data [1]byte
			if _, err := io.ReadFull(connection, data[:]); err != nil {
				t.Fatal(err)
			}
			_ = c.Info()
			if !c.peerECN || !c.echoCongestion {
				t.Fatal("fixture did not establish negotiated ECN feedback")
			}
			sequence++
			flags := byte(TCPFlagACK | TCPFlagCWR)
			switch kind {
			case "future-ACK":
				ack++
			case "too-old-ACK":
				ack -= 1000
			case "no-ACK":
				flags = TCPFlagCWR
			case "SYN":
				flags |= TCPFlagSYN
			case "inexact-RST":
				flags |= TCPFlagRST
				sequence++
			case "old-ACK":
				ack--
			}
			if err := c.SetIdleTimeout(50 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			wire = buildTestTCP(link.remote, link.local, c.key.remote.Port(), c.key.local.Port(), sequence, ack, flags, 65535, nil, nil)
			packet, ok := parseIPPacket(wire, false)
			if !ok {
				t.Fatal("invalid fixture packet")
			}
			if err := stack.handleTCP(packet, time.Now().Add(time.Hour), true, false); err != nil {
				t.Fatal(err)
			}
			_ = c.Info()
			_ = c.Info()
			if !c.echoCongestion {
				t.Fatal("segment cleared congestion feedback")
			}
			select {
			case <-c.done:
				if !errors.Is(c.Info().LastError, os.ErrDeadlineExceeded) {
					t.Fatalf("idle close = %v, want deadline exceeded", c.Info().LastError)
				}
			case <-time.After(time.Second):
				t.Fatal("traffic postponed the idle timeout")
			}
		})
	}
}

func TestTCPOldACKDataRefreshesReceiveActivity(t *testing.T) {
	for _, policy := range []string{"keepalive", "keepalive-user-timeout", "idle-timeout"} {
		t.Run(policy, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.27"), netip.MustParseAddr("192.0.2.28"))
			link.mu.Lock()
			link.echoTCP, link.ecnTCP = true, true
			link.mu.Unlock()
			connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7995))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			c := connection.(*TCPConn)
			if _, err := c.Write([]byte("h")); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(c, data[:]); err != nil || data[0] != 'h' {
				t.Fatalf("ACK history echo = %q, %v", data, err)
			}
			waitFor(t, time.Second, func() bool { return c.Info().BytesAcknowledged == 1 })
			link.mu.Lock()
			link.echoTCP = false
			peer := link.tcp[c.key.local.Port()]
			sequence, ack := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			wire := buildTestTCP(link.remote, link.local, c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK, 65535, nil, []byte("e"))
			setPacketECN(wire, 3)
			if err := writeTestPacket(stack, wire); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, data[:]); err != nil || data[0] != 'e' {
				t.Fatalf("ECN fixture data = %q, %v", data, err)
			}
			_ = c.Info()
			if !c.peerECN || !c.echoCongestion {
				t.Fatal("fixture did not establish negotiated ECN feedback")
			}
			sequence++
			ack--
			if policy == "idle-timeout" {
				if err := c.SetIdleTimeout(150 * time.Millisecond); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := c.SetKeepAliveConfig(KeepAliveConfig{Idle: 150 * time.Millisecond, Interval: 50 * time.Millisecond, Count: 2}); err != nil {
					t.Fatal(err)
				}
				if policy == "keepalive-user-timeout" {
					if err := c.SetUserTimeout(75 * time.Millisecond); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.SetKeepAlive(true); err != nil {
					t.Fatal(err)
				}
			}
			for started := time.Now(); time.Since(started) < 400*time.Millisecond; {
				if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK|TCPFlagCWR, 65535, nil, []byte("x")); err != nil {
					t.Fatal(err)
				}
				sequence++
				if _, err := io.ReadFull(c, data[:]); err != nil || data[0] != 'x' {
					t.Fatalf("accepted old-ACK data = %q, %v; %+v", data, err, c.Info())
				}
				time.Sleep(10 * time.Millisecond)
				select {
				case <-c.done:
					t.Fatalf("connection closed while receiving new data: %+v", c.Info())
				default:
				}
			}
			_ = c.Info()
			if !c.echoCongestion || stack.Stats().TCPKeepAliveProbes != 0 {
				t.Fatalf("old-ACK data changed CWR or triggered keepalive: echo=%t probes=%d", c.echoCongestion, stack.Stats().TCPKeepAliveProbes)
			}
		})
	}
}

func TestTCPACKRTTAmbiguity(t *testing.T) {
	segments := []sentTCPSegment{
		{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted},
		{sequence: 200, end: 300, state: sentTCPSegmentTransmitted},
	}
	if !tcpACKRTTAmbiguous(segments, 300) {
		t.Fatal("cumulative ACK covering a retransmission was treated as an RTT sample")
	}
	if tcpACKRTTAmbiguous(segments, 100) {
		t.Fatal("ACK covering no new range was treated as ambiguous")
	}
	segments[0].state &^= sentTCPSegmentRetransmitted
	if tcpACKRTTAmbiguous(segments, 300) {
		t.Fatal("ACK covering only original transmissions was treated as ambiguous")
	}
}

func TestTCPActiveOpenRetainsSoftNetworkError(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPSYN = 1
	result := make(chan error, 1)
	go func() {
		connection, dialErr := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7996))
		if connection != nil {
			_ = connection.Close()
		}
		result <- dialErr
	}()
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.RLock()
		defer stack.mu.RUnlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	connection.deliverError(ICMPError{Reporter: link.remote, Type: 3, Code: 1})
	connection.wakeActor(tcpActorWakePathMTU)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("active open failed after soft network error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active open did not recover after soft network error")
	}
}

func TestTCPActiveOpenRejectsHardNetworkError(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.dropTCPSYN = 100
	result := make(chan error, 1)
	go func() {
		_, dialErr := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
		result <- dialErr
	}()
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.RLock()
		defer stack.mu.RUnlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	want := ICMPError{Reporter: link.remote, Type: 3, Code: 3, QuotedSource: netip.MustParseAddr("192.0.2.1")}
	connection.deliverError(want)
	select {
	case err := <-result:
		var got ICMPError
		if !errors.As(err, &got) || got.Type != want.Type || got.Code != want.Code {
			t.Fatalf("hard active-open error = %v, want ICMP port unreachable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hard active-open error did not terminate Dial")
	}
}

func TestTCPSimultaneousOpen(t *testing.T) {
	firstAddress := netip.MustParseAddr("192.0.2.21")
	secondAddress := netip.MustParseAddr("192.0.2.22")
	first, second := newStackPair(t, firstAddress, secondAddress, 1500)
	type result struct {
		connection net.Conn
		err        error
	}
	firstResult := make(chan result, 1)
	secondResult := make(chan result, 1)
	go func() {
		connection, err := first.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(firstAddress, 40121), netip.AddrPortFrom(secondAddress, 40122))
		firstResult <- result{connection: connection, err: err}
	}()
	go func() {
		connection, err := second.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(secondAddress, 40122), netip.AddrPortFrom(firstAddress, 40121))
		secondResult <- result{connection: connection, err: err}
	}()
	waitFor(t, time.Second, func() bool {
		return first.Stats().ActiveTCPConnections == 1 && second.Stats().ActiveTCPConnections == 1
	})
	_ = newStackBridge(t, first, second)
	var firstConnection, secondConnection net.Conn
	for index, channel := range []<-chan result{firstResult, secondResult} {
		select {
		case opened := <-channel:
			if opened.err != nil {
				t.Fatalf("simultaneous open %d: %v", index, opened.err)
			}
			if index == 0 {
				firstConnection = opened.connection
			} else {
				secondConnection = opened.connection
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("simultaneous open %d timed out", index)
		}
	}
	defer firstConnection.Close()
	defer secondConnection.Close()
	payload := []byte("crossed-syn")
	if _, err := firstConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = secondConnection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(secondConnection, buffer); err != nil || !bytes.Equal(buffer, payload) {
		t.Fatalf("simultaneous-open stream = %q, %v", buffer, err)
	}
}

func TestTCPMaximumPacingRateLiveUpdate(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7994))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	const limit = uint64(1_000_000)
	if err = tcpConnection.SetMaximumPacingRate(limit); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		info := tcpConnection.Info()
		return info.MaximumPacingRate == limit && info.PacingRate <= limit
	})
	if err = tcpConnection.SetMaximumPacingRate(0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.Info().MaximumPacingRate == 0 })
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetMaximumPacingRate(limit); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed SetMaximumPacingRate = %v, want net.ErrClosed", err)
	}
}

func TestTCPNewRenoPartialACKRetransmitsNextHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7995))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x5a}, 8*1280)
	start := time.Now()
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("NewReno recovery corrupted the stream")
	}
	if elapsed := time.Since(start); elapsed >= tcpInitialRTO {
		t.Fatalf("NewReno recovery took %v, want less than initial RTO", elapsed)
	}
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions < 2 {
		t.Fatalf("TCP retransmissions = %d, want at least 2", retransmissions)
	}
}

func TestTCPNewRenoPartialACKWindow(t *testing.T) {
	const mss = 1000
	for _, test := range []struct {
		name                 string
		window, acknowledged uint32
		want                 uint32
	}{
		{name: "sub-MSS acknowledgement", window: 5000, acknowledged: 500, want: 4500},
		{name: "one MSS acknowledgement", window: 5000, acknowledged: 1000, want: 5000},
		{name: "large acknowledgement", window: 5000, acknowledged: 3000, want: 3000},
		{name: "acknowledgement consumes window", window: 2000, acknowledged: 3000, want: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := newRenoPartialACKWindow(test.window, test.acknowledged, mss); got != test.want {
				t.Fatalf("partial ACK window = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTCPECNRecoveryBoundary(t *testing.T) {
	if !tcpECNStartsRecovery(false, 100, 0) {
		t.Fatal("first ECE did not start recovery")
	}
	if tcpECNStartsRecovery(true, 200, 200) {
		t.Fatal("ACK at the recovery boundary started another recovery")
	}
	if !tcpECNStartsRecovery(true, 201, 200) {
		t.Fatal("ACK beyond the recovery boundary did not start recovery")
	}
	if !tcpECNStartsRecovery(true, 1, 0xffffffff) {
		t.Fatal("wrapped ACK beyond the recovery boundary was rejected")
	}
}

func TestTCPECNAtMinimumWindowWaitsForRTO(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.sendTCPECE = true
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlReno},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7998))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte{1})
	writeAndReadTCPEcho(t, connection, []byte{2})
	start := time.Now()
	writeAndReadTCPEcho(t, connection, []byte{3})
	if elapsed := time.Since(start); elapsed < tcpMinimumRTO-50*time.Millisecond {
		t.Fatalf("one-MSS repeated ECE delayed next send by %v, want approximately one RTO", elapsed)
	}
}

func TestTCPBBRECNPreservesModelWindow(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("192.0.2.34"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.sendTCPECE = true
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x5a}, 4096))
	info := connection.(*TCPConn).Info()
	if info.CongestionWindow > 1024*1024 {
		t.Fatalf("BBR cwnd after ECE = %d, want model-sized window", info.CongestionWindow)
	}
	if info.SlowStartThreshold != ^uint32(0)>>1 {
		t.Fatalf("BBR ssthresh after ECE = %d, want preserved infinite threshold", info.SlowStartThreshold)
	}
}

func TestTCPConcurrentSlidingWindowAndHalfClose(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.holdTCPACKs = 3
	link.reverseTCPResponses = true

	connections := make([]net.Conn, 2)
	for index := range connections {
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, uint16(8000+index)))
		if err != nil {
			t.Fatal(err)
		}
		connections[index] = connection
		defer connection.Close()
	}
	if connections[0].LocalAddr().String() == connections[1].LocalAddr().String() {
		t.Fatal("TCP connections received the same ephemeral port")
	}

	payload := bytes.Repeat([]byte("sliding-window-"), 600)
	var wait sync.WaitGroup
	for _, connection := range connections {
		connection := connection
		wait.Add(1)
		go func() {
			defer wait.Done()
			if deadlineErr := connection.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
				t.Error(deadlineErr)
				return
			}
			if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
				t.Errorf("TCP Write = %d, %v", n, writeErr)
				return
			}
			response := make([]byte, len(payload))
			if _, readErr := io.ReadFull(connection, response); readErr != nil {
				t.Error(readErr)
				return
			}
			if !bytes.Equal(response, payload) {
				t.Error("TCP echo payload mismatch")
				return
			}
			closer, ok := connection.(interface{ CloseWrite() error })
			if !ok {
				t.Error("TCP connection has no CloseWrite")
				return
			}
			if closeErr := closer.CloseWrite(); closeErr != nil {
				t.Error(closeErr)
				return
			}
			one := make([]byte, 1)
			if n, readErr := connection.Read(one); n != 0 || readErr != io.EOF {
				t.Errorf("read after peer FIN = %d, %v", n, readErr)
			}
		}()
	}
	wait.Wait()
	link.mu.Lock()
	maximumBurst := link.maximumTCPBurst
	clientSACKs := link.clientSACKs
	link.mu.Unlock()
	if maximumBurst < 3 {
		t.Fatalf("maximum unacknowledged TCP burst = %d, want at least 3", maximumBurst)
	}
	if clientSACKs == 0 {
		t.Fatal("client did not report reversed receive ranges with SACK")
	}
}

func TestTCPRetransmitsLostHandshakeAndData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPSYN = 1
	link.dropTCPData = 1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if rto := connection.(*TCPConn).Info().RetransmissionTimeout; rto != 3*time.Second {
		t.Fatalf("data RTO after SYN timeout = %v, want 3s per RFC 6298 section 5.7", rto)
	}
	_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
	payload := []byte("retransmitted payload")
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response = %q", response)
	}
}

func TestTCPActiveHandshakeProcessesEventsWithFullPacketQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.101")
	remote := netip.MustParseAddrPort("192.0.2.102:8080")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	fillTestPacketQueue(t, &stack.outbound, []byte{0x45})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		_, dialErr := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, remote)
		dialed <- dialErr
	}()
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.Lock()
		defer stack.mu.Unlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	info := func() TCPConnInfo {
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case snapshot := <-result:
			return snapshot
		case <-time.After(time.Second):
			t.Fatal("active handshake did not process an Info request with a full packet queue")
			return TCPConnInfo{}
		}
	}
	if snapshot := info(); snapshot.State != TCPStateSYNSent || snapshot.Retransmissions != 0 {
		t.Fatalf("blocked active handshake info = %+v", snapshot)
	}
	initialSequence := uint32(connection.icmpSequence.Load() >> 32)
	forgedReset := buildTestTCP(remote.Addr(), local, remote.Port(), connection.key.local.Port(), 1, initialSequence+1, TCPFlagRST|TCPFlagACK, 65535, nil, nil)
	if err = writeTestPacket(stack, forgedReset); err != nil {
		t.Fatal(err)
	}
	if snapshot := info(); snapshot.State != TCPStateSYNSent || snapshot.Retransmissions != 0 {
		t.Fatalf("pre-publication reset changed active handshake = %+v", snapshot)
	}
	cancel()
	select {
	case err = <-dialed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialTCP cancellation with a full packet queue = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialTCP cancellation remained blocked by the packet queue")
	}
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 0 })
}

func TestTCPActiveHandshakeRTOStartsAfterDeviceDeparture(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.113")
	remote := netip.MustParseAddr("192.0.2.114")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	link := &testPacketLink{local: local, remote: remote, stack: stack, echoTCP: true, sackTCP: true, outbound: make(chan []byte, 1), tcp: make(map[uint16]*testTCPPeer)}
	type dialResult struct {
		connection net.Conn
		err        error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*tcpInitialRTO)
	t.Cleanup(cancel)
	dialed := make(chan dialResult, 1)
	go func() {
		connection, dialErr := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
		dialed <- dialResult{connection: connection, err: dialErr}
	}()

	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.Lock()
		defer stack.mu.Unlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	waitFor(t, tcpInitialRTO+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		for index := range waiters.slots {
			if waiters.slots[index].Load() != nil {
				return true
			}
		}
		return false
	})
	if info := connection.Info(); info.Retransmissions != 0 || info.State != TCPStateSYNSent {
		t.Fatalf("queue-resident active handshake = %+v", info)
	}
	if depth := stack.outbound.len(); depth != 1 {
		t.Fatalf("queue-resident SYN depth = %d, want 1", depth)
	}
	entry, ok := stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("queue-resident SYN was unavailable")
	}
	wire := consumeTestPacket(&stack.outbound, entry)
	if info := connection.Info(); info.Retransmissions != 0 {
		t.Fatalf("device departure counted %d active retransmissions, want 0", info.Retransmissions)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("active handshake retransmitted at device departure: depth %d", depth)
	}
	if err = link.handleOutboundPacket(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-dialed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if err = result.connection.Close(); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestTCPEstablishedRTOStartsAfterDeviceDeparture(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x73}, before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	var departureWaiter *packetQueueDepartureWaiter
	waitFor(t, before.RetransmissionTimeout+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		for index := range waiters.slots {
			if waiter := waiters.slots[index].Load(); waiter != nil {
				departureWaiter = waiter
				return true
			}
		}
		return false
	})
	blocked := connection.Info()
	if blocked.RetransmissionRecovery || blocked.Retransmissions != before.Retransmissions {
		t.Fatalf("queue-resident data entered loss recovery: before=%+v blocked=%+v", before, blocked)
	}
	if depth := stack.outbound.len(); depth != 1 {
		t.Fatalf("queue-resident data depth = %d, want 1", depth)
	}
	entry, available := stack.outbound.tryDequeue()
	if !available {
		t.Fatal("queue-resident TCP data was unavailable")
	}
	wire := consumeTestPacket(&stack.outbound, entry)
	departedAt, departed := departureWaiter.departedTime(stack.timestampEpoch)
	if !departed {
		t.Fatal("TCP data dequeue did not record device departure")
	}
	retryDelay := before.RetransmissionTimeout
	retry, available := waitTestPacketEntry(&stack.outbound, retryDelay+time.Second)
	if !available {
		t.Fatal("timed out waiting for the post-departure retransmission")
	}
	retryQueuedAt := time.Now()
	consumeTestPacket(&stack.outbound, retry)
	if elapsed := retryQueuedAt.Sub(departedAt); elapsed < retryDelay {
		t.Fatalf("retransmission followed device departure after %v, want at least %v", elapsed, retryDelay)
	}
	afterRetry := connection.Info()
	if !afterRetry.RetransmissionRecovery || afterRetry.CongestionWindow != uint32(afterRetry.MaximumSegmentSize) || afterRetry.Retransmissions != before.Retransmissions+1 {
		t.Fatalf("post-departure RTO recovery = before=%+v after=%+v", before, afterRetry)
	}
	if err := link.handleOutboundPacket(wire); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("device-departure TCP echo mismatch")
	}
}

func TestTCPEstablishedActorSurvivesStoppedDeviceRead(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	held := make([]uint16, 0, cap(stack.outbound.free))
	defer func() {
		for _, slot := range held {
			stack.outbound.releaseReserved(slot)
		}
	}()
	holdAllSlots := func() {
		t.Helper()
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
	}
	releaseOneSlot := func() {
		t.Helper()
		last := len(held) - 1
		stack.outbound.releaseReserved(held[last])
		held = held[:last]
	}
	checkResponsive := func(stage string) TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatalf("Info blocked while Stack.Read was stopped during %s", stage)
			return TCPConnInfo{}
		}
	}

	before := connection.Info()
	holdAllSlots()
	payload := bytes.Repeat([]byte("ordinary-output-"), 256)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	blocked := checkResponsive("data output")
	if blocked.BytesSent != before.BytesSent || blocked.Retransmissions != before.Retransmissions {
		t.Fatalf("unpublished data changed send accounting: before=%+v blocked=%+v", before, blocked)
	}
	if blocked.SendBufferSize < len(payload) {
		t.Fatalf("buffered bytes = %d, want at least %d", blocked.SendBufferSize, len(payload))
	}
	if got := stack.Stats().OutboundQueueDrops; got != 0 {
		t.Fatalf("TCP capacity wait counted %d outbound queue drops", got)
	}

	inbound := []byte("peer data while the packet device is not being read")
	link.mu.Lock()
	peer := link.tcp[connection.key.local.Port()]
	serverSequence, clientAcknowledgement := peer.serverNext, peer.clientNext
	peer.serverNext += uint32(len(inbound))
	link.mu.Unlock()
	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), serverSequence, clientAcknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, inbound); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(inbound))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatalf("Read with immediate ACK waiting for device capacity: %v", err)
	}
	if !bytes.Equal(received, inbound) {
		t.Fatalf("received peer data = %q, want %q", received, inbound)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	checkResponsive("acknowledgment output")

	releaseOneSlot()
	deadline := time.Now().Add(5 * time.Second)
	for connection.Info().BytesAcknowledged-before.BytesAcknowledged != uint64(len(payload)) && time.Now().Before(deadline) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			break
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if valid && packet.protocol == ProtocolTCP {
			if err := link.handleOutboundPacket(wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	if acknowledged := connection.Info().BytesAcknowledged - before.BytesAcknowledged; acknowledged != uint64(len(payload)) {
		t.Fatalf("acknowledged bytes after capacity returned = %d, want %d", acknowledged, len(payload))
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("recovered TCP echo payload mismatch")
	}

	deadline = time.Now().Add(time.Second)
	for len(held) != cap(stack.outbound.free) && time.Now().Before(deadline) {
		if slot, reserved := stack.outbound.tryReserve(); reserved {
			held = append(held, slot)
			continue
		}
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			break
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if valid && packet.protocol == ProtocolTCP {
			if err := link.handleOutboundPacket(wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(held) != cap(stack.outbound.free) {
		t.Fatalf("could not reacquire all output slots: held %d of %d", len(held), cap(stack.outbound.free))
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	checkResponsive("FIN output")
	releaseOneSlot()
	finPublished := false
	for attempt := 0; attempt < 2; attempt++ {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
		if !available {
			break
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("post-capacity packet is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if packet.payload[13]&TCPFlagFIN != 0 {
			finPublished = true
			break
		}
		if packet.payload[13]&TCPFlagACK == 0 || headerSize < tcpHeaderSize || headerSize > len(packet.payload) || headerSize != len(packet.payload) {
			t.Fatalf("packet before FIN is not a pure ACK: %x", wire)
		}
	}
	if !finPublished {
		t.Fatal("FIN was not published through the returned output slot")
	}
}

func TestTCPEstablishedActorsShareReturnedOutputCapacity(t *testing.T) {
	const flows = 8
	_, stack, connections := newManuallyPumpedTCPConnections(t, flows)
	for _, connection := range connections {
		defer connection.Close()
	}

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

	wantPorts := make(map[uint16]struct{}, flows)
	for index, connection := range connections {
		port := connection.key.local.Port()
		wantPorts[port] = struct{}{}
		before := connection.Info()
		payload := bytes.Repeat([]byte{byte(index)}, 32*1024)
		if n, err := connection.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("flow %d Write = %d, %v", index, n, err)
		}
		blocked := connection.Info()
		if blocked.BytesSent != before.BytesSent || blocked.SendBufferSize < len(payload) {
			t.Fatalf("flow %d changed transmission state without capacity: before=%+v blocked=%+v", index, before, blocked)
		}
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	served := make(map[uint16]int, flows)
	deadline := time.Now().Add(2 * time.Second)
	for packets := 0; len(served) != flows && packets < 4*flows && time.Now().Before(deadline); packets++ {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			break
		}
		packet, valid := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatal("returned capacity published a non-TCP packet")
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize >= len(packet.payload) {
			t.Fatal("returned capacity published a TCP control packet instead of queued data")
		}
		port := binary.BigEndian.Uint16(packet.payload[0:2])
		if _, wanted := wantPorts[port]; !wanted {
			t.Fatalf("returned capacity served unexpected TCP source port %d", port)
		}
		served[port]++
	}
	if len(served) != flows {
		t.Fatalf("returned output capacity served %d of %d TCP actors within %d packets: %v", len(served), flows, 4*flows, served)
	}
}

func TestTCPPersistRetryBudgets(t *testing.T) {
	for _, test := range []struct {
		name                     string
		unanswered, closedProbes uint8
		closed, readClosed       bool
		softError, wantError     error
	}{
		{name: "open last probe", unanswered: tcpMaximumRTOs - 1},
		{name: "open exhausted", unanswered: tcpMaximumRTOs, wantError: os.ErrDeadlineExceeded},
		{name: "open soft failure", unanswered: tcpMaximumRTOs, softError: syscall.EHOSTUNREACH, wantError: syscall.EHOSTUNREACH},
		{name: "read half close last probe", readClosed: true, unanswered: tcpMaximumRTOs - 1},
		{name: "read half close exhausted", readClosed: true, unanswered: tcpMaximumRTOs, wantError: os.ErrDeadlineExceeded},
		{name: "full close independent budget", closed: true, unanswered: tcpMaximumRTOs, closedProbes: tcpMaximumRTOs - 1},
		{name: "full close exhausted", closed: true, closedProbes: tcpMaximumRTOs, wantError: os.ErrDeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, remote := netip.MustParseAddr("192.0.2.191"), netip.MustParseAddr("198.51.100.191")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			c := newTCPConn(stack, "tcp4", tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
			c.receiveNext = 200
			c.userClosed, c.readClosed = test.closed, test.readClosed
			c.sendBuffer.append([]byte("queued"))
			state := newTCPEstablishedState(c, 100)
			defer state.finish()
			state.persist = true
			state.persistUnanswered, state.persistClosed = test.unanswered, test.closedProbes
			if test.softError != nil {
				state.ensureLivenessState().lastSoftError = test.softError
			}
			slot, available := stack.outbound.tryReserve()
			if !available {
				t.Fatal("no output slot")
			}
			waiter, err := state.drainPersistOutput(tcpOutputReservation{queue: &stack.outbound, slot: slot})
			wantWaiter := test.wantError == nil && !test.closed
			if !errors.Is(err, test.wantError) || (waiter != nil) != wantWaiter {
				t.Fatalf("persist = %v, waiter %v; want %v", err, waiter, test.wantError)
			}
			if test.wantError != nil {
				if stack.Stats().TCPZeroWindowProbes != 0 || len(stack.outbound.free) != cap(stack.outbound.free) {
					t.Fatal("timeout published a probe or leaked its reservation")
				}
				return
			}
			wire := readOutboundPacket(t, stack)
			packet, ok := parseIPPacket(wire, false)
			if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
				t.Fatalf("invalid probe: %x", wire)
			}
			segment := packet.payload
			headerSize := int(segment[12]>>4) * 4
			if binary.BigEndian.Uint32(segment[4:8]) != 99 || binary.BigEndian.Uint32(segment[8:12]) != 200 || segment[13] != TCPFlagACK || !bytes.Equal(segment[headerSize:], tcpZeroWindowProbe[:]) || transportChecksum(local, remote, ProtocolTCP, segment) != 0 {
				t.Fatalf("invalid probe sequence, flags, payload or checksum: %x", wire)
			}
			wantClosed := test.closedProbes
			if test.closed {
				wantClosed++
			}
			if state.persistUnanswered != tcpMaximumRTOs || state.persistClosed != wantClosed || stack.Stats().TCPZeroWindowProbes != 1 || state.sendNext != 100 {
				t.Fatalf("probe accounting = %+v, stats %+v", state.sendTimer, stack.Stats())
			}
		})
	}
}

func TestTCPPersistACKResetsOnlyUnansweredBudget(t *testing.T) {
	for _, old := range []bool{false, true} {
		t.Run(fmt.Sprintf("old-%v", old), func(t *testing.T) {
			c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			state := tcpEstablishedState{connection: c, sendUnacknowledged: 100, sendNext: 100, bytesAcknowledged: 100, peerMSS: 1200, peerWindow: 0, congestionWindow: 12000, slowStartThreshold: 12000,
				persist: true, persistUnanswered: 14, persistClosed: 9, sendTimer: tcpSendTimerState{persistSince: 1}, controller: newTCPCongestionController(CongestionControlReno)}
			state.ensureLivenessState().lastSoftError = syscall.EHOSTUNREACH
			ack := uint32(100)
			if old {
				ack--
			}
			segment := tcpSegment{sequence: 200, acknowledgement: ack, flags: TCPFlagACK, window: 0}
			state.processAcknowledgment(&segment, time.Now(), 0)
			want := uint8(0)
			if old {
				want = 14
			}
			if state.persistUnanswered != want || state.persistClosed != 9 || state.peerWindow != 0 || state.sendTimer.persistSince != 1 {
				t.Fatalf("ACK budget = %+v, window %d", state.sendTimer, state.peerWindow)
			}
			if old && !errors.Is(state.livenessState.lastSoftError, syscall.EHOSTUNREACH) || !old && state.livenessState.lastSoftError != nil {
				t.Fatalf("ACK soft error = %v, old:%v", state.livenessState.lastSoftError, old)
			}
			state.persist = true
			state.persistUnanswered = tcpMaximumRTOs
			var wantError error = os.ErrDeadlineExceeded
			if old {
				wantError = syscall.EHOSTUNREACH
			}
			if _, err := state.drainPersistOutput(tcpOutputReservation{}); !errors.Is(err, wantError) {
				t.Fatalf("exhausted budget error = %v", err)
			}
			state.livenessState = nil
			state.persistUnanswered = 14
			state.processAcknowledgment(&segment, time.Now(), 0)
			if state.livenessState != nil || state.persistUnanswered != want {
				t.Fatal("persist response allocated liveness state or changed old-ACK accounting")
			}
		})
	}
}

func TestTCPPersistACKClearsSoftErrorWithoutProbeBudget(t *testing.T) {
	for _, old := range []bool{false, true} {
		t.Run(fmt.Sprintf("old-%v", old), func(t *testing.T) {
			c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			state := tcpEstablishedState{
				connection: c, sendUnacknowledged: 100, sendNext: 100,
				bytesAcknowledged: 100, peerMSS: 1200, peerWindow: 0,
				congestionWindow: 12000, slowStartThreshold: 12000,
				controller: newTCPCongestionController(CongestionControlReno),
			}
			state.ensureLivenessState().lastSoftError = syscall.EHOSTUNREACH
			ack := uint32(100)
			if old {
				ack--
			}
			state.processAcknowledgment(&tcpSegment{sequence: 200, acknowledgement: ack, flags: TCPFlagACK, window: 0}, time.Now(), 0)
			if old {
				if !errors.Is(state.livenessState.lastSoftError, syscall.EHOSTUNREACH) {
					t.Fatalf("old ACK cleared soft error: %v", state.livenessState.lastSoftError)
				}
			} else if state.livenessState.lastSoftError != nil {
				t.Fatalf("current ACK retained soft error: %v", state.livenessState.lastSoftError)
			}
		})
	}
}

func TestTCPPersistBudgetWaitsForProbeDeparture(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.192"), netip.MustParseAddr("198.51.100.192")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	c := newTCPConn(stack, "tcp4", tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
	c.sendBuffer.append([]byte("queued"))
	state := newTCPEstablishedState(c, 100)
	defer state.finish()
	state.persist = true
	state.persistUnanswered = tcpMaximumRTOs - 1
	waiter, err := state.drainPersistOutput(tcpOutputReservation{})
	if waiter == nil || err != nil {
		t.Fatalf("last probe = %v, %v", waiter, err)
	}
	if !state.sendTimer.baseDeadline.After(time.Now()) || tcpPersistOutputPending(state, true) {
		t.Fatal("last probe did not register departure before its response deadline")
	}
	if _, departed := waiter.departedTime(stack.timestampEpoch); departed {
		t.Fatal("probe departed before Stack.Read")
	}
	buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
	if n, err := stack.Read(buffers, sizes, 0); err != nil || n != 1 {
		t.Fatalf("Stack.Read = %d, %v", n, err)
	}
	if _, departed := waiter.departedTime(stack.timestampEpoch); !departed {
		t.Fatal("Stack.Read did not complete departure waiter")
	}
	state.sendTimer.baseDeadline = time.Time{}
	if _, err := state.drainPersistOutput(tcpOutputReservation{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("departed exhausted budget = %v", err)
	}
	if stack.Stats().TCPZeroWindowProbes != 1 {
		t.Fatal("departure wait published another probe")
	}
}

func withPausedTCPActor(t *testing.T, c *TCPConn, action func()) {
	t.Helper()
	response := make(chan TCPConnInfo)
	c.mu.Lock()
	if c.pending == nil {
		c.pending = new(tcpPendingEvents)
	}
	c.pending.infoRequests = append(c.pending.infoRequests, response)
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeInfo)
	defer func() {
		select {
		case <-response:
		case <-c.done:
		case <-time.After(2 * time.Second):
			t.Error("actor did not release its diagnostic response")
		}
	}()
	waitFor(t, 2*time.Second, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.pending == nil || len(c.pending.infoRequests) == 0
	})
	select {
	case <-c.done:
		t.Fatalf("actor terminated before timer control: %+v", c.Info())
	default:
	}
	action()
}

func TestTCPPersistDepartureActor(t *testing.T) {
	for _, family := range []struct{ name, local, remote string }{
		{"IPv4", "192.0.2.196", "198.51.100.196"},
		{"IPv6", "2001:db8::196", "2001:db8:1::196"},
	} {
		for _, scenario := range []string{"departure interval", "current ACK after departure", "current ACK", "old ACK", "future ACK", "stale Timestamp", "window reopen", "full Close", "user timeout"} {
			t.Run(family.name+"/"+scenario, func(t *testing.T) {
				local, remote := netip.MustParseAddr(family.local), netip.MustParseAddr(family.remote)
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "departure interval" || scenario == "current ACK after departure" {
					stack.timestampEpoch = time.Now().Add(-2 * tcpMaximumRTO)
					stack.outbound.epoch = stack.timestampEpoch
					stack.loopback.epoch = stack.timestampEpoch
				}
				t.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				network := "tcp4"
				if local.Is6() {
					network = "tcp6"
				}
				c := newTCPConn(stack, network, tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
				c.receiveNext, c.peerWindow, c.peerMSS = 200, 65535, 1460
				if scenario == "stale Timestamp" {
					c.peerTimestamp, c.recentTimestamp = true, 300
				}
				c.sendBuffer.append([]byte{1})
				stack.mu.Lock()
				stack.tcp[c.key] = c
				stack.stats.activeTCPConnections.Add(1)
				stack.mu.Unlock()
				actorTimer := newOwnedTimer()
				go func() {
					defer stack.removeTCP(c)
					defer close(c.done)
					defer actorTimer.close()
					c.finish(c.established(100, actorTimer, tcpInitialReceive{}))
				}()
				c.wakeActor(tcpActorWakeSend)
				t.Cleanup(func() {
					c.abort(net.ErrClosed)
					select {
					case <-c.done:
					case <-time.After(2 * time.Second):
						t.Error("persist actor did not terminate")
					}
				})
				_ = readOutboundPacket(t, stack)
				deliver := func(ack uint32, window uint16) {
					t.Helper()
					wire := buildTestTCP(remote, local, 80, 12345, 200, ack, TCPFlagACK, window, nil, nil)
					if err := writeTestPacket(stack, wire); err != nil {
						t.Fatal(err)
					}
					_ = c.Info()
					_ = c.Info()
				}
				deliver(101, 0)
				if info := c.Info(); info.BytesAcknowledged != 1 || info.PeerWindow != 0 {
					t.Fatalf("initial zero-window ACK = %+v", info)
				}
				if _, err := c.Write([]byte("queued")); err != nil {
					t.Fatal(err)
				}
				firePersist := func() {
					t.Helper()
					_ = c.Info()
					withPausedTCPActor(t, c, func() {
						if !actorTimer.active {
							t.Fatal("persist deadline has no active physical timer")
						}
						if !actorTimer.timer.Stop() {
							<-actorTimer.timer.C
						}
						actorTimer.timer.Reset(0)
					})
				}
				for count := uint64(1); count <= tcpMaximumRTOs; count++ {
					firePersist()
					waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == count })
					if count < tcpMaximumRTOs {
						_ = readOutboundPacket(t, stack)
					}
				}
				var waiter *packetQueueDepartureWaiter
				waitFor(t, time.Second, func() bool {
					waiters := stack.outbound.departureWaiters.Load()
					if waiters == nil {
						return false
					}
					for index := range waiters.slots {
						if current := waiters.slots[index].Load(); current != nil {
							waiter = current
							return true
						}
					}
					return false
				})
				withPausedTCPActor(t, c, func() {
					if actorTimer.active {
						t.Fatal("queue-owned final probe retained an active retry timer")
					}
				})
				if info := c.Info(); info.State != TCPStateEstablished || stack.Stats().TCPZeroWindowProbes != tcpMaximumRTOs {
					t.Fatalf("queued terminal probe = %+v", info)
				}
				switch scenario {
				case "departure interval":
					var responseDeadline time.Time
					withPausedTCPActor(t, c, func() {
						buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
						if n, err := stack.Read(buffers, sizes, 0); err != nil || n != 1 {
							t.Fatalf("Stack.Read = %d, %v", n, err)
						}
						if _, departed := waiter.departedTime(stack.timestampEpoch); !departed {
							t.Fatal("Stack.Read did not complete the final probe's waiter")
						}
						departedAt := time.Now().Add(-tcpMaximumRTO + 250*time.Millisecond)
						waiter.departedAt.Store(int64(monotonicStampAt(stack.timestampEpoch, departedAt)))
						responseDeadline = departedAt.Add(tcpMaximumRTO)
					})
					_ = c.Info()
					_ = c.Info()
					withPausedTCPActor(t, c, func() {
						select {
						case expiredAt := <-actorTimer.timer.C:
							if difference := expiredAt.Sub(responseDeadline); difference < -20*time.Millisecond || difference > 20*time.Millisecond {
								t.Fatalf("persist expiry = %v, want %v", expiredAt, responseDeadline)
							}
							actorTimer.timer.Reset(0)
						case <-time.After(2 * time.Second):
							t.Fatal("persist timer did not use the full departure-based interval")
						}
					})
				case "current ACK after departure":
					withPausedTCPActor(t, c, func() {
						buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
						if n, err := stack.Read(buffers, sizes, 0); err != nil || n != 1 {
							t.Fatalf("Stack.Read = %d, %v", n, err)
						}
						if _, departed := waiter.departedTime(stack.timestampEpoch); !departed {
							t.Fatal("Stack.Read did not complete the final probe's waiter")
						}
						departedAt := time.Now().Add(-tcpMaximumRTO + 500*time.Millisecond)
						waiter.departedAt.Store(int64(monotonicStampAt(stack.timestampEpoch, departedAt)))
						wire := buildTestTCP(remote, local, 80, 12345, 200, 101, TCPFlagACK, 0, nil, nil)
						if err := writeTestPacket(stack, wire); err != nil {
							t.Fatal(err)
						}
					})
					_ = c.Info()
					if probes := stack.Stats().TCPZeroWindowProbes; probes != tcpMaximumRTOs {
						t.Fatalf("current ACK after departure published probe immediately: %d", probes)
					}
					time.Sleep(100 * time.Millisecond)
					if probes := stack.Stats().TCPZeroWindowProbes; probes != tcpMaximumRTOs {
						t.Fatalf("current ACK after departure shortened deadline: %d", probes)
					}
					waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == tcpMaximumRTOs+1 })
					if info := c.Info(); info.State != TCPStateEstablished {
						t.Fatalf("current ACK after departure changed state: %+v", info)
					}
					return
				case "current ACK":
					deliver(101, 0)
					if info := c.Info(); info.State != TCPStateEstablished || stack.Stats().TCPZeroWindowProbes != tcpMaximumRTOs {
						t.Fatalf("current ACK did not retain the next probe interval: %+v", info)
					}
					withPausedTCPActor(t, c, func() {
						if actorTimer.active {
							t.Fatal("current ACK armed persist timer before probe departure")
						}
						if _, departed := waiter.departedTime(stack.timestampEpoch); departed {
							t.Fatal("terminal probe departed before the explicit queue read")
						}
					})
					withPausedTCPActor(t, c, func() {
						buffers, sizes := [][]byte{make([]byte, 1500)}, make([]int, 1)
						if n, err := stack.Read(buffers, sizes, 0); err != nil || n != 1 {
							t.Fatalf("Stack.Read = %d, %v", n, err)
						}
						if _, departed := waiter.departedTime(stack.timestampEpoch); !departed {
							t.Fatal("current ACK discarded the terminal departure waiter")
						}
					})
					firePersist()
					waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == tcpMaximumRTOs+1 })
					if info := c.Info(); info.State != TCPStateEstablished {
						t.Fatalf("current ACK did not cancel the terminal wait: %+v", info)
					}
					return
				case "old ACK", "future ACK", "stale Timestamp":
					if scenario == "old ACK" {
						deliver(100, 0)
					} else if scenario == "future ACK" {
						deliver(102, 0)
					} else {
						wire := buildTestTCP(remote, local, 80, 12345, 200, 101, TCPFlagACK, 0, tcpTimestampOptions(100, 0), nil)
						if err := writeTestPacket(stack, wire); err != nil {
							t.Fatal(err)
						}
						_ = c.Info()
						_ = c.Info()
					}
					withPausedTCPActor(t, c, func() {
						if actorTimer.active || stack.Stats().TCPZeroWindowProbes != tcpMaximumRTOs {
							t.Fatal("unaccepted or old ACK canceled the terminal departure wait")
						}
					})
					return
				case "window reopen":
					deliver(101, 65535)
					waitFor(t, time.Second, func() bool { return c.Info().BytesSent == 1+uint64(len("queued")) })
					if info := c.Info(); info.State != TCPStateEstablished || info.PeerWindow == 0 || stack.Stats().TCPZeroWindowProbes != tcpMaximumRTOs {
						t.Fatalf("window reopening did not replace persist: %+v", info)
					}
					return
				case "full Close":
					if err := c.Close(); err != nil {
						t.Fatal(err)
					}
					firePersist()
					waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == tcpMaximumRTOs+1 })
					for count := uint64(tcpMaximumRTOs + 1); count < 2*tcpMaximumRTOs; count++ {
						deliver(101, 0)
						firePersist()
						waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == count+1 })
					}
					deliver(101, 0)
					firePersist()
				case "user timeout":
					if err := c.SetUserTimeout(100 * time.Millisecond); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-c.done:
				case <-time.After(2 * time.Second):
					t.Fatal("persist actor did not apply its terminal deadline")
				}
				var wantError error = os.ErrDeadlineExceeded
				if scenario == "user timeout" {
					wantError = syscall.ETIMEDOUT
				}
				if info := c.Info(); !errors.Is(info.LastError, wantError) {
					t.Fatalf("persist terminal error = %v, want %v", info.LastError, wantError)
				}
			})
		}
	}
}

func TestTCPPersistResponsivePeerKeepsZeroWindow(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.195"), netip.MustParseAddr("198.51.100.195")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	c := newTCPConn(stack, "tcp4", tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
	c.sendBuffer.append([]byte("queued"))
	state := newTCPEstablishedState(c, 100)
	defer state.finish()
	state.persistClosed = 9
	for i := 0; i < 2*tcpMaximumRTOs; i++ {
		state.persist = true
		state.sendTimer.baseDeadline = time.Time{}
		if waiter, err := state.drainPersistOutput(tcpOutputReservation{}); waiter != nil || err != nil {
			t.Fatalf("probe %d = %v, %v", i, waiter, err)
		}
		_ = readOutboundPacket(t, stack)
		segment := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 0}
		state.processAcknowledgment(&segment, time.Now(), 0)
		if state.persistUnanswered != 0 || state.persistClosed != 9 || !state.persist || state.peerWindow != 0 || state.sendNext != 100 {
			t.Fatalf("response %d changed persist state: %+v", i, state.sendTimer)
		}
	}
	if got := stack.Stats().TCPZeroWindowProbes; got != 2*tcpMaximumRTOs {
		t.Fatalf("probes = %d", got)
	}
	state.peerWindow = 65535
	state.armPersist(time.Time{}, len("queued"), false)
	if state.persist || !state.sendTimer.baseDeadline.IsZero() || state.persistClosed != 0 || state.sendTimer.persistHostQueueToken != 0 {
		t.Fatalf("window reopening retained persist state: %+v", state.sendTimer)
	}
}

func TestTCPPersistCapacityDoesNotConsumeBudgets(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.193"), netip.MustParseAddr("198.51.100.193")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	c := newTCPConn(stack, "tcp4", tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
	c.userClosed = true
	c.sendBuffer.append([]byte("queued"))
	state := newTCPEstablishedState(c, 100)
	defer state.finish()
	state.persist = true
	state.persistUnanswered, state.persistClosed = 14, 14
	before := state.sendTimer
	var held []uint16
	for {
		slot, ok := stack.outbound.tryReserve()
		if !ok {
			break
		}
		held = append(held, slot)
	}
	defer func() {
		for _, slot := range held {
			stack.outbound.releaseReserved(slot)
		}
	}()
	for i := 0; i < 20; i++ {
		if waiter, err := state.drainPersistOutput(tcpOutputReservation{}); waiter != nil || err != nil || state.sendTimer != before || state.persistUnanswered != 14 || state.persistClosed != 14 {
			t.Fatalf("capacity retry = %v, %v, %+v", waiter, err, state.sendTimer)
		}
	}
	if stack.Stats().TCPZeroWindowProbes != 0 {
		t.Fatal("capacity shortage counted a probe")
	}
}

func TestTCPPersistProbeSurvivesStoppedDeviceRead(t *testing.T) {
	for _, test := range []struct {
		name         string
		reopenWindow bool
	}{
		{name: "returned capacity publishes probe"},
		{name: "window update cancels probe", reopenWindow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()

			clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
			link.mu.Lock()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool { return connection.Info().PeerWindow == 0 })

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

			payload := []byte("persist output")
			if n, err := connection.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("Write = %d, %v", n, err)
			}
			_ = connection.Info()
			before := connection.Info()
			persistDelay := before.RetransmissionTimeout
			if persistDelay < time.Second {
				persistDelay = time.Second
			}
			time.Sleep(persistDelay + 100*time.Millisecond)

			responsive := make(chan TCPConnInfo, 1)
			go func() {
				_ = connection.Info()
				responsive <- connection.Info()
			}()
			var blocked TCPConnInfo
			select {
			case blocked = <-responsive:
			case <-time.After(time.Second):
				t.Fatal("Info blocked while an expired persist probe waited for device capacity")
			}
			if blocked.BytesSent != before.BytesSent || stack.Stats().TCPZeroWindowProbes != 0 {
				t.Fatalf("unpublished persist probe = before:%+v blocked:%+v stats:%+v", before, blocked, stack.Stats())
			}

			if test.reopenWindow {
				if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				_ = connection.Info()
				opened := connection.Info()
				if opened.PeerWindow == 0 || opened.BytesSent != before.BytesSent || stack.Stats().TCPZeroWindowProbes != 0 {
					t.Fatalf("window update did not cancel unpublished persist output: before:%+v opened:%+v stats:%+v", before, opened, stack.Stats())
				}
			}

			last := len(held) - 1
			stack.outbound.releaseReserved(held[last])
			held = held[:last]
			entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
			if !available {
				t.Fatal("persist-blocked output did not resume when device capacity returned")
			}
			wire := consumeTestPacket(&stack.outbound, entry)
			packet, valid := parseIPPacket(wire, false)
			if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
				t.Fatalf("persist capacity-wakeup packet is not TCP: %x", wire)
			}
			headerSize := int(packet.payload[12]>>4) * 4
			if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
				t.Fatalf("persist capacity-wakeup header length = %d in %x", headerSize, wire)
			}
			gotSequence := binary.BigEndian.Uint32(packet.payload[4:8])
			gotPayload := packet.payload[headerSize:]
			if test.reopenWindow {
				if gotSequence != acknowledgement || !bytes.Equal(gotPayload, payload) {
					t.Fatalf("window-reopened output did not replace persist probe: %x", wire)
				}
				if probes := stack.Stats().TCPZeroWindowProbes; probes != 0 {
					t.Fatalf("canceled persist probes = %d, want 0", probes)
				}
			} else {
				if gotSequence != acknowledgement-1 || !bytes.Equal(gotPayload, tcpZeroWindowProbe[:]) {
					t.Fatalf("resumed output is not the current zero-window probe: %x", wire)
				}
				waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == 1 })
			}
		})
	}
}

func TestTCPZeroWindowOutstandingUsesResponsiveRetry(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
	link.mu.Lock()
	peer := link.tcp[clientPort]
	serverSequence := peer.serverNext
	link.mu.Unlock()
	payload := []byte("outstanding")
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("initial data was not published")
	}
	original := consumeTestPacket(&stack.outbound, entry)
	packet, err := ParseIPPacket(original)
	if err != nil {
		t.Fatalf("invalid initial data packet: %v", err)
	}
	wire, err := packet.TCPSegment()
	if err != nil || len(wire.Payload) != len(payload) {
		t.Fatalf("initial TCP payload = %d, %v", len(wire.Payload), err)
	}
	if err = link.deliverTCP(8080, clientPort, serverSequence, wire.SequenceNumber, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().PeerWindow == 0 })
	before := connection.Info()
	if before.State != TCPStateEstablished || before.BytesSent != uint64(len(payload)) {
		t.Fatalf("zero-window flight = %+v", before)
	}
	entry, available = waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout+2*time.Second)
	if !available {
		t.Fatal("zero-window retransmission was not published")
	}
	retry := consumeTestPacket(&stack.outbound, entry)
	retryPacket, err := ParseIPPacket(retry)
	if err != nil {
		t.Fatalf("invalid zero-window retransmission: %v", err)
	}
	retryWire, err := retryPacket.TCPSegment()
	if err != nil || retryWire.SequenceNumber != wire.SequenceNumber || len(retryWire.Payload) != len(payload) {
		t.Fatalf("zero-window retry = seq:%d payload:%d, want seq:%d payload:%d", retryWire.SequenceNumber, len(retryWire.Payload), wire.SequenceNumber, len(payload))
	}
	if info := connection.Info(); info.State != TCPStateEstablished || info.PathMTU != before.PathMTU || info.Retransmissions == 0 {
		t.Fatalf("zero-window retry changed connection state: before:%+v after:%+v", before, info)
	}
	if err = link.deliverTCP(8080, clientPort, serverSequence, wire.SequenceNumber, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	guard := before.RetransmissionTimeout / 3
	if guard < 25*time.Millisecond {
		guard = 25 * time.Millisecond
	}
	if entry, available := waitTestPacketEntry(&stack.outbound, guard); available {
		consumeTestPacket(&stack.outbound, entry)
		t.Fatal("current zero-window ACK triggered ordinary recovery output")
	}
}

func TestTCPZeroWindowOutstandingReopensAfterQueueWait(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	payload := []byte("queued zero-window")
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	waitFor(t, time.Second, func() bool { return stack.outbound.len() == 1 })

	clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
	link.mu.Lock()
	peer := link.tcp[clientPort]
	serverSequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()

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
	if len(held) != cap(stack.outbound.free)-1 {
		t.Fatalf("held output slots = %d, want %d", len(held), cap(stack.outbound.free)-1)
	}

	var departureWaiter *packetQueueDepartureWaiter
	waitFor(t, before.RetransmissionTimeout+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		for index := range waiters.slots {
			if waiter := waiters.slots[index].Load(); waiter != nil {
				departureWaiter = waiter
				return true
			}
		}
		return false
	})

	if err := link.deliverTCP(8080, clientPort, serverSequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().PeerWindow == 0 })
	if err := link.deliverTCP(8080, clientPort, serverSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().PeerWindow != 0 })

	entry, available := stack.outbound.tryDequeue()
	if !available {
		t.Fatal("queue-resident TCP data was unavailable")
	}
	original := consumeTestPacket(&stack.outbound, entry)
	if len(original) == 0 {
		t.Fatal("queue-resident TCP data was empty")
	}
	if _, departed := departureWaiter.departedTime(stack.timestampEpoch); !departed {
		t.Fatal("window-reopened target did not record device departure")
	}

	guard := before.RetransmissionTimeout / 3
	if guard < 25*time.Millisecond {
		guard = 25 * time.Millisecond
	}
	if entry, available := waitTestPacketEntry(&stack.outbound, guard); available {
		consumeTestPacket(&stack.outbound, entry)
		t.Fatal("window-reopened target was retransmitted before a new ordinary RTO")
	}
	entry, available = waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout+time.Second)
	if !available {
		t.Fatal("ordinary retransmission did not resume after queue departure")
	}
	consumeTestPacket(&stack.outbound, entry)
	if info := connection.Info(); info.Retransmissions != before.Retransmissions+1 || info.PeerWindow == 0 {
		t.Fatalf("window-reopened retransmission = %+v, want one ordinary retry", info)
	}
}

func TestTCPZeroWindowOutstandingRetryPolicy(t *testing.T) {
	for _, family := range []struct {
		name, local, remote string
		sack                bool
	}{
		{name: "IPv4", local: "192.0.2.197", remote: "198.51.100.197"},
		{name: "IPv6", local: "2001:db8::197", remote: "2001:db8:1::197"},
		{name: "IPv4 fully SACKed", local: "192.0.2.197", remote: "198.51.100.197", sack: true},
		{name: "IPv6 fully SACKed", local: "2001:db8::197", remote: "2001:db8:1::197", sack: true},
	} {
		t.Run(family.name, func(t *testing.T) {
			local, remote := netip.MustParseAddr(family.local), netip.MustParseAddr(family.remote)
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			network := "tcp4"
			if local.Is6() {
				network = "tcp6"
			}
			c := newTCPConn(stack, network, tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
			c.receiveNext, c.peerWindow, c.peerMSS = 200, 65535, 1200
			c.peerSACK = family.sack
			c.sendBuffer.append([]byte{1})
			stack.mu.Lock()
			stack.tcp[c.key] = c
			stack.stats.activeTCPConnections.Add(1)
			stack.mu.Unlock()
			actorTimer := newOwnedTimer()
			go func() {
				defer stack.removeTCP(c)
				defer close(c.done)
				defer actorTimer.close()
				c.finish(c.established(100, actorTimer, tcpInitialReceive{}))
			}()
			t.Cleanup(func() {
				c.abort(net.ErrClosed)
				select {
				case <-c.done:
				case <-time.After(2 * time.Second):
					t.Error("closed zero-window actor did not terminate")
				}
			})
			c.wakeActor(tcpActorWakeSend)
			_ = readOutboundPacket(t, stack)
			respond := func() {
				t.Helper()
				var options []byte
				if family.sack {
					var sack [10]byte
					sack[0], sack[1] = TCPHeaderOptionSACK, 10
					binary.BigEndian.PutUint32(sack[2:6], 100)
					binary.BigEndian.PutUint32(sack[6:10], 101)
					options = sack[:]
				}
				wire := buildTestTCP(remote, local, 80, 12345, 200, 100, TCPFlagACK, 0, options, nil)
				if err := writeTestPacket(stack, wire); err != nil {
					t.Fatal(err)
				}
				_ = c.Info()
				_ = c.Info()
			}
			respond()
			if info := c.Info(); info.PeerWindow != 0 || info.BytesSent != 1 || info.BytesAcknowledged != 0 {
				t.Fatalf("outstanding zero-window flight = %+v", info)
			}
			fireTimer := func() {
				t.Helper()
				_ = c.Info()
				withPausedTCPActor(t, c, func() {
					if !actorTimer.active {
						t.Fatal("outstanding zero-window flight has no RTO")
					}
					if !actorTimer.timer.Stop() {
						<-actorTimer.timer.C
					}
					actorTimer.timer.Reset(0)
				})
			}
			for count := 1; count <= 2*tcpMaximumRTOs+1; count++ {
				if count == tcpMaximumRTOs+2 {
					if err = c.Close(); err != nil {
						t.Fatal(err)
					}
				}
				fireTimer()
				packet, err := ParseIPPacket(readOutboundPacket(t, stack))
				if err != nil {
					t.Fatal(err)
				}
				wire, err := packet.TCPSegment()
				if err != nil || wire.SequenceNumber != 100 || len(wire.Payload) != 1 {
					t.Fatalf("retry %d = %+v, %v", count, wire, err)
				}
				respond()
			}
			fireTimer()
			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				t.Fatal("responsive zero-window peer removed the full-Close retry bound")
			}
			if info := c.Info(); !errors.Is(info.LastError, os.ErrDeadlineExceeded) || info.Retransmissions != 2*tcpMaximumRTOs+1 {
				t.Fatalf("full-Close terminal state = %+v", info)
			}
		})
	}
}

func TestTCPKeepAliveProbeSurvivesStoppedDeviceRead(t *testing.T) {
	for _, test := range []struct {
		name              string
		inboundActivity   bool
		applicationOutput bool
		closeWrite        bool
		userTimeout       bool
		oldACK            bool
		oldACKData        bool
	}{
		{name: "returned capacity publishes probe"},
		{name: "inbound activity cancels probe", inboundActivity: true},
		{name: "application output cancels probe", applicationOutput: true},
		{name: "CloseWrite cancels probe", closeWrite: true},
		{name: "delayed first probe with user timeout", userTimeout: true},
		{name: "old ACK preserves pending probe and retry count", oldACK: true},
		{name: "old ACK data cancels pending probe", inboundActivity: true, oldACKData: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()

			clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
			link.mu.Lock()
			peer := link.tcp[clientPort]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			if test.oldACK || test.oldACKData {
				if _, err := connection.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				packet, err := ParseIPPacket(readOutboundPacket(t, stack))
				if err != nil {
					t.Fatal(err)
				}
				sent, err := packet.TCPSegment()
				if err != nil || len(sent.Payload) != 1 {
					t.Fatalf("ACK history transmission = %+v, %v", sent, err)
				}
				acknowledgement = sent.SequenceNumber + 1
				if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				waitFor(t, time.Second, func() bool { return connection.Info().BytesAcknowledged == 1 })
			}

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

			keepAlive := KeepAliveConfig{Idle: 100 * time.Millisecond, Interval: 100 * time.Millisecond, Count: 3}
			if test.userTimeout {
				keepAlive.Interval = 300 * time.Millisecond
			}
			if test.oldACK {
				keepAlive.Interval, keepAlive.Count = 300*time.Millisecond, 1
			}
			if err := connection.SetKeepAliveConfig(keepAlive); err != nil {
				t.Fatal(err)
			}
			if test.userTimeout {
				if err := connection.SetUserTimeout(75 * time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			if err := connection.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			_ = connection.Info()
			_ = connection.Info()
			time.Sleep(keepAlive.Idle + 50*time.Millisecond)

			responsive := make(chan TCPConnInfo, 1)
			go func() {
				_ = connection.Info()
				responsive <- connection.Info()
			}()
			select {
			case info := <-responsive:
				if info.KeepAliveConfig != keepAlive || stack.Stats().TCPKeepAliveProbes != 0 {
					t.Fatalf("unpublished keepalive probe = info:%+v stats:%+v", info, stack.Stats())
				}
			case <-time.After(time.Second):
				t.Fatal("Info blocked while a keepalive probe waited for device capacity")
			}

			if test.inboundActivity {
				payload := []byte("peer activity")
				link.mu.Lock()
				peer.serverNext += uint32(len(payload))
				link.mu.Unlock()
				ack := acknowledgement
				if test.oldACKData {
					ack--
				}
				if err := link.deliverTCP(8080, clientPort, sequence, ack, TCPFlagACK|TCPFlagPSH, 65535, nil, payload); err != nil {
					t.Fatal(err)
				}
				if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
					t.Fatalf("Read after keepalive cancellation = %q, %v", received, err)
				}
				if err := connection.SetQuickACK(true); err != nil {
					t.Fatal(err)
				}
				_ = connection.Info()
				_ = connection.Info()
			} else if test.applicationOutput {
				payload := []byte("application output")
				if n, err := connection.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("Write = %d, %v", n, err)
				}
				_ = connection.Info()
				_ = connection.Info()
			} else if test.closeWrite {
				if err := connection.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				_ = connection.Info()
				_ = connection.Info()
			} else if test.oldACK {
				if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement-1, TCPFlagACK, 65535, nil, nil); err != nil {
					t.Fatal(err)
				}
				_ = connection.Info()
				_ = connection.Info()
			}

			last := len(held) - 1
			stack.outbound.releaseReserved(held[last])
			held = held[:last]
			entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
			if !available {
				t.Fatal("keepalive-blocked output did not resume when device capacity returned")
			}
			wire := consumeTestPacket(&stack.outbound, entry)
			packet, valid := parseIPPacket(wire, false)
			if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
				t.Fatalf("keepalive capacity-wakeup packet is not TCP: %x", wire)
			}
			headerSize := int(packet.payload[12]>>4) * 4
			if headerSize < tcpHeaderSize || headerSize > len(packet.payload) || packet.payload[13]&TCPFlagACK == 0 {
				t.Fatalf("invalid keepalive capacity-wakeup TCP segment: %x", wire)
			}
			gotSequence := binary.BigEndian.Uint32(packet.payload[4:8])
			gotAcknowledgement := binary.BigEndian.Uint32(packet.payload[8:12])
			if test.applicationOutput {
				if gotSequence != acknowledgement || !bytes.Equal(packet.payload[headerSize:], []byte("application output")) {
					t.Fatalf("application output did not replace keepalive probe: %x", wire)
				}
				if probes := stack.Stats().TCPKeepAliveProbes; probes != 0 {
					t.Fatalf("application-canceled keepalive probes = %d, want 0", probes)
				}
			} else if test.closeWrite {
				if gotSequence != acknowledgement || headerSize != len(packet.payload) || packet.payload[13] != TCPFlagACK|TCPFlagFIN {
					t.Fatalf("CloseWrite did not replace keepalive probe with FIN: %x", wire)
				}
				if probes := stack.Stats().TCPKeepAliveProbes; probes != 0 {
					t.Fatalf("CloseWrite-canceled keepalive probes = %d, want 0", probes)
				}
			} else if test.inboundActivity {
				if headerSize != len(packet.payload) {
					t.Fatalf("activity response is not a payload-free ACK: %x", wire)
				}
				if gotSequence != acknowledgement || gotAcknowledgement != sequence+uint32(len("peer activity")) {
					t.Fatalf("activity ACK did not replace keepalive probe: %x", wire)
				}
				if probes := stack.Stats().TCPKeepAliveProbes; probes != 0 {
					t.Fatalf("canceled keepalive probes = %d, want 0", probes)
				}
			} else {
				if headerSize != len(packet.payload) {
					t.Fatalf("keepalive probe carries payload: %x", wire)
				}
				if gotSequence != acknowledgement-1 || gotAcknowledgement != sequence {
					t.Fatalf("resumed output is not the current keepalive probe: %x", wire)
				}
				waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })
				if test.oldACK {
					if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement-1, TCPFlagACK, 65535, nil, nil); err != nil {
						t.Fatal(err)
					}
					_ = connection.Info()
					_ = connection.Info()
					select {
					case <-connection.done:
						if info := connection.Info(); !errors.Is(info.LastError, syscall.ETIMEDOUT) || stack.Stats().TCPKeepAliveProbes != 1 {
							t.Fatalf("old ACK changed keepalive retry count: info:%+v probes:%d", info, stack.Stats().TCPKeepAliveProbes)
						}
					case <-time.After(time.Second):
						t.Fatal("old ACK postponed the keepalive timeout")
					}
				}
				if test.userTimeout {
					select {
					case <-connection.done:
						t.Fatalf("delayed first publication caused an immediate timeout: %+v", connection.Info())
					case <-time.After(keepAlive.Interval / 3):
					}
				}
			}
		})
	}
}

func TestTCPKeepAliveOldACKDataPostponesPendingProbe(t *testing.T) {
	for _, userTimeout := range []time.Duration{0, 750 * time.Millisecond} {
		t.Run(userTimeout.String(), func(t *testing.T) {
			link, stack, c := newManuallyPumpedTCPConnection(t)
			defer c.Close()
			if _, err := c.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			packet, err := ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			sent, err := packet.TCPSegment()
			if err != nil || len(sent.Payload) != 1 {
				t.Fatalf("ACK history transmission = %+v, %v", sent, err)
			}
			link.mu.Lock()
			sequence := link.tcp[c.key.local.Port()].serverNext
			link.mu.Unlock()
			ack := sent.SequenceNumber + 1
			if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK, 65535, nil, nil); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool { return c.Info().BytesAcknowledged == 1 })
			config := KeepAliveConfig{Idle: 200 * time.Millisecond, Interval: 100 * time.Millisecond, Count: 2}
			if err := c.SetKeepAliveConfig(config); err != nil {
				t.Fatal(err)
			}
			if err := c.SetUserTimeout(userTimeout); err != nil {
				t.Fatal(err)
			}
			if err := c.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			_ = readOutboundPacket(t, stack)
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })
			var held []uint16
			defer func() {
				for _, slot := range held {
					stack.outbound.releaseReserved(slot)
				}
			}()
			for slot, ok := stack.outbound.tryReserve(); ok; slot, ok = stack.outbound.tryReserve() {
				held = append(held, slot)
			}
			if len(held) != cap(stack.outbound.free) {
				t.Fatalf("held output slots = %d, want %d", len(held), cap(stack.outbound.free))
			}
			time.Sleep(config.Interval + 50*time.Millisecond)
			_ = c.Info()
			_ = c.Info()
			if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, ack-1, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte("x")); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var data [1]byte
			if _, err := io.ReadFull(c, data[:]); err != nil || data[0] != 'x' {
				t.Fatalf("old-ACK receive data = %q, %v", data, err)
			}
			if err := c.SetQuickACK(true); err != nil {
				t.Fatal(err)
			}
			_ = c.Info()
			_ = c.Info()
			last := len(held) - 1
			stack.outbound.releaseReserved(held[last])
			held = held[:last]
			packet, err = ParseIPPacket(readOutboundPacket(t, stack))
			if err != nil {
				t.Fatal(err)
			}
			response, err := packet.TCPSegment()
			if err != nil || response.SequenceNumber != ack || response.AcknowledgmentNumber != sequence+1 || len(response.Payload) != 0 {
				t.Fatalf("data ACK did not supersede keepalive: %+v, %v", response, err)
			}
			select {
			case <-c.done:
				t.Fatalf("old-ACK data did not postpone idle close: %+v", c.Info())
			case <-time.After(config.Idle / 2):
			}
			if probes := stack.Stats().TCPKeepAliveProbes; probes != 1 {
				t.Fatalf("capacity retry probed an active receiver: probes=%d, want 1", probes)
			}
			_ = readOutboundPacket(t, stack)
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 2 })
			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				t.Fatal("new data reset the unanswered keepalive budget")
			}
			if !errors.Is(c.Info().LastError, syscall.ETIMEDOUT) {
				t.Fatalf("idle close = %v, want ETIMEDOUT", c.Info().LastError)
			}
			if userTimeout == 0 && stack.Stats().TCPKeepAliveProbes != uint64(config.Count) {
				t.Fatalf("data reset the probe count: probes=%d, want %d", stack.Stats().TCPKeepAliveProbes, config.Count)
			}
		})
	}
}

func TestTCPKeepAliveCapacityRetryHonorsUserTimeout(t *testing.T) {
	for _, test := range []struct {
		name              string
		expired           bool
		applicationOutput bool
		closeWrite        bool
		concurrentOutput  bool
	}{
		{name: "before timeout"},
		{name: "after timeout", expired: true},
		{name: "queued Write supersedes expired idle timeout", expired: true, applicationOutput: true},
		{name: "queued FIN supersedes expired idle timeout", expired: true, closeWrite: true},
		{name: "Write wake races returned capacity", expired: true, applicationOutput: true, concurrentOutput: true},
		{name: "CloseWrite wake races returned capacity", expired: true, closeWrite: true, concurrentOutput: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stack, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			keepAlive := KeepAliveConfig{Idle: 100 * time.Millisecond, Interval: 600 * time.Millisecond, Count: 20}
			userTimeout := 2 * time.Second
			if err := connection.SetKeepAliveConfig(keepAlive); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetUserTimeout(userTimeout); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetKeepAlive(true); err != nil {
				t.Fatal(err)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
			if !available {
				t.Fatal("initial keepalive probe was not published")
			}
			wire := consumeTestPacket(&stack.outbound, entry)
			initial, valid := parseIPPacket(wire, false)
			if !valid || initial.protocol != ProtocolTCP || len(initial.payload) < tcpHeaderSize || int(initial.payload[12]>>4)*4 != len(initial.payload) || initial.payload[13] != TCPFlagACK {
				t.Fatalf("initial output is not a keepalive ACK: %x", wire)
			}
			waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })

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
			time.Sleep(keepAlive.Interval + 100*time.Millisecond)
			_ = connection.Info()
			_ = connection.Info()

			payload := []byte("new application output")
			if test.applicationOutput {
				if n, err := connection.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("Write = %d, %v", n, err)
				}
			} else if test.closeWrite {
				if err := connection.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if !test.concurrentOutput {
				_ = connection.Info()
				_ = connection.Info()
			}

			connection.mu.Lock()
			locked := true
			defer func() {
				if locked {
					connection.mu.Unlock()
				}
			}()
			last := len(held) - 1
			stack.outbound.releaseReserved(held[last])
			held = held[:last]
			if !test.applicationOutput && !test.closeWrite {
				waitFor(t, time.Second, func() bool { return len(stack.outbound.free) == 0 })
			}
			if test.expired {
				time.Sleep(userTimeout)
			}
			connection.mu.Unlock()
			locked = false

			if test.expired && !test.applicationOutput && !test.closeWrite {
				select {
				case <-connection.done:
				case <-time.After(keepAlive.Interval / 2):
					t.Fatalf("capacity retry postponed an expired user timeout: %+v", connection.Info())
				}
				if info := connection.Info(); !errors.Is(info.LastError, syscall.ETIMEDOUT) || stack.Stats().TCPKeepAliveProbes != 1 {
					t.Fatalf("expired capacity retry = info:%+v stats:%+v", info, stack.Stats())
				}
				for entry, available := stack.outbound.tryDequeue(); available; entry, available = stack.outbound.tryDequeue() {
					stack.outbound.release(entry)
				}
				if free := len(stack.outbound.free); free != cap(stack.outbound.free)-len(held) {
					t.Fatalf("free output slots after timeout = %d, want %d", free, cap(stack.outbound.free)-len(held))
				}
				return
			}
			entry, available = waitTestPacketEntry(&stack.outbound, keepAlive.Interval/2)
			if !available {
				t.Fatal("capacity retry did not publish the expected TCP output")
			}
			wire = consumeTestPacket(&stack.outbound, entry)
			packet, valid := parseIPPacket(wire, false)
			if test.applicationOutput || test.closeWrite {
				if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
					t.Fatalf("capacity retry did not publish TCP: %x", wire)
				}
				headerSize := int(packet.payload[12]>>4) * 4
				if headerSize < tcpHeaderSize || headerSize > len(packet.payload) || binary.BigEndian.Uint32(packet.payload[4:8]) != binary.BigEndian.Uint32(initial.payload[4:8])+1 {
					t.Fatalf("invalid resumed sequence space: %x", wire)
				}
				if test.applicationOutput && !bytes.Equal(packet.payload[headerSize:], payload) || test.closeWrite && (headerSize != len(packet.payload) || packet.payload[13] != TCPFlagACK|TCPFlagFIN) {
					t.Fatalf("queued data or FIN did not supersede idle probe: %x", wire)
				}
				if info := connection.Info(); info.LastError != nil || stack.Stats().TCPKeepAliveProbes != 1 {
					t.Fatalf("idle timeout consumed queued output: info:%+v stats:%+v", info, stack.Stats())
				}
				if free := len(stack.outbound.free); free != cap(stack.outbound.free)-len(held) {
					t.Fatalf("free output slots after resumed output = %d, want %d", free, cap(stack.outbound.free)-len(held))
				}
				return
			}
			if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || int(packet.payload[12]>>4)*4 != len(packet.payload) || packet.payload[13] != TCPFlagACK || !bytes.Equal(packet.payload[4:12], initial.payload[4:12]) {
				t.Fatalf("capacity retry is not the current keepalive probe: %x", wire)
			}
			if info := connection.Info(); info.State != TCPStateEstablished || info.LastError != nil || stack.Stats().TCPKeepAliveProbes != 2 {
				t.Fatalf("unexpired capacity retry = info:%+v stats:%+v", info, stack.Stats())
			}
		})
	}
}

func TestTCPLivenessTimeoutSurvivesStoppedDeviceRead(t *testing.T) {
	t.Run("idle timeout", func(t *testing.T) {
		_, stack, connection := newManuallyPumpedTCPConnection(t)
		defer connection.Close()

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

		if err := connection.SetKeepAliveConfig(KeepAliveConfig{Idle: 25 * time.Millisecond, Interval: 25 * time.Millisecond, Count: 20}); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetIdleTimeout(125 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		_ = connection.Info()
		_ = connection.Info()
		select {
		case <-connection.done:
		case <-time.After(time.Second):
			t.Fatal("idle timeout was suppressed by a keepalive waiting for device capacity")
		}
		if info := connection.Info(); !errors.Is(info.LastError, os.ErrDeadlineExceeded) || stack.Stats().TCPKeepAliveProbes != 0 {
			t.Fatalf("queue-blocked idle timeout = info:%+v stats:%+v", info, stack.Stats())
		}
	})

	t.Run("user timeout", func(t *testing.T) {
		_, stack, connection := newManuallyPumpedTCPConnection(t)
		defer connection.Close()
		if err := connection.SetKeepAliveConfig(KeepAliveConfig{Idle: 25 * time.Millisecond, Interval: 25 * time.Millisecond, Count: 20}); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetUserTimeout(150 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		_ = connection.Info()
		_ = connection.Info()

		entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
		if !available {
			t.Fatal("initial keepalive probe was not published")
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || int(packet.payload[12]>>4)*4 != len(packet.payload) {
			t.Fatalf("initial keepalive output is not a payload-free TCP segment: %x", wire)
		}
		waitFor(t, time.Second, func() bool { return stack.Stats().TCPKeepAliveProbes == 1 })

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

		select {
		case <-connection.done:
		case <-time.After(time.Second):
			t.Fatal("user timeout was suppressed by a keepalive waiting for device capacity")
		}
		if info := connection.Info(); !errors.Is(info.LastError, syscall.ETIMEDOUT) || stack.Stats().TCPKeepAliveProbes != 1 {
			t.Fatalf("queue-blocked keepalive user timeout = info:%+v stats:%+v", info, stack.Stats())
		}
	})
}

func TestTCPSACKRecoverySurvivesStoppedDeviceRead(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	payload := bytes.Repeat([]byte{0x5a}, 5*before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	type dataSegment struct {
		wire     []byte
		sequence uint32
		payload  []byte
	}
	segments := make([]dataSegment, 0, 5)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		if len(segmentPayload) == 0 {
			t.Fatalf("initial output is not a data segment: %x", wire)
		}
		segments = append(segments, dataSegment{
			wire:     wire,
			sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
			payload:  append([]byte(nil), segmentPayload...),
		})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) < 4 {
		t.Fatalf("initial TCP flight has %d segments, want at least 4", len(segments))
	}

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
	for _, segment := range segments[1:] {
		if err := link.handleOutboundPacket(segment.wire); err != nil {
			t.Fatal(err)
		}
	}
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while SACK recovery waited for device capacity")
			return TCPConnInfo{}
		}
	}
	var blocked TCPConnInfo
	for {
		blocked = responsiveInfo()
		if blocked.InboundQueueBytes == 0 {
			break
		}
	}
	if !blocked.FastRecovery {
		t.Fatalf("SACK feedback did not enter fast recovery: %+v", blocked)
	}
	if blocked.Retransmissions != before.Retransmissions {
		t.Fatalf("unpublished SACK recovery counted %d retransmissions, want %d", blocked.Retransmissions, before.Retransmissions)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("SACK recovery did not resume when device capacity returned")
	}
	retransmissionWire := consumeTestPacket(&stack.outbound, entry)
	retransmission, valid := parseIPPacket(retransmissionWire, false)
	if !valid || retransmission.protocol != ProtocolTCP || len(retransmission.payload) < tcpHeaderSize {
		t.Fatalf("recovery output is not TCP: %x", retransmissionWire)
	}
	headerSize := int(retransmission.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(retransmission.payload) {
		t.Fatalf("recovery TCP header length = %d in %x", headerSize, retransmissionWire)
	}
	if sequence := binary.BigEndian.Uint32(retransmission.payload[4:8]); sequence != segments[0].sequence {
		t.Fatalf("retransmitted sequence = %#x, want first lost sequence %#x", sequence, segments[0].sequence)
	}
	if !bytes.Equal(retransmission.payload[headerSize:], segments[0].payload) {
		t.Fatal("retransmitted first-segment payload mismatch")
	}
	after := responsiveInfo()
	if after.Retransmissions != before.Retransmissions+1 {
		t.Fatalf("published SACK recovery counted %d retransmissions, want %d", after.Retransmissions, before.Retransmissions+1)
	}
	if err := link.handleOutboundPacket(retransmissionWire); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("SACK-recovered TCP echo payload mismatch")
	}
}

type tcpRecoveryLossRecorder struct {
	mu        sync.Mutex
	algorithm CongestionController
	losses    int
	timeouts  int
}

func (r *tcpRecoveryLossRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventLoss || event.Type == CongestionEventTimeout {
		r.mu.Lock()
		if event.Type == CongestionEventLoss {
			r.losses++
		} else {
			r.timeouts++
		}
		r.mu.Unlock()
	}
	r.algorithm.HandleCongestionEvent(event)
}

func (r *tcpRecoveryLossRecorder) lossCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.losses
}

func (r *tcpRecoveryLossRecorder) timeoutCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timeouts
}

func TestTCPTailLossProbeSurvivesStoppedDeviceRead(t *testing.T) {
	_, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	payload := bytes.Repeat([]byte{0x46}, 2*before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	type dataSegment struct {
		sequence uint32
		payload  []byte
	}
	segments := make([]dataSegment, 0, 2)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		if len(segmentPayload) == 0 {
			t.Fatalf("initial output is not a data segment: %x", wire)
		}
		segments = append(segments, dataSegment{
			sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
			payload:  append([]byte(nil), segmentPayload...),
		})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) < 2 {
		t.Fatalf("initial TCP flight has %d segments, want at least 2", len(segments))
	}

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
	probeDelay := tailLossProbeDelay(before.RTT, before.RetransmissionTimeout, false)
	if probeDelay >= before.RetransmissionTimeout {
		t.Fatalf("tail-loss probe delay = %v, want less than RTO %v", probeDelay, before.RetransmissionTimeout)
	}
	time.Sleep(probeDelay + (before.RetransmissionTimeout-probeDelay)/2)
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while a tail-loss probe waited for device capacity")
			return TCPConnInfo{}
		}
	}
	_ = responsiveInfo()
	blocked := responsiveInfo()
	if blocked.Retransmissions != before.Retransmissions || blocked.RetransmissionRecovery {
		t.Fatalf("unpublished tail-loss probe = before:%+v blocked:%+v", before, blocked)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("tail-loss probe did not resume when device capacity returned")
	}
	probeWire := consumeTestPacket(&stack.outbound, entry)
	probe, valid := parseIPPacket(probeWire, false)
	if !valid || probe.protocol != ProtocolTCP || len(probe.payload) < tcpHeaderSize {
		t.Fatalf("tail-loss probe is not TCP: %x", probeWire)
	}
	headerSize := int(probe.payload[12]>>4) * 4
	lastSegment := segments[len(segments)-1]
	if headerSize < tcpHeaderSize || headerSize > len(probe.payload) || binary.BigEndian.Uint32(probe.payload[4:8]) != lastSegment.sequence || !bytes.Equal(probe.payload[headerSize:], lastSegment.payload) {
		t.Fatalf("tail-loss probe does not retransmit the final range: %x", probeWire)
	}
	after := responsiveInfo()
	if after.Retransmissions != before.Retransmissions+1 || stack.Stats().TCPTailLossProbes != 1 {
		t.Fatalf("published tail-loss probe = before:%+v after:%+v stats:%+v", before, after, stack.Stats())
	}
}

func TestTCPTailLossProbeNewDataSurvivesStoppedDeviceRead(t *testing.T) {
	_, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	payload := bytes.Repeat([]byte{0x68}, int(before.CongestionWindow)+before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	firstSequence := uint32(0)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < int(before.CongestionWindow) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("initial TCP flight = %d bytes, want congestion window %d", queuedBytes, before.CongestionWindow)
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		if queuedBytes == 0 {
			firstSequence = binary.BigEndian.Uint32(packet.payload[4:8])
		}
		queuedBytes += len(packet.payload) - headerSize
	}
	if queuedBytes != int(before.CongestionWindow) {
		t.Fatalf("initial TCP flight = %d bytes, want congestion window %d", queuedBytes, before.CongestionWindow)
	}

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
	probeDelay := tailLossProbeDelay(before.RTT, before.RetransmissionTimeout, false)
	if probeDelay >= before.RetransmissionTimeout {
		t.Fatalf("tail-loss probe delay = %v, want less than RTO %v", probeDelay, before.RetransmissionTimeout)
	}
	time.Sleep(probeDelay + (before.RetransmissionTimeout-probeDelay)/2)
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while a new-data tail-loss probe waited for device capacity")
			return TCPConnInfo{}
		}
	}
	_ = responsiveInfo()
	blocked := responsiveInfo()
	if blocked.Retransmissions != before.Retransmissions || blocked.BytesSent != before.BytesSent+uint64(queuedBytes) {
		t.Fatalf("unpublished new-data tail-loss probe = before:%+v blocked:%+v", before, blocked)
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("new-data tail-loss probe did not resume when device capacity returned")
	}
	probeWire := consumeTestPacket(&stack.outbound, entry)
	probe, valid := parseIPPacket(probeWire, false)
	if !valid || probe.protocol != ProtocolTCP || len(probe.payload) < tcpHeaderSize {
		t.Fatalf("new-data tail-loss probe is not TCP: %x", probeWire)
	}
	headerSize := int(probe.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(probe.payload) {
		t.Fatalf("new-data tail-loss probe header length = %d in %x", headerSize, probeWire)
	}
	probePayload := probe.payload[headerSize:]
	wantSequence := firstSequence + uint32(queuedBytes)
	if binary.BigEndian.Uint32(probe.payload[4:8]) != wantSequence || !bytes.Equal(probePayload, payload[queuedBytes:queuedBytes+len(probePayload)]) {
		t.Fatalf("tail-loss probe did not publish current unsent data: %x", probeWire)
	}
	after := responsiveInfo()
	if after.Retransmissions != before.Retransmissions || after.BytesSent != before.BytesSent+uint64(queuedBytes+len(probePayload)) || stack.Stats().TCPTailLossProbes != 1 {
		t.Fatalf("published new-data tail-loss probe = before:%+v after:%+v stats:%+v", before, after, stack.Stats())
	}
}

func TestTCPRTORecoverySurvivesStoppedDeviceRead(t *testing.T) {
	_, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	recorder := &tcpRecoveryLossRecorder{algorithm: newRenoCongestionControl()}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-rto-device-backpressure", New: func(CongestionControlContext) CongestionController { return recorder },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x2f}, 2*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	type dataSegment struct {
		sequence uint32
		payload  []byte
	}
	segments := make([]dataSegment, 0, 2)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		segments = append(segments, dataSegment{
			sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
			payload:  append([]byte(nil), segmentPayload...),
		})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) < 2 {
		t.Fatalf("initial TCP flight has %d segments, want at least 2", len(segments))
	}
	probeEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout)
	if !available {
		t.Fatal("tail-loss probe was not published before the RTO")
	}
	probeWire := consumeTestPacket(&stack.outbound, probeEntry)
	probe, valid := parseIPPacket(probeWire, false)
	if !valid || probe.protocol != ProtocolTCP || len(probe.payload) < tcpHeaderSize || binary.BigEndian.Uint32(probe.payload[4:8]) != segments[len(segments)-1].sequence {
		t.Fatalf("pre-RTO output is not the final-range tail-loss probe: %x", probeWire)
	}
	afterProbe := connection.Info()
	if afterProbe.Retransmissions != before.Retransmissions+1 || afterProbe.RetransmissionRecovery {
		t.Fatalf("tail-loss probe state = before:%+v after:%+v", before, afterProbe)
	}

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
	waitFor(t, 2*before.RetransmissionTimeout+time.Second, func() bool { return recorder.timeoutCount() != 0 })
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while RTO output waited for device capacity")
			return TCPConnInfo{}
		}
	}
	blocked := responsiveInfo()
	if !blocked.RetransmissionRecovery || blocked.Retransmissions != afterProbe.Retransmissions || recorder.timeoutCount() != 1 {
		t.Fatalf("unpublished RTO recovery = after-probe:%+v blocked:%+v timeout-events:%d", afterProbe, blocked, recorder.timeoutCount())
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	rtoEntry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("RTO retransmission did not resume when device capacity returned")
	}
	rtoWire := consumeTestPacket(&stack.outbound, rtoEntry)
	rtoPacket, valid := parseIPPacket(rtoWire, false)
	if !valid || rtoPacket.protocol != ProtocolTCP || len(rtoPacket.payload) < tcpHeaderSize {
		t.Fatalf("RTO recovery output is not TCP: %x", rtoWire)
	}
	headerSize := int(rtoPacket.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(rtoPacket.payload) || binary.BigEndian.Uint32(rtoPacket.payload[4:8]) != segments[0].sequence || !bytes.Equal(rtoPacket.payload[headerSize:], segments[0].payload) {
		t.Fatalf("RTO recovery does not retransmit the first range: %x", rtoWire)
	}
	after := responsiveInfo()
	if after.Retransmissions != afterProbe.Retransmissions+1 || recorder.timeoutCount() != 1 {
		t.Fatalf("published RTO recovery = after-probe:%+v after:%+v timeout-events:%d", afterProbe, after, recorder.timeoutCount())
	}
}

func TestTCPRTOPendingOutputCanceledByLateACK(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	recorder := &tcpRecoveryLossRecorder{algorithm: newRenoCongestionControl()}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-rto-late-ack", New: func(CongestionControlContext) CongestionController { return recorder },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x91}, 2*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	type dataSegment struct {
		wire    []byte
		payload []byte
	}
	segments := make([]dataSegment, 0, 2)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		segments = append(segments, dataSegment{wire: wire, payload: append([]byte(nil), segmentPayload...)})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) < 2 {
		t.Fatalf("initial TCP flight has %d segments, want at least 2", len(segments))
	}
	probeEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout)
	if !available {
		t.Fatal("tail-loss probe was not published before the RTO")
	}
	consumeTestPacket(&stack.outbound, probeEntry)
	afterProbe := connection.Info()

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
	waitFor(t, 2*before.RetransmissionTimeout+time.Second, func() bool { return recorder.timeoutCount() != 0 })
	if err = link.handleOutboundPacket(segments[0].wire); err != nil {
		t.Fatal(err)
	}
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked after a late ACK canceled pending RTO output")
			return TCPConnInfo{}
		}
	}
	_ = responsiveInfo()
	afterACK := responsiveInfo()
	if afterACK.RetransmissionRecovery || afterACK.Retransmissions != afterProbe.Retransmissions || afterACK.BytesAcknowledged-before.BytesAcknowledged != uint64(len(segments[0].payload)) || afterACK.SpuriousRecoveryUndos == 0 {
		t.Fatalf("late-ACK timeout cancellation = before:%+v after-probe:%+v after-ACK:%+v", before, afterProbe, afterACK)
	}
	if recorder.timeoutCount() != 1 {
		t.Fatalf("late-ACK timeout events = %d, want 1", recorder.timeoutCount())
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}
}

func TestTCPRTOPendingOutputCanceledAfterCongestionControlChange(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	recorder := &tcpRecoveryLossRecorder{algorithm: newRenoCongestionControl()}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-rto-controller-change", New: func(CongestionControlContext) CongestionController { return recorder },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x39}, 2*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	sequence := uint32(0)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		if queuedBytes == 0 {
			sequence = binary.BigEndian.Uint32(packet.payload[4:8])
		}
		queuedBytes += len(packet.payload) - headerSize
	}
	probeEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout)
	if !available {
		t.Fatal("tail-loss probe was not published before the RTO")
	}
	consumeTestPacket(&stack.outbound, probeEntry)
	afterProbe := connection.Info()

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
	waitFor(t, 2*before.RetransmissionTimeout+time.Second, func() bool { return recorder.timeoutCount() != 0 })

	replacement, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-rto-controller-replacement", New: func(CongestionControlContext) CongestionController { return newRenoCongestionControl() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(replacement); err != nil {
		t.Fatal(err)
	}
	changed := connection.Info()
	if changed.CongestionControl != "test-rto-controller-replacement" || !changed.RetransmissionRecovery || changed.Retransmissions != afterProbe.Retransmissions {
		t.Fatalf("pending RTO after controller change = after-probe:%+v changed:%+v", afterProbe, changed)
	}

	clientPort := connection.key.local.Port()
	link.mu.Lock()
	serverSequence := link.tcp[clientPort].serverNext
	link.mu.Unlock()
	if err = link.deliverTCP(connection.key.remote.Port(), clientPort, serverSequence, sequence+uint32(len(payload)), TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	afterACK := connection.Info()
	if afterACK.RetransmissionRecovery || afterACK.Retransmissions != afterProbe.Retransmissions || afterACK.BytesAcknowledged-before.BytesAcknowledged != uint64(len(payload)) || afterACK.SpuriousRecoveryUndos != before.SpuriousRecoveryUndos {
		t.Fatalf("late ACK after controller change = before:%+v after-probe:%+v after-ACK:%+v", before, afterProbe, afterACK)
	}
	if recorder.timeoutCount() != 1 {
		t.Fatalf("late-ACK timeout events = %d, want 1", recorder.timeoutCount())
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}
}

func TestTCPRTOPendingPathMTURetransmissionStartsFRTO(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	recorder := &tcpRecoveryLossRecorder{algorithm: newRenoCongestionControl()}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-rto-pending-pmtu", New: func(CongestionControlContext) CongestionController { return recorder },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0xa7}, 2*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	type dataSegment struct {
		wire     []byte
		sequence uint32
		payload  []byte
	}
	segments := make([]dataSegment, 0, 2)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		segments = append(segments, dataSegment{
			wire:     wire,
			sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
			payload:  append([]byte(nil), segmentPayload...),
		})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) < 2 {
		t.Fatalf("initial TCP flight has %d segments, want at least 2", len(segments))
	}
	probeEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout)
	if !available {
		t.Fatal("tail-loss probe was not published before the RTO")
	}
	consumeTestPacket(&stack.outbound, probeEntry)
	afterProbe := connection.Info()

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
	waitFor(t, 2*before.RetransmissionTimeout+time.Second, func() bool { return recorder.timeoutCount() != 0 })

	const reducedMTU = 1000
	if err = writeTestPacket(stack, buildTestPacketTooBig(link.remote, link.local, segments[0].wire, reducedMTU)); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	blocked := connection.Info()
	if blocked.PathMTU != reducedMTU || !blocked.RetransmissionRecovery || blocked.Retransmissions != afterProbe.Retransmissions || recorder.timeoutCount() != 1 {
		t.Fatalf("pending RTO path-MTU state = after-probe:%+v blocked:%+v timeout-events:%d", afterProbe, blocked, recorder.timeoutCount())
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	replacementEntry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("path-MTU replacement did not resume when device capacity returned")
	}
	replacementWire := consumeTestPacket(&stack.outbound, replacementEntry)
	replacement, valid := parseIPPacket(replacementWire, false)
	if !valid || replacement.protocol != ProtocolTCP || len(replacement.payload) < tcpHeaderSize {
		t.Fatalf("path-MTU replacement is not TCP: %x", replacementWire)
	}
	headerSize := int(replacement.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(replacement.payload) || len(replacementWire) > reducedMTU || binary.BigEndian.Uint32(replacement.payload[4:8]) != segments[0].sequence {
		t.Fatalf("path-MTU replacement does not cover the first reduced-MTU range: %x", replacementWire)
	}
	replacementPayload := replacement.payload[headerSize:]
	afterReplacement := connection.Info()
	if afterReplacement.Retransmissions != afterProbe.Retransmissions+1 || afterReplacement.SpuriousRecoveryUndos != before.SpuriousRecoveryUndos {
		t.Fatalf("published path-MTU replacement = before:%+v after:%+v", before, afterReplacement)
	}

	clientPort := connection.key.local.Port()
	link.mu.Lock()
	serverSequence := link.tcp[clientPort].serverNext
	link.mu.Unlock()
	acknowledgement := segments[0].sequence + uint32(len(replacementPayload))
	if err = link.deliverTCP(connection.key.remote.Port(), clientPort, serverSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	afterACK := connection.Info()
	if !afterACK.RetransmissionRecovery || afterACK.SpuriousRecoveryUndos != before.SpuriousRecoveryUndos || afterACK.Retransmissions != afterReplacement.Retransmissions+1 {
		t.Fatalf("path-MTU F-RTO ACK = replacement:%+v after:%+v", afterReplacement, afterACK)
	}
	fallbackEntry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("path-MTU F-RTO fallback was not published")
	}
	fallbackWire := consumeTestPacket(&stack.outbound, fallbackEntry)
	fallback, valid := parseIPPacket(fallbackWire, false)
	if !valid || fallback.protocol != ProtocolTCP || len(fallback.payload) < tcpHeaderSize {
		t.Fatalf("path-MTU F-RTO fallback is not TCP: %x", fallbackWire)
	}
	wantSequence := segments[0].sequence + uint32(len(replacementPayload))
	if sequence := binary.BigEndian.Uint32(fallback.payload[4:8]); sequence != wantSequence {
		t.Fatalf("path-MTU F-RTO fallback sequence = %#x, want %#x", sequence, wantSequence)
	}
}

func TestTCPFRTOFallbackSurvivesStoppedDeviceRead(t *testing.T) {
	t.Run("Open", func(t *testing.T) {
		testTCPFRTOFallbackSurvivesStoppedDeviceRead(t, false, false)
	})
	t.Run("AfterCloseWrite", func(t *testing.T) {
		testTCPFRTOFallbackSurvivesStoppedDeviceRead(t, true, false)
	})
	t.Run("NewACKSupersedesFallback", func(t *testing.T) {
		testTCPFRTOFallbackSurvivesStoppedDeviceRead(t, false, true)
	})
}

func testTCPFRTOFallbackSurvivesStoppedDeviceRead(t *testing.T, closeWrite, supersedeFallback bool) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	segmentCount := 2
	if supersedeFallback {
		segmentCount = 3
	}
	payload := bytes.Repeat([]byte{0x7d}, segmentCount*before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if closeWrite {
		if err := connection.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	type dataSegment struct {
		wire     []byte
		sequence uint32
		payload  []byte
	}
	segments := make([]dataSegment, 0, segmentCount)
	queuedBytes := 0
	finQueued := !closeWrite
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) || !finQueued {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d; FIN queued = %t, want %t", queuedBytes, len(payload), finQueued, closeWrite)
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		if len(segmentPayload) != 0 {
			segments = append(segments, dataSegment{
				wire:     wire,
				sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
				payload:  append([]byte(nil), segmentPayload...),
			})
			queuedBytes += len(segmentPayload)
		}
		if packet.payload[13]&TCPFlagFIN != 0 {
			finQueued = true
		}
	}
	if len(segments) < segmentCount {
		t.Fatalf("initial TCP flight has %d segments, want at least %d", len(segments), segmentCount)
	}
	probeEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout)
	if !available {
		t.Fatal("tail-loss probe was not published before the RTO")
	}
	consumeTestPacket(&stack.outbound, probeEntry)
	rtoEntry, available := waitTestPacketEntry(&stack.outbound, 2*before.RetransmissionTimeout+time.Second)
	if !available {
		t.Fatal("initial RTO retransmission was not published")
	}
	rtoWire := consumeTestPacket(&stack.outbound, rtoEntry)
	rtoPacket, valid := parseIPPacket(rtoWire, false)
	if !valid || rtoPacket.protocol != ProtocolTCP || len(rtoPacket.payload) < tcpHeaderSize || binary.BigEndian.Uint32(rtoPacket.payload[4:8]) != segments[0].sequence {
		t.Fatalf("initial RTO output does not retransmit the first range: %x", rtoWire)
	}
	rtoInfo := connection.Info()
	if !rtoInfo.RetransmissionRecovery || rtoInfo.Retransmissions != before.Retransmissions+2 {
		t.Fatalf("initial RTO state = before:%+v after:%+v", before, rtoInfo)
	}

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
	if err := link.handleOutboundPacket(rtoWire); err != nil {
		t.Fatal(err)
	}
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while F-RTO fallback waited for device capacity")
			return TCPConnInfo{}
		}
	}
	_ = responsiveInfo()
	blocked := responsiveInfo()
	if !blocked.RetransmissionRecovery || blocked.BytesAcknowledged-before.BytesAcknowledged != uint64(len(segments[0].payload)) || blocked.Retransmissions != rtoInfo.Retransmissions {
		t.Fatalf("unpublished F-RTO fallback = before:%+v RTO:%+v blocked:%+v", before, rtoInfo, blocked)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}
	if supersedeFallback {
		if err := link.handleOutboundPacket(segments[1].wire); err != nil {
			t.Fatal(err)
		}
		wantAcknowledged := before.BytesAcknowledged + uint64(len(segments[0].payload)+len(segments[1].payload))
		deadline := time.Now().Add(time.Second)
		for blocked.BytesAcknowledged < wantAcknowledged && time.Now().Before(deadline) {
			blocked = responsiveInfo()
		}
		if blocked.BytesAcknowledged != wantAcknowledged || !blocked.RetransmissionRecovery || blocked.Retransmissions != rtoInfo.Retransmissions {
			t.Fatalf("ACK-superseded F-RTO fallback = RTO:%+v after:%+v", rtoInfo, blocked)
		}
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	fallbackEntry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("F-RTO output did not resume when device capacity returned")
	}
	fallbackWire := consumeTestPacket(&stack.outbound, fallbackEntry)
	fallback, valid := parseIPPacket(fallbackWire, false)
	if !valid || fallback.protocol != ProtocolTCP || len(fallback.payload) < tcpHeaderSize {
		t.Fatalf("F-RTO fallback output is not TCP: %x", fallbackWire)
	}
	headerSize := int(fallback.payload[12]>>4) * 4
	wantSegment := segments[1]
	if supersedeFallback {
		wantSegment = segments[2]
	}
	if headerSize < tcpHeaderSize || headerSize > len(fallback.payload) {
		t.Fatalf("F-RTO recovery TCP header length = %d in %x", headerSize, fallbackWire)
	}
	after := responsiveInfo()
	if len(fallback.payload) == headerSize && supersedeFallback {
		if fallback.payload[13] != TCPFlagACK || after.Retransmissions != rtoInfo.Retransmissions {
			t.Fatalf("ACK-only F-RTO recovery = RTO:%+v after:%+v wire:%x", rtoInfo, after, fallbackWire)
		}
		if err := link.handleOutboundPacket(fallbackWire); err != nil {
			t.Fatal(err)
		}
		if err := link.handleOutboundPacket(wantSegment.wire); err != nil {
			t.Fatal(err)
		}
	} else {
		if binary.BigEndian.Uint32(fallback.payload[4:8]) != wantSegment.sequence || !bytes.Equal(fallback.payload[headerSize:], wantSegment.payload) {
			t.Fatalf("F-RTO recovery does not retransmit the current next range: %x", fallbackWire)
		}
		if after.Retransmissions != rtoInfo.Retransmissions+1 {
			t.Fatalf("published F-RTO recovery = RTO:%+v after:%+v", rtoInfo, after)
		}
		if err := link.handleOutboundPacket(fallbackWire); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("F-RTO fallback TCP echo payload mismatch")
	}
}

func TestTCPLostRetransmissionSurvivesStoppedDeviceRead(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	recorder := &tcpRecoveryLossRecorder{algorithm: newRenoCongestionControl()}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "test-lost-retransmission", New: func(CongestionControlContext) CongestionController { return recorder },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x37}, 6*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	type dataSegment struct {
		wire     []byte
		sequence uint32
	}
	segments := make([]dataSegment, 0, 6)
	queuedBytes := 0
	deadline := time.Now().Add(time.Second)
	for queuedBytes < len(payload) {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !available {
			t.Fatalf("queued TCP bytes = %d, want %d", queuedBytes, len(payload))
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("initial output is not TCP: %x", wire)
		}
		headerSize := int(packet.payload[12]>>4) * 4
		if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
			t.Fatalf("initial TCP header length = %d in %x", headerSize, wire)
		}
		segmentPayload := packet.payload[headerSize:]
		if len(segmentPayload) == 0 {
			t.Fatalf("initial output is not a data segment: %x", wire)
		}
		segments = append(segments, dataSegment{
			wire:     wire,
			sequence: binary.BigEndian.Uint32(packet.payload[4:8]),
		})
		queuedBytes += len(segmentPayload)
	}
	if len(segments) != 6 {
		t.Fatalf("initial TCP flight has %d segments, want 6", len(segments))
	}

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
	responsiveInfo := func() TCPConnInfo {
		t.Helper()
		result := make(chan TCPConnInfo, 1)
		go func() { result <- connection.Info() }()
		select {
		case info := <-result:
			return info
		case <-time.After(time.Second):
			t.Fatal("Info blocked while lost-retransmission recovery waited for device capacity")
			return TCPConnInfo{}
		}
	}
	waitInboundDrained := func() TCPConnInfo {
		t.Helper()
		for {
			info := responsiveInfo()
			if info.InboundQueueBytes == 0 {
				return info
			}
		}
	}
	var blocked TCPConnInfo
	for _, index := range []int{1, 3, 4} {
		if err = link.handleOutboundPacket(segments[index].wire); err != nil {
			t.Fatal(err)
		}
		blocked = waitInboundDrained()
	}
	if !blocked.FastRecovery || recorder.lossCount() != 1 {
		t.Fatalf("initial recovery = fast:%t loss events:%d, want true/1", blocked.FastRecovery, recorder.lossCount())
	}

	releaseSlot := func() {
		t.Helper()
		last := len(held) - 1
		stack.outbound.releaseReserved(held[last])
		held = held[:last]
	}
	readRetransmission := func(wantSequence uint32) []byte {
		t.Helper()
		entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
		if !available {
			t.Fatalf("retransmission %#x was not published", wantSequence)
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, valid := parseIPPacket(wire, false)
		if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
			t.Fatalf("recovery output is not TCP: %x", wire)
		}
		if sequence := binary.BigEndian.Uint32(packet.payload[4:8]); sequence != wantSequence {
			t.Fatalf("retransmitted sequence = %#x, want %#x", sequence, wantSequence)
		}
		return wire
	}

	releaseSlot()
	readRetransmission(segments[0].sequence)
	if slot, reserved := stack.outbound.tryReserve(); !reserved {
		t.Fatal("failed to retain the returned first-recovery output slot")
	} else {
		held = append(held, slot)
	}
	if err = link.handleOutboundPacket(segments[5].wire); err != nil {
		t.Fatal(err)
	}
	_ = waitInboundDrained()
	releaseSlot()
	secondRecovery := readRetransmission(segments[2].sequence)
	if slot, reserved := stack.outbound.tryReserve(); !reserved {
		t.Fatal("failed to retain the returned recovery output slot")
	} else {
		held = append(held, slot)
	}
	time.Sleep(before.MinimumRTT + time.Millisecond)
	if err = link.handleOutboundPacket(secondRecovery); err != nil {
		t.Fatal(err)
	}
	lost := waitInboundDrained()
	if losses := recorder.lossCount(); losses != 2 {
		t.Fatalf("loss events after RACK detected a lost retransmission = %d, want 2", losses)
	}
	if lost.Retransmissions != before.Retransmissions+2 {
		t.Fatalf("published retransmissions = %d, want %d", lost.Retransmissions, before.Retransmissions+2)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("full reserved output queue contains %d published packets, want 0", depth)
	}

	releaseSlot()
	finalRecovery := readRetransmission(segments[0].sequence)
	if err = link.handleOutboundPacket(finalRecovery); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("lost-retransmission recovery payload mismatch")
	}
}

func TestTCPPathMTURetransmissionSurvivesStoppedDeviceRead(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	payload := bytes.Repeat([]byte{0x6d}, before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("initial TCP data was not published")
	}
	originalWire := consumeTestPacket(&stack.outbound, entry)
	original, valid := parseIPPacket(originalWire, false)
	if !valid || original.protocol != ProtocolTCP || len(original.payload) < tcpHeaderSize {
		t.Fatalf("initial output is not TCP: %x", originalWire)
	}
	originalHeaderSize := int(original.payload[12]>>4) * 4
	if originalHeaderSize < tcpHeaderSize || originalHeaderSize > len(original.payload) || !bytes.Equal(original.payload[originalHeaderSize:], payload) {
		t.Fatalf("initial TCP data mismatch: %x", originalWire)
	}
	originalSequence := binary.BigEndian.Uint32(original.payload[4:8])

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
	const reducedMTU = 1000
	if err := writeTestPacket(stack, buildTestPacketTooBig(link.remote, link.local, originalWire, reducedMTU)); err != nil {
		t.Fatal(err)
	}
	clientPort := connection.key.local.Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	serverSequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err := link.deliverTCP(connection.key.remote.Port(), clientPort, serverSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	blocked := connection.Info()
	if blocked.PathMTU != reducedMTU || blocked.Retransmissions != before.Retransmissions || blocked.RetransmissionRecovery {
		t.Fatalf("blocked path-MTU recovery = before:%+v blocked:%+v", before, blocked)
	}

	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	wait := before.RetransmissionTimeout + time.Second
	entry, available = waitTestPacketEntry(&stack.outbound, wait)
	if !available {
		t.Fatalf("path-MTU retransmission did not resume within %v of returned capacity", wait)
	}
	retransmissionWire := consumeTestPacket(&stack.outbound, entry)
	retransmission, valid := parseIPPacket(retransmissionWire, false)
	if !valid || retransmission.protocol != ProtocolTCP || len(retransmission.payload) < tcpHeaderSize {
		t.Fatalf("path-MTU recovery output is not TCP: %x", retransmissionWire)
	}
	if len(retransmissionWire) > reducedMTU {
		t.Fatalf("path-MTU retransmission length = %d, want <= %d", len(retransmissionWire), reducedMTU)
	}
	if sequence := binary.BigEndian.Uint32(retransmission.payload[4:8]); sequence != originalSequence {
		t.Fatalf("path-MTU retransmitted sequence = %#x, want %#x", sequence, originalSequence)
	}
	if err := link.deliverTCP(connection.key.remote.Port(), clientPort, serverSequence, originalSequence+uint32(len(payload)), TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	after := connection.Info()
	if after.Retransmissions != before.Retransmissions+1 || after.RetransmissionRecovery || after.FastRecovery {
		t.Fatalf("published path-MTU recovery = before:%+v after:%+v", before, after)
	}
}

func TestTCPPathMTURetransmissionRemainsDueAfterDeviceDeparture(t *testing.T) {
	_, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()

	before := connection.Info()
	beforeStats := stack.Stats()
	payload := bytes.Repeat([]byte{0x4d}, before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	waitFor(t, time.Second, func() bool { return stack.outbound.len() == 1 })
	held := make([]uint16, 0, cap(stack.outbound.free)-1)
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
	if len(held) != cap(stack.outbound.free)-1 {
		t.Fatalf("held output slots = %d, want %d", len(held), cap(stack.outbound.free)-1)
	}

	var departureWaiter *packetQueueDepartureWaiter
	waitFor(t, before.RetransmissionTimeout+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		for index := range waiters.slots {
			if waiter := waiters.slots[index].Load(); waiter != nil {
				departureWaiter = waiter
				return true
			}
		}
		return false
	})
	const reducedMTU = 1000
	local := connection.key.local.Addr()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())},
		MTU:            reducedMTU,
	}); err != nil {
		t.Fatal(err)
	}
	blocked := connection.Info()
	if blocked.PathMTU != reducedMTU || blocked.Retransmissions != before.Retransmissions || blocked.RetransmissionRecovery {
		t.Fatalf("queue-resident path-MTU recovery = before:%+v blocked:%+v", before, blocked)
	}

	entry, available := stack.outbound.tryDequeue()
	if !available {
		t.Fatal("queue-resident TCP data was unavailable")
	}
	originalWire := consumeTestPacket(&stack.outbound, entry)
	if len(originalWire) <= reducedMTU {
		t.Fatalf("original queued packet length = %d, want > %d", len(originalWire), reducedMTU)
	}
	_, departed := departureWaiter.departedTime(stack.timestampEpoch)
	if !departed {
		t.Fatal("path-MTU target dequeue did not record device departure")
	}
	retransmissionEntry, available := waitTestPacketEntry(&stack.outbound, before.RetransmissionTimeout+time.Second)
	if !available {
		t.Fatal("path-MTU retransmission did not resume after device departure")
	}
	retransmissionWire := append([]byte(nil), retransmissionEntry.packet...)
	defer stack.outbound.release(retransmissionEntry)
	if len(retransmissionWire) > reducedMTU {
		t.Fatalf("path-MTU retransmission length = %d, want <= %d", len(retransmissionWire), reducedMTU)
	}
	after := connection.Info()
	if after.Retransmissions != before.Retransmissions+1 || after.RetransmissionRecovery || after.FastRecovery {
		t.Fatalf("published path-MTU retransmission = before:%+v after:%+v", before, after)
	}
	if afterStats := stack.Stats(); afterStats.TCPTailLossProbes != beforeStats.TCPTailLossProbes {
		t.Fatalf("path-MTU departure emitted %d tail-loss probes, want 0", afterStats.TCPTailLossProbes-beforeStats.TCPTailLossProbes)
	}
}

func TestTCPImmediateACKReplacesDelayedACKWhileDeviceReadStopped(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	if err := connection.SetQuickACK(false); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()

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

	clientPort := connection.key.local.Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	peer.serverNext++
	link.mu.Unlock()
	packet := buildTestTCP(link.remote, link.local, 8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte{1})
	if err := stack.handleInboundPacket(packet, time.Now().Add(10*time.Second), false, 0); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var received [1]byte
	if _, err := io.ReadFull(connection, received[:]); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()

	if err := connection.SetQuickACK(true); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()
	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
	if !available {
		t.Fatal("immediate ACK remained gated by the replaced delayed-ACK deadline")
	}
	wire := consumeTestPacket(&stack.outbound, entry)
	parsed, valid := parseIPPacket(wire, false)
	if !valid || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("capacity wakeup packet is not TCP: %x", wire)
	}
	headerSize := int(parsed.payload[12]>>4) * 4
	if parsed.payload[13] != TCPFlagACK || headerSize < tcpHeaderSize || headerSize != len(parsed.payload) || binary.BigEndian.Uint32(parsed.payload[8:12]) != sequence+1 {
		t.Fatalf("capacity wakeup packet is not the pending pure ACK: %x", wire)
	}
}

func TestTCPEstablishedControlResponseDoesNotWaitForDeviceQueue(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	clientPort := uint16(connection.LocalAddr().(*net.TCPAddr).Port)
	link.mu.Lock()
	peer := link.tcp[clientPort]
	sequence, acknowledgement := peer.serverNext-1, peer.clientNext
	link.mu.Unlock()
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	responsive := make(chan struct{})
	go func() {
		_ = connection.Info()
		_ = connection.Info()
		close(responsive)
	}()
	select {
	case <-responsive:
	case <-time.After(time.Second):
		t.Fatal("queue-full control response blocked the TCP actor")
	}
	if depth := stack.outbound.len(); depth != cap(stack.outbound.free) {
		t.Fatalf("queue depth after dropped control response = %d, want %d", depth, cap(stack.outbound.free))
	}
	entry, available := stack.outbound.tryDequeue()
	if !available {
		t.Fatal("full device queue had no releasable packet")
	}
	consumeTestPacket(&stack.outbound, entry)
	if err := link.deliverTCP(8080, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return stack.outbound.len() == cap(stack.outbound.free) })
	foundACK := false
	for {
		entry, available = stack.outbound.tryDequeue()
		if !available {
			break
		}
		packet := consumeTestPacket(&stack.outbound, entry)
		parsed, valid := parseIPPacket(packet, false)
		if valid && parsed.protocol == ProtocolTCP && len(parsed.payload) >= tcpHeaderSize &&
			binary.BigEndian.Uint16(parsed.payload[0:2]) == clientPort &&
			binary.BigEndian.Uint16(parsed.payload[2:4]) == 8080 &&
			parsed.payload[13]&TCPFlagACK != 0 {
			foundACK = true
		}
	}
	if !foundACK {
		t.Fatal("repeated peer probe did not regenerate its ACK after capacity returned")
	}
}

func TestTCPWriteReturnsAfterBuffering(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 100
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8084))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	started := time.Now()
	if n, writeErr := connection.Write([]byte("buffered without ACK")); writeErr != nil || n != 20 {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("Write waited %v for peer acknowledgement", elapsed)
	}
}

func TestTCPExpiredWriteDeadlineRejectsBufferedWrite(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8096))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, writeErr := connection.Write([]byte("late")); n != 0 || !errors.Is(writeErr, os.ErrDeadlineExceeded) {
		t.Fatalf("expired buffered Write = %d, %v, want 0, deadline", n, writeErr)
	}
}

func TestTCPSendBufferDeadlineIsRecoverable(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8085))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, tcpSendCapacity+1)
	n, err := connection.Write(payload)
	if n != tcpSendCapacity || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("bounded Write = %d, %v, want %d, os.ErrDeadlineExceeded", n, err, tcpSendCapacity)
	}
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	acknowledgement := peer.highestClientEnd
	peer.clientNext = acknowledgement
	serverSequence := peer.serverNext
	link.dropTCPData = 0
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), serverSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err = connection.Write(payload[tcpSendCapacity:]); n != 1 || err != nil {
		t.Fatalf("Write after timeout = %d, %v", n, err)
	}
}

func TestTCPRTOPartialACKAdvancesLossRecovery(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	link.dropTCPData = 3
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8097))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x5a}, 3*1280)
	start := time.Now()
	writeAndReadTCPEcho(t, connection, payload)
	if elapsed := time.Since(start); elapsed >= tcpInitialRTO {
		t.Fatalf("RTO partial-ACK recovery took %v, want less than %v", elapsed, tcpInitialRTO)
	}
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions < 3 {
		t.Fatalf("RTO recovery retransmissions = %d, want at least 3", retransmissions)
	}
}

func TestTCPFRTORecoversSpuriousTimeout(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		algorithm := algorithm
		t.Run(algorithm, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
			defer stack.Close()
			link.echoTCP = true
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8098))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			tcpConnection := connection.(*TCPConn)
			if err = tcpConnection.SetCongestionControl(algorithm); err != nil {
				t.Fatal(err)
			}
			link.armTCPDelaySpike(1)
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{0x7b}, 128*1024)
			writeAndReadTCPEcho(t, connection, payload)
			deadline := time.Now().Add(5 * time.Second)
			for tcpConnection.Info().SpuriousRecoveryUndos == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if tcpConnection.Info().SpuriousRecoveryUndos == 0 {
				triggered, released, held := link.tcpDelaySpikeStatus()
				t.Fatalf("F-RTO did not undo recovery: triggered %t released %t held %d info=%+v stats=%+v", triggered, released, held, tcpConnection.Info(), stack.Stats())
			}
			triggered, released, held := link.tcpDelaySpikeStatus()
			if !triggered || !released || held < 2 {
				t.Fatalf("delay spike = triggered %t released %t held %d", triggered, released, held)
			}
			if err := link.releaseTCPDelayOriginal(); err != nil {
				t.Fatal(err)
			}
			info := tcpConnection.Info()
			if info.Retransmissions == 0 {
				t.Fatalf("delay spike did not trigger a retransmission timeout: rto=%v state=%+v", info.RetransmissionTimeout, info)
			}
			if info.SpuriousRecoveryUndos == 0 {
				t.Fatal("F-RTO did not undo the spurious timeout recovery")
			}
		})
	}
}

func TestTCPFRTOFallsBackAfterRealLoss(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8099))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x39}, 512))
	info := connection.(*TCPConn).Info()
	if info.Retransmissions == 0 {
		t.Fatal("real loss did not trigger retransmission recovery")
	}
	if info.SpuriousRecoveryUndos != 0 {
		t.Fatalf("real loss produced %d spurious-recovery undos", info.SpuriousRecoveryUndos)
	}
}

func TestTCPFRTOECNFeedbackRequiresNegotiation(t *testing.T) {
	for _, negotiated := range []bool{false, true} {
		t.Run(fmt.Sprintf("negotiated=%t", negotiated), func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
			defer stack.Close()
			link.echoTCP = true
			link.ecnTCP = negotiated
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8103))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			tcpConnection := connection.(*TCPConn)
			if tcpConnection.peerECN != negotiated {
				t.Fatalf("ECN negotiation = %t, want %t", tcpConnection.peerECN, negotiated)
			}
			link.armTCPDelaySpike(1)
			link.mu.Lock()
			link.sendTCPECE = true
			link.mu.Unlock()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x4e}, 32*1024))
			info := tcpConnection.Info()
			if info.Retransmissions == 0 {
				t.Fatal("delay spike did not trigger a retransmission timeout")
			}
			if negotiated && info.SpuriousRecoveryUndos != 0 {
				t.Fatalf("negotiated ECE produced %d spurious-recovery undos", info.SpuriousRecoveryUndos)
			}
			if !negotiated && info.SpuriousRecoveryUndos == 0 {
				t.Fatal("unnegotiated ECE prevented F-RTO undo")
			}
			if err = link.releaseTCPDelayOriginal(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPFRTORestartsAfterRecurringTimeout(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8100))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	link.armTCPDelaySpike(2)
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x6d}, 128*1024))
	info := connection.(*TCPConn).Info()
	if info.Retransmissions < 2 {
		t.Fatalf("recurring timeout retransmissions = %d, want at least 2", info.Retransmissions)
	}
	if info.SpuriousRecoveryUndos == 0 {
		t.Fatal("recurring timeout did not restart F-RTO detection")
	}
	if err := link.releaseTCPDelayOriginal(); err != nil {
		t.Fatal(err)
	}
}

func TestTCPFRTOSACKFallbackRetransmitsImmediately(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPOrdinals = make(map[int]bool, 10)
	for ordinal := 1; ordinal <= 10; ordinal++ {
		link.dropTCPOrdinals[ordinal] = true
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8101))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte{0xa7}, 32*1024)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, 2*time.Second, func() bool { return tcpConnection.Info().Retransmissions != 0 })
	waitFor(t, 300*time.Millisecond, func() bool { return tcpConnection.Info().Retransmissions > 1 })
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("F-RTO SACK fallback payload mismatch")
	}
	if undos := tcpConnection.Info().SpuriousRecoveryUndos; undos != 0 {
		t.Fatalf("real SACK loss produced %d spurious-recovery undos", undos)
	}
}

func TestTCPSACKRecoversMultipleSegments(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte("selective-ack-"), 600)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("SACK recovery payload mismatch")
	}
	link.mu.Lock()
	recovered := link.sackRecovery
	link.mu.Unlock()
	if !recovered {
		t.Fatal("peer did not observe selective-ack hole recovery")
	}
}

func TestTCPDataSACKPayloadUsesOptionBudget(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
	}{
		{name: "ipv4", local: netip.MustParseAddr("192.0.2.1"), remote: netip.MustParseAddr("192.0.2.2")},
		{name: "ipv6", local: netip.MustParseAddr("2001:db8::1"), remote: netip.MustParseAddr("2001:db8::2")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			link.echoTCP = true
			link.timestampTCP = true
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8082))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			tcpConnection := connection.(*TCPConn)
			if tcpConnection.peerMSS != 1280 {
				t.Fatalf("test peer MSS = %d, want 1280", tcpConnection.peerMSS)
			}
			localPort := tcpConnection.key.local.Port()
			link.mu.Lock()
			peer := link.tcp[localPort]
			serverSequence, clientAcknowledgement := peer.serverNext+100, peer.clientNext
			link.mu.Unlock()
			if err = link.deliverTCP(tcpConnection.key.remote.Port(), localPort, serverSequence, clientAcknowledgement, TCPFlagACK, 65535, nil, bytes.Repeat([]byte{0x7f}, 100)); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool {
				link.mu.Lock()
				defer link.mu.Unlock()
				return link.clientSACKs != 0
			})
			if _, err = connection.Write(bytes.Repeat([]byte{0x52}, 1300)); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool {
				link.mu.Lock()
				defer link.mu.Unlock()
				return link.maximumTCPDataWithSACK != 0
			})
			link.mu.Lock()
			maximum := link.maximumTCPDataWithSACK
			link.mu.Unlock()
			if maximum != 1256 {
				t.Fatalf("timestamped SACK data payload = %d, want 1256", maximum)
			}
		})
	}
}

func TestTCPSACKRenegingWaitsBeforeClearingScoreboard(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.sackReneging = true
	link.dropTCPOrdinals = map[int]bool{1: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8102))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x42}, 16*1024)
	writeAndReadTCPEcho(t, connection, payload)
	link.mu.Lock()
	delay := link.sackRenegingDelay
	link.mu.Unlock()
	if delay < 8*time.Millisecond || delay >= tcpMinimumRTO {
		t.Fatalf("SACK reneging recovery delay = %v, want Linux grace interval before RTO", delay)
	}
	if undos := connection.(*TCPConn).Info().SpuriousRecoveryUndos; undos != 0 {
		t.Fatalf("SACK reneging produced %d spurious-recovery undos", undos)
	}
}

func TestTCPSACKRenegingDelay(t *testing.T) {
	if delay := tcpSACKRenegingDelay(8 * time.Millisecond); delay != 10*time.Millisecond {
		t.Fatalf("short-RTT reneging delay = %v, want 10ms", delay)
	}
	if delay := tcpSACKRenegingDelay(200 * time.Millisecond); delay != 100*time.Millisecond {
		t.Fatalf("long-RTT reneging delay = %v, want 100ms", delay)
	}
}

func TestTCPSACKIgnoresPureDuplicateACKs(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8086))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if !tcpConnection.Info().SACK {
		t.Fatal("test connection did not negotiate SACK")
	}
	if n, writeErr := connection.Write([]byte("unacknowledged")); writeErr != nil || n != len("unacknowledged") {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.dropTCPData == 0
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	for range [4]struct{}{} {
		if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions != 0 {
		t.Fatalf("retransmissions after pure SACK-less duplicate ACKs = %d, want 0", retransmissions)
	}
}

func TestTCPSACKRecoversMultipleHolesPerRound(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8087))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("multiple-sack-holes-"), 700)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("multiple-hole recovery payload mismatch")
	}
	link.mu.Lock()
	recoveries := link.sackRecoveries
	link.mu.Unlock()
	if recoveries < 2 {
		t.Fatalf("SACK hole recoveries = %d, want at least 2", recoveries)
	}
}

func TestTCPRACKTimerRecoversSingleSACKHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPOrdinals = map[int]bool{1: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8093))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x53}, 2*1280)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	stats := stack.Stats()
	if stats.TCPRACKRetransmissions == 0 {
		t.Fatalf("RACK retransmissions = %d, want at least one", stats.TCPRACKRetransmissions)
	}
}

func TestTCPLimitedTransmitIsExcludedFromRecoveryFlight(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200},
		{sequence: 200, end: 300, state: sentTCPSegmentLimited},
		{sequence: 300, end: 400, state: sentTCPSegmentSACKed},
	}
	if flight := lossRecoveryFlightSize(outstanding); flight != 100 {
		t.Fatalf("Limited Transmit recovery flight = %d, want 100", flight)
	}
}

func TestTCPRateApplicationLimitedWaitsForKnownLoss(t *testing.T) {
	const mss = 1000
	outstanding := []sentTCPSegment{
		{sequence: 0, end: mss, state: sentTCPSegmentTransmitted},
		{sequence: mss, end: 2 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 2 * mss, end: 3 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 3 * mss, end: 4 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
	}
	if tcpRateApplicationLimited(0, false, mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("known unretransmitted SACK loss was classified as application limited")
	}
	outstanding[0].state.set(sentTCPSegmentSACKRetried, true)
	if !tcpRateApplicationLimited(0, false, mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("drained application queue after retransmitting known losses was not classified as application limited")
	}
	if !tcpRateApplicationLimited(0, false, mss, 10*mss, false, true, outstanding, mss) {
		t.Fatal("known loss outside recovery incorrectly blocked application-limited state")
	}
	if tcpRateApplicationLimited(mss, false, mss, 10*mss, true, true, outstanding, mss) ||
		tcpRateApplicationLimited(0, true, mss, 10*mss, true, true, outstanding, mss) ||
		tcpRateApplicationLimited(0, false, 10*mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("write queue, host queue, or congestion window limitation was classified as application limited")
	}
}

func TestTCPTailLossProbe(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8082))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte("warmup"))
	link.mu.Lock()
	link.holdTCPACKs = 2
	link.dropTCPOrdinals = map[int]bool{3: true}
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, make([]byte, 2000))
	link.mu.Lock()
	retransmitted, delay := link.tailRetransmission, link.tailRecoveryDelay
	link.mu.Unlock()
	if probes := stack.Stats().TCPTailLossProbes; !retransmitted || probes == 0 || delay >= tcpInitialRTO {
		t.Fatalf("tail retransmission = %v after %v with %d probes, want an RFC 8985 probe before initial RTO %v", retransmitted, delay, probes, tcpInitialRTO)
	}
}

func TestTCPTailLossProbeSendsNewData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.holdTCPACKs = 11
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x4f}, 11*1280)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	stats := stack.Stats()
	if stats.TCPTailLossProbes == 0 || stats.TCPRetransmissions != 0 {
		t.Fatalf("new-data TLP stats = probes %d retransmissions %d", stats.TCPTailLossProbes, stats.TCPRetransmissions)
	}
}

func TestTCPTailLossProbeAllowsRemoteDelayedACK(t *testing.T) {
	const smoothedRTT = 20 * time.Millisecond
	if delay := tailLossProbeDelay(smoothedRTT, time.Second, true); delay != 2*smoothedRTT+tcpTailLossProbeACKDelay {
		t.Fatalf("single-segment TLP delay = %v, want %v", delay, 2*smoothedRTT+tcpTailLossProbeACKDelay)
	}
	if delay := tailLossProbeDelay(smoothedRTT, time.Second, false); delay != 2*smoothedRTT {
		t.Fatalf("multi-segment TLP delay = %v, want %v", delay, 2*smoothedRTT)
	}
	if delay := tailLossProbeDelay(450*time.Millisecond, time.Second, true); delay != time.Second {
		t.Fatalf("RTO-capped TLP delay = %v, want %v", delay, time.Second)
	}
}

func TestTCPStaleRetransmissionTimerClearsEmptyFlight(t *testing.T) {
	for _, kind := range []tcpRetransmissionKind{
		tcpRetransmissionRTO,
		tcpRetransmissionProbe,
		tcpRetransmissionRACK,
		tcpRetransmissionSACKReneging,
	} {
		state := tcpEstablishedState{
			retransmit:             true,
			retransmissionKind:     kind,
			retransmissionDeadline: time.Now(),
		}
		if index := state.retransmissionTarget(kind); index != -1 {
			t.Fatalf("empty retransmission target for kind %d = %d, want none", kind, index)
		}
		if state.retransmit || state.retransmissionKind != tcpRetransmissionRTO || !state.retransmissionDeadline.IsZero() {
			t.Fatalf("empty retransmission timer for kind %d = active:%v kind:%v deadline:%v, want cleared RTO state", kind, state.retransmit, state.retransmissionKind, state.retransmissionDeadline)
		}
	}
}

func TestTCPSendTimerOwnership(t *testing.T) {
	t.Run("final cumulative ACK stops the loss clock", func(t *testing.T) {
		for _, kind := range []tcpRetransmissionKind{tcpRetransmissionRTO, tcpRetransmissionProbe, tcpRetransmissionRACK, tcpRetransmissionSACKReneging} {
			now := time.Now()
			state := tcpEstablishedState{
				retransmit: true, retransmissionKind: kind, retransmissionDeadline: now,
				sendTimer: tcpSendTimerState{baseDeadline: now},
			}
			state.updateRetransmissionTimer(tcpRetransmissionRestart, now)
			if state.retransmit || state.retransmissionKind != tcpRetransmissionRTO || !state.retransmissionDeadline.IsZero() || !state.sendTimer.baseDeadline.IsZero() {
				t.Fatalf("final ACK retained loss clock for kind %d: %+v", kind, state.sendTimer)
			}
		}
	})
	t.Run("remaining flight restarts at processing time", func(t *testing.T) {
		receivedAt := time.Now().Add(-time.Hour)
		state := tcpEstablishedState{
			connection:  &TCPConn{stack: &Stack{timestampEpoch: receivedAt}},
			outstanding: []sentTCPSegment{{sequence: 100, end: 200}},
			peerWindow:  65535,
			rtt:         rttEstimator{rto: time.Second},
		}
		before := time.Now()
		state.updateRetransmissionTimer(tcpRetransmissionRestart, receivedAt)
		after := time.Now()
		if !state.retransmit || state.retransmissionKind != tcpRetransmissionRTO || state.sendTimer.baseDeadline.Before(before.Add(time.Second)) || state.sendTimer.baseDeadline.After(after.Add(time.Second)) || !state.retransmissionDeadline.Equal(state.sendTimer.baseDeadline) {
			t.Fatalf("remaining flight restart = %v, want processing time plus RTO", state.retransmissionDeadline)
		}
	})
	t.Run("persist survives unrelated wakes", func(t *testing.T) {
		deadline := time.Now().Add(time.Second)
		for _, update := range []tcpRetransmissionUpdate{tcpRetransmissionPreserve, tcpRetransmissionReselect, tcpRetransmissionRestart} {
			state := tcpEstablishedState{
				persist:   true,
				sendTimer: tcpSendTimerState{baseDeadline: deadline},
			}
			state.updateRetransmissionTimer(update, time.Now())
			if !state.persist || !state.sendTimer.baseDeadline.Equal(deadline) {
				t.Fatalf("persist timer after update %d = active:%v deadline:%v, want %v", update, state.persist, state.sendTimer.baseDeadline, deadline)
			}
		}
	})
	t.Run("new flight replaces persist clock", func(t *testing.T) {
		now := time.Now()
		persistDeadline := now.Add(10 * time.Second)
		state := tcpEstablishedState{
			connection:        &TCPConn{stack: &Stack{timestampEpoch: now}},
			outstanding:       []sentTCPSegment{{}},
			rtt:               rttEstimator{rto: time.Second},
			persist:           true,
			sendTimer:         tcpSendTimerState{baseDeadline: persistDeadline, persistRTO: 2 * time.Second},
			persistUnanswered: 3, persistClosed: 3,
		}
		state.updateRetransmissionTimer(tcpRetransmissionReselect, now)
		if state.persist || !state.retransmit || state.sendTimer.baseDeadline.Equal(persistDeadline) {
			t.Fatalf("send timer after new flight = persist:%v retransmit:%v deadline:%v", state.persist, state.retransmit, state.sendTimer.baseDeadline)
		}
		if state.sendTimer.persistRTO != time.Second || state.persistUnanswered != 0 || state.persistClosed != 0 {
			t.Fatalf("persist backoff after new flight = %+v", state.sendTimer)
		}
	})
	t.Run("SACK reneging grace is not restarted", func(t *testing.T) {
		state := tcpEstablishedState{
			peerSACK:     true,
			sackedRanges: 1,
			peerWindow:   65535,
			outstanding:  []sentTCPSegment{{state: sentTCPSegmentSACKed}},
		}
		state.armSACKReneging()
		deadline := state.retransmissionDeadline
		state.selectRetransmission(time.Now().Add(time.Second), time.Time{}, time.Time{})
		if state.retransmissionKind != tcpRetransmissionSACKReneging || !state.retransmissionDeadline.Equal(deadline) {
			t.Fatalf("SACK reneging timer = kind:%v deadline:%v, want kind:%v deadline:%v", state.retransmissionKind, state.retransmissionDeadline, tcpRetransmissionSACKReneging, deadline)
		}
	})
}

func TestTCPZeroWindowUsesOrdinaryRTOPath(t *testing.T) {
	now := time.Now()
	state := tcpEstablishedState{
		connection:         &TCPConn{stack: &Stack{timestampEpoch: now}},
		outstanding:        []sentTCPSegment{{sequence: 100, end: 200}},
		sendUnacknowledged: 100, sendNext: 200,
		peerWindow: 0,
		controller: newTCPCongestionController(CongestionControlReno),
		rtt:        rttEstimator{baseRTO: time.Second, rto: time.Second},
	}
	state.armRetransmission()
	if !state.retransmit || state.retransmissionKind != tcpRetransmissionRTO || state.retransmissionDeadline.IsZero() || state.persist {
		t.Fatalf("zero-window timer = active:%v kind:%v deadline:%v persist:%v", state.retransmit, state.retransmissionKind, state.retransmissionDeadline, state.persist)
	}
	ordinaryDeadline := state.retransmissionDeadline
	state.retransmissionKind = tcpRetransmissionProbe
	state.retransmissionDeadline = ordinaryDeadline.Add(-time.Millisecond)
	state.reselectRetransmission(now)
	if state.retransmissionKind != tcpRetransmissionRTO || !state.retransmissionDeadline.Equal(ordinaryDeadline) {
		t.Fatalf("zero-window reselect = kind:%v deadline:%v, want RTO at %v", state.retransmissionKind, state.retransmissionDeadline, ordinaryDeadline)
	}
	state.outstanding[0].state.set(sentTCPSegmentSACKed, true)
	state.sackedRanges = 1
	if index := state.retransmissionTarget(tcpRetransmissionRTO); index != 0 {
		t.Fatalf("fully SACKed zero-window target = %d, want queue head", index)
	}
	state.armPersist(time.Time{}, 200, false)
	if state.persist || !state.retransmit || !state.retransmissionDeadline.Equal(ordinaryDeadline) {
		t.Fatal("unsent data replaced the outstanding flight's RTO with persist")
	}
	state.retransmissionDeadline = time.Time{}
	state.reselectRetransmission(now)
	if !state.retransmissionDeadline.IsZero() || !tcpTimerOutputPending(&state, false) {
		t.Fatal("SACK reselection restarted an already consumed zero-window RTO")
	}
}

func TestTCPSACKRenegingRetainsSelectedDeadline(t *testing.T) {
	now := time.Now()
	deadline := now.Add(25 * time.Millisecond)
	state := tcpEstablishedState{
		connection: &TCPConn{stack: &Stack{timestampEpoch: now}},
		outstanding: []sentTCPSegment{{sequence: 100, end: 200,
			state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed}},
		peerWindow: 65535, peerSACK: true, sackedRanges: 1,
		retransmit: true, retransmissionKind: tcpRetransmissionSACKReneging,
		retransmissionDeadline: deadline,
		rtt:                    rttEstimator{rto: time.Second},
	}
	state.selectRetransmission(now.Add(time.Second), now, now)
	if state.retransmissionKind != tcpRetransmissionSACKReneging || !state.retransmissionDeadline.Equal(deadline) {
		t.Fatalf("SACK-reneging selection = kind:%v deadline:%v, want original deadline %v", state.retransmissionKind, state.retransmissionDeadline, deadline)
	}
	state.reselectRetransmission(now)
	if state.retransmissionKind != tcpRetransmissionSACKReneging || !state.retransmissionDeadline.Equal(deadline) {
		t.Fatalf("SACK-reneging reselection = kind:%v deadline:%v, want original deadline %v", state.retransmissionKind, state.retransmissionDeadline, deadline)
	}
}

func TestTCPZeroWindowACKProgressSelectsRemainingFlightClock(t *testing.T) {
	now := time.Now()
	state := tcpEstablishedState{
		connection: &TCPConn{stack: &Stack{timestampEpoch: now.Add(-time.Minute)}},
		outstanding: []sentTCPSegment{
			{sequence: 100, end: 150, firstSent: 30 * time.Second},
			{sequence: 150, end: 200, firstSent: 45 * time.Second},
		},
		sendUnacknowledged: 100, sendNext: 200,
		peerWindow: 0,
		controller: newTCPCongestionController(CongestionControlReno),
		rtt:        rttEstimator{baseRTO: time.Second, rto: time.Second},
	}
	before := state.zeroWindowDeadline(0)
	state.processAcknowledgment(&tcpSegment{acknowledgement: 150, flags: TCPFlagACK, window: 0}, now, 0)
	if after := state.zeroWindowDeadline(0); !after.Equal(before.Add(15 * time.Second)) {
		t.Fatalf("remaining zero-window flight deadline = %v, want %v", after, before.Add(15*time.Second))
	}
}

func TestTCPZeroWindowTransitionAvoidsOrdinaryLossAccounting(t *testing.T) {
	now := time.Now()
	state := tcpEstablishedState{
		connection:         &TCPConn{stack: &Stack{timestampEpoch: now}},
		outstanding:        []sentTCPSegment{{sequence: 100, end: 200}},
		sendUnacknowledged: 100, sendNext: 200,
		peerWindow:             65535,
		controller:             newTCPCongestionController(CongestionControlReno),
		rtt:                    rttEstimator{baseRTO: time.Second, rto: time.Second},
		retransmit:             true,
		retransmissionKind:     tcpRetransmissionRTO,
		retransmissionDeadline: now.Add(time.Second),
		rtoAttempts:            3,
		blackHoleRTOs:          2,
	}
	state.peerWindowSequence = 0
	update := state.processAcknowledgment(&tcpSegment{sequence: 0, acknowledgement: 100, flags: TCPFlagACK, window: 0}, now, 0)
	state.updateRetransmissionTimer(update, now)
	if state.retransmissionKind != tcpRetransmissionRTO || state.rtoAttempts != 3 || state.blackHoleRTOs != 2 {
		t.Fatalf("zero-window transition = kind:%v rto:%d black-hole:%d", state.retransmissionKind, state.rtoAttempts, state.blackHoleRTOs)
	}
}

func TestTCPZeroWindowRetransmissionDisablesLossEvidence(t *testing.T) {
	now := time.Now()
	recorder := new(congestionAPILossRecorder)
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "zero-window-loss-evidence", New: func(CongestionControlContext) CongestionController { return recorder },
		Features: CongestionControlFeatureDeliveryRate | CongestionControlFeatureTransmissionEvents | CongestionControlFeatureLossEvents,
	})
	controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, 20_000, 40_000, 1000, 1)
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.stack = &Stack{timestampEpoch: now}
	state := tcpEstablishedState{
		connection:         connection,
		controller:         controller,
		peerMSS:            1000,
		peerWindow:         0,
		sendUnacknowledged: 100,
		sendNext:           1100,
		congestionWindow:   20_000,
		slowStartThreshold: 40_000,
		rtt:                rttEstimator{baseRTO: time.Second, rto: time.Second},
		retransmit:         true,
		retransmissionKind: tcpRetransmissionRTO,
		outstanding: []sentTCPSegment{{sequence: 100, end: 1100,
			state: sentTCPSegmentTransmitted, congestionPacketState: controller.transmissionState()}},
	}
	if index := state.prepareRetransmission(0, true, false, false, false, 0, now); index != 0 {
		t.Fatalf("zero-window retransmission index = %d, want 0", index)
	}
	if recorder.lossEvidence {
		t.Fatal("zero-window retransmission exposed loss evidence for congestion attribution")
	}
}

func TestTCPZeroWindowRecoveryCannotPublishOutsideWindow(t *testing.T) {
	state := tcpEstablishedState{
		outstanding:        []sentTCPSegment{{sequence: 100, end: 200}},
		retransmit:         true,
		retransmissionKind: tcpRetransmissionRTO,
		peerWindow:         0,
		rtoRecovery:        true,
		fastRecovery:       true,
		haveRACKLoss:       true,
	}
	if state.recoveryOutputPending() || state.recoveryOutputReady() {
		t.Fatal("zero-window recovery exposed ordinary output while the peer window was closed")
	}
	state.peerWindow = 65535
	if !state.recoveryOutputPending() || !state.recoveryOutputReady() {
		t.Fatal("recovery did not resume after the peer reopened its window")
	}
}

func TestTCPZeroWindowOutstandingTimeoutUsesLinuxSilenceBudget(t *testing.T) {
	now := time.Now()
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	c.stack = &Stack{timestampEpoch: now.Add(-tcpZeroWindowOutstandingTimeout - time.Second)}
	state := tcpEstablishedState{
		connection:  c,
		outstanding: []sentTCPSegment{{sequence: 100, end: 200}},
		peerWindow:  0,
	}
	state.lastActivity = now.Add(-tcpZeroWindowOutstandingTimeout - time.Second)
	if err := state.zeroWindowTimeoutError(now, 0); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("silent zero-window flight error = %v, want deadline exceeded", err)
	}
	state.lastActivity = now.Add(-time.Second)
	if err := state.zeroWindowTimeoutError(now, 0); err != nil {
		t.Fatalf("responsive zero-window flight error = %v", err)
	}
	state.outstanding[0].firstSent = time.Second
	state.lastActivity = now.Add(-tcpZeroWindowOutstandingTimeout)
	if err := state.zeroWindowTimeoutError(now, 0); err != nil {
		t.Fatalf("zero-window exact silence deadline error = %v, want nil", err)
	}
	state.outstanding[0].firstSent = time.Second - time.Nanosecond
	state.lastActivity = now.Add(-tcpZeroWindowOutstandingTimeout - time.Nanosecond)
	if err := state.zeroWindowTimeoutError(now, 0); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("zero-window exceeded silence deadline error = %v, want deadline exceeded", err)
	}
	c.userTimeout = 50 * time.Millisecond
	state.outstanding[0].firstSent = now.Add(-c.userTimeout).Sub(c.stack.timestampEpoch)
	if err := state.zeroWindowTimeoutError(now, c.userTimeout); err != nil {
		t.Fatalf("user-timeout exact zero-window deadline error = %v, want nil", err)
	}
	state.outstanding[0].firstSent -= time.Nanosecond
	if err := state.zeroWindowTimeoutError(now, c.userTimeout); !errors.Is(err, syscall.ETIMEDOUT) {
		t.Fatalf("user-timeout exceeded zero-window deadline error = %v, want ETIMEDOUT", err)
	}
}

func TestTCPZeroWindowOutstandingArmsSilenceDeadline(t *testing.T) {
	now := time.Now()
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.stack = &Stack{timestampEpoch: now.Add(-tcpZeroWindowOutstandingTimeout - time.Second)}
	state := tcpEstablishedState{
		connection:         connection,
		outstanding:        []sentTCPSegment{{sequence: 100, end: 200}},
		peerWindow:         0,
		retransmit:         true,
		retransmissionKind: tcpRetransmissionRTO,
		lastActivity:       now.Add(-tcpZeroWindowOutstandingTimeout - time.Second),
	}
	state.armLiveness(false)
	if !state.liveness {
		t.Fatal("zero-window silence deadline was not armed")
	}
	if state.livenessDeadline.After(time.Now().Add(time.Second)) {
		t.Fatalf("zero-window silence deadline = %v, want an already due deadline", state.livenessDeadline)
	}
}

func TestTCPZeroWindowLivenessUsesStableClocks(t *testing.T) {
	for _, test := range []struct {
		name        string
		outstanding bool
		sacked      bool
		timeout     time.Duration
		active      bool
	}{
		{name: "pure persist", timeout: time.Second, active: true},
		{name: "pure persist without user timeout"},
		{name: "outstanding", outstanding: true, active: true},
		{name: "outstanding user timeout", outstanding: true, timeout: time.Second, active: true},
		{name: "fully SACKed user timeout", outstanding: true, sacked: true, timeout: time.Second, active: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			c.stack = &Stack{timestampEpoch: now.Add(-time.Minute)}
			c.userTimeout = test.timeout
			c.sendBuffer.append(make([]byte, 200))
			state := tcpEstablishedState{
				connection: c, sendUnacknowledged: 100, sendNext: 100,
				lastActivity: now, rtt: rttEstimator{rto: time.Second},
			}
			if test.outstanding {
				state.sendNext = 200
				state.outstanding = []sentTCPSegment{{sequence: 100, end: 200, firstSent: time.Minute,
					hostQueue: packetQueueTicket{queuedAt: monotonicStampAt(c.stack.timestampEpoch, now)}}}
				if test.sacked {
					state.outstanding[0].state.set(sentTCPSegmentSACKed, true)
					state.sackedRanges = 1
				}
			}
			state.armPersist(time.Time{}, c.sendBuffer.size, false)
			state.armLiveness(false)
			if state.liveness != test.active {
				t.Fatalf("liveness = %t, want %t", state.liveness, test.active)
			}
			started := state.sendTimer.persistSince
			if (started != 0) == test.outstanding || state.livenessState != nil {
				t.Fatal("pure-persist history was not independent of optional liveness state")
			}
			if !test.active {
				return
			}
			deadline := state.livenessDeadline
			for i := 0; i < 5; i++ {
				state.updateRetransmissionTimer(tcpRetransmissionReselect, now)
				state.armLiveness(false)
				if !state.livenessDeadline.Equal(deadline) || state.sendTimer.persistSince != started {
					t.Fatal("timer reselection or liveness rearming moved the zero-window clock")
				}
			}
			state.peerWindow = 65535
			state.armPersist(time.Time{}, c.sendBuffer.size, false)
			state.armLiveness(false)
			if state.sendTimer.persistSince != 0 {
				t.Fatal("window reopening retained the zero-window clock")
			}
		})
	}
}

func TestTCPZeroWindowRetransmissionPrecedesSACKReneging(t *testing.T) {
	for _, fullySACKed := range []bool{false, true} {
		t.Run(fmt.Sprintf("fully-SACKed=%t", fullySACKed), func(t *testing.T) {
			now := time.Now()
			c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			state := tcpEstablishedState{
				connection: c,
				outstanding: []sentTCPSegment{
					{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
					{sequence: 200, end: 300, state: sentTCPSegmentTransmitted},
				},
				peerWindow: 0, peerSACK: true, sackedRanges: 1,
				rtt: rttEstimator{rto: time.Second},
			}
			if fullySACKed {
				state.outstanding[1].state.set(sentTCPSegmentSACKed, true)
				state.sackedRanges++
			}
			state.selectRetransmission(now, now, now)
			if state.retransmissionKind != tcpRetransmissionRTO {
				t.Fatalf("zero-window SACKed flight kind = %v, want ordinary RTO", state.retransmissionKind)
			}
			if index := state.retransmissionTarget(tcpRetransmissionRTO); index != 0 {
				t.Fatalf("zero-window SACKed target = %d, want queue head", index)
			}
		})
	}
}

func TestTCPZeroWindowSACKRenegingRecovery(t *testing.T) {
	link, stack, c := newManuallyPumpedTCPConnection(t)
	defer c.Close()
	mss := c.Info().MaximumSegmentSize
	payload := make([]byte, 3*mss)
	for index := range payload {
		payload[index] = byte(index / mss)
	}
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	var flight [3]TCPSegment
	for index := range flight {
		packet, err := ParseIPPacket(readOutboundPacket(t, stack))
		if err != nil {
			t.Fatal(err)
		}
		flight[index], err = packet.TCPSegment()
		if err != nil || !bytes.Equal(flight[index].Payload, payload[index*mss:(index+1)*mss]) {
			t.Fatalf("initial segment %d = %+v, %v", index, flight[index], err)
		}
	}
	link.mu.Lock()
	peer := link.tcp[c.key.local.Port()]
	sequence := peer.serverNext
	link.mu.Unlock()
	var sack [10]byte
	sack[0], sack[1] = TCPHeaderOptionSACK, 10
	binary.BigEndian.PutUint32(sack[2:6], flight[1].SequenceNumber)
	binary.BigEndian.PutUint32(sack[6:10], flight[1].SequenceNumber+uint32(mss))
	if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, flight[0].SequenceNumber, TCPFlagACK, 0, sack[:], nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return c.Info().PeerWindow == 0 })
	link.mu.Lock()
	peer.clientNext = flight[1].SequenceNumber
	peer.pending = append(peer.pending, flight[0].Payload)
	link.mu.Unlock()
	if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, flight[1].SequenceNumber, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return c.Info().BytesAcknowledged == uint64(mss) })
	entry, ok := waitTestPacketEntry(&stack.outbound, c.Info().RetransmissionTimeout+time.Second)
	if !ok {
		t.Fatal("zero-window reneging did not publish an RTO retransmission")
	}
	retry := consumeTestPacket(&stack.outbound, entry)
	packet, err := ParseIPPacket(retry)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.TCPSegment()
	if err != nil || wire.SequenceNumber != flight[1].SequenceNumber || !bytes.Equal(wire.Payload, flight[1].Payload) {
		t.Fatalf("zero-window reneging retry = %+v, %v; want SACKed left edge %d", wire, err, flight[1].SequenceNumber)
	}
	if stats := stack.Stats(); stats.TCPZeroWindowProbes != 0 || stats.TCPTailLossProbes != 0 {
		t.Fatalf("zero-window reneging used a non-RTO probe: %+v", stats)
	}
	if err = link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, flight[1].SequenceNumber, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = link.handleOutboundPacket(retry); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(3 * time.Second); c.Info().BytesAcknowledged != uint64(len(payload)); {
		if time.Now().After(until) {
			t.Fatalf("reopened reneging flight did not drain: %+v", c.Info())
		}
		if entry, available := waitTestPacketEntry(&stack.outbound, 20*time.Millisecond); available {
			if err = link.handleOutboundPacket(consumeTestPacket(&stack.outbound, entry)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if n, err := io.ReadFull(c, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("reopened reneging stream = %d/%d bytes, %v", n, len(payload), err)
	}
}

func TestTCPZeroWindowRetransmissionCancelsPLPMTUProbe(t *testing.T) {
	for _, family := range []struct{ name, local, remote string }{
		{"IPv4", "192.0.2.204", "198.51.100.204"},
		{"IPv6", "2001:db8::204", "2001:db8:1::204"},
	} {
		t.Run(family.name, func(t *testing.T) {
			local, remote := netip.MustParseAddr(family.local), netip.MustParseAddr(family.remote)
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}, MTU: 3000})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			network := "tcp4"
			if local.Is6() {
				network = "tcp6"
			}
			c := newTCPConn(stack, network, tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1500, tcpSocketOptionSet{})
			c.peerMSS, c.peerWindow = 2960, 0
			payloadSize := tcpMSSForMTU(2000, local)
			c.sendBuffer.append(bytes.Repeat([]byte{0x33}, payloadSize))
			state := newTCPEstablishedState(c, 100)
			defer state.finish()
			state.sendNext = 100 + uint32(payloadSize)
			state.outstanding = []sentTCPSegment{{sequence: 100, end: state.sendNext, flags: TCPFlagACK, state: sentTCPSegmentTransmitted | sentTCPSegmentMTUProbe}}
			state.pathMTUState = &tcpEstablishedPathMTUState{discovery: tcpPLPMTU{active: true, searching: true, probeMTU: 2000, probeStart: 100, probeEnd: state.sendNext, searchLow: 1500, searchHigh: 3000}}
			index := state.prepareRetransmission(0, true, false, false, false, 0, time.Now())
			if index != 0 || len(state.outstanding) != 2 {
				t.Fatalf("retransmission index/segments = %d/%d, want 0/2", index, len(state.outstanding))
			}
			discovery := state.pathMTUState.discovery
			if discovery.active || discovery.probeMTU != 0 || !discovery.searching || discovery.searchLow != 1500 || discovery.searchHigh != 3000 || c.mtu != 1500 || stack.Stats().PathMTUProbeFailures != 0 {
				t.Fatalf("inconclusive retry changed confirmed MTU or search bounds: mtu=%d discovery=%+v stats=%+v", c.mtu, discovery, stack.Stats())
			}
			for _, segment := range state.outstanding {
				if segment.dataSize() > state.peerMSS || segment.state.has(sentTCPSegmentMTUProbe) {
					t.Fatalf("unsafe probe remainder: %+v", segment)
				}
			}
			window, _, blocked, err := c.publishBufferedSegmentForMTU(state.sendUnacknowledged, state.outstanding[index], state.receiveNext, 65535, nil, false, c.mtu, tcpOutputWindow{})
			window.release()
			if err != nil || blocked {
				t.Fatalf("zero-window retry publication = blocked:%t error:%v", blocked, err)
			}
			wire := readOutboundPacket(t, stack)
			if len(wire) > c.mtu {
				t.Fatalf("retry packet length = %d, exceeds confirmed MTU %d", len(wire), c.mtu)
			}
		})
	}
}

func TestTCPZeroWindowPLPMTURecovery(t *testing.T) {
	for _, family := range []struct {
		name, local, remote string
		mtu                 int
	}{
		{"IPv4", "192.0.2.39", "192.0.2.40", 1000},
		{"IPv6", "2001:db8::39", "2001:db8::40", 1280},
	} {
		t.Run(family.name, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr(family.local), netip.MustParseAddr(family.remote))
			link.mu.Lock()
			link.echoTCP = true
			link.mu.Unlock()
			if !stack.observePathMTU(link.remote, uint32(family.mtu)) {
				t.Fatal("failed to install confirmed PMTU")
			}
			stack.pathMTUMu.Lock()
			entry := stack.pathMTU[link.remote]
			entry.updated = time.Now().Add(-pathMTULifetime + 50*time.Millisecond)
			stack.pathMTU[link.remote] = entry
			stack.pathMTUMu.Unlock()
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8094))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			c := connection.(*TCPConn)
			waitFor(t, time.Second, func() bool { return c.Info().PathMTUDiscovery })
			link.mu.Lock()
			link.echoTCP = false
			peer := link.tcp[c.key.local.Port()]
			sequence, ack := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			payload := bytes.Repeat([]byte{0x33}, 16*1024)
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			var held []ipPacket
			probeSeen := false
			probeDeadline := time.NewTimer(time.Second)
			defer probeDeadline.Stop()
			for !probeSeen {
				select {
				case wire := <-link.outbound:
					packet, ok := parseIPPacket(wire, false)
					if !ok || packet.protocol != ProtocolTCP {
						t.Fatal("invalid held TCP packet")
					}
					held = append(held, packet)
					probeSeen = len(wire) > family.mtu
				case <-probeDeadline.C:
					t.Fatalf("oversized probe was not published: %+v", c.Info())
				}
			}
			if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK, 0, nil, nil); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool { return c.Info().PeerWindow == 0 })
			retrySeen := false
			retryDeadline := time.NewTimer(2 * time.Second)
			defer retryDeadline.Stop()
			for !retrySeen {
				select {
				case wire := <-link.outbound:
					packet, ok := parseIPPacket(wire, false)
					if !ok || packet.protocol != ProtocolTCP {
						t.Fatal("invalid held TCP packet")
					}
					headerSize := int(packet.payload[12]>>4) * 4
					retrySeen = binary.BigEndian.Uint32(packet.payload[4:8]) == ack && len(packet.payload) > headerSize && len(wire) <= family.mtu
					held = append(held, packet)
				case <-retryDeadline.C:
					t.Fatalf("confirmed-MTU zero-window retry was not published: %+v", c.Info())
				}
			}
			waitFor(t, time.Second, func() bool { return c.Info().Retransmissions != 0 })
			if info := c.Info(); info.PathMTU != family.mtu || info.PathMTUProbe != 0 || info.PathMTUProbeFailures != 0 {
				t.Fatalf("zero-window retry misclassified PMTU loss: %+v", info)
			}
			if err := link.deliverTCP(c.key.remote.Port(), c.key.local.Port(), sequence, ack, TCPFlagACK, 65535, nil, nil); err != nil {
				t.Fatal(err)
			}
			for _, packet := range held {
				if err := link.handleTCP(packet); err != nil {
					t.Fatal(err)
				}
			}
			deliveryDeadline := time.NewTimer(5 * time.Second)
			defer deliveryDeadline.Stop()
			for {
				link.mu.Lock()
				delivered := peer.clientNext == ack+uint32(len(payload))
				link.mu.Unlock()
				if delivered {
					break
				}
				select {
				case wire := <-link.outbound:
					packet, ok := parseIPPacket(wire, false)
					if !ok || packet.protocol != ProtocolTCP {
						t.Fatal("invalid resumed TCP packet")
					}
					if err := link.handleTCP(packet); err != nil {
						t.Fatal(err)
					}
				case <-deliveryDeadline.C:
					t.Fatalf("reopened flight was not delivered: %+v", c.Info())
				}
			}
			link.mu.Lock()
			link.echoTCP = true
			link.mu.Unlock()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			received := make([]byte, len(payload))
			if n, err := io.ReadFull(c, received); err != nil || !bytes.Equal(received, payload) {
				link.mu.Lock()
				peer := link.tcp[c.key.local.Port()]
				peerNext, pending, outOfOrder := peer.clientNext, len(peer.pending), len(peer.outOfOrder)
				link.mu.Unlock()
				t.Fatalf("reopened stream = %d/%d bytes equal:%t error:%v info:%+v peer next:%d pending:%d out-of-order:%d", n, len(payload), bytes.Equal(received, payload), err, c.Info(), peerNext, pending, outOfOrder)
			}
		})
	}
}

func TestTCPPathMTUReduction(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	link.tcpPathMTU = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8083))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x6d}, 1300)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("PMTU TCP response mismatch")
	}
	link.mu.Lock()
	injected, maximum := link.pathMTUInjected, link.postPathMTUMaximum
	link.mu.Unlock()
	if !injected || maximum > int(link.tcpPathMTU) {
		t.Fatalf("Packet Too Big injected = %v, later maximum packet = %d, PMTU = %d", injected, maximum, link.tcpPathMTU)
	}
	if info := connection.(*TCPConn).Info(); info.MaximumSegmentSize != 948 {
		t.Fatalf("timestamped PMTU send MSS = %d, want 948", info.MaximumSegmentSize)
	}
}

func TestTCPPathMTUReductionPreservesFINSequence(t *testing.T) {
	original := sentTCPSegment{
		sequence: 100, end: 1101, flags: TCPFlagACK | TCPFlagPSH | TCPFlagFIN,
	}
	segments := splitTCPSegments([]sentTCPSegment{original}, 600)
	if len(segments) != 2 {
		t.Fatalf("resegmented FIN ranges = %d, want 2", len(segments))
	}
	if segments[0].end != 700 || segments[0].flags&(TCPFlagPSH|TCPFlagFIN) != 0 {
		t.Fatalf("first resegmented range = [%d,%d) flags=%#x", segments[0].sequence, segments[0].end, segments[0].flags)
	}
	last := segments[1]
	if last.sequence != 700 || last.end != original.end || last.flags&(TCPFlagPSH|TCPFlagFIN) != TCPFlagPSH|TCPFlagFIN {
		t.Fatalf("last resegmented FIN range = [%d,%d) flags=%#x, want [700,1101) PSH|FIN", last.sequence, last.end, last.flags)
	}
}

func TestTCPPathMTUReductionNotifiesSiblingFlows(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.37"), netip.MustParseAddr("192.0.2.38"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.tcpPathMTU = 1000
	link.mu.Unlock()
	first, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8093))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = first.SetDeadline(time.Now().Add(3 * time.Second))
	_ = second.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, first, bytes.Repeat([]byte{0x41}, 1300))
	link.mu.Lock()
	link.postPathMTUMaximum = 0
	link.mu.Unlock()
	writeAndReadTCPEcho(t, second, bytes.Repeat([]byte{0x42}, 1100))
	link.mu.Lock()
	maximum := link.postPathMTUMaximum
	link.mu.Unlock()
	if maximum > 1000 {
		t.Fatalf("sibling TCP flow emitted %d-byte packet after destination PMTU update", maximum)
	}
}

func TestTCPMTUIncreaseRaisesMSS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.timestampTCP = true
	link.mu.Unlock()
	localPrefix := netip.PrefixFrom(link.local, 32)
	if err := stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{localPrefix}, MTU: 1280}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8089))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	link.mu.Lock()
	link.maximumTCPData = 0
	link.mu.Unlock()
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{localPrefix}, MTU: 2000}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		info := connection.(*TCPConn).Info()
		return info.PathMTU == 2000 && info.MaximumSegmentSize == 1268
	})
	payload := bytes.Repeat([]byte{0x4d}, 1280)
	writeAndReadTCPEcho(t, connection, payload)
	link.mu.Lock()
	maximum := link.maximumTCPData
	link.mu.Unlock()
	if maximum != 1268 {
		t.Fatalf("TCP payload after MTU increase = %d, want 1268", maximum)
	}
}

func TestTCPPathMTUExpiryProbesUpward(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.35"), netip.MustParseAddr("192.0.2.36"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, 1000) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 100*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8090))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x31}, 1100))
	link.mu.Lock()
	before := link.maximumTCPData
	link.maximumTCPData = 0
	link.mu.Unlock()
	if before > 960 {
		t.Fatalf("TCP payload before PMTU expiry = %d, want <= 960", before)
	}

	payload := bytes.Repeat([]byte{0x32}, 8*1024)
	deadline := time.Now().Add(time.Second)
	after := 0
	for after <= 960 && time.Now().Before(deadline) {
		link.mu.Lock()
		link.maximumTCPData = 0
		link.mu.Unlock()
		writeAndReadTCPEcho(t, connection, payload)
		link.mu.Lock()
		after = link.maximumTCPData
		link.mu.Unlock()
		if after <= 960 {
			time.Sleep(time.Millisecond)
		}
	}
	if after <= 960 || stack.Stats().PathMTUProbeSuccesses == 0 {
		t.Fatalf("TCP payload/probe successes after PMTU expiry = %d/%d, want payload > 960 and a confirmed probe", after, stack.Stats().PathMTUProbeSuccesses)
	}
}

func TestTCPPathMTUSubthresholdConvergenceRefreshesCache(t *testing.T) {
	const linkMTU = 1400
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.45"), netip.MustParseAddr("192.0.2.46"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, linkMTU-5) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 25*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8095))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitFor(t, time.Second, func() bool {
		expiry, exists := stack.pathMTUExpiry(link.remote)
		return exists && time.Until(expiry) > pathMTULifetime-time.Minute
	})
	if info := connection.(*TCPConn).Info(); info.PathMTUDiscovery || info.PathMTU != linkMTU-5 {
		t.Fatalf("sub-threshold PLPMTU state = searching %t MTU %d", info.PathMTUDiscovery, info.PathMTU)
	}
}

func TestTCPPathMTUIsolatedProbeFailure(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.39"), netip.MustParseAddr("192.0.2.40"))
	link.mu.Lock()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPAbove = 1100
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, 1000) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 50*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8094))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(75 * time.Millisecond)
	payload := bytes.Repeat([]byte{0x33}, 16*1024)
	writeAndReadTCPEcho(t, connection, payload)
	stats := stack.Stats()
	if stats.PathMTUProbeFailures == 0 || stats.PathMTUProbes == 0 {
		t.Fatalf("isolated PLPMTU failure stats = probes %d failures %d", stats.PathMTUProbes, stats.PathMTUProbeFailures)
	}
}

func TestTCPRouteRemovalReportsNetworkUnreachable(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("192.0.2.34"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8091))
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		Routes:         []Route{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("Read after route removal = %v, want ENETUNREACH", err)
	}
}

func TestTCPSilentPathMTUBlackHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPAbove = 1280
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8086))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	initialMTU := stack.mtuFor(link.remote)
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	payload := bytes.Repeat([]byte{0x7a}, 1300)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("black-hole recovery payload mismatch")
	}
	if mtu := stack.mtuFor(link.remote); mtu != initialMTU {
		t.Fatalf("connection-local black-hole recovery changed cached path MTU to %d", mtu)
	}
}

func TestTCPBlackHoleMTUFloor(t *testing.T) {
	if got := nextBlackHoleMTU(1006, false); got != 576 {
		t.Fatalf("next IPv4 black-hole MTU = %d, want 576", got)
	}
	if got := nextBlackHoleMTU(576, false); got != 508 {
		t.Fatalf("next IPv4 black-hole MTU below 576 = %d, want 508", got)
	}
	if got := nextBlackHoleMTU(296, false); got != 68 {
		t.Fatalf("next IPv4 black-hole MTU at the minimum plateau = %d, want 68", got)
	}
	if got := nextBlackHoleMTU(68, false); got != 68 {
		t.Fatalf("IPv4 black-hole MTU below floor = %d, want 68", got)
	}
	if got := nextBlackHoleProbeMTU(1400, false, 1200, false); got != 1006 {
		t.Fatalf("IPv4 black-hole probe with 1200-byte peer MSS = %d, want 1006", got)
	}
	if got := nextBlackHoleProbeMTU(1500, false, 536, false); got != 508 {
		t.Fatalf("IPv4 black-hole probe below conventional MSS floor = %d, want 508", got)
	}
	if got := nextBlackHoleProbeMTU(1500, true, 1400, true); got != 1280 {
		t.Fatalf("IPv6 black-hole probe = %d, want 1280", got)
	}
}

func TestTCPOutOfOrderEarlierFINWins(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	receiveNext := uint32(100)
	receiveWindow := uint32(1000)
	var pieces []tcpReceivedPiece
	bytes := 0
	connection.receiveTCPData(200, nil, true, receiveWindow, 0, &receiveNext, &pieces, &bytes)
	if len(pieces) != 1 || pieces[0].sequence != 200 || !pieces[0].fin {
		t.Fatal("later out-of-order FIN was not retained")
	}
	connection.receiveTCPData(150, nil, true, receiveWindow, 0, &receiveNext, &pieces, &bytes)
	if len(pieces) != 1 || pieces[0].sequence != 150 || !pieces[0].fin {
		t.Fatalf("normalized FIN pieces = %+v, want FIN at 150", pieces)
	}
}

func TestTCPOutOfOrderFINCompactsTruncatedRange(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	owner := make([]byte, 32)
	copy(owner, "abcdefghijklmnopqrstuvwxyz")
	pieces := []tcpReceivedPiece{{sequence: 104, payload: owner}}
	bytes := len(owner)
	receiveNext := uint32(100)
	connection.receiveTCPData(106, nil, true, 64, 0, &receiveNext, &pieces, &bytes)
	if len(pieces) != 1 || !pieces[0].fin || string(pieces[0].payload) != "ab" ||
		&pieces[0].payload[0] == &owner[0] || cap(pieces[0].payload) != len(pieces[0].payload) || bytes != 2 {
		t.Fatalf("FIN-truncated range retained owner backing: pieces=%+v bytes=%d capacity=%d", pieces, bytes, cap(pieces[0].payload))
	}
}

func TestTCPOutOfOrderFINWaitsForSequenceGap(t *testing.T) {
	connection := &TCPConn{
		receiveCapacity: 32,
		readNotify:      make(chan struct{}),
	}
	receiveNext := uint32(100)
	var pieces []tcpReceivedPiece
	outOfOrderBytes := 0
	if delivered, closed := connection.receiveTCPData(104, []byte("ef"), true, 32, 0, &receiveNext, &pieces, &outOfOrderBytes); delivered || closed {
		t.Fatalf("out-of-order data plus FIN = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 100 || connection.readBuffer.size != 0 {
		t.Fatalf("gapped receive state = next %d buffer %q", receiveNext, testTCPReadBufferBytes(&connection.readBuffer))
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("abcd"), false, 32, 0, &receiveNext, &pieces, &outOfOrderBytes); !delivered || !closed {
		t.Fatalf("gap completion = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 107 || string(testTCPReadBufferBytes(&connection.readBuffer)) != "abcdef" || len(pieces) != 0 || outOfOrderBytes != 0 {
		t.Fatalf("completed receive state = next %d buffer %q pieces %d bytes %d", receiveNext, testTCPReadBufferBytes(&connection.readBuffer), len(pieces), outOfOrderBytes)
	}
	connection.setReadEOF()
	buffer := make([]byte, 6)
	if n, err := connection.Read(buffer); n != len(buffer) || err != nil || string(buffer) != "abcdef" {
		t.Fatalf("Read before EOF = %d, %v, %q", n, err, buffer)
	}
	if n, err := connection.Read(buffer[:1]); n != 0 || err != io.EOF {
		t.Fatalf("final Read = %d, %v; want 0, EOF", n, err)
	}
}

func TestTCPPartialACKCanLeaveFINOnly(t *testing.T) {
	segment := sentTCPSegment{
		sequence: 100, end: 104, flags: TCPFlagACK | TCPFlagPSH | TCPFlagFIN,
		state: sentTCPSegmentCWR, delivery: tcpDeliverySnapshot{deliveredStamp: 1},
	}
	trimAcknowledgedTCPSegment(&segment, 103)
	if segment.sequence != 103 || segment.end != 104 || segment.dataSize() != 0 || segment.flags&TCPFlagFIN == 0 || segment.flags&TCPFlagPSH != 0 || segment.state.has(sentTCPSegmentCWR) || segment.delivery.deliveredStamp == 0 {
		t.Fatalf("FIN-only remainder = %+v", segment)
	}
}

func TestTCPCloseWithUnreadDataIsAbortive(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.readBuffer.append([]byte("unread"))
	connection.sendBuffer.append([]byte("unsent"))
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.abortCh:
	default:
		t.Fatal("Close with unread data did not request an abortive reset")
	}
	if !connection.takeAbortReset() {
		t.Fatal("unread-data close suppressed the reset")
	}
	if connection.takeAbortReset() {
		t.Fatal("unread-data close published the reset more than once")
	}
	if connection.sendBuffer.size != 0 {
		t.Fatalf("abortive close retained %d send bytes", connection.sendBuffer.size)
	}
}

func TestTCPConcurrentAbortPublication(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	first := errors.New("first abort")
	connection.abortWithoutReset(first)

	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			connection.abort(errors.New("later abort"))
		}()
	}
	wait.Wait()
	select {
	case <-connection.abortCh:
	default:
		t.Fatal("abort did not close its notification channel")
	}
	if err := connection.abortedError(); err != first {
		t.Fatalf("abort error = %v, want first publication", err)
	}
	if connection.takeAbortReset() {
		t.Fatal("later abort changed the first publication's reset policy")
	}

	nilCause := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	nilCause.abortWithoutReset(nil)
	nilCause.abort(errors.New("later abort"))
	if err := nilCause.abortedError(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil abort error = %v, want net.ErrClosed", err)
	}
	if nilCause.takeAbortReset() {
		t.Fatal("later abort changed a nil cause's reset policy")
	}
}

func TestTCPConcurrentClosePublication(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.linger = 0
	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			<-start
			results <- connection.Close()
		}()
	}
	close(start)
	succeeded := 0
	for index := 0; index < callers; index++ {
		err := <-results
		if err == nil {
			succeeded++
		} else if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("concurrent Close error = %v, want net.ErrClosed", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent Close calls = %d, want 1", succeeded)
	}
	if !connection.takeAbortReset() || connection.takeAbortReset() {
		t.Fatal("concurrent Close did not publish exactly one abortive reset")
	}
}

func TestTCPImmediateIODoesNotAllocateDeadlineChannels(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.mu.Lock()
	connection.readBuffer.append([]byte{0x5a})
	connection.mu.Unlock()
	var payload [1]byte
	if n, err := connection.Read(payload[:]); err != nil || n != len(payload) {
		t.Fatalf("immediate Read = %d, %v", n, err)
	}
	if n, err := connection.Write(payload[:]); err != nil || n != len(payload) {
		t.Fatalf("immediate Write = %d, %v", n, err)
	}
	connection.mu.Lock()
	readDeadline := connection.readDeadline.channelLocked()
	writeDeadline := connection.writeDeadline.channelLocked()
	connection.mu.Unlock()
	if readDeadline != nil || writeDeadline != nil {
		t.Fatal("immediate I/O allocated a deadline channel")
	}
}

func TestTCPNetworkNamePreserved(t *testing.T) {
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		if got := newTCPNetwork(network).name(); got != network {
			t.Errorf("network name = %q, want %q", got, network)
		}
	}
}

func TestTCPConnectionMemoryLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return
	}
	for _, test := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"TCPConn", unsafe.Sizeof(TCPConn{}), 688},
		{"socketDeadline", unsafe.Sizeof(socketDeadline{}), 16},
		{"tcpEstablishedState", unsafe.Sizeof(tcpEstablishedState{}), 1528},
		{"tcpRACKSample", unsafe.Sizeof(tcpRACKSample{}), 48},
		{"tcpEstablishedLivenessState", unsafe.Sizeof(tcpEstablishedLivenessState{}), 56},
		{"tcpEstablishedPathMTUState", unsafe.Sizeof(tcpEstablishedPathMTUState{}), 120},
		{"tcpRecoveryUndo", unsafe.Sizeof(tcpRecoveryUndo{}), 80},
		{"tcpRecoveryTransportState", unsafe.Sizeof(tcpRecoveryTransportState{}), 56},
		{"tcpCongestionController", unsafe.Sizeof(tcpCongestionController{}), 472},
		{"CongestionRateSample", unsafe.Sizeof(CongestionRateSample{}), 136},
	} {
		if test.got != test.want {
			t.Errorf("%s size = %d, want %d; reassess per-connection allocation classes", test.name, test.got, test.want)
		}
	}

	var state tcpEstablishedState
	liveness := state.ensureLivenessState()
	if state.pathMTUState != nil || state.ensureLivenessState() != liveness {
		t.Fatal("liveness state initialized or retained an unrelated path state")
	}
	pathState := state.ensurePathMTUState()
	if state.ensurePathMTUState() != pathState || state.livenessState != liveness {
		t.Fatal("path state initialization replaced an independent liveness state")
	}
}

func TestTCPSendBufferChunkOwnership(t *testing.T) {
	payload := make([]byte, tcpSendChunkMaximum+512)
	for index := range payload {
		payload[index] = byte(index*37 + 11)
	}
	var buffer tcpSendBuffer
	buffer.append(payload)
	if buffer.size != len(payload) || len(buffer.chunks) != 2 {
		t.Fatalf("chunked send buffer = %d bytes in %d chunks", buffer.size, len(buffer.chunks))
	}
	const gather = 300
	offset := tcpSendChunkMaximum - 100
	var view tcpPayloadView
	total := buffer.view(offset, gather, &view)
	snapshot := make([]byte, view.size)
	view.copyTo(snapshot)
	if total != len(payload) || !bytes.Equal(snapshot, payload[offset:offset+gather]) {
		t.Fatalf("cross-chunk snapshot = %d/%d bytes, equal %t", len(snapshot), total, bytes.Equal(snapshot, payload[offset:offset+gather]))
	}
	buffer.acknowledge(tcpSendChunkMaximum)
	total = buffer.view(0, len(payload), &view)
	remaining := make([]byte, view.size)
	view.copyTo(remaining)
	if total != 512 || !bytes.Equal(remaining, payload[tcpSendChunkMaximum:]) {
		t.Fatalf("acknowledged send buffer = %d/%d bytes, equal %t", len(remaining), total, bytes.Equal(remaining, payload[tcpSendChunkMaximum:]))
	}

	var reusable tcpSendBuffer
	reusable.append([]byte("first"))
	firstStorage := &reusable.chunks[0].storage[0]
	reusable.acknowledge(len("first"))
	reusable.append([]byte("second"))
	if &reusable.chunks[0].storage[0] != firstStorage {
		t.Fatal("acknowledged storage was not reused")
	}
}

func TestTCPSendBufferAdaptiveChunkRetention(t *testing.T) {
	var buffer tcpSendBuffer
	buffer.append([]byte{1})
	if capacity := cap(buffer.chunks[0].storage); capacity != tcpSendChunkInitial {
		t.Fatalf("initial small send chunk capacity = %d, want %d", capacity, tcpSendChunkInitial)
	}
	buffer.append(make([]byte, tcpSendChunkInitial))
	if capacity := cap(buffer.chunks[1].storage); capacity != tcpSendChunkMinimum {
		t.Fatalf("later small send chunk capacity = %d, want %d", capacity, tcpSendChunkMinimum)
	}

	var moderate tcpSendBuffer
	payload := make([]byte, 8*1024)
	moderate.append(payload)
	moderate.acknowledge(len(payload))
	if moderate.spare != nil || moderate.reusableState != tcpSendReusableReleased {
		t.Fatalf("one-shot moderate chunk retained: spare=%d state=%d", cap(moderate.spare), moderate.reusableState)
	}
	moderate.append(payload)
	moderate.acknowledge(len(payload))
	if cap(moderate.spare) != len(payload) || moderate.reusableState != tcpSendReusableConfirmed {
		t.Fatalf("repeated moderate chunk not retained: spare=%d state=%d", cap(moderate.spare), moderate.reusableState)
	}

	var live tcpSendBuffer
	live.append(make([]byte, tcpSendChunkInitial))
	live.append([]byte{1})
	live.acknowledge(tcpSendChunkInitial)
	live.append(make([]byte, tcpSendChunkMinimum))
	if capacity := cap(live.chunks[1].storage); capacity < tcpSendChunkMinimum {
		t.Fatalf("small first-chunk spare reused in live queue: capacity=%d", capacity)
	}
	var view tcpPayloadView
	live.view(0, tcpSendChunkMaximum, &view)
}

func TestTCPCloseWithoutUnreadDataRemainsGraceful(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.abortCh:
		t.Fatal("graceful Close unexpectedly requested a reset")
	default:
	}
	connection.abortWithoutReset(net.ErrClosed)
}

func TestTCPTimeoutErrorPreservesSoftFailure(t *testing.T) {
	want := ICMPError{Reporter: netip.MustParseAddr("192.0.2.254"), Type: 3, Code: 1}
	var gotICMP ICMPError
	if got := tcpTimeoutError(want); !errors.As(got, &gotICMP) || gotICMP.Reporter != want.Reporter || gotICMP.Type != want.Type || gotICMP.Code != want.Code {
		t.Fatalf("timeout error = %v, want %v", got, want)
	}
	if got := tcpTimeoutError(nil); got != os.ErrDeadlineExceeded {
		t.Fatalf("timeout error = %v, want os.ErrDeadlineExceeded", got)
	}
}

func TestRACKMarksOlderTransmission(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(20*time.Millisecond))},
	}
	var delivered []sentTCPSegment
	outstanding, _, _, _, delivered = applyTCPSACK(outstanding, []TCPSACKBlock{{LeftEdge: 200, RightEdge: 300}})
	state := tcpEstablishedState{connection: &TCPConn{stack: &Stack{timestampEpoch: base}}}
	state.observeRACKDelivery(delivered, 300, &tcpSegment{}, base.Add(25*time.Millisecond), 0, 0)
	markRACKLoss(outstanding, state.rackLatestDelivered, base.Add(25*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) || outstanding[1].state.has(sentTCPSegmentRACKLost) {
		t.Fatalf("RACK loss state = [%v %v]", outstanding[0].state.has(sentTCPSegmentRACKLost), outstanding[1].state.has(sentTCPSegmentRACKLost))
	}
}

func TestRACKWaitsFromCurrentTime(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(time.Millisecond)), state: sentTCPSegmentSACKed},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].transmittedAt(base), end: outstanding[1].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond, base); !ok || delay != 5*time.Millisecond {
		t.Fatalf("RACK loss delay = %v, %t; want 5ms, true", delay, ok)
	}
	markRACKLoss(outstanding, delivered, base.Add(19*time.Millisecond), 10*time.Millisecond, base)
	if outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK declared loss before the reordering timer expired")
	}
	markRACKLoss(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK did not declare loss when the reordering timer expired")
	}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond, base); ok {
		t.Fatalf("RACK rearmed an already declared loss with delay %v", delay)
	}
}

func TestRACKCanDetectLostRetransmission(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, state: sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, state: sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(base, base.Add(time.Millisecond))},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].transmittedAt(base), end: outstanding[1].end, rtt: 5 * time.Millisecond}
	markRACKLoss(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) || outstanding[0].state.has(sentTCPSegmentSACKRetried) {
		t.Fatalf("lost retransmission state = lost %t retried %t", outstanding[0].state.has(sentTCPSegmentRACKLost), outstanding[0].state.has(sentTCPSegmentSACKRetried))
	}
}

func TestRACKPreservesTransmissionOrderAcrossClockTies(t *testing.T) {
	base := time.Unix(100, 0)
	var transport tcpEstablishedState
	original := testPacketQueueTicketAt(base, base)
	retransmission := testPacketQueueTicketAt(base, base)
	originalOrder := transport.recordTransmission(original)
	retransmissionOrder := transport.recordTransmission(retransmission)
	if got := retransmission.queuedTime(base); !got.Equal(base) {
		t.Fatalf("clock-tied queue publication time = %v, want %v", got, base)
	}
	if !tcpSequenceGreater(retransmissionOrder, originalOrder) {
		t.Fatalf("clock-tied transmission order = %d after %d", retransmissionOrder, originalOrder)
	}
	transport.connection = &TCPConn{stack: &Stack{timestampEpoch: base}}
	transport.rackLatestDelivered = tcpRACKSample{sentAt: original.queuedTime(base), end: 200, order: originalOrder}
	transport.observeRACKDelivery([]sentTCPSegment{{end: 300, hostQueue: original, transmissionOrder: originalOrder}}, 300, &tcpSegment{}, base.Add(time.Millisecond), 0, 0)
	if transport.rackLatestDelivered.end != 300 {
		t.Fatalf("same-transmission clock tie selected end %d, want 300", transport.rackLatestDelivered.end)
	}
	segment := sentTCPSegment{
		sequence:          100,
		end:               200,
		state:             sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried,
		hostQueue:         retransmission,
		transmissionOrder: retransmissionOrder,
	}
	delivered := tcpRACKSample{sentAt: original.queuedTime(base), end: 300, order: originalOrder, rtt: time.Millisecond}
	outstanding := []sentTCPSegment{segment}
	if markRACKLoss(outstanding, delivered, retransmission.queuedTime(base).Add(time.Millisecond), 0, base); outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK treated an earlier clock-tied flight as newer than its retransmission")
	}

	later := testPacketQueueTicketAt(base, base)
	delivered.order = transport.recordTransmission(later)
	delivered.sentAt = later.queuedTime(base)
	if !markRACKLoss(outstanding, delivered, later.queuedTime(base).Add(time.Millisecond), 0, base) || !outstanding[0].state.has(sentTCPSegmentRACKLost) || outstanding[0].state.has(sentTCPSegmentSACKRetried) {
		t.Fatalf("later delivery did not mark the retransmission lost: state=%#x", outstanding[0].state)
	}

	transport.transmissionOrder = ^uint32(0)
	if wrapped := transport.recordTransmission(later); wrapped != 1 || !tcpClockTieTransmissionAfter(wrapped, 0, ^uint32(0), 0) {
		t.Fatalf("wrapped transmission order = %d, want 1 after %d", wrapped, uint32(^uint32(0)))
	}
}

func TestRACKDeliveryClipsAcknowledgedEnd(t *testing.T) {
	base := time.Unix(100, 0)
	for _, test := range []struct{ end, acknowledged, want uint32 }{
		{200, 150, 150},
		{50, ^uint32(0) - 50, ^uint32(0) - 50},
		{50, 25, 25},
		{^uint32(0) - 50, 50, ^uint32(0) - 50},
	} {
		state := tcpEstablishedState{connection: &TCPConn{stack: &Stack{timestampEpoch: base}}}
		delivered := []sentTCPSegment{{end: test.end, hostQueue: testPacketQueueTicketAt(base, base)}}
		state.observeRACKDelivery(delivered, test.acknowledged, &tcpSegment{}, base.Add(time.Millisecond), 0, 0)
		if got := state.rackLatestDelivered.end; got != test.want {
			t.Fatalf("delivered end %d capped at %d = %d, want %d", test.end, test.acknowledged, got, test.want)
		}
	}
}

func TestRACKUsesMaximumRemainingWait(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(3*time.Millisecond))},
		{sequence: 300, end: 400, state: sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(base, base.Add(5*time.Millisecond))},
	}
	delivered := tcpRACKSample{sentAt: outstanding[2].transmittedAt(base), end: outstanding[2].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(10*time.Millisecond), 5*time.Millisecond, base); !ok || delay != 8*time.Millisecond {
		t.Fatalf("RACK maximum loss delay = %v, %t; want 8ms, true", delay, ok)
	}
}

func TestRACKLossCutoffMatchesTransmissionTimes(t *testing.T) {
	for _, epoch := range []time.Time{time.Unix(100, 0), time.Now()} {
		for _, elapsed := range []time.Duration{-time.Nanosecond, 0, time.Millisecond, 3*time.Millisecond - time.Nanosecond, 3 * time.Millisecond, 3*time.Millisecond + time.Nanosecond, 10 * time.Millisecond} {
			now := epoch.Add(elapsed)
			const rtt, window = time.Millisecond, 2 * time.Millisecond
			outstanding := []sentTCPSegment{
				{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(epoch, epoch)},
				{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(time.Nanosecond))},
				{sequence: 300, end: 400, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(time.Millisecond)), state: sentTCPSegmentSACKed},
				{sequence: 400, end: 500, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(2*time.Millisecond)), state: sentTCPSegmentRACKLost | sentTCPSegmentSACKRetried},
				{sequence: 500, end: 600},
				{sequence: 600, end: 700, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(4*time.Millisecond))},
			}
			delivered := tcpRACKSample{sentAt: epoch.Add(4 * time.Millisecond), end: 600, rtt: rtt}
			want := append([]sentTCPSegment(nil), outstanding...)
			var wantDelay time.Duration
			wantTimer, wantLoss := false, false
			for index := range want {
				segment := &want[index]
				sentAt := segment.transmittedAt(epoch)
				latestAt := delivered.sentAt
				after := latestAt.After(sentAt) || latestAt.Equal(sentAt) && tcpClockTieTransmissionAfter(delivered.order, delivered.end, segment.transmissionOrder, segment.end)
				deadline := sentAt.Add(rtt + window)
				if !segment.state.has(sentTCPSegmentSACKed|sentTCPSegmentRACKLost) && after {
					remaining := deadline.Sub(now)
					if remaining < 0 {
						remaining = 0
					}
					if !wantTimer || remaining > wantDelay {
						wantDelay = remaining
					}
					wantTimer = true
				}
				if !segment.state.has(sentTCPSegmentSACKed) && after && !now.Before(deadline) {
					segment.state |= sentTCPSegmentRACKLost
					segment.state.set(sentTCPSegmentSACKRetried, false)
				}
				wantLoss = wantLoss || segment.state.has(sentTCPSegmentRACKLost) && !segment.state.has(sentTCPSegmentSACKRetried)
			}
			if delay, ok := rackLossDelay(outstanding, delivered, now, window, epoch); ok != wantTimer || delay != wantDelay {
				t.Fatalf("epoch %v elapsed %v: RACK delay = %v, %t; want %v, %t", epoch, elapsed, delay, ok, wantDelay, wantTimer)
			}
			if lost := markRACKLoss(outstanding, delivered, now, window, epoch); lost != wantLoss {
				t.Fatalf("epoch %v elapsed %v: RACK loss = %t, want %t", epoch, elapsed, lost, wantLoss)
			}
			for index := range outstanding {
				if outstanding[index].state != want[index].state {
					t.Fatalf("epoch %v elapsed %v range %d: state = %#x, want %#x", epoch, elapsed, index, outstanding[index].state, want[index].state)
				}
			}
		}
	}
}

func TestRACKRejectsAmbiguousRetransmissionRTT(t *testing.T) {
	base := time.Unix(100, 0)
	for _, test := range []struct {
		name          string
		rtt           time.Duration
		echo          uint32
		retransmitted bool
		valid         bool
	}{
		{"below-minimum", 5 * time.Millisecond, 200, true, false},
		{"older-echo", 20 * time.Millisecond, 199, true, false},
		{"latest-echo", 20 * time.Millisecond, 200, true, true},
		{"original", 20 * time.Millisecond, 0, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := tcpEstablishedState{
				connection: &TCPConn{stack: &Stack{timestampEpoch: base}},
				rtt:        rttEstimator{minimum: 10 * time.Millisecond},
			}
			segment := sentTCPSegment{end: 200, timestamp: 200, hostQueue: testPacketQueueTicketAt(base, base)}
			segment.state.set(sentTCPSegmentRetransmitted, test.retransmitted)
			state.observeRACKDelivery([]sentTCPSegment{segment}, 200, &tcpSegment{}, base.Add(test.rtt), test.echo, 0)
			if valid := !state.rackLatestDelivered.sentAt.IsZero(); valid != test.valid {
				t.Fatalf("RACK sample = %+v, want valid %t", state.rackLatestDelivered, test.valid)
			}
		})
	}
}

func TestRACKSampleRTTBounds(t *testing.T) {
	for _, retransmitted := range []bool{false, true} {
		for _, elapsed := range []time.Duration{-time.Millisecond, -time.Nanosecond, 0, time.Nanosecond, time.Microsecond, time.Millisecond} {
			t.Run(fmt.Sprintf("retransmitted-%t/%s", retransmitted, elapsed), func(t *testing.T) {
				base := time.Unix(100, 0)
				sentAt := base.Add(time.Second)
				sample := tcpRACKSample{sentAt: sentAt, end: 200, rtt: elapsed, timestamp: 100, retransmitted: retransmitted}
				state := tcpEstablishedState{connection: &TCPConn{stack: &Stack{timestampEpoch: base}}}
				segment := sentTCPSegment{end: sample.end, timestamp: sample.timestamp, hostQueue: testPacketQueueTicketAt(base, sentAt)}
				segment.state.set(sentTCPSegmentRetransmitted, retransmitted)
				state.observeRACKDelivery([]sentTCPSegment{segment}, sample.end, &tcpSegment{}, sentAt.Add(elapsed), sample.timestamp, 0)
				got := state.rackLatestDelivered
				if elapsed < 0 {
					if !got.sentAt.IsZero() {
						t.Fatalf("negative RTT sample was accepted: %+v", got)
					}
					return
				}
				if sample.rtt < time.Microsecond {
					sample.rtt = time.Microsecond
				}
				if got != sample {
					t.Fatalf("RACK sample = %+v, want %+v", got, sample)
				}
			})
		}
	}
}

func TestTCPRACKIgnoresTransmissionAfterACKArrival(t *testing.T) {
	for _, name := range []string{"cumulative", "partial", "SACK"} {
		for _, previous := range []bool{false, true} {
			for _, clock := range []string{"unstamped", "arrival", "advanced"} {
				t.Run(fmt.Sprintf("%s/previous-%t/%s", name, previous, clock), func(t *testing.T) {
					now := time.Unix(100, 0)
					epoch := now.Add(-time.Second)
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: epoch}
					connection.sendBuffer.append(make([]byte, 200))
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(CongestionControlReno),
						peerMSS: 100, peerSACK: true, peerWindow: 65535,
						sendUnacknowledged: 100, sendNext: 300,
						congestionWindow: 1000, slowStartThreshold: 1000, rtt: newRTTEstimator(time.Second),
						outstanding: []sentTCPSegment{
							{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(epoch, now.Add(time.Millisecond))},
							{sequence: 200, end: 300, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Millisecond))},
						},
					}
					state.rtt.observeAt(time.Microsecond, monotonicStampAt(epoch, now.Add(-30*time.Millisecond)))
					if previous {
						state.rackLatestDelivered = tcpRACKSample{sentAt: now.Add(-2 * time.Millisecond), end: 100, rtt: 2 * time.Millisecond}
					}
					wantRACK := state.rackLatestDelivered
					state.rebaseOutstanding()
					state.controller.initialize(CongestionPhaseOpen, epoch, 0, 0, 1000, 1000, 100, 1)
					segment := tcpSegment{acknowledgement: 200, flags: TCPFlagACK, window: 65535}
					if name == "partial" {
						segment.acknowledgement = 150
					} else if name == "SACK" {
						segment.acknowledgement = 100
						var options [10]byte
						options[0], options[1] = TCPHeaderOptionSACK, 10
						binary.BigEndian.PutUint32(options[2:6], 100)
						binary.BigEndian.PutUint32(options[6:10], 200)
						segment.setOptions(options[:])
					}
					processedAt := now
					if clock != "unstamped" {
						segment.receivedAt = monotonicStampAt(epoch, now)
						if clock == "advanced" {
							processedAt = tcpQueuedSegmentEventTime(segment, now.Add(2*time.Millisecond), epoch)
							if processedAt != now.Add(2*time.Millisecond) {
								t.Fatalf("actor event time regressed: %v", processedAt)
							}
						}
					}
					state.processAcknowledgment(&segment, processedAt, 0)
					if state.rackLatestDelivered != wantRACK {
						t.Fatalf("RACK advanced from an ACK predating the transmission: %+v, want %+v", state.rackLatestDelivered, wantRACK)
					}
					wantForwardACK := uint32(200)
					if name == "partial" {
						wantForwardACK = 150
					}
					if !state.rackForwardACKSet || state.rackForwardACK != wantForwardACK || state.rackReorderingSeen {
						t.Fatalf("forward ACK = %d, set %t, reordering %t; want %d, true, false", state.rackForwardACK, state.rackForwardACKSet, state.rackReorderingSeen, wantForwardACK)
					}
					if state.haveRACKLoss || state.controller.state.LostBytes != 0 {
						t.Fatalf("ACK inferred false loss: RACK %t, lost bytes %d", state.haveRACKLoss, state.controller.state.LostBytes)
					}
					if state.sendUnacknowledged != segment.acknowledgement {
						t.Fatalf("cumulative ACK was not applied: %d, want %d", state.sendUnacknowledged, segment.acknowledgement)
					}
					if name == "SACK" && (state.sackedBytes != 100 || !state.outstanding[0].state.has(sentTCPSegmentSACKed)) {
						t.Fatal("selective ACK was not applied")
					}
					if name == "partial" && state.outstanding[0].sequence != 150 {
						t.Fatal("partial ACK did not trim the acknowledged prefix")
					}
				})
			}
		}
	}
}

func TestTCPRACKSelectsLatestValidDelivery(t *testing.T) {
	for _, method := range []string{"cumulative", "partial", "SACK"} {
		for _, previous := range []string{"none", "older", "newer"} {
			for _, test := range []struct {
				name       string
				rtt        time.Duration
				minimumRTT time.Duration
				echo       uint32
				valid      bool
			}{
				{"future", -time.Millisecond, time.Microsecond, 200, false},
				{"old-timestamp-echo", 6 * time.Millisecond, time.Microsecond, 199, false},
				{"below-minimum-RTT", 2 * time.Millisecond, 5 * time.Millisecond, 200, false},
				{"new-minimum-RTT", 2 * time.Millisecond, 0, 200, false},
				{"valid-retransmission", 6 * time.Millisecond, time.Microsecond, 200, true},
			} {
				if test.minimumRTT == 0 && method != "SACK" {
					continue
				}
				t.Run(fmt.Sprintf("%s/previous-%s/%s", method, previous, test.name), func(t *testing.T) {
					now := time.Unix(100, 0)
					epoch := now.Add(-time.Second)
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: epoch}
					connection.sendBuffer.append(make([]byte, 300))
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(CongestionControlReno),
						peerMSS: 100, peerSACK: true, peerWindow: 65535,
						sendUnacknowledged: 100, sendNext: 400,
						congestionWindow: 1000, slowStartThreshold: 1000, rtt: newRTTEstimator(time.Second),
						outstanding: []sentTCPSegment{
							{sequence: 100, end: 200, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-20*time.Millisecond))},
							{sequence: 200, end: 300, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-10*time.Millisecond))},
							{sequence: 300, end: 400, timestamp: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-test.rtt))},
						},
					}
					if test.minimumRTT != 0 {
						state.rtt.observeAt(test.minimumRTT, monotonicStampAt(epoch, now.Add(-30*time.Millisecond)))
					}
					if previous == "older" {
						state.rackLatestDelivered = tcpRACKSample{sentAt: now.Add(-30 * time.Millisecond), end: 90, rtt: 30 * time.Millisecond}
					} else if previous == "newer" {
						state.rackLatestDelivered = tcpRACKSample{sentAt: now.Add(-5 * time.Millisecond), end: 90, rtt: 5 * time.Millisecond}
					}
					state.rebaseOutstanding()
					state.controller.initialize(CongestionPhaseOpen, epoch, state.rtt.minimum, state.rtt.srtt, 1000, 1000, 100, 1)
					segment := tcpSegment{acknowledgement: 400, flags: TCPFlagACK, window: 65535, receivedAt: monotonicStampAt(epoch, now)}
					if method == "partial" {
						segment.acknowledgement = 350
					} else if method == "SACK" {
						segment.acknowledgement = 100
						var options [10]byte
						options[0], options[1] = TCPHeaderOptionSACK, 10
						binary.BigEndian.PutUint32(options[2:6], 200)
						binary.BigEndian.PutUint32(options[6:10], 400)
						segment.setOptions(options[:])
					}
					want := tcpRACKSample{sentAt: now.Add(-10 * time.Millisecond), end: 300, rtt: 10 * time.Millisecond}
					if test.valid {
						end := uint32(400)
						if method == "partial" {
							end = 350
						}
						want = tcpRACKSample{sentAt: now.Add(-test.rtt), end: end, rtt: test.rtt, timestamp: 200, retransmitted: true}
					}
					if previous == "newer" {
						rtt := want.rtt
						want = state.rackLatestDelivered
						want.rtt = rtt
					}
					processedAt := tcpQueuedSegmentEventTime(segment, now.Add(2*time.Millisecond), epoch)
					state.processAcknowledgment(&segment, processedAt, test.echo)
					if state.rackLatestDelivered != want {
						t.Fatalf("latest valid RACK delivery = %+v, want %+v", state.rackLatestDelivered, want)
					}
					wantForwardACK := uint32(400)
					if method == "partial" {
						wantForwardACK = 350
					}
					if !state.rackForwardACKSet || state.rackForwardACK != wantForwardACK || state.rackReorderingSeen {
						t.Fatalf("forward ACK = %d, set %t, reordering %t; want %d, true, false", state.rackForwardACK, state.rackForwardACKSet, state.rackReorderingSeen, wantForwardACK)
					}
					if state.sendUnacknowledged != segment.acknowledgement {
						t.Fatalf("cumulative ACK = %d, want %d", state.sendUnacknowledged, segment.acknowledgement)
					}
					if method == "SACK" && state.sackedBytes != 200 {
						t.Fatalf("SACKed bytes = %d, want 200", state.sackedBytes)
					}
					if method == "partial" && state.outstanding[0].sequence != 350 {
						t.Fatal("partial ACK did not trim the acknowledged prefix")
					}
				})
			}
		}
	}
}

func TestTCPRACKSelectsDeliveryRTTAcrossACKRanges(t *testing.T) {
	for _, test := range []struct {
		name          string
		ack           uint32
		blocks        []TCPSACKBlock
		sentAt        [4]time.Duration
		retransmitted int
		wantEnd       uint32
	}{
		{name: "SACK ascending", ack: 100, blocks: []TCPSACKBlock{{200, 300}, {400, 500}},
			sentAt: [4]time.Duration{25, 10, 25, 20}, retransmitted: -1, wantEnd: 500},
		{name: "SACK descending", ack: 100, blocks: []TCPSACKBlock{{400, 500}, {200, 300}},
			sentAt: [4]time.Duration{25, 10, 25, 20}, retransmitted: -1, wantEnd: 500},
		{name: "SACK retransmission", ack: 100, blocks: []TCPSACKBlock{{400, 500}, {200, 300}},
			sentAt: [4]time.Duration{25, 20, 25, 10}, retransmitted: 1, wantEnd: 300},
		{name: "cumulative", ack: 300,
			sentAt: [4]time.Duration{20, 10, 25, 25}, retransmitted: 0, wantEnd: 200},
		{name: "partial cumulative", ack: 250,
			sentAt: [4]time.Duration{20, 10, 25, 25}, retransmitted: 0, wantEnd: 200},
		{name: "cumulative and SACK", ack: 200, blocks: []TCPSACKBlock{{400, 500}},
			sentAt: [4]time.Duration{20, 25, 25, 10}, retransmitted: 0, wantEnd: 200},
	} {
		for _, previous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/previous-%t", test.name, previous), func(t *testing.T) {
				epoch := time.Unix(100, 0)
				arrival := epoch.Add(30 * time.Millisecond)
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{timestampEpoch: epoch}
				connection.sendBuffer.append(make([]byte, 400))
				state := tcpEstablishedState{
					connection: connection, controller: newTCPCongestionController(CongestionControlReno),
					peerMSS: 100, peerSACK: true, peerWindow: 65535,
					sendUnacknowledged: 100, sendNext: 500,
					congestionWindow: 1000, slowStartThreshold: 1000,
					rtt: newRTTEstimator(time.Second), rackReorderingSeen: true,
				}
				for index, elapsed := range test.sentAt {
					segment := sentTCPSegment{
						sequence: uint32(100 + 100*index), end: uint32(200 + 100*index),
						state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(elapsed*time.Millisecond)),
					}
					segment.state.set(sentTCPSegmentRetransmitted, index == test.retransmitted)
					state.outstanding = append(state.outstanding, segment)
				}
				want := tcpRACKSample{sentAt: epoch.Add(20 * time.Millisecond), end: test.wantEnd, rtt: 10 * time.Millisecond, retransmitted: test.retransmitted >= 0}
				if previous {
					state.rackLatestDelivered = tcpRACKSample{sentAt: epoch.Add(25 * time.Millisecond), end: 100, rtt: 2 * time.Millisecond}
					want = state.rackLatestDelivered
					want.rtt = 10 * time.Millisecond
				}
				state.rtt.observeAt(time.Millisecond, monotonicStampAt(epoch, epoch.Add(29*time.Millisecond)))
				state.rebaseOutstanding()
				state.controller.initialize(CongestionPhaseOpen, epoch, state.rtt.minimum, state.rtt.srtt, 1000, 1000, 100, 1)
				ack := tcpSegment{acknowledgement: test.ack, flags: TCPFlagACK, window: 65535, receivedAt: monotonicStampAt(epoch, arrival)}
				if len(test.blocks) != 0 {
					options := make([]byte, 2+8*len(test.blocks))
					options[0], options[1] = TCPHeaderOptionSACK, byte(len(options))
					for index, block := range test.blocks {
						binary.BigEndian.PutUint32(options[2+8*index:6+8*index], block.LeftEdge)
						binary.BigEndian.PutUint32(options[6+8*index:10+8*index], block.RightEdge)
					}
					ack.setOptions(options)
				}
				state.processAcknowledgment(&ack, arrival, 0)
				if state.rackLatestDelivered != want {
					t.Fatalf("RACK delivery = %+v, want %+v", state.rackLatestDelivered, want)
				}
				outstanding := []sentTCPSegment{{sequence: 600, end: 700, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(19900*time.Microsecond))}}
				const window = 250 * time.Microsecond
				deadline := epoch.Add(30150 * time.Microsecond)
				before := deadline.Add(-time.Nanosecond)
				if delay, ok := rackLossDelay(outstanding, state.rackLatestDelivered, before, window, epoch); !ok || delay != time.Nanosecond {
					t.Fatalf("RACK remaining wait = %v, %t; want 1ns, true", delay, ok)
				}
				if markRACKLoss(outstanding, state.rackLatestDelivered, before, window, epoch) {
					t.Fatal("RACK declared loss before the delivery-based deadline")
				}
				if !markRACKLoss(outstanding, state.rackLatestDelivered, deadline, window, epoch) {
					t.Fatal("RACK did not declare loss at the delivery-based deadline")
				}
			})
		}
	}
}

func TestTCPRACKOlderDeliveryRefreshesRTT(t *testing.T) {
	epoch := time.Unix(100, 0)
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.stack = &Stack{timestampEpoch: epoch}
	connection.sendBuffer.append(make([]byte, 300))
	state := tcpEstablishedState{
		connection: connection, controller: newTCPCongestionController(CongestionControlReno),
		peerMSS: 100, peerSACK: true, peerWindow: 65535,
		sendUnacknowledged: 100, sendNext: 400,
		congestionWindow: 1000, slowStartThreshold: 1000, rtt: newRTTEstimator(time.Second),
		rackReorderingSeen: true,
		outstanding: []sentTCPSegment{
			{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost | sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(18*time.Millisecond))},
			{sequence: 200, end: 300, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(10*time.Millisecond))},
			{sequence: 300, end: 400, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(20*time.Millisecond))},
		},
	}
	state.rtt.observeAt(10*time.Millisecond, monotonicStampAt(epoch, epoch.Add(29*time.Millisecond)))
	state.rebaseOutstanding()
	state.controller.initialize(CongestionPhaseOpen, epoch, state.rtt.minimum, state.rtt.srtt, 1000, 1000, 100, 1)
	ack := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 65535}
	var options [10]byte
	options[0], options[1] = TCPHeaderOptionSACK, 10
	binary.BigEndian.PutUint32(options[2:6], 300)
	binary.BigEndian.PutUint32(options[6:10], 400)
	ack.setOptions(options[:])
	firstArrival := epoch.Add(30 * time.Millisecond)
	ack.receivedAt = monotonicStampAt(epoch, firstArrival)
	state.processAcknowledgment(&ack, firstArrival, 0)
	if !state.outstanding[1].state.has(sentTCPSegmentRACKLost) || state.outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatalf("first SACK loss state = [%#x %#x]", state.outstanding[0].state, state.outstanding[1].state)
	}
	if deadline, ok := state.rackDeadline(firstArrival, true); !ok || deadline != epoch.Add(30500*time.Microsecond) {
		t.Fatalf("first SACK deadline = %v, %t; want epoch+30.5ms", deadline.Sub(epoch), ok)
	}
	latest := state.rackLatestDelivered
	binary.BigEndian.PutUint32(options[2:6], 200)
	binary.BigEndian.PutUint32(options[6:10], 300)
	ack.setOptions(options[:])
	arrival := epoch.Add(30400 * time.Microsecond)
	ack.receivedAt = monotonicStampAt(epoch, arrival)
	state.processAcknowledgment(&ack, arrival, 0)
	latest.rtt = 20400 * time.Microsecond
	if state.rackLatestDelivered != latest || state.sackedBytes != 200 || state.outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatalf("older delivery = %+v, SACKed %d, remaining state %#x; want %+v, 200, no loss", state.rackLatestDelivered, state.sackedBytes, state.outstanding[0].state, latest)
	}
	wantDeadline := epoch.Add(40900 * time.Microsecond)
	if deadline, ok := state.rackDeadline(arrival, true); !ok || deadline != wantDeadline {
		t.Fatalf("older delivery deadline = %v, %t; want epoch+40.9ms", deadline.Sub(epoch), ok)
	}
	repeatedArrival := arrival.Add(time.Microsecond)
	ack.receivedAt = monotonicStampAt(epoch, repeatedArrival)
	state.processAcknowledgment(&ack, repeatedArrival, 0)
	if state.rackLatestDelivered != latest {
		t.Fatal("repeated SACK refreshed the delivery RTT")
	}
	markRACKLoss(state.outstanding, latest, wantDeadline.Add(-time.Nanosecond), 2500*time.Microsecond, epoch)
	if state.outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK declared the remaining retransmission lost before its deadline")
	}
	if !markRACKLoss(state.outstanding, latest, wantDeadline, 2500*time.Microsecond, epoch) || !state.outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK did not declare loss at the refreshed deadline")
	}
}

func TestTCPRACKCumulativeACKDoesNotResampleSACKedData(t *testing.T) {
	for _, ack := range []uint32{150, 200} {
		t.Run(fmt.Sprint(ack), func(t *testing.T) {
			epoch := time.Unix(100, 0)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			connection.sendBuffer.append(make([]byte, 100))
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(CongestionControlReno),
				peerMSS: 100, peerSACK: true, peerWindow: 65535,
				sendUnacknowledged: 100, sendNext: 200,
				congestionWindow: 1000, slowStartThreshold: 1000, rtt: newRTTEstimator(time.Second),
				rackLatestDelivered: tcpRACKSample{sentAt: epoch.Add(10 * time.Millisecond), end: 200, rtt: 10 * time.Millisecond},
				rackForwardACK:      200, rackForwardACKSet: true,
				outstanding: []sentTCPSegment{{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(10*time.Millisecond))}},
			}
			state.rtt.observeAt(10*time.Millisecond, monotonicStampAt(epoch, epoch.Add(20*time.Millisecond)))
			state.rebaseOutstanding()
			state.recountSACK()
			state.controller.initialize(CongestionPhaseOpen, epoch, state.rtt.minimum, state.rtt.srtt, 1000, 1000, 100, 1)
			want := state.rackLatestDelivered
			arrival := epoch.Add(30 * time.Millisecond)
			segment := tcpSegment{acknowledgement: ack, flags: TCPFlagACK, window: 65535, receivedAt: monotonicStampAt(epoch, arrival)}
			state.processAcknowledgment(&segment, arrival, 0)
			if state.rackLatestDelivered != want || state.sendUnacknowledged != ack {
				t.Fatalf("cumulative ACK delivery = %+v at %d, want %+v at %d", state.rackLatestDelivered, state.sendUnacknowledged, want, ack)
			}
			if state.rackForwardACK != 200 || state.rackReorderingSeen {
				t.Fatalf("SACKed delivery changed reordering evidence: forward ACK %d, reordering %t", state.rackForwardACK, state.rackReorderingSeen)
			}
		})
	}
}

func TestRACKRepeatedSACKIsNotNewDelivery(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{{sequence: 100, end: 200, timestamp: 10, hostQueue: testPacketQueueTicketAt(base, base)}}
	outstanding, _, _, newInformation, delivered := applyTCPSACK(outstanding, []TCPSACKBlock{{LeftEdge: 100, RightEdge: 200}})
	state := tcpEstablishedState{connection: &TCPConn{stack: &Stack{timestampEpoch: base}}}
	state.observeRACKDelivery(delivered, 200, &tcpSegment{}, base.Add(time.Millisecond), 0, 0)
	if !newInformation || len(delivered) != 1 || !state.rackLatestDelivered.sentAt.Equal(base) {
		t.Fatalf("initial SACK = new %t delivered %+v", newInformation, delivered)
	}
	_, _, _, newInformation, delivered = applyTCPSACK(outstanding, []TCPSACKBlock{{LeftEdge: 100, RightEdge: 200}})
	previous := state.rackLatestDelivered
	state.observeRACKDelivery(delivered, 200, &tcpSegment{}, base.Add(2*time.Millisecond), 0, 0)
	if newInformation || len(delivered) != 0 || state.rackLatestDelivered != previous {
		t.Fatalf("repeated SACK = new %t delivered %+v", newInformation, delivered)
	}
}

func TestFirstRACKLossRequiresTimeBasedEvidence(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200},
		{sequence: 200, end: 300, state: sentTCPSegmentRACKLost | sentTCPSegmentSACKed},
		{sequence: 300, end: 400, state: sentTCPSegmentRACKLost},
	}
	if index := firstRACKLoss(outstanding); index != 2 {
		t.Fatalf("first RACK loss = %d, want 2", index)
	}
	outstanding[2].state.set(sentTCPSegmentRACKLost, false)
	if index := firstRACKLoss(outstanding); index != -1 {
		t.Fatalf("RACK loss without evidence = %d, want -1", index)
	}
}

func TestRACKDetectsOriginalDataReordering(t *testing.T) {
	var forward uint32
	var set bool
	if reordered := rackAdvanceForwardACK(&forward, &set, 300, false); reordered || !set || forward != 300 {
		t.Fatalf("initial FACK = %d, %t, reordered %t", forward, set, reordered)
	}
	if reordered := rackAdvanceForwardACK(&forward, &set, 200, false); !reordered {
		t.Fatal("original data below FACK did not record reordering")
	}
	if reordered := rackAdvanceForwardACK(&forward, &set, 100, true); reordered {
		t.Fatal("retransmitted data below FACK recorded path reordering")
	}
}

func TestRACKReorderingWindowUsesMinimumRTT(t *testing.T) {
	if window := rackReorderingWindow(4*time.Millisecond, 20*time.Millisecond, 1); window != time.Millisecond {
		t.Fatalf("RACK reordering window = %v, want 1ms", window)
	}
	if window := rackReorderingWindow(80*time.Millisecond, 10*time.Millisecond, 1); window != 10*time.Millisecond {
		t.Fatalf("SRTT-bounded RACK window = %v, want 10ms", window)
	}
	if window := rackReorderingWindow(0, 10*time.Millisecond, 1); window != 0 {
		t.Fatalf("unsampled RACK window = %v, want 0", window)
	}
	if window := rackReorderingWindow(4*time.Millisecond, 20*time.Millisecond, 4); window != 4*time.Millisecond {
		t.Fatalf("DSACK-expanded RACK window = %v, want 4ms", window)
	}
	var estimator rttEstimator
	estimator.observeAt(20*time.Millisecond, 1)
	estimator.observeAt(4*time.Millisecond, 2)
	if estimator.minimum != 4*time.Millisecond {
		t.Fatalf("minimum RTT = %v, want 4ms", estimator.minimum)
	}
}

func TestTCPRTTSampleUsesSegmentArrivalTime(t *testing.T) {
	base := time.Unix(100, 0)
	if sample := elapsedRTTSampleAt(base, base.Add(10*time.Millisecond)); sample != 10*time.Millisecond {
		t.Fatalf("RTT sample = %v, want 10ms", sample)
	}
	if sample := elapsedRTTSampleAt(base, base.Add(-time.Second)); sample != time.Microsecond {
		t.Fatalf("reordered clock sample = %v, want 1us", sample)
	}
	if sample := elapsedRTTSampleAt(time.Time{}, base); sample != 0 {
		t.Fatalf("missing RTT sample = %v, want 0", sample)
	}
}

func TestTCPCumulativeACKRTTSampleMatchesElapsedTime(t *testing.T) {
	for clock, epoch := range []time.Time{time.Unix(100, 0), time.Now()} {
		for _, elapsed := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond, time.Microsecond, time.Millisecond, 2 * tcpMaximumRTO} {
			for _, stamped := range []bool{false, true} {
				t.Run(fmt.Sprintf("clock-%d/stamped-%t/%v", clock, stamped, elapsed), func(t *testing.T) {
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: epoch}
					connection.sendBuffer.append(make([]byte, 100))
					transmission := sentTCPSegment{sequence: 100, end: 200, state: sentTCPSegmentTransmitted}
					var sentAt time.Time
					if stamped {
						sentAt = epoch
						transmission.hostQueue = testPacketQueueTicketAt(epoch, sentAt)
					}
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(CongestionControlReno),
						peerMSS: 100, peerWindow: 65535, sendUnacknowledged: 100, sendNext: 200,
						congestionWindow: 1000, slowStartThreshold: 1000,
						rtt: newRTTEstimator(time.Second), outstanding: []sentTCPSegment{transmission},
					}
					state.controller.initialize(CongestionPhaseOpen, epoch, 0, 0, 1000, 1000, 100, 1)
					eventAt := epoch.Add(elapsed)
					want := state.rtt
					want.observeAt(elapsedRTTSampleAt(sentAt, eventAt), monotonicStampAt(epoch, eventAt))
					segment := tcpSegment{acknowledgement: 200, flags: TCPFlagACK, window: 65535, receivedAt: monotonicStampAt(epoch, epoch)}
					state.processAcknowledgment(&segment, eventAt, 0)
					if state.rtt != want {
						t.Fatalf("cumulative ACK RTT estimator = %+v, want %+v", state.rtt, want)
					}
				})
			}
		}
	}
}

func TestTCPSegmentEventTime(t *testing.T) {
	now := time.Unix(200, 0)
	receivedAt := now.Add(-10 * time.Millisecond)
	epoch := receivedAt.Add(-time.Second)
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, receivedAt)}, now, time.Time{}, epoch); got != receivedAt {
		t.Fatalf("segment event time = %v, want %v", got, receivedAt)
	}
	if got := tcpSegmentEventTime(tcpSegment{}, now, time.Time{}, epoch); got != now {
		t.Fatalf("missing segment event time = %v, want %v", got, now)
	}
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, now.Add(time.Second))}, now, time.Time{}, epoch); got != now {
		t.Fatalf("future segment event time = %v, want %v", got, now)
	}
	previous := receivedAt.Add(time.Second)
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, receivedAt)}, now, previous, epoch); got != previous {
		t.Fatalf("regressing segment event time = %v, want %v", got, previous)
	}
}

func TestTCPQueuedSegmentEventTime(t *testing.T) {
	epoch := time.Now().Add(-time.Second)
	previous := epoch.Add(500 * time.Millisecond)
	arrival := previous.Add(100 * time.Millisecond)
	if got := tcpQueuedSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, arrival)}, previous, epoch); got != arrival {
		t.Fatalf("queued segment event time = %v, want %v", got, arrival)
	}
	older := previous.Add(-time.Millisecond)
	if got := tcpQueuedSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, older)}, previous, epoch); got != previous {
		t.Fatalf("reordered queued segment event time = %v, want %v", got, previous)
	}
	before := time.Now()
	got := tcpQueuedSegmentEventTime(tcpSegment{}, previous, epoch)
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("unstamped queued segment event time = %v, processing interval [%v, %v]", got, before, after)
	}
}

func TestTCPEmptyFlightTimerOwnership(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	for _, kind := range []tcpRetransmissionKind{tcpRetransmissionRTO, tcpRetransmissionProbe, tcpRetransmissionRACK, tcpRetransmissionSACKReneging, tcpRetransmissionPathMTU, tcpRetransmissionClose} {
		for _, update := range []tcpRetransmissionUpdate{tcpRetransmissionPreserve, tcpRetransmissionRestart, tcpRetransmissionReselect} {
			state := tcpEstablishedState{retransmit: true, retransmissionKind: kind, retransmissionDeadline: deadline}
			state.sendTimer.baseDeadline = deadline
			state.updateRetransmissionTimer(update, time.Now())
			if kind >= tcpRetransmissionPathMTU {
				if !state.retransmit || state.retransmissionKind != kind || !state.retransmissionDeadline.Equal(deadline) || !state.sendTimer.baseDeadline.Equal(deadline) {
					t.Fatalf("owned timer kind=%v update=%v was cleared: %+v", kind, update, state)
				}
			} else if state.retransmit || state.retransmissionKind != tcpRetransmissionRTO || !state.retransmissionDeadline.IsZero() || !state.sendTimer.baseDeadline.IsZero() {
				t.Fatalf("empty loss timer kind=%v update=%v was retained: %+v", kind, update, state)
			}
		}
	}
	state := tcpEstablishedState{persist: true}
	state.sendTimer.baseDeadline = deadline
	state.updateRetransmissionTimer(tcpRetransmissionRestart, time.Now())
	if !state.persist || !state.sendTimer.baseDeadline.Equal(deadline) {
		t.Fatalf("ACK timer maintenance changed pure persist: %+v", state)
	}
}

func TestTCPPersistHistoryIndependentOfUserTimeout(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	c.stack = &Stack{timestampEpoch: started}
	c.sendBuffer.append([]byte("blocked"))
	state := tcpEstablishedState{connection: c, rtt: rttEstimator{rto: time.Second}}
	state.armPersist(started, c.sendBuffer.size, false)
	history := state.sendTimer.persistSince
	for _, timeout := range []time.Duration{0, 5 * time.Second, 0, 9 * time.Second} {
		c.userTimeout = timeout
		state.armLiveness(false)
		if state.sendTimer.persistSince != history || history == 0 || state.livenessState != nil {
			t.Fatal("changing user timeout moved persist history or allocated liveness state")
		}
		want := time.Time{}
		if timeout != 0 {
			want = started.Add(timeout)
		}
		if !state.livenessDeadline.Equal(want) || state.liveness != (timeout != 0) {
			t.Fatalf("user timeout %v deadline = %v, want %v", timeout, state.livenessDeadline, want)
		}
	}
	state.persist = false
	state.armPersist(started.Add(2*time.Second), c.sendBuffer.size, false)
	state.armLiveness(false)
	if state.sendTimer.persistSince != history || !state.livenessDeadline.Equal(started.Add(c.userTimeout)) {
		t.Fatal("probe rearming restarted the persist episode")
	}
	state.peerWindow = 65535
	state.armPersist(time.Time{}, c.sendBuffer.size, false)
	state.armLiveness(false)
	if state.sendTimer.persistSince != 0 || state.liveness {
		t.Fatal("window reopening retained persist history or its deadline")
	}
	state.peerWindow = 0
	next := started.Add(10 * time.Second)
	state.armPersist(next, c.sendBuffer.size, false)
	state.armLiveness(false)
	if !state.livenessDeadline.Equal(next.Add(c.userTimeout)) || state.sendTimer.persistSince == history {
		t.Fatal("a new persist episode reused the old history")
	}
}

func TestTCPPersistHistoryClearsOnExit(t *testing.T) {
	for _, mode := range []string{"empty queue", "window reopened", "outstanding", "outstanding timer update", "FIN sent"} {
		t.Run(mode, func(t *testing.T) {
			started := time.Now()
			c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			c.stack = &Stack{timestampEpoch: started}
			c.sendBuffer.append([]byte("blocked"))
			state := tcpEstablishedState{connection: c, rtt: rttEstimator{rto: time.Second}}
			state.armPersist(started, c.sendBuffer.size, false)
			if state.sendTimer.persistSince == 0 {
				t.Fatal("persist history was not established")
			}
			total, writeClosed := c.sendBuffer.size, false
			switch mode {
			case "empty queue":
				total = 0
			case "window reopened":
				state.peerWindow = 65535
			case "outstanding", "outstanding timer update":
				state.outstanding = []sentTCPSegment{{sequence: 0, end: 1, firstSent: 0}}
			case "FIN sent":
				total, writeClosed, state.localFINSent = 0, true, true
			}
			if mode == "outstanding timer update" {
				state.updateRetransmissionTimer(tcpRetransmissionPreserve, started)
			} else {
				state.armPersist(time.Time{}, total, writeClosed)
			}
			if state.sendTimer.persistSince != 0 || state.persist {
				t.Fatalf("persist history survived %s: %+v", mode, state.sendTimer)
			}
		})
	}
}

func TestTCPLivenessDeadlineTracksActivity(t *testing.T) {
	idle := time.Second
	connection := &TCPConn{
		keepAlive:       true,
		keepAliveConfig: KeepAliveConfig{Idle: idle, Interval: time.Second, Count: 3},
	}
	firstActivity := time.Now().Add(-time.Hour)
	state := tcpEstablishedState{connection: connection, lastActivity: firstActivity}
	state.armLiveness(false)
	if want := firstActivity.Add(idle); !state.liveness || state.livenessDeadline != want {
		t.Fatalf("initial liveness = %t at %v, want true at %v", state.liveness, state.livenessDeadline, want)
	}

	secondActivity := firstActivity.Add(10 * time.Minute)
	state.lastActivity = secondActivity
	state.armLiveness(false)
	if want := secondActivity.Add(idle); !state.liveness || state.livenessDeadline != want {
		t.Fatalf("rearmed liveness = %t at %v, want true at %v", state.liveness, state.livenessDeadline, want)
	}
}

func TestTCPLivenessKeepAliveEnableDeadline(t *testing.T) {
	activity := time.Unix(1700000000, 0)
	config := KeepAliveConfig{Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}
	for _, test := range []struct {
		name                                    string
		enabledAfter, probeAfter, receivedAfter time.Duration
		deadlineAfter                           time.Duration
		probes                                  int
	}{
		{name: "first enable", enabledAfter: time.Second, deadlineAfter: 31 * time.Second},
		{name: "before previous check", enabledAfter: 31 * time.Second, probeAfter: 30 * time.Second, probes: 1, deadlineAfter: 61 * time.Second},
		{name: "same clock tick", enabledAfter: 30 * time.Second, probeAfter: 30 * time.Second, probes: 1, deadlineAfter: 60 * time.Second},
		{name: "after previous check", enabledAfter: 50 * time.Second, probeAfter: 30 * time.Second, probes: 1, deadlineAfter: 80 * time.Second},
		{name: "received data postpones idle", enabledAfter: 31 * time.Second, probeAfter: 30 * time.Second, receivedAfter: 35 * time.Second, probes: 1, deadlineAfter: 65 * time.Second},
		{name: "published probe resumes interval", probeAfter: 61 * time.Second, probes: 2, deadlineAfter: 71 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := &TCPConn{stack: &Stack{timestampEpoch: activity}}
			liveness := &tcpEstablishedLivenessState{keepAliveProbes: test.probes}
			if test.enabledAfter != 0 {
				liveness.keepAliveEnabledAt = monotonicStampAt(activity, activity.Add(test.enabledAfter))
			}
			if test.probeAfter != 0 {
				liveness.lastKeepAlive = activity.Add(test.probeAfter)
			}
			state := tcpEstablishedState{connection: connection, livenessState: liveness, lastActivity: activity}
			if test.receivedAfter != 0 {
				state.lastDataReceived = monotonicStampAt(activity, activity.Add(test.receivedAfter))
			}
			if got, want := state.keepAliveDeadline(state.receiveActivityTime(), config), activity.Add(test.deadlineAfter); !got.Equal(want) {
				t.Fatalf("keepalive deadline = %v, want %v", got, want)
			}
			if liveness.keepAliveProbes != test.probes {
				t.Fatal("keepalive scheduling reset published probe history")
			}
		})
	}
}

func TestTCPLivenessKeepAliveUserTimeoutDeadline(t *testing.T) {
	activity := time.Unix(1700000000, 0)
	for _, test := range []struct {
		name          string
		userTimeout   time.Duration
		idleTimeout   time.Duration
		probed        bool
		pending       bool
		disabled      bool
		outstanding   bool
		zeroWindow    bool
		dataAfter     time.Duration
		deadlineAfter time.Duration
	}{
		{name: "first probe short timeout", userTimeout: 5 * time.Second, deadlineAfter: 30 * time.Second},
		{name: "first probe equal timeout", userTimeout: 30 * time.Second, deadlineAfter: 30 * time.Second},
		{name: "first probe long timeout", userTimeout: 45 * time.Second, deadlineAfter: 30 * time.Second},
		{name: "after probe short timeout", userTimeout: 5 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "after probe idle timeout", userTimeout: 30 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "after probe between checks", userTimeout: 35 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "after probe at check", userTimeout: 40 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "after probe later timeout", userTimeout: 45 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "pending first probe", userTimeout: 5 * time.Second, pending: true},
		{name: "pending after probe short timeout", userTimeout: 5 * time.Second, probed: true, pending: true, deadlineAfter: 40 * time.Second},
		{name: "pending after probe between checks", userTimeout: 35 * time.Second, probed: true, pending: true, deadlineAfter: 40 * time.Second},
		{name: "pending after probe later timeout", userTimeout: 45 * time.Second, probed: true, pending: true, deadlineAfter: 45 * time.Second},
		{name: "pending without user timeout", probed: true, pending: true},
		{name: "disabled after probe", userTimeout: 5 * time.Second, probed: true, disabled: true},
		{name: "disabled pending probe", userTimeout: 5 * time.Second, probed: true, pending: true, disabled: true},
		{name: "independent idle timeout", userTimeout: 5 * time.Second, idleTimeout: 35 * time.Second, probed: true, deadlineAfter: 35 * time.Second},
		{name: "pending independent idle timeout", userTimeout: 45 * time.Second, idleTimeout: 35 * time.Second, probed: true, pending: true, deadlineAfter: 35 * time.Second},
		{name: "outstanding data", userTimeout: 5 * time.Second, probed: true, outstanding: true, deadlineAfter: 37 * time.Second},
		{name: "pending outstanding data", userTimeout: 5 * time.Second, probed: true, pending: true, outstanding: true, deadlineAfter: 37 * time.Second},
		{name: "zero window", userTimeout: 5 * time.Second, probed: true, zeroWindow: true, deadlineAfter: 37 * time.Second},
		{name: "pending zero window", userTimeout: 5 * time.Second, probed: true, pending: true, zeroWindow: true, deadlineAfter: 37 * time.Second},
		{name: "data postpones first probe", dataAfter: 20 * time.Second, deadlineAfter: 50 * time.Second},
		{name: "data postpones subsequent probe", dataAfter: 35 * time.Second, probed: true, deadlineAfter: 65 * time.Second},
		{name: "probe interval remains minimum", dataAfter: 5 * time.Second, probed: true, deadlineAfter: 40 * time.Second},
		{name: "data postpones pending user timeout", userTimeout: 45 * time.Second, dataAfter: 35 * time.Second, probed: true, pending: true, deadlineAfter: 80 * time.Second},
		{name: "data postpones independent idle timeout", idleTimeout: 10 * time.Second, dataAfter: 35 * time.Second, probed: true, deadlineAfter: 45 * time.Second},
		{name: "data cannot postpone outstanding user timeout", userTimeout: 5 * time.Second, dataAfter: 35 * time.Second, probed: true, outstanding: true, deadlineAfter: 37 * time.Second},
		{name: "data cannot postpone persist user timeout", userTimeout: 5 * time.Second, dataAfter: 35 * time.Second, probed: true, zeroWindow: true, deadlineAfter: 37 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := &TCPConn{
				stack:           &Stack{timestampEpoch: activity},
				keepAlive:       !test.disabled,
				keepAliveConfig: KeepAliveConfig{Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3},
				userTimeout:     test.userTimeout,
				idleTimeout:     test.idleTimeout,
			}
			state := tcpEstablishedState{connection: connection, lastActivity: activity, peerWindow: 65535}
			if test.dataAfter != 0 {
				state.lastDataReceived = monotonicStampAt(activity, activity.Add(test.dataAfter))
			}
			if test.probed {
				state.livenessState = &tcpEstablishedLivenessState{keepAliveProbes: 1, lastKeepAlive: activity.Add(30 * time.Second)}
			}
			if test.outstanding {
				state.outstanding = []sentTCPSegment{{firstSent: 32 * time.Second}}
			}
			if test.zeroWindow {
				connection.sendBuffer.append([]byte("blocked"))
				state.peerWindow = 0
				state.armPersist(activity.Add(32*time.Second), connection.sendBuffer.size, false)
			}
			state.armLiveness(test.pending)
			var want time.Time
			if test.deadlineAfter != 0 {
				want = activity.Add(test.deadlineAfter)
			}
			if state.liveness != !want.IsZero() || !state.livenessDeadline.Equal(want) {
				t.Fatalf("liveness = %t at %v, want %t at %v", state.liveness, state.livenessDeadline, !want.IsZero(), want)
			}
		})
	}
}

func TestTCPDispatchPreservesPacketArrivalTime(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	key := tcpKey{local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 50000)}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	stack.tcp[key] = connection
	packet, ok := parseIPPacket(buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), 1, 1, TCPFlagACK, 65535, nil, nil), false)
	if !ok {
		t.Fatal("test TCP packet did not parse")
	}
	receivedAt := stack.timestampEpoch.Add(250 * time.Millisecond)
	if err = stack.handleTCP(packet, receivedAt, true, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.inbound.notify:
		segment, dequeued := connection.inbound.dequeue()
		if !dequeued {
			t.Fatal("TCP dispatch notification had no segment")
		}
		if got := segment.receivedAt.time(stack.timestampEpoch); got != receivedAt {
			t.Fatalf("dispatched arrival time = %v, want %v", got, receivedAt)
		}
	default:
		t.Fatal("TCP segment was not dispatched")
	}
}

func TestTCPTimestampUsesEventTime(t *testing.T) {
	epoch := time.Unix(300, 0)
	stack := &Stack{timestampEpoch: epoch}
	if got := stack.tcpTimestampAt(epoch.Add(1234 * time.Millisecond)); got != 1235 {
		t.Fatalf("TCP timestamp = %d, want 1235", got)
	}
}

func TestTCPInitialSequenceRFC6528(t *testing.T) {
	epoch := time.Unix(400, 0)
	stack := &Stack{timestampEpoch: epoch}
	for index := range stack.tcpISNSecret {
		stack.tcpISNSecret[index] = byte(index)
	}
	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.1:40000"),
		remote: netip.MustParseAddrPort("198.51.100.1:443"),
	}
	base := stack.tcpInitialSequence(key, epoch)
	if got := stack.tcpInitialSequence(key, epoch.Add(4*time.Microsecond)); got != base+1 {
		t.Fatalf("ISN after one RFC timer tick = %#x, want %#x", got, base+1)
	}
	if got := stack.tcpInitialSequence(key, epoch.Add(-time.Second)); got != base {
		t.Fatalf("ISN before epoch = %#x, want clamped value %#x", got, base)
	}
	wrap := time.Duration(uint64(1)<<32) * 4 * time.Microsecond
	if got := stack.tcpInitialSequence(key, epoch.Add(wrap)); got != base {
		t.Fatalf("ISN after timer wrap = %#x, want %#x", got, base)
	}
	differentTuple := key
	differentTuple.remote = netip.MustParseAddrPort("198.51.100.1:444")
	if got := stack.tcpInitialSequence(differentTuple, epoch); got == base {
		t.Fatal("different TCP four-tuples received the same keyed offset")
	}
	differentSecret := &Stack{timestampEpoch: epoch, tcpISNSecret: stack.tcpISNSecret}
	differentSecret.tcpISNSecret[0] ^= 0xff
	if got := differentSecret.tcpInitialSequence(key, epoch); got == base {
		t.Fatal("different RFC 6528 secrets received the same keyed offset")
	}
	key6 := tcpKey{
		local:  netip.MustParseAddrPort("[2001:db8::1]:40000"),
		remote: netip.MustParseAddrPort("[2001:db8:1::1]:443"),
	}
	if got := stack.tcpInitialSequence(key6, epoch); got == base {
		t.Fatal("IPv4 and IPv6 connection spaces received the same keyed offset")
	}
}

func TestTCPDSACKParsing(t *testing.T) {
	options := make([]byte, 10)
	options[0], options[1] = 5, 10
	binary.BigEndian.PutUint32(options[2:6], 200)
	binary.BigEndian.PutUint32(options[6:10], 300)
	if block, ok := parseTCPDSACKOption(options, 300, 500, 200); !ok || block != (TCPSACKBlock{LeftEdge: 200, RightEdge: 300}) {
		t.Fatalf("below-ACK DSACK = %#v, %t", block, ok)
	}
	if _, ok := parseTCPDSACKOption(options, 300, 500, 50); ok {
		t.Fatal("DSACK older than retained send history was accepted")
	}

	options = make([]byte, 18)
	options[0], options[1] = 5, 18
	binary.BigEndian.PutUint32(options[2:6], 250)
	binary.BigEndian.PutUint32(options[6:10], 300)
	binary.BigEndian.PutUint32(options[10:14], 200)
	binary.BigEndian.PutUint32(options[14:18], 350)
	if block, ok := parseTCPDSACKOption(options, 100, 400, 0); !ok || block != (TCPSACKBlock{LeftEdge: 250, RightEdge: 300}) {
		t.Fatalf("contained DSACK = %#v, %t", block, ok)
	}
	binary.BigEndian.PutUint32(options[2:6], 301)
	binary.BigEndian.PutUint32(options[6:10], 300)
	if block, ok := parseTCPDSACKOption(options, 100, 400, 0); ok {
		t.Fatalf("reversed contained DSACK = %#v, want rejected", block)
	}
	for _, test := range []struct {
		name                               string
		ack, next, history                 uint32
		left, right, outerLeft, outerRight uint32
		valid                              bool
	}{
		{name: "expired history cannot use containment", ack: 4000, next: 6000, history: 3000, left: 0, right: 500, outerLeft: 0, outerRight: 1000},
		{name: "containing block beyond send next", ack: 300, next: 500, left: 450, right: 490, outerLeft: 400, outerRight: 600},
		{name: "containing block before ACK", ack: 300, next: 500, left: 320, right: 340, outerLeft: 290, outerRight: 400},
		{name: "valid contained block", ack: 100, next: 400, left: 250, right: 300, outerLeft: 200, outerRight: 350, valid: true},
		{name: "valid history ignores invalid following block", ack: 300, next: 500, history: 200, left: 200, right: 250, outerLeft: 400, outerRight: 600, valid: true},
		{name: "wrapped contained block", ack: 0xfffffff0, next: 0x40, left: 0, right: 0x10, outerLeft: 0xfffffff8, outerRight: 0x20, valid: true},
		{name: "wrapped containing block beyond send next", ack: 0xfffffff0, next: 0x40, left: 0x20, right: 0x30, outerLeft: 0x10, outerRight: 0x50},
		{name: "wrapped expired history", ack: 0x20, next: 0x80, history: 0x10, left: 0xfffffff0, right: 0, outerLeft: 0xffffffe0, outerRight: 0x10},
		{name: "wrapped acknowledged history", ack: 0x20, next: 0x80, history: 0x30, left: 0xfffffffc, right: 0x10, outerLeft: 0xfffffff8, outerRight: 0x10, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire [18]byte
			wire[0], wire[1] = 5, 18
			binary.BigEndian.PutUint32(wire[2:6], test.left)
			binary.BigEndian.PutUint32(wire[6:10], test.right)
			binary.BigEndian.PutUint32(wire[10:14], test.outerLeft)
			binary.BigEndian.PutUint32(wire[14:18], test.outerRight)
			block, valid := parseTCPDSACKOption(wire[:], test.ack, test.next, test.history)
			if valid != test.valid || valid && block != (TCPSACKBlock{LeftEdge: test.left, RightEdge: test.right}) {
				t.Fatalf("DSACK = %#v, %t, want [%#x,%#x), %t", block, valid, test.left, test.right, test.valid)
			}
		})
	}
}

func TestTCPRepeatedSACKIsNotNewInformation(t *testing.T) {
	outstanding := []sentTCPSegment{{sequence: 100, end: 200}, {sequence: 200, end: 300, delivery: tcpDeliverySnapshot{deliveredStamp: 1}}}
	blocks := []TCPSACKBlock{{LeftEdge: 200, RightEdge: 300}}
	var present, fresh bool
	var delivered []sentTCPSegment
	outstanding, _, present, fresh, delivered = applyTCPSACK(outstanding, blocks)
	if !present || !fresh || len(delivered) != 1 || delivered[0].delivery.deliveredStamp == 0 || outstanding[1].delivery.deliveredStamp != 0 {
		t.Fatalf("first SACK state = present %t, fresh %t; want true, true", present, fresh)
	}
	outstanding, _, present, fresh, delivered = applyTCPSACK(outstanding, blocks)
	if !present || fresh || len(delivered) != 0 {
		t.Fatalf("repeated SACK state = present %t, fresh %t; want true, false", present, fresh)
	}
}

func TestTCPPartialSACKSplitsScoreboard(t *testing.T) {
	outstanding := []sentTCPSegment{{sequence: 100, end: 400, flags: TCPFlagACK | TCPFlagPSH, state: sentTCPSegmentTransmitted}}
	var present, fresh bool
	var delivered []sentTCPSegment
	outstanding, _, present, fresh, delivered = applyTCPSACK(outstanding, []TCPSACKBlock{{LeftEdge: 200, RightEdge: 300}})
	if !present || !fresh || len(delivered) != 1 || len(outstanding) != 3 {
		t.Fatalf("partial SACK state = present %t fresh %t delivered %d segments %d", present, fresh, len(delivered), len(outstanding))
	}
	for index, want := range []struct {
		start, end uint32
		sacked     bool
		payload    int
		push       bool
	}{{100, 200, false, 100, false}, {200, 300, true, 100, false}, {300, 400, false, 100, true}} {
		segment := outstanding[index]
		if segment.sequence != want.start || segment.end != want.end || segment.state.has(sentTCPSegmentSACKed) != want.sacked || segment.dataSize() != want.payload || segment.flags&TCPFlagPSH != 0 != want.push {
			t.Fatalf("segment %d = [%d,%d) sacked=%t payload=%d flags=%#x", index, segment.sequence, segment.end, segment.state.has(sentTCPSegmentSACKed), segment.dataSize(), segment.flags)
		}
	}
	if ranges, bytes := tcpSACKedState(outstanding); ranges != 1 || bytes != 100 {
		t.Fatalf("partial SACK aggregate = %d ranges/%d bytes, want 1/100", ranges, bytes)
	}
}

func TestTCPSACKOrdersSplitRangesWithinOneTransmission(t *testing.T) {
	epoch := time.Unix(100, 0)
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse-%t", reverse), func(t *testing.T) {
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(CongestionControlReno),
				peerMSS: 100, peerSACK: true, peerWindow: 65535,
				sendUnacknowledged: 100, sendNext: 400,
				congestionWindow: 1000, slowStartThreshold: 1000, rtt: newRTTEstimator(time.Second),
				outstanding: []sentTCPSegment{{
					sequence: 100, end: 400, state: sentTCPSegmentTransmitted,
					hostQueue: testPacketQueueTicketAt(epoch, epoch), transmissionOrder: 7,
				}},
			}
			state.rebaseOutstanding()
			state.controller.initialize(CongestionPhaseOpen, epoch, 0, 0, 1000, 1000, 100, 1)
			blocks := []TCPSACKBlock{{LeftEdge: 150, RightEdge: 200}, {LeftEdge: 300, RightEdge: 350}}
			if reverse {
				blocks[0], blocks[1] = blocks[1], blocks[0]
			}
			var options [18]byte
			options[0], options[1] = TCPHeaderOptionSACK, 18
			for index, block := range blocks {
				binary.BigEndian.PutUint32(options[2+index*8:6+index*8], block.LeftEdge)
				binary.BigEndian.PutUint32(options[6+index*8:10+index*8], block.RightEdge)
			}
			segment := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 65535}
			segment.setOptions(options[:])
			state.processAcknowledgment(&segment, epoch.Add(10*time.Millisecond), 0)
			want := tcpRACKSample{sentAt: epoch, order: 7, end: 350, rtt: 10 * time.Millisecond}
			if state.rackLatestDelivered != want {
				t.Fatalf("latest split SACK transmission = %+v, want %+v", state.rackLatestDelivered, want)
			}
		})
	}
}

func TestTCPSACKSplitMetadataIsBounded(t *testing.T) {
	payloadSize := uint32(4 * tcpMaximumSACKSplitRanges)
	outstanding := []sentTCPSegment{{sequence: 0, end: payloadSize, state: sentTCPSegmentTransmitted}}
	for offset := uint32(1); offset+1 < payloadSize; offset += 2 {
		outstanding, _, _, _, _ = applyTCPSACK(outstanding, []TCPSACKBlock{{LeftEdge: offset, RightEdge: offset + 1}})
	}
	splitRanges := 0
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKSplit) {
			splitRanges++
		}
	}
	if splitRanges > tcpMaximumSACKSplitRanges {
		t.Fatalf("SACK-created ranges = %d, limit %d", splitRanges, tcpMaximumSACKSplitRanges)
	}
	if len(outstanding) > tcpMaximumSACKSplitRanges+1 {
		t.Fatalf("scoreboard ranges = %d after adversarial byte SACKs", len(outstanding))
	}
}

func TestTCPPeerMSSHasLinuxSafetyFloor(t *testing.T) {
	options := []byte{2, 4, 0, 1}
	mss, _, _, _, _, _ := parseTCPOptions(options, 536, 1400)
	if mss != tcpMinimumPeerMSS {
		t.Fatalf("one-byte peer MSS = %d, want Linux safety floor %d", mss, tcpMinimumPeerMSS)
	}
	if got := clampMSS(1, 16); got != 16 {
		t.Fatalf("path-derived MSS below peer safety floor = %d, want 16", got)
	}
	for _, test := range []struct {
		peer, path, options, want int
	}{
		{536, 1348, 0, 536},
		{536, 1348, 28, 508},
		{1268, 1348, 0, 1268},
		{1268, 1348, 12, 1256},
		{524, 1348, 12, 512},
	} {
		if got := tcpSegmentPayloadLimit(test.peer, test.path, test.options); got != test.want {
			t.Errorf("payload limit peer=%d path=%d options=%d = %d, want %d", test.peer, test.path, test.options, got, test.want)
		}
	}
	for _, test := range []struct {
		peer, path, want int
		timestamp        bool
	}{
		{peer: 1280, path: 1460, want: 1280},
		{peer: 1280, path: 1460, want: 1268, timestamp: true},
		{peer: 536, path: 1460, want: 524, timestamp: true},
	} {
		got := tcpEffectiveSendMSS(test.peer, test.path, test.timestamp)
		if got != test.want {
			t.Errorf("effective send MSS peer=%d path=%d timestamp=%t = %d, want %d", test.peer, test.path, test.timestamp, got, test.want)
		}
	}
}

func TestTCPSACKIsLostAndPipe(t *testing.T) {
	byRanges := []sentTCPSegment{
		{sequence: 0, end: 100},
		{sequence: 100, end: 150, state: sentTCPSegmentSACKed},
		{sequence: 150, end: 200, state: sentTCPSegmentSACKed},
		{sequence: 200, end: 250, state: sentTCPSegmentSACKed},
	}
	if !sackSegmentLost(byRanges, 0, 100) {
		t.Fatal("three SACKed transmitted ranges did not satisfy IsLost")
	}
	byBytes := []sentTCPSegment{{sequence: 0, end: 100}, {sequence: 100, end: 201, state: sentTCPSegmentSACKed}, {sequence: 201, end: 302, state: sentTCPSegmentSACKed}}
	if !sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("more than 2*SMSS SACKed bytes did not satisfy IsLost")
	}
	byBytes[2].end = 300
	if sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("exactly 2*SMSS SACKed bytes satisfied strict IsLost byte test")
	}
	speculative := []sentTCPSegment{{sequence: 0, end: 100, state: sentTCPSegmentSACKRetried}}
	if pipe := sackRecoveryPipe(speculative, 100); pipe != 200 {
		t.Fatalf("speculative retransmission pipe = %d, want 200", pipe)
	}
	lost := []sentTCPSegment{{sequence: 0, end: 100, state: sentTCPSegmentRACKLost}}
	if pipe := sackRecoveryPipe(lost, 100); pipe != 0 {
		t.Fatalf("unretransmitted lost range pipe = %d, want 0", pipe)
	}
	lost[0].state.set(sentTCPSegmentSACKRetried, true)
	if pipe := sackRecoveryPipe(lost, 100); pipe != 100 {
		t.Fatalf("retransmitted RACK loss pipe = %d, want 100", pipe)
	}
	flightState := tcpEstablishedState{
		outstanding: speculative, sendNext: 100,
		peerSACK: true, fastRecovery: true, peerMSS: 100,
	}
	if flight := flightState.congestionFlight(); flight != 200 {
		t.Fatalf("SACK recovery congestion flight = %d, want 200", flight)
	}
	flightState.fastRecovery = false
	if flight := flightState.congestionFlight(); flight != 100 {
		t.Fatalf("ordinary congestion flight = %d, want 100", flight)
	}
	if !sackRecoveryCanSend(false, 1000, 100, 1000) {
		t.Fatal("recovery-entry retransmission was incorrectly cwnd-gated")
	}
	if sackRecoveryCanSend(true, 1000, 100, 1000) {
		t.Fatal("RFC 6675 allowed a retransmission without cwnd-Pipe space")
	}
	if !sackRecoveryCanSend(true, 900, 100, 1000) {
		t.Fatal("RFC 6675 rejected a retransmission with exactly one segment of space")
	}
	wrappedSACK := []sentTCPSegment{{sequence: 0xfffffff0, end: 0x10, state: sentTCPSegmentSACKed}, {sequence: 0x10, end: 0x30, state: sentTCPSegmentSACKed}}
	if highest := highestSACKedSequence(wrappedSACK); highest != 0x30 {
		t.Fatalf("wrapped HighSACK = %#x, want 0x30", highest)
	}
}

func TestTCPSACKLossThresholds(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(algorithm, func(t *testing.T) {
			for _, test := range []struct {
				name  string
				sizes []int
				rack  bool
				lost  bool
			}{
				{name: "below range threshold", sizes: []int{1, 1}},
				{name: "at range threshold", sizes: []int{1, 1, 1}, lost: true},
				{name: "at byte threshold", sizes: []int{mss, mss}},
				{name: "above byte threshold", sizes: []int{mss, mss + 1}, lost: true},
				{name: "RACK below thresholds", sizes: []int{1}, rack: true, lost: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					for _, oldACK := range []bool{false, true} {
						now := time.Unix(100, 0)
						epoch := now.Add(-time.Second)
						connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
						connection.stack = &Stack{timestampEpoch: epoch}
						state := tcpEstablishedState{
							connection: connection, controller: newTCPCongestionController(algorithm),
							peerMSS: mss, peerSACK: true, peerWindow: 40_000,
							sendUnacknowledged: 100, sendNext: 1100,
							congestionWindow: 10 * mss, slowStartThreshold: 20 * mss,
							rackReorderingSeen: true, rtt: newRTTEstimator(time.Second),
						}
						state.controller.initialize(CongestionPhaseOpen, epoch, 100*time.Millisecond, 100*time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
						defer state.controller.release(now, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), mss, state.rtt.srtt, state.rtt.minimum)
						state.rtt.minimum, state.rtt.srtt = 100*time.Millisecond, 100*time.Millisecond
						ticket := testPacketQueueTicketAt(epoch, now.Add(-100*time.Millisecond))
						state.outstanding = []sentTCPSegment{{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted, hostQueue: ticket}}
						if test.rack {
							state.outstanding[0].hostQueue = testPacketQueueTicketAt(epoch, now.Add(-200*time.Millisecond))
						}
						for _, size := range test.sizes {
							state.outstanding = append(state.outstanding, sentTCPSegment{sequence: state.sendNext, end: state.sendNext + uint32(size), state: sentTCPSegmentTransmitted, hostQueue: ticket})
							state.sendNext += uint32(size)
						}
						state.rebaseOutstanding()
						var options [10]byte
						options[0], options[1] = TCPHeaderOptionSACK, 10
						binary.BigEndian.PutUint32(options[2:6], 1100)
						binary.BigEndian.PutUint32(options[6:10], state.sendNext)
						segment := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 40_000}
						if oldACK {
							segment.acknowledgement--
						}
						segment.setOptions(options[:])
						state.processAcknowledgment(&segment, now, 0)
						wantLoss := uint64(0)
						if test.lost && (state.controller.usesDeliveryRate() || state.controller.usesLossEvents()) {
							wantLoss = mss
						}
						if state.fastRecovery != test.lost || state.controller.state.LostBytes != wantLoss || state.haveRACKLoss != test.rack || state.duplicateACKs >= tcpDuplicateACKThreshold || state.outstanding[0].state.has(sentTCPSegmentTransmissionLost) != test.lost || state.outstanding[0].lossAlreadyReported() != test.lost {
							t.Fatalf("old ACK %t: recovery/loss/RACK/duplicates = %t/%d/%t/%d", oldACK, state.fastRecovery, state.controller.state.LostBytes, state.haveRACKLoss, state.duplicateACKs)
						}
						state.processAcknowledgment(&segment, now, 0)
						if state.controller.state.LostBytes != wantLoss || state.fastRecovery != test.lost {
							t.Fatalf("old ACK %t: repeated evidence changed loss or recovery", oldACK)
						}
					}
				})
			}
		})
	}
}

func TestTCPRACKPipePreservesOriginalLoss(t *testing.T) {
	const mss = 1000
	outstanding := []sentTCPSegment{{sequence: 1000, end: 2000, state: sentTCPSegmentTransmitted | sentTCPSegmentRACKLost}}
	if newlyLost, replacementLost := markProvenTCPLosses(outstanding, mss, false); !newlyLost || replacementLost || !outstanding[0].state.has(sentTCPSegmentOriginalLost) || outstanding[0].lossAlreadyReported() {
		t.Fatalf("unreported RACK loss = %+v", outstanding[0])
	}
	marked := outstanding[0].state
	if newlyLost, replacementLost := markProvenTCPLosses(outstanding, mss, false); newlyLost || replacementLost || outstanding[0].state != marked {
		t.Fatal("repeated RACK evidence changed loss state before reporting")
	}
	if losses := recordTestTCPLosses(outstanding, mss); losses != mss || sackRecoveryPipe(outstanding, mss) != 0 {
		t.Fatalf("original loss = %d bytes, Pipe %d", losses, sackRecoveryPipe(outstanding, mss))
	}
	for generation := 0; generation < 2; generation++ {
		outstanding[0].advanceTransmissionGeneration()
		outstanding[0].state &^= sentTCPSegmentRACKLost
		outstanding[0].state |= sentTCPSegmentSACKRetried
		if pipe := sackRecoveryPipe(outstanding, mss); pipe != mss {
			t.Fatalf("generation %d Pipe = %d, want %d", generation, pipe, mss)
		}
		if losses := recordTestTCPLosses(outstanding, mss); losses != 0 || sackSegmentLost(outstanding, 0, mss) {
			t.Fatalf("original loss reauthorized replacement: loss %d state %#x", losses, outstanding[0].state)
		}
		outstanding[0].state |= sentTCPSegmentRACKLost
		outstanding[0].state &^= sentTCPSegmentSACKRetried
		if losses := recordTestTCPLosses(outstanding, mss); losses != mss || sackRecoveryPipe(outstanding, mss) != 0 {
			t.Fatalf("generation %d loss = %d, Pipe %d", generation, losses, sackRecoveryPipe(outstanding, mss))
		}
	}
	outstanding[0].advanceTransmissionGeneration()
	outstanding[0].state &^= sentTCPSegmentRACKLost
	outstanding[0].state |= sentTCPSegmentSACKRetried
	split := splitTCPSegments(outstanding, mss/2)
	if len(split) != 2 || !split[0].state.has(sentTCPSegmentOriginalLost) || !split[1].state.has(sentTCPSegmentOriginalLost) || sackRecoveryPipe(split, mss/2) != mss {
		t.Fatalf("split replacement = %+v, Pipe %d", split, sackRecoveryPipe(split, mss/2))
	}
}

func TestTCPRTOTransmissionFlight(t *testing.T) {
	state := tcpEstablishedState{outstanding: []sentTCPSegment{{sequence: 0xfffffff0, end: 0x31, flags: TCPFlagACK | TCPFlagFIN}}}
	for flags := sentTCPSegmentState(0); flags < sentTCPSegmentTransmissionLost<<1; flags++ {
		state.outstanding[0].state = flags
		var copies uint32
		if !flags.has(sentTCPSegmentSACKed) {
			copies = 1
			if flags.has(sentTCPSegmentOriginalLost) {
				copies--
			}
			if flags.has(sentTCPSegmentRetransmitted) && !flags.has(sentTCPSegmentTransmissionLost) {
				copies++
			}
		}
		if got, want := state.rtoTransmissionFlight(), copies*65; got != want {
			t.Fatalf("flags %#x: transmission flight = %d, want %d", flags, got, want)
		}
	}
}

type tcpBatchFlightRecorder struct {
	flights  chan uint32
	timeouts chan struct{}
	window   uint32
}

func (r *tcpBatchFlightRecorder) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventInitialize:
		event.State.CongestionWindow = r.window
	case CongestionEventTimeout:
		select {
		case r.timeouts <- struct{}{}:
		default:
		}
	case CongestionEventPacketRetransmitted:
		if event.State.Phase == CongestionPhaseLoss {
			r.flights <- event.State.BytesInFlight
		}
	}
}

func TestTCPRTOBatchFlightSnapshots(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		for _, fin := range []bool{false, true} {
			t.Run(fmt.Sprintf("blocked-%t/FIN-%t", blocked, fin), func(t *testing.T) {
				const mss, count = 1000, 10
				first := uint32(0xfffffff0)
				local, remote := netip.MustParseAddr("192.0.2.213"), netip.MustParseAddr("192.0.2.214")
				recorder := &tcpBatchFlightRecorder{flights: make(chan uint32, 32), timeouts: make(chan struct{}, 1), window: count*mss + 1}
				factory, err := NewCongestionControlFactory(CongestionControlDefinition{
					Name: "test-rto-batch-flight", Features: CongestionControlFeatureTransmissionEvents,
					New: func(CongestionControlContext) CongestionController { return recorder },
				})
				if err != nil {
					t.Fatal(err)
				}
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1200, TCP: TCPSocketDefaults{CongestionControlFactory: factory}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				c := newTCPConn(stack, "tcp4", tcpKey{local: netip.AddrPortFrom(local, 12345), remote: netip.AddrPortFrom(remote, 80)}, 1200, tcpSocketOptionSet{})
				c.receiveNext, c.peerWindow, c.peerMSS = 200, 65535, mss
				c.peerSACK, c.peerECN, c.writeClosed = true, true, fin
				c.sendBuffer.append(bytes.Repeat([]byte{0x5b}, count*mss))
				stack.mu.Lock()
				stack.tcp[c.key] = c
				stack.stats.activeTCPConnections.Add(1)
				stack.mu.Unlock()
				actorTimer := newOwnedTimer()
				go func() {
					defer stack.removeTCP(c)
					defer close(c.done)
					defer actorTimer.close()
					c.finish(c.established(first, actorTimer, tcpInitialReceive{}))
				}()
				c.wakeActor(tcpActorWakeSend)
				t.Cleanup(func() {
					c.abort(net.ErrClosed)
					select {
					case <-c.done:
					case <-time.After(2 * time.Second):
						t.Error("RTO flight actor did not terminate")
					}
				})
				packets := count
				if fin {
					packets++
				}
				read := func(index int) {
					t.Helper()
					entry, available := waitTestPacketEntry(&stack.outbound, 3*time.Second)
					if !available {
						t.Fatalf("no output for range %d: %+v", index, c.Info())
					}
					packet, ok := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
					if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
						t.Fatalf("invalid TCP output for range %d", index)
					}
					if sequence := binary.BigEndian.Uint32(packet.payload[4:8]); sequence != first+uint32(index*mss) {
						t.Fatalf("range %d sequence = %d, want %d", index, sequence, first+uint32(index*mss))
					}
					header := int(packet.payload[12]>>4) * 4
					if index < count {
						if header < tcpHeaderSize || header > len(packet.payload) || !bytes.Equal(packet.payload[header:], bytes.Repeat([]byte{0x5b}, mss)) {
							t.Fatalf("invalid data for range %d", index)
						}
					} else if packet.payload[13]&TCPFlagFIN == 0 || header != len(packet.payload) {
						t.Fatal("last range is not FIN-only")
					}
				}
				for index := 0; index < packets; index++ {
					read(index)
				}
				var held []uint16
				defer func() {
					for _, slot := range held {
						stack.outbound.releaseReserved(slot)
					}
				}()
				if blocked {
					for {
						slot, ok := stack.outbound.tryReserve()
						if !ok {
							break
						}
						held = append(held, slot)
					}
					select {
					case <-recorder.timeouts:
					case <-time.After(2 * time.Second):
						t.Fatal("blocked output did not enter RTO recovery")
					}
					last := len(held) - 1
					stack.outbound.releaseReserved(held[last])
					held = held[:last]
				}
				read(0)
				select {
				case flight := <-recorder.flights:
					if flight != 0 {
						t.Fatalf("first RTO flight = %d, want 0", flight)
					}
				case <-time.After(time.Second):
					t.Fatal("missing RTO transmission event")
				}
				if blocked {
					for range [3]struct{}{} {
						last := len(held) - 1
						stack.outbound.releaseReserved(held[last])
						held = held[:last]
					}
				}
				time.Sleep(time.Millisecond)
				if err = writeTestPacket(stack, buildTestTCP(remote, local, 80, 12345, 200, first+mss, TCPFlagACK|TCPFlagECE, 65535, nil, nil)); err != nil {
					t.Fatal(err)
				}
				for index := 1; index < packets; index++ {
					read(index)
					select {
					case flight := <-recorder.flights:
						if want := uint32((index - 1) * mss); flight != want {
							t.Fatalf("range %d flight = %d, want %d", index, flight, want)
						}
					case <-time.After(time.Second):
						t.Fatalf("missing transmission event for range %d", index)
					}
				}
			})
		}
	}
}

func TestTCPRTOTransmissionLoss(t *testing.T) {
	const mss = 1000
	for _, test := range []struct {
		name      string
		age, rtt  time.Duration
		flags     sentTCPSegmentState
		pending   bool
		unsetTime bool
		lost      bool
		flight    uint32
		newLosses uint64
	}{
		{name: "aged original", age: time.Second, rtt: 100 * time.Millisecond, lost: true, newLosses: mss},
		{name: "exact RTT", age: 100 * time.Millisecond, rtt: 100 * time.Millisecond, lost: true, newLosses: mss},
		{name: "just before RTT", age: 100*time.Millisecond - time.Nanosecond, rtt: 100 * time.Millisecond, flight: mss},
		{name: "just after RTT", age: 100*time.Millisecond + time.Nanosecond, rtt: 100 * time.Millisecond, lost: true, newLosses: mss},
		{name: "recent original", age: 50 * time.Millisecond, rtt: 100 * time.Millisecond, flight: mss},
		{name: "unknown RTT", age: time.Millisecond, lost: true, newLosses: mss},
		{name: "future queue stamp", age: -time.Nanosecond, flight: mss},
		{name: "cutoff before epoch", age: 2 * time.Second, rtt: 2*time.Second + time.Nanosecond, flight: mss},
		{name: "cutoff at epoch", age: 2 * time.Second, rtt: 2 * time.Second, lost: true, newLosses: mss},
		{name: "cutoff after epoch", age: 2 * time.Second, rtt: 2*time.Second - time.Nanosecond, lost: true, newLosses: mss},
		{name: "unset queue stamp", rtt: 2*time.Second + time.Nanosecond, unsetTime: true, lost: true, newLosses: mss},
		{name: "recent replacement", age: 50 * time.Millisecond, rtt: 100 * time.Millisecond, flags: sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost | sentTCPSegmentSACKRetried, flight: mss},
		{name: "aged replacement", age: time.Second, rtt: 100 * time.Millisecond, flags: sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost | sentTCPSegmentSACKRetried, lost: true, newLosses: mss},
		{name: "recent speculative copy", age: 50 * time.Millisecond, rtt: 100 * time.Millisecond, flags: sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried, flight: 2 * mss},
		{name: "already reported", age: time.Second, flags: sentTCPSegmentOriginalLost | sentTCPSegmentLossReported | sentTCPSegmentTransmissionLost, lost: true},
		{name: "reported generation after undo", age: time.Second, flags: sentTCPSegmentLossReported, lost: true},
		{name: "inferred but unreported", age: time.Second, flags: sentTCPSegmentOriginalLost | sentTCPSegmentTransmissionLost, lost: true, newLosses: mss},
		{name: "SACKed", age: time.Second, flags: sentTCPSegmentSACKed},
		{name: "host queue original", age: time.Second, pending: true, flight: mss},
		{name: "host queue replacement", age: time.Second, pending: true, flags: sentTCPSegmentOriginalLost | sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried, flight: mss},
		{name: "recent original recovery markers", age: 50 * time.Millisecond, rtt: 100 * time.Millisecond, flags: sentTCPSegmentSACKRetried | sentTCPSegmentRACKLost, flight: mss},
		{name: "SACKed recovery markers", age: time.Second, flags: sentTCPSegmentSACKed | sentTCPSegmentSACKRetried | sentTCPSegmentRACKLost},
		{name: "host queue recovery markers", age: time.Second, pending: true, flags: sentTCPSegmentSACKRetried | sentTCPSegmentRACKLost, flight: mss},
		{name: "reported recovery markers", age: time.Second, flags: sentTCPSegmentOriginalLost | sentTCPSegmentLossReported | sentTCPSegmentTransmissionLost | sentTCPSegmentSACKRetried | sentTCPSegmentRACKLost, lost: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, clock := range []struct {
				name     string
				now      time.Time
				recovery bool
			}{
				{name: "wall", now: time.Unix(100, 0)},
				{name: "monotonic", now: time.Now()},
				{name: "wall-in-recovery", now: time.Unix(100, 0), recovery: true},
				{name: "monotonic-in-recovery", now: time.Now(), recovery: true},
			} {
				t.Run(clock.name, func(t *testing.T) {
					now := clock.now
					epoch := now.Add(-2 * time.Second)
					stack := &Stack{timestampEpoch: epoch}
					ticket := testPacketQueueTicketAt(epoch, now.Add(-test.age))
					if test.unsetTime {
						ticket.queuedAt = 0
					}
					if test.pending {
						stack.outbound.initFIFO(1, epoch)
						slot, _ := stack.outbound.tryReserve()
						queued, _ := stack.outbound.enqueueReservedTCP(slot, []byte{1}, false, 1, false)
						ticket.token = queued.token
					}
					state := tcpEstablishedState{
						connection: &TCPConn{stack: stack}, controller: newTCPCongestionController(CongestionControlBBR3),
						peerMSS: mss, peerSACK: true, fastRecovery: clock.recovery,
						sendUnacknowledged: 100, sendNext: 2100, congestionWindow: 10 * mss, slowStartThreshold: 20 * mss,
						rackLatestDelivered: tcpRACKSample{rtt: test.rtt}, rtt: newRTTEstimator(time.Second),
						outstanding: []sentTCPSegment{
							{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Second))},
							{sequence: 1100, end: 2100, state: sentTCPSegmentTransmitted | test.flags, hostQueue: ticket},
						},
					}
					if test.flags.has(sentTCPSegmentSACKed) {
						state.sackedRanges, state.sackedBytes = 1, mss
					}
					state.controller.initialize(CongestionPhaseRecovery, epoch, test.rtt, test.rtt, state.congestionWindow, state.slowStartThreshold, mss, 1)
					if index := state.prepareRetransmission(0, true, false, true, false, 0, now); index != 0 {
						t.Fatalf("RTO target = %d", index)
					}
					segment := &state.outstanding[1]
					if lost := segment.state.has(sentTCPSegmentTransmissionLost); lost != test.lost {
						t.Fatalf("latest-copy loss = %t, state %#x", lost, segment.state)
					}
					if segment.state.has(sentTCPSegmentSACKed) != test.flags.has(sentTCPSegmentSACKed) || segment.state.has(sentTCPSegmentSACKRetried|sentTCPSegmentRACKLost) {
						t.Fatalf("RTO selection state = %#x", segment.state)
					}
					if flight := state.rtoTransmissionFlight(); flight != test.flight {
						t.Fatalf("transmission flight = %d, want %d", flight, test.flight)
					}
					losses := state.controller.state.LostBytes
					if losses != mss+test.newLosses {
						t.Fatalf("lost bytes = %d, want %d", losses, mss+test.newLosses)
					}
					state.prepareRetransmission(0, true, false, true, false, 0, now)
					if state.controller.state.LostBytes != losses {
						t.Fatal("repeated timeout reported the same generations twice")
					}
					state.outstanding[0].advanceTransmissionGeneration()
					state.outstanding[0].hostQueue = testPacketQueueTicketAt(epoch, now)
					if flight := state.rtoTransmissionFlight(); flight != test.flight+mss {
						t.Fatalf("published flight = %d, want %d", flight, test.flight+mss)
					}
					state.prepareRetransmission(0, true, false, true, false, 0, now.Add(time.Second))
					wantLosses := losses + mss
					if !test.lost && !test.pending && !test.flags.has(sentTCPSegmentSACKed) {
						wantLosses += mss
					}
					if state.controller.state.LostBytes != wantLosses {
						t.Fatalf("replacement timeout loss = %d", state.controller.state.LostBytes)
					}
				})
			}
		})
	}
}

func TestTCPRTOAfterSACKReneging(t *testing.T) {
	const mss = 1000
	for _, test := range []struct {
		name    string
		flags   sentTCPSegmentState
		pending bool
	}{
		{name: "recent original"},
		{name: "recent SACKed original", flags: sentTCPSegmentSACKed},
		{name: "recent SACKed replacement", flags: sentTCPSegmentSACKed | sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost},
		{name: "host-owned original", flags: sentTCPSegmentSACKed, pending: true},
		{name: "host-owned replacement", flags: sentTCPSegmentSACKed | sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost, pending: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(100, 0)
			epoch := now.Add(-2 * time.Second)
			stack := &Stack{timestampEpoch: epoch}
			ticket := testPacketQueueTicketAt(epoch, now.Add(-75*time.Millisecond))
			if test.pending {
				stack.outbound.initFIFO(1, epoch)
				slot, _ := stack.outbound.tryReserve()
				queued, _ := stack.outbound.enqueueReservedTCP(slot, []byte{1}, false, 1, false)
				ticket.token = queued.token
			}
			state := tcpEstablishedState{
				connection: &TCPConn{stack: stack}, controller: newTCPCongestionController(CongestionControlBBR3),
				peerMSS: mss, peerSACK: true, peerWindow: 65535,
				sendUnacknowledged: 100, sendNext: 2100,
				congestionWindow: 10 * mss, slowStartThreshold: 20 * mss,
				rtt: newRTTEstimator(time.Second), rackLatestDelivered: tcpRACKSample{rtt: 100 * time.Millisecond},
				outstanding: []sentTCPSegment{
					{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Second))},
					{sequence: 1100, end: 2100, state: sentTCPSegmentTransmitted | test.flags, hostQueue: ticket},
				},
			}
			state.recountSACK()
			state.controller.initialize(CongestionPhaseOpen, epoch, 100*time.Millisecond, 100*time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
			recorder := &bbr3RenegingRecorder{algorithm: state.controller.algorithm.(*bbr3CongestionControl)}
			state.controller.algorithm = recorder
			if index := state.prepareRetransmission(-1, true, false, true, false, 0, now); index != 0 {
				t.Fatalf("reneging RTO target = %d, want 0", index)
			}
			wantFlight, wantLosses := uint32(0), uint64(2*mss)
			if test.pending {
				wantFlight, wantLosses = mss, mss
			}
			if !state.sackRenegingRecovery || state.sackedRanges != 0 || state.sackedBytes != 0 || state.frtoState != tcpFRTOInactive {
				t.Fatal("confirmed reneging retained SACK state or enabled F-RTO")
			}
			if flight := state.rtoTransmissionFlight(); flight != wantFlight || state.controller.state.LostBytes != wantLosses || recorder.validLoss.Load() != 0 || recorder.staleLoss.Load() != wantLosses/mss {
				t.Fatalf("reneging flight/loss/evidence = %d/%d/%d/%d, want %d/%d/0/%d", flight, state.controller.state.LostBytes, recorder.validLoss.Load(), recorder.staleLoss.Load(), wantFlight, wantLosses, wantLosses/mss)
			}
			state.prepareRetransmission(0, true, false, false, false, 0, now)
			if state.controller.state.LostBytes != wantLosses {
				t.Fatal("repeated preparation reported a generation twice")
			}
			state.outstanding[0].advanceTransmissionGeneration()
			state.controller.onRetransmit(mss, mss, now, monotonicStampAt(epoch, now), state.congestionWindow, state.congestionFlight(), wantFlight, 2*mss, state.rtt.srtt, state.slowStartThreshold)
			if snapshot := bbr3DecodePacketState(state.controller.transmissionState()).inflight; snapshot != wantFlight+mss {
				t.Fatalf("reneging replacement snapshot = %d, want %d", snapshot, wantFlight+mss)
			}
			if !test.pending {
				state.outstanding[1].advanceTransmissionGeneration()
				state.outstanding[1].hostQueue = testPacketQueueTicketAt(epoch, now)
			}
			state.prepareRetransmission(0, true, false, true, false, 0, now.Add(time.Millisecond))
			if flight := state.rtoTransmissionFlight(); flight != mss {
				t.Fatalf("ordinary RTO during reneging recovery flight = %d, want %d", flight, mss)
			}
		})
	}
}

func TestTCPRTOFlightSurvivesScoreboardChanges(t *testing.T) {
	state := tcpEstablishedState{outstanding: []sentTCPSegment{{
		sequence: 0xfffffff0, end: 0x31, flags: TCPFlagACK | TCPFlagFIN,
		state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost | sentTCPSegmentSACKRetried,
	}}}
	if flight := state.rtoTransmissionFlight(); flight != 65 {
		t.Fatalf("FIN/wrapped live replacement flight = %d, want 65", flight)
	}
	state.outstanding = splitTCPSegments(state.outstanding, 16)
	if flight := state.rtoTransmissionFlight(); len(state.outstanding) != 4 || flight != 65 {
		t.Fatalf("PMTU split flight = %d, ranges %d", flight, len(state.outstanding))
	}
	trimAcknowledgedTCPSegment(&state.outstanding[0], 0xfffffff8)
	if flight := state.rtoTransmissionFlight(); flight != 57 {
		t.Fatalf("partial-ACK flight = %d, want 57", flight)
	}
	state.outstanding[1].state |= sentTCPSegmentSACKed
	if flight := state.rtoTransmissionFlight(); flight != 41 {
		t.Fatalf("SACK flight = %d, want 41", flight)
	}
	state.outstanding[1].state &^= sentTCPSegmentSACKed
	state.outstanding[1].markLost(true)
	if bytes := recordTCPSegmentLoss(&state.outstanding[1]); bytes != 16 || state.rtoTransmissionFlight() != 41 {
		t.Fatalf("reneged-copy loss = %d, flight %d", bytes, state.rtoTransmissionFlight())
	}
	state.outstanding[1].advanceTransmissionGeneration()
	if flight := state.rtoTransmissionFlight(); flight != 57 {
		t.Fatalf("new PMTU replacement flight = %d, want 57", flight)
	}
	state.outstanding = []sentTCPSegment{{sequence: 10, end: 11, flags: TCPFlagFIN, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentOriginalLost}}
	if flight := state.rtoTransmissionFlight(); flight != 1 {
		t.Fatalf("FIN-only flight = %d, want 1", flight)
	}
	state.outstanding = nil
	if flight := state.rtoTransmissionFlight(); flight != 0 {
		t.Fatalf("empty flight = %d", flight)
	}
}

func TestTCPRTORetainsRecentReplacementAfterSACK(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	epoch := now.Add(-time.Second)
	state := tcpEstablishedState{
		connection: &TCPConn{stack: &Stack{timestampEpoch: epoch}},
		controller: newTCPCongestionController(CongestionControlBBR3),
		peerMSS:    mss, peerSACK: true, sendNext: 5 * mss,
		congestionWindow: 10 * mss, slowStartThreshold: 20 * mss, rtt: newRTTEstimator(time.Second),
		rackLatestDelivered: tcpRACKSample{rtt: 100 * time.Millisecond},
		outstanding: []sentTCPSegment{
			{sequence: 0, end: mss, state: sentTCPSegmentTransmitted},
			{sequence: mss, end: 2 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted | sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-50*time.Millisecond))},
			{sequence: 2 * mss, end: 3 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
			{sequence: 3 * mss, end: 4 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
			{sequence: 4 * mss, end: 5 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		},
		sackedRanges: 3, sackedBytes: 3 * mss,
	}
	state.controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
	state.prepareRetransmission(0, true, false, true, false, 0, now)
	if state.outstanding[1].state.has(sentTCPSegmentSACKRetried) || state.rtoTransmissionFlight() != 2*mss {
		t.Fatal("RTO did not retain both recent speculative copies")
	}
	if lost := recordTestTCPLosses(state.outstanding, mss); lost != 0 || state.rtoTransmissionFlight() != mss || state.outstanding[1].state.has(sentTCPSegmentTransmissionLost) {
		t.Fatalf("SACK-only loss = %d, latest flight %d, state %#x", lost, state.rtoTransmissionFlight(), state.outstanding[1].state)
	}
	state.outstanding[1].state |= sentTCPSegmentRACKLost
	if lost := recordTestTCPLosses(state.outstanding, mss); lost != mss || state.rtoTransmissionFlight() != 0 {
		t.Fatalf("RACK loss = %d, flight %d", lost, state.rtoTransmissionFlight())
	}
}

func TestTCPRTOFlightUndoAndControllerChange(t *testing.T) {
	const mss = 1000
	now := time.Now()
	state := tcpEstablishedState{
		connection: &TCPConn{stack: &Stack{timestampEpoch: now.Add(-time.Second)}},
		controller: newTCPCongestionController(CongestionControlBBR3),
		peerMSS:    mss, congestionWindow: 10 * mss, slowStartThreshold: 20 * mss,
		sendUnacknowledged: 100, sendNext: 2100, rtt: newRTTEstimator(time.Second),
		outstanding: []sentTCPSegment{
			{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted},
			{sequence: 1100, end: 2100, state: sentTCPSegmentTransmitted},
		},
	}
	state.controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
	state.prepareRetransmission(0, true, false, true, false, 0, now)
	state.outstanding[0].advanceTransmissionGeneration()
	state.outstanding[0].state |= sentTCPSegmentSACKRetried
	losses := state.controller.state.LostBytes
	if !state.restoreSpuriousRecovery(now.Add(time.Millisecond), 0) {
		t.Fatal("timeout was not undone")
	}
	if flight := state.rtoTransmissionFlight(); flight != 3*mss || state.controller.state.LostBytes != losses || state.outstanding[0].state.has(sentTCPSegmentTransmissionLost) {
		t.Fatalf("undo flight = %d, lost bytes %d/%d", flight, state.controller.state.LostBytes, losses)
	}
	state.prepareRetransmission(0, true, false, true, false, 0, now.Add(time.Second))
	state.outstanding[0].advanceTransmissionGeneration()
	if flight := state.rtoTransmissionFlight(); flight != mss {
		t.Fatalf("RTO replacement flight = %d", flight)
	}
	flags := [2]sentTCPSegmentState{state.outstanding[0].state, state.outstanding[1].state}
	factory, _ := registeredCongestionControlFactory(CongestionControlReno)
	state.changeCongestionController(factory, 0)
	if state.outstanding[0].state != flags[0] || state.outstanding[1].state != flags[1] || state.rtoTransmissionFlight() != mss {
		t.Fatal("controller change altered live-copy membership")
	}
}

func TestTCPSACKReplacementRetainsOriginalLoss(t *testing.T) {
	const mss = 1000
	for _, test := range []struct {
		name     string
		sizes    []uint32
		original bool
	}{
		{name: "below threshold", sizes: []uint32{mss}, original: false},
		{name: "range threshold", sizes: []uint32{100, 100, 100}, original: true},
		{name: "byte threshold", sizes: []uint32{mss, mss + 1}, original: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			outstanding := []sentTCPSegment{{sequence: 0, end: mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKRetried}}
			outstanding[0].advanceTransmissionGeneration()
			sequence := uint32(mss)
			for _, size := range test.sizes {
				outstanding = append(outstanding, sentTCPSegment{sequence: sequence, end: sequence + size, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed})
				sequence += size
			}
			if losses := recordTestTCPLosses(outstanding, mss); losses != 0 || outstanding[0].lossAlreadyReported() || outstanding[0].state.has(sentTCPSegmentOriginalLost) != test.original {
				t.Fatalf("replacement loss = %d, original %t, reported %t", losses, outstanding[0].state.has(sentTCPSegmentOriginalLost), outstanding[0].lossAlreadyReported())
			}
			wantPipe := uint32(2 * mss)
			if test.original {
				wantPipe = mss
			}
			if pipe := sackRecoveryPipe(outstanding, mss); pipe != wantPipe {
				t.Fatalf("replacement Pipe = %d, want %d", pipe, wantPipe)
			}
			outstanding[0].state |= sentTCPSegmentRACKLost
			outstanding[0].state &^= sentTCPSegmentSACKRetried
			if losses := recordTestTCPLosses(outstanding, mss); losses != mss || sackRecoveryPipe(outstanding, mss) != 0 {
				t.Fatalf("RACK replacement loss = %d, Pipe %d", losses, sackRecoveryPipe(outstanding, mss))
			}
			if losses := recordTestTCPLosses(outstanding, mss); losses != 0 {
				t.Fatalf("replacement loss reported twice: %d", losses)
			}
		})
	}
}

func TestTCPEifelPartialACKDoesNotReportSpuriousLoss(t *testing.T) {
	for _, test := range []struct {
		name string
		echo uint32
		ecn  bool
		frto bool
		sack bool
		undo bool
		loss uint64
	}{
		{name: "original timestamp", echo: 100, frto: true, undo: true},
		{name: "retransmission timestamp", echo: 1200, loss: 1000},
		{name: "F-RTO probe allowance", echo: 1200, frto: true},
		{name: "ECN feedback", echo: 100, ecn: true, frto: true, loss: 1000},
		{name: "fresh SACK loss after undo", echo: 100, sack: true, undo: true, loss: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := time.Now().Add(-2 * time.Second)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: start}
			connection.sendBuffer.append(make([]byte, 2000))
			connection.peerTimestamp, connection.peerECN = true, test.ecn
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(CongestionControlBBR3),
				peerMSS: 1000, peerWindow: 65535, sendUnacknowledged: 1000, sendNext: 3000,
				congestionWindow: 10000, slowStartThreshold: 10000,
				rtt:                 rttEstimator{initialized: true, srtt: 100 * time.Millisecond, minimum: 100 * time.Millisecond, rto: time.Second},
				rackLatestDelivered: tcpRACKSample{rtt: 100 * time.Millisecond},
				outstanding:         []sentTCPSegment{{sequence: 1000, end: 2000}, {sequence: 2000, end: 3000}},
			}
			if test.sack {
				state.peerSACK, state.sendNext = true, 6000
				connection.peerSACK = true
				connection.sendBuffer.append(make([]byte, 3000))
				for sequence := uint32(3000); sequence < state.sendNext; sequence += 1000 {
					state.outstanding = append(state.outstanding, sentTCPSegment{sequence: sequence, end: sequence + 1000})
				}
			}
			state.rebaseOutstanding()
			state.controller.initialize(CongestionPhaseOpen, start, state.rtt.srtt, state.rtt.minimum, 10000, 10000, 1000, 1)
			for index := range state.outstanding {
				sentAt := start.Add(time.Duration(100+index*50) * time.Millisecond)
				if index != 0 {
					sentAt = start.Add(time.Duration(1100+index*10) * time.Millisecond)
				}
				segment := &state.outstanding[index]
				segment.state = sentTCPSegmentTransmitted
				segment.hostQueue.queuedAt = monotonicStampAt(start, sentAt)
				segment.timestamp = uint32(100 + index*50)
				segment.delivery, _ = state.controller.onDataSend(1000, 1000, sentAt, segment.hostQueue.queuedAt, uint32(index*1000), 10000, uint32(index*1000), uint32(index*1000), state.rtt.srtt, 10000)
				segment.congestionPacketState = state.controller.transmissionState()
			}
			retransmittedAt := start.Add(1200 * time.Millisecond)
			if index := state.prepareRetransmission(0, true, false, true, false, 0, retransmittedAt); index != 0 {
				t.Fatalf("RTO selected range %d, want 0", index)
			}
			beforeLost := state.controller.state.LostBytes
			state.undo.recordRetransmission(1000, 2000, 1200, false)
			transmissionFlight := state.rtoTransmissionFlight()
			state.outstanding[0].advanceTransmissionGeneration()
			state.outstanding[0].state |= sentTCPSegmentSACKRetried
			state.outstanding[0].timestamp = 1200
			state.outstanding[0].hostQueue.queuedAt = monotonicStampAt(start, retransmittedAt)
			state.outstanding[0].delivery = state.controller.onRetransmit(1000, 1000, retransmittedAt, state.outstanding[0].hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), transmissionFlight, state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
			state.outstanding[0].congestionPacketState = state.controller.transmissionState()
			state.frtoState = tcpFRTOInactive
			if test.frto {
				state.frtoState = tcpFRTOAwaitingACK
			}
			flags := byte(TCPFlagACK)
			if test.ecn {
				flags |= TCPFlagECE
			}
			segment := tcpSegment{sequence: 100, acknowledgement: 2000, flags: flags, window: 65535}
			if test.sack {
				var options [10]byte
				options[0], options[1] = TCPHeaderOptionSACK, 10
				binary.BigEndian.PutUint32(options[2:6], 3000)
				binary.BigEndian.PutUint32(options[6:10], 6000)
				segment.setOptions(options[:])
			}
			state.processAcknowledgment(&segment, start.Add(1300*time.Millisecond), test.echo)
			if state.rtoRecovery == test.undo || (state.undo.spuriousUndos != 0) != test.undo || state.controller.state.LostBytes != beforeLost+test.loss || state.deliverySample.losses != test.loss || state.outstanding[0].lossAlreadyReported() != (test.loss != 0) {
				t.Fatalf("partial ACK = recovery %t undos %d losses %d/%d sample %d state %#x", state.rtoRecovery, state.undo.spuriousUndos, beforeLost, state.controller.state.LostBytes, state.deliverySample.losses, state.outstanding[0].state)
			}
			if test.undo && !test.sack && state.outstanding[0].state.has(sentTCPSegmentOriginalLost|sentTCPSegmentRACKLost|sentTCPSegmentTransmissionLost) {
				t.Fatalf("spurious RTO retained loss marks: %#x", state.outstanding[0].state)
			}
		})
	}
}

func TestTCPPRRDeliveryAndSendCount(t *testing.T) {
	if window := prrCongestionWindow(800, 500, 1000, 100, 0, 100, true, false, 100); window != 850 {
		t.Fatalf("PRR proportional window = %d, want 850", window)
	}
	if window := prrCongestionWindow(300, 500, 1000, 100, 0, 100, true, false, 100); window != 500 {
		t.Fatalf("PRR slow-start reduction window = %d, want 500", window)
	}
	if window := prrCongestionWindow(300, 500, 1000, 100, 0, 100, true, true, 100); window != 400 {
		t.Fatalf("PRR packet-conservation window with new loss = %d, want 400", window)
	}
	if window := prrCongestionWindow(500, 500, 1000, 100, 0, 100, false, true, 100); window != 600 {
		t.Fatalf("PRR forced entry window = %d, want 600", window)
	}
	if window := prrCongestionWindow(500, 500, 1000, 100, 100, 100, false, true, 100); window != 500 {
		t.Fatalf("PRR repeated forced entry window = %d, want 500", window)
	}
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		controller := newTCPCongestionController(algorithm)
		controller.initialize(CongestionPhaseRecovery, time.Unix(100, 0), time.Millisecond, time.Millisecond, 6000, 8000, 1000, 1)
		want := uint32(4100)
		if algorithm == CongestionControlBBR || algorithm == CongestionControlBBR3 {
			want = 6000
		}
		if window := controller.applyPRRWindow(time.Unix(100, 0), 6000, 4100, 0); window != want {
			t.Fatalf("%s PRR window = %d, want %d", algorithm, window, want)
		}
	}
}

func TestTCPPRRCumulativeDelivery(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, test := range []struct {
			name      string
			ack       uint32
			sacked    []int
			withSACK  bool
			delivered uint64
		}{
			{name: "complete ranges", ack: 300, delivered: 200},
			{name: "partial range", ack: 350, delivered: 250},
			{name: "earlier SACK", ack: 350, sacked: []int{0}, delivered: 150},
			{name: "partial earlier SACK", ack: 350, sacked: []int{2}, delivered: 200},
			{name: "only earlier SACK", ack: 300, sacked: []int{0, 1}},
			{name: "cumulative and SACK", ack: 350, sacked: []int{0}, withSACK: true, delivered: 250},
		} {
			t.Run(algorithm+"/"+test.name, func(t *testing.T) {
				now := time.Unix(100, 0)
				epoch := now.Add(-time.Second)
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{timestampEpoch: epoch}
				state := tcpEstablishedState{
					connection: connection, controller: newTCPCongestionController(algorithm),
					peerMSS: 100, peerSACK: true, peerWindow: 65535,
					sendUnacknowledged: 100, sendNext: 500, fastRecovery: true, recoveryPoint: 500,
					congestionWindow: 400, slowStartThreshold: 400, prrPriorFlight: 400,
					rtt: newRTTEstimator(time.Second), outstanding: make([]sentTCPSegment, 4),
				}
				for index := range state.outstanding {
					state.outstanding[index] = sentTCPSegment{
						sequence: uint32(100 + 100*index), end: uint32(200 + 100*index),
						state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Millisecond)),
					}
				}
				for _, index := range test.sacked {
					state.outstanding[index].state |= sentTCPSegmentSACKed
					state.sackedRanges++
					state.sackedBytes += 100
				}
				state.controller.initialize(CongestionPhaseRecovery, epoch, time.Millisecond, time.Millisecond, 400, 400, 100, 1)
				state.rebaseOutstanding()
				segment := tcpSegment{acknowledgement: test.ack, flags: TCPFlagACK, window: 65535}
				if test.withSACK {
					var options [10]byte
					options[0], options[1] = TCPHeaderOptionSACK, 10
					binary.BigEndian.PutUint32(options[2:6], 400)
					binary.BigEndian.PutUint32(options[6:10], 500)
					segment.setOptions(options[:])
				}
				state.processAcknowledgment(&segment, now, 0)
				if !state.fastRecovery || state.prrDelivered != test.delivered || state.sendUnacknowledged != test.ack || state.outstanding[0].sequence != test.ack {
					t.Fatalf("cumulative ACK: recovery:%t delivered:%d SND.UNA:%d first:%d, want true/%d/%d/%d", state.fastRecovery, state.prrDelivered, state.sendUnacknowledged, state.outstanding[0].sequence, test.delivered, test.ack, test.ack)
				}
				state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0)
				if state.prrDelivered != test.delivered {
					t.Fatalf("repeated ACK credited delivery twice: %d, want %d", state.prrDelivered, test.delivered)
				}
			})
		}
	}
}

func TestTCPPRREntryRetransmissionReadiness(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(algorithm+"/no delivery", func(t *testing.T) {
			const mss = 1000
			now := time.Unix(100, 0)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: now.Add(-time.Second)}
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(algorithm),
				peerSACK: true, peerMSS: mss, peerWindow: 65535,
				sendUnacknowledged: 100, sendNext: 3100,
				congestionWindow: 6000, slowStartThreshold: 20000,
				sackedRanges: 1, sackedBytes: mss, rtt: newRTTEstimator(time.Second),
				outstanding: []sentTCPSegment{
					{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted | sentTCPSegmentRACKLost},
					{sequence: 1100, end: 2100, state: sentTCPSegmentTransmitted | sentTCPSegmentRACKLost},
					{sequence: 2100, end: 3100, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
				},
			}
			state.controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
			if index := state.prepareRetransmission(0, false, false, true, false, 0, now); index != 0 {
				t.Fatalf("timer recovery target = %d, want 0", index)
			}
			if !state.fastRecovery || state.prrPriorFlight != 2*mss || state.prrDelivered != 0 || state.prrOut != 0 || state.congestionWindow != 0 {
				t.Fatalf("timer entry = active:%t flight:%d delivered:%d sent:%d window:%d", state.fastRecovery, state.prrPriorFlight, state.prrDelivered, state.prrOut, state.congestionWindow)
			}
			if !state.recoveryOutputReady() || sackRecoveryCanSend(true, 0, mss, state.congestionWindow) {
				t.Fatal("timer entry must authorize only its retransmission, not new data")
			}
			state.outstanding[0].advanceTransmissionGeneration()
			state.outstanding[0].state.set(sentTCPSegmentRACKLost, false)
			state.outstanding[0].state.set(sentTCPSegmentSACKRetried, true)
			state.prrOut += mss
			if firstUnretriedLoss(state.outstanding, mss) != 1 || state.recoveryOutputReady() || state.canRetransmitRecovery(sackRecoveryPipe(state.outstanding, mss), mss) {
				t.Fatal("first publication authorized another loss without delivery credit")
			}
		})
	}
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		t.Run(algorithm, func(t *testing.T) {
			state := tcpEstablishedState{
				controller: newTCPCongestionController(algorithm), peerSACK: true,
				peerMSS: 1000, peerWindow: 65535, fastRecovery: true,
				outstanding: []sentTCPSegment{{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted | sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost | sentTCPSegmentTransmissionLost}},
			}
			want := algorithm == CongestionControlReno || algorithm == CongestionControlCUBIC
			if ready := state.recoveryOutputReady(); ready != want {
				t.Fatalf("entry output readiness = %t, want %t", ready, want)
			}
			if sackRecoveryCanSend(true, 0, 1000, 0) {
				t.Fatal("ordinary new data acquired the entry-retransmission exemption")
			}
			state.prrOut = 1000
			if state.recoveryOutputReady() || state.canRetransmitRecovery(0, 1000) {
				t.Fatal("successful entry retransmission did not consume its exemption")
			}
		})
	}
}

func TestTCPLateDSACKUndoPreservesProbeRTTWindow(t *testing.T) {
	for _, algorithm := range []string{CongestionControlBBR, CongestionControlBBR3} {
		for _, test := range []struct {
			name        string
			ack         uint32
			outstanding bool
		}{
			{name: "empty flight", ack: 5000},
			{name: "old ACK", ack: 4000},
			{name: "active flight", ack: 5000, outstanding: true},
			{name: "new delivery", ack: 6000, outstanding: true},
		} {
			t.Run(algorithm+"/"+test.name, func(t *testing.T) {
				const mss = 1000
				now := time.Unix(100, 0)
				epoch := now.Add(-time.Second)
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{timestampEpoch: epoch}
				state := tcpEstablishedState{
					connection: connection, controller: newTCPCongestionController(algorithm),
					peerMSS: mss, peerSACK: true, peerWindow: 65535,
					sendUnacknowledged: 5000, sendNext: 5000, bytesAcknowledged: 5000,
					congestionWindow: 4000, slowStartThreshold: 20000,
					rtt: newRTTEstimator(time.Second), undo: new(tcpRecoveryUndo),
				}
				state.controller.initialize(CongestionPhaseOpen, epoch, 10*time.Millisecond, 20*time.Millisecond, 20000, 20000, mss, 1)
				state.undo.begin(false, 4000, 20000, 20000, 10000, &state.controller, state.rtt, now.Add(-time.Second))
				state.undo.recordRetransmission(1000, 2000, 10, false)
				state.recordRetransmission(1000, 2000)
				if test.outstanding {
					state.sendNext = 6000
					state.outstanding = []sentTCPSegment{{sequence: 5000, end: 6000, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Millisecond))}}
					state.rebaseOutstanding()
				}
				cap := uint32(4000)
				switch model := state.controller.algorithm.(type) {
				case *bbrCongestionControl:
					model.mode, model.priorWindow = bbrProbeRTT, 20000
					model.minimumRTT, model.bandwidth = 10*time.Millisecond, 1000000
					model.minimumRTTStamp = now
				case *bbr3CongestionControl:
					model.mode, model.priorWindow = bbrProbeRTT, 20000
					model.minimumRTT, model.bandwidthHigh[1] = 10*time.Millisecond, 1000000
					model.minimumRTTStamp, model.probeRTTStamp = now, now
					cap = 5000
				}
				var options [10]byte
				options[0], options[1] = TCPHeaderOptionSACK, 10
				binary.BigEndian.PutUint32(options[2:6], 1000)
				binary.BigEndian.PutUint32(options[6:10], 2000)
				segment := tcpSegment{acknowledgement: test.ack, flags: TCPFlagACK, window: 65535}
				segment.setOptions(options[:])
				state.processAcknowledgment(&segment, now, 0)
				if state.undo.spuriousUndos != 1 || state.congestionWindow > cap {
					t.Fatalf("DSACK undo = count:%d window:%d, cap:%d", state.undo.spuriousUndos, state.congestionWindow, cap)
				}
				switch model := state.controller.algorithm.(type) {
				case *bbrCongestionControl:
					if model.mode != bbrProbeRTT || model.priorWindow != 20000 {
						t.Fatalf("undo changed ProbeRTT mode/prior window: %v/%d", model.mode, model.priorWindow)
					}
					model.probeDone, model.probeRound = now, true
					window := model.updateMinimumRTT(state.congestionWindow, &tcpDeliveryRateSample{ackTime: now.Add(time.Second)}, mss)
					if model.mode == bbrProbeRTT || window < 20000 {
						t.Fatalf("ProbeRTT exit lost the saved window: %v/%d", model.mode, window)
					}
				case *bbr3CongestionControl:
					if model.mode != bbrProbeRTT || model.priorWindow != 20000 {
						t.Fatalf("undo changed ProbeRTT mode/prior window: %v/%d", model.mode, model.priorWindow)
					}
					model.probeDone, model.probeRound = now, true
					window := model.updateMinimumRTT(state.congestionWindow, &tcpDeliveryRateSample{ackTime: now.Add(time.Second)}, mss)
					if model.mode == bbrProbeRTT || window < 20000 {
						t.Fatalf("ProbeRTT exit lost the saved window: %v/%d", model.mode, window)
					}
				}
			})
		}
	}
}

func TestTCPBBR3LateDSACKUndoPreservesCruiseWindow(t *testing.T) {
	for _, test := range []struct {
		name        string
		ack         uint32
		outstanding bool
		wantWindow  uint32
	}{
		{name: "empty flight", ack: 5000, wantWindow: 17032},
		{name: "empty flight old ACK", ack: 4000, wantWindow: 17032},
		{name: "active flight old ACK", ack: 4000, outstanding: true, wantWindow: 17032},
		{name: "active flight current ACK", ack: 5000, outstanding: true, wantWindow: 17032},
		{name: "new delivery", ack: 6000, outstanding: true, wantWindow: 6000},
	} {
		t.Run(test.name, func(t *testing.T) {
			const mss = 1000
			now := time.Unix(100, 0)
			epoch := now.Add(-time.Second)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(CongestionControlBBR3),
				peerMSS: mss, peerSACK: true, peerWindow: 65535,
				sendUnacknowledged: 5000, sendNext: 5000, bytesAcknowledged: 5000,
				congestionWindow: 4000, slowStartThreshold: 20000,
				rtt: newRTTEstimator(time.Second), undo: new(tcpRecoveryUndo),
			}
			state.controller.initialize(CongestionPhaseOpen, epoch, 10*time.Millisecond, 20*time.Millisecond, 20000, 20000, mss, 1)
			model := state.controller.algorithm.(*bbr3CongestionControl)
			model.mode, model.probePhase = bbrProbeBandwidth, bbr3ProbeDown
			model.inflightHigh, model.fullBandwidthReached = 20000, true
			model.minimumRTT, model.bandwidthHigh[1] = 10*time.Millisecond, 1000000
			model.minimumRTTStamp, model.probeRTTStamp = now, now
			state.undo.begin(false, 4000, 20000, 20000, 10000, &state.controller, state.rtt, epoch)
			state.undo.recordRetransmission(1000, 2000, 10, false)
			state.recordRetransmission(1000, 2000)
			model.inflightHigh = 12000
			model.probeStarted, model.probeWait = now, time.Second
			model.enterProbePhase(bbr3ProbeCruise, now)
			if test.outstanding {
				state.sendNext = 6000
				state.outstanding = []sentTCPSegment{{sequence: 5000, end: 6000, state: sentTCPSegmentTransmitted, hostQueue: testPacketQueueTicketAt(epoch, now.Add(-time.Millisecond))}}
				state.rebaseOutstanding()
			}
			var options [10]byte
			options[0], options[1] = TCPHeaderOptionSACK, 10
			binary.BigEndian.PutUint32(options[2:6], 1000)
			binary.BigEndian.PutUint32(options[6:10], 2000)
			segment := tcpSegment{acknowledgement: test.ack, flags: TCPFlagACK, window: 65535}
			segment.setOptions(options[:])
			state.processAcknowledgment(&segment, now, 0)
			if state.undo.spuriousUndos != 1 || state.undo.active || state.fastRecovery || state.rtoRecovery || state.congestionWindow != test.wantWindow {
				t.Fatalf("DSACK undo = count %d active %t fast %t RTO %t window %d; want window %d", state.undo.spuriousUndos, state.undo.active, state.fastRecovery, state.rtoRecovery, state.congestionWindow, test.wantWindow)
			}
			if model.mode != bbrProbeBandwidth || model.probePhase != bbr3ProbeCruise || model.inflightHigh != 20000 || model.inflightLow != 0 || model.priorWindow != 20000 || model.undoBounds {
				t.Fatalf("DSACK model = %s/%s high %d low %d prior %d checkpoint %t", model.mode, model.probePhase, model.inflightHigh, model.inflightLow, model.priorWindow, model.undoBounds)
			}
		})
	}
}

func TestTCPPRRRecoveryEntryCredit(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC} {
		for _, test := range []struct {
			name            string
			ack             uint32
			priorSACK       bool
			limitedTransmit bool
			lostReplacement bool
			wantDelivery    uint64
			wantPriorFlight uint32
		}{
			{name: "SACK", wantDelivery: 6000, wantPriorFlight: 10000},
			{name: "cumulative and SACK", ack: 1000, wantDelivery: 7000, wantPriorFlight: 10000},
			{name: "earlier SACK", priorSACK: true, wantDelivery: 4000, wantPriorFlight: 8000},
			{name: "Limited Transmit", limitedTransmit: true, wantDelivery: 6000, wantPriorFlight: 10000},
			{name: "lost replacement", lostReplacement: true, wantDelivery: 6000, wantPriorFlight: 10000},
		} {
			t.Run(algorithm+"/"+test.name, func(t *testing.T) {
				const mss = 1000
				now := time.Unix(100, 0)
				epoch := now.Add(-time.Second)
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{timestampEpoch: epoch}
				state := tcpEstablishedState{
					connection: connection, controller: newTCPCongestionController(algorithm),
					peerMSS: mss, peerSACK: true, peerWindow: 65535,
					sendNext: 10000, congestionWindow: 10000, slowStartThreshold: 20000,
					rtt: newRTTEstimator(time.Second), outstanding: make([]sentTCPSegment, 10),
				}
				for i := range state.outstanding {
					state.outstanding[i] = sentTCPSegment{
						sequence: uint32(i * mss), end: uint32((i + 1) * mss),
						state:     sentTCPSegmentTransmitted,
						hostQueue: testPacketQueueTicketAt(epoch, now.Add(-500*time.Millisecond)),
					}
				}
				if test.priorSACK {
					state.outstanding[6].state |= sentTCPSegmentSACKed
					state.outstanding[7].state |= sentTCPSegmentSACKed
					state.sackedRanges, state.sackedBytes = 2, 2000
				}
				if test.limitedTransmit {
					state.outstanding[8].state |= sentTCPSegmentLimited
					state.outstanding[9].state |= sentTCPSegmentLimited
					state.limitedTransmitActive = true
				}
				phase := CongestionPhaseOpen
				if test.lostReplacement {
					state.fastRecovery, state.recoveryPoint = true, state.sendNext
					state.prrPriorFlight, state.prrDelivered, state.prrOut = 12000, 2000, 1000
					state.outstanding[0].advanceTransmissionGeneration()
					state.outstanding[0].state |= sentTCPSegmentSACKRetried
					phase = CongestionPhaseRecovery
				}
				state.controller.initialize(phase, epoch, 10*time.Millisecond, 20*time.Millisecond, 10000, 20000, mss, 1)
				state.rebaseOutstanding()
				var options [10]byte
				options[0], options[1] = TCPHeaderOptionSACK, 10
				binary.BigEndian.PutUint32(options[2:6], 2000)
				binary.BigEndian.PutUint32(options[6:10], 8000)
				segment := tcpSegment{acknowledgement: test.ack, flags: TCPFlagACK, window: 65535}
				segment.setOptions(options[:])
				state.processAcknowledgment(&segment, now, 0)
				if !state.fastRecovery || state.prrDelivered != test.wantDelivery || state.prrOut != 0 || state.prrPriorFlight != test.wantPriorFlight {
					t.Fatalf("entry PRR = active:%t delivered:%d sent:%d flight:%d, want true/%d/0/%d", state.fastRecovery, state.prrDelivered, state.prrOut, state.prrPriorFlight, test.wantDelivery, test.wantPriorFlight)
				}
				window := state.congestionWindow
				state.processAcknowledgment(&segment, now.Add(time.Millisecond), 0)
				if state.prrDelivered != test.wantDelivery || state.prrOut != 0 || state.prrPriorFlight != test.wantPriorFlight || state.congestionWindow != window {
					t.Fatal("repeated SACK changed the PRR episode or granted more output")
				}
				segment = tcpSegment{acknowledgement: state.sendNext, flags: TCPFlagACK, window: 65535}
				state.processAcknowledgment(&segment, now.Add(2*time.Millisecond), 0)
				if state.fastRecovery || state.prrPriorFlight != 0 || state.prrDelivered != 0 || state.prrOut != 0 {
					t.Fatal("the concluding ACK retained or replenished PRR credit")
				}
			})
		}
	}
}

func TestTCPPRRFirstRetransmissionPreservesCredit(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	if err := connection.SetCongestionControl(CongestionControlCUBIC); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	payload := bytes.Repeat([]byte{0x5b}, 10*before.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	segments := make([][]byte, 0, 10)
	for len(segments) < 10 {
		entry, ok := waitTestPacketEntry(&stack.outbound, time.Second)
		if !ok {
			t.Fatalf("initial flight contains %d/10 packets", len(segments))
		}
		segments = append(segments, consumeTestPacket(&stack.outbound, entry))
	}
	held := make([]uint16, 0, cap(stack.outbound.free))
	defer func() {
		for _, slot := range held {
			stack.outbound.releaseReserved(slot)
		}
	}()
	for {
		slot, ok := stack.outbound.tryReserve()
		if !ok {
			break
		}
		held = append(held, slot)
	}
	for _, wire := range segments[2:8] {
		if err := link.handleOutboundPacket(wire); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	var blocked TCPConnInfo
	for {
		blocked = connection.Info()
		if blocked.InboundQueueBytes == 0 && blocked.FastRecovery {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SACK processing did not enter recovery: %+v", blocked)
		}
		runtime.Gosched()
	}
	if blocked.Retransmissions != before.Retransmissions {
		t.Fatal("blocked recovery published a retransmission")
	}
	last := len(held) - 1
	stack.outbound.releaseReserved(held[last])
	held = held[:last]
	for i := 0; i < 2; i++ {
		entry, ok := waitTestPacketEntry(&stack.outbound, time.Second)
		if !ok {
			t.Fatalf("retransmission %d lost the remaining entry-ACK credit", i+1)
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		packet, ok := parseIPPacket(wire, false)
		original, _ := parseIPPacket(segments[i], false)
		if !ok || packet.protocol != ProtocolTCP || !bytes.Equal(packet.payload[4:8], original.payload[4:8]) {
			t.Fatalf("retransmission %d does not fill the expected hole: %x", i+1, wire)
		}
	}
	after := connection.Info()
	if after.CongestionWindow != blocked.CongestionWindow || after.Retransmissions != before.Retransmissions+2 {
		t.Fatalf("first sends changed the grant: before %+v, after %+v", blocked, after)
	}
}

func TestTCPPRRTracksNewLoss(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(algorithm, func(t *testing.T) {
			for _, test := range []struct {
				name          string
				deliverSecond bool
				alreadyLost   bool
				speculative   bool
				wantWindow    uint32
			}{
				{name: "unchanged loss count", wantWindow: 4100},
				{name: "decreasing loss count", deliverSecond: true, wantWindow: 4100},
				{name: "no new loss", alreadyLost: true, wantWindow: 5100},
				{name: "speculative replacement", speculative: true, wantWindow: 5100},
				{name: "known original loss", speculative: true, alreadyLost: true, wantWindow: 6100},
			} {
				t.Run(test.name, func(t *testing.T) {
					const mss = 1000
					now := time.Unix(100, 0)
					epoch := now.Add(-time.Second)
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: epoch}
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(algorithm),
						peerMSS: mss, peerSACK: true, peerWindow: 40_000,
						sendNext: 5100, recoveryPoint: 5100, fastRecovery: true,
						congestionWindow: 6000, slowStartThreshold: 6000,
						prrPriorFlight: 12_000, prrDelivered: 6900, prrOut: 6900,
						rtt: newRTTEstimator(time.Second),
						outstanding: []sentTCPSegment{
							{sequence: 0, end: 100},
							{sequence: 100, end: 1100},
							{sequence: 1100, end: 2100},
							{sequence: 2100, end: 3100},
							{sequence: 3100, end: 4100},
							{sequence: 4100, end: 5100},
						},
					}
					const lost = sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost | sentTCPSegmentLossReported | sentTCPSegmentTransmissionLost
					state.outstanding[1].state = lost
					if test.deliverSecond {
						state.outstanding[3].state = lost
					}
					if test.alreadyLost && !test.speculative {
						state.outstanding[2].state = lost
					}
					for i := range state.outstanding {
						state.outstanding[i].state |= sentTCPSegmentTransmitted
						state.outstanding[i].hostQueue = testPacketQueueTicketAt(epoch, now.Add(-500*time.Millisecond))
					}
					if test.speculative {
						state.congestionWindow, state.slowStartThreshold = 8000, 8000
						state.outstanding[0].state |= lost
						state.outstanding[1].state &^= lost
						hole := &state.outstanding[2]
						hole.advanceTransmissionGeneration()
						hole.state |= sentTCPSegmentSACKRetried
						hole.hostQueue = testPacketQueueTicketAt(epoch, now.Add(-50*time.Millisecond))
						if test.alreadyLost {
							hole.state |= sentTCPSegmentOriginalLost
						}
					}
					state.controller.initialize(CongestionPhaseRecovery, epoch, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
					state.rebaseOutstanding()
					var options [18]byte
					options[0], options[1] = TCPHeaderOptionSACK, 18
					binary.BigEndian.PutUint32(options[2:6], 100)
					binary.BigEndian.PutUint32(options[6:10], 1100)
					binary.BigEndian.PutUint32(options[10:14], 2100)
					binary.BigEndian.PutUint32(options[14:18], 5100)
					segment := tcpSegment{sequence: 100, acknowledgement: 100, flags: TCPFlagACK, window: 40_000}
					segment.setOptions(options[:])
					state.processAcknowledgment(&segment, now, 0)
					if state.prrDelivered != 11_000 || state.prrOut != 6900 || state.congestionWindow != test.wantWindow {
						t.Fatalf("PRR delivered/sent/window = %d/%d/%d, want 11000/6900/%d", state.prrDelivered, state.prrOut, state.congestionWindow, test.wantWindow)
					}
					if !state.outstanding[0].state.has(sentTCPSegmentSACKed) || !state.outstanding[1].state.has(sentTCPSegmentOriginalLost) {
						t.Fatal("ACK did not deliver the old loss and confirm the remaining hole")
					}
					wantPipe := uint32(0)
					if test.speculative {
						wantPipe = mss
						hole := &state.outstanding[1]
						if hole.lossAlreadyReported() || hole.state.has(sentTCPSegmentRACKLost|sentTCPSegmentTransmissionLost) || !hole.state.has(sentTCPSegmentSACKRetried) || state.controller.state.LostBytes != 0 {
							t.Fatalf("SACK evidence reported a live replacement as lost: %#x, loss bytes %d", hole.state, state.controller.state.LostBytes)
						}
						beforeWindow := state.congestionWindow
						state.processAcknowledgment(&segment, now, 0)
						if state.congestionWindow != beforeWindow || state.prrDelivered != 11_000 || state.controller.state.LostBytes != 0 {
							t.Fatal("repeated SACK evidence changed PRR or loss accounting")
						}
					} else if !state.outstanding[1].lossAlreadyReported() || !state.outstanding[1].state.has(sentTCPSegmentRACKLost) {
						t.Fatal("newly lost current transmission was not reported")
					}
					if sackRecoveryPipe(state.outstanding, mss) != wantPipe || !state.fastRecovery || state.undo != nil {
						t.Fatal("ACK changed recovery ownership or allocated an unused undo checkpoint")
					}
				})
			}
		})
	}
}

func TestTCPPRRNewLossAfterRTOUndo(t *testing.T) {
	for _, test := range []struct {
		name, algorithm string
		sackOnly        bool
		eifel           bool
	}{
		{name: "Reno RACK", algorithm: CongestionControlReno},
		{name: "Reno SACK", algorithm: CongestionControlReno, sackOnly: true},
		{name: "CUBIC RACK", algorithm: CongestionControlCUBIC},
		{name: "CUBIC SACK", algorithm: CongestionControlCUBIC, sackOnly: true},
		{name: "Reno RACK Eifel ACK", algorithm: CongestionControlReno, eifel: true},
		{name: "Reno SACK Eifel ACK", algorithm: CongestionControlReno, sackOnly: true, eifel: true},
		{name: "CUBIC RACK Eifel ACK", algorithm: CongestionControlCUBIC, eifel: true},
		{name: "CUBIC SACK Eifel ACK", algorithm: CongestionControlCUBIC, sackOnly: true, eifel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const mss = 1000
			now := time.Unix(100, 0)
			epoch := now.Add(-time.Second)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(test.algorithm),
				peerMSS: mss, peerSACK: true, peerWindow: 40_000,
				sendNext: 5100, congestionWindow: 6000, slowStartThreshold: 6000,
				fastRecovery: true, recoveryPoint: 5100,
				prrPriorFlight: 12_000, prrDelivered: 6900, prrOut: 6900,
				rtt: newRTTEstimator(time.Second),
				outstanding: []sentTCPSegment{
					{sequence: 0, end: 100},
					{sequence: 100, end: 1100},
					{sequence: 1100, end: 2100},
					{sequence: 2100, end: 3100},
					{sequence: 3100, end: 4100},
					{sequence: 4100, end: 5100},
				},
			}
			state.controller.initialize(CongestionPhaseRecovery, epoch, time.Millisecond, time.Millisecond, 6000, 6000, mss, 1)
			defer state.controller.release(now, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), mss, state.rtt.srtt, state.rtt.minimum)
			for index := range state.outstanding {
				state.outstanding[index].state = sentTCPSegmentTransmitted
				state.outstanding[index].hostQueue = testPacketQueueTicketAt(epoch, now.Add(-500*time.Millisecond))
			}
			state.outstanding[1].state |= sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost | sentTCPSegmentLossReported | sentTCPSegmentTransmissionLost
			state.prepareRetransmission(0, true, false, true, false, 0, now)
			if !state.outstanding[2].lossAlreadyReported() {
				t.Fatal("RTO did not report the aged original")
			}
			if test.eifel {
				state.undo.recordRetransmission(0, 100, 100, false)
				state.outstanding[0].advanceTransmissionGeneration()
				state.outstanding[0].timestamp = 100
				state.outstanding[0].hostQueue = testPacketQueueTicketAt(epoch, now)
			} else {
				if !state.restoreSpuriousRecovery(now, 0) {
					t.Fatal("RTO undo failed")
				}
				if !state.outstanding[2].lossAlreadyReported() || state.outstanding[2].state.has(sentTCPSegmentOriginalLost|sentTCPSegmentTransmissionLost|sentTCPSegmentRACKLost) {
					t.Fatal("unexpected original state after RTO undo")
				}
				if !state.fastRecovery || state.prrPriorFlight != 12_000 || state.prrDelivered != 6900 || state.prrOut != 6900 {
					t.Fatal("undo did not resume the prior PRR episode")
				}
			}
			state.rackReorderingSeen = test.sackOnly
			state.rebaseOutstanding()
			var options [18]byte
			options[0], options[1] = TCPHeaderOptionSACK, 18
			binary.BigEndian.PutUint32(options[2:6], 100)
			binary.BigEndian.PutUint32(options[6:10], 1100)
			binary.BigEndian.PutUint32(options[10:14], 2100)
			binary.BigEndian.PutUint32(options[14:18], 5100)
			segment := tcpSegment{sequence: 100, acknowledgement: 100, flags: TCPFlagACK, window: 40_000}
			segment.setOptions(options[:])
			state.processAcknowledgment(&segment, now, 99)
			if !state.outstanding[1].state.has(sentTCPSegmentOriginalLost) || state.outstanding[1].state.has(sentTCPSegmentRACKLost) == test.sackOnly {
				t.Fatalf("ACK did not infer the expected original loss: state %#x", state.outstanding[1].state)
			}
			if state.congestionWindow != 4100 {
				t.Fatalf("PRR cwnd = %d, want 4100 without the SafeACK bonus", state.congestionWindow)
			}
			if state.undo.spuriousUndos != 1 || !state.fastRecovery || state.prrDelivered != 11_000 {
				t.Fatal("ACK did not retain the resumed recovery's delivery credit")
			}
		})
	}
}

func TestTCPSequenceWrapAndSACK(t *testing.T) {
	acknowledged, sendNext := uint32(0xfffffff0), uint32(0x30)
	options := make([]byte, 10)
	options[0], options[1] = 5, 10
	binary.BigEndian.PutUint32(options[2:6], 0)
	binary.BigEndian.PutUint32(options[6:10], 0x20)
	blocks := parseTCPSACKOptions(options, acknowledged, sendNext)
	if len(blocks) != 1 || blocks[0].LeftEdge != 0 || blocks[0].RightEdge != 0x20 {
		t.Fatalf("wrapped SACK blocks = %#v", blocks)
	}
	if !tcpSequenceLess(0xfffffff0, 0x10) || !tcpSequenceGreater(0x10, 0xfffffff0) {
		t.Fatal("wrapped sequence ordering failed")
	}
}

func TestTCPSACKCoalescesAdjacentPieces(t *testing.T) {
	pieces := []tcpReceivedPiece{
		{sequence: 100, payload: []byte("ab")},
		{sequence: 102, payload: []byte("cd")},
		{sequence: 106, payload: []byte("ef")},
	}
	var workspace [34]byte
	options := tcpSACKOptions(pieces, 103, 4, TCPSACKBlock{}, false, &workspace)
	blocks := parseTCPSACKOptions(options, 90, 120)
	if len(blocks) != 2 || blocks[0] != (TCPSACKBlock{LeftEdge: 100, RightEdge: 104}) || blocks[1] != (TCPSACKBlock{LeftEdge: 106, RightEdge: 108}) {
		t.Fatalf("coalesced SACK blocks = %#v", blocks)
	}
}

func TestTCPSACKOptionsDoNotAllocate(t *testing.T) {
	pieces := []tcpReceivedPiece{
		{sequence: 100, payload: []byte("ab")},
		{sequence: 102, payload: []byte("cd")},
		{sequence: 108, payload: []byte("ef")},
	}
	allocations := testing.AllocsPerRun(100, func() {
		var workspace [34]byte
		if options := tcpSACKOptions(pieces, 103, 4, TCPSACKBlock{}, false, &workspace); len(options) != 18 {
			panic("unexpected SACK option size")
		}
	})
	if allocations != 0 {
		t.Fatalf("SACK option allocations = %v, want 0", allocations)
	}
}

func TestTCPSACKBlockLimit(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	for _, test := range []struct {
		name           string
		mtu            int
		address        netip.Addr
		timestamp      bool
		reservePayload int
		want           int
	}{
		{name: "IPv4 maximum", mtu: 1500, address: ipv4, want: 4},
		{name: "IPv4 maximum with timestamp", mtu: 1500, address: ipv4, timestamp: true, want: 3},
		{name: "IPv4 minimum with payload", mtu: 68, address: ipv4, reservePayload: 1, want: 2},
		{name: "IPv4 small with timestamp", mtu: 68, address: ipv4, timestamp: true, reservePayload: 1, want: 1},
		{name: "too small", mtu: 59, address: ipv4, timestamp: true, want: 0},
		{name: "IPv6 minimum", mtu: 1280, address: ipv6, timestamp: true, reservePayload: 1, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpSACKBlockLimit(test.mtu, test.address, test.timestamp, test.reservePayload); got != test.want {
				t.Fatalf("tcpSACKBlockLimit = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTCPSACKPiggybacksOnData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	clientPort := connection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	serverSequence := peer.serverNext
	clientAcknowledgement := peer.clientNext
	link.mu.Unlock()
	if err = link.deliverTCP(8081, clientPort, serverSequence+4, clientAcknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte("late")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientSACKs != 0
	})
	if _, err = connection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientDataSACKs != 0
	})
}

func TestTCPDSACKGeneration(t *testing.T) {
	if block, ok := tcpDuplicateSACKBlock(90, 20, false, 100, nil); !ok || block != (TCPSACKBlock{LeftEdge: 90, RightEdge: 100}) {
		t.Fatalf("below-ACK duplicate block = %#v, %t", block, ok)
	}
	pieces := []tcpReceivedPiece{{sequence: 120, payload: make([]byte, 20)}}
	block, ok := tcpDuplicateSACKBlock(125, 20, false, 100, pieces)
	if !ok || block != (TCPSACKBlock{LeftEdge: 125, RightEdge: 140}) {
		t.Fatalf("contained duplicate block = %#v, %t", block, ok)
	}
	var workspace [34]byte
	options := tcpSACKOptions(pieces, 125, 2, block, true, &workspace)
	if len(options) != 18 || binary.BigEndian.Uint32(options[2:6]) != 125 || binary.BigEndian.Uint32(options[6:10]) != 140 ||
		binary.BigEndian.Uint32(options[10:14]) != 120 || binary.BigEndian.Uint32(options[14:18]) != 140 {
		t.Fatalf("DSACK-first options = %x", options)
	}
}

func TestTCPOutOfOrderOverlapPreservesFirstData(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	outOfOrder := []tcpReceivedPiece{{sequence: 104, payload: []byte("old")}}
	outOfOrderBytes := 3
	incoming := []byte("abcdef")
	connection.receiveTCPData(102, incoming, false, 32, 0, &receiveNext, &outOfOrder, &outOfOrderBytes)
	if len(outOfOrder) != 3 || outOfOrderBytes != 6 {
		t.Fatalf("out-of-order state = %d pieces, %d bytes; want 3, 6", len(outOfOrder), outOfOrderBytes)
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("00"), false, 32, 0, &receiveNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("receiveTCPData = %t, %t; want true, false", delivered, closed)
	}
	if got := string(testTCPReadBufferBytes(&connection.readBuffer)); got != "00aboldf" {
		t.Fatalf("overlap payload = %q, want %q", got, "00aboldf")
	}
}

func TestTCPOutOfOrderAdoptsCompleteOwnedRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	payload := []byte("owned")
	payload = payload[:len(payload):len(payload)]
	var pieces []tcpReceivedPiece
	bytes := 0
	receiveNext := uint32(100)
	connection.receiveTCPData(104, payload, false, 32, 0, &receiveNext, &pieces, &bytes)
	if len(pieces) != 1 || &pieces[0].payload[0] != &payload[0] {
		t.Fatal("single uncovered range did not transfer its backing")
	}
}

func TestTCPOutOfOrderCompactsPartialOwnedRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	owner := make([]byte, 32)
	copy(owner[28:], "tail")
	payload := owner[28:]
	var pieces []tcpReceivedPiece
	bytes := 0
	receiveNext := uint32(100)
	connection.receiveTCPOutOfOrder(&receiveNext, 32, 0, 104, payload, owner, false, &pieces, &bytes)
	if len(pieces) != 1 || string(pieces[0].payload) != "tail" || &pieces[0].payload[0] == &owner[28] || cap(pieces[0].payload) != len(pieces[0].payload) {
		t.Fatalf("partial payload retained owner backing: pieces=%+v capacity=%d", pieces, cap(pieces[0].payload))
	}
}

func TestTCPPromoteCompactsPartiallyDeliveredRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 2, readNotify: make(chan struct{})}
	owner := make([]byte, 32)
	copy(owner, "data")
	pieces := []tcpReceivedPiece{{sequence: 100, payload: owner[:4]}}
	bytes := 4
	receiveNext := uint32(100)
	if delivered, closed := connection.promoteTCPReceived(0, &receiveNext, &pieces, &bytes); !delivered || closed {
		t.Fatalf("partial promotion = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 102 || bytes != 2 || len(pieces) != 1 || string(pieces[0].payload) != "ta" ||
		&pieces[0].payload[0] == &owner[2] || cap(pieces[0].payload) != len(pieces[0].payload) {
		t.Fatalf("partial promotion retained owner backing: next=%d bytes=%d pieces=%+v capacity=%d", receiveNext, bytes, pieces, cap(pieces[0].payload))
	}
}

func TestTCPPromoteReleasesConsumedRangeReferences(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 8, readNotify: make(chan struct{})}
	backing := []tcpReceivedPiece{
		{sequence: 100, payload: []byte("a")},
		{sequence: 101, payload: []byte("b")},
		{sequence: 103, payload: []byte("d"), fin: true},
	}
	pieces, retained, next := backing, 3, uint32(100)
	if delivered, closed := connection.promoteTCPReceived(0, &next, &pieces, &retained); !delivered || closed || next != 102 || len(pieces) != 1 || retained != 1 {
		t.Fatalf("promotion = delivered %t closed %t next %d pieces %d bytes %d", delivered, closed, next, len(pieces), retained)
	}
	for index := 0; index < 2; index++ {
		if backing[index].payload != nil || backing[index].fin || backing[index].sequence != 0 {
			t.Fatalf("consumed slot %d still retains a range: %+v", index, backing[index])
		}
	}
	if delivered, closed := connection.receiveTCPData(next, []byte("c"), false, 8, 0, &next, &pieces, &retained); !delivered || !closed || next != 105 || pieces != nil || retained != 0 || string(testTCPReadBufferBytes(&connection.readBuffer)) != "abcd" {
		t.Fatalf("final promotion = delivered %t closed %t next %d pieces %d bytes %d", delivered, closed, next, len(pieces), retained)
	}
}

func TestTCPOutOfOrderUsesPromisedWindow(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	var outOfOrder []tcpReceivedPiece
	outOfOrderBytes := 0
	first := []byte("first")
	connection.receiveTCPData(120, first, false, 32, 0, &receiveNext, &outOfOrder, &outOfOrderBytes)
	if outOfOrderBytes != len(first) {
		t.Fatal("first out-of-order range was rejected")
	}
	edge := []byte("edge")
	connection.receiveTCPData(128, edge, false, 32, 0, &receiveNext, &outOfOrder, &outOfOrderBytes)
	if outOfOrderBytes != 9 {
		t.Fatalf("out-of-order bytes = %d, want 9", outOfOrderBytes)
	}
}

func TestTCPOutOfOrderFullQueueAcceptsGap(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffff0} {
		t.Run(fmt.Sprintf("sequence-%x", start), func(t *testing.T) {
			const capacity = tcpMaximumOutOfOrder
			connection := &TCPConn{receiveCapacity: capacity, readNotify: make(chan struct{})}
			next := start
			var pieces []tcpReceivedPiece
			retained := 0
			want := make([]byte, capacity+1)
			want[0] = 42
			for index := 0; index < capacity; index++ {
				want[index+1] = byte(index)
				connection.receiveTCPData(start+1+uint32(index), want[index+1:index+2:index+2], index == capacity-1, capacity+2, 1, &next, &pieces, &retained)
			}
			if len(pieces) != capacity || retained != capacity || next != start || connection.readBuffer.size != 0 {
				t.Fatalf("full queue = pieces %d bytes %d next %d readable %d", len(pieces), retained, next, connection.readBuffer.size)
			}
			if delivered, closed := connection.receiveTCPData(start, want[:1:1], false, capacity+2, 1, &next, &pieces, &retained); !delivered || !closed {
				t.Fatalf("gap filling = delivered %t closed %t", delivered, closed)
			}
			if next != start+capacity+2 || retained != 0 || pieces != nil || connection.outOfOrderUnread.Load() != 0 || !bytes.Equal(testTCPReadBufferBytes(&connection.readBuffer), want) {
				t.Fatalf("gap result = next %d pieces %d bytes %d readable %d", next, len(pieces), retained, connection.readBuffer.size)
			}
		})
	}
}

func TestTCPOutOfOrderFullQueuePrunesHighestRanges(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffff0} {
		t.Run(fmt.Sprintf("sequence-%x", start), func(t *testing.T) {
			const capacity = 2*tcpMaximumOutOfOrder + 10
			connection := &TCPConn{receiveCapacity: capacity, readNotify: make(chan struct{})}
			next := start
			pieces := make([]tcpReceivedPiece, tcpMaximumOutOfOrder)
			for index := range pieces {
				pieces[index] = tcpReceivedPiece{sequence: next + 4 + uint32(2*index), payload: []byte{byte(index)}}
			}
			retained := len(pieces)
			last := pieces[len(pieces)-1].sequence
			if delivered, closed := connection.receiveTCPData(next+2, []byte{'y'}, false, capacity, 0, &next, &pieces, &retained); delivered || closed {
				t.Fatalf("gapped insertion = delivered %t closed %t", delivered, closed)
			}
			if len(pieces) != tcpMaximumOutOfOrder || cap(pieces) > tcpMaximumOutOfOrder || retained != tcpMaximumOutOfOrder || connection.outOfOrderUnread.Load() != int64(retained) || pieces[0].sequence != next+2 || pieces[len(pieces)-1].sequence != last-2 {
				t.Fatalf("pruned queue = len %d cap %d bytes %d first %d last %d", len(pieces), cap(pieces), retained, pieces[0].sequence, pieces[len(pieces)-1].sequence)
			}
			var workspace [34]byte
			for _, block := range parseTCPSACKOptions(tcpSACKOptions(pieces, last, 4, TCPSACKBlock{}, false, &workspace), next, next+capacity) {
				if tcpSequenceGreater(block.RightEdge, last-1) {
					t.Fatalf("SACK still reports discarded data: %+v", block)
				}
			}
			for _, incoming := range [][]byte{{'z'}, nil} {
				if allocations := testing.AllocsPerRun(10, func() {
					if delivered, closed := connection.receiveTCPData(last+2, incoming, true, capacity, 0, &next, &pieces, &retained); delivered || closed {
						t.Fatalf("high-sequence insertion = delivered %t closed %t", delivered, closed)
					}
				}); allocations != 0 {
					t.Fatalf("discarding a highest range with %d payload bytes allocated %g objects", len(incoming), allocations)
				}
			}
			if len(pieces) != tcpMaximumOutOfOrder || cap(pieces) > tcpMaximumOutOfOrder || retained != tcpMaximumOutOfOrder || connection.outOfOrderUnread.Load() != int64(retained) || pieces[len(pieces)-1].sequence != last-2 || pieces[len(pieces)-1].fin {
				t.Fatal("metadata pruning retained the incoming high-sequence range or FIN")
			}
			options := tcpSACKOptions(pieces, last+2, 4, TCPSACKBlock{}, false, &workspace)
			if len(options) != 34 || options[0] != TCPHeaderOptionSACK || options[1] != byte(len(options)) ||
				binary.BigEndian.Uint32(options[2:6]) != last-2 || binary.BigEndian.Uint32(options[6:10]) != last-1 {
				t.Fatalf("SACK after discarding the incoming range = %x", options)
			}
			for _, block := range parseTCPSACKOptions(options, next, next+capacity) {
				if tcpSequenceGreater(block.RightEdge, last-1) {
					t.Fatalf("SACK reports the discarded incoming range: %+v", block)
				}
			}
			payload := bytes.Repeat([]byte{'x'}, 2*tcpMaximumOutOfOrder+4)
			want := append([]byte(nil), payload...)
			want[2] = 'y'
			for index := 0; index < tcpMaximumOutOfOrder-1; index++ {
				want[4+2*index] = byte(index)
			}
			if delivered, closed := connection.receiveTCPData(next, payload, false, capacity, 0, &next, &pieces, &retained); !delivered || closed {
				t.Fatalf("overlapping gap filling = delivered %t closed %t", delivered, closed)
			}
			if next != start+uint32(len(payload)) || pieces != nil || retained != 0 || !bytes.Equal(testTCPReadBufferBytes(&connection.readBuffer), want) {
				t.Fatalf("overlapping result = next %d pieces %d bytes %d readable %d", next, len(pieces), retained, connection.readBuffer.size)
			}
		})
	}
}

func TestTCPOutOfOrderFullQueueAcceptsTailFIN(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffff0} {
		t.Run(fmt.Sprintf("sequence-%x", start), func(t *testing.T) {
			const count = tcpMaximumOutOfOrder
			connection := &TCPConn{receiveCapacity: count + 1, readNotify: make(chan struct{})}
			pieces := make([]tcpReceivedPiece, count)
			want := make([]byte, count+1)
			want[0] = 'g'
			for index := range pieces {
				want[index+1] = byte(index)
				pieces[index] = tcpReceivedPiece{sequence: start + 1 + uint32(index), payload: want[index+1 : index+2 : index+2]}
			}
			next, retained := start, count
			if delivered, closed := connection.receiveTCPData(start+count+1, nil, true, count+2, 0, &next, &pieces, &retained); delivered || closed {
				t.Fatalf("tail FIN = delivered %t closed %t", delivered, closed)
			}
			if next != start || retained != count || len(pieces) != count || !pieces[len(pieces)-1].fin {
				t.Fatal("full metadata queue failed to attach a FIN to its retained tail")
			}
			if delivered, closed := connection.receiveTCPData(start, want[:1:1], false, count+2, 0, &next, &pieces, &retained); !delivered || !closed {
				t.Fatalf("gap filling = delivered %t closed %t", delivered, closed)
			}
			if next != start+count+2 || pieces != nil || retained != 0 || connection.outOfOrderUnread.Load() != 0 || !bytes.Equal(testTCPReadBufferBytes(&connection.readBuffer), want) {
				t.Fatal("gap filling failed to preserve data and consume the retained FIN")
			}
		})
	}
}

func TestTCPOutOfOrderFullQueuePromotesContiguousPrefix(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffff0} {
		t.Run(fmt.Sprintf("sequence-%x", start), func(t *testing.T) {
			const count = tcpMaximumOutOfOrder
			connection := &TCPConn{receiveCapacity: count + 1, readNotify: make(chan struct{})}
			pieces := make([]tcpReceivedPiece, count)
			want := make([]byte, count+1)
			for index := range pieces {
				want[index] = byte(index)
				pieces[index] = tcpReceivedPiece{sequence: start + uint32(index), payload: want[index : index+1 : index+1]}
			}
			want[count] = 'z'
			next, retained := start, count
			if delivered, closed := connection.receiveTCPData(start+count, want[count:], false, count+1, 0, &next, &pieces, &retained); !delivered || closed {
				t.Fatalf("tail input = delivered %t closed %t", delivered, closed)
			}
			if next != start+count+1 || pieces != nil || retained != 0 || connection.outOfOrderUnread.Load() != 0 || !bytes.Equal(testTCPReadBufferBytes(&connection.readBuffer), want) {
				t.Fatal("tail input failed to promote the retained prefix and new data")
			}
		})
	}
}

func TestTCPOutOfOrderFullQueuePrunesAfterReadBufferShrink(t *testing.T) {
	for _, payload := range [][]byte{{'z'}, nil} {
		t.Run(fmt.Sprintf("payload-%d", len(payload)), func(t *testing.T) {
			const count = tcpMaximumOutOfOrder
			connection := &TCPConn{receiveCapacity: count, readNotify: make(chan struct{})}
			pieces := make([]tcpReceivedPiece, count)
			next, retained := uint32(100), count
			for index := range pieces {
				pieces[index] = tcpReceivedPiece{sequence: next + 1 + uint32(index), payload: []byte{byte(index)}}
			}
			if err := connection.SetReadBuffer(count / 2); err != nil {
				t.Fatal(err)
			}
			if delivered, closed := connection.receiveTCPData(next+count+1, payload, true, count+3, 0, &next, &pieces, &retained); delivered || closed {
				t.Fatalf("tail input = delivered %t closed %t", delivered, closed)
			}
			if next != 100 || len(pieces) != count/2 || retained != count/2 || connection.outOfOrderUnread.Load() != count/2 {
				t.Fatal("tail input bypassed pruning to the smaller byte budget")
			}
			for index, piece := range pieces {
				if piece.sequence != next+1+uint32(index) || len(piece.payload) != 1 || piece.payload[0] != byte(index) || piece.fin {
					t.Fatal("byte-budget pruning changed the retained prefix")
				}
			}
		})
	}
}

func TestTCPOutOfOrderSACKReportsRetainedInput(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffff7} {
		for _, test := range []struct {
			name string
			keep int
		}{
			{name: "partial", keep: 3},
			{name: "discarded", keep: 0},
		} {
			t.Run(fmt.Sprintf("sequence-%x/%s", start, test.name), func(t *testing.T) {
				connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
				next := start
				var pieces []tcpReceivedPiece
				retained := 0
				connection.receiveTCPData(start+4, []byte("ab"), false, 32, 0, &next, &pieces, &retained)
				if next != start || retained != 2 || len(pieces) != 1 {
					t.Fatal("initial out-of-order range was not retained")
				}
				if err := connection.SetReadBuffer(2 + test.keep); err != nil {
					t.Fatal(err)
				}
				payload := []byte("uvwxyz")
				if delivered, closed := connection.receiveTCPData(start+8, payload, true, 32, 0, &next, &pieces, &retained); delivered || closed {
					t.Fatalf("pruned reception = delivered %t closed %t", delivered, closed)
				}
				want := []TCPSACKBlock{{LeftEdge: start + 4, RightEdge: start + 6}}
				if test.keep != 0 {
					want = []TCPSACKBlock{
						{LeftEdge: start + 8, RightEdge: start + 8 + uint32(test.keep)},
						want[0],
					}
				}
				if next != start || connection.readBuffer.size != 0 || retained != 2+test.keep || connection.outOfOrderUnread.Load() != int64(retained) || len(pieces) != len(want) {
					t.Fatalf("pruned queue = next %d readable %d bytes %d pieces %d", next, connection.readBuffer.size, retained, len(pieces))
				}
				if pieces[0].sequence != start+4 || string(pieces[0].payload) != "ab" {
					t.Fatal("pruning changed the earlier retained range")
				}
				if test.keep != 0 && (pieces[1].sequence != start+8 || !bytes.Equal(pieces[1].payload, payload[:test.keep])) {
					t.Fatal("pruning did not retain the incoming prefix")
				}
				for _, piece := range pieces {
					if piece.fin {
						t.Fatal("pruning retained the incoming FIN")
					}
				}
				var workspace [34]byte
				options := tcpSACKOptions(pieces, start+8, 4, TCPSACKBlock{}, false, &workspace)
				if len(options) != 2+8*len(want) || options[0] != TCPHeaderOptionSACK || options[1] != byte(len(options)) {
					t.Fatalf("SACK option framing = %x", options)
				}
				for index, expected := range want {
					offset := 2 + 8*index
					actual := TCPSACKBlock{
						LeftEdge:  binary.BigEndian.Uint32(options[offset : offset+4]),
						RightEdge: binary.BigEndian.Uint32(options[offset+4 : offset+8]),
					}
					if actual != expected {
						t.Fatalf("SACK block %d = %+v, want %+v", index, actual, expected)
					}
				}
			})
		}
	}
}

func TestTCPOutOfOrderByteLimitPreservesGapAndDefersFIN(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 5, readNotify: make(chan struct{})}
	next := uint32(100)
	owner := []byte("older")
	pieces := []tcpReceivedPiece{{sequence: 104, payload: owner, fin: true}}
	retained := len(owner)
	if delivered, closed := connection.receiveTCPData(100, []byte("ABCDEFGH"), false, 10, 0, &next, &pieces, &retained); !delivered || closed {
		t.Fatalf("byte-limited gap filling = delivered %t closed %t", delivered, closed)
	}
	if got := string(testTCPReadBufferBytes(&connection.readBuffer)); got != "ABCDo" || next != 105 || pieces != nil || retained != 0 {
		t.Fatalf("byte-limited result = %q next %d pieces %d bytes %d", got, next, len(pieces), retained)
	}
	last := connection.readBuffer.chunks[len(connection.readBuffer.chunks)-1]
	if cap(last) != len(last) || &last[0] == &owner[0] {
		t.Fatal("trimmed tail retained its original allocation")
	}
	connection.readBuffer.reset()
	if delivered, closed := connection.receiveTCPData(105, []byte("lder"), true, 5, 0, &next, &pieces, &retained); !delivered || !closed || next != 110 || string(testTCPReadBufferBytes(&connection.readBuffer)) != "lder" {
		t.Fatalf("tail retransmission = delivered %t closed %t next %d", delivered, closed, next)
	}
}

func TestTCPOutOfOrderShrinkPreservesGapProgress(t *testing.T) {
	for _, occupied := range []int{0, 3} {
		for _, extra := range []uint16{0, 2} {
			t.Run(fmt.Sprintf("readable-%d/extra-%d", occupied, extra), func(t *testing.T) {
				connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
				connection.readBuffer.append(bytes.Repeat([]byte{'x'}, occupied))
				next := uint32(100)
				var pieces []tcpReceivedPiece
				retained := 0
				connection.receiveTCPData(104, []byte("abcdefghijklmnop"), true, 32, 0, &next, &pieces, &retained)
				if next != 100 || retained != 16 || len(pieces) != 1 {
					t.Fatalf("initial queue = next %d bytes %d pieces %d", next, retained, len(pieces))
				}
				if err := connection.SetReadBuffer(8); err != nil {
					t.Fatal(err)
				}
				if delivered, closed := connection.receiveTCPData(next, []byte("GAP!"), false, 32, extra, &next, &pieces, &retained); !delivered || closed {
					t.Fatalf("gap filling after shrink = delivered %t closed %t", delivered, closed)
				}
				accepted := 8 + int(extra) - occupied
				want := strings.Repeat("x", occupied) + "GAP!abcdefghijklmnop"[:accepted]
				if next != 100+uint32(accepted) || pieces != nil || retained != 0 || connection.outOfOrderUnread.Load() != 0 || string(testTCPReadBufferBytes(&connection.readBuffer)) != want {
					t.Fatalf("shrunken queue = next %d pieces %d bytes %d readable %q; want %q", next, len(pieces), retained, testTCPReadBufferBytes(&connection.readBuffer), want)
				}
			})
		}
	}
}

func TestTCPReceiveProgressAfterReadBufferShrink(t *testing.T) {
	link, _, connection := newManuallyPumpedTCPConnection(t)
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	peer := link.tcp[connection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err := link.deliverTCP(8080, connection.key.local.Port(), sequence+4, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, []byte("abcdefghijklmnop")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.outOfOrderUnread.Load() == 16 })
	if err := connection.SetReadBuffer(8); err != nil {
		t.Fatal(err)
	}
	if err := link.deliverTCP(8080, connection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte("GAP!")); err != nil {
		t.Fatal(err)
	}
	var buffer [8]byte
	if n, err := io.ReadFull(connection, buffer[:]); err != nil || n != len(buffer) || string(buffer[:]) != "GAP!abcd" {
		t.Fatalf("gap delivery = %d, %v, %q", n, err, buffer)
	}
	if connection.outOfOrderUnread.Load() != 0 {
		t.Fatal("high sequence data survived beyond the shrunken receive budget")
	}
	if err := link.deliverTCP(8080, connection.key.local.Port(), sequence+8, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, []byte("efghijklmnop")); err != nil {
		t.Fatal(err)
	}
	if n, err := io.ReadFull(connection, buffer[:]); err != nil || n != len(buffer) || string(buffer[:]) != "efghijkl" {
		t.Fatalf("partial tail delivery = %d, %v, %q", n, err, buffer)
	}
	if err := link.deliverTCP(8080, connection.key.local.Port(), sequence+16, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, []byte("mnop")); err != nil {
		t.Fatal(err)
	}
	if n, err := io.ReadFull(connection, buffer[:4]); err != nil || n != 4 || string(buffer[:4]) != "mnop" {
		t.Fatalf("final tail delivery = %d, %v, %q", n, err, buffer[:4])
	}
	if n, err := connection.Read(buffer[:]); n != 0 || err != io.EOF {
		t.Fatalf("Read after the complete FIN = %d, %v", n, err)
	}
	if info := connection.Info(); info.BytesReceived != 20 || info.State != TCPStateCloseWait {
		t.Fatalf("completed receive after shrink = %+v", info)
	}
}

func TestTCPPromoteAfterReadBufferShrink(t *testing.T) {
	for _, occupied := range []int{0, 8} {
		for _, extra := range []uint16{0, 2} {
			t.Run(fmt.Sprintf("readable-%d/extra-%d", occupied, extra), func(t *testing.T) {
				connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
				connection.readBuffer.append(bytes.Repeat([]byte{'x'}, occupied))
				pieces := []tcpReceivedPiece{
					{sequence: 100, payload: []byte("abcd")},
					{sequence: 104, payload: []byte("efgh")},
					{sequence: 108, payload: []byte("ijkl"), fin: true},
				}
				retained, next := 12, uint32(100)
				if err := connection.SetReadBuffer(8); err != nil {
					t.Fatal(err)
				}
				var received []byte
				for iteration := 0; iteration < 3; iteration++ {
					previous := next
					_, closed := connection.promoteTCPReceived(extra, &next, &pieces, &retained)
					if connection.readBuffer.size > 8+int(extra) || retained+connection.readBuffer.size > 12+occupied || connection.outOfOrderUnread.Load() != int64(retained) {
						t.Fatalf("promotion exceeded receive storage: readable %d retained %d", connection.readBuffer.size, retained)
					}
					if iteration == 0 && next != 100+uint32(8+int(extra)-occupied) {
						t.Fatalf("promotion blocked by later ranges: next %d", next)
					}
					buffer := make([]byte, connection.readBuffer.size)
					if len(buffer) != 0 {
						if n, err := connection.Read(buffer); err != nil || n != len(buffer) {
							t.Fatalf("Read = %d, %v; want %d, nil", n, err, len(buffer))
						}
						received = append(received, buffer...)
					}
					if closed {
						if next != 113 || pieces != nil || retained != 0 || string(received) != strings.Repeat("x", occupied)+"abcdefghijkl" {
							t.Fatalf("completed promotion = next %d pieces %d bytes %d payload %q", next, len(pieces), retained, received)
						}
						return
					}
					if next == previous && len(buffer) == 0 {
						t.Fatal("read-window wake made no receive progress")
					}
				}
				t.Fatal("continuous queued data did not finish after draining the read buffer")
			})
		}
	}
}

func TestTCPConnectionResourceLimit(t *testing.T) {
	const maximumConnections = 3
	local := netip.MustParseAddr("192.0.2.1")
	stack, err := New(Config{
		LocalAddresses:    []netip.Prefix{netip.PrefixFrom(local, 32)},
		MTU:               1400,
		MaxTCPConnections: maximumConnections,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("192.0.2.2")
	stack.mu.Lock()
	for index := 0; index < maximumConnections; index++ {
		port := uint16(dynamicPortFirst + index)
		key := tcpKey{local: netip.AddrPortFrom(local, port), remote: netip.AddrPortFrom(remote, uint16(index+1))}
		stack.tcp[key] = &TCPConn{}
	}
	stack.mu.Unlock()
	_, err = stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 443))
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("DialTCP error = %v, want ErrResourceLimit", err)
	}
	acceptResult := make(chan error, 1)
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		if connection != nil {
			_ = connection.Close()
		}
		acceptResult <- acceptErr
	})
	if err != nil {
		t.Fatal(err)
	}
	packet := buildTestTCP(remote, local, 55000, 443, 100, 0, TCPFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-acceptResult:
		if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("TCPForwarderRequest.Accept error = %v, want ErrResourceLimit", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCPForwarderRequest.Accept did not report the connection limit")
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	stack.mu.Lock()
	stack.tcp = make(map[tcpKey]*TCPConn)
	stack.mu.Unlock()
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTCPInboundQueueHasByteCapacity(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.76"), netip.MustParseAddr("198.51.100.76"))
	connection := newTCPConn(stack, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	segment := tcpSegment{payload: make([]byte, 65535)}
	accepted := 0
	for connection.enqueueInbound(segment) {
		accepted++
	}
	if accepted == 0 {
		t.Fatal("inbound byte queue accepted no segments")
	}
	if queued := connection.inbound.retainedBytes(); queued > tcpInboundByteCapacity {
		t.Fatalf("queued TCP bytes = %d, limit %d", queued, tcpInboundByteCapacity)
	}
	consumed, ok := connection.inbound.dequeue()
	if !ok {
		t.Fatal("full inbound queue did not return a segment")
	}
	if consumed.retainedBytes != 0 {
		t.Fatalf("consumed segment retained accounting = %d", consumed.retainedBytes)
	}
	if !connection.enqueueInbound(segment) {
		t.Fatal("released inbound byte capacity was not reusable")
	}
	peak := connection.inbound.peakBytes()
	connection.inbound.close()
	if connection.enqueueInbound(segment) {
		t.Fatal("closed inbound queue accepted a segment")
	}
	if queued := connection.inbound.retainedBytes(); queued != 0 {
		t.Fatalf("closed inbound queue retained %d bytes", queued)
	}
	if retainedPeak := connection.inbound.peakBytes(); retainedPeak != peak {
		t.Fatalf("closed inbound queue peak = %d, want %d", retainedPeak, peak)
	}
}

func TestTCPInboundQueueOverloadUpdatesDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.77")
	remote := netip.MustParseAddr("198.51.100.77")
	_, stack := newTestStack(t, local, remote)
	key := tcpKey{
		local:  netip.AddrPortFrom(local, 8080),
		remote: netip.AddrPortFrom(remote, 45000),
	}
	connection := newTCPConn(stack, "tcp4", key, 1400, tcpSocketOptionSet{})
	connection.inbound.mu.Lock()
	connection.inbound.bytes = tcpInboundByteCapacity
	connection.inbound.mu.Unlock()
	stack.mu.Lock()
	stack.tcp[key] = connection
	stack.mu.Unlock()
	t.Cleanup(func() {
		stack.mu.Lock()
		delete(stack.tcp, key)
		stack.mu.Unlock()
		connection.inbound.close()
	})
	packet := buildTestTCP(remote, local, 45000, 8080, 1, 1, TCPFlagACK, 65535, nil, []byte("overload"))
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if dropped := connection.inboundQueueDrops.Load(); dropped != 1 {
		t.Fatalf("connection inbound queue drops = %d, want 1", dropped)
	}
	stats := stack.Stats()
	if stats.TCPInboundQueueDrops != 1 || stats.InboundDroppedPackets != 1 {
		t.Fatalf("stack overload diagnostics = %+v", stats)
	}
}

func TestTCPInboundQueuePrependHonorsByteCapacity(t *testing.T) {
	queue := newTCPSegmentQueue()
	segment := tcpSegment{payload: make([]byte, 65535)}
	for queue.enqueue(segment) {
	}
	if queue.prepend(segment) {
		t.Fatal("inbound queue prepend exceeded byte capacity")
	}
	if queued := queue.retainedBytes(); queued > tcpInboundByteCapacity {
		t.Fatalf("queued TCP bytes = %d, limit %d", queued, tcpInboundByteCapacity)
	}
}

func TestTCPInboundQueueRetainsOnlySmallBacking(t *testing.T) {
	queue := newTCPSegmentQueue()
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
			t.Fatal("small inbound queue rejected a segment")
		}
	}
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) {
			t.Fatalf("small inbound queue dequeue = %d, %v, want %d, true", segment.sequence, ok, index)
		}
	}
	if len(queue.segments) != 0 || cap(queue.segments) == 0 || cap(queue.segments) > tcpMetadataQueueRetain {
		t.Fatalf("small drained inbound queue = len %d cap %d", len(queue.segments), cap(queue.segments))
	}
	for index := 0; index < tcpMetadataQueueRetain+1; index++ {
		if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
			t.Fatal("large inbound queue rejected a segment")
		}
	}
	for index := 0; index < tcpMetadataQueueRetain+1; index++ {
		if _, ok := queue.dequeue(); !ok {
			t.Fatal("large inbound queue lost a segment")
		}
	}
	if queue.segments != nil || queue.head != 0 {
		t.Fatalf("large drained inbound queue retained len %d cap %d head %d", len(queue.segments), cap(queue.segments), queue.head)
	}
	if !queue.enqueue(tcpSegment{}) || cap(queue.segments) != tcpMetadataQueueRetain {
		t.Fatalf("burst-aware inbound queue restarted with capacity %d, want %d", cap(queue.segments), tcpMetadataQueueRetain)
	}
	if _, ok := queue.dequeue(); !ok {
		t.Fatal("burst-aware inbound queue lost a segment")
	}
}

func TestTCPNetworkErrorQueueIsLazyBoundedAndOrdered(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	if connection.pending != nil {
		t.Fatal("new TCP connection allocated a network-error queue")
	}
	errorsByIndex := make([]error, tcpMaximumPendingNetworkErrors+2)
	for index := range errorsByIndex {
		errorsByIndex[index] = errors.New(strconv.Itoa(index))
		connection.deliverError(errorsByIndex[index])
	}
	if got := len(connection.pending.networkErrors); got != tcpMaximumPendingNetworkErrors {
		t.Fatalf("queued network errors = %d, want %d", got, tcpMaximumPendingNetworkErrors)
	}
	for index := 0; index < tcpMaximumPendingNetworkErrors; index++ {
		got, ok := connection.takeNetworkError()
		if !ok || got != errorsByIndex[index] {
			t.Fatalf("network error %d = %v, %v", index, got, ok)
		}
	}
	if got, ok := connection.takeNetworkError(); ok || got != nil {
		t.Fatalf("empty network-error queue returned %v, %v", got, ok)
	}
	for index := 0; index < 2; index++ {
		connection.deliverError(errorsByIndex[index])
	}
	retainedCapacity := cap(connection.pending.networkErrors)
	connection.discardNetworkErrors()
	if got := len(connection.pending.networkErrors); got != 0 || cap(connection.pending.networkErrors) != retainedCapacity {
		t.Fatalf("discarded network-error queue = len %d cap %d, want len 0 cap %d", got, cap(connection.pending.networkErrors), retainedCapacity)
	}
	for _, retained := range connection.pending.networkErrors[:retainedCapacity] {
		if retained != nil {
			t.Fatalf("discarded network-error queue retained %v", retained)
		}
	}
}

func TestTCPIPv4ReassemblyTimeoutDoesNotQueueError(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.196"), netip.MustParseAddr("198.51.100.196")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	key := tcpKey{local: netip.AddrPortFrom(local, 40196), remote: netip.AddrPortFrom(remote, 40197)}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	connection.publishICMPSequenceRange(100, 120)
	stack.mu.Lock()
	stack.tcp[key] = connection
	stack.mu.Unlock()
	defer func() {
		stack.mu.Lock()
		delete(stack.tcp, key)
		stack.mu.Unlock()
	}()
	segment := mustTestWire((TCPSegment{Source: key.local, Destination: key.remote, SequenceNumber: 100, Flags: TCPFlagACK}).MarshalBinary())
	quote := mustTestWire((IPPacket{Source: local, Destination: remote, Protocol: ProtocolTCP, HopLimit: 64, Payload: segment}).MarshalBinary())
	inject := func(code uint8) {
		t.Helper()
		message, err := (ICMPError{Reporter: remote, Type: ICMPv4TypeTimeExceeded, Code: code, QuotedPacket: quote}).ICMPMessage(local)
		if err != nil {
			t.Fatal(err)
		}
		wire := mustTestWire((IPPacket{Source: remote, Destination: local, Protocol: ProtocolICMPv4, HopLimit: 64, Payload: mustTestWire(message.MarshalBinary())}).MarshalBinary())
		if err = writeTestPacket(stack, wire); err != nil {
			t.Fatal(err)
		}
	}
	inject(ICMPv4TimeExceededCodeFragmentReassembly)
	connection.mu.Lock()
	allocated := connection.pending != nil
	connection.mu.Unlock()
	if allocated || connection.takeActorWake() != 0 {
		t.Fatal("reassembly timeout allocated TCP error state or woke its actor")
	}
	inject(ICMPv4TimeExceededCodeTTLInTransit)
	inject(ICMPv4TimeExceededCodeFragmentReassembly)
	queued, ok := connection.takeNetworkError()
	var networkError ICMPError
	if !ok || !errors.As(queued, &networkError) || networkError.Code != ICMPv4TimeExceededCodeTTLInTransit || !bytes.Equal(networkError.QuotedPacket, quote) {
		t.Fatalf("correlated TCP TTL error = %v, %t", queued, ok)
	}
	if queued, ok = connection.takeNetworkError(); ok || queued != nil {
		t.Fatalf("reassembly timeout appended another TCP error: %v, %t", queued, ok)
	}
	if connection.takeActorWake() != tcpActorWakeNetworkError {
		t.Fatal("reportable TCP error did not wake its actor")
	}
}

func TestTCPReadNotificationIsLazyAndCannotMissWake(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	if connection.readNotify != nil {
		t.Fatal("new TCP connection allocated a read notification")
	}
	connection.mu.Lock()
	connection.readBuffer.append([]byte{1})
	connection.notifyReadLocked()
	connection.mu.Unlock()
	var immediate [1]byte
	if n, err := connection.Read(immediate[:]); n != 1 || err != nil || immediate[0] != 1 {
		t.Fatalf("immediate Read = %d, %v, %v", n, err, immediate)
	}
	if connection.readNotify != nil {
		t.Fatal("buffered Read allocated a notification")
	}

	result := make(chan error, 1)
	go func() {
		var value [1]byte
		_, err := connection.Read(value[:])
		if err == nil && value[0] != 2 {
			err = errors.New("blocked Read returned the wrong byte")
		}
		result <- err
	}()
	waitFor(t, time.Second, func() bool {
		connection.mu.Lock()
		initialized := connection.readNotify != nil
		connection.mu.Unlock()
		return initialized
	})
	connection.mu.Lock()
	connection.readBuffer.append([]byte{2})
	connection.notifyReadLocked()
	connection.mu.Unlock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read missed its notification")
	}
}

func TestTCPInboundQueueCompactsConsumedPrefixBeforeGrowing(t *testing.T) {
	queue := newTCPSegmentQueue()
	queue.segments = make([]tcpSegment, 0, 8)
	for index := 0; index < cap(queue.segments); index++ {
		segment := tcpSegment{sequence: uint32(index), payload: []byte{byte(index)}}
		segment.setOptions([]byte{1, byte(index)})
		if !queue.enqueue(segment) {
			t.Fatal("inbound queue rejected a segment")
		}
	}
	backing := &queue.segments[0]
	capacity := cap(queue.segments)
	for index := 0; index < capacity/2; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) {
			t.Fatalf("inbound queue dequeue = %d, %v, want %d, true", segment.sequence, ok, index)
		}
	}
	last := tcpSegment{sequence: uint32(capacity), payload: []byte{byte(capacity)}}
	last.setOptions([]byte{1, byte(capacity)})
	if !queue.enqueue(last) {
		t.Fatal("inbound queue rejected a segment after consuming its prefix")
	}
	if queue.head != 0 || cap(queue.segments) != capacity || &queue.segments[0] != backing {
		t.Fatalf("inbound queue grew instead of compacting: head %d len %d cap %d", queue.head, len(queue.segments), cap(queue.segments))
	}
	for index := capacity / 2; index <= capacity; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) || !bytes.Equal(segment.payload, []byte{byte(index)}) || !bytes.Equal(segment.optionBytes(), []byte{1, byte(index)}) {
			t.Fatalf("compacted inbound queue dequeue = %+v, %v, want sequence %d", segment, ok, index)
		}
	}
}

func BenchmarkTCPInboundQueueSingleSegment(b *testing.B) {
	queue := newTCPSegmentQueue()
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for index := 0; index < tcpMetadataQueueInitial; index++ {
			if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
				b.Fatal("single-segment inbound queue rejected a segment")
			}
		}
		for index := 0; index < tcpMetadataQueueInitial; index++ {
			if _, ok := queue.dequeue(); !ok {
				b.Fatal("single-segment inbound queue lost a segment")
			}
		}
	}
}

func BenchmarkTCPInboundQueueColdBurst(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		queue := newTCPSegmentQueue()
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
				b.Fatal("cold inbound queue rejected a segment")
			}
		}
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if _, ok := queue.dequeue(); !ok {
				b.Fatal("cold inbound queue lost a segment")
			}
		}
	}
}

func BenchmarkTCPInboundQueueSmallBurst(b *testing.B) {
	queue := newTCPSegmentQueue()
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
			b.Fatal("warm-up inbound queue rejected a segment")
		}
	}
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		if _, ok := queue.dequeue(); !ok {
			b.Fatal("warm-up inbound queue lost a segment")
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
				b.Fatal("inbound queue rejected a segment")
			}
		}
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if _, ok := queue.dequeue(); !ok {
				b.Fatal("inbound queue lost a segment")
			}
		}
	}
}

func BenchmarkTCPSendBufferReuse(b *testing.B) {
	for _, size := range []int{1, 8 * 1024, 32 * 1024, 128 * 1024, 256 * 1024, 1024 * 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			payload := make([]byte, size)
			var buffer tcpSendBuffer
			for iteration := 0; iteration < 2; iteration++ {
				buffer.append(payload)
				buffer.acknowledge(len(payload))
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				buffer.append(payload)
				buffer.acknowledge(len(payload))
			}
		})
	}
}

func BenchmarkTCPAcknowledgmentCycle(b *testing.B) {
	const mss = 1200
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(algorithm, func(b *testing.B) {
			for _, name := range []string{"duplicate", "advancing", "SACK-advancing", "SACK-advancing-flight", "SACK-duplicate", "SACK-repeated", "SACK-new-old"} {
				b.Run(name, func(b *testing.B) {
					remainingFlight := name == "SACK-advancing-flight"
					advancing := name == "advancing" || name == "SACK-advancing" || remainingFlight
					oldACK := name == "SACK-new-old"
					selective := name == "SACK-repeated" || oldACK
					start := time.Now()
					stack := &Stack{timestampEpoch: start}
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = stack
					state := tcpEstablishedState{
						connection: connection, peerMSS: mss, peerWindow: 65535,
						peerSACK:         name != "duplicate" && name != "advancing",
						congestionWindow: 10 * mss, slowStartThreshold: 10 * mss,
						sendUnacknowledged: 100, bytesAcknowledged: 100,
						controller: newTCPCongestionController(algorithm),
						rtt:        rttEstimator{srtt: time.Millisecond, minimum: time.Millisecond, rto: time.Second},
					}
					state.controller.initialize(CongestionPhaseOpen, start, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
					var outstanding [2]sentTCPSegment
					segment := tcpSegment{sequence: 200, flags: TCPFlagACK, window: 65535}
					if selective {
						var options [10]byte
						options[0], options[1] = 5, 10
						binary.BigEndian.PutUint32(options[2:6], 100+mss)
						binary.BigEndian.PutUint32(options[6:10], 100+2*mss)
						segment.setOptions(options[:])
					}
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						sentAt := start.Add(time.Duration(iteration) * time.Millisecond)
						stamp := monotonicStampAt(start, sentAt)
						state.congestionWindow = 10 * mss
						state.sendNext = state.sendUnacknowledged + mss
						state.duplicateACKs = 0
						state.outstanding = outstanding[:1]
						state.outstandingBase, state.outstandingHead = outstanding[:0], 0
						outstanding[0] = sentTCPSegment{sequence: state.sendUnacknowledged, end: state.sendNext, firstSent: sentAt.Sub(start), hostQueue: packetQueueTicket{queuedAt: stamp}, state: sentTCPSegmentTransmitted}
						segment.acknowledgement = state.sendUnacknowledged
						if selective || remainingFlight {
							state.outstanding = outstanding[:]
							outstanding[1] = sentTCPSegment{sequence: state.sendNext, end: state.sendNext + mss, firstSent: sentAt.Sub(start), hostQueue: packetQueueTicket{queuedAt: stamp}, state: sentTCPSegmentTransmitted}
							state.sendNext += mss
							state.rackLatestDelivered = tcpRACKSample{}
							if oldACK {
								segment.acknowledgement--
								state.sackedRanges, state.sackedBytes = 0, 0
								outstanding[1].delivery, _ = state.controller.onDataSend(mss, mss, sentAt, stamp, mss, state.congestionWindow, 0, 0, state.rtt.srtt, state.slowStartThreshold)
								outstanding[1].congestionPacketState = state.controller.transmissionState()
							} else if !remainingFlight {
								outstanding[1].state.set(sentTCPSegmentSACKed, true)
								state.sackedRanges, state.sackedBytes = 1, mss
							}
						}
						if advancing {
							outstanding[0].delivery, _ = state.controller.onDataSend(mss, mss, sentAt, stamp, 0, state.congestionWindow, 0, 0, state.rtt.srtt, state.slowStartThreshold)
							outstanding[0].congestionPacketState = state.controller.transmissionState()
							segment.acknowledgement = outstanding[0].end
							if remainingFlight {
								outstanding[1].delivery, _ = state.controller.onDataSend(mss, mss, sentAt, stamp, mss, state.congestionWindow, mss, mss, state.rtt.srtt, state.slowStartThreshold)
								outstanding[1].congestionPacketState = state.controller.transmissionState()
							}
						}
						receivedAt := sentAt.Add(time.Millisecond)
						segment.receivedAt = monotonicStampAt(start, receivedAt)
						update := state.processAcknowledgment(&segment, receivedAt, 0)
						state.updateRetransmissionTimer(update, receivedAt)
					}
					b.StopTimer()
					if remainingFlight && (len(state.outstanding) != 1 || !state.retransmit || state.sendTimer.baseDeadline.IsZero()) {
						b.Fatal("advancing ACK did not retain the remaining flight's loss timer")
					}
				})
			}
		})
	}
}

func BenchmarkTCPReceiveData(b *testing.B) {
	for _, size := range []int{1200, 8948} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			for _, count := range []int{0, 32} {
				b.Run(fmt.Sprintf("queued-%d", count), func(b *testing.B) {
					payload := make([]byte, size)
					capacity := (count + 1) * size
					connection := &TCPConn{receiveCapacity: capacity, readNotify: make(chan struct{})}
					workspace := make([]tcpReceivedPiece, count, count+1)
					next := uint32(100)
					b.ReportAllocs()
					b.SetBytes(int64(capacity))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						connection.readBuffer.reset()
						pieces := workspace[:count]
						for index := range pieces {
							pieces[index] = tcpReceivedPiece{sequence: next + uint32((index+1)*size), payload: payload}
						}
						retained := count * size
						progress, closed := connection.receiveTCPData(next, payload, false, uint32(capacity), 0, &next, &pieces, &retained)
						if !progress || closed || retained != 0 || connection.readBuffer.size != capacity {
							b.Fatal("receive did not deliver the complete contiguous range")
						}
					}
				})
			}
		})
	}
}

func BenchmarkTCPOutOfOrderPressure(b *testing.B) {
	for _, stride := range []int{1, 2} {
		b.Run(fmt.Sprintf("stride-%d", stride), func(b *testing.B) {
			const count = tcpMaximumOutOfOrder
			size := stride * (count + 1)
			connection := &TCPConn{receiveCapacity: size, readNotify: make(chan struct{})}
			payload := bytes.Repeat([]byte{'x'}, size)
			workspace := make([]tcpReceivedPiece, count)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				connection.readBuffer.reset()
				next := uint32(100)
				pieces := workspace[:]
				for index := range pieces {
					pieces[index] = tcpReceivedPiece{sequence: next + uint32(stride*(index+1)), payload: payload[:1:1]}
				}
				retained := count
				incoming := payload[:1:1]
				if stride == 2 {
					incoming = payload
				}
				progress, closed := connection.receiveTCPData(next, incoming, false, uint32(size), 0, &next, &pieces, &retained)
				if !progress || closed || pieces != nil || retained != 0 || connection.outOfOrderUnread.Load() != 0 || next != 100+uint32(size) || connection.readBuffer.size != size {
					b.Fatal("full OFO queue did not deliver its complete gap-filling input")
				}
			}
		})
	}
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "highest-discard", payload: []byte{'x'}},
		{name: "highest-FIN-discard"},
	} {
		b.Run(test.name, func(b *testing.B) {
			const count = tcpMaximumOutOfOrder
			const capacity = 2*(count+1) + 2
			connection := &TCPConn{receiveCapacity: capacity, readNotify: make(chan struct{})}
			next, retained := uint32(100), count
			pieces := make([]tcpReceivedPiece, count)
			for index := range pieces {
				pieces[index] = tcpReceivedPiece{sequence: next + uint32(2*(index+1)), payload: []byte{byte(index)}}
			}
			connection.outOfOrderUnread.Store(count)
			sequence := next + 2*(count+1)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if delivered, closed := connection.receiveTCPData(sequence, test.payload, true, capacity, 0, &next, &pieces, &retained); delivered || closed {
					b.Fatal("discarded input advanced receive state")
				}
			}
			b.StopTimer()
			if next != 100 || len(pieces) != count || retained != count || connection.outOfOrderUnread.Load() != count || connection.readBuffer.size != 0 {
				b.Fatal("discarded input changed the retained queue")
			}
			for index, piece := range pieces {
				if piece.sequence != next+uint32(2*(index+1)) || piece.fin || len(piece.payload) != 1 || piece.payload[0] != byte(index) {
					b.Fatal("discarded input changed a retained range")
				}
			}
		})
	}
}

func BenchmarkTCPSACKRecoveryAccounting(b *testing.B) {
	const mss = 1200
	for _, count := range []int{2, 32, 512} {
		b.Run(fmt.Sprintf("ranges-%d", count), func(b *testing.B) {
			outstanding := make([]sentTCPSegment, count)
			for index := range outstanding {
				outstanding[index] = sentTCPSegment{sequence: uint32(index * mss), end: uint32((index + 1) * mss), state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed}
			}
			var flight uint32
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				outstanding[0].state = sentTCPSegmentTransmitted | sentTCPSegmentRACKLost
				flight = recordTestTCPLosses(outstanding, mss)
				outstanding[0].advanceTransmissionGeneration()
				outstanding[0].state.set(sentTCPSegmentSACKRetried, true)
				outstanding[0].state.set(sentTCPSegmentRACKLost, false)
				flight += sackRecoveryPipe(outstanding, mss)
			}
			runtime.KeepAlive(flight)
		})
	}
}

type tcpRecoveryACKFixture struct {
	initial      tcpEstablishedState
	state        tcpEstablishedState
	original     []sentTCPSegment
	segment      tcpSegment
	ackTime      time.Time
	restoreModel func()
}

func newTCPRecoveryACKFixture(tb testing.TB, algorithm string, count int) *tcpRecoveryACKFixture {
	tb.Helper()
	const mss = 1000
	now := time.Unix(100, 0)
	epoch := now.Add(-time.Second)
	end := uint32(100 + (count-1)*mss)
	window := uint32(count * mss)
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{
		writeBuffer: socketOptionOverride[int]{value: int(window), set: true},
	})
	connection.stack = &Stack{timestampEpoch: epoch}
	fixture := &tcpRecoveryACKFixture{
		initial: tcpEstablishedState{
			connection: connection, controller: newTCPCongestionController(algorithm),
			peerMSS: mss, peerSACK: true, peerWindow: 65_535,
			sendNext: end, recoveryPoint: end, fastRecovery: true,
			congestionWindow: window, slowStartThreshold: window, prrPriorFlight: window,
			rtt: newRTTEstimator(time.Second), outstanding: make([]sentTCPSegment, count),
		},
		original: make([]sentTCPSegment, count),
		segment:  tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 65_535},
		ackTime:  now,
	}
	state := &fixture.initial
	state.rebaseOutstanding()
	state.controller.initialize(CongestionPhaseRecovery, epoch, time.Millisecond, time.Millisecond, window, window, mss, 1)
	if state.controller.usesDeliveryRate() {
		state.deliverySample = new(tcpDeliveryRateSample)
	}
	switch model := state.controller.algorithm.(type) {
	case *renoCongestionControl:
		initial := *model
		fixture.restoreModel = func() { *model = initial }
	case *cubicCongestionControl:
		initial := *model
		fixture.restoreModel = func() { *model = initial }
	case *bbrCongestionControl:
		initial := *model
		fixture.restoreModel = func() { *model = initial }
	case *bbr3CongestionControl:
		initial := *model
		fixture.restoreModel = func() { *model = initial }
	default:
		tb.Fatalf("unsupported recovery ACK controller %T", model)
	}
	for index := range fixture.original {
		start := uint32(100 + (index-1)*mss)
		if index == 0 {
			start = 0
		}
		fixture.original[index] = sentTCPSegment{
			sequence: start, end: uint32(100 + index*mss), state: sentTCPSegmentTransmitted,
			hostQueue: testPacketQueueTicketAt(epoch, now.Add(-500*time.Millisecond)),
			delivery:  tcpDeliverySnapshot{deliveredStamp: 1},
		}
	}
	fixture.original[1].state |= sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost | sentTCPSegmentLossReported | sentTCPSegmentTransmissionLost
	var options [18]byte
	options[0], options[1] = TCPHeaderOptionSACK, 18
	binary.BigEndian.PutUint32(options[2:6], 100)
	binary.BigEndian.PutUint32(options[6:10], 1100)
	binary.BigEndian.PutUint32(options[10:14], end-3*mss)
	binary.BigEndian.PutUint32(options[14:18], end)
	fixture.segment.setOptions(options[:])
	return fixture
}

func (f *tcpRecoveryACKFixture) reset() {
	f.state = f.initial
	f.restoreModel()
	copy(f.state.outstanding, f.original)
	if f.state.deliverySample != nil {
		*f.state.deliverySample = tcpDeliveryRateSample{}
	}
}

func TestTCPRecoveryAcknowledgmentFixture(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, count := range []int{6, 64, 512} {
			t.Run(fmt.Sprintf("%s/ranges-%d", algorithm, count), func(t *testing.T) {
				fixture := newTCPRecoveryACKFixture(t, algorithm, count)
				var want tcpEstablishedState
				for iteration := 0; iteration < 3; iteration++ {
					fixture.reset()
					fixture.state.processAcknowledgment(&fixture.segment, fixture.ackTime, 0)
					state := fixture.state
					if state.sendUnacknowledged != 100 || state.sackedRanges != 4 || state.sackedBytes != 4000 || !state.fastRecovery || state.prrDelivered != 4100 {
						t.Fatalf("iteration %d did not deliver the expected ACK/SACK ranges", iteration)
					}
					if sample := state.deliverySample; sample != nil {
						if !sample.valid || sample.acked != 4100 || sample.delivered != 4100 || state.controller.state.DeliveredBytes != 4100 {
							t.Fatalf("iteration %d rate sample = %+v, delivered total %d", iteration, sample, state.controller.state.DeliveredBytes)
						}
						copy := *sample
						state.deliverySample = &copy
					}
					state.outstanding = append([]sentTCPSegment(nil), state.outstanding...)
					state.outstandingBase = append([]sentTCPSegment(nil), state.outstandingBase...)
					model := reflect.ValueOf(state.controller.algorithm).Elem()
					copy := reflect.New(model.Type())
					copy.Elem().Set(model)
					state.controller.algorithm = copy.Interface().(CongestionController)
					if iteration == 0 {
						want = state
					} else if !reflect.DeepEqual(state, want) {
						t.Fatalf("iteration %d changed the recovery ACK result", iteration)
					}
				}
			})
		}
	}
}

func BenchmarkTCPRecoveryAcknowledgment(b *testing.B) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(algorithm, func(b *testing.B) {
			for _, count := range []int{6, 64, 512} {
				b.Run(fmt.Sprintf("ranges-%d", count), func(b *testing.B) {
					fixture := newTCPRecoveryACKFixture(b, algorithm, count)
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						fixture.reset()
						fixture.state.processAcknowledgment(&fixture.segment, fixture.ackTime, 0)
					}
				})
			}
		})
	}
}

func BenchmarkTCPRTOAccounting(b *testing.B) {
	const mss = 1000
	for _, count := range []int{16, 128, 1024, 8192} {
		b.Run(fmt.Sprintf("ranges-%d", count), func(b *testing.B) {
			b.Run("known-loss", func(b *testing.B) {
				outstanding := make([]sentTCPSegment, count)
				for index := range outstanding {
					outstanding[index] = sentTCPSegment{
						sequence: uint32(index * mss), end: uint32((index + 1) * mss),
						state: sentTCPSegmentTransmitted | sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost | sentTCPSegmentTransmissionLost,
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				var newlyLost, replacementLost bool
				for iteration := 0; iteration < b.N; iteration++ {
					newlyLost, replacementLost = markProvenTCPLosses(outstanding, mss, false)
				}
				b.StopTimer()
				if newlyLost || replacementLost {
					b.Fatal("known losses became new evidence")
				}
			})
			for _, pattern := range []struct {
				name          string
				flags         sentTCPSegmentState
				alternateLoss bool
			}{
				{name: "flight", flags: sentTCPSegmentOriginalLost | sentTCPSegmentRetransmitted, alternateLoss: true},
				{name: "flight-live"},
				{name: "flight-lost", flags: sentTCPSegmentOriginalLost | sentTCPSegmentTransmissionLost},
				{name: "flight-sacked", flags: sentTCPSegmentSACKed},
				{name: "flight-speculative", flags: sentTCPSegmentRetransmitted},
			} {
				b.Run(pattern.name, func(b *testing.B) {
					state := tcpEstablishedState{outstanding: make([]sentTCPSegment, count)}
					for index := range state.outstanding {
						segment := &state.outstanding[index]
						segment.sequence, segment.end = uint32(index*mss), uint32((index+1)*mss)
						segment.state = sentTCPSegmentTransmitted | pattern.flags
						if pattern.alternateLoss && index%2 == 0 {
							segment.state |= sentTCPSegmentTransmissionLost
						}
					}
					var flight uint32
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						flight = state.rtoTransmissionFlight()
					}
					runtime.KeepAlive(flight)
				})
			}
			for _, clock := range []struct {
				suffix string
				now    time.Time
			}{{now: time.Unix(100, 0)}, {suffix: "-monotonic", now: time.Now()}} {
				for _, repeated := range []bool{false, true} {
					name := "timeout-first"
					if repeated {
						name = "timeout-repeated"
					}
					b.Run(name+clock.suffix, func(b *testing.B) {
						now := clock.now
						state := tcpEstablishedState{
							connection: &TCPConn{stack: &Stack{timestampEpoch: now.Add(-time.Second)}},
							controller: newTCPCongestionController(CongestionControlBBR3),
							peerMSS:    mss, peerSACK: true, rtt: newRTTEstimator(time.Second),
							sendNext: uint32(count * mss), congestionWindow: 10 * mss, slowStartThreshold: 20 * mss,
							outstanding: make([]sentTCPSegment, count),
							undo:        new(tcpRecoveryUndo),
						}
						for index := range state.outstanding {
							state.outstanding[index] = sentTCPSegment{sequence: uint32(index * mss), end: uint32((index + 1) * mss), state: sentTCPSegmentTransmitted, hostQueue: packetQueueTicket{queuedAt: 1}}
						}
						state.controller.initialize(CongestionPhaseOpen, now, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
						if repeated {
							state.prepareRetransmission(0, true, false, true, false, 0, now)
							state.outstanding[0].advanceTransmissionGeneration()
						}
						initial := state
						model := state.controller.algorithm.(*bbr3CongestionControl)
						initialModel := *model
						initialSegments := append([]sentTCPSegment(nil), state.outstanding...)
						b.ReportAllocs()
						b.ResetTimer()
						for iteration := 0; iteration < b.N; iteration++ {
							state = initial
							*model = initialModel
							copy(state.outstanding, initialSegments)
							state.prepareRetransmission(0, true, false, true, false, 0, now)
						}
						b.StopTimer()
						if !state.rtoRecovery || !state.undo.active {
							b.Fatal("timeout did not enter recoverable RTO state")
						}
					})
				}
			}
		})
	}
}

func BenchmarkTCPHandlePureACK(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.241")
	remote := netip.MustParseAddr("198.51.100.241")
	_, stack := newTestStack(b, local, remote)
	key := tcpKey{
		local:  netip.AddrPortFrom(local, 8443),
		remote: netip.AddrPortFrom(remote, 49152),
	}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	stack.mu.Lock()
	stack.tcp[key] = connection
	stack.mu.Unlock()
	packet, ok := parseIPPacket(buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), 100, 200, TCPFlagACK, 65535, tcpTimestampOptions(123, 456), nil), false)
	if !ok {
		b.Fatal("failed to parse benchmark packet")
	}
	receivedAt := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := stack.handleTCP(packet, receivedAt, true, false); err != nil {
			b.Fatal(err)
		}
		if _, ok = connection.inbound.dequeue(); !ok {
			b.Fatal("TCP segment was not queued")
		}
	}
}

func BenchmarkTCPTimeWaitACKAdmission(b *testing.B) {
	now := time.Now()
	for _, timestamped := range []bool{false, true} {
		name := "without-timestamp"
		if timestamped {
			name = "with-timestamp"
		}
		b.Run(name, func(b *testing.B) {
			stack := &Stack{}
			connection := &TCPConn{stack: stack, peerTimestamp: true, recentTimestamp: 123}
			state := &tcpEstablishedState{
				connection:          connection,
				receiveNext:         100,
				lastACKSent:         100,
				lastTimestampUpdate: now,
				receiveWindowState:  newTCPReceiveWindow(100, 65535, false, false, 0),
			}
			segment := tcpSegment{sequence: 100, flags: TCPFlagACK}
			if timestamped {
				segment.setOptions(tcpTimestampOptions(123, 456))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if state.handleTimeWaitSegment(segment, now, now) {
					b.Fatal("TIME-WAIT ACK unexpectedly replaced the connection")
				}
			}
		})
	}
}

func TestBuildTCPPacketIntoOverwritesReusedBuffer(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.242")
	target := netip.MustParseAddr("198.51.100.242")
	options := tcpTimestampOptions(123, 456)
	payload := []byte("reused TCP packet")
	_, _, packetSize, err := tcpPacketLayout(source, target, options, len(payload), 1500)
	if err != nil {
		t.Fatal(err)
	}
	want, err := buildTCPPacketInto(make([]byte, packetSize), source, target, 49152, 8443, 100, 200, TCPFlagACK|TCPFlagPSH, 32768, options, payload, 1500, 0x28, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	dirty := make([]byte, packetSize)
	for index := range dirty {
		dirty[index] = 0xff
	}
	got, err := buildTCPPacketInto(dirty, source, target, 49152, 8443, 100, 200, TCPFlagACK|TCPFlagPSH, 32768, options, payload, 1500, 0x28, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reused TCP packet differs:\n got %x\nwant %x", got, want)
	}
}

func TestTCPPublishReservationLifecycle(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.245")
	remote := netip.MustParseAddr("198.51.100.245")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.AddrPortFrom(local, 49152),
		remote: netip.AddrPortFrom(remote, 8443),
	}, 1400, tcpSocketOptionSet{})
	payloadBytes := []byte("reserved publication")
	var payload tcpPayloadView
	payload.setBytes(payloadBytes)
	slot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("TCP publication could not reserve an output slot")
	}
	ticket, err := connection.publishReservedTCP(100, 200, TCPFlagACK|TCPFlagPSH, 32768, nil, &payload, 1400, 0, 0, tcpOutputReservation{
		queue: &stack.outbound, slot: slot,
	}, tcpOutputSequenceRange{unacknowledged: 90, next: 120})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := connection.icmpSequence.Load(), uint64(90)<<32|120; got != want {
		t.Fatalf("published TCP sequence range = %#x, want %#x", got, want)
	}
	if !ticket.pending(stack) {
		t.Fatal("published TCP ticket is not pending")
	}
	entry, available := stack.outbound.tryDequeue()
	if !available {
		t.Fatal("published TCP packet is not queued")
	}
	packet, valid := parseIPPacket(entry.packet, false)
	if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || !bytes.Equal(packet.payload[tcpHeaderSize:], payloadBytes) {
		t.Fatalf("published TCP packet = %x", entry.packet)
	}
	stack.outbound.release(entry)
	if ticket.pending(stack) {
		t.Fatal("TCP ticket remained pending after queue release")
	}
	if got := stack.Stats().OutboundPackets; got != 1 {
		t.Fatalf("outbound packets = %d, want 1", got)
	}
}

func TestTCPPublicationFailureReleasesReservation(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.246")
	remote := netip.MustParseAddr("198.51.100.246")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.AddrPortFrom(local, 49152),
		remote: netip.AddrPortFrom(remote, 8443),
	}, 1400, tcpSocketOptionSet{})
	var payload tcpPayloadView
	payload.setBytes([]byte("invalid packet layout"))
	connection.publishICMPSequenceRange(10, 20)
	slot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("TCP publication could not reserve an output slot")
	}
	_, err = connection.publishReservedTCP(100, 200, TCPFlagACK, 32768, nil, &payload, 39, 0, 0, tcpOutputReservation{
		queue: &stack.outbound, slot: slot,
	}, tcpOutputSequenceRange{unacknowledged: 100, next: 120})
	if err == nil {
		t.Fatal("TCP publication accepted an invalid MTU")
	}
	if stack.outbound.len() != 0 || len(stack.outbound.free) != cap(stack.outbound.free) {
		t.Fatalf("failed TCP publication retained queue state: packets=%d free=%d/%d", stack.outbound.len(), len(stack.outbound.free), cap(stack.outbound.free))
	}
	if got := stack.Stats().OutboundPackets; got != 0 {
		t.Fatalf("failed TCP publication counted %d outbound packets", got)
	}
	if got, want := connection.icmpSequence.Load(), uint64(10)<<32|20; got != want {
		t.Fatalf("failed TCP publication changed sequence range to %#x, want %#x", got, want)
	}
}

func TestTCPPublishRevalidatesReservedOutputQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.247")
	remote := netip.MustParseAddr("198.51.100.247")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.AddrPortFrom(local, 49152),
		remote: netip.AddrPortFrom(remote, 8443),
	}, 1400, tcpSocketOptionSet{})
	connection.publishICMPSequenceRange(10, 20)
	slot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("TCP publication could not reserve the original output queue")
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local, 32), netip.PrefixFrom(remote, 32),
	}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	var payload tcpPayloadView
	_, err = connection.publishReservedTCP(100, 200, TCPFlagACK, 32768, nil, &payload, 1400, 0, 0, tcpOutputReservation{
		queue: &stack.outbound, slot: slot,
	}, tcpOutputSequenceRange{unacknowledged: 100, next: 120})
	if !errors.Is(err, errTCPOutputRouteChanged) {
		t.Fatalf("publication with a stale output queue = %v", err)
	}
	if stack.outbound.len() != 0 || len(stack.outbound.free) != cap(stack.outbound.free) {
		t.Fatalf("stale TCP reservation retained outbound state: packets=%d free=%d/%d", stack.outbound.len(), len(stack.outbound.free), cap(stack.outbound.free))
	}
	if stack.loopback.len() != 0 || len(stack.loopback.free) != cap(stack.loopback.free) {
		t.Fatalf("stale TCP reservation changed loopback state: packets=%d free=%d/%d", stack.loopback.len(), len(stack.loopback.free), cap(stack.loopback.free))
	}
	if got, want := connection.icmpSequence.Load(), uint64(10)<<32|20; got != want {
		t.Fatalf("stale TCP reservation changed sequence range to %#x, want %#x", got, want)
	}
}

func TestTCPSegmentTimestampOptionsUseFixedWorkspace(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.243")
	remote := netip.MustParseAddr("198.51.100.243")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.AddrPortFrom(local, 49152),
		remote: netip.AddrPortFrom(remote, 8443),
	}, 1500, tcpSocketOptionSet{})

	connection.peerTimestamp = true
	connection.recentTimestamp = 0x10203040
	extra := []byte{1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	queue, loopback := stack.outputQueueFor(remote)
	slot, err := stack.tryReservePacket(queue)
	if err != nil {
		t.Fatal(err)
	}
	var payload tcpPayloadView
	published, err := connection.publishReservedPayloadForMTU(100, 200, TCPFlagACK, 32768, extra, &payload, false, 1500, tcpOutputReservation{
		queue: queue, slot: slot, loopback: loopback,
	}, tcpOutputSequenceRange{})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := published.timestamp
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || len(packet.payload) < tcpHeaderSize {
		t.Fatal("timestamped TCP segment could not be parsed")
	}
	headerSize := int(packet.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
		t.Fatalf("timestamped TCP header size = %d", headerSize)
	}
	want := []byte{
		TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10,
		byte(timestamp >> 24), byte(timestamp >> 16), byte(timestamp >> 8), byte(timestamp),
		0x10, 0x20, 0x30, 0x40,
	}
	want = append(want, extra...)
	if got := packet.payload[tcpHeaderSize:headerSize]; !bytes.Equal(got, want) {
		t.Fatalf("timestamped TCP options = %x, want %x", got, want)
	}
	if err = connection.trySendSegmentWithOptions(101, 201, TCPFlagACK, 32768, extra); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || len(packet.payload) < tcpHeaderSize {
		t.Fatal("best-effort timestamped TCP segment could not be parsed")
	}
	headerSize = int(packet.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
		t.Fatalf("best-effort timestamped TCP header size = %d", headerSize)
	}
	got := packet.payload[tcpHeaderSize:headerSize]
	if len(got) != 12+len(extra) || !bytes.Equal(got[:4], []byte{TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10}) ||
		binary.BigEndian.Uint32(got[8:12]) != connection.recentTimestamp || !bytes.Equal(got[12:], extra) {
		t.Fatalf("best-effort timestamped TCP options = %x", got)
	}
	slot, err = stack.tryReservePacket(queue)
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.publishReservedPayloadForMTU(100, 200, TCPFlagACK, 32768, make([]byte, 29), &payload, false, 1500, tcpOutputReservation{
		queue: queue, slot: slot, loopback: loopback,
	}, tcpOutputSequenceRange{})
	if err == nil || err.Error() != "mipstack: invalid TCP options" {
		t.Fatalf("oversized timestamp options error = %v", err)
	}
	if err = connection.trySendSegmentWithOptions(100, 200, TCPFlagACK, 32768, make([]byte, 29)); err == nil || err.Error() != "mipstack: invalid TCP options" {
		t.Fatalf("oversized best-effort timestamp options error = %v", err)
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		stack.outbound.release(entry)
		t.Fatal("oversized timestamp options emitted a packet")
	}
}

func TestTCPActorWakeCoalescesStateChanges(t *testing.T) {
	connection := &TCPConn{inbound: newTCPSegmentQueue()}
	connection.wakeActor(tcpActorWakeSend)
	connection.wakeActor(tcpActorWakeWindow)
	connection.wakeActor(tcpActorWakeOptions | tcpActorWakePathMTU)
	select {
	case <-connection.inbound.notify:
	default:
		t.Fatal("actor wake was not published")
	}
	want := uint32(tcpActorWakeSend | tcpActorWakeWindow | tcpActorWakeOptions | tcpActorWakePathMTU)
	if got := connection.takeActorWake(); got != want {
		t.Fatalf("actor wake flags = %#x, want %#x", got, want)
	}
	select {
	case <-connection.inbound.notify:
		t.Fatal("coalesced actor wake published more than one token")
	default:
	}
	connection.wakeActor(tcpActorWakeSend)
	select {
	case <-connection.inbound.notify:
	default:
		t.Fatal("actor wake did not rearm after consumption")
	}

	connection.takeActorWake()
	if !connection.inbound.enqueue(tcpSegment{sequence: 1}) {
		t.Fatal("packet wake was not queued")
	}
	connection.wakeActor(tcpActorWakeInfo)
	select {
	case <-connection.inbound.notify:
	default:
		t.Fatal("shared packet and state wake was not published")
	}
	if got := connection.takeActorWake(); got != tcpActorWakeInfo {
		t.Fatalf("coalesced packet wake flags = %#x, want %#x", got, tcpActorWakeInfo)
	}
	if segment, ok := connection.inbound.dequeue(); !ok || segment.sequence != 1 {
		t.Fatalf("coalesced packet wake lost segment: %+v, %v", segment, ok)
	}
}

func TestTCPTimerOrderingDrainsPreDeadlineBacklog(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("198.51.100.77"))
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9077))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if _, err = connection.Write([]byte("timer ordering")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		return peer != nil && tcpSequenceGreater(peer.highestClientEnd, peer.clientNext)
	})

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, cumulativeACK := peer.serverNext, peer.highestClientEnd
	link.mu.Unlock()
	baseline := tcpConnection.retransmissions.Load()
	tcpConnection.mu.Lock()
	arrival := time.Now().Add(-time.Second)
	arrivalStamp := monotonicStampAt(tcpConnection.stack.timestampEpoch, arrival)
	queued := true
	for index := 0; index < 2048; index++ {
		queued = tcpConnection.enqueueInbound(tcpSegment{sequence: sequence, window: 65535, receivedAt: arrivalStamp}) && queued
	}
	queued = tcpConnection.enqueueInbound(tcpSegment{
		sequence: sequence, acknowledgement: cumulativeACK, flags: TCPFlagACK, window: 65535, receivedAt: arrivalStamp,
	}) && queued
	time.Sleep(tcpMinimumRTO + 50*time.Millisecond)
	tcpConnection.mu.Unlock()
	if !queued {
		t.Fatal("pre-deadline TCP backlog exceeded its byte capacity")
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.inbound.len() == 0 })
	if retransmissions := tcpConnection.retransmissions.Load(); retransmissions != baseline {
		t.Fatalf("pre-deadline backlog caused %d retransmissions, want 0", retransmissions-baseline)
	}
}

func TestTCPTimerBacklogSnapshotDoesNotGrow(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	var backlog tcpTimerBacklog
	drain, forceTimer := backlog.order(2048, deadline, time.Now())
	if !drain || forceTimer {
		t.Fatalf("initial backlog = drain %t force %t", drain, forceTimer)
	}
	if batchLength := backlog.receiveBatchLength(4096, forceTimer); batchLength != tcpActorReceiveBatch {
		t.Fatalf("initial receive batch = %d, want %d", batchLength, tcpActorReceiveBatch)
	}
	backlog.consumed()
	for remaining := 2047; remaining > 0; remaining-- {
		drain, forceTimer := backlog.order(4096, deadline, time.Now())
		if !drain || forceTimer {
			t.Fatalf("backlog with %d snapshot events = drain %t force %t", remaining, drain, forceTimer)
		}
		if remaining < tcpActorReceiveBatch {
			if batchLength := backlog.receiveBatchLength(4096, forceTimer); batchLength != remaining {
				t.Fatalf("receive batch with %d snapshot events = %d", remaining, batchLength)
			}
		}
		backlog.consumed()
	}
	if drain, forceTimer := backlog.order(4096, deadline, time.Now()); drain || !forceTimer {
		t.Fatalf("drained snapshot = drain %t force %t, want false/true", drain, forceTimer)
	} else if batchLength := backlog.receiveBatchLength(4096, forceTimer); batchLength != 1 {
		t.Fatalf("receive batch at timer boundary = %d, want 1", batchLength)
	}
	if drain, forceTimer := backlog.order(4096, time.Now().Add(time.Second), time.Now()); drain || forceTimer {
		t.Fatalf("future deadline = drain %t force %t, want false/false", drain, forceTimer)
	}
}

func TestTCPConcurrentCloseAndDeadlines(t *testing.T) {
	for _, name := range []string{"Close", "CloseWriteAndClose"} {
		t.Run(name, func(t *testing.T) {
			link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
			defer stack.Close()
			link.echoTCP = true
			link.dropTCPData = 1000
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9106))
			if err != nil {
				t.Fatal(err)
			}
			var wait sync.WaitGroup
			wait.Add(4)
			go func() {
				defer wait.Done()
				_, _ = connection.Write(make([]byte, tcpSendCapacity*2))
			}()
			go func() {
				defer wait.Done()
				_, _ = connection.Read(make([]byte, 1))
			}()
			go func() {
				defer wait.Done()
				for index := 0; index < 100; index++ {
					_ = connection.SetDeadline(time.Now().Add(time.Duration(index+1) * time.Millisecond))
				}
			}()
			go func() {
				defer wait.Done()
				tcpConnection := connection.(*TCPConn)
				for index := 0; index < 100; index++ {
					_ = tcpConnection.SetQuickACK(index%2 == 0)
				}
			}()
			if name == "CloseWriteAndClose" {
				wait.Add(1)
				go func() {
					defer wait.Done()
					for index := 0; index < 100; index++ {
						_ = connection.(*TCPConn).CloseWrite()
					}
				}()
			}
			time.Sleep(5 * time.Millisecond)
			_ = connection.Close()
			done := make(chan struct{})
			go func() {
				wait.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("concurrent socket operations did not terminate")
			}
		})
	}
}

func TestTCPPortReuseByFourTuple(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	first, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9100))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstPort := first.LocalAddr().(*net.TCPAddr).Port
	secondRemote := netip.AddrPortFrom(link.remote, 9101)
	stack.mu.Lock()
	cursor := &stack.nextPort[0]
	offset := automaticTCPPortOffsets(cursor.secret, link.local, secondRemote)[0] % dynamicPortCount
	position := uint32(firstPort - dynamicPortFirst)
	cursor.dynamic = uint16((position + dynamicPortCount - offset) % dynamicPortCount)
	stack.mu.Unlock()
	second, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, secondRemote)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.LocalAddr().(*net.TCPAddr).Port != firstPort {
		t.Fatalf("second local port = %v, want reused %d", second.LocalAddr(), firstPort)
	}
	if stats := stack.Stats(); stats.ActiveTCPConnections != 2 {
		t.Fatalf("active TCP connections = %d, want 2", stats.ActiveTCPConnections)
	}
}

func TestTCPACKPolicy(t *testing.T) {
	epoch := time.Now()
	connection := &TCPConn{stack: &Stack{timestampEpoch: epoch}}
	state := tcpEstablishedState{
		connection: connection, pathMSS: 1460, receiveMSS: 1460,
		receiveNext: 1000, lastACKSent: 1000,
		receiveWindowState: tcpReceiveWindow{right: 1000 + 1024*1024},
		rtt:                rttEstimator{rto: 200 * time.Millisecond},
		ackPending:         true,
		ackPingPong:        true,
	}
	state.replenishQuickACK(tcpMaximumQuickACKs)
	if state.quickACKBudget != tcpMaximumQuickACKs {
		t.Fatalf("quick ACK budget = %d, want %d", state.quickACKBudget, tcpMaximumQuickACKs)
	}
	if !state.ackPending || !state.ackPingPong {
		t.Fatal("budget replenishment discarded pending or ping-pong state")
	}
	state.enterQuickACK(2)
	if state.ackPingPong {
		t.Fatal("enterQuickACK retained ping-pong state")
	}
	state.quickACKBudget = 0
	state.ackPending = false
	state.ackPingPong = true
	state.lastDataReceived = monotonicStampAt(epoch, epoch)
	state.observeReceivedData(epoch.Add(time.Second))
	if state.quickACKBudget != tcpMaximumQuickACKs || !state.ackPingPong {
		t.Fatalf("idle replenishment state = budget %d, ping-pong %t", state.quickACKBudget, state.ackPingPong)
	}
	state.quickACKBudget = 0
	state.enterQuickACK(2)
	if state.quickACKBudget != 2 || state.ackPingPong {
		t.Fatalf("explicit quick ACK state = budget %d, ping-pong %t", state.quickACKBudget, state.ackPingPong)
	}
	state.quickACKBudget = 2
	state.ackPending = true
	state.receiveNext++
	state.commitAcknowledgment(512, state.receiveWindowState.right, 0, false)
	if state.quickACKBudget != 1 || state.ackPending {
		t.Fatalf("committed ACK state = budget %d, pending %t", state.quickACKBudget, state.ackPending)
	}
	state.lastDataReceived = monotonicStampAt(epoch, epoch.Add(time.Second))
	state.observeSentData(monotonicStampAt(epoch, epoch.Add(time.Second+time.Millisecond)))
	if !state.ackPingPong {
		t.Fatal("prompt application response did not enter ping-pong mode")
	}
	state.quickACKBudget = 2
	state.ackPending = true
	state.outOfOrder = []tcpReceivedPiece{{sequence: state.receiveNext + 1, payload: []byte{1}}}
	state.peerSACK = false
	state.commitAcknowledgment(512, state.receiveWindowState.right, 0, false)
	if state.ackPending || state.quickACKBudget != 1 {
		t.Fatalf("non-SACK ACK state = budget %d, pending %t", state.quickACKBudget, state.ackPending)
	}
	state.quickACKBudget = 2
	state.ackPending = true
	state.peerSACK = true
	state.commitAcknowledgment(512, state.receiveWindowState.right, 0, false)
	if !state.ackPending || state.quickACKBudget != 2 {
		t.Fatalf("omitted SACK ACK state = budget %d, pending %t", state.quickACKBudget, state.ackPending)
	}
	state.commitAcknowledgment(512, state.receiveWindowState.right, 0, true)
	if state.ackPending || state.quickACKBudget != 1 {
		t.Fatalf("selective ACK state = budget %d, pending %t", state.quickACKBudget, state.ackPending)
	}
	if state.observeDataECN(2) || !state.ecnDataSeen {
		t.Fatal("first ECT data requested a quick ACK or was not recorded")
	}
	if !state.observeDataECN(0) {
		t.Fatal("non-ECT data after ECT did not request a quick ACK")
	}
	if !state.observeDataECN(3) || !connection.echoCongestion {
		t.Fatal("new CE episode did not request a quick ACK and ECE")
	}
	if state.observeDataECN(3) {
		t.Fatal("continuing CE episode requested another quick ACK transition")
	}
}

func TestTCPReceiveMSSMeasurement(t *testing.T) {
	state := tcpEstablishedState{connection: &TCPConn{}, pathMSS: 1460, receiveMSS: 1460}
	segment := tcpSegment{payload: make([]byte, 536)}
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 1460 || state.lastReceiveSegmentSize != 536 {
		t.Fatalf("first smaller segment = MSS %d candidate %d", state.receiveMSS, state.lastReceiveSegmentSize)
	}
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 536 || state.lastReceiveSegmentSize != 0 {
		t.Fatalf("confirmed smaller segment = MSS %d candidate %d", state.receiveMSS, state.lastReceiveSegmentSize)
	}
	segment = tcpSegment{flags: TCPFlagPSH, payload: make([]byte, 1200)}
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 1200 {
		t.Fatalf("larger segment MSS = %d, want 1200", state.receiveMSS)
	}
	segment = tcpSegment{flags: TCPFlagPSH, payload: make([]byte, 64)}
	state.measureReceiveMSS(&segment)
	segment.flags = 0
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 1200 || state.lastReceiveSegmentSize != 64 {
		t.Fatalf("PSH remnant changed MSS: MSS %d candidate %d", state.receiveMSS, state.lastReceiveSegmentSize)
	}
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 64 {
		t.Fatalf("repeated path-limited segment MSS = %d, want 64", state.receiveMSS)
	}
	state.receiveMSS = 536
	segment = tcpSegment{payload: make([]byte, tcpMinimumPeerMSS-1)}
	state.measureReceiveMSS(&segment)
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 536 || state.lastReceiveSegmentSize != 0 {
		t.Fatalf("sub-minimum MSS changed estimate: MSS %d candidate %d", state.receiveMSS, state.lastReceiveSegmentSize)
	}
	state.pathMSS = 16
	state.receiveMSS = 16
	segment = tcpSegment{payload: []byte{1}}
	state.measureReceiveMSS(&segment)
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 1 || state.lastReceiveSegmentSize != 0 {
		t.Fatalf("legacy low-MTU MSS = %d candidate %d, want 1 and 0", state.receiveMSS, state.lastReceiveSegmentSize)
	}
	state.pathMSS = 1460
	state.connection.peerTimestamp = true
	state.receiveMSS = 1460
	segment = tcpSegment{optionLength: 24, payload: make([]byte, 1188)}
	state.measureReceiveMSS(&segment)
	segment = tcpSegment{optionLength: 32, payload: make([]byte, 1180)}
	state.measureReceiveMSS(&segment)
	if state.receiveMSS != 1200 || state.lastReceiveSegmentSize != 0 {
		t.Fatalf("variable-option MSS = %d candidate %d", state.receiveMSS, state.lastReceiveSegmentSize)
	}
}

func TestTCPQuickACKWakeLastRequestWins(t *testing.T) {
	connection := TCPConn{}
	connection.inbound.notify = make(chan struct{}, 1)
	connection.updateActorWake(tcpActorWakeQuickACKMask, tcpActorWakeQuickACKEnable)
	connection.updateActorWake(tcpActorWakeQuickACKMask, tcpActorWakeQuickACKDisable)
	if wake := connection.takeActorWake(); wake&tcpActorWakeQuickACKMask != tcpActorWakeQuickACKDisable {
		t.Fatalf("last quick ACK wake = %#x, want disable", wake)
	}
	select {
	case <-connection.inbound.notify:
	default:
		t.Fatal("quick ACK wake did not notify the actor")
	}
}

func TestTCPDelayedACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9102))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if err = tcpConnection.SetQuickACK(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	deliver := func(payload byte) {
		link.mu.Lock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		sequence, acknowledgement := peer.serverNext, peer.clientNext
		peer.serverNext++
		link.mu.Unlock()
		if err := link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte{payload}); err != nil {
			t.Fatal(err)
		}
	}
	link.mu.Lock()
	baseline := link.clientACKs
	link.mu.Unlock()
	deliver(1)
	deliver(2)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+1
	})
	link.mu.Lock()
	afterPair := link.clientACKs
	link.mu.Unlock()
	if afterPair != baseline+1 {
		t.Fatalf("ACKs for two segments = %d, want 1", afterPair-baseline)
	}
	deliver(3)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= afterPair+1
	})
	link.mu.Lock()
	afterTimer := link.clientACKs
	link.mu.Unlock()
	deliver(4)
	deliver(5)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= afterTimer+2
	})
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetQuickACK(true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetQuickACK after Close = %v, want net.ErrClosed", err)
	}
}

func TestTCPCompressedSACKScheduling(t *testing.T) {
	state := tcpEstablishedState{}
	state.rtt.srtt = 900 * time.Microsecond
	state.quickACKBudget = 1
	if !state.scheduleSACKACK(time.Unix(0, 0)) {
		t.Fatal("quick-ACK budget did not bypass SACK compression")
	}
	if state.sackACKs != 0 {
		t.Fatalf("quick SACK ACK advanced duplicate counter to %d", state.sackACKs)
	}
	state.clearDelayedACK()
	state.quickACKBudget = 0
	for acknowledgement := 0; acknowledgement < tcpDuplicateACKThreshold; acknowledgement++ {
		if !state.scheduleSACKACK(time.Unix(0, 0)) {
			t.Fatalf("initial SACK ACK %d was compressed", acknowledgement+1)
		}
		state.clearDelayedACK()
	}
	receivedAt := time.Unix(1, 0)
	if state.scheduleSACKACK(receivedAt) {
		t.Fatal("fourth SACK ACK was not compressed")
	}
	if deadline := state.delayedACKDeadline; !deadline.Equal(receivedAt.Add(297 * time.Microsecond)) {
		t.Fatalf("compressed SACK deadline = %v, want %v", deadline, receivedAt.Add(297*time.Microsecond))
	}
	for acknowledgement := 1; acknowledgement < tcpMaximumCompressedSACKs; acknowledgement++ {
		if state.scheduleSACKACK(receivedAt) {
			t.Fatalf("compressed SACK ACK %d flushed before the count limit", acknowledgement+1)
		}
	}
	if !state.scheduleSACKACK(receivedAt) {
		t.Fatal("SACK ACK beyond the compression count limit remained deferred")
	}
	state.clearDelayedACK()
	if state.compressedSACKs != 0 {
		t.Fatalf("sent ACK retained %d compressed SACKs", state.compressedSACKs)
	}
	if delay := tcpCompressedSACKDelay(30 * time.Millisecond); delay != time.Millisecond {
		t.Fatalf("long-RTT compressed SACK delay = %v, want 1ms", delay)
	}
	if delay := tcpCompressedSACKDelay(0); delay != time.Millisecond {
		t.Fatalf("unknown-RTT compressed SACK delay = %v, want 1ms", delay)
	}
}

func TestTCPCompressedSACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.61"), netip.MustParseAddr("198.51.100.61"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9106))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0 && link.tcp[tcpConnection.key.local.Port()] != nil
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	baseline := link.clientACKs
	link.mu.Unlock()
	actorResponse := make(chan TCPConnInfo)
	tcpConnection.mu.Lock()
	if tcpConnection.pending == nil {
		tcpConnection.pending = new(tcpPendingEvents)
	}
	tcpConnection.pending.infoRequests = append(tcpConnection.pending.infoRequests, actorResponse)
	tcpConnection.mu.Unlock()
	tcpConnection.wakeActor(tcpActorWakeInfo)
	waitFor(t, time.Second, func() bool {
		tcpConnection.mu.Lock()
		dequeued := len(tcpConnection.pending.infoRequests) == 0
		tcpConnection.mu.Unlock()
		return dequeued
	})
	for index := uint32(1); index <= 16; index++ {
		if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+index, acknowledgement, TCPFlagACK, 65535, nil, []byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-actorResponse:
	case <-time.After(time.Second):
		t.Fatal("TCP actor did not reach the diagnostic response")
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+4
	})
	time.Sleep(5 * time.Millisecond)
	link.mu.Lock()
	compressed := link.clientACKs - baseline
	link.mu.Unlock()
	if compressed != 4 {
		t.Fatalf("ACKs for 16 out-of-order segments = %d, want 4", compressed)
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte{0}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+5
	})
	received := make([]byte, 17)
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	for index, value := range received {
		if value != byte(index) {
			t.Fatalf("reassembled byte %d = %d", index, value)
		}
	}

	sequence += uint32(len(received))
	link.mu.Lock()
	baseline = link.clientACKs
	link.mu.Unlock()
	for index := uint32(1); index <= 3; index++ {
		if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+index, acknowledgement, TCPFlagACK, 65535, nil, []byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+3, acknowledgement, TCPFlagACK, 65535, nil, []byte{3}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+4
	})
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+4, acknowledgement, TCPFlagACK, 65535, nil, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence+5, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+5
	})
	time.Sleep(5 * time.Millisecond)
	link.mu.Lock()
	immediate := link.clientACKs - baseline
	link.mu.Unlock()
	if immediate != 6 {
		t.Fatalf("SACK, DSACK, post-DSACK quick, and FIN ACKs = %d, want 6", immediate)
	}
}

func TestTCPZeroWindowProbePreservesSequenceSpace(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9105))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.Info().PeerWindow == 0 })
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	if n, writeErr := connection.Write([]byte("probe")); writeErr != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.protocol != ProtocolTCP {
			t.Fatalf("invalid persist packet: %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		if got := binary.BigEndian.Uint32(parsed.payload[4:8]); got != acknowledgement-1 {
			t.Fatalf("persist sequence = %d, want %d", got, acknowledgement-1)
		}
		if data := parsed.payload[headerSize:]; !bytes.Equal(data, tcpZeroWindowProbe[:]) {
			t.Fatalf("persist payload = %x, want %x", data, tcpZeroWindowProbe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for persist probe")
	}
	waitFor(t, time.Second, func() bool { return stack.Stats().TCPZeroWindowProbes == 1 })
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet, false)
		if !ok || parsed.protocol != ProtocolTCP {
			t.Fatalf("invalid post-persist packet: %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		if got := binary.BigEndian.Uint32(parsed.payload[4:8]); got != acknowledgement {
			t.Fatalf("post-persist sequence = %d, want %d", got, acknowledgement)
		}
		if data := parsed.payload[headerSize:]; !bytes.Equal(data, []byte("probe")) {
			t.Fatalf("post-persist payload = %q, want %q", data, "probe")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending data after window update")
	}
}

func TestTCPZeroWindowRetainsOutstandingRetransmission(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9106))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)

	link.mu.Lock()
	link.echoTCP = false
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	for {
		select {
		case <-link.outbound:
		default:
			goto drained
		}
	}

drained:
	if n, writeErr := connection.Write([]byte("outstanding")); writeErr != nil || n != len("outstanding") {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	initialData := false
	deadline := time.After(time.Second)
	for !initialData {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
				continue
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			initialData = headerSize >= tcpHeaderSize && headerSize < len(parsed.payload)
		case <-deadline:
			t.Fatal("timed out waiting for initial data segment")
		}
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return stack.Stats().TCPRetransmissions != 0 })
	stats := stack.Stats()
	if stats.TCPRetransmissions == 0 {
		t.Fatal("outstanding data lost its retransmission timer during zero window")
	}
	if stats.TCPZeroWindowProbes != 0 {
		t.Fatalf("zero-window probes with packets_out = %d, want 0", stats.TCPZeroWindowProbes)
	}
}

func TestTCPZeroWindowConsumesInOrderFIN(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.echoTCP = true
	connectionNet, err := (&Dialer{Options: []SocketOption{SocketOptions.ReadBuffer(1)}}).DialTCP(
		context.Background(), stack, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 9107))
	if err != nil {
		t.Fatal(err)
	}
	connection := connectionNet.(*TCPConn)
	defer connection.Close()

	link.mu.Lock()
	peer := link.tcp[connection.key.local.Port()]
	if peer == nil {
		link.mu.Unlock()
		t.Fatal("TCP peer state was not created")
	}
	dataSequence, acknowledgement := peer.serverNext, peer.clientNext
	peer.serverNext++
	link.echoTCP = false
	link.mu.Unlock()

	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), dataSequence, acknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte{'x'}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		info := connection.Info()
		return info.ReceiveBufferSize == 1 && info.ReceiveWindow == 0
	})
	readACK := func(want uint32) (uint16, byte) {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			select {
			case packet := <-link.outbound:
				parsed, ok := parseIPPacket(packet, false)
				if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
					continue
				}
				tcp := parsed.payload
				headerSize := int(tcp[12]>>4) * 4
				if headerSize < tcpHeaderSize || headerSize > len(tcp) {
					continue
				}
				if tcp[13]&TCPFlagACK != 0 && binary.BigEndian.Uint32(tcp[8:12]) == want {
					return binary.BigEndian.Uint16(tcp[14:16]), tcp[13]
				}
			case <-deadline:
				t.Fatalf("timed out waiting for TCP ACK %d", want)
				return 0, 0
			}
		}
	}
	if window, _ := readACK(dataSequence + 1); window != 0 {
		t.Fatalf("window after filling one-byte receive buffer = %d, want zero", window)
	}

	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), dataSequence+1, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, []byte{'y'}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().State == TCPStateEstablished })
	if _, flags := readACK(dataSequence + 1); flags&TCPFlagFIN != 0 {
		t.Fatal("zero-window data plus FIN unexpectedly closed the stream")
	}

	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), dataSequence+2, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().State == TCPStateEstablished })
	if _, flags := readACK(dataSequence + 1); flags&TCPFlagFIN != 0 {
		t.Fatal("out-of-window FIN unexpectedly closed the stream")
	}

	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), dataSequence+1, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.Info().State == TCPStateCloseWait })
	if window, _ := readACK(dataSequence + 2); window != 0 {
		t.Fatalf("window after zero-window FIN = %d, want zero", window)
	}
	if err := connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 1 || readErr != nil {
		t.Fatalf("buffered byte before EOF = %d, %v", n, readErr)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("zero-window FIN read = %d, %v; want 0, EOF", n, readErr)
	}
}

func TestTCPTimestampsPAWSAndMSS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9103))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if !tcpConnection.peerTimestamp {
		t.Fatal("TCP timestamps were not negotiated")
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x4a}, 1300)
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(connection, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	maximumPayload := link.maximumTCPData
	link.mu.Unlock()
	if maximumPayload != 1268 {
		t.Fatalf("timestamped TCP payload = %d, want 1268", maximumPayload)
	}

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	stale := buildTestTCP(link.remote, link.local, tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, tcpTimestampOptions(1, 0), []byte("stale"))
	if err = writeTestPacket(stack, stale); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, readErr := connection.Read(make([]byte, 5)); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("PAWS stale read = %d, %v", n, readErr)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	link.mu.Lock()
	peer.serverNext += 5
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	fresh := make([]byte, 5)
	if _, err = io.ReadFull(connection, fresh); err != nil || string(fresh) != "fresh" {
		t.Fatalf("fresh timestamp read = %q, %v", fresh, err)
	}
}

func TestTCPPureACKAdvancesPAWS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9108))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	baseTimestamp := peer.timestamp
	link.mu.Unlock()
	deliver := func(timestamp uint32, payload []byte) {
		t.Helper()
		packet := buildTestTCP(link.remote, link.local, tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, tcpTimestampOptions(timestamp, 0), payload)
		if writeErr := writeTestPacket(stack, packet); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	deliver(baseTimestamp+100, nil)
	deliver(baseTimestamp+1, []byte("data"))
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	payload := make([]byte, 4)
	if n, readErr := connection.Read(payload); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("stale data after newer pure ACK = %d, %v", n, readErr)
	}
	deliver(baseTimestamp+101, []byte("data"))
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(connection, payload); err != nil || string(payload) != "data" {
		t.Fatalf("fresh data after newer pure ACK = %q, %v", payload, err)
	}
}

func TestTCPMissingTimestampRemainsCompatible(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9109))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	serverPort := tcpConnection.key.remote.Port()
	clientPort := tcpConnection.key.local.Port()
	link.mu.Unlock()
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	if _, err = connection.Write([]byte("seed")); err != nil {
		t.Fatal(err)
	}
	var seedPacket []byte
	select {
	case seedPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for seed TCP packet")
	}
	seedParsed, ok := parseIPPacket(seedPacket, false)
	if !ok || len(seedParsed.payload) < tcpHeaderSize {
		t.Fatalf("seed TCP packet = %x", seedPacket)
	}
	seedHeaderSize := int(seedParsed.payload[12]>>4) * 4
	_, baseTimestamp, timestampPresent := parseTCPTimestamp(seedParsed.payload[tcpHeaderSize:seedHeaderSize])
	if !timestampPresent || baseTimestamp == 0 {
		t.Fatal("timestamp negotiation did not establish a TCP timestamp echo")
	}
	missingTimestamp := buildTestTCP(link.remote, link.local, serverPort, clientPort, sequence, acknowledgement, TCPFlagACK|TCPFlagPSH, 65535, nil, []byte("without-ts"))
	if err = writeTestPacket(stack, missingTimestamp); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len("without-ts"))
	if _, err = io.ReadFull(connection, received); err != nil || string(received) != "without-ts" {
		t.Fatalf("missing-timestamp payload = %q, %v", received, err)
	}
	var ackPacket []byte
	select {
	case ackPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for missing-timestamp ACK")
	}
	ackParsed, ok := parseIPPacket(ackPacket, false)
	if !ok || len(ackParsed.payload) < tcpHeaderSize {
		t.Fatalf("missing-timestamp ACK = %x", ackPacket)
	}
	ackHeaderSize := int(ackParsed.payload[12]>>4) * 4
	_, acknowledgementEcho, timestampPresent := parseTCPTimestamp(ackParsed.payload[tcpHeaderSize:ackHeaderSize])
	if !timestampPresent || acknowledgementEcho != baseTimestamp {
		t.Fatalf("missing-timestamp ACK TSecr = %d, want unchanged %d", acknowledgementEcho, baseTimestamp)
	}
	missingFIN := buildTestTCP(link.remote, link.local, serverPort, clientPort, sequence+uint32(len(received)), acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil)
	if err = writeTestPacket(stack, missingFIN); err != nil {
		t.Fatal(err)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("missing-timestamp FIN read = %d, %v", n, readErr)
	}
}

func TestTCPPAWSPrecedesWindowAdmission(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9110))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	link.echoTCP = false
	peer := link.tcp[tcpConnection.key.local.Port()]
	serverNext := peer.serverNext
	serverPort := tcpConnection.key.remote.Port()
	clientPort := tcpConnection.key.local.Port()
	link.mu.Unlock()
	const pending = "pending"
	if _, err = connection.Write([]byte(pending)); err != nil {
		t.Fatal(err)
	}
	var dataPacket []byte
	select {
	case dataPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending TCP packet")
	}
	dataParsed, ok := parseIPPacket(dataPacket, false)
	if !ok || dataParsed.protocol != ProtocolTCP || len(dataParsed.payload) < tcpHeaderSize {
		t.Fatalf("pending TCP packet = %x", dataPacket)
	}
	dataSequence := binary.BigEndian.Uint32(dataParsed.payload[4:8])
	_ = tcpConnection.Info()
	stale := buildTestTCP(link.remote, link.local, serverPort, clientPort, serverNext+tcpReceiveCapacity+1,
		dataSequence+1, TCPFlagACK, 0, tcpTimestampOptions(1, 0), nil)
	if err = writeTestPacket(stack, stale); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	var parsed ipPacket
	for {
		select {
		case challenge := <-link.outbound:
			candidate, candidateOK := parseIPPacket(challenge, false)
			if !candidateOK || candidate.protocol != ProtocolTCP || len(candidate.payload) < tcpHeaderSize {
				continue
			}
			headerSize := int(candidate.payload[12]>>4) * 4
			if headerSize < tcpHeaderSize || headerSize > len(candidate.payload) || len(candidate.payload) != headerSize {
				continue
			}
			parsed = candidate
		case <-deadline.C:
			t.Fatal("timed out waiting for PAWS challenge")
		}
		if parsed.payload != nil {
			break
		}
	}
	if got := binary.BigEndian.Uint32(parsed.payload[4:8]); got != dataSequence+uint32(len(pending)) {
		t.Fatalf("PAWS challenge sequence = %d, want current send next %d", got, dataSequence+uint32(len(pending)))
	}
}

func TestTCPRecentTimestampWaitsForValidACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("192.0.2.6"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9111))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	link.echoTCP = false
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement, timestamp := peer.serverNext, peer.clientNext, peer.timestamp
	serverPort, clientPort := tcpConnection.key.remote.Port(), tcpConnection.key.local.Port()
	link.mu.Unlock()
	if timestamp == 0 || tcpConnection.recentTimestamp != timestamp {
		t.Fatalf("initial TS.Recent = %d, peer timestamp = %d", tcpConnection.recentTimestamp, timestamp)
	}
	for _, test := range []struct {
		name  string
		flags byte
		ack   uint32
		seq   uint32
	}{
		{name: "invalid ACK", flags: TCPFlagACK, ack: acknowledgement + 1, seq: sequence},
		{name: "ACK before acknowledged history", flags: TCPFlagACK, ack: acknowledgement - 5, seq: sequence},
		{name: "RST", flags: TCPFlagRST | TCPFlagACK, ack: acknowledgement, seq: sequence + 1},
		{name: "SYN", flags: TCPFlagSYN | TCPFlagACK, ack: acknowledgement, seq: sequence},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := buildTestTCP(link.remote, link.local, serverPort, clientPort, test.seq, test.ack, test.flags, 65535, tcpTimestampOptions(timestamp+1000, 0), nil)
			if err := writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			_ = tcpConnection.Info()
			_ = tcpConnection.Info()
			if got := tcpConnection.recentTimestamp; got != timestamp {
				t.Fatalf("TS.Recent after %s = %d, want %d", test.name, got, timestamp)
			}
		})
	}
	replayed := buildTestTCP(link.remote, link.local, serverPort, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, tcpTimestampOptions(timestamp-1, 0), nil)
	if err := writeTestPacket(stack, replayed); err != nil {
		t.Fatal(err)
	}
	_ = tcpConnection.Info()
	_ = tcpConnection.Info()
	if got := tcpConnection.recentTimestamp; got != timestamp {
		t.Fatalf("TS.Recent after tolerated one-tick replay = %d, want %d", got, timestamp)
	}
	validTimestamp := timestamp + 100
	valid := buildTestTCP(link.remote, link.local, serverPort, clientPort, sequence, acknowledgement, TCPFlagACK, 65535, tcpTimestampOptions(validTimestamp, 0), nil)
	if err := writeTestPacket(stack, valid); err != nil {
		t.Fatal(err)
	}
	_ = tcpConnection.Info()
	_ = tcpConnection.Info()
	if got := tcpConnection.recentTimestamp; got != validTimestamp {
		t.Fatalf("TS.Recent after valid ACK = %d, want %d", got, validTimestamp)
	}
}

func TestTCPPAWSLinuxRules(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name          string
		tsval, recent uint32
		age           time.Duration
		window        uint32
		reject        bool
	}{
		{name: "equal", tsval: 100, recent: 100, window: 0},
		{name: "one tick replay", tsval: 99, recent: 100, window: 1},
		{name: "older than replay", tsval: 98, recent: 100, window: 1, reject: true},
		{name: "zero recent", tsval: 1, recent: 0, window: 0},
		{name: "fresh lifetime boundary", tsval: 1, recent: 100, age: 2147*time.Second - time.Nanosecond, reject: true},
		{name: "exact lifetime boundary", tsval: 1, recent: 100, age: 2147 * time.Second},
		{name: "expired recent", tsval: 1, recent: 100, age: 2148 * time.Second},
		{name: "microsecond clock before expiry", tsval: 2_400_000_100, recent: 100, age: 2146 * time.Second, reject: true},
		{name: "microsecond clock after idle", tsval: 2_400_000_100, recent: 100, age: 40 * time.Minute},
		{name: "millisecond clock after idle", tsval: 2_400_100, recent: 100, age: 40 * time.Minute},
		{name: "serial wrap", tsval: 1, recent: ^uint32(0), window: 0},
		{name: "serial wrap older", tsval: ^uint32(0), recent: 1, window: 0, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpPAWSReject(test.tsval, test.recent, now.Add(-test.age), now, test.window); got != test.reject {
				t.Fatalf("PAWS reject = %v, want %v", got, test.reject)
			}
		})
	}
}

func TestTCPPAWSHighFrequencyRecovery(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		local, remote := netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("192.0.2.6")
		if ipv6 {
			name = "ipv6"
			local, remote = netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8::6")
		}
		t.Run(name, func(t *testing.T) {
			link, stack := newTestStack(t, local, remote)
			link.mu.Lock()
			link.echoTCP, link.timestampTCP = true, true
			link.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 9112))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			c := connection.(*TCPConn)
			link.mu.Lock()
			link.echoTCP = false
			peer := link.tcp[c.key.local.Port()]
			sequence, acknowledgement, seedTimestamp := peer.serverNext, peer.clientNext, peer.timestamp+100
			link.mu.Unlock()
			start := time.Now().Add(time.Second)
			inject := func(seq, ack, tsval uint32, at time.Time, payload string) {
				t.Helper()
				wire := buildTestTCP(remote, local, c.key.remote.Port(), c.key.local.Port(), seq, ack, TCPFlagACK|TCPFlagPSH, 65535, tcpTimestampOptions(tsval, 0), []byte(payload))
				packet, ok := parseIPPacket(wire, false)
				if !ok {
					t.Fatal("invalid fixture IP packet")
				}
				if err := stack.handleTCP(packet, at, true, false); err != nil {
					t.Fatal(err)
				}
			}
			read := func(want string) {
				t.Helper()
				_ = connection.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, len(want))
				if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != want {
					t.Fatalf("received %q, %v; want %q", buffer, err, want)
				}
			}
			assertACK := func(wantAck, wantEcho uint32) {
				t.Helper()
				deadline := time.NewTimer(time.Second)
				defer deadline.Stop()
				for {
					select {
					case wire := <-link.outbound:
						packet, ok := parseIPPacket(wire, false)
						if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize || binary.BigEndian.Uint32(packet.payload[8:12]) != wantAck {
							continue
						}
						headerSize := int(packet.payload[12]>>4) * 4
						_, echo, present := parseTCPTimestamp(packet.payload[tcpHeaderSize:headerSize])
						if !present || echo != wantEcho {
							t.Fatalf("ACK timestamp echo = %d, present:%v; want %d", echo, present, wantEcho)
						}
						return
					case <-deadline.C:
						t.Fatalf("no ACK for sequence %d", wantAck)
					}
				}
			}
			assertRejected := func() {
				t.Helper()
				_ = connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				var buffer [16]byte
				if n, err := connection.Read(buffer[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("rejected segment delivered %q, %v", buffer[:n], err)
				}
			}
			inject(sequence, acknowledgement, seedTimestamp, start, "seed")
			read("seed")
			sequence += 4
			assertACK(sequence, seedTimestamp)
			inject(sequence, acknowledgement, seedTimestamp-2, start.Add(2147*time.Second-time.Nanosecond), "stale")
			assertRejected()
			recoveredTimestamp := seedTimestamp + 2_400_000_000
			recoveredAt := start.Add(40 * time.Minute)
			inject(sequence, acknowledgement+1, recoveredTimestamp+100, recoveredAt, "bad ACK")
			inject(sequence+1<<30, acknowledgement, recoveredTimestamp+100, recoveredAt, "bad sequence")
			assertRejected()
			inject(sequence, acknowledgement, recoveredTimestamp, recoveredAt, "recovered")
			read("recovered")
			sequence += uint32(len("recovered"))
			assertACK(sequence, recoveredTimestamp)
			inject(sequence, acknowledgement, recoveredTimestamp-2, recoveredAt.Add(time.Second), "replay")
			assertRejected()
			inject(sequence, acknowledgement, recoveredTimestamp+1, recoveredAt.Add(2*time.Second), "fresh")
			read("fresh")
			sequence += uint32(len("fresh"))
			assertACK(sequence, recoveredTimestamp+1)
		})
	}
}

func BenchmarkTCPPAWS(b *testing.B) {
	now := time.Now()
	for _, test := range []struct {
		name  string
		tsval uint32
		age   time.Duration
	}{
		{name: "increasing", tsval: 101},
		{name: "equal", tsval: 100},
		{name: "stale", tsval: 98, age: time.Second},
		{name: "expired", tsval: 2_400_000_100, age: 40 * time.Minute},
	} {
		b.Run(test.name, func(b *testing.B) {
			recentAt := now.Add(-test.age)
			rejections := 0
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if tcpPAWSReject(test.tsval, 100, recentAt, now, tcpPAWSReplayWindow) {
					rejections++
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(rejections)/float64(b.N), "reject/op")
		})
	}
}

func TestTCPPAWSDisorderedACK(t *testing.T) {
	state := &tcpEstablishedState{
		connection:         &TCPConn{recentTimestamp: 100},
		receiveNext:        1000,
		sendUnacknowledged: 2000,
		peerWindow:         4096,
		peerWindowSequence: 1000,
		rtt:                rttEstimator{rto: 10 * time.Millisecond},
	}
	if drop, accept := tcpPAWSDisorderedACK(tcpSegment{sequence: 999, acknowledgement: 2000, flags: TCPFlagACK}, state, 90); !drop || accept {
		t.Fatalf("old duplicate ACK decision = drop:%v accept:%v, want drop only", drop, accept)
	}
	if drop, accept := tcpPAWSDisorderedACK(tcpSegment{sequence: 1000, acknowledgement: 2000, window: 4096, flags: TCPFlagACK}, state, 90); drop || !accept {
		t.Fatalf("replay-window duplicate ACK decision = drop:%v accept:%v, want accept only", drop, accept)
	}
	if drop, accept := tcpPAWSDisorderedACK(tcpSegment{sequence: 1000, acknowledgement: 2000, window: 0, flags: TCPFlagACK}, state, 90); drop || accept {
		t.Fatalf("window-update ACK decision = drop:%v accept:%v, want ordinary PAWS reject", drop, accept)
	}
	if drop, accept := tcpPAWSDisorderedACK(tcpSegment{sequence: 1000, acknowledgement: 2000, window: 4096, flags: TCPFlagACK}, state, 80); drop || accept {
		t.Fatalf("out-of-replay-window ACK decision = drop:%v accept:%v, want ordinary PAWS reject", drop, accept)
	}
}

func TestTCPECNNegotiation(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9104))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if !connection.(*TCPConn).peerECN {
		t.Fatal("ECN was not negotiated")
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	link.mu.Lock()
	baselineECE, baselineCWR := link.clientECEs, link.clientCWRs
	link.markTCPCE = true
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("marked CE"))
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientECEs > baselineECE
	})
	link.mu.Lock()
	link.sendTCPECE = true
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("echo congestion"))
	link.mu.Lock()
	link.sendTCPECE = false
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("send CWR"))
	link.mu.Lock()
	ectPackets, cwrPackets := link.clientECTPackets, link.clientCWRs
	link.mu.Unlock()
	if ectPackets < 3 {
		t.Fatalf("ECT data packets = %d, want at least 3", ectPackets)
	}
	if cwrPackets <= baselineCWR {
		t.Fatal("client did not acknowledge ECE with CWR")
	}
}

type minimumWindowCongestionControl struct{}

func (*minimumWindowCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventInitialize {
		event.State.CongestionWindow = uint32(event.State.MaximumSegmentSize)
	}
}

func TestTCPECNMinimumWindowACKRestartsRTO(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.disableTCPSACK = true
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: "minimum-window-test",
		New:  func(CongestionControlContext) CongestionController { return new(minimumWindowCongestionControl) },
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := Dialer{Options: []SocketOption{SocketOptions.CongestionControlFactory(factory)}}
	connection, err := dialer.DialTCP(context.Background(), stack, "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9109))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	rto := tcpConnection.Info().RetransmissionTimeout
	link.mu.Lock()
	link.sendTCPECE = true
	link.partialTCPACK = 1
	link.delayTCPACK = rto / 2
	link.mu.Unlock()
	_ = connection.SetDeadline(time.Now().Add(4 * rto))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x5e}, 1200))
	baseline := tcpConnection.Info().Retransmissions
	if baseline != 0 {
		t.Fatalf("pre-ACK retransmissions = %d, want 0", baseline)
	}
	time.Sleep(3 * rto / 4)
	if retransmissions := tcpConnection.Info().Retransmissions; retransmissions != baseline {
		t.Fatalf("pre-deadline ECN hold caused retransmissions = %d, want %d", retransmissions, baseline)
	}
}

func TestTCPRetransmissionsAreNotECT(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9107))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	link.mu.Lock()
	baselineCWR := link.clientCWRs
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("retransmitted without ECT"))
	writeAndReadTCPEcho(t, connection, []byte("advance past TLP"))
	writeAndReadTCPEcho(t, connection, []byte("carry CWR"))
	link.mu.Lock()
	initialECT, retransmittedECT, cwrPackets := link.clientECTPackets, link.clientRetransmittedECT, link.clientCWRs
	link.mu.Unlock()
	if initialECT == 0 {
		t.Fatal("initial ECN-capable data was not marked ECT")
	}
	if retransmittedECT != 0 {
		t.Fatalf("ECT-marked retransmissions = %d, want 0", retransmittedECT)
	}
	if cwrPackets <= baselineCWR {
		t.Fatal("loss recovery did not send CWR on subsequent new data")
	}
}

func TestTCPECNSYNFallback(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.dropECNSYN = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9108))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.(*TCPConn).peerECN {
		t.Fatal("fallback connection unexpectedly negotiated ECN")
	}
	link.mu.Lock()
	legacySYNs := link.legacySYNSends
	link.mu.Unlock()
	if legacySYNs == 0 {
		t.Fatal("connection did not retry with a legacy SYN")
	}
}

func TestTCPDelayedECNSYNACKDoesNotUndoFallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.74")
	remote := netip.MustParseAddr("198.51.100.74")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 45000), remote: netip.AddrPortFrom(remote, 8080),
	}, 1400, tcpSocketOptionSet{})

	result := make(chan error, 1)
	go func() { result <- testTCPHandshake(connection, 1000) }()
	readSYN := func() []byte {
		select {
		case packet := <-link.outbound:
			return packet
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for active SYN")
			return nil
		}
	}
	first := readSYN()
	parsed, ok := parseIPPacket(first, false)
	if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13]&(TCPFlagECE|TCPFlagCWR) != TCPFlagECE|TCPFlagCWR {
		t.Fatalf("initial setup SYN = %x", first)
	}
	second := readSYN()
	parsed, ok = parseIPPacket(second, false)
	if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13]&(TCPFlagECE|TCPFlagCWR) != 0 {
		t.Fatalf("fallback SYN = %x", second)
	}
	enqueueTCPTestSegment(t, connection, tcpSegment{
		sequence: 2000, acknowledgement: 1001, flags: TCPFlagSYN | TCPFlagACK | TCPFlagECE, window: 65535,
	})
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delayed ECN SYN-ACK did not complete fallback handshake")
	}
	if connection.peerECN {
		t.Fatal("delayed setup SYN-ACK re-enabled ECN after fallback")
	}
}

func TestTCPRejectsUnboundPort(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	syn := buildTestTCP(link.remote, link.local, 40000, 9000, 100, 0, TCPFlagSYN, 65535, nil, nil)
	if err := writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response, false)
		if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13] != TCPFlagRST|TCPFlagACK || binary.BigEndian.Uint32(parsed.payload[8:12]) != 101 {
			t.Fatalf("invalid TCP reset: %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP reset")
	}
}

func TestTCPReservedHeaderBitsAreIgnored(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.92")
	remote := netip.MustParseAddr("198.51.100.92")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildTestTCP(remote, local, 50000, 50001, 1, 0, TCPFlagSYN, 65535, nil, nil)
	tcp := packet[20:]
	tcp[12] |= 0x02
	tcp[16], tcp[17] = 0, 0
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(remote, local, ProtocolTCP, tcp))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("reserved TCP header bits dropped packets = %d, want 0", dropped)
	}
	if entry, ok := waitTestPacketEntry(&stack.outbound, time.Second); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		parsed, ok := parseIPPacket(response, false)
		if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13] != TCPFlagRST|TCPFlagACK {
			t.Fatalf("reserved TCP header response = %x", response)
		}
	} else {
		t.Fatal("reserved TCP header was not processed")
	}
}

func TestRTTSampleIsSaturatedBeforeArithmetic(t *testing.T) {
	estimator := rttEstimator{}
	estimator.observeAt(time.Duration(1<<63-1), 1)
	if estimator.srtt != tcpMaximumRTO || estimator.rto != tcpMaximumRTO || estimator.minimum != tcpMaximumRTO {
		t.Fatalf("saturated RTT estimator = srtt %v rto %v minimum %v", estimator.srtt, estimator.rto, estimator.minimum)
	}
}

func TestTCPRFC6069RTOBackoffRevert(t *testing.T) {
	estimator := newRTTEstimator(time.Second)
	estimator.backoff()
	estimator.backoff()
	quote := make([]byte, 8)
	binary.BigEndian.PutUint32(quote[4:8], 100)
	networkUnreachable := ICMPError{
		Type: 3, Code: 0, QuotedSource: netip.MustParseAddr("192.0.2.1"), QuotedPayload: quote,
	}
	if !tcpRevertRTOBackoff(networkUnreachable, 100, 2, &estimator) || estimator.rto != 2*time.Second || estimator.backoffs != 1 {
		t.Fatalf("RFC 6069 IPv4 revert = RTO %v backoffs %d", estimator.rto, estimator.backoffs)
	}
	if tcpRevertRTOBackoff(networkUnreachable, 101, 2, &estimator) {
		t.Fatal("RFC 6069 accepted a quote outside SND.UNA")
	}
	portUnreachable := networkUnreachable
	portUnreachable.Code = 3
	if tcpRevertRTOBackoff(portUnreachable, 100, 2, &estimator) {
		t.Fatal("RFC 6069 accepted port unreachable")
	}
	ipv6NoRoute := ICMPError{
		Type: 1, Code: 0, QuotedSource: netip.MustParseAddr("2001:db8::1"), QuotedPayload: quote,
	}
	if !tcpRevertRTOBackoff(ipv6NoRoute, 100, 2, &estimator) || estimator.rto != time.Second || estimator.backoffs != 0 {
		t.Fatalf("RFC 6069 IPv6 revert = RTO %v backoffs %d", estimator.rto, estimator.backoffs)
	}

	capped := newRTTEstimator(80 * time.Second)
	capped.backoff()
	capped.backoff()
	if capped.rto != tcpMaximumRTO || !capped.revertBackoff() || capped.rto != tcpMaximumRTO || !capped.revertBackoff() || capped.rto != 80*time.Second {
		t.Fatalf("capped RTO revert = RTO %v backoffs %d", capped.rto, capped.backoffs)
	}
}

func TestTCPMinimumRTTAdaptsToLongerPath(t *testing.T) {
	var filter tcpMinimumRTTFilter
	start := monotonicStamp(1)
	if minimum := filter.observe(start, 10*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("initial minimum RTT = %v", minimum)
	}
	if minimum := filter.observe(start+monotonicStamp(tcpMinimumRTTWindow/4+time.Second), 20*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("quarter-window minimum RTT = %v", minimum)
	}
	if minimum := filter.observe(start+monotonicStamp(tcpMinimumRTTWindow/2+time.Second), 30*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("half-window minimum RTT = %v", minimum)
	}
	if minimum := filter.observe(start+monotonicStamp(tcpMinimumRTTWindow+time.Second), 40*time.Millisecond); minimum != 20*time.Millisecond {
		t.Fatalf("expired path minimum RTT = %v, want 20ms", minimum)
	}
	if minimum := filter.observe(start+monotonicStamp(tcpMinimumRTTWindow+2*time.Second), 5*time.Millisecond); minimum != 5*time.Millisecond {
		t.Fatalf("new lower minimum RTT = %v, want 5ms", minimum)
	}
}

func TestPublicTCPSegmentCodec(t *testing.T) {
	tests := []TCPSegment{
		{
			Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("198.51.100.2:443"),
			SequenceNumber: 0x12345678, AcknowledgmentNumber: 0x87654321,
			Flags:      TCPFlagNS | TCPFlagCWR | TCPFlagECE | TCPFlagURG | TCPFlagACK | TCPFlagPSH | TCPFlagSYN,
			WindowSize: 32768, UrgentPointer: 7, Options: []byte{2, 4, 0x05, 0xb4, 1}, Payload: []byte("tcp-v4-payload"),
		},
		{
			Source: netip.MustParseAddrPort("[2001:db8::1]:23456"), Destination: netip.MustParseAddrPort("[2001:db8::2]:8443"),
			SequenceNumber: 11, AcknowledgmentNumber: 29, Flags: TCPFlagACK | TCPFlagFIN,
			WindowSize: 65535, Payload: []byte("tcp-v6-payload"),
		},
	}
	for _, test := range tests {
		name := "IPv4"
		if test.Source.Addr().Is6() {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			prefix := []byte{1, 2, 3}
			wire, err := test.AppendBinary(append([]byte(nil), prefix...))
			if err != nil {
				t.Fatalf("append TCP: %v", err)
			}
			if !bytes.Equal(wire[:len(prefix)], prefix) {
				t.Fatal("TCP AppendBinary changed prefix")
			}
			wire = wire[len(prefix):]
			if transportChecksum(test.Source.Addr(), test.Destination.Addr(), ProtocolTCP, wire) != 0 {
				t.Fatal("encoded TCP checksum is invalid")
			}
			packet := IPPacket{Source: test.Source.Addr(), Destination: test.Destination.Addr(), Protocol: ProtocolTCP, HopLimit: 64, Payload: wire}
			parsed, err := packet.TCPSegment()
			if err != nil {
				t.Fatalf("parse TCP: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.SequenceNumber != test.SequenceNumber || parsed.AcknowledgmentNumber != test.AcknowledgmentNumber || parsed.Flags != test.Flags || parsed.WindowSize != test.WindowSize || parsed.UrgentPointer != test.UrgentPointer || !bytes.Equal(parsed.Payload, test.Payload) {
				t.Fatalf("parsed TCP = %+v, want %+v", parsed, test)
			}
			if got, want := len(parsed.Options), (len(test.Options)+3)&^3; got != want || !bytes.Equal(parsed.Options[:len(test.Options)], test.Options) {
				t.Fatalf("parsed TCP options = %x, want prefix %x and length %d", parsed.Options, test.Options, want)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("TCP round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
			inPlace := append([]byte(nil), wire...)
			inPlacePacket := IPPacket{Source: test.Source.Addr(), Destination: test.Destination.Addr(), Protocol: ProtocolTCP, Payload: inPlace}
			inPlaceSegment, err := inPlacePacket.TCPSegment()
			if err != nil {
				t.Fatal(err)
			}
			inPlaceResult, appendErr := inPlaceSegment.AppendBinary(inPlace[:0])
			if appendErr != nil || len(inPlaceResult) == 0 || &inPlaceResult[0] != &inPlace[0] || !bytes.Equal(inPlaceResult, wire) {
				t.Fatalf("in-place TCP round trip: error=%v\n got %x\nwant %x", appendErr, inPlaceResult, wire)
			}
		})
	}
}

func TestPublicTCPSegmentCodecIPv4MappedAddresses(t *testing.T) {
	segment := TCPSegment{
		Source: netip.MustParseAddrPort("[::ffff:192.0.2.1]:12345"), Destination: netip.MustParseAddrPort("[::ffff:198.51.100.2]:443"),
		SequenceNumber: 7, Flags: TCPFlagACK, WindowSize: 4096, Payload: []byte("mapped"),
	}
	wire, err := segment.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: wire}
	parsed, err := packet.TCPSegment()
	if err != nil {
		t.Fatalf("parse mapped TCP segment: %v", err)
	}
	if parsed.Source != netip.AddrPortFrom(segment.Source.Addr().Unmap(), segment.Source.Port()) ||
		parsed.Destination != netip.AddrPortFrom(segment.Destination.Addr().Unmap(), segment.Destination.Port()) ||
		!bytes.Equal(parsed.Payload, segment.Payload) {
		t.Fatalf("parsed mapped TCP segment = %+v", parsed)
	}
}

func TestPublicTCPHeaderOptions(t *testing.T) {
	var mss, scale, sackPermitted, timestamp, sack TCPHeaderOption
	mss.SetMaximumSegmentSize(1460)
	scale.SetWindowScale(255)
	sackPermitted.SetSACKPermitted()
	timestamp.SetTimestamp(0x10203040, 0x50607080)
	wantBlocks := []TCPSACKBlock{{LeftEdge: 0xfffffff0, RightEdge: 0x20}}
	if err := sack.SetSACKBlocks(wantBlocks); err != nil {
		t.Fatal(err)
	}
	unknownData := []byte{0xaa, 0xbb}
	options := []TCPHeaderOption{
		{Kind: TCPHeaderOptionNOP}, mss, scale, sackPermitted, timestamp, sack,
		{Kind: 30, Data: unknownData}, {Kind: 30, Data: []byte{0xcc, 0xdd}},
		{Kind: TCPHeaderOptionEnd},
	}
	segment := TCPSegment{}
	if err := segment.SetHeaderOptions(options); err != nil {
		t.Fatalf("SetHeaderOptions: %v", err)
	}
	wantWire := append([]byte(nil), segment.Options...)
	if literal := mustCodecVector(t,
		"01020405b40303ff0402080a1020304050607080050afffffff0000000201e04aabb1e04ccdd00"); !bytes.Equal(wantWire, literal) {
		t.Fatalf("structured TCP option wire = %x, want %x", wantWire, literal)
	}
	if len(wantWire) != 39 {
		t.Fatalf("encoded option length = %d, want 39", len(wantWire))
	}
	mss.Data[0] ^= 0xff
	unknownData[0] ^= 0xff
	if !bytes.Equal(segment.Options, wantWire) {
		t.Fatal("SetHeaderOptions retained caller storage")
	}

	parsed, err := segment.HeaderOptions()
	if err != nil {
		t.Fatalf("HeaderOptions: %v", err)
	}
	if len(parsed) != len(options) {
		t.Fatalf("parsed %d options, want %d", len(parsed), len(options))
	}
	if value, ok := parsed[1].MaximumSegmentSize(); !ok || value != 1460 {
		t.Fatalf("MSS = %d, %t", value, ok)
	}
	if value, ok := parsed[2].WindowScale(); !ok || value != 255 {
		t.Fatalf("raw Window Scale = %d, %t", value, ok)
	}
	if !parsed[3].IsSACKPermitted() {
		t.Fatal("SACK-Permitted was not recognized")
	}
	if value, echo, ok := parsed[4].Timestamp(); !ok || value != 0x10203040 || echo != 0x50607080 {
		t.Fatalf("Timestamp = %#x/%#x, %t", value, echo, ok)
	}
	blocks, ok := parsed[5].SACKBlocks()
	if !ok || len(blocks) != 1 || blocks[0] != wantBlocks[0] {
		t.Fatalf("SACK blocks = %+v, %t", blocks, ok)
	}
	if parsed[6].Kind != 30 || parsed[7].Kind != 30 || !bytes.Equal(parsed[6].Data, []byte{0xaa, 0xbb}) || parsed[8].Kind != TCPHeaderOptionEnd {
		t.Fatalf("unknown, duplicate, or End options changed: %+v", parsed)
	}

	var copied TCPSegment
	if err = copied.SetHeaderOptions(parsed); err != nil {
		t.Fatalf("copy parsed options: %v", err)
	}
	parsed[6].Data[0] ^= 0xff
	if segment.Options[32] != 0x55 {
		t.Fatal("HeaderOptions Data did not borrow TCPSegment.Options")
	}
	if !bytes.Equal(copied.Options, wantWire) {
		t.Fatal("SetHeaderOptions did not copy parsed Data")
	}
}

func TestPublicTCPHeaderOptionErrors(t *testing.T) {
	segment := TCPSegment{Options: []byte{TCPHeaderOptionNOP}}
	want := append([]byte(nil), segment.Options...)
	tests := []struct {
		name    string
		options []TCPHeaderOption
		wantErr error
	}{
		{name: "End data", options: []TCPHeaderOption{{Kind: TCPHeaderOptionEnd, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "NOP data", options: []TCPHeaderOption{{Kind: TCPHeaderOptionNOP, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "after End", options: []TCPHeaderOption{{Kind: TCPHeaderOptionEnd}, {Kind: TCPHeaderOptionNOP}}, wantErr: syscall.EINVAL},
		{name: "oversized", options: []TCPHeaderOption{{Kind: 30, Data: make([]byte, 39)}}, wantErr: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := segment.SetHeaderOptions(test.options); !errors.Is(err, test.wantErr) {
				t.Fatalf("SetHeaderOptions error = %v, want %v", err, test.wantErr)
			}
			if !bytes.Equal(segment.Options, want) {
				t.Fatal("failed SetHeaderOptions changed the receiver")
			}
		})
	}
	for _, raw := range [][]byte{{30}, {30, 1}, append([]byte{30, 42}, make([]byte, 39)...)} {
		if _, err := (TCPSegment{Options: raw}).HeaderOptions(); err == nil {
			t.Fatalf("HeaderOptions accepted %x", raw)
		}
	}
	malformed := []TCPHeaderOption{
		{Kind: TCPHeaderOptionMSS, Data: []byte{1}},
		{Kind: TCPHeaderOptionWindowScale, Data: []byte{1, 2}},
		{Kind: TCPHeaderOptionTimestamp, Data: make([]byte, 7)},
		{Kind: TCPHeaderOptionSACK, Data: make([]byte, 7)},
	}
	if _, ok := malformed[0].MaximumSegmentSize(); ok {
		t.Fatal("malformed MSS was recognized")
	}
	if _, ok := malformed[1].WindowScale(); ok {
		t.Fatal("malformed Window Scale was recognized")
	}
	if _, _, ok := malformed[2].Timestamp(); ok {
		t.Fatal("malformed Timestamp was recognized")
	}
	if _, ok := malformed[3].SACKBlocks(); ok {
		t.Fatal("malformed SACK was recognized")
	}
	original := TCPHeaderOption{Kind: 99, Data: []byte{1}}
	option := original
	if err := option.SetSACKBlocks(nil); !errors.Is(err, syscall.EINVAL) || option.Kind != original.Kind || !bytes.Equal(option.Data, original.Data) {
		t.Fatalf("empty SetSACKBlocks = %+v, %v", option, err)
	}
	if err := option.SetSACKBlocks(make([]TCPSACKBlock, 5)); !errors.Is(err, syscall.EINVAL) || option.Kind != original.Kind || !bytes.Equal(option.Data, original.Data) {
		t.Fatalf("oversized SetSACKBlocks = %+v, %v", option, err)
	}
}

func TestPublicTCPSegmentNormalizesReservedFieldsAndEOLPadding(t *testing.T) {
	segment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("198.51.100.2:443"),
		Flags: TCPFlagACK, Options: []byte{0, 0xaa, 0xbb, 0xcc}, Payload: []byte("payload"),
	}
	canonical, err := segment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical[tcpHeaderSize:tcpHeaderSize+4], []byte{0, 0, 0, 0}) {
		t.Fatalf("generated EOL padding = %x, want zeros", canonical[tcpHeaderSize:tcpHeaderSize+4])
	}

	wire := append([]byte(nil), canonical...)
	wire[12] |= 0x0e
	copy(wire[tcpHeaderSize+1:tcpHeaderSize+4], []byte{0xaa, 0xbb, 0xcc})
	binary.BigEndian.PutUint16(wire[16:18], 0)
	binary.BigEndian.PutUint16(wire[16:18], transportChecksum(segment.Source.Addr(), segment.Destination.Addr(), ProtocolTCP, wire))
	parsed, err := (IPPacket{
		Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: wire,
	}).TCPSegment()
	if err != nil {
		t.Fatalf("parse nonzero EOL padding: %v", err)
	}
	if !bytes.Equal(parsed.Options, []byte{0, 0xaa, 0xbb, 0xcc}) {
		t.Fatalf("parsed EOL padding = %x", parsed.Options)
	}
	if parsed.Flags != segment.Flags {
		t.Fatalf("parsed flags = %#x, want %#x", parsed.Flags, segment.Flags)
	}
	reencoded, err := parsed.AppendBinary(nil)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		t.Fatalf("normalized TCP segment: error=%v\n got %x\nwant %x", err, reencoded, canonical)
	}
}

func TestPublicTCPSegmentCodecErrorsDoNotModifyDestination(t *testing.T) {
	segment := TCPSegment{Source: netip.MustParseAddrPort("192.0.2.1:1"), Destination: netip.MustParseAddrPort("192.0.2.2:2"), Flags: TCPFlagACK}
	segment.Flags = 1 << 15
	prefix := []byte{9, 8, 7}
	want := append([]byte(nil), prefix...)
	if got, err := segment.AppendBinary(prefix); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(prefix, want) {
		t.Fatalf("invalid TCP AppendBinary: got=%x error=%v", got, err)
	}
	wrongProtocol := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: ProtocolUDP, Payload: make([]byte, udpHeaderSize)}
	if _, err := wrongProtocol.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("wrong TCP protocol error = %v", err)
	}
	segment.Flags = TCPFlagACK
	segment.Source = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone("test"), 1)
	segment.Destination = netip.MustParseAddrPort("[2001:db8::2]:2")
	if _, err := segment.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned TCP segment error = %v", err)
	}
}

func FuzzPublicTCPSegmentCodec(f *testing.F) {
	seed := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("192.0.2.2:443"),
		SequenceNumber: 7, Flags: TCPFlagACK, WindowSize: 4096, Options: []byte{1, 1, 0}, Payload: []byte("seed"),
	}
	wire, err := seed.AppendBinary(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{Source: seed.Source.Addr(), Destination: seed.Destination.Addr(), Protocol: ProtocolTCP, HopLimit: 64, Payload: wire}
		segment, err := packet.TCPSegment()
		if err != nil {
			return
		}
		encoded, err := segment.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed TCP could not be encoded: %v", err)
		}
		assertTCPSegmentWire(t, segment, encoded)
		packet.Payload = encoded
		reparsed, err := packet.TCPSegment()
		if err != nil {
			t.Fatalf("encoded TCP could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place TCP append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func FuzzTCPOptions(f *testing.F) {
	f.Add([]byte{2, 4, 0x05, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, uint32(100), uint32(200))
	f.Add([]byte{5, 10, 0, 0, 0, 120, 0, 0, 0, 160}, uint32(100), uint32(200))
	f.Add([]byte{5, 18, 0, 0, 0, 0, 0, 0, 1, 244, 0, 0, 0, 0, 0, 0, 3, 232}, uint32(4000), uint32(2000))
	f.Add([]byte{5, 18, 0, 0, 1, 194, 0, 0, 1, 234, 0, 0, 1, 144, 0, 0, 2, 88}, uint32(300), uint32(200))
	f.Fuzz(func(t *testing.T, options []byte, acknowledged, sendNext uint32) {
		if len(options) > 40 {
			options = options[:40]
		}
		before := append([]byte(nil), options...)
		window := sendNext % (tcpMaximumScaledWindow + 1)
		sendNext = acknowledged + window
		mss, scale, _, _, _, _ := parseTCPOptions(options, 536, 1360)
		if mss < tcpMinimumPeerMSS || mss > 1360 {
			t.Fatalf("parsed MSS %d is outside [%d, 1360]", mss, tcpMinimumPeerMSS)
		}
		if scale > 14 {
			t.Fatalf("parsed window scale = %d, want <= 14", scale)
		}
		_, _, _ = parseTCPTimestamp(options)
		blocks := parseTCPSACKOptions(options, acknowledged, sendNext)
		for index, block := range blocks {
			leftDistance, rightDistance := block.LeftEdge-acknowledged, block.RightEdge-acknowledged
			if leftDistance >= rightDistance || rightDistance > window {
				t.Fatalf("SACK block %d = [%#x,%#x) outside %#x-byte send window", index, block.LeftEdge, block.RightEdge, window)
			}
			if index != 0 && blocks[index-1].RightEdge-acknowledged >= leftDistance {
				t.Fatalf("SACK blocks %d and %d are unordered or unmerged", index-1, index)
			}
		}
		if block, ok := parseTCPDSACKOption(options, acknowledged, sendNext, window); ok {
			if int32(block.RightEdge-block.LeftEdge) <= 0 {
				t.Fatalf("invalid DSACK block [%#x,%#x)", block.LeftEdge, block.RightEdge)
			}
			if int32(block.RightEdge-acknowledged) <= 0 {
				if acknowledged-block.LeftEdge > window {
					t.Fatalf("DSACK [%#x,%#x) exceeds acknowledged history", block.LeftEdge, block.RightEdge)
				}
			} else if block.LeftEdge-acknowledged >= block.RightEdge-acknowledged || block.RightEdge-acknowledged > window {
				t.Fatalf("DSACK [%#x,%#x) exceeds transmitted flight", block.LeftEdge, block.RightEdge)
			}
		}
		if !bytes.Equal(options, before) {
			t.Fatal("TCP option parsing modified its input")
		}
	})
}

func FuzzPublicTCPHeaderOptions(f *testing.F) {
	f.Add([]byte{TCPHeaderOptionNOP, TCPHeaderOptionMSS, 4, 0x05, 0xb4, TCPHeaderOptionEnd, 0, 0})
	f.Add([]byte{TCPHeaderOptionSACK, 10, 0xff, 0xff, 0xff, 0xf0, 0, 0, 0, 0x20})
	f.Fuzz(func(t *testing.T, wire []byte) {
		before := append([]byte(nil), wire...)
		options, err := (TCPSegment{Options: wire}).HeaderOptions()
		if !bytes.Equal(wire, before) {
			t.Fatal("HeaderOptions modified its input")
		}
		if err != nil {
			return
		}
		for _, option := range options {
			_, _ = option.MaximumSegmentSize()
			_, _ = option.WindowScale()
			_ = option.IsSACKPermitted()
			_, _, _ = option.Timestamp()
			_, _ = option.SACKBlocks()
		}
		var rebuilt TCPSegment
		if err = rebuilt.SetHeaderOptions(options); err != nil {
			t.Fatalf("parsed options could not be rebuilt: %v", err)
		}
		canonical := append([]byte(nil), rebuilt.Options...)
		for index := range wire {
			wire[index] ^= 0xff
		}
		if !bytes.Equal(rebuilt.Options, canonical) {
			t.Fatal("SetHeaderOptions retained parsed input")
		}
		if _, err = rebuilt.HeaderOptions(); err != nil {
			t.Fatalf("rebuilt options could not be parsed: %v", err)
		}
	})
}

func FuzzPublicTCPHeaderOptionSetters(f *testing.F) {
	f.Add(uint16(1460), byte(7), uint32(0x10203040), uint32(0x50607080), []byte(nil))
	f.Add(uint16(536), byte(14), uint32(1), uint32(2), []byte{0x80})
	f.Add(uint16(1460), byte(7), uint32(0x10203040), uint32(0x50607080), []byte{0xff, 0xff, 0xff, 0, 0, 0, 0x20})
	f.Fuzz(func(t *testing.T, mssValue uint16, scaleValue byte, timestampValue, timestampEcho uint32, sackSeed []byte) {
		blockCount := len(sackSeed)%4 + 1
		blocks := make([]TCPSACKBlock, blockCount)
		for index := range blocks {
			for offset := 0; offset < 8; offset++ {
				value := byte(index*8 + offset)
				if len(sackSeed) != 0 {
					value = sackSeed[(index*8+offset)%len(sackSeed)]
				}
				if offset < 4 {
					blocks[index].LeftEdge = blocks[index].LeftEdge<<8 | uint32(value)
				} else {
					blocks[index].RightEdge = blocks[index].RightEdge<<8 | uint32(value)
				}
			}
		}
		var mss, scale, permitted, timestamp, sack TCPHeaderOption
		mss.SetMaximumSegmentSize(mssValue)
		scale.SetWindowScale(scaleValue)
		permitted.SetSACKPermitted()
		timestamp.SetTimestamp(timestampValue, timestampEcho)
		if err := sack.SetSACKBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		wantSACK := []byte{TCPHeaderOptionSACK, byte(2 + 8*len(blocks))}
		for _, block := range blocks {
			var encoded [8]byte
			binary.BigEndian.PutUint32(encoded[:4], block.LeftEdge)
			binary.BigEndian.PutUint32(encoded[4:], block.RightEdge)
			wantSACK = append(wantSACK, encoded[:]...)
		}
		if !bytes.Equal(append([]byte{TCPHeaderOptionSACK, byte(2 + len(sack.Data))}, sack.Data...), wantSACK) {
			t.Fatalf("semantic TCP SACK option = %x, want %x", sack.Data, wantSACK)
		}
		if blockCount > 2 {
			return
		}
		var segment TCPSegment
		if err := segment.SetHeaderOptions([]TCPHeaderOption{mss, scale, permitted, timestamp, sack}); err != nil {
			t.Fatal(err)
		}
		want := []byte{TCPHeaderOptionMSS, 4, byte(mssValue >> 8), byte(mssValue),
			TCPHeaderOptionWindowScale, 3, scaleValue, TCPHeaderOptionSACKPermitted, 2,
			TCPHeaderOptionTimestamp, 10, byte(timestampValue >> 24), byte(timestampValue >> 16), byte(timestampValue >> 8), byte(timestampValue),
			byte(timestampEcho >> 24), byte(timestampEcho >> 16), byte(timestampEcho >> 8), byte(timestampEcho)}
		want = append(want, wantSACK...)
		if !bytes.Equal(segment.Options, want) {
			t.Fatalf("semantic TCP options = %x, want %x", segment.Options, want)
		}
	})
}

func FuzzTCPSACKScoreboard(f *testing.F) {
	f.Add([]byte{0, 0, 10, 0, 0, 20, 40, 1}, uint32(100), uint16(256), uint16(64))
	f.Add([]byte{0, 1, 1, 0, 0, 2, 1, 0}, uint32(0xfffffff0), uint16(96), uint16(32))
	f.Add([]byte(nil), uint32(0xfffffff0), uint16(4095), uint16(0))
	f.Fuzz(func(t *testing.T, events []byte, base uint32, totalValue, segmentValue uint16) {
		if len(events) > 128 {
			events = events[:128]
		}
		total := int(totalValue%4096) + 1
		segmentSize := int(segmentValue%512) + 1
		epoch := time.Unix(300, 0)
		outstanding := make([]sentTCPSegment, 0, (total+segmentSize-1)/segmentSize)
		for start := 0; start < total; start += segmentSize {
			end := start + segmentSize
			if end > total {
				end = total
			}
			flags := byte(TCPFlagACK)
			if end == total {
				flags |= TCPFlagPSH
			}
			outstanding = append(outstanding, sentTCPSegment{
				sequence:  base + uint32(start),
				end:       base + uint32(end),
				flags:     flags,
				state:     sentTCPSegmentTransmitted,
				timestamp: uint32(start),
				hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(time.Duration(start)*time.Microsecond)),
				delivery:  tcpDeliverySnapshot{deliveredStamp: tcpDeliveryTimestamp(start + 1), deliveredFlags: uint32(start)},
			})
		}
		check := func() {
			var totalBytes, sackedBytes uint32
			sackedRanges := 0
			for index, segment := range outstanding {
				start := segment.sequence - base
				end := segment.end - base
				if start >= end || end > uint32(total) {
					t.Fatalf("segment %d outside send window: [%#x,%#x) base %#x total %d", index, segment.sequence, segment.end, base, total)
				}
				if index != 0 && outstanding[index-1].end != segment.sequence {
					t.Fatalf("segments %d and %d are not contiguous: %#x != %#x", index-1, index, outstanding[index-1].end, segment.sequence)
				}
				size := segment.end - segment.sequence
				totalBytes += size
				if segment.state.has(sentTCPSegmentSACKed) {
					sackedRanges++
					sackedBytes += size
				}
			}
			if totalBytes != uint32(total) {
				t.Fatalf("scoreboard covers %d bytes, want %d", totalBytes, total)
			}
			if ranges, bytes := tcpSACKedState(outstanding); ranges != sackedRanges || bytes != sackedBytes {
				t.Fatalf("SACK aggregate = %d/%d, want %d/%d", ranges, bytes, sackedRanges, sackedBytes)
			}
			splitRanges := 0
			for index := range outstanding {
				if outstanding[index].state.has(sentTCPSegmentSACKSplit) {
					splitRanges++
				}
			}
			if splitRanges > tcpMaximumSACKSplitRanges {
				t.Fatalf("SACK-created ranges = %d, limit %d", splitRanges, tcpMaximumSACKSplitRanges)
			}
		}
		check()
		for offset := 0; offset+4 <= len(events); offset += 4 {
			left := int(binary.BigEndian.Uint16(events[offset:offset+2])) % total
			width := int(events[offset+2])%(total-left) + 1
			right := left + width
			if events[offset+3]&1 != 0 && right-left > 1 {
				left++
			}
			block := TCPSACKBlock{LeftEdge: base + uint32(left), RightEdge: base + uint32(right)}
			var highest uint32
			var present, fresh bool
			var newlySACKed []sentTCPSegment
			outstanding, highest, present, fresh, newlySACKed = applyTCPSACK(outstanding, []TCPSACKBlock{block})
			if !present || highest != block.RightEdge {
				t.Fatalf("SACK apply metadata = present %t highest %#x, want true/%#x", present, highest, block.RightEdge)
			}
			if fresh != (len(newlySACKed) != 0) {
				t.Fatalf("fresh SACK metadata = %t with %d newly SACKed ranges", fresh, len(newlySACKed))
			}
			for _, segment := range newlySACKed {
				if segment.sequence-base < uint32(left) || segment.end-base > uint32(right) || !segment.state.has(sentTCPSegmentTransmitted) {
					t.Fatalf("newly SACKed range [%#x,%#x) outside block [%#x,%#x)", segment.sequence, segment.end, block.LeftEdge, block.RightEdge)
				}
			}
			check()
		}
	})
}

func FuzzTCPOutOfOrderRanges(f *testing.F) {
	f.Add([]byte{0, 4, 8, 1, 0, 0, 0, 8, 2, 0, 0, 8, 8, 3, 1}, uint32(100), uint16(64))
	f.Add([]byte{0, 16, 16, 4, 0, 0, 0, 32, 5, 1, 0, 8, 32, 6, 0}, uint32(0xfffffff0), uint16(128))
	f.Fuzz(func(t *testing.T, events []byte, receiveNext uint32, capacityValue uint16) {
		if len(events) > 320 {
			events = events[:320]
		}
		capacity := int(capacityValue)
		if capacity == 0 {
			capacity = 1
		}
		connection := &TCPConn{receiveCapacity: capacity}
		var pieces []tcpReceivedPiece
		outOfOrderBytes := 0
		check := func() {
			bytes := 0
			previousEnd := uint32(0)
			finCount := 0
			for index, piece := range pieces {
				start := piece.sequence - receiveNext
				end := start + uint32(len(piece.payload))
				if len(piece.payload) == 0 && !piece.fin {
					t.Fatalf("empty non-FIN receive piece at %d", index)
				}
				if end > uint32(capacity) || index != 0 && start < previousEnd {
					t.Fatalf("receive piece %d = [%d,%d) outside or overlapping a %d-byte window", index, start, end, capacity)
				}
				if piece.fin {
					finCount++
					if index != len(pieces)-1 {
						t.Fatalf("FIN appears before receive piece %d", index+1)
					}
				}
				previousEnd = end
				bytes += len(piece.payload)
			}
			if finCount > 1 || cap(pieces) > tcpMaximumOutOfOrder || bytes != outOfOrderBytes || bytes+connection.readBuffer.size > capacity {
				t.Fatalf("receive scoreboard = %d FINs, %d pieces, %d/%d bytes", finCount, len(pieces), bytes, outOfOrderBytes)
			}
			if got := connection.outOfOrderUnread.Load(); got != int64(outOfOrderBytes) {
				t.Fatalf("published out-of-order bytes = %d, want %d", got, outOfOrderBytes)
			}
		}
		for offset := 0; offset+5 <= len(events); offset += 5 {
			distance := uint32(binary.BigEndian.Uint16(events[offset : offset+2]))
			length := int(events[offset+2] & 63)
			payload := make([]byte, length)
			for index := range payload {
				payload[index] = events[offset+3] + byte(index)
			}
			_, closed := connection.receiveTCPData(receiveNext+distance, payload, events[offset+4]&1 != 0, uint32(capacity), 0, &receiveNext, &pieces, &outOfOrderBytes)
			check()
			if closed {
				break
			}
		}
		normalized := normalizeTCPReceivedPieces(receiveNext, append([]tcpReceivedPiece(nil), pieces...))
		if len(normalized) != len(pieces) {
			t.Fatalf("normalizing an existing scoreboard changed its length from %d to %d", len(pieces), len(normalized))
		}
		for index := range pieces {
			if normalized[index].sequence != pieces[index].sequence || normalized[index].fin != pieces[index].fin || !bytes.Equal(normalized[index].payload, pieces[index].payload) {
				t.Fatalf("normalizing an existing scoreboard changed piece %d", index)
			}
		}
	})
}

func FuzzTCPEstablishedSegmentSequence(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0xff, 0xff, 4, 0, 'a', 0, 0, 1, 0xff, 0xff, 4, 1, 'b'}, false)
	f.Add([]byte{4, 0, 1, 0x40, 0, 6, 2, 'c', 0, 0, 3, 0x20, 0, 0, 0, 0}, true)
	f.Add([]byte{0, 0, 4, 0xff, 0xff, 0, 0, 0}, false)
	f.Fuzz(func(t *testing.T, events []byte, ipv6 bool) {
		if len(events) > 128 {
			events = events[:128]
		}
		local := netip.MustParseAddr("192.0.2.250")
		remote := netip.MustParseAddr("198.51.100.250")
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::250")
			remote = netip.MustParseAddr("2001:db8:1::250")
		}
		link, stack := newTestStack(t, local, remote)
		link.echoTCP = true
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		netConnection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
		if err != nil {
			t.Fatal(err)
		}
		connection := netConnection.(*TCPConn)

		link.mu.Lock()
		peer := link.tcp[connection.key.local.Port()]
		if peer == nil {
			link.mu.Unlock()
			t.Fatal("emulated peer did not retain the established connection")
		}
		remoteNext, localNext := peer.serverNext, peer.clientNext
		link.mu.Unlock()

		for offset := 0; offset+8 <= len(events); offset += 8 {
			event := events[offset : offset+8]
			sequence := remoteNext + uint32(int32(int8(event[0])))
			acknowledgement := localNext + uint32(int32(int8(event[1])))
			switch event[6] >> 6 {
			case 1:
				sequence = uint32(event[0])
			case 2:
				sequence = ^uint32(event[0])
			case 3:
				acknowledgement = ^uint32(event[1])
			}
			flags := byte(TCPFlagACK)
			if event[2]&1 != 0 {
				flags |= TCPFlagPSH
			}
			if event[2]&2 != 0 {
				flags |= TCPFlagFIN
			}
			if event[2]&4 != 0 {
				flags |= TCPFlagRST
			}
			if event[2]&8 != 0 {
				flags |= TCPFlagSYN
			}
			if event[2]&16 != 0 {
				flags |= TCPFlagECE
			}
			if event[2]&32 != 0 {
				flags |= TCPFlagCWR
			}
			if event[2]&64 != 0 {
				flags |= 0x20
			}
			if event[2]&128 != 0 {
				flags &^= TCPFlagACK
			}
			window := binary.BigEndian.Uint16(event[3:5])
			payload := bytes.Repeat(event[7:8], int(event[5]&15))
			var options, rawOptions []byte
			switch event[6] & 3 {
			case 1:
				options = tcpTimestampOptions(uint32(event[7])<<24|uint32(event[0]), uint32(event[1]))
			case 2:
				options = make([]byte, 12)
				options[0], options[1], options[2], options[3] = 1, 1, 5, 10
				left := localNext + uint32(int32(int8(event[0])))
				right := left + 1 + uint32(event[7]&15)
				binary.BigEndian.PutUint32(options[4:8], left)
				binary.BigEndian.PutUint32(options[8:12], right)
			case 3:
				rawOptions = event[4:8]
				options = []byte{TCPHeaderOptionEnd, 0, 0, 0}
			}
			packet := buildTestTCP(remote, local, 8080, connection.key.local.Port(), sequence, acknowledgement, flags, window, options, payload)
			if rawOptions != nil {
				parsed, parseErr := ParseIPPacket(packet)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				copy(parsed.Payload[tcpHeaderSize:tcpHeaderSize+len(rawOptions)], rawOptions)
				binary.BigEndian.PutUint16(parsed.Payload[16:18], 0)
				binary.BigEndian.PutUint16(parsed.Payload[16:18], transportChecksum(remote, local, ProtocolTCP, parsed.Payload))
			}
			if event[6]&0x10 != 0 {
				setPacketECN(packet, 3)
			}
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			if sequence == remoteNext && acknowledgement == localNext && flags&TCPFlagACK != 0 && flags&(TCPFlagSYN|TCPFlagRST) == 0 {
				remoteNext += uint32(len(payload))
				if flags&TCPFlagFIN != 0 {
					remoteNext++
				}
			}
			if flags&TCPFlagRST != 0 {
				break
			}
		}

		deadline := time.Now().Add(time.Second)
		for connection.inbound.len() != 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
		if queued := connection.inbound.len(); queued != 0 {
			t.Fatalf("established connection retained %d actor segments after drain deadline", queued)
		}
		if retained := connection.inbound.retainedBytes(); retained < 0 || retained > tcpInboundByteCapacity {
			t.Fatalf("established input retained %d bytes, capacity %d", retained, tcpInboundByteCapacity)
		}
		info := connection.Info()
		if info.InboundQueueBytes < 0 || info.InboundQueueBytes > int64(info.InboundQueueCapacity) || info.InboundQueuePeak > int64(info.InboundQueueCapacity) {
			t.Fatalf("established input queue diagnostics = %+v", info)
		}
		if err = stack.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-connection.done:
		case <-time.After(time.Second):
			t.Fatal("established connection did not stop with its stack")
		}
		if connection.inbound.len() != 0 || connection.inbound.retainedBytes() != 0 {
			t.Fatalf("closed established connection retained %d segments and %d bytes", connection.inbound.len(), connection.inbound.retainedBytes())
		}
	})
}

func TestExplicitTCPSourceAndLocalLoopback(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.21")
	serverAddress := netip.MustParseAddr("192.0.2.22")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(clientAddress, 32),
		netip.PrefixFrom(serverAddress, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	udpListener, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	udpRemote := udpListener.LocalAddr().(*net.UDPAddr).AddrPort()
	udpSource := netip.AddrPortFrom(clientAddress, 46000)
	udpClient, err := stack.DialUDP(context.Background(), "udp", udpSource, udpRemote)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	if _, err = udpClient.Write([]byte("udp-loopback")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := udpListener.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "udp-loopback" || source.(*net.UDPAddr).AddrPort() != udpSource {
		t.Fatalf("UDP loopback = %q from %v", buffer[:n], source)
	}

	tcpListener, err := stack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpSource := netip.AddrPortFrom(clientAddress, 46001)
	tcpClient, err := stack.DialTCP(context.Background(), "tcp", tcpSource, tcpListener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer tcpClient.Close()
	tcpServer, err := tcpListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpServer.Close()
	if got := tcpClient.LocalAddr().(*net.TCPAddr).AddrPort(); got != tcpSource {
		t.Fatalf("DialTCP local endpoint = %v, want %v", got, tcpSource)
	}
	if _, err = tcpClient.Write([]byte("tcp-loopback")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(tcpServer, buffer[:12]); err != nil {
		t.Fatal(err)
	}
	if string(buffer[:12]) != "tcp-loopback" {
		t.Fatalf("TCP loopback = %q", buffer[:12])
	}
	if stack.Stats().LoopbackPackets == 0 {
		t.Fatal("local traffic did not use the loopback path")
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		packet := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("local traffic escaped to the link: %x", packet)
	}
}

func TestTCPKeepAliveIdleTimeoutAndSocketOptions(t *testing.T) {
	t.Run("keepalive", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.60"), netip.MustParseAddr("198.51.100.60"))
		link.mu.Lock()
		link.echoTCP = true
		link.mu.Unlock()
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		if err = tcpConnection.SetKeepAlivePeriod(10 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlivePeriod(0); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetKeepAlivePeriod(0) = %v, want EINVAL", err)
		}
		if err = tcpConnection.SetKeepAliveConfig(KeepAliveConfig{Idle: 15 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 2}); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		_, err = tcpConnection.Read(make([]byte, 1))
		if !errors.Is(err, syscall.ETIMEDOUT) {
			t.Fatalf("keepalive terminal error = %v, want ETIMEDOUT", err)
		}
		if stack.Stats().TCPKeepAliveProbes != 2 {
			t.Fatalf("keepalive probes = %d, want 2", stack.Stats().TCPKeepAliveProbes)
		}
	})
	t.Run("outstanding data defers keepalive", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
		defer stack.Close()
		link.echoTCP = true
		connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9303))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		defer tcpConnection.Close()
		if err = tcpConnection.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		link.mu.Lock()
		link.echoTCP = false
		link.mu.Unlock()
		if err = tcpConnection.SetKeepAliveConfig(KeepAliveConfig{Idle: 10 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 1}); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		if _, err = tcpConnection.Write([]byte("unacknowledged")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond)
		if probes := stack.Stats().TCPKeepAliveProbes; probes != 0 {
			t.Fatalf("keepalive probes with outstanding data = %d, want 0", probes)
		}
	})

	t.Run("idle and options", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.61"), netip.MustParseAddr("198.51.100.61"))
		link.mu.Lock()
		link.echoTCP = true
		link.mu.Unlock()
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		if err = tcpConnection.SetNoDelay(false); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetReadBuffer(4096); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetWriteBuffer(8192); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetReadBuffer(0); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetReadBuffer(0) = %v, want EINVAL", err)
		}
		if err = tcpConnection.SetReadBuffer(32 * 1024 * 1024); err != nil {
			t.Fatalf("large SetReadBuffer = %v", err)
		}
		if err = tcpConnection.SetWriteBuffer(32 * 1024 * 1024); err != nil {
			t.Fatalf("large SetWriteBuffer = %v", err)
		}
		if err = tcpConnection.SetIdleTimeout(20 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		_, err = tcpConnection.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle timeout error = %v, want os.ErrDeadlineExceeded", err)
		}
	})
}

func TestTCPTrafficClassSocketOption(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.68"), netip.MustParseAddr("198.51.100.68"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8082))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	if err = tcpConnection.SetTrafficClass(0xab); err != nil {
		t.Fatal(err)
	}
	if got := tcpConnection.Info().TrafficClass; got != 0xa8 {
		t.Fatalf("TCP traffic class = %#x, want %#x", got, 0xa8)
	}
	for _, invalid := range []int{-1, 256} {
		if err = tcpConnection.SetTrafficClass(invalid); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetTrafficClass(%d) = %v, want EINVAL", invalid, err)
		}
	}
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	if _, err = tcpConnection.Write([]byte("traffic class")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)

trafficClassPackets:
	for {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
				continue
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			if headerSize < tcpHeaderSize || headerSize >= len(parsed.payload) {
				continue
			}
			if parsed.trafficClass&0xfc != 0xa8 {
				t.Fatalf("TCP traffic-class packet = %+v", parsed)
			}
			break trafficClassPackets
		case <-deadline:
			t.Fatal("timed out waiting for TCP traffic-class data packet")
		}
	}
	if err = tcpConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetTrafficClass(0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetTrafficClass after Close = %v, want net.ErrClosed", err)
	}
}

func TestTCPPassiveHandshakeProcessesEventsWithFullPacketQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.69")
	remote := netip.MustParseAddr("198.51.100.69")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 8083))
	if err != nil {
		t.Fatal(err)
	}
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	packet := buildTestTCP(remote, local, 45000, 8083, 100, 0, TCPFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		listener.(*TCPListener).mu.Lock()
		defer listener.(*TCPListener).mu.Unlock()
		for candidate := range listener.(*TCPListener).handshaking {
			connection = candidate
			return true
		}
		return false
	})
	info := connection.Info()
	if info.State != TCPStateSYNReceived || info.MaximumSegmentSize == 0 || info.PathMTU != 1400 || info.RetransmissionTimeout != tcpInitialRTO {
		t.Fatalf("passive handshake info = %+v", info)
	}
	initialSequence := uint32(connection.icmpSequence.Load() >> 32)
	for _, flags := range []byte{TCPFlagACK, TCPFlagRST | TCPFlagACK} {
		packet = buildTestTCP(remote, local, 45000, 8083, 101, initialSequence+1, flags, 65535, nil, nil)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if info = connection.Info(); info.State != TCPStateSYNReceived || info.Retransmissions != 0 {
			t.Fatalf("pre-publication flags %#x changed passive handshake = %+v", flags, info)
		}
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("passive handshake remained active after listener close")
	}
	waitFor(t, time.Second, func() bool { return listener.(*TCPListener).Info().HandshakeFailures == 1 })
	closed := listener.(*TCPListener).Info()
	if closed.HandshakeTimeouts != 0 || closed.HandshakeFailures != 1 {
		t.Fatalf("aborted passive handshake diagnostics = %+v", closed)
	}
}

func TestTCPPassiveHandshakeRTOStartsAfterDeviceDeparture(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.115")
	remote := netip.MustParseAddr("198.51.100.115")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 8084))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = writeTestPacket(stack, buildTestTCP(remote, local, 45001, 8084, 100, 0, TCPFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		listener.(*TCPListener).mu.Lock()
		defer listener.(*TCPListener).mu.Unlock()
		for candidate := range listener.(*TCPListener).handshaking {
			connection = candidate
			return true
		}
		return false
	})
	waitFor(t, tcpInitialRTO+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		for index := range waiters.slots {
			if waiters.slots[index].Load() != nil {
				return true
			}
		}
		return false
	})
	if info := connection.Info(); info.Retransmissions != 0 || info.State != TCPStateSYNReceived {
		t.Fatalf("queue-resident passive handshake = %+v", info)
	}
	if depth := stack.outbound.len(); depth != 1 {
		t.Fatalf("queue-resident SYN-ACK depth = %d, want 1", depth)
	}
	entry, ok := stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("queue-resident SYN-ACK was unavailable")
	}
	wire := consumeTestPacket(&stack.outbound, entry)
	if info := connection.Info(); info.Retransmissions != 0 {
		t.Fatalf("device departure counted %d passive retransmissions, want 0", info.Retransmissions)
	}
	if depth := stack.outbound.len(); depth != 0 {
		t.Fatalf("passive handshake retransmitted at device departure: depth %d", depth)
	}
	packet, valid := parseIPPacket(wire, false)
	if !valid || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
		t.Fatal("passive handshake output was not TCP")
	}
	serverSequence := binary.BigEndian.Uint32(packet.payload[4:8])
	if err = writeTestPacket(stack, buildTestTCP(remote, local, 45001, 8084, 101, serverSequence+1, TCPFlagACK, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		acceptedConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptError <- acceptErr
			return
		}
		accepted <- acceptedConnection
	}()
	select {
	case acceptedConnection := <-accepted:
		if err = acceptedConnection.Close(); err != nil {
			t.Fatal(err)
		}
	case err = <-acceptError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting device-departed SYN-ACK")
	}
}

func TestTCPCloseQueuesFIN(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.70"), netip.MustParseAddr("198.51.100.70"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8090))
	if err != nil {
		t.Fatal(err)
	}
	port := connection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.finSent
	})
}

func TestTCPSetLingerAbortiveClose(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.71"), netip.MustParseAddr("198.51.100.71"))
	link.mu.Lock()
	link.echoTCP = true
	link.dropTCPData = 1
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8091))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	port := tcpConnection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if _, err = tcpConnection.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetLinger(-1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetLinger after Close = %v, want net.ErrClosed", err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.resetSeen
	})
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 0 })
}

func TestTCPSetLingerWaitsAndTimesOut(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.72"), netip.MustParseAddr("198.51.100.72"))
	link.mu.Lock()
	link.echoTCP = true
	link.dropTCPFIN = 100
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	port := tcpConnection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if err = tcpConnection.SetLinger(1); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("positive-linger Close duration = %v, want about 1s", elapsed)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.resetSeen
	})
}

func TestTCPSetLingerStopsAfterOrderlyClose(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.73"), netip.MustParseAddr("198.51.100.73"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8093))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	if err = tcpConnection.SetLinger(5); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("orderly positive-linger Close duration = %v, want completion before timeout", elapsed)
	}
}

func TestTCPLingerDurationSaturates(t *testing.T) {
	if duration := tcpLingerDuration(1); duration != time.Second {
		t.Fatalf("one-second linger duration = %v", duration)
	}
	if strconv.IntSize == 64 {
		const maximum = time.Duration(1<<63 - 1)
		if duration := tcpLingerDuration(int(^uint(0) >> 1)); duration != maximum {
			t.Fatalf("overflowing linger duration = %v, want %v", duration, maximum)
		}
	}
}

func BenchmarkTCPStreamRoundTrip(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.240"), netip.MustParseAddr("198.51.100.240"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8443))
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 32*1024)
	response := make([]byte, len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(connection, response); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPApplicationRead(b *testing.B) {
	const receiveChunkSize = 1200
	for _, payloadSize := range []int{64, 512, receiveChunkSize, 4 * 1024, 32 * 1024} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			bufferSizes := []struct {
				name string
				size int
			}{{name: "exact", size: payloadSize}}
			if payloadSize > 4*1024 {
				bufferSizes = append(bufferSizes, struct {
					name string
					size int
				}{name: "4K", size: 4 * 1024})
			}
			for _, bufferSize := range bufferSizes {
				bufferSize := bufferSize
				b.Run(bufferSize.name, func(b *testing.B) {
					chunks := make([][]byte, 0, (payloadSize+receiveChunkSize-1)/receiveChunkSize)
					for offset := 0; offset < payloadSize; {
						length := payloadSize - offset
						if length > receiveChunkSize {
							length = receiveChunkSize
						}
						chunks = append(chunks, bytes.Repeat([]byte{0x5a}, length))
						offset += length
					}

					for _, mode := range []string{"Read", "ReadWithBuffer"} {
						mode := mode
						b.Run(mode, func(b *testing.B) {
							connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
							buffer := make([]byte, bufferSize.size)
							remaining := payloadSize
							getBuffer := func(_ int) []byte {
								length := len(buffer)
								if remaining < length {
									length = remaining
								}
								return buffer[:length]
							}
							b.SetBytes(int64(payloadSize))
							b.ReportAllocs()
							b.ResetTimer()
							if mode == "Read" {
								for iteration := 0; iteration < b.N; iteration++ {
									for _, chunk := range chunks {
										if accepted := connection.appendReadBuffer(chunk, chunk, 0, 0); accepted != len(chunk) {
											b.Fatalf("accepted %d of %d bytes", accepted, len(chunk))
										}
									}
									remaining := payloadSize
									for remaining > 0 {
										length := len(buffer)
										if remaining < length {
											length = remaining
										}
										n, err := connection.Read(buffer[:length])
										if err != nil || n <= 0 || n > length {
											b.Fatalf("Read = %d, %v", n, err)
										}
										if buffer[0] != 0x5a {
											b.Fatalf("Read returned unexpected payload byte %#x", buffer[0])
										}
										remaining -= n
									}
								}
								return
							}

							for iteration := 0; iteration < b.N; iteration++ {
								for _, chunk := range chunks {
									if accepted := connection.appendReadBuffer(chunk, chunk, 0, 0); accepted != len(chunk) {
										b.Fatalf("accepted %d of %d bytes", accepted, len(chunk))
									}
								}
								remaining = payloadSize
								for remaining > 0 {
									n, err := connection.ReadWithBuffer(getBuffer)
									length := len(buffer)
									if remaining < length {
										length = remaining
									}
									if err != nil || n <= 0 || n > length {
										b.Fatalf("ReadWithBuffer = %d, %v", n, err)
									}
									if buffer[0] != 0x5a {
										b.Fatalf("ReadWithBuffer returned unexpected payload byte %#x", buffer[0])
									}
									remaining -= n
								}
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkTCPStreamReadModes(b *testing.B) {
	for _, mode := range []string{"Read", "ReadWithBuffer"} {
		mode := mode
		b.Run(mode, func(b *testing.B) {
			link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.241"), netip.MustParseAddr("198.51.100.241"))
			link.mu.Lock()
			link.echoTCP = true
			link.mu.Unlock()
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8443))
			if err != nil {
				b.Fatal(err)
			}
			tcpConnection := connection.(*TCPConn)
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
				b.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0x5a}, 32*1024)
			response := make([]byte, len(payload))
			offset := 0
			getBuffer := func(_ int) []byte { return response[offset:] }
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			if mode == "Read" {
				for iteration := 0; iteration < b.N; iteration++ {
					if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
						b.Fatalf("Write = %d, %v", n, writeErr)
					}
					offset = 0
					for offset < len(response) {
						n, readErr := tcpConnection.Read(response[offset:])
						if readErr != nil || n <= 0 || n > len(response)-offset {
							b.Fatalf("Read = %d, %v", n, readErr)
						}
						offset += n
					}
					if !bytes.Equal(response, payload) {
						b.Fatal("TCP echo payload mismatch")
					}
				}
				return
			}

			for iteration := 0; iteration < b.N; iteration++ {
				if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
					b.Fatalf("Write = %d, %v", n, writeErr)
				}
				offset = 0
				for offset < len(response) {
					n, readErr := tcpConnection.ReadWithBuffer(getBuffer)
					if readErr != nil || n <= 0 || n > len(response)-offset {
						b.Fatalf("ReadWithBuffer = %d, %v", n, readErr)
					}
					offset += n
				}
				if !bytes.Equal(response, payload) {
					b.Fatal("TCP echo payload mismatch")
				}
			}
		})
	}
}

func BenchmarkTCPReadFrom(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.244"), netip.MustParseAddr("198.51.100.244"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8443))
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	go io.Copy(io.Discard, connection)
	payload := bytes.Repeat([]byte{0x6c}, 4*1024*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if n, readErr := connection.(*TCPConn).ReadFrom(bytes.NewReader(payload)); readErr != nil || n != int64(len(payload)) {
			b.Fatalf("ReadFrom = %d, %v", n, readErr)
		}
	}
}

func BenchmarkTCPSetDeadline(b *testing.B) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := connection.SetDeadline(time.Time{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPDeadlineUpdates(b *testing.B) {
	for _, operation := range []struct {
		name string
		set  func(*TCPConn, time.Time) error
	}{
		{name: "Read", set: (*TCPConn).SetReadDeadline},
		{name: "Write", set: (*TCPConn).SetWriteDeadline},
		{name: "Both", set: (*TCPConn).SetDeadline},
	} {
		operation := operation
		b.Run(operation.name, func(b *testing.B) {
			for _, transition := range []string{"refresh", "clear", "expire"} {
				transition := transition
				b.Run(transition, func(b *testing.B) {
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					defer func() {
						connection.mu.Lock()
						connection.readDeadline.stopLocked()
						connection.writeDeadline.stopLocked()
						connection.mu.Unlock()
					}()
					future := time.Now().Add(time.Hour)
					past := time.Now().Add(-time.Second)
					if err := operation.set(connection, future); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for index := 0; index < b.N; index++ {
						deadline := future
						if transition == "refresh" {
							deadline = time.Now().Add(time.Hour)
						}
						if err := operation.set(connection, deadline); err != nil {
							b.Fatal(err)
						}
						switch transition {
						case "clear":
							if err := operation.set(connection, time.Time{}); err != nil {
								b.Fatal(err)
							}
						case "expire":
							if err := operation.set(connection, past); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		})
	}
}

func BenchmarkTCPApplicationReadDeadline(b *testing.B) {
	for _, payloadSize := range []int{64, 1200} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			for _, mode := range []string{"Read", "ReadWithBuffer"} {
				mode := mode
				b.Run(mode, func(b *testing.B) {
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					defer func() {
						connection.mu.Lock()
						connection.readDeadline.stopLocked()
						connection.mu.Unlock()
					}()
					payload := bytes.Repeat([]byte{0x5a}, payloadSize)
					buffer := make([]byte, payloadSize)
					getBuffer := func(_ int) []byte { return buffer }
					b.SetBytes(int64(payloadSize))
					b.ReportAllocs()
					b.ResetTimer()
					for index := 0; index < b.N; index++ {
						if accepted := connection.appendReadBuffer(payload, payload, 0, 0); accepted != payloadSize {
							b.Fatalf("accepted %d of %d bytes", accepted, payloadSize)
						}
						if err := connection.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
							b.Fatal(err)
						}
						var n int
						var err error
						if mode == "Read" {
							n, err = connection.Read(buffer)
						} else {
							n, err = connection.ReadWithBuffer(getBuffer)
						}
						if err != nil || n != payloadSize || buffer[0] != 0x5a {
							b.Fatalf("%s = %d, %v, first byte %#x", mode, n, err, buffer[0])
						}
					}
				})
			}
		})
	}
}

func BenchmarkPublicTCPSegmentCodec(b *testing.B) {
	segment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("198.51.100.2:443"),
		SequenceNumber: 100, AcknowledgmentNumber: 200, Flags: TCPFlagACK, WindowSize: 32768,
		Options: []byte{TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10, 0, 0, 0, 1, 0, 0, 0, 2},
		Payload: make([]byte, 1200),
	}
	wire, err := segment.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	packet := IPPacket{Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: wire}
	b.Run("parse", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(wire)))
		var parsed TCPSegment
		var parseErr error
		for index := 0; index < b.N; index++ {
			parsed, parseErr = packet.TCPSegment()
		}
		if parseErr != nil || len(parsed.Payload) != len(segment.Payload) {
			b.Fatalf("parse = %v, %v", parsed, parseErr)
		}
	})
	b.Run("append", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(wire)))
		buffer := make([]byte, 0, len(wire))
		var encoded []byte
		var appendErr error
		for index := 0; index < b.N; index++ {
			encoded, appendErr = segment.AppendBinary(buffer[:0])
		}
		if appendErr != nil || len(encoded) != len(wire) {
			b.Fatalf("append length = %d, %v", len(encoded), appendErr)
		}
	})
}

func TestTCPImpairedNetworkConditions(t *testing.T) {
	conditions := []struct {
		name      string
		direction testLinkCondition
		check     func(testLinkDirectionStats, time.Duration) bool
	}{
		{name: "latency-jitter", direction: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond}, check: func(_ testLinkDirectionStats, elapsed time.Duration) bool { return elapsed >= 50*time.Millisecond }},
		{name: "random-loss", direction: testLinkCondition{Latency: 2 * time.Millisecond, LossRate: 0.08}, check: func(stats testLinkDirectionStats, _ time.Duration) bool { return stats.RandomDrops != 0 }},
		{name: "burst-loss", direction: testLinkCondition{Latency: 2 * time.Millisecond, BurstEnterRate: 0.04, BurstExitRate: 0.35}, check: func(stats testLinkDirectionStats, _ time.Duration) bool { return stats.MaximumDropBurst >= 2 }},
		{name: "high-delay-loss", direction: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond, LossRate: 0.08, BurstEnterRate: 0.02, BurstExitRate: 0.4}, check: func(stats testLinkDirectionStats, elapsed time.Duration) bool {
			return stats.RandomDrops >= 2 && elapsed >= 100*time.Millisecond
		}},
		{name: "bandwidth-queue", direction: testLinkCondition{Latency: 3 * time.Millisecond, Bandwidth: 256 * 1024, QueueBytes: 16 * 1024}, check: func(stats testLinkDirectionStats, elapsed time.Duration) bool {
			return stats.QueueDrops != 0 && stats.MaximumQueued > 0 && elapsed >= 300*time.Millisecond
		}},
	}
	for _, test := range conditions {
		t.Run(test.name, func(t *testing.T) {
			client, server, link := newTestTCPConnectionPair(t, CongestionControlCUBIC, testLinkConditions{
				Seed: 9917, ClientToPeer: test.direction, PeerToClient: test.direction,
			})
			started := time.Now()
			transferTestTCPPayload(t, client, server, 96*1024, 15*time.Second)
			if test.check != nil && !test.check(link.Stats(0), time.Since(started)) {
				t.Fatalf("client link condition was not exercised: %+v", link.Stats(0))
			}
		})
	}
}

func TestTCPIPv6FullDuplexUnderAsymmetricImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::201")
	serverAddress := netip.MustParseAddr("2001:db8::202")
	client, server, link := newTestTCPConnectionPairForAddresses(t, CongestionControlCUBIC, testLinkConditions{
		Seed: 4811,
		ClientToPeer: testLinkCondition{
			Latency: 30 * time.Millisecond, Jitter: 8 * time.Millisecond, LossRate: 0.06,
			BurstEnterRate: 0.01, BurstExitRate: 0.5, Bandwidth: 1024 * 1024, QueueBytes: 48 * 1024,
		},
		PeerToClient: testLinkCondition{
			Latency: 5 * time.Millisecond, Jitter: 2 * time.Millisecond, LossRate: 0.04,
			DuplicateRate: 0.03, Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
		},
	}, clientAddress, serverAddress)
	results := make(chan error, 2)
	go func() { results <- exchangeTestTCPPayload(client, server, 128*1024, 20*time.Second, 0x11111111) }()
	go func() { results <- exchangeTestTCPPayload(server, client, 128*1024, 20*time.Second, 0x22222222) }()
	for direction := 0; direction < 2; direction++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	clientStats, serverStats := link.Stats(0), link.Stats(1)
	if clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 || clientStats.Delivered == 0 || serverStats.Delivered == 0 {
		t.Fatalf("asymmetric IPv6 link was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}

func TestTCPConnectionChurnUnderImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.221")
	serverAddress := netip.MustParseAddr("192.0.2.222")
	condition := testLinkCondition{
		Latency: 4 * time.Millisecond, Jitter: 2 * time.Millisecond,
		LossRate:      0.01,
		DuplicateRate: 0.01, Bandwidth: 4 * 1024 * 1024, QueueBytes: 128 * 1024,
	}
	clientStack, serverStack, link := newTestImpairedStackPair(t, CongestionControlCUBIC, testLinkConditions{
		Seed: 8179, ClientToPeer: condition, PeerToClient: condition,
	}, clientAddress, serverAddress)
	listener, err := serverStack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	const waves, flows = 3, 8
	for wave := 0; wave < waves; wave++ {
		accepted := make(chan net.Conn, flows)
		acceptError := make(chan error, 1)
		go func() {
			for flow := 0; flow < flows; flow++ {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					acceptError <- acceptErr
					return
				}
				accepted <- connection
			}
		}()
		type dialResult struct {
			connection *TCPConn
			err        error
		}
		dialed := make(chan dialResult, flows)
		for flow := 0; flow < flows; flow++ {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				connection, dialErr := clientStack.DialTCP(ctx, "tcp4", netip.AddrPort{}, endpoint)
				if dialErr != nil {
					dialed <- dialResult{err: dialErr}
					return
				}
				dialed <- dialResult{connection: connection.(*TCPConn)}
			}()
		}
		clients := make([]*TCPConn, 0, flows)
		for flow := 0; flow < flows; flow++ {
			result := <-dialed
			if result.err != nil {
				t.Fatal(result.err)
			}
			clients = append(clients, result.connection)
		}
		servers := make(map[uint16]*TCPConn, flows)
		acceptDeadline := time.After(15 * time.Second)
		for len(servers) < flows {
			select {
			case connection := <-accepted:
				port := connection.RemoteAddr().(*net.TCPAddr).AddrPort().Port()
				servers[port] = connection.(*TCPConn)
			case err = <-acceptError:
				t.Fatal(err)
			case <-acceptDeadline:
				t.Fatal("timed out accepting impaired TCP churn wave")
			}
		}
		transfers := make(chan error, flows)
		for flow, client := range clients {
			server := servers[client.LocalAddr().(*net.TCPAddr).AddrPort().Port()]
			if server == nil {
				t.Fatalf("missing accepted connection for %v", client.LocalAddr())
			}
			go func(flow int, client, server *TCPConn) {
				transfers <- exchangeTestTCPPayload(client, server, 16*1024, 10*time.Second, uint32(wave<<16|flow))
			}(flow, client, server)
		}
		for flow := 0; flow < flows; flow++ {
			if transferErr := <-transfers; transferErr != nil {
				t.Fatal(transferErr)
			}
		}
		for _, client := range clients {
			_ = client.Close()
		}
		for _, server := range servers {
			_ = server.Close()
		}
	}
	info := listener.(*TCPListener).Info()
	if info.AcceptedConnections != waves*flows || info.HandshakeCompletions != waves*flows {
		t.Fatalf("listener churn diagnostics = %+v", info)
	}
	if clientStats, serverStats := link.Stats(0), link.Stats(1); clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 {
		t.Fatalf("churn link loss was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}

func TestTCPOutstandingSmallFlightReuse(t *testing.T) {
	var control tcpEstablishedState
	control.appendOutstanding(sentTCPSegment{sequence: 1, end: 2, flags: TCPFlagFIN, state: sentTCPSegmentTransmitted}, false)
	if len(control.outstanding) != 1 || cap(control.outstanding) != 1 {
		t.Fatalf("control outstanding length/capacity = %d/%d", len(control.outstanding), cap(control.outstanding))
	}

	var state tcpEstablishedState
	segment := sentTCPSegment{sequence: 1, end: 2, state: sentTCPSegmentTransmitted}
	var multiSegment tcpEstablishedState
	multiSegment.appendOutstanding(segment, true)
	if len(multiSegment.outstanding) != 1 || cap(multiSegment.outstanding) != tcpInitialOutstandingCapacity {
		t.Fatalf("known multi-segment outstanding length/capacity = %d/%d", len(multiSegment.outstanding), cap(multiSegment.outstanding))
	}

	state.appendOutstanding(segment, false)
	state.appendOutstanding(segment, false)
	if len(state.outstanding) != 2 || cap(state.outstanding) != tcpSmallOutstandingCapacity {
		t.Fatalf("initial outstanding length/capacity = %d/%d", len(state.outstanding), cap(state.outstanding))
	}
	state.outstanding[0] = sentTCPSegment{}
	state.outstanding = state.outstanding[1:]
	state.outstandingHead++
	state.appendOutstanding(segment, false)
	if len(state.outstanding) != 2 || cap(state.outstanding) != tcpSmallOutstandingCapacity || state.outstandingHead != 0 {
		t.Fatalf("compacted outstanding length/capacity/head = %d/%d/%d", len(state.outstanding), cap(state.outstanding), state.outstandingHead)
	}
	state.appendOutstanding(segment, false)
	if len(state.outstanding) != 3 || cap(state.outstanding) != tcpInitialOutstandingCapacity {
		t.Fatalf("expanded outstanding length/capacity = %d/%d", len(state.outstanding), cap(state.outstanding))
	}
}

func TestTCPEmptyIOSocketState(t *testing.T) {
	for _, test := range []struct {
		name     string
		prepare  func(*TCPConn) error
		readErr  error
		writeErr error
	}{
		{name: "open"},
		{name: "read deadline", prepare: func(c *TCPConn) error { return c.SetReadDeadline(time.Now().Add(-time.Second)) }},
		{name: "write deadline", prepare: func(c *TCPConn) error { return c.SetWriteDeadline(time.Now().Add(-time.Second)) }, writeErr: os.ErrDeadlineExceeded},
		{name: "CloseRead", prepare: (*TCPConn).CloseRead},
		{name: "CloseWrite", prepare: (*TCPConn).CloseWrite, writeErr: net.ErrClosed},
		{name: "Close", prepare: (*TCPConn).Close, readErr: net.ErrClosed, writeErr: net.ErrClosed},
		{name: "peer reset", prepare: func(c *TCPConn) error { c.finish(syscall.ECONNRESET); return nil }, writeErr: syscall.ECONNRESET},
		{name: "local abort", prepare: func(c *TCPConn) error {
			c.abort(net.ErrClosed)
			c.finish(net.ErrClosed)
			return nil
		}, readErr: net.ErrClosed, writeErr: net.ErrClosed},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, buffer := range [][]byte{nil, make([]byte, 0)} {
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{closeCh: make(chan struct{})}
				t.Cleanup(func() { _ = connection.Close() })
				if test.prepare != nil {
					if err := test.prepare(connection); err != nil {
						t.Fatal(err)
					}
				}
				for _, operation := range []struct {
					name string
					call func([]byte) (int, error)
					want error
				}{{"read", connection.Read, test.readErr}, {"write", connection.Write, test.writeErr}} {
					n, err := operation.call(buffer)
					if n != 0 || !errors.Is(err, operation.want) {
						t.Fatalf("empty %s = %d, %v, want %v", operation.name, n, err, operation.want)
					}
					if err != nil {
						var opError *net.OpError
						if !errors.As(err, &opError) || opError.Op != operation.name {
							t.Fatalf("empty %s lost its operation wrapper: %v", operation.name, err)
						}
					}
				}
				if connection.sendBuffer.size != 0 || connection.actorWakeFlags.Load() != 0 && test.prepare == nil {
					t.Fatal("empty write queued output")
				}
			}
		})
	}
}

func TestTCPEmptyReadPreservesReceiveState(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.stack = &Stack{closeCh: make(chan struct{})}
	defer connection.Close()
	payload := []byte("queued")
	if n := connection.appendReadBuffer(payload, payload, 0, 0); n != len(payload) {
		t.Fatalf("queued %d of %d bytes", n, len(payload))
	}
	if err := connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	connection.finish(syscall.ECONNRESET)
	for _, buffer := range [][]byte{nil, make([]byte, 0)} {
		if n, err := connection.Read(buffer); n != 0 || err != nil {
			t.Fatalf("empty Read with buffered data, reset, and expired deadline = %d, %v", n, err)
		}
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if n, err := connection.Read(buffer); n != len(payload) || err != nil || !bytes.Equal(buffer, payload) {
		t.Fatalf("queued data after empty Read = %q, %d, %v", buffer, n, err)
	}
	if n, err := connection.Read(buffer); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("pending reset after empty Read = %d, %v", n, err)
	}
}

func TestTCPDeadlineRearmWakesBlockedIO(t *testing.T) {
	for _, operation := range []string{"Read", "ReadWithBuffer", "Write", "ReadFrom"} {
		t.Run(operation, func(t *testing.T) {
			_, _, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			writing := operation == "Write" || operation == "ReadFrom"
			if writing {
				if err := connection.SetWriteBuffer(64); err != nil {
					t.Fatal(err)
				}
			}
			if err := connection.SetDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			connection.mu.Lock()
			readTimer, writeTimer := connection.readDeadline.timer, connection.writeDeadline.timer
			readGeneration, writeGeneration := connection.readDeadline.done, connection.writeDeadline.done
			connection.mu.Unlock()
			type result struct {
				n         int64
				err       error
				callbacks int
			}
			completed := make(chan result, 1)
			go func() {
				var got result
				switch operation {
				case "Read":
					n, err := connection.Read(make([]byte, 1))
					got.n, got.err = int64(n), err
				case "ReadWithBuffer":
					n, err := connection.ReadWithBuffer(func(_ int) []byte {
						got.callbacks++
						return make([]byte, 1)
					})
					got.n, got.err = int64(n), err
				case "Write":
					n, err := connection.Write(make([]byte, 128))
					got.n, got.err = int64(n), err
				case "ReadFrom":
					got.n, got.err = connection.ReadFrom(bytes.NewReader(make([]byte, 128)))
				}
				completed <- got
			}()
			waitFor(t, time.Second, func() bool {
				connection.mu.Lock()
				defer connection.mu.Unlock()
				if writing {
					return connection.sendBuffer.size == 64 && connection.sendBuffer.limited
				}
				return connection.readNotify != nil
			})
			if err := connection.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			connection.mu.Lock()
			reused := connection.readDeadline.timer == readTimer && connection.writeDeadline.timer == writeTimer &&
				connection.readDeadline.done == readGeneration && connection.writeDeadline.done == writeGeneration
			connection.mu.Unlock()
			if !reused {
				t.Fatal("updating a blocked operation replaced its timer or wait-channel generation")
			}
			var want int64
			if writing {
				want = 64
			}
			select {
			case got := <-completed:
				if got.n != want || !errors.Is(got.err, os.ErrDeadlineExceeded) || got.callbacks != 0 {
					t.Fatalf("%s = %d, %v, callback calls %d, want %d and deadline", operation, got.n, got.err, got.callbacks, want)
				}
			case <-time.After(time.Second):
				t.Fatal("updated deadline did not wake the blocked operation")
			}
		})
	}
}

func TestTCPResetReleasesUnusedReadTimer(t *testing.T) {
	link, _, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	peer := link.tcp[connection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), sequence, acknowledgement, TCPFlagRST, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("RST did not terminate the protocol actor")
	}
	connection.mu.Lock()
	armed := connection.readDeadline.timer != nil
	connection.mu.Unlock()
	if armed {
		t.Fatal("empty terminal receive queue retained a read timer")
	}
	if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("empty receive queue after reset = %d, %v", n, err)
	}
}

func TestTCPResetPreservesReadDeadline(t *testing.T) {
	for _, mode := range []string{"Read", "ReadWithBuffer", "WriteTo"} {
		t.Run(mode, func(t *testing.T) {
			link, _, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			connection.mu.Lock()
			expired := connection.readDeadline.channelLocked()
			connection.mu.Unlock()
			link.mu.Lock()
			peer := link.tcp[connection.key.local.Port()]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			payload := []byte("queued")
			if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), sequence, acknowledgement, TCPFlagACK, 65535, nil, payload); err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool {
				connection.mu.Lock()
				defer connection.mu.Unlock()
				return connection.readBuffer.size == len(payload)
			})
			if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), sequence+uint32(len(payload)), acknowledgement, TCPFlagRST, 0, nil, nil); err != nil {
				t.Fatal(err)
			}
			select {
			case <-connection.done:
			case <-time.After(time.Second):
				t.Fatal("RST did not terminate the protocol actor")
			}
			select {
			case <-expired:
			case <-time.After(time.Second):
				t.Fatal("protocol termination canceled the application read deadline")
			}
			buffer := make([]byte, len(payload))
			var writer bytes.Buffer
			callbackCalls := 0
			read := func() (int64, error) {
				switch mode {
				case "Read":
					n, err := connection.Read(buffer)
					return int64(n), err
				case "ReadWithBuffer":
					n, err := connection.ReadWithBuffer(func(sizeHint int) []byte {
						callbackCalls++
						if sizeHint != len(payload) {
							t.Errorf("size hint = %d, want %d", sizeHint, len(payload))
						}
						return buffer
					})
					return int64(n), err
				default:
					return connection.WriteTo(&writer)
				}
			}
			if n, err := read(); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || callbackCalls != 0 || writer.Len() != 0 {
				t.Fatalf("read after reset and deadline = %d, %v, callback calls %d, output %d", n, err, callbackCalls, writer.Len())
			}
			if err := connection.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatalf("SetWriteDeadline after peer reset: %v", err)
			}
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("SetReadDeadline after peer reset: %v", err)
			}
			if err := connection.SetDeadline(time.Time{}); err != nil {
				t.Fatalf("SetDeadline after peer reset: %v", err)
			}
			n, err := read()
			if mode == "WriteTo" {
				buffer = writer.Bytes()
				if !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("WriteTo terminal error = %v, want ECONNRESET", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(payload)) || !bytes.Equal(buffer, payload) {
				t.Fatalf("buffered data after reset = %q, %d", buffer, n)
			}
			if n, err := connection.Read(buffer); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("drained reset Read = %d, %v", n, err)
			}
			if n, err := connection.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty Read after peer reset = %d, %v", n, err)
			}
			if n, err := connection.Write([]byte{1}); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("Write after peer reset = %d, %v", n, err)
			}
		})
	}
}

func TestTCPResetWriteDeadlinePriority(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired-before-reset-%t", expired), func(t *testing.T) {
			link, _, connection := newManuallyPumpedTCPConnection(t)
			defer connection.Close()
			deadline := time.Now().Add(time.Hour)
			want := error(syscall.ECONNRESET)
			if expired {
				deadline = time.Now().Add(-time.Second)
				want = os.ErrDeadlineExceeded
			}
			if err := connection.SetWriteDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			link.mu.Lock()
			peer := link.tcp[connection.key.local.Port()]
			sequence, acknowledgement := peer.serverNext, peer.clientNext
			link.mu.Unlock()
			if err := link.deliverTCP(connection.key.remote.Port(), connection.key.local.Port(), sequence, acknowledgement, TCPFlagRST, 0, nil, nil); err != nil {
				t.Fatal(err)
			}
			select {
			case <-connection.done:
			case <-time.After(time.Second):
				t.Fatal("RST did not terminate the protocol actor")
			}
			connection.mu.Lock()
			armed := connection.writeDeadline.timer != nil
			connection.mu.Unlock()
			if armed {
				t.Fatal("peer termination retained a write timer")
			}
			for _, state := range []struct {
				name string
				time time.Time
				set  bool
				want error
			}{
				{name: "existing", want: want},
				{name: "past", time: time.Now().Add(-time.Second), set: true, want: os.ErrDeadlineExceeded},
				{name: "future", time: time.Now().Add(time.Hour), set: true, want: syscall.ECONNRESET},
				{name: "cleared", set: true, want: syscall.ECONNRESET},
			} {
				if state.set {
					if err := connection.SetWriteDeadline(state.time); err != nil {
						t.Fatal(err)
					}
				}
				for _, operation := range []struct {
					name string
					call func() (int64, error)
				}{
					{name: "Write", call: func() (int64, error) { n, err := connection.Write([]byte{1}); return int64(n), err }},
					{name: "empty Write", call: func() (int64, error) { n, err := connection.Write(nil); return int64(n), err }},
					{name: "ReadFrom", call: func() (int64, error) { return connection.ReadFrom(bytes.NewBuffer([]byte{1})) }},
				} {
					if n, err := operation.call(); n != 0 || !errors.Is(err, state.want) {
						t.Fatalf("%s with %s deadline = %d, %v, want %v", operation.name, state.name, n, err, state.want)
					}
				}
			}
		})
	}
}

func TestTCPWriteTerminalDeadlinePriority(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*TCPConn)
		want    error
	}{
		{name: "peer reset", prepare: func(c *TCPConn) { c.finish(syscall.ECONNRESET) }, want: os.ErrDeadlineExceeded},
		{name: "transport timeout", prepare: func(c *TCPConn) { c.finish(syscall.ETIMEDOUT) }, want: os.ErrDeadlineExceeded},
		{name: "local Close", prepare: func(c *TCPConn) { _ = c.Close(); c.finish(net.ErrClosed) }, want: net.ErrClosed},
		{name: "CloseWrite", prepare: func(c *TCPConn) { _ = c.CloseWrite(); c.finish(syscall.ECONNRESET) }, want: syscall.ECONNRESET},
		{name: "local abort", prepare: func(c *TCPConn) { c.abort(syscall.ECONNABORTED); c.finish(syscall.ECONNABORTED) }, want: syscall.ECONNABORTED},
		{name: "Stack Close", prepare: func(c *TCPConn) { close(c.stack.closeCh); c.finish(ErrClosed) }, want: net.ErrClosed},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, payload := range [][]byte{nil, {1}} {
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{closeCh: make(chan struct{})}
				defer connection.Close()
				if err := connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
				test.prepare(connection)
				if n, err := connection.Write(payload); n != 0 || !errors.Is(err, test.want) {
					t.Fatalf("Write(%d bytes) = %d, %v, want %v", len(payload), n, err, test.want)
				}
				connection.mu.Lock()
				armed := connection.writeDeadline.timer != nil
				connection.mu.Unlock()
				if armed {
					t.Fatal("expired or locally closed write retained an armed timer")
				}
			}
		})
	}
}

func TestTCPBlockedWriteTerminalDeadlinePriority(t *testing.T) {
	for _, operation := range []string{"Write", "ReadFrom"} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired-%t", operation, expired), func(t *testing.T) {
				connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				connection.stack = &Stack{closeCh: make(chan struct{})}
				defer connection.Close()
				connection.sendCapacity = 64
				payload := bytes.Repeat([]byte{1}, 128)
				type result struct {
					n   int64
					err error
				}
				completed := make(chan result, 1)
				go func() {
					if operation == "Write" {
						n, err := connection.Write(payload)
						completed <- result{int64(n), err}
					} else {
						n, err := connection.ReadFrom(bytes.NewBuffer(payload))
						completed <- result{n, err}
					}
				}()
				waitFor(t, time.Second, func() bool {
					connection.mu.Lock()
					defer connection.mu.Unlock()
					return connection.sendBuffer.size == 64 && connection.sendBuffer.limited
				})
				connection.mu.Lock()
				connection.terminalErr = syscall.ECONNRESET
				want := error(syscall.ECONNRESET)
				if expired {
					connection.writeDeadline.setLocked(time.Now().Add(-time.Second))
					want = os.ErrDeadlineExceeded
				}
				close(connection.done)
				connection.mu.Unlock()
				select {
				case got := <-completed:
					if got.n != 64 || !errors.Is(got.err, want) {
						t.Fatalf("blocked %s = %d, %v, want %v", operation, got.n, got.err, want)
					}
				case <-time.After(time.Second):
					t.Fatal("actor termination did not wake the writer")
				}
				connection.mu.Lock()
				limited, queued := connection.sendBuffer.limited, connection.sendBuffer.size
				connection.mu.Unlock()
				if limited || queued != 64 {
					t.Fatalf("writer completion changed accepted bytes or pressure state: queued %d limited %t", queued, limited)
				}
			})
		}
	}
}

func TestTCPFirstUnsackedSegment(t *testing.T) {
	for _, test := range []struct {
		name     string
		segments []sentTCPSegment
		want     int
	}{
		{name: "empty", want: -1},
		{name: "unsacked", segments: []sentTCPSegment{{}}, want: 0},
		{name: "all-SACKed", segments: []sentTCPSegment{{state: sentTCPSegmentSACKed}, {state: sentTCPSegmentSACKed}}, want: 0},
		{name: "hole", segments: []sentTCPSegment{{state: sentTCPSegmentSACKed}, {}, {state: sentTCPSegmentSACKed}}, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := firstUnsackedSegment(test.segments); got != test.want {
				t.Fatalf("first unsacked = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTCPFRTOAfterCongestionControlChange(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, phase := range []tcpFRTOState{tcpFRTOTimeoutPending, tcpFRTOAwaitingACK, tcpFRTOProbePending, tcpFRTOProbeSent, tcpFRTOFallbackPending} {
			for _, partial := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/phase-%d/partial-%t", algorithm, phase, partial), func(t *testing.T) {
					start := time.Now()
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: start}
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(CongestionControlCUBIC),
						peerMSS: 1000, peerWindow: 20000, sendUnacknowledged: 2000, sendNext: 6000,
						congestionWindow: 1000, slowStartThreshold: 4000, rtt: newRTTEstimator(20 * time.Millisecond),
						rtoRecovery: true, rtoRecoveryPoint: 4000, frtoState: phase,
						outstanding: []sentTCPSegment{{sequence: 2000, end: 3000}, {sequence: 3000, end: 4000}, {sequence: 4000, end: 5000}, {sequence: 5000, end: 6000}},
						undo:        &tcpRecoveryUndo{},
					}
					state.controller.initialize(CongestionPhaseOpen, start, time.Millisecond, time.Millisecond, 8000, 16000, 1000, monotonicStampAt(start, start))
					state.undo.begin(true, 4000, 8000, 16000, 4000, &state.controller, state.rtt, start)
					state.undo.recordRetransmission(1000, 2000, 1, false)
					state.controller.setCongestionPhase(CongestionPhaseLoss, start)
					if phase == tcpFRTOProbePending {
						state.frtoProbeBudget = 1
					}
					registered, _ := registeredCongestionControlFactory(algorithm)
					definition := registered.definition
					definition.Name = "test-frto-replacement-" + algorithm
					factory, err := NewCongestionControlFactory(definition)
					if err != nil {
						t.Fatal(err)
					}
					state.changeCongestionController(factory, 0)
					defer state.controller.release(time.Now(), state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerMSS, state.rtt.srtt, state.rtt.minimum)
					if state.controller.state.Phase != CongestionPhaseLoss {
						t.Fatal("controller replacement left the timeout recovery phase")
					}
					if state.undo.active {
						t.Fatal("controller replacement retained its predecessor's undo snapshot")
					}
					if partial {
						segment := tcpSegment{acknowledgement: 3000, flags: TCPFlagACK, window: 20000}
						update := state.processAcknowledgment(&segment, start.Add(time.Millisecond), 0)
						state.updateRetransmissionTimer(update, start.Add(time.Millisecond))
						if state.sendUnacknowledged != 3000 || len(state.outstanding) != 3 || !state.retransmit {
							t.Fatalf("partial ACK lost remaining flight: %+v", state)
						}
						if phase == tcpFRTOTimeoutPending || phase == tcpFRTOProbePending || phase == tcpFRTOProbeSent {
							if state.frtoState != tcpFRTOInactive || state.rtoRecovery || state.rtoRecoveryPoint != 0 || state.recoveryOutputPending() || state.recoveryOutputReady() {
								t.Fatalf("spurious partial ACK still authorized RTO output: F-RTO %d RTO %t point %d", state.frtoState, state.rtoRecovery, state.rtoRecoveryPoint)
							}
							if state.controller.state.Phase != CongestionPhaseOpen || state.congestionWindow == 8000 || state.slowStartThreshold != 4000 {
								t.Fatalf("spurious partial ACK restored an unavailable congestion checkpoint: phase %v cwnd %d threshold %d", state.controller.state.Phase, state.congestionWindow, state.slowStartThreshold)
							}
						}
					}
					segment := tcpSegment{acknowledgement: 6000, flags: TCPFlagACK, window: 20000}
					update := state.processAcknowledgment(&segment, start.Add(2*time.Millisecond), 0)
					state.updateRetransmissionTimer(update, start.Add(2*time.Millisecond))
					if len(state.outstanding) != 0 || state.frtoState != tcpFRTOInactive || state.frtoProbeBudget != 0 || state.rtoRecovery || state.retransmit || state.controller.state.Phase != CongestionPhaseOpen {
						t.Fatalf("full ACK did not finish recovery: F-RTO %d budget %d RTO %t timer %t phase %v outstanding %d", state.frtoState, state.frtoProbeBudget, state.rtoRecovery, state.retransmit, state.controller.state.Phase, len(state.outstanding))
					}
					if state.undo.spuriousUndos != 0 || connection.stack.stats.tcpSpuriousRecoveryUndos.Load() != 0 {
						t.Fatal("unavailable undo was counted as a successful restoration")
					}
				})
			}
		}
	}
}

func TestTCPFRTOSACKAfterCongestionControlChange(t *testing.T) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, phase := range []tcpFRTOState{tcpFRTOProbePending, tcpFRTOProbeSent} {
			for _, rackLoss := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/phase-%d/RACK-loss-%t", algorithm, phase, rackLoss), func(t *testing.T) {
					start := time.Now()
					connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
					connection.stack = &Stack{timestampEpoch: start}
					state := tcpEstablishedState{
						connection: connection, controller: newTCPCongestionController(CongestionControlCUBIC),
						peerMSS: 1000, peerSACK: true, peerWindow: 20000,
						sendUnacknowledged: 2000, sendNext: 5000, bytesAcknowledged: 1000,
						congestionWindow: 1000, slowStartThreshold: 4000, rtt: newRTTEstimator(20 * time.Millisecond),
						rtoRecovery: true, rtoRecoveryPoint: 4000, frtoState: phase,
						rackReorderingSeen: true,
						outstanding: []sentTCPSegment{
							{sequence: 2000, end: 3000, state: sentTCPSegmentTransmitted, firstSent: time.Millisecond, hostQueue: packetQueueTicket{queuedAt: monotonicStampAt(start, start.Add(time.Millisecond))}},
							{sequence: 3000, end: 4000, state: sentTCPSegmentTransmitted, firstSent: 2 * time.Millisecond, hostQueue: packetQueueTicket{queuedAt: monotonicStampAt(start, start.Add(2*time.Millisecond))}},
							{sequence: 4000, end: 5000, state: sentTCPSegmentTransmitted, firstSent: 60 * time.Millisecond, hostQueue: packetQueueTicket{queuedAt: monotonicStampAt(start, start.Add(60*time.Millisecond))}},
						},
						undo: &tcpRecoveryUndo{},
						sendTimer:  tcpSendTimerState{baseDeadline: start.Add(time.Second)},
						retransmit: true, retransmissionDeadline: start.Add(time.Second),
					}
					if phase == tcpFRTOProbePending {
						state.frtoProbeBudget = 1
					}
					if rackLoss {
						state.outstanding[0].state.set(sentTCPSegmentRACKLost, true)
						state.haveRACKLoss = true
					}
					state.controller.initialize(CongestionPhaseOpen, start, time.Millisecond, time.Millisecond, 8000, 16000, 1000, monotonicStampAt(start, start))
					state.undo.begin(true, 4000, 8000, 16000, 4000, &state.controller, state.rtt, start)
					state.undo.recordRetransmission(1000, 2000, 1, false)
					state.controller.setCongestionPhase(CongestionPhaseLoss, start)
					registered, _ := registeredCongestionControlFactory(algorithm)
					definition := registered.definition
					definition.Name = "test-frto-sack-replacement-" + algorithm
					factory, err := NewCongestionControlFactory(definition)
					if err != nil {
						t.Fatal(err)
					}
					state.changeCongestionController(factory, 0)
					defer func() {
						state.controller.release(time.Now(), state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerMSS, state.rtt.srtt, state.rtt.minimum)
					}()
					if state.controller.state.Phase != CongestionPhaseLoss {
						t.Fatal("controller replacement left the timeout recovery phase")
					}
					if state.undo.active {
						t.Fatal("controller replacement retained its predecessor's undo snapshot")
					}
					segment := tcpSegment{acknowledgement: 2000, flags: TCPFlagACK, window: 20000}
					segment.setOptions(testSACKOptions(map[uint32][]byte{3000: make([]byte, 1000)}))
					update := state.processAcknowledgment(&segment, start.Add(80*time.Millisecond), 0)
					state.updateRetransmissionTimer(update, start.Add(80*time.Millisecond))
					if state.sendUnacknowledged != 2000 || state.bytesAcknowledged != 1000 || len(state.outstanding) != 3 || state.sackedRanges != 1 || state.sackedBytes != 1000 || !state.outstanding[1].state.has(sentTCPSegmentSACKed) {
						t.Fatalf("selective delivery changed cumulative ACK or lost flight: UNA %d bytes %d flight %d SACK %d/%d", state.sendUnacknowledged, state.bytesAcknowledged, len(state.outstanding), state.sackedRanges, state.sackedBytes)
					}
					if state.frtoState != tcpFRTOInactive || state.frtoProbeBudget != 0 || state.rtoRecovery || state.rtoRecoveryPoint != 0 {
						t.Fatalf("selective delivery retained F-RTO authorization: phase %d budget %d RTO %t point %d", state.frtoState, state.frtoProbeBudget, state.rtoRecovery, state.rtoRecoveryPoint)
					}
					if !state.retransmit || !state.sendTimer.baseDeadline.Equal(start.Add(time.Second)) {
						t.Fatal("selective delivery canceled or restarted the remaining flight's RTO")
					}
					if rackLoss {
						if !state.outstanding[0].state.has(sentTCPSegmentRACKLost) || !state.haveRACKLoss || !state.fastRecovery || !state.recoveryOutputPending() {
							t.Fatal("F-RTO completion discarded independent RACK recovery")
						}
					} else if state.fastRecovery || state.haveRACKLoss || state.controller.state.Phase != CongestionPhaseOpen || state.recoveryOutputPending() || state.recoveryOutputReady() {
						t.Fatal("selective delivery without loss retained immediate recovery output")
					}
					if connection.stack.stats.tcpSpuriousRecoveryUndos.Load() != 0 || state.undo.spuriousUndos != 0 {
						t.Fatal("unavailable undo was counted as a successful restoration")
					}
					segment = tcpSegment{acknowledgement: 5000, flags: TCPFlagACK, window: 20000}
					update = state.processAcknowledgment(&segment, start.Add(81*time.Millisecond), 0)
					state.updateRetransmissionTimer(update, start.Add(81*time.Millisecond))
					if len(state.outstanding) != 0 || state.retransmit || state.fastRecovery || state.rtoRecovery || state.recoveryOutputPending() {
						t.Fatal("full ACK did not release the remaining flight and recovery output")
					}
				})
			}
		}
	}
}

func TestTCPFRTOProbeACKAfterCongestionControlChange(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.251"), netip.MustParseAddr("192.0.2.252"))
	link.mu.Lock()
	link.echoTCP, link.disableTCPSACK = true, true
	link.mu.Unlock()
	dialed, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	connection := dialed.(*TCPConn)
	defer connection.Close()
	if err = connection.SetCongestionControl(CongestionControlReno); err != nil {
		t.Fatal(err)
	}
	before := connection.Info()
	if before.SACK {
		t.Fatal("wire regression requires non-SACK F-RTO")
	}
	link.mu.Lock()
	peer := link.tcp[connection.key.local.Port()]
	sequence, serverSequence := peer.clientNext, peer.serverNext
	link.echoTCP = false
	link.mu.Unlock()
	payload := bytes.Repeat([]byte{0x93}, 20*before.MaximumSegmentSize)
	if n, writeErr := connection.Write(payload); n != len(payload) || writeErr != nil {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	initialEnd := sequence
	retransmitted := false
	for !retransmitted {
		select {
		case wire := <-link.outbound:
			packet, parseErr := ParseIPPacket(wire)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			segment, parseErr := packet.TCPSegment()
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if len(segment.Payload) == 0 {
				continue
			}
			if segment.SequenceNumber == sequence && initialEnd != sequence {
				retransmitted = connection.Info().RetransmissionRecovery
			} else if end := segment.SequenceNumber + uint32(len(segment.Payload)); tcpSequenceGreater(end, initialEnd) {
				initialEnd = end
			}
		case <-deadline.C:
			t.Fatal("initial flight did not enter RTO recovery")
		}
	}
	if initialEnd >= sequence+uint32(len(payload)) {
		t.Fatal("initial flight left no new data for F-RTO probes")
	}
	if err = link.deliverTCP(8080, connection.key.local.Port(), serverSequence, sequence+uint32(before.MaximumSegmentSize), TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	probeEnd := initialEnd
	for probes := 0; probes < 2; {
		select {
		case wire := <-link.outbound:
			packet, parseErr := ParseIPPacket(wire)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			segment, parseErr := packet.TCPSegment()
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if len(segment.Payload) != 0 && tcpSequenceGreaterEqual(segment.SequenceNumber, initialEnd) {
				if segment.SequenceNumber != probeEnd {
					t.Fatalf("F-RTO probe sequence = %d, want %d", segment.SequenceNumber, probeEnd)
				}
				probeEnd += uint32(len(segment.Payload))
				probes++
			}
		case <-deadline.C:
			t.Fatal("F-RTO did not publish two new probes")
		}
	}
	if err = connection.SetCongestionControl(CongestionControlCUBIC); err != nil {
		t.Fatal(err)
	}
	if info := connection.Info(); info.CongestionControl != CongestionControlCUBIC || !info.RetransmissionRecovery {
		t.Fatalf("controller switch during F-RTO = %+v", info)
	}
	partialACK := sequence + 2*uint32(before.MaximumSegmentSize)
	if err = link.deliverTCP(8080, connection.key.local.Port(), serverSequence, partialACK, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return connection.Info().BytesAcknowledged-before.BytesAcknowledged == uint64(partialACK-sequence)
	})
	if info := connection.Info(); info.RetransmissionRecovery {
		t.Fatalf("spurious partial ACK retained RTO recovery: %+v", info)
	}
	if err = link.deliverTCP(8080, connection.key.local.Port(), serverSequence, probeEnd, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return connection.Info().BytesAcknowledged-before.BytesAcknowledged == uint64(probeEnd-sequence)
	})
	info := connection.Info()
	if info.State != TCPStateEstablished || info.RetransmissionRecovery || info.SpuriousRecoveryUndos != before.SpuriousRecoveryUndos {
		t.Fatalf("legal probe ACK after controller replacement = %+v", info)
	}
	select {
	case <-connection.done:
		t.Fatal("legal probe ACK terminated the TCP actor")
	default:
	}
}

func BenchmarkTCPApplicationWrite(b *testing.B) {
	for _, size := range []int{0, 64, 1200, 32 * 1024} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			payload := bytes.Repeat([]byte{0x5a}, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if n, err := connection.Write(payload); n != size || err != nil {
					b.Fatalf("Write = %d, %v", n, err)
				}
				if connection.sendBuffer.size != size {
					b.Fatalf("send buffer size = %d, want %d", connection.sendBuffer.size, size)
				}
				connection.sendBuffer.acknowledge(size)
			}
		})
	}
}

func BenchmarkTCPEmptyRead(b *testing.B) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := connection.Read(nil); n != 0 || err != nil {
			b.Fatalf("Read = %d, %v", n, err)
		}
	}
}

package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var _ interface {
	DialTCP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error)
	DialIP(ctx context.Context, network string, source, remote netip.Addr) (net.Conn, error)
	ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error)
	ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error)
	ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error)
	ListenMulticastUDP(ctx context.Context, network string, group netip.AddrPort) (*UDPConn, error)
} = (*Stack)(nil)

var _ interface {
	ListenTCP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.Listener, error)
	ListenUDP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.PacketConn, error)
	ListenIP(ctx context.Context, stack *Stack, network string, local netip.Addr) (net.PacketConn, error)
} = (*ListenConfig)(nil)

var _ interface {
	DialTCP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error)
	DialIP(ctx context.Context, stack *Stack, network string, source, remote netip.Addr) (net.Conn, error)
} = (*Dialer)(nil)

func TestRXChecksumOffloadIngress(t *testing.T) {
	local4, remote4 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	local6, remote6 := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	echo4 := mustTestWire((ICMPMessage{Source: remote4, Destination: local4, Type: ICMPv4TypeEchoRequest,
		Body: []byte{0, 1, 0, 1, 'x'}}).MarshalBinary())
	echo6 := mustTestWire((ICMPMessage{Source: remote6, Destination: local6, Type: ICMPv6TypeEchoRequest,
		Body: []byte{0, 1, 0, 1, 'x'}}).MarshalBinary())
	for _, test := range []struct {
		name    string
		local   netip.Addr
		packet  []byte
		offset  int
		set     func(*RXChecksumOffload, bool) *RXChecksumOffload
		control bool
	}{
		{"IPv4Header", local4, buildTestUDP(remote4, local4, 49000, 49001, []byte("udp")), 10, (*RXChecksumOffload).SetIPv4Header, false},
		{"TCPv4", local4, buildTestTCP(remote4, local4, 49000, 49001, 100, 0, TCPFlagSYN, 65535, nil, nil), 36, (*RXChecksumOffload).SetTCP, false},
		{"TCPv6", local6, buildTestTCP(remote6, local6, 49000, 49001, 100, 0, TCPFlagSYN, 65535, nil, nil), 56, (*RXChecksumOffload).SetTCP, false},
		{"UDPv4", local4, buildTestUDP(remote4, local4, 49000, 49001, []byte("udp")), 26, (*RXChecksumOffload).SetUDP, false},
		{"UDPv6", local6, buildTestUDP(remote6, local6, 49000, 49001, []byte("udp")), 46, (*RXChecksumOffload).SetUDP, false},
		{"ICMPv4", local4, buildIPPacket(remote4, local4, ProtocolICMPv4, echo4, 0, true), 22, (*RXChecksumOffload).SetICMPv4, false},
		{"ICMPv6", local6, buildIPPacket(remote6, local6, ProtocolICMPv6, echo6, 0, true), 42, (*RXChecksumOffload).SetICMPv6, false},
		{"IGMP", local4, mustCodecVector(t, "4500001c00000000010217ddc0000202e00000011100eeff00000000"), 22, (*RXChecksumOffload).SetIGMP, true},
		{"MLD", netip.MustParseAddr("fe80::1"), mustCodecVector(t,
			"6000000000200001fe800000000000000000000000000002ff020000000000000000000000000001"+
				"3a0005020000010082007c3e03e8000000000000000000000000000000000000"), 50, (*RXChecksumOffload).SetICMPv6, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, test.local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			packet := append([]byte(nil), test.packet...)
			value := binary.BigEndian.Uint16(packet[test.offset:]) ^ 1
			if value == 0 {
				value = 2
			}
			binary.BigEndian.PutUint16(packet[test.offset:], value)
			for _, mode := range []string{"strict", "other-categories", "matching"} {
				var offload RXChecksumOffload
				if mode == "other-categories" {
					offload.flags = rxChecksumOffloadGenerated
					test.set(&offload, false)
				} else {
					test.set(&offload, mode == "matching")
				}
				enabled := mode == "matching"
				stack.SetRXChecksumOffload(offload)
				if n, err := stack.Write([][]byte{packet}, 0); err != nil || n != 1 {
					t.Fatalf("Write = %d, %v", n, err)
				}
				if test.control {
					stack.mu.RLock()
					accepted := stack.multicastSeed != nil
					stack.mu.RUnlock()
					if accepted != enabled {
						t.Fatalf("multicast Query accepted = %t with offload %t", accepted, enabled)
					}
				} else {
					want := 0
					if enabled {
						want = 1
					}
					if got := stack.outbound.len(); got != want {
						t.Fatalf("response count = %d with offload %t", got, enabled)
					}
				}
			}
			if test.name == "IPv4Header" {
				if _, err := ParseIPPacket(packet); err == nil {
					t.Fatal("public codec accepted an invalid IPv4 checksum")
				}
			}
		})
	}
}

func TestRXChecksumOffloadRetainsFramingAndUDPZeroChecks(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family, local, remote, headerSize := "IPv4", netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 20
		if ipv6 {
			family, local, remote, headerSize = "IPv6", netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 40
		}
		t.Run(family, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			var offload RXChecksumOffload
			offload.SetIPv4Header(true).SetTCP(true).SetUDP(true).SetICMPv4(true).SetICMPv6(true).SetIGMP(true)
			stack.SetRXChecksumOffload(offload)
			udp := buildTestUDP(remote, local, 49000, 49001, []byte("udp"))
			zero := append([]byte(nil), udp...)
			zero[headerSize+6], zero[headerSize+7] = 0, 0
			short := append([]byte(nil), udp...)
			binary.BigEndian.PutUint16(short[headerSize+4:headerSize+6], 7)
			tcp := buildTestTCP(remote, local, 49000, 49001, 100, 0, TCPFlagSYN, 65535, nil, nil)
			tcp[headerSize+12] = 0x40
			invalid := [][]byte{short, tcp, udp[:20]}
			if ipv6 {
				invalid = append(invalid, zero)
			} else {
				ihl := append([]byte(nil), udp...)
				ihl[0] = 0x44
				reserved := append([]byte(nil), udp...)
				reserved[6] |= 0x80
				invalid = append(invalid, ihl, reserved)
			}
			if n, err := stack.Write(invalid, 0); err != nil || n != len(invalid) {
				t.Fatalf("invalid batch Write = %d, %v", n, err)
			}
			if stats := stack.Stats(); stats.InboundDroppedPackets != uint64(len(invalid)) || stack.outbound.len() != 0 {
				t.Fatalf("invalid framing or zero UDP checksum was admitted: %+v", stats)
			}
			if !ipv6 {
				if n, err := stack.Write([][]byte{zero}, 0); err != nil || n != 1 || stack.outbound.len() != 1 {
					t.Fatalf("IPv4 zero-checksum Write = %d, %v; responses = %d", n, err, stack.outbound.len())
				}
			}
		})
	}
}

func TestLoopbackChecksumProvenance(t *testing.T) {
	for _, fair := range []bool{false, true} {
		t.Run(fmt.Sprintf("fair-%t", fair), func(t *testing.T) {
			var queue packetQueue
			if fair {
				queue.initFair(1, time.Now(), 1500, [16]byte{1})
			} else {
				queue.initFIFO(1, time.Now())
			}
			packet := buildTestUDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1000, 1001, []byte("queue"))
			for _, validated := range []bool{true, false, true, false} {
				slot, ok := queue.tryReserve()
				if !ok || !queue.enqueueReservedPacket(slot, packet, false, validated) {
					t.Fatal("could not publish reserved slot")
				}
				entry, ok := queue.tryDequeue()
				if !ok || entry.checksumValidated != validated {
					t.Fatalf("queue checksum provenance = %t, want %t", entry.checksumValidated, validated)
				}
				queue.release(entry)
			}
		})
	}
}

func TestRXChecksumOffloadRawLoopbackKeepsValidation(t *testing.T) {
	for _, local := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		for _, headerIncluded := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/header-%t", local, headerIncluded), func(t *testing.T) {
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				stack.SetRXChecksumOffload(RXChecksumOffload{flags: rxChecksumOffloadGenerated})
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				receiver, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(local, 49001))
				if err != nil {
					t.Fatal(err)
				}
				defer receiver.Close()
				dialer := Dialer{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(headerIncluded)}}
				sender, err := dialer.DialIP(context.Background(), stack, "ip:udp", local, local)
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				payload := []byte("raw-local")
				wire := buildTestUDP(local, local, 49000, 49001, payload)
				parsed, ok := parseIPPacket(wire, false)
				if !ok {
					t.Fatal("invalid production fixture")
				}
				parsed.payload[len(parsed.payload)-1] ^= 1
				input := parsed.payload
				if headerIncluded {
					input = wire
				}
				if _, err = sender.Write(input); err != nil {
					t.Fatal(err)
				}
				waitFor(t, time.Second, func() bool { return stack.Stats().InboundDroppedPackets == 1 })
				parsed.payload[len(parsed.payload)-1] ^= 1
				if _, err = sender.Write(input); err != nil {
					t.Fatal(err)
				}
				_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, len(payload))
				if n, _, err := receiver.ReadFrom(buffer); err != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
					t.Fatalf("valid raw loopback ReadFrom = %d, %v, %x", n, err, buffer)
				}
			})
		}
	}
}

func FuzzRXChecksumOffload(f *testing.F) {
	local4, remote4 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	local6, remote6 := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	f.Add([]byte(nil), byte(0))
	f.Add([]byte{0x45, 0, 0, 20}, byte(rxChecksumOffloadGenerated))
	f.Add(buildTestUDP(remote4, local4, 49000, 49001, []byte("udp")), byte(rxChecksumOffloadGenerated))
	f.Add(buildTestTCP(remote6, local6, 49000, 49001, 100, 0, TCPFlagSYN, 65535, nil, nil), byte(rxChecksumOffloadGenerated))
	for _, addresses := range [][2]netip.Addr{{remote4, local4}, {remote6, local6}} {
		protocol, messageType := byte(ProtocolICMPv4), byte(ICMPv4TypeEchoRequest)
		if addresses[0].Is6() {
			protocol, messageType = ProtocolICMPv6, ICMPv6TypeEchoRequest
		}
		message := mustTestWire((ICMPMessage{Source: addresses[0], Destination: addresses[1], Type: messageType,
			Body: []byte{0, 1, 0, 1, 'x'}}).MarshalBinary())
		f.Add(buildIPPacket(addresses[0], addresses[1], protocol, message, 0, true), byte(rxChecksumOffloadGenerated))
	}
	f.Add(mustCodecVector(f, "4500001c00000000010217ddc0000202e00000011100eeff00000000"), byte(rxChecksumOffloadGenerated))
	f.Add(mustCodecVector(f, "6000000000200001fe800000000000000000000000000002ff020000000000000000000000000001"+
		"3a0005020000010082007c3e03e8000000000000000000000000000000000000"), byte(rxChecksumOffloadGenerated))
	f.Fuzz(func(t *testing.T, packet []byte, flags byte) {
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128)}})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		stack.SetRXChecksumOffload(RXChecksumOffload{flags: uint32(flags) & rxChecksumOffloadGenerated})
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStackReadCompletedPacketWinsCloseRace(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.249")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}

	packet := buildIPPacket(local, netip.MustParseAddr("192.0.2.248"), 99, []byte("completed"), 0, true)
	slot, ok := stack.outbound.tryReserve()
	if !ok || !stack.outbound.enqueueReservedPacket(slot, packet, false, false) {
		t.Fatal("failed to enqueue test packet")
	}
	stack.outbound.free <- slot
	buffer := make([]byte, len(packet))
	sizes := make([]int, 1)
	type readResult struct {
		count int
		err   error
	}
	done := make(chan readResult, 1)
	go func() {
		count, readErr := stack.Read([][]byte{buffer}, sizes, 0)
		done <- readResult{count: count, err: readErr}
	}()
	waitFor(t, time.Second, func() bool { return stack.outbound.slots[slot].Load()&1 == 0 })
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	<-stack.outbound.free
	select {
	case result := <-done:
		if result.count != 1 || result.err != nil {
			t.Fatalf("completed Read = %d, %v, want 1, nil", result.count, result.err)
		}
		if sizes[0] != len(packet) || !bytes.Equal(buffer, packet) {
			t.Fatalf("completed Read payload = %d bytes, equal %t", sizes[0], bytes.Equal(buffer, packet))
		}
	case <-time.After(time.Second):
		t.Fatal("completed Read remained blocked")
	}
}

func TestSocketMessagePeekTruncationAndErrorQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.226")
	remote := netip.MustParseAddrPort("198.51.100.226:5353")
	reporter := netip.MustParseAddr("198.51.100.1")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 5300))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()

	payload := []byte("ordinary-datagram")
	if err = writeTestPacket(stack, buildTestUDP(remote.Addr(), local, remote.Port(), 5300, payload)); err != nil {
		t.Fatal(err)
	}
	peekBuffer := make([]byte, 4)
	peek := []SocketMessage{{Buffers: [][]byte{peekBuffer}, OOB: make([]byte, 128)}}
	if count, readErr := connection.ReadBatch(peek, MessageFlagPeek|MessageFlagTruncated); readErr != nil || count != 1 || peek[0].N != len(payload) || peek[0].Flags != MessageFlagTruncated || !bytes.Equal(peekBuffer, payload[:len(peekBuffer)]) {
		t.Fatalf("peeked truncated datagram = count %d message %+v payload %q, %v", count, peek[0], peekBuffer, readErr)
	}
	ordinary := make([]byte, len(payload))
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{ordinary}}}, 0); readErr != nil || count != 1 || !bytes.Equal(ordinary, payload) {
		t.Fatalf("read after peek = count %d payload %q, %v", count, ordinary, readErr)
	}

	quotedPayload := []byte("quoted-udp-payload")
	quotedPacket := buildTestUDP(local, remote.Addr(), 5300, remote.Port(), quotedPayload)
	quoted, ok := parseIPPacket(quotedPacket, false)
	if !ok {
		t.Fatal("failed to parse quoted UDP packet")
	}
	networkError := ICMPError{
		Reporter: reporter, Type: 3, Code: 3,
		QuotedSource: local, QuotedTarget: remote.Addr(), QuotedProtocol: ProtocolUDP,
		QuotedPacket: quotedPacket, QuotedPayload: quoted.payload,
	}
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(remote, networkError)
	invalid := []SocketMessage{{OOB: make([]byte, 128)}}
	if count, readErr := connection.ReadBatch(invalid, MessageFlagErrorQueue); count != 0 || !errors.Is(readErr, syscall.EINVAL) {
		t.Fatalf("invalid error-queue read = %d, %v", count, readErr)
	}
	if info := connection.Info(); info.ErrorQueueEntries != 1 {
		t.Fatalf("invalid error-queue read consumed entry: %+v", info)
	}
	if err = connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	shortPayload := make([]byte, 3)
	shortControl := make([]byte, 8)
	short := []SocketMessage{{Buffers: [][]byte{shortPayload}, OOB: shortControl}}
	if count, readErr := connection.ReadBatch(short, MessageFlagErrorQueue|MessageFlagPeek); readErr != nil || count != 1 || short[0].N != len(shortPayload) ||
		short[0].NN != len(shortControl) || short[0].Flags != MessageFlagErrorQueue|MessageFlagTruncated|MessageFlagControlTruncated || !bytes.Equal(shortPayload, quotedPayload[:len(shortPayload)]) {
		t.Fatalf("short peek error-queue read = %d message %+v payload %q, %v", count, short[0], shortPayload, readErr)
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagErrorQueue); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("MSG_ERRQUEUE|MSG_PEEK did not consume = %d, %v", count, readErr)
	}

	connection.deliverError(remote, networkError)
	fullPayload := make([]byte, 2)
	fullControl := make([]byte, 128)
	full := []SocketMessage{{Buffers: [][]byte{fullPayload}, OOB: fullControl}}
	if count, readErr := connection.ReadBatch(full, MessageFlagErrorQueue|MessageFlagTruncated); readErr != nil || count != 1 || full[0].N != len(quotedPayload) ||
		full[0].Flags != MessageFlagErrorQueue|MessageFlagTruncated || full[0].Addr.(*net.UDPAddr).AddrPort() != remote {
		t.Fatalf("full-length error-queue read = %d message %+v, %v", count, full[0], readErr)
	}
	var control SocketErrorControlMessage
	if parseErr := control.Parse(fullControl[:full[0].NN]); parseErr != nil || control.Errno != 111 || control.Origin != SocketErrorOriginICMP ||
		control.Type != 3 || control.Code != 3 || control.Offender != reporter {
		t.Fatalf("error-queue control = %+v, %v", control, parseErr)
	}

	if err = connection.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(remote, networkError)
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagPeek|MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("unconnected MSG_PEEK after ignored ICMP = %d, %v", count, readErr)
	}
	if info := connection.Info(); info.ErrorQueueEntries != 0 || info.ErrorQueueBytes != 0 {
		t.Fatalf("ignored ICMP retained an error: %+v", info)
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("read after ignored ICMP = %d, %v", count, readErr)
	}
	connectedNet, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connected := connectedNet.(*UDPConn)
	defer connected.Close()
	connected.deliverError(remote, ICMPError{Reporter: reporter, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort})
	if info := connected.Info(); info.ErrorQueueEntries != 0 || info.ICMPErrors != 1 {
		t.Fatalf("connected UDP pending error = %+v", info)
	}
	count, readErr := connected.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagPeek|MessageFlagDontWait)
	var peekError ICMPError
	if count != 0 || !errors.As(readErr, &peekError) || peekError.Code != 3 {
		t.Fatalf("connected UDP MSG_PEEK pending error = %d, %v", count, readErr)
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 {
		t.Fatalf("connected UDP MSG_PEEK retained pending error: %+v", info)
	}
	if count, readErr := connected.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("connected UDP read after MSG_PEEK error consumption = %d, %v", count, readErr)
	}

	ipConnection := newIPConn(stack, "ip4:99", 99, local, remote.Addr(), socketOptionSet{})
	defer ipConnection.closeFromStack()
	ipConnection.ipHeaderIncludedOnWrite.Store(true)
	if err = ipConnection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	rawPacket := buildIPPacket(local, remote.Addr(), 99, []byte("raw-quote"), 7, true)
	raw, ok := parseIPPacket(rawPacket, false)
	if !ok {
		t.Fatal("failed to parse raw quoted packet")
	}
	ipConnection.deliverError(remote.Addr(), ICMPError{
		Reporter: reporter, Type: 3, Code: 2,
		QuotedSource: local, QuotedTarget: remote.Addr(), QuotedProtocol: 99,
		QuotedPacket: rawPacket, QuotedPayload: raw.payload,
	})
	rawBuffer := make([]byte, len(rawPacket))
	rawMessage := []SocketMessage{{Buffers: [][]byte{rawBuffer}, OOB: make([]byte, 128)}}
	if count, readErr := ipConnection.ReadBatch(rawMessage, MessageFlagErrorQueue); readErr != nil || count != 1 || !bytes.Equal(rawBuffer, rawPacket) || rawMessage[0].Addr.String() != remote.Addr().String() {
		t.Fatalf("header-included raw error queue = %d message %+v, %v", count, rawMessage[0], readErr)
	}
}

func TestStackClosePreventsCacheRepopulation(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.250")
	remote := netip.MustParseAddr("198.51.100.250")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	stack.pathMTU[remote] = pathMTUEntry{mtu: 1200, updated: time.Now()}
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 1600), 600, 1)
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	if packet, pending := stack.reassemblePacketStatus(fragments[0], time.Now(), false); packet != nil || !pending {
		t.Fatalf("first fragment = %x, pending %v", packet, pending)
	}
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	stack.pathMTUMu.RLock()
	pathMTUReleased := stack.pathMTU == nil
	stack.pathMTUMu.RUnlock()
	stack.fragmentMu.Lock()
	fragmentsReleased := stack.fragments == nil && stack.fragmentBytes == 0
	stack.fragmentMu.Unlock()
	if !pathMTUReleased || !fragmentsReleased {
		t.Fatalf("Close retained caches: path MTU released=%v, fragments released=%v", pathMTUReleased, fragmentsReleased)
	}
	if err = stack.ConfirmPathMTU(remote, 1200); !errors.Is(err, ErrClosed) {
		t.Fatalf("ConfirmPathMTU after Close = %v", err)
	}
	if stack.observePathMTU(remote, 1000) || stack.confirmPathMTU(remote, 1200, nil) {
		t.Fatal("internal PMTU update succeeded after Close")
	}
	if packet, pending := stack.reassemblePacketStatus(fragments[1], time.Now(), false); packet != nil || pending {
		t.Fatalf("fragment after Close = %x, pending %v", packet, pending)
	}
	stack.pathMTUMu.RLock()
	pathMTUReleased = stack.pathMTU == nil
	stack.pathMTUMu.RUnlock()
	stack.fragmentMu.Lock()
	fragmentsReleased = stack.fragments == nil && stack.fragmentBytes == 0
	stack.fragmentMu.Unlock()
	if !pathMTUReleased || !fragmentsReleased {
		t.Fatalf("post-Close operation rebuilt caches: path MTU released=%v, fragments released=%v", pathMTUReleased, fragmentsReleased)
	}
}

func TestMonotonicStampRoundTripAndClamping(t *testing.T) {
	epoch := time.Unix(100, 123)
	value := epoch.Add(250*time.Millisecond + 456*time.Nanosecond)
	stamp := monotonicStampAt(epoch, value)
	if got := stamp.time(epoch); got != value {
		t.Fatalf("monotonic timestamp round trip = %v, want %v", got, value)
	}
	if got := monotonicStampAt(epoch, epoch.Add(-time.Nanosecond)).time(epoch); got != epoch {
		t.Fatalf("pre-epoch timestamp = %v, want %v", got, epoch)
	}
	if got := monotonicStampAt(epoch, time.Time{}); got != 0 {
		t.Fatalf("zero timestamp encoding = %d, want 0", got)
	}
	if got := monotonicStamp(0).time(epoch); !got.IsZero() {
		t.Fatalf("zero timestamp decoding = %v, want zero time", got)
	}
}

func TestListenValidationPrecedesLifecycle(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenTCP(context.Background(), "udp", netip.AddrPort{})
	if err == nil {
		t.Fatal("ListenTCP accepted an invalid network before Start")
	} else {
		if listener != nil {
			t.Fatalf("ListenTCP error returned non-nil listener %T", listener)
		}
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("invalid network error = %v, want net.UnknownNetworkError", err)
		}
	}
	packet, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("mismatched listen family error = %v, want EAFNOSUPPORT", err)
	} else if packet != nil {
		t.Fatalf("ListenUDP error returned non-nil packet connection %T", packet)
	}
	listener, err = stack.ListenTCP(context.Background(), "tcp", netip.AddrPort{})
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("valid listen before Start error = %v, want ErrNotStarted", err)
	} else if listener != nil {
		t.Fatalf("ListenTCP before Start returned non-nil listener %T", listener)
	}
}

func TestListenErrorsReturnNilResults(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	packet, err := stack.ListenIP(context.Background(), "tcp", netip.Addr{})
	if err == nil || packet != nil {
		t.Fatalf("ListenIP invalid network = %T, %v; want nil, error", packet, err)
	}
	multicastConnection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.MustParseAddrPort("192.0.2.1:5353"))
	if !errors.Is(err, syscall.EINVAL) || multicastConnection != nil {
		t.Fatalf("ListenMulticastUDP invalid group = %T, %v; want nil, EINVAL", multicastConnection, err)
	}

	listener, err := (*ListenConfig)(nil).ListenTCP(context.Background(), nil, "tcp", netip.AddrPort{})
	if err == nil || listener != nil {
		t.Fatalf("ListenConfig.ListenTCP nil stack = %T, %v; want nil, error", listener, err)
	}
	packet, err = (*ListenConfig)(nil).ListenUDP(context.Background(), nil, "udp", netip.AddrPort{})
	if err == nil || packet != nil {
		t.Fatalf("ListenConfig.ListenUDP nil stack = %T, %v; want nil, error", packet, err)
	}
	packet, err = (*ListenConfig)(nil).ListenIP(context.Background(), nil, "ip:99", netip.Addr{})
	if err == nil || packet != nil {
		t.Fatalf("ListenConfig.ListenIP nil stack = %T, %v; want nil, error", packet, err)
	}
}

func TestListenNetworkWildcardNormalization(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.10")
	local6 := netip.MustParseAddr("2001:db8::10")
	remote4 := netip.MustParseAddr("198.51.100.10")
	remote6 := netip.MustParseAddr("2001:db8:1::10")
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
	state := stack.network.Load()
	for _, test := range []struct {
		name    string
		network string
		address netip.Addr
		want    netip.Addr
		dual    bool
	}{
		{name: "generic empty", network: "tcp", want: netip.IPv6Unspecified(), dual: true},
		{name: "generic IPv4 unspecified", network: "tcp", address: netip.IPv4Unspecified(), want: netip.IPv6Unspecified(), dual: true},
		{name: "generic IPv6 unspecified", network: "tcp", address: netip.IPv6Unspecified(), want: netip.IPv6Unspecified(), dual: true},
		{name: "IPv4 empty", network: "tcp4", want: netip.IPv4Unspecified()},
		{name: "IPv6 empty", network: "tcp6", want: netip.IPv6Unspecified()},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, dual, listenErr := listenAddress(state, test.network, "tcp", test.address)
			if listenErr != nil || address != test.want || dual != test.dual {
				t.Fatalf("listenAddress(%q, %v) = %v, %v, %v; want %v, %v, nil", test.network, test.address, address, dual, listenErr, test.want, test.dual)
			}
		})
	}

	tcpListener, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpLocal := tcpListener.Addr().(*net.TCPAddr).AddrPort()
	if !tcpLocal.Addr().Is6() || !tcpLocal.Addr().IsUnspecified() || !tcpListener.(*TCPListener).dual {
		t.Fatalf("generic TCP wildcard = %v, dual = %v", tcpLocal, tcpListener.(*TCPListener).dual)
	}
	stack.mu.RLock()
	passive := stack.tcpPassive.(*tcpPassiveState)
	lookup4 := passive.listener(netip.AddrPortFrom(local4, tcpLocal.Port()), netip.AddrPort{})
	lookup6 := passive.listener(netip.AddrPortFrom(local6, tcpLocal.Port()), netip.AddrPort{})
	stack.mu.RUnlock()
	if lookup4 != tcpListener.(*TCPListener) || lookup6 != tcpListener.(*TCPListener) {
		t.Fatalf("dual TCP lookup = %p/%p, want %p", lookup4, lookup6, tcpListener.(*TCPListener))
	}

	udpConnection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(netip.Addr{}, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	udpLocal := udpConnection.LocalAddr().(*net.UDPAddr).AddrPort()
	if udpLocal != netip.AddrPortFrom(netip.IPv6Unspecified(), 46000) || !udpConnection.(*UDPConn).dual {
		t.Fatalf("generic UDP wildcard = %v, dual = %v", udpLocal, udpConnection.(*UDPConn).dual)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote4, local4, 50000, 46000, []byte("v4"))); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote6, local6, 50001, 46000, []byte("v6"))); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	for _, expected := range []string{"v4", "v6"} {
		n, _, readErr := udpConnection.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != expected {
			t.Fatalf("dual UDP read = %q, %v, want %q", buffer[:n], readErr, expected)
		}
	}

	tcp6, err := stack.ListenTCP(context.Background(), "tcp6", netip.AddrPortFrom(netip.Addr{}, 46001))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp6.Close()
	if tcp6.(*TCPListener).dual || tcp6.Addr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(netip.IPv6Unspecified(), 46001) {
		t.Fatalf("tcp6 wildcard = %v, dual = %v", tcp6.Addr(), tcp6.(*TCPListener).dual)
	}
	udp4, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.Addr{}, 46002))
	if err != nil {
		t.Fatal(err)
	}
	defer udp4.Close()
	if got := udp4.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(netip.IPv4Unspecified(), 46002) {
		t.Fatalf("udp4 empty-address wildcard = %v", got)
	}
	udp6, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(netip.Addr{}, 46003))
	if err != nil {
		t.Fatal(err)
	}
	defer udp6.Close()
	if got := udp6.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(netip.IPv6Unspecified(), 46003) {
		t.Fatalf("udp6 empty-address wildcard = %v", got)
	}
	if _, err = stack.ListenUDP(context.Background(), "tcp", netip.AddrPort{}); err == nil {
		t.Fatal("ListenUDP accepted a TCP network")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("unknown listen network error = %v", err)
		}
	}
}

func TestDialCrossFamilyUnspecifiedSource(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("198.51.100.11"))
	defer stack.Close()
	link.echoTCP = true
	source := netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	remoteTCP := netip.AddrPortFrom(link.remote, 8080)
	connection, err := stack.DialTCP(context.Background(), "tcp", source, remoteTCP)
	if err != nil {
		t.Fatalf("generic DialTCP: %v", err)
	}
	connection.Close()
	if _, err = stack.DialTCP(context.Background(), "tcp4", source, remoteTCP); err == nil {
		t.Fatal("tcp4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("tcp4 source-family error = %T %v", err, err)
		}
	}
	remoteUDP := netip.AddrPortFrom(link.remote, 5353)
	udpConnection, err := stack.DialUDP(context.Background(), "udp", source, remoteUDP)
	if err != nil {
		t.Fatalf("generic DialUDP: %v", err)
	}
	udpConnection.Close()
	if _, err = stack.DialUDP(context.Background(), "udp4", source, remoteUDP); err == nil {
		t.Fatal("udp4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("udp4 source-family error = %T %v", err, err)
		}
	}
	ipConnection, err := stack.DialIP(context.Background(), "ip:99", netip.IPv6Unspecified(), link.remote)
	if err != nil {
		t.Fatalf("generic DialIP: %v", err)
	}
	ipConnection.Close()
	if _, err = stack.DialIP(context.Background(), "ip4:99", netip.IPv6Unspecified(), link.remote); err == nil {
		t.Fatal("ip4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("ip4 source-family error = %T %v", err, err)
		}
	}
}

func TestFullLoopbackQueueDoesNotBlock(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.12")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	fillTestPacketQueue(t, &stack.loopback.packetQueue, []byte{0})
	packet := buildIPPacket(local, local, ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
	if err = stack.tryWritePacket(packet, false); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("tryWritePacket to full loopback queue = %v, want ErrResourceLimit", err)
	}
	if got := stack.Stats().LoopbackQueueDrops; got != 1 {
		t.Fatalf("full loopback queue drops = %d, want 1", got)
	}
}

func TestPacketQueueLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout assertion")
	}
	for _, test := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "packet queue", got: unsafe.Sizeof(packetQueue{}), want: 96},
		{name: "loopback queue", got: unsafe.Sizeof(loopbackQueue{}), want: 104},
		{name: "packet queue entry", got: unsafe.Sizeof(packetQueueEntry{}), want: 32},
	} {
		if test.got != test.want {
			t.Errorf("%s size = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func TestPacketQueueTicketTracksDeviceDequeue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.13")
	remote := netip.MustParseAddr("192.0.2.14")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	packet := buildIPPacket(local, remote, ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
	queue, loopback := stack.outputQueue(packet)
	if loopback {
		t.Fatal("remote packet selected the loopback queue")
	}
	slot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("packet queue slot was not available")
	}
	ticket, published := queue.enqueueReservedTCP(slot, packet, false, 1, false)
	if !published {
		t.Fatal("packet queue ticket was not published")
	}
	stack.recordOutput(false)
	if !ticket.pendingIn(queue) {
		t.Fatal("new packet queue ticket is not pending")
	}
	buffer := make([]byte, 1500)
	if count, readErr := stack.Read([][]byte{buffer}, []int{0}, 0); readErr != nil || count != 1 {
		t.Fatalf("device Read = %d, %v", count, readErr)
	}
	if ticket.pendingIn(queue) {
		t.Fatal("packet queue ticket remained pending after device Read")
	}
}

func TestPacketQueueTicketGenerationSurvivesSlotReuse(t *testing.T) {
	var queue packetQueue
	queue.initFIFO(1, time.Now())
	firstSlot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("first queue slot was not available")
	}
	first, published := queue.enqueueReservedTCP(firstSlot, []byte{1}, false, 1, false)
	if !published {
		t.Fatal("first queue ticket was not published")
	}
	if !first.pendingIn(&queue) {
		t.Fatal("first queue ticket was not pending")
	}
	entry, _ := queue.tryDequeue()
	queue.release(entry)
	if first.pendingIn(&queue) {
		t.Fatal("consumed queue ticket remained pending")
	}
	secondSlot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("reused queue slot was not available")
	}
	second, published := queue.enqueueReservedTCP(secondSlot, []byte{2}, false, 1, false)
	if !published {
		t.Fatal("second queue ticket was not published")
	}
	if !second.pendingIn(&queue) {
		t.Fatal("reused queue slot was not pending")
	}
	if first.pendingIn(&queue) || first.generation() == second.generation() {
		t.Fatalf("slot reuse revived generation %d as %d", first.generation(), second.generation())
	}
	entry, _ = queue.tryDequeue()
	queue.release(entry)
	if second.pendingIn(&queue) {
		t.Fatal("second queue ticket remained pending")
	}
}

func TestPacketQueueTicketSelectsItsQueue(t *testing.T) {
	epoch := time.Now()
	stack := &Stack{}
	stack.outbound.initFIFO(1, epoch)
	stack.loopback.initFIFO(1, epoch)
	outboundSlot, outboundReserved := stack.outbound.tryReserve()
	loopbackSlot, loopbackReserved := stack.loopback.tryReserve()
	if !outboundReserved || !loopbackReserved {
		t.Fatal("packet queue slots were not available")
	}
	outbound, _ := stack.outbound.enqueueReservedTCP(outboundSlot, []byte{1}, false, 1, false)
	loopback, _ := stack.loopback.enqueueReservedTCP(loopbackSlot, []byte{2}, false, 1, true)
	if outbound.loopback() || !loopback.loopback() || !outbound.pending(stack) || !loopback.pending(stack) {
		t.Fatal("packet queue tickets did not retain their queue identity")
	}
	entry, _ := stack.outbound.tryDequeue()
	stack.outbound.release(entry)
	if outbound.pending(stack) || !loopback.pending(stack) {
		t.Fatal("consuming outbound packet changed the wrong ticket")
	}
	entry, _ = stack.loopback.tryDequeue()
	stack.loopback.release(entry)
	if loopback.pending(stack) {
		t.Fatal("loopback ticket remained pending after consumption")
	}
}

func TestPacketQueueDepartureWaiterFollowsExactGeneration(t *testing.T) {
	for _, test := range []struct {
		name     string
		fair     bool
		loopback bool
	}{
		{name: "FIFO"},
		{name: "DRR", fair: true},
		{name: "loopback", loopback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			epoch := time.Now()
			stack := &Stack{}
			queue := &stack.outbound
			if test.loopback {
				queue = &stack.loopback.packetQueue
			}
			if test.fair {
				queue.initFair(1, epoch, 1500, [16]byte{})
			} else {
				queue.initFIFO(1, epoch)
			}
			slot, reserved := queue.tryReserve()
			if !reserved {
				t.Fatal("packet queue slot was not available")
			}
			ticket, published := queue.enqueueReservedTCP(slot, []byte{1}, false, 1, test.loopback)
			if !published {
				t.Fatal("packet queue ticket was not published")
			}
			notify := make(chan struct{}, 1)
			waiter := ticket.departureWaiter(stack, notify)
			if waiter == nil {
				t.Fatal("pending packet did not install a departure waiter")
			}
			if _, departed := waiter.departedTime(epoch); departed {
				t.Fatal("departure waiter completed before dequeue")
			}
			before := time.Now()
			entry, available := queue.tryDequeue()
			if !available {
				t.Fatal("published packet was not schedulable")
			}
			select {
			case <-notify:
			default:
				t.Fatal("queue dequeue did not notify the departure waiter")
			}
			departedAt, departed := waiter.departedTime(epoch)
			if !departed || departedAt.Before(before) || departedAt.After(time.Now()) {
				t.Fatalf("departure time = %v, departed %t", departedAt, departed)
			}
			if ticket.pending(stack) {
				t.Fatal("dequeued ticket remained pending")
			}
			if len(queue.free) != 0 {
				t.Fatal("dequeue released capacity before the consumer finished")
			}
			queue.release(entry)
			if len(queue.free) != cap(queue.free) {
				t.Fatal("packet release did not restore queue capacity")
			}
		})
	}
}

func TestPacketQueueDepartureWaiterSurvivesRegistrationRace(t *testing.T) {
	epoch := time.Now()
	stack := &Stack{}
	stack.outbound.initFIFO(1, epoch)
	for iteration := 0; iteration < 2048; iteration++ {
		slot, reserved := stack.outbound.tryReserve()
		if !reserved {
			t.Fatalf("iteration %d did not reserve the queue slot", iteration)
		}
		ticket, published := stack.outbound.enqueueReservedTCP(slot, []byte{1}, false, 1, false)
		if !published {
			t.Fatalf("iteration %d did not publish the packet", iteration)
		}
		notify := make(chan struct{}, 1)
		result := make(chan *packetQueueDepartureWaiter, 1)
		start := make(chan struct{})
		go func() {
			<-start
			result <- ticket.departureWaiter(stack, notify)
		}()
		close(start)
		entry, available := stack.outbound.tryDequeue()
		if !available {
			t.Fatalf("iteration %d did not dequeue the packet", iteration)
		}
		stack.outbound.release(entry)
		waiter := <-result
		if waiter != nil {
			if _, departed := waiter.departedTime(epoch); !departed {
				t.Fatalf("iteration %d lost a release racing waiter registration", iteration)
			}
		}
		if ticket.departureWaiter(stack, notify) != nil {
			t.Fatalf("iteration %d registered a waiter after departure", iteration)
		}
	}
}

func TestPacketQueueDepartureWaiterDoesNotAliasReusedSlot(t *testing.T) {
	epoch := time.Now()
	stack := &Stack{}
	stack.outbound.initFIFO(1, epoch)
	firstSlot, _ := stack.outbound.tryReserve()
	first, _ := stack.outbound.enqueueReservedTCP(firstSlot, []byte{1}, false, 1, false)
	firstEntry, _ := stack.outbound.tryDequeue()
	stack.outbound.release(firstEntry)

	secondSlot, _ := stack.outbound.tryReserve()
	second, _ := stack.outbound.enqueueReservedTCP(secondSlot, []byte{2}, false, 1, false)
	notify := make(chan struct{}, 1)
	waiter := second.departureWaiter(stack, notify)
	if waiter == nil {
		t.Fatal("reused slot did not install its current departure waiter")
	}
	if first.departureWaiter(stack, notify) != nil {
		t.Fatal("departed generation installed a waiter over a reused slot")
	}
	secondEntry, _ := stack.outbound.tryDequeue()
	stack.outbound.release(secondEntry)
	select {
	case <-notify:
	default:
		t.Fatal("current generation waiter was not notified")
	}
	if _, departed := waiter.departedTime(epoch); !departed {
		t.Fatal("current generation waiter did not record departure")
	}
}

func TestPacketQueueDepartureWaiterCompletesOnClose(t *testing.T) {
	epoch := time.Now()
	stack := &Stack{}
	stack.outbound.initFIFO(1, epoch)
	slot, _ := stack.outbound.tryReserve()
	ticket, _ := stack.outbound.enqueueReservedTCP(slot, []byte{1}, false, 1, false)
	notify := make(chan struct{}, 1)
	waiter := ticket.departureWaiter(stack, notify)
	stack.outbound.close()
	select {
	case <-notify:
	default:
		t.Fatal("queue close did not notify the departure waiter")
	}
	if _, departed := waiter.departedTime(epoch); !departed {
		t.Fatal("queue close did not record packet departure")
	}
}

func TestPacketQueueReleaseDoesNotAllocateDepartureState(t *testing.T) {
	var queue packetQueue
	queue.initFIFO(1, time.Now())
	slot, _ := queue.tryReserve()
	_, _ = queue.enqueueReservedTCP(slot, []byte{1}, false, 1, false)
	entry, _ := queue.tryDequeue()
	queue.release(entry)
	if queue.departureWaiters.Load() != nil {
		t.Fatal("ordinary queue release allocated departure state")
	}
}

func TestTryWriteLoopbackPacketsCloseBeforeBatchPublication(t *testing.T) {
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
		MTU:            1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}

	packets := [][]byte{
		buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), 253, []byte{1}, 1, true),
		buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), 253, []byte{2}, 2, true),
	}
	stack.loopback.batchMu.Lock()
	writeResult := make(chan error, 1)
	go func() { writeResult <- stack.tryWritePackets(packets, outputFlowKey{}, false) }()
	wantFree := cap(stack.loopback.free) - len(packets)
	waitFor(t, time.Second, func() bool { return len(stack.loopback.free) == wantFree })

	closeResult := make(chan error, 1)
	go func() { closeResult <- stack.Close() }()
	select {
	case <-stack.closeCh:
	case <-time.After(time.Second):
		t.Fatal("Close did not publish stack closure")
	}
	stack.loopback.batchMu.Unlock()

	if err = <-writeResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("tryWritePackets during Close = %v, want ErrClosed", err)
	}
	if err = <-closeResult; err != nil {
		t.Fatal(err)
	}
	if got := stack.loopback.len(); got != 0 {
		t.Fatalf("closed batch exposed %d packets", got)
	}
	if got, want := len(stack.loopback.free), cap(stack.loopback.free); got != want {
		t.Fatalf("closed batch free slots = %d, want %d", got, want)
	}
	if got := stack.Stats().LoopbackQueueDrops; got != 0 {
		t.Fatalf("queue close counted %d loopback drops", got)
	}
}

func TestDatagramQueueRetainsOnlySmallBacking(t *testing.T) {
	var queue datagramQueue[int]
	for value := 0; value < datagramQueueRetain; value++ {
		queue.push(value)
	}
	for value := 0; value < datagramQueueRetain; value++ {
		got, ok := queue.pop()
		if !ok || got != value {
			t.Fatalf("small queue pop = %d, %v, want %d, true", got, ok, value)
		}
	}
	if queue.len() != 0 || cap(queue.values) == 0 || cap(queue.values) > datagramQueueRetain {
		t.Fatalf("small drained queue = len %d cap %d", queue.len(), cap(queue.values))
	}
	for value := 0; value < datagramQueueRetain+1; value++ {
		queue.push(value)
	}
	for value := 0; value < datagramQueueRetain+1; value++ {
		got, ok := queue.pop()
		if !ok || got != value {
			t.Fatalf("large queue pop = %d, %v, want %d, true", got, ok, value)
		}
	}
	if queue.values != nil || queue.head != 0 {
		t.Fatalf("large drained queue retained len %d cap %d head %d", len(queue.values), cap(queue.values), queue.head)
	}

	values := [6]int{0, 1, 2, 3, 4, 5}
	compacted := datagramQueue[*int]{values: make([]*int, 4, 4)}
	for index := range compacted.values {
		compacted.values[index] = &values[index]
	}
	for index := 0; index < 2; index++ {
		if got, ok := compacted.pop(); !ok || got != &values[index] {
			t.Fatalf("compaction prefix pop = %v, %v, want %v, true", got, ok, &values[index])
		}
	}
	compacted.push(&values[4])
	compacted.push(&values[5])
	for index := 2; index < len(values); index++ {
		if got, ok := compacted.pop(); !ok || got != &values[index] {
			t.Fatalf("compacted queue pop = %v, %v, want %v, true", got, ok, &values[index])
		}
	}
	for _, retained := range compacted.values[:cap(compacted.values)] {
		if retained != nil {
			t.Fatalf("drained compacted queue retained %v", retained)
		}
	}
}

func TestDatagramSocketLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout assertion")
	}
	for _, test := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "UDPConn", got: unsafe.Sizeof(UDPConn{}), want: 288},
		{name: "IPConn", got: unsafe.Sizeof(IPConn{}), want: 288},
		{name: "datagram write control", got: unsafe.Sizeof(datagramSocketWriteControl{}), want: 16},
		{name: "datagram socket error state", got: unsafe.Sizeof(datagramSocketErrorState{}), want: 72},
		{name: "datagram deadline state", got: unsafe.Sizeof(datagramSocketDeadlineState{}), want: 16},
		{name: "IP socket ICMP filter", got: unsafe.Sizeof(ipConnICMPFilter{}), want: 32},
		{name: "recent destination cache", got: unsafe.Sizeof(recentDestinationCache[netip.AddrPort]{}), want: 8},
		{name: "recent destination state", got: unsafe.Sizeof(recentDestinationCacheState[netip.AddrPort]{}), want: 48},
	} {
		if test.got != test.want {
			t.Errorf("%s size = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func TestSocketDeadlineRefreshAndClear(t *testing.T) {
	var deadline socketDeadline
	initial := deadline.waitLocked()
	deadline.setLocked(time.Now().Add(20 * time.Millisecond).Round(0))
	deadline.setLocked(time.Now().Add(time.Hour).Round(0))
	if current := deadline.waitLocked(); current != initial {
		t.Fatal("live deadline update replaced the waiter channel")
	}
	wait := time.NewTimer(40 * time.Millisecond)
	select {
	case <-initial:
		wait.Stop()
		t.Fatal("superseded deadline closed the waiter channel")
	case <-wait.C:
	}
	deadline.setLocked(time.Time{})
	if current := deadline.waitLocked(); current != initial {
		t.Fatal("clearing a live deadline replaced the waiter channel")
	}
	deadline.setLocked(time.Now().Add(-time.Second))
	select {
	case <-initial:
	default:
		t.Fatal("expired deadline did not close the waiter channel")
	}
	deadline.setLocked(time.Now().Add(time.Hour))
	refreshed := deadline.waitLocked()
	if refreshed == initial {
		t.Fatal("refreshing an expired deadline retained its closed channel")
	}
	select {
	case <-refreshed:
		t.Fatal("refreshed deadline channel is already closed")
	default:
	}
	deadline.stopLocked()
	armed := deadline.timer != nil
	if armed {
		t.Fatal("stopped deadline retained its timer")
	}
}

func TestSocketDeadlineZeroDoesNotAllocateChannel(t *testing.T) {
	var deadline socketDeadline
	deadline.setLocked(time.Time{})
	if deadline.channelLocked() != nil {
		t.Fatal("zero deadline allocated a channel generation")
	}
}

func TestDatagramSocketDeadlineLifecycle(t *testing.T) {
	var deadline datagramSocketDeadline
	deadline.set(time.Time{})
	if deadline.channel() != nil || deadline.state.Load() != nil {
		t.Fatal("zero deadline allocated state")
	}
	initial := deadline.wait()
	deadline.set(time.Now().Add(20 * time.Millisecond).Round(0))
	deadline.set(time.Now().Add(time.Hour).Round(0))
	if current := deadline.wait(); current != initial {
		t.Fatal("live deadline update replaced the waiter channel")
	}
	wait := time.NewTimer(40 * time.Millisecond)
	select {
	case <-initial:
		wait.Stop()
		t.Fatal("superseded deadline closed the waiter channel")
	case <-wait.C:
	}
	deadline.set(time.Time{})
	select {
	case <-initial:
		t.Fatal("cleared live deadline closed the waiter channel")
	default:
	}
	deadline.set(time.Now().Add(-time.Second))
	select {
	case <-initial:
	case <-time.After(time.Second):
		t.Fatal("expired deadline did not close the waiter channel")
	}
	deadline.set(time.Time{})
	if deadline.channel() != nil {
		t.Fatal("cleared expired deadline retained a closed generation")
	}
	if next := deadline.wait(); next == nil || next == initial {
		t.Fatal("wait after clear did not create a live generation")
	}
	deadline.stop()
	if deadline.state.Load() != stoppedDatagramSocketDeadline || deadline.wait() != nil {
		t.Fatal("stop did not publish the terminal state")
	}
}

type deadlineOperationResult struct {
	bytes int
	err   error
}

func testMutableDeadline(t *testing.T, set func(time.Time) error, operation func() (int, error)) {
	t.Helper()
	const pendingDeadlineWindow = 250 * time.Millisecond
	checkTimeout := func(result deadlineOperationResult) {
		t.Helper()
		if result.bytes != 0 || !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("operation = %d, %v, want 0, os.ErrDeadlineExceeded", result.bytes, result.err)
		}
		var netErr net.Error
		if !errors.As(result.err, &netErr) || !netErr.Timeout() {
			t.Fatalf("operation error = %v, want net.Error with Timeout", result.err)
		}
	}
	start := func() <-chan deadlineOperationResult {
		done := make(chan deadlineOperationResult, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			bytes, err := operation()
			done <- deadlineOperationResult{bytes: bytes, err: err}
		}()
		<-started
		return done
	}
	waitUntil := func(deadline time.Time, done <-chan deadlineOperationResult, message string) {
		t.Helper()
		wait := time.NewTimer(time.Until(deadline) + 25*time.Millisecond)
		defer wait.Stop()
		select {
		case result := <-done:
			t.Fatalf("%s: %d, %v", message, result.bytes, result.err)
		case <-wait.C:
		}
	}

	if err := set(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	done := start()
	time.Sleep(10 * time.Millisecond)
	earlier := time.Now().Add(50 * time.Millisecond).Round(0)
	if err := set(earlier); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if time.Now().Before(earlier) {
			t.Fatalf("operation returned before wall-only deadline %v", earlier)
		}
		checkTimeout(result)
	case <-time.After(time.Second):
		t.Fatal("operation did not observe an earlier deadline")
	}

	oldDeadline := time.Now().Add(pendingDeadlineWindow)
	if err := set(oldDeadline); err != nil {
		t.Fatal(err)
	}
	done = start()
	time.Sleep(10 * time.Millisecond)
	later := time.Now().Add(2 * pendingDeadlineWindow)
	if err := set(later); err != nil {
		t.Fatal(err)
	}
	waitUntil(oldDeadline, done, "operation retained the superseded deadline")
	select {
	case result := <-done:
		if time.Now().Before(later) {
			t.Fatalf("operation returned before extended deadline %v", later)
		}
		checkTimeout(result)
	case <-time.After(time.Second):
		t.Fatal("operation did not observe an extended deadline")
	}

	clearedDeadline := time.Now().Add(pendingDeadlineWindow)
	if err := set(clearedDeadline); err != nil {
		t.Fatal(err)
	}
	done = start()
	time.Sleep(10 * time.Millisecond)
	if err := set(time.Time{}); err != nil {
		t.Fatal(err)
	}
	waitUntil(clearedDeadline, done, "operation retained a cleared deadline")
	if err := set(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		checkTimeout(result)
	case <-time.After(time.Second):
		t.Fatal("operation did not observe a deadline after clearing")
	}
}

func TestPendingReadDeadlineUpdates(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.echoTCP = true

	tcpConnection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConnection.Close()
	udpConnection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	ipConnection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	listener, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tests := []struct {
		name      string
		set       func(time.Time) error
		operation func() (int, error)
	}{
		{name: "TCP read", set: tcpConnection.SetReadDeadline, operation: func() (int, error) { return tcpConnection.Read(make([]byte, 1)) }},
		{name: "UDP read", set: udpConnection.SetReadDeadline, operation: func() (int, error) {
			n, _, readErr := udpConnection.ReadFrom(make([]byte, 1))
			return n, readErr
		}},
		{name: "IP read", set: ipConnection.SetReadDeadline, operation: func() (int, error) {
			n, _, readErr := ipConnection.ReadFrom(make([]byte, 1))
			return n, readErr
		}},
		{name: "TCP accept", set: listener.(*TCPListener).SetDeadline, operation: func() (int, error) {
			_, acceptErr := listener.Accept()
			return 0, acceptErr
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { testMutableDeadline(t, test.set, test.operation) })
	}
}

func TestExpiredDeadlinePrecedesQueuedIO(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.31")
	remote := netip.MustParseAddr("192.0.2.32")
	link, stack := newTestStack(t, local, remote)
	link.echoTCP = true
	past := time.Now().Add(-time.Second)

	t.Run("TCP read", func(t *testing.T) {
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 8031))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err = connection.Write([]byte("t")); err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		waitFor(t, time.Second, func() bool {
			tcpConnection.mu.Lock()
			ready := tcpConnection.readBuffer.size != 0
			tcpConnection.mu.Unlock()
			return ready
		})
		if err = connection.SetReadDeadline(past); err != nil {
			t.Fatal(err)
		}
		if n, readErr := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
			t.Fatalf("expired TCP Read = %d, %v", n, readErr)
		}
		if err = connection.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if n, readErr := connection.Read(buffer); n != 1 || readErr != nil || buffer[0] != 't' {
			t.Fatalf("TCP Read after clearing deadline = %d, %q, %v", n, buffer[:n], readErr)
		}
	})

	t.Run("UDP read", func(t *testing.T) {
		packetConnection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(local, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer packetConnection.Close()
		connection := packetConnection.(*UDPConn)
		source := netip.AddrPortFrom(remote, 5300)
		connection.enqueue([]byte("u"), source, local, ipPacketOptions{})
		if err = connection.SetReadDeadline(past); err != nil {
			t.Fatal(err)
		}
		if n, _, readErr := connection.ReadFrom(make([]byte, 1)); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
			t.Fatalf("expired UDP ReadFrom = %d, %v", n, readErr)
		}
		if err = connection.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		n, address, readErr := connection.ReadFrom(buffer)
		if n != 1 || readErr != nil || buffer[0] != 'u' || address.(*net.UDPAddr).AddrPort() != source {
			t.Fatalf("UDP ReadFrom after clearing deadline = %d, %q, %v, %v", n, buffer[:n], address, readErr)
		}
	})

	t.Run("IP read", func(t *testing.T) {
		connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		connection.(*IPConn).enqueuePacket(ipPacket{payload: []byte("i"), source: remote, target: local}, ipPacketOptions{})
		if err = connection.SetReadDeadline(past); err != nil {
			t.Fatal(err)
		}
		if n, _, readErr := connection.ReadFrom(make([]byte, 1)); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
			t.Fatalf("expired IP ReadFrom = %d, %v", n, readErr)
		}
		if err = connection.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		n, address, readErr := connection.ReadFrom(buffer)
		if n != 1 || readErr != nil || buffer[0] != 'i' || address.(*net.IPAddr).String() != remote.String() {
			t.Fatalf("IP ReadFrom after clearing deadline = %d, %q, %v, %v", n, buffer[:n], address, readErr)
		}
	})

	t.Run("TCP accept", func(t *testing.T) {
		listener, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(local, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, listener.(*TCPListener).local)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		waitFor(t, time.Second, func() bool { return listener.(*TCPListener).Info().AcceptQueueConnections == 1 })
		if err = listener.(*TCPListener).SetDeadline(past); err != nil {
			t.Fatal(err)
		}
		if connection, acceptErr := listener.Accept(); connection != nil || !errors.Is(acceptErr, os.ErrDeadlineExceeded) {
			t.Fatalf("expired TCP Accept = %v, %v", connection, acceptErr)
		}
		if err = listener.(*TCPListener).SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = server.Close()
	})
}

func TestDatagramWriteQueueExhaustionPolicy(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("192.0.2.42")
	for _, test := range []struct {
		name       string
		open       func(*Stack) (net.PacketConn, error)
		target     net.Addr
		configure  func(net.PacketConn, bool) error
		statistics func(net.PacketConn) (uint64, uint64)
		correlated func(net.PacketConn) bool
	}{
		{
			name: "UDP",
			open: func(stack *Stack) (net.PacketConn, error) {
				return stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
			},
			target: net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 53)),
			configure: func(connection net.PacketConn, enabled bool) error {
				return connection.(*UDPConn).SetReceiveErrors(enabled)
			},
			statistics: func(connection net.PacketConn) (uint64, uint64) {
				info := connection.(*UDPConn).Info()
				return info.PacketsSent, info.BytesSent
			},
			correlated: func(connection net.PacketConn) bool {
				return connection.(*UDPConn).acceptsError(netip.AddrPortFrom(remote, 53))
			},
		},
		{
			name: "IP",
			open: func(stack *Stack) (net.PacketConn, error) {
				return stack.ListenIP(context.Background(), "ip4:99", local)
			},
			target: ipNetAddr(remote),
			configure: func(connection net.PacketConn, enabled bool) error {
				return connection.(*IPConn).SetReceiveErrors(enabled)
			},
			statistics: func(connection net.PacketConn) (uint64, uint64) {
				info := connection.(*IPConn).Info()
				return info.PacketsSent, info.BytesSent
			},
			correlated: func(connection net.PacketConn) bool {
				return connection.(*IPConn).acceptsError(remote)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			connection, err := test.open(stack)
			if err != nil {
				t.Fatal(err)
			}
			fillTestPacketQueue(t, &stack.outbound, []byte{0})
			payload := []byte("query")
			write := func() deadlineOperationResult {
				done := make(chan deadlineOperationResult, 1)
				go func() {
					bytes, writeErr := connection.WriteTo(payload, test.target)
					done <- deadlineOperationResult{bytes: bytes, err: writeErr}
				}()
				select {
				case result := <-done:
					return result
				case <-time.After(time.Second):
					t.Fatal("datagram write waited for unavailable device capacity")
					return deadlineOperationResult{}
				}
			}

			if err = connection.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			before := stack.outbound.len()
			if result := write(); result.bytes != len(payload) || result.err != nil {
				t.Fatalf("default full-queue WriteTo = %d, %v", result.bytes, result.err)
			}
			if after := stack.outbound.len(); after != before {
				t.Fatalf("default full-queue write changed queue depth from %d to %d", before, after)
			}
			if packets, bytes := test.statistics(connection); packets != 1 || bytes != uint64(len(payload)) {
				t.Fatalf("default full-queue statistics = %d packets, %d bytes", packets, bytes)
			}
			if stats := stack.Stats(); stats.OutboundPackets != 1 || stats.OutboundQueueDrops != 1 {
				t.Fatalf("default full-queue stack statistics = %+v", stats)
			}
			if !test.correlated(connection) {
				t.Fatal("published-backlog write did not retain ICMP correlation")
			}

			if err = test.configure(connection, true); err != nil {
				t.Fatal(err)
			}
			if result := write(); result.bytes != len(payload) || result.err != nil {
				t.Fatalf("extended-error published-backlog WriteTo = %d, %v", result.bytes, result.err)
			}
			if packets, bytes := test.statistics(connection); packets != 2 || bytes != uint64(2*len(payload)) {
				t.Fatalf("published-backlog statistics = %d packets, %d bytes", packets, bytes)
			}
			if stats := stack.Stats(); stats.OutboundPackets != 2 || stats.OutboundQueueDrops != 2 {
				t.Fatalf("published-backlog stack statistics = %+v", stats)
			}
			validPackets := 0
			for {
				entry, available := stack.outbound.tryDequeue()
				if !available {
					break
				}
				if _, parseErr := ParseIPPacket(entry.packet); parseErr == nil {
					validPackets++
				}
				stack.outbound.release(entry)
			}
			if validPackets != 2 {
				t.Fatalf("published-backlog writes retained %d packets, want 2", validPackets)
			}
			held := make([]uint16, cap(stack.outbound.free))
			for index := range held {
				slot, reserved := stack.outbound.tryReserve()
				if !reserved {
					t.Fatalf("unpublished reservation %d was unavailable", index)
				}
				held[index] = slot
			}
			if result := write(); result.bytes != 0 || !errors.Is(result.err, syscall.ENOBUFS) {
				t.Fatalf("extended-error unreclaimable-capacity WriteTo = %d, %v", result.bytes, result.err)
			}
			if packets, bytes := test.statistics(connection); packets != 2 || bytes != uint64(2*len(payload)) {
				t.Fatalf("unreclaimable-capacity statistics = %d packets, %d bytes", packets, bytes)
			}
			if stats := stack.Stats(); stats.OutboundPackets != 2 || stats.OutboundQueueDrops != 3 {
				t.Fatalf("extended-error unreclaimable-capacity stack statistics = %+v", stats)
			}
			if err = test.configure(connection, false); err != nil {
				t.Fatal(err)
			}
			if result := write(); result.bytes != len(payload) || result.err != nil {
				t.Fatalf("default unreclaimable-capacity WriteTo = %d, %v", result.bytes, result.err)
			}
			if packets, bytes := test.statistics(connection); packets != 3 || bytes != uint64(3*len(payload)) {
				t.Fatalf("default unreclaimable-capacity statistics = %d packets, %d bytes", packets, bytes)
			}
			if stats := stack.Stats(); stats.OutboundPackets != 2 || stats.OutboundQueueDrops != 4 {
				t.Fatalf("default unreclaimable-capacity stack statistics = %+v", stats)
			}
			for _, slot := range held {
				stack.outbound.releaseReserved(slot)
			}

			if err = connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			if result := write(); result.bytes != 0 || !errors.Is(result.err, os.ErrDeadlineExceeded) {
				t.Fatalf("expired-deadline WriteTo = %d, %v", result.bytes, result.err)
			}
			if err = connection.Close(); err != nil {
				t.Fatal(err)
			}
			if result := write(); result.bytes != 0 || !errors.Is(result.err, net.ErrClosed) {
				t.Fatalf("closed WriteTo = %d, %v", result.bytes, result.err)
			}
		})
	}
}

func TestDatagramWriteSameFlowReplacementIsSuccessful(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.43")
	remote := netip.MustParseAddr("192.0.2.44")
	for _, test := range []struct {
		name       string
		open       func(*Stack) (net.PacketConn, error)
		target     net.Addr
		configure  func(net.PacketConn, bool) error
		statistics func(net.PacketConn) (uint64, uint64)
	}{
		{
			name: "UDP",
			open: func(stack *Stack) (net.PacketConn, error) {
				return stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
			},
			target: net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 53)),
			configure: func(connection net.PacketConn, enabled bool) error {
				return connection.(*UDPConn).SetReceiveErrors(enabled)
			},
			statistics: func(connection net.PacketConn) (uint64, uint64) {
				info := connection.(*UDPConn).Info()
				return info.PacketsSent, info.BytesSent
			},
		},
		{
			name: "IP",
			open: func(stack *Stack) (net.PacketConn, error) {
				return stack.ListenIP(context.Background(), "ip4:99", local)
			},
			target: ipNetAddr(remote),
			configure: func(connection net.PacketConn, enabled bool) error {
				return connection.(*IPConn).SetReceiveErrors(enabled)
			},
			statistics: func(connection net.PacketConn) (uint64, uint64) {
				info := connection.(*IPConn).Info()
				return info.PacketsSent, info.BytesSent
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			connection, err := test.open(stack)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			oldPayload := []byte("same-flow-old")
			for index := 0; index < outboundPacketQueue; index++ {
				if n, writeErr := connection.WriteTo(oldPayload, test.target); writeErr != nil || n != len(oldPayload) {
					t.Fatalf("initial WriteTo %d = %d, %v", index, n, writeErr)
				}
			}
			if err = test.configure(connection, true); err != nil {
				t.Fatal(err)
			}
			newPayload := []byte("same-flow-new")
			if n, writeErr := connection.WriteTo(newPayload, test.target); n != len(newPayload) || writeErr != nil {
				t.Fatalf("same-flow replacement WriteTo = %d, %v", n, writeErr)
			}
			if packets, bytesSent := test.statistics(connection); packets != outboundPacketQueue+1 || bytesSent != outboundPacketQueue*uint64(len(oldPayload))+uint64(len(newPayload)) {
				t.Fatalf("same-flow replacement statistics = %d packets, %d bytes", packets, bytesSent)
			}
			if stats := stack.Stats(); stats.OutboundPackets != outboundPacketQueue+1 || stats.OutboundQueueDrops != 1 {
				t.Fatalf("same-flow replacement stack statistics = %+v", stats)
			}
			oldCount, newCount := 0, 0
			for {
				entry, available := stack.outbound.tryDequeue()
				if !available {
					break
				}
				switch {
				case bytes.HasSuffix(entry.packet, oldPayload):
					oldCount++
				case bytes.HasSuffix(entry.packet, newPayload):
					newCount++
				default:
					t.Fatalf("unexpected same-flow packet %x", entry.packet)
				}
				stack.outbound.release(entry)
			}
			if oldCount != outboundPacketQueue-1 || newCount != 1 {
				t.Fatalf("same-flow replacement queue = old %d, new %d; want %d, 1", oldCount, newCount, outboundPacketQueue-1)
			}
		})
	}
}

func TestPendingTCPWriteDeadlineUpdates(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8086))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	oldDeadline := time.Now().Add(100 * time.Millisecond)
	if err = connection.SetWriteDeadline(oldDeadline); err != nil {
		t.Fatal(err)
	}
	done := make(chan deadlineOperationResult, 1)
	go func() {
		bytes, writeErr := connection.Write(make([]byte, tcpSendCapacity+1))
		done <- deadlineOperationResult{bytes: bytes, err: writeErr}
	}()
	time.Sleep(10 * time.Millisecond)
	later := time.Now().Add(200 * time.Millisecond)
	if err = connection.SetWriteDeadline(later); err != nil {
		t.Fatal(err)
	}
	wait := time.NewTimer(time.Until(oldDeadline) + 25*time.Millisecond)
	select {
	case result := <-done:
		wait.Stop()
		t.Fatalf("TCP Write retained the superseded deadline: %d, %v", result.bytes, result.err)
	case <-wait.C:
	}
	if err = connection.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	wait = time.NewTimer(time.Until(later) + 25*time.Millisecond)
	select {
	case result := <-done:
		wait.Stop()
		t.Fatalf("TCP Write retained the cleared deadline: %d, %v", result.bytes, result.err)
	case <-wait.C:
	}
	finalDeadline := time.Now().Add(50 * time.Millisecond).Round(0)
	if err = connection.SetWriteDeadline(finalDeadline); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.bytes != tcpSendCapacity || !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("TCP Write = %d, %v, want %d, os.ErrDeadlineExceeded", result.bytes, result.err, tcpSendCapacity)
		}
		checkNetOpError(t, result.err, "write", "tcp")
	case <-time.After(time.Second):
		t.Fatal("TCP Write did not observe the final deadline")
	}
}

func TestSocketReadDeadlineErrors(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	tcpConnection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConnection.Close()
	if err = tcpConnection.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = tcpConnection.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("TCP Read error = %v, want os.ErrDeadlineExceeded", err)
	} else {
		checkNetOpError(t, err, "read", "tcp")
	}
	udpConnection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(link.remote))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	if err = udpConnection.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = udpConnection.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("UDP ReadFrom error = %v, want os.ErrDeadlineExceeded", err)
	} else {
		checkNetOpError(t, err, "read", "udp")
	}
}

func TestAutomaticPortRangeFallback(t *testing.T) {
	cursor := automaticPortCursor{}
	port, err := allocateAutomaticPort(&cursor, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if port != dynamicPortFirst {
		t.Fatalf("first automatic port = %d, want IANA dynamic port %d", port, dynamicPortFirst)
	}

	cursor = automaticPortCursor{}
	port, err = allocateAutomaticPort(&cursor, func(port uint16) bool {
		return port < dynamicPortFirst
	})
	if err != nil {
		t.Fatal(err)
	}
	if port != fallbackPortFirst {
		t.Fatalf("fallback automatic port = %d, want %d", port, fallbackPortFirst)
	}
	if port < 1024 {
		t.Fatalf("automatic allocation selected privileged port %d", port)
	}

	probes := 0
	if _, err = allocateAutomaticPort(&cursor, func(uint16) bool {
		probes++
		return false
	}); !errors.Is(err, ErrNoPorts) {
		t.Fatalf("exhausted automatic range = %v, want ErrNoPorts", err)
	}
	if want := dynamicPortCount + fallbackPortCount; probes != want {
		t.Fatalf("automatic allocation probed %d ports, want %d", probes, want)
	}
}

func TestAutomaticPortCursorUsesKeyedFullPeriodSteps(t *testing.T) {
	first := automaticPortCursor{secret: [16]byte{1}}
	second := automaticPortCursor{secret: [16]byte{2}}
	firstPort, err := allocateAutomaticPort(&first, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondPort, err := allocateAutomaticPort(&second, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if firstPort != dynamicPortFirst || secondPort != dynamicPortFirst {
		t.Fatalf("initial automatic ports = %d, %d", firstPort, secondPort)
	}
	if first.dynamic == 1 || second.dynamic == 1 {
		t.Fatal("automatic port cursor retained a sequential increment")
	}
	if first.dynamic == second.dynamic {
		t.Fatal("automatic port cursors with different keys selected the same increment")
	}

	seen := make(map[uint16]struct{}, dynamicPortCount)
	cursor := automaticPortCursor{secret: [16]byte{3}}
	offsets := [2]uint32{12345, 6789}
	for index := uint32(0); index < dynamicPortCount; index++ {
		port, allocateErr := allocateAutomaticPortWithOffsets(&cursor, offsets, func(uint16) bool { return true })
		if allocateErr != nil {
			t.Fatal(allocateErr)
		}
		if _, exists := seen[port]; exists {
			t.Fatalf("automatic port %d repeated after %d allocations", port, index)
		}
		seen[port] = struct{}{}
	}
}

func TestAutomaticTCPPortOffsetsSeparateDestinations(t *testing.T) {
	secret := [16]byte{4}
	local := netip.MustParseAddr("192.0.2.1")
	first := automaticTCPPortOffsets(secret, local, netip.MustParseAddrPort("198.51.100.1:443"))
	second := automaticTCPPortOffsets(secret, local, netip.MustParseAddrPort("198.51.100.2:443"))
	if first == second {
		t.Fatal("different TCP destinations received the same automatic-port offsets")
	}
}

func TestListenAddressesOverlap(t *testing.T) {
	any4 := netip.IPv4Unspecified()
	any6 := netip.IPv6Unspecified()
	first4 := netip.MustParseAddr("192.0.2.1")
	second4 := netip.MustParseAddr("192.0.2.2")
	first6 := netip.MustParseAddr("2001:db8::1")
	second6 := netip.MustParseAddr("2001:db8::2")
	for _, test := range []struct {
		name                string
		left, right         netip.Addr
		leftDual, rightDual bool
		want                bool
	}{
		{name: "same IPv4", left: first4, right: first4, want: true},
		{name: "different IPv4", left: first4, right: second4},
		{name: "IPv4 wildcard", left: any4, right: first4, want: true},
		{name: "IPv4 wildcard and IPv6", left: any4, right: first6},
		{name: "same IPv6", left: first6, right: first6, want: true},
		{name: "different IPv6", left: first6, right: second6},
		{name: "IPv6 wildcard", left: any6, right: first6, want: true},
		{name: "IPv6-only wildcard and IPv4", left: any6, right: first4},
		{name: "dual wildcard and IPv4", left: any6, leftDual: true, right: first4, want: true},
		{name: "dual wildcard and IPv6", left: any6, leftDual: true, right: first6, want: true},
		{name: "dual and IPv4 wildcards", left: any6, leftDual: true, right: any4, want: true},
		{name: "two dual wildcards", left: any6, leftDual: true, right: any6, rightDual: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if overlap := listenAddressesOverlap(test.left, test.leftDual, test.right, test.rightDual); overlap != test.want {
				t.Fatalf("listenAddressesOverlap = %t, want %t", overlap, test.want)
			}
			if overlap := listenAddressesOverlap(test.right, test.rightDual, test.left, test.leftDual); overlap != test.want {
				t.Fatalf("reversed listenAddressesOverlap = %t, want %t", overlap, test.want)
			}
		})
	}
}

func TestRecentDestinationCacheEvictionAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	epoch := now.Add(-time.Hour)
	stamp := func(value time.Time) monotonicStamp { return monotonicStampAt(epoch, value) }
	var cache recentDestinationCache[int]
	cache.remember(0, stamp(now.Add(-time.Second)))
	for destination := 1; destination < recentDestinationMaximum; destination++ {
		cache.remember(destination, stamp(now))
	}
	cache.remember(recentDestinationMaximum, stamp(now))
	if len(cache.state.entries) != recentDestinationMaximum || cache.contains(0, stamp(now)) || !cache.contains(recentDestinationMaximum, stamp(now)) {
		t.Fatalf("oldest-entry eviction = size %d oldest %t newest %t", len(cache.state.entries), cache.contains(0, stamp(now)), cache.contains(recentDestinationMaximum, stamp(now)))
	}
	expiryTime := now.Add(recentDestinationLifetime)
	for destination := range cache.state.entries {
		cache.state.entries[destination] = stamp(expiryTime)
	}
	cache.state.entries[1] = stamp(now)
	cache.remember(recentDestinationMaximum+1, stamp(expiryTime))
	if len(cache.state.entries) != recentDestinationMaximum || cache.contains(1, stamp(expiryTime)) || !cache.contains(recentDestinationMaximum+1, stamp(expiryTime)) {
		t.Fatalf("expired-entry eviction = size %d expired %t newest %t", len(cache.state.entries), cache.contains(1, stamp(expiryTime)), cache.contains(recentDestinationMaximum+1, stamp(expiryTime)))
	}
	cache.remember(2, stamp(expiryTime.Add(time.Second)))
	if updated := cache.state.entries[2]; updated != stamp(expiryTime.Add(time.Second)) || len(cache.state.entries) != recentDestinationMaximum {
		t.Fatalf("existing-entry update = %v, size %d", updated, len(cache.state.entries))
	}
	cache.state.entries[3] = stamp(expiryTime)
	if cache.contains(3, stamp(expiryTime.Add(recentDestinationLifetime))) {
		t.Fatal("expired destination remained present")
	}
	if _, exists := cache.state.entries[3]; exists {
		t.Fatal("contains retained expired destination")
	}
}

func TestRecentDestinationCacheDefersMapAllocation(t *testing.T) {
	now := time.Unix(1000, 0)
	epoch := now
	stamp := func(value time.Time) monotonicStamp { return monotonicStampAt(epoch, value) }
	var cache recentDestinationCache[int]
	cache.remember(1, stamp(now))
	cache.remember(1, stamp(now.Add(time.Second)))
	if cache.state == nil || cache.state.entries != nil || !cache.contains(1, stamp(now.Add(time.Second))) {
		t.Fatalf("single destination state = %#v", cache.state)
	}
	cache.remember(2, stamp(now.Add(2*time.Second)))
	if len(cache.state.entries) != 2 || !cache.contains(1, stamp(now.Add(2*time.Second))) || !cache.contains(2, stamp(now.Add(2*time.Second))) {
		t.Fatalf("promoted destination state = %#v", cache.state)
	}
}

var benchmarkRecentDestinationCache recentDestinationCache[netip.AddrPort]

func BenchmarkRecentDestinationCacheSingleTarget(b *testing.B) {
	target := netip.MustParseAddrPort("198.51.100.1:53")
	now := monotonicStampAt(time.Unix(1000, 0), time.Unix(1000, 0))
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		var cache recentDestinationCache[netip.AddrPort]
		cache.remember(target, now)
		benchmarkRecentDestinationCache = cache
	}
}

func testOutputUDPPacket(source, target netip.Addr, sourcePort, targetPort uint16, size int) []byte {
	if size < udpHeaderSize {
		size = udpHeaderSize
	}
	payload := make([]byte, size)
	binary.BigEndian.PutUint16(payload[0:2], sourcePort)
	binary.BigEndian.PutUint16(payload[2:4], targetPort)
	return buildIPPacket(source, target, ProtocolUDP, payload, 0, true)
}

func enqueueTestOutputPacket(t *testing.T, queue *packetQueue, packet []byte) {
	t.Helper()
	slot, ok := queue.tryReserve()
	if !ok {
		t.Fatal("output queue has no free slot")
	}
	_ = queue.enqueueReservedPacket(slot, packet, false, false)
}

func TestFairPacketQueueRotatesAfterInitialByteCredit(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	first := testOutputUDPPacket(source, target, 10000, 53, 80)
	second := testOutputUDPPacket(source, target, 10001, 53, 80)
	var queue packetQueue
	queue.initFair(16, time.Now(), len(first), [16]byte{1})
	for index := 0; index < 12; index++ {
		enqueueTestOutputPacket(t, &queue, first)
	}
	enqueueTestOutputPacket(t, &queue, second)
	for index := 0; index < 10; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", index)
		}
		if got := binary.BigEndian.Uint16(entry.packet[20:22]); got != 10000 {
			t.Fatalf("packet %d source port = %d, want first flow", index, got)
		}
		queue.release(entry)
	}
	entry, ok := queue.tryDequeue()
	if !ok {
		t.Fatal("second flow was not scheduled after the initial quantum")
	}
	if got := binary.BigEndian.Uint16(entry.packet[20:22]); got != 10001 {
		t.Fatalf("packet after initial quantum source port = %d, want second flow", got)
	}
	queue.release(entry)
}

func TestFairPacketQueueUsesByteCredit(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.2")
	target := netip.MustParseAddr("198.51.100.2")
	large := testOutputUDPPacket(source, target, 11000, 53, 1400)
	small := testOutputUDPPacket(source, target, 11001, 53, 200)
	var queue packetQueue
	queue.initFair(128, time.Now(), 1500, [16]byte{2})
	for index := 0; index < 64; index++ {
		enqueueTestOutputPacket(t, &queue, large)
		enqueueTestOutputPacket(t, &queue, small)
	}
	bytesByPort := map[uint16]int{}
	for index := 0; index < 75; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", index)
		}
		bytesByPort[binary.BigEndian.Uint16(entry.packet[20:22])] += len(entry.packet)
		queue.release(entry)
	}
	difference := bytesByPort[11000] - bytesByPort[11001]
	if difference < 0 {
		difference = -difference
	}
	if difference > 2*1500 {
		t.Fatalf("byte-fair service differs by %d bytes: %v", difference, bytesByPort)
	}
}

func TestFairPacketQueueBestEffortAdmissionDropsFattestFlow(t *testing.T) {
	const capacity = 8
	source := netip.MustParseAddr("192.0.2.8")
	target := netip.MustParseAddr("198.51.100.8")
	bulk := testOutputUDPPacket(source, target, 12000, 53, 1400)
	sparse := testOutputUDPPacket(source, target, 12001, 53, 128)
	late := testOutputUDPPacket(source, target, 12002, 53, 128)
	var queue packetQueue
	queue.initFair(capacity, time.Now(), 1500, [16]byte{8})
	for index := 0; index < capacity; index++ {
		packet := sparse
		if index < 3 {
			packet = bulk
		}
		enqueueTestOutputPacket(t, &queue, packet)
	}
	replaced, ok := queue.replaceBestEffort()
	if !ok {
		t.Fatal("late flow could not reclaim published backlog")
	}
	if !queue.enqueueReservedPacket(replaced.slot, late, false, false) {
		t.Fatal("late flow was not admitted from published backlog")
	}
	counts := map[uint16]int{}
	for {
		entry, available := queue.tryDequeue()
		if !available {
			break
		}
		counts[binary.BigEndian.Uint16(entry.packet[20:22])]++
		queue.release(entry)
	}
	if counts[12000] != 2 || counts[12001] != 5 || counts[12002] != 1 {
		t.Fatalf("queue after overload admission = %v", counts)
	}
	if available := len(queue.free); available != capacity {
		t.Fatalf("free slots after drain = %d, want %d", available, capacity)
	}
}

func TestFairPacketQueueBestEffortAdmissionRemovesDueFlow(t *testing.T) {
	const (
		capacity = 11
		mtu      = 1500
	)
	oldPacket := make([]byte, mtu)
	oldPacket[0] = 1
	newPacket := make([]byte, 64)
	newPacket[0] = 2
	var queue packetQueue
	queue.initFair(capacity, time.Now(), mtu, [16]byte{9})
	for index := 0; index < capacity; index++ {
		slot, ok := queue.tryReserve()
		if !ok || !queue.enqueueReservedPacketForFlow(slot, oldPacket, false, outputHashedFlowKey(1), false) {
			t.Fatalf("old-flow packet %d was not published", index)
		}
	}
	for index := 0; index < 10; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("initial packet %d was not schedulable", index)
		}
		if entry.packet[0] != 1 {
			t.Fatalf("initial packet marker %d = %d, want 1", index, entry.packet[0])
		}
		queue.release(entry)
	}
	slot, ok := queue.tryReserve()
	if !ok || !queue.enqueueReservedPacketForFlow(slot, newPacket, false, outputHashedFlowKey(2), false) {
		t.Fatal("new-flow packet was not published")
	}
	entry, ok := queue.tryDequeue()
	if !ok {
		t.Fatal("new-flow packet was not schedulable")
	}
	if entry.packet[0] != 2 {
		t.Fatalf("new-flow marker = %d, want 2", entry.packet[0])
	}
	queue.release(entry)
	for index := 0; index < 10; index++ {
		slot, ok = queue.tryReserve()
		if !ok || !queue.enqueueReservedPacketForFlow(slot, newPacket, false, outputHashedFlowKey(2), false) {
			t.Fatalf("filler packet %d was not published", index)
		}
	}
	replaced, ok := queue.replaceBestEffort()
	replacementPacket := make([]byte, 64)
	replacementPacket[0] = 3
	if !ok || !queue.enqueueReservedPacketForFlow(replaced.slot, replacementPacket, false, outputHashedFlowKey(3), false) {
		t.Fatal("due old-flow packet was not replaced")
	}
	entry, ok = queue.tryDequeue()
	if !ok {
		t.Fatal("replacement packet was not schedulable")
	}
	if entry.packet[0] != 3 {
		t.Fatalf("replacement marker = %d, want 3", entry.packet[0])
	}
	queue.release(entry)
	for index := 0; index < 10; index++ {
		entry, ok = queue.tryDequeue()
		if !ok {
			t.Fatalf("filler packet %d was not schedulable", index)
		}
		if entry.packet[0] != 2 {
			t.Fatalf("filler marker %d = %d, want 2", index, entry.packet[0])
		}
		queue.release(entry)
	}
	if available := len(queue.free); available != capacity {
		t.Fatalf("free slots after due-flow replacement = %d, want %d", available, capacity)
	}
}

func TestFairPacketQueueContinuousNewFlowsDoNotStarveOldFlow(t *testing.T) {
	const (
		capacity = 64
		mtu      = 1500
	)
	oldPacket := make([]byte, mtu)
	oldPacket[0] = 1
	newPacket := make([]byte, 64)
	newPacket[0] = 2
	var queue packetQueue
	queue.initFair(capacity, time.Now(), mtu, [16]byte{9})
	for index := 0; index < capacity; index++ {
		slot, ok := queue.tryReserve()
		if !ok {
			t.Fatalf("old-flow reservation %d was unavailable", index)
		}
		if _, published := queue.enqueueReservedTCP(slot, oldPacket, false, 1, false); !published {
			t.Fatalf("old-flow packet %d was not published", index)
		}
	}
	for index := 0; index < 10; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("initial old-flow packet %d was not schedulable", index)
		}
		if entry.packet[0] != 1 {
			t.Fatalf("initial old-flow marker %d = %d, want 1", index, entry.packet[0])
		}
		queue.release(entry)
	}
	servedOldAt := -1
	for flow := 0; flow < 32; flow++ {
		slot, ok := queue.tryReserve()
		if !ok {
			t.Fatalf("new-flow reservation %d was unavailable", flow)
		}
		key := outputHashedFlowKey(uint64(flow + 2))
		if !queue.enqueueReservedPacketForFlow(slot, newPacket, false, key, false) {
			t.Fatalf("new-flow packet %d was not published", flow)
		}
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", flow)
		}
		if entry.packet[0] == 1 && servedOldAt < 0 {
			servedOldAt = flow
		}
		queue.release(entry)
	}
	if servedOldAt < 0 || servedOldAt > 1 {
		t.Fatalf("existing backlogged flow was first served at read %d, want <= 1", servedOldAt)
	}
	for {
		entry, ok := queue.tryDequeue()
		if !ok {
			break
		}
		queue.release(entry)
	}
}

func TestFairPacketQueueContinuousNewFlowsPreserveByteCredit(t *testing.T) {
	const (
		capacity  = 256
		mtu       = 1500
		readCount = 192
	)
	largePacket := make([]byte, mtu)
	largePacket[0] = 1
	smallPacket := make([]byte, 500)
	smallPacket[0] = 2
	newPacket := make([]byte, 64)
	newPacket[0] = 3
	var queue packetQueue
	queue.initFair(capacity, time.Now(), mtu, [16]byte{10})
	for index := 0; index < 100; index++ {
		slot, ok := queue.tryReserve()
		if !ok || !queue.enqueueReservedPacketForFlow(slot, largePacket, false, outputHashedFlowKey(1), false) {
			t.Fatalf("large old-flow packet %d was not published", index)
		}
	}
	for index := 0; index < 156; index++ {
		slot, ok := queue.tryReserve()
		if !ok || !queue.enqueueReservedPacketForFlow(slot, smallPacket, false, outputHashedFlowKey(2), false) {
			t.Fatalf("small old-flow packet %d was not published", index)
		}
	}
	initial := [2]int{}
	for index := 0; index < 40; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("initial packet %d was not schedulable", index)
		}
		if entry.packet[0] < 1 || entry.packet[0] > 2 {
			t.Fatalf("initial packet marker %d = %d, want 1 or 2", index, entry.packet[0])
		}
		initial[entry.packet[0]-1]++
		queue.release(entry)
	}
	if initial != [2]int{10, 30} {
		t.Fatalf("initial flow service = %v, want [10 30]", initial)
	}
	servedBytes := [2]int{}
	for flow := 0; flow < readCount; flow++ {
		slot, ok := queue.tryReserve()
		if !ok {
			t.Fatalf("new-flow reservation %d was unavailable", flow)
		}
		key := outputHashedFlowKey(uint64(flow + 1000))
		if !queue.enqueueReservedPacketForFlow(slot, newPacket, false, key, false) {
			t.Fatalf("new-flow packet %d was not published", flow)
		}
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", flow)
		}
		if marker := entry.packet[0]; marker == 1 || marker == 2 {
			servedBytes[marker-1] += len(entry.packet)
		}
		queue.release(entry)
	}
	difference := servedBytes[0] - servedBytes[1]
	if difference < 0 {
		difference = -difference
	}
	if servedBytes[0] == 0 || servedBytes[1] == 0 || difference > 2*mtu {
		t.Fatalf("old-flow byte service under new-flow pressure = %v", servedBytes)
	}
	for {
		entry, ok := queue.tryDequeue()
		if !ok {
			break
		}
		queue.release(entry)
	}
	if available := len(queue.free); available != capacity {
		t.Fatalf("free slots after drain = %d, want %d", available, capacity)
	}
}

func TestFairPacketQueueBestEffortAdmissionPreservesUnpublishedReservations(t *testing.T) {
	const capacity = 8
	var queue packetQueue
	queue.initFair(capacity, time.Now(), 1500, [16]byte{9})
	reservations := make([]uint16, capacity)
	for index := range reservations {
		slot, ok := queue.tryReserve()
		if !ok {
			t.Fatalf("reservation %d was unavailable", index)
		}
		reservations[index] = slot
	}
	if _, ok := queue.replaceBestEffort(); ok {
		t.Fatal("best-effort admission stole an unpublished reservation")
	}
	if depth := queue.len(); depth != 0 {
		t.Fatalf("unpublished reservations created %d queued packets", depth)
	}
	for _, slot := range reservations {
		queue.releaseReserved(slot)
	}
}

func TestBestEffortAdmissionDoesNotCountReaderRace(t *testing.T) {
	const capacity = 1
	var stack Stack
	queue := &stack.outbound
	queue.initFair(capacity, time.Now(), 1500, [16]byte{9})
	enqueueTestOutputPacket(t, queue, []byte{1})
	if _, err := stack.tryReservePacket(queue); err != ErrResourceLimit {
		t.Fatalf("full queue reservation = %v, want ErrResourceLimit", err)
	}
	entry, ok := queue.tryDequeue()
	if !ok {
		t.Fatal("published packet was unavailable")
	}
	queue.release(entry)
	slot, err := stack.replaceBestEffortPacket(queue)
	if err != nil {
		t.Fatalf("concurrently released capacity: %v", err)
	}
	queue.releaseReserved(slot)
	if got := stack.Stats().OutboundQueueDrops; got != 0 {
		t.Fatalf("concurrently released capacity counted %d queue drops", got)
	}
}

func TestFairPacketQueueBestEffortAdmissionDepartsTCPBacklog(t *testing.T) {
	const capacity = 8
	source := netip.MustParseAddr("192.0.2.9")
	target := netip.MustParseAddr("198.51.100.9")
	tcpPacket := buildTestTCP(source, target, 443, 52000, 1, 1, TCPFlagACK, 65535, nil, make([]byte, 128))
	udpPacket := testOutputUDPPacket(source, target, 52001, 53, 128)
	epoch := time.Now()
	stack := &Stack{timestampEpoch: epoch}
	stack.outbound.initFair(capacity, epoch, 1500, [16]byte{10})
	queue := &stack.outbound
	tickets := make([]packetQueueTicket, capacity)
	for index := range tickets {
		slot, ok := queue.tryReserve()
		if !ok {
			t.Fatalf("TCP reservation %d was unavailable", index)
		}
		var published bool
		tickets[index], published = queue.enqueueReservedTCP(slot, tcpPacket, false, 1, false)
		if !published {
			t.Fatalf("TCP packet %d was not published", index)
		}
	}
	notify := make(chan struct{}, 1)
	waiter := tickets[0].departureWaiter(stack, notify)
	if waiter == nil {
		t.Fatal("oldest TCP ticket was not pending")
	}
	replaced, ok := queue.replaceBestEffort()
	if !ok {
		t.Fatal("UDP packet could not reclaim published TCP backlog")
	}
	if !queue.enqueueReservedPacket(replaced.slot, udpPacket, false, false) {
		t.Fatal("UDP packet did not replace published TCP backlog")
	}
	select {
	case <-notify:
	default:
		t.Fatal("replaced TCP backlog did not notify its departure waiter")
	}
	if _, departed := waiter.departedTime(epoch); !departed {
		t.Fatal("replaced TCP backlog did not record its departure time")
	}
	pending := 0
	for _, ticket := range tickets {
		if ticket.pendingIn(queue) {
			pending++
		}
	}
	if pending != capacity-1 {
		t.Fatalf("pending TCP tickets = %d, want %d", pending, capacity-1)
	}
	for {
		entry, available := queue.tryDequeue()
		if !available {
			break
		}
		queue.release(entry)
	}
}

func TestStackSinglePacketReadAdmitsLateUDPFlow(t *testing.T) {
	const mtu = 1400
	source := netip.MustParseAddr("192.0.2.10")
	target := netip.MustParseAddr("198.51.100.10")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, 32)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	tcpPacket := buildTestTCP(source, target, 443, 52000, 1, 1, TCPFlagACK, 65535, nil, make([]byte, mtu-40))
	for index := 0; index < outboundPacketQueue; index++ {
		slot, ok := stack.outbound.tryReserve()
		if !ok {
			t.Fatalf("TCP reservation %d was unavailable", index)
		}
		if _, published := stack.outbound.enqueueReservedTCP(slot, tcpPacket, false, 1, false); !published {
			t.Fatalf("TCP packet %d was not published", index)
		}
	}
	connection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(source, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	targetAddress := netip.AddrPortFrom(target, 53)
	if n, writeErr := connection.WriteTo([]byte("late"), net.UDPAddrFromAddrPort(targetAddress)); writeErr != nil || n != 4 {
		t.Fatalf("late UDP WriteTo = %d, %v", n, writeErr)
	}
	buffer := [][]byte{make([]byte, mtu)}
	sizes := make([]int, 1)
	foundAt := -1
	for rank := 0; rank <= 10; rank++ {
		count, readErr := stack.Read(buffer, sizes, 0)
		if readErr != nil || count != 1 {
			t.Fatalf("single-packet Read %d = %d, %v", rank, count, readErr)
		}
		packet, parseErr := ParseIPPacket(buffer[0][:sizes[0]])
		if parseErr == nil && packet.Protocol == ProtocolUDP {
			datagram, datagramErr := packet.UDPDatagram()
			if datagramErr == nil && datagram.Source == connection.LocalAddr().(*net.UDPAddr).AddrPort() {
				foundAt = rank
				break
			}
		}
	}
	if foundAt < 0 {
		t.Fatal("late UDP flow was not served within the TCP flow's initial byte credit")
	}
}

func TestStackSinglePacketReadKeepsOutputFlowsFairUnderOverload(t *testing.T) {
	const (
		mtu       = 1400
		readCount = 2048
	)
	local := netip.MustParseAddr("192.0.2.12")
	remote := netip.MustParseAddr("198.51.100.12")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	tcpPacket := buildTestTCP(local, remote, 443, 52000, 1, 1, TCPFlagACK, 65535, nil, make([]byte, 96))
	for index := 0; index < outboundPacketQueue; index++ {
		slot, ok := stack.outbound.tryReserve()
		if !ok {
			t.Fatalf("initial TCP reservation %d was unavailable", index)
		}
		if _, published := stack.outbound.enqueueReservedTCP(slot, tcpPacket, false, 1, false); !published {
			t.Fatalf("initial TCP packet %d was not published", index)
		}
	}
	udpConnections := make([]net.PacketConn, 2)
	for index := range udpConnections {
		udpConnections[index], err = stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
		if err != nil {
			t.Fatal(err)
		}
		connection := udpConnections[index]
		t.Cleanup(func() { _ = connection.Close() })
	}
	ipConnections := make([]net.PacketConn, 2)
	ipNetworks := [...]string{"ip4:252", "ip4:253"}
	for index := range ipConnections {
		ipConnections[index], err = stack.ListenIP(context.Background(), ipNetworks[index], local)
		if err != nil {
			t.Fatal(err)
		}
		connection := ipConnections[index]
		t.Cleanup(func() { _ = connection.Close() })
	}
	payload := make([]byte, 64)
	udpTarget := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 53))
	ipTarget := ipNetAddr(remote)
	buffer := [][]byte{make([]byte, mtu)}
	sizes := make([]int, 1)
	served := make([]int, 5)
	servedBytes := make([]int, len(served))
	udpPorts := []uint16{
		udpConnections[0].LocalAddr().(*net.UDPAddr).AddrPort().Port(),
		udpConnections[1].LocalAddr().(*net.UDPAddr).AddrPort().Port(),
	}
	for read := 0; read < readCount; read++ {
		for index, connection := range udpConnections {
			payload[0] = byte(index)
			if n, writeErr := connection.WriteTo(payload, udpTarget); writeErr != nil || n != len(payload) {
				t.Fatalf("UDP flow %d write before Read %d = %d, %v", index, read, n, writeErr)
			}
		}
		for index, connection := range ipConnections {
			payload[0] = byte(index + len(udpConnections))
			if n, writeErr := connection.WriteTo(payload, ipTarget); writeErr != nil || n != len(payload) {
				t.Fatalf("IP flow %d write before Read %d = %d, %v", index, read, n, writeErr)
			}
		}
		count, readErr := stack.Read(buffer, sizes, 0)
		if readErr != nil || count != 1 {
			t.Fatalf("single-packet Read %d = %d, %v", read, count, readErr)
		}
		packet, parseErr := ParseIPPacket(buffer[0][:sizes[0]])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		switch packet.Protocol {
		case ProtocolTCP:
			served[0]++
			servedBytes[0] += sizes[0]
		case ProtocolUDP:
			datagram, datagramErr := packet.UDPDatagram()
			if datagramErr != nil {
				t.Fatal(datagramErr)
			}
			switch datagram.Source.Port() {
			case udpPorts[0]:
				served[1]++
				servedBytes[1] += sizes[0]
			case udpPorts[1]:
				served[2]++
				servedBytes[2] += sizes[0]
			default:
				t.Fatalf("unexpected UDP source port %d", datagram.Source.Port())
			}
		case 252:
			served[3]++
			servedBytes[3] += sizes[0]
		case 253:
			served[4]++
			servedBytes[4] += sizes[0]
		default:
			t.Fatalf("unexpected output protocol %d", packet.Protocol)
		}
		slot, ok := stack.outbound.tryReserve()
		if !ok {
			t.Fatalf("TCP refill reservation after Read %d was unavailable", read)
		}
		if _, published := stack.outbound.enqueueReservedTCP(slot, tcpPacket, false, 1, false); !published {
			t.Fatalf("TCP refill after Read %d was not published", read)
		}
	}
	minimumBytes, maximumBytes := servedBytes[0], servedBytes[0]
	for flow, count := range served {
		if count == 0 {
			t.Fatalf("output flow %d was starved: %v", flow, served)
		}
		if servedBytes[flow] < minimumBytes {
			minimumBytes = servedBytes[flow]
		}
		if servedBytes[flow] > maximumBytes {
			maximumBytes = servedBytes[flow]
		}
	}
	if maximumBytes-minimumBytes > 12*mtu {
		t.Fatalf("single-packet overload byte service is disproportionate: packets %v bytes %v", served, servedBytes)
	}
}

func TestStackReadFairQueueBoundsLateUDPFlowService(t *testing.T) {
	const (
		mtu              = 1400
		bulkFlows        = 4
		packetsPerFlow   = 48
		initialBurstMTUs = 10
	)
	source := netip.MustParseAddr("192.0.2.7")
	target := netip.MustParseAddr("198.51.100.7")
	bulkPayload := make([]byte, mtu-20)
	bulkPacket := buildIPPacket(source, target, ProtocolTCP, bulkPayload, 0, true)
	latencyPacket := testOutputUDPPacket(source, target, 16000, 53, 64)

	for _, test := range []struct {
		name             string
		fair             bool
		wantInFirstBatch bool
	}{{name: "fifo"}, {name: "drr", fair: true, wantInFirstBatch: true}} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, 32)},
				MTU:            mtu,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !test.fair {
				stack.outbound.initFIFO(outboundPacketQueue, stack.timestampEpoch)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })

			for flow := 0; flow < bulkFlows; flow++ {
				for packet := 0; packet < packetsPerFlow; packet++ {
					slot, ok := stack.outbound.tryReserve()
					if !ok {
						t.Fatal("output queue has no free slot")
					}
					if _, published := stack.outbound.enqueueReservedTCP(slot, bulkPacket, false, uint64(flow+1), false); !published {
						t.Fatal("failed to publish TCP test packet")
					}
				}
			}
			enqueueTestOutputPacket(t, &stack.outbound, latencyPacket)

			buffers := make([][]byte, deviceBatchSize)
			for index := range buffers {
				buffers[index] = make([]byte, mtu)
			}
			sizes := make([]int, len(buffers))
			count, err := stack.Read(buffers, sizes, 0)
			if err != nil {
				t.Fatal(err)
			}
			if count != deviceBatchSize {
				t.Fatalf("first Read batch contains %d packets, want %d", count, deviceBatchSize)
			}
			latencyRank := -1
			for index := 0; index < count; index++ {
				if bytes.Equal(buffers[index][:sizes[index]], latencyPacket) {
					latencyRank = index
					break
				}
			}
			if got := latencyRank >= 0; got != test.wantInFirstBatch {
				t.Fatalf("late UDP flow present in first Read batch = %t at rank %d, want %t", got, latencyRank, test.wantInFirstBatch)
			}
			if test.fair && latencyRank > bulkFlows*initialBurstMTUs {
				t.Fatalf("late UDP flow service rank = %d, want <= %d", latencyRank, bulkFlows*initialBurstMTUs)
			}
		})
	}
}

func TestSemanticFlowKeyMatchesWireClassification(t *testing.T) {
	for _, test := range []struct {
		name           string
		source, target netip.Addr
		options        ipPacketOptions
	}{
		{name: "IPv4", source: netip.MustParseAddr("192.0.2.11"), target: netip.MustParseAddr("198.51.100.11")},
		{name: "IPv6-zero-flow-label", source: netip.MustParseAddr("2001:db8::11"), target: netip.MustParseAddr("2001:db8:1::11")},
		{name: "IPv6", source: netip.MustParseAddr("2001:db8::11"), target: netip.MustParseAddr("2001:db8:1::11"),
			options: ipPacketOptions{flowLabel: 0x12345, flowLabelSet: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			const opaqueProtocol = 253
			datagram := mustTestWire((UDPDatagram{
				Source: netip.AddrPortFrom(test.source, 12000), Destination: netip.AddrPortFrom(test.target, 53), Payload: make([]byte, 2000),
			}).MarshalBinary())
			unfragmented := buildIPPacketWithOptions(test.source, test.target, ProtocolUDP, datagram, 1, false, test.options)
			var queue packetQueue
			queue.initFair(8, time.Now(), 1500, [16]byte{11})
			wireKey := outputHashedFlowKey(outputPacketFlowHash(queue.scheduler.secret, unfragmented))
			semanticKey := queue.ipFlowKey(test.source, test.target, ProtocolUDP, test.options.flowLabel, datagram)
			if wireKey != semanticKey {
				t.Fatalf("UDP flow keys differ: wire=%+v semantic=%+v", wireKey, semanticKey)
			}

			protocol, echoType := byte(ProtocolICMPv4), byte(ICMPv4TypeEchoRequest)
			if test.source.Is6() {
				protocol, echoType = ProtocolICMPv6, ICMPv6TypeEchoRequest
			}
			echo := make([]byte, 8)
			echo[0] = echoType
			binary.BigEndian.PutUint16(echo[4:6], 0x1234)
			unfragmented = buildIPPacketWithOptions(test.source, test.target, protocol, echo, 1, false, test.options)
			wireKey = outputHashedFlowKey(outputPacketFlowHash(queue.scheduler.secret, unfragmented))
			semanticKey = queue.ipFlowKey(test.source, test.target, protocol, test.options.flowLabel, echo)
			if wireKey != semanticKey {
				t.Fatalf("ICMP flow keys differ: wire=%+v semantic=%+v", wireKey, semanticKey)
			}

			unfragmented = buildIPPacketWithOptions(test.source, test.target, opaqueProtocol, nil, 1, false, test.options)
			emptyWireKey := outputHashedFlowKey(outputPacketFlowHash(queue.scheduler.secret, unfragmented))
			semanticKey = queue.ipFlowKey(test.source, test.target, opaqueProtocol, test.options.flowLabel, nil)
			if emptyWireKey != semanticKey {
				t.Fatalf("empty opaque flow keys differ: wire=%+v semantic=%+v", emptyWireKey, semanticKey)
			}
			opaquePayload := []byte{1, 2, 3, 4}
			unfragmented = buildIPPacketWithOptions(test.source, test.target, opaqueProtocol, opaquePayload, 1, false, test.options)
			wireKey = outputHashedFlowKey(outputPacketFlowHash(queue.scheduler.secret, unfragmented))
			semanticKey = queue.ipFlowKey(test.source, test.target, opaqueProtocol, test.options.flowLabel, opaquePayload)
			if wireKey != semanticKey || wireKey != emptyWireKey {
				t.Fatalf("opaque payload split one flow: wire=%+v semantic=%+v empty=%+v", wireKey, semanticKey, emptyWireKey)
			}
		})
	}
}

func TestTryWritePacketsPreservesSinglePacketFlow(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.12")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	packet := testOutputUDPPacket(local, netip.MustParseAddr("198.51.100.12"), 12000, 53, 64)
	flow := outputFlowKey{hash: 1}
	wireFlow := outputHashedFlowKey(outputPacketFlowHash(stack.outbound.scheduler.secret, packet))
	if flow == wireFlow {
		t.Fatal("test semantic flow unexpectedly matches wire classification")
	}
	if err = stack.tryWritePackets([][]byte{packet}, flow, false); err != nil {
		t.Fatal(err)
	}

	stack.outbound.scheduler.mu.Lock()
	semantic := stack.outbound.scheduler.flows[flow]
	classified := stack.outbound.scheduler.flows[wireFlow]
	stack.outbound.scheduler.mu.Unlock()
	if semantic == nil || semantic.head < 0 {
		t.Fatal("single-packet sequence was not assigned to its semantic flow")
	}
	if classified != nil {
		t.Fatal("single-packet sequence was reclassified from its semantic flow")
	}
}

func TestConnectionTCPControlPreservesOutputFlow(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.15:12000")
	remote := netip.MustParseAddrPort("198.51.100.15:443")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local.Addr(), 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	connection := newTCPConn(stack, "tcp4", tcpKey{local: local, remote: remote}, 1500, tcpSocketOptionSet{})
	if err = connection.tryWriteTCPControl(1, 1, TCPFlagACK, 4096, nil); err != nil {
		t.Fatal(err)
	}
	flow := outputFlowKey{tcp: connection.outputFlowID}

	stack.outbound.scheduler.mu.Lock()
	queued := stack.outbound.scheduler.flows[flow]
	stack.outbound.scheduler.mu.Unlock()
	if queued == nil || queued.head < 0 {
		t.Fatal("connection control packet was not assigned to the connection output flow")
	}

	statelessRemote := netip.MustParseAddrPort("198.51.100.16:443")
	if err = stack.tryWriteTCPControl(local.Addr(), statelessRemote.Addr(), local.Port(), statelessRemote.Port(), 1, 1, TCPFlagRST|TCPFlagACK, 0, nil, nil, 1500, 0, 0, 0, false, outputFlowKey{}); err != nil {
		t.Fatal(err)
	}
	packet, err := buildTCPPacketInto(make([]byte, 40), local.Addr(), statelessRemote.Addr(), local.Port(), statelessRemote.Port(), 1, 1, TCPFlagRST|TCPFlagACK, 0, nil, nil, 1500, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wireFlow := outputHashedFlowKey(outputPacketFlowHash(stack.outbound.scheduler.secret, packet))
	stack.outbound.scheduler.mu.Lock()
	queued = stack.outbound.scheduler.flows[wireFlow]
	stack.outbound.scheduler.mu.Unlock()
	if queued == nil || queued.head < 0 {
		t.Fatal("stateless control packet was not classified from its wire tuple")
	}
}

func TestSemanticFlowKeyUsesTransportIdentityAcrossDatagrams(t *testing.T) {
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.13"), netip.MustParseAddr("198.51.100.13")},
		{netip.MustParseAddr("2001:db8::13"), netip.MustParseAddr("2001:db8:1::13")},
	} {
		marshalDatagram := func(sourcePort uint16, marker byte) []byte {
			payload := make([]byte, 2000)
			payload[len(payload)-1] = marker
			return mustTestWire((UDPDatagram{
				Source: netip.AddrPortFrom(addresses[0], sourcePort), Destination: netip.AddrPortFrom(addresses[1], 53), Payload: payload,
			}).MarshalBinary())
		}
		first := marshalDatagram(12000, 0)
		second := marshalDatagram(12000, 1)
		other := marshalDatagram(12001, 0)

		var queue packetQueue
		queue.initFair(8, time.Now(), 1500, [16]byte{13})
		firstKey := queue.ipFlowKey(addresses[0], addresses[1], ProtocolUDP, 0, first)
		if secondKey := queue.ipFlowKey(addresses[0], addresses[1], ProtocolUDP, 0, second); secondKey != firstKey {
			t.Fatalf("%s payload change split one transport flow: first=%+v second=%+v", addresses[0], firstKey, secondKey)
		}
		if otherKey := queue.ipFlowKey(addresses[0], addresses[1], ProtocolUDP, 0, other); otherKey == firstKey {
			t.Fatalf("%s source ports share semantic flow key %+v", addresses[0], firstKey)
		}
	}
}

func TestOutputPacketFlowHashSeparatesTransportTuples(t *testing.T) {
	secret := [16]byte{3}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.3")},
		{netip.MustParseAddr("2001:db8::3"), netip.MustParseAddr("2001:db8:1::3")},
	} {
		first := testOutputUDPPacket(addresses[0], addresses[1], 12000, 53, 64)
		second := testOutputUDPPacket(addresses[0], addresses[1], 12001, 53, 64)
		if firstHash, secondHash := outputPacketFlowHash(secret, first), outputPacketFlowHash(secret, second); firstHash == secondHash {
			t.Fatalf("%s flow hashes collide: %x", addresses[0], firstHash)
		}
		if got, want := outputPacketFlowHash(secret, first), outputPacketFlowHash(secret, append([]byte(nil), first...)); got != want {
			t.Fatalf("%s stable flow hash = %x, want %x", addresses[0], got, want)
		}
		longer := testOutputUDPPacket(addresses[0], addresses[1], 12000, 53, 1400)
		if got, want := outputPacketFlowHash(secret, longer), outputPacketFlowHash(secret, first); got != want {
			t.Fatalf("%s differently sized packets hash to %x and %x", addresses[0], got, want)
		}
	}
}

func TestOutputFlowSelectorsUseOnlyProtocolFields(t *testing.T) {
	if got := outputTransportSelector(ProtocolICMPv4, nil); got != 0 {
		t.Fatalf("empty ICMPv4 selector = %#x, want zero", got)
	}
	ports := []byte{0x12, 0x34, 0x56, 0x78}
	if got, want := outputTransportSelector(ProtocolUDP, ports), uint32(0x12345678); got != want {
		t.Fatalf("port selector = %#x, want %#x", got, want)
	}
	source := netip.MustParseAddr("192.0.2.14")
	target := netip.MustParseAddr("198.51.100.14")
	firstRaw := buildIPPacket(source, target, 99, ports, 0, true)
	secondRaw := buildIPPacket(source, target, 99, []byte{0x87, 0x65, 0x43, 0x21}, 0, true)
	secret := [16]byte{14}
	if first, second := outputPacketFlowHash(secret, firstRaw), outputPacketFlowHash(secret, secondRaw); first != second {
		t.Fatalf("opaque raw payload split one flow: first=%x second=%x", first, second)
	}

	echo := []byte{ICMPv4TypeEchoRequest, 0, 0, 0, 0x12, 0x34, 0x56, 0x78}
	if got, want := outputTransportSelector(ProtocolICMPv4, echo), uint32(0x08001234); got != want {
		t.Fatalf("ICMPv4 Echo selector = %#x, want %#x", got, want)
	}
	echo[6]++
	if got, want := outputTransportSelector(ProtocolICMPv4, echo), uint32(0x08001234); got != want {
		t.Fatalf("ICMPv4 Echo sequence changed selector to %#x, want %#x", got, want)
	}
	errorMessage := []byte{3, 4, 0, 0, 0x12, 0x34, 0x56, 0x78}
	if got, want := outputTransportSelector(ProtocolICMPv4, errorMessage), uint32(0x03040000); got != want {
		t.Fatalf("ICMPv4 error selector = %#x, want %#x", got, want)
	}
	timestamp := []byte{13, 0, 0, 0, 0x12, 0x34}
	if got, want := outputTransportSelector(ProtocolICMPv4, timestamp), uint32(0x0d001234); got != want {
		t.Fatalf("ICMPv4 Timestamp selector = %#x, want %#x", got, want)
	}
}

func TestOutputPacketFlowHashSeparatesIPv4FragmentsFromTransport(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.4")
	target := netip.MustParseAddr("198.51.100.4")
	secret := [16]byte{4}
	const identification = 53
	datagram := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source, 0), Destination: netip.AddrPortFrom(target, identification), Payload: make([]byte, 3000),
	}).MarshalBinary())
	fragments := buildIPv4Fragments(source, target, ProtocolUDP, datagram, 1280, identification)
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	want := outputPacketFlowHash(secret, fragments[0])
	for index, fragment := range fragments[1:] {
		if got := outputPacketFlowHash(secret, fragment); got != want {
			t.Fatalf("fragment %d hash = %x, want %x", index+1, got, want)
		}
	}
	unfragmented := buildIPPacket(source, target, ProtocolUDP, datagram, 0, true)
	if got := outputPacketFlowHash(secret, unfragmented); got == want {
		t.Fatalf("IPv4 fragment identification aliased transport selector %x", got)
	}
}

func TestOutputPacketFlowHashKeepsIPv6FragmentsTogether(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::4")
	target := netip.MustParseAddr("2001:db8:1::4")
	secret := [16]byte{4}
	fragments := buildIPv6FragmentsWithOptions(source, target, ProtocolUDP, make([]byte, 3000), 1280, 0x12345678, ipPacketOptions{})
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	want := outputPacketFlowHash(secret, fragments[0])
	for index, fragment := range fragments[1:] {
		if got := outputPacketFlowHash(secret, fragment); got != want {
			t.Fatalf("fragment %d hash = %x, want %x", index+1, got, want)
		}
	}
	other := buildIPv6FragmentsWithOptions(source, target, ProtocolUDP, make([]byte, 3000), 1280, 0x12345679, ipPacketOptions{})
	if got := outputPacketFlowHash(secret, other[0]); got == want {
		t.Fatalf("different fragment identifications share hash %x", got)
	}
}

func TestOutputPacketFlowHashTraversesIPv6Extensions(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::17")
	target := netip.MustParseAddr("2001:db8:1::17")
	secret := [16]byte{17}
	flowHash := func(packet []byte) uint64 {
		t.Helper()
		return outputPacketFlowHash(secret, packet)
	}
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}

	marshal := func(sourcePort uint16, payloadSize int, headers ...IPv6ExtensionHeader) []byte {
		t.Helper()
		datagram := mustTestWire((UDPDatagram{
			Source: netip.AddrPortFrom(source, sourcePort), Destination: netip.AddrPortFrom(target, 53), Payload: make([]byte, payloadSize),
		}).MarshalBinary())
		packet := IPPacket{Source: source, Destination: target, HopLimit: 64}
		if err := packet.SetIPv6ExtensionHeaders(headers, ProtocolUDP, datagram); err != nil {
			t.Fatal(err)
		}
		return mustTestWire(packet.MarshalBinary())
	}

	first := marshal(12000, 32, hop)
	longer := marshal(12000, 128, hop)
	other := marshal(12001, 32, hop)
	if got, want := flowHash(first), outputIPFlowHash(secret, source, target, ProtocolUDP, 0, 12000<<16|53); got != want {
		t.Fatalf("extension flow hash = %x, want semantic hash %x", got, want)
	}
	if got, want := flowHash(longer), flowHash(first); got != want {
		t.Fatalf("extension payload length split one flow: got %x, want %x", got, want)
	}
	if got, want := flowHash(other), flowHash(first); got == want {
		t.Fatalf("extension transport tuples share hash %x", got)
	}

	firstAtomic, secondAtomic := IPv6ExtensionHeader{}, IPv6ExtensionHeader{}
	if err := firstAtomic.SetFragment(0, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := secondAtomic.SetFragment(0, false, 2); err != nil {
		t.Fatal(err)
	}
	if got, want := flowHash(marshal(12000, 32, hop, secondAtomic)), flowHash(marshal(12000, 32, hop, firstAtomic)); got != want {
		t.Fatalf("atomic fragment identification split transport flow: got %x, want %x", got, want)
	}

	destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
	if err := destination.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	routing := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 7)}
	datagram := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source, 12000), Destination: netip.AddrPortFrom(target, 53), Payload: make([]byte, 3000),
	}).MarshalBinary())
	packet := IPPacket{Source: source, Destination: target, HopLimit: 64}
	if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, routing, destination}, ProtocolUDP, datagram); err != nil {
		t.Fatal(err)
	}
	fragments, err := packet.MarshalFragments(1280, 0x12345678)
	if err != nil {
		t.Fatal(err)
	}
	want := flowHash(fragments[0])
	for index, fragment := range fragments[1:] {
		if got := flowHash(fragment); got != want {
			t.Fatalf("extension fragment %d hash = %x, want %x", index+1, got, want)
		}
	}
	otherFragments, err := packet.MarshalFragments(1280, 0x12345679)
	if err != nil {
		t.Fatal(err)
	}
	if got := flowHash(otherFragments[0]); got == want {
		t.Fatalf("different extension fragment identifications share hash %x", got)
	}
	collidingFragments, err := packet.MarshalFragments(1280, 12000<<16|53)
	if err != nil {
		t.Fatal(err)
	}
	unfragmented := mustTestWire(packet.MarshalBinary())
	if fragmented, complete := flowHash(collidingFragments[0]), flowHash(unfragmented); fragmented == complete {
		t.Fatalf("fragment identification aliased transport selector %x", fragmented)
	}

	malformed := append([]byte(nil), first[:41]...)
	malformed[40] = 1
	otherMalformed := append([]byte(nil), malformed...)
	otherMalformed[40] = 2
	if got, fallback := flowHash(malformed), flowHash(otherMalformed); got != fallback {
		t.Fatalf("malformed extension variants hash to %x and %x, want stable base-header fallback", got, fallback)
	}
	reserved := append([]byte(nil), marshal(12000, 32, hop, firstAtomic)...)
	reserved[51] = 0x02
	otherReserved := append([]byte(nil), reserved...)
	otherReserved[51] = 0x04
	if got, fallback := flowHash(reserved), flowHash(otherReserved); got != fallback {
		t.Fatalf("reserved Fragment variants hash to %x and %x, want stable base-header fallback", got, fallback)
	}
	directReserved := marshal(12000, 32, firstAtomic)
	directReserved[43] = 0x02
	otherDirectReserved := marshal(12000, 32, secondAtomic)
	otherDirectReserved[43] = 0x04
	if got, fallback := flowHash(directReserved), flowHash(otherDirectReserved); got != fallback {
		t.Fatalf("direct reserved Fragment variants hash to %x and %x, want stable base-header fallback", got, fallback)
	}
}

func TestOutputPacketFlowHashUsesIPv6FlowLabelTriplet(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::18")
	target := netip.MustParseAddr("2001:db8:1::18")
	secret := [16]byte{18}
	const flowLabel = 0x12345
	datagram := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source, 12000), Destination: netip.AddrPortFrom(target, 53), Payload: make([]byte, 3000),
	}).MarshalBinary())
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: source, Destination: target, HopLimit: 64, FlowLabel: flowLabel}
	if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop}, ProtocolUDP, datagram); err != nil {
		t.Fatal(err)
	}
	wire := mustTestWire(packet.MarshalBinary())
	want := outputIPFlowHash(secret, source, target, ProtocolUDP, flowLabel, 12000<<16|53)
	if got := outputPacketFlowHash(secret, wire); got != want {
		t.Fatalf("labeled extension packet hash = %x, want triplet hash %x", got, want)
	}
	fragments, err := packet.MarshalFragments(1280, 0x12345678)
	if err != nil {
		t.Fatal(err)
	}
	for index, fragment := range fragments {
		if got := outputPacketFlowHash(secret, fragment); got != want {
			t.Fatalf("labeled fragment %d hash = %x, want triplet hash %x", index, got, want)
		}
	}
	if got := outputIPFlowHash(secret, source, target, ProtocolICMPv6, flowLabel, 0); got != want {
		t.Fatalf("same labeled IPv6 flow with another protocol hashes to %x, want %x", got, want)
	}
	packet.FlowLabel++
	if got := outputPacketFlowHash(secret, mustTestWire(packet.MarshalBinary())); got == want {
		t.Fatalf("different IPv6 flow labels share hash %x", got)
	}
}

func TestOutputPacketFlowHashKeepsICMPEchoSequenceTogether(t *testing.T) {
	secret := [16]byte{5}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("198.51.100.5")},
		{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8:1::5")},
	} {
		protocol, echoType := byte(ProtocolICMPv4), byte(8)
		if addresses[0].Is6() {
			protocol, echoType = ProtocolICMPv6, 128
		}
		makeEcho := func(identifier, sequence uint16) []byte {
			message := make([]byte, 12)
			message[0] = echoType
			binary.BigEndian.PutUint16(message[4:6], identifier)
			binary.BigEndian.PutUint16(message[6:8], sequence)
			if protocol == ProtocolICMPv4 {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
			} else {
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(addresses[0], addresses[1], protocol, message))
			}
			return buildIPPacketWithOptions(addresses[0], addresses[1], protocol, message, 0, true, ipPacketOptions{hopLimit: 64})
		}
		first := makeEcho(0x1234, 1)
		second := makeEcho(0x1234, 2)
		if got, want := outputPacketFlowHash(secret, second), outputPacketFlowHash(secret, first); got != want {
			t.Fatalf("%s echo sequences hash to %x and %x", addresses[0], want, got)
		}
		other := makeEcho(0x1235, 1)
		if got, want := outputPacketFlowHash(secret, other), outputPacketFlowHash(secret, first); got == want {
			t.Fatalf("%s echo identifiers share hash %x", addresses[0], got)
		}
	}
}

var benchmarkOutputPacketFlowHash uint64

func BenchmarkOutputPacketFlowHash(b *testing.B) {
	source4 := netip.MustParseAddr("192.0.2.19")
	target4 := netip.MustParseAddr("198.51.100.19")
	source6 := netip.MustParseAddr("2001:db8::19")
	target6 := netip.MustParseAddr("2001:db8:1::19")
	datagram := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source6, 12000), Destination: netip.AddrPortFrom(target6, 53), Payload: make([]byte, 1200),
	}).MarshalBinary())
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		b.Fatal(err)
	}
	extensionPacket := IPPacket{Source: source6, Destination: target6, HopLimit: 64}
	if err := extensionPacket.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop}, ProtocolUDP, datagram); err != nil {
		b.Fatal(err)
	}
	tcp4, err := buildTCPPacketInto(make([]byte, 40), source4, target4, 12000, 443, 1, 1, TCPFlagRST|TCPFlagACK, 0, nil, nil, 1500, 0, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	tcp6, err := buildTCPPacketInto(make([]byte, 60), source6, target6, 12000, 443, 1, 1, TCPFlagRST|TCPFlagACK, 0, nil, nil, 1500, 0, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name   string
		packet []byte
	}{
		{name: "IPv4-empty", packet: buildIPPacket(source4, target4, 253, nil, 0, true)},
		{name: "IPv4-TCP", packet: tcp4},
		{name: "IPv4-UDP", packet: testOutputUDPPacket(source4, target4, 12000, 53, 1200)},
		{name: "IPv6-empty", packet: buildIPPacket(source6, target6, 253, nil, 0, true)},
		{name: "IPv6-TCP", packet: tcp6},
		{name: "IPv6-UDP", packet: buildIPPacket(source6, target6, ProtocolUDP, datagram, 0, true)},
		{name: "IPv6-hop-by-hop", packet: mustTestWire(extensionPacket.MarshalBinary())},
		{name: "IPv6-labeled", packet: buildIPPacketWithOptions(source6, target6, ProtocolUDP, datagram, 0, true,
			ipPacketOptions{flowLabel: 0x12345, flowLabelSet: true})},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			secret := [16]byte{19}
			b.SetBytes(int64(len(benchmark.packet)))
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkOutputPacketFlowHash = outputPacketFlowHash(secret, benchmark.packet)
			}
		})
	}
}

func TestFairPacketQueueReusesBoundedFlowStorage(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.4")
	target := netip.MustParseAddr("198.51.100.4")
	var queue packetQueue
	queue.initFair(4, time.Now(), 1500, [16]byte{4})
	for round := 0; round < 128; round++ {
		packet := testOutputUDPPacket(source, target, uint16(13000+round), 53, 64)
		enqueueTestOutputPacket(t, &queue, packet)
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("round %d packet was not schedulable", round)
		}
		queue.release(entry)
	}
	if got := len(queue.scheduler.store); got != 4 {
		t.Fatalf("flow storage grew to %d, want 4", got)
	}
	if got := len(queue.scheduler.flows); got > 4 {
		t.Fatalf("retained flow map grew to %d, want <= 4", got)
	}
	for index := 0; index < cap(queue.free); index++ {
		packet := testOutputUDPPacket(source, target, uint16(14000+index), 53, 64)
		enqueueTestOutputPacket(t, &queue, packet)
	}
	for round := 0; round < 128; round++ {
		packet := testOutputUDPPacket(source, target, uint16(15000+round), 53, 64)
		replaced, ok := queue.replaceBestEffort()
		if !ok || !queue.enqueueReservedPacket(replaced.slot, packet, false, false) {
			t.Fatalf("overload flow %d was not admitted", round)
		}
	}
	for {
		entry, ok := queue.tryDequeue()
		if !ok {
			break
		}
		queue.release(entry)
	}
	if got := len(queue.scheduler.store); got != 4 {
		t.Fatalf("overload flow storage grew to %d, want 4", got)
	}
	if got := len(queue.scheduler.flows); got > 4 {
		t.Fatalf("overload flow map grew to %d, want <= 4", got)
	}
}

func TestFairPacketQueueWakesConcurrentSinglePacketReaders(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.6")
	target := netip.MustParseAddr("198.51.100.6")
	var queue packetQueue
	queue.initFair(4, time.Now(), 1500, [16]byte{6})
	packet := testOutputUDPPacket(source, target, 15000, 53, 64)
	closed := make(chan struct{})
	started := make(chan struct{}, 2)
	results := make(chan bool, 2)
	for index := 0; index < 2; index++ {
		go func() {
			started <- struct{}{}
			entry, ok := queue.dequeue(closed)
			if ok {
				queue.release(entry)
			}
			results <- ok
		}()
	}
	<-started
	<-started
	time.Sleep(10 * time.Millisecond)
	for index := 0; index < 2; index++ {
		enqueueTestOutputPacket(t, &queue, packet)
	}
	for index := 0; index < 2; index++ {
		select {
		case ok := <-results:
			if !ok {
				t.Fatalf("single-packet reader %d was closed", index)
			}
		case <-time.After(time.Second):
			close(closed)
			t.Fatalf("single-packet reader %d was not woken", index)
		}
	}
}

func BenchmarkPacketQueueScheduling(b *testing.B) {
	source := netip.MustParseAddr("192.0.2.5")
	target := netip.MustParseAddr("198.51.100.5")
	packet := testOutputUDPPacket(source, target, 14000, 443, 1400)
	const capacity = 256
	for _, benchmark := range []struct {
		name  string
		fair  bool
		flows int
	}{
		{name: "fifo", flows: 1},
		{name: "drr-single", fair: true, flows: 1},
		{name: "drr-64", fair: true, flows: 64},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			var queue packetQueue
			if benchmark.fair {
				queue.initFair(capacity, time.Now(), 1500, [16]byte{5})
			} else {
				queue.initFIFO(capacity, time.Now())
			}
			flowIDs := make([]uint64, benchmark.flows)
			for index := range flowIDs {
				flowIDs[index] = uint64(index + 1)
			}
			b.SetBytes(int64(capacity * len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for index := 0; index < capacity; index++ {
					slot, ok := queue.tryReserve()
					if !ok {
						b.Fatal("output queue unexpectedly full")
					}
					_, _ = queue.enqueueReservedTCP(slot, packet, false, flowIDs[index%len(flowIDs)], false)
				}
				for index := 0; index < capacity; index++ {
					entry, ok := queue.tryDequeue()
					if !ok {
						b.Fatal("output queue unexpectedly empty")
					}
					queue.release(entry)
				}
			}
		})
	}
	b.Run("drr-single-interleaved", func(b *testing.B) {
		var queue packetQueue
		queue.initFair(capacity, time.Now(), 1500, [16]byte{5})
		b.SetBytes(int64(len(packet)))
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			slot, ok := queue.tryReserve()
			if !ok {
				b.Fatal("output queue unexpectedly full")
			}
			_, _ = queue.enqueueReservedTCP(slot, packet, false, 1, false)
			entry, ok := queue.tryDequeue()
			if !ok {
				b.Fatal("output queue unexpectedly empty")
			}
			queue.release(entry)
		}
	})
}

func BenchmarkPacketQueueOverloadAdmission(b *testing.B) {
	source := netip.MustParseAddr("192.0.2.15")
	target := netip.MustParseAddr("198.51.100.15")
	packet := testOutputUDPPacket(source, target, 14000, 443, 1400)
	const capacity = 256

	b.Run("reject-full", func(b *testing.B) {
		var queue packetQueue
		queue.initFair(capacity, time.Now(), 1500, [16]byte{15})
		for index := 0; index < capacity; index++ {
			slot, ok := queue.tryReserve()
			if !ok || !queue.enqueueReservedPacketForFlow(slot, packet, false, outputFlowKey{tcp: 1}, false) {
				b.Fatal("failed to fill output queue")
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			if _, ok := queue.tryReserve(); ok {
				b.Fatal("full output queue admitted a slot")
			}
		}
	})

	for _, flows := range []int{1, 64} {
		b.Run(fmt.Sprintf("replace-fattest-%d", flows), func(b *testing.B) {
			var queue packetQueue
			queue.initFair(capacity, time.Now(), 1500, [16]byte{15})
			for index := 0; index < capacity; index++ {
				slot, ok := queue.tryReserve()
				flow := outputFlowKey{tcp: uint64(index%flows + 1)}
				if !ok || !queue.enqueueReservedPacketForFlow(slot, packet, false, flow, false) {
					b.Fatal("failed to fill output queue")
				}
			}
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				replaced, ok := queue.replaceBestEffort()
				flow := outputFlowKey{tcp: uint64(iteration%flows + 1)}
				if !ok || !queue.enqueueReservedPacketForFlow(replaced.slot, packet, false, flow, false) {
					b.Fatal("failed to replace published backlog")
				}
			}
		})

		b.Run(fmt.Sprintf("stack-replace-fattest-%d", flows), func(b *testing.B) {
			var stack Stack
			queue := &stack.outbound
			queue.initFair(capacity, time.Now(), 1500, [16]byte{15})
			for index := 0; index < capacity; index++ {
				slot, ok := queue.tryReserve()
				flow := outputFlowKey{tcp: uint64(index%flows + 1)}
				if !ok || !queue.enqueueReservedPacketForFlow(slot, packet, false, flow, false) {
					b.Fatal("failed to fill output queue")
				}
			}
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				slot, err := stack.replaceBestEffortPacket(queue)
				flow := outputFlowKey{tcp: uint64(iteration%flows + 1)}
				if err != nil || !queue.enqueueReservedPacketForFlow(slot, packet, false, flow, false) {
					b.Fatal("failed to replace and count published backlog")
				}
			}
		})

	}
}

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
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPublicUDPDatagramCodecKnownAnswers(t *testing.T) {
	tests := []struct {
		name     string
		packet   string
		datagram UDPDatagram
	}{
		{
			name: "IPv4 odd payload",
			packet: "452e0023123440003711452dc0000203c6336404" +
				"14e90035000ff26d00010203040506",
			datagram: UDPDatagram{
				Source: netip.MustParseAddrPort("192.0.2.3:5353"), Destination: netip.MustParseAddrPort("198.51.100.4:53"),
				Payload: mustCodecVector(t, "00010203040506"),
			},
		},
		{
			name: "IPv4 zero checksum",
			packet: "45000021abcd00004011e2bfc0000205c6336406" +
				"30390035000d000068656c6c6f",
			datagram: UDPDatagram{
				Source: netip.MustParseAddrPort("192.0.2.5:12345"), Destination: netip.MustParseAddrPort("198.51.100.6:53"),
				ChecksumDisabled: true, Payload: []byte("hello"),
			},
		},
		{
			name: "IPv6 odd payload",
			packet: "67e123450011114020010db8000000000000000000000003" +
				"20010db8000000000000000000000004" +
				"ffff30390011600a000102030405060708",
			datagram: UDPDatagram{
				Source: netip.MustParseAddrPort("[2001:db8::3]:65535"), Destination: netip.MustParseAddrPort("[2001:db8::4]:12345"),
				Payload: mustCodecVector(t, "000102030405060708"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := ParseIPPacket(mustCodecVector(t, test.packet))
			if err != nil {
				t.Fatal(err)
			}
			datagram, err := packet.UDPDatagram()
			if err != nil {
				t.Fatalf("UDPDatagram: %v", err)
			}
			if !reflect.DeepEqual(datagram, test.datagram) {
				t.Fatalf("parsed datagram = %+v, want %+v", datagram, test.datagram)
			}
			encoded, err := test.datagram.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, packet.Payload) {
				t.Fatalf("MarshalBinary: error=%v\n got %x\nwant %x", err, encoded, packet.Payload)
			}
			assertUDPDatagramWire(t, test.datagram, encoded)
		})
	}
}

func TestPublicUDPDatagramCodecKnownAnswerMutations(t *testing.T) {
	base := mustCodecVector(t, "67e123450011114020010db800000000000000000000000320010db8000000000000000000000004"+
		"ffff30390011600a000102030405060708")
	tests := []struct {
		name   string
		mutate func(IPPacket, []byte)
	}{
		{name: "length below header", mutate: func(packet IPPacket, payload []byte) {
			binary.BigEndian.PutUint16(payload[4:6], 7)
			repairReferenceTransportChecksum(packet.Source, packet.Destination, ProtocolUDP, payload, 6)
		}},
		{name: "length beyond payload", mutate: func(packet IPPacket, payload []byte) {
			binary.BigEndian.PutUint16(payload[4:6], uint16(len(payload)+1))
			repairReferenceTransportChecksum(packet.Source, packet.Destination, ProtocolUDP, payload, 6)
		}},
		{name: "IPv6 zero checksum", mutate: func(_ IPPacket, payload []byte) { payload[6], payload[7] = 0, 0 }},
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
			if _, err = packet.UDPDatagram(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("UDPDatagram error = %v, want EINVAL", err)
			}
			if !bytes.Equal(payload, before) {
				t.Fatal("failed UDP parse modified its input")
			}
		})
	}
}

func FuzzPublicUDPDatagramWireEncoding(f *testing.F) {
	f.Add(false, true, uint16(12345), uint16(53), []byte("IPv4 zero checksum"))
	f.Add(true, false, uint16(65535), uint16(5353), []byte("IPv6 odd"))
	f.Fuzz(func(t *testing.T, ipv6, disableChecksum bool, sourcePort, destinationPort uint16, payload []byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		datagram := UDPDatagram{
			Source:           netip.AddrPortFrom(netip.MustParseAddr("192.0.2.103"), sourcePort),
			Destination:      netip.AddrPortFrom(netip.MustParseAddr("198.51.100.103"), destinationPort),
			ChecksumDisabled: disableChecksum, Payload: payload,
		}
		if ipv6 {
			datagram.Source = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::103"), sourcePort)
			datagram.Destination = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::103"), destinationPort)
			datagram.ChecksumDisabled = false
		}
		wire, err := datagram.AppendBinary(nil)
		if err != nil {
			t.Fatalf("AppendBinary: %v", err)
		}
		assertUDPDatagramWire(t, datagram, wire)
		packet := IPPacket{Source: datagram.Source.Addr(), Destination: datagram.Destination.Addr(), Protocol: ProtocolUDP, Payload: wire}
		if _, err = packet.UDPDatagram(); err != nil {
			t.Fatalf("UDPDatagram(encoded datagram): %v", err)
		}
	})
}

func assertUDPDatagramWire(t testing.TB, datagram UDPDatagram, wire []byte) {
	t.Helper()
	if len(wire) != udpHeaderSize+len(datagram.Payload) ||
		binary.BigEndian.Uint16(wire[0:2]) != datagram.Source.Port() ||
		binary.BigEndian.Uint16(wire[2:4]) != datagram.Destination.Port() ||
		int(binary.BigEndian.Uint16(wire[4:6])) != len(wire) || !bytes.Equal(wire[udpHeaderSize:], datagram.Payload) {
		t.Fatalf("UDP wire does not match semantic value: %x", wire)
	}
	value := binary.BigEndian.Uint16(wire[6:8])
	if datagram.ChecksumDisabled {
		if !datagram.Source.Addr().Unmap().Is4() || value != 0 {
			t.Fatalf("disabled UDP checksum = %#x for %s", value, datagram.Source.Addr())
		}
	} else if value == 0 || referenceTransportChecksum(datagram.Source.Addr(), datagram.Destination.Addr(), ProtocolUDP, wire) != 0 {
		t.Fatalf("UDP reference checksum = %#x, field=%#x", referenceTransportChecksum(datagram.Source.Addr(), datagram.Destination.Addr(), ProtocolUDP, wire), value)
	}
}

type testUDPStringAddress string

func (a testUDPStringAddress) Network() string { return "udp" }
func (a testUDPStringAddress) String() string  { return string(a) }

func TestUDPConcurrentDemultiplexing(t *testing.T) {
	for _, test := range []struct {
		name   string
		local  netip.Addr
		remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.1"), remote: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::1"), remote: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			defer stack.Close()
			first, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.LocalAddr().String() == second.LocalAddr().String() {
				t.Fatal("UDP sockets received the same ephemeral port")
			}
			link.echoUDP = true
			target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(test.remote, 5353))
			connections := []net.PacketConn{first, second}
			var wait sync.WaitGroup
			for index, connection := range connections {
				index, connection := index, connection
				wait.Add(1)
				go func() {
					defer wait.Done()
					payload := []byte{byte(index), 2, 3, 4}
					if _, writeErr := connection.WriteTo(payload, target); writeErr != nil {
						t.Error(writeErr)
						return
					}
					if deadlineErr := connection.SetReadDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
						t.Error(deadlineErr)
						return
					}
					buffer := make([]byte, 32)
					n, source, readErr := connection.ReadFrom(buffer)
					if readErr != nil {
						t.Error(readErr)
						return
					}
					if !bytes.Equal(buffer[:n], payload) || source.String() != target.String() {
						t.Errorf("UDP reply = %x from %v, want %x from %v", buffer[:n], source, payload, target)
					}
				}()
			}
			wait.Wait()
		})
	}
}

func TestUDPDestinationPortZeroUsesProtocolPath(t *testing.T) {
	for _, test := range []struct {
		name           string
		network        string
		client, server netip.Addr
	}{
		{name: "IPv4", network: "udp4", client: netip.MustParseAddr("192.0.2.230"), server: netip.MustParseAddr("192.0.2.231")},
		{name: "IPv6", network: "udp6", client: netip.MustParseAddr("2001:db8::230"), server: netip.MustParseAddr("2001:db8::231")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.client, test.server, 1400)
			newStackBridge(t, client, server)
			connection, err := client.DialUDP(context.Background(), test.network, netip.AddrPort{}, netip.AddrPortFrom(test.server, 0))
			if err != nil {
				t.Fatalf("DialUDP to port zero: %v", err)
			}
			defer connection.Close()
			if n, writeErr := connection.Write([]byte("zero")); writeErr != nil || n != len("zero") {
				t.Fatalf("Write to port zero = %d, %v", n, writeErr)
			}
			if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, readErr := connection.Read(make([]byte, 1)); readErr == nil {
				t.Fatal("port-zero datagram did not receive an ICMP error")
			} else {
				var networkError ICMPError
				if !errors.As(readErr, &networkError) || networkError.QuotedTargetPort != 0 {
					t.Fatalf("port-zero read error = %#v, socket info = %+v", readErr, connection.(*UDPConn).Info())
				}
			}
		})
	}
}

func TestUDPExplicitErrorQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.232")
	first := netip.MustParseAddrPort("198.51.100.232:53")
	second := netip.MustParseAddrPort("198.51.100.233:54")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newUDPConn(stack, "udp4", 5300, false, local, netip.AddrPort{}, datagramSocketOptionSet{})
	defer connection.closeFromStack()
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	if enabled, getErr := connection.ReceiveErrors(); getErr != nil || !enabled {
		t.Fatalf("ReceiveErrors = %v, %v", enabled, getErr)
	}
	connection.deliverError(first, ICMPError{Code: 1})
	connection.deliverError(second, ICMPError{Code: 2})
	if info := connection.Info(); info.ErrorQueueEntries != 2 || info.ErrorQueueBytes != 2*socketErrorMetadataSize || !info.ReceiveErrors || info.ErrorsDropped != 0 {
		t.Fatalf("explicit UDP error queue diagnostics = %+v", info)
	}
	if err = connection.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, readErr := connection.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("ordinary read did not report the pending extended error")
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 2 {
			t.Fatalf("ordinary read with explicit errors = %v, want newest ICMP error", readErr)
		}
	}
	if _, readErr := connection.Read(make([]byte, 1)); !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary read after pending error = %v, want deadline", readErr)
	}
	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	for index, target := range []netip.AddrPort{first, second} {
		queued, readErr := connection.ReadError()
		if readErr != nil || queued == nil {
			t.Fatalf("ReadError %d = %#v, %v", index, queued, readErr)
		}
		address, ok := queued.Addr.(*net.UDPAddr)
		if !ok || address.AddrPort() != target {
			t.Fatalf("ReadError %d address = %#v, want %v", index, queued.Addr, target)
		}
		var networkError ICMPError
		if !errors.As(queued, &networkError) || networkError.Code != byte(index+1) {
			t.Fatalf("ReadError %d payload = %#v", index, queued)
		}
		if index == 0 {
			count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait)
			if count != 0 || !errors.As(readErr, &networkError) || networkError.Code != 2 {
				t.Fatalf("ordinary error after first ReadError = %d, %v", count, readErr)
			}
		}
	}
	if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("empty ReadError = %#v, %v", queued, readErr)
	}

	if err = connection.SetReadBuffer(socketErrorMetadataSize); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(first, ICMPError{Code: 3})
	connection.deliverError(second, ICMPError{Code: 4})
	if info := connection.Info(); info.ErrorQueueEntries != 1 || info.ErrorsDropped != 1 || info.ICMPErrors != 4 {
		t.Fatalf("bounded UDP error queue diagnostics = %+v", info)
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || readErr == nil {
		t.Fatalf("ordinary error after extended queue overflow = %d, %v", count, readErr)
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 4 {
			t.Fatalf("latest pending error after overflow = %v", readErr)
		}
	}
	if _, err = connection.ReadError(); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(first, ICMPError{Code: 5})
	if err = connection.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connection.Info(); info.ErrorQueueEntries != 0 || info.ErrorQueueBytes != 0 {
		t.Fatalf("disabled UDP error queue = %+v", info)
	}
	connection.deliverError(first, ICMPError{Code: 6})
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || readErr == nil {
		t.Fatalf("unconnected UDP read after disabling error queue = %d, %v", count, readErr)
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 5 {
			t.Fatalf("pending error changed when error reception was disabled: %v", readErr)
		}
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("unconnected UDP read after pending error = %d, %v", count, readErr)
	}
	connected := newUDPConn(stack, "udp4", 5301, false, local, first, datagramSocketOptionSet{})
	defer connected.closeFromStack()
	if err = connected.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	connected.deliverError(first, ICMPError{Reporter: first.Addr(), Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort})
	if err = connected.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 {
		t.Fatalf("disabled connected UDP error queue = %+v", info)
	}
	connected.deliverError(first, ICMPError{Reporter: first.Addr(), Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol})
	if err = connected.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 || info.ICMPErrors != 2 {
		t.Fatalf("repeatedly disabling connected UDP error reception discarded a pending error: %+v", info)
	}
	if err = connected.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	count, readErr := connected.Read(make([]byte, 1))
	var networkError ICMPError
	if count != 0 || !errors.As(readErr, &networkError) || networkError.Code != ICMPv4DestinationUnreachableCodeProtocol {
		t.Fatalf("connected UDP read after disabling error queue = %d, %v", count, readErr)
	}
	connection.closeFromStack()
	if _, err = connection.ReceiveErrors(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReceiveErrors after Close = %v", err)
	}
	if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, net.ErrClosed) {
		t.Fatalf("ReadError after Close = %#v, %v", queued, readErr)
	}
}

func TestUDPBatchRead(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.234")
	remote := netip.MustParseAddr("198.51.100.234")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 5310))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	for index, payload := range [][]byte{[]byte("abcdef"), []byte("second")} {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, uint16(5320+index), 5310, payload)); err != nil {
			t.Fatal(err)
		}
	}
	firstA, firstB := make([]byte, 2), make([]byte, 4)
	second := make([]byte, 3)
	messages := []SocketMessage{
		{Buffers: [][]byte{firstA, firstB}, OOB: make([]byte, 128)},
		{Buffers: [][]byte{second}, OOB: make([]byte, 8)},
		{Buffers: [][]byte{make([]byte, 1)}, N: 91, NN: 92, Flags: 93, Addr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 5399))},
	}
	n, err := connection.ReadBatch(messages, 0)
	if err != nil || n != 2 {
		t.Fatalf("ReadBatch = %d, %v, want 2, nil", n, err)
	}
	if string(append(firstA, firstB...)) != "abcdef" || messages[0].N != 6 || messages[0].NN == 0 || messages[0].Flags != 0 {
		t.Fatalf("first batch message = %+v payload %q", messages[0], append(firstA, firstB...))
	}
	if address, ok := messages[0].Addr.(*net.UDPAddr); !ok || address.AddrPort() != netip.AddrPortFrom(remote, 5320) {
		t.Fatalf("first batch source = %#v", messages[0].Addr)
	}
	var control IPv4ControlMessage
	if err = control.Parse(messages[0].OOB[:messages[0].NN]); err != nil || control.Dst != local {
		t.Fatalf("first batch control = %+v, %v", control, err)
	}
	if !bytes.Equal(messages[0].OOB[20:24], local.AsSlice()) || !bytes.Equal(messages[0].OOB[24:28], local.AsSlice()) {
		t.Fatalf("first batch IPv4 packet-info fields = %x/%x, want %s", messages[0].OOB[20:24], messages[0].OOB[24:28], local)
	}
	if string(second) != "sec" || messages[1].N != 3 || messages[1].NN != len(messages[1].OOB) ||
		messages[1].Flags != MessageFlagTruncated|MessageFlagControlTruncated {
		t.Fatalf("second batch message = %+v payload %q", messages[1], second)
	}
	if messages[2].N != 91 || messages[2].NN != 92 || messages[2].Flags != 93 || messages[2].Addr == nil {
		t.Fatalf("unprocessed batch message changed = %+v", messages[2])
	}

	n, err = connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait)
	if n != 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("nonblocking empty ReadBatch = %d, %v", n, err)
	}
	if n, err = connection.ReadBatch(messages[:1], 1); n != 0 || !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("unsupported ReadBatch flags = %d, %v", n, err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 5330, 5310, []byte("kept"))); err != nil {
		t.Fatal(err)
	}
	if n, err = connection.ReadBatch([]SocketMessage{{Buffers: nil}}, MessageFlagDontWait); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("empty-buffer ReadBatch = %d, %v", n, err)
	}
	kept := make([]byte, 4)
	if n, err = connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{kept}}}, MessageFlagDontWait); n != 1 || err != nil || string(kept) != "kept" {
		t.Fatalf("message after invalid buffer = %d, %v, %q", n, err, kept)
	}

	if err = writeTestPacket(stack, buildTestUDP(remote, local, 5331, 5310, []byte("data"))); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(netip.AddrPortFrom(remote, 5331), ICMPError{Code: 7})
	batch := []SocketMessage{{Buffers: [][]byte{make([]byte, 4)}}, {Buffers: [][]byte{make([]byte, 1)}}}
	if n, err = connection.ReadBatch(batch, 0); n != 1 || err != nil {
		t.Fatalf("data after ignored ICMP = %d, %v", n, err)
	}
	if info := connection.Info(); info.ErrorQueueEntries != 0 {
		t.Fatalf("ignored ICMP entered UDP error queue: %+v", info)
	}
	if n, err = connection.ReadBatch(batch[1:], MessageFlagDontWait); n != 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("read after ignored ICMP = %d, %v", n, err)
	}

	connectedTarget := netip.AddrPortFrom(remote, 5331)
	connectedNet, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, connectedTarget)
	if err != nil {
		t.Fatal(err)
	}
	connected := connectedNet.(*UDPConn)
	defer connected.Close()
	connectedPort := connected.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, connectedTarget.Port(), connectedPort, []byte("data"))); err != nil {
		t.Fatal(err)
	}
	connected.deliverError(connectedTarget, ICMPError{Reporter: remote, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort})
	n, err = connected.ReadBatch(batch, 0)
	var networkError ICMPError
	if n != 0 || !errors.As(err, &networkError) || networkError.Code != ICMPv4DestinationUnreachableCodePort {
		t.Fatalf("connected UDP pending error before data = %d, %v", n, err)
	}
	if n, err = connected.ReadBatch(batch, 0); n != 1 || err != nil || string(batch[0].Buffers[0]) != "data" {
		t.Fatalf("connected UDP data after pending error = %d, %v, %q", n, err, batch[0].Buffers[0])
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 {
		t.Fatalf("connected UDP retained an extended error without ReceiveErrors: %+v", info)
	}
	if n, err = connected.ReadBatch(batch[1:], MessageFlagDontWait); n != 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("connected UDP read after queued data = %d, %v", n, err)
	}
}

func TestUDPBatchWrite(t *testing.T) {
	firstLocal := netip.MustParseAddr("192.0.2.235")
	secondLocal := netip.MustParseAddr("192.0.2.236")
	remote := netip.MustParseAddr("198.51.100.235")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(firstLocal, 32), netip.PrefixFrom(secondLocal, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 5340))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	control, err := (&IPv4ControlMessage{Src: secondLocal}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	messages := []SocketMessage{
		{Buffers: [][]byte{[]byte("ab"), []byte("cd")}, Addr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 5350))},
		{Buffers: [][]byte{[]byte("ef"), []byte("gh")}, OOB: control, Addr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 5351))},
	}
	n, err := connection.WriteBatch(messages, 0)
	if err != nil || n != 2 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	for index, want := range []struct {
		payload string
		source  netip.Addr
		port    uint16
	}{{"abcd", firstLocal, 5350}, {"efgh", secondLocal, 5351}} {
		packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
		if !ok || packet.source != want.source || string(packet.payload[udpHeaderSize:]) != want.payload || binary.BigEndian.Uint16(packet.payload[2:4]) != want.port {
			t.Fatalf("batch packet %d = %+v payload %q", index, packet, packet.payload)
		}
		if messages[index].N != 4 || messages[index].NN != len(messages[index].OOB) {
			t.Fatalf("batch result %d = %+v", index, messages[index])
		}
	}
	mixedControl := mustCodecVector(t, "1c00000000000000000000000800000000000000c00002ecc00002eb")
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("spec-dst"), mixedControl, netip.AddrPortFrom(remote, 5352)); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != secondLocal || string(packet.payload[udpHeaderSize:]) != "spec-dst" {
		t.Fatalf("mixed IPv4 packet-info source = %s payload %q, want %s/spec-dst", packet.source, packet.payload[udpHeaderSize:], secondLocal)
	}
	addrOnlyControl := mustCodecVector(t, "1c0000000000000000000000080000000000000000000000c00002ec")
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("addr-only"), addrOnlyControl, netip.AddrPortFrom(remote, 5353)); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != firstLocal || string(packet.payload[udpHeaderSize:]) != "addr-only" {
		t.Fatalf("addr-only IPv4 packet-info source = %s payload %q, want %s/addr-only", packet.source, packet.payload[udpHeaderSize:], firstLocal)
	}
	if n, err = connection.WriteBatch(messages[:1], MessageFlagDontWait); n != 1 || err != nil {
		t.Fatalf("nonblocking WriteBatch = %d, %v", n, err)
	}
	_ = readOutboundPacket(t, stack)
	prefix := []SocketMessage{messages[0], {Buffers: nil, Addr: messages[1].Addr, N: 91, NN: 92, Flags: 93}}
	if n, err = connection.WriteBatch(prefix, 0); n != 1 || err != nil {
		t.Fatalf("partial WriteBatch = %d, %v", n, err)
	}
	if prefix[1].N != 91 || prefix[1].NN != 92 || prefix[1].Flags != 93 {
		t.Fatalf("unprocessed WriteBatch message changed = %+v", prefix[1])
	}
	_ = readOutboundPacket(t, stack)
	if n, err = connection.WriteBatch(prefix[1:], 0); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("retried invalid WriteBatch suffix = %d, %v", n, err)
	}

	connectedNet, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5352))
	if err != nil {
		t.Fatal(err)
	}
	connected := connectedNet.(*UDPConn)
	defer connected.Close()
	connectedMessage := []SocketMessage{{Buffers: [][]byte{[]byte("connected")}}}
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 1 || err != nil {
		t.Fatalf("connected WriteBatch = %d, %v", n, err)
	}
	_ = readOutboundPacket(t, stack)
	if err = connected.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired connected WriteBatch = %d, %v", n, err)
	}
	if operationError := checkNetOpError(t, err, "write", "udp4"); operationError.Addr == nil || operationError.Addr.String() != "198.51.100.235:5352" {
		t.Fatalf("expired connected WriteBatch address = %v", operationError.Addr)
	}
	if err = connected.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	connectedMessage[0].Addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 5352))
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 0 || !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("addressed connected WriteBatch = %d, %v", n, err)
	}
}

func TestUDPFragmentedWriteQueueExhaustionPolicy(t *testing.T) {
	for _, test := range []struct {
		name          string
		flags         int
		receiveErrors bool
	}{
		{name: "default"},
		{name: "default/dontwait", flags: MessageFlagDontWait},
		{name: "receive-errors", receiveErrors: true},
		{name: "receive-errors/dontwait", flags: MessageFlagDontWait, receiveErrors: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.237")
			remote := netip.MustParseAddrPort("198.51.100.237:5353")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 600})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 5341))
			if err != nil {
				t.Fatal(err)
			}
			connection := packetConnection.(*UDPConn)
			defer connection.Close()
			if err = connection.SetReceiveErrors(test.receiveErrors); err != nil {
				t.Fatal(err)
			}

			dummy := buildIPPacket(local, remote.Addr(), ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
			for stack.outbound.len() < outboundPacketQueue-1 {
				if !stack.outbound.tryEnqueue(dummy) {
					t.Fatal("outbound queue filled before the expected boundary")
				}
			}
			before := stack.outbound.len()
			payload := bytes.Repeat([]byte{0x71}, 1200)
			message := []SocketMessage{{Buffers: [][]byte{payload}, Addr: net.UDPAddrFromAddrPort(remote)}}
			count, writeErr := connection.WriteBatch(message, test.flags)
			if count != 1 || writeErr != nil || message[0].N != len(payload) {
				t.Fatalf("fragmented WriteBatch = %d, %v, N=%d", count, writeErr, message[0].N)
			}
			if info := connection.Info(); info.PacketsSent != 1 || info.BytesSent != uint64(len(payload)) {
				t.Fatalf("successful fragmented write statistics = %d packets, %d bytes", info.PacketsSent, info.BytesSent)
			}
			if after := stack.outbound.len(); after != before+1 {
				t.Fatalf("fragmented write changed queue depth from %d to %d, want %d", before, after, before+1)
			}
			if stats := stack.Stats(); stats.OutboundPackets < 2 || stats.OutboundQueueDrops+1 != stats.OutboundPackets {
				t.Fatalf("fragmented write stack statistics = %+v", stats)
			}
			var reassembly IPPacketReassembly
			var reassembled IPPacket
			complete := false
			for {
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					break
				}
				packet, parseErr := ParseIPPacket(entry.packet)
				if parseErr == nil {
					if fragment, fragmented := packet.Fragment(); fragmented && fragment.Protocol == ProtocolUDP {
						var addErr error
						reassembled, complete, addErr = reassembly.Add(packet)
						if addErr != nil {
							t.Fatal(addErr)
						}
					}
				}
				stack.outbound.release(entry)
			}
			datagram, datagramErr := reassembled.UDPDatagram()
			if !complete || datagramErr != nil || !bytes.Equal(datagram.Payload, payload) {
				t.Fatalf("reassembled fragmented WriteBatch = complete %t datagram %+v error %v", complete, datagram, datagramErr)
			}
			if !connection.acceptsError(remote) {
				t.Fatal("fragmented write did not retain ICMP correlation")
			}
		})
	}
}

func TestUDPBatchWriteFragmentedBuffers(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.237")
	remote := netip.MustParseAddr("198.51.100.237")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 600})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5353))
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*UDPConn)
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x5a}, 2000)
	messages := []SocketMessage{{Buffers: [][]byte{payload[:333], payload[333:1500], payload[1500:]}}}
	if count, writeErr := connection.WriteBatch(messages, 0); writeErr != nil || count != 1 || messages[0].N != len(payload) {
		t.Fatalf("fragmented UDP WriteBatch = %d, %v, message %+v", count, writeErr, messages[0])
	}
	receiver, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(remote, 32)}, MTU: 600})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	var reassembled []byte
	for fragmentCount := 0; reassembled == nil && fragmentCount < 16; fragmentCount++ {
		reassembled = receiver.reassemblePacket(readOutboundPacket(t, stack), time.Now())
	}
	packet, ok := parseIPPacket(reassembled, false)
	if !ok || packet.protocol != ProtocolUDP || len(packet.payload) != udpHeaderSize+len(payload) ||
		!bytes.Equal(packet.payload[udpHeaderSize:], payload) || transportChecksum(local, remote, ProtocolUDP, packet.payload) != 0 {
		t.Fatalf("reassembled UDP batch packet = %+v, parsed = %v", packet, ok)
	}
}

func TestUDPPacketizationLayerPathMTUDiscovery(t *testing.T) {
	for _, test := range []struct {
		name       string
		local      netip.Addr
		remote     netip.Addr
		baseMTU    uint32
		payloadLen int
		connected  bool
	}{
		{name: "IPv4 connected", local: netip.MustParseAddr("192.0.2.231"), remote: netip.MustParseAddr("198.51.100.231"), baseMTU: 1000, payloadLen: 1200, connected: true},
		{name: "IPv6 unconnected", local: netip.MustParseAddr("2001:db8::231"), remote: netip.MustParseAddr("2001:db8:1::231"), baseMTU: 1280, payloadLen: 1400},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.local.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if !stack.observePathMTU(test.remote, test.baseMTU) {
				t.Fatal("failed to install base PMTU")
			}
			target := netip.AddrPortFrom(test.remote, 5353)
			var connection *UDPConn
			if test.connected {
				var netConnection net.Conn
				netConnection, err = stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, target)
				if err == nil {
					connection = netConnection.(*UDPConn)
				}
			} else {
				var packetConnection net.PacketConn
				packetConnection, err = stack.ListenUDP(context.Background(), "udp", netip.AddrPort{})
				if err == nil {
					connection = packetConnection.(*UDPConn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, test.payloadLen)
			if test.connected {
				if _, err = connection.Write(payload); err != nil {
					t.Fatal(err)
				}
			} else if _, err = connection.WriteToUDPAddrPort(payload, target); err != nil {
				t.Fatal(err)
			}
			readPacket := func() []byte {
				buffer := make([]byte, 1600)
				sizes := []int{0}
				if _, readErr := stack.Read([][]byte{buffer}, sizes, 0); readErr != nil {
					t.Fatal(readErr)
				}
				return append([]byte(nil), buffer[:sizes[0]]...)
			}
			for fragment := 0; fragment < 2; fragment++ {
				if packet := readPacket(); len(packet) > int(test.baseMTU) {
					t.Fatalf("ordinary UDP fragment size = %d, want <= %d", len(packet), test.baseMTU)
				}
			}
			if test.connected {
				if _, err = connection.WritePathMTUProbe(payload); err != nil {
					t.Fatal(err)
				}
			} else if _, err = connection.WritePathMTUProbeTo(payload, target); err != nil {
				t.Fatal(err)
			}
			probe := readPacket()
			wantProbeSize := test.payloadLen + udpHeaderSize + 20
			if test.remote.Is6() {
				wantProbeSize = test.payloadLen + udpHeaderSize + 40
			}
			if len(probe) != wantProbeSize {
				t.Fatalf("UDP path probe size = %d, want %d", len(probe), wantProbeSize)
			}
			if test.connected {
				err = connection.ConfirmPathMTU(wantProbeSize)
			} else {
				err = connection.ConfirmPathMTUFor(test.remote, wantProbeSize)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mtu, pathErr := stack.PathMTU(test.remote); pathErr != nil || mtu != wantProbeSize {
				t.Fatalf("confirmed UDP PMTU = %d, %v, want %d", mtu, pathErr, wantProbeSize)
			}
		})
	}
}

func TestUDPPathMTUConfirmationCanRaiseExpiredBaseline(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.150")
	remote := netip.MustParseAddr("192.0.2.151")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(remote, 1000) {
		t.Fatal("initial path MTU was not recorded")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[remote]
	entry.updated = time.Now().Add(-pathMTULifetime)
	stack.pathMTU[remote] = entry
	stack.pathMTUMu.Unlock()
	if err = stack.ConfirmPathMTU(remote, 1200); err != nil {
		t.Fatalf("confirming above expired baseline: %v", err)
	}
	if mtu, pathErr := stack.PathMTU(remote); pathErr != nil || mtu != 1200 {
		t.Fatalf("confirmed path MTU = %d, %v, want 1200", mtu, pathErr)
	}
}

func TestPublicUDPDatagramCodec(t *testing.T) {
	tests := []UDPDatagram{
		{Source: netip.MustParseAddrPort("192.0.2.1:5353"), Destination: netip.MustParseAddrPort("198.51.100.2:53"), ChecksumDisabled: true, Payload: []byte("unchecked-v4")},
		{Source: netip.MustParseAddrPort("[2001:db8::1]:5353"), Destination: netip.MustParseAddrPort("[2001:db8::2]:53"), Payload: []byte("checked-v6")},
	}
	for _, test := range tests {
		name := "IPv4ZeroChecksum"
		if test.Source.Addr().Is6() {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			wire, err := test.AppendBinary([]byte{1, 2})
			if err != nil {
				t.Fatalf("append UDP: %v", err)
			}
			if !bytes.Equal(wire[:2], []byte{1, 2}) {
				t.Fatal("UDP AppendBinary changed prefix")
			}
			wire = wire[2:]
			checksumValue := binary.BigEndian.Uint16(wire[6:8])
			if test.ChecksumDisabled && checksumValue != 0 || !test.ChecksumDisabled && (checksumValue == 0 || transportChecksum(test.Source.Addr(), test.Destination.Addr(), ProtocolUDP, wire) != 0) {
				t.Fatalf("encoded UDP checksum = %#x", checksumValue)
			}
			packet := IPPacket{Source: test.Source.Addr(), Destination: test.Destination.Addr(), Protocol: ProtocolUDP, HopLimit: 64, Payload: append(wire, 0xaa, 0xbb)}
			parsed, err := packet.UDPDatagram()
			if err != nil {
				t.Fatalf("parse UDP: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.ChecksumDisabled != test.ChecksumDisabled || !bytes.Equal(parsed.Payload, test.Payload) {
				t.Fatalf("parsed UDP = %+v, want %+v", parsed, test)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("UDP round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
		})
	}
}

func TestPublicUDPDatagramCodecIPv4MappedAddresses(t *testing.T) {
	datagram := UDPDatagram{
		Source: netip.MustParseAddrPort("[::ffff:192.0.2.1]:5353"), Destination: netip.MustParseAddrPort("[::ffff:198.51.100.2]:53"),
		Payload: []byte("mapped"),
	}
	wire, err := datagram.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: datagram.Source.Addr(), Destination: datagram.Destination.Addr(), Protocol: ProtocolUDP, Payload: wire}
	parsed, err := packet.UDPDatagram()
	if err != nil {
		t.Fatalf("parse mapped UDP datagram: %v", err)
	}
	if parsed.Source != netip.AddrPortFrom(datagram.Source.Addr().Unmap(), datagram.Source.Port()) ||
		parsed.Destination != netip.AddrPortFrom(datagram.Destination.Addr().Unmap(), datagram.Destination.Port()) ||
		!bytes.Equal(parsed.Payload, datagram.Payload) {
		t.Fatalf("parsed mapped UDP datagram = %+v", parsed)
	}
}

func TestPublicUDPDatagramCodecErrorsDoNotModifyDestination(t *testing.T) {
	datagram := UDPDatagram{Source: netip.MustParseAddrPort("[2001:db8::1]:1"), Destination: netip.MustParseAddrPort("[2001:db8::2]:2"), ChecksumDisabled: true}
	prefix := []byte{3, 4, 5}
	want := append([]byte(nil), prefix...)
	if got, err := datagram.AppendBinary(prefix); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(prefix, want) {
		t.Fatalf("invalid UDP AppendBinary: got=%x error=%v", got, err)
	}
	datagram.ChecksumDisabled = false
	datagram.Source = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone("test"), 1)
	if _, err := datagram.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned UDP datagram error = %v", err)
	}
}

func FuzzPublicUDPDatagramCodec(f *testing.F) {
	seed := UDPDatagram{Source: netip.MustParseAddrPort("[2001:db8::1]:1234"), Destination: netip.MustParseAddrPort("[2001:db8::2]:53"), Payload: []byte("seed")}
	wire, err := seed.AppendBinary(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{Source: seed.Source.Addr(), Destination: seed.Destination.Addr(), Protocol: ProtocolUDP, HopLimit: 64, Payload: wire}
		datagram, err := packet.UDPDatagram()
		if err != nil {
			return
		}
		encoded, err := datagram.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed UDP could not be encoded: %v", err)
		}
		assertUDPDatagramWire(t, datagram, encoded)
		packet.Payload = encoded
		reparsed, err := packet.UDPDatagram()
		if err != nil {
			t.Fatalf("encoded UDP could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place UDP append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func TestMarshalUDPDatagramOverwritesReusedBuffer(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.243")
	target := netip.MustParseAddr("198.51.100.243")
	payload := []byte("reused UDP datagram")
	want := make([]byte, udpHeaderSize+len(payload))
	marshalUDPDatagram(want, source, target, 49152, 5353, payload)
	dirty := make([]byte, len(want))
	for index := range dirty {
		dirty[index] = 0xff
	}
	marshalUDPDatagram(dirty, source, target, 49152, 5353, payload)
	if !bytes.Equal(dirty, want) {
		t.Fatalf("reused UDP datagram differs:\n got %x\nwant %x", dirty, want)
	}
}

func BenchmarkUDPDatagramRoundTrip(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.241"), netip.MustParseAddr("198.51.100.241"))
	link.mu.Lock()
	link.echoUDP = true
	link.mu.Unlock()
	connection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 5353))
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	response := make([]byte, len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = connection.Read(response); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPFragmentedDatagramOutput(b *testing.B) {
	for _, test := range []struct {
		name           string
		source, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.245"), netip.MustParseAddr("198.51.100.245")},
		{"IPv6", netip.MustParseAddr("2001:db8::245"), netip.MustParseAddr("2001:db8:1::245")},
	} {
		b.Run(test.name, func(b *testing.B) {
			bits := 32
			if test.source.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.source, bits)}, MTU: 1280})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			defer stack.Close()
			connection := newUDPConn(stack, "udp", 49152, test.source.Is6(), test.source, netip.AddrPort{}, datagramSocketOptionSet{})
			payload := bytes.Repeat([]byte{0x6d}, 60*1024)
			maximum := (1280 - 20) &^ 7
			if test.source.Is6() {
				maximum = (1280 - 48) &^ 7
			}
			fragments := (udpHeaderSize + len(payload) + maximum - 1) / maximum
			drain := func() {
				for index := 0; index < fragments; index++ {
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						b.Fatal("missing UDP fragment")
					}
					stack.outbound.release(entry)
				}
			}
			if err = connection.writeDatagramForMTU(test.source, test.target, 49152, 5353, payload, ipPacketOptions{}, sourceFragmentation{allow: true}, 1280); err != nil {
				b.Fatal(err)
			}
			drain()
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err = connection.writeDatagramForMTU(test.source, test.target, 49152, 5353, payload, ipPacketOptions{}, sourceFragmentation{allow: true}, 1280); err != nil {
					b.Fatal(err)
				}
				drain()
			}
		})
	}
}

func TestUDPConcurrentReadersShareDeadline(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.242")
	remote := netip.MustParseAddrPort("198.51.100.242:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	defer connection.closeFromStack()
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const readers = 8
	start := make(chan struct{})
	results := make(chan byte, readers)
	for index := 0; index < readers; index++ {
		go func() {
			<-start
			buffer := make([]byte, 1)
			n, readErr := connection.Read(buffer)
			if readErr != nil || n != 1 {
				results <- 0xff
				return
			}
			results <- buffer[0]
		}()
	}
	close(start)
	for value := byte(0); value < readers; value++ {
		connection.enqueue([]byte{value}, remote, local, ipPacketOptions{})
	}
	seen := make(map[byte]struct{}, readers)
	for index := 0; index < readers; index++ {
		select {
		case value := <-results:
			if value == 0xff {
				t.Fatal("concurrent UDP read failed")
			}
			seen[value] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent UDP readers did not make progress")
		}
	}
	if len(seen) != readers {
		t.Fatalf("concurrent UDP reads received %d distinct datagrams", len(seen))
	}
}

func TestUDPReceiveNotificationIsLazy(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.240")
	remote := netip.MustParseAddrPort("198.51.100.240:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	defer connection.closeFromStack()
	connection.enqueue([]byte{1}, remote, local, ipPacketOptions{})
	buffer := make([]byte, 1)
	if n, readErr := connection.Read(buffer); readErr != nil || n != 1 {
		t.Fatalf("ready read = %d, %v", n, readErr)
	}
	connection.mu.Lock()
	allocated := connection.receiveNotify != nil || connection.readDeadline.state.Load() != nil || connection.errorState != nil
	connection.mu.Unlock()
	if allocated {
		t.Fatal("ready receive path allocated blocking state")
	}
	result := make(chan error, 1)
	go func() {
		_, readErr := connection.Read(buffer)
		result <- readErr
	}()
	waitFor(t, time.Second, func() bool {
		connection.mu.Lock()
		waiting := connection.receiveNotify != nil && connection.readDeadline.state.Load() != nil
		connection.mu.Unlock()
		return waiting
	})
	connection.enqueue([]byte{2}, remote, local, ipPacketOptions{})
	if readErr := <-result; readErr != nil || buffer[0] != 2 {
		t.Fatalf("blocked read = %x, %v", buffer, readErr)
	}
}

func TestUDPDialNetworkValidation(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.121")
	remote := netip.MustParseAddrPort("198.51.100.121:53")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if _, err = stack.DialUDP(context.Background(), "tcp", netip.AddrPort{}, remote); err == nil {
		t.Fatal("DialUDP with TCP network succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialUDP unknown network error = %v", err)
		}
	}
	if _, err = stack.DialUDP(context.Background(), "udp6", netip.AddrPort{}, remote); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("DialUDP family mismatch = %v, want EAFNOSUPPORT", err)
	}
}

func TestConnectedUDP(t *testing.T) {
	for _, test := range []struct {
		name         string
		client, peer netip.Addr
	}{
		{name: "IPv4", client: netip.MustParseAddr("192.0.2.1"), peer: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", client: netip.MustParseAddr("2001:db8::1"), peer: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newStackPair(t, test.client, test.peer, 1400)
			_ = newStackBridge(t, client, peer)
			receiver, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			remote := netip.AddrPortFrom(test.peer, uint16(receiver.LocalAddr().(*net.UDPAddr).Port))
			connection, err := client.DialUDP(context.Background(), "udp", netip.AddrPort{}, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if connection.LocalAddr().(*net.UDPAddr).AddrPort().Addr() != test.client || connection.RemoteAddr().(*net.UDPAddr).AddrPort() != remote {
				t.Fatalf("connected addresses = %v -> %v", connection.LocalAddr(), connection.RemoteAddr())
			}
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			payload := []byte("connected UDP")
			if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
				t.Fatalf("Write = %d, %v", n, writeErr)
			}
			buffer := make([]byte, 64)
			n, source, err := receiver.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("ReadFrom = %q, %v", buffer[:n], err)
			}
			if _, err = receiver.WriteTo([]byte("reply"), source); err != nil {
				t.Fatal(err)
			}
			n, err = connection.Read(buffer)
			if err != nil || string(buffer[:n]) != "reply" {
				t.Fatalf("Read = %q, %v", buffer[:n], err)
			}
			udpConnection := connection.(*UDPConn)
			if _, err = udpConnection.WriteTo(payload, net.UDPAddrFromAddrPort(remote)); err == nil {
				t.Fatal("WriteTo on connected UDP succeeded")
			} else {
				checkNetOpError(t, err, "write", udpConnection.net.name())
			}

			spoof, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer spoof.Close()
			clientEndpoint := connection.LocalAddr().(*net.UDPAddr).AddrPort()
			if _, err = spoof.WriteTo([]byte("spoof"), net.UDPAddrFromAddrPort(clientEndpoint)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if _, err = connection.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("spoof-filter Read error = %v", err)
			}
		})
	}
}

func TestUDPBindingAndExplicitSource(t *testing.T) {
	firstAddress := netip.MustParseAddr("192.0.2.10")
	secondAddress := netip.MustParseAddr("192.0.2.11")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(firstAddress, 32),
		netip.PrefixFrom(secondAddress, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	const sharedPort = 45000
	first, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(firstAddress, sharedPort))
	if err != nil {
		t.Fatal(err)
	}
	second, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(secondAddress, sharedPort))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(netip.IPv4Unspecified(), sharedPort)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("wildcard overlapping exact UDP bindings = %v, want EADDRINUSE", err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}

	source := netip.AddrPortFrom(secondAddress, 45001)
	remote := netip.MustParseAddrPort("198.51.100.20:53")
	connected, err := stack.DialUDP(context.Background(), "udp", source, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if got := connected.LocalAddr().(*net.UDPAddr).AddrPort(); got != source {
		t.Fatalf("DialUDP local endpoint = %v, want %v", got, source)
	}
	if _, err = stack.DialUDP(context.Background(), "udp", source, remote); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("duplicate explicit UDP source = %v, want EADDRINUSE", err)
	}
}

func TestUDPReadAfterCloseDiscardsQueuedDatagram(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.91")
	remote := netip.MustParseAddr("198.51.100.91")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50002))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50003, 50002, []byte("queued"))); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = connection.ReadFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPReceiveBufferCapacity(t *testing.T) {
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
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50002))
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := connection.(*UDPConn)
	if err = udpConnection.SetReadBuffer(2 * (udpDatagramMetadataSize + 1)); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetReadBuffer(0) = %v, want EINVAL", err)
	}
	for index := 0; index < 3; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, uint16(50003+index), 50002, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("receive-capacity drops = %d, want 1", dropped)
	}
	for index := 0; index < 2; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadBuffer(1024); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetReadBuffer after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPReceiveBufferHasNoPacketCountLimit(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.94")
	remote := netip.MustParseAddr("198.51.100.94")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50004))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	const datagrams = 300
	for index := 0; index < datagrams; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 50005, 50004, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("small-datagram drops = %d, want 0", dropped)
	}
	for index := 0; index < datagrams; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
}

func TestUDPConcurrentReaders(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.95")
	remote := netip.MustParseAddr("198.51.100.95")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50006))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const readers = 64
	results := make(chan int, readers)
	for index := 0; index < readers; index++ {
		go func() {
			buffer := make([]byte, 1)
			n, _, readErr := connection.ReadFrom(buffer)
			if readErr != nil || n != 1 {
				results <- -1
				return
			}
			results <- int(buffer[0])
		}()
	}
	for index := 0; index < readers; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 50007, 50006, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[int]bool, readers)
	for index := 0; index < readers; index++ {
		value := <-results
		if value < 0 || seen[value] {
			t.Fatalf("concurrent ReadFrom result %d = %d, already seen = %v", index, value, seen[value])
		}
		seen[value] = true
	}
}

func TestUDPReadWithBufferAddressVariants(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.97")
	remote := netip.MustParseAddrPort("198.51.100.97:5301")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	defer connection.closeFromStack()

	first := []byte("first datagram")
	connection.enqueue(first, remote, local, ipPacketOptions{})
	var firstBuffer []byte
	firstHint := 0
	n, readErr := connection.ReadWithBuffer(func(sizeHint int) []byte {
		firstHint = sizeHint
		firstBuffer = make([]byte, 3)
		return firstBuffer
	})
	if readErr != nil || n != len(firstBuffer) || firstHint != len(first) || string(firstBuffer) != "fir" {
		t.Fatalf("ReadWithBuffer = %d, %v, hint %d, payload %q; want 3, nil, %d, fir", n, readErr, firstHint, firstBuffer, len(first))
	}

	second := []byte("second")
	connection.enqueue(second, remote, local, ipPacketOptions{})
	var secondBuffer []byte
	n, address, readErr := connection.ReadFromWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(second) {
			t.Fatalf("ReadFromWithBuffer size hint = %d; want %d", sizeHint, len(second))
		}
		secondBuffer = make([]byte, sizeHint)
		return secondBuffer
	})
	if readErr != nil || n != len(second) || string(secondBuffer) != string(second) {
		t.Fatalf("ReadFromWithBuffer = %d, %v, payload %q; want %d, nil, %q", n, readErr, secondBuffer, len(second), second)
	}
	if got, ok := address.(*net.UDPAddr); !ok || got.AddrPort() != remote {
		t.Fatalf("ReadFromWithBuffer address = %#v; want %v", address, remote)
	}

	third := []byte("third")
	connection.enqueue(third, remote, local, ipPacketOptions{})
	var thirdBuffer []byte
	n, addressUDP, readErr := connection.ReadFromUDPWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(third) {
			t.Fatalf("ReadFromUDPWithBuffer size hint = %d; want %d", sizeHint, len(third))
		}
		thirdBuffer = make([]byte, sizeHint)
		return thirdBuffer
	})
	if readErr != nil || n != len(third) || string(thirdBuffer) != string(third) || addressUDP == nil || addressUDP.AddrPort() != remote {
		t.Fatalf("ReadFromUDPWithBuffer = %d, %v, address %v, payload %q; want %d, nil, %v, %q", n, readErr, addressUDP, thirdBuffer, len(third), remote, third)
	}

	fourth := []byte("fourth")
	connection.enqueue(fourth, remote, local, ipPacketOptions{})
	var fourthBuffer []byte
	n, addressPort, readErr := connection.ReadFromUDPAddrPortWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(fourth) {
			t.Fatalf("ReadFromUDPAddrPortWithBuffer size hint = %d; want %d", sizeHint, len(fourth))
		}
		fourthBuffer = make([]byte, sizeHint)
		return fourthBuffer
	})
	if readErr != nil || n != len(fourth) || string(fourthBuffer) != string(fourth) || addressPort != remote {
		t.Fatalf("ReadFromUDPAddrPortWithBuffer = %d, %v, address %v, payload %q; want %d, nil, %v, %q", n, readErr, addressPort, fourthBuffer, len(fourth), remote, fourth)
	}

	connection.enqueue(nil, remote, local, ipPacketOptions{})
	emptyHint := -1
	n, addressPort, readErr = connection.ReadFromUDPAddrPortWithBuffer(func(sizeHint int) []byte {
		emptyHint = sizeHint
		return nil
	})
	if readErr != nil || n != 0 || emptyHint != 0 || addressPort != remote {
		t.Fatalf("zero-length ReadWithBuffer = %d, %v, hint %d, address %v; want 0, nil, 0, %v", n, readErr, emptyHint, addressPort, remote)
	}

	if _, _, readErr = connection.ReadFromWithBuffer(nil); !errors.Is(readErr, syscall.EINVAL) {
		t.Fatalf("nil UDP buffer callback error = %v; want EINVAL", readErr)
	}
}

func TestUDPReadWithBufferWaitsOutsideConnectionLock(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.98")
	remote := netip.MustParseAddrPort("198.51.100.98:5301")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	defer connection.closeFromStack()
	callbackCalled := make(chan int, 1)
	result := make(chan struct {
		n           int
		err         error
		hint        int
		payload     []byte
		deadlineErr error
	}, 1)
	go func() {
		var payload []byte
		deadlineErr := error(nil)
		n, readErr := connection.ReadWithBuffer(func(sizeHint int) []byte {
			callbackCalled <- sizeHint
			deadlineErr = connection.SetReadDeadline(time.Time{})
			payload = make([]byte, sizeHint)
			return payload
		})
		result <- struct {
			n           int
			err         error
			hint        int
			payload     []byte
			deadlineErr error
		}{n: n, err: readErr, hint: len(payload), payload: payload, deadlineErr: deadlineErr}
	}()
	select {
	case hint := <-callbackCalled:
		t.Fatalf("UDP buffer callback ran before a datagram was queued with hint %d", hint)
	case <-time.After(20 * time.Millisecond):
	}
	payload := []byte("outside lock")
	connection.enqueue(payload, remote, local, ipPacketOptions{})
	var readResult struct {
		n           int
		err         error
		hint        int
		payload     []byte
		deadlineErr error
	}
	select {
	case hint := <-callbackCalled:
		if hint != len(payload) {
			t.Fatalf("UDP ReadWithBuffer size hint = %d; want %d", hint, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("UDP ReadWithBuffer callback did not run")
	}
	select {
	case readResult = <-result:
	case <-time.After(time.Second):
		t.Fatal("UDP ReadWithBuffer did not return")
	}
	if readResult.n != len(payload) || readResult.err != nil || readResult.hint != len(payload) || string(readResult.payload) != string(payload) || readResult.deadlineErr != nil {
		t.Fatalf("UDP ReadWithBuffer = %d, %v, hint %d, payload %q, deadline error %v; want %d, nil, %d, %q, nil", readResult.n, readResult.err, readResult.hint, readResult.payload, readResult.deadlineErr, len(payload), len(payload), payload)
	}
}

func TestUDPReadWithBufferDeadlineDoesNotCallCallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.99")
	remote := netip.MustParseAddrPort("198.51.100.99:5301")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	defer connection.closeFromStack()
	payload := []byte("deadline")
	connection.enqueue(payload, remote, local, ipPacketOptions{})
	if err := connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	if n, readErr := connection.ReadWithBuffer(func(int) []byte {
		callbackCalls++
		return make([]byte, len(payload))
	}); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) || callbackCalls != 0 {
		t.Fatalf("expired UDP ReadWithBuffer = %d, %v, callback calls %d; want 0, deadline, 0", n, readErr, callbackCalls)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if n, readErr := connection.Read(buffer); n != len(payload) || readErr != nil || string(buffer) != string(payload) {
		t.Fatalf("UDP data after expired ReadWithBuffer = %d, %v, %q; want %d, nil, %q", n, readErr, buffer, len(payload), payload)
	}
}

func TestUDPTypedMethods(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.96")
	remote := netip.MustParseAddr("198.51.100.96")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50008))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()

	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50009, 50008, []byte("udpaddr"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := connection.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != "udpaddr" || source.AddrPort() != netip.AddrPortFrom(remote, 50009) {
		t.Fatalf("ReadFromUDP = %q from %v, %v", buffer[:n], source, err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50010, 50008, []byte("addrport"))); err != nil {
		t.Fatal(err)
	}
	n, sourcePort, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "addrport" || sourcePort != netip.AddrPortFrom(remote, 50010) {
		t.Fatalf("ReadFromUDPAddrPort = %q from %v, %v", buffer[:n], sourcePort, err)
	}
	if _, err = connection.WriteToUDP([]byte("typed"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50011))); err != nil {
		t.Fatal(err)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack), false); !ok || packet.source != local || string(packet.payload[udpHeaderSize:]) != "typed" {
		t.Fatalf("WriteToUDP packet = source %v payload %q, parsed = %v", packet.source, packet.payload, ok)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("typed-port"), netip.AddrPortFrom(remote, 50012)); err != nil {
		t.Fatal(err)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack), false); !ok || packet.source != local || string(packet.payload[udpHeaderSize:]) != "typed-port" {
		t.Fatalf("WriteToUDPAddrPort packet = source %v payload %q, parsed = %v", packet.source, packet.payload, ok)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("invalid"), netip.AddrPort{}); err == nil {
		t.Fatal("WriteToUDPAddrPort accepted an invalid address")
	} else if operationError := checkNetOpError(t, err, "write", "udp"); operationError.Addr == nil || operationError.Addr.Network() != "udp" {
		t.Fatalf("WriteToUDPAddrPort error address = %#v", operationError.Addr)
	}
}

func TestUDPMessagePacketInfoRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name          string
		first, second netip.Addr
		remote        netip.Addr
		controlSize   int
	}{
		{name: "IPv4", first: netip.MustParseAddr("192.0.2.97"), second: netip.MustParseAddr("192.0.2.98"), remote: netip.MustParseAddr("198.51.100.97"), controlSize: 80},
		{name: "IPv6", first: netip.MustParseAddr("2001:db8::97"), second: netip.MustParseAddr("2001:db8::98"), remote: netip.MustParseAddr("2001:db8:1::97"), controlSize: 88},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := test.first.BitLen()
			stack, err := New(Config{LocalAddresses: []netip.Prefix{
				netip.PrefixFrom(test.first, bits), netip.PrefixFrom(test.second, bits),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(wildcardUDP(test.first).Addr(), 50013))
			if err != nil {
				t.Fatal(err)
			}
			connection := packetConnection.(*UDPConn)
			defer connection.Close()
			if err = writeTestPacket(stack, buildTestUDP(test.remote, test.second, 50014, 50013, []byte("request"))); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 3)
			oob := make([]byte, 128)
			n, oobn, flags, source, err := connection.ReadMsgUDPAddrPort(buffer, oob)
			if err != nil || n != 3 || string(buffer) != "req" || source != netip.AddrPortFrom(test.remote, 50014) {
				t.Fatalf("ReadMsgUDPAddrPort = %q, %d oob, flags %#x, source %v, %v", buffer[:n], oobn, flags, source, err)
			}
			if oobn != test.controlSize || flags != MessageFlagTruncated {
				t.Fatalf("packet info size/flags = %d/%#x, want %d/%#x", oobn, flags, test.controlSize, MessageFlagTruncated)
			}
			if test.first.Is4() {
				var message IPv4ControlMessage
				if parseErr := message.Parse(oob[:oobn]); parseErr != nil || message.Dst != test.second {
					t.Fatalf("IPv4 packet info = %+v, %v, want destination %v", message, parseErr, test.second)
				}
			} else {
				var message IPv6ControlMessage
				if parseErr := message.Parse(oob[:oobn]); parseErr != nil || message.Dst != test.second {
					t.Fatalf("IPv6 packet info = %+v, %v, want destination %v", message, parseErr, test.second)
				}
			}
			n, oobWritten, err := connection.WriteMsgUDPAddrPort([]byte("reply"), oob[:oobn], netip.AddrPortFrom(test.remote, 50014))
			if err != nil || n != 5 || oobWritten != oobn {
				t.Fatalf("WriteMsgUDPAddrPort = %d/%d, %v", n, oobWritten, err)
			}
			packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
			if !ok || packet.source != test.second || packet.target != test.remote || string(packet.payload[udpHeaderSize:]) != "reply" {
				t.Fatalf("message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
			}
		})
	}
}

func TestUDPMessageControlValidationAndWriteBuffer(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.99")
	remote := netip.MustParseAddr("198.51.100.99")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50015))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	if err = connection.SetWriteBuffer(64 * 1024); err != nil {
		t.Fatalf("SetWriteBuffer no-op = %v", err)
	}
	if err = connection.SetWriteBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetWriteBuffer(0) = %v, want EINVAL", err)
	}
	control, err := (&IPv4ControlMessage{Src: local}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(control[16:20], 1)
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), control, netip.AddrPortFrom(remote, 50016)); err == nil {
		t.Fatal("WriteMsgUDPAddrPort accepted a nonzero interface index")
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), control[:10], netip.AddrPortFrom(remote, 50016)); err == nil {
		t.Fatal("WriteMsgUDPAddrPort accepted a truncated control message")
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50016, 50015, []byte("control"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	oob := make([]byte, 8)
	_, oobn, flags, _, err := connection.ReadMsgUDPAddrPort(buffer, oob)
	if err != nil || oobn != len(oob) || flags != MessageFlagControlTruncated {
		t.Fatalf("control truncation = oob %d flags %#x, %v", oobn, flags, err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetWriteBuffer(1024); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetWriteBuffer after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::190")
	remote := netip.MustParseAddr("2001:db8::191")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	target := netip.AddrPortFrom(remote, 5353)
	writeAndLabel := func(oob []byte) uint32 {
		t.Helper()
		if oob == nil {
			_, err = connection.WriteToUDPAddrPort([]byte("flow"), target)
		} else {
			_, _, err = connection.WriteMsgUDPAddrPort([]byte("flow"), oob, target)
		}
		if err != nil {
			t.Fatal(err)
		}
		packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
		if !ok {
			t.Fatal("failed to parse IPv6 UDP output")
		}
		return packet.flowLabel
	}
	automatic := writeAndLabel(nil)
	second := writeAndLabel(nil)
	if automatic == 0 || second != automatic {
		t.Fatalf("automatic UDP flow labels = %#x then %#x", automatic, second)
	}
	if err = connection.SetFlowLabel(0x12345); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(nil); label != 0x12345 {
		t.Fatalf("socket UDP flow label = %#x, want 0x12345", label)
	}
	oob, err := (&IPv6ControlMessage{FlowLabel: 0x54321}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(oob); label != 0x54321 {
		t.Fatalf("per-packet UDP flow label = %#x, want 0x54321", label)
	}
	if err = connection.SetFlowLabel(0); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(nil); label != 0 {
		t.Fatalf("explicit zero UDP flow label = %#x", label)
	}
	if info := connection.Info(); info.FlowLabel != 0 {
		t.Fatalf("UDP flow-label diagnostics = %+v", info)
	}
}

func TestUDPMessageIPv6ZeroHopLimit(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::99")
	remote := netip.MustParseAddr("2001:db8:1::99")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(local, 50017))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	if err = connection.SetHopLimit(0); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("default-zero"), netip.AddrPortFrom(remote, 50018)); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 0 || packet.target != remote {
		t.Fatalf("IPv6 default zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
	control := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 0)
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("zero"), control, netip.AddrPortFrom(remote, 50018)); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 0 || packet.target != remote {
		t.Fatalf("IPv6 zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
}

func TestUDPZeroHopLimitFamilyValidation(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.99/32"), netip.MustParsePrefix("2001:db8::99/128"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	for _, test := range []struct {
		name, network string
		local         netip.AddrPort
	}{
		{name: "IPv4", network: "udp4", local: netip.MustParseAddrPort("192.0.2.99:50019")},
		{name: "dual stack", network: "udp", local: netip.AddrPort{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packetConnection, listenErr := stack.ListenUDP(context.Background(), test.network, test.local)
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			defer packetConnection.Close()
			if setErr := packetConnection.(*UDPConn).SetHopLimit(0); setErr == nil {
				t.Fatal("SetHopLimit(0) succeeded")
			}
		})
	}
}

func TestUDPConnectedMessageMethods(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.100")
	remote := netip.MustParseAddr("198.51.100.100")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(remote, 50017))
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*UDPConn)
	defer connection.Close()
	n, oobn, err := connection.WriteMsgUDP([]byte("connected"), nil, nil)
	if err != nil || n != 9 || oobn != 0 {
		t.Fatalf("connected WriteMsgUDP = %d/%d, %v", n, oobn, err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "connected" {
		t.Fatalf("connected message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = connection.WriteMsgUDP([]byte("bad"), nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50017))); err == nil {
		t.Fatal("connected WriteMsgUDP accepted an explicit destination")
	}
	var nilUDP *net.UDPAddr
	if _, err = connection.WriteToUDP([]byte("bad"), nilUDP); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected WriteToUDP(nil) = %v, want net.ErrWriteToConnected", err)
	} else if operationError := checkNetOpError(t, err, "write", "udp"); operationError.Addr != nil {
		t.Fatalf("connected WriteToUDP(nil) error address = %#v, want nil", operationError.Addr)
	}
	if _, err = connection.WriteTo([]byte("bad"), nilUDP); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected WriteTo(nil *net.UDPAddr) = %v, want net.ErrWriteToConnected", err)
	}
	if n, oobn, writeErr := connection.WriteMsgUDPAddrPort([]byte("netip"), nil, netip.AddrPort{}); writeErr != nil || n != 5 || oobn != 0 {
		t.Fatalf("connected WriteMsgUDPAddrPort = %d/%d, %v", n, oobn, writeErr)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "netip" {
		t.Fatalf("connected netip message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), nil, netip.AddrPortFrom(remote, 50017)); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected WriteMsgUDPAddrPort with destination = %v, want net.ErrWriteToConnected", err)
	}
	if err = connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = connection.WriteMsgUDP([]byte("late"), nil, nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected WriteMsgUDP deadline = %v, want deadline", err)
	} else if operationError := checkNetOpError(t, err, "write", "udp"); operationError.Addr != nil {
		t.Fatalf("connected WriteMsgUDP error address = %v, want nil", operationError.Addr)
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("late"), nil, netip.AddrPort{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected WriteMsgUDPAddrPort deadline = %v, want deadline", err)
	} else if operationError := checkNetOpError(t, err, "write", "udp"); operationError.Addr == nil || operationError.Addr.String() != "invalid AddrPort" {
		t.Fatalf("connected WriteMsgUDPAddrPort error address = %#v, want invalid AddrPort", operationError.Addr)
	}
	if _, _, err = connection.WriteMsgUDP([]byte("late"), []byte{1}, nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected WriteMsgUDP invalid control deadline = %v, want deadline", err)
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("late"), []byte{1}, netip.AddrPort{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected WriteMsgUDPAddrPort invalid control deadline = %v, want deadline", err)
	}
	if err = connection.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	localPort := connection.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50017, localPort, []byte("reply"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	oob := make([]byte, 96)
	n, oobn, flags, source, err := connection.ReadMsgUDP(buffer, oob)
	if err != nil || n != 5 || string(buffer[:n]) != "reply" || oobn != 80 || flags != 0 || source.AddrPort() != netip.AddrPortFrom(remote, 50017) {
		t.Fatalf("connected ReadMsgUDP = %q/%d flags %#x from %v, %v", buffer[:n], oobn, flags, source, err)
	}
}

func TestUDPUnconnectedMessageRequiresDestination(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.101")
	remote := netip.MustParseAddr("198.51.100.101")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, _, err = connection.(*UDPConn).WriteMsgUDPAddrPort([]byte("missing"), nil, netip.AddrPort{}); err == nil {
		t.Fatal("unconnected WriteMsgUDPAddrPort accepted an invalid destination")
	} else {
		operationError := checkNetOpError(t, err, "write", "udp4")
		if operationError.Addr == nil || operationError.Addr.String() != "invalid AddrPort" {
			t.Fatalf("unconnected WriteMsgUDPAddrPort error address = %#v, want invalid AddrPort", operationError.Addr)
		}
	}
	var nilUDP *net.UDPAddr
	if _, err = connection.WriteTo([]byte("missing"), nilUDP); err == nil {
		t.Fatal("unconnected WriteTo accepted a nil *net.UDPAddr")
	} else if operationError := checkNetOpError(t, err, "write", "udp4"); operationError.Addr != nil {
		t.Fatalf("nil *net.UDPAddr error address = %#v, want nil", operationError.Addr)
	}
	if _, err = connection.WriteTo([]byte("invalid"), testUDPStringAddress("not-an-address")); err == nil {
		t.Fatal("unconnected WriteTo accepted an invalid generic destination")
	} else {
		checkNetOpError(t, err, "write", "udp4")
	}
	address := testUDPStringAddress(netip.AddrPortFrom(remote, 50018).String())
	if n, writeErr := connection.WriteTo([]byte("generic"), address); writeErr != nil || n != 7 {
		t.Fatalf("WriteTo generic UDP address = %d, %v", n, writeErr)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "generic" {
		t.Fatalf("generic UDP packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	udpConnection := connection.(*UDPConn)
	if err = udpConnection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50018))
	if _, _, err = udpConnection.WriteMsgUDP([]byte("late"), []byte{1}, target); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unconnected WriteMsgUDP invalid control deadline = %v, want deadline", err)
	}
	wrongFamily := &net.UDPAddr{IP: net.ParseIP("2001:db8::101"), Port: 50018}
	if _, _, err = udpConnection.WriteMsgUDP([]byte("wrong-family"), []byte{1}, wrongFamily); err == nil {
		t.Fatal("WriteMsgUDP accepted an IPv6 destination on an IPv4 socket")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("WriteMsgUDP family/control precedence = %T %v, want net.AddrError", err, err)
		}
	}
}

func TestUDPOversizedWriteReturnsMessageTooLong(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.93")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.MustParseAddrPort("198.51.100.93:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if n, writeErr := connection.Write(make([]byte, 65535-20-udpHeaderSize)); writeErr != nil || n != 65535-20-udpHeaderSize {
		t.Fatalf("maximum IPv4 UDP Write = %d, %v", n, writeErr)
	}
	if _, err = connection.Write(make([]byte, 65536-20-udpHeaderSize)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("IPv4 UDP Write above 65507 bytes = %v, want EMSGSIZE", err)
	}
	if _, err = connection.Write(make([]byte, 65536-udpHeaderSize)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized UDP Write = %v, want EMSGSIZE", err)
	}
}

func TestUnconnectedUDPReadAndConnectedWriteToError(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.94")
	remote := netip.MustParseAddr("198.51.100.94")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 54000))
	if err != nil {
		t.Fatal(err)
	}
	listener := packetConnection.(*UDPConn)
	defer listener.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 54001, 54000, []byte("read"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if n, readErr := listener.Read(buffer); readErr != nil || n != 4 || string(buffer) != "read" {
		t.Fatalf("unconnected UDP Read = %q, %v", buffer[:n], readErr)
	}
	connected, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 54002))
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if _, err = connected.(*UDPConn).WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(remote, 54003)); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected UDP WriteTo = %v, want net.ErrWriteToConnected", err)
	}
}

func TestUDPIPv4MappedNetAddrWrites(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.96")
	remote := netip.MustParseAddr("198.51.100.96")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	target := &net.UDPAddr{IP: net.ParseIP(remote.String()), Port: 56000}
	if _, err = packetConnection.WriteTo([]byte("packet"), target); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "packet" {
		t.Fatalf("mapped PacketConn write = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = packetConnection.(*UDPConn).WriteMsgUDP([]byte("message"), nil, target); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "message" {
		t.Fatalf("mapped WriteMsgUDP = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
}

func TestUDPDefaultsAndDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.134")
	remote := netip.MustParseAddr("192.0.2.135")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		UDP: UDPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{ReceiveBuffer: 2048, HopLimit: 31, TrafficClass: 0xb8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5353))
	if err != nil {
		t.Fatal(err)
	}
	udp := connection.(*UDPConn)
	if err = udp.SetPathMTUDiscovery(PathMTUDiscovery(99)); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("invalid UDP PMTU mode = %v", err)
	}
	if err = udp.SetPathMTUDiscovery(PathMTUDiscoveryProbe); err != nil {
		t.Fatal(err)
	}
	if mode, modeErr := udp.PathMTUDiscovery(); modeErr != nil || mode != PathMTUDiscoveryProbe {
		t.Fatalf("UDP PMTU mode = %v, %v", mode, modeErr)
	}
	if err = udp.SetHopLimit(37); err != nil {
		t.Fatal(err)
	}
	if err = udp.SetTrafficClass(0x2e); err != nil {
		t.Fatal(err)
	}
	if _, err = udp.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 37 || packet.trafficClass != 0x2e {
		t.Fatalf("UDP output options = hop %d class %#x", packet.hopLimit, packet.trafficClass)
	}
	zeroClass := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTypeOfService, 0)
	if _, _, err = udp.WriteMsgUDP([]byte("zero"), zeroClass, nil); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 37 || packet.trafficClass != 0 {
		t.Fatalf("UDP explicit zero traffic class = hop %d class %#x", packet.hopLimit, packet.trafficClass)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 5353, udp.port, []byte("answer"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := udp.Read(buffer); readErr != nil || string(buffer[:n]) != "answer" {
		t.Fatalf("UDP Read = %q, %v", buffer[:n], readErr)
	}
	if err = udp.SetReadBuffer(udpDatagramMetadataSize); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 5353, udp.port, nil)); err != nil {
			t.Fatal(err)
		}
	}
	info := udp.Info()
	if info.PacketsSent != 2 || info.BytesSent != 9 || info.PacketsReceived != 2 || info.BytesReceived != 6 ||
		info.PacketsDropped != 1 || info.ReceiveQueuePackets != 1 || info.ReceiveQueueBytes != udpDatagramMetadataSize ||
		info.ReceiveQueueCapacity != udpDatagramMetadataSize || info.PathMTU != 1400 || info.PathMTUDiscovery != PathMTUDiscoveryProbe ||
		info.HopLimit != 37 || info.TrafficClass != 0x2e {
		t.Fatalf("UDP Info = %+v", info)
	}
}

func BenchmarkUDPReceiveQueue(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.243")
	remote := netip.MustParseAddrPort("198.51.100.243:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	b.Cleanup(connection.closeFromStack)
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		if n, _, _, _, _, readErr := connection.readDatagram(buffer, nil); readErr != nil || n != len(payload) {
			b.Fatalf("readDatagram = %d, %v", n, readErr)
		}
	}
}

func BenchmarkUDPReadBufferAPI(b *testing.B) {
	for _, payloadSize := range []int{64, 512, 1200, 4096, 65507} {
		payloadSize := payloadSize
		for _, mode := range []string{
			"Read", "ReadWithBuffer",
			"ReadFrom", "ReadFromWithBuffer",
			"ReadFromUDP", "ReadFromUDPWithBuffer",
			"ReadFromUDPAddrPort", "ReadFromUDPAddrPortWithBuffer",
		} {
			mode := mode
			b.Run(fmt.Sprintf("%s/%d", mode, payloadSize), func(b *testing.B) {
				local := netip.MustParseAddr("192.0.2.245")
				remote := netip.MustParseAddrPort("198.51.100.245:5353")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
				if err != nil {
					b.Fatal(err)
				}
				connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
				b.Cleanup(connection.closeFromStack)
				payload := bytes.Repeat([]byte{0x5a}, payloadSize)
				buffer := make([]byte, payloadSize)
				getBuffer := func(int) []byte { return buffer }
				b.SetBytes(int64(payloadSize))
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					connection.enqueue(payload, remote, local, ipPacketOptions{})
					var n int
					switch mode {
					case "Read":
						n, err = connection.Read(buffer)
					case "ReadWithBuffer":
						n, err = connection.ReadWithBuffer(getBuffer)
					case "ReadFrom":
						n, _, err = connection.ReadFrom(buffer)
					case "ReadFromWithBuffer":
						n, _, err = connection.ReadFromWithBuffer(getBuffer)
					case "ReadFromUDP":
						n, _, err = connection.ReadFromUDP(buffer)
					case "ReadFromUDPWithBuffer":
						n, _, err = connection.ReadFromUDPWithBuffer(getBuffer)
					case "ReadFromUDPAddrPort":
						n, _, err = connection.ReadFromUDPAddrPort(buffer)
					case "ReadFromUDPAddrPortWithBuffer":
						n, _, err = connection.ReadFromUDPAddrPortWithBuffer(getBuffer)
					}
					if err != nil || n != payloadSize {
						b.Fatalf("%s = %d, %v", mode, n, err)
					}
				}
			})
		}
	}
}

func BenchmarkUDPReadMessageAPI(b *testing.B) {
	for _, mode := range []string{"ReadMsg", "ReadBatch"} {
		b.Run(mode, func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.248")
			remote := netip.MustParseAddrPort("198.51.100.248:5353")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				b.Fatal(err)
			}
			connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
			b.Cleanup(connection.closeFromStack)
			payload := bytes.Repeat([]byte{0x5a}, 1200)
			buffer := make([]byte, len(payload))
			control := make([]byte, 128)
			messages := []SocketMessage{{Buffers: [][]byte{buffer}, OOB: control}}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				connection.enqueue(payload, remote, local, ipPacketOptions{})
				if mode == "ReadMsg" {
					n, _, _, _, readErr := connection.ReadMsgUDPAddrPort(buffer, control)
					if readErr != nil || n != len(payload) {
						b.Fatalf("ReadMsgUDPAddrPort = %d, %v", n, readErr)
					}
				} else {
					messages[0].N, messages[0].NN, messages[0].Flags = 0, 0, 0
					count, readErr := connection.ReadBatch(messages, 0)
					if readErr != nil || count != 1 || messages[0].N != len(payload) {
						b.Fatalf("ReadBatch = %d/%d, %v", count, messages[0].N, readErr)
					}
				}
			}
		})
	}
}

func BenchmarkUDPBatchWrite(b *testing.B) {
	const batchSize = 16
	const payloadSize = 1200
	for _, buffersPerMessage := range []int{1, 2} {
		b.Run(fmt.Sprintf("buffers-%d", buffersPerMessage), func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.242")
			remote := netip.MustParseAddrPort("198.51.100.242:5353")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			netConnection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
			if err != nil {
				b.Fatal(err)
			}
			connection := netConnection.(*UDPConn)
			b.Cleanup(func() {
				_ = connection.Close()
				_ = stack.Close()
			})
			payload := make([]byte, payloadSize)
			messages := make([]SocketMessage, batchSize)
			for index := range messages {
				messages[index].Buffers = [][]byte{payload}
				if buffersPerMessage == 2 {
					messages[index].Buffers = [][]byte{payload[:400], payload[400:]}
				}
			}
			packets := make([][]byte, batchSize)
			for index := range packets {
				packets[index] = make([]byte, 1500)
			}
			sizes := make([]int, batchSize)
			b.SetBytes(batchSize * payloadSize)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if count, writeErr := connection.WriteBatch(messages, 0); writeErr != nil || count != batchSize {
					b.Fatalf("WriteBatch = %d, %v", count, writeErr)
				}
				if count, readErr := stack.Read(packets, sizes, 0); readErr != nil || count != batchSize {
					b.Fatalf("Stack.Read = %d, %v", count, readErr)
				}
			}
		})
	}
}

func TestUDPReceivePayloadSpareIsBoundedAndReleased(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.247")
	remote := netip.MustParseAddrPort("198.51.100.247:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote, datagramSocketOptionSet{})
	read := func(payload []byte) {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		buffer := make([]byte, len(payload))
		if n, _, _, _, _, readErr := connection.readDatagram(buffer, nil); readErr != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
			t.Fatalf("readDatagram = %d bytes, %v", n, readErr)
		}
	}
	read(make([]byte, 1200))
	connection.mu.Lock()
	spareCapacity := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if spareCapacity < 1200 || spareCapacity > datagramReusablePayloadLimit {
		t.Fatalf("receive spare capacity = %d", spareCapacity)
	}
	read(make([]byte, datagramReusablePayloadLimit+1))
	connection.mu.Lock()
	retainedAfterJumbo := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterJumbo != spareCapacity {
		t.Fatalf("jumbo read changed receive spare capacity from %d to %d", spareCapacity, retainedAfterJumbo)
	}
	connection.closeFromStack()
	connection.mu.Lock()
	retainedAfterClose := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterClose != 0 {
		t.Fatalf("closed socket retained receive spare capacity %d", retainedAfterClose)
	}
}

func TestUDPConnCloseReleasesRetainedState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.253")
	remote := netip.MustParseAddrPort("198.51.100.253:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newUDPConn(stack, "udp4", 5300, false, local, netip.AddrPort{}, datagramSocketOptionSet{})
	if err = connection.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	connection.enqueue(make([]byte, 1200), remote, local, ipPacketOptions{})
	connection.rememberTarget(remote)
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(remote, ICMPError{Reporter: remote.Addr(), Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort, QuotedPayload: make([]byte, 1200)})
	connection.mu.Lock()
	if connection.errorState == nil || connection.errorState.pending == nil || connection.errorState.queue.len() == 0 {
		connection.mu.Unlock()
		t.Fatal("UDP socket did not retain an error before close")
	}
	connection.receiveSpare = make([]byte, 0, 1200)
	connection.mu.Unlock()
	connection.closeFromStack()
	connection.rememberTarget(remote)
	connection.deliverError(remote, ICMPError{Reporter: remote.Addr(), Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort, QuotedPayload: make([]byte, 1200)})
	connection.enqueue(make([]byte, 1200), remote, local, ipPacketOptions{})
	connection.mu.Lock()
	released := connection.receive.values == nil && connection.receiveSpare == nil && connection.queuedBytes == 0 &&
		connection.errorState != nil && connection.errorState.queue.values == nil && connection.errorState.queuedBytes == 0 &&
		connection.recentTargets.state == nil && connection.errorState.lastError == nil && connection.errorState.pending == nil &&
		connection.readDeadline.state.Load() == stoppedDatagramSocketDeadline && connection.writeDeadline.state.Load() == stoppedDatagramSocketDeadline
	connection.mu.Unlock()
	if !released || connection.errorState.icmpErrors != 1 {
		t.Fatal("closed UDP socket retained or recreated payload-bearing state")
	}
}

func TestUDPImpairedLinkLatencyAndLoss(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	link := newTestImpairedLink(t, client, server, testLinkConditions{
		Seed:         7123,
		ClientToPeer: testLinkCondition{Latency: 30 * time.Millisecond, Jitter: 5 * time.Millisecond, LossRate: 0.2},
	})
	serverSocket, err := server.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(serverAddress, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()
	clientSocket, err := client.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	started := time.Now()
	for sequence := uint32(0); sequence < 64; sequence++ {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, sequence)
		if _, err = clientSocket.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, time.Second, func() bool { return link.Stats(0).Packets == 64 })
	scheduled := link.Stats(0)
	wantReceived := int(scheduled.Packets - scheduled.RandomDrops - scheduled.QueueDrops)
	_ = serverSocket.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4)
	received := 0
	firstDelivery := time.Duration(0)
	lastSequence := uint32(0)
	reordered := false
	for received < wantReceived {
		_, _, err = serverSocket.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if received == 0 {
			firstDelivery = time.Since(started)
		}
		sequence := binary.BigEndian.Uint32(buffer)
		if received != 0 && sequence < lastSequence {
			reordered = true
		}
		lastSequence = sequence
		received++
	}
	stats := link.Stats(0)
	if stats.RandomDrops == 0 || received == 0 || received >= 64 || stats.Delivered != uint64(received) {
		t.Fatalf("UDP impairment = received %d, stats %+v", received, stats)
	}
	if firstDelivery < 20*time.Millisecond {
		t.Fatalf("first UDP delivery after %v, want propagation delay", firstDelivery)
	}
	if !reordered {
		t.Fatal("UDP jitter did not exercise packet reordering")
	}
}

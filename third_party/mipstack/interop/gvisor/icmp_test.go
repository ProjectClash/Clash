package gvisorinterop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

func TestICMPEchoInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu)+"/mipstack-sends", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testMipstackICMPEcho(t, network, family, mtu)
			})
			t.Run(family.name+"/"+interopMTUName(mtu)+"/gvisor-sends", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testGVisorICMPEcho(t, network, family, mtu)
			})
		}
	}
}

func TestPublicICMPMessageCodecInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			captured := make(chan []byte, 4)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					select {
					case captured <- append([]byte(nil), packet...):
					default:
					}
					return false
				},
			})
			protocol := mipstack.ProtocolICMPv4
			if family.mipstackAddress.Is6() {
				protocol = mipstack.ProtocolICMPv6
			}
			message := mipstack.ICMPMessage{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
			}
			if err := message.SetEchoRequest(0x1234, 7, []byte("public-icmp-codec")); err != nil {
				t.Fatalf("construct public ICMP echo request: %v", err)
			}
			body := append([]byte(nil), message.Body...)
			expectedReply, err := message.EchoReply(family.gvisorAddress)
			if err != nil {
				t.Fatalf("construct public ICMP echo reply: %v", err)
			}
			expectedReplyWire, err := expectedReply.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP echo reply: %v", err)
			}
			icmpWire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP message: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: protocol, HopLimit: 64, Payload: icmpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public ICMP packet: %v", err)
			}
			select {
			case responseWire := <-captured:
				parsedPacket, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor ICMP packet: %v", parseErr)
				}
				actualProtocol, actualReplyWire, upperErr := parsedPacket.UpperLayer()
				if upperErr != nil {
					t.Fatalf("locate gVisor ICMP reply: %v", upperErr)
				}
				if actualProtocol != protocol {
					t.Fatalf("gVisor ICMP reply protocol = %d, want %d", actualProtocol, protocol)
				}
				if !bytes.Equal(actualReplyWire, expectedReplyWire) {
					t.Fatalf("public ICMP echo reply = %x, gVisor reply = %x", expectedReplyWire, actualReplyWire)
				}
				parsed, parseErr := parsedPacket.ICMPMessage()
				identifier, sequence, payload, echo := parsed.Echo()
				if parseErr != nil || parsed.Source != family.gvisorAddress || parsed.Destination != family.mipstackAddress ||
					!parsed.IsEchoReply() || identifier != 0x1234 || sequence != 7 || !bytes.Equal(payload, []byte("public-icmp-codec")) ||
					!echo || !bytes.Equal(parsed.Body, body) {
					t.Fatalf("parsed gVisor ICMP = %+v, %v", parsed, parseErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor ICMP reply")
			}
		})
	}
}

func TestPublicICMPErrorInterop(t *testing.T) {
	const (
		mipstackPort = 44021
		gvisorPort   = 44022
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			captured := make(chan []byte, 4)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					select {
					case captured <- append([]byte(nil), packet...):
					default:
					}
					return false
				},
			})
			datagram := mipstack.UDPDatagram{
				Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination: netipAddrPort(family.gvisorAddress, gvisorPort),
				Payload:     []byte("unbound-public-udp"),
			}
			udpWire, err := datagram.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode UDP probe: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 64, Payload: udpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode UDP probe packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver UDP probe: %v", err)
			}
			select {
			case responseWire := <-captured:
				response, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor ICMP error packet: %v", parseErr)
				}
				message, parseErr := response.ICMPMessage()
				if parseErr != nil {
					t.Fatalf("parse gVisor ICMP error message: %v", parseErr)
				}
				networkError, parseErr := message.ICMPError()
				if parseErr != nil {
					t.Fatalf("parse gVisor quoted packet: %v", parseErr)
				}
				wantType, wantCode := uint8(header.ICMPv4DstUnreachable), uint8(header.ICMPv4PortUnreachable)
				if family.mipstackAddress.Is6() {
					wantType, wantCode = uint8(header.ICMPv6DstUnreachable), uint8(header.ICMPv6PortUnreachable)
				}
				if !message.IsError() || message.Type != wantType || message.Code != wantCode ||
					networkError.Reporter != family.gvisorAddress || networkError.QuotedSource != family.mipstackAddress ||
					networkError.QuotedTarget != family.gvisorAddress || networkError.QuotedProtocol != mipstack.ProtocolUDP ||
					networkError.QuotedSourcePort != mipstackPort || networkError.QuotedTargetPort != gvisorPort {
					t.Fatalf("decoded gVisor ICMP error = message %+v, error %+v", message, networkError)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor ICMP error")
			}
		})
	}
}

func TestPublicICMPErrorConstructionInterop(t *testing.T) {
	const (
		gvisorPort   = 44041
		mipstackPort = 44042
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, interopDefaultMTU)
			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			datagram := mipstack.UDPDatagram{
				Source:      netipAddrPort(family.gvisorAddress, gvisorPort),
				Destination: netipAddrPort(family.mipstackAddress, mipstackPort),
				Payload:     []byte("quoted-public-udp"),
			}
			udpWire, err := datagram.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode quoted UDP datagram: %v", err)
			}
			quotedPacket := mipstack.IPPacket{
				Source: family.gvisorAddress, Destination: family.mipstackAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 31, Payload: udpWire,
			}
			quote, err := quotedPacket.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode quoted IP packet: %v", err)
			}
			messageType, code, protocol := uint8(mipstack.ICMPv4TypeDestinationUnreachable), uint8(mipstack.ICMPv4DestinationUnreachableCodePort), mipstack.ProtocolICMPv4
			if family.mipstackAddress.Is6() {
				messageType, code, protocol = mipstack.ICMPv6TypeDestinationUnreachable, mipstack.ICMPv6DestinationUnreachableCodePort, mipstack.ProtocolICMPv6
			}
			networkError := mipstack.ICMPError{
				Reporter: family.mipstackAddress, Type: messageType, Code: code, QuotedPacket: quote,
			}
			message, err := networkError.ICMPMessage(family.gvisorAddress)
			if err != nil {
				t.Fatalf("construct public ICMP error: %v", err)
			}
			icmpWire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP error: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: protocol, HopLimit: 64, Payload: icmpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP error packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public ICMP error: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			received, _, err := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if err != nil {
				t.Fatalf("read public ICMP error in gVisor: %v", err)
			}
			received, err = stripGVisorRawHeader(family, received)
			if err != nil {
				t.Fatalf("strip gVisor raw IP header: %v", err)
			}
			if !bytes.Equal(received, icmpWire) || len(received) < 8 || received[0] != messageType || received[1] != code ||
				!bytes.Equal(received[8:], quote) {
				t.Fatalf("gVisor received ICMP error = %x, want %x", received, icmpWire)
			}
		})
	}
}

func TestPublicICMPExtensionInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				connection, err := network.mipstack.ListenIP(context.Background(), family.icmpNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatalf("listen mipstack raw ICMP: %v", err)
				}
				defer connection.Close()
				if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatal(err)
				}

				var queue waiter.Queue
				endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor raw ICMP endpoint: %s", tcpipErr.String())
				}
				defer endpoint.Close()
				if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor raw ICMP endpoint: %s", tcpipErr.String())
				}
				if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
					t.Fatalf("connect gVisor raw ICMP endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)

				gvisorWire, quote, pointer, err := makeInteropICMPExtension(
					family, family.gvisorAddress, family.mipstackAddress,
					family.mipstackAddress, family.gvisorAddress,
				)
				if err != nil {
					t.Fatal(err)
				}
				written, writeErr := endpoint.Write(bytes.NewReader(gvisorWire), tcpip.WriteOptions{})
				_, gvisorMTUFloor := writeErr.(*tcpip.ErrMessageTooLong)
				if (writeErr != nil && !(family.mipstackAddress.Is4() && mtu == 68 && gvisorMTUFloor)) ||
					(writeErr == nil && written != int64(len(gvisorWire))) {
					t.Fatalf("write gVisor RFC 4884 message: n=%d, error=%s", written, tcpipErrorString(writeErr))
				}
				if writeErr == nil {
					storage := make([]byte, 65535)
					read, readErr := connection.(*mipstack.IPConn).Read(storage)
					if readErr != nil {
						t.Fatalf("read gVisor RFC 4884 message in mipstack: %v", readErr)
					}
					if !bytes.Equal(storage[:read], gvisorWire) {
						t.Fatalf("mipstack received RFC 4884 message = %x, want %x", storage[:read], gvisorWire)
					}
					protocol := mipstack.ProtocolICMPv4
					if family.mipstackAddress.Is6() {
						protocol = mipstack.ProtocolICMPv6
					}
					parsedMessage, err := (mipstack.IPPacket{
						Source: family.gvisorAddress, Destination: family.mipstackAddress,
						Protocol: protocol, HopLimit: 64, Payload: storage[:read],
					}).ICMPMessage()
					if err != nil {
						t.Fatalf("parse gVisor RFC 4884 message: %v", err)
					}
					parsedError, err := parsedMessage.ICMPError()
					if err != nil || !bytes.Equal(parsedError.QuotedPacket, quote) {
						t.Fatalf("decode gVisor RFC 4884 error = %+v, %v", parsedError, err)
					}
					objects, err := parsedError.ExtensionObjects()
					if err != nil || len(objects) != 1 {
						t.Fatalf("decode gVisor RFC 4884 objects = %+v, %v", objects, err)
					}
					if family.mipstackAddress.Is6() {
						if value, ok := objects[0].Pointer(); !ok || value != pointer {
							t.Fatalf("decode gVisor Headers Too Long Pointer = %d, %t", value, ok)
						}
					} else if objects[0].Class != 0xfe || objects[0].Type != 7 || !bytes.Equal(objects[0].Data, []byte{1, 2, 3, 4}) {
						t.Fatalf("decode gVisor unknown extension object = %+v", objects[0])
					}
				}

				mipWire, _, _, err := makeMipstackICMPExtension(
					family, family.mipstackAddress, family.gvisorAddress,
					family.gvisorAddress, family.mipstackAddress,
				)
				if err != nil {
					t.Fatal(err)
				}
				if written, writeErr := connection.WriteTo(mipWire, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(mipWire) {
					t.Fatalf("write mipstack RFC 4884 message: n=%d, error=%v", written, writeErr)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				received, _, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
				cancel()
				if readErr != nil {
					t.Fatalf("read mipstack RFC 4884 message in gVisor: %v", readErr)
				}
				received, err = stripGVisorRawHeader(family, received)
				if err != nil || !bytes.Equal(received, mipWire) {
					t.Fatalf("gVisor received RFC 4884 message = %x, %v; want %x", received, err, mipWire)
				}
			})
		}
	}
}

func makeInteropICMPExtension(family interopFamily, reporter, destination, quotedSource, quotedTarget netip.Addr) (message, quote []byte, pointer uint32, err error) {
	quote, err = makeInteropICMPQuote(quotedSource, quotedTarget)
	if err != nil {
		return nil, nil, 0, err
	}
	const paddedQuoteLength = 128
	message = make([]byte, 8+paddedQuoteLength+4+8)
	copy(message[8:], quote)
	structure := message[8+paddedQuoteLength:]
	structure[0] = 2 << 4
	binary.BigEndian.PutUint16(structure[4:6], 8)
	if family.mipstackAddress.Is4() {
		message[0], message[1], message[5] = mipstack.ICMPv4TypeTimeExceeded, mipstack.ICMPv4TimeExceededCodeTTLInTransit, paddedQuoteLength/4
		structure[6], structure[7] = 0xfe, 7
		copy(structure[8:], []byte{1, 2, 3, 4})
	} else {
		message[0], message[1], message[4] = mipstack.ICMPv6TypeDestinationUnreachable, mipstack.ICMPv6DestinationUnreachableCodeHeadersTooLong, paddedQuoteLength/8
		structure[6], structure[7] = mipstack.ICMPExtensionClassExtendedInformation, mipstack.ICMPExtensionExtendedInformationTypePointer
		pointer = uint32(len(quote) + 4096)
		binary.BigEndian.PutUint32(structure[8:12], pointer)
	}
	binary.BigEndian.PutUint16(structure[2:4], ^checksum.Checksum(structure, 0))
	if family.mipstackAddress.Is4() {
		binary.BigEndian.PutUint16(message[2:4], ^checksum.Checksum(message, 0))
	} else {
		icmpHeader := header.ICMPv6(message[:8])
		icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHeader, Src: gvisorAddress(reporter), Dst: gvisorAddress(destination),
			PayloadCsum: checksum.Checksum(message[8:], 0), PayloadLen: len(message) - 8,
		}))
	}
	return message, quote, pointer, nil
}

func makeInteropICMPQuote(source, destination netip.Addr) ([]byte, error) {
	udpWire, err := (mipstack.UDPDatagram{
		Source: netipAddrPort(source, 45001), Destination: netipAddrPort(destination, 45002),
		Payload: []byte("rfc4884-interop"),
	}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	return (mipstack.IPPacket{
		Source: source, Destination: destination,
		Protocol: mipstack.ProtocolUDP, HopLimit: 31, Payload: udpWire,
	}).MarshalBinary()
}

func makeMipstackICMPExtension(family interopFamily, reporter, destination, quotedSource, quotedTarget netip.Addr) (message, quote []byte, pointer uint32, err error) {
	quote, err = makeInteropICMPQuote(quotedSource, quotedTarget)
	if err != nil {
		return nil, nil, 0, err
	}
	messageType, code := uint8(mipstack.ICMPv4TypeTimeExceeded), uint8(mipstack.ICMPv4TimeExceededCodeTTLInTransit)
	objects := []mipstack.ICMPExtensionObject{{Class: 0xfe, Type: 7, Data: []byte{1, 2, 3, 4}}}
	if family.mipstackAddress.Is6() {
		messageType, code = mipstack.ICMPv6TypeDestinationUnreachable, mipstack.ICMPv6DestinationUnreachableCodeHeadersTooLong
		pointer = uint32(len(quote) + 4096)
		var object mipstack.ICMPExtensionObject
		object.SetPointer(pointer)
		objects = []mipstack.ICMPExtensionObject{object}
	}
	networkError := mipstack.ICMPError{Reporter: reporter, Type: messageType, Code: code, QuotedPacket: quote}
	if err = networkError.SetExtensionObjects(objects); err != nil {
		return nil, nil, 0, err
	}
	semantic, err := networkError.ICMPMessage(destination)
	if err != nil {
		return nil, nil, 0, err
	}
	message, err = semantic.MarshalBinary()
	return message, quote, pointer, err
}

func TestMipstackICMPFilterInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, interopDefaultMTU)
			var option mipstack.SocketOption
			if family.mipstackAddress.Is4() {
				var filter mipstack.ICMPv4Filter
				filter.Block(uint8(header.ICMPv4EchoReply))
				option = mipstack.SocketOptions.ICMPv4Filter(filter)
			} else {
				var filter mipstack.ICMPv6Filter
				filter.Block(uint8(header.ICMPv6EchoReply))
				option = mipstack.SocketOptions.ICMPv6Filter(filter)
			}
			connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{option}}).ListenIP(
				context.Background(), network.mipstack, family.icmpNetwork, family.mipstackAddress,
			)
			if err != nil {
				t.Fatalf("listen with mipstack ICMP filter: %v", err)
			}
			defer connection.Close()

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}

			message := makeICMPEcho(family, true, 0x5310, 1, []byte("filtered"), family.gvisorAddress, family.mipstackAddress)
			if written, writeErr := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(message)) {
				t.Fatalf("write filtered gVisor ICMP: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			if err = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, readErr := connection.(*mipstack.IPConn).Read(make([]byte, 64)); !errors.Is(readErr, os.ErrDeadlineExceeded) {
				t.Fatalf("blocked ICMP read = %v, want deadline", readErr)
			}
			if err = connection.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if family.mipstackAddress.Is4() {
				err = connection.(*mipstack.IPConn).SetICMPv4Filter(mipstack.ICMPv4Filter{})
			} else {
				err = connection.(*mipstack.IPConn).SetICMPv6Filter(mipstack.ICMPv6Filter{})
			}
			if err != nil {
				t.Fatal(err)
			}
			message = makeICMPEcho(family, true, 0x5310, 2, []byte("accepted"), family.gvisorAddress, family.mipstackAddress)
			if written, writeErr := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(message)) {
				t.Fatalf("write accepted gVisor ICMP: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			storage := make([]byte, 64)
			read, readErr := connection.(*mipstack.IPConn).Read(storage)
			if readErr != nil || !bytes.Equal(storage[:read], message) {
				t.Fatalf("accepted gVisor ICMP = %x, %v", storage[:read], readErr)
			}
		})
	}
}

func TestGVisorICMPv6FilterInterop(t *testing.T) {
	family := interopFamilies[1]
	network := newFamilyInteropNetwork(t, family, interopDefaultMTU)
	connection, err := network.mipstack.ListenIP(context.Background(), family.icmpNetwork, family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with mipstack ICMPv6 socket: %v", err)
	}
	defer connection.Close()

	var queue waiter.Queue
	endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	defer endpoint.Close()
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		t.Fatalf("bind gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	var filter tcpip.ICMPv6Filter
	filter.DenyType[uint8(header.ICMPv6EchoReply)>>5] |= uint32(1) << (uint8(header.ICMPv6EchoReply) & 31)
	if tcpipErr = endpoint.SetSockOpt(&filter); tcpipErr != nil {
		t.Fatalf("set gVisor ICMPv6 filter: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	message := makeICMPEcho(family, true, 0x5320, 1, []byte("filtered"), family.mipstackAddress, family.gvisorAddress)
	if written, writeErr := connection.WriteTo(message, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(message) {
		t.Fatalf("write filtered mipstack ICMPv6: n=%d, error=%v", written, writeErr)
	}
	blockedContext, cancelBlocked := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, _, readErr := readGVisorEndpoint(blockedContext, endpoint, notifications, 64); !errors.Is(readErr, context.DeadlineExceeded) {
		cancelBlocked()
		t.Fatalf("gVisor blocked ICMPv6 read = %v, want deadline", readErr)
	}
	cancelBlocked()
	if tcpipErr = endpoint.SetSockOpt(&tcpip.ICMPv6Filter{}); tcpipErr != nil {
		t.Fatalf("clear gVisor ICMPv6 filter: %s", tcpipErr.String())
	}
	message = makeICMPEcho(family, true, 0x5320, 2, []byte("accepted"), family.mipstackAddress, family.gvisorAddress)
	if written, writeErr := connection.WriteTo(message, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(message) {
		t.Fatalf("write accepted mipstack ICMPv6: n=%d, error=%v", written, writeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packet, _, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 64)
	if readErr != nil || !bytes.Equal(packet, message) {
		t.Fatalf("accepted mipstack ICMPv6 = %x, %v", packet, readErr)
	}
}

func testMipstackICMPEcho(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := network.mipstack.DialIP(ctx, family.icmpNetwork, family.mipstackAddress, family.gvisorAddress)
	if err != nil {
		t.Fatalf("dial mipstack ICMP: %v", err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set mipstack ICMP deadline: %v", err)
	}

	storage := make([]byte, 65535)
	const identifier = 0x5101
	for index, size := range []int{29, fragmentedInteropPayloadSize(mtu, 4096)} {
		payload := patternedPayload(size, byte(43+index))
		request := makeICMPEcho(family, false, identifier, uint16(index+1), payload, family.mipstackAddress, family.gvisorAddress)
		written, writeErr := connection.Write(request)
		if writeErr != nil || written != len(request) {
			t.Fatalf("write mipstack ICMP echo: n=%d, error=%v", written, writeErr)
		}
		read, readErr := connection.Read(storage)
		if readErr != nil {
			t.Fatalf("read mipstack ICMP echo reply: %v", readErr)
		}
		if err = validateICMPEcho(family, storage[:read], true, identifier, uint16(index+1), payload, family.gvisorAddress, family.mipstackAddress); err != nil {
			t.Fatal(err)
		}
	}
}

func testGVisorICMPEcho(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var queue waiter.Queue
	endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	defer endpoint.Close()
	const identifier = 0x5201
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
		t.Fatalf("bind gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	for index, size := range []int{31, fragmentedInteropPayloadSize(mtu, 4096)} {
		payload := patternedPayload(size, byte(71+index))
		request := makeICMPEcho(family, false, identifier, uint16(index+1), payload, family.gvisorAddress, family.mipstackAddress)
		written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
		if writeErr != nil || written != int64(len(request)) {
			t.Fatalf("write gVisor ICMP echo: n=%d, error=%v", written, tcpipErrorString(writeErr))
		}
		reply, _, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
		if readErr != nil {
			t.Fatalf("read gVisor ICMP echo reply: %v", readErr)
		}
		if err := validateICMPEcho(family, reply, true, identifier, uint16(index+1), payload, family.mipstackAddress, family.gvisorAddress); err != nil {
			t.Fatal(err)
		}
	}
}

func makeICMPEcho(family interopFamily, reply bool, identifier, sequence uint16, payload []byte, source, target netip.Addr) []byte {
	message := make([]byte, 8+len(payload))
	copy(message[8:], payload)
	if family.networkProtocol == header.IPv4ProtocolNumber {
		icmpHeader := header.ICMPv4(message[:8])
		messageType := header.ICMPv4Echo
		if reply {
			messageType = header.ICMPv4EchoReply
		}
		icmpHeader.SetType(messageType)
		icmpHeader.SetCode(0)
		icmpHeader.SetIdent(identifier)
		icmpHeader.SetSequence(sequence)
		icmpHeader.SetChecksum(^checksum.Checksum(message, 0))
		return message
	}

	icmpHeader := header.ICMPv6(message[:8])
	messageType := header.ICMPv6EchoRequest
	if reply {
		messageType = header.ICMPv6EchoReply
	}
	icmpHeader.SetType(messageType)
	icmpHeader.SetCode(0)
	icmpHeader.SetIdent(identifier)
	icmpHeader.SetSequence(sequence)
	icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHeader,
		Src:         gvisorAddress(source),
		Dst:         gvisorAddress(target),
		PayloadCsum: checksum.Checksum(message[8:], 0),
		PayloadLen:  len(message) - 8,
	}))
	return message
}

func validateICMPEcho(family interopFamily, message []byte, reply bool, identifier, sequence uint16, payload []byte, source, target netip.Addr) error {
	if len(message) != 8+len(payload) {
		return fmt.Errorf("ICMP echo length: got %d, want %d", len(message), 8+len(payload))
	}
	if family.networkProtocol == header.IPv4ProtocolNumber {
		icmpHeader := header.ICMPv4(message[:8])
		expectedType := header.ICMPv4Echo
		if reply {
			expectedType = header.ICMPv4EchoReply
		}
		if icmpHeader.Type() != expectedType || icmpHeader.Code() != 0 {
			return fmt.Errorf("ICMPv4 echo type/code: got %d/%d, want %d/0", icmpHeader.Type(), icmpHeader.Code(), expectedType)
		}
		if checksum.Checksum(message, 0) != 0xffff {
			return errors.New("ICMPv4 echo checksum is invalid")
		}
	} else {
		icmpHeader := header.ICMPv6(message[:8])
		expectedType := header.ICMPv6EchoRequest
		if reply {
			expectedType = header.ICMPv6EchoReply
		}
		if icmpHeader.Type() != expectedType || icmpHeader.Code() != 0 {
			return fmt.Errorf("ICMPv6 echo type/code: got %d/%d, want %d/0", icmpHeader.Type(), icmpHeader.Code(), expectedType)
		}
		actualChecksum := icmpHeader.Checksum()
		icmpHeader.SetChecksum(0)
		expectedChecksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHeader,
			Src:         gvisorAddress(source),
			Dst:         gvisorAddress(target),
			PayloadCsum: checksum.Checksum(message[8:], 0),
			PayloadLen:  len(message) - 8,
		})
		icmpHeader.SetChecksum(actualChecksum)
		if actualChecksum != expectedChecksum {
			return fmt.Errorf("ICMPv6 echo checksum: got %#04x, want %#04x", actualChecksum, expectedChecksum)
		}
	}
	var actualIdentifier, actualSequence uint16
	if family.networkProtocol == header.IPv4ProtocolNumber {
		actualIdentifier = header.ICMPv4(message[:8]).Ident()
		actualSequence = header.ICMPv4(message[:8]).Sequence()
	} else {
		actualIdentifier = header.ICMPv6(message[:8]).Ident()
		actualSequence = header.ICMPv6(message[:8]).Sequence()
	}
	if actualIdentifier != identifier || actualSequence != sequence {
		return fmt.Errorf("ICMP echo identifier/sequence: got %#x/%d, want %#x/%d", actualIdentifier, actualSequence, identifier, sequence)
	}
	if !bytes.Equal(message[8:], payload) {
		return errors.New("ICMP echo payload mismatch")
	}
	return nil
}

func tcpipErrorString(err tcpip.Error) string {
	if err == nil {
		return "<nil>"
	}
	return err.String()
}

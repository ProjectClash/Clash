package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPublicICMPMessageCodecKnownAnswers(t *testing.T) {
	tests := []struct {
		name    string
		packet  string
		message ICMPMessage
	}{
		{
			name: "Linux IPv4 Echo",
			packet: "45000025ff4740004001b78cc0000201c0000202" +
				"080039bfaa2f0001000102030405060708",
			message: ICMPMessage{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
				Type: ICMPv4TypeEchoRequest, Body: mustCodecVector(t, "aa2f0001000102030405060708"),
			},
		},
		{
			name: "IPv6 Echo odd payload",
			packet: "6000000000113aff20010db8000000000000000000000005" +
				"20010db8000000000000000000000006" +
				"8000a77a12345678000102030405060708",
			message: ICMPMessage{
				Source: netip.MustParseAddr("2001:db8::5"), Destination: netip.MustParseAddr("2001:db8::6"),
				Type: ICMPv6TypeEchoRequest, Body: mustCodecVector(t, "12345678000102030405060708"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := ParseIPPacket(mustCodecVector(t, test.packet))
			if err != nil {
				t.Fatal(err)
			}
			message, err := packet.ICMPMessage()
			if err != nil {
				t.Fatalf("ICMPMessage: %v", err)
			}
			if !reflect.DeepEqual(message, test.message) {
				t.Fatalf("parsed message = %+v, want %+v", message, test.message)
			}
			identifier, sequence, payload, ok := message.Echo()
			if !ok || identifier != binary.BigEndian.Uint16(message.Body[:2]) ||
				sequence != binary.BigEndian.Uint16(message.Body[2:4]) || !bytes.Equal(payload, message.Body[4:]) {
				t.Fatalf("Echo = %#x/%#x/%x/%t", identifier, sequence, payload, ok)
			}
			encoded, err := test.message.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, packet.Payload) {
				t.Fatalf("MarshalBinary: error=%v\n got %x\nwant %x", err, encoded, packet.Payload)
			}
			assertICMPMessageWire(t, test.message, encoded)
		})
	}
}

func TestPublicICMPErrorExtensionKnownAnswer(t *testing.T) {
	wire := mustCodecVector(t, "6000000000943a4020010db8ffff0000000000000000000120010db8000000000000000000000001"+
		"0108fcfc10000000600000000008113f20010db800000000000000000000000120010db800010000"+
		"0000000000000001c73801bb00080000000000000000000000000000000000000000000000000000"+
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000"+
		"000000000000000000000000000000002000dbc60008040100000030")
	packet, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	message, err := packet.ICMPMessage()
	if err != nil {
		t.Fatalf("ICMPMessage: %v", err)
	}
	networkError, err := message.ICMPError()
	if err != nil {
		t.Fatalf("ICMPError: %v", err)
	}
	quote := mustCodecVector(t, "600000000008113f20010db800000000000000000000000120010db8000100000000000000000001c73801bb00080000")
	if networkError.Reporter != netip.MustParseAddr("2001:db8:ffff::1") ||
		networkError.Type != ICMPv6TypeDestinationUnreachable || networkError.Code != ICMPv6DestinationUnreachableCodeHeadersTooLong ||
		networkError.QuotedSource != netip.MustParseAddr("2001:db8::1") ||
		networkError.QuotedTarget != netip.MustParseAddr("2001:db8:1::1") ||
		networkError.QuotedProtocol != ProtocolUDP || networkError.QuotedSourcePort != 51000 ||
		networkError.QuotedTargetPort != 443 || !bytes.Equal(networkError.QuotedPacket, quote) {
		t.Fatalf("parsed RFC 8883 error = %+v", networkError)
	}
	objects, err := networkError.ExtensionObjects()
	if err != nil || len(objects) != 1 {
		t.Fatalf("ExtensionObjects = %+v, %v", objects, err)
	}
	if pointer, ok := objects[0].Pointer(); !ok || pointer != 48 {
		t.Fatalf("RFC 8883 Pointer = %d/%t", pointer, ok)
	}
	rebuilt, err := networkError.ICMPMessage(netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("ICMPMessage construction: %v", err)
	}
	encoded, err := rebuilt.MarshalBinary()
	if err != nil || !bytes.Equal(encoded, packet.Payload) {
		t.Fatalf("RFC 4884/8883 encoding: error=%v\n got %x\nwant %x", err, encoded, packet.Payload)
	}
	if got := referenceTransportChecksum(packet.Source, packet.Destination, ProtocolICMPv6, packet.Payload); got != 0 {
		t.Fatalf("ICMPv6 reference checksum = %#x, want zero", got)
	}
	structure := packet.Payload[len(packet.Payload)-12:]
	if got := referenceChecksum(structure); got != 0 {
		t.Fatalf("RFC 4884 Extension Structure checksum = %#x, want zero", got)
	}

	corrupted := append([]byte(nil), wire...)
	corruptedPacket, err := ParseIPPacket(corrupted)
	if err != nil {
		t.Fatal(err)
	}
	corruptedPacket.Payload[len(corruptedPacket.Payload)-10] ^= 1
	repairReferenceTransportChecksum(corruptedPacket.Source, corruptedPacket.Destination,
		ProtocolICMPv6, corruptedPacket.Payload, 2)
	corruptedMessage, err := corruptedPacket.ICMPMessage()
	if err != nil {
		t.Fatalf("ICMP envelope after extension mutation: %v", err)
	}
	if _, err = corruptedMessage.ICMPError(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ICMPError with bad RFC 4884 checksum error = %v, want EINVAL", err)
	}
}

func TestPublicICMPMessageCodecKnownAnswerMutations(t *testing.T) {
	for _, test := range []struct {
		name string
		wire string
	}{
		{
			name: "IPv4",
			wire: "45000025ff4740004001b78cc0000201c0000202" +
				"080039bfaa2f0001000102030405060708",
		},
		{
			name: "IPv6",
			wire: "6000000000113aff20010db8000000000000000000000005" +
				"20010db8000000000000000000000006" +
				"8000a77a12345678000102030405060708",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet, err := ParseIPPacket(mustCodecVector(t, test.wire))
			if err != nil {
				t.Fatal(err)
			}
			payload := append([]byte(nil), packet.Payload...)
			payload[len(payload)-1] ^= 1
			packet.Payload = payload
			if _, err = packet.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("ICMPMessage error = %v, want EINVAL", err)
			}
		})
	}
}

func FuzzPublicICMPMessageWireEncoding(f *testing.F) {
	f.Add(false, byte(ICMPv4TypeEchoRequest), byte(0), uint32(0x12340001), []byte("IPv4 ICMP"))
	f.Add(true, byte(ICMPv6TypeEchoRequest), byte(0), uint32(0x56780002), []byte("IPv6 ICMP odd"))
	f.Fuzz(func(t *testing.T, ipv6 bool, messageType, code byte, prefix uint32, payload []byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		body := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(body[:4], prefix)
		copy(body[4:], payload)
		message := ICMPMessage{
			Source: netip.MustParseAddr("192.0.2.104"), Destination: netip.MustParseAddr("198.51.100.104"),
			Type: messageType, Code: code, Body: body,
		}
		protocol := ProtocolICMPv4
		if ipv6 {
			message.Source = netip.MustParseAddr("2001:db8::104")
			message.Destination = netip.MustParseAddr("2001:db8:1::104")
			protocol = ProtocolICMPv6
		}
		wire, err := message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("AppendBinary: %v", err)
		}
		assertICMPMessageWire(t, message, wire)
		packet := IPPacket{Source: message.Source, Destination: message.Destination, Protocol: protocol, Payload: wire}
		if _, err = packet.ICMPMessage(); err != nil {
			t.Fatalf("ICMPMessage(encoded message): %v", err)
		}
	})
}

func assertICMPMessageWire(t testing.TB, message ICMPMessage, wire []byte) {
	t.Helper()
	if len(wire) != 4+len(message.Body) || wire[0] != message.Type || wire[1] != message.Code || !bytes.Equal(wire[4:], message.Body) {
		t.Fatalf("ICMP wire does not match semantic value: %x", wire)
	}
	value := referenceChecksum(wire)
	if message.Source.Unmap().Is6() {
		value = referenceTransportChecksum(message.Source, message.Destination, ProtocolICMPv6, wire)
	}
	if value != 0 {
		t.Fatalf("ICMP reference checksum = %#x, want zero", value)
	}
}

func TestLegacyIPv4PathMTU(t *testing.T) {
	packet := buildIPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), ProtocolTCP, make([]byte, 1400), 1, true)
	if mtu := legacyIPv4PathMTU(packet); mtu != 1006 {
		t.Fatalf("legacy PMTU = %d, want 1006", mtu)
	}
	if mtu := legacyIPv4PathMTU([]byte{0x45}); mtu != 0 {
		t.Fatalf("truncated legacy PMTU = %d, want 0", mtu)
	}
	malformed := make([]byte, 20)
	malformed[0] = 0x45
	if mtu := legacyIPv4PathMTU(malformed); mtu != 0 {
		t.Fatalf("malformed legacy PMTU = %d, want 0", mtu)
	}
}

func TestICMPErrorCodeValidation(t *testing.T) {
	for _, test := range []struct {
		protocol, messageType, code byte
		valid                       bool
	}{
		{ProtocolICMPv4, 3, 15, true},
		{ProtocolICMPv4, 3, 16, false},
		{ProtocolICMPv4, 11, 1, true},
		{ProtocolICMPv4, 11, 2, false},
		{ProtocolICMPv4, 12, 2, true},
		{ProtocolICMPv4, 12, 3, false},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodeSourceRoutingHeader, true},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodeHeadersTooLong, true},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodePRoute, true},
		{ProtocolICMPv6, 1, 10, false},
		{ProtocolICMPv6, 2, 0, true},
		{ProtocolICMPv6, 2, 1, false},
		{ProtocolICMPv6, 3, 1, true},
		{ProtocolICMPv6, 3, 2, false},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeIncompleteFirstFragment, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeSRUpperLayerHeader, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeUnrecognizedNextHeaderAtIntermediateNode, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeOptionTooBig, true},
		{ProtocolICMPv6, 4, 11, false},
		{ProtocolICMPv4, 8, 0, false},
	} {
		if got := validICMPErrorCode(test.protocol, test.messageType, test.code); got != test.valid {
			t.Errorf("validICMPErrorCode(%d, %d, %d) = %v, want %v", test.protocol, test.messageType, test.code, got, test.valid)
		}
	}
}

func TestTruncatedICMPv6ErrorIsRejected(t *testing.T) {
	if _, ok := parseICMPError(ipPacket{protocol: ProtocolICMPv6, payload: []byte{1}}); ok {
		t.Fatal("truncated ICMPv6 error was accepted")
	}
}

func TestICMPErrorRejectsCrossFamilyQuote(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol byte
		typeCode [2]byte
		quoted   []byte
	}{
		{
			name: "ICMPv4 quoting IPv6", protocol: ProtocolICMPv4, typeCode: [2]byte{3, 1},
			quoted: buildIPPacket(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), ProtocolUDP, make([]byte, 8), 0, true),
		},
		{
			name: "ICMPv6 quoting IPv4", protocol: ProtocolICMPv6, typeCode: [2]byte{1, 0},
			quoted: buildIPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), ProtocolUDP, make([]byte, 8), 1, true),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := make([]byte, 8+len(test.quoted))
			message[0], message[1] = test.typeCode[0], test.typeCode[1]
			copy(message[8:], test.quoted)
			if _, ok := parseICMPError(ipPacket{protocol: test.protocol, payload: message}); ok {
				t.Fatal("cross-family quoted packet was accepted")
			}
		})
	}
}

func TestQuotedIPv6FirstFragmentIgnoresReservedBits(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::1")
	target := netip.MustParseAddr("2001:db8::2")
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0], fragment[1] = ProtocolUDP, 0xff
	binary.BigEndian.PutUint16(fragment[2:4], 0x0007)
	packet := buildIPPacket(source, target, 44, fragment, 0, false)
	quotedSource, quotedTarget, protocol, payload, ok := quotedIPPayload(packet)
	if !ok || quotedSource != source || quotedTarget != target || protocol != ProtocolUDP || len(payload) != udpHeaderSize {
		t.Fatalf("quoted reserved-bit first fragment = %v %v %d %d, parsed = %v", quotedSource, quotedTarget, protocol, len(payload), ok)
	}
}

func FuzzICMPErrorQuotes(f *testing.F) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	quoted4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 1, true)
	quoted6 := buildIPPacket(source6, target6, ProtocolTCP, make([]byte, tcpHeaderSize), 0, true)
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0] = ProtocolUDP
	binary.BigEndian.PutUint16(fragment[2:4], 1)
	quotedFragment6 := buildIPPacket(source6, target6, 44, fragment, 0, false)
	authentication := make([]byte, 16+udpHeaderSize)
	authentication[0], authentication[1] = ProtocolUDP, 2
	quotedAuthentication6 := buildIPPacket(source6, target6, IPv6ExtensionHeaderAuthentication, authentication, 0, false)
	f.Add([]byte(nil), false, byte(3), byte(1))
	f.Add(quoted4, false, byte(3), byte(4))
	f.Add(quoted6, true, byte(1), byte(0))
	f.Add(quotedFragment6, true, byte(2), byte(0))
	f.Add(quotedAuthentication6, true, byte(4), byte(1))
	f.Add(buildTestIPv6Extension(source6, target6, 60, []byte{ProtocolUDP, 4, 0, 0, 0, 0, 0, 0}), true, byte(3), byte(0))
	f.Fuzz(func(t *testing.T, quote []byte, ipv6 bool, messageType, code byte) {
		if len(quote) > 65575 {
			quote = quote[:65575]
		}
		before := append([]byte(nil), quote...)
		_, _, _, _, _ = quotedIPPayload(quote)
		_ = legacyIPv4PathMTU(quote)
		_ = packetInvokesICMPError(quote)
		message := make([]byte, 8+len(quote))
		message[0], message[1] = messageType, code
		copy(message[8:], quote)
		protocol := byte(ProtocolICMPv4)
		reporter := netip.MustParseAddr("203.0.113.1")
		if ipv6 {
			protocol = ProtocolICMPv6
			reporter = netip.MustParseAddr("2001:db8:ffff::1")
		}
		networkError, ok := parseICMPError(ipPacket{source: reporter, protocol: protocol, payload: message})
		destination := target4
		if ipv6 {
			destination = target6
		}
		publicMessage := ICMPMessage{
			Source: reporter, Destination: destination,
			Type: messageType, Code: code, Body: message[4:],
		}
		publicError, publicErr := publicMessage.ICMPError()
		if !bytes.Equal(quote, before) {
			t.Fatal("ICMP quote parsing modified its input")
		}
		if !ok {
			if publicErr == nil {
				t.Fatalf("public parser accepted an error rejected by the stack parser: %+v", publicError)
			}
			return
		}
		if publicErr != nil {
			t.Fatalf("public parser rejected an error accepted by the stack parser: %v", publicErr)
		}
		if !reflect.DeepEqual(publicError, networkError) {
			t.Fatalf("public and stack ICMP parsers disagree:\n public: %+v\n  stack: %+v", publicError, networkError)
		}
		if !validICMPErrorCode(protocol, messageType, code) {
			t.Fatalf("accepted invalid ICMP type/code %d/%d for protocol %d", messageType, code, protocol)
		}
		if networkError.Reporter != reporter || networkError.QuotedSource.Is6() != ipv6 || networkError.QuotedTarget.Is6() != ipv6 ||
			!networkError.QuotedSource.IsValid() || !networkError.QuotedTarget.IsValid() {
			t.Fatalf("invalid parsed ICMP endpoints: reporter %v, quote %v -> %v", networkError.Reporter, networkError.QuotedSource, networkError.QuotedTarget)
		}
		if !bytes.Equal(networkError.QuotedPacket, quote) {
			t.Fatal("parsed ICMP quote differs from its input")
		}
		if len(networkError.QuotedPayload) > len(networkError.QuotedPacket) ||
			!bytes.Equal(networkError.QuotedPayload, networkError.QuotedPacket[len(networkError.QuotedPacket)-len(networkError.QuotedPayload):]) {
			t.Fatal("parsed ICMP payload is not a quoted-packet suffix")
		}
		if len(networkError.QuotedPacket) <= 65535-8 {
			constructed, constructErr := publicError.ICMPMessage(destination)
			if constructErr != nil {
				t.Fatalf("construct parsed ICMP error: %v", constructErr)
			}
			reparsed, parseErr := constructed.ICMPError()
			if parseErr != nil {
				t.Fatalf("parse reconstructed ICMP error: %v", parseErr)
			}
			if !reflect.DeepEqual(reparsed, publicError) {
				t.Fatalf("ICMP error reconstruction changed semantics:\n original: %+v\n  rebuilt: %+v", publicError, reparsed)
			}
		}
		cloned := cloneICMPError(networkError)
		clonedPacket := append([]byte(nil), cloned.QuotedPacket...)
		clonedPayload := append([]byte(nil), cloned.QuotedPayload...)
		if len(cloned.QuotedPayload) != 0 {
			offset := len(cloned.QuotedPacket) - len(cloned.QuotedPayload)
			if &cloned.QuotedPayload[0] != &cloned.QuotedPacket[offset] {
				t.Fatal("cloned ICMP payload does not retain its packet-suffix relationship")
			}
		}
		if len(networkError.QuotedPacket) != 0 {
			networkError.QuotedPacket[0] ^= 0xff
		}
		if len(networkError.QuotedPayload) != 0 {
			networkError.QuotedPayload[0] ^= 0xff
		}
		if !bytes.Equal(cloned.QuotedPacket, clonedPacket) || !bytes.Equal(cloned.QuotedPayload, clonedPayload) {
			t.Fatal("cloned ICMP error retained caller-owned storage")
		}
	})
}

func FuzzICMPExtensionObjects(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 0, 0, 0, 17})
	f.Add([]byte{0, 4, 0xfe, 0x7d, 0, 8, 1, 2, 1, 2, 3, 4})
	f.Add([]byte{0, 7, 1, 1, 1, 2, 3})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 65535 {
			encoded = encoded[:65535]
		}
		before := append([]byte(nil), encoded...)
		networkError := ICMPError{Extensions: encoded}
		objects, err := networkError.ExtensionObjects()
		if !bytes.Equal(encoded, before) {
			t.Fatal("ExtensionObjects modified its input")
		}
		hasPointer, valid := validateICMPExtensionObjects(encoded)
		if len(encoded) == 0 {
			if err != nil || objects != nil || valid || hasPointer {
				t.Fatalf("empty extension result = %+v, %v, %t/%t", objects, err, hasPointer, valid)
			}
			return
		}
		if err != nil {
			if valid {
				t.Fatal("public parser rejected an internally valid object sequence")
			}
			return
		}
		if !valid || len(objects) == 0 {
			t.Fatal("public parser accepted an internally invalid object sequence")
		}
		var rebuilt ICMPError
		if err = rebuilt.SetExtensionObjects(objects); err != nil || !bytes.Equal(rebuilt.Extensions, encoded) {
			t.Fatalf("object round trip = %x, %v; want %x", rebuilt.Extensions, err, encoded)
		}
		foundPointer := false
		for _, object := range objects {
			_, pointer := object.Pointer()
			foundPointer = foundPointer || pointer
		}
		if foundPointer != hasPointer {
			t.Fatalf("Pointer classification = %t, want %t", foundPointer, hasPointer)
		}
	})
}

func FuzzICMPExtensionMessages(f *testing.F) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8::2")
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 21, true)
	quote6 := buildIPPacket(source6, target6, ProtocolUDP, make([]byte, udpHeaderSize), 0, true)
	for _, seed := range []struct {
		ipv6        bool
		messageType uint8
		code        uint8
		quote       []byte
	}{
		{messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit, quote: quote4},
		{ipv6: true, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeHeadersTooLong, quote: quote6},
	} {
		reporter, destination := netip.MustParseAddr("203.0.113.1"), source4
		objects := []ICMPExtensionObject{{Class: 0xfe, Type: 1, Data: []byte{1, 2, 3, 4}}}
		if seed.ipv6 {
			reporter, destination = netip.MustParseAddr("2001:db8:ffff::1"), source6
			var pointer ICMPExtensionObject
			pointer.SetPointer(2048)
			objects = append(objects, pointer)
		}
		networkError := ICMPError{Reporter: reporter, Type: seed.messageType, Code: seed.code, QuotedPacket: seed.quote}
		if err := networkError.SetExtensionObjects(objects); err != nil {
			f.Fatal(err)
		}
		message, err := networkError.ICMPMessage(destination)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append([]byte(nil), message.Body...), seed.ipv6, seed.messageType, seed.code)
	}
	f.Add([]byte(nil), false, byte(3), byte(1))
	f.Add(make([]byte, 4), true, byte(1), byte(8))
	f.Fuzz(func(t *testing.T, body []byte, ipv6 bool, messageType, code byte) {
		if len(body) > 65531 {
			body = body[:65531]
		}
		before := append([]byte(nil), body...)
		reporter, destination := netip.MustParseAddr("203.0.113.1"), source4
		protocol := byte(ProtocolICMPv4)
		if ipv6 {
			reporter, destination = netip.MustParseAddr("2001:db8:ffff::1"), source6
			protocol = ProtocolICMPv6
		}
		message := ICMPMessage{Source: reporter, Destination: destination, Type: messageType, Code: code, Body: body}
		publicError, err := message.ICMPError()
		stackError, ok := parseICMPErrorFields(reporter, protocol, messageType, code, body)
		if !bytes.Equal(body, before) {
			t.Fatal("extended ICMP parser modified its input")
		}
		if (err == nil) != ok || ok && !reflect.DeepEqual(publicError, stackError) {
			t.Fatalf("public/stack parse disagreement: public=%+v/%v stack=%+v/%t", publicError, err, stackError, ok)
		}
		if err != nil {
			return
		}
		rebuilt, rebuildErr := publicError.ICMPMessage(destination)
		if rebuildErr != nil {
			t.Fatalf("rebuild parsed extended error: %v", rebuildErr)
		}
		reparsed, reparseErr := rebuilt.ICMPError()
		if reparseErr != nil || !reflect.DeepEqual(reparsed, publicError) {
			t.Fatalf("extended semantic round trip: got %+v/%v, want %+v", reparsed, reparseErr, publicError)
		}
	})
}

func TestTCPICMPSequenceCorrelation(t *testing.T) {
	connection := &TCPConn{}
	quoted := make([]byte, 8)
	check := func(sequence uint32, want bool) {
		binary.BigEndian.PutUint32(quoted[4:8], sequence)
		if got := connection.acceptsICMPQuote(quoted); got != want {
			t.Errorf("sequence %#x accepted = %v, want %v", sequence, got, want)
		}
	}
	connection.publishICMPSequenceRange(100, 120)
	check(99, false)
	check(100, true)
	check(110, true)
	check(120, true)
	check(121, false)
	connection.publishICMPSequenceRange(0xfffffff0, 0x10)
	check(0xffffffef, false)
	check(0xfffffff0, true)
	check(0, true)
	check(0x10, true)
	check(0x11, false)
	if connection.acceptsICMPQuote(quoted[:7]) {
		t.Fatal("truncated TCP quotation was accepted")
	}
}

func TestPublicICMPMessageCodec(t *testing.T) {
	tests := []ICMPMessage{
		{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Type: 8, Body: []byte{0x12, 0x34, 0, 7, 'v', '4'}},
		{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Type: 128, Body: []byte{0x56, 0x78, 0, 9, 'v', '6'}},
	}
	for _, test := range tests {
		name := "IPv4"
		protocol := ProtocolICMPv4
		if test.Source.Is6() {
			name, protocol = "IPv6", ProtocolICMPv6
		}
		t.Run(name, func(t *testing.T) {
			wire, err := test.AppendBinary([]byte{0xaa})
			if err != nil {
				t.Fatalf("append ICMP: %v", err)
			}
			if wire[0] != 0xaa {
				t.Fatal("ICMP AppendBinary changed prefix")
			}
			wire = wire[1:]
			valid := checksum(wire) == 0
			if test.Source.Is6() {
				valid = transportChecksum(test.Source, test.Destination, ProtocolICMPv6, wire) == 0
			}
			if !valid {
				t.Fatal("encoded ICMP checksum is invalid")
			}
			packet := IPPacket{Source: test.Source, Destination: test.Destination, Protocol: protocol, HopLimit: 64, Payload: wire}
			parsed, err := packet.ICMPMessage()
			if err != nil {
				t.Fatalf("parse ICMP: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.Type != test.Type || parsed.Code != test.Code || !bytes.Equal(parsed.Body, test.Body) || !parsed.IsEchoRequest() {
				t.Fatalf("parsed ICMP = %+v, want %+v", parsed, test)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("ICMP round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
		})
	}
}

func TestPublicICMPMessageEchoFieldsAndConstruction(t *testing.T) {
	for _, test := range []struct {
		name                   string
		source, destination    netip.Addr
		protocol               int
		requestType, replyType uint8
	}{
		{
			name: "IPv4 mapped", source: netip.MustParseAddr("::ffff:192.0.2.1"),
			destination: netip.MustParseAddr("::ffff:198.51.100.1"), protocol: ProtocolICMPv4,
			requestType: ICMPv4TypeEchoRequest, replyType: ICMPv4TypeEchoReply,
		},
		{
			name: "IPv6", source: netip.MustParseAddr("2001:db8::1"),
			destination: netip.MustParseAddr("2001:db8::2"), protocol: ProtocolICMPv6,
			requestType: ICMPv6TypeEchoRequest, replyType: ICMPv6TypeEchoReply,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("echo-payload")
			message := ICMPMessage{
				Source: test.source, Destination: test.destination,
				Type: 0xff, Code: 0xff, Body: []byte("replaced"),
			}
			if err := message.SetEchoRequest(0x1234, 0x5678, payload); err != nil {
				t.Fatalf("SetEchoRequest: %v", err)
			}
			if message.Source != test.source || message.Destination != test.destination {
				t.Fatalf("SetEchoRequest changed address context: %s -> %s", message.Source, message.Destination)
			}
			payload[0] ^= 0xff
			identifier, sequence, data, ok := message.Echo()
			if !ok || identifier != 0x1234 || sequence != 0x5678 || !bytes.Equal(data, []byte("echo-payload")) {
				t.Fatalf("Echo = %#x/%#x/%q/%t", identifier, sequence, data, ok)
			}
			if message.Type != test.requestType || message.Code != ICMPCodeNone || !message.IsEchoRequest() || message.IsEchoReply() {
				t.Fatalf("constructed Echo Request = %+v", message)
			}
			if &data[0] != &message.Body[4] {
				t.Fatal("Echo copied its payload")
			}

			wire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode constructed Echo Request: %v", err)
			}
			parsed, err := (IPPacket{
				Source: message.Source, Destination: message.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse constructed Echo Request: %v", err)
			}
			identifier, sequence, data, ok = parsed.Echo()
			if !ok || identifier != 0x1234 || sequence != 0x5678 || !bytes.Equal(data, []byte("echo-payload")) {
				t.Fatalf("parsed Echo = %#x/%#x/%q/%t", identifier, sequence, data, ok)
			}

			overlapping := message.Body[1:]
			wantReplyPayload := append([]byte(nil), overlapping...)
			if err = message.SetEchoReply(0xabcd, 9, overlapping); err != nil {
				t.Fatalf("SetEchoReply with overlapping payload: %v", err)
			}
			identifier, sequence, data, ok = message.Echo()
			if !ok || identifier != 0xabcd || sequence != 9 || !bytes.Equal(data, wantReplyPayload) ||
				message.Type != test.replyType || message.Code != ICMPCodeNone || message.IsEchoRequest() || !message.IsEchoReply() {
				t.Fatalf("constructed Echo Reply = %+v, fields %#x/%#x/%q/%t", message, identifier, sequence, data, ok)
			}
		})
	}
}

func TestPublicICMPMessageEchoValidation(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
		Type: ICMPv4TypeEchoRequest, Code: ICMPCodeNone, Body: []byte{0, 1, 0, 2},
	}
	invalidMessages := []ICMPMessage{
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeEchoRequest, Code: 1, Body: v4.Body},
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeDestinationUnreachable, Body: v4.Body},
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeEchoRequest, Body: v4.Body[:3]},
		{Source: v4.Source, Destination: netip.MustParseAddr("2001:db8::1"), Type: ICMPv4TypeEchoRequest, Body: v4.Body},
		{Source: netip.MustParseAddr("fe80::1").WithZone("zone"), Destination: netip.MustParseAddr("2001:db8::1"), Type: ICMPv6TypeEchoRequest, Body: v4.Body},
	}
	for index, message := range invalidMessages {
		if identifier, sequence, payload, ok := message.Echo(); ok || identifier != 0 || sequence != 0 || payload != nil ||
			message.IsEchoRequest() || message.IsEchoReply() {
			t.Fatalf("invalid Echo %d was accepted", index)
		}
	}

	for _, test := range []struct {
		name    string
		message ICMPMessage
		payload []byte
		want    error
	}{
		{name: "invalid source", message: ICMPMessage{Destination: v4.Destination}, want: syscall.EINVAL},
		{name: "invalid destination", message: ICMPMessage{Source: v4.Source}, want: syscall.EINVAL},
		{name: "cross family", message: ICMPMessage{Source: v4.Source, Destination: netip.MustParseAddr("2001:db8::1")}, want: syscall.EINVAL},
		{name: "zoned", message: ICMPMessage{Source: netip.MustParseAddr("2001:db8::1").WithZone("zone"), Destination: netip.MustParseAddr("2001:db8::2")}, want: syscall.EINVAL},
		{name: "oversized", message: v4, payload: make([]byte, 65535-8+1), want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := test.message
			message.Type, message.Code, message.Body = 0xfe, 0xfd, []byte("unchanged")
			before := message
			before.Body = append([]byte(nil), message.Body...)
			if err := message.SetEchoRequest(1, 2, test.payload); !errors.Is(err, test.want) {
				t.Fatalf("SetEchoRequest error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(message, before) {
				t.Fatalf("failed SetEchoRequest changed receiver: got %+v, want %+v", message, before)
			}
		})
	}
	var nilMessage *ICMPMessage
	if err := nilMessage.SetEchoRequest(1, 2, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetEchoRequest error = %v", err)
	}
	if err := nilMessage.SetEchoReply(1, 2, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetEchoReply error = %v", err)
	}
}

func TestPublicICMPError(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	udp := make([]byte, udpHeaderSize)
	binary.BigEndian.PutUint16(udp[0:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quoted4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 7, true)
	body4 := make([]byte, 4+len(quoted4))
	binary.BigEndian.PutUint16(body4[2:4], 1280)
	copy(body4[4:], quoted4)
	message4 := ICMPMessage{
		Source: netip.MustParseAddr("198.51.100.254"), Destination: source4,
		Type: 3, Code: 4, Body: body4,
	}
	if !message4.IsError() {
		t.Fatal("IPv4 Fragmentation Needed was not classified as an error")
	}
	error4, err := message4.ICMPError()
	if err != nil {
		t.Fatalf("parse IPv4 ICMP error: %v", err)
	}
	if error4.Reporter != message4.Source || error4.Type != message4.Type || error4.Code != message4.Code || error4.MTU != 1280 ||
		error4.QuotedSource != source4 || error4.QuotedTarget != target4 || error4.QuotedProtocol != ProtocolUDP ||
		error4.QuotedSourcePort != 42000 || error4.QuotedTargetPort != 53 || !bytes.Equal(error4.QuotedPacket, quoted4) ||
		!bytes.Equal(error4.QuotedPayload, udp) {
		t.Fatalf("IPv4 ICMP error = %+v", error4)
	}
	if &error4.QuotedPacket[0] != &message4.Body[4] || &error4.QuotedPayload[0] != &message4.Body[4+20] {
		t.Fatal("public ICMP error parser copied its quoted packet")
	}

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	tcp := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51000)
	quoted6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)
	body6 := make([]byte, 4+len(quoted6))
	binary.BigEndian.PutUint32(body6[:4], 17)
	copy(body6[4:], quoted6)
	message6 := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8:ffff::1"), Destination: source6,
		Type: 4, Code: 0, Body: body6,
	}
	error6, err := message6.ICMPError()
	if err != nil {
		t.Fatalf("parse IPv6 ICMP error: %v", err)
	}
	if !message6.IsError() || error6.Pointer != 17 || error6.QuotedSourcePort != 443 || error6.QuotedTargetPort != 51000 ||
		error6.QuotedSource != source6 || error6.QuotedTarget != target6 || error6.QuotedProtocol != ProtocolTCP {
		t.Fatalf("IPv6 ICMP error = %+v", error6)
	}

	quotedNoNext := buildIPPacket(source6, target6, ProtocolNoNextHeader, []byte{1, 2, 3, 4}, 0, true)
	noNext := ICMPMessage{
		Source: message6.Source, Destination: source6, Type: 1, Code: 0,
		Body: append(make([]byte, 4), quotedNoNext...),
	}
	noNextError, err := noNext.ICMPError()
	if err != nil || noNextError.QuotedProtocol != ProtocolNoNextHeader || noNextError.QuotedPayload != nil ||
		!bytes.Equal(noNextError.QuotedPacket, quotedNoNext) {
		t.Fatalf("IPv6 No Next Header quote = %+v, %v", noNextError, err)
	}
}

func TestPublicICMPErrorConstruction(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	reporter4 := netip.MustParseAddr("198.51.100.254")
	udp := make([]byte, udpHeaderSize+16)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 7, true)[:20+udpHeaderSize]

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	reporter6 := netip.MustParseAddr("2001:db8:ffff::1")
	tcp := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcp[:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	quote6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)

	for _, test := range []struct {
		name                  string
		reporter, destination netip.Addr
		messageType, code     uint8
		mtu, pointer          uint32
		quote                 []byte
		protocol              int
	}{
		{name: "IPv4 fragmentation needed", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeFragmentationNeeded, mtu: 1280, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv4 parameter problem", reporter: reporter4, destination: source4, messageType: ICMPv4TypeParameterProblem, code: ICMPv4ParameterProblemCodePointer, pointer: 17, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv4 host unreachable", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeHost, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv6 packet too big", reporter: reporter6, destination: source6, messageType: ICMPv6TypePacketTooBig, code: ICMPCodeNone, mtu: 1280, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 parameter problem", reporter: reporter6, destination: source6, messageType: ICMPv6TypeParameterProblem, code: ICMPv6ParameterProblemCodeUnrecognizedNextHeader, pointer: 41, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 processing-limit parameter problem", reporter: reporter6, destination: source6, messageType: ICMPv6TypeParameterProblem, code: ICMPv6ParameterProblemCodeOptionTooBig, pointer: 48, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 P-Route error", reporter: reporter6, destination: source6, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodePRoute, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 time exceeded", reporter: reporter6, destination: source6, messageType: ICMPv6TypeTimeExceeded, code: ICMPv6TimeExceededCodeHopLimitInTransit, quote: quote6, protocol: ProtocolICMPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			quote := append([]byte(nil), test.quote...)
			wantQuote := append([]byte(nil), quote...)
			networkError := ICMPError{
				Reporter: test.reporter, Type: test.messageType, Code: test.code,
				MTU: test.mtu, Pointer: test.pointer, QuotedPacket: quote,
				QuotedSource: netip.IPv6Loopback(), QuotedTarget: netip.IPv6Loopback(),
				QuotedProtocol: 0xff, QuotedPayload: []byte("ignored"),
				QuotedSourcePort: 1, QuotedTargetPort: 2,
			}
			message, err := networkError.ICMPMessage(test.destination)
			if err != nil {
				t.Fatalf("construct ICMP error: %v", err)
			}
			if message.Source != test.reporter || message.Destination != test.destination || message.Type != test.messageType ||
				message.Code != test.code || !bytes.Equal(message.Body[4:], wantQuote) {
				t.Fatalf("constructed ICMP error = %+v", message)
			}
			if &message.Body[4] == &quote[0] {
				t.Fatal("ICMP error construction retained QuotedPacket")
			}
			quote[0] ^= 0xff
			if !bytes.Equal(message.Body[4:], wantQuote) {
				t.Fatal("mutating QuotedPacket changed constructed ICMP error")
			}

			wire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode constructed ICMP error: %v", err)
			}
			parsedMessage, err := (IPPacket{
				Source: message.Source, Destination: message.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse constructed ICMP error: %v", err)
			}
			parsedError, err := parsedMessage.ICMPError()
			if err != nil {
				t.Fatalf("decode constructed ICMP error: %v", err)
			}
			if parsedError.Reporter != test.reporter || parsedError.Type != test.messageType || parsedError.Code != test.code ||
				parsedError.MTU != test.mtu || parsedError.Pointer != test.pointer || !bytes.Equal(parsedError.QuotedPacket, wantQuote) {
				t.Fatalf("decoded constructed ICMP error = %+v", parsedError)
			}
		})
	}
}

func TestPublicICMPExtensionObjects(t *testing.T) {
	unknownData := []byte{1, 2, 3, 4}
	pointer := ICMPExtensionObject{}
	pointer.SetPointer(0x10203040)
	pointerData := pointer.Data
	objects := []ICMPExtensionObject{
		{Class: 0xfe, Type: 0x7d, Data: unknownData},
		pointer,
		{Class: ICMPExtensionClassExtendedInformation, Type: ICMPExtensionExtendedInformationTypePointer, Data: []byte{5, 6, 7, 8}},
	}
	var networkError ICMPError
	if err := networkError.SetExtensionObjects(objects); err != nil {
		t.Fatalf("SetExtensionObjects: %v", err)
	}
	wantEncoding := []byte{
		0, 8, 0xfe, 0x7d, 1, 2, 3, 4,
		0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 0x10, 0x20, 0x30, 0x40,
		0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 5, 6, 7, 8,
	}
	if !bytes.Equal(networkError.Extensions, wantEncoding) {
		t.Fatalf("extension encoding = %x, want %x", networkError.Extensions, wantEncoding)
	}
	unknownData[0] ^= 0xff
	pointerData[0] ^= 0xff
	if !bytes.Equal(networkError.Extensions, wantEncoding) {
		t.Fatal("SetExtensionObjects retained caller storage")
	}

	parsed, err := networkError.ExtensionObjects()
	if err != nil || len(parsed) != len(objects) {
		t.Fatalf("ExtensionObjects = %+v, %v", parsed, err)
	}
	if &parsed[0].Data[0] != &networkError.Extensions[icmpExtensionObjectHeaderSize] {
		t.Fatal("ExtensionObjects copied object data")
	}
	if value, ok := parsed[1].Pointer(); !ok || value != 0x10203040 {
		t.Fatalf("Pointer = %#x, %t", value, ok)
	}
	if value, ok := parsed[0].Pointer(); ok || value != 0 {
		t.Fatalf("unknown object Pointer = %#x, %t", value, ok)
	}

	before := append([]byte(nil), networkError.Extensions...)
	large := make([]byte, 40000)
	for _, test := range []struct {
		name    string
		objects []ICMPExtensionObject
		want    error
	}{
		{name: "unaligned data", objects: []ICMPExtensionObject{{Data: []byte{1}}}, want: syscall.EINVAL},
		{name: "object too large", objects: []ICMPExtensionObject{{Data: make([]byte, 65532)}}, want: syscall.EMSGSIZE},
		{name: "sequence too large", objects: []ICMPExtensionObject{{Data: large}, {Data: large}}, want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := networkError.SetExtensionObjects(test.objects); !errors.Is(err, test.want) {
				t.Fatalf("SetExtensionObjects error = %v, want %v", err, test.want)
			}
			if !bytes.Equal(networkError.Extensions, before) {
				t.Fatal("failed SetExtensionObjects changed receiver")
			}
		})
	}

	for _, encoded := range [][]byte{
		{0, 3, 1, 1},
		{0, 6, 1, 1, 0, 0},
		{0, 8, 1, 1},
		{0, 4, 1, 1, 0},
	} {
		if objects, err := (ICMPError{Extensions: encoded}).ExtensionObjects(); !errors.Is(err, syscall.EINVAL) || objects != nil {
			t.Fatalf("malformed ExtensionObjects(%x) = %+v, %v", encoded, objects, err)
		}
	}
	var nilError *ICMPError
	if err := nilError.SetExtensionObjects(objects); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetExtensionObjects error = %v", err)
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{}); err != nil || networkError.Extensions != nil {
		t.Fatalf("clear ExtensionObjects = %x, %v", networkError.Extensions, err)
	}
	if objects, err := networkError.ExtensionObjects(); err != nil || objects != nil {
		t.Fatalf("empty ExtensionObjects = %+v, %v", objects, err)
	}
	ordinary := cloneICMPError(ICMPError{QuotedPacket: []byte{1, 2, 3, 4}})
	if ordinary.Extensions != nil {
		t.Fatalf("ordinary clone has non-nil empty Extensions: %x", ordinary.Extensions)
	}
}

func TestPublicICMPExtensionRoundTrip(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	reporter4 := netip.MustParseAddr("198.51.100.254")
	udp := make([]byte, udpHeaderSize+5)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 9, true)

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	reporter6 := netip.MustParseAddr("2001:db8:ffff::1")
	tcp := make([]byte, tcpHeaderSize+1)
	binary.BigEndian.PutUint16(tcp[:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	quote6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)

	for _, test := range []struct {
		name                  string
		reporter, destination netip.Addr
		messageType, code     uint8
		mtu, pointer          uint32
		quote                 []byte
		lengthOffset, unit    int
	}{
		{name: "IPv4 destination unreachable", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeFragmentationNeeded, mtu: 1280, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv4 time exceeded", reporter: reporter4, destination: source4, messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv4 parameter problem", reporter: reporter4, destination: source4, messageType: ICMPv4TypeParameterProblem, code: ICMPv4ParameterProblemCodePointer, pointer: 17, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv6 destination unreachable", reporter: reporter6, destination: source6, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeNoRoute, quote: quote6, lengthOffset: 0, unit: 8},
		{name: "IPv6 time exceeded", reporter: reporter6, destination: source6, messageType: ICMPv6TypeTimeExceeded, code: ICMPv6TimeExceededCodeHopLimitInTransit, quote: quote6, lengthOffset: 0, unit: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			quote := append([]byte(nil), test.quote...)
			networkError := ICMPError{
				Reporter: test.reporter, Type: test.messageType, Code: test.code,
				MTU: test.mtu, Pointer: test.pointer, QuotedPacket: quote,
			}
			objects := []ICMPExtensionObject{{Class: 0xee, Type: 7, Data: []byte{1, 2, 3, 4}}}
			if err := networkError.SetExtensionObjects(objects); err != nil {
				t.Fatal(err)
			}
			wantExtensions := append([]byte(nil), networkError.Extensions...)
			message, err := networkError.ICMPMessage(test.destination)
			if err != nil {
				t.Fatalf("construct extended ICMP error: %v", err)
			}
			paddedLength := int(message.Body[test.lengthOffset]) * test.unit
			if paddedLength < icmpExtensionMinimumQuoteSize || paddedLength%test.unit != 0 || len(message.Body) != 4+paddedLength+icmpExtensionHeaderSize+len(wantExtensions) {
				t.Fatalf("extended body layout = length field %d, body %d", paddedLength, len(message.Body))
			}
			structure := message.Body[4+paddedLength:]
			if structure[0] != icmpExtensionVersion<<4 || structure[1] != 0 || checksum(structure) != 0 ||
				!bytes.Equal(structure[icmpExtensionHeaderSize:], wantExtensions) {
				t.Fatalf("extension structure = %x", structure)
			}
			quote[0] ^= 0xff
			networkError.Extensions[0] ^= 0xff
			if !bytes.Equal(message.Body[4:4+len(test.quote)], test.quote) ||
				!bytes.Equal(structure[icmpExtensionHeaderSize:], wantExtensions) {
				t.Fatal("ICMPMessage retained constructor storage")
			}

			parsed, err := message.ICMPError()
			if err != nil {
				t.Fatalf("parse extended ICMP error: %v", err)
			}
			if parsed.Reporter != test.reporter || parsed.Type != test.messageType || parsed.Code != test.code ||
				parsed.MTU != test.mtu || parsed.Pointer != test.pointer || !bytes.Equal(parsed.QuotedPacket, test.quote) ||
				!bytes.Equal(parsed.Extensions, wantExtensions) {
				t.Fatalf("parsed extended ICMP error = %+v", parsed)
			}
			parsedObjects, err := parsed.ExtensionObjects()
			if err != nil || len(parsedObjects) != 1 || parsedObjects[0].Class != 0xee || parsedObjects[0].Type != 7 ||
				!bytes.Equal(parsedObjects[0].Data, []byte{1, 2, 3, 4}) {
				t.Fatalf("parsed extension objects = %+v, %v", parsedObjects, err)
			}
			cloned := cloneICMPError(parsed)
			wantPacket := append([]byte(nil), cloned.QuotedPacket...)
			wantClonedExtensions := append([]byte(nil), cloned.Extensions...)
			parsed.QuotedPacket[0] ^= 0xff
			parsed.Extensions[0] ^= 0xff
			if !bytes.Equal(cloned.QuotedPacket, wantPacket) || !bytes.Equal(cloned.Extensions, wantClonedExtensions) {
				t.Fatal("cloneICMPError retained extended message storage")
			}
			if got, want := socketErrorSize(cloned), socketErrorMetadataSize+len(cloned.QuotedPacket)+len(cloned.Extensions); got != want {
				t.Fatalf("extended socket error size = %d, want %d", got, want)
			}
		})
	}
}

func TestPublicICMPv6HeadersTooLong(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::1")
	target := netip.MustParseAddr("2001:db8:1::1")
	reporter := netip.MustParseAddr("2001:db8:ffff::1")
	udp := make([]byte, udpHeaderSize)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	quote := buildIPPacket(source, target, ProtocolUDP, udp, 0, true)
	pointer := ICMPExtensionObject{}
	pointer.SetPointer(4096)
	networkError := ICMPError{
		Reporter: reporter, Type: ICMPv6TypeDestinationUnreachable,
		Code: ICMPv6DestinationUnreachableCodeHeadersTooLong, QuotedPacket: quote,
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{
		{Class: 0xfc, Type: 3}, pointer, pointer,
	}); err != nil {
		t.Fatal(err)
	}
	message, err := networkError.ICMPMessage(source)
	if err != nil || !message.IsError() {
		t.Fatalf("construct Headers Too Long = %+v, %v", message, err)
	}
	wire, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedMessage, err := (IPPacket{
		Source: reporter, Destination: source, Protocol: ProtocolICMPv6, HopLimit: 64, Payload: wire,
	}).ICMPMessage()
	if err != nil {
		t.Fatalf("parse Headers Too Long wire message: %v", err)
	}
	parsed, err := parsedMessage.ICMPError()
	if err != nil || parsed.Pointer != 0 || parsed.MTU != 0 {
		t.Fatalf("parse Headers Too Long = %+v, %v", parsed, err)
	}
	objects, err := parsed.ExtensionObjects()
	if err != nil || len(objects) != 3 {
		t.Fatalf("Headers Too Long objects = %+v, %v", objects, err)
	}
	for _, index := range []int{1, 2} {
		if value, ok := objects[index].Pointer(); !ok || value != 4096 {
			t.Fatalf("Headers Too Long Pointer %d = %d, %t", index, value, ok)
		}
	}
	control, err := socketErrorControlForRead(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var controlMessage SocketErrorControlMessage
	err = controlMessage.Parse(control)
	if err != nil || controlMessage.Info != 0 || controlMessage.Errno != 71 {
		t.Fatalf("Headers Too Long error control = %+v, %v", controlMessage, err)
	}

	missing := networkError
	missing.Extensions = nil
	if _, err = missing.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without extensions error = %v", err)
	}
	if err = missing.SetExtensionObjects([]ICMPExtensionObject{{Class: 0xfc, Type: 3}}); err != nil {
		t.Fatal(err)
	}
	if _, err = missing.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without Pointer error = %v", err)
	}
	plain := ICMPMessage{
		Source: reporter, Destination: source, Type: ICMPv6TypeDestinationUnreachable,
		Code: ICMPv6DestinationUnreachableCodeHeadersTooLong, Body: append(make([]byte, 4), quote...),
	}
	if !plain.IsError() {
		t.Fatal("Headers Too Long was not classified as an ICMP error")
	}
	if _, err = plain.ICMPError(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without wire Pointer error = %v", err)
	}
}

func TestPublicICMPExtensionValidation(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	reporter := netip.MustParseAddr("198.51.100.254")
	quote := buildIPPacket(source, target, ProtocolUDP, make([]byte, udpHeaderSize+5), 11, true)
	networkError := ICMPError{
		Reporter: reporter, Type: ICMPv4TypeDestinationUnreachable,
		Code: ICMPv4DestinationUnreachableCodeHost, QuotedPacket: quote,
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{{Class: 7, Type: 9, Data: []byte{1, 2, 3, 4}}}); err != nil {
		t.Fatal(err)
	}
	message, err := networkError.ICMPMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte(nil), message.Body...)
	paddedLength := int(base[1]) * 4
	structureOffset := 4 + paddedLength
	parse := func(body []byte) error {
		candidate := message
		candidate.Body = body
		_, parseErr := candidate.ICMPError()
		return parseErr
	}
	check := func(name string, mutate func([]byte) []byte, wantError bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			body := mutate(append([]byte(nil), base...))
			err := parse(body)
			if (err != nil) != wantError {
				t.Fatalf("ICMPError error = %v, wantError %t; body=%x", err, wantError, body)
			}
		})
	}
	check("checksum omitted", func(body []byte) []byte {
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, false)
	check("nonzero reserved", func(body []byte) []byte {
		body[structureOffset] |= 0x0f
		body[structureOffset+1] = 0xff
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, false)
	check("bad checksum", func(body []byte) []byte {
		body[len(body)-1] ^= 0x80
		return body
	}, true)
	check("unknown version", func(body []byte) []byte {
		body[structureOffset] = 3 << 4
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("quote shorter than minimum", func(body []byte) []byte {
		body[1] = 31
		return body
	}, true)
	check("no objects", func(body []byte) []byte {
		return body[:structureOffset+icmpExtensionHeaderSize]
	}, true)
	check("object shorter than header", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 3)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("object not aligned", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 6)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("object overrun", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 12)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("trailing partial object", func(body []byte) []byte {
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return append(body, 0)
	}, true)
	check("nonzero quote padding", func(body []byte) []byte {
		body[4+len(quote)] = 1
		return body
	}, true)

	lengthZero := append([]byte(nil), base...)
	lengthZero[1] = 0
	withoutExtensions := message
	withoutExtensions.Body = lengthZero
	parsed, err := withoutExtensions.ICMPError()
	if err != nil || len(parsed.Extensions) != 0 || len(parsed.QuotedPacket) != len(lengthZero)-4 {
		t.Fatalf("zero Length extension handling = %+v, %v", parsed, err)
	}

	quote6 := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	for _, test := range []ICMPError{
		{Reporter: netip.MustParseAddr("2001:db8::ff"), Type: ICMPv6TypePacketTooBig, Code: 0, MTU: 1280, QuotedPacket: quote6, Extensions: networkError.Extensions},
		{Reporter: netip.MustParseAddr("2001:db8::ff"), Type: ICMPv6TypeParameterProblem, Code: 0, QuotedPacket: quote6, Extensions: networkError.Extensions},
	} {
		if _, err := test.ICMPMessage(netip.MustParseAddr("2001:db8::1")); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("extensions on unsupported type %d error = %v", test.Type, err)
		}
	}

	longQuote := buildIPPacket(source, target, ProtocolUDP, make([]byte, 180), 12, true)
	truncated := networkError
	truncated.QuotedPacket = longQuote[:100]
	if _, err := truncated.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short truncated extension quote error = %v", err)
	}
	truncated.QuotedPacket = longQuote[:130]
	truncatedMessage, err := truncated.ICMPMessage(source)
	if err != nil {
		t.Fatalf("128-byte truncated extension quote: %v", err)
	}
	truncatedParsed, err := truncatedMessage.ICMPError()
	if err != nil || len(truncatedParsed.QuotedPacket) != 132 {
		t.Fatalf("aligned truncated quote = %d bytes, %v", len(truncatedParsed.QuotedPacket), err)
	}
	oversized := networkError
	oversized.QuotedPacket = buildIPPacket(source, target, ProtocolUDP, make([]byte, 1001), 13, true)
	if _, err := oversized.ICMPMessage(source); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("unrepresentable IPv4 quote error = %v", err)
	}
}

func TestPublicICMPErrorConstructionFailures(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 1, true)
	quote6 := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	base := ICMPError{
		Reporter: netip.MustParseAddr("198.51.100.254"),
		Type:     ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHost,
		QuotedPacket: quote4,
	}
	for _, test := range []struct {
		name         string
		networkError ICMPError
		destination  netip.Addr
		want         error
	}{
		{name: "invalid reporter", networkError: func() ICMPError { value := base; value.Reporter = netip.Addr{}; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "invalid destination", networkError: base, destination: netip.Addr{}, want: syscall.EINVAL},
		{name: "zoned reporter", networkError: ICMPError{Reporter: netip.MustParseAddr("fe80::1").WithZone("zone"), Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeNoRoute, QuotedPacket: quote6}, destination: netip.MustParseAddr("2001:db8::1"), want: syscall.EINVAL},
		{name: "cross-family destination", networkError: base, destination: netip.MustParseAddr("2001:db8::1"), want: syscall.EINVAL},
		{name: "invalid code", networkError: func() ICMPError { value := base; value.Code = 16; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "missing quote", networkError: func() ICMPError { value := base; value.QuotedPacket = nil; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "cross-family quote", networkError: func() ICMPError { value := base; value.QuotedPacket = quote6; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "unrelated MTU", networkError: func() ICMPError { value := base; value.MTU = 1; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "unrelated pointer", networkError: func() ICMPError { value := base; value.Pointer = 1; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "IPv4 MTU overflow", networkError: func() ICMPError {
			value := base
			value.Code = ICMPv4DestinationUnreachableCodeFragmentationNeeded
			value.MTU = 1 << 16
			return value
		}(), destination: source4, want: syscall.EINVAL},
		{name: "IPv4 pointer overflow", networkError: func() ICMPError {
			value := base
			value.Type = ICMPv4TypeParameterProblem
			value.Code = ICMPv4ParameterProblemCodePointer
			value.Pointer = 1 << 8
			return value
		}(), destination: source4, want: syscall.EINVAL},
		{name: "oversized quote", networkError: func() ICMPError {
			value := base
			value.QuotedPacket = append(append([]byte(nil), quote4...), make([]byte, 65535-8-len(quote4)+1)...)
			return value
		}(), destination: source4, want: syscall.EMSGSIZE},
		{name: "oversized malformed quote", networkError: func() ICMPError {
			value := base
			value.QuotedPacket = make([]byte, 65535-8+1)
			return value
		}(), destination: source4, want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			message, err := test.networkError.ICMPMessage(test.destination)
			if !errors.Is(err, test.want) || !reflect.ValueOf(message).IsZero() {
				t.Fatalf("ICMPMessage = %+v, %v; want zero value and %v", message, err, test.want)
			}
		})
	}
}

func TestPublicICMPErrorFailures(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.254"), Destination: netip.MustParseAddr("192.0.2.1"),
		Type: 3, Code: 1, Body: make([]byte, 4),
	}
	v6Quote := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	mappedQuote := append([]byte(nil), v6Quote...)
	mappedSource := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	copy(mappedQuote[8:24], mappedSource[:])
	crossFamily := v4
	crossFamily.Body = append(make([]byte, 4), v6Quote...)
	mapped := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8::ff"), Destination: netip.MustParseAddr("2001:db8::1"),
		Type: 1, Code: 0, Body: append(make([]byte, 4), mappedQuote...),
	}
	invalidCode := v4
	invalidCode.Code = 16
	shortBody := v4
	shortBody.Body = make([]byte, 3)
	for _, test := range []struct {
		name       string
		message    ICMPMessage
		classified bool
	}{
		{name: "missing quote", message: v4, classified: true},
		{name: "cross-family quote", message: crossFamily, classified: true},
		{name: "mapped IPv6 quote", message: mapped, classified: true},
		{name: "invalid code", message: invalidCode},
		{name: "short body", message: shortBody, classified: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.message.IsError() != test.classified {
				t.Fatalf("IsError classification for %s is inconsistent", test.name)
			}
			if result, err := test.message.ICMPError(); !errors.Is(err, syscall.EINVAL) || !reflect.ValueOf(result).IsZero() {
				t.Fatalf("ICMPError = %+v, %v; want zero value and EINVAL", result, err)
			}
		})
	}
}

func TestPublicICMPMessageEchoReply(t *testing.T) {
	tests := []struct {
		name      string
		request   ICMPMessage
		source    netip.Addr
		protocol  int
		replyType uint8
	}{
		{
			name: "IPv4 mapped",
			request: ICMPMessage{
				Source: netip.MustParseAddr("::ffff:192.0.2.1"), Destination: netip.MustParseAddr("::ffff:198.51.100.1"),
				Type: 8, Body: []byte{0x12, 0x34, 0, 7, 'v', '4'},
			},
			source: netip.MustParseAddr("::ffff:198.51.100.2"), protocol: ProtocolICMPv4, replyType: 0,
		},
		{
			name: "IPv6 multicast request",
			request: ICMPMessage{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("ff02::1"),
				Type: 128, Body: []byte{0x56, 0x78, 0, 9, 'v', '6'},
			},
			source: netip.MustParseAddr("2001:db8:1::1"), protocol: ProtocolICMPv6, replyType: 129,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestWire, err := test.request.AppendBinary(nil)
			if err != nil {
				t.Fatalf("append Echo Request: %v", err)
			}
			request, err := (IPPacket{
				Source: test.request.Source.Unmap(), Destination: test.request.Destination.Unmap(),
				Protocol: test.protocol, HopLimit: 64, Payload: requestWire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse Echo Request: %v", err)
			}
			reply, err := request.EchoReply(test.source)
			if err != nil {
				t.Fatalf("EchoReply: %v", err)
			}
			if reply.Source != test.source.Unmap() || reply.Destination != test.request.Source.Unmap() ||
				reply.Type != test.replyType || reply.Code != 0 || !bytes.Equal(reply.Body, test.request.Body) {
				t.Fatalf("EchoReply = %+v", reply)
			}
			if &reply.Body[0] != &request.Body[0] {
				t.Fatal("EchoReply copied Body")
			}
			if reply.IsEchoRequest() {
				t.Fatal("Echo Reply classified as a request")
			}

			backing := &requestWire[0]
			wire, err := reply.AppendBinary(requestWire[:0])
			if err != nil {
				t.Fatalf("append Echo Reply: %v", err)
			}
			if &wire[0] != backing {
				t.Fatal("in-place Echo Reply encoding replaced wire backing")
			}
			parsed, err := (IPPacket{
				Source: reply.Source, Destination: reply.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse Echo Reply: %v", err)
			}
			if parsed.Type != test.replyType || parsed.Code != 0 || !bytes.Equal(parsed.Body, test.request.Body) {
				t.Fatalf("parsed Echo Reply = %+v", parsed)
			}
		})
	}
}

func TestPublicICMPMessageEchoReplyErrors(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Type: 8, Body: []byte{0, 1, 0, 2},
	}
	v6 := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Type: 128, Body: []byte{0, 1, 0, 2},
	}
	nonEcho := v4
	nonEcho.Type = 0
	nonzeroCode := v4
	nonzeroCode.Code = 1
	shortBody := v4
	shortBody.Body = make([]byte, 3)
	zonedRequest := v6
	zonedRequest.Source = zonedRequest.Source.WithZone("test")
	oversizedBody := v4
	oversizedBody.Body = make([]byte, 65532)
	tests := []struct {
		name    string
		request ICMPMessage
		source  netip.Addr
		want    error
	}{
		{name: "non-Echo", request: nonEcho, source: v4.Destination, want: syscall.EINVAL},
		{name: "nonzero code", request: nonzeroCode, source: v4.Destination, want: syscall.EINVAL},
		{name: "short body", request: shortBody, source: v4.Destination, want: syscall.EINVAL},
		{name: "invalid source", request: v4, source: netip.Addr{}, want: syscall.EINVAL},
		{name: "cross-family source", request: v4, source: v6.Destination, want: syscall.EINVAL},
		{name: "zoned source", request: v6, source: v6.Destination.WithZone("test"), want: syscall.EINVAL},
		{name: "zoned request", request: zonedRequest, source: v6.Destination, want: syscall.EINVAL},
		{name: "oversized body", request: oversizedBody, source: v4.Destination, want: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reply, err := test.request.EchoReply(test.source)
			if !errors.Is(err, test.want) {
				t.Fatalf("EchoReply error = %v, want %v", err, test.want)
			}
			if reply.Source.IsValid() || reply.Destination.IsValid() || reply.Body != nil {
				t.Fatalf("failed EchoReply returned %+v", reply)
			}
		})
	}
}

func TestPublicICMPMessageCodecErrorsDoNotModifyDestination(t *testing.T) {
	message := ICMPMessage{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Type: 8, Body: make([]byte, 4)}
	message.Destination = netip.MustParseAddr("2001:db8::1")
	prefix := []byte{4, 5, 6}
	want := append([]byte(nil), prefix...)
	if got, err := message.AppendBinary(prefix); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(prefix, want) {
		t.Fatalf("invalid ICMP AppendBinary: got=%x error=%v", got, err)
	}
	message.Destination = netip.MustParseAddr("192.0.2.2")
	message.Body = nil
	if _, err := message.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short ICMP body error = %v", err)
	}
	shortMessage := []byte{200, 0, 0, 0}
	binary.BigEndian.PutUint16(shortMessage[2:4], checksum(shortMessage))
	packet := IPPacket{Source: message.Source, Destination: message.Destination, Protocol: ProtocolICMPv4, Payload: shortMessage}
	if _, err := packet.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short ICMP parse error = %v", err)
	}
	message.Body = make([]byte, 4)
	message.Source = netip.MustParseAddr("2001:db8::1").WithZone("test")
	message.Destination = netip.MustParseAddr("2001:db8::2")
	if _, err := message.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned ICMP message error = %v", err)
	}
}

func FuzzPublicICMPMessageCodec(f *testing.F) {
	seed := ICMPMessage{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Type: 128, Body: []byte{0, 1, 0, 2, 3}}
	wire, err := seed.AppendBinary(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{Source: seed.Source, Destination: seed.Destination, Protocol: ProtocolICMPv6, HopLimit: 64, Payload: wire}
		message, err := packet.ICMPMessage()
		if err != nil {
			return
		}
		encoded, err := message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed ICMP could not be encoded: %v", err)
		}
		assertICMPMessageWire(t, message, encoded)
		packet.Payload = encoded
		reparsed, err := packet.ICMPMessage()
		if err != nil {
			t.Fatalf("encoded ICMP could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place ICMP append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func FuzzPublicICMPEchoConstruction(f *testing.F) {
	f.Add(false, false, uint16(0x1234), uint16(7), []byte("IPv4 Echo"))
	f.Add(true, true, uint16(0xabcd), uint16(9), []byte("IPv6 Echo"))
	f.Fuzz(func(t *testing.T, ipv6, reply bool, identifier, sequence uint16, payload []byte) {
		if len(payload) > 65535-8 {
			payload = payload[:65535-8]
		}
		wantPayload := append([]byte(nil), payload...)
		message := ICMPMessage{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
		}
		protocol := ProtocolICMPv4
		if ipv6 {
			message.Source = netip.MustParseAddr("2001:db8::1")
			message.Destination = netip.MustParseAddr("2001:db8::2")
			protocol = ProtocolICMPv6
		}
		var err error
		if reply {
			err = message.SetEchoReply(identifier, sequence, payload)
		} else {
			err = message.SetEchoRequest(identifier, sequence, payload)
		}
		if err != nil {
			t.Fatalf("construct Echo: %v", err)
		}
		for index := range payload {
			payload[index] ^= 0xff
		}
		gotIdentifier, gotSequence, gotPayload, ok := message.Echo()
		if !ok || gotIdentifier != identifier || gotSequence != sequence || !bytes.Equal(gotPayload, wantPayload) ||
			message.IsEchoReply() != reply || message.IsEchoRequest() == reply {
			t.Fatalf("constructed Echo = %+v, fields %#x/%#x/%x/%t", message, gotIdentifier, gotSequence, gotPayload, ok)
		}
		wire, err := message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("encode Echo: %v", err)
		}
		assertICMPMessageWire(t, message, wire)
		parsed, err := (IPPacket{
			Source: message.Source, Destination: message.Destination,
			Protocol: protocol, HopLimit: 64, Payload: wire,
		}).ICMPMessage()
		if err != nil {
			t.Fatalf("parse Echo: %v", err)
		}
		gotIdentifier, gotSequence, gotPayload, ok = parsed.Echo()
		if !ok || gotIdentifier != identifier || gotSequence != sequence || !bytes.Equal(gotPayload, wantPayload) {
			t.Fatalf("parsed Echo fields = %#x/%#x/%x/%t", gotIdentifier, gotSequence, gotPayload, ok)
		}
	})
}

func TestICMPEchoReply(t *testing.T) {
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
			icmp := make([]byte, 12)
			protocol := byte(ProtocolICMPv4)
			icmp[0] = 8
			if test.local.Is6() {
				protocol = ProtocolICMPv6
				icmp[0] = 128
			}
			binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
			copy(icmp[8:], []byte("ping"))
			if test.local.Is4() {
				binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			} else {
				binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(test.remote, test.local, protocol, icmp))
			}
			request := buildIPPacket(test.remote, test.local, protocol, icmp, 1, true)
			if err := writeTestPacket(stack, request); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				parsed, ok := parseIPPacket(response, false)
				if !ok || parsed.source != test.local || parsed.target != test.remote || len(parsed.payload) != len(icmp) {
					t.Fatalf("invalid ICMP response: %x", response)
				}
				expectedType := byte(0)
				if test.local.Is6() {
					expectedType = 129
				}
				if parsed.payload[0] != expectedType || !bytes.Equal(parsed.payload[4:], icmp[4:]) {
					t.Fatalf("ICMP response payload = %x", parsed.payload)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for ICMP reply")
			}
		})
	}
}

func TestUDPPortUnreachable(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		typeCode      [2]byte
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.41"), remote: netip.MustParseAddr("198.51.100.41"), typeCode: [2]byte{3, 3}},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::41"), remote: netip.MustParseAddr("2001:db8:1::41"), typeCode: [2]byte{1, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			packet := buildTestUDP(test.remote, test.local, 41001, 41002, []byte("unbound"))
			if err := writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				parsed, ok := parseIPPacket(response, false)
				if !ok || len(parsed.payload) < 8 || parsed.payload[0] != test.typeCode[0] || parsed.payload[1] != test.typeCode[1] {
					t.Fatalf("port-unreachable response = %x, parsed = %v", response, ok)
				}
				remoteError, ok := parseICMPError(parsed)
				if !ok || remoteError.QuotedSource != test.remote || remoteError.QuotedTarget != test.local || remoteError.QuotedProtocol != ProtocolUDP || len(remoteError.QuotedPayload) < 4 || binary.BigEndian.Uint16(remoteError.QuotedPayload[0:2]) != 41001 || binary.BigEndian.Uint16(remoteError.QuotedPayload[2:4]) != 41002 {
					t.Fatalf("quoted UDP tuple = %+v, parsed = %v", remoteError, ok)
				}
				if text := remoteError.Error(); text == "" {
					t.Fatal("ICMP error formatted as an empty string")
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for port-unreachable response")
			}
		})
	}
}

func TestUDPPathMTUAndICMPCorrelation(t *testing.T) {
	for _, test := range []struct {
		name                   string
		local, remote, unknown netip.Addr
		mtu                    uint32
		payloadSize            int
	}{
		{
			name: "IPv4", local: netip.MustParseAddr("192.0.2.1"), remote: netip.MustParseAddr("192.0.2.2"),
			unknown: netip.MustParseAddr("192.0.2.3"), mtu: 1200, payloadSize: 1250,
		},
		{
			name: "IPv6", local: netip.MustParseAddr("2001:db8::1"), remote: netip.MustParseAddr("2001:db8::2"),
			unknown: netip.MustParseAddr("2001:db8::3"), mtu: 1280, payloadSize: 1300,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 128
			if test.local.Is4() {
				bits = 32
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			destination := netip.AddrPortFrom(test.remote, 5353)
			connection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, test.payloadSize)
			if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
				t.Fatal(err)
			}
			original := readOutboundPacket(t, stack)
			if len(original) > 1400 {
				t.Fatalf("initial packet size = %d", len(original))
			}
			localPort := connection.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			unknownQuote := buildTestUDP(test.local, test.unknown, localPort, destination.Port(), payload)
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			errorPacket := buildTestPacketTooBig(test.remote, test.local, original, test.mtu)
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			if info := connection.(*UDPConn).Info(); info.ErrorQueueEntries != 0 || info.LastError != nil || info.ICMPErrors != 0 {
				t.Fatalf("unconnected UDP retained an implicit ICMP error: %+v", info)
			}
			if count, readErr := connection.(*UDPConn).ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("unconnected UDP read after ICMP = %d, %v", count, readErr)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("PMTU after ignored ICMP = %d, want %d", learned, test.mtu)
			}
			if err = connection.(*UDPConn).SetPathMTUDiscovery(PathMTUDiscoveryWant); err != nil {
				t.Fatal(err)
			}
			if err = connection.(*UDPConn).SetReceiveErrors(true); err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			for index := range errorPacket {
				errorPacket[index] = 0
			}
			var reported *net.OpError
			reported, err = connection.(*UDPConn).ReadError()
			if err != nil {
				t.Fatal(err)
			}
			var operationError *net.OpError
			if !errors.As(reported, &operationError) {
				t.Fatalf("ReadError result = %#v, want UDP error for %s", reported, destination)
			}
			errorAddress, ok := operationError.Addr.(*net.UDPAddr)
			if !ok || errorAddress.AddrPort() != destination {
				t.Fatalf("ReadError address = %#v, want %s", operationError.Addr, destination)
			}
			var icmpError ICMPError
			if !errors.As(reported, &icmpError) || icmpError.MTU != test.mtu {
				t.Fatalf("ReadError result does not expose ICMP Packet Too Big: %#v", reported)
			}
			if icmpError.QuotedSourcePort != localPort || icmpError.QuotedTargetPort != destination.Port() || len(icmpError.QuotedPayload) < udpHeaderSize {
				t.Fatalf("retained ICMP quote = %+v payload %x", icmpError, icmpError.QuotedPayload)
			}
			if queued, readErr := connection.(*UDPConn).ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("unmatched UDP ICMP error was queued: %#v, %v", queued, readErr)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("learned PMTU = %d, want %d", learned, test.mtu)
			}
			if unknown := stack.mtuFor(test.unknown); unknown != 1400 {
				t.Fatalf("unmatched target PMTU = %d, want 1400", unknown)
			}
			if err = connection.(*UDPConn).SetPathMTUDiscovery(PathMTUDiscoveryDont); err != nil {
				t.Fatal(err)
			}
			if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 2; index++ {
				packet := readOutboundPacket(t, stack)
				if len(packet) > int(test.mtu) {
					t.Fatalf("PMTU fragment %d size = %d, want <= %d", index, len(packet), test.mtu)
				}
			}
		})
	}
}

func TestUDPExtendedICMPErrorCorrelation(t *testing.T) {
	for _, mode := range []string{"strict", "offload"} {
		for _, test := range []struct {
			name          string
			local, remote netip.Addr
			messageType   uint8
			code          uint8
		}{
			{
				name: "IPv4", local: netip.MustParseAddr("192.0.2.210"), remote: netip.MustParseAddr("192.0.2.211"),
				messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit,
			},
			{
				name: "IPv6", local: netip.MustParseAddr("2001:db8::210"), remote: netip.MustParseAddr("2001:db8::211"),
				messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeHeadersTooLong,
			},
		} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				bits, protocol := 32, ProtocolICMPv4
				if test.local.Is6() {
					bits, protocol = 128, ProtocolICMPv6
				}
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				var offload RXChecksumOffload
				offload.SetICMPv4(mode == "offload" && test.local.Is4()).SetICMPv6(mode == "offload" && test.local.Is6())
				stack.SetRXChecksumOffload(offload)
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				connection, err := stack.ListenUDP(context.Background(), "udp", wildcardUDP(test.remote))
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if err = connection.(*UDPConn).SetReceiveErrors(true); err != nil {
					t.Fatal(err)
				}
				target := netip.AddrPortFrom(test.remote, 5353)
				payload := []byte("extended-error-correlation")
				if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(target)); err != nil {
					t.Fatal(err)
				}
				original := readOutboundPacket(t, stack)
				networkError := ICMPError{
					Reporter: test.remote, Type: test.messageType, Code: test.code,
					QuotedPacket: original,
				}
				objects := []ICMPExtensionObject{{Class: 0xfe, Type: 7, Data: []byte{1, 2, 3, 4}}}
				if test.local.Is6() {
					var pointer ICMPExtensionObject
					pointer.SetPointer(uint32(len(original) + 4096))
					objects = []ICMPExtensionObject{pointer}
				}
				if err = networkError.SetExtensionObjects(objects); err != nil {
					t.Fatal(err)
				}
				message, err := networkError.ICMPMessage(test.local)
				if err != nil {
					t.Fatal(err)
				}
				icmpWire, err := message.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				errorPacket, err := (IPPacket{
					Source: test.remote, Destination: test.local,
					Protocol: protocol, HopLimit: 64, Payload: icmpWire,
				}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				badMessage := message
				badMessage.Body = append([]byte(nil), message.Body...)
				extension := badMessage.Body[len(badMessage.Body)-len(networkError.Extensions):]
				value := binary.BigEndian.Uint16(extension[2:4]) ^ 1
				if value == 0 {
					value = 2
				}
				binary.BigEndian.PutUint16(extension[2:4], value)
				badICMP, err := badMessage.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				badPacket, err := (IPPacket{
					Source: test.remote, Destination: test.local,
					Protocol: protocol, HopLimit: 64, Payload: badICMP,
				}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				headerSize := 20
				if test.local.Is6() {
					headerSize = 40
				}
				rejected := [][]byte{badPacket}
				badOuter := append([]byte(nil), errorPacket...)
				badOuter[headerSize+2] ^= 1
				if mode == "offload" {
					badBoth := append([]byte(nil), badPacket...)
					badBoth[headerSize+2] ^= 1
					rejected = append(rejected, badBoth)
					errorPacket = badOuter
				} else {
					rejected = append(rejected, badOuter)
				}
				_, _ = stack.Write(rejected, 0)
				if n, readErr := connection.(*UDPConn).ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); n != 0 || !errors.Is(readErr, syscall.EAGAIN) {
					t.Fatalf("invalid ICMP ordinary error = %d, %v", n, readErr)
				}
				if reported, readErr := connection.(*UDPConn).ReadError(); reported != nil || !errors.Is(readErr, syscall.EAGAIN) {
					t.Fatalf("invalid ICMP extended error = %v, %v", reported, readErr)
				}
				if err = writeTestPacket(stack, errorPacket); err != nil {
					t.Fatal(err)
				}
				for index := range errorPacket {
					errorPacket[index] = 0
				}
				for index := range networkError.Extensions {
					networkError.Extensions[index] = 0
				}
				var ordinary ICMPError
				if n, readErr := connection.(*UDPConn).ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); n != 0 ||
					!errors.As(readErr, &ordinary) || ordinary.Type != test.messageType || ordinary.Code != test.code || !bytes.Equal(ordinary.QuotedPacket, original) {
					t.Fatalf("ordinary extended ICMP error = %d, %v", n, readErr)
				}
				reported, readErr := connection.(*UDPConn).ReadError()
				if readErr != nil {
					t.Fatal(readErr)
				}
				var operationError *net.OpError
				if !errors.As(reported, &operationError) {
					t.Fatalf("ReadError result = %#v, want extended network error", reported)
				}
				address, ok := operationError.Addr.(*net.UDPAddr)
				if !ok || address.AddrPort() != target {
					t.Fatalf("extended error address = %#v, want %s", operationError.Addr, target)
				}
				var received ICMPError
				if !errors.As(reported, &received) || received.Type != test.messageType || received.Code != test.code ||
					!bytes.Equal(received.QuotedPacket, original) || len(received.QuotedPayload) != udpHeaderSize+len(payload) {
					t.Fatalf("retained extended ICMP error = %+v, payload %x", received, received.QuotedPayload)
				}
				receivedObjects, err := received.ExtensionObjects()
				if err != nil || len(receivedObjects) != 1 {
					t.Fatalf("retained extension objects = %+v, %v", receivedObjects, err)
				}
				if test.local.Is6() {
					if pointer, ok := receivedObjects[0].Pointer(); !ok || pointer != uint32(len(original)+4096) {
						t.Fatalf("retained Headers Too Long Pointer = %d, %t", pointer, ok)
					}
				} else if !bytes.Equal(receivedObjects[0].Data, []byte{1, 2, 3, 4}) {
					t.Fatalf("retained unknown extension = %+v", receivedObjects[0])
				}
				if queued, readErr := connection.(*UDPConn).ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
					t.Fatalf("unexpected extra extended ICMP error = %v, %v", queued, readErr)
				}
			})
		}
	}
}

func TestIPConnPathMTUAndICMPCorrelation(t *testing.T) {
	for _, test := range []struct {
		name                   string
		local, remote, unknown netip.Addr
		mtu                    uint32
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.180"), remote: netip.MustParseAddr("192.0.2.181"), unknown: netip.MustParseAddr("192.0.2.182"), mtu: 1200},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::180"), remote: netip.MustParseAddr("2001:db8::181"), unknown: netip.MustParseAddr("2001:db8::182"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.local.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 256)
			if _, err = connection.WriteTo(payload, ipNetAddr(test.remote)); err != nil {
				t.Fatal(err)
			}
			original := readOutboundPacket(t, stack)
			unknownQuote := buildIPPacket(test.local, test.unknown, 99, payload, 1, true)
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			errorPacket := buildTestPacketTooBig(test.remote, test.local, original, test.mtu)
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			if info := connection.(*IPConn).Info(); info.ErrorQueueEntries != 0 || info.LastError != nil || info.ICMPErrors != 0 {
				t.Fatalf("unconnected IP retained an implicit ICMP error: %+v", info)
			}
			if count, readErr := connection.(*IPConn).ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("unconnected IP read after ICMP = %d, %v", count, readErr)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("PMTU after ignored ICMP = %d, want %d", learned, test.mtu)
			}
			if err = connection.(*IPConn).SetReceiveErrors(true); err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			reported, readErr := connection.(*IPConn).ReadError()
			if readErr != nil {
				t.Fatal(readErr)
			}
			var operationError *net.OpError
			if !errors.As(reported, &operationError) {
				t.Fatalf("ReadError result = %#v, want IP socket network error", reported)
			}
			errorAddress, ok := operationError.Addr.(*net.IPAddr)
			if !ok || errorAddress.String() != test.remote.String() {
				t.Fatalf("ReadError address = %#v, want %s", operationError.Addr, test.remote)
			}
			var icmpError ICMPError
			if !errors.As(reported, &icmpError) || icmpError.MTU != test.mtu || icmpError.QuotedProtocol != 99 {
				t.Fatalf("ReadError result does not expose matching ICMP error: %#v", reported)
			}
			if queued, readErr := connection.(*IPConn).ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("unmatched IP ICMP error was queued: %#v, %v", queued, readErr)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("learned PMTU = %d, want %d", learned, test.mtu)
			}
			if unknown := stack.mtuFor(test.unknown); unknown != 1400 {
				t.Fatalf("unmatched target PMTU = %d, want 1400", unknown)
			}
			info := connection.(*IPConn).Info()
			if info.ICMPErrors != 1 || info.LastError == nil || info.PathMTU != 0 {
				t.Fatalf("IP socket diagnostics = %+v", info)
			}
		})
	}
}

func TestDatagramPathMTUDiscoverySocketPolicy(t *testing.T) {
	type pathMTUSocket interface {
		net.Conn
		ReadBatch([]SocketMessage, int) (int, error)
		SetPathMTUDiscovery(PathMTUDiscovery) error
		PathMTUDiscovery() (PathMTUDiscovery, error)
	}
	protocols := []struct {
		name string
		open func(*Stack, netip.Addr) (pathMTUSocket, error)
	}{
		{name: "UDP", open: func(stack *Stack, remote netip.Addr) (pathMTUSocket, error) {
			connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5353))
			if err != nil {
				return nil, err
			}
			return connection.(*UDPConn), nil
		}},
		{name: "IP", open: func(stack *Stack, remote netip.Addr) (pathMTUSocket, error) {
			connection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
			if err != nil {
				return nil, err
			}
			return connection.(*IPConn), nil
		}},
	}
	modes := []struct {
		name    string
		mode    PathMTUDiscovery
		updates bool
	}{
		{name: "dont", mode: PathMTUDiscoveryDont, updates: true},
		{name: "want", mode: PathMTUDiscoveryWant, updates: true},
		{name: "do", mode: PathMTUDiscoveryDo, updates: true},
		{name: "probe", mode: PathMTUDiscoveryProbe, updates: true},
		{name: "interface", mode: PathMTUDiscoveryInterface},
		{name: "omit", mode: PathMTUDiscoveryOmit},
	}
	for _, protocol := range protocols {
		for _, mode := range modes {
			t.Run(protocol.name+"/"+mode.name, func(t *testing.T) {
				local := netip.MustParseAddr("192.0.2.190")
				remote := netip.MustParseAddr("198.51.100.190")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				connection, err := protocol.open(stack, remote)
				if err != nil {
					t.Fatal(err)
				}
				if initial, getErr := connection.PathMTUDiscovery(); getErr != nil || initial != PathMTUDiscoveryDont {
					t.Fatalf("initial PathMTUDiscovery = %v, %v", initial, getErr)
				}
				if err = connection.SetPathMTUDiscovery(mode.mode); err != nil {
					t.Fatal(err)
				}
				if selected, getErr := connection.PathMTUDiscovery(); getErr != nil || selected != mode.mode {
					t.Fatalf("PathMTUDiscovery = %v, %v, want %v", selected, getErr, mode.mode)
				}
				if err = connection.SetPathMTUDiscovery(PathMTUDiscovery(99)); !errors.Is(err, syscall.EINVAL) {
					t.Fatalf("invalid SetPathMTUDiscovery = %v", err)
				}
				if selected, getErr := connection.PathMTUDiscovery(); getErr != nil || selected != mode.mode {
					t.Fatalf("invalid option changed mode to %v, %v", selected, getErr)
				}
				if _, err = connection.Write([]byte("probe")); err != nil {
					t.Fatal(err)
				}
				quoted := readOutboundPacket(t, stack)
				if err = writeTestPacket(stack, buildTestPacketTooBig(remote, local, quoted, 1200)); err != nil {
					t.Fatal(err)
				}
				wantMTU := 1400
				if mode.updates {
					wantMTU = 1200
				}
				if mtu := stack.mtuFor(remote); mtu != wantMTU {
					t.Fatalf("PMTU after Packet Too Big = %d, want %d", mtu, wantMTU)
				}
				count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait)
				if mode.mode == PathMTUDiscoveryDont {
					if count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
						t.Fatalf("PMTUDISC_DONT socket error = %d, %#v, want EAGAIN", count, readErr)
					}
				} else {
					var networkError ICMPError
					if count != 0 || !errors.As(readErr, &networkError) || networkError.MTU != 1200 {
						t.Fatalf("socket error = %d, %#v, want Packet Too Big", count, readErr)
					}
				}
				if err = connection.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err = connection.PathMTUDiscovery(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("PathMTUDiscovery after Close = %v", err)
				}
				if err = connection.SetPathMTUDiscovery(mode.mode); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("SetPathMTUDiscovery after Close = %v", err)
				}
			})
		}
	}
}

func TestConnectedDatagramICMPOrdinaryAndExtendedErrors(t *testing.T) {
	type errorSocket interface {
		net.Conn
		ReadBatch([]SocketMessage, int) (int, error)
		WriteBatch([]SocketMessage, int) (int, error)
		ReadError() (*net.OpError, error)
		SetReceiveErrors(bool) error
	}
	for _, family := range []struct {
		name, udpNetwork, ipNetwork string
		local, remote               netip.Addr
		icmpProtocol                int
		hardType, hardCode          byte
		softType                    byte
	}{
		{"IPv4", "udp4", "ip4:99", netip.MustParseAddr("192.0.2.193"), netip.MustParseAddr("198.51.100.193"), ProtocolICMPv4,
			ICMPv4TypeDestinationUnreachable, ICMPv4DestinationUnreachableCodePort, ICMPv4TypeTimeExceeded},
		{"IPv6", "udp6", "ip6:99", netip.MustParseAddr("2001:db8::193"), netip.MustParseAddr("2001:db8::194"), ProtocolICMPv6,
			ICMPv6TypeDestinationUnreachable, ICMPv6DestinationUnreachableCodePort, ICMPv6TypeTimeExceeded},
	} {
		for _, protocol := range []string{"UDP", "IP payload", "IP header-included"} {
			t.Run(family.name+"/"+protocol, func(t *testing.T) {
				bits := 32
				if family.local.Is6() {
					bits = 128
				}
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(family.local, bits)}, MTU: 1400})
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				var opened net.Conn
				if protocol == "UDP" {
					opened, err = stack.DialUDP(context.Background(), family.udpNetwork, netip.AddrPort{}, netip.AddrPortFrom(family.remote, 5353))
				} else {
					opened, err = stack.DialIP(context.Background(), family.ipNetwork, netip.Addr{}, family.remote)
				}
				if err != nil {
					t.Fatal(err)
				}
				connection := opened.(errorSocket)
				defer connection.Close()
				writePayload := []byte("request")
				if protocol == "IP header-included" {
					if err = opened.(*IPConn).SetIPHeaderIncludedOnWrite(true); err != nil {
						t.Fatal(err)
					}
					writePayload, err = (IPPacket{Source: family.local, Destination: family.remote, Protocol: 99, HopLimit: 64, Payload: writePayload}).MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
				}

				inject := func(quoted []byte, messageType, code byte) {
					t.Helper()
					message, marshalErr := (ICMPError{Reporter: family.remote, Type: messageType, Code: code, QuotedPacket: quoted}).ICMPMessage(family.local)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					body, marshalErr := message.MarshalBinary()
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					wire, marshalErr := (IPPacket{Source: family.remote, Destination: family.local, Protocol: family.icmpProtocol, HopLimit: 64, Payload: body}).MarshalBinary()
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if marshalErr = writeTestPacket(stack, wire); marshalErr != nil {
						t.Fatal(marshalErr)
					}
				}
				request := func() []byte {
					t.Helper()
					if _, writeErr := connection.Write(writePayload); writeErr != nil {
						t.Fatal(writeErr)
					}
					return readOutboundPacket(t, stack)
				}
				checkWriteOutput := func(quoted []byte) {
					t.Helper()
					sent, parseErr := ParseIPPacket(readOutboundPacket(t, stack))
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					original, parseErr := ParseIPPacket(quoted)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					if sent.Source != original.Source || sent.Destination != original.Destination || sent.Protocol != original.Protocol || !bytes.Equal(sent.Payload, original.Payload) {
						t.Fatalf("write after pending error = %+v, want source %v, destination %v, protocol %d, payload %x", sent, original.Source, original.Destination, original.Protocol, original.Payload)
					}
				}
				readNonblocking := func() (int, error) {
					t.Helper()
					return connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1500)}}}, MessageFlagDontWait)
				}

				quoted := request()
				var payload []byte
				inboundProtocol := 99
				if protocol == "UDP" {
					inboundProtocol = ProtocolUDP
					port := connection.LocalAddr().(*net.UDPAddr).Port
					payload, err = (UDPDatagram{
						Source: netip.AddrPortFrom(family.remote, 5353), Destination: netip.AddrPortFrom(family.local, uint16(port)),
						Payload: []byte("queued"),
					}).MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					payload = []byte("queued")
				}
				inbound, marshalErr := (IPPacket{Source: family.remote, Destination: family.local, Protocol: inboundProtocol, HopLimit: 64, Payload: payload}).MarshalBinary()
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if err = writeTestPacket(stack, inbound); err != nil {
					t.Fatal(err)
				}
				inject(quoted, family.hardType, family.hardCode)
				count, readErr := readNonblocking()
				var networkError ICMPError
				if count != 0 || !errors.Is(readErr, syscall.ECONNREFUSED) || !errors.As(readErr, &networkError) || !bytes.Equal(networkError.QuotedPacket, quoted) {
					t.Fatalf("hard error before queued data = %d, %v", count, readErr)
				}
				if count, readErr = readNonblocking(); count != 1 || readErr != nil {
					t.Fatalf("queued data after hard error = %d, %v", count, readErr)
				}
				if queued, queueErr := connection.ReadError(); queued != nil || !errors.Is(queueErr, syscall.EAGAIN) {
					t.Fatalf("default extended queue = %v, %v", queued, queueErr)
				}

				quoted = request()
				inject(quoted, family.hardType, family.hardCode)
				if _, writeErr := connection.Write(writePayload); protocol == "IP payload" {
					if writeErr != nil {
						t.Fatalf("ordinary raw write with pending error = %v", writeErr)
					}
					checkWriteOutput(quoted)
					count, readErr = readNonblocking()
					if count != 0 || !errors.As(readErr, &networkError) || !bytes.Equal(networkError.QuotedPacket, quoted) {
						t.Fatalf("ordinary raw write consumed pending error = %d, %v", count, readErr)
					}
				} else if writeErr == nil {
					t.Fatal("UDP or header-included raw write did not consume pending error")
				} else {
					var operation *net.OpError
					if !errors.As(writeErr, &operation) || operation.Op != "write" || !errors.Is(writeErr, syscall.ECONNREFUSED) || !errors.As(writeErr, &networkError) || !bytes.Equal(networkError.QuotedPacket, quoted) {
						t.Fatalf("write error lost operation or ICMP quote: %v", writeErr)
					}
				}
				quoted = request()
				inject(quoted, family.hardType, family.hardCode)
				batch := []SocketMessage{{Buffers: [][]byte{writePayload[:len(writePayload)/2], writePayload[len(writePayload)/2:]}}}
				batchCount, batchErr := connection.WriteBatch(batch, 0)
				if protocol == "IP payload" {
					if batchCount != 1 || batchErr != nil {
						t.Fatalf("ordinary raw batch write with pending error = %d, %v", batchCount, batchErr)
					}
					checkWriteOutput(quoted)
					count, readErr = readNonblocking()
					if count != 0 || !errors.As(readErr, &networkError) || !bytes.Equal(networkError.QuotedPacket, quoted) {
						t.Fatalf("ordinary raw batch write consumed pending error = %d, %v", count, readErr)
					}
				} else {
					if batchCount != 0 || !errors.Is(batchErr, syscall.ECONNREFUSED) || !errors.As(batchErr, &networkError) || !bytes.Equal(networkError.QuotedPacket, quoted) {
						t.Fatalf("pending batch write error = %d, %v", batchCount, batchErr)
					}
					if batchCount, batchErr = connection.WriteBatch(batch, 0); batchCount != 1 || batchErr != nil {
						t.Fatalf("batch write after pending error = %d, %v", batchCount, batchErr)
					}
					checkWriteOutput(quoted)
				}
				quoted = request()
				inject(quoted, family.softType, 0)
				if count, readErr = readNonblocking(); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
					t.Fatalf("default soft error = %d, %v", count, readErr)
				}

				if err = connection.SetReceiveErrors(true); err != nil {
					t.Fatal(err)
				}
				quoted = request()
				inject(quoted, family.softType, 0)
				if count, readErr = readNonblocking(); count != 0 || !errors.Is(readErr, syscall.EHOSTUNREACH) || !errors.As(readErr, &networkError) || networkError.Type != family.softType || !bytes.Equal(networkError.QuotedPacket, quoted) {
					t.Fatalf("enabled soft pending error = %d, %v", count, readErr)
				}
				queued, queueErr := connection.ReadError()
				if queueErr != nil || !errors.As(queued, &networkError) || networkError.Type != family.softType || !bytes.Equal(networkError.QuotedPacket, quoted) {
					t.Fatalf("enabled soft extended error = %v, %v", queued, queueErr)
				}
			})
		}
	}
}

func TestLinuxDatagramICMPReportPolicy(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.198")
	v6 := netip.MustParseAddr("2001:db8::198")
	for _, test := range []struct {
		name                          string
		error                         ICMPError
		connected, receiveErrors, raw bool
		mode                          PathMTUDiscovery
		pending, queued               bool
	}{
		{name: "connected IPv4 port unreachable", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort}, connected: true, pending: true},
		{name: "unconnected IPv4 port unreachable", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort}},
		{name: "unconnected IPv4 extended port unreachable", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort}, receiveErrors: true, pending: true, queued: true},
		{name: "connected IPv4 host unreachable", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHost}, connected: true},
		{name: "connected IPv4 protocol unreachable", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol}, connected: true, pending: true},
		{name: "IPv4 UDP PMTUDISC_DONT extended", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeFragmentationNeeded}, connected: true, receiveErrors: true},
		{name: "IPv4 raw PMTUDISC_DONT extended", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeFragmentationNeeded}, connected: true, receiveErrors: true, raw: true, pending: true, queued: true},
		{name: "IPv4 UDP PMTUDISC_WANT", error: ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeFragmentationNeeded}, connected: true, mode: PathMTUDiscoveryWant, pending: true},
		{name: "connected IPv6 no route", error: ICMPError{Reporter: v6, Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeNoRoute}, connected: true},
		{name: "connected IPv6 prohibited", error: ICMPError{Reporter: v6, Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeAdministrativelyProhibited}, connected: true, pending: true},
		{name: "IPv6 UDP PTB PMTUDISC_WANT", error: ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, connected: true, mode: PathMTUDiscoveryWant, pending: true},
		{name: "IPv6 UDP PTB PMTUDISC_INTERFACE extended", error: ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, connected: true, receiveErrors: true, mode: PathMTUDiscoveryInterface},
		{name: "IPv6 raw PTB PMTUDISC_WANT", error: ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, connected: true, raw: true, mode: PathMTUDiscoveryWant},
		{name: "IPv6 raw PTB PMTUDISC_DO", error: ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, connected: true, raw: true, mode: PathMTUDiscoveryDo, pending: true},
		{name: "IPv6 raw PTB extended", error: ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, receiveErrors: true, raw: true, pending: true, queued: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pending, queued := linuxDatagramICMPReport(test.error, test.connected, test.receiveErrors, test.raw, test.mode)
			if pending != test.pending || queued != test.queued {
				t.Fatalf("report policy = pending %t queue %t, want pending %t queue %t", pending, queued, test.pending, test.queued)
			}
		})
	}
}

func TestLinuxICMPErrorConversion(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.199")
	v6 := netip.MustParseAddr("2001:db8::199")
	for _, test := range []struct {
		name string
		err  ICMPError
		wire uint32
		hard bool
	}{
		{"IPv4 port unreachable", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort}, 111, true},
		{"IPv4 host unknown", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHostUnknown}, 112, true},
		{"IPv4 source host isolated", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeSourceHostIsolated}, 64, true},
		{"IPv4 parameter problem", ICMPError{Reporter: v4, Type: ICMPv4TypeParameterProblem}, 71, true},
		{"IPv6 parameter problem", ICMPError{Reporter: v6, Type: ICMPv6TypeParameterProblem}, 71, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conversion := linuxICMPErrorConversion(test.err)
			if conversion.linuxErrno != test.wire || conversion.hard != test.hard {
				t.Fatalf("ICMP conversion = %+v, want wire %d, hard %t", conversion, test.wire, test.hard)
			}
		})
	}
}

func TestICMPErrorSyscallCause(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.199")
	v6 := netip.MustParseAddr("2001:db8::199")
	for _, test := range []struct {
		name string
		err  ICMPError
		want syscall.Errno
	}{
		{"IPv4 network unreachable", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeNetwork}, syscall.ENETUNREACH},
		{"IPv4 host unreachable", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHost}, syscall.EHOSTUNREACH},
		{"IPv4 protocol unreachable", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol}, syscall.ENOPROTOOPT},
		{"IPv4 port unreachable", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort}, syscall.ECONNREFUSED},
		{"IPv4 fragmentation needed", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeFragmentationNeeded}, syscall.EMSGSIZE},
		{"IPv4 source route failed", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeSourceRouteFailed}, syscall.EOPNOTSUPP},
		{"IPv4 time exceeded", ICMPError{Reporter: v4, Type: ICMPv4TypeTimeExceeded}, syscall.EHOSTUNREACH},
		{"IPv4 parameter problem", ICMPError{Reporter: v4, Type: ICMPv4TypeParameterProblem}, syscall.EPROTO},
		{"IPv6 no route", ICMPError{Reporter: v6, Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeNoRoute}, syscall.ENETUNREACH},
		{"IPv6 prohibited", ICMPError{Reporter: v6, Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeAdministrativelyProhibited}, syscall.EACCES},
		{"IPv6 port unreachable", ICMPError{Reporter: v6, Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodePort}, syscall.ECONNREFUSED},
		{"IPv6 packet too big", ICMPError{Reporter: v6, Type: ICMPv6TypePacketTooBig}, syscall.EMSGSIZE},
		{"IPv6 time exceeded", ICMPError{Reporter: v6, Type: ICMPv6TypeTimeExceeded}, syscall.EHOSTUNREACH},
		{"IPv6 parameter problem", ICMPError{Reporter: v6, Type: ICMPv6TypeParameterProblem}, syscall.EPROTO},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapped := &net.OpError{Op: "read", Err: test.err}
			if !errors.Is(wrapped, test.want) {
				t.Fatalf("ICMP error %v does not match %v", wrapped, test.want)
			}
			var errno syscall.Errno
			if !errors.As(wrapped, &errno) || errno != test.want {
				t.Fatalf("ICMP syscall cause = %v, want %v", errno, test.want)
			}
			var networkError ICMPError
			if !errors.As(wrapped, &networkError) || !reflect.DeepEqual(networkError, test.err) {
				t.Fatalf("ICMP details = %+v, want %+v", networkError, test.err)
			}
		})
	}
	for _, err := range []ICMPError{
		{},
		{Reporter: v4, Type: ICMPv4TypeEchoRequest},
		{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: 255},
		{Reporter: v6, Type: ICMPv6TypePacketTooBig, Code: 1},
	} {
		if cause := err.Unwrap(); cause != nil {
			t.Fatalf("invalid ICMP error %+v has syscall cause %v", err, cause)
		}
	}
}

func TestICMPErrorSyscallRareCodes(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.199")
	hostDownExact, notOnNetworkExact := false, false
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "solaris", "windows":
		hostDownExact = true
	}
	switch runtime.GOOS {
	case "android", "illumos", "js", "linux", "solaris", "windows":
		notOnNetworkExact = true
	}
	for _, test := range []struct {
		name         string
		networkError ICMPError
		exact        bool
		meaning      string
		fallback     syscall.Errno
	}{
		{"host unknown", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHostUnknown}, hostDownExact, "host is down", syscall.EHOSTUNREACH},
		{"source host isolated", ICMPError{Reporter: v4, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeSourceHostIsolated}, notOnNetworkExact, "machine is not on the network", syscall.ENETUNREACH},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause, ok := test.networkError.Unwrap().(syscall.Errno)
			if !ok {
				t.Fatalf("ICMP syscall cause = %T, want syscall.Errno", test.networkError.Unwrap())
			}
			if test.exact {
				if !strings.EqualFold(cause.Error(), test.meaning) {
					t.Fatalf("ICMP syscall cause = %v, want %q", cause, test.meaning)
				}
			} else if !errors.Is(test.networkError, test.fallback) {
				t.Fatalf("ICMP syscall cause = %v, want %v", cause, test.fallback)
			}
		})
	}
}

func TestIPConnICMPErrorDoesNotRequireTransportHeader(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.183")
	remote := netip.MustParseAddr("192.0.2.184")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.ListenIP(context.Background(), "ip4:17", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.(*IPConn).SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.WriteTo([]byte{1, 2, 3, 4}, ipNetAddr(remote)); err != nil {
		t.Fatal(err)
	}
	original := readOutboundPacket(t, stack)
	if err = writeTestPacket(stack, buildTestPacketTooBig(remote, local, original, 1200)); err != nil {
		t.Fatal(err)
	}
	reported, readErr := connection.(*IPConn).ReadError()
	if readErr != nil {
		t.Fatal(readErr)
	}
	var icmpError ICMPError
	if !errors.As(reported, &icmpError) || icmpError.QuotedProtocol != ProtocolUDP || len(icmpError.QuotedPayload) != 4 {
		t.Fatalf("short quoted transport error = %#v", reported)
	}
}

func TestControlResponseRateLimitAndStats(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	stack.controlMu.Lock()
	stack.controlLimiters[controlResponseTCPReset] = tokenBucket{tokens: 1, updated: time.Now()}
	stack.controlLimiters[controlResponseTCPChallengeACK] = tokenBucket{tokens: 1, updated: time.Now()}
	stack.controlMu.Unlock()
	if !stack.allowControlResponse(controlResponseTCPReset) {
		t.Fatal("first control response was unexpectedly limited")
	}
	if stack.allowControlResponse(controlResponseTCPReset) {
		t.Fatal("second control response exceeded the token bucket")
	}
	if !stack.allowControlResponse(controlResponseTCPChallengeACK) || stack.allowControlResponse(controlResponseTCPChallengeACK) {
		t.Fatal("TCP challenge ACK did not use its independent token bucket")
	}
	stats := stack.Stats()
	if stats.RateLimitedControlResponses != 2 {
		t.Fatalf("rate-limited responses = %d, want 2", stats.RateLimitedControlResponses)
	}
}

func TestICMPErrorTargetRateLimitFairness(t *testing.T) {
	var stack Stack
	class := icmpErrorResponsePortUnreachable
	sourceA := netip.MustParseAddr("192.0.2.201")
	sourceB := netip.MustParseAddr("192.0.2.202")
	now := time.Now()
	stack.controlMu.Lock()
	table := stack.icmpErrorLimiterTableLocked(class)
	table.aggregate = tokenBucket{tokens: icmpErrorAggregateBurst, updated: now}
	sourceABytes := sourceA.As16()
	hashA := sipHash24(stack.icmpErrorLimiterSecret, sourceABytes[:])
	targetA := table.targetBucketLocked(sourceA, hashA, now)
	*targetA = tokenBucket{tokens: 1, updated: now}
	sourceBBytes := sourceB.As16()
	hashB := sipHash24(stack.icmpErrorLimiterSecret, sourceBBytes[:])
	targetB := table.targetBucketLocked(sourceB, hashB, now)
	*targetB = tokenBucket{tokens: 1, updated: now}
	stack.controlMu.Unlock()

	if !stack.allowICMPErrorResponseTo(class, sourceA) {
		t.Fatal("source A response was unexpectedly limited")
	}
	if stack.allowICMPErrorResponseTo(class, sourceA) {
		t.Fatal("source A exceeded its destination bucket")
	}
	if stack.allowICMPErrorResponseTo(class, netip.MustParseAddr("::ffff:192.0.2.201")) {
		t.Fatal("IPv4-mapped source A bypassed its destination bucket")
	}
	if !stack.allowICMPErrorResponseTo(class, sourceB) {
		t.Fatal("source B was starved by source A")
	}

	var targetRejected Stack
	now = time.Now()
	targetRejected.controlMu.Lock()
	targetTable := targetRejected.icmpErrorLimiterTableLocked(class)
	targetAddress := sourceA.As16()
	targetHash := sipHash24(targetRejected.icmpErrorLimiterSecret, targetAddress[:])
	targetBucket := targetTable.targetBucketLocked(sourceA, targetHash, now)
	*targetBucket = tokenBucket{updated: now.Add(time.Hour)}
	targetTable.aggregate = tokenBucket{tokens: 2, updated: now}
	targetRejected.controlMu.Unlock()
	if targetRejected.allowICMPErrorResponseTo(class, sourceA) {
		t.Fatal("empty destination bucket admitted a response")
	}
	targetRejected.controlMu.Lock()
	remaining := targetTable.aggregate.tokens
	targetRejected.controlMu.Unlock()
	if remaining < 1.5 {
		t.Fatalf("target rejection consumed global token: remaining=%v", remaining)
	}

	var refilled Stack
	now = time.Now()
	refilled.controlMu.Lock()
	refillTable := refilled.icmpErrorLimiterTableLocked(class)
	refillTable.aggregate = tokenBucket{updated: now.Add(-time.Second)}
	refillAddress := sourceA.As16()
	refillHash := sipHash24(refilled.icmpErrorLimiterSecret, refillAddress[:])
	refillTarget := refillTable.targetBucketLocked(sourceA, refillHash, now.Add(-time.Second))
	*refillTarget = tokenBucket{updated: now.Add(-time.Second)}
	refilled.controlMu.Unlock()
	if !refilled.allowICMPErrorResponseTo(class, sourceA) {
		t.Fatal("refilled destination bucket did not admit a response")
	}

	var invalidDestination Stack
	if invalidDestination.allowICMPErrorResponseTo(class, netip.Addr{}) {
		t.Fatal("invalid destination was admitted")
	}
	if invalidDestination.icmpErrorLimiters != nil {
		t.Fatal("invalid destination allocated destination state")
	}
}

func TestICMPErrorReserveIsolationAndEnvelope(t *testing.T) {
	if icmpErrorAggregateBurst+icmpErrorReserveBurst != controlResponseBurst {
		t.Fatalf("aggregate and reserve burst = %d, want %d", icmpErrorAggregateBurst+icmpErrorReserveBurst, controlResponseBurst)
	}
	if rate := time.Second * icmpErrorReserveBurst / icmpErrorReserveInterval; rate != icmpErrorReserveRate {
		t.Fatalf("aggregate reserve rate = %v, want %d", rate, icmpErrorReserveRate)
	}

	var stack Stack
	stack.timestampEpoch = time.Now()
	var destinations [icmpErrorReserveBuckets][3]netip.Addr
	var found [icmpErrorReserveBuckets]int
	remaining := len(destinations) * len(destinations[0])
	for value := uint32(1); value < 1<<24 && remaining != 0; value++ {
		address := netip.AddrFrom4([4]byte{198, byte(value >> 16), byte(value >> 8), byte(value)})
		addressBytes := address.As16()
		hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
		first := int(uint32(hash>>32) % icmpErrorReserveBuckets)
		second := int(uint32(hash>>48) % icmpErrorReserveBuckets)
		if first != second || found[first] == len(destinations[first]) {
			continue
		}
		destinations[first][found[first]] = address
		found[first]++
		remaining--
	}
	if remaining != 0 {
		t.Fatal("could not find reserve-bucket test destinations")
	}

	stack.controlMu.Lock()
	table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
	table.aggregate = tokenBucket{tokens: -1000, updated: time.Now()}
	stack.controlMu.Unlock()
	first, second, collision := destinations[0][0], destinations[0][1], destinations[0][2]
	if !stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, first) {
		t.Fatal("first destination did not receive protected service")
	}
	stack.controlMu.Lock()
	firstAddress := first.As16()
	firstHash := sipHash24(stack.icmpErrorLimiterSecret, firstAddress[:])
	firstTokens := table.targetBucketLocked(first, firstHash, time.Now()).tokens
	stack.controlMu.Unlock()
	if firstTokens >= icmpErrorTargetBurst {
		t.Fatalf("target tokens after protected admission = %v, want less than %d", firstTokens, icmpErrorTargetBurst)
	}
	if stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, first) {
		t.Fatal("one destination consumed both reserve choices")
	}
	if !stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, second) {
		t.Fatal("second destination did not use the collision fallback")
	}
	if stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, collision) {
		t.Fatal("destination colliding with two occupied reserve slots was admitted")
	}
	if victim := destinations[1][0]; !stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, victim) {
		t.Fatal("one occupied pair starved an unrelated destination")
	}

	var targetLimited Stack
	targetLimited.timestampEpoch = time.Now()
	targetLimited.controlMu.Lock()
	targetTable := targetLimited.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
	now := time.Now()
	targetTable.aggregate = tokenBucket{tokens: 1, updated: now}
	address := first.As16()
	hash := sipHash24(targetLimited.icmpErrorLimiterSecret, address[:])
	target := targetTable.targetBucketLocked(first, hash, now)
	*target = tokenBucket{tokens: 1, updated: now}
	targetLimited.controlMu.Unlock()
	if !targetLimited.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, first) {
		t.Fatal("ordinary service did not consume the available target token")
	}
	targetLimited.controlMu.Lock()
	if target.tokens >= 1 {
		targetLimited.controlMu.Unlock()
		t.Fatalf("target tokens after ordinary admission = %v, want less than one", target.tokens)
	}
	*target = tokenBucket{updated: time.Now().Add(time.Hour)}
	now = time.Now()
	targetTable.aggregate = tokenBucket{tokens: -1000, updated: now}
	targetTable.reserveAggregate = tokenBucket{tokens: 1, updated: now}
	targetLimited.controlMu.Unlock()
	if targetLimited.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, first) {
		t.Fatal("protected service bypassed an exhausted target bucket")
	}
	targetLimited.controlMu.Lock()
	remainingReserve := targetTable.reserveAggregate.tokens
	remainingAggregate := targetTable.aggregate.tokens
	targetLimited.controlMu.Unlock()
	if remainingReserve < 1 || remainingAggregate < -1000 {
		t.Fatalf("target rejection consumed aggregate credit: reserve=%v aggregate=%v", remainingReserve, remainingAggregate)
	}

	var envelope Stack
	envelope.timestampEpoch = time.Now()
	envelope.controlMu.Lock()
	envelopeTable := envelope.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
	envelopeStart := time.Now()
	envelopeTable.aggregate = tokenBucket{tokens: -1000, updated: envelopeStart}
	envelope.controlMu.Unlock()
	admitted := 0
	for index := range destinations {
		for candidate := 0; candidate < icmpErrorReserveGroups; candidate++ {
			if envelope.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, destinations[index][candidate]) {
				admitted++
			}
		}
	}
	if admitted != icmpErrorReserveBurst {
		t.Fatalf("reserve admissions = %d, want %d", admitted, icmpErrorReserveBurst)
	}
	envelope.controlMu.Lock()
	elapsed := time.Since(envelopeStart)
	debt := envelopeTable.aggregate.tokens
	envelopeTable.reserveAggregate = tokenBucket{updated: time.Now().Add(time.Hour)}
	envelope.controlMu.Unlock()
	maximumDebt := -1000 - float64(admitted) + elapsed.Seconds()*controlResponseRate + 1e-6
	if debt > maximumDebt {
		t.Fatalf("aggregate debt after reserve admissions = %v, want at most %v", debt, maximumDebt)
	}
	if envelope.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, destinations[0][2]) {
		t.Fatal("exhausted reserve admitted another destination")
	}
}

func TestICMPErrorReserveProductionIsolation(t *testing.T) {
	for _, test := range []struct {
		name        string
		local       netip.Addr
		candidate   func(uint32) netip.Addr
		protocol    byte
		messageType byte
		code        byte
	}{
		{
			name:  "IPv4",
			local: netip.MustParseAddr("192.0.2.212"),
			candidate: func(value uint32) netip.Addr {
				return netip.AddrFrom4([4]byte{198, byte(value >> 16), byte(value >> 8), byte(value)})
			},
			protocol:    ProtocolICMPv4,
			messageType: ICMPv4TypeDestinationUnreachable,
			code:        ICMPv4DestinationUnreachableCodePort,
		},
		{
			name:  "IPv6",
			local: netip.MustParseAddr("2001:db8::212"),
			candidate: func(value uint32) netip.Addr {
				var address [16]byte
				address[0], address[1], address[2], address[3] = 0x20, 0x01, 0x0d, 0xb8
				address[4], address[5], address[6], address[7] = 0, 0, 0, 0x03
				binary.BigEndian.PutUint32(address[12:], value)
				return netip.AddrFrom16(address)
			},
			protocol:    ProtocolICMPv6,
			messageType: ICMPv6TypeDestinationUnreachable,
			code:        ICMPv6DestinationUnreachableCodePort,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, test.local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })

			var sources [5]netip.Addr
			remaining := len(sources)
			for value := uint32(1); value < 1<<24 && remaining != 0; value++ {
				address := test.candidate(value)
				addressBytes := address.As16()
				hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
				first := int(uint32(hash>>32) % icmpErrorReserveBuckets)
				second := int(uint32(hash>>48) % icmpErrorReserveBuckets)
				if first != second || first >= len(sources) || sources[first].IsValid() {
					continue
				}
				sources[first] = address
				remaining--
			}
			if remaining != 0 {
				t.Fatal("could not find reserve-isolation source addresses")
			}

			stack.controlMu.Lock()
			table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
			table.aggregate = tokenBucket{updated: time.Now().Add(time.Hour)}
			stack.controlMu.Unlock()
			send := func(source netip.Addr, sourcePort uint16) bool {
				if err = writeTestPacket(stack, buildTestUDP(source, test.local, sourcePort, 53000, []byte("reserve"))); err != nil {
					t.Fatal(err)
				}
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					return false
				}
				response, parsed := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
				if !parsed || response.protocol != test.protocol || response.target != source || len(response.payload) < 2 || response.payload[0] != test.messageType || response.payload[1] != test.code {
					t.Fatalf("source %s response = %#v", source, response)
				}
				return true
			}
			for index, source := range sources[:4] {
				if !send(source, uint16(44000+index*4)) {
					t.Fatalf("attacker source %s did not receive protected service", source)
				}
				for repeat := 1; repeat < 4; repeat++ {
					if send(source, uint16(44000+index*4+repeat)) {
						t.Fatalf("attacker source %s consumed a second protected response", source)
					}
				}
			}
			if !send(sources[4], 44100) {
				t.Fatal("unrelated source was starved by protected-service attackers")
			}
			if send(sources[4], 44101) {
				t.Fatal("unrelated source consumed a second protected response")
			}
		})
	}
}

func TestICMPErrorLimiterUsesDedicatedSecret(t *testing.T) {
	destination := netip.MustParseAddr("198.51.100.18")
	class := icmpErrorResponsePortUnreachable
	flowSecret := [16]byte{0x11}
	limiterSecret := [16]byte{0x22}
	address := destination.As16()
	expectedIndex := func(secret [16]byte) int {
		return int(uint32(sipHash24(secret, address[:])) % uint32(icmpErrorTargetEntries))
	}
	if expectedIndex(flowSecret) == expectedIndex(limiterSecret) {
		t.Fatal("test keys selected the same destination slot")
	}
	lookupIndex := func(flowSecret, limiterSecret [16]byte) int {
		stack := Stack{flowLabelSecret: flowSecret, icmpErrorLimiterSecret: limiterSecret}
		stack.controlMu.Lock()
		table := stack.icmpErrorLimiterTableLocked(class)
		table.targetBucketLocked(destination, sipHash24(limiterSecret, address[:]), time.Now())
		index := -1
		for candidate, entry := range table.entries {
			if entry.destination == destination {
				index = candidate
				break
			}
		}
		stack.controlMu.Unlock()
		return index
	}

	index := lookupIndex(flowSecret, limiterSecret)
	if index != expectedIndex(limiterSecret) {
		t.Fatalf("destination slot = %d, want slot selected by ICMP-error limiter secret %d", index, expectedIndex(limiterSecret))
	}
	if index != lookupIndex([16]byte{0x33}, limiterSecret) {
		t.Fatal("changing the Flow Label secret changed destination-slot selection")
	}

	var alternate [16]byte
	foundAlternate := false
	for value := 1; value < 256; value++ {
		alternate[0] = byte(value)
		if expectedIndex(alternate) != index {
			foundAlternate = true
			break
		}
	}
	if !foundAlternate {
		t.Fatal("could not find an alternate ICMP-error limiter slot")
	}
	if alternateIndex := lookupIndex(flowSecret, alternate); alternateIndex != expectedIndex(alternate) {
		t.Fatalf("destination slot with alternate ICMP-error limiter secret = %d, want %d", alternateIndex, expectedIndex(alternate))
	}
}

func TestICMPErrorLimiterBounded(t *testing.T) {
	var stack Stack
	class := icmpErrorResponseParameterProblem
	for index := 0; index < icmpErrorTargetEntries+icmpErrorTargetOverflowBuckets+16; index++ {
		address := netip.AddrFrom4([4]byte{198, 51, 100, byte(index)})
		if !stack.allowICMPErrorResponseTo(class, address) {
			t.Fatalf("address %s was unexpectedly limited", address)
		}
	}
	stack.controlMu.Lock()
	state := stack.icmpErrorLimiters
	if state == nil || state.tables[class] == nil {
		stack.controlMu.Unlock()
		t.Fatal("source churn did not allocate destination table")
	}
	table := state.tables[class]
	exact := 0
	for _, entry := range table.entries {
		if entry.destination.IsValid() {
			exact++
		}
	}
	overflowUsed := false
	for _, bucket := range table.overflow {
		if !bucket.updated.IsZero() {
			overflowUsed = true
			break
		}
	}
	stack.controlMu.Unlock()
	if exact != icmpErrorTargetEntries {
		t.Fatalf("exact target entries = %d, want %d", exact, icmpErrorTargetEntries)
	}
	if !overflowUsed {
		t.Fatal("source churn did not use a fixed overflow bucket")
	}
}

func TestICMPErrorLimiterOverflowCollision(t *testing.T) {
	var stack Stack
	class := icmpErrorResponseParameterProblem
	now := time.Now()
	stack.controlMu.Lock()
	table := stack.icmpErrorLimiterTableLocked(class)
	table.aggregate = tokenBucket{tokens: icmpErrorAggregateBurst, updated: now}
	for index := 0; index < icmpErrorTargetEntries; index++ {
		address := netip.AddrFrom4([4]byte{198, 51, byte(index >> 8), byte(index)})
		addressBytes := address.As16()
		hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
		bucket := table.targetBucketLocked(address, hash, now)
		*bucket = tokenBucket{tokens: icmpErrorTargetBurst, updated: now}
	}
	exact := 0
	for _, entry := range table.entries {
		if entry.destination.IsValid() {
			exact++
		}
	}
	if exact != icmpErrorTargetEntries {
		stack.controlMu.Unlock()
		t.Fatalf("exact target entries = %d, want %d", exact, icmpErrorTargetEntries)
	}
	var first, collision, separate netip.Addr
	var firstBucket, collisionBucket, separateBucket *tokenBucket
	for index := icmpErrorTargetEntries; index < 65536 && (!first.IsValid() || !collision.IsValid() || !separate.IsValid()); index++ {
		address := netip.AddrFrom4([4]byte{198, 51, byte(index >> 8), byte(index)})
		addressBytes := address.As16()
		hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
		bucket := table.targetBucketLocked(address, hash, now)
		switch {
		case !first.IsValid():
			first, firstBucket = address, bucket
		case !collision.IsValid() && bucket == firstBucket:
			collision, collisionBucket = address, bucket
		case !separate.IsValid() && bucket != firstBucket:
			separate, separateBucket = address, bucket
		}
	}
	if !first.IsValid() || !collision.IsValid() || !separate.IsValid() || firstBucket == nil || collisionBucket == nil || separateBucket == nil {
		stack.controlMu.Unlock()
		t.Fatal("could not find both colliding and separate overflow destinations")
	}
	*firstBucket = tokenBucket{tokens: 1, updated: now}
	*separateBucket = tokenBucket{tokens: 1, updated: now}
	stack.controlMu.Unlock()

	if !stack.allowICMPErrorResponseTo(class, first) {
		t.Fatalf("first overflow destination %s was unexpectedly limited", first)
	}
	if stack.allowICMPErrorResponseTo(class, collision) {
		t.Fatalf("colliding overflow destination %s bypassed its shared bucket", collision)
	}
	if !stack.allowICMPErrorResponseTo(class, separate) {
		t.Fatalf("separate overflow destination %s was limited by another bucket", separate)
	}
}

func TestICMPErrorLimiterOverflowCollisionProduction(t *testing.T) {
	for _, test := range []struct {
		name, local       string
		filled, candidate func(uint32) netip.Addr
		messageType       byte
		code              byte
		protocol          byte
	}{
		{
			name: "IPv4", local: "192.0.2.231",
			filled: func(value uint32) netip.Addr {
				return netip.AddrFrom4([4]byte{198, 51, 100, byte(value)})
			},
			candidate: func(value uint32) netip.Addr {
				return netip.AddrFrom4([4]byte{198, 51, byte(value >> 8), byte(value)})
			},
			messageType: ICMPv4TypeDestinationUnreachable,
			code:        ICMPv4DestinationUnreachableCodePort,
			protocol:    ProtocolICMPv4,
		},
		{
			name: "IPv6", local: "2001:db8::231",
			filled: func(value uint32) netip.Addr {
				var address [16]byte
				address[0], address[1], address[2], address[3] = 0x20, 0x01, 0x0d, 0xb8
				address[4], address[5], address[6], address[7] = 0, 0, 0, 0x01
				binary.BigEndian.PutUint32(address[12:], value)
				return netip.AddrFrom16(address)
			},
			candidate: func(value uint32) netip.Addr {
				var address [16]byte
				address[0], address[1], address[2], address[3] = 0x20, 0x01, 0x0d, 0xb8
				address[4], address[5], address[6], address[7] = 0, 0, 0, 0x02
				binary.BigEndian.PutUint32(address[12:], value)
				return netip.AddrFrom16(address)
			},
			messageType: ICMPv6TypeDestinationUnreachable,
			code:        ICMPv6DestinationUnreachableCodePort,
			protocol:    ProtocolICMPv6,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr(test.local)
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })

			send := func(source netip.Addr, port uint16) {
				if err = writeTestPacket(stack, buildTestUDP(source, local, port, 53000, []byte("probe"))); err != nil {
					t.Fatal(err)
				}
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					t.Fatalf("source %s response was unexpectedly limited", source)
				}
				response, parsed := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
				if !parsed || response.protocol != test.protocol || response.target != source || len(response.payload) < 2 || response.payload[0] != test.messageType || response.payload[1] != test.code {
					t.Fatalf("source %s response = %#v", source, response)
				}
			}

			for index := uint32(1); index <= icmpErrorTargetEntries; index++ {
				send(test.filled(index), uint16(40000+index))
			}
			class := icmpErrorResponsePortUnreachable
			stack.controlMu.Lock()
			table := stack.icmpErrorLimiters.tables[class]
			exact := 0
			for _, entry := range table.entries {
				if entry.destination.IsValid() {
					exact++
				}
			}
			if exact != icmpErrorTargetEntries {
				stack.controlMu.Unlock()
				t.Fatalf("exact target entries = %d, want %d", exact, icmpErrorTargetEntries)
			}
			now := time.Now()
			var first, collision, separate netip.Addr
			var firstBucket, collisionBucket, separateBucket *tokenBucket
			for index := uint32(65); index < 65536 && (!first.IsValid() || !collision.IsValid() || !separate.IsValid()); index++ {
				address := test.candidate(index)
				addressBytes := address.As16()
				hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
				bucket := table.targetBucketLocked(address, hash, now)
				switch {
				case !first.IsValid():
					first, firstBucket = address, bucket
				case !collision.IsValid() && bucket == firstBucket:
					collision, collisionBucket = address, bucket
				case !separate.IsValid() && bucket != firstBucket:
					separate, separateBucket = address, bucket
				}
			}
			stack.controlMu.Unlock()
			if !first.IsValid() || !collision.IsValid() || !separate.IsValid() || firstBucket == nil || collisionBucket == nil || separateBucket == nil {
				t.Fatal("could not find both colliding and separate overflow destinations")
			}

			for index := 0; index < icmpErrorTargetBurst; index++ {
				send(first, uint16(41000+index))
			}
			stack.controlMu.Lock()
			*firstBucket = tokenBucket{updated: time.Now().Add(time.Hour)}
			stack.controlMu.Unlock()
			if err = writeTestPacket(stack, buildTestUDP(collision, local, 42000, 53000, []byte("collision"))); err != nil {
				t.Fatal(err)
			}
			if entry, ok := stack.outbound.tryDequeue(); ok {
				stack.outbound.release(entry)
				t.Fatalf("colliding destination %s bypassed its shared overflow bucket", collision)
			}
			send(separate, 42001)
		})
	}
}

func TestICMPErrorLimiterReusesIdleSlot(t *testing.T) {
	var stack Stack
	class := icmpErrorResponseFragmentTimeout
	old := time.Now().Add(-2 * icmpErrorTargetIdle)
	newAddress := netip.MustParseAddr("203.0.113.250")
	stack.controlMu.Lock()
	table := stack.icmpErrorLimiterTableLocked(class)
	for index := 0; index < icmpErrorTargetEntries; index++ {
		address := netip.AddrFrom4([4]byte{203, 0, 113, byte(index)})
		addressBytes := address.As16()
		hash := sipHash24(stack.icmpErrorLimiterSecret, addressBytes[:])
		bucket := table.targetBucketLocked(address, hash, old)
		*bucket = tokenBucket{tokens: 1, updated: old}
	}
	newAddressBytes := newAddress.As16()
	table.targetBucketLocked(newAddress, sipHash24(stack.icmpErrorLimiterSecret, newAddressBytes[:]), time.Now())
	stack.controlMu.Unlock()

	found := false
	exact := 0
	for _, entry := range table.entries {
		if !entry.destination.IsValid() {
			continue
		}
		exact++
		if entry.destination == newAddress {
			found = true
		}
	}
	if exact != icmpErrorTargetEntries || !found {
		t.Fatalf("idle target reuse = exact %d, want %d, found new address %v", exact, icmpErrorTargetEntries, found)
	}
}

func TestPortUnreachableRateLimitGlobalAggregate(t *testing.T) {
	for _, test := range []struct {
		name, local string
		sources     []netip.Addr
		messageType byte
		code        byte
	}{
		{
			name: "IPv4", local: "192.0.2.210",
			sources: []netip.Addr{
				netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"),
				netip.MustParseAddr("198.51.100.3"), netip.MustParseAddr("198.51.100.4"),
			},
			messageType: ICMPv4TypeDestinationUnreachable,
			code:        ICMPv4DestinationUnreachableCodePort,
		},
		{
			name: "IPv6", local: "2001:db8::210",
			sources: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("2001:db8:1::3"), netip.MustParseAddr("2001:db8:1::4"),
			},
			messageType: ICMPv6TypeDestinationUnreachable,
			code:        ICMPv6DestinationUnreachableCodePort,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr(test.local)
			bits := local.BitLen()
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			wantProtocol := byte(ProtocolICMPv4)
			if local.Is6() {
				wantProtocol = ProtocolICMPv6
			}
			start := time.Now()
			admitted := 0
			for packetIndex := 0; packetIndex < icmpErrorTargetBurst+8; packetIndex++ {
				for sourceIndex, source := range test.sources {
					if err = writeTestPacket(stack, buildTestUDP(source, local, uint16(42000+sourceIndex*64+packetIndex), 53000, []byte("probe"))); err != nil {
						t.Fatal(err)
					}
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						continue
					}
					admitted++
					response, parsed := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
					if !parsed || response.protocol != wantProtocol || response.target != source || len(response.payload) < 2 || response.payload[0] != test.messageType || response.payload[1] != test.code {
						t.Fatalf("source %s response = %#v", source, response)
					}
				}
			}
			maximum := controlResponseBurst + int(math.Ceil(time.Since(start).Seconds()*controlResponseRate))
			if admitted < icmpErrorAggregateBurst || admitted > maximum {
				t.Fatalf("admitted responses = %d, want at least %d and at most %d", admitted, icmpErrorAggregateBurst, maximum)
			}
			stack.controlMu.Lock()
			table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
			debt := table.aggregate.tokens
			stack.controlMu.Unlock()
			minimum := -float64(icmpErrorReserveBurst)
			if debt < minimum {
				t.Fatalf("aggregate debt = %v, minimum %v", debt, minimum)
			}
		})
	}
}

func TestICMPErrorLimiterProductionPaths(t *testing.T) {
	type family struct {
		name, local, sourceA, sourceB, external string
	}
	type path struct {
		name                           string
		class                          icmpErrorResponseClass
		promiscuous                    bool
		v4Type, v4Code, v6Type, v6Code byte
		setup                          func(*testing.T, *Stack)
		inject                         func(*testing.T, *Stack, netip.Addr, netip.Addr, uint16)
	}
	families := []family{
		{name: "IPv4", local: "192.0.2.220", sourceA: "198.51.100.220", sourceB: "198.51.100.221", external: "203.0.113.220"},
		{name: "IPv6", local: "2001:db8::220", sourceA: "2001:db8:1::220", sourceB: "2001:db8:1::221", external: "2001:db8:2::220"},
	}
	paths := []path{
		{
			name: "AdministrativeUnreachable", class: icmpErrorResponsePortUnreachable, promiscuous: true,
			v4Type: ICMPv4TypeDestinationUnreachable, v4Code: ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited,
			v6Type: ICMPv6TypeDestinationUnreachable, v6Code: ICMPv6DestinationUnreachableCodeAdministrativelyProhibited,
			setup: func(t *testing.T, stack *Stack) {
				forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
					if rejectErr := request.Reject(); rejectErr != nil {
						t.Errorf("ICMP Reject = %v", rejectErr)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = forwarder.Close() })
			},
			inject: func(t *testing.T, stack *Stack, source, target netip.Addr, _ uint16) {
				message := ICMPMessage{Source: source, Destination: target}
				if err := message.SetEchoRequest(1, 1, nil); err != nil {
					t.Fatal(err)
				}
				icmpWire, err := message.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				protocol := ProtocolICMPv4
				if source.Is6() {
					protocol = ProtocolICMPv6
				}
				packet, err := (IPPacket{
					Source: source, Destination: target, Protocol: protocol, HopLimit: 64, Payload: icmpWire,
				}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if err = writeTestPacket(stack, packet); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "FragmentReassemblyTimeout", class: icmpErrorResponseFragmentTimeout,
			v4Type: ICMPv4TypeTimeExceeded, v4Code: ICMPv4TimeExceededCodeFragmentReassembly,
			v6Type: ICMPv6TypeTimeExceeded, v6Code: ICMPv6TimeExceededCodeFragmentReassembly,
			inject: func(t *testing.T, stack *Stack, source, target netip.Addr, identification uint16) {
				payload := bytes.Repeat([]byte{0x5a}, 2000)
				var fragments [][]byte
				lifetime := fragmentIPv6Lifetime
				if source.Is4() {
					fragments = buildIPv4Fragments(source, target, ProtocolUDP, payload, 1280, identification)
					lifetime = fragmentIPv4Lifetime
				} else {
					fragments = buildIPv6FragmentsWithOptions(source, target, ProtocolUDP, payload, 1280, uint32(identification), ipPacketOptions{})
				}
				start := time.Now()
				if err := writeTestPacket(stack, fragments[0]); err != nil {
					t.Fatal(err)
				}
				stack.expireFragments(start.Add(lifetime + time.Second))
			},
		},
		{
			name: "PortUnreachable", class: icmpErrorResponsePortUnreachable,
			v4Type: ICMPv4TypeDestinationUnreachable, v4Code: ICMPv4DestinationUnreachableCodePort,
			v6Type: ICMPv6TypeDestinationUnreachable, v6Code: ICMPv6DestinationUnreachableCodePort,
			inject: func(t *testing.T, stack *Stack, source, target netip.Addr, _ uint16) {
				if err := writeTestPacket(stack, buildTestUDP(source, target, 42000, 53000, []byte("probe"))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ProtocolUnreachable", class: icmpErrorResponseParameterProblem,
			v4Type: ICMPv4TypeDestinationUnreachable, v4Code: ICMPv4DestinationUnreachableCodeProtocol,
			v6Type: ICMPv6TypeParameterProblem, v6Code: ICMPv6ParameterProblemCodeUnrecognizedNextHeader,
			inject: func(t *testing.T, stack *Stack, source, target netip.Addr, _ uint16) {
				if err := writeTestPacket(stack, buildIPPacket(source, target, 99, []byte("unknown"), 1, true)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ParameterProblem", class: icmpErrorResponseParameterProblem,
			v4Type: ICMPv4TypeParameterProblem, v4Code: ICMPv4ParameterProblemCodePointer,
			v6Type: ICMPv6TypeParameterProblem, v6Code: ICMPv6ParameterProblemCodeUnrecognizedOption,
			inject: func(t *testing.T, stack *Stack, source, target netip.Addr, _ uint16) {
				var packet []byte
				if source.Is4() {
					packet = buildTestIPv4Options(source, target, []byte{IPv4HeaderOptionRecordRoute, 1})
				} else {
					packet = buildTestIPv6Extension(source, target, IPv6ExtensionHeaderHopByHop,
						[]byte{ProtocolUDP, 0, 0x80, 0, 1, 0, 0, 0})
				}
				if err := writeTestPacket(stack, packet); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, family := range families {
		family := family
		for _, path := range paths {
			path := path
			t.Run(family.name+"/"+path.name, func(t *testing.T) {
				local := netip.MustParseAddr(family.local)
				sourceA := netip.MustParseAddr(family.sourceA)
				sourceB := netip.MustParseAddr(family.sourceB)
				target := local
				if path.promiscuous {
					target = netip.MustParseAddr(family.external)
				}
				bits := local.BitLen()
				stack, err := New(Config{
					LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)},
					Promiscuous:    path.promiscuous,
					MTU:            1400,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
				if path.setup != nil {
					path.setup(t, stack)
				}
				wantProtocol := byte(ProtocolICMPv4)
				wantType, wantCode := path.v4Type, path.v4Code
				if local.Is6() {
					wantProtocol = ProtocolICMPv6
					wantType, wantCode = path.v6Type, path.v6Code
				}
				admissionStart := time.Now()
				for packetIndex := 0; packetIndex < icmpErrorTargetBurst; packetIndex++ {
					path.inject(t, stack, sourceA, target, uint16(220+packetIndex))
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						t.Fatalf("source %s response %d was unexpectedly limited", sourceA, packetIndex+1)
					}
					response, parsed := parseIPPacket(consumeTestPacket(&stack.outbound, entry), false)
					if !parsed || response.protocol != wantProtocol || response.target != sourceA || len(response.payload) < 2 || response.payload[0] != wantType || response.payload[1] != wantCode {
						t.Fatalf("source %s response = %#v", sourceA, response)
					}
				}
				stack.controlMu.Lock()
				var table *icmpErrorLimiterTable
				if stack.icmpErrorLimiters != nil {
					table = stack.icmpErrorLimiters.tables[path.class]
				}
				var blocked *tokenBucket
				if table != nil {
					for index := range table.entries {
						if table.entries[index].destination == sourceA {
							blocked = &table.entries[index].bucket
							break
						}
					}
				}
				remaining := -1.0
				if blocked != nil {
					remaining = blocked.tokens
				}
				stack.controlMu.Unlock()
				if blocked == nil {
					t.Fatalf("source %s did not create a destination bucket", sourceA)
				}
				if elapsed := time.Since(admissionStart); elapsed < 2*time.Second {
					maxRefill := elapsed.Seconds() * icmpErrorTargetRate
					if remaining > maxRefill+1e-6 {
						t.Fatalf("source %s retained %v destination tokens after %d responses (elapsed %v)", sourceA, remaining, icmpErrorTargetBurst, elapsed)
					}
				}
				stack.controlMu.Lock()
				sourceBytes := sourceA.As16()
				blocked = table.targetBucketLocked(sourceA, sipHash24(stack.icmpErrorLimiterSecret, sourceBytes[:]), time.Now())
				*blocked = tokenBucket{updated: time.Now().Add(time.Hour)}
				stack.controlMu.Unlock()
				path.inject(t, stack, sourceA, target, 280)
				if entry, ok := stack.outbound.tryDequeue(); ok {
					stack.outbound.release(entry)
					t.Fatalf("source %s exceeded its destination burst", sourceA)
				}

				path.inject(t, stack, sourceB, target, 281)
				response := readOutboundPacket(t, stack)
				parsed, ok := parseIPPacket(response, false)
				if !ok || parsed.source != target || parsed.target != sourceB || len(parsed.payload) < 8 || parsed.payload[0] != wantType || parsed.payload[1] != wantCode {
					t.Fatalf("production path response = %x, parsed = %#v", response, parsed)
				}
			})
		}
	}
}

func TestICMPv6ErrorSizeLimit(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("2001:db8::95"), netip.MustParseAddr("2001:db8:1::95"))
	defer stack.Close()
	request := buildTestUDP(link.remote, link.local, 55000, 55001, bytes.Repeat([]byte{0x5a}, 1400))
	if err := writeTestPacket(stack, request); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMPv6 error")
	}
	if len(response) != ipv6MinimumMTU {
		t.Fatalf("ICMPv6 error size = %d, want %d", len(response), ipv6MinimumMTU)
	}
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) != ipv6MinimumMTU-40 || parsed.payload[0] != 1 || parsed.payload[1] != 4 {
		t.Fatalf("ICMPv6 error = %x, parsed = %v", response[:48], ok)
	}
}

func TestLimitedBroadcastSourceIsDropped(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.95"), netip.MustParseAddr("198.51.100.95"))
	defer stack.Close()
	request := buildTestUDP(netip.MustParseAddr("255.255.255.255"), link.local, 55002, 55003, []byte("drop"))
	if err := writeTestPacket(stack, request); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		t.Fatalf("limited-broadcast source produced a response: %x", response)
	case <-time.After(25 * time.Millisecond):
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("limited-broadcast drops = %d, want 1", dropped)
	}
}

func BenchmarkICMPErrorLimiterReject(b *testing.B) {
	destination := netip.MustParseAddr("198.51.100.201")
	for _, test := range []struct {
		name string
	}{
		{name: "OrdinaryTarget"},
		{name: "SameOwner"},
		{name: "KeyedCollision"},
		{name: "ReserveExhausted"},
	} {
		b.Run(test.name, func(b *testing.B) {
			stack := Stack{timestampEpoch: time.Now(), icmpErrorLimiterSecret: [16]byte{1, 2, 3, 4}}
			now := time.Now()
			future := now.Add(time.Hour)
			futureStamp := monotonicStampAt(stack.timestampEpoch, future)
			stack.controlMu.Lock()
			table := stack.icmpErrorLimiterTableLocked(icmpErrorResponsePortUnreachable)
			address := destination.As16()
			hash := sipHash24(stack.icmpErrorLimiterSecret, address[:])
			switch test.name {
			case "OrdinaryTarget":
				table.aggregate = tokenBucket{tokens: icmpErrorAggregateBurst, updated: now}
				*table.targetBucketLocked(destination, hash, now) = tokenBucket{updated: future}
			case "SameOwner":
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{tokens: icmpErrorReserveBurst, updated: now}
				table.reserve[0][uint32(hash>>32)%icmpErrorReserveBuckets] = icmpErrorReserveSlot{
					availableAt: futureStamp,
					ownerHash:   hash,
				}
			case "KeyedCollision":
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{tokens: icmpErrorReserveBurst, updated: now}
				table.reserve[0][uint32(hash>>32)%icmpErrorReserveBuckets] = icmpErrorReserveSlot{availableAt: futureStamp, ownerHash: hash + 1}
				table.reserve[1][uint32(hash>>48)%icmpErrorReserveBuckets] = icmpErrorReserveSlot{availableAt: futureStamp, ownerHash: hash + 2}
			case "ReserveExhausted":
				table.aggregate = tokenBucket{updated: future}
				table.reserveAggregate = tokenBucket{updated: future}
			}
			stack.controlMu.Unlock()
			if stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, destination) {
				b.Fatal("benchmark limiter admitted its setup probe")
			}

			b.ReportAllocs()
			b.ResetTimer()
			var allowed bool
			for index := 0; index < b.N; index++ {
				allowed = stack.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, destination)
			}
			if allowed {
				b.Fatal("exhausted limiter admitted a response")
			}
		})
	}
}

func BenchmarkPublicICMPErrorCodec(b *testing.B) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	reporter := netip.MustParseAddr("198.51.100.254")
	quote := buildIPPacket(source, target, ProtocolUDP, make([]byte, udpHeaderSize+64), 31, true)
	plainError := ICMPError{
		Reporter: reporter, Type: ICMPv4TypeTimeExceeded,
		Code: ICMPv4TimeExceededCodeTTLInTransit, QuotedPacket: quote,
	}
	extendedError := plainError
	if err := extendedError.SetExtensionObjects([]ICMPExtensionObject{
		{Class: 0xfe, Type: 1, Data: []byte{1, 2, 3, 4}},
	}); err != nil {
		b.Fatal(err)
	}
	plainMessage, err := plainError.ICMPMessage(source)
	if err != nil {
		b.Fatal(err)
	}
	extendedMessage, err := extendedError.ICMPMessage(source)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ParsePlain", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(plainMessage.Body)))
		var parsed ICMPError
		var parseErr error
		for i := 0; i < b.N; i++ {
			parsed, parseErr = plainMessage.ICMPError()
		}
		if parseErr != nil || parsed.Reporter != reporter {
			b.Fatal(parseErr)
		}
	})
	b.Run("ParseExtended", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(extendedMessage.Body)))
		var parsed ICMPError
		var parseErr error
		for i := 0; i < b.N; i++ {
			parsed, parseErr = extendedMessage.ICMPError()
		}
		if parseErr != nil || len(parsed.Extensions) == 0 {
			b.Fatal(parseErr)
		}
	})
	b.Run("ExtensionObjects", func(b *testing.B) {
		b.ReportAllocs()
		var objects []ICMPExtensionObject
		var parseErr error
		for i := 0; i < b.N; i++ {
			objects, parseErr = extendedError.ExtensionObjects()
		}
		if parseErr != nil || len(objects) != 1 {
			b.Fatal(parseErr)
		}
	})
	b.Run("ConstructPlain", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(plainMessage.Body)))
		var message ICMPMessage
		var constructErr error
		for i := 0; i < b.N; i++ {
			message, constructErr = plainError.ICMPMessage(source)
		}
		if constructErr != nil || len(message.Body) == 0 {
			b.Fatal(constructErr)
		}
	})
	b.Run("ConstructExtended", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(extendedMessage.Body)))
		var message ICMPMessage
		var constructErr error
		for i := 0; i < b.N; i++ {
			message, constructErr = extendedError.ICMPMessage(source)
		}
		if constructErr != nil || len(message.Body) == 0 {
			b.Fatal(constructErr)
		}
	})
}

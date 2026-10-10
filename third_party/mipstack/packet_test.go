package mipstack

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type binaryAppender interface {
	AppendBinary([]byte) ([]byte, error)
}

var (
	_ encoding.BinaryMarshaler = IPPacket{}
	_ encoding.BinaryMarshaler = TCPSegment{}
	_ encoding.BinaryMarshaler = UDPDatagram{}
	_ encoding.BinaryMarshaler = ICMPMessage{}
	_ binaryAppender           = IPPacket{}
	_ binaryAppender           = TCPSegment{}
	_ binaryAppender           = UDPDatagram{}
	_ binaryAppender           = ICMPMessage{}
)

func referenceChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func referenceTransportChecksum(source, destination netip.Addr, protocol byte, payload []byte) uint16 {
	source, destination = source.Unmap(), destination.Unmap()
	pseudoHeader := make([]byte, 0, 40+len(payload))
	pseudoHeader = append(pseudoHeader, source.AsSlice()...)
	pseudoHeader = append(pseudoHeader, destination.AsSlice()...)
	if source.Is4() {
		pseudoHeader = append(pseudoHeader, 0, protocol, byte(len(payload)>>8), byte(len(payload)))
	} else {
		length := uint32(len(payload))
		pseudoHeader = append(pseudoHeader,
			byte(length>>24), byte(length>>16), byte(length>>8), byte(length), 0, 0, 0, protocol)
	}
	pseudoHeader = append(pseudoHeader, payload...)
	return referenceChecksum(pseudoHeader)
}

func TestChecksumRFC1071KnownAnswers(t *testing.T) {
	data := mustCodecVector(t, "0001f203f4f5f6f7")
	if got := referenceChecksum(data); got != 0x220d {
		t.Fatalf("reference checksum = %#x, want %#x", got, uint16(0x220d))
	}
	if got := checksum(data); got != 0x220d {
		t.Fatalf("checksum = %#x, want %#x", got, uint16(0x220d))
	}
	withChecksum := mustCodecVector(t, "0001f203f4f5f6f7220d")
	if got := referenceChecksum(withChecksum); got != 0 {
		t.Fatalf("reference checksum over checksummed RFC vector = %#x, want zero", got)
	}
	if got := checksum(withChecksum); got != 0 {
		t.Fatalf("checksum over checksummed RFC vector = %#x, want zero", got)
	}
}

func TestPublicIPPacketCodecKnownAnswerMutations(t *testing.T) {
	tcp4 := mustCodecVector(t, "4500003c5053400040066665c0000201c0000202"+
		"b5fa01bbe3655ed100000000a002faf0e3b40000020405b40402080ad7fe1368000000000103030a")
	udp6 := mustCodecVector(t, "67e123450011114020010db800000000000000000000000320010db8000000000000000000000004"+
		"ffff30390011600a000102030405060708")
	fragment6 := mustCodecVector(t, "622345670020003f20010db800000000000000000000000920010db800000000000000000000000a"+
		"2c000502000000000600000110203040000102030405060708090a0b0c0d0e0f")
	tests := []struct {
		name   string
		base   []byte
		mutate func([]byte)
	}{
		{name: "IPv4 version", base: tcp4, mutate: func(wire []byte) { wire[0] = 0x55 }},
		{name: "IPv4 short IHL", base: tcp4, mutate: func(wire []byte) { wire[0] = 0x44 }},
		{name: "IPv4 total length below header", base: tcp4, mutate: func(wire []byte) {
			binary.BigEndian.PutUint16(wire[2:4], 19)
			repairReferenceIPv4Checksum(wire)
		}},
		{name: "IPv4 reserved fragment bit", base: tcp4, mutate: func(wire []byte) {
			wire[6] |= 0x80
			repairReferenceIPv4Checksum(wire)
		}},
		{name: "IPv4 checksum", base: tcp4, mutate: func(wire []byte) { wire[8] ^= 1 }},
		{name: "IPv6 declared length", base: udp6, mutate: func(wire []byte) {
			binary.BigEndian.PutUint16(wire[4:6], binary.BigEndian.Uint16(wire[4:6])+1)
		}},
		{name: "IPv6 extension length", base: fragment6, mutate: func(wire []byte) { wire[41] = 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := append([]byte(nil), test.base...)
			test.mutate(wire)
			before := append([]byte(nil), wire...)
			if _, err := ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("ParseIPPacket error = %v, want EINVAL", err)
			}
			if !bytes.Equal(wire, before) {
				t.Fatal("failed ParseIPPacket modified its input")
			}
		})
	}
}

func TestPublicIPPacketCodecKnownAnswers(t *testing.T) {
	tests := []struct {
		name   string
		wire   string
		packet IPPacket
	}{
		{
			name: "Linux IPv4 TCP SYN",
			wire: "4500003c5053400040066665c0000201c0000202" +
				"b5fa01bbe3655ed100000000a002faf0e3b40000" +
				"020405b40402080ad7fe1368000000000103030a",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
				Protocol: ProtocolTCP, HopLimit: 64, Identification: 0x5053, DontFragment: true,
				Payload: mustCodecVector(t, "b5fa01bbe3655ed100000000a002faf0e3b40000"+
					"020405b40402080ad7fe1368000000000103030a"),
			},
		},
		{
			name: "IPv6 TCP odd payload",
			wire: "6ab543210025062520010db8000000000000000000000001" +
				"20010db8000000000000000000000002" +
				"5ba020fb01020304a0b0c0d080184567d9560000" +
				"0101080a11223344556677880102030405",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
				Protocol: ProtocolTCP, HopLimit: 37, TrafficClass: 0xab, FlowLabel: 0x54321,
				Payload: mustCodecVector(t, "5ba020fb01020304a0b0c0d080184567d9560000"+
					"0101080a11223344556677880102030405"),
			},
		},
		{
			name: "IPv4 TCP SACK",
			wire: "45000048999940004006b4dfc6336402c0000201" +
				"01bbb5fa1111111122222222d0101000562e0000" +
				"0101080a01020304050607080101051200001000000020000000300000004000",
			packet: IPPacket{
				Source: netip.MustParseAddr("198.51.100.2"), Destination: netip.MustParseAddr("192.0.2.1"),
				Protocol: ProtocolTCP, HopLimit: 64, Identification: 0x9999, DontFragment: true,
				Payload: mustCodecVector(t, "01bbb5fa1111111122222222d0101000562e0000"+
					"0101080a01020304050607080101051200001000000020000000300000004000"),
			},
		},
		{
			name: "IPv4 UDP odd payload",
			wire: "452e0023123440003711452dc0000203c6336404" + "14e90035000ff26d00010203040506",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.3"), Destination: netip.MustParseAddr("198.51.100.4"),
				Protocol: ProtocolUDP, HopLimit: 55, TrafficClass: 0x2e, Identification: 0x1234, DontFragment: true,
				Payload: mustCodecVector(t, "14e90035000ff26d00010203040506"),
			},
		},
		{
			name: "IPv4 UDP zero checksum",
			wire: "45000021abcd00004011e2bfc0000205c6336406" + "30390035000d000068656c6c6f",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.5"), Destination: netip.MustParseAddr("198.51.100.6"),
				Protocol: ProtocolUDP, HopLimit: 64, Identification: 0xabcd,
				Payload: mustCodecVector(t, "30390035000d000068656c6c6f"),
			},
		},
		{
			name: "IPv4 options and odd payload",
			wire: "47030021beef400011fd2a55cb007101cb007102" + "0194040000000000deadbeef01",
			packet: IPPacket{
				Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("203.0.113.2"),
				Protocol: 253, HopLimit: 17, TrafficClass: 3, Identification: 0xbeef, DontFragment: true,
				IPv4Options: mustCodecVector(t, "0194040000000000"), Payload: mustCodecVector(t, "deadbeef01"),
			},
		},
		{
			name: "IPv6 UDP odd payload",
			wire: "67e123450011114020010db8000000000000000000000003" +
				"20010db8000000000000000000000004" + "ffff30390011600a000102030405060708",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::3"), Destination: netip.MustParseAddr("2001:db8::4"),
				Protocol: ProtocolUDP, HopLimit: 64, TrafficClass: 0x7e, FlowLabel: 0x12345,
				Payload: mustCodecVector(t, "ffff30390011600a000102030405060708"),
			},
		},
		{
			name: "Linux IPv4 ICMP Echo",
			wire: "45000025ff4740004001b78cc0000201c0000202" + "080039bfaa2f0001000102030405060708",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
				Protocol: ProtocolICMPv4, HopLimit: 64, Identification: 0xff47, DontFragment: true,
				Payload: mustCodecVector(t, "080039bfaa2f0001000102030405060708"),
			},
		},
		{
			name: "IPv6 ICMP Echo odd payload",
			wire: "6000000000113aff20010db8000000000000000000000005" +
				"20010db8000000000000000000000006" + "8000a77a12345678000102030405060708",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::5"), Destination: netip.MustParseAddr("2001:db8::6"),
				Protocol: ProtocolICMPv6, HopLimit: 255,
				Payload: mustCodecVector(t, "8000a77a12345678000102030405060708"),
			},
		},
		{
			name: "IPv4 first fragment",
			wire: "45000024778820001ffd170dc000020ac633640a" + "000102030405060708090a0b0c0d0e0f",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.10"),
				Protocol: 253, HopLimit: 31, Identification: 0x7788, MoreFragments: true,
				Payload: mustCodecVector(t, "000102030405060708090a0b0c0d0e0f"),
			},
		},
		{
			name: "IPv4 last fragment",
			wire: "45000019778800021ffd3716c000020ac633640a1011121314",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.10"),
				Protocol: 253, HopLimit: 31, Identification: 0x7788, FragmentOffset: 16,
				Payload: mustCodecVector(t, "1011121314"),
			},
		},
		{
			name: "IPv6 atomic fragment",
			wire: "655abcde00162c4020010db8000000000000000000000007" +
				"20010db8000000000000000000000008" + "11000000deadbeef9c409c41000e318a61746f6d6963",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::7"), Destination: netip.MustParseAddr("2001:db8::8"),
				Protocol: IPv6ExtensionHeaderFragment, HopLimit: 64, TrafficClass: 0x55, FlowLabel: 0xabcde,
				Payload: mustCodecVector(t, "11000000deadbeef9c409c41000e318a61746f6d6963"),
			},
		},
		{
			name: "IPv6 Hop-by-Hop first fragment",
			wire: "622345670020003f20010db8000000000000000000000009" +
				"20010db800000000000000000000000a" +
				"2c000502000000000600000110203040000102030405060708090a0b0c0d0e0f",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::9"), Destination: netip.MustParseAddr("2001:db8::a"),
				Protocol: IPv6ExtensionHeaderHopByHop, HopLimit: 63, TrafficClass: 0x22, FlowLabel: 0x34567,
				Payload: mustCodecVector(t, "2c000502000000000600000110203040000102030405060708090a0b0c0d0e0f"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := mustCodecVector(t, test.wire)
			before := append([]byte(nil), wire...)
			packet, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("ParseIPPacket: %v", err)
			}
			if !bytes.Equal(wire, before) {
				t.Fatal("ParseIPPacket modified the known-answer input")
			}
			if !equalIPPackets(packet, test.packet) {
				t.Fatalf("parsed packet = %+v, want %+v", packet, test.packet)
			}
			encoded, err := test.packet.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("MarshalBinary: error=%v\n got %x\nwant %x", err, encoded, wire)
			}
			if packet.Source.Is4() {
				headerSize := int(wire[0]&0x0f) * 4
				if got := referenceChecksum(wire[:headerSize]); got != 0 {
					t.Fatalf("IPv4 header reference checksum = %#x, want zero", got)
				}
			}
		})
	}

	optionPacket, err := ParseIPPacket(mustCodecVector(t,
		"47030021beef400011fd2a55cb007101cb0071020194040000000000deadbeef01"))
	if err != nil {
		t.Fatal(err)
	}
	options, err := optionPacket.IPv4HeaderOptions()
	if err != nil || len(options) != 3 || options[0].Type != IPv4HeaderOptionNOP ||
		options[1].Type != IPv4HeaderOptionRouterAlert || options[2].Type != IPv4HeaderOptionEnd {
		t.Fatalf("IPv4HeaderOptions = %+v, %v", options, err)
	}
	if alert, ok := options[1].RouterAlert(); !ok || alert != 0 {
		t.Fatalf("IPv4 Router Alert = %d/%t", alert, ok)
	}
}

func repairReferenceIPv4Checksum(wire []byte) {
	headerSize := int(wire[0]&0x0f) * 4
	wire[10], wire[11] = 0, 0
	binary.BigEndian.PutUint16(wire[10:12], referenceChecksum(wire[:headerSize]))
}

func repairReferenceTransportChecksum(source, destination netip.Addr, protocol byte, payload []byte, offset int) {
	payload[offset], payload[offset+1] = 0, 0
	value := referenceTransportChecksum(source, destination, protocol, payload)
	if protocol == ProtocolUDP && value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(payload[offset:offset+2], value)
}

func FuzzPublicIPPacketWireEncoding(f *testing.F) {
	f.Add(false, byte(99), byte(64), byte(0x2e), uint32(0), uint16(0x1234), true, byte(0), []byte("IPv4 payload"))
	f.Add(true, byte(253), byte(1), byte(0xab), uint32(0x54321), uint16(0), false, byte(0), []byte("IPv6 payload"))
	f.Fuzz(func(t *testing.T, ipv6 bool, protocol, hopLimit, trafficClass byte, flowLabel uint32,
		identification uint16, dontFragment bool, optionForm byte, payload []byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		packet := IPPacket{
			Source: netip.MustParseAddr("192.0.2.101"), Destination: netip.MustParseAddr("198.51.100.101"),
			Protocol: int(protocol), HopLimit: int(hopLimit), TrafficClass: int(trafficClass),
			Identification: identification, DontFragment: dontFragment, Payload: payload,
		}
		switch optionForm % 4 {
		case 1:
			packet.IPv4Options = []byte{IPv4HeaderOptionNOP}
		case 2:
			packet.IPv4Options = []byte{IPv4HeaderOptionRouterAlert, 4, 0, 0}
		case 3:
			packet.IPv4Options = []byte{IPv4HeaderOptionEnd, 0xaa, 0xbb}
		}
		if ipv6 {
			packet.Source = netip.MustParseAddr("2001:db8::101")
			packet.Destination = netip.MustParseAddr("2001:db8:1::101")
			packet.FlowLabel = flowLabel & ipv6MaximumFlowLabel
			packet.Identification, packet.DontFragment, packet.IPv4Options = 0, false, nil
			switch packet.Protocol {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting, IPv6ExtensionHeaderFragment,
				IPv6ExtensionHeaderAuthentication, IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility:
				packet.Protocol = 253
			}
		}
		wire, err := packet.AppendBinary(nil)
		if err != nil {
			t.Fatalf("AppendBinary: %v (IPv6=%t protocol=%d hop=%d traffic=%d flow=%#x identification=%d DF=%t optionForm=%d options=%x payload=%d)",
				err, ipv6, protocol, hopLimit, trafficClass, flowLabel, identification, dontFragment,
				optionForm, packet.IPv4Options, len(payload))
		}
		assertIPPacketWire(t, packet, wire)
		parsed, err := ParseIPPacket(wire)
		if err != nil {
			t.Fatalf("ParseIPPacket(encoded packet): %v", err)
		}
		if parsed.Source != packet.Source || parsed.Destination != packet.Destination ||
			parsed.Protocol != packet.Protocol || parsed.HopLimit != packet.HopLimit ||
			parsed.TrafficClass != packet.TrafficClass || parsed.FlowLabel != packet.FlowLabel ||
			parsed.Identification != packet.Identification || parsed.DontFragment != packet.DontFragment ||
			!bytes.Equal(parsed.Payload, packet.Payload) {
			t.Fatalf("parsed encoded packet = %+v, want fields from %+v", parsed, packet)
		}
	})
}

func equalIPPackets(left, right IPPacket) bool {
	return left.Source == right.Source && left.Destination == right.Destination &&
		left.Protocol == right.Protocol && left.HopLimit == right.HopLimit &&
		left.TrafficClass == right.TrafficClass && left.FlowLabel == right.FlowLabel &&
		left.Identification == right.Identification && left.DontFragment == right.DontFragment &&
		left.MoreFragments == right.MoreFragments && left.FragmentOffset == right.FragmentOffset &&
		bytes.Equal(left.IPv4Options, right.IPv4Options) && bytes.Equal(left.Payload, right.Payload)
}

func assertIPPacketWire(t testing.TB, packet IPPacket, wire []byte) {
	t.Helper()
	if packet.Source.Unmap().Is4() {
		headerSize := 20 + (len(packet.IPv4Options)+3)&^3
		if len(wire) != headerSize+len(packet.Payload) || wire[0] != 0x40|byte(headerSize/4) ||
			wire[1] != byte(packet.TrafficClass) || int(binary.BigEndian.Uint16(wire[2:4])) != len(wire) ||
			binary.BigEndian.Uint16(wire[4:6]) != packet.Identification || wire[8] != byte(packet.HopLimit) ||
			wire[9] != byte(packet.Protocol) || !bytes.Equal(wire[12:16], packet.Source.Unmap().AsSlice()) ||
			!bytes.Equal(wire[16:20], packet.Destination.Unmap().AsSlice()) {
			t.Fatalf("IPv4 fixed header does not match semantic value: %x", wire[:20])
		}
		fragment := uint16(packet.FragmentOffset / 8)
		if packet.DontFragment {
			fragment |= 0x4000
		}
		if packet.MoreFragments {
			fragment |= 0x2000
		}
		if binary.BigEndian.Uint16(wire[6:8]) != fragment || referenceChecksum(wire[:headerSize]) != 0 {
			t.Fatalf("IPv4 fragment/checksum fields are invalid: %x", wire[:headerSize])
		}
		contentSize := len(packet.IPv4Options)
		for offset := 0; offset < len(packet.IPv4Options); {
			optionType := packet.IPv4Options[offset]
			if optionType == IPv4HeaderOptionEnd {
				contentSize = offset + 1
				break
			}
			if optionType == IPv4HeaderOptionNOP {
				offset++
			} else {
				offset += int(packet.IPv4Options[offset+1])
			}
		}
		if !bytes.Equal(wire[20:20+contentSize], packet.IPv4Options[:contentSize]) {
			t.Fatalf("IPv4 options = %x, want prefix %x", wire[20:headerSize], packet.IPv4Options[:contentSize])
		}
		for _, value := range wire[20+contentSize : headerSize] {
			if value != 0 {
				t.Fatalf("IPv4 option padding is nonzero: %x", wire[20:headerSize])
			}
		}
		if !bytes.Equal(wire[headerSize:], packet.Payload) {
			t.Fatalf("IPv4 payload = %x, want %x", wire[headerSize:], packet.Payload)
		}
		return
	}
	if len(wire) != 40+len(packet.Payload) || wire[0]>>4 != 6 ||
		int(wire[0]&0x0f)<<4|int(wire[1]>>4) != packet.TrafficClass ||
		uint32(wire[1]&0x0f)<<16|uint32(binary.BigEndian.Uint16(wire[2:4])) != packet.FlowLabel ||
		int(binary.BigEndian.Uint16(wire[4:6])) != len(packet.Payload) || wire[6] != byte(packet.Protocol) ||
		wire[7] != byte(packet.HopLimit) || !bytes.Equal(wire[8:24], packet.Source.AsSlice()) ||
		!bytes.Equal(wire[24:40], packet.Destination.AsSlice()) || !bytes.Equal(wire[40:], packet.Payload) {
		t.Fatalf("IPv6 wire does not match semantic value: %x", wire)
	}
}

func TestChecksumMatchesReference(t *testing.T) {
	data := make([]byte, 65535)
	for index := range data {
		data[index] = byte(index*37 + 11)
	}
	for _, size := range []int{0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 1500, 65534, 65535} {
		if got, want := checksum(data[:size]), referenceChecksum(data[:size]); got != want {
			t.Fatalf("checksum at length %d = %#x, want %#x", size, got, want)
		}
	}
}

func TestTransportChecksumMatchesReference(t *testing.T) {
	payload := make([]byte, 65535)
	for index := range payload {
		payload[index] = byte(index*53 + 17)
	}
	for _, test := range []struct {
		name           string
		source, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("198.51.100.231")},
		{"IPv6", netip.MustParseAddr("2001:db8:ffff:1::abcd"), netip.MustParseAddr("fdff:ffff:ffff:ffff::1234")},
	} {
		for _, size := range []int{0, 1, 7, 8, 15, 16, 17, 1500, 65535} {
			if got, want := transportChecksum(test.source, test.target, ProtocolTCP, payload[:size]), referenceTransportChecksum(test.source, test.target, ProtocolTCP, payload[:size]); got != want {
				t.Fatalf("%s transport checksum at length %d = %#x, want %#x", test.name, size, got, want)
			}
		}
	}
}

func TestTransportChecksumPartsMatchesContiguousPayload(t *testing.T) {
	payload := make([]byte, 257)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.17"), netip.MustParseAddr("198.51.100.17")},
		{netip.MustParseAddr("2001:db8::17"), netip.MustParseAddr("2001:db8:1::17")},
	} {
		want := transportChecksum(addresses[0], addresses[1], ProtocolUDP, payload)
		for split := 0; split <= len(payload); split++ {
			if got := transportChecksumParts(addresses[0], addresses[1], ProtocolUDP, len(payload), payload[:split], payload[split:]); got != want {
				t.Fatalf("%s split %d checksum = %#x, want %#x", addresses[0], split, got, want)
			}
		}
	}
}

func TestPublicIPPacketCodec(t *testing.T) {
	tests := []IPPacket{
		{
			Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
			Protocol: 99, HopLimit: 0, TrafficClass: 0xab, Identification: 0x1234, DontFragment: true,
			IPv4Options: []byte{1, 148, 4, 0, 0}, Payload: []byte("ipv4-codec-payload"),
		},
		{
			Source: netip.MustParseAddr("2001:db8::10"), Destination: netip.MustParseAddr("2001:db8::20"),
			Protocol: 60, HopLimit: 0, TrafficClass: 0xab, FlowLabel: 0xabcde,
			Payload: append([]byte{99, 0, 0x80, 0, 0, 0, 0, 0}, []byte("ipv6-upper-layer")...),
		},
	}
	for _, test := range tests {
		name := "IPv4"
		if test.Source.Is6() {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			prefix := []byte{0xaa, 0xbb, 0xcc}
			wire, err := test.AppendBinary(append([]byte(nil), prefix...))
			if err != nil {
				t.Fatalf("append packet: %v", err)
			}
			if !bytes.Equal(wire[:len(prefix)], prefix) {
				t.Fatal("AppendBinary changed the destination prefix")
			}
			wire = wire[len(prefix):]
			parsed, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("parse packet: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.Protocol != test.Protocol || parsed.HopLimit != 0 || parsed.TrafficClass != test.TrafficClass || parsed.FlowLabel != test.FlowLabel || parsed.Identification != test.Identification || parsed.DontFragment != test.DontFragment {
				t.Fatalf("parsed packet metadata = %+v, want %+v", parsed, test)
			}
			protocol, upper, err := parsed.UpperLayer()
			if err != nil {
				t.Fatalf("locate upper layer: %v", err)
			}
			wantProtocol, wantUpper := test.Protocol, test.Payload
			if test.Source.Is6() {
				wantProtocol, wantUpper = 99, test.Payload[8:]
			}
			if protocol != wantProtocol || !bytes.Equal(upper, wantUpper) {
				t.Fatalf("upper layer = protocol %d payload %x, want %d %x", protocol, upper, wantProtocol, wantUpper)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("packet round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
			inPlace := append([]byte(nil), wire...)
			inPlacePacket, err := ParseIPPacket(inPlace)
			if err != nil {
				t.Fatal(err)
			}
			inPlaceResult, appendErr := inPlacePacket.AppendBinary(inPlace[:0])
			if appendErr != nil || len(inPlaceResult) == 0 || &inPlaceResult[0] != &inPlace[0] || !bytes.Equal(inPlaceResult, wire) {
				t.Fatalf("in-place packet round trip: error=%v\n got %x\nwant %x", appendErr, inPlaceResult, wire)
			}
		})
	}
}

func TestPublicRawIPPacketCodec(t *testing.T) {
	tests := []IPPacket{
		{
			Source: netip.MustParseAddr("192.0.2.30"), Destination: netip.MustParseAddr("198.51.100.30"),
			Protocol: 99, HopLimit: 31, TrafficClass: 0x2e, Identification: 0x1234,
			IPv4Options: []byte{IPv4HeaderOptionNOP}, Payload: []byte("raw-ipv4-payload"),
		},
		{
			Source: netip.MustParseAddr("2001:db8::30"), Destination: netip.MustParseAddr("2001:db8::31"),
			Protocol: 99, HopLimit: 32, TrafficClass: 0x03, FlowLabel: 0x12345,
			Payload: []byte("raw-ipv6-payload"),
		},
	}
	for _, packet := range tests {
		strict, err := packet.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		prefix := []byte{0xaa, 0xbb, 0xcc}
		raw, err := packet.AppendRawBinary(append([]byte(nil), prefix...))
		if err != nil {
			t.Fatalf("append raw packet: %v", err)
		}
		if !bytes.Equal(raw[:len(prefix)], prefix) || !bytes.Equal(raw[len(prefix):], strict) {
			t.Fatalf("raw packet differs from strict encoding:\n raw %x\nstrict %x", raw[len(prefix):], strict)
		}
	}

	fragment := IPv6ExtensionHeader{
		Type: IPv6ExtensionHeaderFragment,
		Data: []byte{0x7f, 0, 0x06, 0x12, 0x34, 0x56, 0x78},
	}
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::32"), Destination: netip.MustParseAddr("2001:db8::33"), HopLimit: 64,
	}
	if err := packet.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{fragment}, 99, []byte("opaque")); err != nil {
		t.Fatal(err)
	}
	raw, err := packet.MarshalRawBinary()
	if err != nil {
		t.Fatalf("marshal reserved raw Fragment fields: %v", err)
	}
	if !bytes.Equal(raw[40:], packet.Payload) {
		t.Fatalf("raw payload = %x, want %x", raw[40:], packet.Payload)
	}
	strict, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal strict atomic Fragment: %v", err)
	}
	if strict[41] != 0 || binary.BigEndian.Uint16(strict[42:44]) != 0 {
		t.Fatalf("strict Fragment reserved fields = %x", strict[40:44])
	}
	if raw[41] != 0x7f || binary.BigEndian.Uint16(raw[42:44]) != 0x0006 {
		t.Fatalf("raw Fragment reserved fields = %x", raw[40:44])
	}
	wantRaw := append([]byte(nil), raw...)
	inPlace := append([]byte(nil), raw...)
	packet.Payload = inPlace[40:]
	inPlace, err = packet.AppendRawBinary(inPlace[:0])
	if err != nil || !bytes.Equal(inPlace, wantRaw) {
		t.Fatalf("in-place raw packet: error=%v\n got %x\nwant %x", err, inPlace, wantRaw)
	}

	malformed := IPPacket{
		Source: netip.MustParseAddr("192.0.2.34"), Destination: netip.MustParseAddr("198.51.100.34"),
		Protocol: 99, HopLimit: 64, IPv4Options: []byte{30, 1, 0xaa}, Payload: []byte("malformed-option"),
	}
	if _, err = malformed.MarshalBinary(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("strict malformed IPv4 option error = %v", err)
	}
	raw, err = malformed.MarshalRawBinary()
	if err != nil {
		t.Fatalf("marshal raw malformed IPv4 option: %v", err)
	}
	if !bytes.Equal(raw[20:24], []byte{30, 1, 0xaa, 0}) || InternetChecksum(raw[:24]) != 0 {
		t.Fatalf("raw malformed IPv4 option packet = %x", raw)
	}
	if _, err = ParseIPPacket(raw); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("parse malformed raw IPv4 option error = %v", err)
	}
}

func TestPublicIPv4HeaderOptions(t *testing.T) {
	data := []byte{0xaa, 0xbb}
	options := []IPv4HeaderOption{
		{Type: IPv4HeaderOptionNOP},
		{Type: IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
		{Type: 30, Data: data},
		{Type: 30, Data: []byte{0xcc}},
		{Type: IPv4HeaderOptionEnd},
	}
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Protocol: 99, HopLimit: 64, Payload: []byte("structured-ipv4-options"),
	}
	if err := packet.SetIPv4HeaderOptions(options); err != nil {
		t.Fatalf("SetIPv4HeaderOptions: %v", err)
	}
	wantOptions := append([]byte(nil), packet.IPv4Options...)
	if literal := mustCodecVector(t, "01940400001e04aabb1e03cc00"); !bytes.Equal(wantOptions, literal) {
		t.Fatalf("structured IPv4 option wire = %x, want %x", wantOptions, literal)
	}
	data[0] ^= 0xff
	if !bytes.Equal(packet.IPv4Options, wantOptions) {
		t.Fatal("SetIPv4HeaderOptions retained caller storage")
	}
	parsed, err := packet.IPv4HeaderOptions()
	if err != nil {
		t.Fatalf("IPv4HeaderOptions: %v", err)
	}
	if len(parsed) != len(options) || parsed[0].Type != IPv4HeaderOptionNOP ||
		parsed[1].Type != IPv4HeaderOptionRouterAlert || !bytes.Equal(parsed[1].Data, []byte{0, 0}) ||
		parsed[2].Type != 30 || parsed[3].Type != 30 || parsed[4].Type != IPv4HeaderOptionEnd {
		t.Fatalf("parsed IPv4 options = %+v", parsed)
	}
	sourceRoute := IPv4HeaderOption{Type: IPv4HeaderOptionLooseSourceRoute}
	if !sourceRoute.Copied() || sourceRoute.Class() != 0 || sourceRoute.Number() != 3 {
		t.Fatalf("source-route type fields = copied %t class %d number %d", sourceRoute.Copied(), sourceRoute.Class(), sourceRoute.Number())
	}

	copyPacket := packet
	if err = copyPacket.SetIPv4HeaderOptions(parsed); err != nil {
		t.Fatalf("copy parsed IPv4 options: %v", err)
	}
	parsed[2].Data[0] ^= 0xff
	if packet.IPv4Options[7] != 0x55 {
		t.Fatal("IPv4HeaderOptions Data did not borrow IPv4Options")
	}
	if !bytes.Equal(copyPacket.IPv4Options, wantOptions) {
		t.Fatal("SetIPv4HeaderOptions did not copy parsed Data")
	}
	wire, err := copyPacket.AppendBinary(nil)
	if err != nil {
		t.Fatalf("encode IPv4 options: %v", err)
	}
	decoded, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("decode IPv4 options: %v", err)
	}
	decodedOptions, err := decoded.IPv4HeaderOptions()
	if err != nil || len(decodedOptions) != len(options) {
		t.Fatalf("decoded IPv4 options = %+v, %v", decodedOptions, err)
	}
}

func TestPublicRouterAlertOptions(t *testing.T) {
	for _, value := range []uint16{0, 1, 0xffff} {
		t.Run(fmt.Sprintf("value-%d", value), func(t *testing.T) {
			ipv4Option := IPv4HeaderOption{Type: IPv4HeaderOptionNOP, Data: []byte{1, 2, 3}}
			ipv4Option.SetRouterAlert(value)
			if got, ok := ipv4Option.RouterAlert(); !ok || got != value {
				t.Fatalf("IPv4 Router Alert = %d/%t, want %d/true", got, ok, value)
			}
			ipv4Packet := IPPacket{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
				Protocol: 99, HopLimit: 64, Payload: []byte("router-alert-v4"),
			}
			if err := ipv4Packet.SetIPv4HeaderOptions([]IPv4HeaderOption{{Type: IPv4HeaderOptionNOP}, ipv4Option}); err != nil {
				t.Fatalf("set IPv4 Router Alert: %v", err)
			}
			wire, err := ipv4Packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode IPv4 Router Alert: %v", err)
			}
			parsedPacket, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("parse IPv4 Router Alert: %v", err)
			}
			options, err := parsedPacket.IPv4HeaderOptions()
			if err != nil || len(options) < 2 {
				t.Fatalf("parse IPv4 Router Alert options: %+v, %v", options, err)
			}
			if got, ok := options[1].RouterAlert(); !ok || got != value {
				t.Fatalf("parsed IPv4 Router Alert = %d/%t, want %d/true", got, ok, value)
			}

			ipv6Option := IPv6ExtensionOption{Type: IPv6ExtensionOptionPad1, Data: []byte{1, 2, 3}}
			ipv6Option.SetRouterAlert(value)
			if got, ok := ipv6Option.RouterAlert(); !ok || got != value {
				t.Fatalf("IPv6 Router Alert = %d/%t, want %d/true", got, ok, value)
			}
			hopByHop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
			if err = hopByHop.SetOptions([]IPv6ExtensionOption{ipv6Option}); err != nil {
				t.Fatalf("set IPv6 Router Alert: %v", err)
			}
			ipv6Packet := IPPacket{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), HopLimit: 64,
			}
			if err = ipv6Packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hopByHop}, 99, []byte("router-alert-v6")); err != nil {
				t.Fatalf("set IPv6 Router Alert header: %v", err)
			}
			wire, err = ipv6Packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode IPv6 Router Alert: %v", err)
			}
			parsedPacket, err = ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("parse IPv6 Router Alert: %v", err)
			}
			headers, _, _, err := parsedPacket.IPv6ExtensionHeaders()
			if err != nil || len(headers) != 1 {
				t.Fatalf("parse IPv6 Router Alert headers: %+v, %v", headers, err)
			}
			options6, err := headers[0].Options()
			if err != nil || len(options6) < 1 {
				t.Fatalf("parse IPv6 Router Alert options: %+v, %v", options6, err)
			}
			if got, ok := options6[0].RouterAlert(); !ok || got != value {
				t.Fatalf("parsed IPv6 Router Alert = %d/%t, want %d/true", got, ok, value)
			}
		})
	}
	for index, option := range []IPv4HeaderOption{
		{},
		{Type: IPv4HeaderOptionRouterAlert},
		{Type: IPv4HeaderOptionRouterAlert, Data: []byte{0}},
		{Type: IPv4HeaderOptionRouterAlert, Data: []byte{0, 0, 0}},
	} {
		if value, ok := option.RouterAlert(); ok || value != 0 {
			t.Fatalf("malformed IPv4 Router Alert %d was accepted", index)
		}
	}
	for index, option := range []IPv6ExtensionOption{
		{},
		{Type: IPv6ExtensionOptionRouterAlert},
		{Type: IPv6ExtensionOptionRouterAlert, Data: []byte{0}},
		{Type: IPv6ExtensionOptionRouterAlert, Data: []byte{0, 0, 0}},
	} {
		if value, ok := option.RouterAlert(); ok || value != 0 {
			t.Fatalf("malformed IPv6 Router Alert %d was accepted", index)
		}
	}
}

func TestPublicIPv4HeaderOptionErrors(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		IPv4Options: []byte{IPv4HeaderOptionNOP},
	}
	want := append([]byte(nil), packet.IPv4Options...)
	tests := []struct {
		name    string
		options []IPv4HeaderOption
		wantErr error
	}{
		{name: "End data", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionEnd, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "NOP data", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionNOP, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "after End", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionEnd}, {Type: IPv4HeaderOptionNOP}}, wantErr: syscall.EINVAL},
		{name: "oversized", options: []IPv4HeaderOption{{Type: 30, Data: make([]byte, 39)}}, wantErr: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := packet.SetIPv4HeaderOptions(test.options); !errors.Is(err, test.wantErr) {
				t.Fatalf("SetIPv4HeaderOptions error = %v, want %v", err, test.wantErr)
			}
			if !bytes.Equal(packet.IPv4Options, want) {
				t.Fatal("failed SetIPv4HeaderOptions changed the receiver")
			}
		})
	}
	for _, raw := range [][]byte{{30}, {30, 1}, make([]byte, 41)} {
		packet.IPv4Options = raw
		if _, err := packet.IPv4HeaderOptions(); err == nil {
			t.Fatalf("IPv4HeaderOptions accepted %x", raw)
		}
	}
	v6 := IPPacket{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2")}
	if _, err := v6.IPv4HeaderOptions(); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv6 IPv4HeaderOptions error = %v", err)
	}
	if err := v6.SetIPv4HeaderOptions(nil); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv6 SetIPv4HeaderOptions error = %v", err)
	}
}

func TestPublicIPv4HeaderOptionsNormalizeEOLPadding(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Protocol: ProtocolUDP, HopLimit: 64,
		IPv4Options: []byte{IPv4HeaderOptionEnd, 0xaa, 0xbb, 0xcc}, Payload: make([]byte, udpHeaderSize),
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[20:24], []byte{0, 0, 0, 0}) {
		t.Fatalf("generated IPv4 EOL padding = %x, want zeros", wire[20:24])
	}

	raw := append([]byte(nil), wire...)
	copy(raw[21:24], []byte{0xaa, 0xbb, 0xcc})
	raw[10], raw[11] = 0, 0
	binary.BigEndian.PutUint16(raw[10:12], checksum(raw[:24]))
	parsed, err := ParseIPPacket(raw)
	if err != nil {
		t.Fatalf("parse nonzero IPv4 EOL padding: %v", err)
	}
	if !bytes.Equal(parsed.IPv4Options, raw[20:24]) {
		t.Fatalf("parsed IPv4 EOL padding = %x, want %x", parsed.IPv4Options, raw[20:24])
	}
	options, err := parsed.IPv4HeaderOptions()
	if err != nil || len(options) != 1 || options[0].Type != IPv4HeaderOptionEnd {
		t.Fatalf("structured IPv4 EOL = %+v, error=%v", options, err)
	}
	reencoded, err := parsed.AppendBinary(nil)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("normalized IPv4 packet: error=%v\n got %x\nwant %x", err, reencoded, wire)
	}
	wantRaw := append([]byte(nil), raw...)
	rawReencoded, err := parsed.AppendRawBinary(nil)
	if err != nil || !bytes.Equal(rawReencoded, wantRaw) {
		t.Fatalf("raw IPv4 packet round trip: error=%v\n got %x\nwant %x", err, rawReencoded, wantRaw)
	}
	rawReencoded, err = parsed.AppendRawBinary(raw[:0])
	if err != nil || !bytes.Equal(rawReencoded, wantRaw) {
		t.Fatalf("in-place raw IPv4 packet round trip: error=%v\n got %x\nwant %x", err, rawReencoded, wantRaw)
	}
	internal, ok := parseIPPacket(raw, false)
	if !ok || internal.parameterError {
		t.Fatalf("runtime parser rejected Linux-compatible EOL padding: %+v, ok=%t", internal, ok)
	}
}

func TestPublicIPv6ExtensionHeaders(t *testing.T) {
	unknownData := []byte{1, 2, 3}
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions([]IPv6ExtensionOption{
		{Type: IPv6ExtensionOptionRouterAlert, Data: []byte{0, 0}},
		{Type: 0xe3, Data: unknownData},
		{Type: IPv6ExtensionOptionPad1},
	}); err != nil {
		t.Fatalf("set Hop-by-Hop options: %v", err)
	}
	wantHop := append([]byte(nil), hop.Data...)
	if literal := mustCodecVector(t, "0105020000e3030102030001020000"); !bytes.Equal(wantHop, literal) {
		t.Fatalf("structured Hop-by-Hop option wire = %x, want %x", wantHop, literal)
	}
	unknownData[0] ^= 0xff
	if !bytes.Equal(hop.Data, wantHop) {
		t.Fatal("SetOptions retained caller storage")
	}
	options, err := hop.Options()
	if err != nil {
		t.Fatalf("parse Hop-by-Hop options: %v", err)
	}
	if len(options) < 3 || options[0].Type != IPv6ExtensionOptionRouterAlert || options[1].Type != 0xe3 ||
		options[1].Action() != 3 || !options[1].MayChangeInTransit() || !bytes.Equal(options[1].Data, []byte{1, 2, 3}) {
		t.Fatalf("parsed IPv6 options = %+v", options)
	}
	hopCopy := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = hopCopy.SetOptions(options); err != nil {
		t.Fatalf("copy parsed IPv6 options: %v", err)
	}
	options[1].Data[0] ^= 0xff
	if !bytes.Equal(hopCopy.Data, wantHop) {
		t.Fatal("SetOptions did not copy parsed Data")
	}

	destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
	if err = destination.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	routing := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: []byte{0, 0, 0, 0, 0, 0, 0}}
	fragment := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderFragment, Data: []byte{0, 0, 0, 0x12, 0x34, 0x56, 0x78}}
	authentication := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderAuthentication, Data: make([]byte, 15)}
	authentication.Data[0] = 2
	mobility := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderMobility, Data: []byte{0, 0, 0, 0, 0, 0, 0}}
	headers := []IPv6ExtensionHeader{hopCopy, routing, fragment, authentication, destination, mobility}
	payload := []byte("extension-payload")
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), HopLimit: 64,
	}
	if err = packet.SetIPv6ExtensionHeaders(headers, 99, payload); err != nil {
		t.Fatalf("SetIPv6ExtensionHeaders: %v", err)
	}
	wantPayload := mustCodecVector(t,
		"2b0105020000e3030102030001020000"+
			"2c00000000000000"+
			"3300000012345678"+
			"3c020000000000000000000000000000"+
			"8700010400000000"+
			"6300000000000000"+
			"657874656e73696f6e2d7061796c6f6164")
	if packet.Protocol != IPv6ExtensionHeaderHopByHop || !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatalf("structured IPv6 extension wire = protocol %d payload %x, want %d/%x",
			packet.Protocol, packet.Payload, IPv6ExtensionHeaderHopByHop, wantPayload)
	}
	headers[1].Data[1] ^= 0xff
	payload[0] ^= 0xff
	if !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatal("SetIPv6ExtensionHeaders retained caller storage")
	}
	parsedHeaders, protocol, upper, err := packet.IPv6ExtensionHeaders()
	if err != nil || protocol != 99 || !bytes.Equal(upper, []byte("extension-payload")) || len(parsedHeaders) != len(headers) {
		t.Fatalf("IPv6ExtensionHeaders = %d headers, protocol %d, payload %x, %v", len(parsedHeaders), protocol, upper, err)
	}
	for index := range headers {
		if parsedHeaders[index].Type != headers[index].Type {
			t.Fatalf("header %d type = %d, want %d", index, parsedHeaders[index].Type, headers[index].Type)
		}
	}
	if gotProtocol, gotPayload, upperErr := packet.UpperLayer(); upperErr != nil || gotProtocol != 99 || !bytes.Equal(gotPayload, upper) {
		t.Fatalf("UpperLayer = %d/%x, %v", gotProtocol, gotPayload, upperErr)
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatalf("encode extension chain: %v", err)
	}
	decoded, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("decode extension chain: %v", err)
	}
	decodedHeaders, protocol, upper, err := decoded.IPv6ExtensionHeaders()
	if err != nil || protocol != 99 || !bytes.Equal(upper, []byte("extension-payload")) || len(decodedHeaders) != len(headers) {
		t.Fatalf("decoded extension chain = %d/%d/%x, %v", len(decodedHeaders), protocol, upper, err)
	}
	noNext := packet
	trailing := []byte{1, 2, 3}
	if err = noNext.SetIPv6ExtensionHeaders(nil, ProtocolNoNextHeader, trailing); err != nil {
		t.Fatal(err)
	}
	noHeaders, noProtocol, noPayload, err := noNext.IPv6ExtensionHeaders()
	if err != nil || len(noHeaders) != 0 || noProtocol != ProtocolNoNextHeader || !bytes.Equal(noPayload, trailing) {
		t.Fatalf("No Next Header structural result = %+v/%d/%x, %v", noHeaders, noProtocol, noPayload, err)
	}
	if _, ignored, err := noNext.UpperLayer(); err != nil || ignored != nil {
		t.Fatalf("No Next Header upper payload = %x, %v", ignored, err)
	}
}

func TestPublicRawIPv6ExtensionHeaders(t *testing.T) {
	destinationData := make([]byte, 7)
	hopData := make([]byte, 7)
	payload := []byte("raw-extension-payload")
	headers := []IPv6ExtensionHeader{
		{Type: IPv6ExtensionHeaderDestination, Data: destinationData},
		{Type: IPv6ExtensionHeaderHopByHop, Data: hopData},
	}
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::40"), Destination: netip.MustParseAddr("2001:db8::41"),
		Protocol: 99, HopLimit: 64, Payload: []byte("unchanged"),
	}
	strict := packet
	if err := strict.SetIPv6ExtensionHeaders(headers, ProtocolUDP, payload); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("strict late Hop-by-Hop error = %v", err)
	}
	if err := packet.SetRawIPv6ExtensionHeaders(headers, ProtocolUDP, payload); err != nil {
		t.Fatalf("set raw extension headers: %v", err)
	}
	wantPayload := append([]byte{IPv6ExtensionHeaderHopByHop}, destinationData...)
	wantPayload = append(wantPayload, ProtocolUDP)
	wantPayload = append(wantPayload, hopData...)
	wantPayload = append(wantPayload, payload...)
	if packet.Protocol != IPv6ExtensionHeaderDestination || !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatalf("raw extension chain = protocol %d payload %x, want %d/%x", packet.Protocol, packet.Payload, IPv6ExtensionHeaderDestination, wantPayload)
	}
	destinationData[0], hopData[0], payload[0] = 1, 1, 'X'
	if !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatal("SetRawIPv6ExtensionHeaders retained caller storage")
	}
	wire, err := packet.MarshalRawBinary()
	if err != nil {
		t.Fatalf("marshal raw extension chain: %v", err)
	}
	if !bytes.Equal(wire[40:], wantPayload) {
		t.Fatalf("raw extension wire payload = %x, want %x", wire[40:], wantPayload)
	}
	if _, err = ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("misplaced Hop-by-Hop parse error = %v", err)
	}
	firstFragment, secondFragment := IPv6ExtensionHeader{}, IPv6ExtensionHeader{}
	if err = firstFragment.SetFragment(0, false, 1); err != nil {
		t.Fatal(err)
	}
	if err = secondFragment.SetFragment(0, false, 2); err != nil {
		t.Fatal(err)
	}
	jumbo := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = jumbo.SetOptions([]IPv6ExtensionOption{{Type: IPv6ExtensionOptionJumboPayload, Data: []byte{0, 1, 0, 0}}}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		headers []IPv6ExtensionHeader
	}{
		{name: "malformed framing", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderRouting, Data: []byte{0xff}}}},
		{name: "duplicate Fragment", headers: []IPv6ExtensionHeader{firstFragment, secondFragment}},
		{name: "Jumbo Payload option", headers: []IPv6ExtensionHeader{jumbo}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rawPacket := IPPacket{Source: packet.Source, Destination: packet.Destination, HopLimit: 64}
			if rawErr := rawPacket.SetRawIPv6ExtensionHeaders(test.headers, ProtocolUDP, nil); rawErr != nil {
				t.Fatalf("SetRawIPv6ExtensionHeaders: %v", rawErr)
			}
			if _, rawErr := rawPacket.MarshalRawBinary(); rawErr != nil {
				t.Fatalf("MarshalRawBinary: %v", rawErr)
			}
			strictPacket := IPPacket{Source: packet.Source, Destination: packet.Destination, HopLimit: 64}
			if strictErr := strictPacket.SetIPv6ExtensionHeaders(test.headers, ProtocolUDP, nil); !errors.Is(strictErr, syscall.EINVAL) {
				t.Fatalf("strict SetIPv6ExtensionHeaders error = %v", strictErr)
			}
		})
	}

	wantPacket := packet
	if err = packet.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{{Type: 99}}, ProtocolUDP, nil); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("unknown raw extension header error = %v", err)
	}
	if err = packet.SetRawIPv6ExtensionHeaders(nil, 256, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("invalid raw terminal protocol error = %v", err)
	}
	if err = packet.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderRouting}}, ProtocolUDP, make([]byte, 65535)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized raw extension chain error = %v", err)
	}
	if packet.Protocol != wantPacket.Protocol || !bytes.Equal(packet.Payload, wantPacket.Payload) {
		t.Fatal("failed SetRawIPv6ExtensionHeaders changed the receiver")
	}
	if err = (*IPPacket)(nil).SetRawIPv6ExtensionHeaders(nil, ProtocolUDP, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetRawIPv6ExtensionHeaders error = %v", err)
	}
	ipv4 := IPPacket{Source: netip.MustParseAddr("192.0.2.40"), Destination: netip.MustParseAddr("198.51.100.40")}
	if err = ipv4.SetRawIPv6ExtensionHeaders(nil, ProtocolUDP, nil); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv4 SetRawIPv6ExtensionHeaders error = %v", err)
	}
}

func TestPublicIPv6ExtensionHeaderErrors(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 99, Payload: []byte{1, 2, 3},
	}
	wantProtocol, wantPayload := packet.Protocol, append([]byte(nil), packet.Payload...)
	fragment := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderFragment, Data: []byte{0, 0, 1, 0, 0, 0, 1}}
	jumbo := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := jumbo.SetOptions([]IPv6ExtensionOption{{Type: IPv6ExtensionOptionJumboPayload, Data: []byte{0, 1, 0, 0}}}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		headers  []IPv6ExtensionHeader
		protocol int
		payload  []byte
		wantErr  error
	}{
		{name: "extension terminal", protocol: IPv6ExtensionHeaderDestination, wantErr: syscall.EINVAL},
		{name: "unknown header", headers: []IPv6ExtensionHeader{{Type: 99}}, protocol: ProtocolUDP, wantErr: syscall.EPROTONOSUPPORT},
		{name: "late Hop-by-Hop", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)}, {Type: IPv6ExtensionHeaderHopByHop, Data: make([]byte, 7)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "malformed Routing", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 6)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "short Authentication", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderAuthentication, Data: make([]byte, 7)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "misaligned Authentication", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderAuthentication, Data: append([]byte{1}, make([]byte, 10)...)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "non-atomic Fragment", headers: []IPv6ExtensionHeader{fragment}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "Jumbo Payload", headers: []IPv6ExtensionHeader{jumbo}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "oversized", protocol: ProtocolUDP, payload: make([]byte, 65536), wantErr: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := packet.SetIPv6ExtensionHeaders(test.headers, test.protocol, test.payload); !errors.Is(err, test.wantErr) {
				t.Fatalf("SetIPv6ExtensionHeaders error = %v, want %v", err, test.wantErr)
			}
			if packet.Protocol != wantProtocol || !bytes.Equal(packet.Payload, wantPayload) {
				t.Fatal("failed SetIPv6ExtensionHeaders changed the receiver")
			}
		})
	}
	v4 := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1")}
	if _, _, _, err := v4.IPv6ExtensionHeaders(); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv4 IPv6ExtensionHeaders error = %v", err)
	}
	if err := v4.SetIPv6ExtensionHeaders(nil, ProtocolUDP, nil); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv4 SetIPv6ExtensionHeaders error = %v", err)
	}
	if _, err := (IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 7)}).Options(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("Routing Options error = %v", err)
	}
	header := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination, Data: []byte{0, 1, 2}}
	wantData := append([]byte(nil), header.Data...)
	if err := header.SetOptions([]IPv6ExtensionOption{{Type: IPv6ExtensionOptionPad1, Data: []byte{1}}}); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(header.Data, wantData) {
		t.Fatalf("invalid Pad1 SetOptions = %x, %v", header.Data, err)
	}
	if err := header.SetOptions([]IPv6ExtensionOption{{Type: 30, Data: make([]byte, 256)}}); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(header.Data, wantData) {
		t.Fatalf("oversized option SetOptions = %x, %v", header.Data, err)
	}
}

func TestPublicIPv6FragmentHeader(t *testing.T) {
	header := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: []byte{1, 2, 3}}
	if err := header.SetFragment(24, true, 0x12345678); err != nil {
		t.Fatalf("SetFragment: %v", err)
	}
	offset, more, identification, ok := header.Fragment()
	if !ok || offset != 24 || !more || identification != 0x12345678 || header.Type != IPv6ExtensionHeaderFragment ||
		len(header.Data) != 7 || header.Data[0] != 0 || header.Data[2]&6 != 0 {
		t.Fatalf("Fragment = offset %d, more %t, identification %#x, valid %t, header %+v", offset, more, identification, ok, header)
	}
	header.Data[0] = 0xff
	header.Data[2] |= 6
	offset, more, identification, ok = header.Fragment()
	if !ok || offset != 24 || !more || identification != 0x12345678 {
		t.Fatalf("Fragment with reserved fields = offset %d, more %t, identification %#x, valid %t", offset, more, identification, ok)
	}
	wantType, wantData := header.Type, append([]byte(nil), header.Data...)
	for _, invalid := range []int{-8, 1, 65536} {
		if err := header.SetFragment(invalid, false, 1); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetFragment(%d) error = %v", invalid, err)
		}
		if header.Type != wantType || !bytes.Equal(header.Data, wantData) {
			t.Fatalf("failed SetFragment(%d) changed receiver", invalid)
		}
	}
	if _, _, _, ok = (IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 7)}).Fragment(); ok {
		t.Fatal("Routing header decoded as Fragment")
	}
	if _, _, _, ok = (IPv6ExtensionHeader{Type: IPv6ExtensionHeaderFragment, Data: make([]byte, 6)}).Fragment(); ok {
		t.Fatal("short Fragment header decoded")
	}
}

func TestPublicIPPacketFragmentCodec(t *testing.T) {
	ipv4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.11"), Destination: netip.MustParseAddr("198.51.100.11"),
		Protocol: 99, HopLimit: 47, Identification: 0x1234, DontFragment: true,
		MoreFragments: true, FragmentOffset: 24, Payload: []byte("fragment-payload"),
	}
	for _, packet := range []IPPacket{ipv4} {
		wire, err := packet.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal IPv4 fragment: %v", err)
		}
		parsed, err := ParseIPPacket(wire)
		if err != nil {
			t.Fatalf("parse IPv4 fragment: %v", err)
		}
		view, fragmented := parsed.Fragment()
		if !fragmented || view.Protocol != packet.Protocol || view.Identification != uint32(packet.Identification) ||
			view.Offset != packet.FragmentOffset || view.MoreFragments != packet.MoreFragments || !bytes.Equal(view.Payload, packet.Payload) || view.IsAtomic() {
			t.Fatalf("IPv4 fragment view = %+v, fragmented %t", view, fragmented)
		}
		if _, _, err = parsed.UpperLayer(); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("IPv4 fragment UpperLayer error = %v", err)
		}
		roundTrip, err := parsed.MarshalBinary()
		if err != nil || !bytes.Equal(roundTrip, wire) {
			t.Fatalf("IPv4 fragment round trip: %v\n got %x\nwant %x", err, roundTrip, wire)
		}
	}

	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	fragment := IPv6ExtensionHeader{}
	if err := fragment.SetFragment(16, true, 0x89abcdef); err != nil {
		t.Fatal(err)
	}
	rawFragmentPayload := make([]byte, 16)
	for index := range rawFragmentPayload {
		rawFragmentPayload[index] = byte(index + 1)
	}
	ipv6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::11"), Destination: netip.MustParseAddr("2001:db8::12"), HopLimit: 31,
	}
	if err := ipv6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, fragment}, IPv6ExtensionHeaderDestination, rawFragmentPayload); err != nil {
		t.Fatalf("construct IPv6 fragment: %v", err)
	}
	wire, err := ipv6.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal IPv6 fragment: %v", err)
	}
	parsed, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse IPv6 fragment: %v", err)
	}
	headers, protocol, payload, err := parsed.IPv6ExtensionHeaders()
	if err != nil || len(headers) != 2 || protocol != IPv6ExtensionHeaderDestination || !bytes.Equal(payload, rawFragmentPayload) {
		t.Fatalf("IPv6 fragment extension view = %+v/%d/%x, %v", headers, protocol, payload, err)
	}
	view, fragmented := parsed.Fragment()
	if !fragmented || view.Protocol != IPv6ExtensionHeaderDestination || view.Identification != 0x89abcdef ||
		view.Offset != 16 || !view.MoreFragments || !bytes.Equal(view.Payload, rawFragmentPayload) || view.IsAtomic() {
		t.Fatalf("IPv6 fragment view = %+v, fragmented %t", view, fragmented)
	}
	if _, _, err = parsed.UpperLayer(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("IPv6 fragment UpperLayer error = %v", err)
	}
	roundTrip, err := parsed.MarshalBinary()
	if err != nil || !bytes.Equal(roundTrip, wire) {
		t.Fatalf("IPv6 fragment round trip: %v\n got %x\nwant %x", err, roundTrip, wire)
	}

	atomic := IPv6ExtensionHeader{}
	if err = atomic.SetFragment(0, false, 7); err != nil {
		t.Fatal(err)
	}
	destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
	if err = destination.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	if err = ipv6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{atomic, destination}, 99, []byte("atomic-upper")); err != nil {
		t.Fatalf("construct atomic fragment: %v", err)
	}
	view, fragmented = ipv6.Fragment()
	if !fragmented || !view.IsAtomic() || view.Protocol != IPv6ExtensionHeaderDestination || view.Identification != 7 {
		t.Fatalf("atomic fragment view = %+v, fragmented %t", view, fragmented)
	}
	if protocol, payload, err = ipv6.UpperLayer(); err != nil || protocol != 99 || !bytes.Equal(payload, []byte("atomic-upper")) {
		t.Fatalf("atomic UpperLayer = %d/%x, %v", protocol, payload, err)
	}
}

func TestPublicIPPacketFragmentErrors(t *testing.T) {
	v4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.21"), Destination: netip.MustParseAddr("198.51.100.21"),
		Protocol: 99, HopLimit: 64, Identification: 1, Payload: make([]byte, 16),
	}
	for _, mutate := range []func(*IPPacket){
		func(packet *IPPacket) { packet.FragmentOffset = 1 },
		func(packet *IPPacket) { packet.FragmentOffset = 65536 },
		func(packet *IPPacket) { packet.MoreFragments, packet.Payload = true, packet.Payload[:15] },
		func(packet *IPPacket) { packet.FragmentOffset, packet.Payload = 8, nil },
	} {
		packet := v4
		mutate(&packet)
		if _, err := packet.MarshalBinary(); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("invalid IPv4 fragment %+v error = %v", packet, err)
		}
	}

	invalidV4 := buildIPPacket(v4.Source, v4.Destination, byte(v4.Protocol), make([]byte, 15), v4.Identification, false)
	binary.BigEndian.PutUint16(invalidV4[6:8], 0x2000)
	invalidV4[10], invalidV4[11] = 0, 0
	binary.BigEndian.PutUint16(invalidV4[10:12], checksum(invalidV4[:20]))
	if _, err := ParseIPPacket(invalidV4); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("misaligned IPv4 non-final fragment error = %v", err)
	}

	source6 := netip.MustParseAddr("2001:db8::21")
	target6 := netip.MustParseAddr("2001:db8::22")
	fragment := IPv6ExtensionHeader{}
	if err := fragment.SetFragment(0, true, 0); err != nil {
		t.Fatal(err)
	}
	fragmentPacket := IPPacket{Source: source6, Destination: target6, HopLimit: 64}
	if err := fragmentPacket.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{fragment}, 99, make([]byte, 15)); err != nil {
		t.Fatal(err)
	}
	fragmentWire, err := fragmentPacket.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseIPPacket(fragmentWire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("misaligned IPv6 non-final fragment error = %v", err)
	}
	first, second := IPv6ExtensionHeader{}, IPv6ExtensionHeader{}
	if err = first.SetFragment(0, false, 0); err != nil {
		t.Fatal(err)
	}
	if err = second.SetFragment(0, false, 0); err != nil {
		t.Fatal(err)
	}
	fragmentPacket = IPPacket{Source: source6, Destination: target6, HopLimit: 64}
	if err = fragmentPacket.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{
		first,
		second,
	}, 99, nil); err != nil {
		t.Fatal(err)
	}
	fragmentWire, err = fragmentPacket.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseIPPacket(fragmentWire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("multiple IPv6 Fragment headers error = %v", err)
	}

	packet6 := IPPacket{Source: source6, Destination: target6, HopLimit: 64}
	if err := packet6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{first, second}, 99, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("multiple SetIPv6ExtensionHeaders fragments error = %v", err)
	}
}

func TestPublicRawIPPacketFragments(t *testing.T) {
	ipv4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.22"), Destination: netip.MustParseAddr("198.51.100.22"),
		Protocol: 99, HopLimit: 64, Identification: 0x1234, MoreFragments: true, Payload: make([]byte, 15),
	}
	if _, err := ipv4.MarshalBinary(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("strict misaligned IPv4 fragment error = %v", err)
	}
	wire, err := ipv4.MarshalRawBinary()
	if err != nil {
		t.Fatalf("marshal raw IPv4 fragment: %v", err)
	}
	if binary.BigEndian.Uint16(wire[6:8]) != 0x2000 || InternetChecksum(wire[:20]) != 0 || !bytes.Equal(wire[20:], ipv4.Payload) {
		t.Fatalf("raw IPv4 fragment = %x", wire)
	}
	if _, err = ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("misaligned IPv4 fragment parse error = %v", err)
	}
	ipv4.FragmentOffset = 1
	if _, err = ipv4.MarshalRawBinary(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("unrepresentable raw IPv4 fragment offset error = %v", err)
	}

	fragment := IPv6ExtensionHeader{}
	if err = fragment.SetFragment(0, true, 0x12345678); err != nil {
		t.Fatal(err)
	}
	ipv6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::22"), Destination: netip.MustParseAddr("2001:db8::23"), HopLimit: 64,
	}
	if err = ipv6.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{fragment}, ProtocolUDP, make([]byte, 9)); err != nil {
		t.Fatalf("set raw IPv6 fragment: %v", err)
	}
	if _, err = ipv6.MarshalBinary(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("strict misaligned IPv6 fragment error = %v", err)
	}
	if _, err = ipv6.MarshalFragments(1280, 1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("strict fragmentation of raw IPv6 fragment error = %v", err)
	}
	wire, err = ipv6.MarshalRawBinary()
	if err != nil {
		t.Fatalf("marshal raw IPv6 fragment: %v", err)
	}
	if wire[6] != IPv6ExtensionHeaderFragment || wire[40] != ProtocolUDP || binary.BigEndian.Uint16(wire[42:44]) != 1 || binary.BigEndian.Uint32(wire[44:48]) != 0x12345678 || len(wire[48:]) != 9 {
		t.Fatalf("raw IPv6 fragment = %x", wire)
	}
	if _, err = ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("misaligned IPv6 fragment parse error = %v", err)
	}
}

func TestPublicIPFragmentMaximumOffsets(t *testing.T) {
	ipv4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.23"), Destination: netip.MustParseAddr("198.51.100.23"),
		Protocol: 99, Identification: 7, FragmentOffset: 65512, Payload: make([]byte, 3),
	}
	wire, err := ipv4.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal maximum IPv4 fragment: %v", err)
	}
	parsed, err := ParseIPPacket(wire)
	view, fragmented := parsed.Fragment()
	if err != nil || !fragmented || view.Offset != 65512 || len(view.Payload) != 3 {
		t.Fatalf("maximum IPv4 fragment = %+v, valid %t, error %v", view, fragmented, err)
	}
	ipv4.Payload = make([]byte, 4)
	if _, err = ipv4.MarshalBinary(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("oversized reassembled IPv4 fragment error = %v", err)
	}
	ipv4.Payload = make([]byte, 3)
	ipv4.IPv4Options = make([]byte, 40)
	wire, err = ipv4.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal maximum IPv4 fragment with options: %v", err)
	}
	if _, err = ParseIPPacket(wire); err != nil {
		t.Fatalf("parse maximum IPv4 fragment with options: %v", err)
	}

	header := IPv6ExtensionHeader{}
	if err = header.SetFragment(65528, false, 0x89abcdef); err != nil {
		t.Fatalf("construct maximum IPv6 Fragment header: %v", err)
	}
	ipv6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::23"), Destination: netip.MustParseAddr("2001:db8::24"), HopLimit: 64,
	}
	if err = ipv6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{header}, 99, make([]byte, 7)); err != nil {
		t.Fatalf("construct maximum IPv6 fragment: %v", err)
	}
	wire, err = ipv6.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal maximum IPv6 fragment: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	view, fragmented = parsed.Fragment()
	if err != nil || !fragmented || view.Offset != 65528 || len(view.Payload) != 7 {
		t.Fatalf("maximum IPv6 fragment = %+v, valid %t, error %v", view, fragmented, err)
	}
	if err = ipv6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{header}, 99, make([]byte, 8)); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("oversized reassembled IPv6 fragment error = %v", err)
	}
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = hop.SetOptions(nil); err != nil {
		t.Fatalf("construct Hop-by-Hop header: %v", err)
	}
	if err = ipv6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, header}, 99, make([]byte, 7)); err != nil {
		t.Fatalf("construct maximum IPv6 fragment with prefix: %v", err)
	}
	wire, err = ipv6.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal maximum IPv6 fragment with prefix: %v", err)
	}
	if _, err = ParseIPPacket(wire); err != nil {
		t.Fatalf("parse maximum IPv6 fragment with prefix: %v", err)
	}
}

func TestPublicIPv4MarshalFragments(t *testing.T) {
	payload := make([]byte, 2503)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.31"), Destination: netip.MustParseAddr("198.51.100.31"),
		Protocol: 99, HopLimit: 49, TrafficClass: 0x2e, Identification: 0x4567, Payload: payload,
	}
	if err := packet.SetIPv4HeaderOptions([]IPv4HeaderOption{
		{Type: 0x9e, Data: []byte{1, 2}}, {Type: 0x1e, Data: []byte{3, 4}},
	}); err != nil {
		t.Fatal(err)
	}
	fragments, err := packet.MarshalFragments(400, 0xdeadbeef)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("MarshalFragments = %d packets, %v", len(fragments), err)
	}
	reassembled := make([]byte, len(payload))
	covered := 0
	for index, wire := range fragments {
		if len(wire) > 400 {
			t.Fatalf("fragment %d size = %d", index, len(wire))
		}
		parsed, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatalf("parse fragment %d: %v", index, parseErr)
		}
		view, ok := parsed.Fragment()
		if !ok || view.Identification != uint32(packet.Identification) || view.Offset != covered || view.MoreFragments != (index+1 < len(fragments)) {
			t.Fatalf("fragment %d view = %+v, valid %t", index, view, ok)
		}
		copy(reassembled[view.Offset:], view.Payload)
		covered += len(view.Payload)
		if view.Offset == 0 {
			if !bytes.Equal(parsed.IPv4Options, packet.IPv4Options) {
				t.Fatalf("first fragment options = %x, want %x", parsed.IPv4Options, packet.IPv4Options)
			}
		} else if !bytes.Equal(parsed.IPv4Options, []byte{0x9e, 4, 1, 2, 1, 1, 1, 1}) {
			t.Fatalf("later fragment options = %x", parsed.IPv4Options)
		}
	}
	if covered != len(payload) || !bytes.Equal(reassembled, payload) {
		t.Fatal("IPv4 fragment payload did not reconstruct")
	}

	refragment := packet
	refragment.FragmentOffset = 800
	refragment.MoreFragments = true
	refragment.Payload = payload[:800]
	fragments, err = refragment.MarshalFragments(220, 0)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("IPv4 refragment = %d packets, %v", len(fragments), err)
	}
	covered = 0
	for index, wire := range fragments {
		parsed, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		view, ok := parsed.Fragment()
		if !ok || view.Offset != 800+covered || !view.MoreFragments || !bytes.Equal(parsed.IPv4Options, []byte{0x9e, 4, 1, 2, 1, 1, 1, 1}) {
			t.Fatalf("refragment %d = %+v, options %x", index, view, parsed.IPv4Options)
		}
		covered += len(view.Payload)
	}
	if covered != len(refragment.Payload) {
		t.Fatalf("refragment coverage = %d, want %d", covered, len(refragment.Payload))
	}

	df := packet
	df.DontFragment = true
	if fragments, err = df.MarshalFragments(400, 0); !errors.Is(err, syscall.EMSGSIZE) || fragments != nil {
		t.Fatalf("DF MarshalFragments = %d packets, %v", len(fragments), err)
	}
	fitting := packet
	fitting.Payload = fitting.Payload[:32]
	want, err := fitting.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fragments, err = fitting.MarshalFragments(len(want), 0)
	if err != nil || len(fragments) != 1 || !bytes.Equal(fragments[0], want) {
		t.Fatalf("fitting MarshalFragments = %d packets, %v", len(fragments), err)
	}
	fitting.Payload[0] ^= 0xff
	if bytes.Equal(fragments[0][len(fragments[0])-len(fitting.Payload):], fitting.Payload) {
		t.Fatal("fitting MarshalFragments retained payload storage")
	}
}

func TestPublicIPv6MarshalFragments(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::31")
	target := netip.MustParseAddr("2001:db8::32")
	udpPayload := make([]byte, 3003)
	for index := range udpPayload {
		udpPayload[index] = byte(index*31 + 11)
	}
	udpWire, err := (UDPDatagram{
		Source: netip.AddrPortFrom(source, 31001), Destination: netip.AddrPortFrom(target, 31002), Payload: udpPayload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
	if err = hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	if err = destination.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	routing := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 7)}
	packet := IPPacket{Source: source, Destination: target, HopLimit: 39, TrafficClass: 0x2e, FlowLabel: 0x12345}
	if err = packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, routing, destination}, ProtocolUDP, udpWire); err != nil {
		t.Fatal(err)
	}
	fragments, err := packet.MarshalFragments(1280, 0x76543210)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("IPv6 MarshalFragments = %d packets, %v", len(fragments), err)
	}
	fragmentable := packet.Payload[16:]
	reassembled := make([]byte, len(fragmentable))
	covered := 0
	for index, wire := range fragments {
		if len(wire) > 1280 {
			t.Fatalf("IPv6 fragment %d size = %d", index, len(wire))
		}
		parsed, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatalf("parse IPv6 fragment %d: %v", index, parseErr)
		}
		headers, protocol, raw, headersErr := parsed.IPv6ExtensionHeaders()
		view, ok := parsed.Fragment()
		if headersErr != nil || len(headers) != 3 || headers[0].Type != IPv6ExtensionHeaderHopByHop ||
			headers[1].Type != IPv6ExtensionHeaderRouting || headers[2].Type != IPv6ExtensionHeaderFragment ||
			protocol != IPv6ExtensionHeaderDestination || !ok || view.Identification != 0x76543210 ||
			view.Offset != covered || view.MoreFragments != (index+1 < len(fragments)) || !bytes.Equal(raw, view.Payload) {
			t.Fatalf("IPv6 fragment %d = headers %+v protocol %d view %+v, errors %v/%t", index, headers, protocol, view, headersErr, ok)
		}
		copy(reassembled[view.Offset:], view.Payload)
		covered += len(view.Payload)
	}
	if covered != len(fragmentable) || !bytes.Equal(reassembled, fragmentable) {
		t.Fatal("IPv6 fragmentable part did not reconstruct")
	}

	atomic := IPv6ExtensionHeader{}
	if err = atomic.SetFragment(0, false, 1); err != nil {
		t.Fatal(err)
	}
	authentication := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderAuthentication, Data: make([]byte, 15)}
	authentication.Data[0] = 2
	atomicPacket := IPPacket{Source: source, Destination: target, HopLimit: 64}
	if err = atomicPacket.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, authentication, atomic, destination}, ProtocolUDP, udpWire); err != nil {
		t.Fatal(err)
	}
	fragments, err = atomicPacket.MarshalFragments(1280, 0xaabbccdd)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("atomic MarshalFragments = %d packets, %v", len(fragments), err)
	}
	atomicFragmentable := make([]byte, len(authentication.Data)+1+len(destination.Data)+1+len(udpWire))
	atomicCovered := 0
	for index, wire := range fragments {
		parsed, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		view, ok := parsed.Fragment()
		if !ok || view.Identification != 0xaabbccdd || view.Protocol != IPv6ExtensionHeaderAuthentication || view.Offset != atomicCovered {
			t.Fatalf("atomic replacement fragment %d = %+v, valid %t", index, view, ok)
		}
		copy(atomicFragmentable[view.Offset:], view.Payload)
		atomicCovered += len(view.Payload)
	}
	if atomicCovered != len(atomicFragmentable) {
		t.Fatalf("atomic replacement coverage = %d, want %d", atomicCovered, len(atomicFragmentable))
	}
	reconstructedAtomic := IPPacket{
		Source: source, Destination: target, Protocol: IPv6ExtensionHeaderAuthentication, HopLimit: 64, Payload: atomicFragmentable,
	}
	atomicHeaders, atomicProtocol, atomicUpper, atomicErr := reconstructedAtomic.IPv6ExtensionHeaders()
	if atomicErr != nil || len(atomicHeaders) != 2 || atomicHeaders[0].Type != IPv6ExtensionHeaderAuthentication ||
		atomicHeaders[1].Type != IPv6ExtensionHeaderDestination || atomicProtocol != ProtocolUDP || !bytes.Equal(atomicUpper, udpWire) {
		t.Fatalf("reconstructed atomic replacement = %+v/%d/%x, %v", atomicHeaders, atomicProtocol, atomicUpper, atomicErr)
	}

	nonAtomic := IPv6ExtensionHeader{}
	if err = nonAtomic.SetFragment(0, true, 3); err != nil {
		t.Fatal(err)
	}
	nonAtomicPacket := IPPacket{Source: source, Destination: target, HopLimit: 64}
	if err = nonAtomicPacket.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{nonAtomic}, ProtocolUDP, make([]byte, 1280)); err != nil {
		t.Fatal(err)
	}
	if fragments, err = nonAtomicPacket.MarshalFragments(1000, 4); !errors.Is(err, syscall.EMSGSIZE) || fragments != nil {
		t.Fatalf("non-atomic refragment = %d packets, %v", len(fragments), err)
	}

	tcpHeader := make([]byte, 256)
	tcpHeader[12] = 15 << 4
	tcpPacket := IPPacket{
		Source: source, Destination: target, Protocol: ProtocolTCP, HopLimit: 64,
		TrafficClass: 0xab, FlowLabel: 0xabcde, Payload: tcpHeader,
	}
	if fragments, err = tcpPacket.MarshalFragments(104, 5); !errors.Is(err, syscall.EMSGSIZE) || fragments != nil {
		t.Fatalf("RFC 7112 short first fragment = %d packets, %v", len(fragments), err)
	}
	fragments, err = tcpPacket.MarshalFragments(112, 5)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("RFC 7112 exact first fragment = %d packets, %v", len(fragments), err)
	}
	firstPacket, err := ParseIPPacket(fragments[0])
	if err != nil {
		t.Fatal(err)
	}
	firstView, ok := firstPacket.Fragment()
	if !ok || len(firstView.Payload) < 60 || !firstView.MoreFragments || firstPacket.Source != source || firstPacket.Destination != target ||
		firstPacket.HopLimit != tcpPacket.HopLimit || firstPacket.TrafficClass != tcpPacket.TrafficClass || firstPacket.FlowLabel != tcpPacket.FlowLabel {
		t.Fatalf("RFC 7112 first fragment view = %+v, valid %t", firstView, ok)
	}
}

func TestPublicCodecAppendBinaryOverlappingOptions(t *testing.T) {
	ip := IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: 99, HopLimit: 64, IPv4Options: []byte{1, 1, 1, 1, 148, 4, 0, 0}, Payload: []byte("overlapping-ip-options"),
	}
	ipWire, err := ip.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP, err := ParseIPPacket(ipWire)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP.IPv4Options = parsedIP.IPv4Options[4:8]
	wantIP := parsedIP
	wantIP.IPv4Options = append([]byte(nil), parsedIP.IPv4Options...)
	wantIP.Payload = append([]byte(nil), parsedIP.Payload...)
	wantIPWire, err := wantIP.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedIP, err := parsedIP.AppendBinary(ipWire[:0])
	if err != nil || len(encodedIP) == 0 || &encodedIP[0] != &ipWire[0] || !bytes.Equal(encodedIP, wantIPWire) {
		t.Fatalf("overlapping IPv4 options: error=%v\n got %x\nwant %x", err, encodedIP, wantIPWire)
	}

	segment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:443"),
		Flags: TCPFlagACK, Options: []byte{1, 1, 1, 1, 2, 4, 5, 180}, Payload: []byte("overlapping-tcp-options"),
	}
	tcpWire, err := segment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedSegment, err := (IPPacket{
		Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: tcpWire,
	}).TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	parsedSegment.Options = parsedSegment.Options[4:8]
	wantSegment := parsedSegment
	wantSegment.Options = append([]byte(nil), parsedSegment.Options...)
	wantSegment.Payload = append([]byte(nil), parsedSegment.Payload...)
	wantTCPWire, err := wantSegment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedTCP, err := parsedSegment.AppendBinary(tcpWire[:0])
	if err != nil || len(encodedTCP) == 0 || &encodedTCP[0] != &tcpWire[0] || !bytes.Equal(encodedTCP, wantTCPWire) {
		t.Fatalf("overlapping TCP options: error=%v\n got %x\nwant %x", err, encodedTCP, wantTCPWire)
	}
}

func TestPublicCodecAppendBinaryOverlappingInput(t *testing.T) {
	type appendTest struct {
		name   string
		wire   []byte
		append func([]byte) ([]byte, error)
	}
	tests := []appendTest{}

	ipWire, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: 99, HopLimit: 64, IPv4Options: []byte{1, 148, 4, 0, 0}, Payload: []byte("overlapping-ip-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP, err := ParseIPPacket(ipWire)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"IP", ipWire, parsedIP.AppendBinary})

	tcpWire, err := (TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:443"),
		Flags: TCPFlagACK, Options: []byte{2, 4, 5, 180, 1}, Payload: []byte("overlapping-tcp-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedTCP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolTCP, Payload: tcpWire,
	}).TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"TCP", tcpWire, parsedTCP.AppendBinary})

	udpWire, err := (UDPDatagram{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:53"),
		Payload: []byte("overlapping-udp-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedUDP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolUDP, Payload: udpWire,
	}).UDPDatagram()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"UDP", udpWire, parsedUDP.AppendBinary})

	icmpWire, err := (ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Type: 8, Body: []byte{0x12, 0x34, 0, 1, 'e', 'c', 'h', 'o'},
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedICMP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolICMPv4, Payload: icmpWire,
	}).ICMPMessage()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"ICMP", icmpWire, parsedICMP.AppendBinary})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := append([]byte(nil), test.wire...)
			got, appendErr := test.append(test.wire[:0])
			if appendErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("overlapping AppendBinary: error=%v\n got %x\nwant %x", appendErr, got, want)
			}
		})
	}
}

func TestPublicIPPacketCodecPolicyBoundary(t *testing.T) {
	ipv4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: ProtocolTCP,
		HopLimit: 64, IPv4Options: []byte{131, 7, 4, 203, 0, 113, 1}, Payload: make([]byte, tcpHeaderSize),
	}
	wire, err := ipv4.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal source-routed IPv4: %v", err)
	}
	parsed, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse source-routed IPv4: %v", err)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("source-routed TCP error = %v, want EPROTONOSUPPORT", err)
	}
	icmpPayload, err := (ICMPMessage{
		Source: ipv4.Source, Destination: ipv4.Destination, Type: 8, Body: []byte{0, 1, 0, 2},
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedICMP := ipv4
	sourceRoutedICMP.Protocol, sourceRoutedICMP.Payload = ProtocolICMPv4, icmpPayload
	if _, err = sourceRoutedICMP.ICMPMessage(); err != nil {
		t.Fatalf("decode source-routed ICMPv4 without a pseudo-header: %v", err)
	}
	uncheckedUDPPayload, err := (UDPDatagram{
		Source: netip.AddrPortFrom(ipv4.Source, 1234), Destination: netip.AddrPortFrom(ipv4.Destination, 53),
		ChecksumDisabled: true,
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedUDP := ipv4
	sourceRoutedUDP.Protocol, sourceRoutedUDP.Payload = ProtocolUDP, uncheckedUDPPayload
	if _, err = sourceRoutedUDP.UDPDatagram(); err != nil {
		t.Fatalf("decode source-routed IPv4 UDP without a pseudo-header checksum: %v", err)
	}
	checkedUDPPayload, err := (UDPDatagram{
		Source: netip.AddrPortFrom(ipv4.Source, 1234), Destination: netip.AddrPortFrom(ipv4.Destination, 53),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedUDP.Payload = checkedUDPPayload
	if _, err = sourceRoutedUDP.UDPDatagram(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("source-routed checksummed UDP error = %v, want EPROTONOSUPPORT", err)
	}
	exhaustedSegment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("192.0.2.2:443"),
		Flags: TCPFlagACK,
	}
	exhaustedPayload, err := exhaustedSegment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	exhausted := ipv4
	exhausted.IPv4Options = []byte{131, 7, 8, 203, 0, 113, 1}
	exhausted.Payload = exhaustedPayload
	wire, err = exhausted.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal exhausted source route: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse exhausted source route: %v", err)
	}
	if _, err = parsed.TCPSegment(); err != nil {
		t.Fatalf("decode TCP after exhausted source route: %v", err)
	}

	ipv6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Protocol: 43, HopLimit: 64,
		Payload: append([]byte{ProtocolTCP, 0, 0, 1, 0, 0, 0, 0}, make([]byte, tcpHeaderSize)...),
	}
	wire, err = ipv6.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal actively routed IPv6: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse actively routed IPv6: %v", err)
	}
	if protocol, _, upperErr := parsed.UpperLayer(); upperErr != nil || protocol != ProtocolTCP {
		t.Fatalf("routed upper layer = %d, %v", protocol, upperErr)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("routed TCP error = %v, want EPROTONOSUPPORT", err)
	}

	homeAddressOptions := make([]byte, 24)
	homeAddressOptions[0], homeAddressOptions[1] = ProtocolTCP, 2
	homeAddressOptions[2], homeAddressOptions[3] = 201, 16
	copy(homeAddressOptions[4:20], netip.MustParseAddr("2001:db8::10").AsSlice())
	homeAddressOptions[20], homeAddressOptions[21] = 1, 1
	homeAddressPacket := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 60, HopLimit: 64, Payload: append(homeAddressOptions, make([]byte, tcpHeaderSize)...),
	}
	wire, err = homeAddressPacket.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal Home Address packet: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse Home Address packet: %v", err)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("Home Address TCP error = %v, want EPROTONOSUPPORT", err)
	}
}

func TestPublicIPv6NoNextHeaderAndLinkPadding(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 59, HopLimit: 64, Payload: []byte{1, 2, 3, 4},
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	protocol, upper, err := parsed.UpperLayer()
	if err != nil || protocol != 59 || len(upper) != 0 || !bytes.Equal(parsed.Payload, packet.Payload) {
		t.Fatalf("No Next Header upper layer = %d, %x, %v; packet payload=%x", protocol, upper, err, parsed.Payload)
	}

	empty := packet
	empty.Payload = nil
	wire, err = empty.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), wire...), 1, 2, 3, 4, 5, 6)
	parsed, err = ParseIPPacket(padded)
	if err != nil || len(parsed.Payload) != 0 {
		t.Fatalf("parse padded zero-payload IPv6: packet=%+v error=%v", parsed, err)
	}
	internal, ok := parseIPPacket(padded, false)
	if !ok || len(internal.payload) != 0 || len(internal.original) != len(wire) {
		t.Fatalf("internal padded zero-payload IPv6 = %+v, %v", internal, ok)
	}
}

func TestPublicIPv6JumboPayloadOptionRejected(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 0, HopLimit: 64,
		Payload: []byte{59, 0, 194, 4, 0, 1, 0, 0},
	}
	if _, err := packet.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("constructing a Jumbo Payload option returned %v, want EINVAL", err)
	}

	wire := make([]byte, 48)
	wire[0], wire[6], wire[7] = 0x60, 0, 64
	binary.BigEndian.PutUint16(wire[4:6], 8)
	source, destination := packet.Source.As16(), packet.Destination.As16()
	copy(wire[8:24], source[:])
	copy(wire[24:40], destination[:])
	copy(wire[40:], packet.Payload)
	if _, err := ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("parsing a Jumbo Payload option returned %v, want EINVAL", err)
	}
	binary.BigEndian.PutUint16(wire[4:6], 0)
	if _, err := ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("parsing a Payload Length zero jumbogram returned %v, want EINVAL", err)
	}
}

func TestPublicIPv6ExtensionIntegrityFieldsRemainOpaque(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 0, HopLimit: 64,
		Payload: []byte{
			51, 0, 1, 4, 0xaa, 0xbb, 0xcc, 0xdd,
			135, 2, 0xaa, 0xbb, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
			44, 0, 5, 0xcc, 0, 0, 0, 0,
			99, 0xff, 0, 6, 0x12, 0x34, 0x56, 0x78,
			1, 2, 3, 4,
		},
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[44:48], []byte{0, 0, 0, 0}) || wire[73] != 0 || binary.BigEndian.Uint16(wire[74:76]) != 0 {
		t.Fatalf("generated padding and Fragment reserved fields were not cleared: %x", wire[40:80])
	}
	if binary.BigEndian.Uint16(wire[50:52]) != 0xaabb || wire[67] != 0xcc {
		t.Fatalf("integrity-protected extension fields were changed: %x", wire[40:80])
	}

	raw := append([]byte(nil), wire...)
	copy(raw[44:48], []byte{0xaa, 0xbb, 0xcc, 0xdd})
	binary.BigEndian.PutUint16(raw[50:52], 0xddee)
	raw[67] = 0xee
	raw[73] = 0xff
	binary.BigEndian.PutUint16(raw[74:76], 6)
	parsed, err := ParseIPPacket(raw)
	if err != nil {
		t.Fatalf("parse nonzero reserved fields: %v", err)
	}
	if !bytes.Equal(parsed.Payload, raw[40:]) {
		t.Fatal("ParseIPPacket did not preserve received extension bytes")
	}
	headers, protocol, payload, err := parsed.IPv6ExtensionHeaders()
	if err != nil || len(headers) != 4 || protocol != 99 || !bytes.Equal(payload, []byte{1, 2, 3, 4}) ||
		!bytes.Equal(headers[0].Data[3:], []byte{0xaa, 0xbb, 0xcc, 0xdd}) ||
		binary.BigEndian.Uint16(headers[1].Data[1:3]) != 0xddee || headers[2].Data[2] != 0xee ||
		headers[3].Data[0] != 0xff || binary.BigEndian.Uint16(headers[3].Data[1:3]) != 6 {
		t.Fatalf("structured extension fields did not preserve received bytes: headers=%+v protocol=%d payload=%x error=%v", headers, protocol, payload, err)
	}
	want := append([]byte(nil), raw...)
	copy(want[44:48], []byte{0, 0, 0, 0})
	want[73] = 0
	binary.BigEndian.PutUint16(want[74:76], 0)
	reencoded, err := parsed.AppendBinary(nil)
	if err != nil || !bytes.Equal(reencoded, want) {
		t.Fatalf("normalized IPv6 packet: error=%v\n got %x\nwant %x", err, reencoded, want)
	}
}

func TestIPv6MappedAddressesAreRejected(t *testing.T) {
	packet := make([]byte, 40)
	packet[0], packet[6], packet[7] = 0x60, 59, 64
	source := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	destination := netip.MustParseAddr("2001:db8::1").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	if _, err := ParseIPPacket(packet); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("mapped IPv6 ParseIPPacket error = %v", err)
	}
	if _, ok := parseIPPacket(packet, false); ok {
		t.Fatal("internal parser accepted a mapped IPv6 source")
	}
}

func TestPublicIPPacketCodecErrorsDoNotModifyDestination(t *testing.T) {
	valid := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: 99, HopLimit: 64, Payload: []byte{1}}
	invalid := valid
	invalid.HopLimit = 256
	destination := []byte{1, 2, 3}
	want := append([]byte(nil), destination...)
	if got, err := invalid.AppendBinary(destination); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(destination, want) {
		t.Fatalf("invalid AppendBinary: got=%x error=%v", got, err)
	}
	if got, err := invalid.AppendRawBinary(destination); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(destination, want) {
		t.Fatalf("invalid AppendRawBinary: got=%x error=%v", got, err)
	}
	if _, err := ParseIPPacket([]byte{0x40}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("truncated ParseIPPacket error = %v", err)
	}
	invalid = valid
	invalid.Source = netip.MustParseAddr("2001:db8::1").WithZone("test")
	invalid.Destination = netip.MustParseAddr("2001:db8::2")
	if _, err := invalid.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned IP packet error = %v", err)
	}
}

func TestPublicChecksumAPI(t *testing.T) {
	payload := []byte("public-checksum")
	if got, want := InternetChecksum(payload), checksum(payload); got != want {
		t.Fatalf("InternetChecksum = %#x, want %#x", got, want)
	}
	source, destination := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	got, err := IPTransportChecksum(source, destination, ProtocolUDP, payload)
	if err != nil || got != transportChecksum(source, destination, ProtocolUDP, payload) {
		t.Fatalf("IPTransportChecksum = %#x, %v", got, err)
	}
	if _, err = IPTransportChecksum(source, netip.MustParseAddr("192.0.2.1"), ProtocolUDP, payload); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("cross-family checksum error = %v", err)
	}
	mappedSource := netip.MustParseAddr("::ffff:192.0.2.1")
	mappedDestination := netip.MustParseAddr("::ffff:198.51.100.1")
	mapped, err := IPTransportChecksum(mappedSource, mappedDestination, ProtocolUDP, payload)
	if want := transportChecksum(mappedSource.Unmap(), mappedDestination.Unmap(), ProtocolUDP, payload); err != nil || mapped != want {
		t.Fatalf("mapped IPv4 checksum = %#x, %v; want %#x", mapped, err, want)
	}
	for _, protocol := range []int{-1, 256} {
		if _, err = IPTransportChecksum(source, destination, protocol, payload); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("protocol %d checksum error = %v", protocol, err)
		}
	}
	if _, err = IPTransportChecksum(source.WithZone("test"), destination, ProtocolUDP, payload); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned checksum error = %v", err)
	}
	if _, err = IPTransportChecksum(source, destination, ProtocolUDP, make([]byte, 65536)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized checksum error = %v", err)
	}
}

func TestPublicChecksumPartsAPI(t *testing.T) {
	payload := []byte("multipart-checksum-payload")
	parts := [][]byte{payload[:1], nil, payload[1:6], {}, payload[6:17], payload[17:]}
	if got, want := InternetChecksumParts(parts...), InternetChecksum(payload); got != want {
		t.Fatalf("InternetChecksumParts = %#x, want %#x", got, want)
	}
	if got, want := InternetChecksumParts(), InternetChecksum(nil); got != want {
		t.Fatalf("empty InternetChecksumParts = %#x, want %#x", got, want)
	}

	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")},
		{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")},
		{netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("::ffff:198.51.100.1")},
	} {
		got, err := IPTransportChecksumParts(addresses[0], addresses[1], ProtocolUDP, parts...)
		want, wantErr := IPTransportChecksum(addresses[0], addresses[1], ProtocolUDP, payload)
		if err != nil || wantErr != nil || got != want {
			t.Fatalf("IPTransportChecksumParts(%s) = %#x, %v; want %#x, %v", addresses[0], got, err, want, wantErr)
		}
		empty, err := IPTransportChecksumParts(addresses[0], addresses[1], ProtocolUDP)
		emptyWant, wantErr := IPTransportChecksum(addresses[0], addresses[1], ProtocolUDP, nil)
		if err != nil || wantErr != nil || empty != emptyWant {
			t.Fatalf("empty IPTransportChecksumParts(%s) = %#x, %v; want %#x, %v", addresses[0], empty, err, emptyWant, wantErr)
		}
	}

	source, destination := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	invalidCases := []struct {
		name        string
		source      netip.Addr
		destination netip.Addr
		protocol    int
	}{
		{name: "cross-family", source: source, destination: netip.MustParseAddr("192.0.2.1"), protocol: ProtocolUDP},
		{name: "zoned", source: source.WithZone("test"), destination: destination, protocol: ProtocolUDP},
		{name: "negative-protocol", source: source, destination: destination, protocol: -1},
		{name: "large-protocol", source: source, destination: destination, protocol: 256},
	}
	oversized := [][]byte{make([]byte, 40000), make([]byte, 25536)}
	for _, test := range invalidCases {
		if _, err := IPTransportChecksumParts(test.source, test.destination, test.protocol, oversized...); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("%s checksum error = %v", test.name, err)
		}
	}
	if _, err := IPTransportChecksumParts(source, destination, ProtocolUDP, oversized...); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("cumulative oversized checksum error = %v", err)
	}
	maximumPayload := make([]byte, 65535)
	for index := range maximumPayload {
		maximumPayload[index] = byte(index*29 + 7)
	}
	maximumParts := [][]byte{maximumPayload[:32767], nil, maximumPayload[32767:]}
	maximum, err := IPTransportChecksumParts(source, destination, ProtocolUDP, maximumParts...)
	maximumWant, wantErr := IPTransportChecksum(source, destination, ProtocolUDP, maximumPayload)
	if err != nil || wantErr != nil || maximum != maximumWant {
		t.Fatalf("maximum multipart checksum = %#x, %v; want %#x, %v", maximum, err, maximumWant, wantErr)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		_ = InternetChecksumParts(parts...)
		_, _ = IPTransportChecksumParts(source, destination, ProtocolUDP, parts...)
	}); allocations != 0 {
		t.Fatalf("multipart checksum allocations = %v", allocations)
	}
}

func TestPublicChecksumPartsEveryPartition(t *testing.T) {
	addresses := [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")},
		{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")},
	}
	for size := 0; size <= 12; size++ {
		payload := make([]byte, size)
		for index := range payload {
			payload[index] = byte(index*53 + size*17)
		}
		partitions := 1
		if size > 1 {
			partitions = 1 << (size - 1)
		}
		for mask := 0; mask < partitions; mask++ {
			parts := make([][]byte, 0, size*2+2)
			parts = append(parts, nil)
			start := 0
			for offset := 1; offset < size; offset++ {
				if mask&(1<<(offset-1)) == 0 {
					continue
				}
				parts = append(parts, payload[start:offset], []byte{})
				start = offset
			}
			parts = append(parts, payload[start:], nil)
			if got, want := InternetChecksumParts(parts...), InternetChecksum(payload); got != want {
				t.Fatalf("size %d partition %#x Internet checksum = %#x, want %#x", size, mask, got, want)
			}
			for _, pair := range addresses {
				got, err := IPTransportChecksumParts(pair[0], pair[1], ProtocolUDP, parts...)
				want, wantErr := IPTransportChecksum(pair[0], pair[1], ProtocolUDP, payload)
				if err != nil || wantErr != nil || got != want {
					t.Fatalf("size %d partition %#x transport checksum for %s = %#x, %v; want %#x, %v", size, mask, pair[0], got, err, want, wantErr)
				}
			}
		}
	}
}

func FuzzPublicIPPacketCodec(f *testing.F) {
	seeds := []IPPacket{
		{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: 99, HopLimit: 64, Payload: []byte("v4")},
		{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: 99, HopLimit: 64, Identification: 7, MoreFragments: true, FragmentOffset: 16, Payload: make([]byte, 16)},
		{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Protocol: 99, HopLimit: 64, Payload: []byte("v6")},
	}
	fragment := IPv6ExtensionHeader{}
	if err := fragment.SetFragment(24, true, 0x12345678); err != nil {
		f.Fatal(err)
	}
	ipv6Fragment := IPPacket{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), HopLimit: 64}
	if err := ipv6Fragment.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{fragment}, IPv6ExtensionHeaderDestination, make([]byte, 16)); err != nil {
		f.Fatal(err)
	}
	seeds = append(seeds, ipv6Fragment)
	for _, seed := range seeds {
		wire, err := seed.AppendBinary(nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		original := append([]byte(nil), wire...)
		packet, err := ParseIPPacket(wire)
		if !bytes.Equal(wire, original) {
			t.Fatal("ParseIPPacket modified its input")
		}
		if err != nil {
			return
		}
		structured := packet
		if packet.Source.Is4() {
			options, optionsErr := packet.IPv4HeaderOptions()
			if optionsErr != nil {
				t.Fatalf("parsed IPv4 options could not be inspected: %v", optionsErr)
			}
			if optionsErr = structured.SetIPv4HeaderOptions(options); optionsErr != nil {
				t.Fatalf("parsed IPv4 options could not be rebuilt: %v", optionsErr)
			}
		} else {
			headers, protocol, payload, headersErr := packet.IPv6ExtensionHeaders()
			if headersErr != nil {
				t.Fatalf("parsed IPv6 headers could not be inspected: %v", headersErr)
			}
			if headersErr = structured.SetIPv6ExtensionHeaders(headers, protocol, payload); headersErr != nil {
				t.Fatalf("parsed IPv6 headers could not be rebuilt: %v", headersErr)
			}
		}
		if _, err = structured.AppendBinary(nil); err != nil {
			t.Fatalf("structured packet could not be encoded: %v", err)
		}
		encoded, err := packet.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed packet could not be encoded: %v", err)
		}
		if _, err = ParseIPPacket(encoded); err != nil {
			t.Fatalf("encoded packet could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		reparsed, err := ParseIPPacket(encoded)
		if err != nil {
			t.Fatal(err)
		}
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place packet append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func FuzzPublicRawIPPacketCodec(f *testing.F) {
	f.Add(false, []byte(nil), []byte("ipv4"), uint16(0), false, false, byte(99))
	f.Add(false, []byte{IPv4HeaderOptionEnd, 0xaa, 0xbb}, []byte{1, 2, 3}, uint16(8191), true, true, byte(ProtocolUDP))
	f.Add(true, []byte(nil), []byte("ipv6"), uint16(0), false, false, byte(253))
	f.Add(true, []byte{0xff, 1, 2, 3}, []byte("extension"), uint16(3), true, false, byte(ProtocolUDP))
	f.Add(true, make([]byte, 64), []byte("long-extension"), uint16(1), true, false, byte(ProtocolUDP))
	ipv4Source := netip.MustParseAddr("192.0.2.1")
	ipv4Destination := netip.MustParseAddr("198.51.100.1")
	ipv6Source := netip.MustParseAddr("2001:db8::1")
	ipv6Destination := netip.MustParseAddr("2001:db8:1::1")
	extensionHeaderTypes := [...]uint8{
		IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting, IPv6ExtensionHeaderFragment,
		IPv6ExtensionHeaderAuthentication, IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility,
	}
	f.Fuzz(func(t *testing.T, ipv6 bool, options, payload []byte, rawOffset uint16, more, dontFragment bool, protocol byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		ipv4Options := options
		if len(ipv4Options) > 40 {
			ipv4Options = ipv4Options[:40]
		}
		packet := IPPacket{
			Source: ipv4Source, Destination: ipv4Destination,
			Protocol: int(protocol), HopLimit: 64, DontFragment: dontFragment, MoreFragments: more,
			FragmentOffset: int(rawOffset&0x1fff) * 8, IPv4Options: ipv4Options, Payload: payload,
		}
		expectedProtocol, expectedPayload := protocol, payload
		if ipv6 {
			packet.Source, packet.Destination = ipv6Source, ipv6Destination
			packet.DontFragment, packet.MoreFragments, packet.FragmentOffset, packet.IPv4Options = false, false, 0, nil
			if more {
				extensionData := options
				if len(extensionData) > 4096 {
					extensionData = extensionData[:4096]
				}
				headerType := extensionHeaderTypes[int(rawOffset)%len(extensionHeaderTypes)]
				if err := packet.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{{Type: headerType, Data: extensionData}}, int(protocol), payload); err != nil {
					t.Fatal(err)
				}
				expectedProtocol = headerType
				expectedPayload = append([]byte{protocol}, extensionData...)
				expectedPayload = append(expectedPayload, payload...)
			}
		}
		prefix := []byte{0xaa, 0xbb, 0xcc}
		wire, err := packet.AppendRawBinary(append([]byte(nil), prefix...))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wire[:len(prefix)], prefix) {
			t.Fatal("AppendRawBinary changed the destination prefix")
		}
		wire = wire[len(prefix):]
		headerSize := 40
		if !ipv6 {
			headerSize = 20 + (len(ipv4Options)+3)&^3
			if len(wire) != headerSize+len(payload) || wire[0] != 0x40|byte(headerSize/4) ||
				binary.BigEndian.Uint16(wire[2:4]) != uint16(len(wire)) || wire[9] != protocol {
				t.Fatalf("invalid raw IPv4 fixed header: %x", wire[:20])
			}
			if !bytes.Equal(wire[20:20+len(ipv4Options)], ipv4Options) || !bytes.Equal(wire[headerSize:], payload) {
				t.Fatal("raw IPv4 encoding did not preserve options or payload")
			}
			fragment := uint16(packet.FragmentOffset / 8)
			if packet.DontFragment {
				fragment |= 0x4000
			}
			if packet.MoreFragments {
				fragment |= 0x2000
			}
			if binary.BigEndian.Uint16(wire[6:8]) != fragment {
				t.Fatal("raw IPv4 encoding did not preserve fragment fields")
			}
			for _, value := range wire[20+len(ipv4Options) : headerSize] {
				if value != 0 {
					t.Fatal("raw IPv4 alignment padding is not zero")
				}
			}
			if referenceChecksum(wire[:headerSize]) != 0 {
				t.Fatal("raw IPv4 header checksum is invalid")
			}
		} else {
			if len(wire) != headerSize+len(expectedPayload) || wire[0]>>4 != 6 ||
				binary.BigEndian.Uint16(wire[4:6]) != uint16(len(expectedPayload)) || wire[6] != expectedProtocol ||
				!bytes.Equal(wire[headerSize:], expectedPayload) {
				t.Fatalf("invalid raw IPv6 encoding: %x", wire)
			}
		}

		overlap := packet
		if ipv6 {
			overlap.Payload = wire[40:]
		} else {
			overlap.IPv4Options = wire[20:headerSize]
			overlap.Payload = wire[headerSize:]
		}
		expected := append([]byte(nil), wire...)
		inPlace, err := overlap.AppendRawBinary(wire[:0])
		if err != nil || !bytes.Equal(inPlace, expected) {
			t.Fatalf("in-place raw packet append: error=%v\n got %x\nwant %x", err, inPlace, expected)
		}
	})
}

func FuzzPublicIPPacketMarshalFragments(f *testing.F) {
	for _, seed := range []IPPacket{
		{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
			Protocol: 99, HopLimit: 64, Identification: 1, Payload: make([]byte, 4096),
		},
		{
			Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
			Protocol: 99, HopLimit: 64, Payload: make([]byte, 4096),
		},
	} {
		wire, err := seed.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire, uint16(1500), uint32(7))
	}
	f.Fuzz(func(t *testing.T, wire []byte, rawMTU uint16, identification uint32) {
		if len(wire) > 8192 {
			return
		}
		packet, err := ParseIPPacket(wire)
		if err != nil {
			return
		}
		minimumMTU := 576
		if packet.Source.Is6() {
			minimumMTU = 1280
		}
		mtu := minimumMTU + int(rawMTU)%((9000-minimumMTU)+1)
		fragments, fragmentErr := packet.MarshalFragments(mtu, identification)
		if fragmentErr != nil {
			if len(fragments) != 0 {
				t.Fatal("failed fragmentation returned partial output")
			}
			return
		}
		if len(fragments) == 0 {
			t.Fatal("successful fragmentation returned no packets")
		}
		for index, fragment := range fragments {
			if len(fragment) > mtu {
				t.Fatalf("fragment %d length = %d, MTU %d", index, len(fragment), mtu)
			}
			if _, parseErr := ParseIPPacket(fragment); parseErr != nil {
				t.Fatalf("fragment %d cannot be parsed: %v", index, parseErr)
			}
		}
	})
}

func FuzzPublicIPv4HeaderOptions(f *testing.F) {
	f.Add([]byte{IPv4HeaderOptionNOP, IPv4HeaderOptionRouterAlert, 4, 0, 0, IPv4HeaderOptionEnd, 0, 0})
	f.Add([]byte{30, 4, 1, 2})
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
			IPv4Options: wire,
		}
		before := append([]byte(nil), wire...)
		options, err := packet.IPv4HeaderOptions()
		if !bytes.Equal(wire, before) {
			t.Fatal("IPv4HeaderOptions modified its input")
		}
		if err != nil {
			return
		}
		var rebuilt = packet
		rebuilt.IPv4Options = nil
		if err = rebuilt.SetIPv4HeaderOptions(options); err != nil {
			t.Fatalf("parsed IPv4 options could not be rebuilt: %v", err)
		}
		canonical := append([]byte(nil), rebuilt.IPv4Options...)
		for index := range wire {
			wire[index] ^= 0xff
		}
		if !bytes.Equal(rebuilt.IPv4Options, canonical) {
			t.Fatal("SetIPv4HeaderOptions retained parsed input")
		}
		if _, err = rebuilt.IPv4HeaderOptions(); err != nil {
			t.Fatalf("rebuilt IPv4 options could not be parsed: %v", err)
		}
	})
}

func FuzzPublicIPv4HeaderOptionSetters(f *testing.F) {
	f.Add(uint16(0), byte(30), []byte{1, 2, 3})
	f.Add(uint16(0xffff), byte(0xff), []byte(nil))
	f.Fuzz(func(t *testing.T, routerAlert uint16, rawType byte, data []byte) {
		if len(data) > 24 {
			data = data[:24]
		}
		unknownType := rawType | 0x1e
		var alert IPv4HeaderOption
		alert.SetRouterAlert(routerAlert)
		packet := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1")}
		if err := packet.SetIPv4HeaderOptions([]IPv4HeaderOption{
			{Type: IPv4HeaderOptionNOP}, alert, {Type: unknownType, Data: data}, {Type: IPv4HeaderOptionEnd},
		}); err != nil {
			t.Fatal(err)
		}
		want := []byte{IPv4HeaderOptionNOP, IPv4HeaderOptionRouterAlert, 4, byte(routerAlert >> 8), byte(routerAlert),
			unknownType, byte(2 + len(data))}
		want = append(want, data...)
		want = append(want, IPv4HeaderOptionEnd)
		if !bytes.Equal(packet.IPv4Options, want) {
			t.Fatalf("semantic IPv4 options = %x, want %x", packet.IPv4Options, want)
		}
		options, err := packet.IPv4HeaderOptions()
		if err != nil || len(options) != 4 {
			t.Fatalf("semantic IPv4 options parsed as %+v, %v", options, err)
		}
	})
}

func FuzzPublicIPv6ExtensionOptions(f *testing.F) {
	f.Add(true, []byte{0, IPv6ExtensionOptionRouterAlert, 2, 0, 0, IPv6ExtensionOptionPadN, 0})
	f.Add(false, []byte{0, 0xe3, 3, 1, 2, 3, IPv6ExtensionOptionPad1})
	f.Fuzz(func(t *testing.T, hopByHop bool, data []byte) {
		headerType := uint8(IPv6ExtensionHeaderDestination)
		if hopByHop {
			headerType = IPv6ExtensionHeaderHopByHop
		}
		header := IPv6ExtensionHeader{Type: headerType, Data: data}
		before := append([]byte(nil), data...)
		options, err := header.Options()
		if !bytes.Equal(data, before) {
			t.Fatal("IPv6 Options modified its input")
		}
		if err != nil {
			return
		}
		for _, option := range options {
			_ = option.Action()
			_ = option.MayChangeInTransit()
		}
		rebuilt := IPv6ExtensionHeader{Type: headerType}
		if err = rebuilt.SetOptions(options); err != nil {
			t.Fatalf("parsed IPv6 options could not be rebuilt: %v", err)
		}
		canonical := append([]byte(nil), rebuilt.Data...)
		for index := range data {
			data[index] ^= 0xff
		}
		if !bytes.Equal(rebuilt.Data, canonical) {
			t.Fatal("SetOptions retained parsed input")
		}
		if _, err = rebuilt.Options(); err != nil {
			t.Fatalf("rebuilt IPv6 options could not be parsed: %v", err)
		}
	})
}

func FuzzPublicIPv6ExtensionOptionSetters(f *testing.F) {
	f.Add(true, uint16(0), byte(0xe3), []byte{1, 2, 3})
	f.Add(false, uint16(0xffff), byte(0x80), []byte(nil))
	f.Fuzz(func(t *testing.T, hopByHop bool, routerAlert uint16, rawType byte, data []byte) {
		if len(data) > 64 {
			data = data[:64]
		}
		headerType := uint8(IPv6ExtensionHeaderDestination)
		if hopByHop {
			headerType = IPv6ExtensionHeaderHopByHop
		}
		unknownType := rawType | 0x80
		var alert IPv6ExtensionOption
		alert.SetRouterAlert(routerAlert)
		header := IPv6ExtensionHeader{Type: headerType}
		if err := header.SetOptions([]IPv6ExtensionOption{alert, {Type: unknownType, Data: data}}); err != nil {
			t.Fatal(err)
		}
		optionSize := 4 + 2 + len(data)
		total := 2 + optionSize
		padding := -total & 7
		want := make([]byte, total+padding-1)
		want[0] = byte((total+padding)/8 - 1)
		want[1], want[2] = IPv6ExtensionOptionRouterAlert, 2
		binary.BigEndian.PutUint16(want[3:5], routerAlert)
		want[5], want[6] = unknownType, byte(len(data))
		copy(want[7:], data)
		offset := 7 + len(data)
		if padding == 1 {
			want[offset] = IPv6ExtensionOptionPad1
		} else if padding > 1 {
			want[offset], want[offset+1] = IPv6ExtensionOptionPadN, byte(padding-2)
		}
		if !bytes.Equal(header.Data, want) {
			t.Fatalf("semantic IPv6 options = %x, want %x", header.Data, want)
		}
		options, err := header.Options()
		if err != nil || len(options) < 2 {
			t.Fatalf("semantic IPv6 options parsed as %+v, %v", options, err)
		}
	})
}

func FuzzChecksumParts(f *testing.F) {
	f.Add([]byte(nil), uint16(0), false, byte(ProtocolUDP))
	f.Add([]byte{1}, uint16(1), false, byte(ProtocolTCP))
	f.Add([]byte{1, 2, 3, 4, 5}, uint16(3), true, byte(ProtocolICMPv6))
	f.Fuzz(func(t *testing.T, payload []byte, splitAt uint16, ipv6 bool, protocol byte) {
		if len(payload) > 65535 {
			payload = payload[:65535]
		}
		if got, want := checksum(payload), referenceChecksum(payload); got != want {
			t.Fatalf("checksum(%d bytes) = %#x, want %#x", len(payload), got, want)
		}

		source := netip.MustParseAddr("192.0.2.129")
		target := netip.MustParseAddr("198.51.100.231")
		if ipv6 {
			source = netip.MustParseAddr("2001:db8:ffff:1::abcd")
			target = netip.MustParseAddr("fdff:ffff:ffff:ffff::1234")
		}
		pseudoHeader := make([]byte, 0, 40+len(payload))
		pseudoHeader = append(pseudoHeader, source.AsSlice()...)
		pseudoHeader = append(pseudoHeader, target.AsSlice()...)
		if ipv6 {
			length := uint32(len(payload))
			pseudoHeader = append(pseudoHeader, byte(length>>24), byte(length>>16), byte(length>>8), byte(length), 0, 0, 0, protocol)
		} else {
			pseudoHeader = append(pseudoHeader, 0, protocol, byte(len(payload)>>8), byte(len(payload)))
		}
		pseudoHeader = append(pseudoHeader, payload...)
		split := int(splitAt) % (len(payload) + 1)
		if got, want := transportChecksumParts(source, target, protocol, len(payload), payload[:split], payload[split:]), referenceChecksum(pseudoHeader); got != want {
			t.Fatalf("transport checksum at split %d/%d = %#x, want %#x", split, len(payload), got, want)
		}
		second := split
		if remaining := len(payload) - split; remaining != 0 {
			second += int(protocol) % (remaining + 1)
		}
		parts := [][]byte{payload[:split], nil, payload[split:second], {}, payload[second:]}
		if got, want := InternetChecksumParts(parts...), referenceChecksum(payload); got != want {
			t.Fatalf("multipart Internet checksum at %d/%d/%d = %#x, want %#x", split, second, len(payload), got, want)
		}
		got, err := IPTransportChecksumParts(source, target, int(protocol), parts...)
		if want := referenceChecksum(pseudoHeader); err != nil || got != want {
			t.Fatalf("multipart transport checksum at %d/%d/%d = %#x, %v; want %#x", split, second, len(payload), got, err, want)
		}
	})
}

func TestIPv6RouterAlertValidation(t *testing.T) {
	valid := []byte{ProtocolICMPv6, 0, 5, 2, 0, 0, 1, 0}
	if !ipv6RouterAlert(valid) {
		t.Fatal("valid IPv6 Router Alert was rejected")
	}
	malformed := []byte{ProtocolICMPv6, 0, 5, 1, 0, 1, 1, 0}
	if ipv6RouterAlert(malformed) {
		t.Fatal("malformed IPv6 Router Alert was accepted")
	}
	duplicate := []byte{ProtocolICMPv6, 1, 5, 2, 0, 0, 5, 2, 0, 0, 1, 4, 0, 0, 0, 0}
	if ipv6RouterAlert(duplicate) {
		t.Fatal("duplicate IPv6 Router Alert was accepted")
	}
}

func TestIPv4RouterAlertValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []byte
		valid   bool
	}{
		{name: "exact", options: []byte{148, 4, 0, 0}, valid: true},
		{name: "with-eol-padding", options: []byte{148, 4, 0, 0, 0, 0, 0, 0}, valid: true},
		{name: "after-nops", options: []byte{1, 1, 1, 1, 148, 4, 0, 0}, valid: true},
		{name: "missing", options: []byte{1, 1, 1, 0}},
		{name: "nonzero-value", options: []byte{148, 4, 0, 1}},
		{name: "duplicate", options: []byte{148, 4, 0, 0, 148, 4, 0, 0}},
		{name: "nonzero-eol-padding", options: []byte{148, 4, 0, 0, 0, 1, 0, 0}, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ipv4RouterAlert(test.options); got != test.valid {
				t.Fatalf("ipv4RouterAlert() = %t, want %t", got, test.valid)
			}
		})
	}
}

func BenchmarkChecksum(b *testing.B) {
	for _, size := range []int{20, 32, 40, 60, 576, 1280, 1500, 9000} {
		b.Run(fmt.Sprintf("%d-byte", size), func(b *testing.B) {
			data := make([]byte, size)
			for index := range data {
				data[index] = byte(index*37 + 11)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			var result uint16
			for index := 0; index < b.N; index++ {
				result = checksum(data)
			}
			if result == 0 {
				b.Fatal("unexpected zero checksum")
			}
		})
	}
}

func BenchmarkChecksumParts(b *testing.B) {
	data := make([]byte, 1500)
	for index := range data {
		data[index] = byte(index*37 + 11)
	}
	tests := []struct {
		name  string
		parts [][]byte
	}{
		{name: "one", parts: [][]byte{data}},
		{name: "two-even", parts: [][]byte{data[:750], data[750:]}},
		{name: "two-odd", parts: [][]byte{data[:751], data[751:]}},
		{name: "six-with-empty", parts: [][]byte{data[:1], nil, data[1:500], {}, data[500:1001], data[1001:]}},
	}
	source, destination := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	for _, test := range tests {
		test := test
		b.Run("Internet/"+test.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			var result uint16
			for index := 0; index < b.N; index++ {
				result = InternetChecksumParts(test.parts...)
			}
			if result == 0 {
				b.Fatal("unexpected zero checksum")
			}
		})
		b.Run("Transport/"+test.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			var result uint16
			for index := 0; index < b.N; index++ {
				var err error
				result, err = IPTransportChecksumParts(source, destination, ProtocolUDP, test.parts...)
				if err != nil {
					b.Fatal(err)
				}
			}
			if result == 0 {
				b.Fatal("unexpected zero checksum")
			}
		})
	}
}

func FuzzInboundPacket(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add(buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), ProtocolUDP, make([]byte, 8), 1, false))
	f.Add(buildMulticastTestIGMPQuery(
		netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 3, nil, true,
	))
	f.Add(buildMulticastTestMLDQuery(
		netip.MustParseAddr("fe80::2"), netip.MustParseAddr("ff02::1"), netip.IPv6Unspecified(), 2, nil,
	))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
		defer stack.Close()
		_ = writeTestPacket(stack, packet)
	})
}

func FuzzInboundChecksummedTransportPackets(f *testing.F) {
	f.Add([]byte("udp"), false, byte(0), uint16(49152), uint16(53), byte(0))
	f.Add([]byte("tcp"), false, byte(1), uint16(49153), uint16(80), byte(TCPFlagSYN))
	f.Add([]byte("icmp"), true, byte(2), uint16(1), uint16(2), byte(0))
	f.Fuzz(func(t *testing.T, payload []byte, ipv6 bool, protocolSelector byte, sourcePort, targetPort uint16, flags byte) {
		if len(payload) > 256 {
			payload = payload[:256]
		}
		local := netip.MustParseAddr("192.0.2.1")
		remote := netip.MustParseAddr("198.51.100.1")
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::1")
			remote = netip.MustParseAddr("2001:db8:1::1")
		}
		_, stack := newTestStack(t, local, remote)
		defer stack.Close()

		var packet []byte
		switch protocolSelector % 3 {
		case 0:
			packet = buildTestUDP(remote, local, sourcePort, targetPort, payload)
		case 1:
			if flags == 0 {
				flags = TCPFlagACK
			}
			options := []byte(nil)
			if flags&TCPFlagSYN != 0 {
				options = []byte{2, 4, 0x05, 0xb4, 4, 2}
			}
			packet = buildTestTCP(remote, local, sourcePort, targetPort, 1000, 2000, flags, 65535, options, payload)
		default:
			message := make([]byte, 8+len(payload))
			if ipv6 {
				message[0] = 128
			} else {
				message[0] = 8
			}
			binary.BigEndian.PutUint16(message[4:6], sourcePort)
			binary.BigEndian.PutUint16(message[6:8], targetPort)
			copy(message[8:], payload)
			if ipv6 {
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(remote, local, ProtocolICMPv6, message))
				packet = buildIPPacket(remote, local, ProtocolICMPv6, message, 1, true)
			} else {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
				packet = buildIPPacket(remote, local, ProtocolICMPv4, message, 1, true)
			}
		}
		if err := writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzIPPacketParsing(f *testing.F) {
	local4 := netip.MustParseAddr("192.0.2.1")
	remote4 := netip.MustParseAddr("198.51.100.1")
	local6 := netip.MustParseAddr("2001:db8::1")
	remote6 := netip.MustParseAddr("2001:db8:1::1")
	f.Add([]byte(nil))
	f.Add(buildIPPacket(remote4, local4, ProtocolUDP, make([]byte, udpHeaderSize), 1, false))
	f.Add(buildTestIPv4Options(remote4, local4, []byte{1, 1, 0, 0}))
	f.Add(buildIPPacket(remote6, local6, ProtocolTCP, make([]byte, tcpHeaderSize), 0, true))
	f.Add(buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 1, 0, 0, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65575 {
			packet = packet[:65575]
		}
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet, false)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified its input")
		}
		repeated, repeatedOK := parseIPPacket(packet, false)
		if repeatedOK != ok {
			t.Fatal("parseIPPacket returned a nondeterministic validity result")
		}
		if !ok {
			return
		}
		if parsed.source != repeated.source || parsed.target != repeated.target || parsed.protocol != repeated.protocol ||
			parsed.protocolOffset != repeated.protocolOffset || parsed.parameterError != repeated.parameterError ||
			parsed.parameterCode != repeated.parameterCode || parsed.parameterAt != repeated.parameterAt ||
			parsed.ecn != repeated.ecn || parsed.hopLimit != repeated.hopLimit || parsed.trafficClass != repeated.trafficClass ||
			parsed.flowLabel != repeated.flowLabel || !bytes.Equal(parsed.payload, repeated.payload) || !bytes.Equal(parsed.original, repeated.original) {
			t.Fatal("parseIPPacket returned nondeterministic packet metadata")
		}
		if len(parsed.original) == 0 || len(parsed.original) > len(packet) || !bytes.Equal(parsed.original, packet[:len(parsed.original)]) {
			t.Fatalf("parsed original length %d is not an input prefix of %d bytes", len(parsed.original), len(packet))
		}
		if !parsed.source.IsValid() || !parsed.target.IsValid() || parsed.source.Is4() != parsed.target.Is4() {
			t.Fatalf("parsed address families are invalid: %v -> %v", parsed.source, parsed.target)
		}
		if parsed.parameterError {
			if parsed.parameterAt >= uint32(len(parsed.original)) {
				t.Fatalf("parameter pointer %d is outside %d-byte packet", parsed.parameterAt, len(parsed.original))
			}
			return
		}
		if parsed.protocolOffset < 0 || parsed.protocolOffset >= len(parsed.original) {
			t.Fatalf("protocol offset %d is outside %d-byte packet", parsed.protocolOffset, len(parsed.original))
		}
		if len(parsed.payload) > len(parsed.original) || !bytes.Equal(parsed.payload, parsed.original[len(parsed.original)-len(parsed.payload):]) {
			t.Fatalf("parsed payload length %d is not an original-packet suffix", len(parsed.payload))
		}
	})
}

func FuzzIPv4OptionParsing(f *testing.F) {
	local := netip.MustParseAddr("192.0.2.171")
	remote := netip.MustParseAddr("198.51.100.171")
	f.Add([]byte(nil))
	f.Add([]byte{1, 1, 0, 0})
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{148, 4, 0, 0})
	f.Add([]byte{148, 3, 0, 0})
	f.Add([]byte{131, 3, 4, 0})
	f.Add([]byte{7, 3, 3, 0})
	f.Add([]byte{68, 4, 5, 0xf0})
	f.Fuzz(func(t *testing.T, input []byte) {
		options := paddedIPv4FuzzOptions(input)
		packet := buildTestIPv4Options(remote, local, options)
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet, false)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified an IPv4 option packet")
		}
		repeated, repeatedOK := parseIPPacket(packet, false)
		if repeatedOK != ok || parsed.parameterError != repeated.parameterError || parsed.parameterAt != repeated.parameterAt ||
			parsed.parameterCode != repeated.parameterCode || parsed.protocol != repeated.protocol || !bytes.Equal(parsed.payload, repeated.payload) {
			t.Fatal("IPv4 option parsing was nondeterministic")
		}

		optionAt, malformed := malformedIPv4Option(options)
		if malformed {
			if optionAt < 0 || optionAt >= len(options) {
				t.Fatalf("malformed IPv4 option pointer %d outside %d-byte option area", optionAt, len(options))
			}
			if !ok || !parsed.parameterError || parsed.parameterCode != 0 || parsed.parameterAt != uint32(20+optionAt) {
				t.Fatalf("malformed IPv4 options %x parsed as %+v, ok=%t", options, parsed, ok)
			}
			return
		}
		if !validateIPv4Options(options) {
			if ok {
				t.Fatalf("policy-rejected IPv4 options %x were accepted as %+v", options, parsed)
			}
			return
		}
		if !ok || parsed.parameterError || parsed.protocol != ProtocolUDP || len(parsed.payload) != udpHeaderSize || parsed.hasRouterAlert() != ipv4RouterAlert(options) {
			t.Fatalf("valid IPv4 options %x parsed as %+v, ok=%t", options, parsed, ok)
		}
	})
}

func paddedIPv4FuzzOptions(input []byte) []byte {
	if len(input) > 40 {
		input = input[:40]
	}
	size := (len(input) + 3) &^ 3
	options := make([]byte, size)
	copy(options, input)
	return options
}

func FuzzIPv6OptionParsing(f *testing.F) {
	local := netip.MustParseAddr("2001:db8::171")
	remote := netip.MustParseAddr("2001:db8:1::171")
	multicast := netip.MustParseAddr("ff02::1")
	f.Add([]byte(nil), true, false)
	f.Add([]byte{5, 2, 0, 0}, true, false)
	f.Add([]byte{0x40, 0}, true, false)
	f.Add([]byte{0x80, 0}, false, false)
	f.Add([]byte{0xc0, 0}, true, true)
	f.Fuzz(func(t *testing.T, input []byte, hopByHop bool, multicastTarget bool) {
		options := paddedIPv6FuzzOptions(input)
		header := make([]byte, 8+len(options))
		header[0] = ProtocolUDP
		header[1] = byte(len(header)/8 - 1)
		copy(header[2:], options)
		extensionType := byte(60)
		if hopByHop {
			extensionType = 0
		}
		target := local
		if multicastTarget {
			target = multicast
		}
		packet := buildTestIPv6Extension(remote, target, extensionType, header)
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet, false)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified an IPv6 option packet")
		}
		repeated, repeatedOK := parseIPPacket(packet, false)
		if repeatedOK != ok || parsed.parameterError != repeated.parameterError || parsed.parameterAt != repeated.parameterAt ||
			parsed.parameterCode != repeated.parameterCode || parsed.protocol != repeated.protocol || !bytes.Equal(parsed.payload, repeated.payload) {
			t.Fatal("IPv6 option parsing was nondeterministic")
		}

		valid, action, optionAt := inspectIPv6Options(header)
		if !valid {
			if optionAt < 0 || optionAt >= len(header) {
				t.Fatalf("invalid IPv6 option pointer %d outside %d-byte header", optionAt, len(header))
			}
			if action >= 2 && (action == 2 || !target.IsMulticast()) {
				if !ok || !parsed.parameterError || parsed.parameterCode != 2 || parsed.parameterAt != uint32(40+optionAt) {
					t.Fatalf("invalid IPv6 options %x parsed as %+v, ok=%t", header, parsed, ok)
				}
			} else if ok {
				t.Fatalf("silently discarded IPv6 options %x were accepted as %+v", header, parsed)
			}
			return
		}
		if !ok || parsed.parameterError || parsed.protocol != ProtocolUDP || len(parsed.payload) != 0 {
			t.Fatalf("valid IPv6 options %x parsed as %+v, ok=%t", header, parsed, ok)
		}
		if hopByHop && parsed.hasRouterAlert() != ipv6RouterAlert(header) {
			t.Fatalf("IPv6 Router Alert mismatch for %x", header)
		}
	})
}

func paddedIPv6FuzzOptions(input []byte) []byte {
	if len(input) > 62 {
		input = input[:62]
	}
	size := (len(input) + 7) &^ 7
	options := make([]byte, size)
	copy(options, input)
	return options
}

func TestIPv6FlowLabelEncodingAndFragmentation(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::10")
	target := netip.MustParseAddr("2001:db8::20")
	const label = uint32(0xabcde)
	packet := buildIPPacketWithOptions(source, target, ProtocolUDP, make([]byte, udpHeaderSize), 0, true, ipPacketOptions{
		trafficClass: 0x2e, flowLabel: label, flowLabelSet: true,
	})
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.trafficClass != 0x2e || parsed.flowLabel != label {
		t.Fatalf("IPv6 flow header = class %#x label %#x, parsed=%v", parsed.trafficClass, parsed.flowLabel, ok)
	}
	setPacketECN(packet, 3)
	parsed, ok = parseIPPacket(packet, false)
	if !ok || parsed.ecn != 3 || parsed.flowLabel != label {
		t.Fatalf("IPv6 ECN update changed flow label: ECN %d label %#x", parsed.ecn, parsed.flowLabel)
	}

	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	err = stack.tryWriteIPSocketPayloadForMTU(source, target, ProtocolUDP, make([]byte, 2000), sourceFragmentation{allow: true}, ipPacketOptions{}, stack.mtuFor(target))
	fragments := takeIPOutputPackets(&stack.outbound)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("IPv6 flow fragmentation = %d packets, %v", len(fragments), err)
	}
	var automatic uint32
	for index, fragment := range fragments {
		current := uint32(fragment[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(fragment[2:4]))
		if current == 0 || index != 0 && current != automatic {
			t.Fatalf("IPv6 fragment %d flow label = %#x, first %#x", index, current, automatic)
		}
		automatic = current
	}
}

func TestStrictIPOptionsAndUnsupportedProtocols(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.50")
	remote4 := netip.MustParseAddr("198.51.100.50")
	validIPv4 := buildTestIPv4Options(remote4, local4, []byte{1, 0, 0, 0})
	if _, ok := parseIPPacket(validIPv4, false); !ok {
		t.Fatal("valid IPv4 options were rejected")
	}
	for _, options := range [][]byte{{7, 1, 0, 0}, {30, 1, 0, 0}} {
		parsed, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, options), false)
		if !ok || !parsed.parameterError || parsed.parameterCode != 0 {
			t.Fatalf("malformed IPv4 options = %+v, %v for %x", parsed, ok, options)
		}
	}
	for _, test := range []struct {
		options []byte
		pointer uint32
	}{
		{[]byte{7, 2, 0, 0}, 21},
		{[]byte{7, 3, 3, 0}, 22},
		{[]byte{68, 4, 4, 0}, 22},
		{[]byte{68, 4, 5, 0xf0}, 23},
		{[]byte{148, 3, 0, 0}, 21},
		{[]byte{131, 2, 0, 0}, 21},
	} {
		parsed, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, test.options), false)
		if !ok || !parsed.parameterError || parsed.parameterAt != test.pointer {
			t.Fatalf("IPv4 option %x = %+v, %v; want pointer %d", test.options, parsed, ok, test.pointer)
		}
	}
	reservedTimestampFlag := buildTestIPv4Options(remote4, local4, []byte{68, 4, 5, 2})
	if parsed, ok := parseIPPacket(reservedTimestampFlag, false); !ok || parsed.parameterError {
		t.Fatalf("Linux-compatible reserved timestamp flag = %+v, parsed=%t", parsed, ok)
	}
	duplicateRoute := buildTestIPv4Options(remote4, local4, []byte{7, 3, 4, 7, 3, 4, 0, 0})
	parsedRoute, ok := parseIPPacket(duplicateRoute, false)
	if !ok || !parsedRoute.parameterError || parsedRoute.parameterAt != 23 {
		t.Fatalf("duplicate IPv4 record route = %+v, %v", parsedRoute, ok)
	}
	if _, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, []byte{131, 3, 4, 0}), false); ok {
		t.Fatal("unsupported IPv4 source route was accepted")
	}

	local6 := netip.MustParseAddr("2001:db8::50")
	remote6 := netip.MustParseAddr("2001:db8::51")
	if _, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 0x40, 0, 0, 0, 0, 0}), false); ok {
		t.Fatal("IPv6 discard-action option was accepted")
	}
	routingError, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 43, []byte{ProtocolUDP, 0, 99, 1, 0, 0, 0, 0}), false)
	if !ok || !routingError.parameterError || routingError.parameterCode != 0 || routingError.parameterAt != 42 {
		t.Fatalf("active IPv6 routing header = %+v, parsed = %v", routingError, ok)
	}
	misplacedHopPacket := IPPacket{Source: remote6, Destination: local6, HopLimit: 64}
	if err := misplacedHopPacket.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{
		{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)},
		{Type: IPv6ExtensionHeaderHopByHop, Data: make([]byte, 7)},
	}, ProtocolUDP, nil); err != nil {
		t.Fatal(err)
	}
	misplacedHop, err := misplacedHopPacket.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	misplacedHopError, ok := parseIPPacket(misplacedHop, false)
	if !ok || !misplacedHopError.parameterError || misplacedHopError.parameterCode != 1 || misplacedHopError.parameterAt != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop header = %+v, parsed = %v", misplacedHopError, ok)
	}
	paddedEmptyPacket := buildIPPacket(remote6, local6, ProtocolUDP, []byte{1}, 0, true)
	paddedEmptyPacket[4], paddedEmptyPacket[5] = 0, 0
	parsedEmptyPacket, ok := parseIPPacket(paddedEmptyPacket, false)
	if !ok || len(parsedEmptyPacket.payload) != 0 || len(parsedEmptyPacket.original) != 40 {
		t.Fatalf("zero-length IPv6 payload with link padding = %+v, parsed=%t", parsedEmptyPacket, ok)
	}
	jumboHeader := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = jumboHeader.SetOptions([]IPv6ExtensionOption{
		{Type: IPv6ExtensionOptionJumboPayload, Data: []byte{0, 1, 0, 0}},
	}); err != nil {
		t.Fatal(err)
	}
	jumbogramPacket := IPPacket{Source: remote6, Destination: local6, HopLimit: 64}
	if err = jumbogramPacket.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{
		jumboHeader,
	}, ProtocolUDP, nil); err != nil {
		t.Fatal(err)
	}
	jumbogram, err := jumbogramPacket.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	jumbogram[4], jumbogram[5] = 0, 0
	if _, ok = parseIPPacket(jumbogram, false); ok {
		t.Fatal("unsupported IPv6 jumbogram was accepted")
	}

	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32),
		netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	unsupportedOption := buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 0x80, 0, 0, 0, 0, 0})
	if err = writeTestPacket(stack, unsupportedOption); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 2 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 unsupported-option response = %x", response)
	}
	malformedIPv4 := buildTestIPv4Options(remote4, local4, []byte{7, 1, 0, 0})
	if err = writeTestPacket(stack, malformedIPv4); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 12 || parsed.payload[1] != 0 || parsed.payload[4] != 20 {
		t.Fatalf("IPv4 malformed-option response = %x", response)
	}
	nonInitial := append([]byte(nil), malformedIPv4...)
	binary.BigEndian.PutUint16(nonInitial[6:8], 1)
	nonInitial[10], nonInitial[11] = 0, 0
	headerSize := int(nonInitial[0]&0x0f) * 4
	binary.BigEndian.PutUint16(nonInitial[10:12], checksum(nonInitial[:headerSize]))
	if err = writeTestPacket(stack, nonInitial); err != nil {
		t.Fatal(err)
	}
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("non-initial malformed fragment produced Parameter Problem: %x", response)
	}
	activeRouting := buildTestIPv6Extension(remote6, local6, 43, []byte{ProtocolUDP, 0, 99, 1, 0, 0, 0, 0})
	if err = writeTestPacket(stack, activeRouting); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 routing-header response = %x", response)
	}
	if err = writeTestPacket(stack, misplacedHop); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop response = %x", response)
	}
	icmpErrorWithUnknownOption := buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolICMPv6, 0, 0x80, 0, 0, 0, 0, 0})
	icmpErrorWithUnknownOption = append(icmpErrorWithUnknownOption, 1, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(icmpErrorWithUnknownOption[4:6], uint16(len(icmpErrorWithUnknownOption)-40))
	if err = writeTestPacket(stack, icmpErrorWithUnknownOption); err != nil {
		t.Fatal(err)
	}
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("ICMPv6 error produced recursive Parameter Problem: %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote4, local4, 99, []byte{1, 2, 3, 4}, 1, true)); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 3 || parsed.payload[1] != 2 {
		t.Fatalf("IPv4 unsupported-protocol response = %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote6, local6, 100, []byte{1, 2, 3, 4}, 0, true)); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 6 {
		t.Fatalf("IPv6 unsupported-protocol response = %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote6, local6, 59, nil, 0, true)); err != nil {
		t.Fatal(err)
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("IPv6 No Next Header produced a response: %x", response)
	}
}

func TestIPv6ExtensionHeadersFollowReceiverRules(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::60")
	remote := netip.MustParseAddr("2001:db8::61")
	firstFragment, secondFragment := IPv6ExtensionHeader{}, IPv6ExtensionHeader{}
	if err := firstFragment.SetFragment(0, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := secondFragment.SetFragment(0, false, 2); err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: remote, Destination: local, HopLimit: 64}
	if err := packet.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{
		{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)},
		{Type: IPv6ExtensionHeaderRouting, Data: []byte{0, 99, 0, 0, 0, 0, 0}},
		{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)},
		{Type: IPv6ExtensionHeaderRouting, Data: []byte{0, 99, 0, 0, 0, 0, 0}},
		{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)},
		firstFragment,
		secondFragment,
	}, ProtocolUDP, []byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	wire, err := packet.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := parseIPPacket(wire, false)
	if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != 8 {
		t.Fatalf("repeated IPv6 extension headers = %+v, parsed = %t", parsed, ok)
	}
}

func TestForeignLoopbackSourceIsDropped(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, source netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.60"), source: netip.MustParseAddr("127.0.0.2")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::60"), source: netip.IPv6Loopback()},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.source)
			request := buildTestUDP(test.source, test.local, 55000, 55001, []byte("drop"))
			if err := writeTestPacket(stack, request); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				t.Fatalf("foreign loopback source produced a response: %x", response)
			case <-time.After(25 * time.Millisecond):
			}
			if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
				t.Fatalf("foreign loopback drops = %d, want 1", dropped)
			}
		})
	}
}

func TestIPv4MappedIPv6WireSourceIsDropped(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::62")
	remote := netip.MustParseAddr("2001:db8::63")
	_, stack := newTestStack(t, local, remote)
	packet := buildIPPacket(remote, local, 99, []byte{1}, 0, true)
	mapped := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	copy(packet[8:24], mapped[:])
	before := stack.Stats().InboundDroppedPackets
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if after := stack.Stats().InboundDroppedPackets; after != before+1 {
		t.Fatalf("mapped IPv6 source drop count = %d, want %d", after, before+1)
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("mapped IPv6 source produced response: %x", response)
	}
}

func TestIPv4MappedIPv6WireDestinationIsDropped(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.62")
	remote6 := netip.MustParseAddr("2001:db8::63")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildIPPacket(remote6, netip.MustParseAddr("2001:db8::62"), 99, []byte{1}, 0, true)
	mapped := netip.MustParseAddr("::ffff:192.0.2.62").As16()
	copy(packet[24:40], mapped[:])
	before := stack.Stats().InboundDroppedPackets
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if after := stack.Stats().InboundDroppedPackets; after != before+1 {
		t.Fatalf("mapped IPv6 destination drop count = %d, want %d", after, before+1)
	}
}

func TestIPv4DirectedBroadcastSourceIsDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.60")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.60/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildTestUDP(netip.MustParseAddr("192.0.2.255"), local, 55000, 55001, []byte("drop"))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("directed-broadcast source produced a response: %x", response)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("directed-broadcast source drops = %d, want 1", dropped)
	}
}

func TestICMPProtocolMustMatchIPFamily(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::70")
	remote := netip.MustParseAddr("2001:db8::71")
	link, stack := newTestStack(t, local, remote)
	echo := make([]byte, 8)
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[2:4], checksum(echo))
	if err := writeTestPacket(stack, buildIPPacket(remote, local, ProtocolICMPv4, echo, 0, true)); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cross-family protocol error")
	}
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 {
		t.Fatalf("cross-family ICMP response = %x", response)
	}
}

func BenchmarkParseIPPacket(b *testing.B) {
	ipv6ExtensionPacket := testIPv6ExtensionBenchmarkPacket()
	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{name: "IPv4", packet: buildTestUDP(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.1"), 50000, 443, make([]byte, 1200))},
		{name: "IPv6", packet: buildTestUDP(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1"), 50000, 443, make([]byte, 1200))},
		{name: "IPv6-extension", packet: ipv6ExtensionPacket},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.packet)))
			for index := 0; index < b.N; index++ {
				if _, err := ParseIPPacket(test.packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIPPacketMarshalFragments(b *testing.B) {
	payload := make([]byte, 16*1024)
	for _, packet := range []IPPacket{
		{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
			Protocol: 99, HopLimit: 64, Identification: 1, Payload: payload,
		},
		{
			Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8:1::1"),
			Protocol: 99, HopLimit: 64, Payload: payload,
		},
	} {
		name := "IPv4"
		if packet.Source.Is6() {
			name = "IPv6"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for index := 0; index < b.N; index++ {
				if _, err := packet.MarshalFragments(1500, uint32(index)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIPPacketAppend(b *testing.B) {
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		b.Fatal(err)
	}
	extensionPacket := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8:1::1"), HopLimit: 64,
	}
	if err := extensionPacket.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop}, ProtocolUDP, make([]byte, 1200)); err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		packet IPPacket
	}{
		{
			name: "IPv4",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
				Protocol: ProtocolUDP, HopLimit: 64, Payload: make([]byte, 1200),
			},
		},
		{
			name: "IPv6",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8:1::1"),
				Protocol: ProtocolUDP, HopLimit: 64, Payload: make([]byte, 1200),
			},
		},
		{name: "IPv6-extension", packet: extensionPacket},
	} {
		b.Run(test.name+"/strict", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.packet.Payload)))
			dst := make([]byte, 0, 1280)
			for index := 0; index < b.N; index++ {
				var err error
				dst, err = test.packet.AppendBinary(dst[:0])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(test.name+"/raw", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.packet.Payload)))
			dst := make([]byte, 0, 1280)
			for index := 0; index < b.N; index++ {
				var err error
				dst, err = test.packet.AppendRawBinary(dst[:0])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStackPacketParsing(b *testing.B) {
	ipv6ExtensionPacket := testIPv6ExtensionBenchmarkPacket()
	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{name: "IPv4", packet: buildTestUDP(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.1"), 50000, 443, make([]byte, 1200))},
		{name: "IPv6", packet: buildTestUDP(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1"), 50000, 443, make([]byte, 1200))},
		{name: "IPv6-extension", packet: ipv6ExtensionPacket},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.packet)))
			for index := 0; index < b.N; index++ {
				if _, ok := parseIPPacket(test.packet, false); !ok {
					b.Fatal("valid packet was rejected")
				}
			}
		})
	}
}

func testIPv6ExtensionBenchmarkPacket() []byte {
	packet := buildTestUDP(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1"), 50000, 443, make([]byte, 1200))
	withExtension := make([]byte, len(packet)+8)
	copy(withExtension[:40], packet[:40])
	withExtension[6] = IPv6ExtensionHeaderHopByHop
	binary.BigEndian.PutUint16(withExtension[4:6], uint16(len(withExtension)-40))
	copy(withExtension[40:48], []byte{ProtocolUDP, 0, IPv6ExtensionOptionPadN, 4, 0, 0, 0, 0})
	copy(withExtension[48:], packet[40:])
	return withExtension
}

func BenchmarkIPPacketFragment(b *testing.B) {
	fragment6 := make([]byte, 8+1200)
	fragment6[0] = ProtocolUDP
	binary.BigEndian.PutUint16(fragment6[2:4], 1)
	binary.BigEndian.PutUint32(fragment6[4:8], 0x12345678)
	extensionFragment6 := make([]byte, 8+len(fragment6))
	copy(extensionFragment6[:8], []byte{IPv6ExtensionHeaderFragment, 0, IPv6ExtensionOptionPadN, 4, 0, 0, 0, 0})
	copy(extensionFragment6[8:], fragment6)
	for _, test := range []struct {
		name   string
		packet IPPacket
	}{
		{
			name: "IPv4",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
				Protocol: ProtocolUDP, MoreFragments: true, Payload: make([]byte, 1200),
			},
		},
		{
			name: "IPv6",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8:1::1"),
				Protocol: IPv6ExtensionHeaderFragment, Payload: fragment6,
			},
		},
		{
			name: "IPv6-extension",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8:1::1"),
				Protocol: IPv6ExtensionHeaderHopByHop, Payload: extensionFragment6,
			},
		},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			var view IPPacketFragmentView
			var ok bool
			for index := 0; index < b.N; index++ {
				view, ok = test.packet.Fragment()
			}
			if !ok || len(view.Payload) == 0 {
				b.Fatal("fragment metadata unavailable")
			}
		})
	}
}

package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func takeIPOutputPackets(queue *packetQueue) [][]byte {
	var packets [][]byte
	for {
		entry, ok := queue.tryDequeue()
		if !ok {
			return packets
		}
		packets = append(packets, consumeTestPacket(queue, entry))
	}
}

func TestPublicFragmentCodecKnownAnswers(t *testing.T) {
	first4 := mustCodecVector(t, "45000024778820001ffd170dc000020ac633640a000102030405060708090a0b0c0d0e0f")
	last4 := mustCodecVector(t, "45000019778800021ffd3716c000020ac633640a1011121314")
	packet4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.10"),
		Protocol: 253, HopLimit: 31, Identification: 0x7788, Payload: mustCodecVector(t, "000102030405060708090a0b0c0d0e0f1011121314"),
	}
	fragments, err := packet4.MarshalFragments(36, 0)
	if err != nil || len(fragments) != 2 || !bytes.Equal(fragments[0], first4) || !bytes.Equal(fragments[1], last4) {
		t.Fatalf("IPv4 MarshalFragments: error=%v\n got %x\nwant [%x %x]", err, fragments, first4, last4)
	}
	for index, wire := range fragments {
		packet, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		fragment, ok := packet.Fragment()
		end := (index + 1) * 16
		if end > len(packet4.Payload) {
			end = len(packet4.Payload)
		}
		if !ok || fragment.Identification != 0x7788 || fragment.Offset != index*16 ||
			fragment.MoreFragments != (index == 0) || !bytes.Equal(fragment.Payload, packet4.Payload[index*16:end]) {
			t.Fatalf("IPv4 fragment %d = %+v/%t", index, fragment, ok)
		}
	}

	first6 := mustCodecVector(t, "622345670020003f20010db800000000000000000000000920010db800000000000000000000000a"+
		"2c00050200000000fd00000110203040000102030405060708090a0b0c0d0e0f")
	middle6 := mustCodecVector(t, "622345670020003f20010db800000000000000000000000920010db800000000000000000000000a"+
		"2c00050200000000fd00001110203040101112131415161718191a1b1c1d1e1f")
	last6 := mustCodecVector(t, "622345670015003f20010db800000000000000000000000920010db800000000000000000000000a"+
		"2c00050200000000fd000020102030402021222324")
	hopByHop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop, Data: mustCodecVector(t, "00050200000000")}
	packet6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::9"), Destination: netip.MustParseAddr("2001:db8::a"),
		HopLimit: 63, TrafficClass: 0x22, FlowLabel: 0x34567,
	}
	if err = packet6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hopByHop}, 253,
		mustCodecVector(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324")); err != nil {
		t.Fatal(err)
	}
	fragments, err = packet6.MarshalFragments(72, 0x10203040)
	if err != nil || len(fragments) != 3 || !bytes.Equal(fragments[0], first6) ||
		!bytes.Equal(fragments[1], middle6) || !bytes.Equal(fragments[2], last6) {
		t.Fatalf("IPv6 MarshalFragments: error=%v\n got %x\nwant [%x %x %x]", err, fragments, first6, middle6, last6)
	}
	for index, wire := range fragments {
		packet, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		fragment, ok := packet.Fragment()
		if !ok || fragment.Protocol != 253 || fragment.Identification != 0x10203040 ||
			fragment.Offset != index*16 || fragment.MoreFragments != (index != len(fragments)-1) {
			t.Fatalf("IPv6 fragment %d = %+v/%t", index, fragment, ok)
		}
	}

	atomicWire := mustCodecVector(t, "655abcde00162c4020010db800000000000000000000000720010db8000000000000000000000008"+
		"11000000deadbeef9c409c41000e318a61746f6d6963")
	atomicPacket, err := ParseIPPacket(atomicWire)
	if err != nil {
		t.Fatal(err)
	}
	atomic, ok := atomicPacket.Fragment()
	if !ok || !atomic.IsAtomic() || atomic.Protocol != ProtocolUDP || atomic.Identification != 0xdeadbeef {
		t.Fatalf("atomic fragment = %+v/%t", atomic, ok)
	}
	datagram, err := atomicPacket.UDPDatagram()
	if err != nil || string(datagram.Payload) != "atomic" {
		t.Fatalf("UDP in atomic fragment = %+v, %v", datagram, err)
	}

	var reassembly4 IPPacketReassembly
	for index, wire := range [][]byte{last4, first4} {
		fragment, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		packet, complete, addErr := reassembly4.Add(fragment)
		if addErr != nil || complete != (index == 1) {
			t.Fatalf("IPv4 known-answer reassembly %d = complete %t, %v", index, complete, addErr)
		}
		if complete {
			want := mustCodecVector(t, "45000029778800001ffd3708c000020ac633640a"+
				"000102030405060708090a0b0c0d0e0f1011121314")
			encoded, encodeErr := packet.MarshalBinary()
			if encodeErr != nil || !bytes.Equal(encoded, want) {
				t.Fatalf("IPv4 known-answer reassembly: error=%v\n got %x\nwant %x", encodeErr, encoded, want)
			}
			if _, fragmented := packet.Fragment(); fragmented {
				t.Fatal("IPv4 known-answer reassembly retained fragment metadata")
			}
		}
	}

	var reassembly6 IPPacketReassembly
	for index, wire := range [][]byte{middle6, last6, first6} {
		fragment, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		packet, complete, addErr := reassembly6.Add(fragment)
		if addErr != nil || complete != (index == 2) {
			t.Fatalf("IPv6 known-answer reassembly %d = complete %t, %v", index, complete, addErr)
		}
		if complete {
			want := mustCodecVector(t, "62234567002d003f20010db8000000000000000000000009"+
				"20010db800000000000000000000000a"+
				"fd00050200000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324")
			encoded, encodeErr := packet.MarshalBinary()
			if encodeErr != nil || !bytes.Equal(encoded, want) {
				t.Fatalf("IPv6 known-answer reassembly: error=%v\n got %x\nwant %x", encodeErr, encoded, want)
			}
			if _, fragmented := packet.Fragment(); fragmented {
				t.Fatal("IPv6 known-answer reassembly retained Fragment header")
			}
		}
	}
}

func TestIPv6AtomicFragmentReservedBits(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2001:db8::1")
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0] = ProtocolUDP
	fragment[1] = 0xff
	binary.BigEndian.PutUint16(fragment[2:4], 0x0002)
	binary.BigEndian.PutUint32(fragment[4:8], 1)
	packet := buildIPPacket(source, target, 44, fragment, 0, false)
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != udpHeaderSize {
		t.Fatalf("IPv6 atomic fragment with reserved bits = %+v, parsed = %v", parsed, ok)
	}
}

func TestIPv6FragmentReservedBitsAreIgnored(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, make([]byte, 24), 56, 7, ipPacketOptions{})
	for index, fragment := range fragments {
		fragment[41] = 0xff
		field := binary.BigEndian.Uint16(fragment[42:44]) | 0x0006
		binary.BigEndian.PutUint16(fragment[42:44], field)
		packet := stack.reassemblePacket(fragment, time.Now())
		if index != len(fragments)-1 && packet != nil {
			t.Fatal("reserved bits completed IPv6 reassembly early")
		}
		if index == len(fragments)-1 {
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != 24 {
				t.Fatalf("reserved-bit IPv6 reassembly = %+v, parsed = %v", parsed, ok)
			}
		}
	}
}

func TestPathMTUDiscoveryOutputPolicy(t *testing.T) {
	type expectation struct {
		error        bool
		fragmented   bool
		dontFragment bool
		identifiable bool
		ceiling      int
	}
	for _, family := range []struct {
		name           string
		source, target netip.Addr
		headerSize     int
		pathMTU        int
	}{
		{name: "IPv4", source: netip.MustParseAddr("192.0.2.201"), target: netip.MustParseAddr("198.51.100.201"), headerSize: 20, pathMTU: 1000},
		{name: "IPv6", source: netip.MustParseAddr("2001:db8::201"), target: netip.MustParseAddr("2001:db8:1::201"), headerSize: 40, pathMTU: 1280},
	} {
		t.Run(family.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(family.source, family.source.BitLen())}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if !stack.observePathMTU(family.target, uint32(family.pathMTU)) {
				t.Fatal("failed to install confirmed PMTU")
			}

			tests := []struct {
				name       string
				mode       PathMTUDiscovery
				packetSize int
				want       expectation
			}{
				{name: "dont-small", mode: PathMTUDiscoveryDont, packetSize: 900, want: expectation{identifiable: true, ceiling: family.pathMTU}},
				{name: "want-small", mode: PathMTUDiscoveryWant, packetSize: 900, want: expectation{dontFragment: true, identifiable: true, ceiling: family.pathMTU}},
				{name: "do-small", mode: PathMTUDiscoveryDo, packetSize: 900, want: expectation{dontFragment: true, ceiling: family.pathMTU}},
				{name: "probe-small", mode: PathMTUDiscoveryProbe, packetSize: 900, want: expectation{dontFragment: true, ceiling: 1500}},
				{name: "interface-small", mode: PathMTUDiscoveryInterface, packetSize: 900, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "omit-small", mode: PathMTUDiscoveryOmit, packetSize: 900, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "dont-path-exceeded", mode: PathMTUDiscoveryDont, packetSize: family.pathMTU + 200, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "want-path-exceeded", mode: PathMTUDiscoveryWant, packetSize: family.pathMTU + 200, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "do-path-exceeded", mode: PathMTUDiscoveryDo, packetSize: family.pathMTU + 200, want: expectation{error: true, ceiling: family.pathMTU}},
				{name: "probe-ignores-path", mode: PathMTUDiscoveryProbe, packetSize: family.pathMTU + 200, want: expectation{dontFragment: true, ceiling: 1500}},
				{name: "interface-ignores-path", mode: PathMTUDiscoveryInterface, packetSize: family.pathMTU + 200, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "omit-ignores-path", mode: PathMTUDiscoveryOmit, packetSize: family.pathMTU + 200, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "dont-interface-exceeded", mode: PathMTUDiscoveryDont, packetSize: 1600, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "want-interface-exceeded", mode: PathMTUDiscoveryWant, packetSize: 1600, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "do-interface-exceeded", mode: PathMTUDiscoveryDo, packetSize: 1600, want: expectation{error: true, ceiling: family.pathMTU}},
				{name: "probe-interface-exceeded", mode: PathMTUDiscoveryProbe, packetSize: 1600, want: expectation{error: true, ceiling: 1500}},
				{name: "interface-interface-exceeded", mode: PathMTUDiscoveryInterface, packetSize: 1600, want: expectation{error: true, ceiling: 1500}},
				{name: "omit-interface-exceeded", mode: PathMTUDiscoveryOmit, packetSize: 1600, want: expectation{fragmented: true, ceiling: 1500}},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					stack.ipv4ID.Store(100)
					mtu, fragmentation := stack.pathMTUOutputPolicy(family.target, test.mode)
					if mtu != test.want.ceiling {
						t.Fatalf("selected MTU = %d, want %d", mtu, test.want.ceiling)
					}
					payload := make([]byte, test.packetSize-family.headerSize)
					outputErr := stack.tryWriteIPSocketPayloadForMTU(family.source, family.target, 99, payload, fragmentation, ipPacketOptions{}, mtu)
					packets := takeIPOutputPackets(&stack.outbound)
					if test.want.error {
						if !errors.Is(outputErr, syscall.EMSGSIZE) || len(packets) != 0 {
							t.Fatalf("output = %d packets, %v; want EMSGSIZE", len(packets), outputErr)
						}
						return
					}
					if outputErr != nil {
						t.Fatal(outputErr)
					}
					if fragmented := len(packets) > 1; fragmented != test.want.fragmented {
						t.Fatalf("fragmented = %v (%d packets), want %v", fragmented, len(packets), test.want.fragmented)
					}
					for _, packet := range packets {
						if len(packet) > test.want.ceiling {
							t.Fatalf("packet length = %d, ceiling %d", len(packet), test.want.ceiling)
						}
						if family.source.Is4() {
							df := binary.BigEndian.Uint16(packet[6:8])&0x4000 != 0
							if df != test.want.dontFragment {
								t.Fatalf("IPv4 DF = %v, want %v", df, test.want.dontFragment)
							}
							identification := binary.BigEndian.Uint16(packet[4:6])
							wantIdentification := test.want.identifiable || test.want.fragmented
							if (identification != 0) != wantIdentification {
								t.Fatalf("IPv4 identification = %d, identifiable want %v", identification, wantIdentification)
							}
						} else if test.want.fragmented && packet[6] != 44 {
							t.Fatalf("IPv6 next header = %d, want Fragment", packet[6])
						}
					}
				})
			}
		})
	}
}

func TestIPv6FragmentAfterRepeatedExtensionHeaders(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	payload := make([]byte, 0, 6*8)
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0)
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0)
	payload = append(payload, 44, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 99, 0, 0, 1, 0, 0, 0, 7)
	payload = append(payload, 1, 2, 3, 4, 5, 6, 7, 8)
	fragment, ok := parseFragment(buildIPPacket(remote, local, 60, payload, 0, false), false)
	if !ok || !fragment.v6 || fragment.protocol != 99 || fragment.offset != 0 || !fragment.more || len(fragment.header) != 80 {
		t.Fatalf("fragment after repeated extension headers = %+v, parsed = %t", fragment, ok)
	}
}

func TestIPv6UnfragmentableHeaderErrors(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::31")
	remote := netip.MustParseAddr("2001:db8::32")
	fragmentHeader := IPv6ExtensionHeader{}
	if err := fragmentHeader.SetFragment(0, true, 7); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		headers  []IPv6ExtensionHeader
		wantCode byte
		wantAt   uint32
	}{
		{
			name: "misplaced Hop-by-Hop",
			headers: []IPv6ExtensionHeader{
				{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)},
				{Type: IPv6ExtensionHeaderHopByHop, Data: make([]byte, 7)},
			},
			wantCode: 1, wantAt: 40,
		},
		{
			name: "unsupported option",
			headers: []IPv6ExtensionHeader{
				{Type: IPv6ExtensionHeaderDestination, Data: []byte{0, 0x80, 0, 0, 0, 0, 0}},
			},
			wantCode: 2, wantAt: 42,
		},
		{
			name: "active routing header",
			headers: []IPv6ExtensionHeader{
				{Type: IPv6ExtensionHeaderRouting, Data: []byte{0, 99, 1, 0, 0, 0, 0}},
			},
			wantCode: 0, wantAt: 42,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := append([]IPv6ExtensionHeader(nil), test.headers...)
			headers = append(headers, fragmentHeader)
			packetValue := IPPacket{Source: remote, Destination: local, HopLimit: 64}
			if err := packetValue.SetRawIPv6ExtensionHeaders(headers, 99, nil); err != nil {
				t.Fatal(err)
			}
			packet, err := packetValue.MarshalRawBinary()
			if err != nil {
				t.Fatal(err)
			}
			fragment, ok := parseFragment(packet, false)
			if !ok || !fragment.parameter || fragment.parameterCode != test.wantCode || fragment.parameterAt != test.wantAt {
				t.Fatalf("unfragmentable-header parse = %+v, parsed=%t", fragment, ok)
			}
			link, stack := newTestStack(t, local, remote)
			if err := writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			var response []byte
			select {
			case response = <-link.outbound:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for unfragmentable-header Parameter Problem")
			}
			parsed, ok := parseIPPacket(response, false)
			if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != test.wantCode || binary.BigEndian.Uint32(parsed.payload[4:8]) != test.wantAt {
				t.Fatalf("unfragmentable-header response = %x", response)
			}
		})
	}
}

func TestIPv6FirstFragmentRequiresCompleteHeaderChain(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragment := make([]byte, 16)
	fragment[0] = ProtocolTCP
	binary.BigEndian.PutUint16(fragment[2:4], 1)
	binary.BigEndian.PutUint32(fragment[4:8], 7)
	packet := buildIPPacket(remote, local, 44, fragment, 0, false)
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RFC 7112 Parameter Problem")
	}
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 3 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 0 {
		t.Fatalf("incomplete first-fragment response = %x", response)
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("incomplete first fragment retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestIPv6FirstFragmentHeaderCompleteness(t *testing.T) {
	extension := func(next byte, length byte, tail []byte) []byte {
		header := []byte{next, length, 0, 0, 0, 0, 0, 0}
		return append(header, tail...)
	}
	udp := make([]byte, udpHeaderSize)
	authentication := append(extension(ProtocolUDP, 2, make([]byte, 8)), udp...)
	tcp := make([]byte, tcpHeaderSize)
	tcp[12] = 5 << 4
	invalidTCPSize := append([]byte(nil), tcp...)
	invalidTCPSize[12] = 4 << 4
	dccpOptions := make([]byte, 20)
	dccpOptions[4] = 5
	dccpLongSequence := make([]byte, 16)
	dccpLongSequence[4], dccpLongSequence[8] = 4, 1
	innerIPv4 := make([]byte, 24)
	innerIPv4[0] = 0x46
	for _, test := range []struct {
		name    string
		next    byte
		payload []byte
		want    bool
	}{
		{name: "hop by hop to UDP", next: 0, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "routing to UDP", next: 43, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "destination to UDP", next: 60, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "mobility to UDP", next: 135, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "truncated extension", next: 60, payload: extension(ProtocolUDP, 1, nil)},
		{name: "AH to UDP", next: IPv6ExtensionHeaderAuthentication, payload: authentication, want: true},
		{name: "short AH", next: IPv6ExtensionHeaderAuthentication, payload: extension(ProtocolUDP, 0, udp)},
		{name: "misaligned AH", next: IPv6ExtensionHeaderAuthentication, payload: extension(ProtocolUDP, 1, append(make([]byte, 4), udp...))},
		{name: "truncated AH", next: IPv6ExtensionHeaderAuthentication, payload: []byte{ProtocolUDP}},
		{name: "nested fragment", next: 44, payload: make([]byte, 8)},
		{name: "TCP", next: ProtocolTCP, payload: tcp, want: true},
		{name: "TCP short", next: ProtocolTCP, payload: tcp[:tcpHeaderSize-1]},
		{name: "TCP invalid data offset is complete", next: ProtocolTCP, payload: invalidTCPSize, want: true},
		{name: "UDP", next: ProtocolUDP, payload: udp, want: true},
		{name: "UDP short", next: ProtocolUDP, payload: udp[:udpHeaderSize-1]},
		{name: "IGMP", next: ProtocolIGMP, payload: make([]byte, 8), want: true},
		{name: "IGMP short", next: ProtocolIGMP, payload: make([]byte, 7)},
		{name: "ESP", next: 50, payload: make([]byte, 8), want: true},
		{name: "ESP short", next: 50, payload: make([]byte, 7)},
		{name: "DCCP", next: 33, payload: make([]byte, 12), want: true},
		{name: "DCCP short", next: 33, payload: make([]byte, 11)},
		{name: "DCCP options", next: 33, payload: dccpOptions, want: true},
		{name: "DCCP truncated options", next: 33, payload: dccpOptions[:19]},
		{name: "DCCP long sequence", next: 33, payload: dccpLongSequence, want: true},
		{name: "DCCP truncated long sequence", next: 33, payload: dccpLongSequence[:15]},
		{name: "SCTP", next: 132, payload: make([]byte, 12), want: true},
		{name: "SCTP short", next: 132, payload: make([]byte, 11)},
		{name: "UDP-Lite", next: 136, payload: make([]byte, 8), want: true},
		{name: "UDP-Lite short", next: 136, payload: make([]byte, 7)},
		{name: "nested IPv4", next: 4, payload: innerIPv4, want: true},
		{name: "nested IPv4 options short", next: 4, payload: innerIPv4[:23]},
		{name: "nested IPv6", next: 41, payload: make([]byte, 40), want: true},
		{name: "nested IPv6 short", next: 41, payload: make([]byte, 39)},
		{name: "no next header", next: 59, want: true},
		{name: "unknown raw protocol", next: 99, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if complete := ipv6FirstFragmentHeaderComplete(test.next, test.payload); complete != test.want {
				t.Fatalf("header complete = %t, want %t", complete, test.want)
			}
		})
	}
}

func TestIPv6NonFinalFragmentRequiresEightBytePayload(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::21")
	remote := netip.MustParseAddr("2001:db8::22")
	link, stack := newTestStack(t, local, remote)
	fragment := IPv6ExtensionHeader{}
	if err := fragment.SetFragment(0, true, 9); err != nil {
		t.Fatal(err)
	}
	packetValue := IPPacket{Source: remote, Destination: local, HopLimit: 64}
	if err := packetValue.SetRawIPv6ExtensionHeaders([]IPv6ExtensionHeader{fragment}, 99, make([]byte, 9)); err != nil {
		t.Fatal(err)
	}
	packet, err := packetValue.MarshalRawBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response, false)
		if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 4 {
			t.Fatalf("misaligned IPv6 fragment response = %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPv6 fragment Parameter Problem")
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if sets != 0 {
		t.Fatalf("misaligned IPv6 fragment retained %d sets", sets)
	}
}

func TestIPv4NonFinalFragmentTrimsPartialOffsetUnit(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.87")
	remote := netip.MustParseAddr("198.51.100.87")
	_, stack := newTestStack(t, local, remote)
	firstPayload := append(bytes.Repeat([]byte{0x41}, 8), 0xff)
	first := buildIPPacket(remote, local, ProtocolUDP, firstPayload, 89, false)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:20]))
	second := buildIPPacket(remote, local, ProtocolUDP, bytes.Repeat([]byte{0x42}, 8), 89, false)
	binary.BigEndian.PutUint16(second[6:8], 1)
	second[10], second[11] = 0, 0
	binary.BigEndian.PutUint16(second[10:12], checksum(second[:20]))
	if packet := stack.reassemblePacket(first, time.Now()); packet != nil {
		t.Fatal("trimmed first fragment completed datagram early")
	}
	packet := stack.reassemblePacket(second, time.Now())
	parsed, ok := parseIPPacket(packet, false)
	if !ok || len(parsed.payload) != 16 || !bytes.Equal(parsed.payload[:8], firstPayload[:8]) || !bytes.Equal(parsed.payload[8:], second[20:]) {
		t.Fatalf("Linux-compatible trimmed IPv4 reassembly = %x parsed=%+v ok=%t", packet, parsed, ok)
	}
}

func TestIPv6FragmentReassemblyLengthOverflow(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::85")
	remote := netip.MustParseAddr("2001:db8::86")
	link, stack := newTestStack(t, local, remote)
	header := IPv6ExtensionHeader{}
	if err := header.SetFragment(0, true, 88); err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: remote, Destination: local, HopLimit: 64}
	if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{header}, ProtocolUDP, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	overflow, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(overflow[42:44], 0xfff9)
	fragment, valid := parseFragment(overflow, false)
	if !valid || !fragment.parameter || fragment.parameterAt != 42 {
		t.Fatalf("overflow fragment parse = %+v, valid=%t", fragment, valid)
	}
	if err := writeTestPacket(stack, overflow); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for oversized-fragment Parameter Problem")
	}
	parsed, ok := parseIPPacket(response, false)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 oversized-reassembly response = %x", response)
	}
}

func TestIPv6IncompleteFirstFragmentDiscardsPriorTail(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::11")
	remote := netip.MustParseAddr("2001:db8::12")
	link, stack := newTestStack(t, local, remote)
	fragments := make([][]byte, 3)
	for index := range fragments {
		header := IPv6ExtensionHeader{}
		if err := header.SetFragment(index*8, index != len(fragments)-1, 17); err != nil {
			t.Fatal(err)
		}
		packet := IPPacket{Source: remote, Destination: local, HopLimit: 64}
		if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{header}, ProtocolTCP, make([]byte, 8)); err != nil {
			t.Fatal(err)
		}
		var err error
		fragments[index], err = packet.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := writeTestPacket(stack, fragments[1]); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	retainedBefore := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if retainedBefore != 1 {
		t.Fatalf("retained tails = %d, want 1", retainedBefore)
	}
	if err := writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response, false)
		if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 3 {
			t.Fatalf("incomplete first-fragment response = %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RFC 7112 Parameter Problem")
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("prior fragment tail retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestUDPFragmentationAndReassembly(t *testing.T) {
	for _, test := range []struct {
		name         string
		client, peer netip.Addr
	}{
		{name: "IPv4", client: netip.MustParseAddr("192.0.2.1"), peer: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", client: netip.MustParseAddr("2001:db8::1"), peer: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 128
			if test.client.Is4() {
				bits = 32
			}
			client, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.client, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			peer, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.peer, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err = peer.Start(); err != nil {
				t.Fatal(err)
			}
			bridge := newStackBridge(t, client, peer)
			sender, err := client.ListenUDP(context.Background(), `udp`, wildcardUDP(test.peer))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			receiver, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			receiverPort := receiver.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(test.peer, receiverPort))
			if _, err = sender.WriteTo(payload, destination); err != nil {
				t.Fatal(err)
			}
			if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(payload))
			n, _, err := receiver.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("reassembled UDP payload size = %d", n)
			}
			bridge.mu.Lock()
			fragments := bridge.clientWrites
			bridge.mu.Unlock()
			if fragments < 3 {
				t.Fatalf("fragment writes = %d, want at least 3", fragments)
			}
		})
	}
}

func TestRXChecksumOffloadReassembly(t *testing.T) {
	for _, local := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		t.Run(local.String(), func(t *testing.T) {
			remote := netip.MustParseAddr("192.0.2.2")
			if local.Is6() {
				remote = netip.MustParseAddr("2001:db8::2")
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}, MTU: 1280})
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
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			for index, corrupt := range []bool{true, false} {
				datagram, err := (UDPDatagram{Source: netip.AddrPortFrom(remote, 49000), Destination: netip.AddrPortFrom(local, 49001), Payload: payload}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if corrupt {
					datagram[len(datagram)-1] ^= 1
				}
				packet := IPPacket{Source: remote, Destination: local, Protocol: ProtocolUDP, HopLimit: 64, Payload: datagram}
				if local.Is4() {
					packet.Identification = uint16(index + 1)
				}
				fragments, err := packet.MarshalFragments(1280, uint32(index+1))
				if err != nil || len(fragments) < 2 {
					t.Fatalf("MarshalFragments = %d, %v", len(fragments), err)
				}
				for _, fragment := range fragments {
					if local.Is4() {
						fragment[10] ^= 1
					}
				}
				if n, err := stack.Write(fragments, 0); err != nil || n != len(fragments) {
					t.Fatalf("fragment Write = %d, %v", n, err)
				}
				if corrupt && stack.Stats().InboundDroppedPackets != 1 {
					t.Fatal("corrupt reassembled UDP was not rejected")
				}
			}
			_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, len(payload))
			if n, _, err := receiver.ReadFrom(buffer); err != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
				t.Fatalf("valid reassembled UDP = %d, %v", n, err)
			}
		})
	}
}

func TestFragmentIdentificationSequences(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.41")
	remote4 := netip.MustParseAddr("192.0.2.42")
	stack4, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}, MTU: 68})
	if err != nil {
		t.Fatal(err)
	}
	stack4.ipv4ID.Store(100)
	err = stack4.tryWriteIPSocketPayloadForMTU(local4, remote4, ProtocolUDP, make([]byte, 96), sourceFragmentation{allow: true}, ipPacketOptions{}, stack4.mtuFor(remote4))
	first := takeIPOutputPackets(&stack4.outbound)
	if err != nil || len(first) < 2 {
		t.Fatalf("first IPv4 fragments = %d, %v", len(first), err)
	}
	err = stack4.tryWriteIPSocketPayloadForMTU(local4, remote4, ProtocolUDP, make([]byte, 96), sourceFragmentation{allow: true}, ipPacketOptions{}, stack4.mtuFor(remote4))
	second := takeIPOutputPackets(&stack4.outbound)
	if err != nil || len(second) < 2 {
		t.Fatalf("second IPv4 fragments = %d, %v", len(second), err)
	}
	for index, packet := range first {
		if id := binary.BigEndian.Uint16(packet[4:6]); id != 101 {
			t.Fatalf("first IPv4 fragment %d ID = %d, want 101", index, id)
		}
	}
	for index, packet := range second {
		if id := binary.BigEndian.Uint16(packet[4:6]); id != 102 {
			t.Fatalf("second IPv4 fragment %d ID = %d, want 102", index, id)
		}
	}
	var invalidLayout ipFragmentLayout
	if err = stack4.ipFragmentLayoutForMTU(local4, remote4, 16, sourceFragmentation{allow: true}, ipPacketOptions{}, 27, &invalidLayout); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("invalid IPv4 fragment MTU = %v, want EMSGSIZE", err)
	}
	if got := stack4.ipv4ID.Load(); got != 102 {
		t.Fatalf("invalid IPv4 fragment MTU consumed Identification: %d", got)
	}
	err = stack4.tryWriteIPSocketPayloadForMTU(local4, remote4, ProtocolICMPv4, make([]byte, 8), sourceFragmentation{dontFragment: true}, ipPacketOptions{}, stack4.mtuFor(remote4))
	atomic4 := takeIPOutputPackets(&stack4.outbound)
	if err != nil || len(atomic4) != 1 {
		t.Fatalf("atomic IPv4 packets = %d, %v", len(atomic4), err)
	}
	if id := binary.BigEndian.Uint16(atomic4[0][4:6]); id != 0 || binary.BigEndian.Uint16(atomic4[0][6:8])&0x4000 == 0 {
		t.Fatalf("atomic IPv4 ID/flags = %d/%#x, want 0/DF", id, binary.BigEndian.Uint16(atomic4[0][6:8]))
	}
	if got := stack4.ipv4ID.Load(); got != 102 {
		t.Fatalf("DF IPv4 consumed Identification: %d", got)
	}

	local6 := netip.MustParseAddr("2001:db8::41")
	remote6 := netip.MustParseAddr("2001:db8::42")
	stack6, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local6, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	stack6.ipv6FragmentID.Store(1000)
	if err = stack6.tryWriteIPSocketPayloadForMTU(local6, remote6, ProtocolUDP, make([]byte, 8), sourceFragmentation{allow: true}, ipPacketOptions{}, stack6.mtuFor(remote6)); err != nil {
		t.Fatal(err)
	}
	takeIPOutputPackets(&stack6.outbound)
	if got := stack6.ipv6FragmentID.Load(); got != 1000 {
		t.Fatalf("unfragmented IPv6 consumed Fragment ID: %d", got)
	}
	err = stack6.tryWriteIPSocketPayloadForMTU(local6, remote6, ProtocolUDP, make([]byte, 1300), sourceFragmentation{allow: true}, ipPacketOptions{}, stack6.mtuFor(remote6))
	fragments6 := takeIPOutputPackets(&stack6.outbound)
	if err != nil || len(fragments6) < 2 {
		t.Fatalf("IPv6 fragments = %d, %v", len(fragments6), err)
	}
	for index, packet := range fragments6 {
		if id := binary.BigEndian.Uint32(packet[44:48]); id != 1001 {
			t.Fatalf("IPv6 fragment %d ID = %d, want 1001", index, id)
		}
	}
	if err = stack6.ipFragmentLayoutForMTU(local6, remote6, 16, sourceFragmentation{allow: true}, ipPacketOptions{}, 55, &invalidLayout); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("invalid IPv6 fragment MTU = %v, want EMSGSIZE", err)
	}
	if got := stack6.ipv6FragmentID.Load(); got != 1001 {
		t.Fatalf("invalid IPv6 fragment MTU consumed Identification: %d", got)
	}
}

func TestIPFragmentLayoutRejectsInvalidBounds(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.63")
	remote4 := netip.MustParseAddr("198.51.100.63")
	remote6 := netip.MustParseAddr("2001:db8:1::63")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	stack.ipv4ID.Store(100)
	stack.ipv6FragmentID.Store(1000)
	for _, test := range []struct {
		name           string
		source, target netip.Addr
		payloadSize    int
		mtu            int
	}{
		{name: "mixed address family", source: local4, target: remote6, payloadSize: 64, mtu: 68},
		{name: "fitting payload", source: local4, target: remote4, payloadSize: 64, mtu: 1500},
		{name: "IPv4 payload overflow", source: local4, target: remote4, payloadSize: 65516, mtu: 1280},
		{name: "IPv6 payload overflow", source: remote6, target: netip.MustParseAddr("2001:db8:2::63"), payloadSize: 65536, mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			var layout ipFragmentLayout
			if err := stack.ipFragmentLayoutForMTU(test.source, test.target, test.payloadSize, sourceFragmentation{allow: true}, ipPacketOptions{}, test.mtu, &layout); !errors.Is(err, syscall.EMSGSIZE) {
				t.Fatalf("layout error = %v, want EMSGSIZE", err)
			}
		})
	}
	if got := stack.ipv4ID.Load(); got != 100 {
		t.Fatalf("invalid layouts consumed IPv4 Identification: %d", got)
	}
	if got := stack.ipv6FragmentID.Load(); got != 1000 {
		t.Fatalf("invalid layouts consumed IPv6 Identification: %d", got)
	}
	var layout ipFragmentLayout
	if err = stack.ipFragmentLayoutForMTU(local4, remote4, 64, sourceFragmentation{allow: true}, ipPacketOptions{}, 68, &layout); err != nil {
		t.Fatal(err)
	}
	if packets := buildIPFragmentPackets(local4, remote4, ProtocolUDP, make([]byte, 63), layout); len(packets) != 0 {
		t.Fatalf("mismatched payload produced %d packets", len(packets))
	}
}

func TestDirectIPv6FragmentOutputOverwritesReusableHeader(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::43")
	remote := netip.MustParseAddr("2001:db8:1::43")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	dirty := bytes.Repeat([]byte{0xff}, 1280)
	stack.outbound.buffers <- dirty[:0]
	datagram, err := (UDPDatagram{Source: netip.AddrPortFrom(local, 1000), Destination: netip.AddrPortFrom(remote, 1001),
		Payload: make([]byte, 1300-udpHeaderSize)}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.writeIPPayload(local, remote, ProtocolUDP, datagram, true); err != nil {
		t.Fatal(err)
	}
	entry, ok := stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("missing first IPv6 fragment")
	}
	if len(entry.packet) != 1280 || entry.packet[40] != ProtocolUDP || entry.packet[41] != 0 {
		t.Fatalf("reused IPv6 fragment header = %x", entry.packet[40:48])
	}
	stack.outbound.release(entry)
	entry, ok = stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("missing second IPv6 fragment")
	}
	stack.outbound.release(entry)
}

func TestIPFragmentMaterializedAndQueuedOutputMatch(t *testing.T) {
	tests := []struct {
		name             string
		source, target   netip.Addr
		payloadSize, mtu int
		fragmentation    sourceFragmentation
		options          ipPacketOptions
	}{
		{
			name: "IPv4/fragmented", source: netip.MustParseAddr("192.0.2.62"), target: netip.MustParseAddr("198.51.100.62"),
			payloadSize: 97, mtu: 68, fragmentation: sourceFragmentation{allow: true, dontFragment: true},
			options: ipPacketOptions{hopLimit: 42, hopLimitSet: true, trafficClass: 0xb8, trafficClassSet: true},
		},
		{
			name: "IPv6/fragmented", source: netip.MustParseAddr("2001:db8::62"), target: netip.MustParseAddr("2001:db8:1::62"),
			payloadSize: 2001, mtu: 1280, fragmentation: sourceFragmentation{allow: true},
			options: ipPacketOptions{hopLimit: 44, hopLimitSet: true, trafficClass: 0x2e, trafficClassSet: true, flowLabel: 0x54321, flowLabelSet: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.source, test.source.BitLen())}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			payload := make([]byte, test.payloadSize)
			for index := range payload {
				payload[index] = byte(index*37 + 11)
			}
			stack.ipv4ID.Store(100)
			stack.ipv6FragmentID.Store(1000)
			if err = stack.tryWriteIPSocketPayloadForMTU(test.source, test.target, 253, payload, test.fragmentation, test.options, test.mtu); err != nil {
				t.Fatal(err)
			}
			queued := takeIPOutputPackets(&stack.outbound)
			if len(queued) < 2 {
				t.Fatalf("queued fragment count = %d, want at least 2", len(queued))
			}
			stack.ipv4ID.Store(100)
			stack.ipv6FragmentID.Store(1000)
			var layout ipFragmentLayout
			if err = stack.ipFragmentLayoutForMTU(test.source, test.target, len(payload), test.fragmentation, test.options, test.mtu, &layout); err != nil {
				t.Fatal(err)
			}
			materialized := buildIPFragmentPackets(test.source, test.target, 253, payload, layout)
			if len(materialized) != len(queued) {
				t.Fatalf("materialized fragment count = %d, want %d", len(materialized), len(queued))
			}
			for index := range queued {
				if !bytes.Equal(materialized[index], queued[index]) {
					t.Fatalf("fragment %d differs:\nmaterialized %x\nqueued %x", index, materialized[index], queued[index])
				}
			}
		})
	}
}

func TestDirectFragmentOutputReclaimsPublishedBacklog(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.44")
	remote := netip.MustParseAddr("198.51.100.44")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 68})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	dummy := buildIPPacket(local, remote, 99, []byte{1}, 0, true)
	for index := 0; index < cap(stack.outbound.free)-1; index++ {
		if !stack.outbound.tryEnqueue(dummy) {
			t.Fatalf("dummy packet %d was not queued", index)
		}
	}
	stack.ipv4ID.Store(100)
	payload := make([]byte, 96)
	err = stack.tryWriteIPSocketPayloadForMTU(local, remote, ProtocolUDP, payload, sourceFragmentation{allow: true}, ipPacketOptions{}, 68)
	if err != nil {
		t.Fatalf("fragmented write over published backlog: %v", err)
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
		if parseErr == nil && packet.Protocol == ProtocolUDP {
			if identification := binary.BigEndian.Uint16(entry.packet[4:6]); identification != 101 {
				t.Fatalf("fragment ID = %d, want 101", identification)
			}
			var addErr error
			reassembled, complete, addErr = reassembly.Add(packet)
			if addErr != nil {
				t.Fatal(addErr)
			}
		}
		stack.outbound.release(entry)
	}
	if !complete || reassembled.Protocol != ProtocolUDP || !bytes.Equal(reassembled.Payload, payload) {
		t.Fatalf("reassembled direct fragment output = complete %t protocol %d payload %x", complete, reassembled.Protocol, reassembled.Payload)
	}
	if stats := stack.Stats(); stats.OutboundPackets < 2 || stats.OutboundQueueDrops+1 != stats.OutboundPackets {
		t.Fatalf("direct fragment output stack statistics = %+v", stats)
	}
}

func TestDirectFragmentedLoopbackOutputUsesAllOrNoneAdmission(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.45")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 68})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	first := bytes.Repeat([]byte{0x31}, 8)
	second := bytes.Repeat([]byte{0x32}, 88)
	var layout ipFragmentLayout
	if err = stack.ipFragmentLayoutForMTU(local, local, len(first)+len(second), sourceFragmentation{allow: true}, ipPacketOptions{}, 68, &layout); err != nil {
		t.Fatal(err)
	}
	dummy := buildIPPacket(local, local, 98, []byte{0}, 1, false)
	for stack.loopback.len() < loopbackPacketQueue-1 {
		if !stack.loopback.tryEnqueue(dummy) {
			t.Fatal("loopback queue filled before the expected boundary")
		}
	}
	before := stack.loopback.len()
	if err = stack.tryWriteIPFragmentsLayout(local, local, 99, first, second, layout, false); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("fragmented loopback write = %v, want ErrResourceLimit", err)
	}
	if after := stack.loopback.len(); after != before {
		t.Fatalf("failed loopback fragment set changed queue depth from %d to %d", before, after)
	}
	payload := append(append([]byte(nil), first...), second...)
	if got, want := stack.Stats().LoopbackQueueDrops, uint64(len(buildIPFragmentPackets(local, local, 99, payload, layout))); got != want {
		t.Fatalf("failed loopback fragment drops = %d, want %d", got, want)
	}
}

func TestMinimumSizeFragmentsReassembleRequiredPacket(t *testing.T) {
	for _, test := range []struct {
		name           string
		local, remote  netip.Addr
		payloadSize    int
		fragmentPacket int
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.45"), remote: netip.MustParseAddr("198.51.100.45"), payloadSize: 1480, fragmentPacket: 28},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::45"), remote: netip.MustParseAddr("2001:db8:1::45"), payloadSize: 1460, fragmentPacket: 56},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, test.payloadSize)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, test.fragmentPacket, 45)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, test.fragmentPacket, 45, ipPacketOptions{})
			}
			if len(fragments) <= 128 || len(fragments) > fragmentMaximumPieces {
				t.Fatalf("fragment count = %d, want 129..%d", len(fragments), fragmentMaximumPieces)
			}
			var packet []byte
			for _, fragment := range fragments {
				packet = stack.reassemblePacket(fragment, time.Now())
			}
			parsed, ok := parseIPPacket(packet, false)
			if !ok || len(packet) != 1500 || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("minimum-fragment reassembly = packet %d payload %d parsed %v", len(packet), len(parsed.payload), ok)
			}
		})
	}
}

func TestFragmentOverlapDropsDatagram(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	payload := bytes.Repeat([]byte{0x44}, 3000)
	fragments := buildIPv4Fragments(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), ProtocolUDP, payload, 1280, 7)
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	if err := writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	overlap := append([]byte(nil), fragments[1]...)
	binary.BigEndian.PutUint16(overlap[6:8], 1|0x2000)
	overlap[10], overlap[11] = 0, 0
	binary.BigEndian.PutUint16(overlap[10:12], checksum(overlap[:20]))
	if err := writeTestPacket(stack, overlap); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("overlapping fragments retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestDuplicateFragmentPreservesReassembly(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.71"), remote: netip.MustParseAddr("192.0.2.72")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::71"), remote: netip.MustParseAddr("2001:db8::72")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stack := newTestStack(t, test.local, test.remote)
			payload := bytes.Repeat([]byte{0x71}, 3000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 71)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 71, ipPacketOptions{})
			}
			if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
				t.Fatal("first fragment completed a datagram")
			}
			if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
				t.Fatal("duplicate fragment completed a datagram")
			}
			var packet []byte
			for _, fragment := range fragments[1:] {
				packet = stack.reassemblePacket(fragment, time.Now())
			}
			parsed, ok := parseIPPacket(packet, false)
			if !ok || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("duplicate-preserving reassembly = parsed %v payload %d", ok, len(parsed.payload))
			}
		})
	}
}

func TestFragmentReassemblySeparatesLoopbackAndDeviceInput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.70")
	remote := netip.MustParseAddr("192.0.2.71")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	first := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 32), 36, 0x7071)[0]
	if packet, pending := stack.reassemblePacketStatus(first, time.Now(), false); packet != nil || !pending {
		t.Fatalf("device fragment = packet %v pending %v", packet != nil, pending)
	}
	if packet, pending := stack.reassemblePacketStatus(first, time.Now(), true); packet != nil || !pending {
		t.Fatalf("loopback fragment = packet %v pending %v", packet != nil, pending)
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	_, device := stack.fragments[fragmentKey{source: remote, target: local, identification: 0x7071, protocol: ProtocolUDP}]
	_, loopback := stack.fragments[fragmentKey{source: remote, target: local, identification: 0x7071, protocol: ProtocolUDP, loopback: true}]
	stack.fragmentMu.Unlock()
	if sets != 2 || !device || !loopback {
		t.Fatalf("fragment ingress domains = sets %d device %t loopback %t", sets, device, loopback)
	}
}

func TestDuplicateFragmentAtPieceLimitPreservesQueue(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.73"), netip.MustParseAddr("192.0.2.74"))
	key := fragmentKey{
		source: netip.MustParseAddr("192.0.2.74"), target: netip.MustParseAddr("192.0.2.73"),
		identification: 73, protocol: ProtocolUDP,
	}
	pieces := make([]fragmentPiece, fragmentMaximumPieces)
	for index := range pieces {
		pieces[index] = fragmentPiece{offset: index * 8, data: make([]byte, 8)}
	}
	stack.fragmentMu.Lock()
	stack.fragments[key] = &ipPacketReassemblyEntry{
		state: ipPacketReassemblyState{
			pieces: pieces, total: -1, bytes: fragmentMaximumPieces * 8,
			protocol: ProtocolUDP, source: key.source, target: key.target, identifier: key.identification,
			ecnMask: 1, maximum: fragmentMaximumDatagram - 20,
		},
		created: time.Now(), updated: time.Now(), accountedBytes: fragmentMaximumPieces * 8,
	}
	stack.fragmentBytes = fragmentMaximumPieces * 8
	stack.fragmentMu.Unlock()
	duplicate := buildIPv4Fragments(key.source, key.target, key.protocol, make([]byte, 16), 28, uint16(key.identification))[0]
	if packet, pending := stack.reassemblePacketStatus(duplicate, time.Now(), false); packet != nil || !pending {
		t.Fatalf("duplicate at piece limit = packet %v pending %v", packet != nil, pending)
	}
	stack.fragmentMu.Lock()
	retained := stack.fragments[key] != nil
	stack.fragmentMu.Unlock()
	if !retained {
		t.Fatal("duplicate fragment removed a full metadata queue")
	}
}

func TestIPv6FragmentUsesFirstNextHeader(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	payload := make([]byte, 24)
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 56, 7, ipPacketOptions{})
	if len(fragments) != 3 {
		t.Fatalf("fragment count = %d, want 3", len(fragments))
	}
	fragments[2][40] = ProtocolTCP
	if packet := stack.reassemblePacket(fragments[2], time.Now()); packet != nil {
		t.Fatal("final fragment completed a datagram")
	}
	if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
		t.Fatal("first fragment completed an incomplete datagram")
	}
	packet := stack.reassemblePacket(fragments[1], time.Now())
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
		t.Fatalf("reassembled packet uses wrong first-fragment metadata: protocol=%d payload=%x", parsed.protocol, parsed.payload)
	}
}

func TestIPv4ReassemblyPreservesHeaderOptions(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.81")
	remote := netip.MustParseAddr("192.0.2.82")
	_, stack := newTestStack(t, local, remote)
	fragments := buildIPv4Fragments(remote, local, 99, bytes.Repeat([]byte{0x5a}, 16), 28, 42)
	first := make([]byte, len(fragments[0])+4)
	copy(first[:20], fragments[0][:20])
	copy(first[20:24], []byte{1, 0, 0, 0})
	copy(first[24:], fragments[0][20:])
	first[0] = 0x46
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:24]))
	if packet := stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("tail fragment completed IPv4 datagram")
	}
	packet := stack.reassemblePacket(first, time.Now())
	if len(packet) != 40 || packet[0]&0x0f != 6 || !bytes.Equal(packet[20:24], []byte{1, 0, 0, 0}) || checksum(packet[:24]) != 0 {
		t.Fatalf("option-preserving IPv4 reassembly = %x", packet)
	}
}

func TestIPv6ReassemblyPreservesUnfragmentableHeaders(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::81")
	remote := netip.MustParseAddr("2001:db8::82")
	_, stack := newTestStack(t, local, remote)
	payload := bytes.Repeat([]byte{0x6b}, 16)
	fragments := make([][]byte, 2)
	for index := range fragments {
		fragmentPayload := make([]byte, 24)
		fragmentPayload[0] = 44
		fragmentPayload[8] = 99
		field := uint16(index * 8)
		if index == 0 {
			field |= 1
		}
		binary.BigEndian.PutUint16(fragmentPayload[10:12], field)
		binary.BigEndian.PutUint32(fragmentPayload[12:16], 77)
		copy(fragmentPayload[16:], payload[index*8:(index+1)*8])
		fragments[index] = buildIPPacket(remote, local, 0, fragmentPayload, 0, false)
	}
	if packet := stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("tail fragment completed IPv6 datagram")
	}
	packet := stack.reassemblePacket(fragments[0], time.Now())
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != 99 || !bytes.Equal(parsed.payload, payload) || len(packet) != 64 || packet[6] != 0 || packet[40] != 99 {
		t.Fatalf("extension-preserving IPv6 reassembly = %x parsed=%+v ok=%v", packet, parsed, ok)
	}
}

func TestFragmentFinalLengthRejectsPriorTail(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::11")
	remote := netip.MustParseAddr("2001:db8::12")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, make([]byte, 24), 56, 8, ipPacketOptions{})
	if len(fragments) != 3 {
		t.Fatalf("fragment count = %d, want 3", len(fragments))
	}
	high := append([]byte(nil), fragments[2]...)
	field := binary.BigEndian.Uint16(high[42:44]) | 1
	binary.BigEndian.PutUint16(high[42:44], field)
	if packet := stack.reassemblePacket(high, time.Now()); packet != nil {
		t.Fatal("high non-final fragment completed a datagram")
	}
	shortFinal := append([]byte(nil), fragments[1]...)
	field = binary.BigEndian.Uint16(shortFinal[42:44]) &^ 1
	binary.BigEndian.PutUint16(shortFinal[42:44], field)
	if packet := stack.reassemblePacket(shortFinal, time.Now()); packet != nil {
		t.Fatal("short final fragment completed a datagram")
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("invalid final length retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestFragmentSetCapacityEvictsOldest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.31")
	remote := netip.MustParseAddr("198.51.100.31")
	_, stack := newTestStack(t, local, remote)
	now := time.Now()
	for identifier := 1; identifier <= fragmentMaximumSets+1; identifier++ {
		fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 2000), 1280, uint16(identifier))
		if len(fragments) < 2 {
			t.Fatal("test payload was not fragmented")
		}
		if packet := stack.reassemblePacket(fragments[0], now.Add(time.Duration(identifier)*time.Millisecond)); packet != nil {
			t.Fatal("incomplete fragment produced a packet")
		}
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	_, oldestPresent := stack.fragments[fragmentKey{source: remote, target: local, identification: 1, protocol: ProtocolUDP}]
	stack.fragmentMu.Unlock()
	if sets != fragmentMaximumSets || oldestPresent {
		t.Fatalf("fragment sets = %d, oldest present = %v", sets, oldestPresent)
	}
	if evictions := stack.Stats().FragmentEvictions; evictions != 1 {
		t.Fatalf("fragment evictions = %d, want 1", evictions)
	}
}

func TestFragmentByteCapacityEvictsOldest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.84")
	remote := netip.MustParseAddr("198.51.100.84")
	_, stack := newTestStack(t, local, remote)
	now := time.Now()
	oldKey := fragmentKey{source: remote, target: local, identification: 1, protocol: ProtocolUDP}
	oldEntry := &ipPacketReassemblyEntry{
		state: ipPacketReassemblyState{
			total: -1, bytes: fragmentMaximumBytes - 1,
			source: remote, target: local, identifier: 1, maximum: fragmentMaximumDatagram - 20,
		},
		created: now, updated: now.Add(-time.Second), accountedBytes: fragmentMaximumBytes - 1,
	}
	stack.fragmentMu.Lock()
	stack.fragments[oldKey] = oldEntry
	stack.fragmentBytes = oldEntry.state.bytes
	stack.fragmentMu.Unlock()
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 16), 28, 2)
	if packet := stack.reassemblePacket(fragments[0], now); packet != nil {
		t.Fatal("incomplete replacement fragment unexpectedly reassembled")
	}
	newKey := fragmentKey{source: remote, target: local, identification: 2, protocol: ProtocolUDP}
	stack.fragmentMu.Lock()
	_, oldPresent := stack.fragments[oldKey]
	newEntry := stack.fragments[newKey]
	retained := stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if oldPresent || newEntry == nil {
		t.Fatalf("byte-pressure sets: old present=%t new present=%t", oldPresent, newEntry != nil)
	}
	if retained != len(fragments[0]) {
		t.Fatalf("retained bytes after byte-pressure eviction = %d, want %d", retained, len(fragments[0]))
	}
	if stack.Stats().FragmentEvictions == 0 {
		t.Fatal("byte-pressure eviction was not counted")
	}
}

func TestFragmentArrivalDoesNotExtendLifetime(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("198.51.100.41")
	_, stack := newTestStack(t, local, remote)
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 3000), 1280, 81)
	if len(fragments) < 3 {
		t.Fatal("test payload did not produce three fragments")
	}
	start := time.Now()
	if packet := stack.reassemblePacket(fragments[0], start); packet != nil {
		t.Fatal("first fragment completed a datagram")
	}
	if packet := stack.reassemblePacket(fragments[1], start.Add(fragmentIPv4Lifetime-time.Second)); packet != nil {
		t.Fatal("second fragment completed a datagram")
	}
	stack.fragmentMu.Lock()
	_ = stack.cleanFragmentsLocked(start.Add(fragmentIPv4Lifetime + time.Second))
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("late fragments extended lifetime: sets=%d bytes=%d", sets, retained)
	}
}

func TestFragmentTimesDoNotFollowLockAcquisitionOrder(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 24), 28, 97)
	if len(fragments) < 3 {
		t.Fatalf("fragment count = %d, want at least 3", len(fragments))
	}
	base := time.Unix(100, 0)
	if packet, pending := stack.reassemblePacketStatus(fragments[1], base.Add(time.Second), false); packet != nil || !pending {
		t.Fatalf("later fragment = packet %x pending %t", packet, pending)
	}
	if packet, pending := stack.reassemblePacketStatus(fragments[2], base, false); packet != nil || !pending {
		t.Fatalf("earlier fragment = packet %x pending %t", packet, pending)
	}
	parsed, ok := parseFragment(fragments[1], false)
	if !ok {
		t.Fatal("test fragment did not parse")
	}
	stack.fragmentMu.Lock()
	entry := stack.fragments[parsed.reassemblyKey(false)]
	stack.fragmentMu.Unlock()
	if entry == nil {
		t.Fatal("incomplete fragment set was not retained")
	}
	if entry.created != base {
		t.Fatalf("fragment creation time = %v, want %v", entry.created, base)
	}
	if entry.updated != base.Add(time.Second) {
		t.Fatalf("fragment update time = %v, want %v", entry.updated, base.Add(time.Second))
	}
}

func TestNextFragmentExpiryUsesFirstArrivalAndAddressFamily(t *testing.T) {
	start := time.Unix(100, 0)
	stack := &Stack{fragments: map[fragmentKey]*ipPacketReassemblyEntry{
		{identification: 1}:           {created: start.Add(time.Second)},
		{identification: 2, v6: true}: {state: ipPacketReassemblyState{v6: true}, created: start.Add(-20 * time.Second)},
	}}
	stack.fragmentMu.Lock()
	next, ok := stack.nextFragmentExpiryLocked()
	stack.fragmentMu.Unlock()
	if !ok || next != start.Add(31*time.Second) {
		t.Fatalf("next fragment expiry = %v, %v; want %v, true", next, ok, start.Add(31*time.Second))
	}
}

func TestFragmentReassemblyTimeoutResponse(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		protocol      byte
		messageType   byte
		lifetime      time.Duration
		offload       bool
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.43"), remote: netip.MustParseAddr("198.51.100.43"), protocol: ProtocolICMPv4, messageType: 11, lifetime: fragmentIPv4Lifetime},
		{name: "IPv4-offload", local: netip.MustParseAddr("192.0.2.43"), remote: netip.MustParseAddr("198.51.100.43"), protocol: ProtocolICMPv4, messageType: 11, lifetime: fragmentIPv4Lifetime, offload: true},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::43"), remote: netip.MustParseAddr("2001:db8:1::43"), protocol: ProtocolICMPv6, messageType: 3, lifetime: fragmentIPv6Lifetime},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, 2000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 42)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 42, ipPacketOptions{})
			}
			if test.offload {
				var offload RXChecksumOffload
				offload.SetIPv4Header(true)
				stack.SetRXChecksumOffload(offload)
				fragments[0][10] ^= 1
			}
			start := time.Now()
			if err := writeTestPacket(stack, fragments[0]); err != nil {
				t.Fatal(err)
			}
			stack.expireFragments(start.Add(test.lifetime + time.Second))
			select {
			case response := <-link.outbound:
				parsed, err := ParseIPPacket(response)
				if err != nil || parsed.Protocol != int(test.protocol) {
					t.Fatalf("fragment timeout response = %x, %v", response, err)
				}
				message, err := parsed.ICMPMessage()
				if err != nil || message.Type != test.messageType || message.Code != 1 {
					t.Fatalf("fragment timeout response = %x", response)
				}
				if test.local.Is6() && len(response) > ipv6MinimumMTU {
					t.Fatalf("IPv6 timeout response size = %d, want <= %d", len(response), ipv6MinimumMTU)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for fragment reassembly error")
			}
			if timeouts := stack.Stats().FragmentTimeouts; timeouts != 1 {
				t.Fatalf("fragment timeouts = %d, want 1", timeouts)
			}
		})
	}
}

func TestFragmentReassemblyTimeoutSuppressesICMPError(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		protocol      byte
		messageType   byte
		lifetime      time.Duration
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.44"), remote: netip.MustParseAddr("198.51.100.44"), protocol: ProtocolICMPv4, messageType: 3, lifetime: fragmentIPv4Lifetime},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::44"), remote: netip.MustParseAddr("2001:db8:1::44"), protocol: ProtocolICMPv6, messageType: 1, lifetime: fragmentIPv6Lifetime},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, 2000)
			payload[0] = test.messageType
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, test.protocol, payload, 1280, 43)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, test.protocol, payload, 1280, 43, ipPacketOptions{})
			}
			start := time.Now()
			_ = stack.reassemblePacket(fragments[0], start)
			stack.expireFragments(start.Add(test.lifetime + time.Second))
			select {
			case response := <-link.outbound:
				t.Fatalf("ICMP error fragment produced timeout response: %x", response)
			case <-time.After(25 * time.Millisecond):
			}
		})
	}
}

func FuzzFragmentParsing(f *testing.F) {
	local := netip.MustParseAddr("192.0.2.32")
	remote := netip.MustParseAddr("198.51.100.32")
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 2000), 1280, 1)
	local6 := netip.MustParseAddr("2001:db8::32")
	remote6 := netip.MustParseAddr("2001:db8:1::32")
	fragments6 := buildIPv6FragmentsWithOptions(remote6, local6, ProtocolUDP, make([]byte, 2000), 1280, 1, ipPacketOptions{})
	f.Add([]byte(nil))
	f.Add(fragments[0])
	f.Add(fragments6[0])
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65575 {
			packet = packet[:65575]
		}
		before := append([]byte(nil), packet...)
		fragment, ok := parseFragment(packet, false)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseFragment modified its input")
		}
		if !ok {
			return
		}
		if len(fragment.original) == 0 || len(fragment.original) > len(packet) || !bytes.Equal(fragment.original, packet[:len(fragment.original)]) {
			t.Fatalf("fragment original length %d is not an input prefix of %d bytes", len(fragment.original), len(packet))
		}
		if !fragment.source.IsValid() || !fragment.target.IsValid() || fragment.source.Is4() != fragment.target.Is4() {
			t.Fatalf("fragment address families are invalid: %v -> %v", fragment.source, fragment.target)
		}
		if fragment.parameter {
			if fragment.parameterAt >= uint32(len(fragment.original)) {
				t.Fatalf("fragment parameter pointer %d is outside %d-byte packet", fragment.parameterAt, len(fragment.original))
			}
			return
		}
		if fragment.offset < 0 || fragment.offset&7 != 0 || fragment.maximum < 0 || len(fragment.payload) > fragment.maximum {
			t.Fatalf("invalid fragment bounds: offset %d payload %d maximum %d", fragment.offset, len(fragment.payload), fragment.maximum)
		}
		if len(fragment.header) == 0 || len(fragment.header) > len(fragment.original) || !bytes.Equal(fragment.header, fragment.original[:len(fragment.header)]) {
			t.Fatalf("fragment header length %d is not an original-packet prefix", len(fragment.header))
		}
		if fragment.nextHeader < 0 || fragment.nextHeader >= len(fragment.header) {
			t.Fatalf("next-header offset %d is outside %d-byte header", fragment.nextHeader, len(fragment.header))
		}
		if len(fragment.payload) > len(fragment.original) || !bytes.Equal(fragment.payload, fragment.original[len(fragment.original)-len(fragment.payload):]) {
			t.Fatalf("fragment payload length %d is not an original-packet suffix", len(fragment.payload))
		}
	})
}

func checkFragmentFuzzResources(t testing.TB, stack *Stack) {
	t.Helper()
	stack.fragmentMu.Lock()
	defer stack.fragmentMu.Unlock()
	if len(stack.fragments) > fragmentMaximumSets || stack.fragmentBytes < 0 || stack.fragmentBytes > fragmentMaximumBytes {
		t.Fatalf("fragment resources = %d sets, %d bytes", len(stack.fragments), stack.fragmentBytes)
	}
	retainedBytes := 0
	for _, entry := range stack.fragments {
		if len(entry.state.pieces) > fragmentMaximumPieces || entry.state.bytes < 0 {
			t.Fatalf("fragment set resources = %d pieces, %d bytes", len(entry.state.pieces), entry.state.bytes)
		}
		payloadBytes := 0
		previousEnd := 0
		for index, piece := range entry.state.pieces {
			if len(piece.data) == 0 || piece.offset < 0 || index != 0 && piece.offset < previousEnd {
				t.Fatalf("invalid retained fragment piece at %d: offset %d length %d after %d", index, piece.offset, len(piece.data), previousEnd)
			}
			previousEnd = piece.offset + len(piece.data)
			payloadBytes += len(piece.data)
		}
		if payloadBytes > entry.state.bytes {
			t.Fatalf("fragment set retained %d payload bytes but accounts for %d", payloadBytes, entry.state.bytes)
		}
		retainedBytes += entry.state.bytes
	}
	if retainedBytes != stack.fragmentBytes {
		t.Fatalf("fragment byte accounting = %d, want %d", stack.fragmentBytes, retainedBytes)
	}
}

func FuzzFragmentReassemblyOrder(f *testing.F) {
	f.Add([]byte{0, 1, 2}, false)
	f.Add([]byte{2, 1, 0}, false)
	f.Add([]byte{0, 0, 2, 1}, true)
	f.Fuzz(func(t *testing.T, order []byte, ipv6 bool) {
		if len(order) > 64 {
			order = order[:64]
		}
		local := netip.MustParseAddr("192.0.2.33")
		remote := netip.MustParseAddr("198.51.100.33")
		bits := 32
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::33")
			remote = netip.MustParseAddr("2001:db8:1::33")
			bits = 128
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		payload := make([]byte, 3000)
		for index := range payload {
			payload[index] = byte(index*31 + 7)
		}
		var fragments [][]byte
		if ipv6 {
			fragments = buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 1280, 77, ipPacketOptions{})
		} else {
			fragments = buildIPv4Fragments(remote, local, ProtocolUDP, payload, 1280, 77)
		}
		now := time.Unix(100, 0)
		for _, selected := range order {
			packet := stack.reassemblePacket(fragments[int(selected)%len(fragments)], now)
			checkFragmentFuzzResources(t, stack)
			if packet == nil {
				continue
			}
			parsed, ok := parseIPPacket(packet, false)
			if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("reassembled fuzz datagram = protocol %d payload %d parsed %t", parsed.protocol, len(parsed.payload), ok)
			}
		}
	})
}

func FuzzFragmentReassemblyOverlap(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 1, 1, 1, 1}, false)
	f.Add([]byte{1, 0, 1, 7, 0, 1, 1, 9}, true)
	f.Add([]byte{
		0, 0, 1, 0,
		1, 1, 1, 0,
		2, 2, 1, 0,
		3, 3, 1, 0,
		4, 4, 1, 0,
		5, 5, 1, 0,
		0, 6, 0, 0,
	}, false)
	f.Fuzz(func(t *testing.T, events []byte, ipv6 bool) {
		if len(events) > 160 {
			events = events[:160]
		}
		local := netip.MustParseAddr("192.0.2.34")
		remote := netip.MustParseAddr("198.51.100.34")
		bits := 32
		payload := make([]byte, 48)
		for index := range payload {
			payload[index] = byte(index*17 + 5)
		}
		var fragments [][]byte
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::34")
			remote = netip.MustParseAddr("2001:db8:1::34")
			bits = 128
			fragments = buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 56, 78, ipPacketOptions{})
		} else {
			fragments = buildIPv4Fragments(remote, local, ProtocolUDP, payload, 28, 78)
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		now := time.Unix(200, 0)
		maximumEnd := 0
		for offset := 0; offset+4 <= len(events); offset += 4 {
			packet := append([]byte(nil), fragments[int(events[offset])%len(fragments)]...)
			fragment, ok := parseFragment(packet, false)
			if !ok || len(fragment.payload) == 0 {
				t.Fatal("generated base fragment is not parseable")
			}
			payloadOffset := len(fragment.original) - len(fragment.payload)
			packet[payloadOffset] ^= events[offset+3]
			fragmentOffset := int(events[offset+1]&7) * 8
			if end := fragmentOffset + len(fragment.payload); end > maximumEnd {
				maximumEnd = end
			}
			more := events[offset+2]&1 != 0
			if events[offset+2]&2 != 0 {
				more = false
			}
			if ipv6 {
				field := uint16(fragmentOffset &^ 7)
				if more {
					field |= 1
				}
				binary.BigEndian.PutUint16(packet[42:44], field)
			} else {
				field := uint16(fragmentOffset / 8)
				if more {
					field |= 0x2000
				}
				binary.BigEndian.PutUint16(packet[6:8], field)
				packet[10], packet[11] = 0, 0
				binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
			}
			reassembled := stack.reassemblePacket(packet, now)
			checkFragmentFuzzResources(t, stack)
			if reassembled == nil {
				continue
			}
			parsed, valid := parseIPPacket(reassembled, false)
			if !valid || parsed.protocol != ProtocolUDP || len(parsed.payload) > maximumEnd {
				t.Fatalf("overlap reassembly produced invalid packet: parsed=%t protocol=%d payload=%d", valid, parsed.protocol, len(parsed.payload))
			}
		}
	})
}

func FuzzIPPayloadFragmentationRoundTrip(f *testing.F) {
	f.Add([]byte("short"), false, uint16(1500), byte(ProtocolUDP), byte(64), byte(0), uint32(0), false)
	f.Add(make([]byte, 1500), false, uint16(68), byte(ProtocolTCP), byte(1), byte(0xff), uint32(0), true)
	f.Add(make([]byte, 3000), true, uint16(1280), byte(99), byte(255), byte(0x2e), uint32(0xabcde), true)
	f.Fuzz(func(t *testing.T, payload []byte, ipv6 bool, mtuSeed uint16, protocol, hopLimit, trafficClass byte, flowLabel uint32, reverse bool) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		original := append([]byte(nil), payload...)
		source := netip.MustParseAddr("198.51.100.35")
		target := netip.MustParseAddr("192.0.2.35")
		mtu := 68 + int(mtuSeed)%1433
		if ipv6 {
			source = netip.MustParseAddr("2001:db8:1::35")
			target = netip.MustParseAddr("2001:db8::35")
			mtu = ipv6MinimumMTU + int(mtuSeed)%(1501-ipv6MinimumMTU)
			protocols := [...]byte{ProtocolTCP, ProtocolUDP, ProtocolICMPv6, 253, 254}
			protocol = protocols[int(protocol)%len(protocols)]
		} else {
			protocols := [...]byte{ProtocolTCP, ProtocolUDP, ProtocolICMPv4, 253, 254}
			protocol = protocols[int(protocol)%len(protocols)]
		}
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(target, target.BitLen())},
			MTU:            1500,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		if hopLimit == 0 {
			hopLimit = 1
		}
		options := ipPacketOptions{
			hopLimit: hopLimit, trafficClass: trafficClass, flowLabel: flowLabel & ipv6MaximumFlowLabel,
			hopLimitSet: true, trafficClassSet: true, flowLabelSet: true,
		}
		err = stack.tryWriteIPSocketPayloadForMTU(
			source, target, protocol, payload, sourceFragmentation{allow: true}, options, mtu,
		)
		if err != nil {
			t.Fatalf("fragmentation of %d-byte payload at MTU %d: %v", len(payload), mtu, err)
		}
		packets := takeIPOutputPackets(&stack.loopback.packetQueue)
		if len(packets) == 0 {
			t.Fatal("fragmentation returned no packets")
		}
		if !bytes.Equal(payload, original) {
			t.Fatal("fragmentation modified caller payload")
		}
		for index, packet := range packets {
			if len(packet) > mtu {
				t.Fatalf("fragment %d has %d bytes, want at most MTU %d", index, len(packet), mtu)
			}
			if len(packets) > 1 {
				if _, ok := parseFragment(packet, false); !ok {
					t.Fatalf("generated fragment %d is not parseable", index)
				}
			}
		}

		var completed []byte
		if len(packets) == 1 {
			completed = packets[0]
		} else {
			now := time.Unix(300, 0)
			for step := range packets {
				index := step
				if reverse {
					index = len(packets) - 1 - step
				}
				packet := stack.reassemblePacket(packets[index], now)
				if step != len(packets)-1 && packet != nil {
					t.Fatalf("reassembly completed after %d of %d fragments", step+1, len(packets))
				}
				if packet != nil {
					completed = packet
				}
			}
			checkFragmentFuzzResources(t, stack)
		}
		parsed, ok := parseIPPacket(completed, false)
		if !ok || parsed.parameterError {
			t.Fatalf("fragmentation round trip produced an invalid packet: parsed=%t metadata=%+v", ok, parsed)
		}
		if parsed.source != source || parsed.target != target || parsed.protocol != protocol || !bytes.Equal(parsed.payload, payload) {
			t.Fatalf("fragmentation round trip = %s -> %s protocol %d payload %d", parsed.source, parsed.target, parsed.protocol, len(parsed.payload))
		}
		if parsed.hopLimit != hopLimit || parsed.trafficClass != trafficClass {
			t.Fatalf("fragmentation changed hop limit/traffic class to %d/%#x, want %d/%#x", parsed.hopLimit, parsed.trafficClass, hopLimit, trafficClass)
		}
		if ipv6 && parsed.flowLabel != options.flowLabel {
			t.Fatalf("fragmentation changed flow label to %#x, want %#x", parsed.flowLabel, options.flowLabel)
		}
	})
}

func TestFragmentECNReassembly(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	fragments := buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 2000), 1280, 91)
	if len(fragments) != 2 {
		t.Fatalf("fragment count = %d, want 2", len(fragments))
	}
	setPacketECN(fragments[0], 2)
	setPacketECN(fragments[1], 3)
	if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
		t.Fatal("first fragment completed a datagram")
	}
	packet := stack.reassemblePacket(fragments[1], time.Now())
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.ecn != 3 {
		t.Fatalf("reassembled ECN = %d, valid = %v, want CE", parsed.ecn, ok)
	}

	fragments = buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 2000), 1280, 92)
	setPacketECN(fragments[0], 0)
	setPacketECN(fragments[1], 2)
	_ = stack.reassemblePacket(fragments[0], time.Now())
	if packet = stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("mixed Not-ECT/ECT fragment set was accepted")
	}

	fragments = buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 3000), 1280, 93)
	setPacketECN(fragments[0], 1)
	setPacketECN(fragments[1], 2)
	setPacketECN(fragments[2], 3)
	_ = stack.reassemblePacket(fragments[0], time.Now())
	_ = stack.reassemblePacket(fragments[1], time.Now())
	packet = stack.reassemblePacket(fragments[2], time.Now())
	parsed, ok = parseIPPacket(packet, false)
	if !ok || parsed.ecn != 3 {
		t.Fatalf("mixed ECT(0)/ECT(1)/CE reassembly = %d, valid = %v, want CE", parsed.ecn, ok)
	}

	if ecn, valid := fragmentECN(1<<1 | 1<<2); valid {
		t.Fatalf("mixed ECT(0)/ECT(1) result = %d, valid = true, want invalid", ecn)
	}
}

func TestIncompleteFragmentIsNotCountedAsDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.90")
	remote := netip.MustParseAddr("198.51.100.90")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	udp := make([]byte, udpHeaderSize+16)
	binary.BigEndian.PutUint16(udp[0:2], 50000)
	binary.BigEndian.PutUint16(udp[2:4], 50001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], transportChecksum(remote, local, ProtocolUDP, udp))
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, udp, 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	if err = writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("incomplete valid fragment counted as dropped: %d", dropped)
	}
}

func TestIPv4FragmentsWithDontFragmentAreAccepted(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.94")
	target := netip.MustParseAddr("192.0.2.94")
	payload := make([]byte, 24)
	fragments := buildIPv4Fragments(source, target, ProtocolUDP, payload, 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	stack := &Stack{fragments: make(map[fragmentKey]*ipPacketReassemblyEntry), fragmentWake: make(chan struct{}, 1)}
	stack.network.Store(&networkState{local: map[netip.Addr]struct{}{target: {}}})
	var packet []byte
	for index := range fragments {
		field := binary.BigEndian.Uint16(fragments[index][6:8]) | 0x4000
		binary.BigEndian.PutUint16(fragments[index][6:8], field)
		fragments[index][10], fragments[index][11] = 0, 0
		binary.BigEndian.PutUint16(fragments[index][10:12], checksum(fragments[index][:20]))
		packet = stack.reassemblePacket(fragments[index], time.Now())
		if index == 0 && stack.fragmentBytes != len(fragments[index]) {
			t.Fatalf("retained first-fragment bytes = %d, want allocation size %d", stack.fragmentBytes, len(fragments[index]))
		}
	}
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
		t.Fatalf("DF fragment reassembly = %+v, parsed = %v", parsed, ok)
	}
	if field := binary.BigEndian.Uint16(packet[6:8]); field&0x4000 == 0 {
		t.Fatalf("reassembled IPv4 flags = %#x, want DF", field)
	}
}

func TestIPv4FragmentWithReservedFlagIsRejected(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.95")
	target := netip.MustParseAddr("192.0.2.95")
	fragments := buildIPv4Fragments(source, target, ProtocolUDP, make([]byte, 24), 28, 2)
	field := binary.BigEndian.Uint16(fragments[0][6:8]) | 0x8000
	binary.BigEndian.PutUint16(fragments[0][6:8], field)
	fragments[0][10], fragments[0][11] = 0, 0
	binary.BigEndian.PutUint16(fragments[0][10:12], checksum(fragments[0][:20]))
	if _, ok := parseFragment(fragments[0], false); ok {
		t.Fatal("fragment with reserved flag was accepted")
	}
}

func TestIPv4FragmentOptionsLimit(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.96")
	target := netip.MustParseAddr("192.0.2.96")
	first := buildTestIPv4Options(source, target, []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(first[4:6], 3)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:24]))
	last := buildIPPacket(source, target, ProtocolUDP, make([]byte, 8), 3, false)
	binary.BigEndian.PutUint16(last[6:8], 8188)
	last[10], last[11] = 0, 0
	binary.BigEndian.PutUint16(last[10:12], checksum(last[:20]))

	for _, order := range []struct {
		name    string
		packets [][]byte
	}{
		{name: "first fragment first", packets: [][]byte{first, last}},
		{name: "last fragment first", packets: [][]byte{last, first}},
	} {
		t.Run(order.name, func(t *testing.T) {
			_, stack := newTestStack(t, target, source)
			defer stack.Close()
			for _, packet := range order.packets {
				if reassembled := stack.reassemblePacket(packet, time.Now()); reassembled != nil {
					t.Fatal("oversized option-bearing datagram was reassembled")
				}
			}
			stack.fragmentMu.Lock()
			sets, retained := len(stack.fragments), stack.fragmentBytes
			stack.fragmentMu.Unlock()
			if sets != 0 || retained != 0 {
				t.Fatalf("oversized fragment set retained: sets=%d bytes=%d", sets, retained)
			}
		})
	}
}

func TestIPPacketReassembly(t *testing.T) {
	for _, test := range []struct {
		name           string
		source         netip.Addr
		destination    netip.Addr
		mtu            int
		identification uint32
	}{
		{name: "IPv4", source: netip.MustParseAddr("192.0.2.210"), destination: netip.MustParseAddr("198.51.100.210"), mtu: 576},
		{name: "IPv6", source: netip.MustParseAddr("2001:db8::210"), destination: netip.MustParseAddr("2001:db8:1::210"), mtu: 1280, identification: 0x10203040},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x5a}, 4097)
			packet := IPPacket{
				Source: test.source, Destination: test.destination,
				Protocol: 253, HopLimit: 37, TrafficClass: 0x2e, Payload: payload,
			}
			if test.source.Is4() {
				packet.Identification = 0x7210
				if err := packet.SetIPv4HeaderOptions([]IPv4HeaderOption{
					{Type: IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
					{Type: IPv4HeaderOptionTimestamp, Data: []byte{5, 0}},
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
				destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
				if err := hop.SetOptions(nil); err != nil {
					t.Fatal(err)
				}
				if err := destination.SetOptions(nil); err != nil {
					t.Fatal(err)
				}
				if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, destination}, 253, payload); err != nil {
					t.Fatal(err)
				}
			}
			fragments, err := packet.MarshalFragments(test.mtu, test.identification)
			if err != nil || len(fragments) < 2 {
				t.Fatalf("MarshalFragments = %d packets, %v", len(fragments), err)
			}
			var reassembly IPPacketReassembly
			var result IPPacket
			for index := len(fragments) - 1; index >= 0; index-- {
				wire := append([]byte(nil), fragments[index]...)
				fragment, parseErr := ParseIPPacket(wire)
				if parseErr != nil {
					t.Fatalf("parse fragment %d: %v", index, parseErr)
				}
				var complete bool
				result, complete, err = reassembly.Add(fragment)
				for offset := range wire {
					wire[offset] = 0
				}
				if err != nil {
					t.Fatalf("add fragment %d: %v", index, err)
				}
				if complete != (index == 0) {
					t.Fatalf("fragment %d complete = %t", index, complete)
				}
			}
			if reassembly.active || reassembly.state.bytes != 0 || len(reassembly.state.pieces) != 0 {
				t.Fatal("completed reassembly retained internal state")
			}
			if _, fragmented := result.Fragment(); fragmented {
				t.Fatal("completed packet retained fragmentation state")
			}
			protocol, upper, upperErr := result.UpperLayer()
			if upperErr != nil || protocol != 253 || !bytes.Equal(upper, payload) {
				t.Fatalf("upper layer = protocol %d bytes %d, %v", protocol, len(upper), upperErr)
			}
			if test.source.Is4() {
				options, optionsErr := result.IPv4HeaderOptions()
				if optionsErr != nil || len(options) < 2 || options[0].Type != IPv4HeaderOptionRouterAlert || options[1].Type != IPv4HeaderOptionTimestamp {
					t.Fatalf("reassembled IPv4 options = %+v, %v", options, optionsErr)
				}
			} else {
				headers, finalProtocol, finalPayload, headersErr := result.IPv6ExtensionHeaders()
				if headersErr != nil || len(headers) != 2 || headers[0].Type != IPv6ExtensionHeaderHopByHop ||
					headers[1].Type != IPv6ExtensionHeaderDestination || finalProtocol != 253 || !bytes.Equal(finalPayload, payload) {
					t.Fatalf("reassembled IPv6 headers = %+v protocol %d bytes %d, %v", headers, finalProtocol, len(finalPayload), headersErr)
				}
			}
		})
	}
}

func TestIPPacketReassemblyErrorsAndReset(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.211")
	destination := netip.MustParseAddr("198.51.100.211")
	packet := IPPacket{
		Source: source, Destination: destination, Protocol: 253,
		Identification: 0x7211, MoreFragments: true, Payload: bytes.Repeat([]byte{0x11}, 16),
	}
	var reassembly IPPacketReassembly
	if _, complete, err := reassembly.Add(packet); err != nil || complete {
		t.Fatalf("initial fragment = complete %t, %v", complete, err)
	}
	retained := reassembly.state.bytes
	if _, _, err := reassembly.Add(IPPacket{Source: source, Destination: destination, Protocol: 253, Payload: []byte{1}}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("unfragmented Add error = %v", err)
	}
	different := packet
	different.Identification++
	if _, _, err := reassembly.Add(different); !errors.Is(err, syscall.EINVAL) || reassembly.state.bytes != retained {
		t.Fatalf("different packet = bytes %d, %v", reassembly.state.bytes, err)
	}
	if _, complete, err := reassembly.Add(packet); err != nil || complete || reassembly.state.bytes != retained {
		t.Fatalf("duplicate = complete %t bytes %d, %v", complete, reassembly.state.bytes, err)
	}
	var duplicateReassembly IPPacketReassembly
	nonInitial := packet
	nonInitial.FragmentOffset = 8
	if _, complete, err := duplicateReassembly.Add(nonInitial); err != nil || complete {
		t.Fatalf("non-initial fragment = complete %t, %v", complete, err)
	}
	duplicateFinal := nonInitial
	duplicateFinal.MoreFragments = false
	if _, complete, err := duplicateReassembly.Add(duplicateFinal); err != nil || complete || duplicateReassembly.state.total != nonInitial.FragmentOffset+len(nonInitial.Payload) || duplicateReassembly.state.bytes != len(nonInitial.Payload) {
		t.Fatalf("duplicate final = complete %t total %d bytes %d, %v", complete, duplicateReassembly.state.total, duplicateReassembly.state.bytes, err)
	}
	first := packet
	first.Payload = first.Payload[:8]
	if _, complete, err := duplicateReassembly.Add(first); err != nil || !complete {
		t.Fatalf("first fragment = complete %t, %v", complete, err)
	}
	if duplicateReassembly.active {
		t.Fatal("completed duplicate test retained reassembly state")
	}
	overlap := packet
	overlap.FragmentOffset = 8
	overlap.Payload = bytes.Repeat([]byte{0x22}, 16)
	if _, _, err := reassembly.Add(overlap); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("overlap error = %v", err)
	}
	if reassembly.active || reassembly.state.bytes != 0 || len(reassembly.state.pieces) != 0 {
		t.Fatal("overlap did not reset the complete reassembly")
	}
	reassembly.Reset()
	reassembly.Reset()

	atomicHeader := IPv6ExtensionHeader{}
	if err := atomicHeader.SetFragment(0, false, 1); err != nil {
		t.Fatal(err)
	}
	atomic := IPPacket{
		Source: netip.MustParseAddr("2001:db8::211"), Destination: netip.MustParseAddr("2001:db8:1::211"),
		Protocol: IPv6ExtensionHeaderFragment, HopLimit: 64,
	}
	if err := atomic.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{atomicHeader}, 253, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembly.Add(atomic); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("atomic fragment error = %v", err)
	}
	nonInitialHeader := IPv6ExtensionHeader{}
	if err := nonInitialHeader.SetFragment(8, true, 2); err != nil {
		t.Fatal(err)
	}
	nonInitial6 := IPPacket{Source: atomic.Source, Destination: atomic.Destination, HopLimit: 64}
	if err := nonInitial6.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{nonInitialHeader}, ProtocolTCP, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := reassembly.Add(nonInitial6); err != nil || complete {
		t.Fatalf("IPv6 non-initial fragment = complete %t, %v", complete, err)
	}
	retained = reassembly.state.bytes
	truncatedHeader := IPv6ExtensionHeader{}
	if err := truncatedHeader.SetFragment(0, true, 2); err != nil {
		t.Fatal(err)
	}
	truncated := IPPacket{Source: atomic.Source, Destination: atomic.Destination, HopLimit: 64}
	if err := truncated.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{truncatedHeader}, ProtocolTCP, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembly.Add(truncated); !errors.Is(err, syscall.EINVAL) || reassembly.state.bytes != retained {
		t.Fatalf("RFC 7112 first fragment = bytes %d, %v", reassembly.state.bytes, err)
	}
	reassembly.Reset()
}

func TestIPPacketReassemblyHasNoStackPieceLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0x7c}, (fragmentMaximumPieces+44)*8)
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.212"), Destination: netip.MustParseAddr("198.51.100.212"),
		Protocol: 253, HopLimit: 64, Identification: 0x7212, Payload: payload,
	}
	fragments, err := packet.MarshalFragments(28, 0)
	if err != nil || len(fragments) <= fragmentMaximumPieces {
		t.Fatalf("eight-byte fragments = %d, %v", len(fragments), err)
	}
	var reassembly IPPacketReassembly
	var result IPPacket
	for index, wire := range fragments {
		fragment, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatalf("parse fragment %d: %v", index, parseErr)
		}
		var complete bool
		result, complete, err = reassembly.Add(fragment)
		if err != nil || complete != (index == len(fragments)-1) {
			t.Fatalf("fragment %d/%d = complete %t, %v", index, len(fragments), complete, err)
		}
	}
	protocol, upper, err := result.UpperLayer()
	if err != nil || protocol != 253 || !bytes.Equal(upper, payload) {
		t.Fatalf("reassembled maximum-piece payload = protocol %d bytes %d, %v", protocol, len(upper), err)
	}
}

func TestStackIPv6NonInitialFragmentMaximumIgnoresLocalPrefix(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::214")
	remote := netip.MustParseAddr("2001:db8:1::214")
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	fragmentHeader := IPv6ExtensionHeader{}
	if err := hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	if err := fragmentHeader.SetFragment(65528, false, 0xabcdef02); err != nil {
		t.Fatal(err)
	}
	packet := IPPacket{Source: remote, Destination: local, HopLimit: 64}
	if err := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop, fragmentHeader}, 253, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fragment, valid := parseFragment(wire, false)
	if !valid || fragment.parameter || fragment.maximum != fragmentMaximumDatagram {
		t.Fatalf("non-initial fragment = valid %t parameter %t maximum %d", valid, fragment.parameter, fragment.maximum)
	}
	_, stack := newTestStack(t, local, remote)
	if completed, pending := stack.reassemblePacketStatus(wire, time.Now(), false); completed != nil || !pending {
		t.Fatalf("maximum non-initial fragment = completed %t pending %t", completed != nil, pending)
	}
}

func FuzzIPPacketReassembly(f *testing.F) {
	f.Add(false, uint16(4097), uint16(576), uint8(0))
	f.Add(true, uint16(4097), uint16(1280), uint8(1))
	f.Fuzz(func(t *testing.T, ipv6 bool, payloadSize, requestedMTU uint16, order uint8) {
		size := 65 + int(payloadSize)%8192
		payload := make([]byte, size)
		for index := range payload {
			payload[index] = byte(index*31 + size)
		}
		packet := IPPacket{Protocol: 253, HopLimit: 64, TrafficClass: 2, Payload: payload}
		mtu := 68 + int(requestedMTU)%1433
		identification := uint32(0)
		if ipv6 {
			packet.Source = netip.MustParseAddr("2001:db8::213")
			packet.Destination = netip.MustParseAddr("2001:db8:1::213")
			mtu = 1280 + int(requestedMTU)%221
			identification = 0xabcdef01
		} else {
			packet.Source = netip.MustParseAddr("192.0.2.213")
			packet.Destination = netip.MustParseAddr("198.51.100.213")
			packet.Identification = 0x7213
		}
		fragments, err := packet.MarshalFragments(mtu, identification)
		if err != nil || len(fragments) < 2 {
			return
		}
		parsed := make([]IPPacket, len(fragments))
		for index, wire := range fragments {
			parsed[index], err = ParseIPPacket(wire)
			if err != nil {
				t.Fatal(err)
			}
		}
		if order&1 != 0 {
			for left, right := 0, len(parsed)-1; left < right; left, right = left+1, right-1 {
				parsed[left], parsed[right] = parsed[right], parsed[left]
			}
		} else if len(parsed) > 1 {
			rotation := int(order) % len(parsed)
			parsed = append(parsed[rotation:], parsed[:rotation]...)
		}
		var reassembly IPPacketReassembly
		var result IPPacket
		completed := false
		for _, fragment := range parsed {
			result, completed, err = reassembly.Add(fragment)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !completed {
			t.Fatal("valid fragment permutation did not complete")
		}
		protocol, upper, err := result.UpperLayer()
		if err != nil || protocol != 253 || !bytes.Equal(upper, payload) {
			t.Fatalf("reassembled packet = protocol %d bytes %d, %v", protocol, len(upper), err)
		}
	})
}

func BenchmarkIPPacketReassembly(b *testing.B) {
	for _, test := range []struct {
		name           string
		source, target netip.Addr
		mtu            int
		identification uint32
	}{
		{name: "IPv4", source: netip.MustParseAddr("192.0.2.239"), target: netip.MustParseAddr("198.51.100.239"), mtu: 1280},
		{name: "IPv6", source: netip.MustParseAddr("2001:db8::239"), target: netip.MustParseAddr("2001:db8:1::239"), mtu: 1280, identification: 239},
	} {
		packet := IPPacket{
			Source: test.source, Destination: test.target,
			Protocol: 253, HopLimit: 64, Identification: uint16(test.identification),
			Payload: bytes.Repeat([]byte{0x4f}, 60*1024),
		}
		if test.source.Is6() {
			packet.Identification = 0
		}
		wireFragments, err := packet.MarshalFragments(test.mtu, test.identification)
		if err != nil {
			b.Fatal(err)
		}
		fragments := make([]IPPacket, len(wireFragments))
		for index, wire := range wireFragments {
			fragments[index], err = ParseIPPacket(wire)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.Run(test.name, func(b *testing.B) {
			b.SetBytes(int64(len(packet.Payload)))
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				var reassembly IPPacketReassembly
				complete := false
				for _, fragment := range fragments {
					_, complete, err = reassembly.Add(fragment)
					if err != nil {
						b.Fatal(err)
					}
				}
				if !complete {
					b.Fatal("fragment sequence did not reassemble")
				}
			}
		})
	}
}

func BenchmarkIPPacketReassemblyFinalFragmentFirst(b *testing.B) {
	packet := IPPacket{
		Source:         netip.MustParseAddr("192.0.2.238"),
		Destination:    netip.MustParseAddr("198.51.100.238"),
		Protocol:       253,
		HopLimit:       64,
		Identification: 238,
		Payload:        bytes.Repeat([]byte{0x4e}, 60*1024),
	}
	wireFragments, err := packet.MarshalFragments(1280, 0)
	if err != nil {
		b.Fatal(err)
	}
	fragments := make([]IPPacket, 0, len(wireFragments))
	last, err := ParseIPPacket(wireFragments[len(wireFragments)-1])
	if err != nil {
		b.Fatal(err)
	}
	fragments = append(fragments, last)
	for _, wire := range wireFragments[:len(wireFragments)-1] {
		fragment, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			b.Fatal(parseErr)
		}
		fragments = append(fragments, fragment)
	}
	b.SetBytes(int64(len(packet.Payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		var reassembly IPPacketReassembly
		complete := false
		for _, fragment := range fragments {
			_, complete, err = reassembly.Add(fragment)
			if err != nil {
				b.Fatal(err)
			}
		}
		if !complete {
			b.Fatal("fragment sequence did not reassemble")
		}
	}
}

func BenchmarkFragmentReassembly(b *testing.B) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.240"), remote: netip.MustParseAddr("198.51.100.240")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::240"), remote: netip.MustParseAddr("2001:db8:1::240")},
	} {
		b.Run(test.name, func(b *testing.B) {
			_, stack := newTestStack(b, test.local, test.remote)
			payload := bytes.Repeat([]byte{0x5a}, 60*1024)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 240)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 240, ipPacketOptions{})
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var packet []byte
				for _, fragment := range fragments {
					packet = stack.reassemblePacket(fragment, time.Now())
				}
				if len(packet) == 0 {
					b.Fatal("fragment sequence did not reassemble")
				}
			}
		})
	}
}

func BenchmarkIPv6FragmentBuild(b *testing.B) {
	source := netip.MustParseAddr("2001:db8::241")
	target := netip.MustParseAddr("2001:db8:1::241")
	payload := bytes.Repeat([]byte{0x6b}, 60*1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for iteration := 0; iteration < b.N; iteration++ {
		fragments := buildIPv6FragmentsWithOptions(source, target, ProtocolUDP, payload, 1280, uint32(iteration), ipPacketOptions{})
		if len(fragments) == 0 {
			b.Fatal("payload was not fragmented")
		}
	}
}

func TestFragmentRangeState(t *testing.T) {
	pieces := []fragmentPiece{
		{offset: 8, data: make([]byte, 8)},
		{offset: 16, data: make([]byte, 8)},
		{offset: 32, data: make([]byte, 8)},
	}
	for _, test := range []struct {
		name              string
		start, end        int
		covered, overlaps bool
	}{
		{name: "empty", start: 8, end: 8},
		{name: "before", start: 0, end: 8},
		{name: "after", start: 40, end: 48},
		{name: "gap", start: 24, end: 32},
		{name: "inside", start: 10, end: 14, covered: true, overlaps: true},
		{name: "adjacent pieces", start: 8, end: 24, covered: true, overlaps: true},
		{name: "partial start", start: 4, end: 12, overlaps: true},
		{name: "partial end", start: 20, end: 28, overlaps: true},
		{name: "spans gap", start: 8, end: 40, overlaps: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			covered, overlaps := fragmentRangeState(pieces, test.start, test.end)
			if covered != test.covered || overlaps != test.overlaps {
				t.Fatalf("range [%d,%d) = covered %t overlaps %t, want %t/%t", test.start, test.end, covered, overlaps, test.covered, test.overlaps)
			}
		})
	}
}

func TestFragmentRangeCursor(t *testing.T) {
	for _, test := range []struct {
		name             string
		total, capacity  int
		want             [][3]int
		wantConstruction bool
	}{
		{name: "empty", capacity: 15},
		{name: "capacity below offset unit", total: 1, capacity: 7},
		{name: "single final range", total: 15, capacity: 15, wantConstruction: true, want: [][3]int{{0, 15, 0}}},
		{name: "aligned final range", total: 16, capacity: 15, wantConstruction: true, want: [][3]int{{0, 8, 1}, {8, 8, 0}}},
		{name: "full final capacity", total: 22, capacity: 15, wantConstruction: true, want: [][3]int{{0, 8, 1}, {8, 14, 0}}},
		{name: "multiple nonfinal ranges", total: 31, capacity: 15, wantConstruction: true, want: [][3]int{{0, 8, 1}, {8, 8, 1}, {16, 15, 0}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cursor, valid := newFragmentRangeCursor(test.total, test.capacity)
			if valid != test.wantConstruction {
				t.Fatalf("newFragmentRangeCursor(%d, %d) valid = %t, want %t", test.total, test.capacity, valid, test.wantConstruction)
			}
			var got [][3]int
			for offset, size, more, ok := cursor.next(); ok; offset, size, more, ok = cursor.next() {
				if more && size%8 != 0 {
					t.Fatalf("non-final range [%d,%d) is not eight-byte aligned", offset, offset+size)
				}
				if size > test.capacity {
					t.Fatalf("range size %d exceeds capacity %d", size, test.capacity)
				}
				moreValue := 0
				if more {
					moreValue = 1
				}
				got = append(got, [3]int{offset, size, moreValue})
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ranges = %v, want %v", got, test.want)
			}
		})
	}
}

func TestFragmentRangeCursorOutputRoundTrip(t *testing.T) {
	payload := make([]byte, 31)
	for index := range payload {
		payload[index] = byte(index*17 + 3)
	}
	for _, test := range []struct {
		name           string
		packet         IPPacket
		mtu            int
		identification uint32
		wantSizes      []int
	}{
		{
			name: "IPv4",
			packet: IPPacket{
				Source: netip.MustParseAddr("192.0.2.231"), Destination: netip.MustParseAddr("198.51.100.231"),
				Protocol: 253, HopLimit: 64, Identification: 0x7231, Payload: payload,
			},
			mtu: 35, wantSizes: []int{28, 28, 35},
		},
		{
			name: "IPv6",
			packet: IPPacket{
				Source: netip.MustParseAddr("2001:db8::231"), Destination: netip.MustParseAddr("2001:db8:1::231"),
				Protocol: 253, HopLimit: 64, Payload: payload,
			},
			mtu: 63, identification: 0x10203231, wantSizes: []int{56, 56, 63},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fragments, err := test.packet.MarshalFragments(test.mtu, test.identification)
			if err != nil {
				t.Fatal(err)
			}
			var reassembly IPPacketReassembly
			var result IPPacket
			for index, wire := range fragments {
				if index >= len(test.wantSizes) || len(wire) != test.wantSizes[index] {
					t.Fatalf("fragment %d size = %d, want %v", index, len(wire), test.wantSizes)
				}
				fragment, parseErr := ParseIPPacket(wire)
				if parseErr != nil {
					t.Fatalf("parse fragment %d: %v", index, parseErr)
				}
				var complete bool
				result, complete, err = reassembly.Add(fragment)
				if err != nil {
					t.Fatalf("add fragment %d: %v", index, err)
				}
				if complete != (index == len(fragments)-1) {
					t.Fatalf("fragment %d complete = %t", index, complete)
				}
			}
			if len(fragments) != len(test.wantSizes) || !bytes.Equal(result.Payload, payload) {
				t.Fatalf("fragment count/payload = %d/%x, want %d/%x", len(fragments), result.Payload, len(test.wantSizes), payload)
			}
		})
	}
}

func BenchmarkFragmentRangeCovered(b *testing.B) {
	pieces := make([]fragmentPiece, fragmentMaximumPieces)
	for index := range pieces {
		pieces[index] = fragmentPiece{offset: index * 8, data: make([]byte, 8)}
	}
	end := len(pieces) * 8
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if covered, _ := fragmentRangeState(pieces, 0, end); !covered {
			b.Fatal("contiguous range was not covered")
		}
	}
}

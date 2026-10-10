package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func newMulticastTestStack(t testing.TB, addresses []netip.Prefix, mtu int) *Stack {
	t.Helper()
	stack, err := New(Config{LocalAddresses: addresses, MTU: uint32(mtu)})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

func multicastTestUDP(t testing.TB, connection net.PacketConn) *UDPConn {
	t.Helper()
	udp, ok := connection.(*UDPConn)
	if !ok {
		t.Fatalf("packet connection type = %T, want *UDPConn", connection)
	}
	return udp
}

func readMulticastTestUDP(t testing.TB, connection *UDPConn, want string) netip.AddrPort {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, source, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != want {
		t.Fatalf("UDP payload = %q, want %q", buffer[:n], want)
	}
	return source
}

func expectMulticastTestUDPTimeout(t testing.TB, connection *UDPConn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadFromUDPAddrPort(make([]byte, 16)); !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ETIMEDOUT) && !errors.Is(err, context.DeadlineExceeded) {
		var netError net.Error
		if !errors.As(err, &netError) || !netError.Timeout() {
			t.Fatalf("UDP read error = %v, want timeout", err)
		}
	}
}

func nextMulticastTestPacket(t testing.TB, stack *Stack, match func(ipPacket) bool) ipPacket {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		entry, ok := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !ok {
			break
		}
		packet := consumeTestPacket(&stack.outbound, entry)
		parsed, valid := parseIPPacket(packet, false)
		if valid && match(parsed) {
			return parsed
		}
	}
	t.Fatal("timed out waiting for matching multicast test packet")
	return ipPacket{}
}

func expectNoMulticastTestPacket(t testing.TB, stack *Stack, wait time.Duration, match func(ipPacket) bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		entry, ok := waitTestPacketEntry(&stack.outbound, time.Until(deadline))
		if !ok {
			return
		}
		packet := consumeTestPacket(&stack.outbound, entry)
		if parsed, valid := parseIPPacket(packet, false); valid && match(parsed) {
			t.Fatalf("unexpected matching multicast test packet: %x", packet)
		}
	}
}

func drainMulticastTestOutput(stack *Stack) {
	for {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			return
		}
		stack.outbound.release(entry)
	}
}

func clearMulticastTestControl(stack *Stack) {
	stack.mu.RLock()
	state, _ := stack.multicast.(*multicastState)
	stack.mu.RUnlock()
	if state != nil {
		state.mu.Lock()
		state.retransmissions = make(map[netip.Addr]*multicastRetransmission)
		state.generalQuery = [2]time.Time{}
		for _, group := range state.groups {
			group.query = multicastPendingQuery{}
		}
		state.wakeLocked()
		state.mu.Unlock()
	}
	time.Sleep(time.Millisecond)
	drainMulticastTestOutput(stack)
}

func buildMulticastTestIGMPQuery(source, target, group netip.Addr, responseCode byte, sources []netip.Addr, routerAlert bool) []byte {
	payloadSize := 8
	if sources != nil {
		payloadSize = 12 + 4*len(sources)
	}
	payload := make([]byte, payloadSize)
	payload[0], payload[1] = igmpMembershipQuery, responseCode
	if group.IsValid() && !group.IsUnspecified() {
		value := group.As4()
		copy(payload[4:8], value[:])
	}
	if sources != nil {
		payload[8], payload[9] = multicastDefaultRobustness, 125
		binary.BigEndian.PutUint16(payload[10:12], uint16(len(sources)))
		offset := 12
		for _, source := range sources {
			value := source.As4()
			copy(payload[offset:offset+4], value[:])
			offset += 4
		}
	}
	binary.BigEndian.PutUint16(payload[2:4], checksum(payload))
	headerSize := 20
	if routerAlert {
		headerSize = 24
	}
	packet := make([]byte, headerSize+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 1, 2
	if routerAlert {
		packet[0] = 0x46
		copy(packet[20:24], []byte{148, 4, 0, 0})
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	sourceBytes, targetBytes := source.As4(), target.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], targetBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
	copy(packet[headerSize:], payload)
	return packet
}

func buildMulticastTestMLDQuery(source, target, group netip.Addr, responseCode uint16, sources []netip.Addr) []byte {
	payloadSize := 24
	if sources != nil {
		payloadSize = 28 + 16*len(sources)
	}
	payload := make([]byte, payloadSize)
	payload[0] = mldMembershipQuery
	binary.BigEndian.PutUint16(payload[4:6], responseCode)
	if group.IsValid() && !group.IsUnspecified() {
		value := group.As16()
		copy(payload[8:24], value[:])
	}
	if sources != nil {
		payload[24], payload[25] = multicastDefaultRobustness, 125
		binary.BigEndian.PutUint16(payload[26:28], uint16(len(sources)))
		offset := 28
		for _, source := range sources {
			value := source.As16()
			copy(payload[offset:offset+16], value[:])
			offset += 16
		}
	}
	binary.BigEndian.PutUint16(payload[2:4], transportChecksum(source, target, ProtocolICMPv6, payload))
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	sourceBytes, targetBytes := source.As16(), target.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], targetBytes[:])
	copy(packet[40:48], []byte{ProtocolICMPv6, 0, 5, 2, 0, 0, 1, 0})
	copy(packet[48:], payload)
	return packet
}

func TestMulticastQueryKnownAnswerVectors(t *testing.T) {
	network4, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}})
	if err != nil {
		t.Fatal(err)
	}
	network6, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		wire     string
		built    []byte
		network  *networkState
		version  uint8
		maximum  time.Duration
		interval time.Duration
		group    netip.Addr
		sources  []netip.Addr
		v6       bool
	}{
		{
			name: "IGMPv1 general",
			wire: "4500001c00000000010217ddc0000202e00000011100eeff00000000",
			built: buildMulticastTestIGMPQuery(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("224.0.0.1"),
				netip.IPv4Unspecified(), 0, nil, false),
			network: network4, version: 1, maximum: multicastDefaultResponseInterval, group: netip.IPv4Unspecified(),
		},
		{
			name: "IGMPv2 group",
			wire: "4600002000000000010271d1c0000202ef010203940400001164fd96ef010203",
			built: buildMulticastTestIGMPQuery(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("239.1.2.3"),
				netip.MustParseAddr("239.1.2.3"), 100, nil, true),
			network: network4, version: 2, maximum: 10 * time.Second, group: netip.MustParseAddr("239.1.2.3"),
		},
		{
			name: "IGMPv3 source",
			wire: "4600002800000000010278c9c0000202e8010203940400001196d7abe8010203027d0001c6336407",
			built: buildMulticastTestIGMPQuery(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("232.1.2.3"),
				netip.MustParseAddr("232.1.2.3"), 0x96, []netip.Addr{netip.MustParseAddr("198.51.100.7")}, true),
			network: network4, version: 3, maximum: 35*time.Second + 200*time.Millisecond, interval: 125 * time.Second,
			group: netip.MustParseAddr("232.1.2.3"), sources: []netip.Addr{netip.MustParseAddr("198.51.100.7")},
		},
		{
			name: "MLDv1 general",
			wire: "6000000000200001fe800000000000000000000000000002ff020000000000000000000000000001" +
				"3a0005020000010082007c3e03e8000000000000000000000000000000000000",
			built: buildMulticastTestMLDQuery(netip.MustParseAddr("fe80::2"), netip.MustParseAddr("ff02::1"),
				netip.IPv6Unspecified(), 1000, nil),
			network: network6, version: 1, maximum: time.Second, group: netip.IPv6Unspecified(), v6: true,
		},
		{
			name: "MLDv2 source",
			wire: "6000000000340001fe800000000000000000000000000002ff3e0000000000000000000000001234" +
				"3a000502000001008200db2c80010000ff3e0000000000000000000000001234027d0001" +
				"fe800000000000000000000000000003",
			built: buildMulticastTestMLDQuery(netip.MustParseAddr("fe80::2"), netip.MustParseAddr("ff3e::1234"),
				netip.MustParseAddr("ff3e::1234"), 0x8001, []netip.Addr{netip.MustParseAddr("fe80::3")}),
			network: network6, version: 2, maximum: 32*time.Second + 776*time.Millisecond, interval: 125 * time.Second,
			group: netip.MustParseAddr("ff3e::1234"), sources: []netip.Addr{netip.MustParseAddr("fe80::3")}, v6: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := mustCodecVector(t, test.wire)
			if !bytes.Equal(test.built, wire) {
				t.Fatalf("query helper output:\n got %x\nwant %x", test.built, wire)
			}
			packet, valid := parseIPPacket(wire, false)
			if !valid {
				t.Fatal("known-answer IP envelope did not parse")
			}
			if packet.source.Is4() {
				headerLength := int(wire[0]&0xf) * 4
				if referenceChecksum(wire[:headerLength]) != 0 || referenceChecksum(packet.payload) != 0 {
					t.Fatal("known-answer IGMP checksums are invalid")
				}
			} else if referenceTransportChecksum(packet.source, packet.target, ProtocolICMPv6, packet.payload) != 0 {
				t.Fatal("known-answer MLD checksum is invalid")
			}
			var query multicastQuery
			if test.v6 {
				query, _, valid = parseMLDQuery(packet, test.network, false)
			} else {
				query, _, valid = parseIGMPQuery(packet, test.network, false)
			}
			sourcesEqual := len(query.sources) == len(test.sources)
			for index := range query.sources {
				if !sourcesEqual || query.sources[index] != test.sources[index] {
					sourcesEqual = false
					break
				}
			}
			if !valid || query.v6 != test.v6 || query.version != test.version || query.maximum != test.maximum ||
				query.queryInterval != test.interval || query.group != test.group || !sourcesEqual {
				t.Fatalf("known-answer query = %+v, valid %t", query, valid)
			}
		})
	}
}

func TestMulticastTimeDecodingReference(t *testing.T) {
	for code := 0; code <= 0xff; code++ {
		linear := time.Duration(code) * 100 * time.Millisecond
		if got := decodeIGMPv2Time(byte(code)); got != linear {
			t.Fatalf("IGMPv2 code %#x = %v, want %v", code, got, linear)
		}
		value := code
		if code >= 0x80 {
			mantissa, exponent := code&0xf|0x10, code>>4&7
			value = mantissa * (1 << (exponent + 3))
		}
		if got, want := decodeIGMPTime(byte(code)), time.Duration(value)*100*time.Millisecond; got != want {
			t.Fatalf("IGMPv3 MRC %#x = %v, want %v", code, got, want)
		}
		if got, want := decodeIGMPQueryInterval(byte(code)), time.Duration(value)*time.Second; got != want {
			t.Fatalf("IGMP/MLD QQIC %#x = %v, want %v", code, got, want)
		}
	}
	for code := 0; code <= 0xffff; code++ {
		value := code
		if code >= 0x8000 {
			mantissa, exponent := code&0xfff|0x1000, code>>12&7
			value = mantissa * (1 << (exponent + 3))
		}
		if got, want := decodeMLDTime(uint16(code)), time.Duration(value)*time.Millisecond; got != want {
			t.Fatalf("MLDv2 MRC %#x = %v, want %v", code, got, want)
		}
	}
}

func FuzzMulticastQueryParsing(f *testing.F) {
	network4, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}})
	if err != nil {
		f.Fatal(err)
	}
	network6, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("fe80::1/128")}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0, 0, 0, 0}, false, true)
	f.Add([]byte{3, 1, 2, 0xff, 1, 2, 3}, false, false)
	f.Add([]byte{2, 0, 1, 0xff, 4, 5}, true, true)
	f.Fuzz(func(t *testing.T, data []byte, ipv6 bool, routerAlert bool) {
		if len(data) > 96 {
			data = data[:96]
		}
		sourceCount := 0
		if len(data) != 0 {
			sourceCount = int(data[0] & 15)
		}
		responseCode := byte(1)
		if len(data) > 3 {
			responseCode = data[3]
		}
		control := byte(0)
		if len(data) > 4 {
			control = data[4]
		}
		extra := 0
		if len(data) > 5 {
			extra = int(data[5] & 31)
			if extra > len(data)-6 {
				extra = len(data) - 6
			}
		}

		if !ipv6 {
			querier := netip.MustParseAddr("192.0.2.2")
			allHosts := netip.MustParseAddr("224.0.0.1")
			group := allHosts
			if len(data) > 1 {
				switch data[1] & 3 {
				case 0:
					group = netip.IPv4Unspecified()
				case 2:
					group = netip.MustParseAddr("192.0.2.99")
				case 3:
					group = netip.MustParseAddr("232.0.0.1")
				}
			}
			target := group
			if target.IsUnspecified() {
				target = allHosts
			}
			if len(data) > 2 {
				switch data[2] & 3 {
				case 1:
					target = netip.MustParseAddr("192.0.2.1")
				case 2:
					target = netip.MustParseAddr("198.51.100.1")
				}
			}
			sources := make([]netip.Addr, sourceCount)
			for index := range sources {
				value := byte(index + 10)
				if 6+index < len(data) {
					value = data[6+index]
				}
				switch value & 3 {
				case 0:
					sources[index] = netip.AddrFrom4([4]byte{198, 51, 100, value})
				case 1:
					sources[index] = netip.IPv4Unspecified()
				case 2:
					sources[index] = netip.AddrFrom4([4]byte{224, 0, 0, value})
				default:
					sources[index] = netip.AddrFrom4([4]byte{192, 0, 2, 255})
				}
			}
			packet := buildMulticastTestIGMPQuery(querier, target, group, responseCode, sources, routerAlert)
			headerSize := int(packet[0]&0x0f) * 4
			if extra != 0 {
				packet = append(packet, data[6:6+extra]...)
			}
			if control&1 != 0 && len(packet)-headerSize >= 12 {
				binary.BigEndian.PutUint16(packet[headerSize+10:headerSize+12], uint16(sourceCount+1))
			}
			binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
			if len(packet)-headerSize >= 4 {
				packet[headerSize+2], packet[headerSize+3] = 0, 0
				binary.BigEndian.PutUint16(packet[headerSize+2:headerSize+4], checksum(packet[headerSize:]))
			}
			packet[10], packet[11] = 0, 0
			binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
			parsed, ok := parseIPPacket(packet, false)
			if !ok {
				t.Fatal("generated IGMP query has an invalid IPv4 envelope")
			}
			query, expected, valid := parseIGMPQuery(parsed, network4, false)
			if !valid {
				return
			}
			if query.v6 || query.version == 0 || query.version > 3 || !expected.Is4() || !expected.IsMulticast() {
				t.Fatalf("valid IGMP query produced inconsistent metadata: query=%+v expected=%s", query, expected)
			}
			if len(query.sources) != 0 && query.group.IsUnspecified() {
				t.Fatalf("source-specific IGMP query without a group: %+v", query)
			}
			for _, source := range query.sources {
				if !validMulticastSourceAddress(network4, source, false) {
					t.Fatalf("valid IGMP query retained invalid source %s", source)
				}
			}
			return
		}

		querier := netip.MustParseAddr("fe80::2")
		allNodes := netip.MustParseAddr("ff02::1")
		group := allNodes
		if len(data) > 1 {
			switch data[1] & 3 {
			case 0:
				group = netip.IPv6Unspecified()
			case 2:
				group = netip.MustParseAddr("2001:db8::99")
			case 3:
				group = netip.MustParseAddr("ff3e::1")
			}
		}
		target := group
		if target.IsUnspecified() {
			target = allNodes
		}
		if len(data) > 2 {
			switch data[2] & 3 {
			case 1:
				target = netip.MustParseAddr("fe80::1")
			case 2:
				target = netip.MustParseAddr("2001:db8::1")
			}
		}
		if control&2 != 0 {
			querier = netip.MustParseAddr("2001:db8::2")
		}
		sources := make([]netip.Addr, sourceCount)
		for index := range sources {
			value := byte(index + 10)
			if 6+index < len(data) {
				value = data[6+index]
			}
			switch value & 3 {
			case 0:
				sources[index] = netip.MustParseAddr("2001:db8::100")
			case 1:
				sources[index] = netip.IPv6Unspecified()
			case 2:
				sources[index] = netip.MustParseAddr("ff02::1")
			default:
				sources[index] = netip.MustParseAddr("fe80::abcd")
			}
		}
		packet := buildMulticastTestMLDQuery(querier, target, group, uint16(responseCode)<<8|uint16(responseCode), sources)
		if !routerAlert {
			copy(packet[42:46], []byte{1, 2, 0, 0})
		}
		if extra != 0 {
			packet = append(packet, data[6:6+extra]...)
		}
		if control&1 != 0 && len(packet) >= 76 {
			binary.BigEndian.PutUint16(packet[74:76], uint16(sourceCount+1))
		}
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		if len(packet) >= 52 {
			packet[50], packet[51] = 0, 0
			source := netip.AddrFrom16([16]byte(packet[8:24]))
			target := netip.AddrFrom16([16]byte(packet[24:40]))
			binary.BigEndian.PutUint16(packet[50:52], transportChecksum(source, target, ProtocolICMPv6, packet[48:]))
		}
		parsed, ok := parseIPPacket(packet, false)
		if !ok {
			t.Fatal("generated MLD query has an invalid IPv6 envelope")
		}
		query, expected, valid := parseMLDQuery(parsed, network6, false)
		if !valid {
			return
		}
		if !query.v6 || query.version == 0 || query.version > 2 || !expected.Is6() || !expected.IsMulticast() {
			t.Fatalf("valid MLD query produced inconsistent metadata: query=%+v expected=%s", query, expected)
		}
		if len(query.sources) != 0 && query.group.IsUnspecified() {
			t.Fatalf("source-specific MLD query without a group: %+v", query)
		}
		for _, source := range query.sources {
			if !validMulticastSourceAddress(network6, source, true) {
				t.Fatalf("valid MLD query retained invalid source %s", source)
			}
		}
	})
}

func multicastTestReportRecords(t testing.TB, packet ipPacket) []multicastReportRecord {
	t.Helper()
	payload := packet.payload
	if packet.source.Is4() {
		if len(payload) < 8 || payload[0] != igmpV3MembershipReport {
			t.Fatalf("not an IGMPv3 report: %x", payload)
		}
		count, offset := int(binary.BigEndian.Uint16(payload[6:8])), 8
		result := make([]multicastReportRecord, 0, count)
		for index := 0; index < count; index++ {
			if len(payload)-offset < 8 {
				t.Fatal("truncated IGMPv3 group record")
			}
			sourceCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
			end := offset + 8 + sourceCount*4
			if end > len(payload) {
				t.Fatal("truncated IGMPv3 sources")
			}
			record := multicastReportRecord{recordType: payload[offset], group: netip.AddrFrom4([4]byte(payload[offset+4 : offset+8]))}
			for sourceOffset := offset + 8; sourceOffset < end; sourceOffset += 4 {
				record.sources = append(record.sources, netip.AddrFrom4([4]byte(payload[sourceOffset:sourceOffset+4])))
			}
			result = append(result, record)
			offset = end + int(payload[offset+1])*4
		}
		return result
	}
	if len(payload) < 8 || payload[0] != mldV2MembershipReport {
		t.Fatalf("not an MLDv2 report: %x", payload)
	}
	count, offset := int(binary.BigEndian.Uint16(payload[6:8])), 8
	result := make([]multicastReportRecord, 0, count)
	for index := 0; index < count; index++ {
		if len(payload)-offset < 20 {
			t.Fatal("truncated MLDv2 group record")
		}
		sourceCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		end := offset + 20 + sourceCount*16
		if end > len(payload) {
			t.Fatal("truncated MLDv2 sources")
		}
		record := multicastReportRecord{recordType: payload[offset], group: netip.AddrFrom16([16]byte(payload[offset+4 : offset+20]))}
		for sourceOffset := offset + 20; sourceOffset < end; sourceOffset += 16 {
			record.sources = append(record.sources, netip.AddrFrom16([16]byte(payload[sourceOffset:sourceOffset+16])))
		}
		result = append(result, record)
		offset = end + int(payload[offset+1])*4
	}
	return result
}

func TestIPv4BroadcastFanoutAndOutput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	remote := netip.MustParseAddr("192.0.2.20")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}, 1400)

	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	firstPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:42000"))
	if err != nil {
		t.Fatal(err)
	}
	defer firstPacket.Close()
	secondPacket, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:42000"))
	if err != nil {
		t.Fatal(err)
	}
	defer secondPacket.Close()
	first, second := multicastTestUDP(t, firstPacket), multicastTestUDP(t, secondPacket)

	if _, err = stack.Write([][]byte{buildTestUDP(remote, broadcast, 53000, 42000, []byte("broadcast-in"))}, 0); err != nil {
		t.Fatal(err)
	}
	if source := readMulticastTestUDP(t, first, "broadcast-in"); source != netip.MustParseAddrPort("192.0.2.20:53000") {
		t.Fatalf("first source = %s", source)
	}
	readMulticastTestUDP(t, second, "broadcast-in")
	if _, err = stack.Write([][]byte{buildTestUDP(remote, broadcast, 53001, 42000, []byte("broadcast-control"))}, 0); err != nil {
		t.Fatal(err)
	}
	controlPayload, controlOOB := make([]byte, 64), make([]byte, 128)
	n, oobn, flags, source, err := first.ReadMsgUDPAddrPort(controlPayload, controlOOB)
	if err != nil || flags != 0 || string(controlPayload[:n]) != "broadcast-control" || source != netip.AddrPortFrom(remote, 53001) {
		t.Fatalf("broadcast ReadMsgUDPAddrPort = %q/%d flags %#x source %s, %v", controlPayload[:n], oobn, flags, source, err)
	}
	var controlMessage IPv4ControlMessage
	if err = controlMessage.Parse(controlOOB[:oobn]); err != nil || controlMessage.Dst != broadcast {
		t.Fatalf("broadcast packet-info = %+v, %v, want destination %s", controlMessage, err, broadcast)
	}
	if !bytes.Equal(controlOOB[20:24], local.AsSlice()) || !bytes.Equal(controlOOB[24:28], broadcast.AsSlice()) {
		t.Fatalf("broadcast packet-info fields = %x/%x, want %s/%s", controlOOB[20:24], controlOOB[24:28], local, broadcast)
	}
	readMulticastTestUDP(t, second, "broadcast-control")

	if _, err = stack.Write([][]byte{buildTestUDP(netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), 68, 42000, []byte("bootstrap"))}, 0); err != nil {
		t.Fatal(err)
	}
	if source := readMulticastTestUDP(t, first, "bootstrap"); source != netip.MustParseAddrPort("0.0.0.0:68") {
		t.Fatalf("bootstrap source = %s", source)
	}
	readMulticastTestUDP(t, second, "bootstrap")
	invalidSources := stack.Stats().InvalidSourcePackets
	if _, err = stack.Write([][]byte{buildTestUDP(netip.IPv4Unspecified(), broadcast, 68, 42000, []byte("invalid"))}, 0); err != nil {
		t.Fatal(err)
	}
	if got := stack.Stats().InvalidSourcePackets; got != invalidSources+1 {
		t.Fatalf("unspecified source to directed broadcast invalid-source count = %d, want %d", got, invalidSources+1)
	}

	receiverPacket, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:42001"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiverPacket.Close()
	receiver := multicastTestUDP(t, receiverPacket)
	senderPacket, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacket.Close()
	sender := multicastTestUDP(t, senderPacket)
	if err = sender.SetBroadcast(false); err != nil {
		t.Fatal(err)
	}
	if _, err = sender.WriteToUDPAddrPort([]byte("denied"), netip.AddrPortFrom(broadcast, 42001)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("broadcast without SO_BROADCAST = %v, want EACCES", err)
	}
	if err = sender.SetBroadcast(true); err != nil {
		t.Fatal(err)
	}
	if _, err = sender.WriteToUDPAddrPort([]byte("broadcast-out"), netip.AddrPortFrom(broadcast, 42001)); err != nil {
		t.Fatal(err)
	}
	readMulticastTestUDP(t, receiver, "broadcast-out")
	outbound := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == ProtocolUDP && packet.target == broadcast
	})
	if outbound.source != local || outbound.hopLimit != 64 || string(outbound.payload[udpHeaderSize:]) != "broadcast-out" {
		t.Fatalf("broadcast output = source %s ttl %d payload %q", outbound.source, outbound.hopLimit, outbound.payload[udpHeaderSize:])
	}

	ipv6Only := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::10/64")}, 1400)
	if _, err = ipv6Only.Write([][]byte{buildTestUDP(remote, netip.MustParseAddr("255.255.255.255"), 53000, 42000, nil)}, 0); err != nil {
		t.Fatal(err)
	}
	if stats := ipv6Only.Stats(); stats.UnacceptedIPPackets != 1 {
		t.Fatalf("IPv6-only limited-broadcast admission = %+v", stats)
	}
}

func TestIPv4BroadcastIPPacketInfo(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	remote := netip.MustParseAddr("192.0.2.20")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}, 1400)
	connectionNet, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	connection := connectionNet.(*IPConn)
	defer connection.Close()
	if _, err = stack.Write([][]byte{buildIPPacket(remote, broadcast, 99, []byte("broadcast-raw"), 1, true)}, 0); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload, control := make([]byte, 64), make([]byte, 128)
	n, oobn, flags, source, err := connection.ReadMsgIP(payload, control)
	if err != nil || flags != 0 || string(payload[:n]) != "broadcast-raw" || source.String() != remote.String() {
		t.Fatalf("broadcast raw ReadMsgIP = %q/%d flags %#x source %v, %v", payload[:n], oobn, flags, source, err)
	}
	var message IPv4ControlMessage
	if err = message.Parse(control[:oobn]); err != nil || message.Dst != broadcast {
		t.Fatalf("broadcast raw packet-info = %+v, %v, want destination %s", message, err, broadcast)
	}
	if oobn < 28 || !bytes.Equal(control[20:24], local.AsSlice()) || !bytes.Equal(control[24:28], broadcast.AsSlice()) {
		t.Fatalf("broadcast raw packet-info fields = %x/%x, want %s/%s", control[20:24], control[24:28], local, broadcast)
	}
	if _, err = stack.Write([][]byte{buildIPPacket(remote, broadcast, 99, []byte("broadcast-batch"), 2, true)}, 0); err != nil {
		t.Fatal(err)
	}
	batch := []SocketMessage{{Buffers: [][]byte{make([]byte, 64)}, OOB: make([]byte, 128)}}
	if count, batchErr := connection.ReadBatch(batch, 0); batchErr != nil || count != 1 || string(batch[0].Buffers[0][:batch[0].N]) != "broadcast-batch" {
		t.Fatalf("broadcast raw ReadBatch = %d/%d, %v", count, batch[0].N, batchErr)
	}
	var batchMessage IPv4ControlMessage
	if err = batchMessage.Parse(batch[0].OOB[:batch[0].NN]); err != nil || batchMessage.Dst != broadcast || !bytes.Equal(batch[0].OOB[20:24], local.AsSlice()) || !bytes.Equal(batch[0].OOB[24:28], broadcast.AsSlice()) {
		t.Fatalf("broadcast raw batch packet-info = %+v, %v, fields %x/%x", batchMessage, err, batch[0].OOB[20:24], batch[0].OOB[24:28])
	}
}

func TestTCPRejectsBroadcastDestination(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}, 1400)
	for _, address := range []netip.Addr{
		netip.MustParseAddr("192.0.2.255"),
		netip.MustParseAddr("255.255.255.255"),
	} {
		connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(address, 443))
		if connection != nil || !errors.Is(err, syscall.EACCES) {
			t.Fatalf("DialTCP to broadcast %s = %v, %v, want EACCES", address, connection, err)
		}
	}
}

func TestASMMulticastIPv4AndIPv6(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.30")
	local6 := netip.MustParseAddr("fe80::30")
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.30/24"),
		netip.MustParsePrefix("fe80::30/64"),
	}, 1400)

	tests := []struct {
		name    string
		network string
		group   netip.Addr
		remote  netip.Addr
		port    uint16
	}{
		{name: "ipv4", network: "udp4", group: netip.MustParseAddr("239.1.2.3"), remote: netip.MustParseAddr("192.0.2.31"), port: 43001},
		{name: "ipv6", network: "udp6", group: netip.MustParseAddr("ff02::1234"), remote: netip.MustParseAddr("fe80::31"), port: 43002},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := stack.ListenMulticastUDP(context.Background(), test.network, netip.AddrPortFrom(test.group, test.port))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			if loopback, err := packet.MulticastLoopback(); err != nil || loopback {
				t.Fatalf("ListenMulticastUDP loopback = %v, %v, want false", loopback, err)
			}

			report := nextMulticastTestPacket(t, stack, func(candidate ipPacket) bool {
				if test.group.Is4() {
					return candidate.protocol == 2 && len(candidate.payload) >= 16 && candidate.payload[0] == igmpV3MembershipReport
				}
				return candidate.protocol == ProtocolICMPv6 && len(candidate.payload) >= 28 && candidate.payload[0] == mldV2MembershipReport
			})
			if report.hopLimit != 1 || !report.hasRouterAlert() {
				t.Fatalf("membership report hop limit/router alert = %d/%v", report.hopLimit, report.hasRouterAlert())
			}

			if _, err = stack.Write([][]byte{buildTestUDP(test.remote, test.group, 53001, test.port, []byte("multicast-in"))}, 0); err != nil {
				t.Fatal(err)
			}
			readMulticastTestUDP(t, packet, "multicast-in")

			if err = packet.SetMulticastLoopback(true); err != nil {
				t.Fatal(err)
			}
			if err = packet.SetMulticastHopLimit(7); err != nil {
				t.Fatal(err)
			}
			if _, err = packet.WriteToUDPAddrPort([]byte("multicast-out"), netip.AddrPortFrom(test.group, test.port)); err != nil {
				t.Fatal(err)
			}
			readMulticastTestUDP(t, packet, "multicast-out")
			outbound := nextMulticastTestPacket(t, stack, func(candidate ipPacket) bool {
				return candidate.protocol == ProtocolUDP && candidate.target == test.group
			})
			wantSource := local4
			if test.group.Is6() {
				wantSource = local6
			}
			if outbound.source != wantSource || outbound.hopLimit != 7 {
				t.Fatalf("multicast output source/hop limit = %s/%d, want %s/7", outbound.source, outbound.hopLimit, wantSource)
			}

			drainMulticastTestOutput(stack)
			if err = packet.SetMulticastHopLimit(0); err != nil {
				t.Fatal(err)
			}
			if _, err = packet.WriteToUDPAddrPort([]byte("host-only"), netip.AddrPortFrom(test.group, test.port)); err != nil {
				t.Fatal(err)
			}
			readMulticastTestUDP(t, packet, "host-only")
			time.Sleep(10 * time.Millisecond)
			for {
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					break
				}
				wire := consumeTestPacket(&stack.outbound, entry)
				candidate, valid := parseIPPacket(wire, false)
				if valid && candidate.protocol == ProtocolUDP && candidate.target == test.group {
					t.Fatal("zero-hop multicast escaped to the link")
				}
			}
		})
	}
}

func TestIPv4MulticastReadPacketInfo(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.33")
	remote := netip.MustParseAddr("192.0.2.34")
	group := netip.MustParseAddr("239.1.2.33")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.33/24")}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 43003))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = stack.Write([][]byte{buildTestUDP(remote, group, 53003, 43003, []byte("multicast-control"))}, 0); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload, oob := make([]byte, 64), make([]byte, 128)
	n, oobn, flags, source, err := connection.ReadMsgUDPAddrPort(payload, oob)
	if err != nil || flags != 0 || string(payload[:n]) != "multicast-control" || source != netip.AddrPortFrom(remote, 53003) {
		t.Fatalf("multicast ReadMsgUDPAddrPort = %q/%d flags %#x source %s, %v", payload[:n], oobn, flags, source, err)
	}
	var message IPv4ControlMessage
	if err = message.Parse(oob[:oobn]); err != nil || message.Dst != group {
		t.Fatalf("multicast packet-info = %+v, %v, want destination %s", message, err, group)
	}
	if oobn < 28 || !bytes.Equal(oob[20:24], local.AsSlice()) || !bytes.Equal(oob[24:28], group.AsSlice()) {
		t.Fatalf("multicast packet-info fields = %x/%x, want %s/%s", oob[20:24], oob[24:28], local, group)
	}
	if _, err = stack.Write([][]byte{buildTestUDP(remote, group, 53004, 43003, []byte("multicast-batch"))}, 0); err != nil {
		t.Fatal(err)
	}
	batch := []SocketMessage{{Buffers: [][]byte{make([]byte, 64)}, OOB: make([]byte, 128)}}
	if count, batchErr := connection.ReadBatch(batch, 0); batchErr != nil || count != 1 || string(batch[0].Buffers[0][:batch[0].N]) != "multicast-batch" {
		t.Fatalf("multicast ReadBatch = %d/%d, %v", count, batch[0].N, batchErr)
	}
	var batchMessage IPv4ControlMessage
	if err = batchMessage.Parse(batch[0].OOB[:batch[0].NN]); err != nil || batchMessage.Dst != group || !bytes.Equal(batch[0].OOB[20:24], local.AsSlice()) || !bytes.Equal(batch[0].OOB[24:28], group.AsSlice()) {
		t.Fatalf("multicast batch packet-info = %+v, %v, fields %x/%x", batchMessage, err, batch[0].OOB[20:24], batch[0].OOB[24:28])
	}
	rawNet, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	raw := rawNet.(*IPConn)
	defer raw.Close()
	if err = raw.JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	if _, err = stack.Write([][]byte{buildIPPacket(remote, group, 99, []byte("multicast-raw"), 2, true)}, 0); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rawPayload, rawOOB := make([]byte, 64), make([]byte, 128)
	rawN, rawOOBN, rawFlags, rawSource, err := raw.ReadMsgIP(rawPayload, rawOOB)
	if err != nil || rawFlags != 0 || string(rawPayload[:rawN]) != "multicast-raw" || rawSource.String() != remote.String() {
		t.Fatalf("multicast raw ReadMsgIP = %q/%d flags %#x source %v, %v", rawPayload[:rawN], rawOOBN, rawFlags, rawSource, err)
	}
	var rawMessage IPv4ControlMessage
	if err = rawMessage.Parse(rawOOB[:rawOOBN]); err != nil || rawMessage.Dst != group {
		t.Fatalf("multicast raw packet-info = %+v, %v, want destination %s", rawMessage, err, group)
	}
	if rawOOBN < 28 || !bytes.Equal(rawOOB[20:24], local.AsSlice()) || !bytes.Equal(rawOOB[24:28], group.AsSlice()) {
		t.Fatalf("multicast raw packet-info fields = %x/%x, want %s/%s", rawOOB[20:24], rawOOB[24:28], local, group)
	}
}

func TestIPv6InterfaceLocalMulticastStaysInsideHost(t *testing.T) {
	group := netip.MustParseAddr("ff01::1234")
	remote := netip.MustParseAddr("2001:db8::31")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::30/64")}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 43003))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	time.Sleep(10 * time.Millisecond)
	if entry, ok := stack.outbound.tryDequeue(); ok {
		packet := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("interface-local join emitted link traffic: %x", packet)
	}
	if _, err = stack.Write([][]byte{buildTestUDP(remote, group, 53003, 43003, []byte("external"))}, 0); err != nil {
		t.Fatal(err)
	}
	expectMulticastTestUDPTimeout(t, connection)
	udp := make([]byte, udpHeaderSize+32)
	binary.BigEndian.PutUint16(udp[0:2], 53003)
	binary.BigEndian.PutUint16(udp[2:4], 43003)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], transportChecksum(remote, group, ProtocolUDP, udp))
	fragments := buildIPv6FragmentsWithOptions(remote, group, ProtocolUDP, udp, 64, 0x1234, ipPacketOptions{})
	if len(fragments) < 2 {
		t.Fatal("interface-local test datagram did not fragment")
	}
	if _, err = stack.Write([][]byte{fragments[0]}, 0); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	retainedFragments := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if retainedFragments != 0 {
		t.Fatalf("external interface-local fragment sets = %d, want 0", retainedFragments)
	}
	if err = connection.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("interface-local"), netip.AddrPortFrom(group, 43003)); err != nil {
		t.Fatal(err)
	}
	readMulticastTestUDP(t, connection, "interface-local")
	fragmentedPayload := make([]byte, 2000)
	for index := range fragmentedPayload {
		fragmentedPayload[index] = byte(index)
	}
	if _, err = connection.WriteToUDPAddrPort(fragmentedPayload, netip.AddrPortFrom(group, 43003)); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(fragmentedPayload))
	n, _, err := connection.ReadFromUDPAddrPort(received)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(fragmentedPayload) || !bytes.Equal(received, fragmentedPayload) {
		t.Fatalf("fragmented interface-local payload length = %d, want %d", n, len(fragmentedPayload))
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		packet := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("interface-local datagram escaped to link: %x", packet)
	}
}

func TestIPv6ReservedMulticastScopeIsRejected(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::32/64")}, 1400)
	packet, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	defer connection.Close()
	for _, address := range []string{"ff00::1234", "ff0f::1234"} {
		reserved := netip.MustParseAddr(address)
		if _, err = stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(reserved, 43004)); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("ListenMulticastUDP reserved scope %s = %v, want EINVAL", address, err)
		}
		if err = connection.JoinGroup(reserved); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("JoinGroup reserved scope %s = %v, want EINVAL", address, err)
		}
		if _, err = connection.WriteToUDPAddrPort([]byte("reserved"), netip.AddrPortFrom(reserved, 43004)); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("multicast output to reserved scope %s = %v, want EINVAL", address, err)
		}
	}
}

func TestIPv6MulticastAddressFormatValidation(t *testing.T) {
	for _, address := range []string{
		"ff12::1",
		"ff32::1",
		"ff72:0140:2001:db8::1",
		"ff32:0100::1",
	} {
		if !validMulticastGroup(netip.MustParseAddr(address)) {
			t.Fatalf("valid IPv6 multicast address %s was rejected", address)
		}
	}
	for _, address := range []string{
		"ff00::1",
		"ff0f::1",
		"ff22::1",
		"ff52::1",
		"ff82::1",
	} {
		if validMulticastGroup(netip.MustParseAddr(address)) {
			t.Fatalf("malformed IPv6 multicast address %s was accepted", address)
		}
	}
}

func TestMulticastReportWireFields(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.40/24")}, 1400)
	group := netip.MustParseAddr("239.10.20.30")
	packet, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 44000))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	report := nextMulticastTestPacket(t, stack, func(candidate ipPacket) bool {
		return candidate.protocol == 2 && len(candidate.payload) >= 16 && candidate.payload[0] == igmpV3MembershipReport
	})
	if report.target != netip.MustParseAddr("224.0.0.22") || checksum(report.payload) != 0 {
		t.Fatalf("IGMPv3 report destination/checksum = %s/%#x", report.target, checksum(report.payload))
	}
	if binary.BigEndian.Uint16(report.original[6:8])&0x4000 == 0 {
		t.Fatal("IGMPv3 report did not set IPv4 DF")
	}
	if count := binary.BigEndian.Uint16(report.payload[6:8]); count != 1 {
		t.Fatalf("IGMPv3 group record count = %d, want 1", count)
	}
	if report.payload[8] != multicastRecordChangeToExcludeMode || netip.AddrFrom4([4]byte(report.payload[12:16])) != group {
		t.Fatalf("IGMPv3 initial record = %x", report.payload[8:16])
	}
}

func TestMulticastReportKnownAnswerVectors(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.40/24"),
		netip.MustParsePrefix("fe80::40/64"),
	}, 1400)
	state := &multicastState{stack: stack}
	group4 := netip.MustParseAddr("239.10.20.30")
	group6 := netip.MustParseAddr("ff02::1234")
	tests := []struct {
		name   string
		wire   string
		target netip.Addr
		send   func()
	}{
		{name: "IGMPv1 report", wire: "1200ead6ef0a141e", target: group4,
			send: func() { state.sendIGMPLegacyReport(group4, 1, true, false, nil) }},
		{name: "IGMPv2 report", wire: "1600e6d6ef0a141e", target: group4,
			send: func() { state.sendIGMPLegacyReport(group4, 2, true, false, nil) }},
		{name: "IGMPv2 leave", wire: "1700e5d6ef0a141e", target: netip.MustParseAddr("224.0.0.2"),
			send: func() { state.sendIGMPLegacyReport(group4, 2, false, true, nil) }},
		{name: "IGMPv3 report", wire: "2200d6d50000000104000000ef0a141e", target: netip.MustParseAddr("224.0.0.22"),
			send: func() {
				state.sendIGMPv3Records([]multicastReportRecord{{recordType: multicastRecordChangeToExcludeMode, group: group4}}, nil)
			}},
		{name: "MLDv1 report", wire: "83005b7e00000000ff020000000000000000000000001234", target: group6,
			send: func() { state.sendMLDv1Report(group6, true, false, nil) }},
		{name: "MLDv1 done", wire: "84006cb000000000ff020000000000000000000000001234", target: netip.MustParseAddr("ff02::2"),
			send: func() { state.sendMLDv1Report(group6, false, true, nil) }},
		{name: "MLDv2 report", wire: "8f005d970000000104000000ff020000000000000000000000001234", target: netip.MustParseAddr("ff02::16"),
			send: func() {
				state.sendMLDv2Records([]multicastReportRecord{{recordType: multicastRecordChangeToExcludeMode, group: group6}}, nil)
			}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.send()
			packet := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool { return packet.target == test.target })
			want := mustCodecVector(t, test.wire)
			if packet.hopLimit != 1 || !packet.hasRouterAlert() || !bytes.Equal(packet.payload, want) {
				t.Fatalf("report = target %s hop-limit %d router-alert %t payload %x, want %s/1/true/%x",
					packet.target, packet.hopLimit, packet.hasRouterAlert(), packet.payload, test.target, want)
			}
			if packet.source.Is4() {
				if packet.source != netip.MustParseAddr("192.0.2.40") || referenceChecksum(packet.payload) != 0 {
					t.Fatalf("IGMP report source/checksum = %s/%#x", packet.source, referenceChecksum(packet.payload))
				}
			} else if packet.source != netip.MustParseAddr("fe80::40") ||
				referenceTransportChecksum(packet.source, packet.target, ProtocolICMPv6, packet.payload) != 0 {
				t.Fatalf("MLD report source/checksum = %s/%#x", packet.source,
					referenceTransportChecksum(packet.source, packet.target, ProtocolICMPv6, packet.payload))
			}
		})
	}
}

func TestBroadcastAndMulticastFragmentReassembly(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.51")
	broadcast := netip.MustParseAddr("192.0.2.255")
	group := netip.MustParseAddr("239.50.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.50/24")}, 300)

	broadcastPacket, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:45000"))
	if err != nil {
		t.Fatal(err)
	}
	defer broadcastPacket.Close()
	broadcastConn := multicastTestUDP(t, broadcastPacket)
	multicastPacket, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 45001))
	if err != nil {
		t.Fatal(err)
	}
	defer multicastPacket.Close()
	drainMulticastTestOutput(stack)

	for _, test := range []struct {
		name       string
		target     netip.Addr
		targetPort uint16
		connection *UDPConn
	}{
		{name: "broadcast", target: broadcast, targetPort: 45000, connection: broadcastConn},
		{name: "multicast", target: group, targetPort: 45001, connection: multicastPacket},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, 900)
			for index := range payload {
				payload[index] = byte(index)
			}
			udp := make([]byte, udpHeaderSize+len(payload))
			marshalUDPDatagram(udp, remote, test.target, 55000, test.targetPort, payload)
			fragments := buildIPv4FragmentsWithOptions(remote, test.target, ProtocolUDP, udp, 180, 0x1234, ipPacketOptions{hopLimit: 1})
			if len(fragments) < 2 {
				t.Fatal("test datagram did not fragment")
			}
			for index := len(fragments) - 1; index >= 0; index-- {
				if _, err := stack.Write([][]byte{fragments[index]}, 0); err != nil {
					t.Fatal(err)
				}
			}
			if err := test.connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(payload))
			n, _, err := test.connection.ReadFromUDPAddrPort(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(payload) {
				t.Fatalf("reassembled payload length = %d, want %d", n, len(payload))
			}
			for index := range payload {
				if buffer[index] != payload[index] {
					t.Fatalf("reassembled byte %d = %d, want %d", index, buffer[index], payload[index])
				}
			}
		})
	}
}

func TestFragmentedMulticastOutputReachesLinkAndLoopback(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.54")
	peer := netip.MustParseAddr("192.0.2.55")
	group := netip.MustParseAddr("239.54.0.1")
	sender := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(source, 24)}, 300)
	receiver := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(peer, 24)}, 300)
	localPacket, err := sender.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 45400))
	if err != nil {
		t.Fatal(err)
	}
	defer localPacket.Close()
	remotePacket, err := receiver.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 45400))
	if err != nil {
		t.Fatal(err)
	}
	defer remotePacket.Close()
	outputPacket, err := sender.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer outputPacket.Close()
	output := multicastTestUDP(t, outputPacket)
	if err = output.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if err = output.SetMulticastHopLimit(5); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(sender)
	clearMulticastTestControl(receiver)
	payload := make([]byte, 900)
	for index := range payload {
		payload[index] = byte(index)
	}
	if _, err = output.WriteToUDPAddrPort(payload, netip.AddrPortFrom(group, 45400)); err != nil {
		t.Fatal(err)
	}
	if from := readMulticastTestUDP(t, localPacket, string(payload)); from.Addr() != source {
		t.Fatalf("fragmented multicast loopback source = %s, want %s", from, source)
	}
	fragments := 0
	for {
		wire := readOutboundPacket(t, sender)
		fragment, valid := parseFragment(wire, false)
		if !valid || fragment.source != source || fragment.target != group || fragment.protocol != ProtocolUDP {
			t.Fatalf("invalid outbound multicast fragment: %x", wire)
		}
		if wire[8] != 5 || len(wire) > 300 {
			t.Fatalf("multicast fragment hop/size = %d/%d", wire[8], len(wire))
		}
		fragments++
		if _, err = receiver.Write([][]byte{wire}, 0); err != nil {
			t.Fatal(err)
		}
		if !fragment.more {
			break
		}
	}
	if fragments < 2 {
		t.Fatalf("fragmented multicast output used %d packet", fragments)
	}
	if from := readMulticastTestUDP(t, remotePacket, string(payload)); from.Addr() != source {
		t.Fatalf("fragmented multicast link source = %s, want %s", from, source)
	}
}

func TestMulticastRawSocketAndNoBroadcastAmplification(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.61")
	group := netip.MustParseAddr("239.61.0.1")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.60/24")}, 1400)
	raw, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = raw.(*IPConn).JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	drainMulticastTestOutput(stack)
	if _, err = stack.Write([][]byte{buildIPPacket(remote, group, 99, []byte("raw-multicast"), 1, false)}, 0); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, source, err := raw.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "raw-multicast" || source.String() != remote.String() {
		t.Fatalf("raw multicast = %q from %v", buffer[:n], source)
	}

	drainMulticastTestOutput(stack)
	echo := make([]byte, 16)
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[4:6], 1)
	binary.BigEndian.PutUint16(echo[6:8], 2)
	binary.BigEndian.PutUint16(echo[2:4], checksum(echo))
	if _, err = stack.Write([][]byte{buildIPPacket(remote, broadcast, ProtocolICMPv4, echo, 1, false)}, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	for {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			break
		}
		wire := consumeTestPacket(&stack.outbound, entry)
		candidate, valid := parseIPPacket(wire, false)
		if valid && candidate.protocol == ProtocolICMPv4 && len(candidate.payload) != 0 && candidate.payload[0] == 0 {
			t.Fatal("broadcast Echo Request caused an amplified Echo Reply")
		}
	}
}

func TestRawIPMulticastMembershipAndSocketOptions(t *testing.T) {
	group := netip.MustParseAddr("239.62.0.1")
	source1 := netip.MustParseAddr("192.0.2.63")
	source2 := netip.MustParseAddr("192.0.2.64")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.62/24")}, 1400)
	raw, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	if broadcast, err := raw.(*IPConn).Broadcast(); err != nil || !broadcast {
		t.Fatalf("raw Broadcast() = %t, %v", broadcast, err)
	}
	if hopLimit, err := raw.(*IPConn).MulticastHopLimit(); err != nil || hopLimit != 1 {
		t.Fatalf("raw MulticastHopLimit() = %d, %v", hopLimit, err)
	}
	if loopback, err := raw.(*IPConn).MulticastLoopback(); err != nil || !loopback {
		t.Fatalf("raw MulticastLoopback() = %t, %v", loopback, err)
	}
	if err = raw.(*IPConn).SetBroadcast(false); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastHopLimit(7); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastLoopback(false); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).JoinSourceSpecificGroup(group, source1); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).JoinSourceSpecificGroup(group, source1); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("duplicate raw SSM join = %v, want EADDRINUSE", err)
	}
	if err = raw.(*IPConn).ExcludeSourceSpecificGroup(group, source2); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("exclude on raw INCLUDE membership = %v, want EINVAL", err)
	}
	if err = raw.(*IPConn).JoinSourceSpecificGroup(group, source2); err != nil {
		t.Fatal(err)
	}
	filter, err := raw.(*IPConn).MulticastSourceFilter(group)
	if err != nil || filter.Mode != MulticastSourceFilterInclude || len(filter.Sources) != 2 || filter.Sources[0] != source1 || filter.Sources[1] != source2 {
		t.Fatalf("raw INCLUDE filter = %+v, %v", filter, err)
	}
	if err = raw.(*IPConn).LeaveSourceSpecificGroup(group, source2); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).LeaveSourceSpecificGroup(group, source1); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).ExcludeSourceSpecificGroup(group, source1); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).IncludeSourceSpecificGroup(group, source1); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude, Sources: []netip.Addr{source2}}); err != nil {
		t.Fatal(err)
	}
	filter, err = raw.(*IPConn).MulticastSourceFilter(group)
	if err != nil || filter.Mode != MulticastSourceFilterExclude || len(filter.Sources) != 1 || filter.Sources[0] != source2 {
		t.Fatalf("raw EXCLUDE filter = %+v, %v", filter, err)
	}
	if err = raw.(*IPConn).LeaveGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.(*IPConn).MulticastSourceFilter(group); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed raw source filter = %v, want net.ErrClosed", err)
	}
}

func TestRawIPMulticastAndBroadcastOutput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.64")
	group := netip.MustParseAddr("239.64.0.1")
	broadcast := netip.MustParseAddr("192.0.2.255")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.64/24")}, 1400)
	raw, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = raw.(*IPConn).JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastHopLimit(3); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	if _, err = raw.WriteTo([]byte("raw-multicast-output"), ipNetAddr(group)); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, source, err := raw.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "raw-multicast-output" || source.String() != local.String() {
		t.Fatalf("raw multicast loopback = %q from %v, %v", buffer[:n], source, err)
	}
	outbound := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 99 && packet.target == group
	})
	if outbound.source != local || outbound.hopLimit != 3 {
		t.Fatalf("raw multicast output = %s -> %s hop %d", outbound.source, outbound.target, outbound.hopLimit)
	}
	if err = raw.(*IPConn).SetBroadcast(false); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.WriteTo([]byte("denied"), ipNetAddr(broadcast)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("raw broadcast without SO_BROADCAST = %v, want EACCES", err)
	}
	if err = raw.(*IPConn).SetBroadcast(true); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.WriteTo([]byte("raw-broadcast-output"), ipNetAddr(broadcast)); err != nil {
		t.Fatal(err)
	}
	outbound = nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 99 && packet.target == broadcast
	})
	if outbound.source != local || outbound.hopLimit != 64 {
		t.Fatalf("raw broadcast output = %s -> %s hop %d", outbound.source, outbound.target, outbound.hopLimit)
	}
}

func TestRawIPNoOutputMulticastStillValidatesPayloadSize(t *testing.T) {
	local := netip.MustParseAddr("fe80::6400")
	group := netip.MustParseAddr("ff01::6400")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	raw, err := stack.ListenIP(context.Background(), "ip6:99", netip.IPv6Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = raw.(*IPConn).SetMulticastLoopback(false); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.WriteTo(make([]byte, 65536), ipNetAddr(group)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized host-local multicast payload = %v, want EMSGSIZE", err)
	}
}

func TestIPv6MulticastUnknownOptionParameterProblem(t *testing.T) {
	local := netip.MustParseAddr("fe80::65")
	remote := netip.MustParseAddr("fe80::66")
	group := netip.MustParseAddr("ff02::6500")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 46500))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	clearMulticastTestControl(stack)
	packet := make([]byte, 56)
	packet[0], packet[6], packet[7] = 0x60, 0, 64
	binary.BigEndian.PutUint16(packet[4:6], 16)
	copy(packet[8:24], remote.AsSlice())
	copy(packet[24:40], group.AsSlice())
	copy(packet[40:48], []byte{ProtocolUDP, 0, 0x80, 0, 1, 0, 0, 0})
	if _, err = stack.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	response := nextMulticastTestPacket(t, stack, func(candidate ipPacket) bool {
		return candidate.protocol == ProtocolICMPv6 && candidate.target == remote && len(candidate.payload) >= 8 && candidate.payload[0] == 4
	})
	if response.source != local || response.payload[1] != 2 || binary.BigEndian.Uint32(response.payload[4:8]) != 42 {
		t.Fatalf("multicast Parameter Problem = source %s type/code %d/%d pointer %d", response.source, response.payload[0], response.payload[1], binary.BigEndian.Uint32(response.payload[4:8]))
	}
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{netip.MustParseAddr("fe80::67")}}); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	if _, err = stack.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if entry, ok := stack.outbound.tryDequeue(); ok {
		output := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("source-filtered Parameter Problem produced output: %x", output)
	}
}

func TestIPv6AllNodesEchoUsesUnicastReplySource(t *testing.T) {
	local := netip.MustParseAddr("fe80::67")
	remote := netip.MustParseAddr("fe80::68")
	allNodes := netip.MustParseAddr("ff02::1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	echo := make([]byte, 16)
	echo[0] = 128
	binary.BigEndian.PutUint16(echo[4:6], 0x1234)
	binary.BigEndian.PutUint16(echo[6:8], 7)
	binary.BigEndian.PutUint16(echo[2:4], transportChecksum(remote, allNodes, ProtocolICMPv6, echo))
	request := buildIPPacket(remote, allNodes, ProtocolICMPv6, echo, 1, false)
	if _, err := stack.Write([][]byte{request}, 0); err != nil {
		t.Fatal(err)
	}
	reply := nextMulticastTestPacket(t, stack, func(candidate ipPacket) bool {
		return candidate.protocol == ProtocolICMPv6 && candidate.target == remote && len(candidate.payload) >= 8 && candidate.payload[0] == 129
	})
	if reply.source != local || transportChecksum(reply.source, reply.target, ProtocolICMPv6, reply.payload) != 0 {
		t.Fatalf("multicast Echo Reply = source %s checksum %#x", reply.source, transportChecksum(reply.source, reply.target, ProtocolICMPv6, reply.payload))
	}
}

func TestIPv6MulticastEchoDoesNotFailInputWhenOutputIsFull(t *testing.T) {
	local := netip.MustParseAddr("fe80::69")
	remote := netip.MustParseAddr("fe80::6a")
	allNodes := netip.MustParseAddr("ff02::1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	dummy := buildIPPacket(local, remote, ProtocolUDP, nil, 1, false)
	fillTestPacketQueue(t, &stack.outbound, dummy)
	echo := make([]byte, 8)
	echo[0] = 128
	binary.BigEndian.PutUint16(echo[2:4], transportChecksum(remote, allNodes, ProtocolICMPv6, echo))
	request := buildIPPacket(remote, allNodes, ProtocolICMPv6, echo, 1, false)
	if _, err := stack.Write([][]byte{request}, 0); err != nil {
		t.Fatalf("multicast Echo input inherited control-output congestion: %v", err)
	}
}

func TestFragmentMembershipRemovalPrunesState(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.71")
	group := netip.MustParseAddr("239.71.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.70/24")}, 1400)
	packet, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 47000))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	udp := make([]byte, 800)
	marshalUDPDatagram(udp, remote, group, 57000, 47000, udp[udpHeaderSize:])
	fragments := buildIPv4FragmentsWithOptions(remote, group, ProtocolUDP, udp, 200, 0x7171, ipPacketOptions{hopLimit: 1})
	if _, err = stack.Write([][]byte{fragments[0]}, 0); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	retained := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if retained != 1 {
		t.Fatalf("retained fragment sets = %d, want 1", retained)
	}
	if err = packet.LeaveGroup(group); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	retained = len(stack.fragments)
	stack.fragmentMu.Unlock()
	if retained != 0 {
		t.Fatalf("fragment sets after leave = %d, want 0", retained)
	}
}

func TestMulticastSourceFilterFanoutAndSnapshot(t *testing.T) {
	group := netip.MustParseAddr("239.80.0.1")
	source1 := netip.MustParseAddr("192.0.2.81")
	source2 := netip.MustParseAddr("192.0.2.82")
	source3 := netip.MustParseAddr("192.0.2.83")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.80/24")}, 1400)
	first, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 48000))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 48000))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = first.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{source1}}); err != nil {
		t.Fatal(err)
	}
	if err = second.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude, Sources: []netip.Addr{source2}}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := first.MulticastSourceFilter(group)
	if err != nil || snapshot.Mode != MulticastSourceFilterInclude || len(snapshot.Sources) != 1 || snapshot.Sources[0] != source1 {
		t.Fatalf("source filter snapshot = %#v, %v", snapshot, err)
	}
	snapshot.Sources[0] = source3
	again, err := first.MulticastSourceFilter(group)
	if err != nil || again.Sources[0] != source1 {
		t.Fatalf("source filter aliased caller memory: %#v, %v", again, err)
	}

	write := func(source netip.Addr, payload string) {
		t.Helper()
		if _, writeErr := stack.Write([][]byte{buildTestUDP(source, group, 58000, 48000, []byte(payload))}, 0); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	write(source1, "source-one")
	readMulticastTestUDP(t, first, "source-one")
	readMulticastTestUDP(t, second, "source-one")
	write(source2, "source-two")
	expectMulticastTestUDPTimeout(t, first)
	expectMulticastTestUDPTimeout(t, second)
	write(source3, "source-three")
	expectMulticastTestUDPTimeout(t, first)
	readMulticastTestUDP(t, second, "source-three")

	stack.mu.RLock()
	state := stack.multicast.(*multicastState)
	state.mu.Lock()
	aggregate := cloneMulticastFilter(state.groups[group].aggregate)
	state.mu.Unlock()
	stack.mu.RUnlock()
	if aggregate.mode != multicastFilterExclude || len(aggregate.sources) != 1 {
		t.Fatalf("aggregate filter = mode %d sources %v", aggregate.mode, aggregate.sources)
	}
	if _, blocked := aggregate.sources[source2]; !blocked {
		t.Fatalf("aggregate EXCLUDE set = %v, want %s", aggregate.sources, source2)
	}

	if err = first.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude}); err != nil {
		t.Fatal(err)
	}
	if _, err = first.MulticastSourceFilter(group); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("empty INCLUDE getter = %v, want EADDRNOTAVAIL", err)
	}
}

func TestMulticastSourceFilterModesMatchLinux(t *testing.T) {
	if MulticastSourceFilterExclude != 0 || MulticastSourceFilterInclude != 1 {
		t.Fatalf("source-filter modes = EXCLUDE %d INCLUDE %d, want Linux MCAST_EXCLUDE 0 and MCAST_INCLUDE 1", MulticastSourceFilterExclude, MulticastSourceFilterInclude)
	}
}

func TestSourceSpecificMulticastRejectsAnySourceOperations(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.110/24"),
		netip.MustParsePrefix("fe80::110/64"),
	}, 1400)
	for _, test := range []struct {
		network string
		local   netip.AddrPort
		group   netip.Addr
		source  netip.Addr
	}{
		{"udp4", netip.MustParseAddrPort("0.0.0.0:43125"), netip.MustParseAddr("232.1.2.3"), netip.MustParseAddr("192.0.2.111")},
		{"udp6", netip.MustParseAddrPort("[::]:43126"), netip.MustParseAddr("ff32::8000:1234"), netip.MustParseAddr("fe80::111")},
	} {
		packet, err := stack.ListenUDP(context.Background(), test.network, test.local)
		if err != nil {
			t.Fatal(err)
		}
		connection := multicastTestUDP(t, packet)
		if err = connection.JoinGroup(test.group); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("%s any-source join = %v, want EINVAL", test.group, err)
		}
		if err = connection.SetMulticastSourceFilter(test.group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude}); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("%s EXCLUDE filter = %v, want EINVAL", test.group, err)
		}
		if err = connection.JoinSourceSpecificGroup(test.group, test.source); err != nil {
			t.Fatalf("%s source-specific join: %v", test.group, err)
		}
		if err = connection.ExcludeSourceSpecificGroup(test.group, test.source); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("%s EXCLUDE delta = %v, want EINVAL", test.group, err)
		}
		if err = connection.LeaveSourceSpecificGroup(test.group, test.source); err != nil {
			t.Fatalf("%s source-specific leave: %v", test.group, err)
		}
		_ = connection.Close()
	}
}

func TestIPv6PrefixBasedMulticastIsNotSourceSpecific(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.MustParsePrefix("fe80::110/64"),
	}, 1400)
	group := netip.MustParseAddr("ff32:0100::1")
	source := netip.MustParseAddr("fe80::111")
	packet, err := stack.ListenUDP(context.Background(), "udp6", netip.MustParseAddrPort("[::]:43129"))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	defer connection.Close()
	if err = connection.JoinGroup(group); err != nil {
		t.Fatalf("prefix-based ASM join: %v", err)
	}
	if err = connection.ExcludeSourceSpecificGroup(group, source); err != nil {
		t.Fatalf("prefix-based ASM EXCLUDE delta: %v", err)
	}
	filter, err := connection.MulticastSourceFilter(group)
	if err != nil {
		t.Fatal(err)
	}
	if filter.Mode != MulticastSourceFilterExclude || len(filter.Sources) != 1 || filter.Sources[0] != source {
		t.Fatalf("prefix-based ASM filter = %+v", filter)
	}
}

func TestSourceSpecificMulticastReportCannotBeSuppressed(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.112/24"),
		netip.MustParsePrefix("fe80::112/64"),
	}, 1400)
	for _, test := range []struct {
		network string
		local   netip.AddrPort
		group   netip.Addr
		source  netip.Addr
	}{
		{"udp4", netip.MustParseAddrPort("0.0.0.0:43127"), netip.MustParseAddr("232.2.3.4"), netip.MustParseAddr("192.0.2.113")},
		{"udp6", netip.MustParseAddrPort("[::]:43128"), netip.MustParseAddr("ff32::8000:2345"), netip.MustParseAddr("fe80::113")},
	} {
		packet, err := stack.ListenUDP(context.Background(), test.network, test.local)
		if err != nil {
			t.Fatal(err)
		}
		connection := multicastTestUDP(t, packet)
		if err = connection.JoinSourceSpecificGroup(test.group, test.source); err != nil {
			t.Fatal(err)
		}
		state := stack.multicast.(*multicastState)
		state.mu.Lock()
		groupState := state.groups[test.group]
		groupState.query = multicastPendingQuery{deadline: time.Now().Add(time.Minute)}
		groupState.lastReporter = true
		state.compatibility[multicastFamilyIndex(test.group)] = 1
		if test.group.Is6() {
			state.mldV1Until = time.Now().Add(time.Minute)
		} else {
			state.igmpV1Until = time.Now().Add(time.Minute)
		}
		state.mu.Unlock()
		state.heardLegacyReport(test.group)
		state.mu.Lock()
		queryPending := !groupState.query.deadline.IsZero()
		lastReporter := groupState.lastReporter
		state.mu.Unlock()
		if !queryPending || !lastReporter {
			t.Fatalf("legacy report suppressed SSM group %s: query=%v reporter=%v", test.group, queryPending, lastReporter)
		}
		_ = connection.Close()
	}
}

func TestMulticastConfigUpdateRemovesSourcesThatBecomeBroadcast(t *testing.T) {
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("198.51.100.114/25")}, 1400)
	includeGroup := netip.MustParseAddr("239.114.0.1")
	excludeGroup := netip.MustParseAddr("239.114.0.2")
	source := netip.MustParseAddr("198.51.100.255")
	includePacket, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:43129"))
	if err != nil {
		t.Fatal(err)
	}
	include := multicastTestUDP(t, includePacket)
	defer include.Close()
	if err = include.JoinSourceSpecificGroup(includeGroup, source); err != nil {
		t.Fatal(err)
	}
	excludePacket, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:43130"))
	if err != nil {
		t.Fatal(err)
	}
	exclude := multicastTestUDP(t, excludePacket)
	defer exclude.Close()
	if err = exclude.JoinGroup(excludeGroup); err != nil {
		t.Fatal(err)
	}
	if err = exclude.ExcludeSourceSpecificGroup(excludeGroup, source); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.114/24")}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = include.MulticastSourceFilter(includeGroup); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("INCLUDE membership after source became broadcast = %v, want EADDRNOTAVAIL", err)
	}
	filter, err := exclude.MulticastSourceFilter(excludeGroup)
	if err != nil {
		t.Fatal(err)
	}
	if filter.Mode != MulticastSourceFilterExclude || len(filter.Sources) != 0 {
		t.Fatalf("EXCLUDE filter after source became broadcast = %+v", filter)
	}
}

func TestMulticastSocketOptionAndMembershipState(t *testing.T) {
	group := netip.MustParseAddr("239.88.0.1")
	source := netip.MustParseAddr("192.0.2.88")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.87/24")}, 1400)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	packet, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:48800"))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude}); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("empty INCLUDE on a fresh stack = %v, want EADDRNOTAVAIL", err)
	}
	stack.mu.RLock()
	createdMulticastState := stack.multicast != nil
	stack.mu.RUnlock()
	if createdMulticastState {
		t.Fatal("failed full-state filter created multicast background state")
	}
	if enabled, getErr := connection.Broadcast(); getErr != nil || !enabled {
		t.Fatalf("default broadcast = %v, %v", enabled, getErr)
	}
	if enabled, getErr := connection.MulticastLoopback(); getErr != nil || !enabled {
		t.Fatalf("default multicast loopback = %v, %v", enabled, getErr)
	}
	if hopLimit, getErr := connection.MulticastHopLimit(); getErr != nil || hopLimit != 1 {
		t.Fatalf("default multicast hop limit = %d, %v", hopLimit, getErr)
	}
	if err = connection.SetMulticastHopLimit(256); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("invalid multicast hop limit = %v, want EINVAL", err)
	}
	if err = connection.JoinGroup(netip.MustParseAddr("ff02::1")); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("cross-family group join = %v, want EAFNOSUPPORT", err)
	}
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("full-state filter without prior join = %v, want EINVAL", err)
	}
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude}); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("empty INCLUDE without prior join = %v, want EADDRNOTAVAIL", err)
	}
	if err = connection.JoinSourceSpecificGroup(group, source); err != nil {
		t.Fatal(err)
	}
	if err = connection.JoinSourceSpecificGroup(group, source); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("duplicate source join = %v, want EADDRINUSE", err)
	}
	if err = connection.ExcludeSourceSpecificGroup(group, source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("EXCLUDE operation in INCLUDE mode = %v, want EINVAL", err)
	}
	if err = connection.LeaveSourceSpecificGroup(group, source); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.MulticastSourceFilter(group); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("filter after final source leave = %v, want EADDRNOTAVAIL", err)
	}
	if err = connection.JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = connection.ExcludeSourceSpecificGroup(group, source); err != nil {
		t.Fatal(err)
	}
	if err = connection.IncludeSourceSpecificGroup(group, source); err != nil {
		t.Fatal(err)
	}
	if err = connection.IncludeSourceSpecificGroup(group, source); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("removing a missing source block = %v, want EADDRNOTAVAIL", err)
	}
	if err = connection.LeaveGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Broadcast(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("broadcast getter after close = %v, want net.ErrClosed", err)
	}
	if err = connection.JoinGroup(group); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("group join after close = %v, want net.ErrClosed", err)
	}
}

func TestMulticastInterfaceFilterAppliesToICMPv6(t *testing.T) {
	local := netip.MustParseAddr("fe80::89")
	allowed := netip.MustParseAddr("fe80::8a")
	blocked := netip.MustParseAddr("fe80::8b")
	group := netip.MustParseAddr("ff02::8900")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 48900))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{allowed}}); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	echoRequest := func(source netip.Addr) []byte {
		payload := make([]byte, 8)
		payload[0] = 128
		binary.BigEndian.PutUint16(payload[4:6], 0x8900)
		binary.BigEndian.PutUint16(payload[2:4], transportChecksum(source, group, ProtocolICMPv6, payload))
		return buildIPPacket(source, group, ProtocolICMPv6, payload, 1, false)
	}
	if _, err = stack.Write([][]byte{echoRequest(blocked)}, 0); err != nil {
		t.Fatal(err)
	}
	expectNoMulticastTestPacket(t, stack, 25*time.Millisecond, func(packet ipPacket) bool {
		return packet.protocol == ProtocolICMPv6 && packet.target == blocked && len(packet.payload) >= 8 && packet.payload[0] == 129
	})
	if _, err = stack.Write([][]byte{echoRequest(allowed)}, 0); err != nil {
		t.Fatal(err)
	}
	reply := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == ProtocolICMPv6 && packet.target == allowed && len(packet.payload) >= 8 && packet.payload[0] == 129
	})
	if reply.source != local {
		t.Fatalf("allowed multicast Echo Reply source = %s, want %s", reply.source, local)
	}
}

func TestIGMPv3QueryCurrentStateAndRouterAlert(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.90")
	querier := netip.MustParseAddr("192.0.2.91")
	group := netip.MustParseAddr("239.90.0.1")
	source1 := netip.MustParseAddr("192.0.2.92")
	source2 := netip.MustParseAddr("192.0.2.93")
	source3 := netip.MustParseAddr("192.0.2.94")
	allHosts := netip.MustParseAddr("224.0.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 49000))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{source1, source2}}); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)

	general := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 0, []netip.Addr{}, true)
	if _, err = stack.Write([][]byte{general}, 0); err != nil {
		t.Fatal(err)
	}
	report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 2 && len(packet.payload) >= 16 && packet.payload[0] == igmpV3MembershipReport && packet.payload[8] == multicastRecordModeIsInclude
	})
	records := multicastTestReportRecords(t, report)
	if len(records) != 1 || records[0].group != group || len(records[0].sources) != 2 || records[0].sources[0] != source1 || records[0].sources[1] != source2 {
		t.Fatalf("general-query records = %#v", records)
	}

	query := buildMulticastTestIGMPQuery(querier, group, group, 0, []netip.Addr{source2, source3}, true)
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	report = nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 2 && len(packet.payload) >= 16 && packet.payload[0] == igmpV3MembershipReport && packet.payload[8] == multicastRecordModeIsInclude
	})
	records = multicastTestReportRecords(t, report)
	if len(records) != 1 || len(records[0].sources) != 1 || records[0].sources[0] != source2 {
		t.Fatalf("INCLUDE source-query records = %#v", records)
	}

	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude, Sources: []netip.Addr{source1}}); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	query = buildMulticastTestIGMPQuery(querier, group, group, 0, []netip.Addr{source1, source2, source3}, true)
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	report = nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 2 && len(packet.payload) >= 16 && packet.payload[0] == igmpV3MembershipReport && packet.payload[8] == multicastRecordModeIsInclude
	})
	records = multicastTestReportRecords(t, report)
	if len(records) != 1 || len(records[0].sources) != 2 || records[0].sources[0] != source2 || records[0].sources[1] != source3 {
		t.Fatalf("EXCLUDE source-query records = %#v", records)
	}

	clearMulticastTestControl(stack)
	withoutAlert := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 0, []netip.Addr{}, false)
	if _, err = stack.Write([][]byte{withoutAlert}, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if entry, ok := stack.outbound.tryDequeue(); ok {
		packet := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("query without Router Alert produced output: %x", packet)
	}
}

func TestMulticastQueryValidationAndDefaultVariables(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.96")
	remote4 := netip.MustParseAddr("192.0.2.97")
	group4 := netip.MustParseAddr("239.96.0.1")
	local6 := netip.MustParseAddr("fe80::96")
	remote6 := netip.MustParseAddr("fe80::97")
	group6 := netip.MustParseAddr("ff02::9600")
	stack := newMulticastTestStack(t, []netip.Prefix{
		netip.PrefixFrom(local4, 24),
		netip.PrefixFrom(local6, 64),
	}, 1400)
	packet4, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group4, 49600))
	if err != nil {
		t.Fatal(err)
	}
	defer packet4.Close()
	packet6, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group6, 49601))
	if err != nil {
		t.Fatal(err)
	}
	defer packet6.Close()
	clearMulticastTestControl(stack)

	state := stack.multicast.(*multicastState)
	state.mu.Lock()
	state.robustness[0], state.queryInterval[0], state.responseInterval[0] = 7, 5*time.Second, 7*time.Second
	state.mu.Unlock()
	query4 := buildMulticastTestIGMPQuery(remote4, group4, group4, 1, []netip.Addr{}, true)
	headerLength := int(query4[0]&0x0f) * 4
	payload4 := query4[headerLength:]
	payload4[8], payload4[9] = 0, 0
	payload4[2], payload4[3] = 0, 0
	binary.BigEndian.PutUint16(payload4[2:4], checksum(payload4))
	if _, err = stack.Write([][]byte{query4}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	robustness, queryInterval, responseInterval := state.robustness[0], state.queryInterval[0], state.responseInterval[0]
	state.mu.Unlock()
	if robustness != multicastDefaultRobustness || queryInterval != multicastDefaultQueryInterval {
		t.Fatalf("zero QRV/QQIC retained %d/%v, want RFC defaults", robustness, queryInterval)
	}
	if responseInterval != 100*time.Millisecond {
		t.Fatalf("IGMP Query Response Interval = %v, want 100ms", responseInterval)
	}

	clearMulticastTestControl(stack)
	unicastQuery := buildMulticastTestIGMPQuery(remote4, local4, netip.IPv4Unspecified(), 1, []netip.Addr{}, true)
	if _, err = stack.Write([][]byte{unicastQuery}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	generalScheduled := !state.generalQuery[0].IsZero()
	state.mu.Unlock()
	if !generalScheduled {
		t.Fatal("unicast-destination IGMP General Query did not schedule the RFC-required response")
	}

	clearMulticastTestControl(stack)
	unspecifiedQuery := buildMulticastTestMLDQuery(netip.IPv6Unspecified(), group6, group6, 1, []netip.Addr{})
	if _, err = stack.Write([][]byte{unspecifiedQuery}, 0); err != nil {
		t.Fatal(err)
	}
	badCodeQuery := buildMulticastTestMLDQuery(remote6, group6, group6, 1, []netip.Addr{})
	badCodeQuery[49] = 1
	badCodeQuery[50], badCodeQuery[51] = 0, 0
	binary.BigEndian.PutUint16(badCodeQuery[50:52], transportChecksum(remote6, group6, ProtocolICMPv6, badCodeQuery[48:]))
	if _, err = stack.Write([][]byte{badCodeQuery}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	queryScheduled := !state.groups[group6].query.deadline.IsZero()
	state.mu.Unlock()
	if queryScheduled {
		t.Fatal("invalid MLD source or Code scheduled a response")
	}

	clearMulticastTestControl(stack)
	state.mu.Lock()
	state.robustness[1], state.queryInterval[1], state.responseInterval[1] = 7, 5*time.Second, 7*time.Second
	state.mu.Unlock()
	unicastMLDQuery := buildMulticastTestMLDQuery(remote6, local6, netip.IPv6Unspecified(), 1, []netip.Addr{})
	unicastMLDQuery[72], unicastMLDQuery[73] = 0, 0
	unicastMLDQuery[50], unicastMLDQuery[51] = 0, 0
	binary.BigEndian.PutUint16(unicastMLDQuery[50:52], transportChecksum(remote6, local6, ProtocolICMPv6, unicastMLDQuery[48:]))
	if _, err = stack.Write([][]byte{unicastMLDQuery}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	generalScheduled = !state.generalQuery[1].IsZero()
	robustness, queryInterval, responseInterval = state.robustness[1], state.queryInterval[1], state.responseInterval[1]
	state.mu.Unlock()
	if !generalScheduled {
		t.Fatal("unicast-destination MLD General Query did not schedule the RFC-required response")
	}
	if robustness != multicastDefaultRobustness || queryInterval != multicastDefaultQueryInterval {
		t.Fatalf("zero MLD QRV/QQIC retained %d/%v, want RFC defaults", robustness, queryInterval)
	}
	if responseInterval != time.Millisecond {
		t.Fatalf("MLD Query Response Interval = %v, want 1ms", responseInterval)
	}
}

func TestMulticastQueryAcceptsAdditionalData(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.98")
	remote4 := netip.MustParseAddr("192.0.2.99")
	group4 := netip.MustParseAddr("239.98.0.1")
	query4 := buildMulticastTestIGMPQuery(remote4, group4, group4, 1, []netip.Addr{}, true)
	headerLength := int(query4[0]&0x0f) * 4
	query4 = append(query4, make([]byte, 4)...)
	binary.BigEndian.PutUint16(query4[2:4], uint16(len(query4)))
	query4[10], query4[11] = 0, 0
	binary.BigEndian.PutUint16(query4[10:12], checksum(query4[:headerLength]))
	query4[headerLength+2], query4[headerLength+3] = 0, 0
	binary.BigEndian.PutUint16(query4[headerLength+2:headerLength+4], checksum(query4[headerLength:]))
	parsed4, ok := parseIPPacket(query4, false)
	if !ok {
		t.Fatal("IGMP test packet did not parse as IP")
	}
	network4, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 24)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, valid := parseIGMPQuery(parsed4, network4, false); !valid {
		t.Fatal("IGMPv3 Query rejected checksum-covered Additional Data")
	}
	malformed4 := append([]byte(nil), query4...)
	binary.BigEndian.PutUint16(malformed4[headerLength+10:headerLength+12], 2)
	malformed4[headerLength+2], malformed4[headerLength+3] = 0, 0
	binary.BigEndian.PutUint16(malformed4[headerLength+2:headerLength+4], checksum(malformed4[headerLength:]))
	parsedMalformed4, ok := parseIPPacket(malformed4, false)
	if !ok {
		t.Fatal("malformed IGMP test packet did not parse as IP")
	}
	if _, _, valid := parseIGMPQuery(parsedMalformed4, network4, false); valid {
		t.Fatal("IGMPv3 Query accepted a source count beyond the available data")
	}

	local6 := netip.MustParseAddr("fe80::98")
	remote6 := netip.MustParseAddr("fe80::99")
	group6 := netip.MustParseAddr("ff02::9800")
	query6 := buildMulticastTestMLDQuery(remote6, group6, group6, 1, []netip.Addr{})
	query6 = append(query6, make([]byte, 16)...)
	binary.BigEndian.PutUint16(query6[4:6], uint16(len(query6)-40))
	payload6 := query6[48:]
	payload6[2], payload6[3] = 0, 0
	binary.BigEndian.PutUint16(payload6[2:4], transportChecksum(remote6, group6, ProtocolICMPv6, payload6))
	parsed6, ok := parseIPPacket(query6, false)
	if !ok {
		t.Fatal("MLD test packet did not parse as IP")
	}
	network6, err := buildNetworkState(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local6, 64)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, valid := parseMLDQuery(parsed6, network6, false); !valid {
		t.Fatal("MLDv2 Query rejected checksum-covered Additional Data")
	}
	malformed6 := append([]byte(nil), query6...)
	payloadMalformed6 := malformed6[48:]
	binary.BigEndian.PutUint16(payloadMalformed6[26:28], 2)
	payloadMalformed6[2], payloadMalformed6[3] = 0, 0
	binary.BigEndian.PutUint16(payloadMalformed6[2:4], transportChecksum(remote6, group6, ProtocolICMPv6, payloadMalformed6))
	parsedMalformed6, ok := parseIPPacket(malformed6, false)
	if !ok {
		t.Fatal("malformed MLD test packet did not parse as IP")
	}
	if _, _, valid := parseMLDQuery(parsedMalformed6, network6, false); valid {
		t.Fatal("MLDv2 Query accepted a source count beyond the available data")
	}
}

func TestMLDv2QueryCurrentState(t *testing.T) {
	local := netip.MustParseAddr("fe80::a0")
	querier := netip.MustParseAddr("fe80::a1")
	group := netip.MustParseAddr("ff02::a123")
	source := netip.MustParseAddr("fe80::a2")
	allNodes := netip.MustParseAddr("ff02::1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 50000))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{source}}); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	query := buildMulticastTestMLDQuery(querier, allNodes, netip.IPv6Unspecified(), 0, []netip.Addr{})
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == ProtocolICMPv6 && len(packet.payload) >= 28 && packet.payload[0] == mldV2MembershipReport && packet.payload[8] == multicastRecordModeIsInclude
	})
	records := multicastTestReportRecords(t, report)
	if len(records) != 1 || records[0].group != group || len(records[0].sources) != 1 || records[0].sources[0] != source {
		t.Fatalf("MLDv2 current-state records = %#v", records)
	}
	if report.target != netip.MustParseAddr("ff02::16") || report.hopLimit != 1 || !report.hasRouterAlert() {
		t.Fatalf("MLDv2 envelope = target %s hop %d alert %v", report.target, report.hopLimit, report.hasRouterAlert())
	}
}

func TestIGMPv2CompatibilityReportSuppressionAndLeave(t *testing.T) {
	for _, offload := range []bool{false, true} {
		t.Run(fmt.Sprintf("offload-%t", offload), func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.110")
			querier := netip.MustParseAddr("192.0.2.111")
			group := netip.MustParseAddr("239.110.0.1")
			allHosts := netip.MustParseAddr("224.0.0.1")
			stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
			var policy RXChecksumOffload
			policy.SetIGMP(offload)
			stack.SetRXChecksumOffload(policy)
			connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 51000))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			clearMulticastTestControl(stack)
			v2Query := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 1, nil, true)
			if _, err = stack.Write([][]byte{v2Query}, 0); err != nil {
				t.Fatal(err)
			}
			report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == 2 && len(packet.payload) == 8 && packet.payload[0] == igmpV2MembershipReport
			})
			if report.target != group || !report.hasRouterAlert() {
				t.Fatalf("IGMPv2 report target/alert = %s/%v", report.target, report.hasRouterAlert())
			}
			if err = connection.LeaveGroup(group); err != nil {
				t.Fatal(err)
			}
			leave := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == 2 && len(packet.payload) == 8 && packet.payload[0] == igmpV2LeaveGroup
			})
			if leave.target != netip.MustParseAddr("224.0.0.2") {
				t.Fatalf("IGMPv2 leave target = %s", leave.target)
			}
			stack.mu.RLock()
			state := stack.multicast.(*multicastState)
			state.mu.Lock()
			_, pendingLeave := state.retransmissions[group]
			state.mu.Unlock()
			stack.mu.RUnlock()
			if pendingLeave {
				t.Fatal("IGMPv2 leave retained a duplicate retransmission")
			}

			if err = connection.JoinGroup(group); err != nil {
				t.Fatal(err)
			}
			joinedReport := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == 2 && len(packet.payload) == 8 && packet.payload[0] == igmpV2MembershipReport
			})
			heard := make([]byte, 8)
			heard[0] = igmpV2MembershipReport
			groupBytes := group.As4()
			copy(heard[4:8], groupBytes[:])
			binary.BigEndian.PutUint16(heard[2:4], checksum(heard))
			withoutAlert := buildMulticastTestIGMPQuery(querier, group, group, 1, nil, false)
			withoutAlertHeader := int(withoutAlert[0]&0x0f) * 4
			copy(withoutAlert[withoutAlertHeader:], heard)
			if _, err = stack.Write([][]byte{withoutAlert}, 0); err != nil {
				t.Fatal(err)
			}
			state.mu.Lock()
			_, pendingWithoutAlert := state.retransmissions[group]
			lastReporterWithoutAlert := state.groups[group].lastReporter
			state.mu.Unlock()
			if !pendingWithoutAlert || !lastReporterWithoutAlert {
				t.Fatalf("IGMPv2 report without Router Alert changed state: pending %v lastReporter %v", pendingWithoutAlert, lastReporterWithoutAlert)
			}
			heardPacket := buildMulticastTestIGMPQuery(querier, local, group, 1, nil, true)
			copy(heardPacket[24:], heard)
			corrupt := append([]byte(nil), joinedReport.original...)
			corrupt[26] ^= 1
			_, _ = stack.Write([][]byte{corrupt}, 0)
			state.mu.Lock()
			_, pendingCorrupt := state.retransmissions[group]
			lastReporterCorrupt := state.groups[group].lastReporter
			state.mu.Unlock()
			if pendingCorrupt == offload || lastReporterCorrupt == offload {
				t.Fatalf("bad-checksum IGMPv2 report with offload %t: pending %t lastReporter %t", offload, pendingCorrupt, lastReporterCorrupt)
			}
			if offload {
				if err = connection.LeaveGroup(group); err != nil {
					t.Fatal(err)
				}
				if err = connection.JoinGroup(group); err != nil {
					t.Fatal(err)
				}
				_ = nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
					return packet.protocol == 2 && len(packet.payload) == 8 && packet.payload[0] == igmpV2MembershipReport
				})
			}
			state.mu.Lock()
			_, pendingBeforeReport := state.retransmissions[group]
			lastReporterBeforeReport := state.groups[group].lastReporter
			state.mu.Unlock()
			if !pendingBeforeReport || !lastReporterBeforeReport {
				t.Fatal("unicast IGMPv2 Report did not start with suppression pending")
			}
			if _, err = stack.Write([][]byte{heardPacket}, 0); err != nil {
				t.Fatal(err)
			}
			state.mu.Lock()
			_, pendingReport := state.retransmissions[group]
			lastReporter := state.groups[group].lastReporter
			state.mu.Unlock()
			if pendingReport || lastReporter {
				t.Fatalf("heard report suppression = pending %v lastReporter %v", pendingReport, lastReporter)
			}
		})
	}
}

func TestIGMPv1CompatibilityOutputCarriesRouterAlert(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.112")
	querier := netip.MustParseAddr("192.0.2.113")
	group := netip.MustParseAddr("239.112.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	query := buildMulticastTestIGMPQuery(querier, netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 0, nil, false)
	if _, err := stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 51200))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 2 && len(packet.payload) == 8 && packet.payload[0] == igmpV1MembershipReport
	})
	if report.target != group || report.hopLimit != 1 || !report.hasRouterAlert() {
		t.Fatalf("IGMPv1 report envelope = target %s hop %d alert %v", report.target, report.hopLimit, report.hasRouterAlert())
	}
}

func TestOlderQueryBeforeFirstMembershipSelectsCompatibilityMode(t *testing.T) {
	t.Run("IGMPv2", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.119")
		querier := netip.MustParseAddr("192.0.2.1")
		group := netip.MustParseAddr("239.119.0.1")
		allHosts := netip.MustParseAddr("224.0.0.1")
		stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
		query := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 1, nil, true)
		if _, err := stack.Write([][]byte{query}, 0); err != nil {
			t.Fatal(err)
		}
		stack.mu.RLock()
		seed, fullState := stack.multicastSeed, stack.multicast
		stack.mu.RUnlock()
		if fullState != nil || seed == nil || seed.compatibility[0] != 2 {
			t.Fatalf("pre-membership IGMP state = full %T seed %+v", fullState, seed)
		}
		connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 43119))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		stack.mu.RLock()
		seed, state := stack.multicastSeed, stack.multicast.(*multicastState)
		stack.mu.RUnlock()
		state.mu.Lock()
		mode := state.compatibility[0]
		state.mu.Unlock()
		if seed != nil || mode != 2 {
			t.Fatalf("promoted IGMP state = seed %+v mode %d", seed, mode)
		}
		report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
			return packet.protocol == 2 && len(packet.payload) >= 8 && packet.payload[0] == igmpV2MembershipReport
		})
		if report.target != group {
			t.Fatalf("IGMPv2 report target = %s, want %s", report.target, group)
		}
	})

	t.Run("MLDv1", func(t *testing.T) {
		local := netip.MustParseAddr("2001:db8::120")
		querier := netip.MustParseAddr("fe80::1")
		group := netip.MustParseAddr("ff02::120")
		allNodes := netip.MustParseAddr("ff02::1")
		stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
		query := buildMulticastTestMLDQuery(querier, allNodes, netip.IPv6Unspecified(), 1, nil)
		if _, err := stack.Write([][]byte{query}, 0); err != nil {
			t.Fatal(err)
		}
		stack.mu.RLock()
		seed, fullState := stack.multicastSeed, stack.multicast
		stack.mu.RUnlock()
		if fullState != nil || seed == nil || seed.compatibility[1] != 1 {
			t.Fatalf("pre-membership MLD state = full %T seed %+v", fullState, seed)
		}
		connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 43120))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		stack.mu.RLock()
		seed, state := stack.multicastSeed, stack.multicast.(*multicastState)
		stack.mu.RUnlock()
		state.mu.Lock()
		mode := state.compatibility[1]
		state.mu.Unlock()
		if seed != nil || mode != 1 {
			t.Fatalf("promoted MLD state = seed %+v mode %d", seed, mode)
		}
		report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
			return packet.protocol == ProtocolICMPv6 && len(packet.payload) >= 24 && packet.payload[0] == mldV1MembershipReport
		})
		if report.target != group {
			t.Fatalf("MLDv1 report target = %s, want %s", report.target, group)
		}
	})
}

func TestInvalidQueryDoesNotCreateMulticastState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.121")
	querier := netip.MustParseAddr("192.0.2.1")
	allHosts := netip.MustParseAddr("224.0.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	query := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 1, nil, true)
	query[len(query)-1] ^= 1
	if _, err := stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	stack.mu.RLock()
	seed, state := stack.multicastSeed, stack.multicast
	stack.mu.RUnlock()
	if seed != nil || state != nil {
		t.Fatalf("invalid Query retained multicast state: seed %+v full %T", seed, state)
	}
}

func TestMLDChecksumReuseRequiresIPv6(t *testing.T) {
	for _, offload := range []bool{false, true} {
		for _, joined := range []bool{false, true} {
			t.Run(fmt.Sprintf("offload-%t/joined-%t", offload, joined), func(t *testing.T) {
				local := netip.MustParseAddr("169.254.0.1")
				remote := netip.MustParseAddr("169.254.0.2")
				stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 16)}, 1400)
				var policy RXChecksumOffload
				policy.SetICMPv6(offload)
				stack.SetRXChecksumOffload(policy)
				var state *multicastState
				var before multicastQuerierState
				if joined {
					connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.MustParseAddrPort("239.121.0.1:43121"))
					if err != nil {
						t.Fatal(err)
					}
					defer connection.Close()
					stack.mu.RLock()
					state = stack.multicast.(*multicastState)
					stack.mu.RUnlock()
					state.mu.Lock()
					before = state.multicastQuerierState
					state.mu.Unlock()
				}
				packet := IPPacket{
					Source: remote, Destination: local, Protocol: ProtocolICMPv6, HopLimit: 1,
					Payload: mustCodecVector(t, "820000010001000000000000000000000000000000000000"),
				}
				var alert IPv4HeaderOption
				alert.SetRouterAlert(0)
				if err := packet.SetIPv4HeaderOptions([]IPv4HeaderOption{alert}); err != nil {
					t.Fatal(err)
				}
				wire, err := packet.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = stack.Write([][]byte{wire}, 0); err != nil {
					t.Fatal(err)
				}
				stack.mu.RLock()
				seed := stack.multicastSeed
				stack.mu.RUnlock()
				if seed != nil {
					t.Fatal("unchecked IPv4 MLD payload created querier state")
				}
				if state != nil {
					state.mu.Lock()
					after := state.multicastQuerierState
					state.mu.Unlock()
					if after != before {
						t.Fatal("unchecked IPv4 MLD payload changed querier state")
					}
				}
			})
		}
	}
}

func TestPreMembershipUnicastIGMPQueryIsConsumed(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.123")
	querier := netip.MustParseAddr("192.0.2.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	query := buildMulticastTestIGMPQuery(querier, local, netip.IPv4Unspecified(), 1, nil, true)
	if _, err := stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	stack.mu.RLock()
	seed := stack.multicastSeed
	stack.mu.RUnlock()
	if seed == nil || seed.compatibility[0] != 2 {
		t.Fatalf("unicast Query seed = %+v", seed)
	}
	if packets := stack.outbound.len(); packets != 0 {
		t.Fatalf("unicast IGMP Query produced %d output packets", packets)
	}
}

func TestFailedMembershipRemovalDoesNotCreateMulticastState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.122")
	group := netip.MustParseAddr("239.122.0.1")
	source := netip.MustParseAddr("192.0.2.123")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	connection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 43122))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	udp := connection.(*UDPConn)
	for _, operation := range []func() error{
		func() error { return udp.LeaveGroup(group) },
		func() error { return udp.LeaveSourceSpecificGroup(group, source) },
		func() error { return udp.ExcludeSourceSpecificGroup(group, source) },
		func() error { return udp.IncludeSourceSpecificGroup(group, source) },
	} {
		if err = operation(); err == nil {
			t.Fatal("membership removal without a join succeeded")
		}
	}
	stack.mu.RLock()
	seed, state := stack.multicastSeed, stack.multicast
	stack.mu.RUnlock()
	if seed != nil || state != nil {
		t.Fatalf("failed membership removal retained state: seed %+v full %T", seed, state)
	}
}

func TestCloseCancelsBlockedMulticastReports(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.124")
	group := netip.MustParseAddr("239.124.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 43124))
	if err != nil {
		t.Fatal(err)
	}
	stack.mu.RLock()
	state := stack.multicast.(*multicastState)
	stack.mu.RUnlock()
	state.mu.Lock()
	cancel := state.reportCancel[0]
	state.mu.Unlock()
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancel:
	default:
		t.Fatal("Stack.Close did not cancel an in-flight multicast report")
	}
	if err = connection.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("connection close after stack close = %v", err)
	}
}

func TestIGMPReportAcceptsUnspecifiedSourceOnly(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.112")
	querier := netip.MustParseAddr("192.0.2.113")
	group := netip.MustParseAddr("239.112.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 51100))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	clearMulticastTestControl(stack)

	query := buildMulticastTestIGMPQuery(querier, netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 1, nil, true)
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	state := stack.multicast.(*multicastState)
	state.mu.Lock()
	if state.groups[group].query.deadline.IsZero() {
		state.mu.Unlock()
		t.Fatal("IGMPv2 Query did not schedule a report")
	}
	state.mu.Unlock()

	report := buildMulticastTestIGMPQuery(netip.IPv4Unspecified(), group, group, 1, nil, true)
	headerLength := int(report[0]&0x0f) * 4
	report[headerLength] = igmpV2MembershipReport
	report[headerLength+1], report[headerLength+2], report[headerLength+3] = 0, 0, 0
	groupBytes := group.As4()
	copy(report[headerLength+4:headerLength+8], groupBytes[:])
	binary.BigEndian.PutUint16(report[headerLength+2:headerLength+4], checksum(report[headerLength:]))
	if _, err = stack.Write([][]byte{report}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	pending := !state.groups[group].query.deadline.IsZero()
	state.mu.Unlock()
	if pending {
		t.Fatal("zero-source IGMP Membership Report did not suppress the pending response")
	}

	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	pending = !state.groups[group].query.deadline.IsZero()
	state.mu.Unlock()
	if !pending {
		t.Fatal("second IGMPv2 Query did not schedule a report")
	}
	fragmentedReport := append(append([]byte(nil), report...), make([]byte, 8)...)
	binary.BigEndian.PutUint16(fragmentedReport[2:4], uint16(len(fragmentedReport)))
	fragmentedReport[10], fragmentedReport[11] = 0, 0
	binary.BigEndian.PutUint16(fragmentedReport[10:12], checksum(fragmentedReport[:headerLength]))
	fragmentedReport[headerLength+2], fragmentedReport[headerLength+3] = 0, 0
	binary.BigEndian.PutUint16(fragmentedReport[headerLength+2:headerLength+4], checksum(fragmentedReport[headerLength:]))
	fragments := make([][]byte, 2)
	for index := range fragments {
		fragment := make([]byte, headerLength+8)
		copy(fragment[:headerLength], fragmentedReport[:headerLength])
		copy(fragment[headerLength:], fragmentedReport[headerLength+index*8:headerLength+(index+1)*8])
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		field := uint16(index)
		if index == 0 {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], field)
		fragment[10], fragment[11] = 0, 0
		binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:headerLength]))
		fragments[index] = fragment
	}
	if _, err = stack.Write([][]byte{fragments[1]}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	pending = !state.groups[group].query.deadline.IsZero()
	state.mu.Unlock()
	if !pending {
		t.Fatal("incomplete zero-source IGMP Report changed query state")
	}
	if _, err = stack.Write([][]byte{fragments[0]}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	pending = !state.groups[group].query.deadline.IsZero()
	state.mu.Unlock()
	if pending {
		t.Fatal("reassembled IGMP Membership Report with Additional Data did not suppress the pending response")
	}

	for _, source := range []netip.Addr{netip.MustParseAddr("0.1.2.3"), netip.IPv4Unspecified()} {
		packet := buildMulticastTestIGMPQuery(source, group, group, 1, nil, true)
		if source.IsUnspecified() {
		} else {
			headerLength = int(packet[0]&0x0f) * 4
			packet[headerLength] = igmpV2MembershipReport
			packet[headerLength+1], packet[headerLength+2], packet[headerLength+3] = 0, 0, 0
			copy(packet[headerLength+4:headerLength+8], groupBytes[:])
			binary.BigEndian.PutUint16(packet[headerLength+2:headerLength+4], checksum(packet[headerLength:]))
		}
		parsed, ok := parseIPPacket(packet, false)
		if !ok {
			t.Fatal("test packet did not parse")
		}
		if validInboundPacketSource(stack.network.Load(), parsed) {
			t.Fatalf("invalid IGMP source %s was accepted", source)
		}
	}
}

func TestOlderQuerierPresentTimeoutFormulas(t *testing.T) {
	now := time.Unix(1234, 0)
	state := &multicastState{
		groups:          make(map[netip.Addr]*multicastGroupState),
		retransmissions: make(map[netip.Addr]*multicastRetransmission),
		multicastQuerierState: multicastQuerierState{
			robustness:       [2]uint8{2, 2},
			queryInterval:    [2]time.Duration{125 * time.Second, 125 * time.Second},
			responseInterval: [2]time.Duration{10 * time.Second, 7 * time.Second},
			compatibility:    [2]uint8{3, 2},
		},
		reportCancel: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
	state.noteQueryVersionLocked(0, 2, true, 0, 0, 250*time.Millisecond, now)
	if want := now.Add(252*time.Second + 500*time.Millisecond); !state.igmpV2Until.Equal(want) {
		t.Fatalf("IGMPv2 querier timeout = %v, want %v", state.igmpV2Until, want)
	}
	state.noteQueryVersionLocked(1, 1, true, 0, 0, 250*time.Millisecond, now)
	if want := now.Add(257 * time.Second); !state.mldV1Until.Equal(want) {
		t.Fatalf("MLDv1 querier timeout = %v, want %v", state.mldV1Until, want)
	}
}

func TestIGMPv2LinearTimeAndGeneralOnlyCompatibility(t *testing.T) {
	if got := decodeIGMPv2Time(255); got != 25*time.Second+500*time.Millisecond {
		t.Fatalf("IGMPv2 Max Resp 255 = %v, want 25.5s", got)
	}
	if got := decodeIGMPTime(255); got == decodeIGMPv2Time(255) {
		t.Fatal("IGMPv2 incorrectly shares the IGMPv3 floating decoder")
	}
	local := netip.MustParseAddr("192.0.2.115")
	querier := netip.MustParseAddr("192.0.2.116")
	group := netip.MustParseAddr("239.115.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 51500))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stack.mu.RLock()
	state := stack.multicast.(*multicastState)
	stack.mu.RUnlock()
	state.mu.Lock()
	if len(state.retransmissions) == 0 {
		state.mu.Unlock()
		t.Fatal("initial state-change retransmission missing")
	}
	state.mu.Unlock()
	groupQuery := buildMulticastTestIGMPQuery(querier, group, group, 1, nil, true)
	if _, err = stack.Write([][]byte{groupQuery}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	modeAfterGroup := state.compatibility[0]
	state.mu.Unlock()
	if modeAfterGroup != 3 {
		t.Fatalf("IGMPv2 Group-Specific Query selected compatibility mode %d", modeAfterGroup)
	}
	generalQuery := buildMulticastTestIGMPQuery(querier, netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 1, nil, true)
	if _, err = stack.Write([][]byte{generalQuery}, 0); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	modeAfterGeneral := state.compatibility[0]
	_, oldRetransmission := state.retransmissions[group]
	state.mu.Unlock()
	if modeAfterGeneral != 2 || oldRetransmission {
		t.Fatalf("IGMPv2 General Query transition = mode %d pending-old %v", modeAfterGeneral, oldRetransmission)
	}
}

func TestLegacyCompatibilityIgnoresSourceOnlyChanges(t *testing.T) {
	group := netip.MustParseAddr("239.121.0.1")
	source1 := netip.MustParseAddr("192.0.2.123")
	source2 := netip.MustParseAddr("192.0.2.124")
	state := &multicastState{
		groups: make(map[netip.Addr]*multicastGroupState), retransmissions: make(map[netip.Addr]*multicastRetransmission),
		multicastQuerierState: multicastQuerierState{
			robustness: [2]uint8{2, 2}, compatibility: [2]uint8{2, 2}, igmpV2Until: time.Now().Add(time.Hour),
		},
		reportCancel: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
	connection := &UDPConn{}
	if err := state.change(connection, multicastJoinSource, group, source1); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.retransmissions = make(map[netip.Addr]*multicastRetransmission)
	state.mu.Unlock()
	if err := state.change(connection, multicastJoinSource, group, source2); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	_, pending := state.retransmissions[group]
	state.mu.Unlock()
	if pending {
		t.Fatal("IGMPv2 compatibility scheduled a source-only report")
	}
	if err := state.change(connection, multicastLeaveSource, group, source2); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	_, pending = state.retransmissions[group]
	state.mu.Unlock()
	if pending {
		t.Fatal("IGMPv2 compatibility scheduled a source-only leave report")
	}
	if err := state.change(connection, multicastLeaveSource, group, source1); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	pendingLeave := state.retransmissions[group]
	state.mu.Unlock()
	if pendingLeave == nil || pendingLeave.exists {
		t.Fatal("IGMPv2 compatibility did not schedule the final group leave")
	}
}

func TestExpiredLegacyCompatibilityIsRefreshedBeforeStateChange(t *testing.T) {
	group := netip.MustParseAddr("239.125.0.1")
	source1 := netip.MustParseAddr("192.0.2.127")
	source2 := netip.MustParseAddr("192.0.2.128")
	state := &multicastState{
		groups: make(map[netip.Addr]*multicastGroupState), retransmissions: make(map[netip.Addr]*multicastRetransmission),
		multicastQuerierState: multicastQuerierState{
			robustness: [2]uint8{2, 2}, compatibility: [2]uint8{2, 2}, igmpV2Until: time.Now().Add(time.Hour),
		},
		reportCancel: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
	connection := &UDPConn{}
	if err := state.change(connection, multicastJoinSource, group, source1); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.retransmissions = make(map[netip.Addr]*multicastRetransmission)
	state.igmpV2Until = time.Now().Add(-time.Second)
	state.compatibility[0] = 2
	state.mu.Unlock()
	if err := state.change(connection, multicastJoinSource, group, source2); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	mode := state.compatibility[0]
	pending := state.retransmissions[group]
	allowed := pending != nil && pending.allow[source2] != 0
	state.mu.Unlock()
	if mode != 3 || !allowed {
		t.Fatalf("expired IGMPv2 mode change = mode %d pending %+v", mode, pending)
	}
}

func TestNewQueriesFollowActiveCompatibilityMode(t *testing.T) {
	t.Run("igmpv1", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.116")
		querier := netip.MustParseAddr("192.0.2.117")
		firstGroup := netip.MustParseAddr("239.116.0.1")
		secondGroup := netip.MustParseAddr("239.116.0.2")
		stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
		first, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(firstGroup, 51600))
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		second, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(secondGroup, 51601))
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		clearMulticastTestControl(stack)
		v1 := buildMulticastTestIGMPQuery(querier, netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 0, nil, false)
		if _, err = stack.Write([][]byte{v1}, 0); err != nil {
			t.Fatal(err)
		}
		clearMulticastTestControl(stack)
		v3 := buildMulticastTestIGMPQuery(querier, firstGroup, firstGroup, 255, []netip.Addr{netip.MustParseAddr("192.0.2.118")}, true)
		if _, err = stack.Write([][]byte{v3}, 0); err != nil {
			t.Fatal(err)
		}
		state := stack.multicast.(*multicastState)
		state.mu.Lock()
		firstQuery, secondQuery := state.groups[firstGroup].query, state.groups[secondGroup].query
		state.mu.Unlock()
		if firstQuery.deadline.IsZero() || secondQuery.deadline.IsZero() || firstQuery.sourceQuery || secondQuery.sourceQuery {
			t.Fatalf("IGMPv3 Query in v1 mode = first %+v second %+v, want two v1 General-Query responses", firstQuery, secondQuery)
		}
	})

	t.Run("mldv1", func(t *testing.T) {
		local := netip.MustParseAddr("fe80::b6")
		querier := netip.MustParseAddr("fe80::b7")
		group := netip.MustParseAddr("ff02::b600")
		stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
		connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 51602))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		clearMulticastTestControl(stack)
		v1 := buildMulticastTestMLDQuery(querier, netip.MustParseAddr("ff02::1"), netip.IPv6Unspecified(), 1, nil)
		if _, err = stack.Write([][]byte{v1}, 0); err != nil {
			t.Fatal(err)
		}
		clearMulticastTestControl(stack)
		v2 := buildMulticastTestMLDQuery(querier, group, group, 0xffff, []netip.Addr{netip.MustParseAddr("fe80::b8")})
		if _, err = stack.Write([][]byte{v2}, 0); err != nil {
			t.Fatal(err)
		}
		state := stack.multicast.(*multicastState)
		state.mu.Lock()
		pending := state.groups[group].query
		state.mu.Unlock()
		if pending.deadline.IsZero() || pending.sourceQuery {
			t.Fatalf("MLDv2 source Query in v1 mode = %+v, want one MLDv1 group response", pending)
		}
	})
}

func TestCompatibilityChangeReplacesReportGenerationUnderDevicePressure(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.117")
	querier := netip.MustParseAddr("192.0.2.118")
	group := netip.MustParseAddr("239.117.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	dummy := buildIPPacket(local, querier, ProtocolUDP, nil, 1, false)
	fillTestPacketQueue(t, &stack.outbound, dummy)
	connection, err := stack.ListenMulticastUDP(context.Background(), "udp4", netip.AddrPortFrom(group, 51700))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	state := stack.multicast.(*multicastState)
	waitFor(t, time.Second, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		pending := state.retransmissions[group]
		return pending == nil || pending.modeRemaining < multicastDefaultRobustness
	})
	query := buildMulticastTestIGMPQuery(querier, netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 1, nil, true)
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < outboundPacketQueue; index++ {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			t.Fatalf("outbound queue drained after %d dummy packets", index)
		}
		stack.outbound.release(entry)
	}
	report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
		return packet.protocol == 2 && len(packet.payload) >= 8
	})
	if report.payload[0] != igmpV2MembershipReport {
		t.Fatalf("stale report generation emitted IGMP type %#x, want v2", report.payload[0])
	}
}

func TestFragmentedNonUnicastLocalCopiesUseAllOrNoneAdmission(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.119")
	remote := netip.MustParseAddr("198.51.100.119")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)}, MTU: 600})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	payload := bytes.Repeat([]byte{0x6d}, 1200)
	packets := buildIPv4Fragments(local, remote, ProtocolUDP, payload, 600, 91)
	if len(packets) < 2 {
		t.Fatal("test payload did not produce multiple fragments")
	}
	dummy := buildIPPacket(local, remote, ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
	for stack.loopback.len() < loopbackPacketQueue-1 {
		if !stack.loopback.tryEnqueue(dummy) {
			t.Fatal("loopback queue filled before the expected boundary")
		}
	}
	if !stack.loopback.tryEnqueue(dummy) {
		t.Fatal("loopback queue could not fill its final slot")
	}
	if err := stack.tryWriteNonUnicastPacket(len(dummy), false, true, func(packet []byte) bool {
		copy(packet, dummy)
		return true
	}, false); err != nil {
		t.Fatalf("local-only non-unicast packet with full queue: %v", err)
	}
	if got := stack.Stats().LoopbackQueueDrops; got != 1 {
		t.Fatalf("local-only non-unicast packet drops = %d, want 1", got)
	}
	entry, ok := stack.loopback.tryDequeue()
	if !ok {
		t.Fatal("full loopback queue could not release one packet")
	}
	stack.loopback.release(entry)
	beforeLocal := stack.loopback.len()
	flow := outputFlowKey{hash: 1}
	if err := stack.tryWriteNonUnicastPackets(packets, true, true, flow, false); err != nil {
		t.Fatalf("external non-unicast write with full local copy queue: %v", err)
	}
	if after := stack.loopback.len(); after != beforeLocal {
		t.Fatalf("best-effort local fragment copy changed queue depth from %d to %d", beforeLocal, after)
	}
	if stack.outbound.len() != len(packets) {
		t.Fatalf("external fragment count = %d, want %d", stack.outbound.len(), len(packets))
	}
	if stats := stack.Stats(); stats.OutboundQueueDrops != 0 || stats.LoopbackQueueDrops != uint64(1+len(packets)) {
		t.Fatalf("external fragments with rejected local copy statistics = %+v", stats)
	}
	for {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			break
		}
		stack.outbound.release(entry)
	}
	for stack.outbound.len() < outboundPacketQueue-1 {
		if !stack.outbound.tryEnqueue(dummy) {
			t.Fatal("outbound queue filled before the expected boundary")
		}
	}
	beforeExternal := stack.outbound.len()
	if err := stack.tryWriteNonUnicastPackets(packets, true, true, flow, false); err != nil {
		t.Fatalf("external non-unicast write over published backlog: %v", err)
	}
	if after := stack.outbound.len(); after != beforeExternal+1 {
		t.Fatalf("external fragment sequence changed queue depth from %d to %d, want %d", beforeExternal, after, beforeExternal+1)
	}
	if after := stack.loopback.len(); after != beforeLocal {
		t.Fatalf("full local copy queue changed depth from %d to %d", beforeLocal, after)
	}
	if stats := stack.Stats(); stats.OutboundQueueDrops != uint64(len(packets)-1) || stats.LoopbackQueueDrops != uint64(1+2*len(packets)) {
		t.Fatalf("fragment replacement with rejected local copy statistics = %+v", stats)
	}
	if err := stack.tryWriteNonUnicastPackets(packets, false, true, flow, false); err != nil {
		t.Fatalf("local-only non-unicast write with full queue: %v", err)
	}
	if after := stack.loopback.len(); after != beforeLocal {
		t.Fatalf("local-only fragment failure changed queue depth from %d to %d", beforeLocal, after)
	}
	if got, want := stack.Stats().LoopbackQueueDrops, uint64(1+3*len(packets)); got != want {
		t.Fatalf("local-only fragment drops = %d, want %d", got, want)
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
	if !complete || !bytes.Equal(reassembled.Payload, payload) {
		t.Fatalf("reassembled external multicast fragments = complete %t payload %x", complete, reassembled.Payload)
	}
	stack.loopback.close()
	if err := stack.tryWriteNonUnicastPacket(len(dummy), true, true, func(packet []byte) bool {
		copy(packet, dummy)
		return true
	}, false); !errors.Is(err, ErrClosed) {
		t.Fatalf("external packet with closed local queue = %v, want ErrClosed", err)
	}
	if err := stack.tryWriteNonUnicastPackets(packets, true, true, flow, false); !errors.Is(err, ErrClosed) {
		t.Fatalf("external write with closed local queue = %v, want ErrClosed", err)
	}
	if got, want := stack.Stats().LoopbackQueueDrops, uint64(1+3*len(packets)); got != want {
		t.Fatalf("closed local queue changed loopback drops to %d, want %d", got, want)
	}
}

func TestNonUnicastMarshalFailureDoesNotCountQueueDrop(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.120")
	remote := netip.MustParseAddr("198.51.100.120")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	dummy := buildIPPacket(local, remote, ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
	for stack.loopback.len() < cap(stack.loopback.free) {
		if !stack.loopback.tryEnqueue(dummy) {
			t.Fatal("loopback queue filled before the expected boundary")
		}
	}
	if err = stack.tryWriteNonUnicastPacket(len(dummy), true, true, func([]byte) bool {
		return false
	}, false); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("non-unicast marshal failure = %v, want EMSGSIZE", err)
	}
	if stats := stack.Stats(); stats.OutboundPackets != 0 || stats.OutboundQueueDrops != 0 || stats.LoopbackQueueDrops != 0 {
		t.Fatalf("non-unicast marshal failure statistics = %+v", stats)
	}
}

func TestMLDv1CompatibilityReportAndDone(t *testing.T) {
	for _, offload := range []bool{false, true} {
		t.Run(fmt.Sprintf("offload-%t", offload), func(t *testing.T) {
			local := netip.MustParseAddr("fe80::b0")
			querier := netip.MustParseAddr("fe80::b1")
			group := netip.MustParseAddr("ff02::b123")
			allNodes := netip.MustParseAddr("ff02::1")
			stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 64)}, 1400)
			var policy RXChecksumOffload
			policy.SetICMPv6(offload)
			stack.SetRXChecksumOffload(policy)
			connection, err := stack.ListenMulticastUDP(context.Background(), "udp6", netip.AddrPortFrom(group, 52000))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			clearMulticastTestControl(stack)
			query := buildMulticastTestMLDQuery(querier, allNodes, netip.IPv6Unspecified(), 1, nil)
			if _, err = stack.Write([][]byte{query}, 0); err != nil {
				t.Fatal(err)
			}
			report := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == ProtocolICMPv6 && len(packet.payload) == 24 && packet.payload[0] == mldV1MembershipReport
			})
			if report.target != group || !report.hasRouterAlert() || report.hopLimit != 1 {
				t.Fatalf("MLDv1 report envelope = target %s alert %v hop %d", report.target, report.hasRouterAlert(), report.hopLimit)
			}
			if err = connection.LeaveGroup(group); err != nil {
				t.Fatal(err)
			}
			done := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == ProtocolICMPv6 && len(packet.payload) == 24 && packet.payload[0] == mldV1ListenerDone
			})
			if done.target != netip.MustParseAddr("ff02::2") {
				t.Fatalf("MLDv1 Done target = %s", done.target)
			}

			if err = connection.JoinGroup(group); err != nil {
				t.Fatal(err)
			}
			joinedReport := nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
				return packet.protocol == ProtocolICMPv6 && len(packet.payload) == 24 && packet.payload[0] == mldV1MembershipReport
			})
			heardPacket := buildMulticastTestMLDQuery(querier, local, group, 1, nil)
			heard := heardPacket[48:]
			heard[0], heard[4], heard[5] = mldV1MembershipReport, 0, 0
			heard[2], heard[3] = 0, 0
			binary.BigEndian.PutUint16(heard[2:4], transportChecksum(querier, local, ProtocolICMPv6, heard))
			state := stack.multicast.(*multicastState)
			badHopLimit := append([]byte(nil), heardPacket...)
			badHopLimit[7] = 2
			badRouterAlert := append([]byte(nil), heardPacket...)
			badRouterAlert[45] = 1
			_, _ = stack.Write([][]byte{badHopLimit, badRouterAlert}, 0)
			state.mu.Lock()
			_, pendingEnvelope := state.retransmissions[group]
			lastReporterEnvelope := state.groups[group].lastReporter
			state.mu.Unlock()
			if !pendingEnvelope || !lastReporterEnvelope {
				t.Fatalf("invalid MLD envelope with offload %t: pending %t lastReporter %t", offload, pendingEnvelope, lastReporterEnvelope)
			}
			corrupt := append([]byte(nil), joinedReport.original...)
			corrupt[50] ^= 1
			_, _ = stack.Write([][]byte{corrupt}, 0)
			state.mu.Lock()
			_, pendingCorrupt := state.retransmissions[group]
			lastReporterCorrupt := state.groups[group].lastReporter
			state.mu.Unlock()
			if pendingCorrupt == offload || lastReporterCorrupt == offload {
				t.Fatalf("bad-checksum MLDv1 report with offload %t: pending %t lastReporter %t", offload, pendingCorrupt, lastReporterCorrupt)
			}
			if offload {
				if err = connection.LeaveGroup(group); err != nil {
					t.Fatal(err)
				}
				if err = connection.JoinGroup(group); err != nil {
					t.Fatal(err)
				}
				_ = nextMulticastTestPacket(t, stack, func(packet ipPacket) bool {
					return packet.protocol == ProtocolICMPv6 && len(packet.payload) == 24 && packet.payload[0] == mldV1MembershipReport
				})
			}
			state.mu.Lock()
			_, pendingBeforeReport := state.retransmissions[group]
			lastReporterBeforeReport := state.groups[group].lastReporter
			state.mu.Unlock()
			if !pendingBeforeReport || !lastReporterBeforeReport {
				t.Fatal("unicast MLDv1 Report did not start with suppression pending")
			}
			if _, err = stack.Write([][]byte{heardPacket}, 0); err != nil {
				t.Fatal(err)
			}
			state.mu.Lock()
			_, pendingReport := state.retransmissions[group]
			lastReporter := state.groups[group].lastReporter
			state.mu.Unlock()
			if pendingReport || lastReporter {
				t.Fatalf("unicast-destination MLDv1 suppression = pending %v lastReporter %v", pendingReport, lastReporter)
			}
		})
	}
}

func TestAllHostsGroupIsImplicitForRawControl(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.120")
	querier := netip.MustParseAddr("192.0.2.121")
	allowed := netip.MustParseAddr("192.0.2.122")
	allHosts := netip.MustParseAddr("224.0.0.1")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	raw, err := stack.ListenIP(context.Background(), "ip4:igmp", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	query := buildMulticastTestIGMPQuery(querier, allHosts, netip.IPv4Unspecified(), 0, nil, false)
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 16)
	n, _, err := raw.ReadFrom(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 || payload[0] != igmpMembershipQuery {
		t.Fatalf("raw implicit all-hosts payload = %x", payload[:n])
	}
	if err = raw.(*IPConn).JoinGroup(allHosts); err != nil {
		t.Fatal(err)
	}
	if err = raw.(*IPConn).SetMulticastSourceFilter(allHosts, MulticastSourceFilter{Mode: MulticastSourceFilterInclude, Sources: []netip.Addr{allowed}}); err != nil {
		t.Fatal(err)
	}
	if _, err = stack.Write([][]byte{query}, 0); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = raw.ReadFrom(payload); err == nil {
		t.Fatal("explicit all-hosts source filter accepted a blocked raw packet")
	} else if netError, ok := err.(net.Error); !ok || !netError.Timeout() {
		t.Fatalf("blocked all-hosts raw read = %v, want timeout", err)
	}
	allowedQuery := buildMulticastTestIGMPQuery(allowed, allHosts, netip.IPv4Unspecified(), 0, nil, false)
	if _, err = stack.Write([][]byte{allowedQuery}, 0); err != nil {
		t.Fatal(err)
	}
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err = raw.ReadFrom(payload); err != nil || n != 8 || payload[0] != igmpMembershipQuery {
		t.Fatalf("allowed all-hosts raw packet = n %d payload %x error %v", n, payload, err)
	}
}

func TestIPv6AllNodesRecognitionRequiresExactFlags(t *testing.T) {
	for _, group := range []string{"ff01::1", "ff02::1"} {
		address := netip.MustParseAddr(group)
		if !isAllHostsGroup(address) {
			t.Fatalf("%s was not recognized as an all-nodes group", address)
		}
		if multicastGroupNeedsReport(address) {
			t.Fatalf("%s unexpectedly requires an MLD report", address)
		}
	}
	for _, test := range []struct {
		group       string
		needsReport bool
	}{
		{group: "ff11::1"},
		{group: "ff12::1", needsReport: true},
	} {
		address := netip.MustParseAddr(test.group)
		if isAllHostsGroup(address) {
			t.Fatalf("flagged multicast group %s was treated as all-nodes", address)
		}
		if got := multicastGroupNeedsReport(address); got != test.needsReport {
			t.Fatalf("multicastGroupNeedsReport(%s) = %v, want %v", address, got, test.needsReport)
		}
	}
}

func TestMulticastMembershipSurvivesTemporaryFamilyRemoval(t *testing.T) {
	local4 := netip.MustParsePrefix("192.0.2.130/24")
	local6 := netip.MustParsePrefix("fe80::130/64")
	group := netip.MustParseAddr("ff02::130")
	remote := netip.MustParseAddr("fe80::131")
	stack := newMulticastTestStack(t, []netip.Prefix{local4, local6}, 1400)
	packet, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(netip.IPv6Unspecified(), 53000))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	defer connection.Close()
	if !connection.dual {
		t.Fatal("generic wildcard was not dual stack")
	}
	if err = connection.JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local4}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = stack.Write([][]byte{buildTestUDP(remote, group, 63000, 53000, []byte("absent"))}, 0); err != nil {
		t.Fatal(err)
	}
	expectMulticastTestUDPTimeout(t, connection)
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local4, local6}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = stack.Write([][]byte{buildTestUDP(remote, group, 63000, 53000, []byte("restored"))}, 0); err != nil {
		t.Fatal(err)
	}
	readMulticastTestUDP(t, connection, "restored")
}

func TestMulticastReportPackingRules(t *testing.T) {
	group := netip.MustParseAddr("239.140.0.1")
	sources := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("192.0.2.5"),
	}
	include := packMulticastRecords([]multicastReportRecord{{recordType: multicastRecordModeIsInclude, group: group, sources: sources}}, 24, 8, 8, 4)
	if len(include) != 3 || len(include[0][0].sources) != 2 || len(include[1][0].sources) != 2 || len(include[2][0].sources) != 1 {
		t.Fatalf("INCLUDE split = %#v", include)
	}
	exclude := packMulticastRecords([]multicastReportRecord{{recordType: multicastRecordModeIsExclude, group: group, sources: sources}}, 24, 8, 8, 4)
	if len(exclude) != 1 || len(exclude[0]) != 1 || len(exclude[0][0].sources) != 2 || exclude[0][0].sources[0] != sources[0] {
		t.Fatalf("EXCLUDE truncation = %#v", exclude)
	}
}

func TestGeneralReportClearsPendingSourceQueryList(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.141")
	group := netip.MustParseAddr("239.141.0.1")
	firstSource := netip.MustParseAddr("192.0.2.142")
	secondSource := netip.MustParseAddr("192.0.2.143")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.PrefixFrom(local, 24)}, 1400)
	packet, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:54100"))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	defer connection.Close()
	if err = connection.JoinSourceSpecificGroup(group, firstSource); err != nil {
		t.Fatal(err)
	}
	if err = connection.JoinSourceSpecificGroup(group, secondSource); err != nil {
		t.Fatal(err)
	}
	clearMulticastTestControl(stack)
	state := stack.multicast.(*multicastState)
	now := time.Now().Add(time.Hour)
	state.mu.Lock()
	state.generalQuery[0] = now
	state.groups[group].query = multicastPendingQuery{
		deadline: now.Add(time.Second), sourceQuery: true,
		sources: map[netip.Addr]struct{}{firstSource: {}},
	}
	state.mu.Unlock()
	batches, _, _ := state.collectReports(now)
	if len(batches) != 1 || len(batches[0].records) != 1 || len(batches[0].records[0].sources) != 2 {
		t.Fatalf("General Report batches = %#v", batches)
	}
	state.mu.Lock()
	pending := state.groups[group].query
	state.mu.Unlock()
	if pending.deadline.IsZero() || pending.sourceQuery || len(pending.sources) != 0 {
		t.Fatalf("pending query after General Report = %+v", pending)
	}
	batches, _, _ = state.collectReports(now.Add(time.Second))
	if len(batches) != 1 || len(batches[0].records) != 1 || len(batches[0].records[0].sources) != 2 {
		t.Fatalf("later Group Report batches = %#v", batches)
	}
}

func TestMulticastConcurrentMembershipCloseAndInput(t *testing.T) {
	group := netip.MustParseAddr("239.150.0.1")
	remote := netip.MustParseAddr("192.0.2.151")
	stack := newMulticastTestStack(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.150/24")}, 1400)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	packet, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:54000"))
	if err != nil {
		t.Fatal(err)
	}
	connection := multicastTestUDP(t, packet)
	if err = connection.JoinGroup(group); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		go func(seed int) {
			defer func() { done <- struct{}{} }()
			for iteration := 0; iteration < 100; iteration++ {
				source := netip.AddrFrom4([4]byte{192, 0, 2, byte(160 + (seed+iteration)%50)})
				_ = connection.SetMulticastSourceFilter(group, MulticastSourceFilter{Mode: MulticastSourceFilterExclude, Sources: []netip.Addr{source}})
				_, _ = stack.Write([][]byte{buildTestUDP(remote, group, 64000, 54000, []byte{byte(iteration)})}, 0)
			}
		}(worker)
	}
	time.Sleep(time.Millisecond)
	_ = connection.Close()
	deadline := time.After(3 * time.Second)
	for worker := 0; worker < 4; worker++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatal("concurrent membership operation deadlocked with close")
		}
	}
}

func BenchmarkUDPInboundDispatch(b *testing.B) {
	for _, test := range []struct {
		name    string
		target  netip.Addr
		members int
		join    bool
	}{
		{name: "unicast-one", target: netip.MustParseAddr("192.0.2.200"), members: 1},
		{name: "broadcast-one", target: netip.MustParseAddr("192.0.2.255"), members: 1},
		{name: "broadcast-eight", target: netip.MustParseAddr("192.0.2.255"), members: 8},
		{name: "multicast-one", target: netip.MustParseAddr("239.200.0.1"), members: 1, join: true},
		{name: "multicast-eight", target: netip.MustParseAddr("239.200.0.1"), members: 8, join: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			stack := newMulticastTestStack(b, []netip.Prefix{netip.MustParsePrefix("192.0.2.200/24")}, 1400)
			connections := make([]*UDPConn, 0, test.members)
			for index := 0; index < test.members; index++ {
				var packet net.PacketConn
				var err error
				if test.members == 1 && !test.join {
					packet, err = stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:55000"))
				} else {
					listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
					packet, err = listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:55000"))
				}
				if err != nil {
					b.Fatal(err)
				}
				connection := multicastTestUDP(b, packet)
				if test.join {
					if err = connection.JoinGroup(test.target); err != nil {
						b.Fatal(err)
					}
				}
				connections = append(connections, connection)
			}
			clearMulticastTestControl(stack)
			packet := buildTestUDP(netip.MustParseAddr("192.0.2.201"), test.target, 65000, 55000, []byte("benchmark-payload"))
			buffer := make([]byte, 64)
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := stack.Write([][]byte{packet}, 0); err != nil {
					b.Fatal(err)
				}
				for _, connection := range connections {
					if _, _, _, _, _, err := connection.readDatagram(buffer, nil); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
			for _, connection := range connections {
				_ = connection.Close()
			}
		})
	}
}

func BenchmarkMulticastSourceFilterUpdate(b *testing.B) {
	group := netip.MustParseAddr("239.201.0.1")
	stack := newMulticastTestStack(b, []netip.Prefix{netip.MustParsePrefix("192.0.2.200/24")}, 1400)
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}
	packet, err := listenConfig.ListenUDP(context.Background(), stack, "udp4", netip.MustParseAddrPort("0.0.0.0:55100"))
	if err != nil {
		b.Fatal(err)
	}
	connection := multicastTestUDP(b, packet)
	b.Cleanup(func() { _ = connection.Close() })
	if err = connection.JoinGroup(group); err != nil {
		b.Fatal(err)
	}
	first := make([]netip.Addr, 16)
	second := make([]netip.Addr, 16)
	for index := range first {
		first[index] = netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})
		second[index] = first[index]
	}
	second[len(second)-1] = netip.MustParseAddr("192.0.2.32")
	filters := [2]MulticastSourceFilter{
		{Mode: MulticastSourceFilterInclude, Sources: first},
		{Mode: MulticastSourceFilterInclude, Sources: second},
	}
	if err = connection.SetMulticastSourceFilter(group, filters[0]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if err = connection.SetMulticastSourceFilter(group, filters[iteration&1]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPMulticastOutput(b *testing.B) {
	for _, loopback := range []bool{false, true} {
		name := "external-only"
		if loopback {
			name = "with-loopback"
		}
		b.Run(name, func(b *testing.B) {
			stack := newMulticastTestStack(b, []netip.Prefix{netip.MustParsePrefix("192.0.2.202/24")}, 1400)
			packet, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:0"))
			if err != nil {
				b.Fatal(err)
			}
			connection := multicastTestUDP(b, packet)
			b.Cleanup(func() { _ = connection.Close() })
			if err = connection.SetMulticastLoopback(loopback); err != nil {
				b.Fatal(err)
			}
			target := netip.MustParseAddrPort("239.202.0.1:55200")
			payload := make([]byte, 1200)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err = connection.WriteToUDPAddrPort(payload, target); err != nil {
					b.Fatal(err)
				}
				entry, ok := stack.outbound.tryDequeue()
				if !ok {
					b.Fatal("multicast write did not queue external output")
				}
				stack.outbound.release(entry)
			}
		})
	}
}

func BenchmarkUDPFragmentedMulticastOutput(b *testing.B) {
	for _, loopback := range []bool{false, true} {
		name := "external-only"
		if loopback {
			name = "with-loopback"
		}
		b.Run(name, func(b *testing.B) {
			stack := newMulticastTestStack(b, []netip.Prefix{netip.MustParsePrefix("192.0.2.203/24")}, 300)
			packet, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("0.0.0.0:0"))
			if err != nil {
				b.Fatal(err)
			}
			connection := multicastTestUDP(b, packet)
			b.Cleanup(func() { _ = connection.Close() })
			if err = connection.SetMulticastLoopback(loopback); err != nil {
				b.Fatal(err)
			}
			target := netip.MustParseAddrPort("239.203.0.1:55300")
			payload := make([]byte, 1200)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err = connection.WriteToUDPAddrPort(payload, target); err != nil {
					b.Fatal(err)
				}
				for {
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						break
					}
					stack.outbound.release(entry)
				}
			}
		})
	}
}

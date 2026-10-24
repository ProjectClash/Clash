package tun

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func testIPv4(source, destination string, protocol byte, payload []byte) []byte {
	return ipv4Packet(netip.MustParseAddr(source).AsSlice(), netip.MustParseAddr(destination).AsSlice(), protocol, payload)
}

func testIPv6(source, destination string, protocol byte, payload []byte) []byte {
	return ipv6Packet(netip.MustParseAddr(source).AsSlice(), netip.MustParseAddr(destination).AsSlice(), protocol, payload)
}

func tcpSegment(sourcePort, destinationPort uint16, seq, ack uint32, flags byte, data []byte) []byte {
	segment := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = 5 << 4
	segment[13] = flags
	copy(segment[20:], data)
	return segment
}

func withIPRewrite(t *testing.T, lines ...IPRewriteRule) {
	t.Helper()
	SetIPRewrite(lines)
	t.Cleanup(func() { SetIPRewrite(nil) })
}

func checksumHolds(t *testing.T, what string, b []byte, initial uint16) {
	t.Helper()
	if sum := onesComplementSum(b, initial); sum != 0xffff {
		t.Errorf("%s checksum does not hold (sum %#04x)", what, sum)
	}
}

func TestIPRewriteTakesOnlyThePacketsItCovers(t *testing.T) {
	packet := testIPv4("172.19.0.1", "192.0.2.1", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil))
	if handled, _, _ := applyIPRewrite(packet, nil); handled {
		t.Fatal("handled with no table")
	}
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect},
		IPRewriteRule{netip.MustParsePrefix("192.0.2.0/24"), IPRewriteDrop},
		IPRewriteRule{netip.MustParsePrefix("192.0.2.0/24"), IPRewriteReject},
	)
	if handled, writeBack, reply := applyIPRewrite(packet, nil); !handled || writeBack || reply != nil {
		t.Fatalf("drop: handled %v, writeBack %v, reply %v", handled, writeBack, reply)
	}
	other := testIPv4("172.19.0.1", "198.51.100.1", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil))
	if handled, _, _ := applyIPRewrite(other, nil); handled {
		t.Fatal("a packet no line covers was handled")
	}
}

func TestIPRewriteReflectSwapsTheAddressesAndKeepsTheChecksums(t *testing.T) {
	withIPRewrite(t, IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect})
	packet := testIPv4("172.19.0.1", "10.7.0.1", protocolTCP, tcpSegment(50000, 62078, 7, 0, 0x02, []byte("hello")))
	original := append([]byte(nil), packet...)
	handled, writeBack, reply := applyIPRewrite(packet, nil)
	if !handled || !writeBack || reply != nil {
		t.Fatalf("reflect: handled %v, writeBack %v, reply %v", handled, writeBack, reply)
	}
	if !bytes.Equal(packet[12:16], original[16:20]) || !bytes.Equal(packet[16:20], original[12:16]) {
		t.Fatalf("addresses %v -> %v, want swapped", packet[12:16], packet[16:20])
	}
	checksumHolds(t, "IPv4 header", packet[:20], 0)
	checksumHolds(t, "TCP", packet[20:], pseudoHeaderSum(packet[12:16], packet[16:20], protocolTCP, len(packet)-20))
}

func TestIPRewriteRejectAnswersTCPWithAReset(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("203.0.113.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("2001:db8::/32"), IPRewriteReject},
	)
	for name, tc := range map[string]struct {
		packet   []byte
		seq, ack uint32
		flags    byte
		ipv6     bool
	}{
		"SYN":        {testIPv4("172.19.0.1", "203.0.113.5", protocolTCP, tcpSegment(50000, 443, 1000, 0, 0x02, nil)), 0, 1001, 0x14, false},
		"ACK + data": {testIPv4("172.19.0.1", "203.0.113.5", protocolTCP, tcpSegment(50000, 443, 1000, 77, 0x18, []byte("abc"))), 77, 0, 0x04, false},
		"IPv6 SYN":   {testIPv6("fdfe:dcba:9876::1", "2001:db8::5", protocolTCP, tcpSegment(50000, 443, 5, 0, 0x02, nil)), 0, 6, 0x14, true},
	} {
		handled, writeBack, reply := applyIPRewrite(tc.packet, nil)
		if !handled || writeBack || reply == nil {
			t.Fatalf("%s: handled %v, writeBack %v, reply %v", name, handled, writeBack, reply)
		}
		headerLength, source, destination := 20, reply[12:16], reply[16:20]
		if tc.ipv6 {
			headerLength, source, destination = 40, reply[8:24], reply[24:40]
		} else {
			checksumHolds(t, name+" IPv4 header", reply[:20], 0)
		}
		segment := reply[headerLength:]
		checksumHolds(t, name+" TCP", segment, pseudoHeaderSum(source, destination, protocolTCP, len(segment)))
		if binary.BigEndian.Uint16(segment[0:2]) != 443 || binary.BigEndian.Uint16(segment[2:4]) != 50000 {
			t.Errorf("%s: ports %d -> %d", name, binary.BigEndian.Uint16(segment[0:2]), binary.BigEndian.Uint16(segment[2:4]))
		}
		if seq, ack, flags := binary.BigEndian.Uint32(segment[4:8]), binary.BigEndian.Uint32(segment[8:12]), segment[13]; seq != tc.seq || ack != tc.ack || flags != tc.flags {
			t.Errorf("%s: seq %d ack %d flags %#x, want %d %d %#x", name, seq, ack, flags, tc.seq, tc.ack, tc.flags)
		}
	}
	reset := testIPv4("172.19.0.1", "203.0.113.5", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x04, nil))
	if _, _, reply := applyIPRewrite(reset, nil); reply != nil {
		t.Error("a RST was answered")
	}
}

func TestIPRewriteRejectAnswersEverythingElseWithAdministrativelyProhibited(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("203.0.113.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("2001:db8::/32"), IPRewriteReject},
	)
	udp := testIPv4("172.19.0.1", "203.0.113.5", 17, []byte{0xc3, 0x50, 0x00, 0x35, 0, 12, 0, 0, 1, 2, 3, 4})
	_, _, reply := applyIPRewrite(udp, nil)
	if reply == nil || reply[9] != protocolICMPv4 || reply[20] != 3 || reply[21] != 13 {
		t.Fatalf("UDP answered %v, want ICMP 3/13", reply)
	}
	checksumHolds(t, "ICMPv4", reply[20:], 0)
	if quoted := reply[28:]; !bytes.Equal(quoted, udp[:28]) {
		t.Errorf("quoted %v, want the header and eight bytes %v", quoted, udp[:28])
	}
	echo := testIPv4("172.19.0.1", "203.0.113.5", protocolICMPv4, []byte{8, 0, 0, 0, 0, 1, 0, 1})
	if _, _, reply := applyIPRewrite(echo, nil); reply == nil || reply[20] != 3 {
		t.Errorf("an echo request was answered %v", reply)
	}
	unreachable := testIPv4("172.19.0.1", "203.0.113.5", protocolICMPv4, []byte{3, 1, 0, 0, 0, 0, 0, 0})
	if _, _, reply := applyIPRewrite(unreachable, nil); reply != nil {
		t.Error("an ICMP error was answered with another")
	}
	udp6 := testIPv6("fdfe:dcba:9876::1", "2001:db8::5", 17, []byte{0xc3, 0x50, 0x00, 0x35, 0, 8, 0, 0})
	_, _, reply6 := applyIPRewrite(udp6, nil)
	if reply6 == nil || reply6[6] != protocolICMPv6 || reply6[40] != 1 || reply6[41] != 1 {
		t.Fatalf("IPv6 UDP answered %v, want ICMPv6 1/1", reply6)
	}
	checksumHolds(t, "ICMPv6", reply6[40:], pseudoHeaderSum(reply6[8:24], reply6[24:40], protocolICMPv6, len(reply6)-40))
}

func TestIPRewriteRejectAnswersNoGroupAndNoErrorBehindExtensionHeaders(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("0.0.0.0/0"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("::/0"), IPRewriteReject},
	)
	udp := []byte{0xc3, 0x50, 0x00, 0x35, 0, 8, 0, 0}
	for name, packet := range map[string][]byte{
		"IPv4 multicast": testIPv4("172.19.0.1", "224.0.0.251", 17, udp),
		"IPv4 broadcast": testIPv4("172.19.0.1", "255.255.255.255", 17, udp),
		"IPv6 multicast": testIPv6("fdfe:dcba:9876::1", "ff02::fb", 17, udp),
		"ICMPv6 error behind hop-by-hop": rawIPv6("2001:db8::5", 0, []byte{58, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0}),
		"later IPv6 fragment": rawIPv6("2001:db8::5", 44, []byte{17, 0, 0, 8 << 3, 0, 0, 0, 1, 0, 0, 0, 0}),
	} {
		if handled, _, reply := applyIPRewrite(packet, nil); !handled || reply != nil {
			t.Errorf("%s: handled %v, answered %v", name, handled, reply)
		}
	}
	behind := rawIPv6("2001:db8::5", 0, append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, udp...))
	if _, _, reply := applyIPRewrite(behind, nil); reply == nil || reply[40] != 1 {
		t.Errorf("a datagram behind a hop-by-hop header was answered %v, want ICMPv6 1/1", reply)
	}
}

func rawIPv6(destination string, next byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6], packet[7] = next, 64
	copy(packet[8:24], netip.MustParseAddr("fdfe:dcba:9876::1").AsSlice())
	copy(packet[24:40], netip.MustParseAddr(destination).AsSlice())
	copy(packet[40:], payload)
	return packet
}

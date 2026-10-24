package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)


type IPRewriteAction uint8

const (
	IPRewriteReflect IPRewriteAction = iota + 1
	IPRewriteReject
	IPRewriteDrop
)

type IPRewriteRule struct {
	Prefix netip.Prefix
	Action IPRewriteAction
}

var ipRewriteTable atomic.Pointer[[]IPRewriteRule]

func SetIPRewrite(rules []IPRewriteRule) {
	if len(rules) == 0 {
		ipRewriteTable.Store(nil)
		return
	}
	table := append([]IPRewriteRule(nil), rules...)
	ipRewriteTable.Store(&table)
}

func LoopbackAddresses(inet4, inet6 []netip.Addr) []netip.Addr {
	var addresses []netip.Addr
	for _, family := range [][]netip.Addr{inet4, inet6} {
		for _, address := range family {
			address = address.Unmap().WithZone("")
			if address.IsValid() && !slices.Contains(addresses, address) {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses
}

func ipRewriteActionFor(destination netip.Addr, loopback []netip.Addr) IPRewriteAction {
	destination = destination.Unmap()
	if slices.Contains(loopback, destination) {
		return IPRewriteReflect
	}
	table := ipRewriteTable.Load()
	if table == nil {
		return 0
	}
	for _, rule := range *table {
		if rule.Prefix.Contains(destination) {
			return rule.Action
		}
	}
	return 0
}

func ipRewriteIdle(loopback []netip.Addr) bool {
	return len(loopback) == 0 && ipRewriteTable.Load() == nil
}

func applyIPRewrite(packet []byte, loopback []netip.Addr) (handled, writeBack bool, reply []byte) {
	if ipRewriteIdle(loopback) {
		return false, false, nil
	}
	destination, ok := packetDestination(packet)
	if !ok {
		return false, false, nil
	}
	return applyIPRewriteAction(packet, ipRewriteActionFor(destination, loopback))
}

func applyIPRewriteAction(packet []byte, action IPRewriteAction) (handled, writeBack bool, reply []byte) {
	switch action {
	case IPRewriteReflect:
		swapPacketAddresses(packet)
		return true, true, nil
	case IPRewriteReject:
		return true, false, rejectReply(packet)
	case IPRewriteDrop:
		return true, false, nil
	}
	return false, false, nil
}

func packetDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	}
	return netip.Addr{}, false
}

func swapPacketAddresses(packet []byte) {
	var source, destination []byte
	if packet[0]>>4 == 4 {
		source, destination = packet[12:16], packet[16:20]
	} else {
		source, destination = packet[8:24], packet[24:40]
	}
	for i := range source {
		source[i], destination[i] = destination[i], source[i]
	}
}

const (
	protocolICMPv4 = 1
	protocolTCP    = 6
	protocolICMPv6 = 58
)

func rejectReply(packet []byte) []byte {
	if destination, ok := packetDestination(packet); !ok || destination.IsMulticast() || destination == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return nil
	}
	if source, ok := packetSource(packet); !ok || source.IsMulticast() || source.IsUnspecified() {
		return nil
	}
	if packet[0]>>4 == 4 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength || binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			return nil
		}
		source, destination := packet[12:16], packet[16:20]
		payload := packet[headerLength:]
		switch packet[9] {
		case protocolTCP:
			segment := tcpReset(payload)
			if segment == nil {
				return nil
			}
			return ipv4Packet(destination, source, protocolTCP, segment)
		case protocolICMPv4:
			if len(payload) < 1 || !icmpv4IsQuery(payload[0]) {
				return nil
			}
		}
		quoted := packet[:shorter(len(packet), headerLength+8)]
		message := make([]byte, 8+len(quoted))
		message[0], message[1] = 3, 13
		copy(message[8:], quoted)
		binary.BigEndian.PutUint16(message[2:4], ^onesComplementSum(message, 0))
		return ipv4Packet(destination, source, protocolICMPv4, message)
	}
	if len(packet) < 40 {
		return nil
	}
	source, destination := packet[8:24], packet[24:40]
	protocol, payload, ok := ipv6UpperLayer(packet)
	if !ok {
		return nil
	}
	switch protocol {
	case protocolTCP:
		segment := tcpReset(payload)
		if segment == nil {
			return nil
		}
		return ipv6Packet(destination, source, protocolTCP, segment)
	case protocolICMPv6:
		if len(payload) < 1 || payload[0] < 128 {
			return nil
		}
	}
	quoted := packet[:shorter(len(packet), 1280-40-8)]
	message := make([]byte, 8+len(quoted))
	message[0], message[1] = 1, 1
	copy(message[8:], quoted)
	return ipv6Packet(destination, source, protocolICMPv6, message)
}

func ipv6UpperLayer(packet []byte) (protocol byte, payload []byte, ok bool) {
	protocol, payload = packet[6], packet[40:]
	for {
		switch protocol {
		case 0, 43, 60:
			if len(payload) < 8 {
				return 0, nil, false
			}
			size := (int(payload[1]) + 1) * 8
			if len(payload) < size {
				return 0, nil, false
			}
			protocol, payload = payload[0], payload[size:]
		case 44:
			if len(payload) < 8 || binary.BigEndian.Uint16(payload[2:4])&^0x7 != 0 {
				return 0, nil, false
			}
			protocol, payload = payload[0], payload[8:]
		default:
			return protocol, payload, true
		}
	}
}

func packetSource(packet []byte) (netip.Addr, bool) {
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), true
	}
	return netip.Addr{}, false
}

func icmpv4IsQuery(typ byte) bool {
	switch typ {
	case 0, 8, 13, 14, 15, 16, 17, 18:
		return true
	}
	return false
}

func tcpReset(segment []byte) []byte {
	if len(segment) < 20 {
		return nil
	}
	flags := segment[13]
	const fin, syn, rst, ack = 0x01, 0x02, 0x04, 0x10
	if flags&rst != 0 {
		return nil
	}
	dataOffset := int(segment[12]>>4) * 4
	if dataOffset < 20 || dataOffset > len(segment) {
		return nil
	}
	reset := make([]byte, 20)
	copy(reset[0:2], segment[2:4])
	copy(reset[2:4], segment[0:2])
	reset[12] = 5 << 4
	if flags&ack != 0 {
		copy(reset[4:8], segment[8:12])
		reset[13] = rst
	} else {
		length := uint32(len(segment) - dataOffset)
		if flags&syn != 0 {
			length++
		}
		if flags&fin != 0 {
			length++
		}
		binary.BigEndian.PutUint32(reset[8:12], binary.BigEndian.Uint32(segment[4:8])+length)
		reset[13] = rst | ack
	}
	return reset
}

func ipv4Packet(source, destination []byte, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source)
	copy(packet[16:20], destination)
	binary.BigEndian.PutUint16(packet[10:12], ^onesComplementSum(packet[:20], 0))
	copy(packet[20:], payload)
	if protocol == protocolTCP {
		pseudo := pseudoHeaderSum(source, destination, protocol, len(payload))
		binary.BigEndian.PutUint16(packet[20+16:20+18], ^onesComplementSum(packet[20:], pseudo))
	}
	return packet
}

func ipv6Packet(source, destination []byte, protocol byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = protocol
	packet[7] = 64
	copy(packet[8:24], source)
	copy(packet[24:40], destination)
	copy(packet[40:], payload)
	checksumAt := 40 + 2
	if protocol == protocolTCP {
		checksumAt = 40 + 16
	}
	pseudo := pseudoHeaderSum(source, destination, protocol, len(payload))
	binary.BigEndian.PutUint16(packet[checksumAt:checksumAt+2], ^onesComplementSum(packet[40:], pseudo))
	return packet
}

func pseudoHeaderSum(source, destination []byte, protocol byte, length int) uint16 {
	sum := onesComplementSum(source, 0)
	sum = onesComplementSum(destination, sum)
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[0:4], uint32(length))
	tail[7] = protocol
	return onesComplementSum(tail[:], sum)
}

func onesComplementSum(b []byte, initial uint16) uint16 {
	sum := uint32(initial)
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

func shorter(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ParseIPRewriteLine(line string) (IPRewriteRule, error) {
	target, action, ok := strings.Cut(line, "=")
	if !ok {
		return IPRewriteRule{}, fmt.Errorf("%q is not <address> = <action>", line)
	}
	target, action = strings.TrimSpace(target), strings.ToLower(strings.TrimSpace(action))
	var rule IPRewriteRule
	switch action {
	case "reflect":
		rule.Action = IPRewriteReflect
	case "reject":
		rule.Action = IPRewriteReject
	case "drop":
		rule.Action = IPRewriteDrop
	default:
		return IPRewriteRule{}, fmt.Errorf("%q: the action is reflect, reject or drop, not %q", line, action)
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		rule.Prefix = prefix.Masked()
	} else if addr, err := netip.ParseAddr(target); err == nil {
		rule.Prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
	} else {
		return IPRewriteRule{}, fmt.Errorf("%q: %q is not an IP address or CIDR", line, target)
	}
	if rule.Prefix.Addr().Is4In6() {
		rule.Prefix = netip.PrefixFrom(rule.Prefix.Addr().Unmap(), rule.Prefix.Bits()-96)
	}
	return rule, nil
}

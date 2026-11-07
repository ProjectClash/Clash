package clash

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

func goIPStackPair(t *testing.T, a, b netip.Prefix) (outbound.IPStack, outbound.IPStack) {
	t.Helper()
	return goIPStackPairOf(t, []netip.Prefix{a}, []netip.Prefix{b})
}

func goIPStackPairOf(t *testing.T, a, b []netip.Prefix) (outbound.IPStack, outbound.IPStack) {
	t.Helper()
	left, err := newGoIPStack(outbound.GoIPStackOptions{LocalAddresses: a, MTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	right, err := newGoIPStack(outbound.GoIPStackOptions{LocalAddresses: b, MTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	for _, stack := range []outbound.IPStack{left, right} {
		if err := stack.Start(); err != nil {
			t.Fatal(err)
		}
	}
	carry := func(from, to outbound.IPStack) {
		buffers, sizes := make([][]byte, from.BatchSize()), make([]int, from.BatchSize())
		for i := range buffers {
			buffers[i] = make([]byte, 16+65535)
		}
		for {
			n, err := from.Read(buffers, sizes, 16)
			if err != nil {
				return
			}
			packets := make([][]byte, n)
			for i := range packets {
				packets[i] = buffers[i][:16+sizes[i]]
			}
			if _, err := to.Write(packets, 16); err != nil {
				return
			}
		}
	}
	go carry(left, right)
	go carry(right, left)
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}

func TestANodesGoStackCarriesTCPBothWays(t *testing.T) {
	for _, family := range []struct{ a, b string }{{"10.7.0.2/32", "10.7.0.1/32"}, {"fd00::2/128", "fd00::1/128"}} {
		a, b := netip.MustParsePrefix(family.a), netip.MustParsePrefix(family.b)
		client, server := goIPStackPair(t, a, b)
		listener, err := server.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(b.Addr(), 80))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(b.Addr(), 80))
		if err != nil {
			t.Fatalf("%s: dial: %v", family.a, err)
		}
		payload := make([]byte, 1<<20)
		for i := range payload {
			payload[i] = byte(i)
		}
		go func() { _, _ = conn.Write(payload) }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		echoed := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echoed); err != nil {
			t.Fatalf("%s: read the echo: %v", family.a, err)
		}
		for i := range echoed {
			if echoed[i] != payload[i] {
				t.Fatalf("%s: byte %d came back as %d", family.a, i, echoed[i])
			}
		}
		_ = conn.Close()
	}
}

func TestADualStackNodesUDPSocketIsOnePortForBothVersions(t *testing.T) {
	client, server := goIPStackPairOf(t,
		[]netip.Prefix{netip.MustParsePrefix("10.7.0.2/32"), netip.MustParsePrefix("fd00::2/128")},
		[]netip.Prefix{netip.MustParsePrefix("10.7.0.1/32"), netip.MustParsePrefix("fd00::1/128")})
	echo := func(local netip.AddrPort) (chan netip.AddrPort, net.PacketConn) {
		conn, err := server.ListenUDP(context.Background(), "udp", local)
		if err != nil {
			t.Fatal(err)
		}
		seen := make(chan netip.AddrPort, 1)
		go func() {
			buffer := make([]byte, 2048)
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			seen <- from.(*net.UDPAddr).AddrPort()
			_, _ = conn.WriteTo(buffer[:n], from)
		}()
		return seen, conn
	}
	seen4, conn4 := echo(netip.MustParseAddrPort("10.7.0.1:53"))
	seen6, conn6 := echo(netip.MustParseAddrPort("[fd00::1]:53"))
	defer conn4.Close()
	defer conn6.Close()
	socket, err := client.ListenUDP(context.Background(), "udp", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	for _, to := range []string{"10.7.0.1:53", "[fd00::1]:53"} {
		if _, err := socket.WriteTo([]byte("hello "+to), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(to))); err != nil {
			t.Fatalf("write to %s: %v", to, err)
		}
	}
	from4, from6 := <-seen4, <-seen6
	if from4.Port() != from6.Port() {
		t.Fatalf("the socket sent from port %d to IPv4 and %d to IPv6", from4.Port(), from6.Port())
	}
	_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	answered := map[string]bool{}
	buffer := make([]byte, 2048)
	for len(answered) < 2 {
		n, from, err := socket.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("answers %v, then %v", answered, err)
		}
		answered[from.String()] = string(buffer[:n]) == "hello "+from.String()
	}
	for from, matched := range answered {
		if !matched {
			t.Fatalf("the answer from %s is not its echo", from)
		}
	}
}

func TestANodesStackAnswersOnlyForTheNodesAddress(t *testing.T) {
	node4, node6 := netip.MustParseAddr("10.66.0.2"), netip.MustParseAddr("fd66::2")
	stack, err := newGoIPStack(outbound.GoIPStackOptions{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(node4, 32), netip.PrefixFrom(node6, 128)},
		MTU:            1420,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	if stack.BatchSize() != 1 {
		t.Fatalf("wireguard-go is handed %d packets a read, want 1", stack.BatchSize())
	}
	replies := make(chan []byte, 64)
	go func() {
		buffers, sizes := [][]byte{make([]byte, 16+65535)}, []int{0}
		for {
			n, err := stack.Read(buffers, sizes, 16)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				select {
				case replies <- append([]byte(nil), buffers[i][16:16+sizes[i]]...):
				default:
				}
			}
		}
	}()
	send := func(packet []byte) {
		t.Helper()
		frame := append(make([]byte, 16, 16+len(packet)), packet...)
		if _, err := stack.Write([][]byte{frame}, 16); err != nil {
			t.Fatal(err)
		}
	}
	const syn, ack = 0x02, 0x10
	peer4, absent4 := netip.MustParseAddr("10.66.0.1"), netip.MustParseAddr("10.66.0.9")
	peer6, absent6 := netip.MustParseAddr("fd66::1"), netip.MustParseAddr("fd66::9")
	mapped := netip.AddrFrom16(node4.As16())
	send(ipv4ICMPEcho(peer4, absent4, 1))
	send(ipv4TCP(netip.AddrPortFrom(peer4, 40001), netip.AddrPortFrom(absent4, 80), syn))
	send(ipv4TCP(netip.AddrPortFrom(peer4, 40002), netip.AddrPortFrom(absent4, 80), ack))
	send(ipv4UDP(netip.AddrPortFrom(peer4, 40003), netip.AddrPortFrom(absent4, 53), []byte("q")))
	send(ipv6ICMPEcho(peer6, absent6, 3))
	send(ipv6TCP(netip.AddrPortFrom(peer6, 40004), netip.AddrPortFrom(absent6, 80), syn))
	send(ipv6UDP(netip.AddrPortFrom(peer6, 40008), netip.AddrPortFrom(absent6, 53), []byte("q")))
	send(ipv6ICMPEcho(peer6, mapped, 5))
	send([]byte{0x45})
	send(ipv4ICMPEcho(peer4, node4, 2))
	send(ipv6ICMPEcho(peer6, node6, 4))
	send(ipv4TCP(netip.AddrPortFrom(peer4, 40005), netip.AddrPortFrom(node4, 80), syn))
	send(ipv6TCP(netip.AddrPortFrom(peer6, 40006), netip.AddrPortFrom(node6, 80), syn))
	send(ipv4UDP(netip.AddrPortFrom(peer4, 40007), netip.AddrPortFrom(node4, 53), []byte("q")))

	want := map[string]bool{"echo4": false, "echo6": false, "reset4": false, "reset6": false, "port unreachable": false}
	quiet := time.After(5 * time.Second)
	for {
		select {
		case reply := <-replies:
			var from netip.Addr
			var protocol byte
			var l4 []byte
			switch {
			case len(reply) >= 28 && reply[0]>>4 == 4:
				from, protocol, l4 = netip.AddrFrom4([4]byte(reply[12:16])), reply[9], reply[20:]
			case len(reply) >= 48 && reply[0]>>4 == 6:
				from, protocol, l4 = netip.AddrFrom16([16]byte(reply[8:24])), reply[6], reply[40:]
			default:
				t.Fatalf("a reply that is not an IP packet the test reads: %x", reply)
			}
			ports := func() (uint16, uint16) { return uint16(l4[0])<<8 | uint16(l4[1]), uint16(l4[2])<<8 | uint16(l4[3]) }
			id := int(l4[4])<<8 | int(l4[5])
			switch {
			case from != node4 && from != node6:
				t.Fatalf("an answer (protocol %d) came in the name of %s, which is not the node's", protocol, from)
			case protocol == 1 && l4[0] == 0 && id == 2:
				want["echo4"] = true
			case protocol == 58 && l4[0] == 129 && id == 4:
				want["echo6"] = true
			case protocol == 6 && len(l4) >= 20 && l4[13]&0x04 != 0:
				sourcePort, destinationPort := ports()
				switch {
				case sourcePort == 80 && destinationPort == 40005 && reply[0]>>4 == 4:
					want["reset4"] = true
				case sourcePort == 80 && destinationPort == 40006 && reply[0]>>4 == 6:
					want["reset6"] = true
				default:
					t.Fatalf("a reset from %s port %d to port %d, which no SYN to the node asked for", from, sourcePort, destinationPort)
				}
			case protocol == 1 && l4[0] == 3 && l4[1] == 3 && len(l4) >= 8+28:
				quoted := l4[8:]
				quotedFrom, quotedTo := uint16(quoted[20])<<8|uint16(quoted[21]), uint16(quoted[22])<<8|uint16(quoted[23])
				if netip.AddrFrom4([4]byte(quoted[16:20])) != node4 || quotedFrom != 40007 || quotedTo != 53 {
					t.Fatalf("a port unreachable for a datagram to %s from port %d to %d, not the node's", netip.AddrFrom4([4]byte(quoted[16:20])), quotedFrom, quotedTo)
				}
				want["port unreachable"] = true
			default:
				t.Fatalf("an unexpected answer from the node: %x", reply)
			}
			done := true
			for _, seen := range want {
				done = done && seen
			}
			if done {
				quiet = time.After(time.Second)
			}
		case <-quiet:
			for answer, seen := range want {
				if !seen {
					t.Fatalf("the node's own addresses: no %s; got %v", answer, want)
				}
			}
			return
		}
	}
}

const echoPayload = "clashping"

func ipv4ICMPEcho(source, destination netip.Addr, id uint16) []byte {
	packet := make([]byte, 20+8+len(echoPayload))
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	packet[2], packet[3] = 0, byte(len(packet))
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	icmp := packet[20:]
	icmp[0] = 8
	icmp[4], icmp[5], icmp[7] = byte(id>>8), byte(id), 1
	copy(icmp[8:], echoPayload)
	putInternetChecksum(icmp, 2)
	putInternetChecksum(packet[:20], 10)
	return packet
}

func ipv6ICMPEcho(source, destination netip.Addr, id uint16) []byte {
	icmp := make([]byte, 8+len(echoPayload))
	icmp[0] = 128
	icmp[4], icmp[5], icmp[7] = byte(id>>8), byte(id), 1
	copy(icmp[8:], echoPayload)
	return ipv6Packet(source, destination, 58, icmp, 2)
}

func ipv4TCP(source, destination netip.AddrPort, flags byte) []byte {
	packet := make([]byte, 40)
	packet[0], packet[8], packet[9] = 0x45, 64, 6
	packet[3] = byte(len(packet))
	copy(packet[12:16], source.Addr().AsSlice())
	copy(packet[16:20], destination.Addr().AsSlice())
	tcp := packet[20:]
	fillTCP(tcp, source.Port(), destination.Port(), flags)
	pseudo := append(append(append([]byte(nil), packet[12:20]...), 0, 6, 0, byte(len(tcp))), tcp...)
	putInternetChecksum(pseudo, 12+16)
	copy(tcp[16:18], pseudo[12+16:12+18])
	putInternetChecksum(packet[:20], 10)
	return packet
}

func ipv6TCP(source, destination netip.AddrPort, flags byte) []byte {
	tcp := make([]byte, 20)
	fillTCP(tcp, source.Port(), destination.Port(), flags)
	return ipv6Packet(source.Addr(), destination.Addr(), 6, tcp, 16)
}

func fillTCP(tcp []byte, source, destination uint16, flags byte) {
	tcp[0], tcp[1] = byte(source>>8), byte(source)
	tcp[2], tcp[3] = byte(destination>>8), byte(destination)
	tcp[7] = 1
	tcp[12], tcp[13] = 5<<4, flags
	tcp[14], tcp[15] = 0xff, 0xff
}

func ipv6Packet(source, destination netip.Addr, next byte, payload []byte, checksumAt int) []byte {
	packet := make([]byte, 40, 40+len(payload))
	packet[0], packet[4], packet[5], packet[6], packet[7] = 0x60, byte(len(payload)>>8), byte(len(payload)), next, 64
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	pseudo := append(append(append([]byte(nil), packet[8:40]...), 0, 0, byte(len(payload)>>8), byte(len(payload)), 0, 0, 0, next), payload...)
	putInternetChecksum(pseudo, 40+checksumAt)
	return append(packet, pseudo[40:]...)
}

func putInternetChecksum(data []byte, at int) {
	data[at], data[at+1] = 0, 0
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	data[at], data[at+1] = byte(^sum>>8), byte(^sum)
}

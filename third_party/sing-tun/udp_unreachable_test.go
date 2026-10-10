package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var (
	_ UDPUnreachableReporter = (*systemUDPPacketWriter4)(nil)
	_ UDPUnreachableReporter = (*systemUDPPacketWriter6)(nil)
	_ UDPUnreachableReporter = (*mipsUDPWriter)(nil)
)

func assertPortUnreachable(t *testing.T, packet []byte, app, remote netip.AddrPort) {
	t.Helper()
	var icmp []byte
	var source, destination netip.Addr
	if app.Addr().Is4() {
		ipHdr := header.IPv4(packet)
		if len(packet) < header.IPv4MinimumSize || ipHdr.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
			t.Fatalf("not ICMPv4: %x", packet)
		}
		if mipsTestChecksum(packet[:ipHdr.HeaderLength()]) != 0 {
			t.Fatal("the IPv4 header checksum does not add up")
		}
		if ipHdr.TTL() == 0 {
			t.Fatal("an error sent with TTL 0 survives only a receiver that never looks")
		}
		source, destination = ipHdr.SourceAddr(), ipHdr.DestinationAddr()
		icmp = ipHdr.Payload()
		if icmp[0] != byte(header.ICMPv4DstUnreachable) || icmp[1] != byte(header.ICMPv4PortUnreachable) {
			t.Fatalf("want ICMPv4 3/3, got %d/%d", icmp[0], icmp[1])
		}
		if mipsTestChecksum(icmp) != 0 {
			t.Fatal("the ICMPv4 checksum does not cover the message: a kernel would drop it")
		}
	} else {
		ipHdr := header.IPv6(packet)
		if len(packet) < header.IPv6MinimumSize || ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber {
			t.Fatalf("not ICMPv6: %x", packet)
		}
		if ipHdr.HopLimit() == 0 {
			t.Fatal("an error sent with hop limit 0 survives only a receiver that never looks")
		}
		source, destination = ipHdr.SourceAddr(), ipHdr.DestinationAddr()
		icmp = ipHdr.Payload()
		if icmp[0] != byte(header.ICMPv6DstUnreachable) || icmp[1] != byte(header.ICMPv6PortUnreachable) {
			t.Fatalf("want ICMPv6 1/4, got %d/%d", icmp[0], icmp[1])
		}
		pseudo := append(append([]byte(nil), ipHdr.SourceAddressSlice()...), ipHdr.DestinationAddressSlice()...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(icmp)))
		pseudo = append(pseudo, 0, 0, 0, byte(header.ICMPv6ProtocolNumber))
		if mipsTestChecksum(append(pseudo, icmp...)) != 0 {
			t.Fatal("the ICMPv6 checksum does not add up: a kernel would drop it")
		}
	}
	if source != remote.Addr() || destination != app.Addr() {
		t.Fatalf("the error must come from where the datagram was going, to the app: got %v -> %v", source, destination)
	}
	quote := icmp[8:]
	var quotedSource, quotedDestination netip.Addr
	var udp []byte
	if app.Addr().Is4() {
		q := header.IPv4(quote)
		if q.Protocol() != uint8(header.UDPProtocolNumber) {
			t.Fatal("the quote must be of a UDP datagram")
		}
		quotedSource, quotedDestination = q.SourceAddr(), q.DestinationAddr()
		udp = quote[q.HeaderLength():]
	} else {
		q := header.IPv6(quote)
		if q.TransportProtocol() != header.UDPProtocolNumber {
			t.Fatal("the quote must be of a UDP datagram")
		}
		quotedSource, quotedDestination = q.SourceAddr(), q.DestinationAddr()
		udp = quote[header.IPv6MinimumSize:]
	}
	if len(udp) < header.UDPMinimumSize {
		t.Fatal("the quote must carry the UDP header: the ports are what match it to a socket")
	}
	u := header.UDP(udp)
	if quotedSource != app.Addr() || quotedDestination != remote.Addr() || u.SourcePort() != app.Port() || u.DestinationPort() != remote.Port() {
		t.Fatalf("the quote must be the datagram as the app sent it, got %v:%d -> %v:%d", quotedSource, u.SourcePort(), quotedDestination, u.DestinationPort())
	}
}

type unreachableHandler struct {
	doorHandler
	writers chan N.PacketWriter
}

func newUnreachableHandler() *unreachableHandler {
	return &unreachableHandler{writers: make(chan N.PacketWriter, 4)}
}

func (h *unreachableHandler) NewPacket(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	b.Release()
	h.writers <- init(nil)
}

func (h *unreachableHandler) writer(t *testing.T) UDPUnreachableReporter {
	t.Helper()
	select {
	case w := <-h.writers:
		reporter, ok := w.(UDPUnreachableReporter)
		if !ok {
			t.Fatalf("%T cannot report a datagram unreachable", w)
		}
		return reporter
	default:
		t.Fatal("the datagram never reached NewPacket")
		return nil
	}
}

func TestSystemStackReportsADatagramUnreachable(t *testing.T) {
	for _, pair := range [][2]string{{"172.19.0.2", "8.8.8.8"}, {"fdfe:dcba:9876::1", "2001:db8::10"}} {
		t.Run(pair[0], func(t *testing.T) {
			handler := newUnreachableHandler()
			tun := &recordingTun{}
			s := doorSystem(handler, tun)
			app := netip.AddrPortFrom(netip.MustParseAddr(pair[0]), 12345)
			remote := netip.AddrPortFrom(netip.MustParseAddr(pair[1]), 443)
			raw := udpPacket(app.Addr(), remote.Addr(), remote.Port(), []byte("a QUIC Initial would be here"))
			var err error
			if app.Addr().Is4() {
				ipHdr := header.IPv4(raw)
				err = s.processIPv4UDP(ipHdr, header.UDP(ipHdr.Payload()))
			} else {
				ipHdr := header.IPv6(raw)
				err = s.processIPv6UDP(ipHdr, header.UDP(ipHdr.Payload()))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := handler.writer(t).ReportUnreachable(); err != nil {
				t.Fatal(err)
			}
			tun.mu.Lock()
			written := tun.written[len(tun.written)-1][PacketOffset:]
			tun.mu.Unlock()
			assertPortUnreachable(t, written, app, remote)
		})
	}
}

func TestSystemStackRejectsALargeIPv4DatagramWithAValidError(t *testing.T) {
	tun := &recordingTun{}
	s := doorSystem(&doorHandler{}, tun)
	app := netip.AddrPortFrom(netip.MustParseAddr("172.19.0.2"), 12345)
	remote := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 443)
	initial := make([]byte, 1200)
	for i := range initial {
		initial[i] = byte(i*7 + 1)
	}
	raw := udpPacket(app.Addr(), remote.Addr(), remote.Port(), initial)
	if err := s.rejectIPv4WithICMP(header.IPv4(raw), header.ICMPv4PortUnreachable); err != nil {
		t.Fatal(err)
	}
	if tun.count() != 1 {
		t.Fatal("a large datagram must still be answered")
	}
	assertPortUnreachable(t, tun.written[0][PacketOffset:], app, remote)
}

func TestMipsStackReportsADatagramUnreachable(t *testing.T) {
	for _, pair := range [][2]string{{"198.18.0.1", "8.8.8.8"}, {"fd00::1", "2001:4860:4860::8888"}} {
		t.Run(pair[0], func(t *testing.T) {
			d := newMemoryTun()
			writers := make(chan N.PacketWriter, 1)
			h := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, init func(N.PacketConn) N.PacketWriter) {
				b.Release()
				writers <- init(nil)
			}}
			testStack(t, d, h, nil)
			app := netip.AddrPortFrom(netip.MustParseAddr(pair[0]), 12345)
			remote := netip.AddrPortFrom(netip.MustParseAddr(pair[1]), 443)
			d.in <- udpPacket(app.Addr(), remote.Addr(), remote.Port(), []byte("hello"))
			writer := (<-writers).(UDPUnreachableReporter)
			if err := writer.ReportUnreachable(); err != nil {
				t.Fatal(err)
			}
			assertPortUnreachable(t, readPacket(t, d), app, remote)
		})
	}
}

func TestSystemStackBoundsTheICMPErrorsItSends(t *testing.T) {
	tun := &recordingTun{}
	s := doorSystem(&doorHandler{}, tun)
	raw := udpPacket(netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("8.8.8.8"), 443, []byte("hello"))
	for i := 0; i < 10*icmpErrorBurst; i++ {
		if err := s.rejectIPv4WithICMP(header.IPv4(raw), header.ICMPv4PortUnreachable); err != nil {
			t.Fatal(err)
		}
	}
	if sent := tun.count(); sent < icmpErrorBurst || sent >= 10*icmpErrorBurst {
		t.Fatalf("a spray of %d datagrams was answered %d times; want the burst of %d and little more", 10*icmpErrorBurst, sent, icmpErrorBurst)
	}
}

func TestNoICMPErrorAnswersADatagramThatWasNotUnicast(t *testing.T) {
	app := netip.MustParseAddr("172.19.0.2")
	for _, destination := range []string{"224.0.0.251", "255.255.255.255", "0.0.0.0", "ff02::fb"} {
		if udpUnreachableAnswerable(app, netip.MustParseAddr(destination)) {
			t.Errorf("a datagram to %s must not be answered with an error", destination)
		}
	}
	for _, source := range []string{"0.0.0.0", "::", "224.0.0.1"} {
		if udpUnreachableAnswerable(netip.MustParseAddr(source), netip.MustParseAddr("8.8.8.8")) {
			t.Errorf("an error must not be sent to %s", source)
		}
	}
	if !udpUnreachableAnswerable(app, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("an ordinary datagram is answerable")
	}

	tun := &recordingTun{}
	s := doorSystem(&doorHandler{}, tun)
	raw := udpPacket(app, netip.MustParseAddr("224.0.0.251"), 5353, []byte("hello"))
	if err := s.rejectIPv4WithICMP(header.IPv4(raw), header.ICMPv4PortUnreachable); err != nil {
		t.Fatal(err)
	}
	if tun.count() != 0 {
		t.Fatal("a multicast datagram was answered with an ICMP error")
	}
}

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var errDoorRefused = errors.New("refused at the door")

type doorHandler struct {
	mu       sync.Mutex
	refuse   error
	asked    []string
	packets  int
	connects int
}

func (h *doorHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, _ DirectRouteContext, _ time.Duration) (DirectRouteDestination, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, network+" "+source.String()+" -> "+destination.String())
	return nil, h.refuse
}

func (h *doorHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	h.mu.Lock()
	h.connects++
	h.mu.Unlock()
	return nil
}

func (h *doorHandler) NewPacket(context.Context, netip.AddrPort, *buf.Buffer, M.Metadata, func(natConn N.PacketConn) N.PacketWriter) {
	h.mu.Lock()
	h.packets++
	h.mu.Unlock()
}

func (h *doorHandler) NewError(context.Context, error) {}

func (h *doorHandler) askedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.asked)
}

type recordingTun struct {
	mu      sync.Mutex
	written [][]byte
}

func (t *recordingTun) Read([]byte) (int, error) { select {} }
func (t *recordingTun) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.written = append(t.written, append([]byte(nil), p...))
	t.mu.Unlock()
	return len(p), nil
}
func (t *recordingTun) Close() error { return nil }

func (t *recordingTun) last(tb testing.TB) header.IPv6 {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.written) == 0 {
		tb.Fatal("nothing was written back to the tun")
	}
	return header.IPv6(t.written[len(t.written)-1][PacketOffset:])
}

func (t *recordingTun) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.written)
}

func doorSystem(handler Handler, tun Tun) *System {
	return &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		tun:              tun,
		mtu:              1500,
		handler:          handler,
		inet6Address:     netip.MustParseAddr("fdfe:dcba:9876::1"),
		inet6NextAddress: netip.MustParseAddr("fdfe:dcba:9876::2"),
		tcpPort6:         50000,
		tcpNat6:          NewNat(context.Background(), time.Minute),
		directNat:        NewDirectRouteMapping(time.Minute),
	}
}

func ipv6TCP(src, dst netip.Addr, flags header.TCPFlags) (header.IPv6, header.TCP) {
	packet := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	tcpHdr.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 7, DataOffset: header.TCPMinimumSize, Flags: flags, WindowSize: 65535})
	return ipHdr, tcpHdr
}

func ipv6UDP(src, dst netip.Addr) (header.IPv6, header.UDP) {
	payload := []byte("hello")
	packet := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize+len(payload))
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.Encode(&header.UDPFields{SrcPort: 40000, DstPort: 443, Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(udpHdr.Payload(), payload)
	return ipHdr, udpHdr
}

var (
	doorClient = netip.MustParseAddr("fdfe:dcba:9876::1")
	doorServer = netip.MustParseAddr("2001:db8::10")
)

func TestSystemStackAnswersARefusedSYNWithRST(t *testing.T) {
	handler := &doorHandler{refuse: errDoorRefused}
	tun := &recordingTun{}
	s := doorSystem(handler, tun)
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagSyn)
	writeBack, err := s.processIPv6TCP(ipHdr, tcpHdr)
	if err != nil {
		t.Fatalf("a refusal is not an error, got %v", err)
	}
	if writeBack {
		t.Fatal("the SYN must not be rewritten towards the forwarder")
	}
	if got := handler.asked; len(got) != 1 || got[0] != "tcp [fdfe:dcba:9876::1]:40000 -> [2001:db8::10]:443" {
		t.Fatalf("the handler is asked once, about the flow as the app sees it, got %v", got)
	}
	reply := tun.last(t)
	if reply.SourceAddr() != doorServer || reply.DestinationAddr() != doorClient || reply.TransportProtocol() != header.TCPProtocolNumber {
		t.Fatalf("the reply must come from the destination to the app, got %v -> %v proto %d", reply.SourceAddr(), reply.DestinationAddr(), reply.TransportProtocol())
	}
	replyTCP := header.TCP(reply.Payload())
	if replyTCP.Flags()&header.TCPFlagRst == 0 || replyTCP.SourcePort() != 443 || replyTCP.DestinationPort() != 40000 {
		t.Fatalf("the reply must be a RST for the app's ports, got flags %v %d -> %d", replyTCP.Flags(), replyTCP.SourcePort(), replyTCP.DestinationPort())
	}
	if s.tcpNat6.LookupBack(50000) != nil {
		t.Fatal("no NAT session may be created for a refused flow")
	}
}

func TestSystemStackForwardsAnAllowedSYNAndAsksOnlyOnce(t *testing.T) {
	handler := &doorHandler{}
	tun := &recordingTun{}
	s := doorSystem(handler, tun)
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagSyn)
	writeBack, err := s.processIPv6TCP(ipHdr, tcpHdr)
	if err != nil || !writeBack {
		t.Fatalf("an allowed SYN flows, got writeBack=%v err=%v", writeBack, err)
	}
	if ipHdr.DestinationAddr() != s.inet6Address || tcpHdr.DestinationPort() != s.tcpPort6 {
		t.Fatal("an allowed SYN is rewritten towards the forwarder as before")
	}
	if tun.count() != 0 {
		t.Fatal("nothing is written back for an allowed SYN")
	}
	ipHdr, tcpHdr = ipv6TCP(doorClient, doorServer, header.TCPFlagAck)
	if _, err := s.processIPv6TCP(ipHdr, tcpHdr); err != nil {
		t.Fatal(err)
	}
	if handler.askedCount() != 1 {
		t.Fatalf("the door is asked at the SYN only, asked %d times", handler.askedCount())
	}
}

func TestSystemStackAnswersARefusedUDPPacketWithNoRoute(t *testing.T) {
	handler := &doorHandler{refuse: errDoorRefused}
	tun := &recordingTun{}
	s := doorSystem(handler, tun)
	ipHdr, udpHdr := ipv6UDP(doorClient, doorServer)
	if err := s.processIPv6UDP(ipHdr, udpHdr); err != nil {
		t.Fatalf("a refusal is not an error, got %v", err)
	}
	if handler.packets != 0 {
		t.Fatal("a refused packet never reaches NewPacket")
	}
	reply := tun.last(t)
	if reply.TransportProtocol() != header.ICMPv6ProtocolNumber || reply.DestinationAddr() != doorClient {
		t.Fatalf("the app must get an ICMPv6 error back, got proto %d to %v", reply.TransportProtocol(), reply.DestinationAddr())
	}
	icmp := header.ICMPv6(reply.Payload())
	if icmp.Type() != header.ICMPv6DstUnreachable || icmp.Code() != header.ICMPv6NetworkUnreachable {
		t.Fatalf("no route to destination is the error an app sees without a tunnel, got type %d code %d", icmp.Type(), icmp.Code())
	}
}

func TestSystemStackForwardsAnAllowedUDPPacket(t *testing.T) {
	handler := &doorHandler{}
	tun := &recordingTun{}
	s := doorSystem(handler, tun)
	ipHdr, udpHdr := ipv6UDP(doorClient, doorServer)
	if err := s.processIPv6UDP(ipHdr, udpHdr); err != nil {
		t.Fatal(err)
	}
	if handler.packets != 1 || tun.count() != 0 {
		t.Fatalf("an allowed packet reaches NewPacket (%d) and nothing is written back (%d)", handler.packets, tun.count())
	}
}

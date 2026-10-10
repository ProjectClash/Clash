//go:build with_gvisor

package tun

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
)

func gvisorDoorStack(t *testing.T, handler Handler) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	ep := channel.New(8, 1500, "")
	s, err := NewGVisorStack(ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarder(context.Background(), s, handler).HandlePacket)
	return s, ep
}

func injectSYN(t *testing.T, ep *channel.Endpoint) {
	t.Helper()
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagSyn)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ep.InjectInbound(tcpip.NetworkProtocolNumber(header.IPv6ProtocolNumber), stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte(ipHdr))}))
}

func readReply(t *testing.T, ep *channel.Endpoint) header.TCP {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		t.Fatal("the stack answered the SYN with nothing")
	}
	defer pkt.DecRef()
	ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
	if ipHdr.SourceAddr() != doorServer || ipHdr.DestinationAddr() != doorClient {
		t.Fatalf("the answer must come from the destination to the app, got %v -> %v", ipHdr.SourceAddr(), ipHdr.DestinationAddr())
	}
	return header.TCP(pkt.TransportHeader().Slice())
}

func TestGVisorStackAnswersARefusedSYNWithRST(t *testing.T) {
	handler := &doorHandler{refuse: errDoorRefused}
	_, ep := gvisorDoorStack(t, handler)
	injectSYN(t, ep)
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("a refused SYN is answered with RST, got flags %v", reply.Flags())
	}
	if handler.askedCount() != 1 || handler.asked[0] != "tcp [fdfe:dcba:9876::1]:40000 -> [2001:db8::10]:443" {
		t.Fatalf("the door is asked once about the flow as the app sees it, got %v", handler.asked)
	}
}

func TestGVisorStackCompletesAnAllowedSYN(t *testing.T) {
	handler := &doorHandler{}
	_, ep := gvisorDoorStack(t, handler)
	injectSYN(t, ep)
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagSyn == 0 || reply.Flags()&header.TCPFlagAck == 0 {
		t.Fatalf("an allowed SYN gets its SYN-ACK, got flags %v", reply.Flags())
	}
}

func TestGVisorUDPForwarderDropsARefusedDatagramBeforeNewPacket(t *testing.T) {
	handler := &doorHandler{refuse: errDoorRefused}
	s, _ := gvisorDoorStack(t, handler)
	forwarder := NewUDPForwarder(context.Background(), s, handler)
	id := stack.TransportEndpointID{
		LocalAddress: tcpip.AddrFrom16(doorServer.As16()), LocalPort: 443,
		RemoteAddress: tcpip.AddrFrom16(doorClient.As16()), RemotePort: 40000,
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("hello"))})
	defer pkt.DecRef()
	if forwarder.HandlePacket(id, pkt) {
		t.Fatal("a refused datagram is not handled: the stack answers it with an ICMP error")
	}
	if handler.packets != 0 {
		t.Fatal("a refused datagram never reaches NewPacket")
	}
	if handler.askedCount() != 1 || handler.asked[0] != "udp [fdfe:dcba:9876::1]:40000 -> [2001:db8::10]:443" {
		t.Fatalf("the door is asked about the datagram as the app sent it, got %v", handler.asked)
	}
	handler.refuse = nil
	if !forwarder.HandlePacket(id, pkt) || handler.packets != 1 {
		t.Fatal("an allowed datagram reaches NewPacket")
	}
}

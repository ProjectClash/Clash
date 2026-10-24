//go:build with_gvisor

package tun

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type capturingTun struct {
	GVisorTun
	written [][]byte
}

func (c *capturingTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	c.written = append(c.written, pkt.Data().AsRange().ToSlice())
	return pkt.Size(), nil
}

type countingDispatcher struct {
	testNetworkDispatcher
	delivered int
}

func (d *countingDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.delivered++
}

func deliver(filter *networkDispatcherFilter, packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	defer pkt.DecRef()
	filter.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
}

func TestTheGVisorFilterAppliesIPRewriteBeforeTheStack(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect},
		IPRewriteRule{netip.MustParsePrefix("203.0.113.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("198.51.100.0/24"), IPRewriteDrop},
	)
	tun := &capturingTun{}
	dispatcher := &countingDispatcher{}
	filter := &networkDispatcherFilter{NetworkDispatcher: dispatcher, writer: tun}

	reflected := testIPv4("172.19.0.1", "10.7.0.1", protocolTCP, tcpSegment(50000, 62078, 1, 0, 0x02, nil))
	deliver(filter, reflected)
	deliver(filter, testIPv4("172.19.0.1", "203.0.113.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)))
	deliver(filter, testIPv4("172.19.0.1", "198.51.100.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)))
	if dispatcher.delivered != 0 || len(tun.written) != 2 {
		t.Fatalf("the stack got %d packets and the tun %d, want 0 and 2", dispatcher.delivered, len(tun.written))
	}
	if back := tun.written[0]; !bytes.Equal(back[12:16], reflected[16:20]) || !bytes.Equal(back[16:20], reflected[12:16]) {
		t.Errorf("reflected %v -> %v, want the addresses swapped", back[12:16], back[16:20])
	}
	if reset := tun.written[1]; reset[9] != protocolTCP || reset[20+13]&0x04 == 0 {
		t.Errorf("the rejected SYN was answered with %v, want a RST", reset)
	}
	deliver(filter, testIPv4("172.19.0.1", "192.0.2.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)))
	if dispatcher.delivered != 1 {
		t.Errorf("a packet no line covers reached the stack %d times, want once", dispatcher.delivered)
	}
}

func TestTheGVisorFilterCopiesNoUncoveredPacket(t *testing.T) {
	withIPRewrite(t, IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect})
	tun := &capturingTun{}
	filter := &networkDispatcherFilter{NetworkDispatcher: &countingDispatcher{}, writer: tun}
	packet := testIPv4("172.19.0.1", "192.0.2.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x10, make([]byte, 1400)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer pkt.DecRef()
	if allocations := testing.AllocsPerRun(100, func() {
		filter.ipRewrite(header.IPv4ProtocolNumber, pkt)
	}); allocations != 0 {
		t.Fatalf("an uncovered packet made %v allocations, want 0", allocations)
	}
	if handled := filter.ipRewrite(header.IPv4ProtocolNumber, pkt); handled || len(tun.written) != 0 {
		t.Fatal("an uncovered packet was taken")
	}
}

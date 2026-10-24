//go:build with_gvisor

package tun

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type endpointTun struct {
	*memoryTun
	endpoint *channel.Endpoint
	written  chan []byte
}

func newEndpointTun() *endpointTun {
	return &endpointTun{memoryTun: newMemoryTun(), endpoint: channel.New(16, 1500, ""), written: make(chan []byte, 16)}
}

func (t *endpointTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	t.written <- bytes.Join(pkt.AsSlices(), nil)
	return pkt.Size(), nil
}

func (t *endpointTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *endpointTun) inject(packet []byte) {
	protocol := header.IPv4ProtocolNumber
	if packet[0]>>4 == 6 {
		protocol = header.IPv6ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	t.endpoint.InjectInbound(protocol, pkt)
	pkt.DecRef()
}

func (t *endpointTun) writtenBack(tb *testing.T) []byte {
	tb.Helper()
	select {
	case packet := <-t.written:
		return packet
	case <-time.After(3 * time.Second):
		tb.Fatal("nothing was written back to the tun")
		return nil
	}
}

func TestTheGVisorStackReflectsEveryPacketToALoopbackAddress(t *testing.T) {
	device := newEndpointTun()
	defer device.Close()
	options := loopbackStackOptions(device)
	options.Context, options.Handler = context.Background(), &testHandler{}
	options.UDPTimeout, options.ICMPTimeout = time.Minute, 50*time.Millisecond
	created, err := NewGVisor(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = created.Start(); err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	for _, probe := range loopbackProbes() {
		device.inject(probe.packet)
		if back := device.writtenBack(t); !bytes.Equal(back, reflectedProbe(probe.packet)) {
			t.Errorf("%s: the tun got %x; want %x", probe.name, back, reflectedProbe(probe.packet))
		}
	}
}

func TestTheGVisorAndMixedStacksCompareTheAddressesTheExtensionRoutes(t *testing.T) {
	_, _, compared := loopbackSpellings()
	device := newEndpointTun()
	defer device.Close()
	options := spelledStackOptions(device)
	options.Context, options.Handler = context.Background(), &testHandler{}
	options.UDPTimeout, options.ICMPTimeout = time.Minute, 50*time.Millisecond
	created, err := NewGVisor(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = created.Start(); err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	filter, ok := created.(*GVisor).endpoint.(*LinkEndpointFilter)
	if !ok {
		t.Fatalf("the gVisor stack's endpoint is %T, not its filter", created.(*GVisor).endpoint)
	}
	if !slices.Equal(filter.LoopbackAddress, compared) {
		t.Errorf("the gVisor filter compares %v, want %v", filter.LoopbackAddress, compared)
	}
	mixedTun := newEndpointTun()
	defer mixedTun.Close()
	created, err = NewMixed(spelledStackOptions(mixedTun))
	if err != nil {
		t.Fatal(err)
	}
	mixed := created.(*Mixed)
	for _, probe := range spelledProbes() {
		device.inject(probe.packet)
		if back := device.writtenBack(t); !bytes.Equal(back, reflectedProbe(probe.packet)) {
			t.Errorf("gVisor, %s: the tun got %x", probe.name, back)
		}
		packet := append([]byte(nil), probe.packet...)
		if !mixed.processPacket(packet) || !bytes.Equal(packet, reflectedProbe(probe.packet)) {
			t.Errorf("mixed, %s: not reflected", probe.name)
		}
	}
}

func TestTheGVisorFilterLeavesAnUnknownActionToTheStack(t *testing.T) {
	withIPRewrite(t, IPRewriteRule{netip.MustParsePrefix("192.0.2.0/24"), IPRewriteDrop + 1})
	tun := &capturingTun{}
	dispatcher := &countingDispatcher{}
	filter := &networkDispatcherFilter{NetworkDispatcher: dispatcher, writer: tun}
	deliver(filter, testIPv4("198.18.0.1", "192.0.2.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)))
	if dispatcher.delivered != 1 || len(tun.written) != 0 {
		t.Fatalf("the stack got %d packets and the tun %d, want 1 and 0", dispatcher.delivered, len(tun.written))
	}
}

func TestTheMixedStackReflectsEveryPacketToALoopbackAddress(t *testing.T) {
	device := newEndpointTun()
	defer device.Close()
	created, err := NewMixed(loopbackStackOptions(device))
	if err != nil {
		t.Fatal(err)
	}
	m := created.(*Mixed)
	for _, probe := range loopbackProbes() {
		packet := append([]byte(nil), probe.packet...)
		if writeBack := m.processPacket(packet); !writeBack || !bytes.Equal(packet, reflectedProbe(probe.packet)) {
			t.Errorf("%s: written back %v as %x; want %x", probe.name, writeBack, packet, reflectedProbe(probe.packet))
		}
	}
}

func TestTheGVisorFilterCopiesNoUncoveredPacketBesideALoopbackAddress(t *testing.T) {
	tun := &capturingTun{}
	filter := &networkDispatcherFilter{NetworkDispatcher: &countingDispatcher{}, writer: tun,
		loopbackAddress: []netip.Addr{loopback4, loopback6}}
	packet := testIPv4("198.18.0.1", "192.0.2.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x10, make([]byte, 1400)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer pkt.DecRef()
	if allocations := testing.AllocsPerRun(100, func() {
		filter.ipRewrite(header.IPv4ProtocolNumber, pkt)
	}); allocations != 0 {
		t.Fatalf("an uncovered packet made %v allocations, want 0", allocations)
	}
	if filter.ipRewrite(header.IPv4ProtocolNumber, pkt) || len(tun.written) != 0 {
		t.Fatal("an uncovered packet was taken")
	}
}

package tun

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
)

func ipRewriteFramed(t *testing.T, frame []byte) []byte {
	t.Helper()
	return frame[PacketOffset:]
}

func TestTheSystemStackAppliesIPRewriteBeforeItsOwnWork(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect},
		IPRewriteRule{netip.MustParsePrefix("203.0.113.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("198.51.100.0/24"), IPRewriteDrop},
	)
	device := newMemoryTun()
	defer device.Close()
	s := &System{tun: device, logger: logger.NOP()}
	reflected := testIPv4("172.19.0.1", "10.7.0.1", protocolTCP, tcpSegment(50000, 62078, 1, 0, 0x02, nil))
	if !s.processPacket(reflected) || !bytes.Equal(reflected[16:20], []byte{172, 19, 0, 1}) {
		t.Fatalf("reflect: not written back swapped (%v -> %v)", reflected[12:16], reflected[16:20])
	}
	if s.processPacket(testIPv4("172.19.0.1", "203.0.113.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil))) {
		t.Fatal("reject: the packet itself was written back")
	}
	if reset := ipRewriteFramed(t, readPacket(t, device)); reset[9] != protocolTCP || reset[20+13]&0x04 == 0 {
		t.Fatalf("reject: answered %v, want a RST", reset)
	}
	if s.processPacket(testIPv4("172.19.0.1", "198.51.100.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil))) {
		t.Fatal("drop: written back")
	}
	select {
	case packet := <-device.out:
		t.Fatalf("drop: answered %v", packet)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTheMipsStackAppliesIPRewriteInItsBatch(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("10.7.0.1/32"), IPRewriteReflect},
		IPRewriteRule{netip.MustParsePrefix("203.0.113.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("198.51.100.0/24"), IPRewriteDrop},
	)
	device := newMemoryTun()
	defer device.Close()
	s := &Mipstack{tun: device, logger: logger.NOP()}
	reflected := testIPv4("172.19.0.1", "10.7.0.1", protocolTCP, tcpSegment(50000, 62078, 1, 0, 0x02, []byte("x")))
	want := append([]byte(nil), reflected...)
	swapPacketAddresses(want)
	s.processPackets([][]byte{
		testIPv4("172.19.0.1", "198.51.100.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)),
		reflected,
		testIPv4("172.19.0.1", "203.0.113.9", protocolTCP, tcpSegment(50000, 443, 1, 0, 0x02, nil)),
	}, 0)
	var got [][]byte
	for len(got) < 2 {
		got = append(got, readPacket(t, device))
	}
	var sawReflected, sawReset bool
	for _, packet := range got {
		if bytes.Equal(packet, want) {
			sawReflected = true
		} else if reset := ipRewriteFramed(t, packet); reset[9] == protocolTCP && reset[20+13]&0x04 != 0 {
			sawReset = true
		}
	}
	if !sawReflected || !sawReset {
		t.Fatalf("the tun got %v; want the reflected packet and a RST", got)
	}
	select {
	case packet := <-device.out:
		t.Fatalf("a third packet reached the tun: %v", packet)
	case <-time.After(50 * time.Millisecond):
	}
}

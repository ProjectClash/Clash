package tun

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/metacubex/sing/common/logger"
)


var (
	loopbackSource4 = netip.MustParseAddr("198.18.0.1")
	loopbackSource6 = netip.MustParseAddr("fd00::1")
	loopback4       = netip.MustParseAddr("10.7.0.1")
	loopback6       = netip.MustParseAddr("fdfe:7::1")
)

type loopbackProbe struct {
	name   string
	packet []byte
}

func loopbackProbes() []loopbackProbe {
	var probes []loopbackProbe
	for _, pair := range [][2]netip.Addr{{loopbackSource4, loopback4}, {loopbackSource6, loopback6}} {
		source, destination := pair[0], pair[1]
		family, icmp, echo := "IPv4", byte(protocolICMPv4), byte(8)
		if source.Is6() {
			family, icmp, echo = "IPv6", byte(protocolICMPv6), byte(128)
		}
		probes = append(probes,
			loopbackProbe{family + " TCP SYN", tcpPacket(source, destination, 1, 0, 0x02, nil)},
			loopbackProbe{family + " UDP", udpPacket(source, destination, 62078, []byte("probe"))},
			loopbackProbe{family + " echo request", transportPacket(source, destination, icmp, []byte{echo, 0, 0, 0, 0x12, 0x34, 0, 1})},
		)
	}
	return probes
}

func reflectedProbe(probe []byte) []byte {
	want := append([]byte(nil), probe...)
	swapPacketAddresses(want)
	return want
}

func loopbackStackOptions(device Tun) StackOptions {
	return StackOptions{Tun: device, Logger: logger.NOP(), TunOptions: Options{
		MTU:                  1500,
		Inet4Address:         []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet6Address:         []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
		Inet4LoopbackAddress: []netip.Addr{loopback4},
		Inet6LoopbackAddress: []netip.Addr{loopback6},
	}}
}

func TestALoopbackAddressIsReflectedAheadOfIPRewrite(t *testing.T) {
	withIPRewrite(t,
		IPRewriteRule{netip.MustParsePrefix("10.7.0.0/24"), IPRewriteReject},
		IPRewriteRule{netip.MustParsePrefix("192.0.2.0/24"), IPRewriteDrop},
	)
	loopback := []netip.Addr{loopback4, loopback6}
	for _, probe := range loopbackProbes() {
		packet := append([]byte(nil), probe.packet...)
		if handled, writeBack, reply := applyIPRewrite(packet, loopback); !handled || !writeBack || reply != nil || !bytes.Equal(packet, reflectedProbe(probe.packet)) {
			t.Errorf("%s: handled %v, writeBack %v, reply %v; want it reflected", probe.name, handled, writeBack, reply)
		}
	}
	neighbour := tcpPacket(loopbackSource4, netip.MustParseAddr("10.7.0.2"), 1, 0, 0x02, nil)
	if handled, writeBack, reply := applyIPRewrite(neighbour, loopback); !handled || writeBack || reply == nil {
		t.Errorf("10.7.0.2: handled %v, writeBack %v, reply %v; want the table's reject", handled, writeBack, reply)
	}
	dropped := tcpPacket(loopbackSource4, netip.MustParseAddr("192.0.2.9"), 1, 0, 0x02, nil)
	if handled, writeBack, reply := applyIPRewrite(dropped, loopback); !handled || writeBack || reply != nil {
		t.Errorf("192.0.2.9: handled %v, writeBack %v, reply %v; want the table's drop", handled, writeBack, reply)
	}
}

func TestALoopbackAddressNeedsNoTable(t *testing.T) {
	probe := tcpPacket(loopbackSource4, loopback4, 1, 0, 0x02, nil)
	if handled, _, _ := applyIPRewrite(append([]byte(nil), probe...), nil); handled {
		t.Fatal("taken with no table and no loopback address")
	}
	if handled, writeBack, _ := applyIPRewrite(append([]byte(nil), probe...), []netip.Addr{loopback4}); !handled || !writeBack {
		t.Fatalf("handled %v, writeBack %v; want a loopback address alone reflected", handled, writeBack)
	}
}

func loopbackSpellings() (inet4, inet6, compared []netip.Addr) {
	inet4 = []netip.Addr{loopback4}
	inet6 = []netip.Addr{netip.MustParseAddr("::ffff:10.7.0.2"), loopback6, netip.MustParseAddr("fe80::1%utun4"), netip.MustParseAddr("::ffff:10.7.0.1")}
	compared = []netip.Addr{loopback4, netip.MustParseAddr("10.7.0.2"), loopback6, netip.MustParseAddr("fe80::1")}
	return
}

func spelledProbes() []loopbackProbe {
	return []loopbackProbe{
		{"::ffff:10.7.0.2", tcpPacket(loopbackSource4, netip.MustParseAddr("10.7.0.2"), 1, 0, 0x02, nil)},
		{"fe80::1%utun4", udpPacket(loopbackSource6, netip.MustParseAddr("fe80::1"), 62078, []byte("probe"))},
	}
}

func spelledStackOptions(device Tun) StackOptions {
	options := loopbackStackOptions(device)
	options.TunOptions.Inet4LoopbackAddress, options.TunOptions.Inet6LoopbackAddress, _ = loopbackSpellings()
	return options
}

func TestTheSystemAndMipsStacksCompareTheAddressesTheExtensionRoutes(t *testing.T) {
	_, _, compared := loopbackSpellings()
	if got := LoopbackAddresses(nil, []netip.Addr{{}}); len(got) != 0 {
		t.Errorf("an empty address is compared as %v", got)
	}
	systemTun := newMemoryTun()
	created, err := NewSystem(spelledStackOptions(systemTun))
	if err != nil {
		t.Fatal(err)
	}
	system := created.(*System)
	t.Cleanup(func() { _ = system.Close(); _ = systemTun.Close() })
	if !slices.Equal(system.ipRewriteLoopback, compared) {
		t.Errorf("system stack compares %v, want %v", system.ipRewriteLoopback, compared)
	}
	mipsTun := newMemoryTun()
	created, err = NewStack("mips", spelledStackOptions(mipsTun))
	if err != nil {
		t.Fatal(err)
	}
	mips := created.(*Mipstack)
	t.Cleanup(func() { _ = mips.Close(); _ = mipsTun.Close() })
	if !slices.Equal(mips.ipRewriteLoopback, compared) {
		t.Errorf("mips stack compares %v, want %v", mips.ipRewriteLoopback, compared)
	}
	for _, probe := range spelledProbes() {
		packet := append([]byte(nil), probe.packet...)
		if !system.processPacket(packet) || !bytes.Equal(packet, reflectedProbe(probe.packet)) {
			t.Errorf("system, %s: not reflected", probe.name)
		}
		mips.processPackets([][]byte{append([]byte(nil), probe.packet...)}, 0)
		if back := readPacket(t, mipsTun); !bytes.Equal(back, reflectedProbe(probe.packet)) {
			t.Errorf("mips, %s: the tun got %x", probe.name, back)
		}
	}
}

func TestTheSystemStackReflectsEveryPacketToALoopbackAddress(t *testing.T) {
	device := newMemoryTun()
	defer device.Close()
	created, err := NewSystem(loopbackStackOptions(device))
	if err != nil {
		t.Fatal(err)
	}
	s := created.(*System)
	for _, probe := range loopbackProbes() {
		packet := append([]byte(nil), probe.packet...)
		if writeBack := s.processPacket(packet); !writeBack || !bytes.Equal(packet, reflectedProbe(probe.packet)) {
			t.Errorf("%s: written back %v as %x; want %x", probe.name, writeBack, packet, reflectedProbe(probe.packet))
		}
	}
}

func TestTheMipsStackReflectsEveryPacketToALoopbackAddress(t *testing.T) {
	device := newMemoryTun()
	testStack(t, device, &testHandler{}, func(options *StackOptions) {
		options.TunOptions.Inet4LoopbackAddress = []netip.Addr{loopback4}
		options.TunOptions.Inet6LoopbackAddress = []netip.Addr{loopback6}
	})
	for _, probe := range loopbackProbes() {
		device.in <- append([]byte(nil), probe.packet...)
		if back := readPacket(t, device); !bytes.Equal(back, reflectedProbe(probe.packet)) {
			t.Errorf("%s: the tun got %x; want %x", probe.name, back, reflectedProbe(probe.packet))
		}
	}
}

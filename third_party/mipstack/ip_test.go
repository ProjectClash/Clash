package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestICMPFilterValues(t *testing.T) {
	var ipv4 ICMPv4Filter
	if ipv4.WillBlock(0) {
		t.Fatal("zero-value ICMPv4 filter blocks Echo Reply")
	}
	ipv4.Block(0)
	ipv4.Block(31)
	if !ipv4.WillBlock(0) || !ipv4.WillBlock(31) || !ipv4.WillBlock(32) {
		t.Fatal("ICMPv4 filter did not preserve the Linux 32-bit mask semantics")
	}
	ipv4.Accept(32)
	if ipv4.WillBlock(0) || !ipv4.WillBlock(31) {
		t.Fatal("ICMPv4 Accept changed the wrong mask bit")
	}
	ipv4.SetAll(true)
	if !ipv4.WillBlock(0) || !ipv4.WillBlock(31) {
		t.Fatal("ICMPv4 SetAll(true) did not block every representable type")
	}
	ipv4.SetAll(false)
	if ipv4.WillBlock(0) || ipv4.WillBlock(31) {
		t.Fatal("ICMPv4 SetAll(false) did not restore the all-accepting filter")
	}

	var ipv6 ICMPv6Filter
	for _, typ := range []uint8{0, 31, 32, 127, 128, 255} {
		if ipv6.WillBlock(typ) {
			t.Fatalf("zero-value ICMPv6 filter blocks type %d", typ)
		}
		ipv6.Block(typ)
		if !ipv6.WillBlock(typ) {
			t.Fatalf("ICMPv6 filter did not block type %d", typ)
		}
	}
	ipv6.Accept(32)
	if ipv6.WillBlock(32) || !ipv6.WillBlock(31) || !ipv6.WillBlock(255) {
		t.Fatal("ICMPv6 Accept changed an adjacent mask word")
	}
	ipv6.SetAll(true)
	for typ := 0; typ <= 255; typ++ {
		if !ipv6.WillBlock(uint8(typ)) {
			t.Fatalf("ICMPv6 SetAll(true) left type %d accepted", typ)
		}
	}
	ipv6.SetAll(false)
	for typ := 0; typ <= 255; typ++ {
		if ipv6.WillBlock(uint8(typ)) {
			t.Fatalf("ICMPv6 SetAll(false) left type %d blocked", typ)
		}
	}
}

func TestIPv6UDPChecksumNegativeZero(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::101")
	target := netip.MustParseAddr("2001:db8::102")
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload[0:2], transportChecksum(source, target, ProtocolUDP, payload))
	if value := transportChecksum(source, target, ProtocolUDP, payload); value != 0 {
		t.Fatalf("constructed UDP checksum = %#x, want zero", value)
	}
	if err := setIPv6PayloadChecksum(payload, source, target, ProtocolUDP, 6); err != nil {
		t.Fatal(err)
	}
	if value := binary.BigEndian.Uint16(payload[6:8]); value != 0xffff {
		t.Fatalf("inserted zero UDP checksum = %#x, want 0xffff", value)
	}
	if value := transportChecksum(source, target, ProtocolUDP, payload); value != 0 {
		t.Fatalf("negative-zero UDP checksum verifies as %#x", value)
	}
}

func TestIPConnReceivePolicyConcurrentUpdates(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.103")
	remote4 := netip.MustParseAddr("198.51.100.103")
	local6 := netip.MustParseAddr("2001:db8::103")
	remote6 := netip.MustParseAddr("2001:db8:1::103")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	ipv4 := newIPConn(stack, "ip4:icmp", ProtocolICMPv4, local4, netip.Addr{}, socketOptionSet{})
	ipv6 := newIPConn(stack, "ip6:99", 99, local6, netip.Addr{}, socketOptionSet{})
	defer ipv4.closeFromStack()
	defer ipv6.closeFromStack()

	checksummed := []byte{0x31, 0x32, 0, 0, 0x35, 0x36, 0x37, 0x38}
	binary.BigEndian.PutUint16(checksummed[2:4], transportChecksum(remote6, local6, 99, checksummed))
	const iterations = 1000
	start := make(chan struct{})
	errors := make(chan error, 2)
	var waitGroup sync.WaitGroup
	waitGroup.Add(4)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			var filter ICMPv4Filter
			if index&1 != 0 {
				filter.Block(0)
			}
			if setErr := ipv4.SetICMPv4Filter(filter); setErr != nil {
				errors <- setErr
				return
			}
			if _, getErr := ipv4.ICMPv4Filter(); getErr != nil {
				errors <- getErr
				return
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			ipv4.enqueuePacket(ipPacket{payload: []byte{0, 0, 0, 0, 1, 2, 3, 4}, source: remote4, target: local4}, ipPacketOptions{})
		}
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			if setErr := ipv6.SetIPv6Checksum(index&1 == 0, 2); setErr != nil {
				errors <- setErr
				return
			}
			if _, _, getErr := ipv6.IPv6Checksum(); getErr != nil {
				errors <- getErr
				return
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			ipv6.enqueuePacket(ipPacket{payload: checksummed, source: remote6, target: local6}, ipPacketOptions{})
		}
	}()
	close(start)
	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent receive-policy operations did not finish")
	}
	select {
	case operationErr := <-errors:
		t.Fatal(operationErr)
	default:
	}
}

func TestIPConnFanoutAndLinuxControl(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		controlSize   int
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.110"), remote: netip.MustParseAddr("198.51.100.110"), controlSize: 80},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::110"), remote: netip.MustParseAddr("2001:db8:1::110"), controlSize: 112},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, test.local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			network := "ip4:99"
			if test.local.Is6() {
				network = "ip6:99"
			}
			exact, err := stack.ListenIP(context.Background(), network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer exact.Close()
			wildcard := netip.IPv4Unspecified()
			if test.local.Is6() {
				wildcard = netip.IPv6Unspecified()
			}
			all, err := stack.ListenIP(context.Background(), network, wildcard)
			if err != nil {
				t.Fatal(err)
			}
			defer all.Close()
			options := ipPacketOptions{hopLimit: 37, trafficClass: 0xb9}
			packet := buildIPPacketWithOptions(test.remote, test.local, 99, []byte("raw-payload"), 7, true, options)
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 32)
			n, source, err := exact.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "raw-payload" || !source.(*net.IPAddr).IP.Equal(net.IP(test.remote.AsSlice())) {
				t.Fatalf("ReadFrom = %q from %v, %v", buffer[:n], source, err)
			}
			short := make([]byte, 3)
			oob := make([]byte, 128)
			n, oobn, flags, source, err := all.(*IPConn).ReadMsgIP(short, oob)
			if err != nil || n != len(short) || string(short) != "raw" || flags != MessageFlagTruncated || oobn != test.controlSize {
				t.Fatalf("ReadMsgIP = %q/%d flags %#x from %v, %v", short[:n], oobn, flags, source, err)
			}
			if test.local.Is4() {
				var message IPv4ControlMessage
				if controlErr := message.Parse(oob[:oobn]); controlErr != nil || message != (IPv4ControlMessage{TTL: 37, TOS: 0xb9, Dst: test.local}) {
					t.Fatalf("IPv4 control = %+v, %v", message, controlErr)
				}
			} else {
				var message IPv6ControlMessage
				if controlErr := message.Parse(oob[:oobn]); controlErr != nil || message != (IPv6ControlMessage{HopLimit: 37, TrafficClass: 0xb9, Dst: test.local}) {
					t.Fatalf("IPv6 control = %+v, %v", message, controlErr)
				}
			}
			if stats := stack.Stats(); stats.ActiveIPSockets != 2 {
				t.Fatalf("active IP sockets = %d, want 2", stats.ActiveIPSockets)
			}
			if stack.outbound.len() != 0 {
				t.Fatal("raw-consumed protocol generated Protocol Unreachable")
			}
		})
	}
}

func TestIPConnFanoutExceedsInlineStorage(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.111")
	remote := netip.MustParseAddr("198.51.100.111")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	connections := make([]net.PacketConn, 0, ipEndpointInlineFanout+3)
	for index := 0; index < cap(connections); index++ {
		connection, listenErr := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		connections = append(connections, connection)
		defer connection.Close()
	}
	packet := buildIPPacket(remote, local, 99, []byte("fan-out"), 0, true)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	for index, connection := range connections {
		if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 16)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != "fan-out" {
			t.Fatalf("connection %d read = %q, %v", index, buffer[:n], readErr)
		}
	}
}

func TestIPConnConcurrentClose(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.112")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}

	const closers = 32
	start := make(chan struct{})
	results := make(chan error, closers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(closers)
	for index := 0; index < closers; index++ {
		go func() {
			defer waitGroup.Done()
			<-start
			results <- connection.Close()
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	nilResults := 0
	for closeErr := range results {
		if closeErr == nil {
			nilResults++
		} else if !errors.Is(closeErr, net.ErrClosed) {
			t.Fatalf("Close = %v", closeErr)
		}
	}
	if nilResults != 1 {
		t.Fatalf("successful Close calls = %d, want 1", nilResults)
	}
	if stats := stack.Stats(); stats.ActiveIPSockets != 0 {
		t.Fatalf("active IP sockets = %d, want 0", stats.ActiveIPSockets)
	}
}

func TestIPConnConcurrentStackAndSocketClose(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.113")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := connection.(*IPConn).Read(make([]byte, 1))
		readResult <- readErr
	}()
	waitFor(t, time.Second, func() bool {
		connection.(*IPConn).mu.Lock()
		waiting := connection.(*IPConn).receiveNotify != nil
		connection.(*IPConn).mu.Unlock()
		return waiting
	})

	start := make(chan struct{})
	stackResult := make(chan error, 1)
	connectionResult := make(chan error, 1)
	go func() {
		<-start
		stackResult <- stack.Close()
	}()
	go func() {
		<-start
		connectionResult <- connection.Close()
	}()
	close(start)
	if closeErr := <-stackResult; closeErr != nil {
		t.Fatalf("Stack.Close = %v", closeErr)
	}
	if closeErr := <-connectionResult; closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		t.Fatalf("IPConn.Close = %v", closeErr)
	}
	if readErr := <-readResult; !errors.Is(readErr, net.ErrClosed) {
		t.Fatalf("blocked Read = %v, want net.ErrClosed", readErr)
	}
}

func TestIPNetworkAPI(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.122")
	local6 := netip.MustParseAddr("2001:db8::122")
	remote4 := netip.MustParseAddr("198.51.100.122")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32),
		netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenIP(context.Background(), "ip4:UDP", local4)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := stack.DialIP(context.Background(), "ip:99", netip.Addr{}, remote4)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := connection.(*IPConn); !ok {
		t.Fatalf("DialIP connection type = %T", connection)
	}
	_ = connection.Close()
	if _, err = stack.ListenIP(context.Background(), "ip6:udp", local4); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("ListenIP family mismatch = %v, want EAFNOSUPPORT", err)
	}
	if _, err = stack.DialIP(context.Background(), "ip4", netip.Addr{}, remote4); err == nil {
		t.Fatal("DialIP without protocol succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialIP unknown network error = %v", err)
		}
	}
	if _, err = stack.DialIP(context.Background(), "ip4:not-a-protocol", netip.Addr{}, remote4); err == nil {
		t.Fatal("DialIP with unknown protocol succeeded")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("DialIP unknown protocol error = %v", err)
		}
	}
}

func TestListenIPEmptyAddressDualStack(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.123")
	local6 := netip.MustParseAddr("2001:db8::123")
	remote4 := netip.MustParseAddr("198.51.100.123")
	remote6 := netip.MustParseAddr("2001:db8:1::123")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if !connection.(*IPConn).dual || connection.(*IPConn).local != netip.IPv6Unspecified() {
		t.Fatalf("generic IP wildcard = %v, dual = %v", connection.(*IPConn).local, connection.(*IPConn).dual)
	}
	for _, packet := range [][]byte{
		buildIPPacket(remote4, local4, 99, []byte("v4"), 1, true),
		buildIPPacket(remote6, local6, 99, []byte("v6"), 2, true),
	} {
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2)
	for _, want := range []string{"v4", "v6"} {
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != want {
			t.Fatalf("dual IP read = %q, %v, want %q", buffer[:n], readErr, want)
		}
	}

	ipv4Only, err := stack.ListenIP(context.Background(), "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipv4Only.Close()
	if ipv4Only.(*IPConn).dual || ipv4Only.(*IPConn).local != netip.IPv4Unspecified() {
		t.Fatalf("IPv4 IP wildcard = %v, dual = %v", ipv4Only.(*IPConn).local, ipv4Only.(*IPConn).dual)
	}
}

func TestIPConnObservesUDPWithoutConsumingIt(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.111")
	remote := netip.MustParseAddr("198.51.100.111")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	raw, err := stack.ListenIP(context.Background(), "ip4:udp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	packetSocket, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50100))
	if err != nil {
		t.Fatal(err)
	}
	defer packetSocket.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50101, 50100, []byte("both"))); err != nil {
		t.Fatal(err)
	}
	rawBuffer := make([]byte, 64)
	n, source, err := raw.ReadFrom(rawBuffer)
	if err != nil || source.String() != remote.String() || n < udpHeaderSize || string(rawBuffer[udpHeaderSize:n]) != "both" {
		t.Fatalf("raw UDP copy = %x from %v, %v", rawBuffer[:n], source, err)
	}
	udpBuffer := make([]byte, 16)
	n, sourceAddr, err := packetSocket.ReadFrom(udpBuffer)
	if err != nil || string(udpBuffer[:n]) != "both" || sourceAddr.String() != netip.AddrPortFrom(remote, 50101).String() {
		t.Fatalf("UDP delivery = %q from %v, %v", udpBuffer[:n], sourceAddr, err)
	}
}

func TestIPConnWriteMsgSourceAndHeaderOptions(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.112")
	second := netip.MustParseAddr("192.0.2.113")
	remote := netip.MustParseAddr("198.51.100.112")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	options := ipPacketOptions{hopLimit: 31, trafficClass: 0xb8}
	oob, err := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: second}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	n, oobn, err := connection.(*IPConn).WriteMsgIP([]byte("raw-output"), oob, ipNetAddr(remote))
	if err != nil || n != 10 || oobn != len(oob) {
		t.Fatalf("WriteMsgIP = %d/%d, %v", n, oobn, err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != second || packet.target != remote || packet.protocol != 99 || packet.hopLimit != options.hopLimit || packet.trafficClass != options.trafficClass || string(packet.payload) != "raw-output" {
		t.Fatalf("raw output = %+v, parsed = %v", packet, ok)
	}
	mixedControl := mustCodecVector(t, "1c00000000000000000000000800000000000000c0000271c0000270")
	n, oobn, err = connection.(*IPConn).WriteMsgIP([]byte("spec-dst"), mixedControl, ipNetAddr(remote))
	if err != nil || n != len("spec-dst") || oobn != len(mixedControl) {
		t.Fatalf("mixed WriteMsgIP = %d/%d, %v", n, oobn, err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != second || string(packet.payload) != "spec-dst" {
		t.Fatalf("mixed IPv4 packet-info source = %s payload %q, want %s/spec-dst", packet.source, packet.payload, second)
	}
	addrOnlyControl := mustCodecVector(t, "1c0000000000000000000000080000000000000000000000c0000271")
	n, oobn, err = connection.(*IPConn).WriteMsgIP([]byte("addr-only"), addrOnlyControl, ipNetAddr(remote))
	if err != nil || n != len("addr-only") || oobn != len(addrOnlyControl) {
		t.Fatalf("addr-only WriteMsgIP = %d/%d, %v", n, oobn, err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != first || string(packet.payload) != "addr-only" {
		t.Fatalf("addr-only IPv4 packet-info source = %s payload %q, want %s/addr-only", packet.source, packet.payload, first)
	}
	if err = connection.(*IPConn).SetWriteBuffer(64 * 1024); err != nil {
		t.Fatalf("SetWriteBuffer no-op = %v", err)
	}
	if err = connection.(*IPConn).SetWriteBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetWriteBuffer(0) = %v, want EINVAL", err)
	}
	specificStack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = specificStack.Start(); err != nil {
		t.Fatal(err)
	}
	defer specificStack.Close()
	specificNet, err := specificStack.ListenIP(context.Background(), "ip4:99", first)
	if err != nil {
		t.Fatal(err)
	}
	specific := specificNet.(*IPConn)
	defer specific.Close()
	specificControl, err := (&IPv4ControlMessage{Src: second}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = specific.WriteMsgIP([]byte("bound-source"), specificControl, ipNetAddr(remote)); err != nil {
		t.Fatalf("specific-bound IP packet-info source = %v", err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, specificStack), false)
	if !ok || packet.source != second || string(packet.payload) != "bound-source" {
		t.Fatalf("specific-bound IP packet-info source = %s payload %q, want %s/bound-source", packet.source, packet.payload, second)
	}
	first6 := netip.MustParseAddr("2001:db8::112")
	second6 := netip.MustParseAddr("2001:db8::113")
	remote6 := netip.MustParseAddr("2001:db8:1::112")
	specificV6Stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first6, 128), netip.PrefixFrom(second6, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = specificV6Stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer specificV6Stack.Close()
	specificV6Net, err := specificV6Stack.ListenIP(context.Background(), "ip6:99", first6)
	if err != nil {
		t.Fatal(err)
	}
	specificV6 := specificV6Net.(*IPConn)
	defer specificV6.Close()
	specificV6Control, err := (&IPv6ControlMessage{Src: second6}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = specificV6.WriteMsgIP([]byte("bound-source-v6"), specificV6Control, ipNetAddr(remote6)); err != nil {
		t.Fatalf("specific-bound IPv6 IP packet-info source = %v", err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, specificV6Stack), false)
	if !ok || packet.source != second6 || string(packet.payload) != "bound-source-v6" {
		t.Fatalf("specific-bound IPv6 IP packet-info source = %s payload %q, want %s/bound-source-v6", packet.source, packet.payload, second6)
	}
}

func TestIPConnTypedWritesAndDeadlines(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.123")
	remote := netip.MustParseAddr("198.51.100.123")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("typed-read"), 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, source, err := connection.(*IPConn).ReadFromIP(buffer)
	if err != nil || string(buffer[:n]) != "typed-read" || source == nil || !source.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("ReadFromIP = %q from %v, %v", buffer[:n], source, err)
	}
	if connection.(*IPConn).RemoteAddr() != nil {
		t.Fatalf("unconnected remote address = %v", connection.(*IPConn).RemoteAddr())
	}
	if _, writeErr := connection.(*IPConn).WriteToIP([]byte("missing"), nil); writeErr == nil {
		t.Fatal("WriteToIP accepted a nil address")
	} else if operationError := checkNetOpError(t, writeErr, "write", "ip4:99"); operationError.Addr != nil {
		t.Fatalf("nil WriteToIP error address = %#v, want nil", operationError.Addr)
	}
	var nilIP *net.IPAddr
	if _, writeErr := connection.WriteTo([]byte("missing"), nilIP); writeErr == nil {
		t.Fatal("WriteTo accepted a nil *net.IPAddr")
	} else if operationError := checkNetOpError(t, writeErr, "write", "ip4:99"); operationError.Addr != nil {
		t.Fatalf("nil *net.IPAddr error address = %#v, want nil", operationError.Addr)
	}
	if err = connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, writeErr := connection.(*IPConn).WriteToIP([]byte("typed"), ipNetAddr(remote)); writeErr != nil || n != len("typed") {
		t.Fatalf("WriteToIP = %d, %v", n, writeErr)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack), false); !ok || string(packet.payload) != "typed" || packet.target != remote {
		t.Fatalf("typed output = %+v, parsed = %v", packet, ok)
	}
	if n, writeErr := connection.WriteTo([]byte("generic"), ipNetAddr(remote)); writeErr != nil || n != len("generic") {
		t.Fatalf("WriteTo = %d, %v", n, writeErr)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack), false); !ok || string(packet.payload) != "generic" || packet.target != remote {
		t.Fatalf("generic output = %+v, parsed = %v", packet, ok)
	}
	if err = connection.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.(*IPConn).WriteToIP([]byte("late"), ipNetAddr(remote)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired WriteToIP = %v, want deadline", err)
	}
	if _, _, err = connection.(*IPConn).WriteMsgIP([]byte("late"), make([]byte, linuxControlHeaderSize), ipNetAddr(remote)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired WriteMsgIP with invalid control = %v, want deadline", err)
	}
	wrongFamily := &net.IPAddr{IP: net.ParseIP("2001:db8::123")}
	if _, _, err = connection.(*IPConn).WriteMsgIP([]byte("wrong-family"), make([]byte, linuxControlHeaderSize), wrongFamily); err == nil {
		t.Fatal("WriteMsgIP accepted an IPv6 destination on an IPv4 socket")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("WriteMsgIP family/control precedence = %T %v, want net.AddrError", err, err)
		}
	}
}

func TestConnectedIPConnAndICMPv6Checksum(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::114")
	remote := netip.MustParseAddr("2001:db8:1::114")
	other := netip.MustParseAddr("2001:db8:1::115")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialIP(context.Background(), "ip6:ipv6-icmp", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ipConnection := connection.(*IPConn)
	if enabled, offset, checksumErr := ipConnection.IPv6Checksum(); checksumErr != nil || !enabled || offset != 2 {
		t.Fatalf("mandatory ICMPv6 checksum policy = %v/%d, %v", enabled, offset, checksumErr)
	}
	for _, enabled := range []bool{false, true} {
		if checksumErr := ipConnection.SetIPv6Checksum(enabled, 2); !errors.Is(checksumErr, syscall.EINVAL) {
			t.Fatalf("SetIPv6Checksum(%v) on ICMPv6 = %v, want EINVAL", enabled, checksumErr)
		}
	}
	if _, writeErr := connection.Write([]byte{128, 0, 0}); !errors.Is(writeErr, syscall.EINVAL) {
		t.Fatalf("short ICMPv6 write = %v, want EINVAL", writeErr)
	}
	payload := []byte{128, 0, 0, 0, 0, 1, 0, 1}
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("connected IP Write = %d, %v", n, writeErr)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || transportChecksum(local, remote, ProtocolICMPv6, packet.payload) != 0 {
		t.Fatalf("ICMPv6 raw checksum is invalid: %x", packet.payload)
	}
	if _, _, err = ipConnection.WriteMsgIP(payload, nil, nil); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected IP WriteMsgIP = %v, want net.ErrWriteToConnected", err)
	} else if operationError := checkNetOpError(t, err, "write", "ip6:ipv6-icmp"); operationError.Addr != nil {
		t.Fatalf("connected IP WriteMsgIP error address = %v, want nil", operationError.Addr)
	}
	if _, err = ipConnection.WriteToIP(payload, nil); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected IP WriteToIP(nil) = %v, want net.ErrWriteToConnected", err)
	} else if operationError := checkNetOpError(t, err, "write", "ip6:ipv6-icmp"); operationError.Addr != nil {
		t.Fatalf("connected IP WriteToIP(nil) error address = %v, want nil", operationError.Addr)
	}
	wrong := buildIPPacket(other, local, ProtocolICMPv6, []byte{129, 0, 0, 0, 0, 1, 0, 1}, 0, true)
	binaryPayload := wrong[40:]
	binaryPayload[2], binaryPayload[3] = 0, 0
	checksumValue := transportChecksum(other, local, ProtocolICMPv6, binaryPayload)
	binaryPayload[2], binaryPayload[3] = byte(checksumValue>>8), byte(checksumValue)
	if err = writeTestPacket(stack, wrong); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err = connection.Read(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected remote filter error = %v, want deadline", err)
	}
	_ = connection.SetReadDeadline(time.Time{})
	invalid := buildIPPacket(remote, local, ProtocolICMPv6, []byte{129, 0, 0, 0, 0, 1, 0, 1}, 0, true)
	if err = writeTestPacket(stack, invalid); err != nil {
		t.Fatal(err)
	}
	readMessages := []SocketMessage{{Buffers: [][]byte{make([]byte, 16)}}}
	if count, readErr := ipConnection.ReadBatch(readMessages, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("invalid ICMPv6 checksum read = %d, %v, want EAGAIN", count, readErr)
	}
	reply := buildIPPacket(remote, local, ProtocolICMPv6, []byte{129, 0, 0, 0, 0, 1, 0, 1}, 0, true)
	replyPayload := reply[40:]
	replyPayload[2], replyPayload[3] = 0, 0
	checksumValue = transportChecksum(remote, local, ProtocolICMPv6, replyPayload)
	replyPayload[2], replyPayload[3] = byte(checksumValue>>8), byte(checksumValue)
	if err = writeTestPacket(stack, reply); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, err := connection.Read(buffer)
	if err != nil || n != len(replyPayload) || !bytes.Equal(buffer[:n], replyPayload) {
		t.Fatalf("connected IP Read = %x, %v", buffer[:n], err)
	}
}

func TestIPConnICMPReceiveFilters(t *testing.T) {
	tests := []struct {
		name        string
		local       netip.Addr
		remote      netip.Addr
		network     string
		protocol    byte
		messageType byte
		option      func() (SocketOption, any)
	}{
		{
			name: "IPv4", local: netip.MustParseAddr("192.0.2.150"), remote: netip.MustParseAddr("198.51.100.150"),
			network: "ip4:icmp", protocol: ProtocolICMPv4, messageType: 0,
			option: func() (SocketOption, any) {
				var filter ICMPv4Filter
				filter.Block(0)
				return SocketOptions.ICMPv4Filter(filter), filter
			},
		},
		{
			name: "IPv6", local: netip.MustParseAddr("2001:db8::150"), remote: netip.MustParseAddr("2001:db8:1::150"),
			network: "ip6:ipv6-icmp", protocol: ProtocolICMPv6, messageType: 129,
			option: func() (SocketOption, any) {
				var filter ICMPv6Filter
				filter.Block(129)
				return SocketOptions.ICMPv6Filter(filter), filter
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, test.local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			option, originalFilter := test.option()
			connection, err := (&ListenConfig{Options: []SocketOption{option}}).ListenIP(context.Background(), stack, test.network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()

			message := []byte{test.messageType, 0, 0, 0, 0x12, 0x34, 0x56, 0x78}
			if test.protocol == ProtocolICMPv4 {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
			} else {
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(test.remote, test.local, test.protocol, message))
			}
			write := func() {
				if writeErr := writeTestPacket(stack, buildIPPacket(test.remote, test.local, test.protocol, message, 1, true)); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			assertEmpty := func() {
				messages := []SocketMessage{{Buffers: [][]byte{make([]byte, 32)}}}
				if count, readErr := connection.(*IPConn).ReadBatch(messages, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
					t.Fatalf("filtered read = %d, %v, want EAGAIN", count, readErr)
				}
			}
			write()
			assertEmpty()

			switch filter := originalFilter.(type) {
			case ICMPv4Filter:
				filter.Accept(test.messageType)
				current, filterErr := connection.(*IPConn).ICMPv4Filter()
				if filterErr != nil || !current.WillBlock(test.messageType) {
					t.Fatalf("ICMPv4 creation snapshot = %+v, %v", current, filterErr)
				}
				current.Accept(test.messageType)
				again, filterErr := connection.(*IPConn).ICMPv4Filter()
				if filterErr != nil || !again.WillBlock(test.messageType) {
					t.Fatalf("ICMPv4 getter retained caller mutation: %+v, %v", again, filterErr)
				}
				var accepting ICMPv4Filter
				if filterErr = connection.(*IPConn).SetICMPv4Filter(accepting); filterErr != nil {
					t.Fatal(filterErr)
				}
				write()
				var blocking ICMPv4Filter
				blocking.Block(test.messageType)
				if filterErr = connection.(*IPConn).SetICMPv4Filter(blocking); filterErr != nil {
					t.Fatal(filterErr)
				}
				blocking.Accept(test.messageType)
			case ICMPv6Filter:
				filter.Accept(test.messageType)
				current, filterErr := connection.(*IPConn).ICMPv6Filter()
				if filterErr != nil || !current.WillBlock(test.messageType) {
					t.Fatalf("ICMPv6 creation snapshot = %+v, %v", current, filterErr)
				}
				current.Accept(test.messageType)
				again, filterErr := connection.(*IPConn).ICMPv6Filter()
				if filterErr != nil || !again.WillBlock(test.messageType) {
					t.Fatalf("ICMPv6 getter retained caller mutation: %+v, %v", again, filterErr)
				}
				var accepting ICMPv6Filter
				if filterErr = connection.(*IPConn).SetICMPv6Filter(accepting); filterErr != nil {
					t.Fatal(filterErr)
				}
				write()
				var blocking ICMPv6Filter
				blocking.Block(test.messageType)
				if filterErr = connection.(*IPConn).SetICMPv6Filter(blocking); filterErr != nil {
					t.Fatal(filterErr)
				}
				blocking.Accept(test.messageType)
			}

			buffer := make([]byte, len(message))
			if read, _, readErr := connection.ReadFrom(buffer); readErr != nil || read != len(message) || !bytes.Equal(buffer, message) {
				t.Fatalf("packet queued before filter replacement = %x, %v", buffer[:read], readErr)
			}
			write()
			assertEmpty()
			if test.protocol == ProtocolICMPv4 {
				message[0], message[2], message[3] = 32, 0, 0
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
				write()
				buffer := make([]byte, len(message))
				if read, _, readErr := connection.ReadFrom(buffer); readErr != nil || read != len(message) || !bytes.Equal(buffer, message) {
					t.Fatalf("out-of-mask ICMPv4 packet = %x, %v", buffer[:read], readErr)
				}
			}
			if stack.outbound.len() != 0 {
				t.Fatal("a filtered raw ICMP packet generated output")
			}
		})
	}
}

func TestIPConnICMPFilterStateIsLazy(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.241")
	connection := newIPConn(nil, "ip4:icmp", ProtocolICMPv4, local, netip.Addr{}, socketOptionSet{})
	if connection.icmpFilter != nil {
		t.Fatal("default ICMP filter allocated state")
	}
	var filter ICMPv4Filter
	filter.Block(ICMPv4TypeEchoRequest)
	if err := connection.SetICMPv4Filter(filter); err != nil || connection.icmpFilter == nil {
		t.Fatalf("SetICMPv4Filter = %v, state %p", err, connection.icmpFilter)
	}
	filter.SetAll(false)
	if err := connection.SetICMPv4Filter(filter); err != nil || connection.icmpFilter != nil {
		t.Fatalf("clear ICMPv4 filter = %v, state %p", err, connection.icmpFilter)
	}
}

func TestIPConnIPv6ChecksumPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::151")
	remote := netip.MustParseAddr("2001:db8:1::151")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPv6Checksum(true, 2),
	}}).ListenIP(context.Background(), stack, "ip6:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if enabled, offset, checksumErr := connection.(*IPConn).IPv6Checksum(); checksumErr != nil || !enabled || offset != 2 {
		t.Fatalf("initial IPv6 checksum policy = %v/%d, %v", enabled, offset, checksumErr)
	}
	if err = connection.(*IPConn).SetIPv6Checksum(true, -1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("negative enabled checksum offset = %v, want EINVAL", err)
	}
	if err = connection.(*IPConn).SetIPv6Checksum(true, 3); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("odd enabled checksum offset = %v, want EINVAL", err)
	}

	valid := []byte{0x31, 0x32, 0, 0, 0x35, 0x36, 0x37, 0x38}
	binary.BigEndian.PutUint16(valid[2:4], transportChecksum(remote, local, 99, valid))
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, valid, 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if read, _, readErr := connection.ReadFrom(buffer); readErr != nil || !bytes.Equal(buffer[:read], valid) {
		t.Fatalf("checksum-valid raw receive = %x, %v", buffer[:read], readErr)
	}
	invalid := append([]byte(nil), valid...)
	invalid[len(invalid)-1] ^= 0xff
	for _, payload := range [][]byte{invalid, {1, 2, 3}} {
		if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, payload, 2, true)); err != nil {
			t.Fatal(err)
		}
	}
	messages := []SocketMessage{{Buffers: [][]byte{buffer}}}
	if count, readErr := connection.(*IPConn).ReadBatch(messages, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("invalid-checksum receive = %d, %v, want EAGAIN", count, readErr)
	}
	if err = connection.(*IPConn).SetIPv6Checksum(false, -99); err != nil {
		t.Fatal(err)
	}
	if enabled, offset, checksumErr := connection.(*IPConn).IPv6Checksum(); checksumErr != nil || enabled || offset != 0 {
		t.Fatalf("disabled IPv6 checksum policy = %v/%d, %v", enabled, offset, checksumErr)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, invalid, 3, true)); err != nil {
		t.Fatal(err)
	}
	if read, _, readErr := connection.ReadFrom(buffer); readErr != nil || !bytes.Equal(buffer[:read], invalid) {
		t.Fatalf("disabled-checksum raw receive = %x, %v", buffer[:read], readErr)
	}
	if err = connection.(*IPConn).SetIPv6Checksum(true, 2); err != nil {
		t.Fatal(err)
	}

	outbound := []byte{0x41, 0x42, 0xaa, 0xbb, 0x45, 0x46, 0x47, 0x48}
	original := append([]byte(nil), outbound...)
	if written, writeErr := connection.(*IPConn).WriteToIP(outbound, ipNetAddr(remote)); writeErr != nil || written != len(outbound) {
		t.Fatalf("checksummed WriteToIP = %d, %v", written, writeErr)
	}
	if !bytes.Equal(outbound, original) {
		t.Fatalf("WriteToIP mutated caller payload: %x", outbound)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || transportChecksum(local, remote, 99, packet.payload) != 0 {
		t.Fatalf("checksummed output = %+v, parsed=%v", packet, ok)
	}

	batchPayload := []byte{0x51, 0x52, 0xaa, 0xbb, 0x55, 0x56, 0x57, 0x58}
	batchOriginal := append([]byte(nil), batchPayload...)
	batch := []SocketMessage{{Buffers: [][]byte{batchPayload[:3], batchPayload[3:]}, Addr: ipNetAddr(remote)}}
	if count, writeErr := connection.(*IPConn).WriteBatch(batch, 0); writeErr != nil || count != 1 || batch[0].N != len(batchPayload) {
		t.Fatalf("checksummed WriteBatch = %d, %v, message=%+v", count, writeErr, batch[0])
	}
	if !bytes.Equal(batchPayload, batchOriginal) {
		t.Fatalf("WriteBatch mutated caller payload: %x", batchPayload)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || transportChecksum(local, remote, 99, packet.payload) != 0 {
		t.Fatalf("checksummed batch output = %+v, parsed=%v", packet, ok)
	}

	fragmented := bytes.Repeat([]byte{0x6b}, 3000)
	fragmentedOriginal := append([]byte(nil), fragmented...)
	fragmentedBatch := []SocketMessage{{Buffers: [][]byte{fragmented[:317], fragmented[317:1301], fragmented[1301:]}, Addr: ipNetAddr(remote)}}
	if count, writeErr := connection.(*IPConn).WriteBatch(fragmentedBatch, 0); writeErr != nil || count != 1 {
		t.Fatalf("checksummed fragmented WriteBatch = %d, %v", count, writeErr)
	}
	if !bytes.Equal(fragmented, fragmentedOriginal) {
		t.Fatal("fragmented WriteBatch mutated caller payload")
	}
	receiver, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(remote, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	var reassembled []byte
	for count := 0; reassembled == nil && count < 16; count++ {
		reassembled = receiver.reassemblePacket(readOutboundPacket(t, stack), time.Now())
	}
	packet, ok = parseIPPacket(reassembled, false)
	if !ok || transportChecksum(local, remote, 99, packet.payload) != 0 || len(packet.payload) != len(fragmented) {
		t.Fatalf("checksummed fragmented output = %+v, parsed=%v", packet, ok)
	}
	if _, writeErr := connection.(*IPConn).WriteToIP([]byte{1, 2, 3}, ipNetAddr(remote)); !errors.Is(writeErr, syscall.EINVAL) {
		t.Fatalf("short checksummed write = %v, want EINVAL", writeErr)
	}
}

func TestRXChecksumOffloadKeepsRawIPv6Policy(t *testing.T) {
	local, remote := netip.MustParseAddr("2001:db8::151"), netip.MustParseAddr("2001:db8::152")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	stack.SetRXChecksumOffload(RXChecksumOffload{flags: rxChecksumOffloadGenerated})
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPv6Checksum(true, 2)}}).ListenIP(context.Background(), stack, "ip6:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload := []byte{1, 2, 0, 0, 5, 6, 7, 8}
	binary.BigEndian.PutUint16(payload[2:4], transportChecksum(remote, local, 99, payload))
	bad := append([]byte(nil), payload...)
	bad[len(bad)-1] ^= 1
	if n, err := stack.Write([][]byte{buildIPPacket(remote, local, 99, bad, 0, true), buildIPPacket(remote, local, 99, payload, 0, true)}, 0); err != nil || n != 2 {
		t.Fatalf("raw input Write = %d, %v", n, err)
	}
	buffer := make([]byte, len(payload))
	messages := []SocketMessage{{Buffers: [][]byte{buffer}}}
	if n, err := connection.(*IPConn).ReadBatch(messages, MessageFlagDontWait); err != nil || n != 1 || !bytes.Equal(buffer, payload) {
		t.Fatalf("raw receive = %d, %v, %x", n, err, buffer)
	}
	if n, err := connection.(*IPConn).ReadBatch(messages, MessageFlagDontWait); n != 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("invalid raw payload queued: %d, %v", n, err)
	}
}

func TestIPConnDualStackIPv6ChecksumIsolation(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.152")
	remote4 := netip.MustParseAddr("198.51.100.152")
	local6 := netip.MustParseAddr("2001:db8::152")
	remote6 := netip.MustParseAddr("2001:db8:1::152")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPv6Checksum(true, 2),
	}}).ListenIP(context.Background(), stack, "ip:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload4 := []byte{1, 2, 0xaa, 0xbb, 5, 6, 7, 8}
	original4 := append([]byte(nil), payload4...)
	if _, err = connection.WriteTo(payload4, ipNetAddr(remote4)); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local4 || !bytes.Equal(packet.payload, original4) || !bytes.Equal(payload4, original4) {
		t.Fatalf("dual-stack IPv4 checksum isolation = %+v payload=%x", packet, payload4)
	}
	payload6 := []byte{1, 2, 0xaa, 0xbb, 5, 6, 7, 8}
	original6 := append([]byte(nil), payload6...)
	if _, err = connection.WriteTo(payload6, ipNetAddr(remote6)); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local6 || transportChecksum(local6, remote6, 99, packet.payload) != 0 || !bytes.Equal(payload6, original6) {
		t.Fatalf("dual-stack IPv6 checksum output = %+v payload=%x", packet, payload6)
	}

	protocol58, err := stack.ListenIP(context.Background(), "ip:58", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer protocol58.Close()
	icmpNumberOverIPv4 := []byte{0x81, 0, 0xaa, 0xbb, 1, 2, 3, 4}
	want := append([]byte(nil), icmpNumberOverIPv4...)
	if _, err = protocol58.WriteTo(icmpNumberOverIPv4, ipNetAddr(remote4)); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local4 || packet.protocol != ProtocolICMPv6 || !bytes.Equal(packet.payload, want) || !bytes.Equal(icmpNumberOverIPv4, want) {
		t.Fatalf("IPv4 protocol 58 was treated as ICMPv6: %+v payload=%x", packet, icmpNumberOverIPv4)
	}
}

func TestIPConnIPv6ChecksumHeaderIncludedOwnership(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::153")
	remote := netip.MustParseAddr("2001:db8:1::153")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPv6Checksum(true, 2),
		SocketOptions.IPHeaderIncludedOnWrite(true),
		SocketOptions.IPHeaderIncludedOnRead(true),
	}}).ListenIP(context.Background(), stack, "ip6:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	complete := buildIPPacket(local, remote, 99, []byte{1, 2, 0xaa, 0xbb, 5, 6, 7, 8}, 0, true)
	wantComplete := append([]byte(nil), complete...)
	if written, writeErr := connection.WriteTo(complete, ipNetAddr(remote)); writeErr != nil || written != len(complete) {
		t.Fatalf("header-included checksummed write = %d, %v", written, writeErr)
	}
	if !bytes.Equal(complete, wantComplete) {
		t.Fatal("header-included write mutated caller packet")
	}
	if emitted := readOutboundPacket(t, stack); !bytes.Equal(emitted, wantComplete) {
		t.Fatalf("header-included checksum policy changed packet:\n got %x\nwant %x", emitted, wantComplete)
	}

	payload := []byte{9, 10, 0, 0, 13, 14, 15, 16}
	binary.BigEndian.PutUint16(payload[2:4], transportChecksum(remote, local, 99, payload))
	inbound := buildIPPacket(remote, local, 99, payload, 0, true)
	if err = writeTestPacket(stack, inbound); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	if read, _, readErr := connection.ReadFrom(buffer); readErr != nil || !bytes.Equal(buffer[:read], inbound) {
		t.Fatalf("header-included checksum-valid read = %x, %v", buffer[:read], readErr)
	}
	invalid := append([]byte(nil), inbound...)
	invalid[len(invalid)-1] ^= 0xff
	if err = writeTestPacket(stack, invalid); err != nil {
		t.Fatal(err)
	}
	messages := []SocketMessage{{Buffers: [][]byte{buffer}}}
	if count, readErr := connection.(*IPConn).ReadBatch(messages, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("header-included invalid checksum read = %d, %v, want EAGAIN", count, readErr)
	}
}

func TestIPHeaderIncludedOutputPreservesIPv6ExtensionFlow(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::156")
	remote := netip.MustParseAddr("2001:db8:1::156")
	multicast := netip.MustParseAddr("ff05::156")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)},
		MTU:            1500,
		IP:             IPSocketDefaults{IPHeaderIncludedOnWrite: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip6:udp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = hop.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		target     netip.Addr
		sourcePort uint16
	}{
		{name: "unicast", target: remote, sourcePort: 12000},
		{name: "multicast", target: multicast, sourcePort: 12001},
	} {
		t.Run(test.name, func(t *testing.T) {
			datagram := mustTestWire((UDPDatagram{
				Source:      netip.AddrPortFrom(local, test.sourcePort),
				Destination: netip.AddrPortFrom(test.target, 53),
				Payload:     []byte("header-included-flow"),
			}).MarshalBinary())
			packet := IPPacket{Source: local, Destination: test.target, HopLimit: 64}
			if setErr := packet.SetIPv6ExtensionHeaders([]IPv6ExtensionHeader{hop}, ProtocolUDP, datagram); setErr != nil {
				t.Fatal(setErr)
			}
			wire := mustTestWire(packet.MarshalBinary())
			want := outputHashedFlowKey(outputIPFlowHash(stack.outbound.scheduler.secret, local, test.target, ProtocolUDP, 0, uint32(test.sourcePort)<<16|53))
			if classified := outputHashedFlowKey(outputPacketFlowHash(stack.outbound.scheduler.secret, wire)); classified != want {
				t.Fatalf("header-included packet classified as %x, want transport flow %x", classified.hash, want.hash)
			}
			if written, writeErr := connection.WriteTo(wire, ipNetAddr(test.target)); writeErr != nil || written != len(wire) {
				t.Fatalf("header-included write = %d, %v", written, writeErr)
			}

			stack.outbound.scheduler.mu.Lock()
			queued := stack.outbound.scheduler.flows[want]
			stack.outbound.scheduler.mu.Unlock()
			if queued == nil || queued.head < 0 {
				t.Fatal("header-included packet was not assigned to its transport flow")
			}
			if emitted := readOutboundPacket(t, stack); !bytes.Equal(emitted, wire) {
				t.Fatalf("header-included output:\n got %x\nwant %x", emitted, wire)
			}
		})
	}
}

func TestIPHeaderIncludedLinuxKnownAnswers(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.154")
	target4 := netip.MustParseAddr("198.51.100.154")
	stack4, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(source4, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack4.Close()
	stack4.ipv4ID.Store(0x4320)
	connection4 := IPConn{stack: stack4}
	input4 := mustCodecVector(t, "462e0001000040002563aabb00000000c633649a01010000deadbeef")
	original4 := append([]byte(nil), input4...)
	layout4, err := parseHeaderIncludedPacket(input4, source4, target4)
	packet4 := make([]byte, len(input4))
	if err == nil {
		connection4.marshalHeaderIncludedPacket(packet4, input4, layout4)
	}
	want4 := mustCodecVector(t, "462e001c43214000256322c7c000029ac633649a01010000deadbeef")
	if err != nil || layout4.packetTarget != target4 || layout4.hopLimit != 37 || !bytes.Equal(packet4, want4) {
		t.Fatalf("Linux IPv4 IP_HDRINCL repair = target %s hop %d error %v\n got %x\nwant %x",
			layout4.packetTarget, layout4.hopLimit, err, packet4, want4)
	}
	if !bytes.Equal(input4, original4) || referenceChecksum(packet4[:24]) != 0 || stack4.ipv4ID.Load() != 0x4321 {
		t.Fatalf("Linux IPv4 IP_HDRINCL ownership/checksum/ID = input %x checksum %#x ID %#x",
			input4, referenceChecksum(packet4[:24]), stack4.ipv4ID.Load())
	}

	explicit4 := mustCodecVector(t, "452e0001123440002563aabbcb007109c633649adeadbeef")
	layout4, err = parseHeaderIncludedPacket(explicit4, source4, target4)
	packet4 = make([]byte, len(explicit4))
	if err == nil {
		connection4.marshalHeaderIncludedPacket(packet4, explicit4, layout4)
	}
	if err != nil || !bytes.Equal(packet4[4:6], explicit4[4:6]) || !bytes.Equal(packet4[12:16], explicit4[12:16]) ||
		binary.BigEndian.Uint16(packet4[2:4]) != uint16(len(packet4)) || referenceChecksum(packet4[:20]) != 0 {
		t.Fatalf("Linux IPv4 explicit ID/source repair = %x, %v", packet4, err)
	}
	if stack4.ipv4ID.Load() != 0x4321 {
		t.Fatalf("explicit IPv4 ID consumed allocator value: %#x", stack4.ipv4ID.Load())
	}

	source6 := netip.MustParseAddr("2001:db8::9a")
	target6 := netip.MustParseAddr("2001:db8:1::9a")
	stack6, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(source6, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack6.Close()
	connection6 := IPConn{stack: stack6}
	input6 := mustCodecVector(t, "6a5543210004632520010db800000000000000000000009a20010db800010000000000000000009adeadbeef")
	original6 := append([]byte(nil), input6...)
	layout6, err := parseHeaderIncludedPacket(input6, source6, target6)
	packet6 := make([]byte, len(input6))
	if err == nil {
		connection6.marshalHeaderIncludedPacket(packet6, input6, layout6)
	}
	if err != nil || layout6.packetTarget != target6 || layout6.hopLimit != 37 || !bytes.Equal(packet6, input6) {
		t.Fatalf("IPv6 header-included packet = target %s hop %d error %v packet %x", layout6.packetTarget, layout6.hopLimit, err, packet6)
	}
	packet6[0] ^= 0xff
	if !bytes.Equal(input6, original6) {
		t.Fatal("IPv6 header-included result aliases caller storage")
	}

	invalid := []struct {
		name                   string
		connection             *IPConn
		selectedSource, target netip.Addr
		input                  []byte
	}{
		{name: "empty", connection: &connection4, selectedSource: source4, target: target4},
		{name: "short IPv4", connection: &connection4, selectedSource: source4, target: target4,
			input: mustCodecVector(t, "45")},
		{name: "IPv4 IHL below minimum", connection: &connection4, selectedSource: source4, target: target4,
			input: mustCodecVector(t, "440000140000000001630000c0000201c6336401")},
		{name: "IPv4 IHL beyond input", connection: &connection4, selectedSource: source4, target: target4,
			input: mustCodecVector(t, "4f0000140000000001630000c0000201c6336401")},
		{name: "IPv6 over IPv4 route", connection: &connection4, selectedSource: source4, target: target4, input: input6},
		{name: "short IPv6", connection: &connection6, selectedSource: source6, target: target6,
			input: mustCodecVector(t, "600000000000632520010db800000000000000000000009a")},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			before := append([]byte(nil), test.input...)
			if _, parseErr := parseHeaderIncludedPacket(test.input, test.selectedSource, test.target); parseErr == nil {
				t.Fatal("invalid header-included packet was accepted")
			}
			if !bytes.Equal(test.input, before) {
				t.Fatal("invalid header-included packet modified caller storage")
			}
		})
	}
}

func FuzzIPHeaderIncludedPreparation(f *testing.F) {
	v4Source := netip.MustParseAddr("192.0.2.154")
	v4Target := netip.MustParseAddr("198.51.100.154")
	v6Source := netip.MustParseAddr("2001:db8::154")
	v6Target := netip.MustParseAddr("2001:db8:1::154")
	v4 := buildIPPacket(v4Source, v4Target, 99, []byte("IPv4"), 1, false)
	v4[2], v4[3], v4[4], v4[5], v4[10], v4[11] = 0, 1, 0, 0, 0xaa, 0xbb
	v4ZeroSource := append([]byte(nil), v4...)
	copy(v4ZeroSource[12:16], []byte{0, 0, 0, 0})
	v6 := buildIPPacket(v6Source, v6Target, 99, []byte("IPv6"), 0, false)
	f.Add([]byte(nil), false)
	f.Add(v4, false)
	f.Add(v4ZeroSource, false)
	f.Add(v6, true)
	f.Add(v4, true)
	f.Fuzz(func(t *testing.T, input []byte, routeIPv6 bool) {
		if len(input) > 65575 {
			input = input[:65575]
		}
		original := append([]byte(nil), input...)
		selectedSource, routeTarget := v4Source, v4Target
		bits := 32
		if routeIPv6 {
			selectedSource, routeTarget = v6Source, v6Target
			bits = 128
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(selectedSource, bits)}})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection := IPConn{stack: stack}
		layout, err := parseHeaderIncludedPacket(input, selectedSource, routeTarget)
		if !bytes.Equal(input, original) {
			t.Fatal("header-included preparation modified caller storage")
		}
		if err != nil {
			return
		}
		packet := make([]byte, len(input))
		connection.marshalHeaderIncludedPacket(packet, input, layout)
		expectedVersion := byte(4)
		if routeIPv6 {
			expectedVersion = 6
		}
		if len(packet) != len(input) || packet[0]>>4 != expectedVersion {
			t.Fatalf("accepted header-included packet has version/length %d/%d", packet[0]>>4, len(packet))
		}
		if routeIPv6 {
			if !bytes.Equal(packet, input) || layout.packetTarget != netip.AddrFrom16([16]byte(packet[24:40])) || layout.hopLimit != packet[7] {
				t.Fatalf("IPv6 header-included result changed caller fields: target=%s hop=%d", layout.packetTarget, layout.hopLimit)
			}
		} else {
			headerSize := int(packet[0]&0x0f) * 4
			if headerSize < 20 || headerSize > len(packet) || binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) || checksum(packet[:headerSize]) != 0 {
				t.Fatalf("IPv4 header-included result has invalid header: %x", packet)
			}
			if layout.packetTarget != netip.AddrFrom4([4]byte(packet[16:20])) || layout.hopLimit != packet[8] {
				t.Fatalf("IPv4 header-included metadata = target %s hop %d", layout.packetTarget, layout.hopLimit)
			}
			if binary.BigEndian.Uint32(input[12:16]) == 0 {
				if !bytes.Equal(packet[12:16], selectedSource.AsSlice()) {
					t.Fatalf("IPv4 zero source repaired to %x, want %s", packet[12:16], selectedSource)
				}
			} else if !bytes.Equal(packet[12:16], input[12:16]) {
				t.Fatal("IPv4 explicit source was changed")
			}
			expected := append([]byte(nil), input...)
			copy(expected[2:6], packet[2:6])
			copy(expected[10:12], packet[10:12])
			copy(expected[12:16], packet[12:16])
			if !bytes.Equal(packet, expected) {
				t.Fatal("IPv4 header-included preparation changed a caller-owned field")
			}
		}
		if len(packet) != 0 {
			packet[0] ^= 0xff
			if !bytes.Equal(input, original) {
				t.Fatal("header-included result aliases caller storage")
			}
		}
	})
}

func TestIPPathMTUProbing(t *testing.T) {
	for _, test := range []struct {
		name      string
		local     netip.Addr
		remote    netip.Addr
		baseMTU   uint32
		connected bool
	}{
		{name: "IPv4 connected", local: netip.MustParseAddr("192.0.2.170"), remote: netip.MustParseAddr("192.0.2.171"), baseMTU: 1000, connected: true},
		{name: "IPv4 unconnected", local: netip.MustParseAddr("192.0.2.172"), remote: netip.MustParseAddr("192.0.2.173"), baseMTU: 1000},
		{name: "IPv6 connected", local: netip.MustParseAddr("2001:db8::170"), remote: netip.MustParseAddr("2001:db8::171"), baseMTU: 1280, connected: true},
		{name: "IPv6 unconnected", local: netip.MustParseAddr("2001:db8::172"), remote: netip.MustParseAddr("2001:db8::173"), baseMTU: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.local.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if !stack.observePathMTU(test.remote, test.baseMTU) {
				t.Fatal("failed to install base PMTU")
			}
			var connection *IPConn
			if test.connected {
				var netConnection net.Conn
				netConnection, err = stack.DialIP(context.Background(), "ip:99", netip.Addr{}, test.remote)
				if err == nil {
					connection = netConnection.(*IPConn)
				}
			} else {
				var packetConnection net.PacketConn
				packetConnection, err = stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
				if err == nil {
					connection = packetConnection.(*IPConn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 1300)
			if test.connected {
				_, err = connection.Write(payload)
			} else {
				_, err = connection.WriteToIP(payload, ipNetAddr(test.remote))
			}
			if err != nil {
				t.Fatal(err)
			}
			for fragment := 0; fragment < 2; fragment++ {
				if packet := readOutboundPacket(t, stack); len(packet) > int(test.baseMTU) {
					t.Fatalf("ordinary IP fragment size = %d, want <= %d", len(packet), test.baseMTU)
				}
			}
			if test.connected {
				_, err = connection.WritePathMTUProbe(payload)
			} else {
				_, err = connection.WritePathMTUProbeTo(payload, test.remote)
			}
			if err != nil {
				t.Fatal(err)
			}
			probe := readOutboundPacket(t, stack)
			wantSize := len(payload) + 20
			if test.remote.Is6() {
				wantSize = len(payload) + 40
			}
			if len(probe) != wantSize {
				t.Fatalf("IP path probe size = %d, want %d", len(probe), wantSize)
			}
			if test.connected {
				err = connection.ConfirmPathMTU(wantSize)
			} else {
				err = connection.ConfirmPathMTUFor(test.remote, wantSize)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mtu, pathErr := stack.PathMTU(test.remote); pathErr != nil || mtu != wantSize {
				t.Fatalf("confirmed IP PMTU = %d, %v, want %d", mtu, pathErr, wantSize)
			}
		})
	}
}

func TestIPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::192")
	remote := netip.MustParseAddr("2001:db8::193")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip6:99", netip.IPv6Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndLabel := func() uint32 {
		t.Helper()
		if _, writeErr := connection.(*IPConn).WriteToIP([]byte("flow"), ipNetAddr(remote)); writeErr != nil {
			t.Fatal(writeErr)
		}
		packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
		if !ok {
			t.Fatal("failed to parse IPv6 IP output")
		}
		return packet.flowLabel
	}
	first := writeAndLabel()
	if first == 0 || writeAndLabel() != first {
		t.Fatalf("unstable automatic IP flow label %#x", first)
	}
	if info := connection.(*IPConn).Info(); info.FlowLabel != 0 {
		t.Fatalf("automatic IP flow-label diagnostics = %+v", info)
	}
	if err = connection.(*IPConn).SetFlowLabel(0x34567); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(); label != 0x34567 {
		t.Fatalf("IP socket flow label = %#x, want 0x34567", label)
	}
	if info := connection.(*IPConn).Info(); info.FlowLabel != 0x34567 {
		t.Fatalf("fixed IP flow-label diagnostics = %+v", info)
	}
}

func TestIPConnFragmentReassembly(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		mtu           uint32
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.116"), remote: netip.MustParseAddr("192.0.2.117"), mtu: 600},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::116"), remote: netip.MustParseAddr("2001:db8::117"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.local, test.remote, test.mtu)
			bridge := newStackBridge(t, client, server)
			network := "ip4:99"
			if test.remote.Is6() {
				network = "ip6:99"
			}
			listener, err := server.ListenIP(context.Background(), network, test.remote)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			connection, err := client.ListenIP(context.Background(), network, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			var oob []byte
			if test.local.Is4() {
				oob, err = (&IPv4ControlMessage{TTL: 29, TOS: 0x2e, Src: test.local}).Marshal()
			} else {
				oob, err = (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, Src: test.local}).Marshal()
			}
			if err != nil {
				t.Fatal(err)
			}
			if n, _, writeErr := connection.(*IPConn).WriteMsgIP(payload, oob, ipNetAddr(test.remote)); writeErr != nil || n != len(payload) {
				t.Fatalf("fragmented WriteMsgIP = %d, %v", n, writeErr)
			}
			buffer := make([]byte, len(payload))
			control := make([]byte, 128)
			n, oobn, flags, source, readErr := listener.(*IPConn).ReadMsgIP(buffer, control)
			if readErr != nil || n != len(payload) || flags != 0 || !bytes.Equal(buffer, payload) || source.String() != test.local.String() {
				t.Fatalf("reassembled ReadMsgIP = %d flags %#x from %v, %v", n, flags, source, readErr)
			}
			if test.local.Is4() {
				var message IPv4ControlMessage
				if controlErr := message.Parse(control[:oobn]); controlErr != nil || message != (IPv4ControlMessage{TTL: 29, TOS: 0x2e, Dst: test.remote}) {
					t.Fatalf("reassembled IPv4 control = %+v, %v", message, controlErr)
				}
			} else {
				var message IPv6ControlMessage
				if controlErr := message.Parse(control[:oobn]); controlErr != nil || message.HopLimit != 29 || message.TrafficClass != 0x2e || message.FlowLabel == 0 || message.Dst != test.remote {
					t.Fatalf("reassembled IPv6 control = %+v, %v", message, controlErr)
				}
			}
			bridge.mu.Lock()
			writes := bridge.clientWrites
			bridge.mu.Unlock()
			if writes < 2 {
				t.Fatalf("fragmented packet writes = %d, want at least 2", writes)
			}
		})
	}
}

func TestIPConnConfigurationLifecycle(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.118")
	second := netip.MustParseAddr("192.0.2.119")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	exact, err := stack.ListenIP(context.Background(), "ip4:99", second)
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32)}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = exact.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed binding ReadFrom = %v, want net.ErrClosed", err)
	}
	if stats := stack.Stats(); stats.ActiveIPSockets != 1 {
		t.Fatalf("active IP sockets after address removal = %d, want 1", stats.ActiveIPSockets)
	}
	v6 := netip.MustParseAddr("2001:db8::118")
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(v6, 128)}, MTU: 1280}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = wildcard.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed family ReadFrom = %v, want net.ErrClosed", err)
	}
	if stats := stack.Stats(); stats.ActiveIPSockets != 0 {
		t.Fatalf("active IP sockets after family removal = %d, want 0", stats.ActiveIPSockets)
	}
}

func TestIPExplicitErrorQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.185")
	first := netip.MustParseAddr("198.51.100.185")
	second := netip.MustParseAddr("198.51.100.186")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newIPConn(stack, "ip4:99", 99, local, netip.Addr{}, socketOptionSet{})
	defer connection.closeFromStack()
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	if enabled, getErr := connection.ReceiveErrors(); getErr != nil || !enabled {
		t.Fatalf("ReceiveErrors = %v, %v", enabled, getErr)
	}
	connection.deliverError(first, ICMPError{Code: 1})
	connection.deliverError(second, ICMPError{Code: 2})
	if info := connection.Info(); info.ErrorQueueEntries != 2 || info.ErrorQueueBytes != 2*socketErrorMetadataSize || !info.ReceiveErrors || info.ErrorsDropped != 0 {
		t.Fatalf("explicit IP error queue diagnostics = %+v", info)
	}
	if err = connection.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, readErr := connection.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("ordinary read did not report the pending extended error")
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 2 {
			t.Fatalf("ordinary read with explicit errors = %v, want newest ICMP error", readErr)
		}
	}
	if _, readErr := connection.Read(make([]byte, 1)); !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary read after pending error = %v, want deadline", readErr)
	}
	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	for index, target := range []netip.Addr{first, second} {
		queued, readErr := connection.ReadError()
		if readErr != nil || queued == nil {
			t.Fatalf("ReadError %d = %#v, %v", index, queued, readErr)
		}
		address, ok := queued.Addr.(*net.IPAddr)
		if !ok || address.String() != target.String() {
			t.Fatalf("ReadError %d address = %#v, want %v", index, queued.Addr, target)
		}
		var networkError ICMPError
		if !errors.As(queued, &networkError) || networkError.Code != byte(index+1) {
			t.Fatalf("ReadError %d payload = %#v", index, queued)
		}
		if index == 0 {
			count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait)
			if count != 0 || !errors.As(readErr, &networkError) || networkError.Code != 2 {
				t.Fatalf("ordinary error after first ReadError = %d, %v", count, readErr)
			}
		}
	}
	if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("empty ReadError = %#v, %v", queued, readErr)
	}

	if err = connection.SetReadBuffer(socketErrorMetadataSize); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(first, ICMPError{Code: 3})
	connection.deliverError(second, ICMPError{Code: 4})
	if info := connection.Info(); info.ErrorQueueEntries != 1 || info.ErrorsDropped != 1 || info.ICMPErrors != 4 {
		t.Fatalf("bounded IP error queue diagnostics = %+v", info)
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || readErr == nil {
		t.Fatalf("ordinary error after extended queue overflow = %d, %v", count, readErr)
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 4 {
			t.Fatalf("latest pending error after overflow = %v", readErr)
		}
	}
	if _, err = connection.ReadError(); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(first, ICMPError{Code: 5})
	if err = connection.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connection.Info(); info.ErrorQueueEntries != 0 || info.ErrorQueueBytes != 0 {
		t.Fatalf("disabled IP error queue = %+v", info)
	}
	connection.deliverError(first, ICMPError{Code: 6})
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || readErr == nil {
		t.Fatalf("unconnected IP read after disabling error queue = %d, %v", count, readErr)
	} else {
		var networkError ICMPError
		if !errors.As(readErr, &networkError) || networkError.Code != 5 {
			t.Fatalf("pending error changed when error reception was disabled: %v", readErr)
		}
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
		t.Fatalf("unconnected IP read after pending error = %d, %v", count, readErr)
	}
	connected := newIPConn(stack, "ip4:99", 99, local, first, socketOptionSet{})
	defer connected.closeFromStack()
	if err = connected.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	connected.deliverError(first, ICMPError{Reporter: first, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodePort})
	if err = connected.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 {
		t.Fatalf("disabled connected IP error queue = %+v", info)
	}
	connected.deliverError(first, ICMPError{Reporter: first, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol})
	if err = connected.SetReceiveErrors(false); err != nil {
		t.Fatal(err)
	}
	if info := connected.Info(); info.ErrorQueueEntries != 0 || info.ICMPErrors != 2 {
		t.Fatalf("repeatedly disabling connected IP error reception discarded a pending error: %+v", info)
	}
	if err = connected.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	count, readErr := connected.Read(make([]byte, 1))
	var networkError ICMPError
	if count != 0 || !errors.As(readErr, &networkError) || networkError.Code != ICMPv4DestinationUnreachableCodeProtocol {
		t.Fatalf("connected IP read after disabling error queue = %d, %v", count, readErr)
	}
	connection.closeFromStack()
	if _, err = connection.ReceiveErrors(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReceiveErrors after Close = %v", err)
	}
	if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, net.ErrClosed) {
		t.Fatalf("ReadError after Close = %#v, %v", queued, readErr)
	}
}

func TestIPErrorQueueFanoutOwnsQuotedPayload(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.186")
	remote := netip.MustParseAddr("198.51.100.186")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	first := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	second := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer first.closeFromStack()
	defer second.closeFromStack()
	for _, connection := range []*IPConn{first, second} {
		if err = connection.SetReceiveErrors(true); err != nil {
			t.Fatal(err)
		}
	}
	state := &ipEndpointState{bindings: map[ipKey]map[*IPConn]struct{}{
		{address: local, protocol: 99}: {first: {}, second: {}},
	}}
	stack.ip = state
	networkError := ICMPError{
		QuotedSource: local, QuotedTarget: remote, QuotedProtocol: 99,
		QuotedPayload: []byte{1, 2, 3, 4},
	}
	if !state.deliverError(stack, networkError) {
		t.Fatal("raw error fanout was not accepted")
	}
	firstError, err := first.ReadError()
	if err != nil {
		t.Fatal(err)
	}
	var firstICMP ICMPError
	if !errors.As(firstError, &firstICMP) {
		t.Fatalf("first error = %#v", firstError)
	}
	firstICMP.QuotedPayload[0] = 0xff
	secondError, err := second.ReadError()
	if err != nil {
		t.Fatal(err)
	}
	var secondICMP ICMPError
	if !errors.As(secondError, &secondICMP) || !bytes.Equal(secondICMP.QuotedPayload, []byte{1, 2, 3, 4}) {
		t.Fatalf("second quoted payload shares ownership: %x", secondICMP.QuotedPayload)
	}
}

func TestIPBatchReadAndWrite(t *testing.T) {
	firstLocal := netip.MustParseAddr("192.0.2.187")
	secondLocal := netip.MustParseAddr("192.0.2.188")
	remote := netip.MustParseAddr("198.51.100.187")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(firstLocal, 32), netip.PrefixFrom(secondLocal, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for index, payload := range [][]byte{[]byte("abcdef"), []byte("second")} {
		packet := buildIPPacket(remote, secondLocal, 99, payload, uint16(index+1), true)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	firstA, firstB := make([]byte, 1), make([]byte, 5)
	second := make([]byte, 2)
	messages := []SocketMessage{
		{Buffers: [][]byte{firstA, firstB}, OOB: make([]byte, 128)},
		{Buffers: [][]byte{second}, OOB: make([]byte, 8)},
		{Buffers: [][]byte{make([]byte, 1)}, N: 91, NN: 92, Flags: 93, Addr: ipNetAddr(remote)},
	}
	n, err := connection.(*IPConn).ReadBatch(messages, 0)
	if err != nil || n != 2 {
		t.Fatalf("ReadBatch = %d, %v", n, err)
	}
	if string(append(firstA, firstB...)) != "abcdef" || messages[0].N != 6 || messages[0].NN == 0 || messages[0].Flags != 0 {
		t.Fatalf("first IP batch message = %+v payload %q", messages[0], append(firstA, firstB...))
	}
	if address, ok := messages[0].Addr.(*net.IPAddr); !ok || address.String() != remote.String() {
		t.Fatalf("first IP batch source = %#v", messages[0].Addr)
	}
	var control IPv4ControlMessage
	if err = control.Parse(messages[0].OOB[:messages[0].NN]); err != nil || control.Dst != secondLocal {
		t.Fatalf("first IP batch control = %+v, %v", control, err)
	}
	if !bytes.Equal(messages[0].OOB[20:24], secondLocal.AsSlice()) || !bytes.Equal(messages[0].OOB[24:28], secondLocal.AsSlice()) {
		t.Fatalf("first IP batch IPv4 packet-info fields = %x/%x, want %s", messages[0].OOB[20:24], messages[0].OOB[24:28], secondLocal)
	}
	if string(second) != "se" || messages[1].NN != 0 || messages[1].Flags != MessageFlagTruncated|MessageFlagControlTruncated {
		t.Fatalf("second IP batch message = %+v payload %q", messages[1], second)
	}
	if messages[2].N != 91 || messages[2].NN != 92 || messages[2].Flags != 93 || messages[2].Addr == nil {
		t.Fatalf("unprocessed IP batch message changed = %+v", messages[2])
	}
	if n, err = connection.(*IPConn).ReadBatch(messages[:1], MessageFlagDontWait); n != 0 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("nonblocking empty IP ReadBatch = %d, %v", n, err)
	}

	controlBytes, err := (&IPv4ControlMessage{Src: secondLocal}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writes := []SocketMessage{
		{Buffers: [][]byte{[]byte("ab"), []byte("cd")}, Addr: ipNetAddr(remote)},
		{Buffers: [][]byte{[]byte("ef"), []byte("gh")}, OOB: controlBytes, Addr: ipNetAddr(remote)},
	}
	if n, err = connection.(*IPConn).WriteBatch(writes, 0); n != 2 || err != nil {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	for index, source := range []netip.Addr{firstLocal, secondLocal} {
		packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
		if !ok || packet.source != source || string(packet.payload) != []string{"abcd", "efgh"}[index] {
			t.Fatalf("IP batch packet %d = %+v payload %q", index, packet, packet.payload)
		}
		if writes[index].N != 4 || writes[index].NN != len(writes[index].OOB) {
			t.Fatalf("IP batch result %d = %+v", index, writes[index])
		}
	}
	prefix := []SocketMessage{writes[0], {Buffers: nil, Addr: ipNetAddr(remote), N: 91, NN: 92, Flags: 93}}
	if n, err = connection.(*IPConn).WriteBatch(prefix, 0); n != 1 || err != nil {
		t.Fatalf("partial IP WriteBatch = %d, %v", n, err)
	}
	if prefix[1].N != 91 || prefix[1].NN != 92 || prefix[1].Flags != 93 {
		t.Fatalf("unprocessed IP WriteBatch message changed = %+v", prefix[1])
	}
	_ = readOutboundPacket(t, stack)
	if n, err = connection.(*IPConn).WriteBatch(prefix[1:], 0); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("retried invalid IP WriteBatch suffix = %d, %v", n, err)
	}

	connectedNet, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connected := connectedNet.(*IPConn)
	defer connected.Close()
	connectedMessage := []SocketMessage{{Buffers: [][]byte{[]byte("connected")}}}
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 1 || err != nil {
		t.Fatalf("connected IP WriteBatch = %d, %v", n, err)
	}
	_ = readOutboundPacket(t, stack)
	if err = connected.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired connected IP WriteBatch = %d, %v", n, err)
	}
	if operationError := checkNetOpError(t, err, "write", "ip4:99"); operationError.Addr == nil || operationError.Addr.String() != remote.String() {
		t.Fatalf("expired connected IP WriteBatch address = %v", operationError.Addr)
	}
	if err = connected.SetIPHeaderIncludedOnWrite(true); err != nil {
		t.Fatal(err)
	}
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired header-included connected IP WriteBatch = %d, %v", n, err)
	}
	if operationError := checkNetOpError(t, err, "write", "ip4:99"); operationError.Addr == nil || operationError.Addr.String() != remote.String() {
		t.Fatalf("expired header-included connected IP WriteBatch address = %v", operationError.Addr)
	}
	if err = connected.SetIPHeaderIncludedOnWrite(false); err != nil {
		t.Fatal(err)
	}
	if err = connected.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err = connected.SetIPHeaderIncludedOnWrite(true); err != nil {
		t.Fatal(err)
	}
	emptyMessage := []SocketMessage{{}}
	if n, err = connected.WriteBatch(emptyMessage, 0); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("empty header-included connected IP WriteBatch = %d, %v", n, err)
	}
	if operationError := checkNetOpError(t, err, "write", "ip4:99"); operationError.Addr == nil || operationError.Addr.String() != remote.String() {
		t.Fatalf("empty header-included connected IP WriteBatch address = %v", operationError.Addr)
	}
	if err = connected.SetIPHeaderIncludedOnWrite(false); err != nil {
		t.Fatal(err)
	}
	connectedMessage[0].Addr = ipNetAddr(remote)
	if n, err = connected.WriteBatch(connectedMessage, 0); n != 0 || !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("addressed connected IP WriteBatch = %d, %v", n, err)
	}
}

func TestIPBatchPreservesPendingErrorAfterPrefix(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.240")
	remote := netip.MustParseAddr("198.51.100.240")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*IPConn)
	defer connection.Close()
	for index, payload := range [][]byte{[]byte("prefix"), []byte("suffix")} {
		if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, payload, uint16(index+1), true)); err != nil {
			t.Fatal(err)
		}
	}
	var network *networkState
	first := SocketMessage{Buffers: [][]byte{make([]byte, 16)}}
	if err = connection.readBatchMessage(&first, 0, true, true, &network); err != nil || first.N != len("prefix") {
		t.Fatalf("prefix IP batch message = %+v, %v", first, err)
	}
	connection.deliverError(remote, ICMPError{Reporter: remote, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol})
	connection.mu.Lock()
	pending := connection.errorState.pending
	connection.mu.Unlock()
	if pending == nil {
		t.Fatal("IP batch pending error was not queued")
	}
	second := SocketMessage{Buffers: [][]byte{make([]byte, 16)}, N: 91, NN: 92, Flags: 93}
	readErr := connection.readBatchMessage(&second, MessageFlagDontWait, false, false, &network)
	var networkError ICMPError
	if readErr != pending || !errors.As(readErr, &networkError) || second.N != 91 || second.NN != 92 || second.Flags != 93 {
		t.Fatalf("pending IP error after batch prefix = %+v, %v", second, readErr)
	}
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{make([]byte, 1)}}}, MessageFlagDontWait); count != 0 || !errors.As(readErr, &networkError) {
		t.Fatalf("pending IP error was not deferred = %d, %v", count, readErr)
	}
	tail := make([]byte, 16)
	if count, readErr := connection.ReadBatch([]SocketMessage{{Buffers: [][]byte{tail}}}, MessageFlagDontWait); count != 1 || readErr != nil || string(tail[:len("suffix")]) != "suffix" {
		t.Fatalf("IP suffix after deferred error = %d, %v, %q", count, readErr, tail)
	}
}

func TestIPBatchWriteIPv6ChecksumAndFlowLabel(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::189")
	remote := netip.MustParseAddr("2001:db8:1::189")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialIP(context.Background(), "ip6:ipv6-icmp", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*IPConn)
	defer connection.Close()
	payload := []byte{128, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4}
	original := append([]byte(nil), payload...)
	messages := []SocketMessage{{Buffers: [][]byte{payload[:3], payload[3:7], payload[7:]}}}
	if count, writeErr := connection.WriteBatch(messages, 0); writeErr != nil || count != 1 {
		t.Fatalf("IPv6 ICMP WriteBatch = %d, %v", count, writeErr)
	}
	if !bytes.Equal(payload, original) {
		t.Fatalf("WriteBatch mutated caller payload: %x", payload)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.source != local || packet.target != remote || packet.protocol != ProtocolICMPv6 ||
		transportChecksum(local, remote, ProtocolICMPv6, packet.payload) != 0 {
		t.Fatalf("IPv6 ICMP batch packet = %+v, parsed = %v", packet, ok)
	}
	wantLabel := stack.automaticFlowLabel(local, remote, ProtocolICMPv6, original)
	if packet.flowLabel != wantLabel {
		t.Fatalf("IPv6 ICMP batch flow label = %#x, want %#x", packet.flowLabel, wantLabel)
	}
}

func TestIPBatchWriteFragmentedBuffers(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.190")
	remote := netip.MustParseAddr("198.51.100.190")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 600})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*IPConn)
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x6b}, 2000)
	messages := []SocketMessage{{Buffers: [][]byte{payload[:511], payload[511:1700], payload[1700:]}}}
	if count, writeErr := connection.WriteBatch(messages, 0); writeErr != nil || count != 1 || messages[0].N != len(payload) {
		t.Fatalf("fragmented IP WriteBatch = %d, %v, message %+v", count, writeErr, messages[0])
	}
	receiver, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(remote, 32)}, MTU: 600})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	var reassembled []byte
	for fragmentCount := 0; reassembled == nil && fragmentCount < 16; fragmentCount++ {
		reassembled = receiver.reassemblePacket(readOutboundPacket(t, stack), time.Now())
	}
	packet, ok := parseIPPacket(reassembled, false)
	if !ok || packet.protocol != 99 || !bytes.Equal(packet.payload, payload) {
		t.Fatalf("reassembled IP batch packet = %+v, parsed = %v", packet, ok)
	}
}

func TestIPFragmentedWriteQueueExhaustionPolicy(t *testing.T) {
	for _, family := range []struct {
		name          string
		network       string
		local, remote netip.Addr
		mtu           uint32
		payloadSize   int
	}{
		{name: "IPv4", network: "ip4:99", local: netip.MustParseAddr("192.0.2.238"), remote: netip.MustParseAddr("198.51.100.238"), mtu: 600, payloadSize: 1200},
		{name: "IPv6", network: "ip6:99", local: netip.MustParseAddr("2001:db8::238"), remote: netip.MustParseAddr("2001:db8:1::238"), mtu: 1280, payloadSize: 2600},
	} {
		for _, policy := range []struct {
			name          string
			flags         int
			receiveErrors bool
		}{
			{name: "default"},
			{name: "default/dontwait", flags: MessageFlagDontWait},
			{name: "receive-errors", receiveErrors: true},
			{name: "receive-errors/dontwait", flags: MessageFlagDontWait, receiveErrors: true},
		} {
			t.Run(family.name+"/"+policy.name, func(t *testing.T) {
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(family.local, family.local.BitLen())}, MTU: family.mtu})
				if err != nil {
					t.Fatal(err)
				}
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				netConnection, err := stack.DialIP(context.Background(), family.network, family.local, family.remote)
				if err != nil {
					t.Fatal(err)
				}
				connection := netConnection.(*IPConn)
				defer connection.Close()
				if err = connection.SetReceiveErrors(policy.receiveErrors); err != nil {
					t.Fatal(err)
				}

				dummy := buildIPPacket(family.local, family.remote, 98, []byte{0}, 1, false)
				for stack.outbound.len() < outboundPacketQueue-1 {
					if !stack.outbound.tryEnqueue(dummy) {
						t.Fatal("outbound queue filled before the expected boundary")
					}
				}
				before := stack.outbound.len()
				payload := bytes.Repeat([]byte{0x72}, family.payloadSize)
				messages := []SocketMessage{{Buffers: [][]byte{payload[:37], payload[37:]}}}
				count, writeErr := connection.WriteBatch(messages, policy.flags)
				if count != 1 || writeErr != nil || messages[0].N != len(payload) {
					t.Fatalf("fragmented IP WriteBatch = %d, %v, N=%d", count, writeErr, messages[0].N)
				}
				if info := connection.Info(); info.PacketsSent != 1 || info.BytesSent != uint64(len(payload)) {
					t.Fatalf("successful fragmented IP statistics = %d packets, %d bytes", info.PacketsSent, info.BytesSent)
				}
				if after := stack.outbound.len(); after != before+1 {
					t.Fatalf("fragmented IP write changed queue depth from %d to %d, want %d", before, after, before+1)
				}
				if stats := stack.Stats(); stats.OutboundPackets < 2 || stats.OutboundQueueDrops+1 != stats.OutboundPackets {
					t.Fatalf("fragmented IP write stack statistics = %+v", stats)
				}
				if !connection.acceptsError(family.remote) {
					t.Fatal("fragmented write did not retain ICMP correlation")
				}
				var reassembly IPPacketReassembly
				var reassembled IPPacket
				complete := false
				for {
					entry, ok := stack.outbound.tryDequeue()
					if !ok {
						break
					}
					packet, parseErr := ParseIPPacket(entry.packet)
					if parseErr == nil && packet.Source == family.local && packet.Destination == family.remote {
						if fragment, fragmented := packet.Fragment(); fragmented && fragment.Protocol == 99 {
							var addErr error
							reassembled, complete, addErr = reassembly.Add(packet)
							if addErr != nil {
								t.Fatal(addErr)
							}
						}
					}
					stack.outbound.release(entry)
				}
				if !complete || reassembled.Protocol != 99 || !bytes.Equal(reassembled.Payload, payload) {
					t.Fatalf("reassembled fragmented IP WriteBatch = complete %t protocol %d payload %x", complete, reassembled.Protocol, reassembled.Payload)
				}
			})
		}
	}
}

func TestIPHeaderIncludedWriteQueueExhaustionPolicy(t *testing.T) {
	for _, policy := range []struct {
		name          string
		flags         int
		receiveErrors bool
	}{
		{name: "default"},
		{name: "default/dontwait", flags: MessageFlagDontWait},
		{name: "receive-errors", receiveErrors: true},
		{name: "receive-errors/dontwait", flags: MessageFlagDontWait, receiveErrors: true},
	} {
		t.Run(policy.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.239")
			remote := netip.MustParseAddr("198.51.100.239")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 9000})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			netConnection, err := stack.DialIP(context.Background(), "ip4:99", local, remote)
			if err != nil {
				t.Fatal(err)
			}
			connection := netConnection.(*IPConn)
			defer connection.Close()
			if err = connection.SetIPHeaderIncludedOnWrite(true); err != nil {
				t.Fatal(err)
			}
			if err = connection.SetReceiveErrors(policy.receiveErrors); err != nil {
				t.Fatal(err)
			}
			dummy := buildIPPacket(local, remote, 98, []byte{0}, 1, false)
			fillTestPacketQueue(t, &stack.outbound, dummy)
			packet := buildIPPacket(local, remote, 99, bytes.Repeat([]byte{0x5a}, 9000-20), 2, true)
			messages := []SocketMessage{{Buffers: [][]byte{packet[:17], packet[17:]}}}
			count, writeErr := connection.WriteBatch(messages, policy.flags)
			if count != 1 || writeErr != nil || messages[0].N != len(packet) {
				t.Fatalf("header-included WriteBatch = %d, %v, N=%d", count, writeErr, messages[0].N)
			}
			if !connection.acceptsError(remote) {
				t.Fatal("header-included write did not retain ICMP correlation")
			}
			if after := stack.outbound.len(); after != outboundPacketQueue {
				t.Fatalf("header-included full-queue write changed depth to %d", after)
			}
			if info := connection.Info(); info.PacketsSent != 1 || info.BytesSent != uint64(len(packet)) {
				t.Fatalf("header-included write statistics = %d packets, %d bytes", info.PacketsSent, info.BytesSent)
			}
			if stats := stack.Stats(); stats.OutboundPackets != 1 || stats.OutboundQueueDrops != 1 {
				t.Fatalf("header-included stack statistics = %+v", stats)
			}
			found := false
			for {
				entry, available := stack.outbound.tryDequeue()
				if !available {
					break
				}
				found = found || bytes.Equal(entry.packet, packet)
				if entry.reusable && cap(entry.packet) > packetReusableBufferLimit {
					if cache := stack.largeBuffers.Load(); cache != nil {
						cache.release(entry.packet)
					}
					entry.reusable = false
				}
				stack.outbound.release(entry)
			}
			if !found {
				t.Fatal("header-included packet was not admitted over published backlog")
			}
			if cache := stack.largeBuffers.Load(); cache == nil || len(cache.buffers) != 1 {
				t.Fatal("header-included jumbo buffer was not retained after device consumption")
			}
		})
	}
}

func TestIPConnReceiveCapacity(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.120")
	remote := netip.MustParseAddr("198.51.100.120")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.(*IPConn).SetReadBuffer(2 * (ipDatagramMetadataSize + 1)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		packet := buildIPPacket(remote, local, 99, []byte{byte(index)}, uint16(index), true)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("raw receive-capacity drops = %d, want 1", dropped)
	}
	for index := 0; index < 2; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("raw ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
}

func TestIPConcurrentReadersShareDeadline(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.121")
	remote := netip.MustParseAddr("198.51.100.121")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer connection.closeFromStack()
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const readers = 8
	start := make(chan struct{})
	results := make(chan byte, readers)
	for index := 0; index < readers; index++ {
		go func() {
			<-start
			buffer := make([]byte, 1)
			n, readErr := connection.Read(buffer)
			if readErr != nil || n != 1 {
				results <- 0xff
				return
			}
			results <- buffer[0]
		}()
	}
	close(start)
	for value := byte(0); value < readers; value++ {
		connection.enqueuePacket(ipPacket{payload: []byte{value}, source: remote, target: local}, ipPacketOptions{})
	}
	seen := make(map[byte]struct{}, readers)
	for index := 0; index < readers; index++ {
		select {
		case value := <-results:
			if value == 0xff {
				t.Fatal("concurrent IP read failed")
			}
			seen[value] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent IP readers did not make progress")
		}
	}
	if len(seen) != readers {
		t.Fatalf("concurrent IP reads received %d distinct datagrams", len(seen))
	}
}

func TestIPReadWithBufferAddressVariants(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.125")
	remote := netip.MustParseAddr("198.51.100.125")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	connected := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer connected.closeFromStack()
	connectedPayload := []byte("connected raw payload")
	connected.enqueuePacket(ipPacket{payload: connectedPayload, source: remote, target: local}, ipPacketOptions{})
	var connectedBuffer []byte
	connectedHint := 0
	n, readErr := connected.ReadWithBuffer(func(sizeHint int) []byte {
		connectedHint = sizeHint
		connectedBuffer = make([]byte, sizeHint)
		return connectedBuffer
	})
	if readErr != nil || n != len(connectedPayload) || connectedHint != len(connectedPayload) || !bytes.Equal(connectedBuffer, connectedPayload) {
		t.Fatalf("ReadWithBuffer = %d, %v, hint %d, payload %q; want %d, nil, %d, %q", n, readErr, connectedHint, connectedBuffer, len(connectedPayload), len(connectedPayload), connectedPayload)
	}

	unconnected := newIPConn(stack, "ip4:99", 99, local, netip.Addr{}, socketOptionSet{})
	defer unconnected.closeFromStack()
	first := []byte("first raw payload")
	unconnected.enqueuePacket(ipPacket{payload: first, source: remote, target: local}, ipPacketOptions{})
	var firstBuffer []byte
	n, address, readErr := unconnected.ReadFromWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(first) {
			t.Fatalf("ReadFromWithBuffer size hint = %d; want %d", sizeHint, len(first))
		}
		firstBuffer = make([]byte, sizeHint)
		return firstBuffer
	})
	if readErr != nil || n != len(first) || !bytes.Equal(firstBuffer, first) {
		t.Fatalf("ReadFromWithBuffer = %d, %v, payload %q; want %d, nil, %q", n, readErr, firstBuffer, len(first), first)
	}
	if got, ok := address.(*net.IPAddr); !ok || !got.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("ReadFromWithBuffer address = %#v; want %v", address, remote)
	}

	second := []byte("second raw payload")
	unconnected.enqueuePacket(ipPacket{payload: second, source: remote, target: local}, ipPacketOptions{})
	var secondBuffer []byte
	n, addressIP, readErr := unconnected.ReadFromIPWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(second) {
			t.Fatalf("ReadFromIPWithBuffer size hint = %d; want %d", sizeHint, len(second))
		}
		secondBuffer = make([]byte, sizeHint)
		return secondBuffer
	})
	if readErr != nil || n != len(second) || !bytes.Equal(secondBuffer, second) {
		t.Fatalf("ReadFromIPWithBuffer = %d, %v, payload %q; want %d, nil, %q", n, readErr, secondBuffer, len(second), second)
	}
	if addressIP == nil || !addressIP.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("ReadFromIPWithBuffer address = %#v; want %v", addressIP, remote)
	}

	short := []byte("short raw payload")
	unconnected.enqueuePacket(ipPacket{payload: short, source: remote, target: local}, ipPacketOptions{})
	var shortBuffer []byte
	n, addressIP, readErr = unconnected.ReadFromIPWithBuffer(func(sizeHint int) []byte {
		if sizeHint != len(short) {
			t.Fatalf("short ReadFromIPWithBuffer size hint = %d; want %d", sizeHint, len(short))
		}
		shortBuffer = make([]byte, 3)
		return shortBuffer
	})
	if readErr != nil || n != len(shortBuffer) || !bytes.Equal(shortBuffer, short[:len(shortBuffer)]) {
		t.Fatalf("short ReadFromIPWithBuffer = %d, %v, payload %q; want %d, nil, %q", n, readErr, shortBuffer, len(shortBuffer), short[:len(shortBuffer)])
	}
	if addressIP == nil || !addressIP.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("short ReadFromIPWithBuffer address = %#v; want %v", addressIP, remote)
	}

	complete := buildIPPacket(remote, local, 99, []byte("complete raw packet"), 125, true)
	headerIncluded := newIPConn(stack, "ip4:99", 99, local, netip.Addr{}, socketOptionSet{
		ip: ipSocketOptionSet{headerIncludedOnRead: socketOptionBoolOverrideEnabled},
	})
	defer headerIncluded.closeFromStack()
	headerIncluded.enqueuePacket(ipPacket{
		payload: []byte("complete raw packet"), original: complete, source: remote, target: local,
	}, ipPacketOptions{})
	var completeBuffer []byte
	completeHint := 0
	n, addressIP, readErr = headerIncluded.ReadFromIPWithBuffer(func(sizeHint int) []byte {
		completeHint = sizeHint
		completeBuffer = make([]byte, sizeHint)
		return completeBuffer
	})
	if readErr != nil || n != len(complete) || completeHint != len(complete) || !bytes.Equal(completeBuffer, complete) {
		t.Fatalf("header-included ReadFromIPWithBuffer = %d, %v, hint %d, payload length %d; want %d, nil, hint %d, payload length %d", n, readErr, completeHint, len(completeBuffer), len(complete), len(complete), len(complete))
	}
	if addressIP == nil || !addressIP.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("header-included source = %#v; want %v", addressIP, remote)
	}

	if _, _, readErr = unconnected.ReadFromWithBuffer(nil); !errors.Is(readErr, syscall.EINVAL) {
		t.Fatalf("nil IP buffer callback error = %v; want EINVAL", readErr)
	}
}

func TestIPReadWithBufferWaitsOutsideConnectionLock(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.126")
	remote := netip.MustParseAddr("198.51.100.126")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer connection.closeFromStack()
	callbackCalled := make(chan int, 1)
	result := make(chan struct {
		n           int
		err         error
		hint        int
		payload     []byte
		deadlineErr error
	}, 1)
	go func() {
		var payload []byte
		deadlineErr := error(nil)
		n, readErr := connection.ReadWithBuffer(func(sizeHint int) []byte {
			callbackCalled <- sizeHint
			deadlineErr = connection.SetReadDeadline(time.Time{})
			payload = make([]byte, sizeHint)
			return payload
		})
		result <- struct {
			n           int
			err         error
			hint        int
			payload     []byte
			deadlineErr error
		}{n: n, err: readErr, hint: len(payload), payload: payload, deadlineErr: deadlineErr}
	}()
	select {
	case hint := <-callbackCalled:
		t.Fatalf("IP buffer callback ran before a datagram was queued with hint %d", hint)
	case <-time.After(20 * time.Millisecond):
	}
	payload := []byte("outside lock")
	connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
	select {
	case hint := <-callbackCalled:
		if hint != len(payload) {
			t.Fatalf("IP ReadWithBuffer size hint = %d; want %d", hint, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("IP ReadWithBuffer callback did not run")
	}
	var readResult struct {
		n           int
		err         error
		hint        int
		payload     []byte
		deadlineErr error
	}
	select {
	case readResult = <-result:
	case <-time.After(time.Second):
		t.Fatal("IP ReadWithBuffer did not return")
	}
	if readResult.n != len(payload) || readResult.err != nil || readResult.hint != len(payload) || string(readResult.payload) != string(payload) || readResult.deadlineErr != nil {
		t.Fatalf("IP ReadWithBuffer = %d, %v, hint %d, payload %q, deadline error %v; want %d, nil, %d, %q, nil", readResult.n, readResult.err, readResult.hint, readResult.payload, readResult.deadlineErr, len(payload), len(payload), payload)
	}
}

func TestIPReadWithBufferDeadlineDoesNotCallCallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.127")
	remote := netip.MustParseAddr("198.51.100.127")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer connection.closeFromStack()
	payload := []byte("deadline")
	connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
	if err = connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	if n, readErr := connection.ReadWithBuffer(func(int) []byte {
		callbackCalls++
		return make([]byte, len(payload))
	}); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) || callbackCalls != 0 {
		t.Fatalf("expired IP ReadWithBuffer = %d, %v, callback calls %d; want 0, deadline, 0", n, readErr, callbackCalls)
	}
	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if n, readErr := connection.Read(buffer); n != len(payload) || readErr != nil || string(buffer) != string(payload) {
		t.Fatalf("IP data after expired ReadWithBuffer = %d, %v, %q; want %d, nil, %q", n, readErr, buffer, len(payload), payload)
	}
}

func TestIPReceiveNotificationIsLazy(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.239")
	remote := netip.MustParseAddr("198.51.100.239")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	defer connection.closeFromStack()
	connection.enqueuePacket(ipPacket{payload: []byte{1}, source: remote, target: local}, ipPacketOptions{})
	buffer := make([]byte, 1)
	if n, readErr := connection.Read(buffer); readErr != nil || n != 1 {
		t.Fatalf("ready read = %d, %v", n, readErr)
	}
	connection.mu.Lock()
	allocated := connection.receiveNotify != nil || connection.readDeadline.state.Load() != nil || connection.errorState != nil
	connection.mu.Unlock()
	if allocated {
		t.Fatal("ready receive path allocated blocking state")
	}
	result := make(chan error, 1)
	go func() {
		_, readErr := connection.Read(buffer)
		result <- readErr
	}()
	waitFor(t, time.Second, func() bool {
		connection.mu.Lock()
		waiting := connection.receiveNotify != nil && connection.readDeadline.state.Load() != nil
		connection.mu.Unlock()
		return waiting
	})
	connection.enqueuePacket(ipPacket{payload: []byte{2}, source: remote, target: local}, ipPacketOptions{})
	if readErr := <-result; readErr != nil || buffer[0] != 2 {
		t.Fatalf("blocked read = %x, %v", buffer, readErr)
	}
}

func TestUnconnectedIPReadAndConnectedWriteToError(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.124")
	remote := netip.MustParseAddr("198.51.100.124")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	listener, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("read"), 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if n, readErr := listener.(*IPConn).Read(buffer); readErr != nil || n != 4 || string(buffer) != "read" {
		t.Fatalf("unconnected IP Read = %q, %v", buffer[:n], readErr)
	}
	netConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connected := netConnection.(*IPConn)
	defer connected.Close()
	if _, err = connected.WriteToIP([]byte("x"), &net.IPAddr{IP: net.IP(remote.AsSlice())}); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected IP WriteTo = %v, want net.ErrWriteToConnected", err)
	}
}

func TestIPDefaultsAndDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::136")
	remote := netip.MustParseAddr("2001:db8::137")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1400,
		IP: IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{ReceiveBuffer: 2048, HopLimit: 29, TrafficClass: 0x28}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialIP(context.Background(), "ip6:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	ip := connection.(*IPConn)
	if err = ip.SetPathMTUDiscovery(PathMTUDiscovery(99)); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("invalid IP PMTU mode = %v", err)
	}
	if err = ip.SetPathMTUDiscovery(PathMTUDiscoveryOmit); err != nil {
		t.Fatal(err)
	}
	if mode, modeErr := ip.PathMTUDiscovery(); modeErr != nil || mode != PathMTUDiscoveryOmit {
		t.Fatalf("IP PMTU mode = %v, %v", mode, modeErr)
	}
	if err = ip.SetHopLimit(41); err != nil {
		t.Fatal(err)
	}
	if err = ip.SetTrafficClass(0x2e); err != nil {
		t.Fatal(err)
	}
	if _, err = ip.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 41 || packet.trafficClass != 0x2e || packet.protocol != 99 {
		t.Fatalf("IP output options = protocol %d hop %d class %#x", packet.protocol, packet.hopLimit, packet.trafficClass)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("answer"), 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := ip.Read(buffer); readErr != nil || string(buffer[:n]) != "answer" {
		t.Fatalf("IP Read = %q, %v", buffer[:n], readErr)
	}
	if err = ip.SetReadBuffer(ipDatagramMetadataSize); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, nil, uint16(index+2), true)); err != nil {
			t.Fatal(err)
		}
	}
	info := ip.Info()
	if info.Protocol != 99 || info.PacketsSent != 1 || info.BytesSent != 5 || info.PacketsReceived != 2 || info.BytesReceived != 6 ||
		info.PacketsDropped != 1 || info.ReceiveQueuePackets != 1 || info.ReceiveQueueBytes != ipDatagramMetadataSize ||
		info.ReceiveQueueCapacity != ipDatagramMetadataSize || info.PathMTU != 1400 || info.PathMTUDiscovery != PathMTUDiscoveryOmit ||
		info.HopLimit != 41 || info.TrafficClass != 0x2e {
		t.Fatalf("IP Info = %+v", info)
	}
}

func TestIPZeroHopLimitFamilyValidation(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.136")
	remote4 := netip.MustParseAddr("198.51.100.136")
	local6 := netip.MustParseAddr("2001:db8::136")
	remote6 := netip.MustParseAddr("2001:db8:1::136")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection6, err := stack.DialIP(context.Background(), "ip6:99", netip.Addr{}, remote6)
	if err != nil {
		t.Fatal(err)
	}
	ip6 := connection6.(*IPConn)
	defer ip6.Close()
	if err = ip6.SetHopLimit(0); err != nil {
		t.Fatal(err)
	}
	if _, err = ip6.Write([]byte("zero")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack), false)
	if !ok || packet.hopLimit != 0 || packet.target != remote6 {
		t.Fatalf("IPv6 default zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
	connection4, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote4)
	if err != nil {
		t.Fatal(err)
	}
	ip4 := connection4.(*IPConn)
	defer ip4.Close()
	if err = ip4.SetHopLimit(0); err == nil {
		t.Fatal("IPv4 SetHopLimit(0) succeeded")
	}
}

func BenchmarkIPReceiveQueue(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.244")
	remote := netip.MustParseAddr("198.51.100.244")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	b.Cleanup(connection.closeFromStack)
	payload := bytes.Repeat([]byte{0x6b}, 1200)
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
		if n, _, _, readErr := connection.readDatagram(buffer, nil); readErr != nil || n != len(payload) {
			b.Fatalf("readDatagram = %d, %v", n, readErr)
		}
	}
}

func BenchmarkIPReadBufferAPI(b *testing.B) {
	for _, payloadSize := range []int{64, 512, 1200, 4096, 65515} {
		payloadSize := payloadSize
		for _, mode := range []string{"Read", "ReadWithBuffer", "ReadFrom", "ReadFromWithBuffer", "ReadFromIP", "ReadFromIPWithBuffer"} {
			mode := mode
			b.Run(fmt.Sprintf("%s/%d", mode, payloadSize), func(b *testing.B) {
				local := netip.MustParseAddr("192.0.2.246")
				remote := netip.MustParseAddr("198.51.100.246")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
				if err != nil {
					b.Fatal(err)
				}
				connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
				b.Cleanup(connection.closeFromStack)
				payload := bytes.Repeat([]byte{0x6b}, payloadSize)
				buffer := make([]byte, payloadSize)
				getBuffer := func(int) []byte { return buffer }
				b.SetBytes(int64(payloadSize))
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
					var n int
					switch mode {
					case "Read":
						n, err = connection.Read(buffer)
					case "ReadWithBuffer":
						n, err = connection.ReadWithBuffer(getBuffer)
					case "ReadFrom":
						n, _, err = connection.ReadFrom(buffer)
					case "ReadFromWithBuffer":
						n, _, err = connection.ReadFromWithBuffer(getBuffer)
					case "ReadFromIP":
						n, _, err = connection.ReadFromIP(buffer)
					case "ReadFromIPWithBuffer":
						n, _, err = connection.ReadFromIPWithBuffer(getBuffer)
					}
					if err != nil || n != payloadSize {
						b.Fatalf("%s = %d, %v", mode, n, err)
					}
				}
			})
		}
	}
}

func BenchmarkIPReadMessageAPI(b *testing.B) {
	for _, mode := range []string{"ReadMsg", "ReadBatch"} {
		b.Run(mode, func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.247")
			remote := netip.MustParseAddr("198.51.100.247")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				b.Fatal(err)
			}
			connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
			b.Cleanup(connection.closeFromStack)
			payload := bytes.Repeat([]byte{0x6b}, 1200)
			buffer := make([]byte, len(payload))
			control := make([]byte, 128)
			messages := []SocketMessage{{Buffers: [][]byte{buffer}, OOB: control}}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
				if mode == "ReadMsg" {
					n, _, _, _, readErr := connection.ReadMsgIP(buffer, control)
					if readErr != nil || n != len(payload) {
						b.Fatalf("ReadMsgIP = %d, %v", n, readErr)
					}
				} else {
					messages[0].N, messages[0].NN, messages[0].Flags = 0, 0, 0
					count, readErr := connection.ReadBatch(messages, 0)
					if readErr != nil || count != 1 || messages[0].N != len(payload) {
						b.Fatalf("ReadBatch = %d/%d, %v", count, messages[0].N, readErr)
					}
				}
			}
		})
	}
}

func BenchmarkIPInboundDispatch(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.238")
	remote := netip.MustParseAddr("198.51.100.238")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, netip.Addr{}, socketOptionSet{})
	stack.mu.Lock()
	state := stack.ipEndpointStateLocked()
	state.register(connection)
	stack.mu.Unlock()
	b.Cleanup(func() {
		connection.closeFromStack()
		_ = stack.Close()
	})
	payload := bytes.Repeat([]byte{0x6b}, 1200)
	packet := ipPacket{payload: payload, source: remote, target: local, protocol: 99}
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if !state.deliver(stack, packet) {
			b.Fatal("raw IP packet was not delivered")
		}
		if n, _, _, readErr := connection.readDatagram(buffer, nil); readErr != nil || n != len(payload) {
			b.Fatalf("readDatagram = %d, %v", n, readErr)
		}
	}
}

func TestIPReceivePayloadSpareIsBoundedAndReleased(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.248")
	remote := netip.MustParseAddr("198.51.100.248")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote, socketOptionSet{})
	read := func(payload []byte) {
		connection.enqueuePacket(ipPacket{payload: payload, source: remote, target: local}, ipPacketOptions{})
		buffer := make([]byte, len(payload))
		if n, _, _, readErr := connection.readDatagram(buffer, nil); readErr != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
			t.Fatalf("readDatagram = %d bytes, %v", n, readErr)
		}
	}
	read(make([]byte, 1200))
	connection.mu.Lock()
	spareCapacity := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if spareCapacity < 1200 || spareCapacity > datagramReusablePayloadLimit {
		t.Fatalf("receive spare capacity = %d", spareCapacity)
	}
	read(make([]byte, datagramReusablePayloadLimit+1))
	connection.mu.Lock()
	retainedAfterJumbo := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterJumbo != spareCapacity {
		t.Fatalf("jumbo read changed receive spare capacity from %d to %d", spareCapacity, retainedAfterJumbo)
	}
	connection.closeFromStack()
	connection.mu.Lock()
	retainedAfterClose := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterClose != 0 {
		t.Fatalf("closed socket retained receive spare capacity %d", retainedAfterClose)
	}
}

func TestIPConnCloseReleasesRetainedState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.254")
	remote := netip.MustParseAddr("198.51.100.254")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newIPConn(stack, "ip4:99", 99, local, netip.Addr{}, socketOptionSet{})
	if err = connection.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	connection.enqueuePacket(ipPacket{payload: make([]byte, 1200), source: remote, target: local}, ipPacketOptions{})
	connection.rememberTarget(remote)
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(remote, ICMPError{Reporter: remote, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol, QuotedPayload: make([]byte, 1200)})
	connection.mu.Lock()
	if connection.errorState == nil || connection.errorState.pending == nil || connection.errorState.queue.len() == 0 {
		connection.mu.Unlock()
		t.Fatal("IP socket did not retain an error before close")
	}
	connection.receiveSpare = make([]byte, 0, 1200)
	connection.mu.Unlock()
	connection.closeFromStack()
	connection.rememberTarget(remote)
	connection.deliverError(remote, ICMPError{Reporter: remote, Type: ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeProtocol, QuotedPayload: make([]byte, 1200)})
	connection.enqueuePacket(ipPacket{payload: make([]byte, 1200), source: remote, target: local}, ipPacketOptions{})
	connection.mu.Lock()
	released := connection.receive.values == nil && connection.receiveSpare == nil && connection.queuedBytes == 0 &&
		connection.errorState != nil && connection.errorState.queue.values == nil && connection.errorState.queuedBytes == 0 &&
		connection.recentTargets.state == nil && connection.errorState.lastError == nil && connection.errorState.pending == nil &&
		connection.readDeadline.state.Load() == stoppedDatagramSocketDeadline && connection.writeDeadline.state.Load() == stoppedDatagramSocketDeadline
	connection.mu.Unlock()
	if !released || connection.errorState.icmpErrors != 1 {
		t.Fatal("closed IP socket retained or recreated payload-bearing state")
	}
}

func BenchmarkIPPacketWrite(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.246")
	remote := netip.MustParseAddr("198.51.100.246")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	connection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = connection.Close()
		_ = stack.Close()
	})
	payload := bytes.Repeat([]byte{0x7c}, 1200)
	buffers := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if count, readErr := stack.Read(buffers, sizes, 0); readErr != nil || count != 1 {
			b.Fatalf("Stack.Read = %d, %v", count, readErr)
		}
	}
}

func BenchmarkIPHeaderIncludedWrite(b *testing.B) {
	local := netip.MustParseAddr("2001:db8::247")
	remote := netip.MustParseAddr("2001:db8:1::247")
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions(nil); err != nil {
		b.Fatal(err)
	}
	for _, mtu := range []int{1500, 9000, 16384, 32768, 65535} {
		b.Run(fmt.Sprintf("mtu-%d", mtu), func(b *testing.B) {
			for _, test := range []struct {
				name      string
				headers   []IPv6ExtensionHeader
				flowLabel uint32
			}{
				{name: "base-header"},
				{name: "hop-by-hop", headers: []IPv6ExtensionHeader{hop}},
				{name: "base-header/labeled", flowLabel: 0x12345},
				{name: "hop-by-hop/labeled", headers: []IPv6ExtensionHeader{hop}, flowLabel: 0x12345},
			} {
				b.Run(test.name, func(b *testing.B) {
					extensionSize := len(test.headers) * 8
					datagram := mustTestWire((UDPDatagram{
						Source:      netip.AddrPortFrom(local, 14000),
						Destination: netip.AddrPortFrom(remote, 443),
						Payload:     make([]byte, mtu-40-extensionSize-udpHeaderSize),
					}).MarshalBinary())
					stack, err := New(Config{
						LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)},
						MTU:            uint32(mtu),
						IP:             IPSocketDefaults{IPHeaderIncludedOnWrite: true},
					})
					if err != nil {
						b.Fatal(err)
					}
					if err = stack.Start(); err != nil {
						b.Fatal(err)
					}
					connection, err := stack.DialIP(context.Background(), "ip6:udp", netip.Addr{}, remote)
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() {
						_ = connection.Close()
						_ = stack.Close()
					})
					packet := IPPacket{Source: local, Destination: remote, HopLimit: 64, FlowLabel: test.flowLabel}
					if err = packet.SetIPv6ExtensionHeaders(test.headers, ProtocolUDP, datagram); err != nil {
						b.Fatal(err)
					}
					wire := mustTestWire(packet.MarshalBinary())
					b.SetBytes(int64(len(wire)))
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						if written, writeErr := connection.Write(wire); writeErr != nil || written != len(wire) {
							b.Fatalf("Write = %d, %v", written, writeErr)
						}
						entry, ok := stack.outbound.tryDequeue()
						if !ok {
							b.Fatal("header-included write did not queue output")
						}
						if entry.reusable && cap(entry.packet) > packetReusableBufferLimit {
							if cache := stack.largeBuffers.Load(); cache != nil {
								cache.release(entry.packet)
							}
							entry.reusable = false
						}
						stack.outbound.release(entry)
					}
				})
			}
		})
	}
}

func BenchmarkIPBatchWrite(b *testing.B) {
	const batchSize = 16
	const payloadSize = 1200
	for _, buffersPerMessage := range []int{1, 2} {
		b.Run(fmt.Sprintf("buffers-%d", buffersPerMessage), func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.245")
			remote := netip.MustParseAddr("198.51.100.245")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			netConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
			if err != nil {
				b.Fatal(err)
			}
			connection := netConnection.(*IPConn)
			b.Cleanup(func() {
				_ = connection.Close()
				_ = stack.Close()
			})
			payload := make([]byte, payloadSize)
			messages := make([]SocketMessage, batchSize)
			for index := range messages {
				messages[index].Buffers = [][]byte{payload}
				if buffersPerMessage == 2 {
					messages[index].Buffers = [][]byte{payload[:400], payload[400:]}
				}
			}
			packets := make([][]byte, batchSize)
			for index := range packets {
				packets[index] = make([]byte, 1500)
			}
			sizes := make([]int, batchSize)
			b.SetBytes(batchSize * payloadSize)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if count, writeErr := connection.WriteBatch(messages, 0); writeErr != nil || count != batchSize {
					b.Fatalf("WriteBatch = %d, %v", count, writeErr)
				}
				if count, readErr := stack.Read(packets, sizes, 0); readErr != nil || count != batchSize {
					b.Fatalf("Stack.Read = %d, %v", count, readErr)
				}
			}
		})
	}
}

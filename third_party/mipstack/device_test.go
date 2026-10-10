package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPacketDeviceIO(t *testing.T) {
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/8"),
			netip.MustParsePrefix("192.168.1.2/24"),
		},
		MTU: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	destination := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.1.99:53"))
	connection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(destination.AddrPort().Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.WriteTo([]byte("query"), destination); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1508)
	sizes := []int{0}
	if count, readErr := stack.Read([][]byte{buffer}, sizes, 8); readErr != nil || count != 1 {
		t.Fatalf("Read = %d, %v", count, readErr)
	}
	packet, ok := parseIPPacket(buffer[8:8+sizes[0]], false)
	if !ok || packet.source != netip.MustParseAddr("192.168.1.2") || packet.target != destination.AddrPort().Addr() {
		t.Fatalf("unexpected outbound packet: source=%s target=%s", packet.source, packet.target)
	}

	icmp := make([]byte, 12)
	icmp[0] = 8
	copy(icmp[8:], []byte("ping"))
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	request := buildIPPacket(netip.MustParseAddr("192.168.1.99"), netip.MustParseAddr("192.168.1.2"), ProtocolICMPv4, icmp, 1, true)
	padded := append(make([]byte, 4), request...)
	if count, writeErr := stack.Write([][]byte{padded}, 4); writeErr != nil || count != 1 {
		t.Fatalf("Write = %d, %v", count, writeErr)
	}
	if count, readErr := stack.Read([][]byte{buffer}, sizes, 0); readErr != nil || count != 1 {
		t.Fatalf("Read echo = %d, %v", count, readErr)
	}
	reply, ok := parseIPPacket(buffer[:sizes[0]], false)
	if !ok || reply.payload[0] != 0 || reply.source != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("unexpected echo reply: %x", buffer[:sizes[0]])
	}
}

func TestPacketDeviceReadUnblocksOnClose(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, listenErr := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(netip.MustParseAddr("192.0.2.2"))); !errors.Is(listenErr, ErrNotStarted) {
		t.Fatalf("ListenUDP before Start = %v", listenErr)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatalf("repeated Start = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, readErr := stack.Read([][]byte{make([]byte, 65535)}, []int{0}, 0)
		done <- readErr
	}()
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v", err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
	if count, writeErr := stack.Write([][]byte{{0x45}}, 0); count != 0 || !errors.Is(writeErr, os.ErrClosed) {
		t.Fatalf("Write after Close = %d, %v", count, writeErr)
	}
}

func TestPacketDeviceCloseDiscardsOutput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.20")
	remote := netip.MustParseAddr("192.0.2.21")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	packet := buildIPPacket(local, remote, ProtocolUDP, make([]byte, udpHeaderSize), 1, false)
	inFlightSlot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("no output slot available for in-flight Read")
	}
	inFlightBuffer, inFlightReusable := stack.outbound.acquireBuffer(len(packet))
	copy(inFlightBuffer, packet)
	if !stack.outbound.enqueueReservedPacket(inFlightSlot, inFlightBuffer, inFlightReusable, false) {
		t.Fatal("failed to publish in-flight output")
	}
	inFlight, available := stack.outbound.tryDequeue()
	if !available || !inFlight.reusable {
		t.Fatal("failed to retain reusable packet across Close")
	}
	if err = stack.tryWritePacket(packet, false); err != nil {
		t.Fatal(err)
	}
	lateSlot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("no output slot available for late publisher")
	}
	lateBuffer, lateReusable := stack.outbound.acquireBuffer(len(packet))
	copy(lateBuffer, packet)
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	if stack.outbound.enqueueReservedPacket(lateSlot, lateBuffer, lateReusable, false) {
		t.Fatal("packet publication succeeded after Close")
	}
	stack.outbound.release(inFlight)
	if queued := stack.outbound.len(); queued != 0 {
		t.Fatalf("Close retained %d outbound packets", queued)
	}
	if slots := len(stack.outbound.free); slots != cap(stack.outbound.free) {
		t.Fatalf("output slots after Close = %d, want %d", slots, cap(stack.outbound.free))
	}
	if buffers := len(stack.outbound.buffers); buffers != 0 {
		t.Fatalf("Close retained %d reusable packet buffers", buffers)
	}
}

func TestPacketDeviceCloseDiscardsLargeOutput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.22")
	remote := netip.MustParseAddrPort("192.0.2.23:9000")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 9000-20-udpHeaderSize)
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	inFlight, available := stack.outbound.tryDequeue()
	if !available || !inFlight.reusable || len(inFlight.packet) != 9000 {
		t.Fatal("failed to retain dequeued jumbo output across Close")
	}
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	lateSlot, reserved := stack.outbound.tryReserve()
	if !reserved {
		t.Fatal("no output slot available for late jumbo publisher")
	}
	lateBuffer, lateReusable := stack.acquireLargeOutputBuffer(9000)
	cache := stack.largeBuffers.Load()
	if cache == nil || !lateReusable {
		t.Fatal("jumbo output cache is unavailable")
	}
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	if stack.outbound.enqueueReservedPacket(lateSlot, lateBuffer, lateReusable, false) {
		t.Fatal("jumbo packet publication succeeded after Close")
	}
	if cache := stack.largeBuffers.Load(); cache != nil {
		cache.release(inFlight.packet)
	}
	inFlight.reusable = false
	stack.outbound.release(inFlight)
	if stack.largeBuffers.Load() != nil || !cache.retired.Load() || len(cache.buffers) != 0 {
		t.Fatal("Close retained or repopulated the jumbo buffer cache")
	}
	if queued := stack.outbound.len(); queued != 0 {
		t.Fatalf("Close retained %d outbound packets", queued)
	}
	if slots := len(stack.outbound.free); slots != cap(stack.outbound.free) {
		t.Fatalf("output slots after Close = %d, want %d", slots, cap(stack.outbound.free))
	}
}

func TestPacketDeviceConcurrentCloseAndPublish(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.24")
	remote := netip.MustParseAddr("192.0.2.25")
	for round := 0; round < 100; round++ {
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		packet := buildIPPacket(local, remote, ProtocolUDP, make([]byte, udpHeaderSize), uint16(round), false)
		for index := 0; index < outboundPacketQueue; index++ {
			if writeErr := stack.tryWritePacket(packet, false); writeErr != nil {
				t.Fatalf("round %d fill packet %d: %v", round, index, writeErr)
			}
		}
		start := make(chan struct{})
		publish := make(chan struct{})
		var ready, writers sync.WaitGroup
		ready.Add(8)
		writers.Add(8)
		for writer := 0; writer < 8; writer++ {
			go func() {
				defer writers.Done()
				<-start
				if writeErr := stack.tryWritePacket(packet, false); writeErr != nil {
					ready.Done()
					t.Errorf("round %d initial publisher: %v", round, writeErr)
					return
				}
				ready.Done()
				<-publish
				for {
					err := stack.tryWritePacket(packet, false)
					if errors.Is(err, ErrClosed) {
						return
					}
					if err != nil && !errors.Is(err, ErrResourceLimit) {
						t.Errorf("round %d publisher: %v", round, err)
						return
					}
				}
			}()
		}
		close(start)
		ready.Wait()
		close(publish)
		if err = stack.Close(); err != nil {
			t.Fatal(err)
		}
		writers.Wait()
		if queued := stack.outbound.len(); queued != 0 {
			t.Fatalf("round %d retained %d outbound packets", round, queued)
		}
		if slots := len(stack.outbound.free); slots != cap(stack.outbound.free) {
			t.Fatalf("round %d output slots = %d, want %d", round, slots, cap(stack.outbound.free))
		}
		if buffers := len(stack.outbound.buffers); buffers != 0 {
			t.Fatalf("round %d retained %d reusable buffers", round, buffers)
		}
	}
}

func TestPacketDeviceLargeBufferCacheBounds(t *testing.T) {
	for _, test := range []struct {
		mtu   int
		slots int
	}{
		{mtu: 1500, slots: 0},
		{mtu: 2048, slots: 0},
		{mtu: 2049, slots: 255},
		{mtu: 9000, slots: 107},
		{mtu: 16384, slots: 88},
		{mtu: 32768, slots: 76},
		{mtu: 65535, slots: 70},
	} {
		t.Run(fmt.Sprintf("mtu-%d", test.mtu), func(t *testing.T) {
			if slots := largePacketBufferSlots(test.mtu); slots != test.slots {
				t.Fatalf("large buffer slots = %d, want %d", slots, test.slots)
			}
			cache := newLargePacketBufferCache(test.mtu)
			if test.slots == 0 {
				if cache != nil {
					t.Fatal("standard MTU created a large buffer cache")
				}
				return
			}
			if cache == nil || cache.maximum != test.mtu || cap(cache.buffers) != test.slots {
				t.Fatalf("large buffer cache = %+v, want maximum %d capacity %d", cache, test.mtu, test.slots)
			}
			for slot := 0; slot < test.slots+1; slot++ {
				cache.release(make([]byte, test.mtu))
			}
			if retained := len(cache.buffers); retained != test.slots {
				t.Fatalf("retained buffers = %d, want %d", retained, test.slots)
			}
			retainedBytes := 0
			for len(cache.buffers) != 0 {
				retainedBytes += cap(<-cache.buffers)
			}
			if maximum := deviceBatchSize*test.mtu + largePacketBufferSlack; retainedBytes > maximum {
				t.Fatalf("retained bytes = %d, want <= %d", retainedBytes, maximum)
			}
		})
	}
}

func TestPacketDeviceLargeBufferCacheSharing(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.1/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	cache := stack.largeBuffers.Load()
	if cache == nil {
		t.Fatal("jumbo MTU did not create a large buffer cache")
	}
	packet, reusable := stack.acquireLargeOutputBuffer(9000)
	if !reusable {
		t.Fatal("jumbo output buffer is not reusable")
	}
	packet[0] = 0xa5
	stack.releaseOutputBuffer(&stack.outbound, packet, reusable)
	if retained := len(cache.buffers); retained != 1 {
		t.Fatalf("retained large buffers = %d, want 1", retained)
	}
	reused, reusable := stack.acquireLargeOutputBuffer(9000)
	if !reusable || len(reused) != 9000 || reused[0] != 0xa5 {
		t.Fatal("loopback output did not reuse the external-output buffer")
	}
	stack.releaseOutputBuffer(&stack.loopback.packetQueue, reused, reusable)

	externalSmall, reusable := stack.outbound.acquireBuffer(1500)
	stack.releaseOutputBuffer(&stack.outbound, externalSmall, reusable)
	localSmall, reusable := stack.loopback.acquireBuffer(1500)
	stack.releaseOutputBuffer(&stack.loopback.packetQueue, localSmall, reusable)
	if len(stack.outbound.buffers) != 1 || len(stack.loopback.buffers) != 1 {
		t.Fatalf("small buffer caches = external %d local %d, want 1 each", len(stack.outbound.buffers), len(stack.loopback.buffers))
	}
	if retained := len(cache.buffers); retained != 1 {
		t.Fatalf("small output changed large buffer retention to %d", retained)
	}
}

func TestPacketDeviceLargeBufferCacheBestEffortReplacement(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	cache := stack.largeBuffers.Load()
	if cache == nil {
		t.Fatal("jumbo MTU did not create a large buffer cache")
	}
	const marker = 0xa5
	for index := 0; index < cap(stack.outbound.free); index++ {
		slot, reserved := stack.outbound.tryReserve()
		if !reserved {
			t.Fatalf("output slot %d was not available", index)
		}
		packet, reusable := stack.acquireLargeOutputBuffer(9000)
		if !reusable {
			t.Fatalf("jumbo packet %d is not reusable", index)
		}
		packet[0] = marker
		if !stack.outbound.enqueueReservedPacketForFlow(slot, packet, reusable, outputHashedFlowKey(1), false) {
			t.Fatalf("jumbo packet %d was not published", index)
		}
	}
	if retained := len(cache.buffers); retained != 0 {
		t.Fatalf("full output queue left %d idle large buffers", retained)
	}
	drops := stack.Stats().OutboundQueueDrops
	slot, err := stack.replaceBestEffortPacket(&stack.outbound)
	if err != nil {
		t.Fatal(err)
	}
	if retained := len(cache.buffers); retained != 1 {
		t.Fatalf("best-effort replacement retained %d large buffers, want 1", retained)
	}
	if got := stack.Stats().OutboundQueueDrops; got != drops+1 {
		t.Fatalf("best-effort replacement drops = %d, want %d", got, drops+1)
	}
	packet, reusable := stack.acquireLargeOutputBuffer(9000)
	if !reusable || packet[0] != marker {
		t.Fatal("best-effort replacement did not return the displaced jumbo buffer")
	}
	stack.releaseOutputBuffer(&stack.outbound, packet, reusable)
	stack.outbound.releaseReserved(slot)
}

func TestPacketDeviceLargeBufferCacheLifecycle(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.1/32")
	configuration := Config{LocalAddresses: []netip.Prefix{local}, MTU: 9000}
	stack, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	first := stack.largeBuffers.Load()
	held, reusable := stack.acquireLargeOutputBuffer(9000)
	if first == nil || !reusable {
		t.Fatal("initial large buffer cache is unavailable")
	}
	first.release(make([]byte, 9000))
	if err = stack.UpdateConfig(configuration); err != nil {
		t.Fatal(err)
	}
	if current := stack.largeBuffers.Load(); current != first || first.retired.Load() {
		t.Fatal("unchanged MTU replaced the large buffer cache")
	}

	configuration.MTU = 32768
	if err = stack.UpdateConfig(configuration); err != nil {
		t.Fatal(err)
	}
	second := stack.largeBuffers.Load()
	if second == nil || second == first || !first.retired.Load() || len(first.buffers) != 0 {
		t.Fatal("MTU increase did not retire and drain the old cache")
	}
	stack.releaseOutputBuffer(&stack.outbound, held, reusable)
	if retained := len(second.buffers); retained != 1 {
		t.Fatalf("current cache retained %d migrated buffers, want 1", retained)
	}

	configuration.MTU = 1500
	if err = stack.UpdateConfig(configuration); err != nil {
		t.Fatal(err)
	}
	if stack.largeBuffers.Load() != nil || !second.retired.Load() || len(second.buffers) != 0 {
		t.Fatal("standard MTU retained a large buffer cache")
	}
	configuration.MTU = 9000
	if err = stack.UpdateConfig(configuration); err != nil {
		t.Fatal(err)
	}
	third := stack.largeBuffers.Load()
	if third == nil || third == first || third == second {
		t.Fatal("jumbo MTU did not install a new cache generation")
	}
	third.release(make([]byte, 9000))
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	if stack.largeBuffers.Load() != nil || !third.retired.Load() || len(third.buffers) != 0 {
		t.Fatal("Close retained the active large buffer cache")
	}
}

func TestPacketDeviceLargeBufferCacheConcurrentRetirement(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.1/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	generations := []*largePacketBufferCache{stack.largeBuffers.Load()}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 1000; iteration++ {
				size := 9000
				if (worker+iteration)&1 != 0 {
					size = 32768
				}
				buffer, reusable := stack.acquireLargeOutputBuffer(size)
				stack.releaseOutputBuffer(&stack.outbound, buffer, reusable)
			}
		}(worker)
	}
	close(start)
	var updateErr error
	for iteration := 0; iteration < 100; iteration++ {
		mtu := uint32(9000)
		if iteration&1 != 0 {
			mtu = 32768
		}
		if updateErr = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local}, MTU: mtu}); updateErr != nil {
			break
		}
		current := stack.largeBuffers.Load()
		if current != generations[len(generations)-1] {
			generations = append(generations, current)
		}
	}
	closeErr := stack.Close()
	workers.Wait()
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if stack.largeBuffers.Load() != nil {
		t.Fatal("Close retained an active large buffer cache")
	}
	for _, generation := range generations {
		if !generation.retired.Load() || len(generation.buffers) != 0 {
			t.Fatal("concurrent retirement retained an obsolete cache generation")
		}
	}
}

func TestDeviceMetadata(t *testing.T) {
	first4 := netip.MustParseAddr("192.0.2.13")
	first6 := netip.MustParseAddr("2001:db8::13")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.PrefixFrom(first4, 32),
			netip.PrefixFrom(first6, 128),
		},
		MTU: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mtu, mtuErr := stack.MTU(); mtuErr != nil || mtu != 1400 {
		t.Fatalf("MTU = %d, %v", mtu, mtuErr)
	}
	if name, nameErr := stack.Name(); nameErr != nil || name != "mihomo IP stack" {
		t.Fatalf("Name = %q, %v", name, nameErr)
	}
	if stack.BatchSize() != deviceBatchSize {
		t.Fatalf("BatchSize = %d, want %d", stack.BatchSize(), deviceBatchSize)
	}
	addresses := stack.LocalAddresses()
	if len(addresses) != 2 || addresses[0] != first4 || addresses[1] != first6 {
		t.Fatalf("local addresses = %v", addresses)
	}
	addresses[0] = netip.Addr{}
	if current := stack.LocalAddresses(); current[0] != first4 {
		t.Fatalf("caller mutated local-address snapshot: %v", current)
	}
	second6 := netip.MustParseAddr("2001:db8::14")
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(second6, 128)},
		MTU:            1300,
	}); err != nil {
		t.Fatal(err)
	}
	if addresses = stack.LocalAddresses(); len(addresses) != 1 || addresses[0] != second6 {
		t.Fatalf("updated local addresses = %v", addresses)
	}
	if mtu, _ := stack.MTU(); mtu != 1300 {
		t.Fatalf("updated MTU = %d, want 1300", mtu)
	}
}

func TestPacketDeviceBatchRead(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.31/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	connection, err := stack.ListenUDP(context.Background(), "udp4", netip.MustParseAddrPort("192.0.2.31:5300"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	for index := 0; index < 3; index++ {
		if _, err = connection.WriteTo([]byte{byte(index)}, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.32:5300"))); err != nil {
			t.Fatal(err)
		}
	}
	const wireguardOffset = 16
	buffers := make([][]byte, 4)
	for index := range buffers {
		buffers[index] = make([]byte, wireguardOffset+1500)
		for prefix := 0; prefix < wireguardOffset; prefix++ {
			buffers[index][prefix] = 0xa5
		}
	}
	sizes := make([]int, len(buffers))
	count, err := stack.Read(buffers, sizes, wireguardOffset)
	if err != nil || count != 3 {
		t.Fatalf("batch Read = %d, %v, want 3, nil", count, err)
	}
	for index := 0; index < count; index++ {
		if !bytes.Equal(buffers[index][:wireguardOffset], bytes.Repeat([]byte{0xa5}, wireguardOffset)) {
			t.Fatalf("batch packet %d overwrote offset prefix", index)
		}
		packet, ok := parseIPPacket(buffers[index][wireguardOffset:wireguardOffset+sizes[index]], false)
		if !ok || len(packet.payload) != udpHeaderSize+1 || packet.payload[udpHeaderSize] != byte(index) {
			t.Fatalf("batch packet %d = %x", index, buffers[index][wireguardOffset:wireguardOffset+sizes[index]])
		}
	}
	if _, err = stack.Read(make([][]byte, 2), make([]int, 1), 0); err == nil {
		t.Fatal("Read accepted a sizes slice shorter than buffers")
	}
}

func TestPacketDeviceWriteCountsConsumedEmptyPacket(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.41/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	const wireguardOffset = 16
	if count, writeErr := stack.Write([][]byte{make([]byte, wireguardOffset)}, wireguardOffset); writeErr != nil || count != 1 {
		t.Fatalf("Write empty packet = %d, %v, want 1, nil", count, writeErr)
	}
	stats := stack.Stats()
	if stats.InboundPackets != 1 || stats.InboundDroppedPackets != 1 || stats.InvalidIPPackets != 1 {
		t.Fatalf("empty packet diagnostics = %+v", stats)
	}
	if count, writeErr := stack.Write([][]byte{make([]byte, wireguardOffset), make([]byte, wireguardOffset-1)}, wireguardOffset); writeErr == nil || count != 1 {
		t.Fatalf("partial Write = %d, %v, want 1 and an offset error", count, writeErr)
	}
}

func TestPacketDeviceBatchReadReportsCompletedPrefix(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.51/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.52:5300"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	for index := 0; index < 2; index++ {
		if _, err = connection.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	const wireguardOffset = 16
	buffers := [][]byte{make([]byte, wireguardOffset+1500), make([]byte, wireguardOffset)}
	sizes := make([]int, len(buffers))
	count, err := stack.Read(buffers, sizes, wireguardOffset)
	if !errors.Is(err, io.ErrShortBuffer) || count != 1 || sizes[0] == 0 || sizes[1] != 0 {
		t.Fatalf("partial Read = %d, %v, sizes %v", count, err, sizes)
	}
}

func TestPacketDeviceShortReadReturnsLargeBuffer(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.61")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.62:5300"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	payload := make([]byte, 9000-20-udpHeaderSize)
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	count, err := stack.Read([][]byte{make([]byte, 8999)}, []int{0}, 0)
	if count != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short jumbo Read = %d, %v, want 0, io.ErrShortBuffer", count, err)
	}
	if slots := len(stack.outbound.free); slots != cap(stack.outbound.free) {
		t.Fatalf("free output slots = %d, want %d", slots, cap(stack.outbound.free))
	}
	cache := stack.largeBuffers.Load()
	if cache == nil || len(cache.buffers) != 1 {
		t.Fatal("short jumbo Read did not return its large buffer")
	}
	packet, reusable := stack.acquireLargeOutputBuffer(9000)
	if !reusable || len(packet) != 9000 {
		t.Fatal("short jumbo Read buffer could not be reused")
	}
	stack.releaseOutputBuffer(&stack.outbound, packet, reusable)
}

func TestPacketDeviceLoopbackReturnsLargeBuffer(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.63")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 5300))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	sender, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(local, 5300))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	payload := bytes.Repeat([]byte{0x5a}, 9000-20-udpHeaderSize)
	if _, err = sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	n, _, err := listener.ReadFrom(received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received[:n], payload) {
		t.Fatal("loopback jumbo payload mismatch")
	}
	cache := stack.largeBuffers.Load()
	waitFor(t, time.Second, func() bool {
		return cache != nil && len(cache.buffers) == 1 && len(stack.loopback.free) == cap(stack.loopback.free)
	})
	packet, reusable := stack.acquireLargeOutputBuffer(9000)
	if !reusable || len(packet) != 9000 {
		t.Fatal("loopback jumbo buffer could not be reused")
	}
	stack.releaseOutputBuffer(&stack.loopback.packetQueue, packet, reusable)
}

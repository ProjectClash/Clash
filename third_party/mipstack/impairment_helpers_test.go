package mipstack

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type testLinkCondition struct {
	Latency        time.Duration
	Jitter         time.Duration
	LossRate       float64
	BurstEnterRate float64
	BurstExitRate  float64
	DuplicateRate  float64
	Bandwidth      int64
	QueueBytes     int
}

type testLinkConditions struct {
	ClientToPeer testLinkCondition
	PeerToClient testLinkCondition
	Seed         int64
}

type testLinkDirectionStats struct {
	Packets          uint64
	Delivered        uint64
	RandomDrops      uint64
	QueueDrops       uint64
	Duplicates       uint64
	MaximumDropBurst int
	MaximumQueued    int
}

type testImpairedPacket struct {
	direction int
	packet    []byte
}

type testScheduledPacket struct {
	direction   int
	destination *Stack
	packet      []byte
	deliverAt   time.Time
	sequence    uint64
	drop        bool
}

type testScheduledPackets []testScheduledPacket

func (p testScheduledPackets) Len() int { return len(p) }
func (p testScheduledPackets) Less(left, right int) bool {
	if p[left].deliverAt.Equal(p[right].deliverAt) {
		return p[left].sequence < p[right].sequence
	}
	return p[left].deliverAt.Before(p[right].deliverAt)
}
func (p testScheduledPackets) Swap(left, right int) { p[left], p[right] = p[right], p[left] }
func (p *testScheduledPackets) Push(value any)      { *p = append(*p, value.(testScheduledPacket)) }
func (p *testScheduledPackets) Pop() any {
	old := *p
	last := len(old) - 1
	value := old[last]
	old[last] = testScheduledPacket{}
	*p = old[:last]
	return value
}

type testLinkDirection struct {
	condition        testLinkCondition
	random           *rand.Rand
	burstLoss        bool
	nextTransmission time.Time
	queuedBytes      int
	transmissions    []testLinkTransmission
	transmissionHead int
	dropBurst        int
}

type testLinkTransmission struct {
	completeAt time.Time
	bytes      int
}

type testImpairedLink struct {
	client, peer *Stack
	input        chan testImpairedPacket
	done         chan struct{}
	pumps        sync.WaitGroup

	mu    sync.Mutex
	stats [2]testLinkDirectionStats
}

func newTestImpairedLink(t *testing.T, client, peer *Stack, conditions testLinkConditions) *testImpairedLink {
	t.Helper()
	link := &testImpairedLink{
		client: client,
		peer:   peer,
		input:  make(chan testImpairedPacket, outboundPacketQueue*2),
		done:   make(chan struct{}),
	}
	link.pumps.Add(2)
	go link.readPackets(client, 0)
	go link.readPackets(peer, 1)
	go link.schedule(conditions)
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
		link.pumps.Wait()
		close(link.input)
		<-link.done
	})
	return link
}

func (l *testImpairedLink) readPackets(source *Stack, direction int) {
	defer l.pumps.Done()
	mtu, _ := source.MTU()
	buffers := make([][]byte, source.BatchSize())
	sizes := make([]int, len(buffers))
	for index := range buffers {
		buffers[index] = make([]byte, mtu)
	}
	for {
		count, err := source.Read(buffers, sizes, 0)
		if err != nil {
			return
		}
		for index := 0; index < count; index++ {
			packet := append([]byte(nil), buffers[index][:sizes[index]]...)
			l.input <- testImpairedPacket{direction: direction, packet: packet}
		}
	}
}

func (l *testImpairedLink) schedule(conditions testLinkConditions) {
	defer close(l.done)
	seed := conditions.Seed
	if seed == 0 {
		seed = 1
	}
	directions := [2]testLinkDirection{
		{condition: conditions.ClientToPeer, random: rand.New(rand.NewSource(seed))},
		{condition: conditions.PeerToClient, random: rand.New(rand.NewSource(seed ^ 0x5deece66d))},
	}
	destinations := [2]*Stack{l.peer, l.client}
	var packets testScheduledPackets
	heap.Init(&packets)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	timerActive := false
	var timerDeadline time.Time
	var sequence uint64
	for {
		var timerReady <-chan time.Time
		if len(packets) != 0 && (!timerActive || packets[0].deliverAt.Before(timerDeadline)) {
			if timerActive && !timer.Stop() {
				<-timer.C
			}
			delay := time.Until(packets[0].deliverAt)
			if delay < 0 {
				delay = 0
			}
			timer.Reset(delay)
			timerActive = true
			timerDeadline = packets[0].deliverAt
		}
		if timerActive {
			timerReady = timer.C
		}
		select {
		case packet, open := <-l.input:
			if !open {
				return
			}
			sequence++
			l.schedulePacket(&packets, &directions[packet.direction], destinations[packet.direction], packet, sequence)
		case <-timerReady:
			timerActive = false
			now := time.Now()
			for len(packets) != 0 && !packets[0].deliverAt.After(now) {
				packet := heap.Pop(&packets).(testScheduledPacket)
				if packet.drop {
					continue
				}
				_, err := packet.destination.Write([][]byte{packet.packet}, 0)
				if err == nil {
					l.mu.Lock()
					l.stats[packet.direction].Delivered++
					l.mu.Unlock()
				}
			}
		}
	}
}

func (l *testImpairedLink) schedulePacket(packets *testScheduledPackets, direction *testLinkDirection, destination *Stack, packet testImpairedPacket, sequence uint64) {
	condition := direction.condition
	size := len(packet.packet)
	now := time.Now()
	direction.releaseTransmissions(now)
	l.mu.Lock()
	l.stats[packet.direction].Packets++
	l.mu.Unlock()
	if condition.QueueBytes > 0 && direction.queuedBytes+size > condition.QueueBytes {
		l.mu.Lock()
		l.stats[packet.direction].QueueDrops++
		l.mu.Unlock()
		return
	}

	transmissionStart := now
	if direction.nextTransmission.After(transmissionStart) {
		transmissionStart = direction.nextTransmission
	}
	transmissionEnd := transmissionStart
	if condition.Bandwidth > 0 {
		serialization := time.Duration((int64(size)*int64(time.Second) + condition.Bandwidth - 1) / condition.Bandwidth)
		transmissionEnd = transmissionStart.Add(serialization)
		direction.nextTransmission = transmissionEnd
	}
	delay := condition.Latency + testLinkJitter(direction.random, condition.Jitter)
	if delay < 0 {
		delay = 0
	}
	delivery := transmissionEnd.Add(delay)
	drop := testLinkRandomDrop(direction)
	direction.queuedBytes += size
	direction.transmissions = append(direction.transmissions, testLinkTransmission{completeAt: transmissionEnd, bytes: size})
	l.mu.Lock()
	if direction.queuedBytes > l.stats[packet.direction].MaximumQueued {
		l.stats[packet.direction].MaximumQueued = direction.queuedBytes
	}
	if drop {
		direction.dropBurst++
		l.stats[packet.direction].RandomDrops++
		if direction.dropBurst > l.stats[packet.direction].MaximumDropBurst {
			l.stats[packet.direction].MaximumDropBurst = direction.dropBurst
		}
	} else {
		direction.dropBurst = 0
	}
	l.mu.Unlock()
	heap.Push(packets, testScheduledPacket{
		direction: packet.direction, destination: destination, packet: packet.packet,
		deliverAt: delivery, sequence: sequence, drop: drop,
	})
	if !drop && condition.DuplicateRate > 0 && direction.random.Float64() < condition.DuplicateRate {
		l.mu.Lock()
		l.stats[packet.direction].Duplicates++
		l.mu.Unlock()
		heap.Push(packets, testScheduledPacket{
			direction: packet.direction, destination: destination, packet: append([]byte(nil), packet.packet...),
			deliverAt: delivery.Add(time.Nanosecond), sequence: sequence + 1<<63,
		})
	}
}

func (d *testLinkDirection) releaseTransmissions(now time.Time) {
	for d.transmissionHead < len(d.transmissions) && !d.transmissions[d.transmissionHead].completeAt.After(now) {
		d.queuedBytes -= d.transmissions[d.transmissionHead].bytes
		d.transmissionHead++
	}
	if d.transmissionHead == 0 {
		return
	}
	if d.transmissionHead == len(d.transmissions) {
		d.transmissions = d.transmissions[:0]
		d.transmissionHead = 0
		return
	}
	if d.transmissionHead >= 64 && d.transmissionHead*2 >= len(d.transmissions) {
		remaining := copy(d.transmissions, d.transmissions[d.transmissionHead:])
		d.transmissions = d.transmissions[:remaining]
		d.transmissionHead = 0
	}
}

func testLinkRandomDrop(direction *testLinkDirection) bool {
	condition := direction.condition
	if direction.burstLoss {
		drop := true
		if condition.BurstExitRate > 0 && direction.random.Float64() < condition.BurstExitRate {
			direction.burstLoss = false
		}
		return drop
	}
	if condition.BurstEnterRate > 0 && direction.random.Float64() < condition.BurstEnterRate {
		direction.burstLoss = true
		return true
	}
	return condition.LossRate > 0 && direction.random.Float64() < condition.LossRate
}

func testLinkJitter(random *rand.Rand, limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return time.Duration(random.Int63n(int64(limit)*2+1)) - limit
}

func (l *testImpairedLink) Stats(direction int) testLinkDirectionStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats[direction]
}

func newTestTCPConnectionPair(t *testing.T, algorithm string, conditions testLinkConditions) (*TCPConn, *TCPConn, *testImpairedLink) {
	return newTestTCPConnectionPairForAddresses(t, algorithm, conditions,
		netip.MustParseAddr("192.0.2.201"), netip.MustParseAddr("192.0.2.202"))
}

func newTestTCPConnectionPairForAddresses(t *testing.T, algorithm string, conditions testLinkConditions, clientAddress, serverAddress netip.Addr) (*TCPConn, *TCPConn, *testImpairedLink) {
	t.Helper()
	client, server, link := newTestImpairedStackPair(t, algorithm, conditions, clientAddress, serverAddress)
	network := "tcp6"
	if serverAddress.Is4() {
		network = "tcp4"
	}
	listener, err := server.ListenTCP(context.Background(), network, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptError <- acceptErr
			return
		}
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := client.DialTCP(ctx, network, netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case serverConnection := <-accepted:
		t.Cleanup(func() {
			_ = connection.Close()
			_ = serverConnection.Close()
		})
		return connection.(*TCPConn), serverConnection.(*TCPConn), link
	case err = <-acceptError:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil, nil, nil
}

func newTestImpairedStackPair(t *testing.T, algorithm string, conditions testLinkConditions, clientAddress, serverAddress netip.Addr) (*Stack, *Stack, *testImpairedLink) {
	t.Helper()
	newStack := func(address netip.Addr) *Stack {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(address, bits)},
			MTU:            1400,
			TCP:            TCPSocketDefaults{CongestionControl: algorithm},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		return stack
	}
	client, server := newStack(clientAddress), newStack(serverAddress)
	link := newTestImpairedLink(t, client, server, conditions)
	return client, server, link
}

func transferTestTCPPayload(t *testing.T, sender net.Conn, receiver net.Conn, size int, timeout time.Duration) {
	t.Helper()
	if err := exchangeTestTCPPayload(sender, receiver, size, timeout, 0); err != nil {
		t.Fatal(err)
	}
}

func exchangeTestTCPPayload(sender net.Conn, receiver net.Conn, size int, timeout time.Duration, salt uint32) error {
	payload := make([]byte, size)
	for offset := 0; offset+4 <= len(payload); offset += 4 {
		binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(offset)^salt)
	}
	_ = sender.SetDeadline(time.Now().Add(timeout))
	_ = receiver.SetDeadline(time.Now().Add(timeout))
	writeResult := make(chan error, 1)
	go func() {
		_, err := sender.Write(payload)
		writeResult <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, received); err != nil {
		return err
	}
	if err := <-writeResult; err != nil {
		return err
	}
	if !bytes.Equal(received, payload) {
		return errors.New("TCP payload was corrupted by impaired delivery")
	}
	return nil
}

func TestImpairedLinkQueueExcludesPropagation(t *testing.T) {
	link := &testImpairedLink{}
	direction := testLinkDirection{
		condition: testLinkCondition{Latency: time.Second, Bandwidth: 1000, QueueBytes: 100},
		random:    rand.New(rand.NewSource(1)),
	}
	var scheduled testScheduledPackets
	heap.Init(&scheduled)
	packet := testImpairedPacket{direction: 0, packet: make([]byte, 100)}
	link.schedulePacket(&scheduled, &direction, nil, packet, 1)
	if len(direction.transmissions) != 1 || len(scheduled) != 1 || direction.queuedBytes != 100 {
		t.Fatalf("first scheduled packet = transmissions %d events %d queued %d", len(direction.transmissions), len(scheduled), direction.queuedBytes)
	}
	transmissionComplete := direction.transmissions[0].completeAt
	if !scheduled[0].deliverAt.After(transmissionComplete) {
		t.Fatalf("delivery %v did not follow serialization %v", scheduled[0].deliverAt, transmissionComplete)
	}
	direction.releaseTransmissions(transmissionComplete)
	if direction.queuedBytes != 0 || len(scheduled) != 1 {
		t.Fatalf("serialized packet retained queue bytes: queued %d events %d", direction.queuedBytes, len(scheduled))
	}
	link.schedulePacket(&scheduled, &direction, nil, packet, 2)
	if stats := link.Stats(0); stats.QueueDrops != 0 || stats.Packets != 2 || direction.queuedBytes != 100 {
		t.Fatalf("second scheduled packet = stats %+v queued %d", stats, direction.queuedBytes)
	}
}

func TestImpairedLinkLossSequenceIsDeterministic(t *testing.T) {
	condition := testLinkCondition{LossRate: 0.1, BurstEnterRate: 0.08, BurstExitRate: 0.3}
	sequence := func(seed int64) []byte {
		direction := testLinkDirection{condition: condition, random: rand.New(rand.NewSource(seed))}
		result := make([]byte, 128)
		for index := range result {
			if testLinkRandomDrop(&direction) {
				result[index] = 1
			}
		}
		return result
	}
	first := sequence(7123)
	second := sequence(7123)
	otherDirection := sequence(7123 ^ 0x5deece66d)
	if !bytes.Equal(first, second) {
		t.Fatal("equal impairment seeds produced different loss sequences")
	}
	if bytes.Equal(first, otherDirection) {
		t.Fatal("opposite impairment directions shared one loss sequence")
	}
	maximumBurst, currentBurst, drops := 0, 0, 0
	for _, drop := range first {
		if drop == 0 {
			currentBurst = 0
			continue
		}
		drops++
		currentBurst++
		if currentBurst > maximumBurst {
			maximumBurst = currentBurst
		}
	}
	if drops == 0 || maximumBurst < 2 {
		t.Fatalf("loss sequence = %d drops, maximum burst %d", drops, maximumBurst)
	}
}

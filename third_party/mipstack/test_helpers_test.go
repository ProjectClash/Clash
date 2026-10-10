package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

func mustCodecVector(t testing.TB, wire string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func testPacketQueueTicketAt(epoch, value time.Time) packetQueueTicket {
	return packetQueueTicket{queuedAt: monotonicStampAt(epoch, value)}
}

func testTCPReadBufferBytes(buffer *tcpReadBuffer) []byte {
	payload := make([]byte, 0, buffer.size)
	for index := buffer.head; index < len(buffer.chunks); index++ {
		payload = append(payload, buffer.chunks[index]...)
	}
	return payload
}

func mustTestWire(wire []byte, err error) []byte {
	if err != nil {
		panic("mipstack: invalid test wire fixture: " + err.Error())
	}
	return wire
}

func buildIPPacket(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool) []byte {
	return buildIPPacketWithOptions(source, target, protocol, payload, identification, dontFragment, ipPacketOptions{})
}

func buildIPPacketWithOptions(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool, options ipPacketOptions) []byte {
	options = options.normalized()
	packet := IPPacket{
		Source: source, Destination: target, Protocol: int(protocol),
		HopLimit: int(options.hopLimit), TrafficClass: int(options.trafficClass),
		FlowLabel: options.flowLabel, Payload: payload,
	}
	if source.Unmap().Is4() {
		packet.Identification = identification
		packet.DontFragment = dontFragment
		packet.FlowLabel = 0
	}
	return mustTestWire(packet.MarshalBinary())
}

func buildIPv4Fragments(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint16) [][]byte {
	return buildIPv4FragmentsWithOptions(source, target, protocol, payload, mtu, identification, ipPacketOptions{})
}

func buildIPv4FragmentsWithOptions(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint16, options ipPacketOptions) [][]byte {
	options = options.normalized()
	packets, err := (IPPacket{
		Source: source, Destination: target, Protocol: int(protocol),
		HopLimit: int(options.hopLimit), TrafficClass: int(options.trafficClass),
		Identification: identification, Payload: payload,
	}).MarshalFragments(mtu, 0)
	if err != nil {
		panic("mipstack: invalid IPv4 fragment fixture: " + err.Error())
	}
	return packets
}

func buildIPv6FragmentsWithOptions(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint32, options ipPacketOptions) [][]byte {
	options = options.normalized()
	packets, err := (IPPacket{
		Source: source, Destination: target, Protocol: int(protocol),
		HopLimit: int(options.hopLimit), TrafficClass: int(options.trafficClass),
		FlowLabel: options.flowLabel, Payload: payload,
	}).MarshalFragments(mtu, identification)
	if err != nil {
		panic("mipstack: invalid IPv6 fragment fixture: " + err.Error())
	}
	return packets
}

func (s *Stack) reassemblePacket(packet []byte, now time.Time) []byte {
	result, _ := s.reassemblePacketStatus(packet, now, false)
	return result
}

func (s *Stack) reassemblePacketStatus(packet []byte, now time.Time, loopback bool) (_ []byte, pending bool) {
	fragment, ok := parseFragment(packet, false)
	if !ok {
		return nil, false
	}
	return s.reassembleParsedFragmentStatus(fragment, now, loopback)
}

func (s *Stack) expireFragments(now time.Time) {
	s.fragmentMu.Lock()
	expired := s.cleanFragmentsLocked(now)
	s.fragmentMu.Unlock()
	s.sendFragmentTimeouts(expired)
}

type testPacketLink struct {
	local, remote         netip.Addr
	stack                 *Stack
	outbound              chan []byte
	echoUDP               bool
	echoTCP               bool
	holdTCPACKs           int
	reverseTCPResponses   bool
	dropTCPSYN            int
	dropECNSYN            bool
	dropTCPData           int
	dropTCPFIN            int
	dropTCPAbove          int
	sackTCP               bool
	disableTCPSACK        bool
	dropTCPOrdinals       map[int]bool
	timestampTCP          bool
	ecnTCP                bool
	disableTCPWindowScale bool
	useTCPWindow          bool
	advertisedTCPWindow   uint16
	markTCPCE             bool
	sendTCPECE            bool
	partialTCPACK         int
	delayTCPACK           time.Duration

	mu                     sync.Mutex
	tcp                    map[uint16]*testTCPPeer
	maximumTCPBurst        int
	clientSACKs            int
	clientDataSACKs        int
	clientACKs             int
	clientTimestamps       int
	clientECTPackets       int
	clientRetransmittedECT int
	maximumTCPData         int
	maximumTCPDataWithSACK int
	clientECEs             int
	clientCWRs             int
	legacySYNSends         int
	lastClientWindow       uint16
	sackRecovery           bool
	sackRecoveries         int
	tailRetransmission     bool
	tailRecoveryDelay      time.Duration
	tcpPathMTU             uint32
	pathMTUInjected        bool
	postPathMTUMaximum     int
	sackReneging           bool
	sackRenegingAt         time.Time
	sackRenegingDelay      time.Duration
	tcpDelaySpike          testTCPDelaySpike
	done                   chan struct{}
}

type testTCPDelaySpike struct {
	armed, released, triggered bool
	haveFirst                  bool
	firstSequence              uint32
	held, repeated             [][]byte
	delayedOriginal            [][]byte
	seen                       map[uint32]struct{}
	heldRanges, releaseAfter   int
	firstRetransmissions       int
}

func consumeTestPacket(queue *packetQueue, entry packetQueueEntry) []byte {
	packet := append([]byte(nil), entry.packet...)
	queue.release(entry)
	return packet
}

func waitTestPacketEntry(queue *packetQueue, timeout time.Duration) (packetQueueEntry, bool) {
	cancel := make(chan struct{})
	timer := time.AfterFunc(timeout, func() { close(cancel) })
	entry, ok := queue.dequeue(cancel)
	if timer.Stop() {
		close(cancel)
	}
	return entry, ok
}

type stackBridge struct {
	client, peer  *Stack
	done          chan struct{}
	mu            sync.Mutex
	clientWrites  int
	clientNext    map[uint16]uint32
	clientGaps    int
	clientRepeats int
	peerSACKs     int
	peerDSACKs    int
}

func newStackBridge(t *testing.T, client, peer *Stack) *stackBridge {
	t.Helper()
	bridge := &stackBridge{client: client, peer: peer, done: make(chan struct{}, 2)}
	go bridge.run(client, peer, true)
	go bridge.run(peer, client, false)
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
		<-bridge.done
		<-bridge.done
	})
	return bridge
}

func (b *stackBridge) run(source, destination *Stack, countClient bool) {
	defer func() { b.done <- struct{}{} }()
	buffers := make([][]byte, source.BatchSize())
	packets := make([][]byte, len(buffers))
	mtu, _ := source.MTU()
	for index := range buffers {
		buffers[index] = make([]byte, mtu)
	}
	sizes := make([]int, len(buffers))
	for {
		count, err := source.Read(buffers, sizes, 0)
		if err != nil {
			return
		}
		if countClient {
			b.mu.Lock()
			b.clientWrites += count
			for index := 0; index < count; index++ {
				b.trackClientTCPPacket(buffers[index][:sizes[index]])
			}
			b.mu.Unlock()
		} else {
			b.mu.Lock()
			for index := 0; index < count; index++ {
				b.trackPeerTCPPacket(buffers[index][:sizes[index]])
			}
			b.mu.Unlock()
		}
		for index := 0; index < count; index++ {
			packets[index] = buffers[index][:sizes[index]]
		}
		_, _ = destination.Write(packets[:count], 0)
	}
}

func (b *stackBridge) trackPeerTCPPacket(packet []byte) {
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		return
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return
	}
	acknowledgement := binary.BigEndian.Uint32(tcp[8:12])
	if headerSize == tcpHeaderSize {
		return
	}
	options := tcp[tcpHeaderSize:headerSize]
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == 0 {
			return
		}
		if kind == 1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return
		}
		if kind == 5 && length >= 10 && (length-2)%8 == 0 {
			firstLeft := binary.BigEndian.Uint32(options[offset+2 : offset+6])
			firstRight := binary.BigEndian.Uint32(options[offset+6 : offset+10])
			dsack := tcpSequenceLessEqual(firstRight, acknowledgement)
			if !dsack && length >= 18 {
				secondLeft := binary.BigEndian.Uint32(options[offset+10 : offset+14])
				secondRight := binary.BigEndian.Uint32(options[offset+14 : offset+18])
				dsack = tcpSequenceGreaterEqual(firstLeft, secondLeft) && tcpSequenceLessEqual(firstRight, secondRight)
			}
			if dsack {
				b.peerDSACKs++
			} else {
				b.peerSACKs++
			}
			return
		}
		offset += length
	}
}

func (b *stackBridge) trackClientTCPPacket(packet []byte) {
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		return
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return
	}
	port := binary.BigEndian.Uint16(tcp[0:2])
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	length := uint32(len(tcp) - headerSize)
	if tcp[13]&TCPFlagSYN != 0 {
		length++
	}
	if tcp[13]&TCPFlagFIN != 0 {
		length++
	}
	if length == 0 {
		return
	}
	if b.clientNext == nil {
		b.clientNext = make(map[uint16]uint32)
	}
	next, exists := b.clientNext[port]
	end := sequence + length
	if !exists || sequence == next {
		b.clientNext[port] = end
		return
	}
	if tcpSequenceLess(sequence, next) {
		b.clientRepeats++
		if tcpSequenceGreater(end, next) {
			b.clientNext[port] = end
		}
		return
	}
	b.clientGaps++
	b.clientNext[port] = end
}

type testTCPPeer struct {
	serverNext       uint32
	clientNext       uint32
	highestClientEnd uint32
	pending          [][]byte
	burst            int
	finSent          bool
	resetSeen        bool
	outOfOrder       map[uint32][]byte
	dropped          map[uint32]time.Time
	seenData         map[uint32]bool
	dataSegments     int
	timestamp        uint32
	clientTimestamp  uint32
}

func newStackPair(t *testing.T, firstAddress, secondAddress netip.Addr, mtu uint32) (*Stack, *Stack) {
	t.Helper()
	bits := 128
	if firstAddress.Is4() {
		bits = 32
	}
	first, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(firstAddress, bits)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Start(); err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(secondAddress, bits)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	return first, second
}

func checkNetOpError(t *testing.T, err error, operation, network string) *net.OpError {
	t.Helper()
	var operationError *net.OpError
	if !errors.As(err, &operationError) {
		t.Fatalf("error %v is not *net.OpError", err)
	}
	if operationError.Op != operation || operationError.Net != network {
		t.Fatalf("net.OpError = op %q net %q, want %q %q", operationError.Op, operationError.Net, operation, network)
	}
	return operationError
}

func newTestStack(t testing.TB, local, remote netip.Addr) (*testPacketLink, *Stack) {
	t.Helper()
	link := &testPacketLink{local: local, remote: remote, outbound: make(chan []byte, 32), tcp: make(map[uint16]*testTCPPeer), done: make(chan struct{})}
	bits := 128
	if local.Is4() {
		bits = 32
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	link.stack = stack
	go link.run()
	t.Cleanup(func() {
		_ = stack.Close()
		<-link.done
	})
	return link, stack
}

func newManuallyPumpedTCPConnections(t *testing.T, count int) (*testPacketLink, *Stack, []*TCPConn) {
	t.Helper()
	if count < 1 {
		t.Fatal("manually pumped TCP connection count must be positive")
	}
	local := netip.MustParseAddr("192.0.2.111")
	remote := netip.MustParseAddr("192.0.2.112")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	link := &testPacketLink{
		local: local, remote: remote, stack: stack, echoTCP: true, sackTCP: true,
		outbound: make(chan []byte, 1), tcp: make(map[uint16]*testTCPPeer),
	}
	type dialResult struct {
		connection net.Conn
		err        error
	}
	connections := make([]*TCPConn, count)
	for index := range connections {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		t.Cleanup(cancel)
		dialed := make(chan dialResult, 1)
		go func(port uint16) {
			connection, dialErr := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, port))
			dialed <- dialResult{connection: connection, err: dialErr}
		}(uint16(8080 + index))
		connected := false
		for !connected {
			select {
			case result := <-dialed:
				cancel()
				if result.err != nil {
					t.Fatal(result.err)
				}
				connections[index] = result.connection.(*TCPConn)
				connected = true
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			default:
			}
			entry, available := stack.outbound.tryDequeue()
			if !available && !connected {
				entry, available = waitTestPacketEntry(&stack.outbound, 10*time.Millisecond)
			}
			if available {
				if err = link.handleOutboundPacket(consumeTestPacket(&stack.outbound, entry)); err != nil {
					t.Fatal(err)
				}
			}
		}
		for {
			entry, available := stack.outbound.tryDequeue()
			if !available {
				break
			}
			if err = link.handleOutboundPacket(consumeTestPacket(&stack.outbound, entry)); err != nil {
				t.Fatal(err)
			}
		}
		_ = connections[index].Info()
	}
	return link, stack, connections
}

func newManuallyPumpedTCPConnection(t *testing.T) (*testPacketLink, *Stack, *TCPConn) {
	t.Helper()
	link, stack, connections := newManuallyPumpedTCPConnections(t, 1)
	return link, stack, connections[0]
}

func (l *testPacketLink) run() {
	defer close(l.done)
	buffer := make([]byte, 65535)
	for {
		sizes := []int{0}
		if _, err := l.stack.Read([][]byte{buffer}, sizes, 0); err != nil {
			return
		}
		_ = l.handleOutboundPacket(buffer[:sizes[0]])
	}
}

func (l *testPacketLink) handleOutboundPacket(packet []byte) error {
	parsed, ok := parseIPPacket(packet, false)
	if !ok {
		return nil
	}
	l.mu.Lock()
	echoUDP, echoTCP := l.echoUDP, l.echoTCP
	l.mu.Unlock()
	if parsed.protocol == ProtocolUDP && echoUDP {
		udp := parsed.payload
		if len(udp) >= udpHeaderSize {
			response := buildTestUDP(parsed.target, parsed.source, binary.BigEndian.Uint16(udp[2:4]), binary.BigEndian.Uint16(udp[0:2]), append([]byte(nil), udp[udpHeaderSize:]...))
			return writeTestPacket(l.stack, response)
		}
	}
	if parsed.protocol == ProtocolTCP && echoTCP {
		if handled, err := l.handleTCPDelaySpike(packet, parsed); handled {
			return err
		}
		return l.handleTCP(parsed)
	}
	select {
	case l.outbound <- append([]byte(nil), packet...):
	default:
	}
	return nil
}

func (l *testPacketLink) armTCPDelaySpike(releaseAfter int) {
	l.mu.Lock()
	l.tcpDelaySpike = testTCPDelaySpike{armed: true, releaseAfter: releaseAfter, seen: make(map[uint32]struct{})}
	l.mu.Unlock()
}

func (l *testPacketLink) tcpDelaySpikeStatus() (triggered, released bool, held int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tcpDelaySpike.triggered, l.tcpDelaySpike.released, l.tcpDelaySpike.heldRanges
}

func (l *testPacketLink) releaseTCPDelayOriginal() error {
	l.mu.Lock()
	packets := l.tcpDelaySpike.delayedOriginal
	l.tcpDelaySpike.delayedOriginal = nil
	l.mu.Unlock()
	for _, raw := range packets {
		packet, ok := parseIPPacket(raw, false)
		if ok {
			if err := l.handleTCP(packet); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *testPacketLink) handleTCPDelaySpike(raw []byte, packet ipPacket) (bool, error) {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize {
		return false, nil
	}
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize >= len(tcp) {
		return false, nil
	}
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	l.mu.Lock()
	delay := &l.tcpDelaySpike
	if !delay.armed || delay.released {
		l.mu.Unlock()
		return false, nil
	}
	if _, exists := delay.seen[sequence]; !exists {
		delay.seen[sequence] = struct{}{}
		delay.held = append(delay.held, append([]byte(nil), raw...))
		if !delay.haveFirst {
			delay.firstSequence, delay.haveFirst = sequence, true
		}
		l.mu.Unlock()
		return true, nil
	} else if sequence != delay.firstSequence {
		delay.repeated = append(delay.repeated, append([]byte(nil), raw...))
		l.mu.Unlock()
		return true, nil
	}
	delay.firstRetransmissions++
	if delay.firstRetransmissions < delay.releaseAfter {
		l.mu.Unlock()
		return true, nil
	}
	held := delay.held
	delay.heldRanges = len(held)
	delay.delayedOriginal = append(delay.delayedOriginal, held[0])
	delay.delayedOriginal = append(delay.delayedOriginal, delay.repeated...)
	delay.held, delay.repeated = nil, nil
	delay.triggered, delay.released = true, true
	l.mu.Unlock()

	if err := l.handleTCP(packet); err != nil {
		return true, err
	}
	for _, delayed := range held[1:] {
		original, ok := parseIPPacket(delayed, false)
		if ok {
			if err := l.handleTCP(original); err != nil {
				return true, err
			}
		}
	}
	return true, nil
}

func (l *testPacketLink) handleTCP(packet ipPacket) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize {
		return nil
	}
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return nil
	}
	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	serverPort := binary.BigEndian.Uint16(tcp[2:4])
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	flags := tcp[13]
	payload := append([]byte(nil), tcp[headerSize:]...)
	l.mu.Lock()
	if len(payload) > l.maximumTCPData {
		l.maximumTCPData = len(payload)
	}
	if packet.ecn == 2 {
		l.clientECTPackets++
	}
	if flags&TCPFlagECE != 0 {
		l.clientECEs++
	}
	if flags&TCPFlagCWR != 0 {
		l.clientCWRs++
	}
	peer := l.tcp[clientPort]
	if flags&TCPFlagSYN != 0 {
		if l.dropECNSYN && flags&(TCPFlagECE|TCPFlagCWR) == TCPFlagECE|TCPFlagCWR {
			l.dropECNSYN = false
			l.mu.Unlock()
			return nil
		}
		if flags&(TCPFlagECE|TCPFlagCWR) == 0 {
			l.legacySYNSends++
		}
		if l.dropTCPSYN > 0 {
			l.dropTCPSYN--
			l.mu.Unlock()
			return nil
		}
		peer = &testTCPPeer{
			serverNext: 0x10000000 + uint32(clientPort), clientNext: sequence + 1, highestClientEnd: sequence + 1,
			outOfOrder: make(map[uint32][]byte), dropped: make(map[uint32]time.Time), seenData: make(map[uint32]bool), timestamp: 1000,
		}
		if value, _, present := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize]); present {
			peer.clientTimestamp = value
			l.clientTimestamps++
		}
		l.tcp[clientPort] = peer
		serverSequence, acknowledgement := peer.serverNext, peer.clientNext
		peer.serverNext++
		l.mu.Unlock()
		options := []byte{2, 4, 0x05, 0x00, 4, 2, 1, 3, 3, 2}
		if l.disableTCPSACK {
			options = []byte{2, 4, 0x05, 0x00, 1, 3, 3, 2}
		}
		if l.disableTCPWindowScale {
			options = []byte{2, 4, 0x05, 0x00}
			if !l.disableTCPSACK {
				options = append(options, 4, 2)
			}
		}
		responseFlags := byte(TCPFlagSYN | TCPFlagACK)
		if l.ecnTCP && flags&TCPFlagECE != 0 && flags&TCPFlagCWR != 0 {
			responseFlags |= TCPFlagECE
		}
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, responseFlags, 65535, options, nil)
	}
	if peer == nil {
		l.mu.Unlock()
		return nil
	}
	if flags&TCPFlagRST != 0 {
		peer.resetSeen = true
		l.mu.Unlock()
		return nil
	}
	if hasTCPOption(tcp[tcpHeaderSize:headerSize], 5) {
		l.clientSACKs++
		if len(payload) != 0 {
			l.clientDataSACKs++
			if len(payload) > l.maximumTCPDataWithSACK {
				l.maximumTCPDataWithSACK = len(payload)
			}
		}
	}
	if value, _, present := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize]); present {
		peer.clientTimestamp = value
		l.clientTimestamps++
	}
	if flags&TCPFlagACK != 0 && len(payload) == 0 {
		l.clientACKs++
		if flags&TCPFlagSYN == 0 {
			l.lastClientWindow = binary.BigEndian.Uint16(tcp[14:16])
		}
	}
	if end := sequence + uint32(len(payload)); len(payload) != 0 && tcpSequenceGreater(end, peer.highestClientEnd) {
		peer.highestClientEnd = end
	}
	if len(payload) != 0 && l.tcpPathMTU != 0 {
		if !l.pathMTUInjected {
			l.pathMTUInjected = true
			mtu := l.tcpPathMTU
			quoted := append([]byte(nil), packet.original...)
			l.mu.Unlock()
			return writeTestPacket(l.stack, buildTestPacketTooBig(l.remote, l.local, quoted, mtu))
		}
		if len(packet.original) > l.postPathMTUMaximum {
			l.postPathMTUMaximum = len(packet.original)
		}
	}
	if len(payload) != 0 && l.dropTCPAbove != 0 && len(packet.original) > l.dropTCPAbove {
		peer.dropped[sequence] = time.Now()
		l.mu.Unlock()
		return nil
	}
	if len(payload) != 0 && !peer.seenData[sequence] {
		peer.seenData[sequence] = true
		peer.dataSegments++
		if l.dropTCPOrdinals[peer.dataSegments] {
			peer.dropped[sequence] = time.Now()
			l.mu.Unlock()
			return nil
		}
	} else if len(payload) != 0 && packet.ecn != 0 {
		l.clientRetransmittedECT++
	}
	if len(payload) != 0 && l.dropTCPData > 0 {
		l.dropTCPData--
		peer.dropped[sequence] = time.Now()
		l.mu.Unlock()
		return nil
	}
	if len(payload) != 0 && tcpSequenceGreater(sequence, peer.clientNext) {
		if _, exists := peer.outOfOrder[sequence]; !exists {
			peer.outOfOrder[sequence] = payload
		}
		acknowledgement := peer.clientNext
		serverSequence := peer.serverNext
		var options []byte
		if l.sackTCP {
			options = testSACKOptions(peer.outOfOrder)
		}
		l.mu.Unlock()
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, TCPFlagACK, 65535, options, nil)
	}
	if len(payload) != 0 && sequence == peer.clientNext {
		if !l.sackRenegingAt.IsZero() && l.sackRenegingDelay == 0 {
			l.sackRenegingDelay = time.Since(l.sackRenegingAt)
		}
		if droppedAt, retransmitted := peer.dropped[sequence]; retransmitted {
			delete(peer.dropped, sequence)
			if l.sackReneging && len(peer.outOfOrder) != 0 {
				peer.outOfOrder = make(map[uint32][]byte)
				l.sackReneging = false
				l.sackRenegingAt = time.Now()
			}
			if len(peer.outOfOrder) != 0 {
				l.sackRecovery = true
				l.sackRecoveries++
			} else {
				l.tailRetransmission = true
				l.tailRecoveryDelay = time.Since(droppedAt)
			}
		}
		peer.clientNext += uint32(len(payload))
		peer.pending = append(peer.pending, payload)
		peer.burst++
		for {
			part, exists := peer.outOfOrder[peer.clientNext]
			if !exists {
				break
			}
			delete(peer.outOfOrder, peer.clientNext)
			peer.clientNext += uint32(len(part))
			peer.pending = append(peer.pending, part)
			peer.burst++
		}
		if peer.burst > l.maximumTCPBurst {
			l.maximumTCPBurst = peer.burst
		}
	}
	if flags&TCPFlagFIN != 0 && sequence+uint32(len(payload)) == peer.clientNext {
		if l.dropTCPFIN > 0 {
			l.dropTCPFIN--
			l.mu.Unlock()
			return nil
		}
		peer.clientNext++
		acknowledgement := peer.clientNext
		serverSequence := peer.serverNext
		peer.finSent = true
		peer.serverNext++
		l.mu.Unlock()
		if err := l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, TCPFlagACK, 65535, nil, nil); err != nil {
			return err
		}
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, TCPFlagACK|TCPFlagFIN, 65535, nil, nil)
	}
	threshold := l.holdTCPACKs
	flush := len(peer.pending) != 0 && (threshold <= 1 || peer.burst >= threshold || flags&TCPFlagPSH != 0)
	if !flush {
		l.mu.Unlock()
		return nil
	}
	pending := peer.pending
	peer.pending = nil
	peer.burst = 0
	acknowledgement := peer.clientNext
	serverSequence := peer.serverNext
	window := uint16(65535)
	delay := l.delayTCPACK
	if l.partialTCPACK > 0 {
		pendingBytes := 0
		for _, part := range pending {
			pendingBytes += len(part)
		}
		if l.partialTCPACK < pendingBytes {
			acknowledgement -= uint32(pendingBytes - l.partialTCPACK)
		}
		l.partialTCPACK = 0
	}
	if l.useTCPWindow {
		window = l.advertisedTCPWindow
	}
	for _, part := range pending {
		peer.serverNext += uint32(len(part))
	}
	l.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	type responsePart struct {
		sequence uint32
		payload  []byte
	}
	responses := make([]responsePart, 0, len(pending))
	for _, part := range pending {
		responses = append(responses, responsePart{sequence: serverSequence, payload: part})
		serverSequence += uint32(len(part))
	}
	if l.reverseTCPResponses {
		for left, right := 0, len(responses)-1; left < right; left, right = left+1, right-1 {
			responses[left], responses[right] = responses[right], responses[left]
		}
	}
	for _, response := range responses {
		if err := l.deliverTCP(serverPort, clientPort, response.sequence, acknowledgement, TCPFlagACK|TCPFlagPSH, window, nil, response.payload); err != nil {
			return err
		}
	}
	return nil
}

func hasTCPOption(options []byte, kind byte) bool {
	parsed, err := (TCPSegment{Options: options}).HeaderOptions()
	if err != nil {
		return false
	}
	for _, option := range parsed {
		if option.Kind == kind {
			return true
		}
	}
	return false
}

func testSACKOptions(outOfOrder map[uint32][]byte) []byte {
	sequences := make([]uint32, 0, len(outOfOrder))
	for sequence := range outOfOrder {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(left, right int) bool { return sequences[left] < sequences[right] })
	if len(sequences) > 4 {
		sequences = sequences[len(sequences)-4:]
	}
	blocks := make([]TCPSACKBlock, len(sequences))
	for index, sequence := range sequences {
		blocks[index] = TCPSACKBlock{LeftEdge: sequence, RightEdge: sequence + uint32(len(outOfOrder[sequence]))}
	}
	var option TCPHeaderOption
	if err := option.SetSACKBlocks(blocks); err != nil {
		panic("mipstack: invalid SACK fixture: " + err.Error())
	}
	segment := TCPSegment{}
	if err := segment.SetHeaderOptions([]TCPHeaderOption{option}); err != nil {
		panic("mipstack: invalid TCP option fixture: " + err.Error())
	}
	return segment.Options
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}

func writeAndReadTCPEcho(t *testing.T, connection net.Conn, payload []byte) {
	t.Helper()
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("TCP Write = %d, %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("TCP echo = %q, want %q", response, payload)
	}
}

func (l *testPacketLink) deliverTCP(sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) error {
	l.mu.Lock()
	peer := l.tcp[targetPort]
	if l.timestampTCP && peer != nil {
		peer.timestamp++
		timestampOptions := tcpTimestampOptions(peer.timestamp, peer.clientTimestamp)
		combined := make([]byte, 0, len(timestampOptions)+len(options))
		combined = append(combined, timestampOptions...)
		combined = append(combined, options...)
		options = combined
	}
	markCE := l.markTCPCE && len(payload) != 0
	if markCE {
		l.markTCPCE = false
	}
	if l.sendTCPECE && flags&TCPFlagACK != 0 {
		flags |= TCPFlagECE
	}
	l.mu.Unlock()
	packet := buildTestTCP(l.remote, l.local, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload)
	if markCE {
		setPacketECN(packet, 3)
	}
	return writeTestPacket(l.stack, packet)
}

func writeTestPacket(stack *Stack, packet []byte) error {
	_, err := stack.Write([][]byte{packet}, 0)
	return err
}

func enqueueTCPTestSegment(t testing.TB, connection *TCPConn, segment tcpSegment) {
	t.Helper()
	if !connection.enqueueInbound(segment) {
		t.Fatal("test TCP segment exceeded the inbound queue")
	}
}

func wildcardUDP(address netip.Addr) netip.AddrPort {
	if address.Is6() {
		return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
}

func readOutboundPacket(t *testing.T, stack *Stack) []byte {
	t.Helper()
	if entry, ok := waitTestPacketEntry(&stack.outbound, time.Second); ok {
		return consumeTestPacket(&stack.outbound, entry)
	}
	t.Fatal("timed out waiting for outbound packet")
	return nil
}

func fillTestPacketQueue(t *testing.T, queue *packetQueue, packet []byte) {
	t.Helper()
	for queue.len() < cap(queue.free) {
		if !queue.tryEnqueue(packet) {
			t.Fatal("packet queue became full before its configured capacity")
		}
	}
}

func buildTestPacketTooBig(reporter, target netip.Addr, quoted []byte, mtu uint32) []byte {
	messageType, code, protocol := byte(ICMPv6TypePacketTooBig), byte(ICMPCodeNone), byte(ProtocolICMPv6)
	if reporter.Is4() {
		messageType, code, protocol = ICMPv4TypeDestinationUnreachable, ICMPv4DestinationUnreachableCodeFragmentationNeeded, ProtocolICMPv4
	}
	message, err := (ICMPError{Reporter: reporter, Type: messageType, Code: code, MTU: mtu, QuotedPacket: quoted}).ICMPMessage(target)
	if err != nil {
		panic("mipstack: invalid ICMP error fixture: " + err.Error())
	}
	icmp := mustTestWire(message.MarshalBinary())
	return buildIPPacket(reporter, target, protocol, icmp, 1, true)
}

func buildTestUDP(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) []byte {
	udp := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source, sourcePort), Destination: netip.AddrPortFrom(target, targetPort), Payload: payload,
	}).MarshalBinary())
	return buildIPPacket(source, target, ProtocolUDP, udp, 1, false)
}

func buildTestTCP(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) []byte {
	tcp := mustTestWire((TCPSegment{
		Source: netip.AddrPortFrom(source, sourcePort), Destination: netip.AddrPortFrom(target, targetPort),
		SequenceNumber: sequence, AcknowledgmentNumber: acknowledgement, Flags: uint16(flags), WindowSize: window,
		Options: options, Payload: payload,
	}).MarshalBinary())
	return buildIPPacket(source, target, ProtocolTCP, tcp, 1, true)
}

func buildTestIPv4Options(source, target netip.Addr, options []byte) []byte {
	udp := mustTestWire((UDPDatagram{
		Source: netip.AddrPortFrom(source, 1), Destination: netip.AddrPortFrom(target, 1), ChecksumDisabled: true,
	}).MarshalBinary())
	return mustTestWire((IPPacket{
		Source: source, Destination: target, Protocol: ProtocolUDP, HopLimit: 64, IPv4Options: options, Payload: udp,
	}).MarshalRawBinary())
}

func buildTestIPv6Extension(source, target netip.Addr, extensionType byte, extension []byte) []byte {
	return mustTestWire((IPPacket{
		Source: source, Destination: target, Protocol: int(extensionType), HopLimit: 64, Payload: extension,
	}).MarshalRawBinary())
}

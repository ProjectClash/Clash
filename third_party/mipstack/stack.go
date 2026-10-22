package mipstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dynamicPortFirst = 49152
	dynamicPortCount = 1 << 14
	fallbackPortFirst = 1024
	fallbackPortCount = dynamicPortFirst - fallbackPortFirst
	defaultMTU = 1500
	ipv6MinimumMTU = 1280
	outboundPacketQueue = 256
	loopbackPacketQueue = 256
	packetReusableBufferLimit = 2048
	largePacketBufferSlack = (outboundPacketQueue - deviceBatchSize) * packetReusableBufferLimit
	pathMTUMaximumEntries = 1024
	pathMTULifetime = 10 * time.Minute
	controlResponseRate = 100
	controlResponseBurst = 200
	icmpErrorTargetRate = controlResponseRate / 4
	icmpErrorTargetBurst = controlResponseBurst / 4
	icmpErrorTargetEntries = 64
	icmpErrorTargetOverflowBuckets = 8
	icmpErrorTargetIdle = time.Minute
	icmpErrorReserveGroups = 2
	icmpErrorReserveBuckets = 16
	icmpErrorReserveRate = icmpErrorTargetRate
	icmpErrorReserveBurst = icmpErrorReserveGroups * icmpErrorReserveBuckets
	icmpErrorReserveInterval = time.Second * icmpErrorReserveBurst / icmpErrorReserveRate
	icmpErrorAggregateBurst = controlResponseBurst - icmpErrorReserveBurst
	recentDestinationMaximum = 256
	recentDestinationLifetime = 2 * time.Minute
	datagramQueueRetain = 4
	datagramReusablePayloadLimit = 2048
)

var (
	ErrClosed = net.ErrClosed
	ErrNotStarted = errors.New("mipstack: stack is not started")
	ErrNoPorts = errors.New("mipstack: no automatic ports available")
	ErrResourceLimit = errors.New("mipstack: resource limit reached")
	ErrForwarderRequestCompleted = errors.New("mipstack: forwarder request is already completed")
)

type TCPSocketDefaults struct {
	CongestionControl string
	CongestionControlFactory *CongestionControlFactory
	ReceiveBuffer int
	MaximumReceiveBuffer int
	SendBuffer int
	MaximumSendBuffer int
	MaximumPacingRate uint64
	AcceptQueue int
	SYNBacklog int
	KeepAlive bool
	KeepAliveConfig KeepAliveConfig
	IdleTimeout time.Duration
	UserTimeout time.Duration
	DisableNoDelay bool
	TrafficClass uint8
	FlowLabel uint32
}

type PathMTUDiscovery int

const (
	PathMTUDiscoveryDont PathMTUDiscovery = iota
	PathMTUDiscoveryWant
	PathMTUDiscoveryDo
	PathMTUDiscoveryProbe
	PathMTUDiscoveryInterface
	PathMTUDiscoveryOmit
)

func (mode PathMTUDiscovery) valid() bool {
	return mode >= PathMTUDiscoveryDont && mode <= PathMTUDiscoveryOmit
}

type SocketMessage struct {
	Buffers [][]byte
	OOB []byte
	Addr net.Addr
	N int
	NN int
	Flags int
}

const (
	MessageFlagPeek = 0x02
	MessageFlagControlTruncated = 0x08
	MessageFlagTruncated = 0x20
	MessageFlagDontWait = 0x40
	MessageFlagErrorQueue = 0x2000
)

type DatagramSocketDefaults struct {
	ReceiveBuffer int
	ReceiveErrors bool
	PathMTUDiscovery PathMTUDiscovery
	HopLimit int
	MulticastHopLimit int
	DisableMulticastLoopback bool
	DisableBroadcast bool
	TrafficClass uint8
	FlowLabel uint32
}

type UDPSocketDefaults struct {
	DatagramSocketDefaults
}

type IPSocketDefaults struct {
	DatagramSocketDefaults

	IPHeaderIncludedOnWrite bool
	IPHeaderIncludedOnRead bool
}

type Config struct {
	LocalAddresses []netip.Prefix
	AddressProperties map[netip.Addr]AddressProperties
	PreferTemporaryAddresses bool
	Promiscuous bool
	MTU uint32
	Routes []Route
	MaxTCPConnections int
	TCP TCPSocketDefaults
	UDP UDPSocketDefaults
	IP IPSocketDefaults
}

type Stack struct {
	network  atomic.Pointer[networkState]
	outbound packetQueue
	loopback loopbackQueue
	largeBuffers atomic.Pointer[largePacketBufferCache]

	mu      sync.RWMutex
	started bool
	closed  bool
	rxChecksumOffload atomic.Uint32
	tcp               map[tcpKey]*TCPConn
	tcpPassive        tcpPassiveEndpoints
	tcpForwarder      tcpForwarderEndpoints
	udp               map[udpKey]*UDPConn
	udpReuse          udpReuseEndpoints
	udpForwarded      map[udpFlowKey]*UDPConn
	udpForwarder      udpForwarderEndpoints
	ip                ipEndpoints
	ipForwarder       ipForwarderEndpoints
	multicast         multicastEndpoints
	multicastSeed     *multicastQuerierSeed
	icmpForwarder     icmpForwarderEndpoints
	nextPort          [2]automaticPortCursor

	tcpTimeWaitReplacer tcpTimeWaitReplacer

	pathMTUMu sync.RWMutex
	pathMTU   map[netip.Addr]pathMTUEntry

	ipv4ID                 atomic.Uint32
	ipv6FragmentID         atomic.Uint32
	nextOutputFlow         atomic.Uint64
	closeCh                chan struct{}
	timestampEpoch         time.Time
	tcpISNSecret           [16]byte
	flowLabelSecret        [16]byte
	icmpErrorLimiterSecret [16]byte

	fragmentMu    sync.Mutex
	fragments     map[fragmentKey]*ipPacketReassemblyEntry
	fragmentBytes int
	fragmentWake  chan struct{}

	controlMu       sync.Mutex
	controlLimiters [controlResponseClassCount]tokenBucket
	icmpErrorLimiters *icmpErrorLimiterState
	stats             stackCounters
}

type inboundDestinationClass uint8

const (
	inboundDestinationRejected inboundDestinationClass = iota
	inboundDestinationLocalUnicast
	inboundDestinationBroadcast
	inboundDestinationMulticast
	inboundDestinationPromiscuousUnicast
)

type StackStats struct {
	InboundPackets uint64
	InboundDroppedPackets uint64
	InvalidIPPackets uint64
	UnacceptedIPPackets uint64
	NonlocalDestinationPackets uint64
	PromiscuousInboundPackets uint64
	InvalidSourcePackets uint64
	OutboundPackets uint64
	OutboundQueueDrops uint64
	LoopbackPackets uint64
	LoopbackQueueDrops uint64
	ActiveTCPConnections uint64
	ActiveTCPListeners uint64
	ActiveUDPSockets uint64
	ActiveIPSockets uint64
	TCPRetransmissions uint64
	TCPInboundQueueDrops uint64
	TCPInvalidSegments uint64
	TCPSACKRetransmissions uint64
	TCPRACKRetransmissions uint64
	TCPTailLossProbes uint64
	TCPSpuriousRecoveryUndos uint64
	TCPZeroWindowProbes uint64
	TCPKeepAliveProbes uint64
	TCPSYNCookiesSent uint64
	TCPSYNCookiesAccepted uint64
	TCPSYNCookiesRejected uint64
	TCPHandshakeTimeouts uint64
	TCPAcceptQueueDrops uint64
	PathMTUUpdates uint64
	PathMTUProbes uint64
	PathMTUProbeSuccesses uint64
	PathMTUProbeFailures uint64
	PathMTUBlackHoleReductions uint64
	FragmentEvictions uint64
	FragmentTimeouts uint64
	RateLimitedControlResponses uint64
}

type stackCounters struct {
	inboundPackets              atomic.Uint64
	inboundDroppedPackets       atomic.Uint64
	invalidIPPackets            atomic.Uint64
	unacceptedIPPackets         atomic.Uint64
	nonlocalDestinationPackets  atomic.Uint64
	promiscuousInboundPackets   atomic.Uint64
	invalidSourcePackets        atomic.Uint64
	outboundPackets             atomic.Uint64
	loopbackPackets             atomic.Uint64
	activeTCPConnections        atomic.Uint64
	activeTCPListeners          atomic.Uint64
	activeUDPSockets            atomic.Uint64
	activeIPSockets             atomic.Uint64
	tcpRetransmissions          atomic.Uint64
	tcpInboundQueueDrops        atomic.Uint64
	tcpInvalidSegments          atomic.Uint64
	tcpSACKRetransmissions      atomic.Uint64
	tcpRACKRetransmissions      atomic.Uint64
	tcpTailLossProbes           atomic.Uint64
	tcpSpuriousRecoveryUndos    atomic.Uint64
	tcpZeroWindowProbes         atomic.Uint64
	tcpKeepAliveProbes          atomic.Uint64
	tcpSYNCookiesSent           atomic.Uint64
	tcpSYNCookiesAccepted       atomic.Uint64
	tcpSYNCookiesRejected       atomic.Uint64
	tcpHandshakeTimeouts        atomic.Uint64
	tcpAcceptQueueDrops         atomic.Uint64
	pathMTUUpdates              atomic.Uint64
	pathMTUProbes               atomic.Uint64
	pathMTUProbeSuccesses       atomic.Uint64
	pathMTUProbeFailures        atomic.Uint64
	pathMTUBlackHoleReductions  atomic.Uint64
	fragmentEvictions           atomic.Uint64
	fragmentTimeouts            atomic.Uint64
	rateLimitedControlResponses atomic.Uint64
	outboundQueueDrops          atomic.Uint64
	loopbackQueueDrops          atomic.Uint64
}

type controlResponseClass uint8

const (
	controlResponseTCPReset controlResponseClass = iota
	controlResponseTCPChallengeACK
	controlResponseEchoReply
	controlResponseClassCount
)

type icmpErrorResponseClass uint8

const (
	icmpErrorResponsePortUnreachable icmpErrorResponseClass = iota
	icmpErrorResponseParameterProblem
	icmpErrorResponseFragmentTimeout
	icmpErrorResponseClassCount
)

type tokenBucket struct {
	tokens  float64
	updated time.Time
}

func (b *tokenBucket) refill(now time.Time, rate, burst float64) {
	if b.updated.IsZero() {
		b.tokens = burst
	} else {
		b.tokens += now.Sub(b.updated).Seconds() * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.updated = now
}

type icmpErrorTargetEntry struct {
	destination netip.Addr
	bucket      tokenBucket
}

type icmpErrorReserveSlot struct {
	availableAt monotonicStamp
	ownerHash   uint64
}

type icmpErrorLimiterTable struct {
	aggregate tokenBucket
	reserveAggregate tokenBucket
	entries          [icmpErrorTargetEntries]icmpErrorTargetEntry
	overflow         [icmpErrorTargetOverflowBuckets]tokenBucket
	reserve          [icmpErrorReserveGroups][icmpErrorReserveBuckets]icmpErrorReserveSlot
}

type icmpErrorLimiterState struct {
	tables [icmpErrorResponseClassCount]*icmpErrorLimiterTable
}

type pathMTUEntry struct {
	mtu     int
	updated time.Time
}

type recentDestinationCache[T comparable] struct {
	state *recentDestinationCacheState[T]
}

type recentDestinationCacheState[T comparable] struct {
	first        T
	firstUpdated monotonicStamp
	entries      map[T]monotonicStamp
}

func (c *recentDestinationCache[T]) remember(destination T, now monotonicStamp) {
	if c.state == nil {
		c.state = &recentDestinationCacheState[T]{first: destination, firstUpdated: now}
		return
	}
	state := c.state
	if state.entries == nil {
		if state.first == destination {
			state.firstUpdated = now
			return
		}
		state.entries = make(map[T]monotonicStamp, 2)
		state.entries[state.first] = state.firstUpdated
		state.entries[destination] = now
		var zero T
		state.first = zero
		state.firstUpdated = 0
		return
	}
	cache := state.entries
	if _, exists := cache[destination]; exists {
		cache[destination] = now
		return
	}
	if len(cache) >= recentDestinationMaximum {
		var oldest T
		var oldestStamp monotonicStamp
		haveOldest := false
		for candidate, candidateStamp := range cache {
			if recentDestinationExpired(candidateStamp, now) {
				delete(cache, candidate)
				continue
			}
			if !haveOldest || candidateStamp < oldestStamp {
				oldest, oldestStamp, haveOldest = candidate, candidateStamp, true
			}
		}
		if len(cache) >= recentDestinationMaximum && haveOldest {
			delete(cache, oldest)
		}
	}
	cache[destination] = now
}

func (c *recentDestinationCache[T]) contains(destination T, now monotonicStamp) bool {
	if c.state == nil {
		return false
	}
	state := c.state
	if state.entries == nil {
		if state.first != destination {
			return false
		}
		if recentDestinationExpired(state.firstUpdated, now) {
			c.state = nil
			return false
		}
		return true
	}
	updated, exists := state.entries[destination]
	if exists && recentDestinationExpired(updated, now) {
		delete(state.entries, destination)
		return false
	}
	return exists
}

func recentDestinationExpired(updated, now monotonicStamp) bool {
	return now >= updated && now-updated >= monotonicStamp(recentDestinationLifetime)
}

type datagramQueue[T any] struct {
	values []T
	head   int
}

const socketErrorMetadataSize = 192

type queuedSocketError struct {
	err     *net.OpError
	payload []byte
	size    int
}

type datagramSocketErrorState struct {
	queue       datagramQueue[queuedSocketError]
	queuedBytes int
	lastError   *net.OpError
	pending    *net.OpError
	icmpErrors uint64
	dropped    uint64
}

func (s *datagramSocketErrorState) len() int {
	if s == nil {
		return 0
	}
	return s.queue.len()
}

func (s *datagramSocketErrorState) bytes() int {
	if s == nil {
		return 0
	}
	return s.queuedBytes
}

func (s *datagramSocketErrorState) push(queued queuedSocketError) {
	s.queue.push(queued)
	s.queuedBytes += queued.size
}

func (s *datagramSocketErrorState) pop() (queuedSocketError, bool) {
	if s == nil {
		return queuedSocketError{}, false
	}
	queued, ok := s.queue.pop()
	if ok {
		s.queuedBytes -= queued.size
		s.rearmPending()
	}
	return queued, ok
}

func (s *datagramSocketErrorState) takePending() *net.OpError {
	if s == nil {
		return nil
	}
	pending := s.pending
	if pending != nil {
		s.pending = nil
	}
	return pending
}

func (s *datagramSocketErrorState) rearmPending() {
	if next, ok := s.queue.peek(); ok {
		s.pending = next.err
	} else {
		s.pending = nil
	}
}

func (s *datagramSocketErrorState) readMessage(message *SocketMessage) (bool, error) {
	if s == nil {
		return false, nil
	}
	size, ok, err := readSocketErrorMessage(&s.queue, message)
	if ok && err == nil {
		s.queuedBytes -= size
		s.rearmPending()
	}
	return ok, err
}

func (s *datagramSocketErrorState) purgeQueue() {
	if s == nil {
		return
	}
	s.queue.clear()
	s.queuedBytes = 0
}

func (s *datagramSocketErrorState) releaseRetained() {
	if s == nil {
		return
	}
	s.purgeQueue()
	s.lastError = nil
	s.pending = nil
}

func socketErrorSize(err error) int {
	size := socketErrorMetadataSize
	var networkError ICMPError
	if errors.As(err, &networkError) {
		if len(networkError.QuotedPacket) != 0 {
			size += len(networkError.QuotedPacket)
		} else {
			size += len(networkError.QuotedPayload)
		}
		size += len(networkError.Extensions)
	}
	return size
}

func messageBufferLength(buffers [][]byte) (int, error) {
	total := 0
	maximum := int(^uint(0) >> 1)
	for _, buffer := range buffers {
		if len(buffer) > maximum-total {
			return 0, syscall.EMSGSIZE
		}
		total += len(buffer)
	}
	if total == 0 {
		return 0, syscall.EINVAL
	}
	return total, nil
}

func copyMessagePayload(buffers [][]byte, payload []byte) int {
	written := 0
	for _, buffer := range buffers {
		if len(payload) == 0 {
			break
		}
		n := copy(buffer, payload)
		written += n
		payload = payload[n:]
	}
	return written
}

func copyMessageBuffers(destination []byte, buffers [][]byte) int {
	written := 0
	for _, buffer := range buffers {
		written += copy(destination[written:], buffer)
		if written == len(destination) {
			break
		}
	}
	return written
}

func copyLinuxControlMessages(destination, control []byte) (int, bool) {
	if len(destination) >= len(control) {
		return copy(destination, control), false
	}
	written := 0
	for len(control) != 0 {
		remaining := len(destination) - written
		if remaining < linuxControlHeaderSize {
			return written, true
		}
		if len(control) < linuxControlHeaderSize {
			copy(destination[written:], control[:remaining])
			return len(destination), true
		}
		length64 := binary.LittleEndian.Uint64(control[:8])
		if length64 < linuxControlHeaderSize || length64 > uint64(len(control)) {
			copy(destination[written:], control[:remaining])
			return len(destination), true
		}
		length := int(length64)
		space := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		if space > len(control) {
			space = len(control)
		}
		copyLength := space
		if copyLength > remaining {
			copyLength = remaining
		}
		copy(destination[written:written+copyLength], control[:copyLength])
		if copyLength < length {
			binary.LittleEndian.PutUint64(destination[written:written+8], uint64(copyLength))
			return written + copyLength, true
		}
		written += copyLength
		if copyLength < space {
			return written, len(control) > space
		}
		control = control[space:]
		if len(control) != 0 && written == len(destination) {
			return written, true
		}
	}
	return written, false
}

func gatherMessagePayload(buffers [][]byte, maximum int) ([]byte, error) {
	size, err := messageBufferLength(buffers)
	if err != nil {
		return nil, err
	}
	if size > maximum {
		return nil, syscall.EMSGSIZE
	}
	if len(buffers) == 1 {
		return buffers[0], nil
	}
	payload := make([]byte, size)
	offset := 0
	for _, buffer := range buffers {
		offset += copy(payload[offset:], buffer)
	}
	return payload, nil
}

func fillSocketErrorMessage(message *SocketMessage, queued queuedSocketError) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return err
	}
	control, err := socketErrorControlForRead(queued.err)
	if err != nil {
		return err
	}
	copied := copyMessagePayload(message.Buffers, queued.payload)
	n := copied
	flags := MessageFlagErrorQueue
	if copied < len(queued.payload) {
		flags |= MessageFlagTruncated
	}
	oobn, controlTruncated := copyLinuxControlMessages(message.OOB, control)
	if controlTruncated {
		flags |= MessageFlagControlTruncated
	}
	message.N, message.NN, message.Flags, message.Addr = n, oobn, flags, queued.err.Addr
	return nil
}

func readSocketErrorMessage(queue *datagramQueue[queuedSocketError], message *SocketMessage) (size int, ok bool, err error) {
	queued, ok := queue.peek()
	if !ok {
		return 0, false, nil
	}
	if err := fillSocketErrorMessage(message, queued); err != nil {
		return 0, true, err
	}
	consumed, popped := queue.pop()
	if !popped {
		panic("mipstack: socket error queue changed while locked")
	}
	return consumed.size, true, nil
}

func (q *datagramQueue[T]) len() int { return len(q.values) - q.head }

func (q *datagramQueue[T]) push(value T) {
	if q.head != 0 && len(q.values) == cap(q.values) {
		copy(q.values, q.values[q.head:])
		remaining := len(q.values) - q.head
		var zero T
		for index := remaining; index < len(q.values); index++ {
			q.values[index] = zero
		}
		q.values = q.values[:remaining]
		q.head = 0
	}
	q.values = append(q.values, value)
}

func (q *datagramQueue[T]) peek() (T, bool) {
	var zero T
	if q.head == len(q.values) {
		return zero, false
	}
	return q.values[q.head], true
}

func (q *datagramQueue[T]) pop() (T, bool) {
	var zero T
	if q.head == len(q.values) {
		return zero, false
	}
	value := q.values[q.head]
	q.values[q.head] = zero
	q.head++
	if q.head == len(q.values) {
		if cap(q.values) <= datagramQueueRetain {
			q.values = q.values[:0]
		} else {
			q.values = nil
		}
		q.head = 0
	}
	return value, true
}

func (q *datagramQueue[T]) clear() {
	var zero T
	for index := range q.values {
		q.values[index] = zero
	}
	q.values = nil
	q.head = 0
}

type udpKey struct {
	address netip.Addr
	port    uint16
}

type udpFlowKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

type tcpKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

type automaticPortCursor struct {
	dynamic      uint16
	fallback     uint16
	dynamicStep  uint16
	fallbackStep uint16
	secret       [16]byte
}

const (
	outputFlowDetached = iota
	outputFlowNew
	outputFlowOld
	outputFlowOldDue
	outputFlowUnused
)

const outputFlowRefillDelay = 40 * time.Millisecond

type outputPacketNode struct {
	entry packetQueueEntry
	next  int
}

type outputFlow struct {
	key        outputFlowKey
	head       int
	tail       int
	credit     int
	state      uint8
	previous   *outputFlow
	next       *outputFlow
	detachedAt time.Time
}

type outputFlowKey struct {
	tcp  uint64
	hash uint64
}

type outputFlowList struct {
	first *outputFlow
	last  *outputFlow
}

func (l *outputFlowList) append(flow *outputFlow) {
	flow.previous = l.last
	flow.next = nil
	if l.last == nil {
		l.first = flow
	} else {
		l.last.next = flow
	}
	l.last = flow
}

func (l *outputFlowList) remove(flow *outputFlow) {
	if flow.previous == nil {
		l.first = flow.next
	} else {
		flow.previous.next = flow.next
	}
	if flow.next == nil {
		l.last = flow.previous
	} else {
		flow.next.previous = flow.previous
	}
	flow.previous, flow.next = nil, nil
}

type fairPacketScheduler struct {
	mu sync.Mutex

	ready chan struct{}
	nodes []outputPacketNode
	flows map[outputFlowKey]*outputFlow
	store []outputFlow
	free  *outputFlow

	newFlows outputFlowList
	oldFlows outputFlowList
	detached outputFlowList
	queued   int
	quantum  int
	initial  int
	secret   [16]byte
	lastFlow *outputFlow
}

func newFairPacketScheduler(capacity, mtu int, secret [16]byte) *fairPacketScheduler {
	if mtu < 1 {
		mtu = defaultMTU
	}
	scheduler := &fairPacketScheduler{
		ready:  make(chan struct{}, 1),
		nodes:  make([]outputPacketNode, capacity),
		flows:  make(map[outputFlowKey]*outputFlow, capacity),
		store:  make([]outputFlow, capacity),
		secret: secret,
	}
	scheduler.setMTULocked(mtu)
	for index := len(scheduler.store) - 1; index >= 0; index-- {
		flow := &scheduler.store[index]
		flow.state = outputFlowUnused
		flow.next = scheduler.free
		scheduler.free = flow
	}
	return scheduler
}

func (s *fairPacketScheduler) setMTU(mtu int) {
	if mtu < 1 {
		mtu = defaultMTU
	}
	s.mu.Lock()
	s.setMTULocked(mtu)
	s.mu.Unlock()
}

func (s *fairPacketScheduler) setMTULocked(mtu int) {
	s.quantum = 2 * mtu
	s.initial = 10 * mtu
}

func (s *fairPacketScheduler) signal() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

func (s *fairPacketScheduler) acquireFlow(key outputFlowKey) *outputFlow {
	if s.free == nil {
		for flow := s.oldFlows.first; flow != nil && s.detached.first == nil; flow = flow.next {
			if flow.head < 0 {
				s.oldFlows.remove(flow)
				s.detachFlow(flow)
				break
			}
		}
		flow := s.detached.first
		if flow == nil {
			panic("mipstack: output flow capacity invariant violated")
		}
		s.detached.remove(flow)
		delete(s.flows, flow.key)
		if s.lastFlow == flow {
			s.lastFlow = nil
		}
		flow.state = outputFlowUnused
		flow.next = s.free
		s.free = flow
	}
	flow := s.free
	s.free = flow.next
	*flow = outputFlow{key: key, head: -1, tail: -1, credit: s.initial, state: outputFlowNew}
	s.flows[key] = flow
	s.newFlows.append(flow)
	return flow
}

func (s *fairPacketScheduler) reactivateFlow(flow *outputFlow) {
	s.detached.remove(flow)
	if time.Since(flow.detachedAt) >= outputFlowRefillDelay && flow.credit < s.quantum {
		flow.credit = s.quantum
	}
	flow.state = outputFlowNew
	flow.detachedAt = time.Time{}
	s.newFlows.append(flow)
}

func (s *fairPacketScheduler) enqueue(entry packetQueueEntry, key outputFlowKey) {
	if key == (outputFlowKey{}) {
		key = outputHashedFlowKey(outputPacketFlowHash(s.secret, entry.packet))
	}
	s.mu.Lock()
	flow := s.lastFlow
	if flow == nil || flow.key != key || flow.state == outputFlowUnused {
		flow = s.flows[key]
	}
	if flow == nil {
		flow = s.acquireFlow(key)
	} else if flow.state == outputFlowDetached {
		s.reactivateFlow(flow)
	}
	s.lastFlow = flow
	node := &s.nodes[entry.slot]
	node.entry, node.next = entry, -1
	if flow.tail < 0 {
		flow.head = int(entry.slot)
	} else {
		s.nodes[flow.tail].next = int(entry.slot)
	}
	flow.tail = int(entry.slot)
	s.queued++
	if s.queued == 1 {
		s.signal()
	}
	s.mu.Unlock()
}

func (s *fairPacketScheduler) detachFlow(flow *outputFlow) {
	flow.state = outputFlowDetached
	flow.detachedAt = time.Now()
	s.detached.append(flow)
}

func (s *fairPacketScheduler) scheduleOldFlowTurn() {
	for s.oldFlows.first != nil {
		flow := s.oldFlows.first
		if flow.head < 0 {
			s.oldFlows.remove(flow)
			s.detachFlow(flow)
			continue
		}
		if flow.credit <= 0 {
			flow.credit += s.quantum
			s.oldFlows.remove(flow)
			s.oldFlows.append(flow)
			continue
		}
		s.oldFlows.remove(flow)
		flow.state = outputFlowOldDue
		s.newFlows.append(flow)
		return
	}
}

func (s *fairPacketScheduler) demoteNewFlow(flow *outputFlow) {
	s.newFlows.remove(flow)
	if s.oldFlows.first != nil {
		s.scheduleOldFlowTurn()
	}
	flow.state = outputFlowOld
	s.oldFlows.append(flow)
}

func (s *fairPacketScheduler) removeHead(flow *outputFlow) packetQueueEntry {
	slot := flow.head
	node := &s.nodes[slot]
	flow.head = node.next
	if flow.head < 0 {
		flow.tail = -1
	}
	entry := node.entry
	node.entry, node.next = packetQueueEntry{}, -1
	s.queued--
	return entry
}

func (s *fairPacketScheduler) dropFromFattestFlow() (packetQueueEntry, bool) {
	s.mu.Lock()
	var fattest *outputFlow
	largestBacklog := 0
	for index := range s.store {
		flow := &s.store[index]
		if flow.state == outputFlowUnused || flow.head < 0 {
			continue
		}
		backlog := 0
		for slot := flow.head; slot >= 0; slot = s.nodes[slot].next {
			backlog += len(s.nodes[slot].entry.packet)
		}
		if fattest == nil || backlog > largestBacklog {
			fattest = flow
			largestBacklog = backlog
		}
	}
	if fattest == nil {
		s.mu.Unlock()
		return packetQueueEntry{}, false
	}
	entry := s.removeHead(fattest)
	if fattest.head < 0 {
		switch fattest.state {
		case outputFlowNew:
			s.newFlows.remove(fattest)
			fattest.state = outputFlowOld
			s.oldFlows.append(fattest)
		case outputFlowOldDue:
			s.newFlows.remove(fattest)
			s.detachFlow(fattest)
		default:
			s.oldFlows.remove(fattest)
			s.detachFlow(fattest)
		}
	}
	s.mu.Unlock()
	return entry, true
}

func (s *fairPacketScheduler) selectList() *outputFlowList {
	if s.newFlows.first != nil {
		return &s.newFlows
	}
	if s.oldFlows.first != nil {
		return &s.oldFlows
	}
	return nil
}

func (s *fairPacketScheduler) tryDequeue() (packetQueueEntry, bool) {
	return s.tryDequeueAndSignal(false)
}

func (s *fairPacketScheduler) tryDequeueAndSignal(signalRemaining bool) (packetQueueEntry, bool) {
	s.mu.Lock()
	for s.queued != 0 {
		list := s.selectList()
		if list == nil {
			s.mu.Unlock()
			return packetQueueEntry{}, false
		}
		flow := list.first
		state := flow.state
		if flow.head < 0 {
			if state == outputFlowNew {
				s.demoteNewFlow(flow)
			} else {
				list.remove(flow)
				s.detachFlow(flow)
			}
			continue
		}
		if flow.credit <= 0 {
			flow.credit += s.quantum
			if state == outputFlowOldDue {
				continue
			}
			if state == outputFlowNew {
				s.demoteNewFlow(flow)
			} else {
				list.remove(flow)
				s.oldFlows.append(flow)
			}
			continue
		}
		entry := s.removeHead(flow)
		flow.credit -= len(entry.packet)
		if state == outputFlowOldDue && flow.head < 0 {
			list.remove(flow)
			s.detachFlow(flow)
		} else if state == outputFlowOldDue && flow.credit <= 0 {
			flow.credit += s.quantum
			list.remove(flow)
			flow.state = outputFlowOld
			s.oldFlows.append(flow)
		} else if flow.head < 0 {
			if state == outputFlowNew {
				s.demoteNewFlow(flow)
			} else {
				list.remove(flow)
				s.detachFlow(flow)
			}
		} else if flow.credit <= 0 {
			flow.credit += s.quantum
			if state == outputFlowNew {
				s.demoteNewFlow(flow)
			} else {
				list.remove(flow)
				s.oldFlows.append(flow)
			}
		}
		if signalRemaining && s.queued != 0 {
			s.signal()
		}
		s.mu.Unlock()
		return entry, true
	}
	s.mu.Unlock()
	return packetQueueEntry{}, false
}

func (s *fairPacketScheduler) dequeue(closeCh <-chan struct{}) (packetQueueEntry, bool) {
	for {
		if entry, ok := s.tryDequeueAndSignal(true); ok {
			return entry, true
		}
		select {
		case <-s.ready:
		case <-closeCh:
			return packetQueueEntry{}, false
		}
	}
}

func (s *fairPacketScheduler) len() int {
	s.mu.Lock()
	queued := s.queued
	s.mu.Unlock()
	return queued
}

func outputHashWord(hash, value uint64) uint64 {
	hash ^= bits.RotateLeft64(value+0x9e3779b97f4a7c15, 23)
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 29
	return hash
}

var outputICMPIdentifierProtocol = [256]byte{
	ICMPv4TypeEchoReply:   ProtocolICMPv4,
	ICMPv4TypeEchoRequest: ProtocolICMPv4,
	13:                    ProtocolICMPv4,
	14:                    ProtocolICMPv4,
	ICMPv6TypeEchoRequest: ProtocolICMPv6,
	ICMPv6TypeEchoReply:   ProtocolICMPv6,
}

func outputTransportSelector(protocol byte, payload []byte) uint32 {
	if protocol == ProtocolTCP || protocol == ProtocolUDP {
		if len(payload) >= 4 {
			return binary.BigEndian.Uint32(payload)
		}
		return 0
	}
	if len(payload) < 2 || protocol != ProtocolICMPv4 && protocol != ProtocolICMPv6 {
		return 0
	}
	selector := uint32(payload[0])<<24 | uint32(payload[1])<<16
	if len(payload) >= 6 && outputICMPIdentifierProtocol[payload[0]] == protocol {
		selector |= uint32(payload[4])<<8 | uint32(payload[5])
	}
	return selector
}

func outputTransportFlowWord(protocol byte, selector uint32) uint64 {
	return uint64(protocol)<<32 | uint64(selector)
}

func outputFragmentFlowWord(protocol byte, identification uint32) uint64 {
	return uint64(1)<<63 | uint64(protocol)<<32 | uint64(identification)
}

func outputPacketFlowHash(secret [16]byte, packet []byte) uint64 {
	hash := binary.LittleEndian.Uint64(secret[0:8]) ^ 0x6a09e667f3bcc909
	seed := binary.LittleEndian.Uint64(secret[8:16])
	if len(packet) == 0 {
		return outputHashWord(hash, seed)
	}
	version := packet[0] >> 4
	hash = outputHashWord(hash, uint64(version)^seed)
	switch version {
	case 4:
		if len(packet) < 20 {
			for index, value := range packet {
				hash = outputHashWord(hash, uint64(value)<<uint((index&7)*8))
			}
			return hash
		}
		addresses := binary.BigEndian.Uint64(packet[12:20])
		hash = outputHashWord(hash, addresses)
		protocol := packet[9]
		headerSize := int(packet[0]&0x0f) * 4
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if fragment&0x3fff != 0 {
			identification := uint32(binary.BigEndian.Uint16(packet[4:6]))
			hash = outputHashWord(hash, outputFragmentFlowWord(protocol, identification))
		} else {
			var selector uint32
			if headerSize >= 20 && headerSize < len(packet) {
				selector = outputTransportSelector(protocol, packet[headerSize:])
			}
			hash = outputHashWord(hash, outputTransportFlowWord(protocol, selector))
		}
	case 6:
		if len(packet) < 40 {
			for index, value := range packet {
				hash = outputHashWord(hash, uint64(value)<<uint((index&7)*8))
			}
			return hash
		}
		for offset := 8; offset < 40; offset += 8 {
			hash = outputHashWord(hash, binary.BigEndian.Uint64(packet[offset:offset+8]))
		}
		flowLabel := uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4]))
		if flowLabel != 0 {
			return outputHashWord(hash, uint64(flowLabel))
		}
		protocol := packet[6]
		if isTraversableIPv6ExtensionHeader(protocol) {
			if extensionHash, valid := outputIPv6ExtensionPacketFlowHash(hash, packet); valid {
				return extensionHash
			}
		}
		var selector uint32
		if len(packet) > 40 {
			selector = outputTransportSelector(protocol, packet[40:])
		}
		hash = outputHashWord(hash, outputTransportFlowWord(protocol, selector))
	default:
		limit := len(packet)
		if limit > 40 {
			limit = 40
		}
		for offset := 0; offset < limit; offset++ {
			hash = outputHashWord(hash, uint64(packet[offset])<<uint((offset&7)*8))
		}
	}
	return hash
}

func outputIPv6ExtensionPacketFlowHash(hash uint64, packet []byte) (uint64, bool) {
	next, offset := packet[6], 40
	for isTraversableIPv6ExtensionHeader(next) {
		headerType := next
		length, valid := ipv6ExtensionHeaderLength(headerType, packet[offset:])
		if !valid {
			return 0, false
		}
		header := packet[offset : offset+length]
		if headerType == IPv6ExtensionHeaderFragment {
			field := binary.BigEndian.Uint16(header[2:4])
			if field&0x0006 != 0 {
				return 0, false
			}
			if field&0xfff9 != 0 {
				word := outputFragmentFlowWord(header[0], binary.BigEndian.Uint32(header[4:8]))
				return outputHashWord(hash, word), true
			}
		}
		next, offset = header[0], offset+length
	}
	selector := outputTransportSelector(next, packet[offset:])
	return outputHashWord(hash, outputTransportFlowWord(next, selector)), true
}

func outputIPFlowHash(secret [16]byte, source, target netip.Addr, protocol byte, flowLabel uint32, selector uint32) uint64 {
	hash := binary.LittleEndian.Uint64(secret[0:8]) ^ 0x6a09e667f3bcc909
	seed := binary.LittleEndian.Uint64(secret[8:16])
	if source.Is4() {
		sourceBytes, targetBytes := source.As4(), target.As4()
		hash = outputHashWord(hash, 4^seed)
		addresses := uint64(binary.BigEndian.Uint32(sourceBytes[:]))<<32 | uint64(binary.BigEndian.Uint32(targetBytes[:]))
		hash = outputHashWord(hash, addresses)
		return outputHashWord(hash, outputTransportFlowWord(protocol, selector))
	}
	sourceBytes, targetBytes := source.As16(), target.As16()
	hash = outputHashWord(hash, 6^seed)
	hash = outputHashWord(hash, binary.BigEndian.Uint64(sourceBytes[0:8]))
	hash = outputHashWord(hash, binary.BigEndian.Uint64(sourceBytes[8:16]))
	hash = outputHashWord(hash, binary.BigEndian.Uint64(targetBytes[0:8]))
	hash = outputHashWord(hash, binary.BigEndian.Uint64(targetBytes[8:16]))
	if flowLabel != 0 {
		return outputHashWord(hash, uint64(flowLabel))
	}
	return outputHashWord(hash, outputTransportFlowWord(protocol, selector))
}

func outputHashedFlowKey(hash uint64) outputFlowKey {
	if hash == 0 {
		hash = 1
	}
	return outputFlowKey{hash: hash}
}

type packetQueueEntry struct {
	packet []byte
	slot   uint16
	reusable bool
	checksumValidated bool
}

type largePacketBufferCache struct {
	maximum int
	buffers chan []byte
	retired atomic.Bool
}

func largePacketBufferSlots(mtu int) int {
	if mtu <= packetReusableBufferLimit {
		return 0
	}
	slots := deviceBatchSize + largePacketBufferSlack/mtu
	if slots > outboundPacketQueue {
		slots = outboundPacketQueue
	}
	return slots
}

func newLargePacketBufferCache(mtu int) *largePacketBufferCache {
	slots := largePacketBufferSlots(mtu)
	if slots == 0 {
		return nil
	}
	return &largePacketBufferCache{maximum: mtu, buffers: make(chan []byte, slots)}
}

func (c *largePacketBufferCache) acquire(size int) ([]byte, bool) {
	if c == nil || c.retired.Load() || size > c.maximum {
		return nil, false
	}
	select {
	case buffer := <-c.buffers:
		if cap(buffer) >= size && cap(buffer) <= c.maximum {
			return buffer[:size], true
		}
	default:
	}
	return nil, false
}

func (c *largePacketBufferCache) release(buffer []byte) {
	if c == nil || c.retired.Load() || cap(buffer) <= packetReusableBufferLimit || cap(buffer) > c.maximum {
		return
	}
	select {
	case c.buffers <- buffer[:0]:
	default:
		return
	}
	if c.retired.Load() {
		select {
		case <-c.buffers:
		default:
		}
	}
}

func (c *largePacketBufferCache) retire() {
	if c == nil {
		return
	}
	c.retired.Store(true)
	for {
		select {
		case <-c.buffers:
		default:
			return
		}
	}
}

type packetQueue struct {
	packets          chan packetQueueEntry
	free             chan uint16
	slots            []atomic.Uint64
	buffers          chan []byte
	epoch            time.Time
	scheduler        *fairPacketScheduler
	departureWaiters atomic.Pointer[packetQueueDepartureWaiters]
	closed           atomic.Bool
}

type loopbackQueue struct {
	packetQueue
	batchMu sync.Mutex
}

type monotonicStamp int64

func monotonicStampAt(epoch, value time.Time) monotonicStamp {
	if value.IsZero() {
		return 0
	}
	elapsed := value.Sub(epoch)
	if elapsed < 0 {
		elapsed = 0
	}
	return monotonicStamp(elapsed) + 1
}

func (s monotonicStamp) time(epoch time.Time) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return epoch.Add(time.Duration(s - 1))
}

type packetQueueTicket struct {
	token    uint64
	queuedAt monotonicStamp
}

type packetQueueDepartureWaiter struct {
	generation uint64
	notify     chan<- struct{}
	departedAt atomic.Int64
}

type packetQueueDepartureWaiters struct {
	slots []atomic.Pointer[packetQueueDepartureWaiter]
}

const (
	packetQueueTicketLoopback = uint64(1) << 16
	packetQueueTicketGenerationShift = 17
	packetQueueTicketGenerationMask = uint64(1)<<47 - 1
	packetQueueSlotPending = uint64(1)
	packetQueueSlotDepartureWaiter = uint64(2)
	packetQueueSlotGenerationShift = 2
)

func packetQueueTicketToken(slot uint16, generation uint64, loopback bool) uint64 {
	token := generation<<packetQueueTicketGenerationShift | uint64(slot)
	if loopback {
		token |= packetQueueTicketLoopback
	}
	return token
}

func (t packetQueueTicket) slot() uint16 { return uint16(t.token) }

func (t packetQueueTicket) generation() uint64 { return t.token >> packetQueueTicketGenerationShift }

func (t packetQueueTicket) loopback() bool { return t.token&packetQueueTicketLoopback != 0 }

func (t packetQueueTicket) queue(stack *Stack) *packetQueue {
	queue := &stack.outbound
	if t.loopback() {
		queue = &stack.loopback.packetQueue
	}
	return queue
}

func (q *packetQueue) initFIFO(capacity int, epoch time.Time) {
	q.initStorage(capacity, epoch)
	q.packets = make(chan packetQueueEntry, capacity)
}

func (q *packetQueue) initStorage(capacity int, epoch time.Time) {
	q.packets = nil
	q.free = make(chan uint16, capacity)
	q.slots = make([]atomic.Uint64, capacity)
	q.departureWaiters.Store(nil)
	q.buffers = make(chan []byte, capacity)
	q.epoch = epoch
	q.scheduler = nil
	q.closed.Store(false)
	for slot := range q.slots {
		q.free <- uint16(slot)
	}
}

func (q *packetQueue) initFair(capacity int, epoch time.Time, mtu int, secret [16]byte) {
	q.initStorage(capacity, epoch)
	q.scheduler = newFairPacketScheduler(capacity, mtu, secret)
}

func (t packetQueueTicket) queuedTime(epoch time.Time) time.Time { return t.queuedAt.time(epoch) }

func (t packetQueueTicket) pendingIn(queue *packetQueue) bool {
	slot := t.slot()
	if queue == nil || int(slot) >= len(queue.slots) {
		return false
	}
	state := queue.slots[slot].Load()
	return state>>packetQueueSlotGenerationShift == t.generation() && state&packetQueueSlotPending != 0
}

func (t packetQueueTicket) pending(stack *Stack) bool {
	return t.pendingIn(t.queue(stack))
}

func (w *packetQueueDepartureWaiter) departedTime(epoch time.Time) (time.Time, bool) {
	stamp := monotonicStamp(w.departedAt.Load())
	return stamp.time(epoch), stamp != 0
}

func (q *packetQueue) ensureDepartureWaiters() *packetQueueDepartureWaiters {
	if waiters := q.departureWaiters.Load(); waiters != nil {
		return waiters
	}
	waiters := &packetQueueDepartureWaiters{slots: make([]atomic.Pointer[packetQueueDepartureWaiter], len(q.slots))}
	if q.departureWaiters.CompareAndSwap(nil, waiters) {
		return waiters
	}
	return q.departureWaiters.Load()
}

func (t packetQueueTicket) departureWaiter(stack *Stack, notify chan<- struct{}) *packetQueueDepartureWaiter {
	if stack == nil {
		return nil
	}
	queue := t.queue(stack)
	slot := t.slot()
	if int(slot) >= len(queue.slots) || !t.pendingIn(queue) {
		return nil
	}
	waiters := queue.ensureDepartureWaiters()
	waiter := &packetQueueDepartureWaiter{generation: t.generation(), notify: notify}
	for {
		state := queue.slots[slot].Load()
		if state>>packetQueueSlotGenerationShift != t.generation() || state&packetQueueSlotPending == 0 {
			return nil
		}
		existing := waiters.slots[slot].Load()
		if existing != nil {
			if existing.generation == t.generation() {
				return existing
			}
			if waiters.slots[slot].CompareAndSwap(existing, nil) {
				queue.completeDepartureWaiter(existing, true)
			}
			continue
		}
		if !waiters.slots[slot].CompareAndSwap(nil, waiter) {
			continue
		}
		for {
			state = queue.slots[slot].Load()
			if state>>packetQueueSlotGenerationShift != t.generation() || state&packetQueueSlotPending == 0 {
				if waiters.slots[slot].CompareAndSwap(waiter, nil) {
					queue.completeDepartureWaiter(waiter, false)
				}
				return waiter
			}
			if queue.slots[slot].CompareAndSwap(state, state|packetQueueSlotDepartureWaiter) {
				return waiter
			}
		}
	}
}

func (q *packetQueue) tryReserve() (uint16, bool) {
	select {
	case slot := <-q.free:
		return slot, true
	default:
		return 0, false
	}
}

func (q *packetQueue) replaceBestEffort() (packetQueueEntry, bool) {
	if q.scheduler == nil {
		return packetQueueEntry{}, false
	}
	entry, ok := q.scheduler.dropFromFattestFlow()
	if !ok {
		return packetQueueEntry{}, false
	}
	if q.depart(entry.slot) {
		q.completeDeparture(entry.slot)
	}
	return entry, true
}

func (q *packetQueue) releaseReserved(slot uint16) { q.free <- slot }

func (q *packetQueue) enqueueReservedTCP(slot uint16, packet []byte, reusable bool, flowID uint64, loopback bool) (ticket packetQueueTicket, published bool) {
	queuedAt := monotonicStampAt(q.epoch, time.Now())
	generation, published := q.publishReserved(slot, packet, reusable, outputFlowKey{tcp: flowID}, true)
	return packetQueueTicket{token: packetQueueTicketToken(slot, generation, loopback), queuedAt: queuedAt}, published
}

func (q *packetQueue) enqueueReservedPacket(slot uint16, packet []byte, reusable, checksumValidated bool) bool {
	_, published := q.publishReserved(slot, packet, reusable, outputFlowKey{}, checksumValidated)
	return published
}

func (q *packetQueue) enqueueReservedPacketForFlow(slot uint16, packet []byte, reusable bool, flow outputFlowKey, checksumValidated bool) bool {
	_, published := q.publishReserved(slot, packet, reusable, flow, checksumValidated)
	return published
}

func (q *packetQueue) publishReserved(slot uint16, packet []byte, reusable bool, flow outputFlowKey, checksumValidated bool) (uint64, bool) {
	state := q.slots[slot].Load()
	generation := (state>>packetQueueSlotGenerationShift + 1) & packetQueueTicketGenerationMask
	if generation == 0 {
		generation = 1
	}
	q.slots[slot].Store(generation<<packetQueueSlotGenerationShift | packetQueueSlotPending)
	entry := packetQueueEntry{packet: packet, slot: slot, reusable: reusable, checksumValidated: checksumValidated}
	if q.scheduler == nil {
		q.packets <- entry
	} else {
		q.scheduler.enqueue(entry, flow)
	}
	if q.closed.Load() {
		q.discard()
		return generation, false
	}
	return generation, true
}

func (q *packetQueue) ipFlowKey(source, target netip.Addr, protocol byte, flowLabel uint32, payload []byte) outputFlowKey {
	if q.scheduler == nil {
		return outputFlowKey{}
	}
	selector := outputTransportSelector(protocol, payload)
	return outputHashedFlowKey(outputIPFlowHash(q.scheduler.secret, source, target, protocol, flowLabel, selector))
}

func (q *packetQueue) dequeue(closeCh <-chan struct{}) (packetQueueEntry, bool) {
	if q.scheduler != nil {
		entry, ok := q.scheduler.dequeue(closeCh)
		if ok && q.depart(entry.slot) {
			q.completeDeparture(entry.slot)
		}
		return entry, ok
	}
	select {
	case entry := <-q.packets:
		if q.depart(entry.slot) {
			q.completeDeparture(entry.slot)
		}
		return entry, true
	case <-closeCh:
		return packetQueueEntry{}, false
	}
}

func (q *packetQueue) tryDequeue() (packetQueueEntry, bool) {
	if q.scheduler != nil {
		entry, ok := q.scheduler.tryDequeue()
		if ok && q.depart(entry.slot) {
			q.completeDeparture(entry.slot)
		}
		return entry, ok
	}
	select {
	case entry := <-q.packets:
		if q.depart(entry.slot) {
			q.completeDeparture(entry.slot)
		}
		return entry, true
	default:
		return packetQueueEntry{}, false
	}
}

func (q *packetQueue) len() int {
	if q.scheduler != nil {
		return q.scheduler.len()
	}
	return len(q.packets)
}

func (q *packetQueue) setMTU(mtu int) {
	if q.scheduler != nil {
		q.scheduler.setMTU(mtu)
	}
}

func (q *packetQueue) tryEnqueue(packet []byte) bool {
	slot, ok := q.tryReserve()
	if !ok {
		return false
	}
	return q.enqueueReservedPacket(slot, packet, false, false)
}

func (q *packetQueue) acquireBuffer(size int) ([]byte, bool) {
	if size > packetReusableBufferLimit {
		return make([]byte, size), false
	}
	select {
	case buffer := <-q.buffers:
		if cap(buffer) >= size {
			return buffer[:size], true
		}
	default:
	}
	return make([]byte, size), true
}

func (q *packetQueue) releaseBuffer(packet []byte, reusable bool) {
	if !reusable || cap(packet) > packetReusableBufferLimit {
		return
	}
	select {
	case q.buffers <- packet[:0]:
	default:
		return
	}
	if q.closed.Load() {
		select {
		case <-q.buffers:
		default:
		}
	}
}

func (s *Stack) acquireLargeOutputBuffer(size int) ([]byte, bool) {
	cache := s.largeBuffers.Load()
	if buffer, ok := cache.acquire(size); ok {
		return buffer, true
	}
	return make([]byte, size), cache != nil && size <= cache.maximum
}

func (s *Stack) releaseOutputBuffer(queue *packetQueue, packet []byte, reusable bool) {
	if !reusable {
		return
	}
	if cap(packet) <= packetReusableBufferLimit {
		queue.releaseBuffer(packet, true)
		return
	}
	if cache := s.largeBuffers.Load(); cache != nil {
		cache.release(packet)
	}
}

func (q *packetQueue) depart(slot uint16) bool {
	state := q.slots[slot].Add(^uint64(0))
	return state&packetQueueSlotDepartureWaiter != 0
}

func (q *packetQueue) release(entry packetQueueEntry) {
	q.releaseBuffer(entry.packet, entry.reusable)
	q.free <- entry.slot
}

func (q *packetQueue) completeDeparture(slot uint16) {
	if waiters := q.departureWaiters.Load(); waiters != nil {
		q.releaseDepartureWaiter(waiters, slot)
	}
}

func (q *packetQueue) releaseDepartureWaiter(waiters *packetQueueDepartureWaiters, slot uint16) {
	waiter := waiters.slots[slot].Load()
	if waiter != nil {
		waiter = waiters.slots[slot].Swap(nil)
	}
	if waiter != nil {
		q.completeDepartureWaiter(waiter, true)
	}
}

func (q *packetQueue) completeDepartureWaiter(waiter *packetQueueDepartureWaiter, notify bool) {
	waiter.departedAt.Store(int64(monotonicStampAt(q.epoch, time.Now())))
	if notify {
		select {
		case waiter.notify <- struct{}{}:
		default:
		}
	}
}

func (q *packetQueue) close() {
	q.closed.Store(true)
	q.discard()
}

func (q *loopbackQueue) close() {
	q.batchMu.Lock()
	q.packetQueue.close()
	q.batchMu.Unlock()
}

func (q *loopbackQueue) tryWritePackets(packets [][]byte, closeCh <-chan struct{}, checksumValidated bool) error {
	if len(packets) == 0 {
		return nil
	}
	select {
	case <-closeCh:
		return ErrClosed
	default:
	}
	if len(packets) > cap(q.free) {
		return ErrResourceLimit
	}
	slots := make([]uint16, len(packets))
	reserved := 0
	for ; reserved < len(slots); reserved++ {
		slot, ok := q.tryReserve()
		if !ok {
			for _, acquired := range slots[:reserved] {
				q.releaseReserved(acquired)
			}
			select {
			case <-closeCh:
				return ErrClosed
			default:
			}
			return ErrResourceLimit
		}
		slots[reserved] = slot
	}
	q.batchMu.Lock()
	defer q.batchMu.Unlock()
	select {
	case <-closeCh:
		for _, slot := range slots {
			q.releaseReserved(slot)
		}
		return ErrClosed
	default:
	}
	if q.closed.Load() {
		for _, slot := range slots {
			q.releaseReserved(slot)
		}
		return ErrClosed
	}
	for index, packet := range packets {
		if !q.enqueueReservedPacket(slots[index], packet, false, checksumValidated) {
			for _, slot := range slots[index+1:] {
				q.releaseReserved(slot)
			}
			return ErrClosed
		}
	}
	return nil
}

func (q *packetQueue) discard() {
	for {
		entry, ok := q.tryDequeue()
		if !ok {
			break
		}
		q.release(entry)
	}
	for {
		select {
		case <-q.buffers:
		default:
			return
		}
	}
}

func New(config Config) (*Stack, error) {
	state, err := buildNetworkState(config)
	if err != nil {
		return nil, err
	}
	var seed [120]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	ports4 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[0:4]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[4:8]) % fallbackPortCount),
	}
	ports6 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[8:12]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[12:16]) % fallbackPortCount),
	}
	copy(ports4.secret[:], seed[40:56])
	copy(ports6.secret[:], seed[56:72])
	ipv4ID := binary.BigEndian.Uint32(seed[16:20])
	ipv6FragmentID := binary.BigEndian.Uint32(seed[20:24])
	timestampEpoch := time.Now()
	var flowLabelSecret [16]byte
	copy(flowLabelSecret[:], seed[72:88])
	var outputFlowSecret [16]byte
	copy(outputFlowSecret[:], seed[88:104])
	var icmpErrorLimiterSecret [16]byte
	copy(icmpErrorLimiterSecret[:], seed[104:120])
	stack := &Stack{
		tcp: make(map[tcpKey]*TCPConn), udp: make(map[udpKey]*UDPConn),
		nextPort: [2]automaticPortCursor{ports4, ports6}, pathMTU: make(map[netip.Addr]pathMTUEntry),
		closeCh: make(chan struct{}), timestampEpoch: timestampEpoch, fragments: make(map[fragmentKey]*ipPacketReassemblyEntry), fragmentWake: make(chan struct{}, 1),
	}
	stack.outbound.initFair(outboundPacketQueue, timestampEpoch, state.mtu, outputFlowSecret)
	stack.loopback.initFIFO(loopbackPacketQueue, timestampEpoch)
	stack.largeBuffers.Store(newLargePacketBufferCache(state.mtu))
	copy(stack.tcpISNSecret[:], seed[24:40])
	stack.flowLabelSecret = flowLabelSecret
	stack.icmpErrorLimiterSecret = icmpErrorLimiterSecret
	stack.ipv4ID.Store(ipv4ID)
	stack.ipv6FragmentID.Store(ipv6FragmentID)
	stack.network.Store(state)
	return stack, nil
}

func (s *Stack) UpdateConfig(config Config) error {
	state, err := buildNetworkState(config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	previous := s.network.Load()
	multicastConfigurationChanged := !previous.sameMulticastConfiguration(state)
	if previous.mtu != state.mtu {
		retired := s.largeBuffers.Swap(newLargePacketBufferCache(state.mtu))
		retired.retire()
	}
	if !previous.samePathConfiguration(state) {
		s.pathMTUMu.Lock()
		s.network.Store(state)
		s.pathMTU = make(map[netip.Addr]pathMTUEntry)
		s.pathMTUMu.Unlock()
	} else {
		s.network.Store(state)
	}
	s.outbound.setMTU(state.mtu)
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	tcpForwarder, udpForwarder, ipForwarder, icmpForwarder := s.tcpForwarder, s.udpForwarder, s.ipForwarder, s.icmpForwarder
	multicast := s.multicast
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	s.mu.Unlock()
	if tcpPassive != nil {
		tcpPassive.updateConfig(s, state)
	}
	if tcpForwarder != nil {
		tcpForwarder.updateConfig(state)
	}
	if udpForwarder != nil {
		udpForwarder.updateConfig(state)
	}
	if ipForwarder != nil {
		ipForwarder.updateConfig(state)
	}
	if icmpForwarder != nil {
		icmpForwarder.updateConfig(state)
	}
	for _, connection := range tcpConnections {
		connection.updateDefaultCongestionControl(state.tcpDefaults.CongestionControlFactory)
		_, routed := state.routeFor(connection.key.remote.Addr())
		if !networkStateHasLocal(state, connection.key.local.Addr()) && !(connection.forwarded && state.acceptsInboundDestination(connection.key.local.Addr())) {
			connection.abortWithoutReset(syscall.EADDRNOTAVAIL)
			continue
		}
		if !routed {
			connection.abortWithoutReset(syscall.ENETUNREACH)
			continue
		}
		connection.wakeActor(tcpActorWakePathMTU)
	}
	for _, connection := range udpConnections {
		if connection.dual && !networkStateHasFamily(state, false) && !networkStateHasFamily(state, true) ||
			!connection.dual && connection.local.IsUnspecified() && !networkStateHasFamily(state, connection.v6) ||
			connection.local.IsValid() && !connection.local.IsUnspecified() && !networkStateHasLocal(state, connection.local) && !(connection.forwarded && state.acceptsInboundDestination(connection.local)) {
			s.closeUDP(connection)
			continue
		}
		if connection.remote.IsValid() {
			if !state.hasOutputPath(connection.remote.Addr()) {
				s.closeUDP(connection)
			}
		}
	}
	if ip != nil {
		ip.updateConfig(s, state)
	}
	if multicast != nil && multicastConfigurationChanged {
		multicast.updateConfig(state)
	}
	s.pruneFragments(state)
	return nil
}

func (s *Stack) LocalAddresses() []netip.Addr {
	return append([]netip.Addr(nil), s.network.Load().sources...)
}

func (s *Stack) RouteFor(destination netip.Addr) (Route, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() || destination.Zone() != "" {
		return Route{}, syscall.EINVAL
	}
	state := s.network.Load()
	if state.broadcastDestination(destination) {
		return Route{}, syscall.EACCES
	}
	route, exists := state.routeFor(destination)
	if !exists {
		return Route{}, syscall.ENETUNREACH
	}
	return route, nil
}

func (s *Stack) PathMTU(destination netip.Addr) (int, error) {
	if _, err := s.RouteFor(destination); err != nil {
		return 0, err
	}
	return s.mtuFor(destination), nil
}

func (s *Stack) ConfirmPathMTU(destination netip.Addr, mtu int) error {
	if _, err := s.RouteFor(destination); err != nil {
		return err
	}
	destination = destination.Unmap()
	minimum := 68
	if destination.Is6() {
		minimum = ipv6MinimumMTU
	}
	s.pathMTUMu.Lock()
	select {
	case <-s.closeCh:
		s.pathMTUMu.Unlock()
		return ErrClosed
	default:
	}
	linkMTU := s.network.Load().mtu
	if mtu < minimum || mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	confirmed := linkMTU
	if current, exists := s.pathMTU[destination]; exists && current.mtu < confirmed {
		confirmed = current.mtu
	}
	if mtu < confirmed {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, nil)
	}
	return nil
}

func networkStateHasLocal(state *networkState, address netip.Addr) bool {
	_, exists := state.local[address.Unmap()]
	return exists
}

func networkStateHasFamily(state *networkState, v6 bool) bool {
	for _, source := range state.sources {
		if source.Is6() == v6 {
			return true
		}
	}
	return false
}

func listenAddress(state *networkState, network, protocol string, address netip.Addr) (netip.Addr, bool, error) {
	if err := validateListenNetwork(network, protocol, address); err != nil {
		return netip.Addr{}, false, err
	}
	switch network {
	case protocol + "4":
		if !networkStateHasFamily(state, false) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv4Unspecified()
		}
		return address, false, nil
	case protocol + "6":
		if !networkStateHasFamily(state, true) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv6Unspecified()
		}
		return address, false, nil
	case protocol:
	}
	if address.IsValid() && !address.IsUnspecified() {
		return address, false, nil
	}
	have4 := networkStateHasFamily(state, false)
	have6 := networkStateHasFamily(state, true)
	if have6 {
		return netip.IPv6Unspecified(), have4, nil
	}
	if have4 {
		return netip.IPv4Unspecified(), false, nil
	}
	return netip.Addr{}, false, syscall.EADDRNOTAVAIL
}

func validateListenNetwork(network, protocol string, address netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if address.IsValid() && address.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if address.IsValid() && address.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

func (s *Stack) mtuFor(destination netip.Addr) int {
	destination = destination.Unmap()
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists {
		return linkMTU
	}
	now := time.Now()
	if exists && now.Sub(entry.updated) < pathMTULifetime && entry.mtu < linkMTU {
		return entry.mtu
	}
	if exists && now.Sub(entry.updated) >= pathMTULifetime {
		s.pathMTUMu.Lock()
		linkMTU = s.network.Load().mtu
		current, currentExists := s.pathMTU[destination]
		if currentExists && now.Sub(current.updated) >= pathMTULifetime {
			delete(s.pathMTU, destination)
			currentExists = false
		}
		s.pathMTUMu.Unlock()
		if currentExists && current.mtu < linkMTU {
			return current.mtu
		}
	}
	return linkMTU
}

func (s *Stack) pathMTUExpiry(destination netip.Addr) (time.Time, bool) {
	destination = destination.Unmap()
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists || entry.mtu >= linkMTU {
		return time.Time{}, false
	}
	return entry.updated.Add(pathMTULifetime), true
}

func (s *Stack) notifyTCPPathMTU(destination netip.Addr, except *TCPConn) {
	destination = destination.Unmap()
	s.mu.RLock()
	for key, connection := range s.tcp {
		if connection == nil || connection == except || key.remote.Addr() != destination {
			continue
		}
		connection.wakeActor(tcpActorWakePathMTU)
	}
	s.mu.RUnlock()
}

func (s *Stack) observePathMTU(destination netip.Addr, mtu uint32) bool {
	destination = destination.Unmap()
	minimum := uint32(68)
	if destination.Is6() {
		minimum = 1280
	}
	if !destination.IsValid() || mtu == 0 {
		return false
	}
	if destination.Is6() && mtu < minimum {
		return false
	}
	if mtu < minimum {
		mtu = minimum
	}
	s.pathMTUMu.Lock()
	defer s.pathMTUMu.Unlock()
	select {
	case <-s.closeCh:
		return false
	default:
	}
	if mtu >= uint32(s.network.Load().mtu) {
		return false
	}
	now := time.Now()
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu < int(mtu) {
			return false
		}
		if current.mtu == int(mtu) {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	s.storePathMTULocked(destination, pathMTUEntry{mtu: int(mtu), updated: now})
	s.stats.pathMTUUpdates.Add(1)
	return true
}

func (s *Stack) storePathMTULocked(destination netip.Addr, entry pathMTUEntry) {
	if _, exists := s.pathMTU[destination]; !exists && len(s.pathMTU) >= pathMTUMaximumEntries {
		var oldestAddress netip.Addr
		var oldest pathMTUEntry
		for address, candidate := range s.pathMTU {
			if !oldestAddress.IsValid() || candidate.updated.Before(oldest.updated) {
				oldestAddress, oldest = address, candidate
			}
		}
		delete(s.pathMTU, oldestAddress)
	}
	s.pathMTU[destination] = entry
}

func (s *Stack) confirmPathMTU(destination netip.Addr, mtu int, except *TCPConn) bool {
	destination = destination.Unmap()
	if !destination.IsValid() || mtu <= 0 {
		return false
	}
	s.pathMTUMu.Lock()
	select {
	case <-s.closeCh:
		s.pathMTUMu.Unlock()
		return false
	default:
	}
	linkMTU := s.network.Load().mtu
	if mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return false
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, except)
	}
	return changed
}

func (s *Stack) confirmPathMTULocked(destination netip.Addr, mtu, linkMTU int, now time.Time) bool {
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu > mtu {
			return false
		}
		if current.mtu == mtu {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	if mtu >= linkMTU {
		delete(s.pathMTU, destination)
	} else {
		s.storePathMTULocked(destination, pathMTUEntry{mtu: mtu, updated: now})
	}
	return true
}

func (s *Stack) Stats() StackStats {
	return StackStats{
		InboundPackets:              s.stats.inboundPackets.Load(),
		InboundDroppedPackets:       s.stats.inboundDroppedPackets.Load(),
		InvalidIPPackets:            s.stats.invalidIPPackets.Load(),
		UnacceptedIPPackets:         s.stats.unacceptedIPPackets.Load(),
		NonlocalDestinationPackets:  s.stats.nonlocalDestinationPackets.Load(),
		PromiscuousInboundPackets:   s.stats.promiscuousInboundPackets.Load(),
		InvalidSourcePackets:        s.stats.invalidSourcePackets.Load(),
		OutboundPackets:             s.stats.outboundPackets.Load(),
		OutboundQueueDrops:          s.stats.outboundQueueDrops.Load(),
		LoopbackPackets:             s.stats.loopbackPackets.Load(),
		LoopbackQueueDrops:          s.stats.loopbackQueueDrops.Load(),
		ActiveTCPConnections:        s.stats.activeTCPConnections.Load(),
		ActiveTCPListeners:          s.stats.activeTCPListeners.Load(),
		ActiveUDPSockets:            s.stats.activeUDPSockets.Load(),
		ActiveIPSockets:             s.stats.activeIPSockets.Load(),
		TCPRetransmissions:          s.stats.tcpRetransmissions.Load(),
		TCPInboundQueueDrops:        s.stats.tcpInboundQueueDrops.Load(),
		TCPInvalidSegments:          s.stats.tcpInvalidSegments.Load(),
		TCPSACKRetransmissions:      s.stats.tcpSACKRetransmissions.Load(),
		TCPRACKRetransmissions:      s.stats.tcpRACKRetransmissions.Load(),
		TCPTailLossProbes:           s.stats.tcpTailLossProbes.Load(),
		TCPSpuriousRecoveryUndos:    s.stats.tcpSpuriousRecoveryUndos.Load(),
		TCPZeroWindowProbes:         s.stats.tcpZeroWindowProbes.Load(),
		TCPKeepAliveProbes:          s.stats.tcpKeepAliveProbes.Load(),
		TCPSYNCookiesSent:           s.stats.tcpSYNCookiesSent.Load(),
		TCPSYNCookiesAccepted:       s.stats.tcpSYNCookiesAccepted.Load(),
		TCPSYNCookiesRejected:       s.stats.tcpSYNCookiesRejected.Load(),
		TCPHandshakeTimeouts:        s.stats.tcpHandshakeTimeouts.Load(),
		TCPAcceptQueueDrops:         s.stats.tcpAcceptQueueDrops.Load(),
		PathMTUUpdates:              s.stats.pathMTUUpdates.Load(),
		PathMTUProbes:               s.stats.pathMTUProbes.Load(),
		PathMTUProbeSuccesses:       s.stats.pathMTUProbeSuccesses.Load(),
		PathMTUProbeFailures:        s.stats.pathMTUProbeFailures.Load(),
		PathMTUBlackHoleReductions:  s.stats.pathMTUBlackHoleReductions.Load(),
		FragmentEvictions:           s.stats.fragmentEvictions.Load(),
		FragmentTimeouts:            s.stats.fragmentTimeouts.Load(),
		RateLimitedControlResponses: s.stats.rateLimitedControlResponses.Load(),
	}
}

func (s *Stack) allowControlResponse(class controlResponseClass) bool {
	s.controlMu.Lock()
	now := time.Now()
	bucket := &s.controlLimiters[class]
	bucket.refill(now, controlResponseRate, controlResponseBurst)
	allowed := bucket.tokens >= 1
	if allowed {
		bucket.tokens--
	}
	s.controlMu.Unlock()
	if !allowed {
		s.stats.rateLimitedControlResponses.Add(1)
	}
	return allowed
}

func (s *Stack) allowICMPErrorResponseTo(class icmpErrorResponseClass, destination netip.Addr) bool {
	if !destination.IsValid() {
		s.stats.rateLimitedControlResponses.Add(1)
		return false
	}
	destination = destination.Unmap().WithZone("")

	s.controlMu.Lock()
	now := time.Now()
	table := s.icmpErrorLimiterTableLocked(class)
	aggregate := &table.aggregate
	aggregate.refill(now, controlResponseRate, icmpErrorAggregateBurst)
	useReserve := aggregate.tokens < 1
	if useReserve {
		reserveAggregate := &table.reserveAggregate
		reserveAggregate.refill(now, icmpErrorReserveRate, icmpErrorReserveBurst)
		if reserveAggregate.tokens < 1 {
			s.controlMu.Unlock()
			s.stats.rateLimitedControlResponses.Add(1)
			return false
		}
	}

	address := destination.As16()
	hash := sipHash24(s.icmpErrorLimiterSecret, address[:])
	var reserve *icmpErrorReserveSlot
	var reserveNow monotonicStamp
	if useReserve {
		reserveNow = monotonicStampAt(s.timestampEpoch, now)
		first := &table.reserve[0][uint32(hash>>32)%icmpErrorReserveBuckets]
		second := &table.reserve[1][uint32(hash>>48)%icmpErrorReserveBuckets]
		if (first.availableAt > reserveNow && first.ownerHash == hash) ||
			(second.availableAt > reserveNow && second.ownerHash == hash) {
			s.controlMu.Unlock()
			s.stats.rateLimitedControlResponses.Add(1)
			return false
		}
		if first.availableAt <= reserveNow {
			reserve = first
		} else if second.availableAt <= reserveNow {
			reserve = second
		} else {
			s.controlMu.Unlock()
			s.stats.rateLimitedControlResponses.Add(1)
			return false
		}
	}
	target := table.targetBucketLocked(destination, hash, now)
	target.refill(now, icmpErrorTargetRate, icmpErrorTargetBurst)
	if target.tokens < 1 {
		s.controlMu.Unlock()
		s.stats.rateLimitedControlResponses.Add(1)
		return false
	}

	aggregate.tokens--
	target.tokens--
	if reserve != nil {
		table.reserveAggregate.tokens--
		reserve.availableAt = reserveNow + monotonicStamp(icmpErrorReserveInterval)
		reserve.ownerHash = hash
	}
	s.controlMu.Unlock()
	return true
}

func (s *Stack) icmpErrorLimiterTableLocked(class icmpErrorResponseClass) *icmpErrorLimiterTable {
	if s.icmpErrorLimiters == nil {
		s.icmpErrorLimiters = &icmpErrorLimiterState{}
	}
	table := s.icmpErrorLimiters.tables[class]
	if table == nil {
		table = &icmpErrorLimiterTable{}
		s.icmpErrorLimiters.tables[class] = table
	}
	return table
}

func (t *icmpErrorLimiterTable) targetBucketLocked(destination netip.Addr, hash uint64, now time.Time) *tokenBucket {
	start := int(uint32(hash) % uint32(len(t.entries)))
	var stale *icmpErrorTargetEntry
	for offset := range t.entries {
		entry := &t.entries[(start+offset)%len(t.entries)]
		if entry.destination == destination {
			return &entry.bucket
		}
		if !entry.destination.IsValid() {
			entry.destination = destination
			entry.bucket = tokenBucket{}
			return &entry.bucket
		}
		if stale == nil && now.Sub(entry.bucket.updated) >= icmpErrorTargetIdle {
			stale = entry
		}
	}
	if stale != nil {
		stale.destination = destination
		stale.bucket = tokenBucket{}
		return &stale.bucket
	}
	return &t.overflow[uint32(hash)%uint32(len(t.overflow))]
}

func (s *Stack) Start() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()
	go s.runFragmentCleaner()
	go s.runLoopback()
	return nil
}

func (s *Stack) runLoopback() {
	for {
		entry, ok := s.loopback.dequeue(s.closeCh)
		if !ok {
			return
		}
		select {
		case <-s.closeCh:
			if entry.reusable && cap(entry.packet) > packetReusableBufferLimit {
				if cache := s.largeBuffers.Load(); cache != nil {
					cache.release(entry.packet)
				}
				entry.reusable = false
			}
			s.loopback.release(entry)
			return
		default:
		}
		rxOffload := uint32(0)
		if entry.checksumValidated {
			rxOffload = rxChecksumOffloadGenerated
		}
		_ = s.handleInboundPacket(entry.packet, time.Now(), true, rxOffload)
		if entry.reusable && cap(entry.packet) > packetReusableBufferLimit {
			if cache := s.largeBuffers.Load(); cache != nil {
				cache.release(entry.packet)
			}
			entry.reusable = false
		}
		s.loopback.release(entry)
	}
}

func (s *Stack) ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if !s.started {
		return ErrNotStarted
	}
	return nil
}

func (s *Stack) sourceForOutput(destination, requested netip.Addr) (netip.Addr, bool, error) {
	state := s.network.Load()
	destination = destination.Unmap()
	if destination.IsMulticast() || state.broadcastDestination(destination) {
		source, err := state.sourceForNonUnicast(destination, requested)
		return source, true, err
	}
	source, err := state.sourceForUnicast(destination, requested)
	return source, false, err
}

func (s *Stack) sourceForRequested(destination, requested netip.Addr) (netip.Addr, error) {
	source, _, err := s.sourceForOutput(destination, requested)
	return source, err
}

func (s *Stack) classifyInboundDestination(state *networkState, destination netip.Addr, loopback bool) inboundDestinationClass {
	if destination.Is4In6() {
		return inboundDestinationRejected
	}
	destination = destination.Unmap()
	if networkStateHasLocal(state, destination) {
		return inboundDestinationLocalUnicast
	}
	if state.broadcastDestination(destination) {
		if !networkStateHasFamily(state, false) {
			return inboundDestinationRejected
		}
		return inboundDestinationBroadcast
	}
	if destination.IsMulticast() {
		if !validMulticastGroup(destination) || isInterfaceLocalMulticast(destination) && !loopback {
			return inboundDestinationRejected
		}
		if isAllHostsGroup(destination) && networkStateHasFamily(state, destination.Is6()) {
			return inboundDestinationMulticast
		}
		s.mu.RLock()
		multicast := s.multicast
		s.mu.RUnlock()
		if multicast != nil && multicast.acceptsDestination(destination) {
			return inboundDestinationMulticast
		}
		return inboundDestinationRejected
	}
	if state.acceptsNonlocalDestination(destination) {
		return inboundDestinationPromiscuousUnicast
	}
	return inboundDestinationRejected
}

func (s *Stack) acceptsInboundDestination(state *networkState, destination netip.Addr, loopback bool) bool {
	return s.classifyInboundDestination(state, destination, loopback) != inboundDestinationRejected
}

func validInboundSource(state *networkState, source, destination netip.Addr) bool {
	if source.Is4In6() {
		return false
	}
	source, destination = source.Unmap(), destination.Unmap()
	if source.Is4() {
		value := source.As4()
		if value[0] == 0 {
			return source.IsUnspecified() && destination == netip.AddrFrom4([4]byte{255, 255, 255, 255})
		}
	}
	if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() ||
		source == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || state.invalidInboundSource(source) {
		return false
	}
	return !source.IsLoopback() || networkStateHasLocal(state, source)
}

func validInboundFragmentSource(state *networkState, source, destination netip.Addr, protocol byte) bool {
	if validInboundSource(state, source, destination) {
		return true
	}
	source = source.Unmap()
	return protocol == ProtocolIGMP && source.Is4() && source.IsUnspecified()
}

func validInboundPacketSource(state *networkState, packet ipPacket) bool {
	if validInboundSource(state, packet.source, packet.target) {
		return true
	}
	source := packet.source.Unmap()
	if packet.protocol != ProtocolIGMP || !source.Is4() || !source.IsUnspecified() || len(packet.payload) == 0 {
		return false
	}
	switch packet.payload[0] {
	case igmpV1MembershipReport, igmpV2MembershipReport, igmpV3MembershipReport:
		return true
	default:
		return false
	}
}

func (s *Stack) automaticFlowLabel(source, target netip.Addr, protocol byte, payload []byte) uint32 {
	var selector [4]byte
	switch protocol {
	case ProtocolTCP, ProtocolUDP:
		if len(payload) >= 4 {
			copy(selector[:], payload[:4])
		}
	case ProtocolICMPv6:
		if len(payload) >= 6 {
			selector[0], selector[1] = payload[0], payload[1]
			copy(selector[2:4], payload[4:6])
		}
	}
	return s.flowLabel(source, target, protocol, selector)
}

func (s *Stack) automaticTransportFlowLabel(source, target netip.Addr, protocol byte, sourcePort, targetPort uint16) uint32 {
	var selector [4]byte
	binary.BigEndian.PutUint16(selector[0:2], sourcePort)
	binary.BigEndian.PutUint16(selector[2:4], targetPort)
	return s.flowLabel(source, target, protocol, selector)
}

func (s *Stack) flowLabel(source, target netip.Addr, protocol byte, selector [4]byte) uint32 {
	var input [37]byte
	sourceValue, targetValue := source.As16(), target.As16()
	copy(input[0:16], sourceValue[:])
	copy(input[16:32], targetValue[:])
	input[32] = protocol
	copy(input[33:37], selector[:])
	label := uint32(sipHash24(s.flowLabelSecret, input[:])) & ipv6MaximumFlowLabel
	if label == 0 {
		label = 1
	}
	return label
}

func allocateAutomaticPort(cursor *automaticPortCursor, available func(uint16) bool) (uint16, error) {
	return allocateAutomaticPortWithOffsets(cursor, [2]uint32{}, available)
}

func allocateAutomaticPortWithOffsets(cursor *automaticPortCursor, offsets [2]uint32, available func(uint16) bool) (uint16, error) {
	ranges := [...]struct {
		id     byte
		first  uint32
		count  uint32
		cursor *uint16
		step   *uint16
	}{
		{0, dynamicPortFirst, dynamicPortCount, &cursor.dynamic, &cursor.dynamicStep},
		{1, fallbackPortFirst, fallbackPortCount, &cursor.fallback, &cursor.fallbackStep},
	}
	for _, portRange := range ranges {
		if *portRange.step == 0 {
			*portRange.step = automaticPortStep(cursor.secret, portRange.id, portRange.count)
		}
		base := uint32(*portRange.cursor)
		start := (base + offsets[portRange.id]%portRange.count) % portRange.count
		for probe := uint32(0); probe < portRange.count; probe++ {
			position := (start + probe*uint32(*portRange.step)) % portRange.count
			port := uint16(portRange.first + position)
			if !available(port) {
				continue
			}
			*portRange.cursor = uint16((base + (probe+1)*uint32(*portRange.step)) % portRange.count)
			return port, nil
		}
	}
	return 0, ErrNoPorts
}

func automaticPortStep(secret [16]byte, id byte, count uint32) uint16 {
	step := uint32(1) + uint32(sipHash24(secret, []byte{id})%uint64(count-1))
	for greatestCommonDivisor(step, count) != 1 {
		step++
		if step == count {
			step = 1
		}
	}
	return uint16(step)
}

func greatestCommonDivisor(left, right uint32) uint32 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func (s *Stack) isLocal(address netip.Addr) bool {
	return networkStateHasLocal(s.network.Load(), address)
}

func (s *Stack) allocateUDPPortLocked(address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		return s.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, address, port, dual)
	})
}

func (s *Stack) udpEndpointAvailableLocked(binding udpSocketBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(s, address, port, dual) {
		return false
	}
	for key, connection := range s.udp {
		if key.port == port && listenAddressesOverlap(key.address, connection.dual, address, dual) {
			return false
		}
	}
	state := s.network.Load()
	for key := range s.udpForwarded {
		if key.remote.IsValid() || key.local.Port() != port || !networkStateHasLocal(state, key.local.Addr()) {
			continue
		}
		if listenAddressesOverlap(key.local.Addr(), false, address, dual) {
			return false
		}
	}
	return true
}

func listenAddressesOverlap(left netip.Addr, leftDual bool, right netip.Addr, rightDual bool) bool {
	if leftDual || rightDual {
		if left.IsUnspecified() && right.IsUnspecified() {
			return true
		}
		if leftDual && right.Is4() || rightDual && left.Is4() {
			return true
		}
	}
	return left.Is6() == right.Is6() && (left.IsUnspecified() || right.IsUnspecified() || left == right)
}

func (s *Stack) allocateTCPPortLocked(local netip.Addr, remote netip.AddrPort) (uint16, error) {
	index := 0
	if remote.Addr().Is6() {
		index = 1
	}
	cursor := &s.nextPort[index]
	offsets := automaticTCPPortOffsets(cursor.secret, local, remote)
	return allocateAutomaticPortWithOffsets(cursor, offsets, func(port uint16) bool {
		if s.tcpPortListenedLocked(local, port) {
			return false
		}
		key := tcpKey{local: netip.AddrPortFrom(local, port), remote: remote}
		if _, exists := s.tcp[key]; exists {
			return false
		}
		return true
	})
}

func automaticTCPPortOffsets(secret [16]byte, local netip.Addr, remote netip.AddrPort) [2]uint32 {
	var input [35]byte
	if local.Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	localValue, remoteValue := local.As16(), remote.Addr().As16()
	copy(input[1:17], localValue[:])
	copy(input[17:33], remoteValue[:])
	binary.BigEndian.PutUint16(input[33:35], remote.Port())
	hash := sipHash24(secret, input[:])
	return [2]uint32{uint32(hash), uint32(hash >> 32)}
}

func (s *Stack) tcpPortListenedLocked(local netip.Addr, port uint16) bool {
	return s.tcpPassive != nil && s.tcpPassive.portListened(local, port)
}

func (s *Stack) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	return s.listenUDP(ctx, network, local, exclusiveUDPSocketBinding{}, datagramSocketOptionSet{})
}

func (s *Stack) listenUDP(ctx context.Context, network string, local netip.AddrPort, binding udpSocketBinding, options datagramSocketOptionSet) (net.PacketConn, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := net.UDPAddrFromAddrPort(local)
	wrap := func(err error) (net.PacketConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "udp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid UDP listen address"))
	}
	if address.IsValid() && !address.IsUnspecified() && !s.isLocal(address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	if err := s.ready(); err != nil {
		return wrap(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(ErrClosed)
	}
	state := s.network.Load()
	address, dual, err := listenAddress(state, network, "udp", address)
	if err != nil {
		return wrap(err)
	}
	if err = (socketOptionSet{datagram: options}).validateFamily(socketOptionUDPListen, address.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.udpEndpointAvailableLocked(binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	connection := newUDPConn(s, network, port, address.Is6(), address, netip.AddrPort{}, options)
	connection.dual = dual
	if err = binding.register(s, connection); err != nil {
		return wrap(err)
	}
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

func (s *Stack) DialUDP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	return s.dialUDP(ctx, network, source, remote, datagramSocketOptionSet{})
}

func (s *Stack) dialUDP(ctx context.Context, network string, source, remote netip.AddrPort, options datagramSocketOptionSet) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := net.UDPAddrFromAddrPort(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "udp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Addr().IsUnspecified() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid UDP destination"))
	}
	if err := (socketOptionSet{datagram: options}).validateFamily(socketOptionUDPDial, remote.Addr().Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		return wrap(nil, err)
	}
	localAddress := net.UDPAddrFromAddrPort(local)
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(local.Addr(), false)
		if err != nil {
			return wrap(localAddress, err)
		}
	} else if !s.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, local.Addr(), port, false) {
		return wrap(localAddress, syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(local.Addr(), port)
	connection := newUDPConn(s, network, port, remote.Addr().Is6(), local.Addr(), remote, options)
	s.udp[udpKey{address: local.Addr(), port: port}] = connection
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

func validateTransportNetwork(network, protocol string, remote netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if remote.IsValid() && remote.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if remote.IsValid() && remote.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

func (s *Stack) localEndpointFor(network string, remote, requested netip.AddrPort) (netip.AddrPort, error) {
	requestedAddress := requested.Addr()
	if requestedAddress.IsValid() {
		requestedAddress = requestedAddress.Unmap()
		if requestedAddress.Zone() != "" || requestedAddress.IsMulticast() {
			return netip.AddrPort{}, syscall.EINVAL
		}
		if requestedAddress.Is6() != remote.Addr().Is6() && (!requestedAddress.IsUnspecified() || network[len(network)-1] == '4' || network[len(network)-1] == '6') {
			family := "IPv6"
			if remote.Addr().Is4() {
				family = "IPv4"
			}
			return netip.AddrPort{}, &net.AddrError{Err: "non-" + family + " address", Addr: requestedAddress.String()}
		}
	}
	address, err := s.sourceForRequested(remote.Addr(), requestedAddress)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, requested.Port()), nil
}

func (s *Stack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if len(sizes) < len(buffers) {
		return 0, errors.New("mipstack: Read sizes shorter than buffers")
	}
	limit := len(buffers)
	if limit > deviceBatchSize {
		limit = deviceBatchSize
	}
	if limit == 0 {
		return 0, errors.New("mipstack: Read requires one buffer and size")
	}
	for index := 0; index < limit; index++ {
		if offset < 0 || offset > len(buffers[index]) {
			return 0, errors.New("mipstack: invalid Read offset")
		}
	}
	readPacket := func(index int, entry packetQueueEntry) error {
		var err error
		if len(entry.packet) > len(buffers[index])-offset {
			err = io.ErrShortBuffer
		} else {
			sizes[index] = copy(buffers[index][offset:], entry.packet)
		}
		if entry.reusable && cap(entry.packet) > packetReusableBufferLimit {
			if cache := s.largeBuffers.Load(); cache != nil {
				cache.release(entry.packet)
			}
			entry.reusable = false
		}
		s.outbound.release(entry)
		return err
	}
	first, ok := s.outbound.dequeue(s.closeCh)
	if !ok {
		return 0, os.ErrClosed
	}
	if err := readPacket(0, first); err != nil {
		return 0, err
	}
	count := 1
	for count < limit {
		entry, available := s.outbound.tryDequeue()
		if !available {
			return count, nil
		}
		if err := readPacket(count, entry); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *Stack) Write(buffers [][]byte, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	receivedAt := time.Now()
	rxOffload := s.rxChecksumOffload.Load()
	count := 0
	for _, buffer := range buffers {
		if offset < 0 || offset > len(buffer) {
			return count, errors.New("mipstack: invalid Write offset")
		}
		if err := s.handleInboundPacket(buffer[offset:], receivedAt, false, rxOffload); err != nil {
			if errors.Is(err, ErrClosed) {
				return count, os.ErrClosed
			}
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *Stack) tryWritePacket(packet []byte, checksumValidated bool) error {
	queue, loopback := s.outputQueue(packet)
	return s.tryWritePacketToFlow(packet, queue, loopback, outputFlowKey{}, checksumValidated)
}

func (s *Stack) tryWritePacketToFlow(packet []byte, queue *packetQueue, loopback bool, flow outputFlowKey, checksumValidated bool) error {
	slot, err := s.tryReservePacket(queue)
	if err == ErrResourceLimit {
		slot, err = s.replaceBestEffortPacket(queue)
	}
	if err != nil {
		return err
	}
	if !queue.enqueueReservedPacketForFlow(slot, packet, false, flow, checksumValidated) {
		return ErrClosed
	}
	s.recordOutput(loopback)
	return nil
}

func (s *Stack) tryReservePacket(queue *packetQueue) (uint16, error) {
	select {
	case <-s.closeCh:
		return 0, ErrClosed
	default:
	}
	if slot, ok := queue.tryReserve(); ok {
		return slot, nil
	}
	select {
	case <-s.closeCh:
		return 0, ErrClosed
	default:
		return 0, ErrResourceLimit
	}
}

func (s *Stack) replaceBestEffortPacket(queue *packetQueue) (uint16, error) {
	if slot, ok := queue.tryReserve(); ok {
		return slot, nil
	}
	if entry, ok := queue.replaceBestEffort(); ok {
		s.releaseOutputBuffer(queue, entry.packet, entry.reusable)
		s.recordQueueDrops(queue, 1)
		return entry.slot, nil
	}
	select {
	case <-s.closeCh:
		return 0, ErrClosed
	default:
		s.recordQueueDrops(queue, 1)
		return 0, ErrResourceLimit
	}
}

func (s *Stack) recordQueueDrops(queue *packetQueue, count uint64) {
	if queue == &s.loopback.packetQueue {
		s.stats.loopbackQueueDrops.Add(count)
		return
	}
	s.stats.outboundQueueDrops.Add(count)
}

func (s *Stack) tryWritePackets(packets [][]byte, flow outputFlowKey, checksumValidated bool) error {
	if len(packets) == 0 {
		return nil
	}
	queue, loopback := s.outputQueue(packets[0])
	if len(packets) == 1 {
		return s.tryWritePacketToFlow(packets[0], queue, loopback, flow, checksumValidated)
	}
	if loopback {
		return s.tryWriteLoopbackPackets(packets, checksumValidated)
	}
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	for _, packet := range packets {
		slot, err := s.tryReservePacket(queue)
		if err == ErrResourceLimit {
			slot, err = s.replaceBestEffortPacket(queue)
		}
		if err != nil {
			return err
		}
		if !queue.enqueueReservedPacketForFlow(slot, packet, false, flow, checksumValidated) {
			return ErrClosed
		}
		s.recordOutput(false)
	}
	return nil
}

func (s *Stack) tryWriteLoopbackPackets(packets [][]byte, checksumValidated bool) error {
	if err := s.loopback.tryWritePackets(packets, s.closeCh, checksumValidated); err != nil {
		if err == ErrResourceLimit {
			s.stats.loopbackQueueDrops.Add(uint64(len(packets)))
		}
		return err
	}
	s.stats.loopbackPackets.Add(uint64(len(packets)))
	return nil
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	return timer, timer.C
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

type socketDeadline struct {
	timer *time.Timer
	done  chan struct{}
}

type datagramSocketDeadline struct {
	state atomic.Pointer[datagramSocketDeadlineState]
}

type datagramSocketDeadlineState struct {
	timer *time.Timer
	done  chan struct{}
}

type datagramSocketWriteControl struct {
	closed        chan struct{}
	writeDeadline datagramSocketDeadline
}

func (c *datagramSocketWriteControl) writeError() error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	select {
	case <-c.writeDeadline.channel():
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}

func datagramLinkWriteError(err error, receiveErrors bool) error {
	if err != ErrResourceLimit {
		return err
	}
	if receiveErrors {
		return syscall.ENOBUFS
	}
	return nil
}

func datagramWriteNeedsCorrelation(err error) bool {
	return err == nil || err == ErrResourceLimit
}

var stoppedDatagramSocketDeadline = &datagramSocketDeadlineState{}

func (d *datagramSocketDeadline) channel() <-chan struct{} {
	state := d.state.Load()
	if state == nil || state == stoppedDatagramSocketDeadline {
		return nil
	}
	return state.done
}

func (d *datagramSocketDeadline) wait() <-chan struct{} {
	for {
		state := d.state.Load()
		if state == stoppedDatagramSocketDeadline {
			return nil
		}
		if state != nil {
			return state.done
		}
		state = &datagramSocketDeadlineState{done: make(chan struct{})}
		if d.state.CompareAndSwap(nil, state) {
			return state.done
		}
	}
}

func (d *datagramSocketDeadline) set(deadline time.Time) {
	state := d.state.Load()
	if (deadline.IsZero() && state == nil) || state == stoppedDatagramSocketDeadline {
		return
	}
	if state == nil {
		d.wait()
		state = d.state.Load()
		if state == stoppedDatagramSocketDeadline {
			return
		}
	}
	if state.timer != nil && !state.timer.Stop() {
		<-state.done
	}
	state.timer = nil
	closed := false
	select {
	case <-state.done:
		closed = true
	default:
	}
	if deadline.IsZero() {
		if closed {
			d.state.CompareAndSwap(state, nil)
		}
		return
	}
	if duration := time.Until(deadline); duration > 0 {
		if closed {
			state = &datagramSocketDeadlineState{done: make(chan struct{})}
			d.state.Store(state)
		}
		done := state.done
		state.timer = time.AfterFunc(duration, func() { close(done) })
		return
	}
	if !closed {
		close(state.done)
	}
}

func (d *datagramSocketDeadline) stop() {
	state := d.state.Swap(stoppedDatagramSocketDeadline)
	if state != nil && state != stoppedDatagramSocketDeadline && state.timer != nil {
		state.timer.Stop()
		state.timer = nil
	}
}

func (d *socketDeadline) setLocked(deadline time.Time) {
	if deadline.IsZero() && d.done == nil && d.timer == nil {
		return
	}
	if d.done == nil {
		d.done = make(chan struct{})
	}
	if d.timer != nil && !d.timer.Stop() {
		<-d.done
	}
	closed := false
	select {
	case <-d.done:
		closed = true
	default:
	}
	if deadline.IsZero() {
		d.timer = nil
		if closed {
			d.done = make(chan struct{})
		}
		return
	}
	if duration := time.Until(deadline); duration > 0 {
		if closed {
			d.done = make(chan struct{})
			d.timer = nil
		}
		if d.timer != nil {
			d.timer.Reset(duration)
		} else {
			done := d.done
			d.timer = time.AfterFunc(duration, func() { close(done) })
		}
		return
	}
	d.timer = nil
	if !closed {
		close(d.done)
	}
}

func (d *socketDeadline) channelLocked() <-chan struct{} { return d.done }

func (d *socketDeadline) waitLocked() <-chan struct{} {
	if d.done == nil {
		d.done = make(chan struct{})
	}
	return d.done
}

func (d *socketDeadline) stopLocked() {
	if d.timer != nil {
		if !d.timer.Stop() {
			<-d.done
		}
		d.timer = nil
	}
}

type ownedTimer struct {
	timer  *time.Timer
	active bool
}

func newOwnedTimer() *ownedTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &ownedTimer{timer: timer}
}

func (t *ownedTimer) reset(duration time.Duration) <-chan time.Time {
	t.stop()
	if duration < 0 {
		duration = 0
	}
	t.timer.Reset(duration)
	t.active = true
	return t.timer.C
}

func (t *ownedTimer) consumed() { t.active = false }

func (t *ownedTimer) stop() {
	if !t.active {
		return
	}
	t.active = false
	if !t.timer.Stop() {
		<-t.timer.C
	}
}

func (t *ownedTimer) close() {
	t.stop()
	t.timer.Stop()
}

func (s *Stack) outputQueue(packet []byte) (*packetQueue, bool) {
	if destination, ok := packetDestination(packet); ok {
		return s.outputQueueFor(destination)
	}
	return &s.outbound, false
}

func (s *Stack) outputQueueFor(destination netip.Addr) (*packetQueue, bool) {
	if s.isLocal(destination) {
		return &s.loopback.packetQueue, true
	}
	return &s.outbound, false
}

func (s *Stack) recordOutput(loopback bool) {
	if loopback {
		s.stats.loopbackPackets.Add(1)
	} else {
		s.stats.outboundPackets.Add(1)
	}
}

func (s *Stack) handleInboundPacket(packet []byte, receivedAt time.Time, loopback bool, rxOffload uint32) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	s.stats.inboundPackets.Add(1)
	parsed, ok := parseIPPacket(packet, rxOffload&rxChecksumOffloadIPv4Header != 0)
	if !ok {
		network := s.network.Load()
		fragment, validFragment := parseFragment(packet, rxOffload&rxChecksumOffloadIPv4Header != 0)
		if validFragment && s.acceptsInboundDestination(network, fragment.target, loopback) &&
			validInboundFragmentSource(network, fragment.source, fragment.target, fragment.protocol) {
			if fragment.truncated || fragment.parameter {
				s.discardFragment(fragment.reassemblyKey(loopback))
				s.stats.inboundDroppedPackets.Add(1)
				destination := s.classifyInboundDestination(s.network.Load(), fragment.target, loopback)
				code, at := byte(3), uint32(0)
				if fragment.parameter && !fragment.truncated {
					code, at = fragment.parameterCode, fragment.parameterAt
				}
				_ = s.sendInboundParameterProblem(ipPacket{
					source: fragment.source, target: fragment.target, original: fragment.original,
					parameterError: true, parameterCode: code, parameterAt: at,
				}, destination)
				return nil
			}
		}
		if validFragment {
			if reassembled, pending := s.reassembleParsedFragmentStatus(fragment, receivedAt, loopback); reassembled != nil {
				rxOffload = 0
				parsed, ok = parseIPPacket(reassembled, false)
			} else if pending {
				return nil
			}
		}
	}
	network := s.network.Load()
	destination := inboundDestinationRejected
	if ok {
		destination = s.classifyInboundDestination(network, parsed.target, loopback)
	}
	acceptedDestination := destination != inboundDestinationRejected
	invalidSource := ok && !validInboundPacketSource(network, parsed)
	if !ok || !acceptedDestination || invalidSource {
		s.stats.inboundDroppedPackets.Add(1)
		if !ok {
			s.stats.invalidIPPackets.Add(1)
		} else {
			s.stats.unacceptedIPPackets.Add(1)
			if !acceptedDestination {
				s.stats.nonlocalDestinationPackets.Add(1)
			} else {
				s.stats.invalidSourcePackets.Add(1)
			}
		}
		return nil
	}
	if destination == inboundDestinationPromiscuousUnicast {
		s.stats.promiscuousInboundPackets.Add(1)
	}
	s.mu.RLock()
	closed := s.closed
	ip := s.ip
	ipForwarder := s.ipForwarder
	multicast := s.multicast
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if parsed.parameterError {
		s.stats.inboundDroppedPackets.Add(1)
		if destination == inboundDestinationMulticast && !isAllHostsGroup(parsed.target) &&
			(multicast == nil || !multicast.acceptsSource(parsed.target, parsed.source)) {
			return nil
		}
		_ = s.sendInboundParameterProblem(parsed, destination)
		return nil
	}
	if parsed.source.Is6() && parsed.protocol == ProtocolICMPv6 &&
		(len(parsed.payload) < 4 || rxOffload&rxChecksumOffloadICMPv6 == 0 && transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	multicastControl := isMulticastControlPacket(parsed)
	skipControlChecksum := false
	if multicastControl {
		if parsed.protocol == ProtocolIGMP {
			skipControlChecksum = rxOffload&rxChecksumOffloadIGMP != 0
		} else {
			skipControlChecksum = parsed.source.Is6()
		}
		multicast = s.multicastStateForQuery(parsed, multicast, receivedAt, skipControlChecksum)
	}
	if destination == inboundDestinationMulticast && (parsed.protocol == ProtocolICMPv4 || parsed.protocol == ProtocolICMPv6) &&
		!isAllHostsGroup(parsed.target) && !isMulticastControlPacket(parsed) &&
		(multicast == nil || !multicast.acceptsSource(parsed.target, parsed.source)) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	rawDelivered := false
	switch destination {
	case inboundDestinationLocalUnicast, inboundDestinationBroadcast:
		rawDelivered = ip != nil && ip.deliver(s, parsed)
	case inboundDestinationMulticast:
		if isAllHostsGroup(parsed.target) {
			if multicast != nil {
				rawDelivered = multicast.deliverImplicitIP(parsed, ip)
			} else {
				rawDelivered = ip != nil && ip.deliver(s, parsed)
			}
		} else {
			rawDelivered = multicast != nil && multicast.deliverIP(parsed)
		}
	}
	if multicastControl {
		if multicast != nil {
			multicast.handleControl(parsed, receivedAt, skipControlChecksum)
		}
		return nil
	}
	switch parsed.protocol {
	case ProtocolTCP:
		if destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast {
			return s.handleTCP(parsed, receivedAt, destination == inboundDestinationLocalUnicast, rxOffload&rxChecksumOffloadTCP != 0)
		}
		return nil
	case ProtocolUDP:
		return s.handleUDP(parsed, destination, rxOffload&rxChecksumOffloadUDP != 0)
	case ProtocolICMPv4:
		if parsed.source.Is4() && (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) {
			return s.handleICMP(parsed, destination == inboundDestinationLocalUnicast, rxOffload&rxChecksumOffloadICMPv4 != 0)
		}
	case ProtocolICMPv6:
		if parsed.source.Is6() && destination == inboundDestinationMulticast {
			return s.handleMulticastICMPv6(parsed)
		}
		if parsed.source.Is6() && (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) {
			return s.handleICMP(parsed, destination == inboundDestinationLocalUnicast, false)
		}
	default:
	}
	noNextHeader := parsed.source.Is6() && parsed.protocol == ProtocolNoNextHeader
	if (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) &&
		!noNextHeader && !rawDelivered && ipForwarder != nil && ipForwarder.handlePacket(parsed) {
		return nil
	}
	if destination != inboundDestinationLocalUnicast || noNextHeader || rawDelivered {
		return nil
	}
	_ = s.sendProtocolUnreachable(parsed)
	return nil
}

func (s *Stack) sendInboundParameterProblem(packet ipPacket, destination inboundDestinationClass) error {
	if destination == inboundDestinationLocalUnicast {
		return s.sendParameterProblem(packet)
	}
	if destination != inboundDestinationMulticast || !packet.source.Is6() || packet.parameterCode != 2 {
		return nil
	}
	source, err := s.sourceForRequested(packet.source, netip.Addr{})
	if err != nil {
		return err
	}
	packet.target = source
	return s.sendParameterProblem(packet)
}

func (s *Stack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	tcpForwarder, udpForwarder, ipForwarder, icmpForwarder := s.tcpForwarder, s.udpForwarder, s.ipForwarder, s.icmpForwarder
	multicast := s.multicast
	s.tcp = nil
	s.tcpPassive = nil
	s.tcpForwarder = nil
	s.udp = nil
	s.udpReuse = nil
	s.udpForwarded = nil
	s.udpForwarder = nil
	s.ip = nil
	s.ipForwarder = nil
	s.icmpForwarder = nil
	s.multicast = nil
	s.multicastSeed = nil
	s.stats.activeTCPConnections.Store(0)
	s.stats.activeTCPListeners.Store(0)
	s.stats.activeUDPSockets.Store(0)
	s.stats.activeIPSockets.Store(0)
	s.mu.Unlock()
	s.largeBuffers.Swap(nil).retire()
	s.outbound.close()
	s.loopback.close()
	s.pathMTUMu.Lock()
	s.pathMTU = nil
	s.pathMTUMu.Unlock()
	s.fragmentMu.Lock()
	s.fragments = nil
	s.fragmentBytes = 0
	s.fragmentMu.Unlock()
	if tcpPassive != nil {
		tcpPassive.closeAll()
	}
	if tcpForwarder != nil {
		tcpForwarder.closeFromStack()
	}
	if udpForwarder != nil {
		udpForwarder.closeFromStack()
	}
	if ipForwarder != nil {
		ipForwarder.closeFromStack()
	}
	if icmpForwarder != nil {
		icmpForwarder.closeFromStack()
	}
	if multicast != nil {
		multicast.close()
	}
	for _, connection := range tcpConnections {
		connection.abortWithoutReset(ErrClosed)
	}
	for _, connection := range udpConnections {
		connection.closeFromStack()
	}
	if ip != nil {
		ip.closeAll()
	}
	return nil
}

func (s *Stack) closeTCPListener(listener *TCPListener) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.tcpPassive.(*tcpPassiveState)
	if ok && state.remove(listener) {
		s.stats.activeTCPListeners.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.tcpPassive = nil
		}
	}
	s.mu.Unlock()
	listener.closeFromStack()
	return removed
}

func (s *Stack) closeUDP(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	flow := udpFlowKey{local: netip.AddrPortFrom(connection.local, connection.port), remote: connection.remote}
	s.mu.Lock()
	removed := false
	if s.udp[key] == connection {
		delete(s.udp, key)
		removed = true
	} else if s.udpForwarded[flow] == connection {
		delete(s.udpForwarded, flow)
		if len(s.udpForwarded) == 0 {
			s.udpForwarded = nil
		}
		removed = true
	} else if s.udpReuse != nil && s.udpReuse.remove(connection) {
		removed = true
		if s.udpReuse.empty() {
			s.udpReuse = nil
		}
	}
	if removed {
		if s.multicast != nil {
			s.multicast.removeEndpoint(connection)
		}
		s.stats.activeUDPSockets.Add(^uint64(0))
	}
	s.mu.Unlock()
	if removed {
		s.pruneFragments(s.network.Load())
	}
	connection.closeFromStack()
	return removed
}

func (s *Stack) udpConnectionsLocked() []*UDPConn {
	connections := make([]*UDPConn, 0, len(s.udp)+len(s.udpForwarded))
	for _, connection := range s.udp {
		connections = append(connections, connection)
	}
	if s.udpReuse != nil {
		connections = append(connections, s.udpReuse.connections()...)
	}
	for _, connection := range s.udpForwarded {
		connections = append(connections, connection)
	}
	return connections
}

func (s *Stack) closeIP(connection *IPConn) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.ip.(*ipEndpointState)
	if ok && state.remove(connection) {
		if s.multicast != nil {
			s.multicast.removeEndpoint(connection)
		}
		s.stats.activeIPSockets.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.ip = nil
		}
	}
	s.mu.Unlock()
	if removed {
		s.pruneFragments(s.network.Load())
	}
	connection.closeFromStack()
	return removed
}

func (s *Stack) removeTCP(connection *TCPConn) {
	s.mu.Lock()
	if s.tcp[connection.key] == connection {
		delete(s.tcp, connection.key)
		s.stats.activeTCPConnections.Add(^uint64(0))
	}
	s.mu.Unlock()
}

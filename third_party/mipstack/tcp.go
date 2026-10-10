package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	TCPFlagFIN = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagECE
	TCPFlagCWR
	TCPFlagNS

	TCPHeaderOptionEnd = 0
	TCPHeaderOptionNOP = 1
	TCPHeaderOptionMSS = 2
	TCPHeaderOptionWindowScale = 3
	TCPHeaderOptionSACKPermitted = 4
	TCPHeaderOptionSACK = 5
	TCPHeaderOptionTimestamp = 8

	tcpHeaderSize = 20
	tcpTimestampOptionSize = 12
	tcpActorWakeSend = uint32(1 << 0)
	tcpActorWakeWindow = uint32(1 << 1)
	tcpActorWakeOptions = uint32(1 << 2)
	tcpActorWakePathMTU = uint32(1 << 3)
	tcpActorWakeNetworkError = uint32(1 << 4)
	tcpActorWakeInfo = uint32(1 << 5)
	tcpActorWakeQuickACKEnable  = uint32(1 << 6)
	tcpActorWakeQuickACKDisable = uint32(1 << 7)
	tcpActorWakeQuickACKMask    = tcpActorWakeQuickACKEnable | tcpActorWakeQuickACKDisable

	tcpMaximumPendingNetworkErrors = 8
	tcpReceiveCapacity = 1024 * 1024
	tcpSendCapacity = 256 * 1024
	tcpMaximumReceiveCapacity = 16 * 1024 * 1024
	tcpMaximumSendCapacity = 16 * 1024 * 1024
	tcpReusableReceivePayloadLimit = 2048
	tcpSendChunkMinimum = 16 * 1024
	tcpSendChunkMaximum = tcpSendCapacity
	tcpMetadataQueueInitial = 1
	tcpMetadataQueueRetain = 4
	tcpActorReceiveBatch = 8
	tcpMaximumOutOfOrder = 4096
	tcpInboundByteCapacity = 2 * tcpMaximumReceiveCapacity
	tcpInboundSegmentMetadata = 128
	tcpAcceptQueue = 128
	tcpSYNBacklog = 256
	tcpMaximumRTOs = 15
	tcpActiveSYNMaximumAttempts = 7
	tcpPassiveSYNMaximumAttempts = 6
	tcpBlackHoleTimeouts = 4
	tcpInitialRTO = time.Second
	tcpMinimumRTO = 200 * time.Millisecond
	tcpMaximumRTO = 120 * time.Second
	tcpDelayedACKTimeout = 25 * time.Millisecond
	tcpMaximumQuickACKs = 16
	tcpMaximumCompressedSACKs = 44
	tcpMaximumCompressedSACKDelay = time.Millisecond
	tcpDefaultReceiveMSS = 536
	tcpTailLossProbeACKDelay = 200 * time.Millisecond
	tcpTimeWaitDuration = 60 * time.Second
	tcpPAWSMaxAge = 24 * 24 * time.Hour
	tcpPAWSReplayWindow uint32 = 1
	tcpFINWaitDuration = 60 * time.Second
	tcpInitialCongestionMSS = 10
	tcpInitialOutstandingCapacity = 16
	tcpSmallOutstandingCapacity = 2
	tcpDuplicateACKThreshold = 3
	tcpMinimumPeerMSS = 48
	tcpMaximumSACKSplitRanges = 1024
	tcpDefaultKeepAliveIdle = 2 * time.Hour
	tcpDefaultKeepAliveInterval = 75 * time.Second
	tcpDefaultKeepAliveCount = 9
	tcpMaximumScaledWindow = uint32(65535) << 14
	tcpPLPMTUProbeThreshold = 8
	tcpPLPMTUProbeMinimumInterval = time.Second
	tcpAutoTuneMinimumInterval = 10 * time.Millisecond
	tcpEifelClockGranularity = time.Millisecond
	tcpRetransmissionHistoryLimit = 128
	tcpMinimumRTTWindow = 300 * time.Second
)

type TCPHeaderOption struct {
	Kind uint8
	Data []byte
}

func tcpHeaderOptionLength(option []byte) int {
	if len(option) < 2 {
		return 0
	}
	length := int(option[1])
	if uint(length-2) > uint(len(option)-2) {
		return 0
	}
	return length
}

type TCPSACKBlock struct {
	LeftEdge uint32
	RightEdge uint32
}

type TCPSegment struct {
	Source netip.AddrPort
	Destination netip.AddrPort
	SequenceNumber uint32
	AcknowledgmentNumber uint32
	Flags uint16
	WindowSize uint16
	UrgentPointer uint16
	Options []byte
	Payload []byte
}

func tcpWireHeaderSize(dataOffset byte, segmentSize int) (int, bool) {
	headerSize := int(dataOffset>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > segmentSize {
		return 0, false
	}
	return headerSize, true
}

func (s TCPSegment) HeaderOptions() ([]TCPHeaderOption, error) {
	if len(s.Options) > 40 {
		return nil, syscall.EMSGSIZE
	}
	var result []TCPHeaderOption
	for offset := 0; offset < len(s.Options); {
		kind := s.Options[offset]
		switch kind {
		case TCPHeaderOptionEnd:
			return append(result, TCPHeaderOption{Kind: kind}), nil
		case TCPHeaderOptionNOP:
			result = append(result, TCPHeaderOption{Kind: kind})
			offset++
			continue
		}
		length := tcpHeaderOptionLength(s.Options[offset:])
		if length == 0 {
			return nil, syscall.EINVAL
		}
		result = append(result, TCPHeaderOption{Kind: kind, Data: s.Options[offset+2 : offset+length]})
		offset += length
	}
	return result, nil
}

func (s *TCPSegment) SetHeaderOptions(options []TCPHeaderOption) error {
	if s == nil {
		return syscall.EINVAL
	}
	size := 0
	ended := false
	for _, option := range options {
		if ended {
			return syscall.EINVAL
		}
		switch option.Kind {
		case TCPHeaderOptionEnd, TCPHeaderOptionNOP:
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			size++
			ended = option.Kind == TCPHeaderOptionEnd
		default:
			if len(option.Data) > 253 {
				return syscall.EINVAL
			}
			size += 2 + len(option.Data)
		}
		if size > 40 {
			return syscall.EMSGSIZE
		}
	}
	var encoded []byte
	if size != 0 {
		encoded = make([]byte, 0, size)
	}
	for _, option := range options {
		encoded = append(encoded, option.Kind)
		if option.Kind == TCPHeaderOptionEnd || option.Kind == TCPHeaderOptionNOP {
			continue
		}
		encoded = append(encoded, byte(2+len(option.Data)))
		encoded = append(encoded, option.Data...)
	}
	s.Options = encoded
	return nil
}

func (o TCPHeaderOption) MaximumSegmentSize() (uint16, bool) {
	if o.Kind != TCPHeaderOptionMSS || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

func (o *TCPHeaderOption) SetMaximumSegmentSize(value uint16) {
	o.Kind = TCPHeaderOptionMSS
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

func (o TCPHeaderOption) WindowScale() (uint8, bool) {
	if o.Kind != TCPHeaderOptionWindowScale || len(o.Data) != 1 {
		return 0, false
	}
	return o.Data[0], true
}

func (o *TCPHeaderOption) SetWindowScale(value uint8) {
	o.Kind = TCPHeaderOptionWindowScale
	o.Data = []byte{value}
}

func (o TCPHeaderOption) IsSACKPermitted() bool {
	return o.Kind == TCPHeaderOptionSACKPermitted && len(o.Data) == 0
}

func (o *TCPHeaderOption) SetSACKPermitted() {
	o.Kind = TCPHeaderOptionSACKPermitted
	o.Data = nil
}

func (o TCPHeaderOption) Timestamp() (value, echo uint32, ok bool) {
	if o.Kind != TCPHeaderOptionTimestamp || len(o.Data) != 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(o.Data[:4]), binary.BigEndian.Uint32(o.Data[4:]), true
}

func (o *TCPHeaderOption) SetTimestamp(value, echo uint32) {
	o.Kind = TCPHeaderOptionTimestamp
	o.Data = make([]byte, 8)
	binary.BigEndian.PutUint32(o.Data[:4], value)
	binary.BigEndian.PutUint32(o.Data[4:], echo)
}

func (o TCPHeaderOption) SACKBlocks() ([]TCPSACKBlock, bool) {
	if o.Kind != TCPHeaderOptionSACK || len(o.Data) < 8 || len(o.Data) > 32 || len(o.Data)%8 != 0 {
		return nil, false
	}
	blocks := make([]TCPSACKBlock, len(o.Data)/8)
	for index := range blocks {
		offset := index * 8
		blocks[index] = TCPSACKBlock{
			LeftEdge:  binary.BigEndian.Uint32(o.Data[offset : offset+4]),
			RightEdge: binary.BigEndian.Uint32(o.Data[offset+4 : offset+8]),
		}
	}
	return blocks, true
}

func (o *TCPHeaderOption) SetSACKBlocks(blocks []TCPSACKBlock) error {
	if o == nil || len(blocks) < 1 || len(blocks) > 4 {
		return syscall.EINVAL
	}
	data := make([]byte, len(blocks)*8)
	for index, block := range blocks {
		offset := index * 8
		binary.BigEndian.PutUint32(data[offset:offset+4], block.LeftEdge)
		binary.BigEndian.PutUint32(data[offset+4:offset+8], block.RightEdge)
	}
	o.Kind = TCPHeaderOptionSACK
	o.Data = data
	return nil
}

func (p IPPacket) TCPSegment() (TCPSegment, error) {
	tcp, pseudoHeaderSafe, err := p.upperLayerForProtocol(ProtocolTCP)
	if err != nil {
		return TCPSegment{}, err
	}
	if !pseudoHeaderSafe {
		return TCPSegment{}, syscall.EPROTONOSUPPORT
	}
	if len(tcp) < tcpHeaderSize {
		return TCPSegment{}, syscall.EINVAL
	}
	headerSize, valid := tcpWireHeaderSize(tcp[12], len(tcp))
	if !valid {
		return TCPSegment{}, syscall.EINVAL
	}
	options := tcp[tcpHeaderSize:headerSize]
	if _, valid = tcpOptionsContentLength(options); !valid {
		return TCPSegment{}, syscall.EINVAL
	}
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	if transportChecksum(source, destination, ProtocolTCP, tcp) != 0 {
		return TCPSegment{}, syscall.EINVAL
	}
	return TCPSegment{
		Source:         netip.AddrPortFrom(source, binary.BigEndian.Uint16(tcp[0:2])),
		Destination:    netip.AddrPortFrom(destination, binary.BigEndian.Uint16(tcp[2:4])),
		SequenceNumber: binary.BigEndian.Uint32(tcp[4:8]), AcknowledgmentNumber: binary.BigEndian.Uint32(tcp[8:12]),
		Flags:      uint16(tcp[13]) | uint16(tcp[12]&1)<<8,
		WindowSize: binary.BigEndian.Uint16(tcp[14:16]), UrgentPointer: binary.BigEndian.Uint16(tcp[18:20]),
		Options: options, Payload: tcp[headerSize:],
	}, nil
}

func (s TCPSegment) MarshalBinary() ([]byte, error) { return s.AppendBinary(nil) }

func (s TCPSegment) AppendBinary(dst []byte) ([]byte, error) {
	normalized, headerSize, totalSize, err := s.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicTCPSegment(dst[start:], normalized, headerSize)
	return dst, nil
}

func (s TCPSegment) wireLayout() (TCPSegment, int, int, error) {
	if s.Source.Addr().Zone() != "" || s.Destination.Addr().Zone() != "" {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	source, destination := s.Source.Addr().Unmap(), s.Destination.Addr().Unmap()
	if !s.Source.IsValid() || !s.Destination.IsValid() || source.Is4() != destination.Is4() ||
		s.Flags&^uint16(TCPFlagFIN|TCPFlagSYN|TCPFlagRST|TCPFlagPSH|TCPFlagACK|TCPFlagURG|TCPFlagECE|TCPFlagCWR|TCPFlagNS) != 0 || len(s.Options) > 40 {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	if _, valid := tcpOptionsContentLength(s.Options); !valid {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	s.Source, s.Destination = netip.AddrPortFrom(source, s.Source.Port()), netip.AddrPortFrom(destination, s.Destination.Port())
	headerSize := tcpHeaderSize + (len(s.Options)+3)&^3
	if len(s.Payload) > 65535-headerSize {
		return TCPSegment{}, 0, 0, syscall.EMSGSIZE
	}
	return s, headerSize, headerSize + len(s.Payload), nil
}

func marshalPublicTCPSegment(dst []byte, s TCPSegment, headerSize int) {
	var options [40]byte
	contentSize, _ := tcpOptionsContentLength(s.Options)
	copy(options[:], s.Options[:contentSize])
	copy(dst[headerSize:], s.Payload)
	copy(dst[tcpHeaderSize:headerSize], options[:len(s.Options)])
	for index := tcpHeaderSize + len(s.Options); index < headerSize; index++ {
		dst[index] = 0
	}
	marshalTCPHeaderFields(dst[:headerSize], s.Source.Port(), s.Destination.Port(), s.SequenceNumber, s.AcknowledgmentNumber, s.Flags, s.WindowSize, s.UrgentPointer)
	binary.BigEndian.PutUint16(dst[16:18], transportChecksum(s.Source.Addr(), s.Destination.Addr(), ProtocolTCP, dst))
}

func marshalTCPHeaderFields(header []byte, sourcePort, destinationPort uint16, sequence, acknowledgement uint32, flags uint16, window, urgent uint16) {
	binary.BigEndian.PutUint16(header[0:2], sourcePort)
	binary.BigEndian.PutUint16(header[2:4], destinationPort)
	binary.BigEndian.PutUint32(header[4:8], sequence)
	binary.BigEndian.PutUint32(header[8:12], acknowledgement)
	header[12], header[13] = byte(len(header)/4)<<4|byte(flags>>8)&1, byte(flags)
	binary.BigEndian.PutUint16(header[14:16], window)
	binary.BigEndian.PutUint16(header[16:18], 0)
	binary.BigEndian.PutUint16(header[18:20], urgent)
}

func tcpOptionsContentLength(options []byte) (int, bool) {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case TCPHeaderOptionEnd:
			return offset + 1, true
		case TCPHeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return 0, false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return 0, false
		}
		offset += length
	}
	return len(options), true
}

type KeepAliveConfig struct {
	Idle time.Duration
	Interval time.Duration
	Count int
}

type TCPState uint8

const (
	TCPStateClosed TCPState = iota
	TCPStateSYNReceived
	TCPStateSYNSent
	TCPStateEstablished
	TCPStateFINWait1
	TCPStateFINWait2
	TCPStateCloseWait
	TCPStateClosing
	TCPStateLastACK
	TCPStateTimeWait
)

func (s TCPState) String() string {
	switch s {
	case TCPStateSYNReceived:
		return "SYN-RECEIVED"
	case TCPStateSYNSent:
		return "SYN-SENT"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFINWait1:
		return "FIN-WAIT-1"
	case TCPStateFINWait2:
		return "FIN-WAIT-2"
	case TCPStateCloseWait:
		return "CLOSE-WAIT"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastACK:
		return "LAST-ACK"
	case TCPStateTimeWait:
		return "TIME-WAIT"
	default:
		return "CLOSED"
	}
}

type TCPConnInfo struct {
	LocalAddress netip.AddrPort
	RemoteAddress netip.AddrPort
	State TCPState
	CongestionControl string
	RTT time.Duration
	MinimumRTT time.Duration
	RTTVariation time.Duration
	RetransmissionTimeout time.Duration
	CongestionWindow uint32
	SlowStartThreshold uint32
	BytesInFlight uint32
	DeliveryRate uint64
	PacingRate uint64
	MaximumPacingRate uint64
	CongestionState string
	PeerWindow uint32
	ReceiveWindow uint32
	MaximumSegmentSize int
	PathMTU int
	SendBufferSize int
	SendBufferCapacity int
	MaximumSendBuffer int
	ReceiveBufferSize int
	ReceiveBufferCapacity int
	MaximumReceiveBuffer int
	BytesSent uint64
	BytesAcknowledged uint64
	BytesReceived uint64
	Retransmissions uint64
	InboundQueueDrops uint64
	InboundQueueBytes int64
	InboundQueuePeak int64
	InboundQueueCapacity int
	FastRecovery bool
	RetransmissionRecovery bool
	HyStartCSS bool
	PathMTUDiscovery bool
	PathMTUProbe int
	WindowScaling bool
	PeerWindowScale uint8
	ReceiveWindowScale uint8
	SACK bool
	Timestamps bool
	ECN bool
	KeepAlive bool
	KeepAliveConfig KeepAliveConfig
	IdleTimeout time.Duration
	UserTimeout time.Duration
	NoDelay bool
	TrafficClass uint8
	FlowLabel uint32
	SpuriousRecoveryUndos uint64
	PathMTUProbes uint64
	PathMTUProbeSuccesses uint64
	PathMTUProbeFailures uint64
	ApplicationLimited bool
	SchedulerLimited bool
	SchedulerLimitedEvents uint64
	LastError error
}

type tcpSocketOptions struct {
	keepAlive         bool
	keepAliveConfig   KeepAliveConfig
	idleTimeout       time.Duration
	userTimeout       time.Duration
	noDelay           bool
	congestionFactory *CongestionControlFactory
	maximumPacingRate uint64
}

type tcpInitialReceive struct {
	payload []byte
	fin     bool
}

type tcpNetwork byte

const (
	tcpNetworkGeneric tcpNetwork = iota
	tcpNetworkIPv4
	tcpNetworkIPv6
)

func newTCPNetwork(network string) tcpNetwork {
	switch network {
	case "tcp4":
		return tcpNetworkIPv4
	case "tcp6":
		return tcpNetworkIPv6
	default:
		return tcpNetworkGeneric
	}
}

func (n tcpNetwork) name() string {
	switch n {
	case tcpNetworkIPv4:
		return "tcp4"
	case tcpNetworkIPv6:
		return "tcp6"
	default:
		return "tcp"
	}
}

type tcpSegment struct {
	sequence        uint32
	acknowledgement uint32
	flags           byte
	window          uint16
	ecn             byte
	optionLength    uint8
	options         [40]byte
	payload         []byte
	retainedBytes   int64
	receivedAt      monotonicStamp
}

func (s *tcpSegment) setOptions(options []byte) {
	if len(options) > len(s.options) {
		panic("mipstack: TCP options exceed header capacity")
	}
	s.optionLength = uint8(copy(s.options[:], options))
}

func (s *tcpSegment) optionBytes() []byte { return s.options[:s.optionLength] }

type tcpSegmentQueue struct {
	mu       sync.Mutex
	segments []tcpSegment
	spare    []byte
	head     int
	bytes    int64
	peak     int64
	closed   bool
	burst  bool
	notify chan struct{}
}

func newTCPSegmentQueue() tcpSegmentQueue {
	return tcpSegmentQueue{notify: make(chan struct{}, 1)}
}

func (q *tcpSegmentQueue) enqueue(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.payload))
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	q.enqueueLocked(segment, retained)
	q.mu.Unlock()
	return true
}

func (q *tcpSegmentQueue) enqueueCopy(segment tcpSegment, payload []byte) bool {
	retained := int64(tcpInboundSegmentMetadata + len(payload))
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	if len(payload) != 0 {
		var owned []byte
		if cap(q.spare) >= len(payload) {
			owned = q.spare[:len(payload)]
			q.spare = nil
		} else {
			owned = make([]byte, len(payload))
		}
		copy(owned, payload)
		segment.payload = owned[:len(owned):len(owned)]
	}
	q.enqueueLocked(segment, retained)
	q.mu.Unlock()
	return true
}

func (q *tcpSegmentQueue) enqueueLocked(segment tcpSegment, retained int64) {
	empty := q.head == len(q.segments)
	if q.head != 0 && len(q.segments) == cap(q.segments) && q.head*2 >= len(q.segments) {
		remaining := copy(q.segments, q.segments[q.head:])
		for index := remaining; index < len(q.segments); index++ {
			q.segments[index] = tcpSegment{}
		}
		q.segments = q.segments[:remaining]
		q.head = 0
	}
	if q.segments == nil {
		capacity := tcpMetadataQueueInitial
		if q.burst {
			capacity = tcpMetadataQueueRetain
		}
		q.segments = make([]tcpSegment, 0, capacity)
	} else if q.head == 0 && len(q.segments) == cap(q.segments) && cap(q.segments) == tcpMetadataQueueInitial {
		segments := make([]tcpSegment, len(q.segments), tcpMetadataQueueRetain)
		copy(segments, q.segments)
		q.segments = segments
	}
	segment.retainedBytes = retained
	q.segments = append(q.segments, segment)
	q.bytes += retained
	if q.bytes > q.peak {
		q.peak = q.bytes
	}
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
}

func (q *tcpSegmentQueue) recyclePayload(payload []byte) {
	if cap(payload) == 0 || cap(payload) > tcpReusableReceivePayloadLimit {
		return
	}
	q.mu.Lock()
	if !q.closed && cap(payload) > cap(q.spare) {
		q.spare = payload[:0]
	}
	q.mu.Unlock()
}

func (q *tcpSegmentQueue) prepend(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.payload))
	segment.retainedBytes = retained
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	empty := q.head == len(q.segments)
	if q.head != 0 {
		q.head--
		q.segments[q.head] = segment
	} else {
		q.segments = append(q.segments, tcpSegment{})
		copy(q.segments[1:], q.segments[:len(q.segments)-1])
		q.segments[0] = segment
	}
	q.bytes += retained
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return true
}

func (q *tcpSegmentQueue) dequeue() (tcpSegment, bool) {
	q.mu.Lock()
	if q.head == len(q.segments) {
		q.mu.Unlock()
		return tcpSegment{}, false
	}
	segment := q.segments[q.head]
	q.segments[q.head] = tcpSegment{}
	q.head++
	q.bytes -= segment.retainedBytes
	segment.retainedBytes = 0
	if q.head == len(q.segments) {
		if cap(q.segments) <= tcpMetadataQueueRetain {
			q.segments = q.segments[:0]
		} else {
			q.burst = true
			q.segments = nil
		}
		q.head = 0
	} else {
		if q.head >= 1024 && q.head*2 >= len(q.segments) {
			copy(q.segments, q.segments[q.head:])
			q.segments = q.segments[:len(q.segments)-q.head]
			q.head = 0
		}
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return segment, true
}

func (q *tcpSegmentQueue) len() int {
	q.mu.Lock()
	length := len(q.segments) - q.head
	q.mu.Unlock()
	return length
}

func (q *tcpSegmentQueue) retainedBytes() int64 {
	q.mu.Lock()
	retained := q.bytes
	q.mu.Unlock()
	return retained
}

func (q *tcpSegmentQueue) peakBytes() int64 {
	q.mu.Lock()
	peak := q.peak
	q.mu.Unlock()
	return peak
}

func (q *tcpSegmentQueue) close() {
	q.mu.Lock()
	q.segments = nil
	q.spare = nil
	q.head = 0
	q.bytes = 0
	q.closed = true
	q.mu.Unlock()
}

type tcpTimerBacklog struct {
	deadline  time.Time
	remaining int
}

func (b *tcpTimerBacklog) order(queueLength int, deadline, now time.Time) (drain, forceTimer bool) {
	if deadline.IsZero() || now.Before(deadline) {
		b.deadline = time.Time{}
		b.remaining = 0
		return false, false
	}
	if b.deadline.IsZero() || !b.deadline.Equal(deadline) {
		b.deadline = deadline
		b.remaining = queueLength
	}
	return b.remaining != 0, b.remaining == 0
}

func (b *tcpTimerBacklog) consumed() {
	if b.remaining > 0 {
		b.remaining--
	}
}

func (b *tcpTimerBacklog) receiveBatchLength(queueLength int, forceTimer bool) int {
	if queueLength > tcpActorReceiveBatch {
		queueLength = tcpActorReceiveBatch
	}
	if b.remaining != 0 && queueLength > b.remaining {
		return b.remaining
	}
	if forceTimer && queueLength > 1 {
		return 1
	}
	return queueLength
}

var tcpZeroWindowProbe = [...]byte{0}

type tcpReceiveWindow struct {
	right uint32
	shift uint8
}

func newTCPReceiveWindow(receiveNext uint32, initial uint16, scaled, initialScaled bool, scale uint8) tcpReceiveWindow {
	initialBytes := uint32(initial)
	window := tcpReceiveWindow{}
	if scaled {
		window.shift = scale
	}
	if initialScaled {
		initialBytes <<= window.shift
	}
	window.right = receiveNext + initialBytes
	return window
}

func tcpReceiveWindowScaleFor(maximum int) uint8 {
	if maximum <= 65535 {
		return 0
	}
	var scale uint8
	for scale < 14 && uint64(65535)<<scale < uint64(maximum) {
		scale++
	}
	return scale
}

func (w *tcpReceiveWindow) next(receiveNext uint32, available, minimumIncrease int) (uint16, uint32) {
	if available < 0 {
		available = 0
	}
	maximum := uint32(65535) << w.shift
	if uint64(available) > uint64(maximum) {
		available = int(maximum)
	}
	desired := receiveNext + uint32(available>>w.shift)<<w.shift
	right := w.right
	if tcpSequenceGreater(desired, right) {
		increase := desired - right
		if minimumIncrease < 0 {
			minimumIncrease = 0
		}
		if increase >= uint32(minimumIncrease) {
			right = desired
		}
	}
	if tcpSequenceLess(right, receiveNext) {
		return 0, right
	}
	return uint16((right - receiveNext) >> w.shift), right
}

func (w *tcpReceiveWindow) size(receiveNext uint32) uint32 {
	if tcpSequenceLess(w.right, receiveNext) {
		return 0
	}
	return w.right - receiveNext
}

func tcpReceiveWindowIncrease(capacity, mss int) int {
	if capacity < 1 {
		return 0
	}
	threshold := capacity/2 + capacity%2
	if mss > 0 && threshold > mss {
		threshold = mss
	}
	return threshold
}

type tcpBufferAutoTune struct {
	updated time.Time
	bytes   uint64
}

func (t *tcpBufferAutoTune) target(now time.Time, rtt time.Duration, total uint64, maximum int) int {
	if rtt <= 0 {
		return 0
	}
	if t.updated.IsZero() {
		t.updated, t.bytes = now, total
		return 0
	}
	elapsed := now.Sub(t.updated)
	interval := rtt
	if interval < tcpAutoTuneMinimumInterval {
		interval = tcpAutoTuneMinimumInterval
	}
	if elapsed < interval {
		return 0
	}
	delta := total - t.bytes
	t.updated, t.bytes = now, total
	if delta == 0 {
		return 0
	}
	perRTT := delta
	if elapsed > rtt {
		perRTT = uint64(float64(delta) * float64(rtt) / float64(elapsed))
	}
	if maximum <= 0 {
		return 0
	}
	if perRTT > uint64(maximum/2) {
		perRTT = uint64(maximum / 2)
	}
	return int(perRTT * 2)
}

type sentTCPSegmentState uint16

const (
	sentTCPSegmentSACKed sentTCPSegmentState = 1 << iota
	sentTCPSegmentSACKRetried
	sentTCPSegmentRACKLost
	sentTCPSegmentLimited
	sentTCPSegmentCWR
	sentTCPSegmentSACKSplit
	sentTCPSegmentMTUProbe
	sentTCPSegmentDeliverySchedulerLimited
	sentTCPSegmentTransmitted
	sentTCPSegmentRetransmitted
	sentTCPSegmentLossReported
)

func (s sentTCPSegmentState) has(flag sentTCPSegmentState) bool { return s&flag != 0 }

func (s *sentTCPSegmentState) set(flag sentTCPSegmentState, enabled bool) {
	if enabled {
		*s |= flag
	} else {
		*s &^= flag
	}
}

func sentTCPSegmentInitialState(limited, cwr, mtuProbe, schedulerLimited bool) sentTCPSegmentState {
	state := sentTCPSegmentTransmitted
	if limited {
		state |= sentTCPSegmentLimited
	}
	if cwr {
		state |= sentTCPSegmentCWR
	}
	if mtuProbe {
		state |= sentTCPSegmentMTUProbe
	}
	if schedulerLimited {
		state |= sentTCPSegmentDeliverySchedulerLimited
	}
	return state
}

type sentTCPSegment struct {
	sequence              uint32
	end                   uint32
	timestamp             uint32
	state                 sentTCPSegmentState
	flags                 byte
	_                     [1]byte
	firstSent             time.Duration
	hostQueue             packetQueueTicket
	congestionPacketState uint64
	delivery              tcpDeliverySnapshot
	transmissionOrder     uint32
}

func (s *sentTCPSegment) dataSize() int {
	size := s.end - s.sequence
	if s.flags&TCPFlagFIN != 0 && size != 0 {
		size--
	}
	return int(size)
}

func (s *sentTCPSegment) isTransmitted() bool {
	return s.state.has(sentTCPSegmentTransmitted)
}

func (s *sentTCPSegment) isRetransmitted() bool {
	return s.state.has(sentTCPSegmentRetransmitted)
}

func (s *sentTCPSegment) lossAlreadyReported() bool {
	return s.state.has(sentTCPSegmentLossReported)
}

func (s *sentTCPSegment) advanceTransmissionGeneration() {
	s.state |= sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted
	s.state &^= sentTCPSegmentLossReported
}

func (s *sentTCPSegment) transmittedAt(epoch time.Time) time.Time {
	return s.hostQueue.queuedTime(epoch)
}

type tcpPLPMTU struct {
	searchLow  int
	searchHigh int
	probeMTU   int
	probeStart uint32
	probeEnd   uint32
	nextProbe  time.Time
	searching  bool
	active     bool
}

func (p *tcpPLPMTU) start(base, maximum int, now time.Time) {
	if maximum-base < tcpPLPMTUProbeThreshold {
		*p = tcpPLPMTU{}
		return
	}
	*p = tcpPLPMTU{searchLow: base, searchHigh: maximum, nextProbe: now, searching: true}
}

func (p *tcpPLPMTU) candidate(now time.Time) (int, bool) {
	if !p.searching || p.active || now.Before(p.nextProbe) || p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		return 0, false
	}
	return p.searchLow + (p.searchHigh-p.searchLow+1)/2, true
}

func (p *tcpPLPMTU) sent(mtu int, start, end uint32) {
	p.probeMTU, p.probeStart, p.probeEnd, p.active = mtu, start, end, true
}

func (p *tcpPLPMTU) success(now time.Time) int {
	mtu := p.probeMTU
	p.searchLow = mtu
	p.active = false
	p.probeMTU = 0
	p.nextProbe = now
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
	return mtu
}

func (p *tcpPLPMTU) failed(now time.Time, headway time.Duration) {
	if p.probeMTU > 0 && p.probeMTU-1 < p.searchHigh {
		p.searchHigh = p.probeMTU - 1
	}
	p.active = false
	p.probeMTU = 0
	if headway < tcpPLPMTUProbeMinimumInterval {
		headway = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(headway)
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
}

func (p *tcpPLPMTU) inconclusive(now time.Time, delay time.Duration) {
	p.active = false
	p.probeMTU = 0
	if delay < tcpPLPMTUProbeMinimumInterval {
		delay = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(delay)
}

func tcpPLPMTUProbeHeadway(window uint32, mss int, roundTrip time.Duration) time.Duration {
	if mss < 1 {
		mss = 1
	}
	if roundTrip <= 0 {
		roundTrip = tcpInitialRTO
	}
	packets := (uint64(window) + uint64(mss) - 1) / uint64(mss)
	if packets == 0 {
		packets = 1
	}
	const maximum = time.Duration(1<<63 - 1)
	if packets > uint64(maximum/roundTrip) {
		return maximum
	}
	headway := time.Duration(packets) * roundTrip
	if headway < tcpPLPMTUProbeMinimumInterval {
		return tcpPLPMTUProbeMinimumInterval
	}
	return headway
}

func tcpPLPMTUTimeoutDelay(headway time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if headway > maximum/5 {
		return maximum
	}
	return 5 * headway
}

func tcpCongestionValueForMSS(value uint32, oldMSS, newMSS int, floor bool) uint32 {
	if value == 0 || oldMSS < 1 || newMSS < 1 || newMSS >= oldMSS {
		return value
	}
	value = uint32(uint64(value) * uint64(newMSS) / uint64(oldMSS))
	if floor && value < uint32(newMSS) {
		return uint32(newMSS)
	}
	return value
}

func (p *tcpPLPMTU) reduce(mtu, prior, maximum int, now time.Time) {
	high := maximum
	if prior > mtu && prior-1 < high {
		high = prior - 1
	}
	p.start(mtu, high, now.Add(pathMTULifetime))
}

type tcpUndoRange struct {
	sequence   uint32
	end        uint32
	duplicated bool
}

type tcpRecoveryUndo struct {
	active              bool
	timeout             bool
	eifelChecked        bool
	dsackDisabled       bool
	retransmitTimestamp uint32
	point               uint32
	priorThreshold      uint32
	priorFlight         uint32
	spuriousUndos uint64
	priorSRTT, priorRTTVar time.Duration
	ranges                 []tcpUndoRange
	transport *tcpRecoveryTransportState
}

type tcpRecoveryTransportState struct {
	phase                                   CongestionPhase
	recoveryPoint, rtoRecoveryPoint         uint32
	ecnRecoveryPoint, prrPriorFlight        uint32
	prrDelivered, prrOut                    uint64
	rtoAttempts                             int
	frtoProbeBudget                         uint8
	fastRecovery, rtoRecovery               bool
	frtoState                               tcpFRTOState
	sackRenegingRecovery, ecnRecoveryActive bool
	captured                                bool
}

type tcpEifelRTOResponse struct {
	point          uint32
	previousSRTT   time.Duration
	previousRTTVar time.Duration
	pending        bool
}

type tcpRetransmissionRecord struct {
	sequence uint32
	end      uint32
	count    int
}

type tcpRetransmissionHistory struct {
	ranges []tcpRetransmissionRecord
}

func (u *tcpRecoveryUndo) begin(timeout bool, point, window, threshold, flight uint32, controller *tcpCongestionController, rtt rttEstimator) {
	controller.checkpointRecovery(time.Now(), window, threshold, flight, controller.state.MaximumSegmentSize)
	spuriousUndos := u.spuriousUndos
	transport := u.transport
	*u = tcpRecoveryUndo{
		active: true, timeout: timeout, point: point,
		priorThreshold: threshold, priorFlight: flight, spuriousUndos: spuriousUndos,
		priorSRTT: rtt.srtt, priorRTTVar: rtt.variation, transport: transport,
	}
	if u.transport != nil {
		*u.transport = tcpRecoveryTransportState{}
	}
}

func (u *tcpRecoveryUndo) setTransport(transport tcpRecoveryTransportState) {
	if !transport.captured {
		return
	}
	if u.transport == nil {
		u.transport = new(tcpRecoveryTransportState)
	}
	*u.transport = transport
}

func (u *tcpRecoveryUndo) recordRetransmission(sequence, end, timestamp uint32, repeated bool) {
	if !u.active {
		return
	}
	if repeated {
		u.dsackDisabled = true
	}
	if u.retransmitTimestamp == 0 {
		u.retransmitTimestamp = timestamp
	}
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if candidate.sequence == sequence && candidate.end == end {
			return
		}
	}
	u.ranges = append(u.ranges, tcpUndoRange{sequence: sequence, end: end})
}

func (u *tcpRecoveryUndo) detectEifel(timestampEcho uint32, currentDSACK, priorDSACK bool, acknowledgement uint32) bool {
	if !u.active || u.eifelChecked || u.retransmitTimestamp == 0 || timestampEcho == 0 {
		return false
	}
	u.eifelChecked = true
	if !tcpSequenceLess(timestampEcho, u.retransmitTimestamp) || currentDSACK {
		return false
	}
	return priorDSACK || tcpSequenceLess(acknowledgement, u.point)
}

func (u *tcpRecoveryUndo) observeDSACK(block TCPSACKBlock, acknowledgement, sendUnacknowledged uint32, scoreboardEmpty bool) bool {
	if !u.active || u.dsackDisabled {
		return false
	}
	if scoreboardEmpty && block.LeftEdge == sendUnacknowledged {
		u.dsackDisabled = true
		return false
	}
	matched := false
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if tcpSequenceLessEqual(block.LeftEdge, candidate.sequence) && tcpSequenceGreaterEqual(block.RightEdge, candidate.end) {
			candidate.duplicated = true
			matched = true
		}
	}
	if !matched {
		u.dsackDisabled = true
		return false
	}
	if len(u.ranges) == 0 {
		return false
	}
	for _, candidate := range u.ranges {
		if !candidate.duplicated || tcpSequenceLess(acknowledgement, candidate.end) {
			return false
		}
	}
	return true
}

func (u *tcpRecoveryUndo) restore(currentWindow, flight, acknowledged uint32, mss int, current *tcpCongestionController, now time.Time, phase CongestionPhase) (uint32, uint32) {
	credit := acknowledged
	if initial := initialTCPWindow(mss); credit > initial {
		credit = initial
	}
	window := growCongestionWindow(flight, credit)
	if window < uint32(mss) {
		window = uint32(mss)
	}
	threshold := u.priorFlight
	if threshold < u.priorThreshold {
		threshold = u.priorThreshold
	}
	window, threshold = current.undoRecovery(now, currentWindow, window, threshold, flight, mss, phase)
	u.active = false
	return window, threshold
}

func (u *tcpRecoveryUndo) eifelRTOResponse() tcpEifelRTOResponse {
	if !u.timeout {
		return tcpEifelRTOResponse{}
	}
	return tcpEifelRTOResponse{
		point: u.point, previousSRTT: u.priorSRTT + 2*tcpEifelClockGranularity,
		previousRTTVar: u.priorRTTVar, pending: true,
	}
}

func (e *tcpEifelRTOResponse) observe(acknowledgement uint32, sample time.Duration, rtt *rttEstimator) bool {
	if !e.pending || sample <= 0 || !tcpSequenceGreater(acknowledgement, e.point) {
		return false
	}
	sample = normalizedRTTSample(sample)
	rtt.srtt = e.previousSRTT
	if rtt.srtt < sample {
		rtt.srtt = sample
	}
	rtt.variation = e.previousRTTVar
	if half := sample / 2; rtt.variation < half {
		rtt.variation = half
	}
	rtt.initialized = true
	rtt.updateRTO()
	e.pending = false
	return true
}

func (h *tcpRetransmissionHistory) record(sequence, end uint32) {
	for index := len(h.ranges) - 1; index >= 0; index-- {
		rangeState := &h.ranges[index]
		if rangeState.sequence == sequence && rangeState.end == end {
			rangeState.count++
			return
		}
	}
	repeated := false
	for index := range h.ranges {
		rangeState := &h.ranges[index]
		if tcpSequenceLess(sequence, rangeState.end) && tcpSequenceLess(rangeState.sequence, end) {
			repeated = true
			if rangeState.count < 2 {
				rangeState.count = 2
			}
		}
	}
	if len(h.ranges) == tcpRetransmissionHistoryLimit {
		copy(h.ranges, h.ranges[1:])
		h.ranges = h.ranges[:len(h.ranges)-1]
	}
	count := 1
	if repeated {
		count = 2
	}
	h.ranges = append(h.ranges, tcpRetransmissionRecord{sequence: sequence, end: end, count: count})
}

func (h *tcpRetransmissionHistory) match(block TCPSACKBlock) (bool, bool) {
	matched, repeated := false, false
	for _, rangeState := range h.ranges {
		if tcpSequenceLessEqual(block.LeftEdge, rangeState.sequence) && tcpSequenceGreaterEqual(block.RightEdge, rangeState.end) {
			matched = true
			repeated = repeated || rangeState.count > 1
		}
	}
	return matched, repeated
}

type tcpRACKSample struct {
	sentAt        time.Time
	end           uint32
	order         uint32
	rtt           time.Duration
	timestamp     uint32
	retransmitted bool
}

type tcpEstablishedLivenessState struct {
	zeroWindowSince, lastKeepAlive time.Time
	lastSoftError                  error
	keepAliveProbes                int
}

type tcpEstablishedPathMTUState struct {
	discovery                   tcpPLPMTU
	blackHoleExpiry             time.Time
	probes, successes, failures uint64
	blackHoleMTU                int
}

type tcpSendTimerState struct {
	baseDeadline    time.Time
	persistRTO      time.Duration
	persistAttempts int
}

type tcpEstablishedState struct {
	connection *TCPConn
	peerMSS, pathMSS, receiveMSS                int
	peerWindow, peerWindowSequence              uint32
	maximumPeerWindow                           uint32
	bytesAcknowledged, bytesSent, bytesReceived uint64
	sendUnacknowledged, sendNext, receiveNext   uint32
	congestionWindow, slowStartThreshold        uint32
	ecnRecoveryPoint                            uint32
	outstanding, outstandingBase        []sentTCPSegment
	outstandingHead                     int
	outOfOrder                          []tcpReceivedPiece
	outOfOrderBytes                     int
	recentDSACK                         TCPSACKBlock
	duplicateACKs                       int
	recoveryPoint, rtoRecoveryPoint     uint32
	prrPriorFlight, recentSACK          uint32
	prrDelivered, prrOut                uint64
	lastACKSent, tailProbeEnd           uint32
	tailProbeBytes                      int
	tailProbeState, tailProbeRTTSamples uint64
	rtoAttempts                         int
	blackHoleRTOs                       int
	lastTimestampUpdate                 time.Time
	controller                          tcpCongestionController
	rackLatestDelivered                 tcpRACKSample
	rackForwardACK                      uint32
	rackReorderingScale, rackDSACKRound uint32
	rackReorderPersist                  int
	ecnHoldUntil                        time.Time
	lastTransmission, cwndUsageStamp    monotonicStamp
	cwndUsed, transmissionOrder         uint32
	receiveAutoTune, sendAutoTune       tcpBufferAutoTune
	hyStart                             tcpHyStart
	undo              *tcpRecoveryUndo
	eifelRTO          *tcpEifelRTOResponse
	retransmitHistory *tcpRetransmissionHistory
	sackedRanges      int
	sackedBytes       uint32
	rtt               rttEstimator
	actorTimerChannel                 <-chan time.Time
	actorTimerDeadline                time.Time
	retransmissionDeadline            time.Time
	sendTimer                         tcpSendTimerState
	delayedACKDeadline                time.Time
	livenessDeadline, pathMTUDeadline time.Time
	pacingDeadline                    time.Time
	deliverySample          *tcpDeliveryRateSample
	lastDataReceived        monotonicStamp
	lastAdvertisedWindow    uint16
	lastReceiveSegmentSize  uint16
	receiveWindowState      tcpReceiveWindow
	lastActivity, eventTime time.Time
	sackWorkspace *[34]byte
	livenessState *tcpEstablishedLivenessState
	pathMTUState  *tcpEstablishedPathMTUState

	peerScale, quickACKBudget, sackACKs, compressedSACKs uint8
	frtoProbeBudget                                      uint8
	peerSACK, haveRecentDSACK                            bool
	localFINSent, localFINAcked                          bool
	remoteFINReceived, timeWaitRequired                  bool
	finWaitArmed, timeWaitArmed, fastRecovery            bool
	limitedTransmitActive                                bool
	tailProbeActive, tailProbeRetransmit                 bool
	rtoRecovery, sackRenegingRecovery                    bool
	ecnRecoveryActive, ecnDataSeen                       bool
	rackForwardACKSet, rackReorderingSeen                bool
	rackDSACKRoundSet, seenDSACK                         bool
	dsackUndoDisabled, haveRACKLoss                      bool
	retransmit, persist, delayedACK                      bool
	ackPending, ackPingPong                              bool
	liveness, pathMTUProbe, pacing                       bool
	retransmissionKind                                   tcpRetransmissionKind
	frtoState                                            tcpFRTOState
}

type tcpFRTOState uint8

const (
	tcpFRTOInactive tcpFRTOState = iota
	tcpFRTOTimeoutPending
	tcpFRTOAwaitingACK
	tcpFRTOProbePending
	tcpFRTOProbeSent
	tcpFRTOFallbackPending
)

type tcpRetransmissionKind uint8

const (
	tcpRetransmissionRTO tcpRetransmissionKind = iota
	tcpRetransmissionProbe
	tcpRetransmissionRACK
	tcpRetransmissionSACKReneging
	tcpRetransmissionPathMTU
	tcpRetransmissionClose
)

type tcpRetransmissionUpdate uint8

const (
	tcpRetransmissionPreserve tcpRetransmissionUpdate = iota
	tcpRetransmissionReselect
	tcpRetransmissionRestart
)

type tcpOrdinaryOutputKind uint8

const (
	tcpOrdinaryOutputNone tcpOrdinaryOutputKind = iota
	tcpOrdinaryOutputData
	tcpOrdinaryOutputFIN
	tcpOrdinaryOutputACK
)

func (s *tcpEstablishedState) ensureLivenessState() *tcpEstablishedLivenessState {
	if s.livenessState == nil {
		s.livenessState = new(tcpEstablishedLivenessState)
	}
	return s.livenessState
}

func (s *tcpEstablishedState) ensurePathMTUState() *tcpEstablishedPathMTUState {
	if s.pathMTUState == nil {
		s.pathMTUState = new(tcpEstablishedPathMTUState)
	}
	return s.pathMTUState
}

func newTCPEstablishedState(c *TCPConn, sendNext uint32) *tcpEstablishedState {
	rawPathMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	peerMSS := tcpEffectiveSendMSS(c.peerMSS, rawPathMSS, c.peerTimestamp)
	localMaximum := rawPathMSS
	if c.peerTimestamp {
		localMaximum -= tcpTimestampOptionSize
	}
	receiveMSS := localMaximum
	if receiveMSS > tcpDefaultReceiveMSS {
		receiveMSS = tcpDefaultReceiveMSS
	}
	options := c.socketOptions()
	now := time.Now()
	state := &tcpEstablishedState{
		connection: c,
		sendNext:   sendNext, sendUnacknowledged: sendNext,
		peerMSS: peerMSS, pathMSS: localMaximum, receiveMSS: receiveMSS,
		peerScale: c.peerWindowScale, peerSACK: c.peerSACK,
		peerWindow: c.peerWindow, peerWindowSequence: c.peerWindowSeq,
		maximumPeerWindow: c.peerWindow,
		receiveNext:       c.receiveNext, lastACKSent: c.receiveNext,
		congestionWindow: initialTCPWindow(peerMSS), slowStartThreshold: ^uint32(0) >> 1,
		lastTimestampUpdate: now, rackReorderingScale: 1,
		cwndUsageStamp: monotonicStampAt(c.stack.timestampEpoch, now),
		sendTimer:      tcpSendTimerState{persistRTO: time.Second},
		controller: newTCPCongestionControllerFromFactory(options.congestionFactory, CongestionControlContext{
			LocalAddress: c.key.local, RemoteAddress: c.key.remote,
			Passive: c.passive, Forwarded: c.forwarded,
		}),
	}
	state.controller.setMaximumPacingRate(options.maximumPacingRate)
	c.publishICMPSequenceRange(state.sendUnacknowledged, state.sendNext)
	initialDataRTO := tcpInitialRTO
	if c.handshakeTimeout {
		initialDataRTO = 3 * time.Second
	}
	state.rtt = newRTTEstimator(initialDataRTO)
	if !c.handshakeTimeout {
		state.rtt.observeAt(c.handshakeRTT, monotonicStampAt(c.stack.timestampEpoch, now))
	}
	state.congestionWindow, state.slowStartThreshold = state.controller.initialize(now, state.rtt.minimum, state.rtt.srtt, state.congestionWindow, state.slowStartThreshold, state.peerMSS, monotonicStampAt(c.stack.timestampEpoch, now))
	initialWindowScaled := c.peerWindowScaling && !c.passive
	state.lastAdvertisedWindow = c.receiveWindow(0, initialWindowScaled)
	state.receiveWindowState = newTCPReceiveWindow(state.receiveNext, state.lastAdvertisedWindow, c.peerWindowScaling, initialWindowScaled, c.receiveWindowScale)
	state.receiveAutoTune.updated = now
	state.receiveAutoTune.bytes = c.applicationReads.Load()
	state.sendAutoTune.updated = now
	state.hyStart.start(state.sendNext)
	state.lastActivity = now
	state.eventTime = now
	return state
}

func (s *tcpEstablishedState) finish() {
	defer s.controller.release(time.Now(), s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	c := s.connection
	if c.takeAbortReset() {
		sequence := tcpAcceptableSendSequence(s.sendUnacknowledged, s.sendNext, s.peerWindow, s.peerScale)
		window, _ := s.nextAdvertisedReceiveWindow()
		_ = c.sendAbortReset(sequence, s.receiveNext, window)
	}
	info := s.tcpInfo()
	c.lastInfo.Store(&info)
}

func (s *tcpEstablishedState) compactOutstanding() {
	if s.outstandingHead == 0 {
		return
	}
	if len(s.outstanding) == 0 {
		s.outstanding, s.outstandingBase, s.outstandingHead = nil, nil, 0
		return
	}
	storage := s.outstandingBase[:s.outstandingHead+len(s.outstanding)]
	copy(storage, s.outstanding)
	for index := len(s.outstanding); index < len(storage); index++ {
		storage[index] = sentTCPSegment{}
	}
	s.outstanding = storage[:len(s.outstanding)]
	s.outstandingHead = 0
}

func (s *tcpEstablishedState) appendOutstanding(segment sentTCPSegment, moreDataAvailable bool) {
	if s.outstanding == nil {
		capacity := 1
		if segment.dataSize() != 0 {
			capacity = tcpSmallOutstandingCapacity
			if moreDataAvailable {
				capacity = tcpInitialOutstandingCapacity
			}
		}
		s.outstandingBase = make([]sentTCPSegment, 0, capacity)
		s.outstanding = s.outstandingBase
	}
	if len(s.outstanding) == cap(s.outstanding) {
		if s.outstandingHead != 0 {
			s.compactOutstanding()
		}
		if len(s.outstanding) == cap(s.outstanding) && cap(s.outstanding) == tcpSmallOutstandingCapacity {
			storage := make([]sentTCPSegment, len(s.outstanding), tcpInitialOutstandingCapacity)
			copy(storage, s.outstanding)
			s.outstandingBase = storage[:0]
			s.outstanding = storage
			s.outstandingHead = 0
		}
	}
	priorCapacity := cap(s.outstanding)
	s.outstanding = append(s.outstanding, segment)
	if cap(s.outstanding) != priorCapacity {
		s.outstandingBase = s.outstanding[:0]
		s.outstandingHead = 0
	}
}

func (s *tcpEstablishedState) rebaseOutstanding() {
	if len(s.outstanding) == 0 {
		s.outstanding, s.outstandingBase, s.outstandingHead = nil, nil, 0
		return
	}
	s.outstandingBase = s.outstanding[:0]
	s.outstandingHead = 0
}

func (s *tcpEstablishedState) ordinaryFlight() uint32 {
	flight := s.sendNext - s.sendUnacknowledged
	if s.sackedBytes > flight {
		return 0
	}
	return flight - s.sackedBytes
}

func (s *tcpEstablishedState) congestionFlight() uint32 {
	if s.peerSACK && s.fastRecovery {
		return sackRecoveryPipe(s.outstanding, s.peerMSS)
	}
	return s.ordinaryFlight()
}

func (s *tcpEstablishedState) recountSACK() {
	s.sackedRanges, s.sackedBytes = tcpSACKedState(s.outstanding)
}

func (s *tcpEstablishedState) recordRetransmission(start, end uint32) {
	if s.retransmitHistory == nil {
		s.retransmitHistory = new(tcpRetransmissionHistory)
	}
	s.retransmitHistory.record(start, end)
}

func (s *tcpEstablishedState) recordProvenLosses(duringACK bool, observedAt time.Time) {
	if !s.controller.usesLossEvents() {
		s.controller.noteLoss(recordProvenTCPLosses(s.outstanding, s.peerMSS), duringACK)
		return
	}
	if !duringACK {
		observedAt = time.Now()
	}
	recordProvenTCPLossesWith(s.outstanding, s.peerMSS, func(segment *sentTCPSegment, bytes uint32) {
		s.controller.notePacketLoss(segment, bytes, duringACK, observedAt, s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt)
	})
}

func (s *tcpEstablishedState) connectionState() TCPState {
	switch {
	case s.timeWaitArmed:
		return TCPStateTimeWait
	case !s.localFINSent && s.remoteFINReceived:
		return TCPStateCloseWait
	case !s.localFINSent:
		return TCPStateEstablished
	case !s.localFINAcked && !s.timeWaitRequired:
		return TCPStateLastACK
	case !s.localFINAcked && s.remoteFINReceived:
		return TCPStateClosing
	case !s.localFINAcked:
		return TCPStateFINWait1
	case !s.remoteFINReceived:
		return TCPStateFINWait2
	default:
		return TCPStateClosed
	}
}

type tcpTimeWaitReplacer func(*Stack, *TCPConn, tcpSegment) bool

func (s *tcpEstablishedState) handleTimeWaitSegment(segment tcpSegment, receivedAt, handledAt time.Time) bool {
	if segment.flags&TCPFlagRST != 0 {
		return false
	}
	if segment.flags&TCPFlagSYN != 0 {
		if segment.flags&(TCPFlagACK|TCPFlagFIN) != 0 {
			if segment.flags&TCPFlagACK != 0 {
				s.refreshTimeWaitTimer(handledAt)
			}
			s.trySendChallengeACK()
			return false
		}
		sequenceNew := tcpSequenceGreater(segment.sequence, s.receiveNext)
		timestampNew, pawsReject := false, false
		timestamp, _, present := parseTCPTimestamp(segment.optionBytes())
		if present {
			if s.connection.peerTimestamp {
				pawsReject = tcpPAWSReject(timestamp, s.connection.recentTimestamp, s.lastTimestampUpdate, receivedAt, 0)
				timestampNew = !pawsReject && tcpSequenceGreater(timestamp, s.connection.recentTimestamp)
			} else {
				timestampNew = true
			}
		}
		if pawsReject || !sequenceNew && !timestampNew {
			if pawsReject {
				s.refreshTimeWaitTimer(handledAt)
			}
			s.trySendChallengeACK()
			return false
		}
		if s.connection.stack.tryReplaceTCPTimeWait(s.connection, segment) {
			return true
		}
		if segment.flags&TCPFlagACK != 0 {
			s.refreshTimeWaitTimer(handledAt)
		}
		s.trySendChallengeACK()
		return false
	}
	var timestamp uint32
	present := false
	if s.connection.peerTimestamp {
		timestamp, _, present = parseTCPTimestamp(segment.optionBytes())
		if present && tcpPAWSReject(timestamp, s.connection.recentTimestamp, s.lastTimestampUpdate, receivedAt, 0) {
			s.refreshTimeWaitTimer(handledAt)
			s.trySendChallengeACK()
			return false
		}
	}
	retransmittedFIN := segment.flags&(TCPFlagSYN|TCPFlagRST) == 0 && segment.flags&(TCPFlagACK|TCPFlagFIN) == TCPFlagACK|TCPFlagFIN &&
		segment.sequence+uint32(len(segment.payload))+1 == s.receiveNext
	if !retransmittedFIN && !tcpSegmentAcceptable(segment.sequence, uint32(len(segment.payload)), s.receiveNext, s.receiveWindowState.size(s.receiveNext)) {
		if segment.flags&TCPFlagACK != 0 {
			s.refreshTimeWaitTimer(handledAt)
		}
		s.trySendACK()
		return false
	}
	if present && segment.flags&TCPFlagACK != 0 &&
		segment.flags&(TCPFlagSYN|TCPFlagFIN|TCPFlagRST) == 0 && len(segment.payload) == 0 &&
		segment.sequence == s.receiveNext {
		s.connection.recentTimestamp = timestamp
		s.lastTimestampUpdate = receivedAt
	}
	if retransmittedFIN {
		s.trySendACK()
		s.armClose(handledAt, tcpTimeWaitDuration)
		return false
	}
	if segment.flags&TCPFlagACK != 0 {
		s.refreshTimeWaitTimer(handledAt)
	}
	if segment.flags&TCPFlagACK == 0 || segment.sequence != s.receiveNext || len(segment.payload) != 0 {
		s.trySendACK()
	}
	return false
}

func (s *tcpEstablishedState) tcpInfo() TCPConnInfo {
	c := s.connection
	c.mu.Lock()
	info := c.tcpConnInfoBaseLocked(s.connectionState())
	info.CongestionControl = s.controller.algorithmName()
	info.RTT, info.MinimumRTT, info.RTTVariation, info.RetransmissionTimeout = s.rtt.srtt, s.rtt.minimum, s.rtt.variation, s.rtt.rto
	info.CongestionWindow, info.SlowStartThreshold = s.congestionWindow, s.slowStartThreshold
	info.BytesInFlight = s.congestionFlight()
	diagnostics := s.controller.diagnostics(time.Now(), s.congestionWindow, s.slowStartThreshold, info.BytesInFlight, s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	info.DeliveryRate, info.PacingRate = diagnostics.DeliveryRate, diagnostics.PacingRate
	info.CongestionState = diagnostics.State
	info.ApplicationLimited, info.SchedulerLimited = diagnostics.ApplicationLimited, diagnostics.SchedulerLimited
	info.SchedulerLimitedEvents = diagnostics.SchedulerLimitedEvents
	info.MaximumPacingRate = s.controller.maximumPacingRate
	info.PeerWindow, info.ReceiveWindow = s.peerWindow, s.receiveWindowState.size(s.receiveNext)
	info.MaximumSegmentSize, info.PathMTU = s.peerMSS, c.mtu
	dataAcknowledged := s.bytesAcknowledged
	if dataAcknowledged > s.bytesSent {
		dataAcknowledged = s.bytesSent
	}
	info.BytesSent, info.BytesAcknowledged, info.BytesReceived = s.bytesSent, dataAcknowledged, s.bytesReceived
	info.FastRecovery, info.RetransmissionRecovery, info.HyStartCSS = s.fastRecovery, s.rtoRecovery, s.hyStart.css
	if s.undo != nil {
		info.SpuriousRecoveryUndos = s.undo.spuriousUndos
	}
	if s.pathMTUState != nil {
		info.PathMTUDiscovery, info.PathMTUProbe = s.pathMTUState.discovery.searching, s.pathMTUState.discovery.probeMTU
		info.PathMTUProbes = s.pathMTUState.probes
		info.PathMTUProbeSuccesses, info.PathMTUProbeFailures = s.pathMTUState.successes, s.pathMTUState.failures
	}
	c.mu.Unlock()
	return info
}

func (s *tcpEstablishedState) nextAdvertisedReceiveWindow() (uint16, uint32) {
	available, capacity := s.connection.receiveSpace(s.outOfOrderBytes)
	return s.receiveWindowState.next(s.receiveNext, available, tcpReceiveWindowIncrease(capacity, s.receiveMSS))
}

func (s *tcpEstablishedState) effectivePathMTU() int {
	c := s.connection
	mtu := c.stack.mtuFor(c.key.remote.Addr())
	if s.pathMTUState != nil && s.pathMTUState.blackHoleMTU > 0 && s.pathMTUState.blackHoleMTU < mtu {
		mtu = s.pathMTUState.blackHoleMTU
	}
	return mtu
}

func (s *tcpEstablishedState) armPacingAt(deadline time.Time) {
	s.pacing = true
	s.pacingDeadline = deadline
}

func (s *tcpEstablishedState) keepAliveEligible() bool {
	if len(s.outstanding) != 0 {
		return false
	}
	offset := int(s.sendNext - s.sendUnacknowledged)
	total, writeClosed, _ := s.connection.sendState()
	return offset >= total && (!writeClosed || s.localFINSent)
}

func (s *tcpEstablishedState) userTimeoutDeadline(now time.Time, timeout time.Duration) time.Time {
	if timeout <= 0 {
		if s.livenessState != nil {
			s.livenessState.zeroWindowSince = time.Time{}
		}
		return time.Time{}
	}
	var oldest time.Time
	if len(s.outstanding) != 0 {
		index := 0
		if s.sackedRanges != 0 {
			index = firstUnsackedSegment(s.outstanding)
		}
		oldest = s.connection.stack.timestampEpoch.Add(s.outstanding[index].firstSent)
	}
	offset := int(s.sendNext - s.sendUnacknowledged)
	total, writeClosed, _ := s.connection.sendState()
	zeroWindowBlocked := s.peerWindow == 0 && (offset < total || writeClosed && !s.localFINSent)
	if zeroWindowBlocked {
		liveness := s.ensureLivenessState()
		if liveness.zeroWindowSince.IsZero() {
			liveness.zeroWindowSince = now
		}
		if oldest.IsZero() || liveness.zeroWindowSince.Before(oldest) {
			oldest = liveness.zeroWindowSince
		}
	} else if s.livenessState != nil {
		s.livenessState.zeroWindowSince = time.Time{}
	}
	if oldest.IsZero() {
		return time.Time{}
	}
	return oldest.Add(timeout)
}

func (s *tcpEstablishedState) ageRACKReordering() {
	if s.rackReorderPersist <= 0 {
		return
	}
	s.rackReorderPersist--
	if s.rackReorderPersist == 0 {
		s.rackReorderingScale = 1
	}
}

func (s *tcpEstablishedState) observeRACKReordering(end uint32, retransmitted bool) {
	if rackAdvanceForwardACK(&s.rackForwardACK, &s.rackForwardACKSet, end, retransmitted) {
		s.rackReorderingSeen = true
	}
}

func (s *tcpEstablishedState) rackDeadline(now time.Time, haveSACKed bool) (time.Time, bool) {
	if !s.peerSACK || len(s.outstanding) == 0 || !haveSACKed && !s.rackLatestDelivered.retransmitted {
		return time.Time{}, false
	}
	reorderingWindow := rackReorderingWindow(s.rtt.minimum, s.rtt.srtt, s.rackReorderingScale)
	if !s.rackReorderingSeen && (s.fastRecovery || s.rtoRecovery || s.sackedRanges >= tcpDuplicateACKThreshold) {
		reorderingWindow = 0
	}
	delay, exists := rackLossDelay(s.outstanding, s.rackLatestDelivered, now, reorderingWindow, s.connection.stack.timestampEpoch)
	if !exists {
		return time.Time{}, false
	}
	return now.Add(delay), true
}

func (s *tcpEstablishedState) armClose(startedAt time.Time, duration time.Duration) {
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	s.retransmissionDeadline = startedAt.Add(duration)
	s.retransmit = true
	s.retransmissionKind = tcpRetransmissionClose
	s.sendTimer.baseDeadline = time.Time{}
}

func (s *tcpEstablishedState) refreshTimeWaitTimer(handledAt time.Time) {
	if handledAt.IsZero() {
		handledAt = time.Now()
	}
	s.retransmissionDeadline = handledAt.Add(tcpTimeWaitDuration)
}

func (s *tcpEstablishedState) clearDelayedACK() {
	s.delayedACK = false
	s.delayedACKDeadline = time.Time{}
	s.ackPending = false
	s.compressedSACKs = 0
}

func (s *tcpEstablishedState) replenishQuickACK(maximum uint8) {
	quickACKs := uint32(2)
	if s.receiveMSS > 0 {
		window := s.receiveWindowState.size(s.receiveNext)
		quickACKs = window / (2 * uint32(s.receiveMSS))
		if quickACKs == 0 {
			quickACKs = 2
		}
	}
	if quickACKs > uint32(maximum) {
		quickACKs = uint32(maximum)
	}
	if uint8(quickACKs) > s.quickACKBudget {
		s.quickACKBudget = uint8(quickACKs)
	}
}

func (s *tcpEstablishedState) enterQuickACK(maximum uint8) {
	s.replenishQuickACK(maximum)
	s.ackPingPong = false
}

func (s *tcpEstablishedState) observeReceivedData(receivedAt time.Time) {
	stamp := monotonicStampAt(s.connection.stack.timestampEpoch, receivedAt)
	if s.lastDataReceived == 0 || stamp > s.lastDataReceived && time.Duration(stamp-s.lastDataReceived) > s.rtt.rto {
		s.replenishQuickACK(tcpMaximumQuickACKs)
	}
	s.lastDataReceived = stamp
}

func (s *tcpEstablishedState) observeDataECN(ecn byte) bool {
	if ecn == 0 {
		return s.ecnDataSeen
	}
	s.ecnDataSeen = true
	if ecn != 3 || s.connection.echoCongestion {
		return false
	}
	s.connection.echoCongestion = true
	return true
}

func (s *tcpEstablishedState) measureReceiveMSS(segment *tcpSegment) {
	segmentSize := len(segment.payload)
	fixedOptions := 0
	if s.connection.peerTimestamp {
		fixedOptions = tcpTimestampOptionSize
	}
	if optionSize := int(segment.optionLength); optionSize > fixedOptions {
		segmentSize += optionSize - fixedOptions
	}
	if segmentSize <= 0 {
		return
	}
	if segmentSize >= s.receiveMSS {
		if segmentSize > s.receiveMSS {
			s.receiveMSS = segmentSize
			if s.receiveMSS > s.pathMSS {
				s.receiveMSS = s.pathMSS
			}
		}
		s.lastReceiveSegmentSize = 0
		return
	}
	if segment.flags&(TCPFlagPSH|TCPFlagFIN) != 0 ||
		segmentSize < tcpMinimumPeerMSS && s.pathMSS >= tcpMinimumPeerMSS {
		s.lastReceiveSegmentSize = 0
		return
	}
	if s.lastReceiveSegmentSize == uint16(segmentSize) {
		s.receiveMSS = segmentSize
		s.lastReceiveSegmentSize = 0
		return
	}
	s.lastReceiveSegmentSize = uint16(segmentSize)
}

func (s *tcpEstablishedState) recordTransmission(ticket packetQueueTicket) uint32 {
	s.lastTransmission = ticket.queuedAt
	s.transmissionOrder++
	if s.transmissionOrder == 0 {
		s.transmissionOrder = 1
	}
	return s.transmissionOrder
}

func (s *tcpEstablishedState) observeSentData(sentAt monotonicStamp) {
	if s.lastDataReceived == 0 {
		return
	}
	if sentAt >= s.lastDataReceived && time.Duration(sentAt-s.lastDataReceived) < tcpDelayedACKTimeout {
		s.ackPingPong = true
	}
}

func (s *tcpEstablishedState) commitAcknowledgment(window uint16, right uint32, selective bool) {
	pending := s.ackPending
	selectivePending := s.peerSACK && (len(s.outOfOrder) != 0 || s.haveRecentDSACK)
	satisfied := selective || !selectivePending
	s.receiveWindowState.right = right
	s.lastACKSent = s.receiveNext
	s.lastAdvertisedWindow = window
	if pending && satisfied && s.quickACKBudget != 0 {
		s.quickACKBudget--
	}
	if satisfied {
		s.clearDelayedACK()
	}
}

func (s *tcpEstablishedState) armPathMTUProbe() {
	s.pathMTUProbe = false
	s.pathMTUDeadline = time.Time{}
	if s.pathMTUState != nil && s.pathMTUState.discovery.searching {
		if !s.pathMTUState.discovery.active && time.Now().Before(s.pathMTUState.discovery.nextProbe) {
			s.pathMTUProbe = true
			s.pathMTUDeadline = s.pathMTUState.discovery.nextProbe
		}
		return
	}
	c := s.connection
	expiry, exists := c.stack.pathMTUExpiry(c.key.remote.Addr())
	if s.pathMTUState != nil && !s.pathMTUState.blackHoleExpiry.IsZero() && (!exists || s.pathMTUState.blackHoleExpiry.Before(expiry)) {
		expiry, exists = s.pathMTUState.blackHoleExpiry, true
	}
	if exists {
		s.pathMTUProbe = true
		s.pathMTUDeadline = expiry
	}
}

func (s *tcpEstablishedState) armLiveness(keepAliveOutputPending bool) {
	s.liveness = false
	s.livenessDeadline = time.Time{}
	if s.localFINAcked && s.remoteFINReceived {
		return
	}
	options := s.connection.socketOptions()
	var deadline time.Time
	if options.idleTimeout > 0 {
		deadline = s.lastActivity.Add(options.idleTimeout)
	}
	if options.userTimeout > 0 {
		if userDeadline := s.userTimeoutDeadline(time.Now(), options.userTimeout); !userDeadline.IsZero() && (deadline.IsZero() || userDeadline.Before(deadline)) {
			deadline = userDeadline
		}
	} else if s.livenessState != nil {
		s.livenessState.zeroWindowSince = time.Time{}
	}
	if options.userTimeout > 0 && s.livenessState != nil && s.livenessState.keepAliveProbes != 0 {
		keepAliveUserDeadline := s.lastActivity.Add(options.userTimeout)
		if deadline.IsZero() || keepAliveUserDeadline.Before(deadline) {
			deadline = keepAliveUserDeadline
		}
	}
	if !keepAliveOutputPending && options.keepAlive && s.keepAliveEligible() {
		keepAliveDeadline := s.lastActivity.Add(options.keepAliveConfig.Idle)
		if s.livenessState != nil && s.livenessState.keepAliveProbes != 0 {
			keepAliveDeadline = s.livenessState.lastKeepAlive.Add(options.keepAliveConfig.Interval)
		}
		if deadline.IsZero() || keepAliveDeadline.Before(deadline) {
			deadline = keepAliveDeadline
		}
	}
	if !deadline.IsZero() {
		s.liveness = true
		s.livenessDeadline = deadline
	}
}

func (s *tcpEstablishedState) selectRetransmission(rtoDeadline, probeBase, rackObservedAt time.Time) {
	if len(s.outstanding) == 0 {
		s.retransmit = false
		s.retransmissionDeadline = time.Time{}
		s.retransmissionKind = tcpRetransmissionRTO
		s.sendTimer.baseDeadline = time.Time{}
		return
	}
	index := 0
	if s.sackedRanges != 0 {
		index = firstUnsackedSegment(s.outstanding)
		if index < 0 {
			index = 0
		}
	}
	if rtoDeadline.IsZero() {
		rtoDeadline = s.outstanding[index].transmittedAt(s.connection.stack.timestampEpoch).Add(s.rtt.rto)
	}
	s.sendTimer.baseDeadline = rtoDeadline
	if s.peerSACK && s.outstanding[0].state.has(sentTCPSegmentSACKed) {
		s.armSACKReneging()
		return
	}
	s.retransmit = false
	s.retransmissionDeadline = time.Time{}
	s.retransmissionKind = tcpRetransmissionRTO
	deadline := rtoDeadline
	haveSACKed := s.peerSACK && s.sackedRanges != 0
	if s.peerSACK && s.peerWindow != 0 && s.ecnHoldUntil.IsZero() && !s.tailProbeActive && s.rtt.samples > s.tailProbeRTTSamples && !s.fastRecovery && !s.rtoRecovery && !haveSACKed {
		probeIndex := len(s.outstanding) - 1
		if probeBase.IsZero() {
			probeBase = s.outstanding[probeIndex].transmittedAt(s.connection.stack.timestampEpoch)
		}
		probeDeadline := probeBase.Add(tailLossProbeDelay(s.rtt.srtt, s.rtt.rto, len(s.outstanding) == 1))
		if probeDeadline.Before(deadline) {
			deadline = probeDeadline
			s.retransmissionKind = tcpRetransmissionProbe
		}
	}
	if s.peerSACK && (haveSACKed || s.rackLatestDelivered.retransmitted) {
		if rackObservedAt.IsZero() {
			rackObservedAt = time.Now()
		}
		if candidate, exists := s.rackDeadline(rackObservedAt, haveSACKed); exists && !candidate.After(deadline) {
			deadline = candidate
			s.retransmissionKind = tcpRetransmissionRACK
		}
	}
	s.retransmit = true
	s.retransmissionDeadline = deadline
}

func (s *tcpEstablishedState) armRetransmission() {
	s.selectRetransmission(time.Time{}, time.Time{}, time.Time{})
}

func (s *tcpEstablishedState) armRetransmissionAfterACK(acknowledgedAt time.Time) {
	now := time.Now()
	s.selectRetransmission(now.Add(s.rtt.rto), now, acknowledgedAt)
}

func (s *tcpEstablishedState) reselectRetransmission(observedAt time.Time) {
	if len(s.outstanding) == 0 {
		s.armRetransmission()
		return
	}
	if s.peerSACK && s.outstanding[0].state.has(sentTCPSegmentSACKed) {
		s.armSACKReneging()
		return
	}
	deadline := s.sendTimer.baseDeadline
	if deadline.IsZero() {
		index := firstUnsackedSegment(s.outstanding)
		if index < 0 {
			index = 0
		}
		deadline = s.outstanding[index].transmittedAt(s.connection.stack.timestampEpoch).Add(s.rtt.rto)
		s.sendTimer.baseDeadline = deadline
	}
	kind := tcpRetransmissionRTO
	haveSACKed := s.peerSACK && s.sackedRanges != 0
	if s.retransmit && s.retransmissionKind == tcpRetransmissionProbe && !haveSACKed && !s.retransmissionDeadline.IsZero() && s.retransmissionDeadline.Before(deadline) {
		deadline = s.retransmissionDeadline
		kind = tcpRetransmissionProbe
	}
	if s.peerSACK && (haveSACKed || s.rackLatestDelivered.retransmitted) {
		if candidate, exists := s.rackDeadline(observedAt, haveSACKed); exists && !candidate.After(deadline) {
			deadline = candidate
			kind = tcpRetransmissionRACK
		}
	}
	s.retransmit = true
	s.retransmissionDeadline = deadline
	s.retransmissionKind = kind
}

func (s *tcpEstablishedState) updateRetransmissionTimer(update tcpRetransmissionUpdate, observedAt time.Time) {
	if s.retransmit && s.retransmissionKind >= tcpRetransmissionPathMTU {
		return
	}
	if s.persist && len(s.outstanding) == 0 {
		return
	}
	if s.persist {
		s.persist = false
		s.sendTimer.baseDeadline = time.Time{}
		s.sendTimer.persistRTO = time.Second
		s.sendTimer.persistAttempts = 0
	}
	switch update {
	case tcpRetransmissionRestart:
		s.armRetransmissionAfterACK(observedAt)
	case tcpRetransmissionReselect:
		s.reselectRetransmission(observedAt)
	default:
		if !s.retransmit || s.retransmissionDeadline.IsZero() || len(s.outstanding) == 0 {
			s.armRetransmission()
		}
	}
}

func (s *tcpEstablishedState) armSACKReneging() {
	if s.retransmit && s.retransmissionKind == tcpRetransmissionSACKReneging && !s.retransmissionDeadline.IsZero() {
		return
	}
	s.retransmissionKind = tcpRetransmissionSACKReneging
	s.retransmit = true
	s.retransmissionDeadline = time.Now().Add(tcpSACKRenegingDelay(s.rtt.srtt))
}

func (s *tcpEstablishedState) retransmissionTarget(kind tcpRetransmissionKind) int {
	index := firstUnsackedSegment(s.outstanding)
	if kind == tcpRetransmissionProbe {
		index = lastUnsackedSegment(s.outstanding)
	}
	if index < 0 || index >= len(s.outstanding) {
		s.armRetransmission()
		return -1
	}
	return index
}

func tcpTimerOutputPending(state *tcpEstablishedState, hostQueueWaiting bool) bool {
	if hostQueueWaiting || !state.retransmit || !state.retransmissionDeadline.IsZero() {
		return false
	}
	return state.retransmissionKind == tcpRetransmissionRTO || state.retransmissionKind == tcpRetransmissionProbe
}

func tcpPersistOutputPending(state *tcpEstablishedState) bool {
	return state.persist && state.sendTimer.baseDeadline.IsZero() && state.peerWindow == 0 && len(state.outstanding) == 0
}

func (s *tcpEstablishedState) armPersist(sentAt time.Time, total int, writeClosed bool) {
	offset := int(s.sendNext - s.sendUnacknowledged)
	pending := len(s.outstanding) == 0 && (offset < total || writeClosed && !s.localFINSent)
	if pending && s.peerWindow == 0 && !s.persist {
		if s.sendTimer.persistRTO < s.rtt.rto {
			s.sendTimer.persistRTO = s.rtt.rto
		}
		s.sendTimer.baseDeadline = time.Now().Add(s.sendTimer.persistRTO)
		if !sentAt.IsZero() {
			s.sendTimer.baseDeadline = sentAt.Add(s.sendTimer.persistRTO)
		}
		s.persist = true
	} else if s.peerWindow != 0 || !pending {
		s.persist = false
		if !s.retransmit {
			s.sendTimer.baseDeadline = time.Time{}
		}
		s.sendTimer.persistRTO = time.Second
		s.sendTimer.persistAttempts = 0
	}
}

func (s *tcpEstablishedState) sackOptions(reservePayload int) ([]byte, bool) {
	if !s.peerSACK || len(s.outOfOrder) == 0 && !s.haveRecentDSACK {
		return nil, false
	}
	if s.sackWorkspace == nil {
		s.sackWorkspace = new([34]byte)
	}
	c := s.connection
	maximumBlocks := tcpSACKBlockLimit(c.mtu, c.key.local.Addr(), c.peerTimestamp, reservePayload)
	options := tcpSACKOptions(s.outOfOrder, s.recentSACK, maximumBlocks, s.recentDSACK, s.haveRecentDSACK, s.sackWorkspace)
	return options, s.haveRecentDSACK && len(options) >= 10
}

func (s *tcpEstablishedState) sackOptionSize(reservePayload int) int {
	if !s.peerSACK || len(s.outOfOrder) == 0 && !s.haveRecentDSACK {
		return 0
	}
	maximum := tcpSACKBlockLimit(s.connection.mtu, s.connection.key.local.Addr(), s.connection.peerTimestamp, reservePayload)
	if maximum == 0 {
		return 0
	}
	blocks := 0
	if s.haveRecentDSACK {
		blocks++
	}
	for index := len(s.outOfOrder) - 1; index >= 0 && blocks < maximum; {
		_, index = tcpReceivedSACKBlockBackward(s.outOfOrder, index)
		blocks++
	}
	if blocks == 0 {
		return 0
	}
	return 2 + 8*blocks
}

func (s *tcpEstablishedState) ordinaryOutputKind() tcpOrdinaryOutputKind {
	c := s.connection
	if s.localFINSent || s.pacing {
		if s.ackPending && !s.delayedACK {
			return tcpOrdinaryOutputACK
		}
		return tcpOrdinaryOutputNone
	}
	windowFlight := s.sendNext - s.sendUnacknowledged
	congestionFlight := s.congestionFlight()
	total, writeClosed, _ := c.sendState()
	ecnReady := s.ecnHoldUntil.IsZero() || !time.Now().Before(s.ecnHoldUntil)
	if ecnReady {
		congestionAllowance := uint32(0)
		if s.frtoState == tcpFRTOProbePending {
			congestionAllowance = 2 * uint32(s.peerMSS)
			if congestionFlight > s.congestionWindow {
				congestionAllowance = growCongestionWindow(congestionAllowance, congestionFlight-s.congestionWindow)
			}
		} else if !s.rtoRecovery && !s.fastRecovery && s.duplicateACKs > 0 && s.duplicateACKs < tcpDuplicateACKThreshold {
			congestionAllowance = uint32(s.duplicateACKs * s.peerMSS)
		}
		congestionLimit := growCongestionWindow(s.congestionWindow, congestionAllowance)
		if windowFlight < s.peerWindow && congestionFlight < congestionLimit {
			offset := int(s.sendNext - s.sendUnacknowledged)
			queued := total - offset
			if queued > 0 {
				available := int(s.peerWindow - windowFlight)
				if congestionAvailable := int(congestionLimit - congestionFlight); available > congestionAvailable {
					available = congestionAvailable
				}
				if len(s.outstanding) == 0 || writeClosed || c.socketOptions().noDelay {
					return tcpOrdinaryOutputData
				}
				optionSize := (s.sackOptionSize(1) + 3) &^ 3
				if optionSize >= s.pathMSS {
					optionSize = 0
				}
				segmentMSS := tcpSegmentPayloadLimit(s.peerMSS, s.pathMSS, optionSize)
				if queued >= segmentMSS && available >= segmentMSS {
					return tcpOrdinaryOutputData
				}
			}
		}
	}
	if s.ackPending && !s.delayedACK {
		return tcpOrdinaryOutputACK
	}
	offset := int(s.sendNext - s.sendUnacknowledged)
	if writeClosed && offset >= total && windowFlight < s.peerWindow && congestionFlight < s.congestionWindow && ecnReady {
		return tcpOrdinaryOutputFIN
	}
	return tcpOrdinaryOutputNone
}

func (s *tcpEstablishedState) recoveryOutputPending() bool {
	return (s.retransmit && s.retransmissionKind == tcpRetransmissionPathMTU) || s.rtoRecovery || s.fastRecovery || s.haveRACKLoss
}

func (s *tcpEstablishedState) recoveryOutputReady() bool {
	if s.retransmit && s.retransmissionKind == tcpRetransmissionPathMTU {
		return firstUnsackedSegment(s.outstanding) >= 0
	}
	if s.rtoRecovery && s.frtoState == tcpFRTOFallbackPending {
		return firstUnsackedSegment(s.outstanding) >= 0
	}
	if s.rtoRecovery && s.frtoState == tcpFRTOInactive && len(s.outstanding) != 0 {
		index := firstUnsackedSegment(s.outstanding)
		if s.peerSACK {
			index = firstRACKLoss(s.outstanding)
		} else if index >= 0 && s.outstanding[index].state.has(sentTCPSegmentSACKRetried) {
			index = -1
		}
		if index >= 0 {
			return true
		}
	}
	if len(s.outstanding) == 0 || !s.fastRecovery && !s.haveRACKLoss {
		return false
	}
	if !s.peerSACK {
		if !s.fastRecovery {
			return false
		}
		index := firstUnsackedSegment(s.outstanding)
		return index >= 0 && !s.outstanding[index].state.has(sentTCPSegmentSACKRetried)
	}
	index := firstUnretriedLoss(s.outstanding, s.peerMSS)
	if index < 0 && s.fastRecovery {
		index = firstUnretriedSACKHole(s.outstanding, highestSACKedSequence(s.outstanding))
	}
	if index < 0 || s.pacing {
		return false
	}
	size := s.outstanding[index].end - s.outstanding[index].sequence
	return sackRecoveryCanSend(s.fastRecovery, sackRecoveryPipe(s.outstanding, s.peerMSS), size, s.congestionWindow)
}

func (s *tcpEstablishedState) sendACKAt(sequence uint32, reservation tcpOutputReservation) error {
	options, dsackSent := s.sackOptions(0)
	window, right := s.nextAdvertisedReceiveWindow()
	var payload tcpPayloadView
	if _, err := s.connection.publishReservedPayloadForMTU(sequence, s.receiveNext, TCPFlagACK, window, options, &payload, false, s.connection.mtu, reservation, tcpOutputSequenceRange{}); err != nil {
		return err
	}
	if dsackSent {
		s.haveRecentDSACK = false
	}
	s.commitAcknowledgment(window, right, len(options) != 0)
	return nil
}

func (s *tcpEstablishedState) sendACK(reservation tcpOutputReservation) error {
	sequence := tcpAcceptableSendSequence(s.sendUnacknowledged, s.sendNext, s.peerWindow, s.peerScale)
	return s.sendACKAt(sequence, reservation)
}

func (s *tcpEstablishedState) trySendACKAt(sequence uint32) {
	options, dsackSent := s.sackOptions(0)
	window, right := s.nextAdvertisedReceiveWindow()
	if err := s.connection.trySendSegmentWithOptions(sequence, s.receiveNext, TCPFlagACK, window, options); err != nil {
		return
	}
	if dsackSent {
		s.haveRecentDSACK = false
	}
	s.commitAcknowledgment(window, right, len(options) != 0)
}

func (s *tcpEstablishedState) trySendACK() {
	sequence := tcpAcceptableSendSequence(s.sendUnacknowledged, s.sendNext, s.peerWindow, s.peerScale)
	s.trySendACKAt(sequence)
}

func (s *tcpEstablishedState) trySendChallengeACK() {
	if !s.connection.stack.allowControlResponse(controlResponseTCPChallengeACK) {
		return
	}
	s.trySendACK()
}

func (s *tcpEstablishedState) trySendChallengeACKAt(sequence uint32) {
	if !s.connection.stack.allowControlResponse(controlResponseTCPChallengeACK) {
		return
	}
	s.trySendACKAt(sequence)
}

func (s *tcpEstablishedState) scheduleACK(immediate, data bool, receivedAt time.Time) bool {
	s.ackPending = true
	quick := data && s.quickACKBudget != 0 && !s.ackPingPong
	fullSegments := data && s.receiveMSS > 0 && s.receiveNext-s.lastACKSent > uint32(s.receiveMSS)
	if immediate || quick || fullSegments {
		return true
	}
	if !s.delayedACK {
		s.delayedACKDeadline = receivedAt.Add(tcpDelayedACKTimeout)
		s.delayedACK = true
	}
	return false
}

func (s *tcpEstablishedState) scheduleSACKACK(receivedAt time.Time) bool {
	s.ackPending = true
	if s.quickACKBudget != 0 {
		return true
	}
	if s.sackACKs < tcpDuplicateACKThreshold {
		s.sackACKs++
		return true
	}
	if s.compressedSACKs >= tcpMaximumCompressedSACKs {
		return true
	}
	s.compressedSACKs++
	if !s.delayedACK {
		s.delayedACKDeadline = receivedAt.Add(tcpCompressedSACKDelay(s.rtt.srtt))
		s.delayedACK = true
	}
	return false
}

func (s *tcpEstablishedState) validateCongestionWindow(now monotonicStamp, queued int, sendBufferLimited bool) {
	if s.controller.customWindowValidation() || s.fastRecovery || s.rtoRecovery || s.controller.state.Phase != CongestionPhaseOpen {
		return
	}
	flight := s.congestionFlight()
	if congestionWindowLimited(s.congestionWindow, flight, s.peerMSS) {
		s.cwndUsed = 0
		s.cwndUsageStamp = now
		return
	}
	if flight > s.cwndUsed {
		s.cwndUsed = flight
	}
	windowFlight := s.sendNext - s.sendUnacknowledged
	underutilized := queued < s.peerMSS || windowFlight >= s.peerWindow
	if !underutilized || s.cwndUsageStamp == 0 || time.Duration(now-s.cwndUsageStamp) < s.rtt.rto {
		return
	}
	if sendBufferLimited {
		s.cwndUsed = 0
		s.cwndUsageStamp = now
		return
	}
	used := s.cwndUsed
	if initial := initialTCPWindow(s.peerMSS); used < initial {
		used = initial
	}
	if used < s.congestionWindow {
		s.slowStartThreshold = tcpCurrentSlowStartThreshold(s.congestionWindow, s.slowStartThreshold)
		s.congestionWindow = (s.congestionWindow + used) / 2
	}
	s.cwndUsed = 0
	s.cwndUsageStamp = now
}

func (s *tcpEstablishedState) recoveryTransportState(timeout bool) tcpRecoveryTransportState {
	rtoAttempts := s.rtoAttempts
	if timeout && rtoAttempts != 0 {
		rtoAttempts--
	}
	transport := tcpRecoveryTransportState{
		phase:         s.controller.state.Phase,
		recoveryPoint: s.recoveryPoint, rtoRecoveryPoint: s.rtoRecoveryPoint,
		ecnRecoveryPoint: s.ecnRecoveryPoint, prrPriorFlight: s.prrPriorFlight,
		prrDelivered: s.prrDelivered, prrOut: s.prrOut, rtoAttempts: rtoAttempts,
		fastRecovery: s.fastRecovery, rtoRecovery: s.rtoRecovery,
		frtoState:            s.frtoState,
		frtoProbeBudget:      s.frtoProbeBudget,
		sackRenegingRecovery: s.sackRenegingRecovery,
		ecnRecoveryActive:    s.ecnRecoveryActive,
	}
	transport.captured = transport.phase != CongestionPhaseOpen || transport.fastRecovery || transport.rtoRecovery || transport.frtoState != tcpFRTOInactive || transport.sackRenegingRecovery
	return transport
}

func (t *tcpRecoveryTransportState) recoveryPhaseAt(acknowledgement uint32) CongestionPhase {
	if t == nil || !t.captured {
		return CongestionPhaseOpen
	}
	switch t.phase {
	case CongestionPhaseRecovery:
		if !t.fastRecovery || tcpSequenceGreaterEqual(acknowledgement, t.recoveryPoint) {
			return CongestionPhaseOpen
		}
	case CongestionPhaseLoss:
		if !t.rtoRecovery || t.frtoState == tcpFRTOInactive && tcpSequenceGreaterEqual(acknowledgement, t.rtoRecoveryPoint) {
			return CongestionPhaseOpen
		}
	case CongestionPhaseCWR:
		if t.ecnRecoveryActive && tcpSequenceGreaterEqual(acknowledgement, t.ecnRecoveryPoint) {
			return CongestionPhaseOpen
		}
	}
	return t.phase
}

func (s *tcpEstablishedState) restoreRecoveryTransportState(acknowledged uint32) {
	transport := tcpRecoveryTransportState{}
	if s.undo.transport != nil {
		transport = *s.undo.transport
	}
	s.fastRecovery = transport.fastRecovery && tcpSequenceLess(s.sendUnacknowledged, transport.recoveryPoint)
	s.rtoRecovery = transport.rtoRecovery && (transport.frtoState != tcpFRTOInactive || tcpSequenceLess(s.sendUnacknowledged, transport.rtoRecoveryPoint))
	s.frtoState = tcpFRTOInactive
	s.frtoProbeBudget = 0
	if s.rtoRecovery {
		s.frtoState = transport.frtoState
		s.frtoProbeBudget = transport.frtoProbeBudget
	}
	s.sackRenegingRecovery = s.rtoRecovery && transport.sackRenegingRecovery
	s.recoveryPoint, s.rtoRecoveryPoint = transport.recoveryPoint, transport.rtoRecoveryPoint
	if s.fastRecovery {
		s.prrPriorFlight, s.prrDelivered, s.prrOut = transport.prrPriorFlight, transport.prrDelivered, transport.prrOut
	} else {
		s.prrPriorFlight, s.prrDelivered, s.prrOut = 0, 0, 0
	}
	if !s.rtoRecovery {
		s.rtoRecoveryPoint = 0
	}
	s.ecnRecoveryActive, s.ecnRecoveryPoint = transport.ecnRecoveryActive, transport.ecnRecoveryPoint
	if acknowledged == 0 {
		s.rtoAttempts = transport.rtoAttempts
	}
}

func (s *tcpEstablishedState) restoreSpuriousRecovery(receivedAt time.Time, acknowledged uint32) bool {
	if s.undo == nil || !s.undo.active {
		return false
	}
	flight := s.ordinaryFlight()
	response := s.undo.eifelRTOResponse()
	phase := s.undo.transport.recoveryPhaseAt(s.sendUnacknowledged)
	s.congestionWindow, s.slowStartThreshold = s.undo.restore(s.congestionWindow, flight, acknowledged, s.peerMSS, &s.controller, receivedAt, phase)
	if response.pending {
		if s.eifelRTO == nil {
			s.eifelRTO = new(tcpEifelRTOResponse)
		}
		*s.eifelRTO = response
	}
	s.restoreRecoveryTransportState(acknowledged)
	s.undo.spuriousUndos++
	s.connection.stack.stats.tcpSpuriousRecoveryUndos.Add(1)
	return true
}

func (s *tcpEstablishedState) changeCongestionController(factory *CongestionControlFactory, maximumPacingRate uint64) {
	if factory == s.controller.factory {
		if s.controller.setMaximumPacingRate(maximumPacingRate) {
			s.pacing = false
			s.pacingDeadline = time.Time{}
		}
		return
	}
	now := time.Now()
	s.controller.release(now, s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	c := s.connection
	s.controller = newTCPCongestionControllerFromFactory(factory, CongestionControlContext{
		LocalAddress: c.key.local, RemoteAddress: c.key.remote,
		Passive: c.passive, Forwarded: c.forwarded,
	})
	s.controller.setMaximumPacingRate(maximumPacingRate)
	if s.undo != nil {
		s.undo.active = false
	}
	for index := range s.outstanding {
		s.outstanding[index].delivery = tcpDeliverySnapshot{}
		s.outstanding[index].congestionPacketState = 0
	}
	s.congestionWindow, s.slowStartThreshold = s.controller.initialize(now, s.rtt.minimum, s.rtt.srtt, s.congestionWindow, s.slowStartThreshold, s.peerMSS, monotonicStampAt(c.stack.timestampEpoch, now))
	s.hyStart.disable()
	s.pacing = false
	s.pacingDeadline = time.Time{}
}

func (s *tcpEstablishedState) consumeActorTimer(actorTimer *ownedTimer) {
	actorTimer.consumed()
	s.actorTimerChannel = nil
	s.actorTimerDeadline = time.Time{}
}

type tcpReceivedPiece struct {
	sequence uint32
	payload  []byte
	fin      bool
}

type tcpReadBuffer struct {
	chunks [][]byte
	head   int
	size   int
}

func (b *tcpReadBuffer) append(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if b.head != 0 && len(b.chunks) == cap(b.chunks) {
		live := copy(b.chunks, b.chunks[b.head:])
		for index := live; index < len(b.chunks); index++ {
			b.chunks[index] = nil
		}
		b.chunks = b.chunks[:live]
		b.head = 0
	}
	b.chunks = append(b.chunks, payload)
	b.size += len(payload)
}

func (b *tcpReadBuffer) read(destination []byte, maximum int, recycle func([]byte)) int {
	if maximum > len(destination) {
		maximum = len(destination)
	}
	if maximum > b.size {
		maximum = b.size
	}
	written := 0
	for written < maximum {
		chunk := b.chunks[b.head]
		n := copy(destination[written:maximum], chunk)
		written += n
		b.size -= n
		if n == len(chunk) {
			if recycle != nil {
				recycle(chunk)
			}
			b.chunks[b.head] = nil
			b.head++
		} else {
			b.chunks[b.head] = chunk[n:]
		}
	}
	if b.size == 0 {
		b.reset()
	}
	return written
}

func (b *tcpReadBuffer) take(maximum int) ([]byte, bool) {
	chunk := b.chunks[b.head]
	complete := len(chunk) <= maximum
	if len(chunk) > maximum {
		chunk = chunk[:maximum:maximum]
	} else {
		chunk = chunk[:len(chunk):len(chunk)]
	}
	b.size -= len(chunk)
	if len(chunk) == len(b.chunks[b.head]) {
		b.chunks[b.head] = nil
		b.head++
	} else {
		b.chunks[b.head] = b.chunks[b.head][len(chunk):]
	}
	if b.size == 0 {
		b.reset()
	}
	return chunk, complete
}

func (b *tcpReadBuffer) reset() {
	for index := range b.chunks {
		b.chunks[index] = nil
	}
	if cap(b.chunks) > tcpReadChunkRetain {
		b.chunks = nil
	} else {
		b.chunks = b.chunks[:0]
	}
	b.head = 0
	b.size = 0
}

type tcpSendChunk struct {
	storage     []byte
	start       int
	end         int
	streamStart uint64
}

const tcpPayloadViewMaximumChunks = 5

type tcpPayloadView struct {
	chunks [tcpPayloadViewMaximumChunks][]byte
	count  int
	size   int
}

func (v *tcpPayloadView) setBytes(payload []byte) {
	*v = tcpPayloadView{}
	if len(payload) != 0 {
		v.chunks[0] = payload
		v.count = 1
		v.size = len(payload)
	}
}

func (v *tcpPayloadView) copyTo(destination []byte) int {
	copied := 0
	for index := 0; index < v.count; index++ {
		copied += copy(destination[copied:], v.chunks[index])
	}
	return copied
}

type tcpSendBuffer struct {
	chunks []tcpSendChunk
	spare  []byte
	base   uint64
	end    uint64
	size   int
	reusableState uint8
	limited bool
}

const (
	tcpSendReusableUnseen uint8 = iota
	tcpSendReusableReleased
	tcpSendReusableConfirmed
)

func (b *tcpSendBuffer) append(payload []byte) {
	for len(payload) != 0 {
		if len(b.chunks) == 0 || b.chunks[len(b.chunks)-1].end == cap(b.chunks[len(b.chunks)-1].storage) {
			capacity := len(payload)
			if len(b.chunks) == 0 && capacity < tcpSendChunkMinimum {
				if capacity < tcpSendChunkInitial {
					capacity = tcpSendChunkInitial
				}
			} else if capacity < tcpSendChunkMinimum {
				capacity = tcpSendChunkMinimum
			} else if capacity > tcpSendChunkMaximum {
				capacity = tcpSendChunkMaximum
			}
			var storage []byte
			if b.spare != nil && (len(b.chunks) == 0 || cap(b.spare) >= tcpSendChunkMinimum) &&
				(!tcpFitSmallSendSpare || cap(b.spare) >= tcpSendChunkMinimum || cap(b.spare) >= capacity) {
				storage = b.spare
				b.spare = nil
			}
			if cap(storage) == 0 {
				if tcpFitSmallSendSpare {
					b.spare = nil
				}
				storage = make([]byte, capacity)
				if capacity > tcpSendChunkInitial && capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableReleased {
					b.reusableState = tcpSendReusableConfirmed
				}
			} else {
				storage = storage[:cap(storage)]
			}
			b.chunks = append(b.chunks, tcpSendChunk{storage: storage, streamStart: b.end})
		}
		chunk := &b.chunks[len(b.chunks)-1]
		written := copy(chunk.storage[chunk.end:], payload)
		chunk.end += written
		b.end += uint64(written)
		b.size += written
		payload = payload[written:]
	}
}

func (b *tcpSendBuffer) view(offset, maximum int, result *tcpPayloadView) int {
	*result = tcpPayloadView{}
	total := b.size
	if offset < 0 || offset >= total || maximum <= 0 {
		return total
	}
	wanted := maximum
	if available := total - offset; wanted > available {
		wanted = available
	}
	target := b.base + uint64(offset)
	low, high := 0, len(b.chunks)
	for low < high {
		middle := int(uint(low+high) >> 1)
		chunk := &b.chunks[middle]
		if chunk.streamStart+uint64(chunk.end-chunk.start) <= target {
			low = middle + 1
		} else {
			high = middle
		}
	}
	remaining := wanted
	for index := low; index < len(b.chunks) && remaining != 0; index++ {
		chunk := &b.chunks[index]
		start := chunk.start
		if index == low {
			start += int(target - chunk.streamStart)
		}
		size := chunk.end - start
		if size > remaining {
			size = remaining
		}
		if size == 0 {
			continue
		}
		if result.count == len(result.chunks) {
			panic("mipstack: TCP payload spans too many send chunks")
		}
		result.chunks[result.count] = chunk.storage[start : start+size : start+size]
		result.count++
		result.size += size
		remaining -= size
	}
	return total
}

func (b *tcpSendBuffer) acknowledge(size int) {
	if size > b.size {
		size = b.size
	}
	if size <= 0 {
		return
	}
	b.base += uint64(size)
	b.size -= size
	remaining := size
	for remaining != 0 && len(b.chunks) != 0 {
		chunk := &b.chunks[0]
		available := chunk.end - chunk.start
		if remaining < available {
			chunk.start += remaining
			chunk.streamStart += uint64(remaining)
			remaining = 0
			break
		}
		remaining -= available
		capacity := cap(chunk.storage)
		if capacity <= tcpSendChunkInitial || capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableConfirmed {
			if capacity > cap(b.spare) {
				b.spare = chunk.storage[:0]
			}
		} else if capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableUnseen {
			b.reusableState = tcpSendReusableReleased
		}
		b.chunks[0] = tcpSendChunk{}
		b.chunks = b.chunks[1:]
	}
	if len(b.chunks) == 0 {
		b.chunks = nil
		b.base, b.end = 0, 0
	}
}

func (b *tcpSendBuffer) clear() { *b = tcpSendBuffer{} }

type tcpPendingEvents struct {
	networkErrors []error
	infoRequests []chan TCPConnInfo
}

type TCPConn struct {
	stack *Stack
	key   tcpKey
	mtu   int

	inbound        tcpSegmentQueue
	actorWakeFlags atomic.Uint32
	abortCh        chan struct{}
	done           chan struct{}
	lingerDone        chan struct{}
	readCallMu        sync.Mutex
	writeCallMu       sync.Mutex
	icmpSequence      atomic.Uint64
	applicationReads  atomic.Uint64
	outOfOrderUnread  atomic.Int64
	retransmissions   atomic.Uint64
	inboundQueueDrops atomic.Uint64
	lastInfo          atomic.Pointer[TCPConnInfo]
	sendCapacityHint  atomic.Int64

	abortMu  sync.Mutex
	abortErr error

	mu          sync.Mutex
	readBuffer  tcpReadBuffer
	readErr     error
	terminalErr error
	pending       *tcpPendingEvents
	readDeadline  socketDeadline
	writeDeadline socketDeadline
	readNotify        chan struct{}
	sendChanged       chan struct{}
	sendBuffer        tcpSendBuffer
	receiveCapacity   int
	sendCapacity      int
	receiveMaximum    int
	sendMaximum       int
	keepAliveConfig   KeepAliveConfig
	idleTimeout       time.Duration
	userTimeout       time.Duration
	congestionFactory *CongestionControlFactory
	maximumPacingRate uint64
	outputFlowID      uint64
	trafficClass      atomic.Uint32
	flowLabel         uint32
	linger            int

	peerMSS         int
	recentTimestamp uint32
	receiveNext     uint32
	peerWindow      uint32
	peerWindowSeq   uint32
	handshakeRTT    time.Duration

	passive bool
	reuseAddress bool
	reusePort bool
	forwarded bool
	abortRST                                 bool
	userClosed, readClosed, writeClosed      bool
	receiveAutoTune, sendAutoTune, keepAlive bool
	noDelay, congestionUser                  bool
	receiveWindowScale, peerWindowScale      uint8
	lingerComplete                            bool
	peerWindowScaling                         bool
	peerSACK, peerTimestamp, peerECN          bool
	echoCongestion, sendCWR, handshakeTimeout bool
	net                                       tcpNetwork
}

type tcpListenKey struct {
	address netip.Addr
	port    uint16
}

type tcpPassiveEndpoints interface {
	portListened(local netip.Addr, port uint16) bool
	handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error)
	timeWaitListener(local, remote netip.AddrPort) *TCPListener
	updateConfig(stack *Stack, network *networkState)
	closeAll()
}

type tcpReuseEndpoints interface {
	empty() bool
	listeners() []*TCPListener
	overlaps(address netip.Addr, port uint16, dual bool) bool
	listener(binding, local, remote netip.AddrPort) *TCPListener
	add(listener *TCPListener)
	remove(listener *TCPListener) bool
}

type tcpPassiveState struct {
	exclusive           map[tcpListenKey]*TCPListener
	reuse               tcpReuseEndpoints
	cookieMu            sync.Mutex
	cookieKey           [16]byte
	cookieSet           bool
	cookieEpoch         time.Time
	cookiePeriod        uint64
	cookieActive        bool
	cookieScaleSet      bool
	cookieScalePeriod   uint64
	cookieWindowScale   uint8
	previousScaleSet    bool
	previousScalePeriod uint64
	previousWindowScale uint8
}

type tcpListenerBinding interface {
	available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool
	register(state *tcpPassiveState, listener *TCPListener) error
	connectionReusable(*TCPConn) bool
}

type exclusiveTCPListenerBinding struct {
	reuseAddress bool
}

type TCPListenerInfo struct {
	LocalAddress netip.AddrPort
	Closed bool
	AcceptQueueConnections int
	AcceptQueueCapacity int
	AcceptQueuePeak int
	SYNBacklogConnections int
	SYNBacklogCapacity int
	SYNBacklogPeak int
	SYNsReceived uint64
	StatefulHandshakes uint64
	HandshakeCompletions uint64
	HandshakeFailures uint64
	HandshakeTimeouts uint64
	SYNCookiesSent uint64
	SYNCookiesAccepted uint64
	SYNCookiesRejected uint64
	AcceptQueueDrops uint64
	AcceptedConnections uint64
}

type TCPListener struct {
	stack        *Stack
	key          tcpListenKey
	local        netip.AddrPort
	dual         bool
	net          string
	options      tcpSocketOptionSet
	reuseAddress bool
	reusePort    bool

	accept         chan *TCPConn
	closed         chan struct{}
	once           sync.Once
	backlog        int
	acceptCapacity int

	mu          sync.Mutex
	deadline    socketDeadline
	pending     map[*TCPConn]struct{}
	handshaking map[*TCPConn]struct{}
	acceptPeak  int
	backlogPeak int

	synsReceived         atomic.Uint64
	statefulHandshakes   atomic.Uint64
	handshakeCompletions atomic.Uint64
	handshakeFailures    atomic.Uint64
	handshakeTimeouts    atomic.Uint64
	synCookiesSent       atomic.Uint64
	synCookiesAccepted   atomic.Uint64
	synCookiesRejected   atomic.Uint64
	acceptQueueDrops     atomic.Uint64
	acceptedConnections  atomic.Uint64
}

func (s *Stack) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error) {
	return s.listenTCP(ctx, network, local, exclusiveTCPListenerBinding{reuseAddress: true}, tcpSocketOptionSet{})
}

func (s *Stack) listenTCP(ctx context.Context, network string, local netip.AddrPort, binding tcpListenerBinding, options tcpSocketOptionSet) (net.Listener, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := net.TCPAddrFromAddrPort(local)
	wrap := func(err error) (net.Listener, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "tcp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid TCP listen address"))
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
	address, dual, err := listenAddress(state, network, "tcp", address)
	if err != nil {
		return wrap(err)
	}
	if err = (socketOptionSet{tcp: options}).validateFamily(socketOptionTCPListen, address.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	passive := s.tcpPassiveStateLocked()
	defer func() {
		if passive.empty() && s.tcpPassive == passive {
			s.tcpPassive = nil
		}
	}()
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPListenPortLocked(passive, address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.tcpListenEndpointAvailableLocked(passive, binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(address, port)
	key := tcpListenKey{address: address, port: port}
	acceptCapacity := state.tcpDefaults.AcceptQueue
	if options.acceptQueue.set {
		acceptCapacity = options.acceptQueue.value
	}
	backlog := state.tcpDefaults.SYNBacklog
	if options.synBacklog.set {
		backlog = options.synBacklog.value
	}
	listener := &TCPListener{
		stack: s, key: key, local: local, dual: dual, net: network, options: options, accept: make(chan *TCPConn, acceptCapacity), backlog: backlog,
		acceptCapacity: acceptCapacity,
		closed:         make(chan struct{}), pending: make(map[*TCPConn]struct{}), handshaking: make(map[*TCPConn]struct{}),
	}
	if err = binding.register(passive, listener); err != nil {
		return wrap(err)
	}
	s.tcpTimeWaitReplacer = replaceTCPTimeWait
	s.stats.activeTCPListeners.Add(1)
	return listener, nil
}

func (s *Stack) tcpPassiveStateLocked() *tcpPassiveState {
	if s.tcpPassive == nil {
		state := &tcpPassiveState{exclusive: make(map[tcpListenKey]*TCPListener)}
		s.tcpPassive = state
		return state
	}
	return s.tcpPassive.(*tcpPassiveState)
}

func (s *Stack) allocateTCPListenPortLocked(state *tcpPassiveState, address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		return s.tcpListenEndpointAvailableLocked(state, exclusiveTCPListenerBinding{}, address, port, dual)
	})
}

func (s *Stack) tcpListenEndpointAvailableLocked(state *tcpPassiveState, binding tcpListenerBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(state, address, port, dual) {
		return false
	}
	for key, connection := range s.tcp {
		local := key.local
		if local.Port() == port && listenAddressesOverlap(local.Addr(), false, address, dual) {
			if !binding.connectionReusable(connection) {
				return false
			}
		}
	}
	return true
}

func (exclusiveTCPListenerBinding) available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool {
	return !state.overlaps(address, port, dual)
}

func (binding exclusiveTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	listener.reuseAddress = binding.reuseAddress
	state.exclusive[listener.key] = listener
	return nil
}

func (binding exclusiveTCPListenerBinding) connectionReusable(connection *TCPConn) bool {
	return binding.reuseAddress && connection.reuseAddress
}

func (state *tcpPassiveState) empty() bool {
	return len(state.exclusive) == 0 && (state.reuse == nil || state.reuse.empty())
}

func (state *tcpPassiveState) listeners() []*TCPListener {
	listeners := make([]*TCPListener, 0, len(state.exclusive))
	for _, listener := range state.exclusive {
		listeners = append(listeners, listener)
	}
	if state.reuse != nil {
		listeners = append(listeners, state.reuse.listeners()...)
	}
	return listeners
}

func (state *tcpPassiveState) updateConfig(stack *Stack, network *networkState) {
	stack.mu.RLock()
	if stack.tcpPassive != state {
		stack.mu.RUnlock()
		return
	}
	listeners := state.listeners()
	stack.mu.RUnlock()
	for _, listener := range listeners {
		address := listener.local.Addr()
		if listener.dual && !networkStateHasFamily(network, false) && !networkStateHasFamily(network, true) ||
			!listener.dual && address.IsUnspecified() && !networkStateHasFamily(network, address.Is6()) ||
			!address.IsUnspecified() && !networkStateHasLocal(network, address) {
			stack.closeTCPListener(listener)
		}
	}
}

func (state *tcpPassiveState) closeAll() {
	for _, listener := range state.listeners() {
		listener.closeFromStack()
	}
}

func (state *tcpPassiveState) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, listener := range state.exclusive {
		if key.port == port && listenAddressesOverlap(key.address, listener.dual, address, dual) {
			return true
		}
	}
	return state.reuse != nil && state.reuse.overlaps(address, port, dual)
}

func (state *tcpPassiveState) listener(local, remote netip.AddrPort) *TCPListener {
	if listener := state.exclusive[tcpListenKey{address: local.Addr(), port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(local, local, remote); listener != nil {
			return listener
		}
	}
	wildcard := netip.IPv4Unspecified()
	if local.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	wildcardLocal := netip.AddrPortFrom(wildcard, local.Port())
	if listener := state.exclusive[tcpListenKey{address: wildcard, port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(wildcardLocal, local, remote); listener != nil {
			return listener
		}
	}
	if local.Addr().Is4() {
		dualLocal := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		if listener := state.exclusive[tcpListenKey{address: dualLocal.Addr(), port: local.Port()}]; listener != nil && listener.dual {
			return listener
		}
		if state.reuse != nil {
			if listener := state.reuse.listener(dualLocal, local, remote); listener != nil && listener.dual {
				return listener
			}
		}
	}
	return nil
}

func (state *tcpPassiveState) portListened(local netip.Addr, port uint16) bool {
	return state.overlaps(local, port, false)
}

func (state *tcpPassiveState) remove(listener *TCPListener) bool {
	if state.exclusive[listener.key] == listener {
		delete(state.exclusive, listener.key)
		return true
	}
	if state.reuse != nil && state.reuse.remove(listener) {
		if state.reuse.empty() {
			state.reuse = nil
		}
		return true
	}
	return false
}

func (l *TCPListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return nil, l.operationError("accept", net.ErrClosed)
	default:
	}
	timeout := l.deadline.waitLocked()
	select {
	case <-timeout:
		l.mu.Unlock()
		return nil, l.operationError("accept", os.ErrDeadlineExceeded)
	default:
	}
	accept := l.accept
	l.mu.Unlock()
	select {
	case connection := <-accept:
		l.mu.Lock()
		select {
		case <-l.closed:
			l.mu.Unlock()
			return nil, l.operationError("accept", net.ErrClosed)
		default:
		}
		delete(l.pending, connection)
		l.mu.Unlock()
		l.acceptedConnections.Add(1)
		return connection, nil
	case <-timeout:
		return nil, l.operationError("accept", os.ErrDeadlineExceeded)
	case <-l.closed:
		return nil, l.operationError("accept", net.ErrClosed)
	}
}

func (l *TCPListener) Close() error {
	if l.stack.closeTCPListener(l) {
		return nil
	}
	return l.operationError("close", net.ErrClosed)
}

func (l *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.local) }

func (l *TCPListener) Info() TCPListenerInfo {
	l.mu.Lock()
	info := TCPListenerInfo{
		LocalAddress:           l.local,
		AcceptQueueConnections: len(l.accept), AcceptQueueCapacity: l.acceptCapacity, AcceptQueuePeak: l.acceptPeak,
		SYNBacklogConnections: len(l.handshaking), SYNBacklogCapacity: l.backlog, SYNBacklogPeak: l.backlogPeak,
	}
	select {
	case <-l.closed:
		info.Closed = true
	default:
	}
	l.mu.Unlock()
	info.SYNsReceived = l.synsReceived.Load()
	info.StatefulHandshakes = l.statefulHandshakes.Load()
	info.HandshakeCompletions = l.handshakeCompletions.Load()
	info.HandshakeFailures = l.handshakeFailures.Load()
	info.HandshakeTimeouts = l.handshakeTimeouts.Load()
	info.SYNCookiesSent = l.synCookiesSent.Load()
	info.SYNCookiesAccepted = l.synCookiesAccepted.Load()
	info.SYNCookiesRejected = l.synCookiesRejected.Load()
	info.AcceptQueueDrops = l.acceptQueueDrops.Load()
	info.AcceptedConnections = l.acceptedConnections.Load()
	return info
}

func (l *TCPListener) SetDeadline(deadline time.Time) error {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return l.operationError("set", net.ErrClosed)
	default:
	}
	l.deadline.setLocked(deadline)
	l.mu.Unlock()
	return nil
}

func (l *TCPListener) operationError(operation string, err error) error {
	return socketOperationError(operation, l.net, nil, l.Addr(), err)
}

func (l *TCPListener) trackHandshake(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	if len(l.handshaking) >= l.backlog {
		return false
	}
	l.pending[connection] = struct{}{}
	l.handshaking[connection] = struct{}{}
	if len(l.handshaking) > l.backlogPeak {
		l.backlogPeak = len(l.handshaking)
	}
	return true
}

func (l *TCPListener) canReplace(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	_, pending := l.pending[connection]
	return !pending
}

func (l *TCPListener) trackCompleted(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
		l.pending[connection] = struct{}{}
		return true
	}
}

func (l *TCPListener) removePending(connection *TCPConn) {
	l.mu.Lock()
	delete(l.pending, connection)
	delete(l.handshaking, connection)
	l.mu.Unlock()
}

func (l *TCPListener) enqueue(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.handshaking, connection)
	select {
	case <-l.closed:
		return false
	default:
	}
	select {
	case l.accept <- connection:
		l.handshakeCompletions.Add(1)
		if len(l.accept) > l.acceptPeak {
			l.acceptPeak = len(l.accept)
		}
		return true
	default:
		l.acceptQueueDrops.Add(1)
		l.stack.stats.tcpAcceptQueueDrops.Add(1)
		return false
	}
}

func (l *TCPListener) noteHandshakeFailure(err error) {
	l.handshakeFailures.Add(1)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		l.handshakeTimeouts.Add(1)
		l.stack.stats.tcpHandshakeTimeouts.Add(1)
	}
}

func (l *TCPListener) closeFromStack() {
	l.once.Do(func() {
		l.mu.Lock()
		l.deadline.stopLocked()
		close(l.closed)
		pending := make([]*TCPConn, 0, len(l.pending))
		for connection := range l.pending {
			pending = append(pending, connection)
		}
		l.accept = nil
		l.pending = nil
		l.handshaking = nil
		l.mu.Unlock()
		for _, connection := range pending {
			connection.abort(net.ErrClosed)
		}
	})
}

var _ net.Listener = (*TCPListener)(nil)

func (s *Stack) DialTCP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	return s.dialTCP(ctx, network, source, remote, tcpSocketOptionSet{})
}

func (s *Stack) dialTCP(ctx context.Context, network string, source, remote netip.AddrPort, options tcpSocketOptionSet) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := net.TCPAddrFromAddrPort(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "tcp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid TCP destination"))
	}
	if err := (socketOptionSet{tcp: options}).validateFamily(socketOptionTCPDial, remote.Addr().Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if s.network.Load().broadcastDestination(remote.Addr()) {
		return wrap(nil, syscall.EACCES)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		s.mu.Unlock()
		return wrap(nil, err)
	}
	localAddress := local.Addr()
	localNetAddress := net.TCPAddrFromAddrPort(local)
	connectionMTU := s.mtuFor(remote.Addr())
	if !s.tcpConnectionAvailableLocked() {
		s.mu.Unlock()
		return wrap(localNetAddress, ErrResourceLimit)
	}
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPPortLocked(localAddress, remote)
		if err != nil {
			s.mu.Unlock()
			return wrap(localNetAddress, err)
		}
	} else {
		key := tcpKey{local: netip.AddrPortFrom(localAddress, port), remote: remote}
		if s.tcpPortListenedLocked(localAddress, port) {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
		if _, exists := s.tcp[key]; exists {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
	}
	key := tcpKey{local: netip.AddrPortFrom(localAddress.Unmap(), port), remote: remote}
	initialSequence := s.tcpInitialSequence(key, time.Now())
	connection := newTCPConn(s, network, key, connectionMTU, options)
	connected := make(chan error, 1)
	connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
	s.tcp[key] = connection
	s.stats.activeTCPConnections.Add(1)
	s.mu.Unlock()
	go connection.run(initialSequence, connected)
	select {
	case err = <-connected:
		if err != nil {
			return wrap(connection.LocalAddr(), err)
		}
		return connection, nil
	case <-ctx.Done():
		connection.abort(ctx.Err())
		return wrap(connection.LocalAddr(), ctx.Err())
	}
}

func newTCPConn(stack *Stack, network string, key tcpKey, mtu int, options tcpSocketOptionSet) *TCPConn {
	defaults, _ := normalizeTCPSocketDefaults(TCPSocketDefaults{})
	if stack != nil {
		state := stack.network.Load()
		defaults = state.tcpDefaults
	}
	defaults = applyTCPSocketOptions(defaults, options)
	connection := &TCPConn{
		stack: stack, net: newTCPNetwork(network), key: key, mtu: mtu,
		inbound: newTCPSegmentQueue(),
		abortCh: make(chan struct{}), done: make(chan struct{}),
		noDelay: !defaults.DisableNoDelay, linger: -1,
		receiveCapacity: defaults.ReceiveBuffer, sendCapacity: defaults.SendBuffer,
		receiveMaximum: defaults.MaximumReceiveBuffer, sendMaximum: defaults.MaximumSendBuffer,
		receiveAutoTune: defaults.MaximumReceiveBuffer > defaults.ReceiveBuffer,
		sendAutoTune:    defaults.MaximumSendBuffer > defaults.SendBuffer,
		keepAlive:       defaults.KeepAlive, keepAliveConfig: defaults.KeepAliveConfig,
		idleTimeout: defaults.IdleTimeout, userTimeout: defaults.UserTimeout,
		congestionFactory:  defaults.CongestionControlFactory,
		congestionUser:     options.congestionControl.set,
		maximumPacingRate:  defaults.MaximumPacingRate,
		receiveWindowScale: tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer),
	}
	if stack != nil {
		connection.outputFlowID = stack.nextOutputFlow.Add(1)
	}
	if key.local.Addr().Is6() {
		if options.flowLabel.set {
			connection.flowLabel = options.flowLabel.value
		} else {
			connection.flowLabel = defaults.FlowLabel
		}
		if connection.flowLabel == 0 && !options.flowLabel.set && stack != nil {
			connection.flowLabel = stack.automaticTransportFlowLabel(key.local.Addr(), key.remote.Addr(), ProtocolTCP, key.local.Port(), key.remote.Port())
		}
	}
	connection.trafficClass.Store(uint32(defaults.TrafficClass))
	connection.sendCapacityHint.Store(int64(defaults.SendBuffer))
	return connection
}

func applyTCPSocketOptions(defaults TCPSocketDefaults, options tcpSocketOptionSet) TCPSocketDefaults {
	if options.readBuffer.set {
		defaults.ReceiveBuffer = options.readBuffer.value
		defaults.MaximumReceiveBuffer = options.readBuffer.value
	}
	if options.writeBuffer.set {
		defaults.SendBuffer = options.writeBuffer.value
		defaults.MaximumSendBuffer = options.writeBuffer.value
	}
	if options.keepAlive != socketOptionBoolOverrideUnset {
		defaults.KeepAlive = options.keepAlive == socketOptionBoolOverrideEnabled
	}
	if options.keepAliveConfig.set {
		defaults.KeepAliveConfig = options.keepAliveConfig.value
	}
	if options.noDelay != socketOptionBoolOverrideUnset {
		defaults.DisableNoDelay = options.noDelay == socketOptionBoolOverrideDisabled
	}
	if options.idleTimeout.set {
		defaults.IdleTimeout = options.idleTimeout.value
	}
	if options.userTimeout.set {
		defaults.UserTimeout = options.userTimeout.value
	}
	if options.congestionControl.set {
		defaults.CongestionControlFactory = options.congestionControl.value
	}
	if options.maximumPacingRate.set {
		defaults.MaximumPacingRate = options.maximumPacingRate.value
	}
	if options.trafficClass.set {
		defaults.TrafficClass = uint8(options.trafficClass.value) & 0xfc
	}
	if options.flowLabel.set {
		defaults.FlowLabel = options.flowLabel.value
	}
	return defaults
}

func (s *Stack) tcpTimestamp() uint32 {
	return s.tcpTimestampAt(time.Now())
}

func (s *Stack) tcpTimestampAt(now time.Time) uint32 {
	return uint32(now.Sub(s.timestampEpoch)/time.Millisecond) + 1
}

func tcpPAWSReject(tsval, recent uint32, recentAt, receivedAt time.Time, replayWindow uint32) bool {
	if recent == 0 || int32(recent-tsval) <= int32(replayWindow) {
		return false
	}
	return receivedAt.Sub(recentAt) < tcpPAWSMaxAge
}

func tcpPAWSReplayTicks(rto time.Duration) uint32 {
	ticks := uint64(rto / time.Millisecond)
	ticks += ticks / 5
	if ticks < uint64(tcpPAWSReplayWindow) {
		ticks = uint64(tcpPAWSReplayWindow)
	}
	return uint32(ticks)
}

func tcpTimestampEchoInRange(echo, first, last uint32) bool {
	return tcpSequenceGreaterEqual(echo, first) && tcpSequenceLessEqual(echo, last)
}

type tcpHandshakeTimestampRange struct {
	first, last uint32
	valid       bool
}

func (s *Stack) tcpInitialSequence(key tcpKey, now time.Time) uint32 {
	var connectionID [37]byte
	if key.local.Addr().Is6() {
		connectionID[0] = 6
	} else {
		connectionID[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(connectionID[1:17], local[:])
	copy(connectionID[17:33], remote[:])
	binary.BigEndian.PutUint16(connectionID[33:35], key.local.Port())
	binary.BigEndian.PutUint16(connectionID[35:37], key.remote.Port())
	elapsed := now.Sub(s.timestampEpoch)
	var timer uint32
	if elapsed > 0 {
		timer = uint32(elapsed / (4 * time.Microsecond))
	}
	return timer + uint32(sipHash24(s.tcpISNSecret, connectionID[:]))
}

func (s *Stack) handleTCP(packet ipPacket, receivedAt time.Time, localDestination, skipChecksum bool) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize || !skipChecksum && transportChecksum(packet.source, packet.target, ProtocolTCP, tcp) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	headerSize, valid := tcpWireHeaderSize(tcp[12], len(tcp))
	if !valid {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(tcp[0:2])
	targetPort := binary.BigEndian.Uint16(tcp[2:4])
	segment := tcpSegment{
		sequence: binary.BigEndian.Uint32(tcp[4:8]), acknowledgement: binary.BigEndian.Uint32(tcp[8:12]),
		flags: tcp[13], window: binary.BigEndian.Uint16(tcp[14:16]), ecn: packet.ecn,
		receivedAt: monotonicStampAt(s.timestampEpoch, receivedAt),
	}
	segment.setOptions(tcp[tcpHeaderSize:headerSize])
	payload := tcp[headerSize:]
	key := tcpKey{local: netip.AddrPortFrom(packet.target, targetPort), remote: netip.AddrPortFrom(packet.source, sourcePort)}
	s.mu.RLock()
	connection := s.tcp[key]
	s.mu.RUnlock()
	if connection != nil {
		if !connection.enqueueInboundCopy(segment, payload) {
			s.stats.inboundDroppedPackets.Add(1)
			s.stats.tcpInboundQueueDrops.Add(1)
		}
		return nil
	}
	s.mu.RLock()
	passive, forwarder := s.tcpPassive, s.tcpForwarder
	s.mu.RUnlock()
	if len(payload) != 0 {
		if localDestination && passive != nil || forwarder != nil {
			segment.payload = append([]byte(nil), payload...)
			segment.payload = segment.payload[:len(segment.payload):len(segment.payload)]
		} else {
			segment.payload = payload
		}
	}
	if localDestination && passive != nil {
		handled, err := passive.handleSegment(s, packet, segment, key)
		if handled || err != nil {
			return err
		}
	}
	if forwarder != nil && forwarder.handleSegment(segment, key) {
		return nil
	}
	if !localDestination {
		return nil
	}
	_ = s.rejectTCPSegment(key, segment)
	return nil
}

func (s *Stack) tryReplaceTCPTimeWait(connection *TCPConn, segment tcpSegment) bool {
	s.mu.RLock()
	replacer := s.tcpTimeWaitReplacer
	s.mu.RUnlock()
	if replacer == nil {
		return false
	}
	return replacer(s, connection, segment)
}

func replaceTCPTimeWait(s *Stack, connection *TCPConn, segment tcpSegment) bool {
	key := connection.key
	s.mu.Lock()
	if s.tcp[key] != connection {
		s.mu.Unlock()
		return false
	}
	passive := s.tcpPassive
	var listener *TCPListener
	if passive != nil {
		listener = passive.timeWaitListener(key.local, key.remote)
	}
	if listener != nil {
		if !listener.canReplace(connection) {
			s.mu.Unlock()
			return false
		}
		listener.synsReceived.Add(1)
		initialSequence := connection.timeWaitReplacementSequence()
		replacement := newTCPConn(s, listener.net, key, s.mtuFor(key.remote.Addr()), listener.options)
		replacement.passive = true
		replacement.reuseAddress, replacement.reusePort = listener.reuseAddress, listener.reusePort
		replacement.publishICMPSequenceRange(initialSequence, initialSequence+1)
		if !listener.trackHandshake(replacement) {
			s.mu.Unlock()
			return false
		}
		listener.statefulHandshakes.Add(1)
		s.tcp[key] = replacement
		s.mu.Unlock()
		connection.abortWithoutReset(net.ErrClosed)
		go replacement.runPassive(listener, segment, initialSequence)
		return true
	}
	forwarder := s.tcpForwarder
	if forwarder == nil {
		s.mu.Unlock()
		return false
	}
	if forwarder.handleTimeWaitSegment(segment, key) {
		delete(s.tcp, key)
		s.stats.activeTCPConnections.Add(^uint64(0))
		s.mu.Unlock()
		connection.abortWithoutReset(net.ErrClosed)
		return true
	}
	s.mu.Unlock()
	return false
}

func (s *Stack) rejectTCPSegment(key tcpKey, segment tcpSegment) error {
	if segment.flags&TCPFlagRST != 0 {
		return nil
	}
	state := s.network.Load()
	if !state.acceptsInboundDestination(key.local.Addr()) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(key.remote.Addr()); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowControlResponse(controlResponseTCPReset) {
		return nil
	}
	var sequence, acknowledgement uint32
	flags := byte(TCPFlagRST)
	if segment.flags&TCPFlagACK != 0 {
		sequence = segment.acknowledgement
	} else {
		acknowledgement = segment.sequence + uint32(len(segment.payload))
		if segment.flags&TCPFlagSYN != 0 {
			acknowledgement++
		}
		if segment.flags&TCPFlagFIN != 0 {
			acknowledgement++
		}
		flags |= TCPFlagACK
	}
	err := s.tryWriteTCPControl(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, acknowledgement, flags, 0, nil, nil, s.mtuFor(key.remote.Addr()), 0, 0, 0, false, outputFlowKey{})
	if err == ErrResourceLimit {
		return nil
	}
	return err
}

func (f *TCPForwarder) acceptTCP(request *TCPForwarderRequest, options tcpSocketOptionSet) (*TCPConn, <-chan error, error) {
	stack := f.stack
	stack.mu.Lock()
	if stack.closed {
		stack.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if stack.tcpForwarder != f {
		stack.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	state := stack.network.Load()
	if !state.acceptsInboundDestination(request.key.local.Addr()) {
		stack.mu.Unlock()
		return nil, nil, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(request.key.remote.Addr()); !routed {
		stack.mu.Unlock()
		return nil, nil, syscall.ENETUNREACH
	}
	if stack.tcp[request.key] != nil || networkStateHasLocal(state, request.key.local.Addr()) && stack.tcpPortListenedLocked(request.key.local.Addr(), request.key.local.Port()) {
		stack.mu.Unlock()
		return nil, nil, syscall.EADDRINUSE
	}
	if !stack.tcpConnectionAvailableLocked() {
		stack.mu.Unlock()
		return nil, nil, ErrResourceLimit
	}
	network := "tcp4"
	if request.key.local.Addr().Is6() {
		network = "tcp6"
	}
	connection := newTCPConn(stack, network, request.key, stack.mtuFor(request.key.remote.Addr()), options)
	connection.passive = true
	connection.forwarded = true
	initialSequence := stack.tcpInitialSequence(request.key, tcpSegmentEventTime(request.segment, time.Now(), time.Time{}, stack.timestampEpoch))
	connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
	stack.tcp[request.key] = connection
	stack.stats.activeTCPConnections.Add(1)
	stack.mu.Unlock()
	f.remove(request)
	result := make(chan error, 1)
	go connection.runForwardedPassive(request.segment, initialSequence, result)
	return connection, result, nil
}

func (s *Stack) tcpConnectionAvailableLocked() bool {
	maximum := s.network.Load().maxTCPConnections
	return maximum == 0 || len(s.tcp) < maximum
}

func (state *tcpPassiveState) handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	if key.remote.Port() == 0 {
		return false, nil
	}
	if segment.flags&TCPFlagSYN != 0 && segment.flags&(TCPFlagACK|TCPFlagRST) == 0 {
		return state.handleSYN(stack, packet, segment, key)
	}
	if segment.flags&TCPFlagACK != 0 && segment.flags&(TCPFlagSYN|TCPFlagRST) == 0 {
		return state.handleSYNCookieACK(stack, segment, key)
	}
	return false, nil
}

func (state *tcpPassiveState) timeWaitListener(local, remote netip.AddrPort) *TCPListener {
	return state.listener(local, remote)
}

func (state *tcpPassiveState) handleSYN(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	listener.synsReceived.Add(1)
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener != nil && stack.tcpConnectionAvailableLocked() {
		initialSequence := stack.tcpInitialSequence(key, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
		connection := newTCPConn(stack, listener.net, key, stack.mtuFor(packet.source), listener.options)
		connection.passive = true
		connection.reuseAddress, connection.reusePort = listener.reuseAddress, listener.reusePort
		connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
		if listener.trackHandshake(connection) {
			listener.statefulHandshakes.Add(1)
			stack.tcp[key] = connection
			stack.stats.activeTCPConnections.Add(1)
			stack.mu.Unlock()
			go connection.runPassive(listener, segment, initialSequence)
			return true, nil
		}
	}
	stack.mu.Unlock()
	if listener == nil {
		return false, nil
	}
	err := state.sendSYNCookie(stack, listener, key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
	if err == nil {
		listener.synCookiesSent.Add(1)
		stack.stats.tcpSYNCookiesSent.Add(1)
	} else if errors.Is(err, ErrResourceLimit) {
		return true, nil
	}
	return true, err
}

func (state *tcpPassiveState) handleSYNCookieACK(stack *Stack, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	initialSequence, options, valid, attempted := state.validateSYNCookie(key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
	if !valid {
		if attempted {
			listener.synCookiesRejected.Add(1)
			stack.stats.tcpSYNCookiesRejected.Add(1)
		}
		return false, nil
	}
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener == nil {
		stack.mu.Unlock()
		return false, nil
	}
	if !stack.tcpConnectionAvailableLocked() {
		stack.mu.Unlock()
		return true, nil
	}
	connection := newTCPConn(stack, listener.net, key, stack.mtuFor(key.remote.Addr()), listener.options)
	connection.passive = true
	connection.reuseAddress, connection.reusePort = listener.reuseAddress, listener.reusePort
	connection.publishICMPSequenceRange(initialSequence+1, initialSequence+1)
	connection.peerMSS = options.mss
	connection.peerWindowScale = options.windowScale
	connection.peerWindowScaling = options.windowScaling
	connection.peerSACK = options.sack
	connection.peerTimestamp = options.timestamp
	connection.recentTimestamp = options.timestampNow
	connection.peerECN = options.ecn
	connection.receiveNext = segment.sequence
	connection.peerWindow = uint32(segment.window)
	if options.windowScaling {
		connection.peerWindow <<= options.windowScale
	}
	connection.peerWindowSeq = segment.sequence
	connection.receiveWindowScale = options.localWindowScale
	if !listener.trackCompleted(connection) {
		stack.mu.Unlock()
		return true, nil
	}
	listener.synCookiesAccepted.Add(1)
	stack.stats.tcpSYNCookiesAccepted.Add(1)
	stack.tcp[key] = connection
	stack.stats.activeTCPConnections.Add(1)
	stack.mu.Unlock()
	go connection.runPassiveCookie(listener, segment, initialSequence)
	return true, nil
}

func tcpPacketLayout(source, target netip.Addr, options []byte, payloadSize, mtu int) (ipSize, headerSize, packetSize int, err error) {
	headerSize = tcpHeaderSize + (len(options)+3)&^3
	if len(options) > 40 || headerSize > 60 {
		return 0, 0, 0, errors.New("mipstack: invalid TCP options")
	}
	ipSize = ipHeaderSize(source, target, headerSize+payloadSize)
	if ipSize == 0 || ipSize+headerSize+payloadSize > mtu {
		return 0, 0, 0, syscall.EMSGSIZE
	}
	return ipSize, headerSize, ipSize + headerSize + payloadSize, nil
}

func buildTCPPacketInto(packet []byte, source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte, flowLabel uint32) ([]byte, error) {
	var view tcpPayloadView
	view.setBytes(payload)
	return buildTCPPacketViewInto(packet, source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, &view, mtu, trafficClass, ecn, flowLabel)
}

func buildTCPPacketViewInto(packet []byte, source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, mtu int, trafficClass, ecn byte, flowLabel uint32) ([]byte, error) {
	ipSize, headerSize, packetSize, err := tcpPacketLayout(source, target, options, payload.size, mtu)
	if err != nil {
		return nil, err
	}
	if len(packet) != packetSize {
		return nil, errors.New("mipstack: invalid TCP packet buffer size")
	}
	if !marshalIPHeader(packet, source, target, ProtocolTCP, 0, true, ipPacketOptions{
		trafficClass: trafficClass&0xfc | ecn&3, flowLabel: flowLabel, flowLabelSet: true,
	}) {
		return nil, syscall.EMSGSIZE
	}
	tcp := packet[ipSize:]
	for index := tcpHeaderSize; index < headerSize; index++ {
		tcp[index] = 0
	}
	copy(tcp[tcpHeaderSize:headerSize], options)
	marshalTCPHeaderFields(tcp[:headerSize], sourcePort, targetPort, sequence, acknowledgement, uint16(flags), window, 0)
	if payload.copyTo(tcp[headerSize:]) != payload.size {
		return nil, errors.New("mipstack: incomplete TCP payload view")
	}
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(source, target, ProtocolTCP, tcp))
	return packet, nil
}

func (s *Stack) tryWriteTCPControl(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte, flowLabel uint32, flowLabelSet bool, flow outputFlowKey) error {
	if source.Is6() && !flowLabelSet {
		flowLabel = s.network.Load().tcpDefaults.FlowLabel
		if flowLabel == 0 {
			flowLabel = s.automaticTransportFlowLabel(source, target, ProtocolTCP, sourcePort, targetPort)
		}
	}
	_, _, packetSize, err := tcpPacketLayout(source, target, options, len(payload), mtu)
	if err != nil {
		return err
	}
	queue, loopback := s.outputQueueFor(target)
	slot, err := s.tryReservePacket(queue)
	if err == ErrResourceLimit {
		slot, err = s.replaceBestEffortPacket(queue)
	}
	if err != nil {
		return err
	}
	var packet []byte
	var reusable bool
	if packetSize <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(packetSize)
	} else {
		packet, reusable = s.acquireLargeOutputBuffer(packetSize)
	}
	built, err := buildTCPPacketInto(packet, source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn, flowLabel)
	if err != nil {
		s.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return err
	}
	if !queue.enqueueReservedPacketForFlow(slot, built, reusable, flow, true) {
		return ErrClosed
	}
	s.recordOutput(loopback)
	return nil
}

func (c *TCPConn) deliverError(err error) {
	var networkError ICMPError
	if errors.As(err, &networkError) && networkError.MTU != 0 {
		return
	}
	c.mu.Lock()
	if c.terminalErr != nil {
		c.mu.Unlock()
		return
	}
	queued := c.pending == nil || len(c.pending.networkErrors) < tcpMaximumPendingNetworkErrors
	if queued {
		if c.pending == nil {
			c.pending = new(tcpPendingEvents)
		}
		if c.pending.networkErrors == nil {
			c.pending.networkErrors = make([]error, 0, tcpMaximumPendingNetworkErrors)
		}
		c.pending.networkErrors = append(c.pending.networkErrors, err)
	}
	c.mu.Unlock()
	if queued {
		c.wakeActor(tcpActorWakeNetworkError)
	}
}

func (c *TCPConn) takeNetworkError() (error, bool) {
	c.mu.Lock()
	if c.pending == nil || len(c.pending.networkErrors) == 0 {
		c.mu.Unlock()
		return nil, false
	}
	errors := c.pending.networkErrors
	err := errors[0]
	copy(errors, errors[1:])
	last := len(errors) - 1
	errors[last] = nil
	c.pending.networkErrors = errors[:last]
	c.mu.Unlock()
	return err, true
}

func (c *TCPConn) discardNetworkErrors() {
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return
	}
	for index := range c.pending.networkErrors {
		c.pending.networkErrors[index] = nil
	}
	c.pending.networkErrors = c.pending.networkErrors[:0]
	c.mu.Unlock()
}

func (c *TCPConn) enqueueInbound(segment tcpSegment) bool {
	if c.inbound.enqueue(segment) {
		return true
	}
	c.inboundQueueDrops.Add(1)
	return false
}

func (c *TCPConn) enqueueInboundCopy(segment tcpSegment, payload []byte) bool {
	if c.inbound.enqueueCopy(segment, payload) {
		return true
	}
	c.inboundQueueDrops.Add(1)
	return false
}

func (c *TCPConn) wakeActor(flags uint32) {
	c.updateActorWake(0, flags)
}

func (c *TCPConn) updateActorWake(clear, set uint32) {
	for {
		previous := c.actorWakeFlags.Load()
		if c.actorWakeFlags.CompareAndSwap(previous, previous&^clear|set) {
			if previous != 0 {
				return
			}
			break
		}
	}
	select {
	case c.inbound.notify <- struct{}{}:
	default:
	}
}

func (c *TCPConn) takeActorWake() uint32 { return c.actorWakeFlags.Swap(0) }

func (c *TCPConn) publishICMPSequenceRange(unacknowledged, next uint32) {
	c.icmpSequence.Store(uint64(unacknowledged)<<32 | uint64(next))
}

func (c *TCPConn) timeWaitReplacementSequence() uint32 {
	sequence := uint32(c.icmpSequence.Load()) + 65535 + 2
	if sequence == 0 {
		sequence++
	}
	return sequence
}

func (c *TCPConn) acceptsICMPQuote(quoted []byte) bool {
	if len(quoted) < 8 {
		return false
	}
	sequenceRange := c.icmpSequence.Load()
	unacknowledged := uint32(sequenceRange >> 32)
	next := uint32(sequenceRange)
	sequence := binary.BigEndian.Uint32(quoted[4:8])
	return sequence-unacknowledged <= next-unacknowledged
}

func (c *TCPConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	_, n, _, err := c.readChunk(buffer, len(buffer), nil)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.operationError("read", err)
	}
	return n, err
}

func (c *TCPConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	if getBuffer == nil {
		return 0, c.operationError("read", syscall.EINVAL)
	}
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	_, n, _, err := c.readChunk(nil, 0, getBuffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.operationError("read", err)
	}
	return n, err
}

func (c *TCPConn) readChunk(destination []byte, maximum int, getBuffer func(sizeHint int) []byte) ([]byte, int, bool, error) {
	for {
		c.mu.Lock()
		if c.userClosed || c.readClosed {
			c.mu.Unlock()
			return nil, 0, false, net.ErrClosed
		}
		timeout := c.readDeadline.channelLocked()
		select {
		case <-timeout:
			c.mu.Unlock()
			return nil, 0, false, os.ErrDeadlineExceeded
		default:
		}
		if c.readBuffer.size != 0 {
			var payload []byte
			recyclable := false
			n := 0
			if destination == nil {
				if getBuffer != nil {
					sizeHint := c.readBuffer.size
					c.mu.Unlock()
					destination = getBuffer(sizeHint)
					if len(destination) == 0 {
						return nil, 0, false, io.ErrShortBuffer
					}
					maximum = len(destination)
					continue
				}
				payload, recyclable = c.readBuffer.take(maximum)
				n = len(payload)
			} else {
				n = c.readBuffer.read(destination, maximum, c.inbound.recyclePayload)
			}
			c.mu.Unlock()
			c.applicationReads.Add(uint64(n))
			c.wakeActor(tcpActorWakeWindow)
			return payload, n, recyclable, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return nil, 0, false, err
		}
		if c.readNotify == nil {
			c.readNotify = make(chan struct{}, 1)
		}
		notified := c.readNotify
		if timeout == nil {
			timeout = c.readDeadline.waitLocked()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return nil, 0, false, os.ErrDeadlineExceeded
		case <-c.done:
		}
	}
}

func (c *TCPConn) WriteTo(writer io.Writer) (int64, error) {
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	if target, ok := writer.(*TCPConn); ok {
		return c.writeToTCP(target)
	}
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		_, n, _, readErr := c.readChunk(buffer, len(buffer), nil)
		if n > 0 {
			written, writeErr := writer.Write(buffer[:n])
			if written < 0 || written > n {
				return total, c.operationError("writeto", errors.New("mipstack: invalid Write count"))
			}
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("writeto", writeErr)
			}
			if written != n {
				return total, c.operationError("writeto", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("writeto", readErr)
		}
	}
}

func (c *TCPConn) writeToTCP(target *TCPConn) (int64, error) {
	var total int64
	for {
		payload, _, recyclable, readErr := c.readChunk(nil, 32*1024, nil)
		if len(payload) != 0 {
			written, writeErr := target.Write(payload)
			if recyclable {
				c.inbound.recyclePayload(payload)
			}
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("writeto", writeErr)
			}
			if written != len(payload) {
				return total, c.operationError("writeto", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("writeto", readErr)
		}
	}
}

func (c *TCPConn) Write(payload []byte) (int, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	written, err := c.write(payload)
	if err != nil {
		return written, c.operationError("write", err)
	}
	return written, nil
}

func (c *TCPConn) write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(payload) {
		c.mu.Lock()
		if c.userClosed || c.writeClosed || c.terminalErr != nil {
			c.sendBuffer.limited = false
			err := c.connectionErrorLocked()
			c.mu.Unlock()
			return written, err
		}
		timeout := c.writeDeadline.channelLocked()
		select {
		case <-timeout:
			c.sendBuffer.limited = false
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		default:
		}
		available := c.sendCapacity - c.sendBuffer.size
		if available > len(payload)-written {
			available = len(payload) - written
		}
		if available > 0 {
			c.sendBuffer.append(payload[written : written+available])
			written += available
		}
		var sendChanged <-chan struct{}
		if written != len(payload) {
			if c.sendChanged == nil {
				c.sendChanged = make(chan struct{}, 1)
			}
			sendChanged = c.sendChanged
			if timeout == nil {
				timeout = c.writeDeadline.waitLocked()
			}
		}
		c.sendBuffer.limited = written != len(payload)
		c.mu.Unlock()
		if available > 0 {
			c.notifySend()
		}
		if written == len(payload) {
			return written, nil
		}
		select {
		case <-sendChanged:
		case <-timeout:
			c.mu.Lock()
			c.sendBuffer.limited = false
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		case <-c.done:
			c.mu.Lock()
			c.sendBuffer.limited = false
			err := c.connectionErrorLocked()
			c.mu.Unlock()
			return written, err
		}
	}
	return written, nil
}

func (c *TCPConn) ReadFrom(reader io.Reader) (int64, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	buffer := make([]byte, 32*1024)
	var total int64
	emptyReads := 0
	for {
		n, readErr := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			return total, c.operationError("readfrom", errors.New("mipstack: invalid Read count"))
		}
		if n > 0 {
			emptyReads = 0
			written, writeErr := c.write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("readfrom", writeErr)
			}
			if written != n {
				return total, c.operationError("readfrom", io.ErrShortWrite)
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return total, c.operationError("readfrom", io.ErrNoProgress)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("readfrom", readErr)
		}
	}
}

func (c *TCPConn) CloseWrite() error {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.mu.Unlock()
	c.notifySend()
	return nil
}

func (c *TCPConn) CloseRead() error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if !c.readClosed {
		c.readClosed = true
		c.readBuffer.reset()
		c.readErr = net.ErrClosed
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeWindow)
	return nil
}

func (c *TCPConn) Close() error {
	startedAt := time.Now()
	linger := -1
	var lingerDone <-chan struct{}
	abortive := false
	c.mu.Lock()
	if c.userClosed {
		c.mu.Unlock()
		return c.operationError("close", net.ErrClosed)
	}
	c.readDeadline.stopLocked()
	c.writeDeadline.stopLocked()
	if !c.writeClosed {
		c.writeClosed = true
	}
	linger = c.linger
	abortive = linger == 0 || c.readBuffer.size != 0 || c.outOfOrderUnread.Load() != 0
	if linger > 0 && !abortive && !c.lingerComplete {
		if c.lingerDone == nil {
			c.lingerDone = make(chan struct{})
		}
		lingerDone = c.lingerDone
	}
	c.userClosed = true
	c.readErr = net.ErrClosed
	c.readBuffer.reset()
	if abortive {
		c.sendBuffer.clear()
	}
	c.notifySendChangedLocked()
	c.notifyReadLocked()
	c.mu.Unlock()
	if abortive {
		c.abort(net.ErrClosed)
		return nil
	}
	c.notifySend()
	if linger > 0 && lingerDone != nil {
		timer, timeout := deadlineTimer(startedAt.Add(tcpLingerDuration(linger)))
		select {
		case <-lingerDone:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
		case <-timeout:
			c.abort(net.ErrClosed)
		}
	}
	return nil
}

func (c *TCPConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.local) }

func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.remote) }

func (c *TCPConn) Info() TCPConnInfo {
	select {
	case <-c.done:
		if info := c.lastInfo.Load(); info != nil {
			return *info
		}
		return c.tcpConnInfoBase(TCPStateClosed)
	default:
	}
	response := make(chan TCPConnInfo, 1)
	c.mu.Lock()
	queued := c.terminalErr == nil
	if queued {
		if c.pending == nil {
			c.pending = new(tcpPendingEvents)
		}
		c.pending.infoRequests = append(c.pending.infoRequests, response)
	}
	c.mu.Unlock()
	if queued {
		c.wakeActor(tcpActorWakeInfo)
		select {
		case info := <-response:
			return info
		case <-c.done:
		}
	} else {
		<-c.done
	}
	if info := c.lastInfo.Load(); info != nil {
		return *info
	}
	return c.tcpConnInfoBase(TCPStateClosed)
}

func (c *TCPConn) takeInfoRequests() []chan TCPConnInfo {
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return nil
	}
	requests := c.pending.infoRequests
	c.pending.infoRequests = nil
	c.mu.Unlock()
	return requests
}

func (c *TCPConn) tcpConnInfoBase(state TCPState) TCPConnInfo {
	c.mu.Lock()
	info := c.tcpConnInfoBaseLocked(state)
	c.mu.Unlock()
	return info
}

func (c *TCPConn) tcpConnInfoBaseLocked(state TCPState) TCPConnInfo {
	info := TCPConnInfo{
		LocalAddress: c.key.local, RemoteAddress: c.key.remote, State: state,
		CongestionControl: c.congestionFactory.Name(),
		SendBufferSize:    c.sendBuffer.size, SendBufferCapacity: c.sendCapacity, MaximumSendBuffer: c.sendMaximum,
		ReceiveBufferSize: c.readBuffer.size + int(c.outOfOrderUnread.Load()), ReceiveBufferCapacity: c.receiveCapacity, MaximumReceiveBuffer: c.receiveMaximum,
		Retransmissions: c.retransmissions.Load(), InboundQueueDrops: c.inboundQueueDrops.Load(),
		InboundQueueBytes: c.inbound.retainedBytes(), InboundQueuePeak: c.inbound.peakBytes(), InboundQueueCapacity: tcpInboundByteCapacity,
		WindowScaling:   c.peerWindowScaling,
		PeerWindowScale: c.peerWindowScale, ReceiveWindowScale: c.receiveWindowScale,
		SACK: c.peerSACK, Timestamps: c.peerTimestamp, ECN: c.peerECN,
		KeepAlive: c.keepAlive, KeepAliveConfig: c.keepAliveConfig, IdleTimeout: c.idleTimeout, UserTimeout: c.userTimeout, NoDelay: c.noDelay,
		TrafficClass: uint8(c.trafficClass.Load()), FlowLabel: c.flowLabel, MaximumPacingRate: c.maximumPacingRate,
		LastError: c.terminalErr,
	}
	return info
}

func (c *TCPConn) respondTCPConnInfo(requests []chan TCPConnInfo, info TCPConnInfo) {
	if len(requests) == 0 {
		return
	}
	c.lastInfo.Store(&info)
	for _, response := range requests {
		response <- info
	}
}

func (c *TCPConn) noteRetransmission() {
	c.stack.stats.tcpRetransmissions.Add(1)
	c.retransmissions.Add(1)
}

func (c *TCPConn) handshakeTCPConnInfo(state TCPState, mss int, rto time.Duration) TCPConnInfo {
	info := c.tcpConnInfoBase(state)
	info.MaximumSegmentSize = mss
	info.PathMTU = c.mtu
	info.RetransmissionTimeout = rto
	info.PeerWindow = c.peerWindow
	info.ReceiveWindow = uint32(c.receiveAvailable(0))
	return info
}

func (c *TCPConn) MultipathTCP() (bool, error) { return false, nil }

func (c *TCPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.net.name(), c.LocalAddr(), c.RemoteAddr(), err)
}

func (c *TCPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net.name(), nil, c.LocalAddr(), err)
}

func (c *TCPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.readDeadline.setLocked(deadline)
	c.writeDeadline.setLocked(deadline)
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.readDeadline.setLocked(deadline)
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.writeDeadline.setLocked(deadline)
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) SetKeepAlive(enabled bool) error {
	return c.updateSocketOptions(func() { c.keepAlive = enabled })
}

func (c *TCPConn) SetKeepAlivePeriod(period time.Duration) error {
	if period <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.keepAliveConfig.Idle = period
		c.keepAliveConfig.Interval = period
	})
}

func (c *TCPConn) SetKeepAliveConfig(config KeepAliveConfig) error {
	if config.Idle <= 0 || config.Interval <= 0 || config.Count <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.keepAliveConfig = config })
}

func (c *TCPConn) SetIdleTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.idleTimeout = timeout })
}

func (c *TCPConn) SetUserTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.userTimeout = timeout })
}

func (c *TCPConn) SetNoDelay(noDelay bool) error {
	err := c.updateSocketOptions(func() { c.noDelay = noDelay })
	if err == nil {
		c.notifySend()
	}
	return err
}

func (c *TCPConn) SetQuickACK(enabled bool) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.mu.Unlock()
	wake := tcpActorWakeQuickACKDisable
	if enabled {
		wake = tcpActorWakeQuickACKEnable
	}
	c.updateActorWake(tcpActorWakeQuickACKMask, wake)
	return nil
}

func (c *TCPConn) SetCongestionControl(algorithm string) error {
	factory, exists := registeredCongestionControlFactory(algorithm)
	if !exists {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.congestionFactory = factory
		c.congestionUser = true
	})
}

func (c *TCPConn) SetCongestionControlFactory(factory *CongestionControlFactory) error {
	if !factory.valid() {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.congestionFactory = factory
		c.congestionUser = true
	})
}

func (c *TCPConn) SetMaximumPacingRate(bytesPerSecond uint64) error {
	return c.updateSocketOptions(func() { c.maximumPacingRate = bytesPerSecond })
}

func (c *TCPConn) SetTrafficClass(value int) error {
	if value < 0 || value > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.trafficClass.Store(uint32(uint8(value) & 0xfc))
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) SetLinger(seconds int) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.linger = seconds
	c.mu.Unlock()
	return nil
}

func tcpLingerDuration(seconds int) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if int64(seconds) > int64(maximum)/int64(time.Second) {
		return maximum
	}
	return time.Duration(seconds) * time.Second
}

func (c *TCPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.receiveCapacity = bytes
	c.receiveAutoTune = false
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeWindow)
	return nil
}

func (c *TCPConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.sendCapacity = bytes
	c.sendAutoTune = false
	c.sendCapacityHint.Store(int64(bytes))
	c.notifySendChangedLocked()
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) growReceiveCapacity(target int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.receiveAutoTune || target <= c.receiveCapacity {
		return false
	}
	if maximum := c.receiveCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.receiveMaximum
	if maximum <= 0 {
		maximum = tcpMaximumReceiveCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.receiveCapacity {
		return false
	}
	c.receiveCapacity = target
	return true
}

func (c *TCPConn) growSendCapacity(target int) bool {
	if target <= int(c.sendCapacityHint.Load()) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sendAutoTune || target <= c.sendCapacity {
		return false
	}
	if maximum := c.sendCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.sendMaximum
	if maximum <= 0 {
		maximum = tcpMaximumSendCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.sendCapacity {
		return false
	}
	c.sendCapacity = target
	c.sendCapacityHint.Store(int64(target))
	c.notifySendChangedLocked()
	return true
}

func (c *TCPConn) updateSocketOptions(update func()) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	update()
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeOptions)
	return nil
}

func (c *TCPConn) socketOptions() tcpSocketOptions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return tcpSocketOptions{
		keepAlive: c.keepAlive, keepAliveConfig: c.keepAliveConfig,
		idleTimeout: c.idleTimeout, userTimeout: c.userTimeout, noDelay: c.noDelay,
		congestionFactory: c.congestionFactory,
		maximumPacingRate: c.maximumPacingRate,
	}
}

func (c *TCPConn) updateDefaultCongestionControl(factory *CongestionControlFactory) {
	c.mu.Lock()
	if c.congestionUser || c.userClosed || c.terminalErr != nil || c.congestionFactory == factory {
		c.mu.Unlock()
		return
	}
	c.congestionFactory = factory
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeOptions)
}

func (c *TCPConn) abort(err error) {
	c.abortWithReset(err, true)
}

func (c *TCPConn) abortWithoutReset(err error) {
	c.abortWithReset(err, false)
}

func (c *TCPConn) abortWithReset(err error, reset bool) {
	c.abortMu.Lock()
	select {
	case <-c.abortCh:
	default:
		c.abortErr = err
		c.abortRST = reset
		close(c.abortCh)
	}
	c.abortMu.Unlock()
}

func (c *TCPConn) abortedError() error {
	c.abortMu.Lock()
	defer c.abortMu.Unlock()
	if c.abortErr == nil {
		return net.ErrClosed
	}
	return c.abortErr
}

func (c *TCPConn) takeAbortReset() bool {
	c.abortMu.Lock()
	reset := c.abortRST
	c.abortRST = false
	c.abortMu.Unlock()
	return reset
}

func (c *TCPConn) connectionErrorLocked() error {
	if c.terminalErr != nil {
		return c.terminalErr
	}
	return net.ErrClosed
}

func (c *TCPConn) notifyReadLocked() {
	if c.readNotify == nil {
		return
	}
	select {
	case c.readNotify <- struct{}{}:
	default:
	}
}

func (c *TCPConn) notifySend() {
	c.wakeActor(tcpActorWakeSend)
}

func (c *TCPConn) notifySendChangedLocked() {
	if c.sendChanged == nil {
		return
	}
	select {
	case c.sendChanged <- struct{}{}:
	default:
	}
}

func (c *TCPConn) notifyLingerDone() {
	c.mu.Lock()
	if !c.lingerComplete {
		c.lingerComplete = true
		if c.lingerDone != nil {
			close(c.lingerDone)
			c.lingerDone = nil
		}
	}
	c.mu.Unlock()
}

func (c *TCPConn) sendState() (int, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendBuffer.size, c.writeClosed, c.sendBuffer.limited
}

func (c *TCPConn) sendView(offset, maximum int, payload *tcpPayloadView) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.sendBuffer.view(offset, maximum, payload)
	return total, c.writeClosed
}

func (c *TCPConn) acknowledgeSend(size int) {
	if size <= 0 {
		return
	}
	c.mu.Lock()
	if size > c.sendBuffer.size {
		size = c.sendBuffer.size
	}
	if size != 0 {
		c.sendBuffer.acknowledge(size)
		c.notifySendChangedLocked()
	}
	c.mu.Unlock()
}

func (c *TCPConn) discardingReads() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readClosed || c.userClosed
}

func (c *TCPConn) applicationReceiveClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.userClosed
}

func (c *TCPConn) appendReadBuffer(payload []byte, owner []byte, outOfOrderBytes int) int {
	return c.appendTCPReadBuffer(payload, owner, outOfOrderBytes, false)
}

func (c *TCPConn) appendTCPReadBuffer(payload []byte, owner []byte, outOfOrderBytes int, queued bool) int {
	c.mu.Lock()
	originalSize := len(payload)
	available := c.receiveCapacity - c.readBuffer.size - outOfOrderBytes
	if c.userClosed || c.readClosed {
		accepted := len(payload)
		reset := c.userClosed && accepted != 0
		c.outOfOrderUnread.Store(int64(outOfOrderBytes))
		c.mu.Unlock()
		if reset {
			c.abort(net.ErrClosed)
		}
		return accepted
	}
	if available < 0 {
		available = 0
	}
	if len(payload) > available {
		payload = payload[:available]
	}
	if queued {
		outOfOrderBytes += originalSize - len(payload)
	}
	c.outOfOrderUnread.Store(int64(outOfOrderBytes))
	payload = retainTCPPayload(payload, owner)
	c.readBuffer.append(payload)
	if len(payload) != 0 {
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	return len(payload)
}

func retainTCPPayload(payload, owner []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) == len(owner) && cap(owner) == len(owner) && &payload[0] == &owner[0] {
		return payload[:len(payload):len(payload)]
	}
	retained := append([]byte(nil), payload...)
	return retained[:len(retained):len(retained)]
}

func (c *TCPConn) receiveAvailable(outOfOrderBytes int) int {
	available, _ := c.receiveSpace(outOfOrderBytes)
	return available
}

func (c *TCPConn) receiveSpace(outOfOrderBytes int) (available, capacity int) {
	c.mu.Lock()
	capacity = c.receiveCapacity
	available = capacity - c.readBuffer.size - outOfOrderBytes
	if c.userClosed || c.readClosed {
		available = capacity - outOfOrderBytes
	}
	c.mu.Unlock()
	return
}

func (c *TCPConn) receiveWindow(outOfOrderBytes int, scaled bool) uint16 {
	available := c.receiveAvailable(outOfOrderBytes)
	if available <= 0 {
		return 0
	}
	if scaled {
		available >>= c.receiveWindowScale
	}
	if available > 65535 {
		available = 65535
	}
	return uint16(available)
}

func (c *TCPConn) setReadEOF() {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = io.EOF
		c.notifyReadLocked()
	}
	c.mu.Unlock()
}

func (c *TCPConn) finish(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	discardReceive := false
	select {
	case <-c.stack.closeCh:
		discardReceive = true
	default:
	}
	if !discardReceive {
		select {
		case <-c.abortCh:
			discardReceive = true
		default:
		}
	}
	c.mu.Lock()
	c.terminalErr = err
	c.readDeadline.stopLocked()
	c.writeDeadline.stopLocked()
	if discardReceive {
		c.readBuffer = tcpReadBuffer{}
		c.outOfOrderUnread.Store(0)
		c.readErr = err
	} else if c.readErr == nil {
		c.readErr = err
	}
	c.sendBuffer.clear()

	c.pending = nil
	c.notifyReadLocked()
	c.notifySendChangedLocked()
	c.mu.Unlock()
	c.inbound.close()
	base := c.tcpConnInfoBase(TCPStateClosed)
	if previous := c.lastInfo.Load(); previous != nil {
		info := *previous
		info.State = TCPStateClosed
		info.SendBufferSize, info.SendBufferCapacity, info.MaximumSendBuffer = base.SendBufferSize, base.SendBufferCapacity, base.MaximumSendBuffer
		info.ReceiveBufferSize, info.ReceiveBufferCapacity, info.MaximumReceiveBuffer = base.ReceiveBufferSize, base.ReceiveBufferCapacity, base.MaximumReceiveBuffer
		info.Retransmissions = base.Retransmissions
		info.InboundQueueDrops, info.InboundQueueBytes = base.InboundQueueDrops, base.InboundQueueBytes
		info.InboundQueuePeak, info.InboundQueueCapacity = base.InboundQueuePeak, base.InboundQueueCapacity
		info.KeepAlive, info.KeepAliveConfig, info.IdleTimeout, info.UserTimeout, info.NoDelay = base.KeepAlive, base.KeepAliveConfig, base.IdleTimeout, base.UserTimeout, base.NoDelay
		info.MaximumPacingRate = base.MaximumPacingRate
		info.TrafficClass = base.TrafficClass
		info.LastError = err
		c.lastInfo.Store(&info)
	} else {
		base.LastError = err
		c.lastInfo.Store(&base)
	}
}

func (c *TCPConn) run(initialSequence uint32, connected chan<- error) {
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	var initialReceive tcpInitialReceive
	err := c.handshake(initialSequence, protocolTimer, &initialReceive)
	if err != nil {
		connected <- err
		c.finish(err)
		return
	}
	connected <- nil
	err = c.established(initialSequence+1, protocolTimer, initialReceive)
	c.finish(err)
}

func (c *TCPConn) runPassive(listener *TCPListener, syn tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if err := c.passiveHandshake(syn, initialSequence, protocolTimer, tcpHandshakeTimestampRange{}); err != nil {
		listener.noteHandshakeFailure(err)
		if errors.Is(err, net.ErrClosed) {
			_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
		}
		c.finish(err)
		return
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
		c.finish(syscall.ECONNABORTED)
		return
	}
	queued = true
	err := c.established(initialSequence+1, protocolTimer, tcpInitialReceive{payload: syn.payload, fin: syn.flags&TCPFlagFIN != 0})
	c.finish(err)
}

func (c *TCPConn) runForwardedPassive(syn tcpSegment, initialSequence uint32, result chan<- error) {
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if err := c.passiveHandshake(syn, initialSequence, protocolTimer, tcpHandshakeTimestampRange{}); err != nil {
		result <- err
		c.finish(err)
		return
	}
	result <- nil
	err := c.established(initialSequence+1, protocolTimer, tcpInitialReceive{payload: syn.payload, fin: syn.flags&TCPFlagFIN != 0})
	c.finish(err)
}

func (c *TCPConn) passiveHandshake(syn tcpSegment, initialSequence uint32, timer *ownedTimer, activeTimestampRange tcpHandshakeTimestampRange) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(syn.optionBytes(), defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
	c.peerMSS, c.peerWindowScale, c.peerWindowScaling, c.peerSACK = mss, scale, windowScaling, sack
	c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
	c.peerECN = syn.flags&(TCPFlagECE|TCPFlagCWR) == TCPFlagECE|TCPFlagCWR
	c.receiveNext = syn.sequence + 1
	c.peerWindow = uint32(syn.window)
	c.peerWindowSeq = syn.sequence

	rto := tcpInitialRTO
	transmissions := 0
	timeoutAttempts := 0
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var synSentAt time.Time
	var synHostQueue packetQueueTicket
	var hostQueueWait *packetQueueDepartureWaiter
	var optionStorage [40]byte
	var synTimestampFirst, synTimestampLast uint32
	synTimestampSent := false
	send := func(reservation tcpOutputReservation, rearm bool) error {
		c.mtu = c.stack.mtuFor(c.key.remote.Addr())
		localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
		if localMSS < 1 {
			reservation.release()
			return errors.New("mipstack: MTU is too small for TCP")
		}
		timestampNow := uint32(0)
		if timestamp {
			timestampNow = c.stack.tcpTimestamp()
		}
		options := tcpPassiveSYNOptions(optionStorage[:0], localMSS, sack, windowScaling, timestamp, c.receiveWindowScale, timestampNow, c.recentTimestamp)
		flags := byte(TCPFlagSYN | TCPFlagACK)
		if c.peerECN {
			flags |= TCPFlagECE
		}
		var payload tcpPayloadView
		hostQueue, err := c.publishReservedTCP(initialSequence, c.receiveNext, flags, c.receiveWindow(0, false), options, &payload, c.mtu, uint8(c.trafficClass.Load()), 0, reservation, tcpOutputSequenceRange{})
		if err != nil {
			return err
		}
		if timestamp {
			if !synTimestampSent {
				synTimestampFirst = timestampNow
				synTimestampSent = true
			}
			synTimestampLast = timestampNow
		}
		if hostQueueWait != nil {
			hostQueueWait = nil
			rearm = true
		}
		synHostQueue = hostQueue
		synSentAt = hostQueue.queuedTime(c.stack.timestampEpoch)
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	sendReserved := func(queue *packetQueue, slot uint16, loopback, rearm bool) error {
		reservation := tcpOutputReservation{queue: queue, slot: slot, loopback: loopback}
		select {
		case <-c.abortCh:
			reservation.release()
			return c.abortedError()
		case <-c.stack.closeCh:
			reservation.release()
			return ErrClosed
		default:
		}
		return send(reservation, rearm)
	}
	sendPending, sendRearm := true, true
	eventTime := tcpSegmentEventTime(syn, time.Now(), time.Time{}, c.stack.timestampEpoch)
	recentTimestampAt := eventTime
	var timerBacklog tcpTimerBacklog
	for {
		select {
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		default:
		}
		if hostQueueWait != nil {
			if departedAt, departed := hostQueueWait.departedTime(c.stack.timestampEpoch); departed {
				hostQueueWait = nil
				timeoutDeadline = departedAt.Add(rto)
				timeout = timer.reset(time.Until(timeoutDeadline))
			}
		}
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			activeTimeout = nil
		} else if forceTimeout && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		var outputQueue *packetQueue
		var outputLoopback bool
		var activeOutput <-chan uint16
		if sendPending && !drainBacklog && !forceTimeout {
			outputQueue, outputLoopback = c.stack.outputQueueFor(c.key.remote.Addr())
			activeOutput = outputQueue.free
			if c.actorWakeFlags.Load() == 0 && c.inbound.len() == 0 {
				select {
				case slot := <-activeOutput:
					if err := sendReserved(outputQueue, slot, outputLoopback, sendRearm); err != nil {
						if errors.Is(err, errTCPOutputRouteChanged) {
							continue
						}
						return err
					}
					sendPending, sendRearm = false, false
					continue
				default:
				}
			}
		}
		select {
		case slot := <-activeOutput:
			if err := sendReserved(outputQueue, slot, outputLoopback, sendRearm); err != nil {
				if errors.Is(err, errTCPOutputRouteChanged) {
					continue
				}
				return err
			}
			sendPending, sendRearm = false, false
		case <-inboundNotify:
			wake := c.takeActorWake()
			if wake&tcpActorWakeNetworkError != 0 {
				c.discardNetworkErrors()
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), c.handshakeTCPConnInfo(TCPStateSYNReceived, localMSS, rto))
			}
			if wake&tcpActorWakePathMTU != 0 {
				c.mtu = c.stack.mtuFor(c.key.remote.Addr())
				localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
				if localMSS < 1 {
					return errors.New("mipstack: MTU is too small for TCP")
				}
				if hostQueueWait != nil {
					sendRearm = true
				}
				sendPending = true
			}
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime, c.stack.timestampEpoch)
			eventTime = receivedAt
			segmentLength := uint32(len(segment.payload))
			if segment.flags&TCPFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&TCPFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := uint32(c.receiveWindow(0, false))
			if segment.flags&TCPFlagRST != 0 {
				if segment.sequence == c.receiveNext && (segment.flags&TCPFlagACK == 0 || transmissions != 0) {
					return syscall.ECONNRESET
				}
				if tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) && c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
				}
				continue
			}
			timestampValue, timestampEcho, timestampPresent := uint32(0), uint32(0), false
			if c.peerTimestamp {
				timestampValue, timestampEcho, timestampPresent = parseTCPTimestamp(segment.optionBytes())
				if timestampPresent && tcpPAWSReject(timestampValue, c.recentTimestamp, recentTimestampAt, receivedAt, 0) {
					if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
						_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
					}
					continue
				}
			}
			if transmissions != 0 && !c.passive && segment.flags&(TCPFlagSYN|TCPFlagACK) == TCPFlagSYN|TCPFlagACK && segment.acknowledgement == initialSequence+1 && segment.sequence+1 == c.receiveNext {
				if timestampPresent && timestampEcho != 0 && (!activeTimestampRange.valid || !tcpTimestampEchoInRange(timestampEcho, activeTimestampRange.first, activeTimestampRange.last)) {
					if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
						_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
					}
					continue
				}
				if timestampPresent {
					c.recentTimestamp = timestampValue
					recentTimestampAt = receivedAt
				}
				c.peerWindow = uint32(segment.window)
				c.peerWindowSeq = segment.sequence
				if transmissions == 1 {
					c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
				}
				timer.stop()
				_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, c.peerWindowScaling))
				return nil
			}
			if segment.flags&TCPFlagSYN != 0 && segment.flags&TCPFlagACK == 0 && segment.sequence+1 == c.receiveNext {
				if segment.flags&(TCPFlagECE|TCPFlagCWR) != TCPFlagECE|TCPFlagCWR {
					c.peerECN = false
				}
				if timestampPresent {
					c.recentTimestamp = timestampValue
					recentTimestampAt = receivedAt
				}
				if hostQueueWait != nil {
					sendRearm = true
				}
				sendPending = true
				continue
			}
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
				}
				continue
			}
			if segment.flags&TCPFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				_ = c.tryWriteTCPControl(segment.acknowledgement, 0, TCPFlagRST, 0, nil)
				continue
			}
			if segment.flags&TCPFlagACK != 0 && timestampPresent && timestampEcho != 0 &&
				(!synTimestampSent || !tcpTimestampEchoInRange(timestampEcho, synTimestampFirst, synTimestampLast)) {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
				}
				continue
			}
			if segment.flags&TCPFlagSYN != 0 {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false))
				}
				continue
			}
			if transmissions == 0 || segment.flags&TCPFlagACK == 0 || segment.acknowledgement != initialSequence+1 {
				continue
			}
			if timestampPresent {
				c.recentTimestamp = timestampValue
				recentTimestampAt = receivedAt
			}
			c.peerWindow = uint32(segment.window)
			if c.peerWindowScaling {
				c.peerWindow <<= c.peerWindowScale
			}
			c.peerWindowSeq = segment.sequence
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			if len(segment.payload) != 0 || segment.flags&TCPFlagFIN != 0 {
				if !c.inbound.prepend(segment) {
					c.inboundQueueDrops.Add(1)
					c.stack.stats.inboundDroppedPackets.Add(1)
					c.stack.stats.tcpInboundQueueDrops.Add(1)
				}
			}
			return nil
		case <-activeTimeout:
			timer.consumed()
			timeout = nil
			timeoutDeadline = time.Time{}
			if waiter := synHostQueue.departureWaiter(c.stack, c.inbound.notify); waiter != nil {
				hostQueueWait = waiter
				continue
			}
			if timeoutAttempts >= tcpPassiveSYNMaximumAttempts-1 {
				return os.ErrDeadlineExceeded
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			sendPending, sendRearm = true, true
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

func (c *TCPConn) handshake(initialSequence uint32, timer *ownedTimer, initialReceive *tcpInitialReceive) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	rto := tcpInitialRTO
	transmissions := 0
	timeoutAttempts := 0
	ecnFallback := false
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var lastSoftError error
	var synSentAt time.Time
	var synHostQueue packetQueueTicket
	var hostQueueWait *packetQueueDepartureWaiter
	var optionStorage [40]byte
	var synTimestampFirst, synTimestampLast uint32
	synTimestampSent := false
	send := func(reservation tcpOutputReservation, rearm bool) error {
		c.mtu = c.stack.mtuFor(c.key.remote.Addr())
		localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
		if localMSS < 1 {
			reservation.release()
			return errors.New("mipstack: MTU is too small for TCP")
		}
		timestampNow := c.stack.tcpTimestamp()
		options := tcpSYNOptions(optionStorage[:0], localMSS, c.receiveWindowScale, timestampNow)
		flags := byte(TCPFlagSYN)
		if !ecnFallback {
			flags |= TCPFlagECE | TCPFlagCWR
		}
		var payload tcpPayloadView
		hostQueue, err := c.publishReservedTCP(initialSequence, 0, flags, c.receiveWindow(0, false), options, &payload, c.mtu, uint8(c.trafficClass.Load()), 0, reservation, tcpOutputSequenceRange{})
		if err != nil {
			return err
		}
		if !synTimestampSent {
			synTimestampFirst = timestampNow
			synTimestampSent = true
		}
		synTimestampLast = timestampNow
		if hostQueueWait != nil {
			hostQueueWait = nil
			rearm = true
		}
		synHostQueue = hostQueue
		synSentAt = hostQueue.queuedTime(c.stack.timestampEpoch)
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	sendReserved := func(queue *packetQueue, slot uint16, loopback, rearm bool) error {
		reservation := tcpOutputReservation{queue: queue, slot: slot, loopback: loopback}
		select {
		case <-c.abortCh:
			reservation.release()
			return c.abortedError()
		case <-c.stack.closeCh:
			reservation.release()
			return ErrClosed
		default:
		}
		return send(reservation, rearm)
	}
	sendPending, sendRearm := true, true
	eventTime := time.Now()
	var timerBacklog tcpTimerBacklog
	for {
		select {
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		default:
		}
		if hostQueueWait != nil {
			if departedAt, departed := hostQueueWait.departedTime(c.stack.timestampEpoch); departed {
				hostQueueWait = nil
				timeoutDeadline = departedAt.Add(rto)
				timeout = timer.reset(time.Until(timeoutDeadline))
			}
		}
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			activeTimeout = nil
		} else if forceTimeout && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		var outputQueue *packetQueue
		var outputLoopback bool
		var activeOutput <-chan uint16
		if sendPending && !drainBacklog && !forceTimeout {
			outputQueue, outputLoopback = c.stack.outputQueueFor(c.key.remote.Addr())
			activeOutput = outputQueue.free
			if c.actorWakeFlags.Load() == 0 && c.inbound.len() == 0 {
				select {
				case slot := <-activeOutput:
					if err := sendReserved(outputQueue, slot, outputLoopback, sendRearm); err != nil {
						if errors.Is(err, errTCPOutputRouteChanged) {
							continue
						}
						return err
					}
					sendPending, sendRearm = false, false
					continue
				default:
				}
			}
		}
		select {
		case slot := <-activeOutput:
			if err := sendReserved(outputQueue, slot, outputLoopback, sendRearm); err != nil {
				if errors.Is(err, errTCPOutputRouteChanged) {
					continue
				}
				return err
			}
			sendPending, sendRearm = false, false
		case <-inboundNotify:
			wake := c.takeActorWake()
			if wake&tcpActorWakeNetworkError != 0 {
				for {
					err, ok := c.takeNetworkError()
					if !ok {
						break
					}
					if tcpActiveOpenHardError(err) {
						return err
					}
					lastSoftError = err
				}
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), c.handshakeTCPConnInfo(TCPStateSYNSent, localMSS, rto))
			}
			if wake&tcpActorWakePathMTU != 0 {
				c.mtu = c.stack.mtuFor(c.key.remote.Addr())
				localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
				if localMSS < 1 {
					return errors.New("mipstack: MTU is too small for TCP")
				}
				if hostQueueWait != nil {
					sendRearm = true
				}
				sendPending = true
			}
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime, c.stack.timestampEpoch)
			eventTime = receivedAt
			if segment.flags&TCPFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				if segment.flags&TCPFlagRST == 0 {
					_ = c.tryWriteTCPControl(segment.acknowledgement, 0, TCPFlagRST, 0, nil)
				}
				continue
			}
			if segment.flags&TCPFlagRST != 0 {
				if transmissions != 0 && segment.flags&TCPFlagACK != 0 && segment.acknowledgement == initialSequence+1 {
					return syscall.ECONNREFUSED
				}
				continue
			}
			if segment.flags&TCPFlagSYN != 0 && segment.flags&TCPFlagACK == 0 {
				timer.stop()
				if initialReceive != nil {
					*initialReceive = tcpInitialReceive{payload: segment.payload, fin: segment.flags&TCPFlagFIN != 0}
				}
				return c.passiveHandshake(segment, initialSequence, timer, tcpHandshakeTimestampRange{first: synTimestampFirst, last: synTimestampLast, valid: synTimestampSent})
			}
			if transmissions == 0 || segment.flags&(TCPFlagSYN|TCPFlagACK) != TCPFlagSYN|TCPFlagACK || segment.acknowledgement != initialSequence+1 {
				continue
			}
			mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(segment.optionBytes(), defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
			_, timestampEcho, timestampPresent := parseTCPTimestamp(segment.optionBytes())
			if timestampPresent && timestampEcho != 0 &&
				(!synTimestampSent || !tcpTimestampEchoInRange(timestampEcho, synTimestampFirst, synTimestampLast)) {
				_ = c.tryWriteTCPControl(segment.acknowledgement, 0, TCPFlagRST, 0, nil)
				continue
			}
			c.peerMSS, c.peerWindowScale, c.peerSACK = mss, scale, sack
			c.peerWindowScaling = windowScaling
			c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
			c.peerECN = !ecnFallback && segment.flags&TCPFlagECE != 0 && segment.flags&TCPFlagCWR == 0
			c.receiveNext = segment.sequence + 1
			if initialReceive != nil {
				*initialReceive = tcpInitialReceive{payload: segment.payload, fin: segment.flags&TCPFlagFIN != 0}
			}
			c.peerWindow = uint32(segment.window)
			c.peerWindowSeq = segment.sequence
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			_ = c.trySendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, c.peerWindowScaling))
			return nil
		case <-activeTimeout:
			timer.consumed()
			timeout = nil
			timeoutDeadline = time.Time{}
			if waiter := synHostQueue.departureWaiter(c.stack, c.inbound.notify); waiter != nil {
				hostQueueWait = waiter
				continue
			}
			if timeoutAttempts >= tcpActiveSYNMaximumAttempts-1 {
				return tcpTimeoutError(lastSoftError)
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			ecnFallback = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			sendPending, sendRearm = true, true
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

func (state *tcpEstablishedState) processAcknowledgment(segment *tcpSegment, receivedAt time.Time, timestampEcho uint32) {
	c := state.connection
	ack := segment.acknowledgement
	previousSendUnacknowledged := state.sendUnacknowledged
	sackScoreboardEmpty := state.sackedRanges == 0
	previousWindow := state.peerWindow
	ackAdvanced := tcpSequenceGreater(ack, state.sendUnacknowledged)
	if peerWindow, update := tcpWindowUpdate(ackAdvanced, segment.sequence, state.peerWindowSequence, segment.window, state.peerScale, state.peerWindow); update {
		state.peerWindow = peerWindow
		if state.peerWindow > state.maximumPeerWindow {
			state.maximumPeerWindow = state.peerWindow
		}
		state.peerWindowSequence = segment.sequence
	}
	recoveryAtACK := state.fastRecovery
	hadSACKedAtACK := state.sackedRanges != 0
	newlyDelivered := uint32(0)
	acknowledgedForUndo := uint32(0)
	rttSample := time.Duration(0)
	sampledRTT := false
	partialCumulativeACK := false
	rtoPartialACK := false
	sackReneging := false
	rateSACKReneging := state.sackRenegingRecovery
	ecnCongestion := false
	hadOutstandingAtACK := len(state.outstanding) != 0
	flightBeforeACK := state.congestionFlight()
	deliveryACK := state.controller.usesDeliveryRate()
	if deliveryACK {
		if state.deliverySample == nil {
			state.deliverySample = new(tcpDeliveryRateSample)
		} else {
			*state.deliverySample = tcpDeliveryRateSample{}
		}
		state.deliverySample.ackTime = receivedAt
	}
	if state.ecnRecoveryActive && state.controller.state.Phase == CongestionPhaseCWR && tcpSequenceGreaterEqual(ack, state.ecnRecoveryPoint) {
		state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
	}
	ecnFeedback := c.peerECN && segment.flags&TCPFlagECE != 0
	if ecnFeedback && state.frtoState != tcpFRTOInactive {
		if state.undo != nil {
			state.undo.active = false
		}
		state.frtoState = tcpFRTOInactive
		state.frtoProbeBudget = 0
	}
	if state.frtoState == tcpFRTOFallbackPending && ackAdvanced {
		state.frtoState = tcpFRTOInactive
		state.frtoProbeBudget = 0
	}
	if ecnFeedback && len(state.outstanding) != 0 && tcpECNStartsRecovery(state.ecnRecoveryActive, ack, state.ecnRecoveryPoint) {
		state.hyStart.disable()
		if state.undo != nil {
			state.undo.active = false
		}
		minimumWindow := state.congestionWindow <= uint32(state.peerMSS)
		flight := state.congestionFlight()
		state.slowStartThreshold, state.congestionWindow = state.controller.onECN(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, receivedAt)
		state.ecnRecoveryPoint = state.sendNext
		state.ecnRecoveryActive = true
		ecnCongestion = true
		c.sendCWR = true
		if minimumWindow {
			state.ecnHoldUntil = receivedAt.Add(state.rtt.rto)
			state.controller.cancelPacingWake()
			state.armPacingAt(state.ecnHoldUntil)
		}
	}
	if tcpSequenceGreater(ack, state.sendUnacknowledged) {
		acknowledged := ack - state.sendUnacknowledged
		acknowledgedForUndo = acknowledged
		probeSucceeded := state.pathMTUState != nil && state.pathMTUState.discovery.active && tcpSequenceGreaterEqual(ack, state.pathMTUState.discovery.probeEnd)
		newlyDelivered = tcpNewlyAcknowledgedBytes(state.outstanding, ack)
		state.bytesAcknowledged += uint64(acknowledged)
		c.acknowledgeSend(int(acknowledged))
		state.sendUnacknowledged = ack
		c.publishICMPSequenceRange(state.sendUnacknowledged, state.sendNext)
		state.duplicateACKs = 0
		state.rtoAttempts = 0
		if state.rtoRecovery {
			if tcpSequenceGreaterEqual(ack, state.rtoRecoveryPoint) && state.frtoState == tcpFRTOInactive {
				state.rtoRecovery = false
				state.rtoRecoveryPoint = 0
				state.sackRenegingRecovery = false
				state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
				state.ageRACKReordering()
			} else {
				rtoPartialACK = true
			}
		}
		state.blackHoleRTOs = 0
		if state.livenessState != nil {
			state.livenessState.lastSoftError = nil
		}
		if c.peerTimestamp && timestampEcho != 0 {
			delta := c.stack.tcpTimestampAt(receivedAt) - timestampEcho
			if delta != 0 && time.Duration(delta)*time.Millisecond <= tcpMaximumRTO {
				rttSample = time.Duration(delta) * time.Millisecond
				state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
				sampledRTT = true
			}
		}
		ambiguousRTT := tcpACKRTTAmbiguous(state.outstanding, ack)
		for len(state.outstanding) != 0 && tcpSequenceGreaterEqual(ack, state.outstanding[0].end) {
			oldest := state.outstanding[0]
			if deliveryACK {
				state.deliverySample.observe(oldest)
			}
			if oldest.state.has(sentTCPSegmentSACKed) {
				state.sackedRanges--
				state.sackedBytes -= oldest.end - oldest.sequence
			} else {
				state.observeRACKReordering(oldest.end, oldest.isRetransmitted())
			}
			transmittedAt := oldest.transmittedAt(c.stack.timestampEpoch)
			candidate := tcpRACKSample{sentAt: transmittedAt, end: oldest.end, order: oldest.transmissionOrder, rtt: elapsedRTTSampleAt(transmittedAt, receivedAt), timestamp: oldest.timestamp, retransmitted: oldest.isRetransmitted()}
			state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(candidate, state.rtt.minimum, timestampEcho))
			if !sampledRTT && !ambiguousRTT && !oldest.isRetransmitted() {
				rttSample = elapsedRTTSampleAt(transmittedAt, receivedAt)
				state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
				sampledRTT = true
			}
			if oldest.flags&TCPFlagFIN != 0 {
				state.localFINAcked = true
				c.notifyLingerDone()
			}
			state.outstanding[0] = sentTCPSegment{}
			state.outstanding = state.outstanding[1:]
			state.outstandingHead++
		}
		if len(state.outstanding) == 0 {
			state.outstanding, state.outstandingBase, state.outstandingHead = nil, nil, 0
			state.sackedRanges, state.sackedBytes = 0, 0
		}
		if len(state.outstanding) != 0 && tcpSequenceGreater(ack, state.outstanding[0].sequence) {
			partialCumulativeACK = true
			if deliveryACK {
				state.deliverySample.observe(state.outstanding[0])
			}
			if state.outstanding[0].state.has(sentTCPSegmentSACKed) {
				state.sackedBytes -= ack - state.outstanding[0].sequence
			} else {
				state.observeRACKReordering(ack, state.outstanding[0].isRetransmitted())
			}
			transmittedAt := state.outstanding[0].transmittedAt(c.stack.timestampEpoch)
			candidate := tcpRACKSample{sentAt: transmittedAt, end: ack, order: state.outstanding[0].transmissionOrder, rtt: elapsedRTTSampleAt(transmittedAt, receivedAt), timestamp: state.outstanding[0].timestamp, retransmitted: state.outstanding[0].isRetransmitted()}
			state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(candidate, state.rtt.minimum, timestampEcho))
			trimAcknowledgedTCPSegment(&state.outstanding[0], ack)
		}
		sackReneging = state.peerSACK && len(state.outstanding) != 0 && state.outstanding[0].state.has(sentTCPSegmentSACKed)
		if probeSucceeded {
			mtu := state.pathMTUState.discovery.success(receivedAt)
			c.stack.confirmPathMTU(c.key.remote.Addr(), mtu, c)
			state.ensurePathMTUState().successes++
			c.stack.stats.pathMTUProbeSuccesses.Add(1)
			state.applyPathMTU(mtu, false)
		}
		if !state.fastRecovery && state.limitedTransmitActive {
			for index := range state.outstanding {
				state.outstanding[index].state.set(sentTCPSegmentLimited, false)
			}
			state.limitedTransmitActive = false
		}
		if state.tailProbeActive && tcpSequenceGreaterEqual(ack, state.tailProbeEnd) {
			if !state.tailProbeRetransmit {
				state.tailProbeActive = false
			} else if tcpSequenceGreater(ack, state.tailProbeEnd) {
				state.controller.onTailLossProbeRecovered(receivedAt, state.tailProbeBytes, state.tailProbeState, state.congestionWindow, state.slowStartThreshold, flightBeforeACK, state.peerMSS, state.rtt.srtt)
				if !state.fastRecovery {
					if tcpECNStartsRecovery(state.ecnRecoveryActive, state.sendUnacknowledged, state.ecnRecoveryPoint) {
						state.hyStart.disable()
						state.slowStartThreshold, state.congestionWindow = state.controller.onCongestion(state.congestionWindow, flightBeforeACK, state.slowStartThreshold, state.peerMSS, receivedAt)
						state.congestionWindow = state.controller.exitRecoveryWindow(receivedAt, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerSACK)
						state.ecnRecoveryPoint = state.sendNext
						state.ecnRecoveryActive = true
						if c.peerECN {
							c.sendCWR = true
						}
					}
				}
				state.tailProbeActive = false
				state.tailProbeRetransmit = false
			}
		}
		now := receivedAt
		if state.fastRecovery {
			if tcpSequenceGreaterEqual(ack, state.recoveryPoint) {
				state.ageRACKReordering()
				state.fastRecovery = false
				state.prrPriorFlight = 0
				state.prrDelivered = 0
				state.prrOut = 0
				state.congestionWindow = state.controller.exitRecoveryWindow(receivedAt, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerSACK)
			} else if !state.peerSACK {
				state.congestionWindow = state.controller.partialACKWindow(receivedAt, state.congestionWindow, acknowledged, state.congestionFlight(), state.peerMSS)
				index := firstUnsackedSegment(state.outstanding)
				if index >= 0 {
					state.outstanding[index].state.set(sentTCPSegmentSACKRetried, false)
				}
				state.enterRecovery(index, receivedAt)
			}
		} else if !ecnCongestion && !state.controller.usesDeliveryRate() {
			growth := acknowledged
			sample := normalizedRTTSample(rttSample)
			if state.congestionWindow < state.slowStartThreshold {
				var completed bool
				growth, completed = state.hyStart.onACK(ack, state.sendNext, acknowledged, sample)
				if completed {
					state.slowStartThreshold = state.congestionWindow
				}
			}
			state.congestionWindow, state.slowStartThreshold = state.controller.onACKWithThreshold(state.congestionWindow, growth, ack, state.peerMSS, now, state.rtt.srtt, state.rtt.minimum, sample, flightBeforeACK, state.slowStartThreshold, false)
		}
		if target := state.sendAutoTune.target(receivedAt, state.rtt.srtt, state.bytesAcknowledged, c.sendMaximum); target > 0 {
			c.growSendCapacity(target)
		}
	}
	history := uint32(state.bytesAcknowledged)
	if state.bytesAcknowledged > uint64(tcpMaximumScaledWindow) {
		history = tcpMaximumScaledWindow
	}
	dsack, hasDSACK := TCPSACKBlock{}, false
	if state.peerSACK {
		dsack, hasDSACK = parseTCPDSACKOption(segment.optionBytes(), ack, state.sendNext, history)
	}
	priorDSACK := state.seenDSACK
	spuriousRecovery := state.undo != nil && ackAdvanced && state.undo.detectEifel(timestampEcho, hasDSACK, priorDSACK, ack)
	if hasDSACK {
		if !state.dsackUndoDisabled {
			matched, repeated := false, false
			if state.retransmitHistory != nil {
				matched, repeated = state.retransmitHistory.match(dsack)
			}
			switch {
			case !matched:
				state.dsackUndoDisabled = true
				if state.undo != nil {
					state.undo.dsackDisabled = true
				}
			case repeated:
				if state.undo != nil {
					state.undo.dsackDisabled = true
				}
			case state.undo != nil && state.undo.observeDSACK(dsack, ack, previousSendUnacknowledged, sackScoreboardEmpty):
				spuriousRecovery = true
			}
		}
		state.seenDSACK = true
		state.rackReorderingSeen = true
		state.rackReorderPersist = 16
		if !state.rackDSACKRoundSet || tcpSequenceGreater(ack, state.rackDSACKRound) {
			if state.rackReorderingScale != ^uint32(0) {
				state.rackReorderingScale++
			}
			state.rackDSACKRound = state.sendNext
			state.rackDSACKRoundSet = true
		}
		if state.tailProbeActive && state.tailProbeRetransmit && tcpSequenceLess(dsack.LeftEdge, state.tailProbeEnd) && tcpSequenceGreaterEqual(dsack.RightEdge, state.tailProbeEnd) {
			state.tailProbeActive = false
			state.tailProbeRetransmit = false
		}
	}
	if spuriousRecovery && ecnFeedback {
		state.undo.active = false
		state.frtoState = tcpFRTOInactive
		state.frtoProbeBudget = 0
	} else if spuriousRecovery {
		state.restoreSpuriousRecovery(receivedAt, acknowledgedForUndo)
	}
	if state.eifelRTO != nil && state.eifelRTO.observe(ack, rttSample, &state.rtt) {
		state.eifelRTO = nil
	}
	var highestSACK uint32
	hasSACK := false
	newSACKInfo := false
	frtoOriginalDelivered := false
	trackPRRLoss := recoveryAtACK && state.fastRecovery && state.peerSACK
	lostBefore := 0
	if trackPRRLoss {
		lostBefore = sackLostRangeCount(state.outstanding, state.peerMSS)
	}
	if state.peerSACK && len(state.outstanding) != 0 {
		blocks := parseTCPSACKOptions(segment.optionBytes(), state.sendUnacknowledged, state.sendNext)
		var latestSACK tcpRACKSample
		var newlySACKed []sentTCPSegment
		var earliestSACK time.Time
		if len(blocks) != 0 {
			state.compactOutstanding()
			state.outstanding, highestSACK, hasSACK, newSACKInfo, latestSACK, newlySACKed = applyTCPSACK(state.outstanding, blocks, c.stack.timestampEpoch)
			state.rebaseOutstanding()
		}
		if hasSACK {
			state.recountSACK()
		}
		for _, candidate := range newlySACKed {
			newlyDelivered = growCongestionWindow(newlyDelivered, candidate.end-candidate.sequence)
			if deliveryACK {
				state.deliverySample.observe(candidate)
			}
			if !candidate.isRetransmitted() {
				if state.frtoState != tcpFRTOInactive && tcpSequenceLess(candidate.sequence, state.rtoRecoveryPoint) {
					frtoOriginalDelivered = true
				}
				sentAt := candidate.transmittedAt(c.stack.timestampEpoch)
				if earliestSACK.IsZero() || sentAt.Before(earliestSACK) {
					earliestSACK = sentAt
				}
			}
			state.observeRACKReordering(candidate.end, candidate.isRetransmitted())
		}
		if !sampledRTT && !earliestSACK.IsZero() {
			rttSample = elapsedRTTSampleAt(earliestSACK, receivedAt)
			state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
			sampledRTT = true
		}
		latestSACK.rtt = elapsedRTTSampleAt(latestSACK.sentAt, receivedAt)
		state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(latestSACK, state.rtt.minimum, timestampEcho))
		reorderingWindow := rackReorderingWindow(state.rtt.minimum, state.rtt.srtt, state.rackReorderingScale)
		if !state.rackReorderingSeen && (state.fastRecovery || state.rtoRecovery || state.sackedRanges >= tcpDuplicateACKThreshold) {
			reorderingWindow = 0
		}
		if !sackReneging && (state.rackLatestDelivered.retransmitted || state.sackedRanges != 0) {
			state.haveRACKLoss = markRACKLoss(state.outstanding, state.rackLatestDelivered, receivedAt, reorderingWindow, c.stack.timestampEpoch)
		}
	}
	newlyLost := trackPRRLoss && sackLostRangeCount(state.outstanding, state.peerMSS) > lostBefore
	if recoveryAtACK && state.fastRecovery && state.peerSACK && newlyDelivered != 0 {
		state.prrDelivered += uint64(newlyDelivered)
		pipe := sackRecoveryPipe(state.outstanding, state.peerMSS)
		proposed := prrCongestionWindow(pipe, state.slowStartThreshold, state.prrPriorFlight, state.prrDelivered, state.prrOut, newlyDelivered, ackAdvanced, newlyLost, state.peerMSS)
		state.congestionWindow = state.controller.applyPRRWindow(receivedAt, state.congestionWindow, proposed, pipe)
	}
	probeFailed := false
	if state.pathMTUState != nil && state.pathMTUState.discovery.active && hasSACK && state.sendUnacknowledged == state.pathMTUState.discovery.probeStart && isolatedPLPMTUProbeLoss(state.outstanding, state.pathMTUState.discovery.probeStart, highestSACK, state.peerMSS) {
		state.failPLPMTUProbe()
		probeFailed = true
	}
	if !sackReneging && (hasSACK || state.haveRACKLoss) {
		state.recordProvenLosses(deliveryACK, receivedAt)
	}
	if state.tailProbeActive && state.tailProbeRetransmit && !ackAdvanced && ack == state.tailProbeEnd && previousWindow == state.peerWindow && !hasSACK && len(segment.payload) == 0 && segment.flags&TCPFlagFIN == 0 {
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
	}
	if deliveryACK && state.tailProbeActive && state.tailProbeRetransmit && ack == state.tailProbeEnd {
		state.deliverySample.tailLossProbeACK = true
	}
	if sackReneging {
		state.armSACKReneging()
	}
	duplicateEvidence := tcpDuplicateACKEvidence(*segment, state.peerSACK, newSACKInfo, ackAdvanced, state.sendUnacknowledged, previousWindow, state.peerWindow)
	if state.frtoState == tcpFRTOFallbackPending && (duplicateEvidence || sackReneging) {
		state.frtoState = tcpFRTOInactive
		state.frtoProbeBudget = 0
	}
	if state.frtoState != tcpFRTOInactive && !sackReneging {
		spurious, fallback, limitWindow := false, false, false
		probePublished := state.frtoState == tcpFRTOProbeSent || state.frtoState == tcpFRTOProbePending && state.frtoProbeBudget < 2
		if state.frtoState == tcpFRTOTimeoutPending {
			spurious = ackAdvanced
		} else if probePublished {
			if state.peerSACK {
				beyondRecovery := tcpSequenceGreater(ack, state.rtoRecoveryPoint) || hasSACK && tcpSequenceGreater(highestSACK, state.rtoRecoveryPoint)
				spurious = !beyondRecovery && (ackAdvanced || frtoOriginalDelivered)
				fallback = beyondRecovery || duplicateEvidence && !frtoOriginalDelivered
			} else {
				spurious = ackAdvanced
				fallback = duplicateEvidence
			}
			limitWindow = fallback
		} else if ackAdvanced {
			retransmissionEnd := uint32(0)
			if state.undo != nil && len(state.undo.ranges) != 0 {
				retransmissionEnd = state.undo.ranges[0].end
			}
			fallback = retransmissionEnd == 0 || tcpSequenceLess(ack, retransmissionEnd) || tcpSequenceGreaterEqual(ack, state.rtoRecoveryPoint)
			if !fallback {
				state.frtoState = tcpFRTOProbePending
				state.frtoProbeBudget = 2
				rtoPartialACK = false
			}
		} else if !state.peerSACK && duplicateEvidence {
			fallback = true
		}
		switch {
		case spurious:
			pendingTimeout := state.frtoState == tcpFRTOTimeoutPending
			if state.restoreSpuriousRecovery(receivedAt, acknowledgedForUndo) {
				rtoPartialACK = false
			} else if pendingTimeout {
				state.frtoState = tcpFRTOInactive
				state.frtoProbeBudget = 0
				if tcpSequenceGreaterEqual(ack, state.rtoRecoveryPoint) {
					state.rtoRecovery = false
					state.rtoRecoveryPoint = 0
					state.sackRenegingRecovery = false
					state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
					rtoPartialACK = false
				}
			}
		case fallback:
			state.frtoState = tcpFRTOInactive
			state.frtoProbeBudget = 0
			if limitWindow {
				limit := 3 * uint32(state.peerMSS)
				if state.congestionWindow > limit {
					state.congestionWindow = limit
				}
			}
			if tcpSequenceGreaterEqual(ack, state.rtoRecoveryPoint) {
				state.rtoRecovery = false
				state.rtoRecoveryPoint = 0
				state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
				rtoPartialACK = false
			} else {
				rtoPartialACK = true
			}
		}
	}
	if rtoPartialACK && !sackReneging {
		index := firstUnsackedSegment(state.outstanding)
		if state.peerSACK {
			index = firstRACKLoss(state.outstanding)
		}
		if index >= 0 {
			segment := &state.outstanding[index]
			if !state.peerSACK {
				segment.state.set(sentTCPSegmentSACKRetried, false)
			}
			lossObservedAt := receivedAt
			if !deliveryACK {
				lossObservedAt = time.Now()
			}
			state.controller.notePacketLoss(segment, recordTCPSegmentLoss(segment, true), deliveryACK, lossObservedAt, state.congestionWindow, state.slowStartThreshold, state.ordinaryFlight(), state.peerMSS, state.rtt.srtt)
			state.tailProbeActive = false
			state.tailProbeRetransmit = false
		}
	}
	if !sackReneging && !state.rtoRecovery && state.haveRACKLoss {
		state.enterRecovery(firstUnretriedLoss(state.outstanding, state.peerMSS), receivedAt)
		state.haveRACKLoss = hasRACKLoss(state.outstanding)
	}
	countDuplicate := duplicateEvidence && (!state.peerSACK || !state.fastRecovery)
	if !probeFailed && !state.rtoRecovery && len(state.outstanding) != 0 && countDuplicate {
		state.duplicateACKs++
		if state.duplicateACKs < tcpDuplicateACKThreshold && !state.fastRecovery {
		} else if state.duplicateACKs == tcpDuplicateACKThreshold {
			if state.peerSACK {
				state.enterRecovery(firstUnsackedSegment(state.outstanding), receivedAt)
			} else {
				state.enterRecovery(firstUnsackedSegment(state.outstanding), receivedAt)
			}
		} else if state.duplicateACKs > tcpDuplicateACKThreshold && !state.peerSACK {
			state.congestionWindow = state.controller.duplicateACKWindow(receivedAt, state.congestionWindow, state.congestionFlight(), state.peerMSS)
		}
	}
	if deliveryACK {
		if hadOutstandingAtACK {
			state.controller.finishDeliveryRateSample(state.deliverySample, newlyDelivered, flightBeforeACK, state.congestionFlight(), receivedAt, monotonicStampAt(c.stack.timestampEpoch, receivedAt), state.rtt.minimum, state.rtt.srtt, normalizedRTTSample(rttSample), rateSACKReneging)
			state.deliverySample.recovery = state.fastRecovery || state.rtoRecovery
			state.deliverySample.fastRecovery = state.fastRecovery
			state.deliverySample.ackDelayed = ackAdvanced && !partialCumulativeACK && !hadSACKedAtACK && !ecnCongestion && !hasDSACK && !state.deliverySample.recovery && state.deliverySample.losses == 0 && !state.deliverySample.retransmitted && state.deliverySample.acked < uint32(state.peerMSS) && state.deliverySample.delivered == state.deliverySample.acked
			var threshold uint32
			state.congestionWindow, threshold = state.controller.onDeliveryRateSample(state.congestionWindow, state.slowStartThreshold, state.peerMSS, ack, state.deliverySample)
			if threshold != 0 {
				state.slowStartThreshold = threshold
			}
		}
	}
	if multiplier := state.controller.sendBufferMultiplier(); hadOutstandingAtACK && newlyDelivered != 0 && multiplier != 0 {
		target := uint64(state.congestionWindow) * uint64(multiplier)
		if target > uint64(c.sendMaximum) {
			target = uint64(c.sendMaximum)
		}
		c.growSendCapacity(int(target))
	}
}

func (c *TCPConn) established(sendNext uint32, actorTimer *ownedTimer, initialReceive tcpInitialReceive) error {
	state := newTCPEstablishedState(c, sendNext)
	defer state.finish()
	var hostQueueWait *packetQueueDepartureWaiter
	var hostQueueWaitTicket packetQueueTicket
	livenessDirty := false
	ordinaryOutputWaiting, recoveryOutputWaiting := false, false
	keepAliveOutputWaiting := false
	var sendNextData func(tcpOutputWindow, uint32, bool) (tcpOutputWindow, bool, bool, error)
	sendNextData = func(outputWindow tcpOutputWindow, congestionAllowance uint32, limitedTransmit bool) (tcpOutputWindow, bool, bool, error) {
		windowFlight := state.sendNext - state.sendUnacknowledged
		if state.localFINSent || windowFlight >= state.peerWindow {
			return outputWindow, false, false, nil
		}
		congestionFlight := state.congestionFlight()
		congestionLimit := growCongestionWindow(state.congestionWindow, congestionAllowance)
		if congestionFlight >= congestionLimit {
			return outputWindow, false, false, nil
		}
		now := time.Now()
		if !state.ecnHoldUntil.IsZero() {
			if now.Before(state.ecnHoldUntil) {
				state.armPacingAt(state.ecnHoldUntil)
				return outputWindow, false, false, nil
			}
			state.ecnHoldUntil = time.Time{}
		}
		nowStamp := monotonicStampAt(c.stack.timestampEpoch, now)
		if congestionFlight == 0 && state.lastTransmission != 0 && time.Duration(nowStamp-state.lastTransmission) > state.rtt.rto && !state.controller.customWindowValidation() {
			state.slowStartThreshold = tcpCurrentSlowStartThreshold(state.congestionWindow, state.slowStartThreshold)
			state.congestionWindow = tcpRestartWindow(state.congestionWindow, state.peerMSS, time.Duration(nowStamp-state.lastTransmission), state.rtt.rto)
			state.cwndUsed = 0
			state.cwndUsageStamp = nowStamp
			state.hyStart.restartRound(state.sendNext)
			congestionLimit = growCongestionWindow(state.congestionWindow, congestionAllowance)
		}
		offset := int(state.sendNext - state.sendUnacknowledged)
		options, dsackSent := state.sackOptions(1)
		optionSize := (len(options) + 3) &^ 3
		if optionSize >= state.pathMSS {
			options = nil
			dsackSent = false
			optionSize = 0
		}
		segmentMSS := tcpSegmentPayloadLimit(state.peerMSS, state.pathMSS, optionSize)
		size := segmentMSS
		transmitMTU := c.mtu
		probe := false
		probePayload := 0
		canProbePath := state.pathMTUState != nil && state.pathMTUState.discovery.searching && !state.fastRecovery && !state.rtoRecovery && state.sackedRanges == 0
		if canProbePath {
			candidateMTU, ok := state.pathMTUState.discovery.candidate(now)
			if ok {
				candidateMSS := tcpMSSForMTU(candidateMTU, c.key.local.Addr())
				candidateMSS = tcpEffectiveSendMSS(c.peerMSS, candidateMSS, c.peerTimestamp)
				candidateMSS -= optionSize
				total, _, _ := c.sendState()
				if candidateMSS > segmentMSS && total-offset >= candidateMSS+(tcpDuplicateACKThreshold+1)*segmentMSS {
					size = candidateMSS
					probePayload = candidateMSS
					transmitMTU = candidateMTU
					probe = true
				}
			}
		}
		if available := int(state.peerWindow - windowFlight); size > available {
			size = available
		}
		if available := int(congestionLimit - congestionFlight); size > available {
			size = available
		}
		if probe && size != probePayload {
			probe = false
			transmitMTU = c.mtu
			if size > segmentMSS {
				size = segmentMSS
			}
		}
		if size <= 0 {
			return outputWindow, false, false, nil
		}
		var payload tcpPayloadView
		total, writeClosed := c.sendView(offset, size, &payload)
		if payload.size == 0 {
			return outputWindow, false, false, nil
		}
		if delay := state.controller.pacingDelay(now, payload.size, state.congestionWindow, congestionFlight, state.peerMSS, state.rtt.srtt, state.slowStartThreshold); delay > 0 {
			state.armPacingAt(now.Add(delay))
			return outputWindow, false, false, nil
		}
		if congestionAllowance == 0 {
			if len(state.outstanding) != 0 && payload.size < segmentMSS && !writeClosed && !c.socketOptions().noDelay {
				return outputWindow, false, false, nil
			}
		}
		flags := byte(TCPFlagACK)
		if offset+payload.size == total {
			flags |= TCPFlagPSH
		}
		next := state.sendNext + uint32(payload.size)
		window, right := state.nextAdvertisedReceiveWindow()
		reservation, outputWindow, available := outputWindow.reserve(c)
		if !available {
			return outputWindow, false, true, nil
		}
		published, err := c.publishReservedPayloadForMTU(state.sendNext, state.receiveNext, flags, window, options, &payload, true, transmitMTU, reservation, tcpOutputSequenceRange{
			unacknowledged: state.sendUnacknowledged,
			next:           next,
		})
		if err != nil {
			return outputWindow, false, false, err
		}
		hostQueue := published.hostQueue
		transmissionOrder := state.recordTransmission(hostQueue)
		if published.carriesCWR {
			c.sendCWR = false
		}
		sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
		if dsackSent {
			state.haveRecentDSACK = false
		}
		state.commitAcknowledgment(window, right, len(options) != 0)
		state.observeSentData(hostQueue.queuedAt)
		rate, updatedWindow := state.controller.onDataSend(payload.size, state.peerMSS, sentAt, hostQueue.queuedAt, windowFlight, state.congestionWindow, congestionFlight, state.rtt.srtt, state.slowStartThreshold)
		state.congestionWindow = updatedWindow
		state.appendOutstanding(sentTCPSegment{sequence: state.sendNext, end: next, flags: flags, timestamp: published.timestamp, state: sentTCPSegmentInitialState(limitedTransmit, published.carriesCWR, probe, state.controller.schedulerLimited()), firstSent: sentAt.Sub(c.stack.timestampEpoch), hostQueue: hostQueue, congestionPacketState: state.controller.transmissionState(), delivery: rate, transmissionOrder: transmissionOrder}, offset+payload.size < total)
		state.bytesSent += uint64(payload.size)
		if probe {
			state.pathMTUState.discovery.sent(transmitMTU, state.sendNext, next)
			state.ensurePathMTUState().probes++
			c.stack.stats.pathMTUProbes.Add(1)
		}
		if state.fastRecovery && state.peerSACK {
			state.prrOut += uint64(payload.size)
		}
		state.sendNext = next
		livenessDirty = true
		return outputWindow, true, false, nil
	}
	flushACK := func(first tcpOutputReservation) error {
		if !state.ackPending {
			if first.queue != nil {
				first.release()
			}
			return nil
		}
		if tcpTimerOutputPending(state, hostQueueWait != nil) || tcpPersistOutputPending(state) || keepAliveOutputWaiting {
			if first.queue != nil {
				first.release()
			}
			return nil
		}
		state.delayedACK = false
		state.delayedACKDeadline = time.Time{}
		outputWindow := newTCPOutputWindow(first)
		var sent bool
		var blocked bool
		var err error
		outputWindow, sent, blocked, err = sendNextData(outputWindow, 0, false)
		if errors.Is(err, errTCPOutputRouteChanged) {
			ordinaryOutputWaiting = true
			outputWindow.release()
			return nil
		}
		if err != nil || blocked {
			if blocked {
				ordinaryOutputWaiting = true
			}
			outputWindow.release()
			return err
		}
		if sent {
			state.updateRetransmissionTimer(tcpRetransmissionPreserve, state.eventTime)
		}
		if state.ackPending {
			var reservation tcpOutputReservation
			var available bool
			reservation, outputWindow, available = outputWindow.reserve(c)
			if !available {
				ordinaryOutputWaiting = true
				outputWindow.release()
				return nil
			}
			if err = state.sendACK(reservation); errors.Is(err, errTCPOutputRouteChanged) {
				ordinaryOutputWaiting = true
				outputWindow.release()
				return nil
			} else if err != nil {
				outputWindow.release()
				return err
			}
		}
		outputWindow.release()
		return nil
	}
	var retransmitRTORecovery func(tcpOutputWindow, int) (tcpOutputWindow, bool, error)
	fillWindow := func(retransmissionUpdate tcpRetransmissionUpdate, first tcpOutputReservation) error {
		if tcpTimerOutputPending(state, hostQueueWait != nil) || tcpPersistOutputPending(state) {
			if first.queue != nil {
				first.release()
			}
			return nil
		}
		outputWindow := newTCPOutputWindow(first)
		livenessDirty = true
		capacityBlocked := false
		for state.frtoState == tcpFRTOProbePending {
			allowance := 2 * uint32(state.peerMSS)
			if flight := state.congestionFlight(); flight > state.congestionWindow {
				allowance = growCongestionWindow(allowance, flight-state.congestionWindow)
			}
			var sent, blocked bool
			var err error
			outputWindow, sent, blocked, err = sendNextData(outputWindow, allowance, false)
			if err != nil {
				if errors.Is(err, errTCPOutputRouteChanged) {
					ordinaryOutputWaiting = true
					outputWindow.release()
					return nil
				}
				outputWindow.release()
				return err
			}
			if blocked {
				capacityBlocked = true
				break
			}
			if sent {
				state.frtoProbeBudget--
				if state.frtoProbeBudget == 0 {
					state.frtoState = tcpFRTOProbeSent
				}
				continue
			}
			if state.frtoProbeBudget == 2 {
				state.frtoState = tcpFRTOFallbackPending
				state.frtoProbeBudget = 0
				outputWindow, blocked, err = retransmitRTORecovery(outputWindow, firstUnsackedSegment(state.outstanding))
				if err != nil {
					outputWindow.release()
					return err
				}
				if blocked {
					recoveryOutputWaiting = true
					capacityBlocked = true
				} else {
					state.frtoState = tcpFRTOInactive
				}
			} else {
				state.frtoState = tcpFRTOProbeSent
				state.frtoProbeBudget = 0
			}
			break
		}
		if state.localFINSent {
			state.updateRetransmissionTimer(retransmissionUpdate, state.eventTime)
			state.armPersist(time.Time{}, 0, false)
			outputWindow.release()
			return nil
		}
		limitedTransmit := !state.rtoRecovery && !state.fastRecovery && state.duplicateACKs > 0 && state.duplicateACKs < tcpDuplicateACKThreshold
		for limitedTransmit && !capacityBlocked {
			var sent, blocked bool
			var err error
			outputWindow, sent, blocked, err = sendNextData(outputWindow, uint32(state.duplicateACKs*state.peerMSS), true)
			if err != nil {
				if errors.Is(err, errTCPOutputRouteChanged) {
					ordinaryOutputWaiting = true
					outputWindow.release()
					return nil
				}
				outputWindow.release()
				return err
			}
			if blocked {
				capacityBlocked = true
				break
			}
			if !sent {
				break
			}
			state.limitedTransmitActive = true
		}
		for !capacityBlocked {
			var sent, blocked bool
			var err error
			outputWindow, sent, blocked, err = sendNextData(outputWindow, 0, false)
			if err != nil {
				if errors.Is(err, errTCPOutputRouteChanged) {
					ordinaryOutputWaiting = true
					outputWindow.release()
					return nil
				}
				outputWindow.release()
				return err
			}
			if blocked {
				capacityBlocked = true
				break
			}
			if !sent {
				break
			}
		}
		offset := int(state.sendNext - state.sendUnacknowledged)
		total, writeClosed, sendBufferLimited := c.sendState()
		if !state.controller.customWindowValidation() {
			state.validateCongestionWindow(monotonicStampAt(c.stack.timestampEpoch, time.Now()), total-offset, sendBufferLimited)
		}
		if state.ecnHoldUntil.IsZero() || !time.Now().Before(state.ecnHoldUntil) {
			windowFlight := state.sendNext - state.sendUnacknowledged
			congestionFlight := state.congestionFlight()
			hostQueued := false
			usesDeliveryRate := state.controller.usesDeliveryRate()
			if usesDeliveryRate && total-offset < state.peerMSS && len(state.outstanding) != 0 {
				hostQueued = state.outstanding[len(state.outstanding)-1].hostQueue.pending(c.stack)
			}
			if usesDeliveryRate && tcpRateApplicationLimited(total-offset, hostQueued, congestionFlight, state.congestionWindow, state.fastRecovery, state.peerSACK, state.outstanding, state.peerMSS) {
				state.controller.markApplicationLimited(congestionFlight)
			}
			if writeClosed && offset >= total && windowFlight < state.peerWindow && congestionFlight < state.congestionWindow {
				var reservation tcpOutputReservation
				var available bool
				reservation, outputWindow, available = outputWindow.reserve(c)
				if available {
					options, dsackSent := state.sackOptions(0)
					window, right := state.nextAdvertisedReceiveWindow()
					var payload tcpPayloadView
					published, err := c.publishReservedPayloadForMTU(state.sendNext, state.receiveNext, TCPFlagACK|TCPFlagFIN, window, options, &payload, false, c.mtu, reservation, tcpOutputSequenceRange{
						unacknowledged: state.sendUnacknowledged,
						next:           state.sendNext + 1,
					})
					if err != nil {
						if errors.Is(err, errTCPOutputRouteChanged) {
							ordinaryOutputWaiting = true
							outputWindow.release()
							return nil
						}
						outputWindow.release()
						return err
					}
					hostQueue := published.hostQueue
					transmissionOrder := state.recordTransmission(hostQueue)
					sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
					if dsackSent {
						state.haveRecentDSACK = false
					}
					state.commitAcknowledgment(window, right, len(options) != 0)
					state.appendOutstanding(sentTCPSegment{sequence: state.sendNext, end: state.sendNext + 1, flags: TCPFlagACK | TCPFlagFIN, timestamp: published.timestamp, state: sentTCPSegmentTransmitted, firstSent: sentAt.Sub(c.stack.timestampEpoch), hostQueue: hostQueue, transmissionOrder: transmissionOrder}, false)
					state.sendNext++
					state.timeWaitRequired = !state.remoteFINReceived
					state.localFINSent = true
				} else {
					capacityBlocked = true
				}
			}
		}
		state.updateRetransmissionTimer(retransmissionUpdate, state.eventTime)
		state.armPersist(time.Time{}, total, writeClosed)
		if capacityBlocked {
			ordinaryOutputWaiting = true
		}
		outputWindow.release()
		return nil
	}
	publishRetransmission := func(outputWindow tcpOutputWindow, index int, timeout bool) (tcpOutputWindow, bool, error) {
		if index < 0 || index >= len(state.outstanding) {
			return outputWindow, false, nil
		}
		oldest := &state.outstanding[index]
		rackRetransmission := oldest.state.has(sentTCPSegmentRACKLost)
		repeated := oldest.isRetransmitted()
		window, right := state.nextAdvertisedReceiveWindow()
		outputWindow, published, blocked, err := c.publishBufferedSegmentForMTU(state.sendUnacknowledged, *oldest, state.receiveNext, window, nil, false, c.mtu, outputWindow)
		if err != nil || blocked {
			return outputWindow, blocked, err
		}
		hostQueue := published.hostQueue
		transmissionOrder := state.recordTransmission(hostQueue)
		state.recordRetransmission(oldest.sequence, oldest.end)
		if state.undo != nil {
			state.undo.recordRetransmission(oldest.sequence, oldest.end, published.timestamp, repeated)
		}
		state.commitAcknowledgment(window, right, false)
		oldest.timestamp = published.timestamp
		oldest.hostQueue = hostQueue
		oldest.transmissionOrder = transmissionOrder
		oldest.advanceTransmissionGeneration()
		oldest.state.set(sentTCPSegmentSACKRetried, true)
		oldest.state.set(sentTCPSegmentRACKLost, false)
		if rackRetransmission {
			state.haveRACKLoss = hasRACKLoss(state.outstanding)
		}
		oldest.state.set(sentTCPSegmentCWR, false)
		c.noteRetransmission()
		if !timeout && state.peerSACK {
			c.stack.stats.tcpSACKRetransmissions.Add(1)
			if rackRetransmission {
				c.stack.stats.tcpRACKRetransmissions.Add(1)
			}
			firstRecoverySend := state.fastRecovery && state.prrOut == 0
			if state.fastRecovery {
				state.prrOut += uint64(oldest.dataSize())
			}
			if firstRecoverySend {
				state.congestionWindow = sackRecoveryPipe(state.outstanding, state.peerMSS)
			}
		}
		if timeout && len(state.outstanding) != 0 {
			if state.frtoState == tcpFRTOTimeoutPending {
				state.frtoState = tcpFRTOAwaitingACK
			}
			state.armRetransmission()
		}
		oldest.delivery = state.controller.onRetransmit(oldest.dataSize(), state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch), oldest.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		oldest.congestionPacketState = state.controller.transmissionState()
		oldest.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		return outputWindow, false, nil
	}
	retransmitRTORecovery = func(outputWindow tcpOutputWindow, index int) (tcpOutputWindow, bool, error) {
		if len(state.outstanding) == 0 {
			return outputWindow, false, nil
		}
		if index < 0 || index >= len(state.outstanding) {
			return outputWindow, false, nil
		}
		segment := &state.outstanding[index]
		window, right := state.nextAdvertisedReceiveWindow()
		outputWindow, published, blocked, err := c.publishBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu, outputWindow)
		if err != nil || blocked {
			return outputWindow, blocked, err
		}
		hostQueue := published.hostQueue
		transmissionOrder := state.recordTransmission(hostQueue)
		state.recordRetransmission(segment.sequence, segment.end)
		if state.undo != nil {
			state.undo.recordRetransmission(segment.sequence, segment.end, published.timestamp, segment.isRetransmitted())
		}
		state.commitAcknowledgment(window, right, false)
		if segment.state.has(sentTCPSegmentCWR) && c.peerECN {
			c.sendCWR = true
		}
		segment.state.set(sentTCPSegmentCWR, false)
		segment.timestamp = published.timestamp
		segment.hostQueue = hostQueue
		segment.transmissionOrder = transmissionOrder
		state.controller.notePacketLoss(segment, recordTCPSegmentLoss(segment, true), false, time.Now(), state.congestionWindow, state.slowStartThreshold, state.ordinaryFlight(), state.peerMSS, state.rtt.srtt)
		segment.advanceTransmissionGeneration()
		segment.state.set(sentTCPSegmentSACKRetried, true)
		rackLost := segment.state.has(sentTCPSegmentRACKLost)
		segment.state.set(sentTCPSegmentRACKLost, false)
		if rackLost {
			state.haveRACKLoss = hasRACKLoss(state.outstanding)
		}
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
		c.noteRetransmission()
		segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.ordinaryFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		segment.congestionPacketState = state.controller.transmissionState()
		segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		return outputWindow, false, nil
	}
	drainTimerOutput := func(first tcpOutputReservation) error {
		outputWindow := newTCPOutputWindow(first)
		if !tcpTimerOutputPending(state, hostQueueWait != nil) {
			outputWindow.release()
			return nil
		}
		retransmissionKind := state.retransmissionKind
		pendingIndex := state.retransmissionTarget(retransmissionKind)
		if pendingIndex < 0 {
			outputWindow.release()
			return nil
		}
		if retransmissionKind == tcpRetransmissionRTO {
			var err error
			outputWindow, _, err = publishRetransmission(outputWindow, pendingIndex, true)
			outputWindow.release()
			return err
		}

		outputWindow, sent, blocked, err := sendNextData(outputWindow, uint32(state.peerMSS), false)
		if errors.Is(err, errTCPOutputRouteChanged) {
			blocked, err = true, nil
		}
		if err != nil || blocked {
			outputWindow.release()
			return err
		}
		probeSentAt := time.Time{}
		if sent {
			probeSentAt = state.outstanding[len(state.outstanding)-1].transmittedAt(c.stack.timestampEpoch)
		}
		state.tailProbeRetransmit = !sent
		state.tailProbeBytes = 0
		state.tailProbeState = 0
		if !sent {
			segment := &state.outstanding[pendingIndex]
			originalCongestionState := segment.congestionPacketState
			window, right := state.nextAdvertisedReceiveWindow()
			var published tcpPublishedTransmission
			outputWindow, published, blocked, err = c.publishBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu, outputWindow)
			if err != nil || blocked {
				outputWindow.release()
				return err
			}
			hostQueue := published.hostQueue
			transmissionOrder := state.recordTransmission(hostQueue)
			state.recordRetransmission(segment.sequence, segment.end)
			sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
			state.commitAcknowledgment(window, right, false)
			segment.timestamp = published.timestamp
			segment.hostQueue = hostQueue
			segment.transmissionOrder = transmissionOrder
			probeSentAt = sentAt
			segment.advanceTransmissionGeneration()
			c.noteRetransmission()
			segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
			segment.congestionPacketState = state.controller.transmissionState()
			state.tailProbeBytes = segment.dataSize()
			state.tailProbeState = originalCongestionState
			segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		}
		state.tailProbeActive = true
		state.tailProbeEnd = state.sendNext
		state.tailProbeRTTSamples = state.rtt.samples
		c.stack.stats.tcpTailLossProbes.Add(1)
		state.armRetransmissionAfterACK(probeSentAt)
		outputWindow.release()
		return nil
	}
	drainPersistOutput := func(first tcpOutputReservation) error {
		outputWindow := newTCPOutputWindow(first)
		if !tcpPersistOutputPending(state) {
			outputWindow.release()
			return nil
		}
		reservation, outputWindow, available := outputWindow.reserve(c)
		if !available {
			outputWindow.release()
			return nil
		}
		window, right := state.nextAdvertisedReceiveWindow()
		var payload tcpPayloadView
		payload.setBytes(tcpZeroWindowProbe[:])
		published, err := c.publishReservedPayloadForMTU(state.sendUnacknowledged-1, state.receiveNext, TCPFlagACK, window, nil, &payload, false, c.mtu, reservation, tcpOutputSequenceRange{})
		if errors.Is(err, errTCPOutputRouteChanged) {
			outputWindow.release()
			return nil
		}
		if err != nil {
			outputWindow.release()
			return err
		}
		hostQueue := published.hostQueue
		probeSentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
		state.commitAcknowledgment(window, right, false)
		c.stack.stats.tcpZeroWindowProbes.Add(1)
		if c.applicationReceiveClosed() {
			state.sendTimer.persistAttempts++
		}
		state.persist = false
		state.sendTimer.persistRTO *= 2
		if state.sendTimer.persistRTO > tcpMaximumRTO {
			state.sendTimer.persistRTO = tcpMaximumRTO
		}
		total, writeClosed, _ := c.sendState()
		state.armPersist(probeSentAt, total, writeClosed)
		outputWindow.release()
		return nil
	}
	drainKeepAliveOutput := func(first tcpOutputReservation) error {
		outputWindow := newTCPOutputWindow(first)
		if !keepAliveOutputWaiting {
			outputWindow.release()
			return nil
		}
		options := c.socketOptions()
		if !options.keepAlive || !state.keepAliveEligible() {
			keepAliveOutputWaiting = false
			outputWindow.release()
			return nil
		}
		reservation, outputWindow, available := outputWindow.reserve(c)
		if !available {
			outputWindow.release()
			return nil
		}
		probeSequence := state.sendNext - 1
		window, right := state.nextAdvertisedReceiveWindow()
		var payload tcpPayloadView
		sequenceRange := tcpOutputSequenceRange{}
		if probeSequence-state.sendUnacknowledged > state.sendNext-state.sendUnacknowledged {
			sequenceRange = tcpOutputSequenceRange{unacknowledged: probeSequence, next: state.sendNext}
		}
		published, err := c.publishReservedPayloadForMTU(probeSequence, state.receiveNext, TCPFlagACK, window, nil, &payload, false, c.mtu, reservation, sequenceRange)
		if errors.Is(err, errTCPOutputRouteChanged) {
			outputWindow.release()
			return nil
		}
		if err != nil {
			outputWindow.release()
			return err
		}
		hostQueue := published.hostQueue
		state.commitAcknowledgment(window, right, false)
		liveness := state.ensureLivenessState()
		liveness.keepAliveProbes++
		liveness.lastKeepAlive = hostQueue.queuedTime(c.stack.timestampEpoch)
		c.stack.stats.tcpKeepAliveProbes.Add(1)
		keepAliveOutputWaiting = false
		outputWindow.release()
		return nil
	}
	drainPathMTURetransmission := func(outputWindow tcpOutputWindow) (tcpOutputWindow, bool, error) {
		if !state.retransmit || state.retransmissionKind != tcpRetransmissionPathMTU {
			return outputWindow, false, nil
		}
		index := firstUnsackedSegment(state.outstanding)
		if index < 0 {
			state.armRetransmission()
			return outputWindow, false, nil
		}
		segment := &state.outstanding[index]
		repeated := segment.isRetransmitted()
		window, right := state.nextAdvertisedReceiveWindow()
		outputWindow, published, blocked, err := c.publishBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu, outputWindow)
		if err != nil || blocked {
			return outputWindow, blocked, err
		}
		hostQueue := published.hostQueue
		transmissionOrder := state.recordTransmission(hostQueue)
		state.recordRetransmission(segment.sequence, segment.end)
		if state.undo != nil {
			state.undo.recordRetransmission(segment.sequence, segment.end, published.timestamp, repeated)
		}
		state.commitAcknowledgment(window, right, false)
		if segment.state.has(sentTCPSegmentCWR) && c.peerECN {
			c.sendCWR = true
		}
		segment.state.set(sentTCPSegmentCWR, false)
		segment.timestamp = published.timestamp
		segment.hostQueue = hostQueue
		segment.transmissionOrder = transmissionOrder
		segment.advanceTransmissionGeneration()
		segment.state.set(sentTCPSegmentRACKLost, false)
		segment.state.set(sentTCPSegmentSACKRetried, true)
		state.haveRACKLoss = hasRACKLoss(state.outstanding)
		c.noteRetransmission()
		segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		segment.congestionPacketState = state.controller.transmissionState()
		segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		if state.frtoState == tcpFRTOTimeoutPending {
			state.frtoState = tcpFRTOAwaitingACK
		}
		state.armRetransmission()
		return outputWindow, false, nil
	}
	drainPathMTU := func(first tcpOutputReservation) error {
		outputWindow := newTCPOutputWindow(first)
		outputWindow, blocked, err := drainPathMTURetransmission(outputWindow)
		if blocked {
			recoveryOutputWaiting = true
		}
		outputWindow.release()
		return err
	}
	drainRecovery := func(first tcpOutputReservation) error {
		outputWindow := newTCPOutputWindow(first)
		if tcpTimerOutputPending(state, hostQueueWait != nil) || tcpPersistOutputPending(state) {
			outputWindow.release()
			return nil
		}
		var blocked bool
		var err error
		outputWindow, blocked, err = drainPathMTURetransmission(outputWindow)
		if err == nil && !blocked && state.rtoRecovery && state.frtoState == tcpFRTOFallbackPending {
			outputWindow, blocked, err = retransmitRTORecovery(outputWindow, firstUnsackedSegment(state.outstanding))
			if err == nil && !blocked {
				state.frtoState = tcpFRTOInactive
				state.frtoProbeBudget = 0
			}
			if blocked {
				recoveryOutputWaiting = true
			}
			outputWindow.release()
			return err
		}
		if err == nil && !blocked && state.rtoRecovery && state.frtoState == tcpFRTOInactive && len(state.outstanding) != 0 {
			index := firstUnsackedSegment(state.outstanding)
			if state.peerSACK {
				index = firstRACKLoss(state.outstanding)
			} else if index >= 0 && state.outstanding[index].state.has(sentTCPSegmentSACKRetried) {
				index = -1
			}
			outputWindow, blocked, err = retransmitRTORecovery(outputWindow, index)
		}
		if err == nil && !blocked && len(state.outstanding) != 0 {
			if state.peerSACK && (state.fastRecovery || state.haveRACKLoss) {
				highest := uint32(0)
				if state.fastRecovery {
					highest = highestSACKedSequence(state.outstanding)
				}
				for {
					index := firstUnretriedLoss(state.outstanding, state.peerMSS)
					if index < 0 && state.fastRecovery {
						index = firstUnretriedSACKHole(state.outstanding, highest)
					}
					if index < 0 {
						break
					}
					size := state.outstanding[index].end - state.outstanding[index].sequence
					pipe := sackRecoveryPipe(state.outstanding, state.peerMSS)
					if !sackRecoveryCanSend(state.fastRecovery, pipe, size, state.congestionWindow) {
						break
					}
					if state.fastRecovery {
						now := time.Now()
						if delay := state.controller.pacingDelay(now, int(size), state.congestionWindow, pipe, state.peerMSS, state.rtt.srtt, state.slowStartThreshold); delay > 0 {
							state.armPacingAt(now.Add(delay))
							break
						}
					}
					outputWindow, blocked, err = publishRetransmission(outputWindow, index, false)
					if err != nil || blocked {
						break
					}
				}
			} else if !state.peerSACK && state.fastRecovery {
				index := firstUnsackedSegment(state.outstanding)
				if index >= 0 && !state.outstanding[index].state.has(sentTCPSegmentSACKRetried) {
					outputWindow, blocked, err = publishRetransmission(outputWindow, index, false)
				}
			}
		}
		if blocked {
			recoveryOutputWaiting = true
		}
		outputWindow.release()
		return err
	}
	if len(initialReceive.payload) != 0 || initialReceive.fin {
		payload := initialReceive.payload
		fin := initialReceive.fin
		previousReceiveNext := state.receiveNext
		_, closed := c.receiveTCPData(state.receiveNext, payload, fin, state.receiveWindowState.size(state.receiveNext), &state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
		advanced := state.receiveNext - previousReceiveNext
		if closed && advanced != 0 {
			advanced--
		}
		state.bytesReceived += uint64(advanced)
		if closed {
			state.remoteFINReceived = true
			c.setReadEOF()
		}
		receivedAt := time.Now()
		if len(payload) != 0 {
			state.observeReceivedData(receivedAt)
		}
		if state.scheduleACK(true, len(payload) != 0, receivedAt) {
			if err := flushACK(tcpOutputReservation{}); err != nil {
				return err
			}
		}
	}
	state.armPathMTUProbe()
	state.armLiveness(false)
	livenessDirty = false
	var timerBacklog tcpTimerBacklog
	const (
		actorTimerNone = iota
		actorTimerRetransmission
		actorTimerPersist
		actorTimerDelayedACK
		actorTimerLiveness
		actorTimerPathMTU
		actorTimerPacing
	)
	for {
		if hostQueueWait != nil {
			matchingTarget := false
			if state.retransmit && state.retransmissionKind != tcpRetransmissionClose {
				index := state.retransmissionTarget(state.retransmissionKind)
				matchingTarget = index >= 0 && state.outstanding[index].hostQueue.token == hostQueueWaitTicket.token
			}
			departedAt, departed := hostQueueWait.departedTime(c.stack.timestampEpoch)
			if departed || !matchingTarget {
				hostQueueWait = nil
				hostQueueWaitTicket = packetQueueTicket{}
				if state.retransmit && state.retransmissionKind == tcpRetransmissionPathMTU {
					state.retransmissionDeadline = time.Time{}
				} else if departed && matchingTarget {
					state.selectRetransmission(departedAt.Add(state.rtt.rto), departedAt, departedAt)
				} else if len(state.outstanding) != 0 && (!state.retransmit || state.retransmissionDeadline.IsZero()) {
					state.armRetransmission()
				}
			} else {
				state.retransmissionDeadline = time.Time{}
			}
		}
		if livenessDirty {
			state.armLiveness(keepAliveOutputWaiting)
			livenessDirty = false
		}
		timerOutput := tcpTimerOutputPending(state, hostQueueWait != nil)
		persistOutput := tcpPersistOutputPending(state)
		keepAliveOutput := keepAliveOutputWaiting
		recoveryOutput := false
		if !timerOutput && recoveryOutputWaiting && !persistOutput && !keepAliveOutput {
			recoveryOutput = state.recoveryOutputReady()
			if !recoveryOutput {
				recoveryOutputWaiting = false
			}
		}
		var activeRetransmit, activePersist, activeDelayedACK <-chan time.Time
		var activeLiveness, activePathMTUProbe, activePacing <-chan time.Time
		inboundNotify := c.inbound.notify
		var earliestTimer time.Time
		nextActorTimer := actorTimerNone
		for _, timer := range [...]struct {
			active   bool
			deadline time.Time
			kind     int
		}{
			{state.retransmit && !recoveryOutput, state.retransmissionDeadline, actorTimerRetransmission},
			{state.persist, state.sendTimer.baseDeadline, actorTimerPersist},
			{state.delayedACK, state.delayedACKDeadline, actorTimerDelayedACK},
			{state.liveness, state.livenessDeadline, actorTimerLiveness},
			{state.pathMTUProbe, state.pathMTUDeadline, actorTimerPathMTU},
			{state.pacing, state.pacingDeadline, actorTimerPacing},
		} {
			if timer.active && !timer.deadline.IsZero() && (earliestTimer.IsZero() || timer.deadline.Before(earliestTimer)) {
				earliestTimer = timer.deadline
				nextActorTimer = timer.kind
			}
		}
		if earliestTimer.IsZero() {
			if state.actorTimerChannel != nil {
				actorTimer.stop()
				state.actorTimerChannel = nil
				state.actorTimerDeadline = time.Time{}
			}
		} else if state.actorTimerChannel == nil || !state.actorTimerDeadline.Equal(earliestTimer) {
			state.actorTimerChannel = actorTimer.reset(time.Until(earliestTimer))
			state.actorTimerDeadline = earliestTimer
		}
		switch nextActorTimer {
		case actorTimerRetransmission:
			activeRetransmit = state.actorTimerChannel
		case actorTimerPersist:
			activePersist = state.actorTimerChannel
		case actorTimerDelayedACK:
			activeDelayedACK = state.actorTimerChannel
		case actorTimerLiveness:
			activeLiveness = state.actorTimerChannel
		case actorTimerPathMTU:
			activePathMTUProbe = state.actorTimerChannel
		case actorTimerPacing:
			activePacing = state.actorTimerChannel
		}
		queuedSegments := c.inbound.len()
		drainBacklog, forceTimer := timerBacklog.order(queuedSegments, earliestTimer, time.Now())
		if drainBacklog {
			activeRetransmit, activePersist, activeDelayedACK = nil, nil, nil
			activeLiveness, activePathMTUProbe, activePacing = nil, nil, nil
		} else if forceTimer && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		outputKind := tcpOrdinaryOutputNone
		var outputQueue *packetQueue
		var outputLoopback bool
		var activeOutput <-chan uint16
		if (timerOutput || persistOutput || keepAliveOutput || ordinaryOutputWaiting || recoveryOutputWaiting) && !drainBacklog && !forceTimer {
			if !timerOutput && !persistOutput && !keepAliveOutput && !recoveryOutput && ordinaryOutputWaiting {
				outputKind = state.ordinaryOutputKind()
			}
			if timerOutput || persistOutput || keepAliveOutput || recoveryOutput || outputKind != tcpOrdinaryOutputNone {
				outputQueue, outputLoopback = c.stack.outputQueueFor(c.key.remote.Addr())
				activeOutput = outputQueue.free
			} else {
				ordinaryOutputWaiting = false
			}
		}
		select {
		case slot := <-activeOutput:
			reservation := tcpOutputReservation{queue: outputQueue, slot: slot, loopback: outputLoopback}
			if timerOutput {
				if err := drainTimerOutput(reservation); err != nil {
					return err
				}
			} else if persistOutput {
				if err := drainPersistOutput(reservation); err != nil {
					return err
				}
			} else if keepAliveOutput {
				if err := drainKeepAliveOutput(reservation); err != nil {
					return err
				}
				state.armLiveness(keepAliveOutputWaiting)
			} else if recoveryOutput {
				recoveryOutputWaiting = false
				if err := drainRecovery(reservation); err != nil {
					return err
				}
			} else {
				ordinaryOutputWaiting = false
				if outputKind == tcpOrdinaryOutputACK || state.ackPending && !state.delayedACK {
					if err := flushACK(reservation); err != nil {
						return err
					}
				} else if err := fillWindow(tcpRetransmissionPreserve, reservation); err != nil {
					return err
				}
			}
			ordinaryOutputWaiting = true
		case <-inboundNotify:
			wake := c.takeActorWake()
			ackNow := false
			if wake&tcpActorWakeSend != 0 {
				keepAliveOutputWaiting = false
			}
			if wake&tcpActorWakeNetworkError != 0 {
				for {
					err, ok := c.takeNetworkError()
					if !ok {
						break
					}
					state.ensureLivenessState().lastSoftError = err
					if tcpRevertRTOBackoff(err, state.sendUnacknowledged, state.rtoAttempts, &state.rtt) && (!state.retransmit || state.retransmissionKind != tcpRetransmissionPathMTU) && !tcpTimerOutputPending(state, hostQueueWait != nil) {
						state.armRetransmission()
					}
				}
			}
			if wake&tcpActorWakeQuickACKEnable != 0 {
				state.enterQuickACK(tcpMaximumQuickACKs)
				ackNow = state.ackPending
			} else if wake&tcpActorWakeQuickACKDisable != 0 {
				state.ackPingPong = true
			}
			fillSendWindow := wake&(tcpActorWakeSend|tcpActorWakeWindow|tcpActorWakeOptions) != 0
			if wake&tcpActorWakePathMTU != 0 {
				state.applyPathMTU(state.effectivePathMTU(), true)
				if err := drainPathMTU(tcpOutputReservation{}); err != nil {
					return err
				}
			}
			if wake&tcpActorWakeOptions != 0 {
				options := c.socketOptions()
				state.changeCongestionController(options.congestionFactory, options.maximumPacingRate)
				if state.livenessState != nil {
					state.livenessState.keepAliveProbes = 0
					state.livenessState.lastKeepAlive = time.Time{}
				}
				keepAliveOutputWaiting = false
				state.armLiveness(false)
			}
			if wake&tcpActorWakeWindow != 0 {
				now := time.Now()
				if target := state.receiveAutoTune.target(now, state.rtt.srtt, c.applicationReads.Load(), c.receiveMaximum); target > 0 {
					c.growReceiveCapacity(target)
				}
				if c.discardingReads() {
					state.outOfOrder = nil
					state.outOfOrderBytes = 0
					c.outOfOrderUnread.Store(0)
				} else if len(state.outOfOrder) != 0 {
					previousReceiveNext := state.receiveNext
					_, closed := c.promoteTCPReceived(&state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
					advanced := state.receiveNext - previousReceiveNext
					if closed && advanced != 0 {
						advanced--
					}
					state.bytesReceived += uint64(advanced)
					if closed {
						state.remoteFINReceived = true
						c.setReadEOF()
					}
					if state.receiveNext != previousReceiveNext {
						state.sackACKs = 0
						ackNow = state.scheduleACK(true, false, now) || ackNow
					}
				}
				available, capacity := c.receiveSpace(state.outOfOrderBytes)
				window, _ := state.receiveWindowState.next(state.receiveNext, available, tcpReceiveWindowIncrease(capacity, state.receiveMSS))
				if window > state.lastAdvertisedWindow {
					ackNow = state.scheduleACK(state.lastAdvertisedWindow == 0, false, now) || ackNow
				}
			}
			if ackNow {
				if err := flushACK(tcpOutputReservation{}); err != nil {
					return err
				}
			}
			if fillSendWindow {
				if err := fillWindow(tcpRetransmissionPreserve, tcpOutputReservation{}); err != nil {
					return err
				}
			}
			if wake&tcpActorWakeSend != 0 && state.localFINAcked && !state.remoteFINReceived && !state.finWaitArmed && c.applicationReceiveClosed() {
				state.armClose(time.Now(), tcpFINWaitDuration)
				state.finWaitArmed = true
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), state.tcpInfo())
			}

			if queuedSegments == 0 {
				queuedSegments = c.inbound.len()
			}
			batchLength := timerBacklog.receiveBatchLength(queuedSegments, forceTimer)
			var handledAt time.Time
			for batchIndex := 0; batchIndex < batchLength; batchIndex++ {
				segment, ok := c.inbound.dequeue()
				if !ok {
					break
				}
				timerBacklog.consumed()
				receivedAt := tcpQueuedSegmentEventTime(segment, state.eventTime, c.stack.timestampEpoch)
				state.eventTime = receivedAt
				payloadLength := uint32(len(segment.payload))
				receiveWindow := state.receiveWindowState.size(state.receiveNext)
				if state.timeWaitArmed {
					if handledAt.IsZero() {
						handledAt = time.Now()
					}
					if state.handleTimeWaitSegment(segment, receivedAt, handledAt) {
						return nil
					}
					continue
				}
				timestampEcho := uint32(0)
				timestampValue := uint32(0)
				timestampPresent := false
				if c.peerTimestamp && segment.flags&TCPFlagRST == 0 {
					timestampValue, timestampEcho, timestampPresent = parseTCPTimestamp(segment.optionBytes())
					if timestampPresent && tcpPAWSReject(timestampValue, c.recentTimestamp, state.lastTimestampUpdate, receivedAt, tcpPAWSReplayWindow) {
						drop, acceptReplay := tcpPAWSDisorderedACK(segment, state, timestampValue)
						if drop {
							continue
						}
						if !acceptReplay {
							state.trySendChallengeACK()
							continue
						}
					}
				}
				if !tcpSegmentAcceptable(segment.sequence, payloadLength, state.receiveNext, receiveWindow) {
					if segment.flags&TCPFlagRST == 0 {
						if tcpKeepAliveOrWindowProbe(segment, payloadLength, state.receiveNext, receiveWindow) {
							state.trySendACK()
						} else {
							sequence := tcpChallengeACKSequence(segment, state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
							state.trySendChallengeACKAt(sequence)
						}
					}
					continue
				}
				state.lastActivity = receivedAt
				keepAliveOutputWaiting = false
				if state.livenessState != nil {
					state.livenessState.lastKeepAlive = time.Time{}
					state.livenessState.keepAliveProbes = 0
				}
				livenessDirty = true
				if c.peerECN {
					if segment.flags&TCPFlagCWR != 0 {
						c.echoCongestion = false
					}
				}
				if segment.flags&TCPFlagRST != 0 {
					if segment.sequence == state.receiveNext {
						return syscall.ECONNRESET
					}
					state.trySendChallengeACK()
					continue
				}
				if segment.flags&TCPFlagSYN != 0 {
					state.trySendChallengeACK()
					continue
				}
				if segment.flags&TCPFlagACK == 0 {
					continue
				}
				ack := segment.acknowledgement
				retransmissionUpdate := tcpRetransmissionPreserve
				if tcpSequenceGreater(ack, state.sendNext) {
					state.trySendChallengeACK()
					continue
				}
				if tcpSequenceLess(ack, state.sendUnacknowledged) {
					oldestAcceptable := state.maximumPeerWindow
					if uint64(oldestAcceptable) > state.bytesAcknowledged {
						oldestAcceptable = uint32(state.bytesAcknowledged)
					}
					if tcpSequenceLess(ack, state.sendUnacknowledged-oldestAcceptable) {
						state.trySendChallengeACK()
						continue
					}
				}
				if timestampPresent && segment.flags&(TCPFlagSYN|TCPFlagRST) == 0 && !tcpSequenceLess(ack, state.sendUnacknowledged) &&
					tcpSequenceLessEqual(segment.sequence, state.lastACKSent) &&
					!tcpPAWSReject(timestampValue, c.recentTimestamp, state.lastTimestampUpdate, receivedAt, 0) {
					c.recentTimestamp = timestampValue
					state.lastTimestampUpdate = receivedAt
				}
				if !tcpSequenceLess(ack, state.sendUnacknowledged) {
					if tcpSequenceGreater(ack, state.sendUnacknowledged) {
						retransmissionUpdate = tcpRetransmissionRestart
					} else {
						retransmissionUpdate = tcpRetransmissionReselect
					}
					state.processAcknowledgment(&segment, receivedAt, timestampEcho)
					if tcpTimerOutputPending(state, hostQueueWait != nil) && (retransmissionUpdate == tcpRetransmissionRestart || retransmissionUpdate == tcpRetransmissionReselect && state.retransmissionKind == tcpRetransmissionProbe) {
						state.updateRetransmissionTimer(retransmissionUpdate, state.eventTime)
						retransmissionUpdate = tcpRetransmissionPreserve
					}
					if state.recoveryOutputPending() {
						if err := drainRecovery(tcpOutputReservation{}); err != nil {
							return err
						}
					}
				}

				fin := segment.flags&TCPFlagFIN != 0
				if len(segment.payload) != 0 || fin {
					previousReceiveNext := state.receiveNext
					newPayloadData := len(segment.payload) != 0 && tcpSequenceGreater(segment.sequence+uint32(len(segment.payload)), previousReceiveNext)
					if newPayloadData && c.applicationReceiveClosed() {
						sequence := tcpAcceptableSendSequence(state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
						window, _ := state.nextAdvertisedReceiveWindow()
						_ = c.trySendSegment(sequence, state.receiveNext, TCPFlagRST|TCPFlagACK, window)
						return net.ErrClosed
					}
					receivedData := false
					quickECN := c.peerECN && len(segment.payload) != 0 && state.observeDataECN(segment.ecn)
					hadOutOfOrder := len(state.outOfOrder) != 0
					state.recentSACK = segment.sequence
					if state.peerSACK {
						if block, duplicate := tcpDuplicateSACKBlock(segment.sequence, len(segment.payload), fin, state.receiveNext, state.outOfOrder); duplicate {
							state.recentDSACK, state.haveRecentDSACK = block, true
						}
					}
					if !state.remoteFINReceived {
						_, closed := c.receiveTCPData(segment.sequence, segment.payload, fin, receiveWindow, &state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
						advanced := state.receiveNext - previousReceiveNext
						if closed && advanced != 0 {
							advanced--
						}
						receivedData = advanced != 0
						state.bytesReceived += uint64(advanced)
						if closed {
							state.remoteFINReceived = true
							c.setReadEOF()
						}
					}
					irregularData := len(segment.payload) != 0 && (segment.sequence != previousReceiveNext || hadOutOfOrder || len(state.outOfOrder) != 0 || !newPayloadData)
					if newPayloadData {
						state.measureReceiveMSS(&segment)
					}
					if receivedData {
						state.observeReceivedData(receivedAt)
					}
					if state.receiveNext != previousReceiveNext {
						state.sackACKs = 0
					}
					compressSACK := state.peerSACK && newPayloadData && !receivedData && !fin && !quickECN && !state.haveRecentDSACK && len(state.outOfOrder) != 0
					if irregularData && !compressSACK {
						state.enterQuickACK(tcpMaximumQuickACKs)
					}
					if quickECN {
						state.enterQuickACK(2)
					}
					ackNow := false
					if compressSACK {
						ackNow = state.scheduleSACKACK(receivedAt)
					} else {
						ackNow = state.scheduleACK(fin || irregularData, newPayloadData, receivedAt)
					}
					if ackNow {
						if err := flushACK(tcpOutputReservation{}); err != nil {
							return err
						}
					}
				}
				if state.localFINAcked && state.remoteFINReceived {
					if !state.timeWaitRequired {
						return nil
					}
					if !state.timeWaitArmed || fin {
						startedAt := receivedAt
						if fin {
							startedAt = time.Now()
						}
						state.armClose(startedAt, tcpTimeWaitDuration)
						state.timeWaitArmed = true
					}
				} else if state.localFINAcked && !state.finWaitArmed && c.applicationReceiveClosed() {
					state.armClose(receivedAt, tcpFINWaitDuration)
					state.finWaitArmed = true
				}
				if err := fillWindow(retransmissionUpdate, tcpOutputReservation{}); err != nil {
					return err
				}
			}

		case <-activeRetransmit:
			state.consumeActorTimer(actorTimer)
			state.retransmit = true
			state.retransmissionDeadline = time.Time{}
			retransmissionKind := state.retransmissionKind
			sackReneging := retransmissionKind == tcpRetransmissionSACKReneging
			if sackReneging {
				state.retransmissionKind = tcpRetransmissionRTO
			}
			if retransmissionKind == tcpRetransmissionClose {
				return net.ErrClosed
			}
			if sackReneging && len(state.outstanding) != 0 && state.outstanding[0].state.has(sentTCPSegmentSACKed) {
				for index := range state.outstanding {
					state.outstanding[index].state.set(sentTCPSegmentSACKed, false)
				}
				state.sackedRanges, state.sackedBytes = 0, 0
				state.haveRACKLoss = false
				state.sackRenegingRecovery = true
			}
			pendingIndex := state.retransmissionTarget(retransmissionKind)
			if pendingIndex < 0 {
				continue
			}
			hostQueueTicket := state.outstanding[pendingIndex].hostQueue
			if waiter := hostQueueTicket.departureWaiter(c.stack, c.inbound.notify); waiter != nil {
				hostQueueWait = waiter
				hostQueueWaitTicket = hostQueueTicket
				state.retransmit = true
				state.retransmissionDeadline = time.Time{}
				continue
			}
			if retransmissionKind == tcpRetransmissionRACK {
				reorderingWindow := rackReorderingWindow(state.rtt.minimum, state.rtt.srtt, state.rackReorderingScale)
				if !state.rackReorderingSeen && (state.fastRecovery || state.rtoRecovery || state.sackedRanges >= tcpDuplicateACKThreshold) {
					reorderingWindow = 0
				}
				state.haveRACKLoss = markRACKLoss(state.outstanding, state.rackLatestDelivered, time.Now(), reorderingWindow, c.stack.timestampEpoch)
				if state.haveRACKLoss {
					if state.pathMTUState != nil && state.pathMTUState.discovery.active && state.sendUnacknowledged == state.pathMTUState.discovery.probeStart && isolatedPLPMTUProbeLoss(state.outstanding, state.pathMTUState.discovery.probeStart, highestSACKedSequence(state.outstanding), state.peerMSS) {
						state.failPLPMTUProbe()
						if err := drainPathMTU(tcpOutputReservation{}); err != nil {
							return err
						}
					}
					state.recordProvenLosses(false, time.Time{})
					if state.haveRACKLoss {
						state.prepareRetransmission(firstUnretriedLoss(state.outstanding, state.peerMSS), false, false, time.Time{})
						if err := drainRecovery(tcpOutputReservation{}); err != nil {
							return err
						}
					}
					state.haveRACKLoss = hasRACKLoss(state.outstanding)
				}
				if state.retransmissionKind != tcpRetransmissionPathMTU {
					state.armRetransmission()
				}
				continue
			}
			if retransmissionKind == tcpRetransmissionProbe {
				if err := drainTimerOutput(tcpOutputReservation{}); err != nil {
					return err
				}
				continue
			}
			state.rtoAttempts++
			if state.rtoAttempts > tcpMaximumRTOs {
				var softError error
				if state.livenessState != nil {
					softError = state.livenessState.lastSoftError
				}
				return tcpTimeoutError(softError)
			}
			state.blackHoleRTOs++
			if state.blackHoleRTOs >= tcpBlackHoleTimeouts {
				if len(state.outstanding) != 0 {
					segment := state.outstanding[firstUnsackedSegment(state.outstanding)]
					mtu := nextBlackHoleProbeMTU(c.mtu, c.key.remote.Addr().Is6(), segment.dataSize(), c.peerTimestamp)
					if mtu < c.mtu {
						c.stack.stats.pathMTUBlackHoleReductions.Add(1)
						pathState := state.ensurePathMTUState()
						pathState.blackHoleMTU = mtu
						pathState.blackHoleExpiry = time.Now().Add(pathMTULifetime)
						state.applyPathMTU(state.effectivePathMTU(), false)
					}
				}
			}
			pendingIndex = state.prepareRetransmission(pendingIndex, true, false, time.Time{})
			if pendingIndex < 0 {
				state.armRetransmission()
				continue
			}
			state.retransmit = true
			state.retransmissionDeadline = time.Time{}
			state.retransmissionKind = tcpRetransmissionRTO
			if err := drainTimerOutput(tcpOutputReservation{}); err != nil {
				return err
			}

		case <-activePersist:
			state.consumeActorTimer(actorTimer)
			state.persist = true
			state.sendTimer.baseDeadline = time.Time{}
			if c.applicationReceiveClosed() && state.sendTimer.persistAttempts >= tcpMaximumRTOs {
				return os.ErrDeadlineExceeded
			}
			if err := drainPersistOutput(tcpOutputReservation{}); err != nil {
				return err
			}

		case <-activeDelayedACK:
			state.consumeActorTimer(actorTimer)
			state.delayedACK = false
			state.delayedACKDeadline = time.Time{}
			state.ackPingPong = false
			if err := flushACK(tcpOutputReservation{}); err != nil {
				return err
			}

		case <-activePathMTUProbe:
			state.consumeActorTimer(actorTimer)
			state.pathMTUProbe = false
			state.pathMTUDeadline = time.Time{}
			now := time.Now()
			if state.pathMTUState != nil && state.pathMTUState.discovery.searching {
				state.pathMTUState.discovery.nextProbe = now
				if err := fillWindow(tcpRetransmissionPreserve, tcpOutputReservation{}); err != nil {
					return err
				}
				continue
			}
			if state.pathMTUState != nil && !state.pathMTUState.blackHoleExpiry.IsZero() && !now.Before(state.pathMTUState.blackHoleExpiry) {
				state.pathMTUState.blackHoleMTU = 0
				state.pathMTUState.blackHoleExpiry = time.Time{}
			}
			pathState := state.ensurePathMTUState()
			pathState.discovery.start(c.mtu, c.stack.network.Load().mtu, now)
			if !pathState.discovery.searching {
				c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
				state.armPathMTUProbe()
			}
			if err := fillWindow(tcpRetransmissionPreserve, tcpOutputReservation{}); err != nil {
				return err
			}
		case <-activePacing:
			state.consumeActorTimer(actorTimer)
			state.pacing = false
			state.pacingDeadline = time.Time{}
			state.controller.onPacingWake(time.Now(), state.congestionFlight())
			if state.fastRecovery && state.peerSACK && len(state.outstanding) != 0 {
				if err := drainRecovery(tcpOutputReservation{}); err != nil {
					return err
				}
			}
			if err := fillWindow(tcpRetransmissionPreserve, tcpOutputReservation{}); err != nil {
				return err
			}
		case <-activeLiveness:
			state.consumeActorTimer(actorTimer)
			state.liveness = false
			state.livenessDeadline = time.Time{}
			options := c.socketOptions()
			now := time.Now()
			if options.idleTimeout > 0 && !now.Before(state.lastActivity.Add(options.idleTimeout)) {
				return os.ErrDeadlineExceeded
			}
			if deadline := state.userTimeoutDeadline(now, options.userTimeout); !deadline.IsZero() && !now.Before(deadline) {
				return syscall.ETIMEDOUT
			}
			if options.userTimeout > 0 && state.livenessState != nil && state.livenessState.keepAliveProbes != 0 && !now.Before(state.lastActivity.Add(options.userTimeout)) {
				return syscall.ETIMEDOUT
			}
			if options.keepAlive && state.keepAliveEligible() {
				deadline := state.lastActivity.Add(options.keepAliveConfig.Idle)
				if state.livenessState != nil && state.livenessState.keepAliveProbes != 0 {
					deadline = state.livenessState.lastKeepAlive.Add(options.keepAliveConfig.Interval)
				}
				if !now.Before(deadline) {
					if options.userTimeout == 0 && state.livenessState != nil && state.livenessState.keepAliveProbes >= options.keepAliveConfig.Count {
						return syscall.ETIMEDOUT
					}
					keepAliveOutputWaiting = true
					if err := drainKeepAliveOutput(tcpOutputReservation{}); err != nil {
						return err
					}
				}
			}
			state.armLiveness(keepAliveOutputWaiting)
		case <-c.abortCh:
			err := c.abortedError()
			if c.takeAbortReset() {
				sequence := tcpAcceptableSendSequence(state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
				window, _ := state.nextAdvertisedReceiveWindow()
				_ = c.sendAbortReset(sequence, state.receiveNext, window)
			}
			return err
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

func (state *tcpEstablishedState) prepareRetransmission(index int, timeout, duringACK bool, lossObservedAt time.Time) int {
	if len(state.outstanding) == 0 {
		return -1
	}
	if index < 0 || index >= len(state.outstanding) {
		index = firstUnsackedSegment(state.outstanding)
	}
	if index < 0 || index >= len(state.outstanding) {
		return -1
	}
	c := state.connection
	frtoEligible := timeout && !state.fastRecovery && !state.sackRenegingRecovery && (!state.rtoRecovery || state.rtoAttempts > 1) && (state.pathMTUState == nil || !state.pathMTUState.discovery.active)
	if state.pathMTUState != nil && state.pathMTUState.discovery.active {
		retransmitSequence := state.outstanding[index].sequence
		delay := tcpPLPMTUProbeHeadway(state.congestionWindow, state.peerMSS, state.rtt.srtt)
		if timeout {
			delay = tcpPLPMTUTimeoutDelay(delay)
		}
		state.pathMTUState.discovery.inconclusive(time.Now(), delay)
		for segmentIndex := range state.outstanding {
			state.outstanding[segmentIndex].state.set(sentTCPSegmentMTUProbe, false)
		}
		state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
		state.rebaseOutstanding()
		if state.sackedRanges != 0 {
			state.recountSACK()
		}
		index = -1
		for segmentIndex := range state.outstanding {
			if state.outstanding[segmentIndex].sequence == retransmitSequence {
				index = segmentIndex
				break
			}
		}
		if index < 0 {
			index = firstUnsackedSegment(state.outstanding)
		}
		state.armPathMTUProbe()
	}
	if index < 0 || index >= len(state.outstanding) {
		return -1
	}
	oldest := &state.outstanding[index]
	rackRetransmission := oldest.state.has(sentTCPSegmentRACKLost)
	lostRetransmission := rackRetransmission && oldest.isRetransmitted()
	lostCWR := oldest.state.has(sentTCPSegmentCWR)
	beginUndo := timeout && !state.rtoRecovery || !timeout && (!state.fastRecovery || lostRetransmission)
	if beginUndo {
		flight := state.ordinaryFlight()
		if !timeout {
			flight = state.controller.recoveryFlight(time.Now(), flight, lossRecoveryFlightSize(state.outstanding))
		}
		if state.undo == nil {
			state.undo = new(tcpRecoveryUndo)
		}
		transport := state.recoveryTransportState(timeout)
		state.undo.begin(timeout, state.sendNext, state.congestionWindow, state.slowStartThreshold, flight, &state.controller, state.rtt)
		state.undo.setTransport(transport)
	}
	lossProven := timeout || !state.peerSACK || sackSegmentLost(state.outstanding, index, state.peerMSS)
	if !duringACK {
		lossObservedAt = time.Now()
	}
	state.controller.notePacketLoss(oldest, recordTCPSegmentLoss(oldest, lossProven), duringACK, lossObservedAt, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerMSS, state.rtt.srtt)
	if timeout {
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
		flight := state.ordinaryFlight()
		if !state.rtoRecovery {
			state.hyStart.disable()
			state.slowStartThreshold = state.controller.onTimeout(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch))
			state.rtoRecovery = true
			if c.peerECN {
				c.sendCWR = true
			}
		}
		state.rtoRecoveryPoint = state.sendNext
		state.frtoState = tcpFRTOInactive
		state.frtoProbeBudget = 0
		if frtoEligible {
			state.frtoState = tcpFRTOTimeoutPending
		}
		state.congestionWindow = uint32(state.peerMSS)
		state.fastRecovery = false
		state.prrPriorFlight = 0
		state.prrDelivered = 0
		state.prrOut = 0
		state.ecnRecoveryPoint = state.sendNext
		state.ecnRecoveryActive = true
		for index := range state.outstanding {
			state.outstanding[index].state.set(sentTCPSegmentSACKRetried, false)
			state.outstanding[index].state.set(sentTCPSegmentRACKLost, false)
		}
		state.haveRACKLoss = false
		state.rtt.backoff()
	} else {
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
		if !state.fastRecovery || lostRetransmission {
			state.hyStart.disable()
			ordinary := state.ordinaryFlight()
			flight := state.controller.recoveryFlight(oldest.transmittedAt(c.stack.timestampEpoch), ordinary, lossRecoveryFlightSize(state.outstanding))
			if state.limitedTransmitActive {
				for index := range state.outstanding {
					state.outstanding[index].state.set(sentTCPSegmentLimited, false)
				}
				state.limitedTransmitActive = false
			}
			if lostRetransmission || lostCWR || tcpECNStartsRecovery(state.ecnRecoveryActive, state.sendUnacknowledged, state.ecnRecoveryPoint) {
				state.slowStartThreshold, state.congestionWindow = state.controller.onCongestion(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch))
				state.ecnRecoveryPoint = state.sendNext
				state.ecnRecoveryActive = true
				if c.peerECN {
					c.sendCWR = true
				}
			}
			state.congestionWindow = state.controller.recoveryWindow(oldest.transmittedAt(c.stack.timestampEpoch), state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, state.peerSACK)
			state.fastRecovery = true
			state.recoveryPoint = state.sendNext
			if state.peerSACK {
				state.prrPriorFlight = flight
				state.prrDelivered = 0
				state.prrOut = 0
			}
		}
	}
	return index
}

func (state *tcpEstablishedState) enterRecovery(index int, receivedAt time.Time) {
	state.prepareRetransmission(index, false, state.controller.usesDeliveryRate(), receivedAt)
}

func (state *tcpEstablishedState) armPathMTURetransmission() {
	if len(state.outstanding) == 0 || state.retransmit && state.retransmissionKind == tcpRetransmissionClose {
		return
	}
	state.retransmit = true
	state.retransmissionDeadline = time.Now()
	state.retransmissionKind = tcpRetransmissionPathMTU
}

func (state *tcpEstablishedState) failPLPMTUProbe() {
	if state.pathMTUState == nil || !state.pathMTUState.discovery.active {
		return
	}
	c := state.connection
	state.pathMTUState.discovery.failed(time.Now(), tcpPLPMTUProbeHeadway(state.congestionWindow, state.peerMSS, state.rtt.srtt))
	if !state.pathMTUState.discovery.searching {
		c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
	}
	for index := range state.outstanding {
		segment := &state.outstanding[index]
		if segment.state.has(sentTCPSegmentMTUProbe) {
			segment.state |= sentTCPSegmentLossReported
		}
		segment.state.set(sentTCPSegmentMTUProbe, false)
	}
	state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
	state.rebaseOutstanding()
	if state.sackedRanges != 0 {
		state.recountSACK()
	}
	index := firstUnsackedSegment(state.outstanding)
	if index < 0 || index >= len(state.outstanding) {
		state.armPathMTUProbe()
		return
	}
	state.ensurePathMTUState().failures++
	c.stack.stats.pathMTUProbeFailures.Add(1)
	state.armPathMTURetransmission()
	state.armPathMTUProbe()
}

func (state *tcpEstablishedState) applyPathMTU(mtu int, retransmit bool) {
	c := state.connection
	options := c.socketOptions()
	state.changeCongestionController(options.congestionFactory, options.maximumPacingRate)
	priorMTU := c.mtu
	c.mtu = mtu
	if mtu < priorMTU {
		for index := range state.outstanding {
			state.outstanding[index].state.set(sentTCPSegmentMTUProbe, false)
		}
		state.ensurePathMTUState().discovery.reduce(mtu, priorMTU, c.stack.network.Load().mtu, time.Now())
	}
	rawPathMSS := tcpMSSForMTU(mtu, c.key.local.Addr())
	state.pathMSS = rawPathMSS
	if c.peerTimestamp {
		state.pathMSS -= tcpTimestampOptionSize
	}
	if state.receiveMSS > state.pathMSS {
		state.receiveMSS = state.pathMSS
	}
	state.lastReceiveSegmentSize = 0
	state.armPathMTUProbe()
	newMSS := tcpEffectiveSendMSS(c.peerMSS, rawPathMSS, c.peerTimestamp)
	if newMSS == state.peerMSS {
		return
	}
	if newMSS > state.peerMSS {
		state.peerMSS = newMSS
		state.controller.onMTUChange(state.congestionWindow, state.slowStartThreshold, state.peerMSS)
		return
	}
	oldMSS := state.peerMSS
	state.peerMSS = newMSS
	state.congestionWindow = tcpCongestionValueForMSS(state.congestionWindow, oldMSS, newMSS, true)
	if state.slowStartThreshold != ^uint32(0)>>1 {
		state.slowStartThreshold = tcpCongestionValueForMSS(state.slowStartThreshold, oldMSS, newMSS, false)
	}
	state.controller.onMTUChange(state.congestionWindow, state.slowStartThreshold, state.peerMSS)
	state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
	state.rebaseOutstanding()
	if state.sackedRanges != 0 {
		state.recountSACK()
	}
	if retransmit {
		state.armPathMTURetransmission()
	}
}

func (c *TCPConn) sendAbortReset(sequence, acknowledgement uint32, window uint16) error {
	return c.trySendSegment(sequence, acknowledgement, TCPFlagRST|TCPFlagACK, window)
}

func (c *TCPConn) trySendSegment(sequence, acknowledgement uint32, flags byte, window uint16) error {
	return c.trySendSegmentWithOptions(sequence, acknowledgement, flags, window, nil)
}

func (c *TCPConn) trySendSegmentWithOptions(sequence, acknowledgement uint32, flags byte, window uint16, options []byte) error {
	var timestampOptions [40]byte
	if c.peerTimestamp {
		if len(options) > len(timestampOptions)-tcpTimestampOptionSize {
			return errors.New("mipstack: invalid TCP options")
		}
		encoded := appendTCPTimestampOptions(timestampOptions[:0], c.stack.tcpTimestamp(), c.recentTimestamp)
		options = append(encoded, options...)
	}
	if c.echoCongestion {
		flags |= TCPFlagECE
	}
	return c.tryWriteTCPControl(sequence, acknowledgement, flags, window, options)
}

func (c *TCPConn) tryWriteTCPControl(sequence, acknowledgement uint32, flags byte, window uint16, options []byte) error {
	if c.forwarded && !c.stack.network.Load().acceptsInboundDestination(c.key.local.Addr()) {
		return syscall.EADDRNOTAVAIL
	}
	return c.stack.tryWriteTCPControl(
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, nil, c.mtu, uint8(c.trafficClass.Load()), 0, c.flowLabel, true,
		outputFlowKey{tcp: c.outputFlowID},
	)
}

func (c *TCPConn) publishReservedPayloadForMTU(sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, ecnCapable bool, mtu int, reservation tcpOutputReservation, sequenceRange tcpOutputSequenceRange) (tcpPublishedTransmission, error) {
	timestamp := uint32(0)
	var timestampOptions [40]byte
	if c.peerTimestamp {
		if len(options) > len(timestampOptions)-tcpTimestampOptionSize {
			reservation.release()
			return tcpPublishedTransmission{}, errors.New("mipstack: invalid TCP options")
		}
		timestamp = c.stack.tcpTimestamp()
		encoded := appendTCPTimestampOptions(timestampOptions[:0], timestamp, c.recentTimestamp)
		options = append(encoded, options...)
	}
	if c.echoCongestion {
		flags |= TCPFlagECE
	}
	includeCWR := c.sendCWR && ecnCapable && payload.size != 0
	if includeCWR {
		flags |= TCPFlagCWR
	}
	ecn := byte(0)
	if c.peerECN && ecnCapable && payload.size != 0 {
		ecn = 2
	}
	hostQueue, err := c.publishReservedTCP(sequence, acknowledgement, flags, window, options, payload, mtu, uint8(c.trafficClass.Load()), ecn, reservation, sequenceRange)
	if err != nil {
		return tcpPublishedTransmission{}, err
	}
	return tcpPublishedTransmission{hostQueue: hostQueue, timestamp: timestamp, carriesCWR: includeCWR}, nil
}

func (c *TCPConn) publishBufferedSegmentForMTU(sendBase uint32, segment sentTCPSegment, acknowledgement uint32, window uint16, options []byte, ecnCapable bool, mtu int, outputWindow tcpOutputWindow) (tcpOutputWindow, tcpPublishedTransmission, bool, error) {
	var payload tcpPayloadView
	if err := c.bufferedSegmentPayload(sendBase, segment, &payload); err != nil {
		return outputWindow, tcpPublishedTransmission{}, false, err
	}
	reservation, outputWindow, available := outputWindow.reserve(c)
	if !available {
		return outputWindow, tcpPublishedTransmission{}, true, nil
	}
	published, err := c.publishReservedPayloadForMTU(segment.sequence, acknowledgement, segment.flags, window, options, &payload, ecnCapable, mtu, reservation, tcpOutputSequenceRange{})
	if errors.Is(err, errTCPOutputRouteChanged) {
		return outputWindow, tcpPublishedTransmission{}, true, nil
	}
	return outputWindow, published, false, err
}

func (c *TCPConn) bufferedSegmentPayload(sendBase uint32, segment sentTCPSegment, payload *tcpPayloadView) error {
	size := segment.dataSize()
	if size == 0 {
		*payload = tcpPayloadView{}
		return nil
	}
	c.sendView(int(segment.sequence-sendBase), size, payload)
	if payload.size != size {
		return errors.New("mipstack: TCP retransmission data is unavailable")
	}
	return nil
}

type tcpOutputReservation struct {
	queue    *packetQueue
	slot     uint16
	loopback bool
}

func (r tcpOutputReservation) release() { r.queue.releaseReserved(r.slot) }

type tcpOutputSequenceRange struct {
	unacknowledged uint32
	next           uint32
}

type tcpPublishedTransmission struct {
	hostQueue  packetQueueTicket
	timestamp  uint32
	carriesCWR bool
}

type tcpOutputWindow struct {
	queue     *packetQueue
	slot      uint16
	remaining uint16
	first     bool
	loopback  bool
}

func newTCPOutputWindow(reservation tcpOutputReservation) tcpOutputWindow {
	var w tcpOutputWindow
	if reservation.queue != nil {
		w.queue = reservation.queue
		w.slot = reservation.slot
		w.remaining = uint16(len(reservation.queue.free))
		w.first = true
		w.loopback = reservation.loopback
	}
	return w
}

func (w tcpOutputWindow) reserve(c *TCPConn) (tcpOutputReservation, tcpOutputWindow, bool) {
	if w.first {
		w.first = false
		return tcpOutputReservation{queue: w.queue, slot: w.slot, loopback: w.loopback}, w, true
	}
	if w.queue == nil {
		queue, loopback := c.stack.outputQueueFor(c.key.remote.Addr())
		slot, available := queue.tryReserve()
		if !available {
			return tcpOutputReservation{}, w, false
		}
		w.queue = queue
		w.loopback = loopback
		w.remaining = uint16(len(queue.free))
		return tcpOutputReservation{queue: queue, slot: slot, loopback: loopback}, w, true
	}
	if w.remaining == 0 {
		return tcpOutputReservation{}, w, false
	}
	slot, available := w.queue.tryReserve()
	if !available {
		w.remaining = 0
		return tcpOutputReservation{}, w, false
	}
	w.remaining--
	return tcpOutputReservation{queue: w.queue, slot: slot, loopback: w.loopback}, w, true
}

func (w tcpOutputWindow) release() {
	if w.first {
		tcpOutputReservation{queue: w.queue, slot: w.slot, loopback: w.loopback}.release()
	}
}

var errTCPOutputRouteChanged = errors.New("mipstack: TCP output route changed")

func (c *TCPConn) publishReservedTCP(sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, mtu int, trafficClass, ecn byte, reservation tcpOutputReservation, sequenceRange tcpOutputSequenceRange) (packetQueueTicket, error) {
	_, _, packetSize, err := tcpPacketLayout(c.key.local.Addr(), c.key.remote.Addr(), options, payload.size, mtu)
	if err != nil {
		reservation.release()
		return packetQueueTicket{}, err
	}
	if c.forwarded && !c.stack.network.Load().acceptsInboundDestination(c.key.local.Addr()) {
		reservation.release()
		return packetQueueTicket{}, syscall.EADDRNOTAVAIL
	}
	queue, loopback := c.stack.outputQueueFor(c.key.remote.Addr())
	if reservation.queue != queue || reservation.loopback != loopback {
		reservation.release()
		return packetQueueTicket{}, errTCPOutputRouteChanged
	}
	var packet []byte
	var reusable bool
	if packetSize <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(packetSize)
	} else {
		packet, reusable = c.stack.acquireLargeOutputBuffer(packetSize)
	}
	built, err := buildTCPPacketViewInto(
		packet,
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn, c.flowLabel,
	)
	if err != nil {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		reservation.release()
		return packetQueueTicket{}, err
	}
	if sequenceRange.unacknowledged != sequenceRange.next {
		c.publishICMPSequenceRange(sequenceRange.unacknowledged, sequenceRange.next)
	}
	hostQueue, published := queue.enqueueReservedTCP(reservation.slot, built, reusable, c.outputFlowID, loopback)
	if !published {
		return packetQueueTicket{}, ErrClosed
	}
	c.stack.recordOutput(loopback)
	return hostQueue, nil
}

type rttEstimator struct {
	initialized bool
	samples     uint64
	minimum     time.Duration
	minimums    tcpMinimumRTTFilter
	srtt        time.Duration
	variation   time.Duration
	baseRTO     time.Duration
	rto         time.Duration
	backoffs    uint8
}

func newRTTEstimator(initial time.Duration) rttEstimator {
	return rttEstimator{baseRTO: initial, rto: initial}
}

type tcpMinimumRTTSample struct {
	at    monotonicStamp
	value time.Duration
}

type tcpMinimumRTTFilter struct {
	samples     [3]tcpMinimumRTTSample
	initialized bool
}

func (f *tcpMinimumRTTFilter) observe(now monotonicStamp, value time.Duration) time.Duration {
	candidate := tcpMinimumRTTSample{at: now, value: value}
	if !f.initialized || value <= f.samples[0].value || time.Duration(now-f.samples[2].at) > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = candidate, candidate, candidate
		f.initialized = true
		return value
	}
	if value <= f.samples[1].value {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if value <= f.samples[2].value {
		f.samples[2] = candidate
	}
	delta := time.Duration(now - f.samples[0].at)
	if delta > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		if time.Duration(now-f.samples[0].at) > tcpMinimumRTTWindow {
			f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		}
	} else if f.samples[1].at == f.samples[0].at && delta > tcpMinimumRTTWindow/4 {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if f.samples[2].at == f.samples[1].at && delta > tcpMinimumRTTWindow/2 {
		f.samples[2] = candidate
	}
	return f.samples[0].value
}

func (r *rttEstimator) observeAt(sample time.Duration, receivedAt monotonicStamp) {
	if sample <= 0 {
		return
	}
	r.samples++
	sample = normalizedRTTSample(sample)
	r.minimum = r.minimums.observe(receivedAt, sample)
	if !r.initialized {
		r.srtt = sample
		r.variation = sample / 2
		r.initialized = true
	} else {
		difference := r.srtt - sample
		if difference < 0 {
			difference = -difference
		}
		r.variation = (3*r.variation + difference) / 4
		r.srtt = (7*r.srtt + sample) / 8
	}
	r.updateRTO()
}

func (r *rttEstimator) updateRTO() {
	r.baseRTO = r.srtt + 4*r.variation
	if r.baseRTO < tcpMinimumRTO {
		r.baseRTO = tcpMinimumRTO
	} else if r.baseRTO > tcpMaximumRTO {
		r.baseRTO = tcpMaximumRTO
	}
	r.rto = r.baseRTO
	r.backoffs = 0
}

func normalizedRTTSample(sample time.Duration) time.Duration {
	if sample > tcpMaximumRTO {
		return tcpMaximumRTO
	}
	return sample
}

func elapsedRTTSampleAt(sentAt, receivedAt time.Time) time.Duration {
	if sentAt.IsZero() {
		return 0
	}
	sample := receivedAt.Sub(sentAt)
	if sample < time.Microsecond {
		return time.Microsecond
	}
	return sample
}

func tcpSegmentEventTime(segment tcpSegment, now, previous, epoch time.Time) time.Time {
	result := segment.receivedAt.time(epoch)
	if result.IsZero() || result.After(now) {
		result = now
	}
	if result.Before(previous) {
		result = previous
	}
	return result
}

func tcpQueuedSegmentEventTime(segment tcpSegment, previous, epoch time.Time) time.Time {
	result := segment.receivedAt.time(epoch)
	if result.IsZero() {
		result = time.Now()
	}
	if result.Before(previous) {
		result = previous
	}
	return result
}

func (r *rttEstimator) backoff() {
	if r.baseRTO <= 0 {
		r.baseRTO = r.rto
		if r.baseRTO <= 0 {
			r.baseRTO = tcpInitialRTO
		}
	}
	if r.backoffs != ^uint8(0) {
		r.backoffs++
	}
	r.rto = backedOffRTO(r.baseRTO, r.backoffs)
}

func (r *rttEstimator) revertBackoff() bool {
	if r.backoffs == 0 {
		return false
	}
	r.backoffs--
	r.rto = backedOffRTO(r.baseRTO, r.backoffs)
	return true
}

func backedOffRTO(base time.Duration, backoffs uint8) time.Duration {
	if base <= 0 {
		base = tcpInitialRTO
	}
	result := base
	for backoff := uint8(0); backoff < backoffs; backoff++ {
		if result >= tcpMaximumRTO/2 {
			return tcpMaximumRTO
		}
		result *= 2
	}
	if result > tcpMaximumRTO {
		return tcpMaximumRTO
	}
	return result
}

func tcpMSSForMTU(mtu int, address netip.Addr) int {
	header := tcpHeaderSize + 40
	if address.Is4() {
		header = tcpHeaderSize + 20
	}
	maximum := mtu - header
	if maximum > 65535 {
		maximum = 65535
	}
	return maximum
}

func nextBlackHoleMTU(current int, ipv6 bool) int {
	if ipv6 {
		if current > ipv6MinimumMTU {
			return ipv6MinimumMTU
		}
		return current
	}
	for _, candidate := range [...]int{1500, 1280, 1006, 576, 508, 296, 68} {
		if candidate < current {
			return candidate
		}
	}
	return current
}

func nextBlackHoleProbeMTU(current int, ipv6 bool, payloadSize int, timestamp bool) int {
	address := netip.IPv4Unspecified()
	if ipv6 {
		address = netip.IPv6Unspecified()
	}
	probe := current
	for {
		next := nextBlackHoleMTU(probe, ipv6)
		if next >= probe {
			return current
		}
		maximumPayload := tcpMSSForMTU(next, address)
		if timestamp {
			maximumPayload -= tcpTimestampOptionSize
		}
		if payloadSize > maximumPayload {
			return next
		}
		probe = next
	}
}

func tcpTimeoutError(softError error) error {
	if softError != nil {
		return softError
	}
	return os.ErrDeadlineExceeded
}

func tcpActiveOpenHardError(err error) bool {
	var networkError ICMPError
	if !errors.As(err, &networkError) {
		return false
	}
	if networkError.QuotedSource.Is6() {
		return networkError.Type == ICMPv6TypeDestinationUnreachable && networkError.Code == ICMPv6DestinationUnreachableCodePort
	}
	return networkError.Type == ICMPv4TypeDestinationUnreachable &&
		(networkError.Code == ICMPv4DestinationUnreachableCodeProtocol || networkError.Code == ICMPv4DestinationUnreachableCodePort)
}

func tcpRevertRTOBackoff(err error, sendUnacknowledged uint32, retransmissions int, rtt *rttEstimator) bool {
	if retransmissions == 0 || rtt == nil {
		return false
	}
	var networkError ICMPError
	if !errors.As(err, &networkError) || len(networkError.QuotedPayload) < 8 {
		return false
	}
	revert := false
	if networkError.QuotedSource.Is6() {
		revert = networkError.Type == ICMPv6TypeDestinationUnreachable && networkError.Code == ICMPv6DestinationUnreachableCodeNoRoute
	} else {
		revert = networkError.Type == ICMPv4TypeDestinationUnreachable &&
			(networkError.Code == ICMPv4DestinationUnreachableCodeNetwork || networkError.Code == ICMPv4DestinationUnreachableCodeHost)
	}
	if !revert || binary.BigEndian.Uint32(networkError.QuotedPayload[4:8]) != sendUnacknowledged {
		return false
	}
	return rtt.revertBackoff()
}

func tcpSYNOptions(storage []byte, mss int, windowScale uint8, timestamp uint32) []byte {
	return tcpPassiveSYNOptions(storage, mss, true, true, true, windowScale, timestamp, 0)
}

func tcpPassiveSYNOptions(storage []byte, mss int, sack, windowScaling, timestamp bool, windowScale uint8, timestampValue, timestampEcho uint32) []byte {
	options := append(storage[:0], TCPHeaderOptionMSS, 4, byte(mss>>8), byte(mss))
	if sack {
		options = append(options, TCPHeaderOptionSACKPermitted, 2)
	}
	if windowScaling {
		options = append(options, TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, windowScale)
	}
	if timestamp {
		offset := len(options)
		options = append(options, TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], timestampValue)
		binary.BigEndian.PutUint32(options[offset+8:offset+12], timestampEcho)
	}
	return options
}

func parseTCPOptions(options []byte, fallback, localMaximum int) (int, uint8, bool, bool, bool, uint32) {
	mss := fallback
	var scale uint8
	var windowScaling bool
	var sack bool
	var timestamp bool
	var timestampValue uint32
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case TCPHeaderOptionEnd:
			return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
		case TCPHeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		switch kind {
		case TCPHeaderOptionMSS:
			if length == 4 {
				value := int(binary.BigEndian.Uint16(options[offset+2 : offset+4]))
				if value != 0 {
					mss = value
				}
			}
		case TCPHeaderOptionWindowScale:
			if length == 3 {
				windowScaling = true
				scale = options[offset+2]
				if scale > 14 {
					scale = 14
				}
			}
		case TCPHeaderOptionSACKPermitted:
			sack = length == 2
		case TCPHeaderOptionTimestamp:
			if length == 10 {
				timestamp = true
				timestampValue = binary.BigEndian.Uint32(options[offset+2 : offset+6])
			}
		}
		offset += length
	}
	return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
}

func parseTCPTimestamp(options []byte) (uint32, uint32, bool) {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionTimestamp && length == 10 {
			return binary.BigEndian.Uint32(options[offset+2 : offset+6]), binary.BigEndian.Uint32(options[offset+6 : offset+10]), true
		}
		offset += length
	}
	return 0, 0, false
}

func appendTCPTimestampOptions(dst []byte, value, echo uint32) []byte {
	start := len(dst)
	dst = append(dst,
		TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10,
		0, 0, 0, 0, 0, 0, 0, 0,
	)
	binary.BigEndian.PutUint32(dst[start+4:start+8], value)
	binary.BigEndian.PutUint32(dst[start+8:start+12], echo)
	return dst
}

func tcpTimestampOptions(value, echo uint32) []byte {
	return appendTCPTimestampOptions(nil, value, echo)
}

func tcpSACKBlockLimit(mtu int, address netip.Addr, timestamp bool, reservePayload int) int {
	ipHeader := 40
	if address.Is4() {
		ipHeader = 20
	}
	budget := mtu - ipHeader - tcpHeaderSize - reservePayload
	if budget > 40 {
		budget = 40
	}
	if budget < 0 {
		return 0
	}
	timestampSize := 0
	maximum := 4
	if timestamp {
		timestampSize = tcpTimestampOptionSize
		maximum = 3
	}
	for blocks := maximum; blocks > 0; blocks-- {
		optionSize := timestampSize + 2 + 8*blocks
		optionSize = (optionSize + 3) &^ 3
		if optionSize <= budget {
			return blocks
		}
	}
	return 0
}

func tcpSACKOptions(pieces []tcpReceivedPiece, recent uint32, maximumBlocks int, dsack TCPSACKBlock, haveDSACK bool, workspace *[34]byte) []byte {
	if maximumBlocks < 1 {
		return nil
	}
	if maximumBlocks > 4 {
		maximumBlocks = 4
	}
	var recentBlock TCPSACKBlock
	haveRecent := false
	for index := 0; index < len(pieces); {
		block, next := tcpReceivedSACKBlockForward(pieces, index)
		if tcpSequenceGreaterEqual(recent, block.LeftEdge) && tcpSequenceLess(recent, block.RightEdge) {
			recentBlock, haveRecent = block, true
			break
		}
		index = next
	}
	var ordered [4]TCPSACKBlock
	count := 0
	if haveDSACK {
		ordered[count] = dsack
		count++
	}
	if haveRecent && count < maximumBlocks {
		ordered[count] = recentBlock
		count++
	}
	for index := len(pieces) - 1; index >= 0 && count < maximumBlocks; {
		block, previous := tcpReceivedSACKBlockBackward(pieces, index)
		index = previous
		if haveRecent && block == recentBlock {
			continue
		}
		ordered[count] = block
		count++
	}
	if count == 0 {
		return nil
	}
	options := workspace[:2+8*count]
	options[0], options[1] = TCPHeaderOptionSACK, byte(len(options))
	for index, block := range ordered[:count] {
		offset := 2 + 8*index
		binary.BigEndian.PutUint32(options[offset:offset+4], block.LeftEdge)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], block.RightEdge)
	}
	return options
}

func tcpReceivedSACKBlockForward(pieces []tcpReceivedPiece, index int) (TCPSACKBlock, int) {
	piece := pieces[index]
	block := TCPSACKBlock{LeftEdge: piece.sequence, RightEdge: piece.sequence + uint32(len(piece.payload))}
	if piece.fin {
		block.RightEdge++
	}
	index++
	for index < len(pieces) {
		piece = pieces[index]
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if tcpSequenceGreater(piece.sequence, block.RightEdge) {
			break
		}
		if tcpSequenceGreater(right, block.RightEdge) {
			block.RightEdge = right
		}
		index++
	}
	return block, index
}

func tcpReceivedSACKBlockBackward(pieces []tcpReceivedPiece, index int) (TCPSACKBlock, int) {
	piece := pieces[index]
	block := TCPSACKBlock{LeftEdge: piece.sequence, RightEdge: piece.sequence + uint32(len(piece.payload))}
	if piece.fin {
		block.RightEdge++
	}
	index--
	for index >= 0 {
		piece = pieces[index]
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if tcpSequenceGreater(block.LeftEdge, right) {
			break
		}
		block.LeftEdge = piece.sequence
		if tcpSequenceGreater(right, block.RightEdge) {
			block.RightEdge = right
		}
		index--
	}
	return block, index
}

func tcpDuplicateSACKBlock(sequence uint32, payloadLength int, fin bool, receiveNext uint32, pieces []tcpReceivedPiece) (TCPSACKBlock, bool) {
	length := uint32(payloadLength)
	if fin {
		length++
	}
	if length == 0 {
		return TCPSACKBlock{}, false
	}
	end := sequence + length
	if tcpSequenceLess(sequence, receiveNext) {
		right := end
		if tcpSequenceGreater(right, receiveNext) {
			right = receiveNext
		}
		if tcpSequenceGreater(right, sequence) {
			return TCPSACKBlock{LeftEdge: sequence, RightEdge: right}, true
		}
		sequence = receiveNext
	}
	incomingStart := sequence - receiveNext
	incomingEnd := end - receiveNext
	if incomingStart >= incomingEnd {
		return TCPSACKBlock{}, false
	}
	for _, piece := range pieces {
		pieceStart := piece.sequence - receiveNext
		pieceEnd := pieceStart + uint32(len(piece.payload))
		if piece.fin {
			pieceEnd++
		}
		left := incomingStart
		if pieceStart > left {
			left = pieceStart
		}
		right := incomingEnd
		if pieceEnd < right {
			right = pieceEnd
		}
		if left < right {
			return TCPSACKBlock{LeftEdge: receiveNext + left, RightEdge: receiveNext + right}, true
		}
	}
	return TCPSACKBlock{}, false
}

func parseTCPDSACKOption(options []byte, acknowledged, sendNext, history uint32) (TCPSACKBlock, bool) {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionSACK && length >= 10 && (length-2)%8 == 0 {
			left := binary.BigEndian.Uint32(options[offset+2 : offset+6])
			right := binary.BigEndian.Uint32(options[offset+6 : offset+10])
			block := TCPSACKBlock{LeftEdge: left, RightEdge: right}
			if !tcpSequenceLess(left, right) {
				return TCPSACKBlock{}, false
			}
			if tcpSequenceLessEqual(right, acknowledged) && acknowledged-left <= history {
				return block, true
			}
			if length >= 18 {
				secondLeft := binary.BigEndian.Uint32(options[offset+10 : offset+14])
				secondRight := binary.BigEndian.Uint32(options[offset+14 : offset+18])
				secondLength := secondRight - secondLeft
				if secondLength != 0 && secondLength <= sendNext-acknowledged &&
					left-secondLeft < secondLength && right-secondLeft <= secondLength {
					return block, true
				}
			}
			return TCPSACKBlock{}, false
		}
		offset += length
	}
	return TCPSACKBlock{}, false
}

func parseTCPSACKOptions(options []byte, acknowledged, sendNext uint32) []TCPSACKBlock {
	window := sendNext - acknowledged
	var blocks []TCPSACKBlock
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionSACK && length >= 10 && (length-2)%8 == 0 {
			for blockOffset := offset + 2; blockOffset < offset+length; blockOffset += 8 {
				left := binary.BigEndian.Uint32(options[blockOffset : blockOffset+4])
				right := binary.BigEndian.Uint32(options[blockOffset+4 : blockOffset+8])
				leftDistance, rightDistance := left-acknowledged, right-acknowledged
				if leftDistance < rightDistance && rightDistance <= window {
					blocks = append(blocks, TCPSACKBlock{LeftEdge: left, RightEdge: right})
				}
			}
		}
		offset += length
	}
	sort.Slice(blocks, func(left, right int) bool {
		return blocks[left].LeftEdge-acknowledged < blocks[right].LeftEdge-acknowledged
	})
	merged := blocks[:0]
	for _, block := range blocks {
		if len(merged) == 0 || tcpSequenceLess(merged[len(merged)-1].RightEdge, block.LeftEdge) {
			merged = append(merged, block)
			continue
		}
		if tcpSequenceGreater(block.RightEdge, merged[len(merged)-1].RightEdge) {
			merged[len(merged)-1].RightEdge = block.RightEdge
		}
	}
	return merged
}

func applyTCPSACK(outstanding []sentTCPSegment, blocks []TCPSACKBlock, epoch time.Time) ([]sentTCPSegment, uint32, bool, bool, tcpRACKSample, []sentTCPSegment) {
	var highest uint32
	var newInformation bool
	var latest tcpRACKSample
	var newlySACKed []sentTCPSegment
	for blockIndex, block := range blocks {
		if blockIndex == 0 || tcpSequenceGreater(block.RightEdge, highest) {
			highest = block.RightEdge
		}
		outstanding = splitTCPSegmentAt(outstanding, block.LeftEdge)
		outstanding = splitTCPSegmentAt(outstanding, block.RightEdge)
		for index := range outstanding {
			segment := &outstanding[index]
			if tcpSequenceGreaterEqual(segment.sequence, block.LeftEdge) && tcpSequenceGreaterEqual(block.RightEdge, segment.end) {
				if !segment.state.has(sentTCPSegmentSACKed) {
					newInformation = true
					newlySACKed = append(newlySACKed, *segment)
					latest = newerRACKSample(latest, tcpRACKSample{sentAt: segment.transmittedAt(epoch), end: segment.end, order: segment.transmissionOrder, timestamp: segment.timestamp, retransmitted: segment.isRetransmitted()})
					segment.delivery.deliveredStamp = 0
				}
				segment.state.set(sentTCPSegmentSACKed, true)
			}
		}
	}
	return outstanding, highest, len(blocks) != 0, newInformation, latest, newlySACKed
}

func splitTCPSegmentAt(outstanding []sentTCPSegment, boundary uint32) []sentTCPSegment {
	splitRanges := 0
	for index := range outstanding {
		if outstanding[index].state.has(sentTCPSegmentSACKSplit) {
			splitRanges++
		}
	}
	for index := range outstanding {
		segment := outstanding[index]
		if !tcpSequenceGreater(boundary, segment.sequence) || !tcpSequenceLess(boundary, segment.end) {
			continue
		}
		increase := 1
		if !segment.state.has(sentTCPSegmentSACKSplit) {
			increase = 2
		}
		if splitRanges+increase > tcpMaximumSACKSplitRanges {
			return outstanding
		}
		left, right := segment, segment
		left.state.set(sentTCPSegmentSACKSplit, true)
		right.state.set(sentTCPSegmentSACKSplit, true)
		left.end = boundary
		left.flags &^= TCPFlagPSH | TCPFlagFIN
		right.sequence = boundary
		outstanding = append(outstanding, sentTCPSegment{})
		copy(outstanding[index+2:], outstanding[index+1:])
		outstanding[index], outstanding[index+1] = left, right
		return outstanding
	}
	return outstanding
}

func firstUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return 0
}

func lastUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := len(outstanding) - 1; index >= 0; index-- {
		if !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return len(outstanding) - 1
}

func tailLossProbeDelay(smoothedRTT, rto time.Duration, singleSegment bool) time.Duration {
	delay := 2 * smoothedRTT
	if smoothedRTT == 0 {
		delay = rto
	} else if singleSegment {
		delay += tcpTailLossProbeACKDelay
	}
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > rto {
		delay = rto
	}
	return delay
}

func tcpSACKedState(outstanding []sentTCPSegment) (ranges int, bytes uint32) {
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKed) {
			ranges++
			bytes += segment.end - segment.sequence
		}
	}
	return ranges, bytes
}

func highestSACKedSequence(outstanding []sentTCPSegment) uint32 {
	var highest uint32
	var found bool
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKed) && (!found || tcpSequenceGreater(segment.end, highest)) {
			highest = segment.end
			found = true
		}
	}
	return highest
}

func firstUnretriedLoss(outstanding []sentTCPSegment, mss int) int {
	index := -1
	var sackedRanges, sackedBytes int
	for next := len(outstanding) - 1; next >= 0; next-- {
		segment := outstanding[next]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		lost := segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !segment.state.has(sentTCPSegmentSACKRetried) && lost {
			index = next
		}
	}
	return index
}

func tcpRateApplicationLimited(queued int, hostQueued bool, flight, window uint32, recovery, peerSACK bool, outstanding []sentTCPSegment, mss int) bool {
	if queued >= mss || hostQueued || flight >= window {
		return false
	}
	return !recovery || !peerSACK || firstUnretriedLoss(outstanding, mss) < 0
}

func firstUnretriedSACKHole(outstanding []sentTCPSegment, highest uint32) int {
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.state.has(sentTCPSegmentSACKed) && !segment.state.has(sentTCPSegmentSACKRetried) && tcpSequenceLess(segment.sequence, highest) {
			return index
		}
	}
	return -1
}

func sackLostRangeCount(outstanding []sentTCPSegment, mss int) int {
	count := 0
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		if segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss {
			count++
		}
	}
	return count
}

func sackSegmentLost(outstanding []sentTCPSegment, index, mss int) bool {
	if index < 0 || index >= len(outstanding) || outstanding[index].state.has(sentTCPSegmentSACKed) {
		return false
	}
	if outstanding[index].state.has(sentTCPSegmentRACKLost) {
		return true
	}
	var ranges, bytes int
	for next := index + 1; next < len(outstanding); next++ {
		segment := outstanding[next]
		if !segment.state.has(sentTCPSegmentSACKed) {
			continue
		}
		ranges++
		bytes += int(segment.end - segment.sequence)
		if ranges >= tcpDuplicateACKThreshold || mss > 0 && bytes > (tcpDuplicateACKThreshold-1)*mss {
			return true
		}
	}
	return false
}

func recordTCPSegmentLoss(segment *sentTCPSegment, proven bool) uint32 {
	if !proven || segment == nil || !segment.isTransmitted() || segment.lossAlreadyReported() {
		return 0
	}
	segment.state |= sentTCPSegmentLossReported
	return segment.end - segment.sequence
}

func recordProvenTCPLosses(outstanding []sentTCPSegment, mss int) uint32 {
	return recordProvenTCPLossesWith(outstanding, mss, nil)
}

func recordProvenTCPLossesWith(outstanding []sentTCPSegment, mss int, report func(*sentTCPSegment, uint32)) uint32 {
	var losses uint32
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := &outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		lost := segment.state.has(sentTCPSegmentRACKLost) || !segment.state.has(sentTCPSegmentSACKRetried) && (sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss)
		if lost {
			bytes := recordTCPSegmentLoss(segment, true)
			losses = growCongestionWindow(losses, bytes)
			if bytes != 0 && report != nil {
				report(segment, bytes)
			}
		}
	}
	return losses
}

func isolatedPLPMTUProbeLoss(outstanding []sentTCPSegment, probeStart, highestSACK uint32, mss int) bool {
	probeIndex := -1
	for index, segment := range outstanding {
		if segment.sequence == probeStart {
			probeIndex = index
			break
		}
	}
	if !sackSegmentLost(outstanding, probeIndex, mss) {
		return false
	}
	for index, segment := range outstanding {
		if index != probeIndex && !segment.state.has(sentTCPSegmentSACKed) && tcpSequenceLess(segment.sequence, highestSACK) {
			return false
		}
	}
	return true
}

func lossRecoveryFlightSize(outstanding []sentTCPSegment) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if !segment.state.has(sentTCPSegmentSACKed) && !segment.state.has(sentTCPSegmentLimited) {
			bytes += segment.end - segment.sequence
		}
	}
	return bytes
}

func tcpACKRTTAmbiguous(outstanding []sentTCPSegment, acknowledgement uint32) bool {
	for _, segment := range outstanding {
		if !tcpSequenceLess(segment.sequence, acknowledgement) {
			break
		}
		if segment.isRetransmitted() {
			return true
		}
	}
	return false
}

func sackRecoveryPipe(outstanding []sentTCPSegment, mss int) uint32 {
	var bytes uint32
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		size := segment.end - segment.sequence
		lost := segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !lost {
			bytes = growCongestionWindow(bytes, size)
		}
		if segment.state.has(sentTCPSegmentSACKRetried) {
			bytes = growCongestionWindow(bytes, size)
		}
	}
	return bytes
}

func sackRecoveryCanSend(recovery bool, pipe, size, window uint32) bool {
	return !recovery || uint64(pipe)+uint64(size) <= uint64(window)
}

func tcpNewlyAcknowledgedBytes(outstanding []sentTCPSegment, acknowledgement uint32) uint32 {
	var delivered uint32
	for _, segment := range outstanding {
		if !tcpSequenceGreater(acknowledgement, segment.sequence) {
			break
		}
		if segment.state.has(sentTCPSegmentSACKed) {
			continue
		}
		end := segment.end
		if tcpSequenceLess(acknowledgement, end) {
			end = acknowledgement
		}
		delivered = growCongestionWindow(delivered, end-segment.sequence)
	}
	return delivered
}

func prrCongestionWindow(pipe, threshold, priorFlight uint32, delivered, sent uint64, newlyDelivered uint32, cumulativeACK, newlyLost bool, mss int) uint32 {
	if newlyDelivered == 0 || priorFlight == 0 || mss < 1 {
		return pipe
	}
	var allowance uint64
	if pipe > threshold {
		target := (uint64(threshold)*delivered + uint64(priorFlight) - 1) / uint64(priorFlight)
		if target > sent {
			allowance = target - sent
		}
	} else {
		if delivered > sent {
			allowance = delivered - sent
		}
		if allowance < uint64(newlyDelivered) {
			allowance = uint64(newlyDelivered)
		}
		if cumulativeACK && !newlyLost {
			allowance += uint64(mss)
		}
		if available := uint64(threshold - pipe); allowance > available {
			allowance = available
		}
	}
	if allowance > uint64(tcpMaximumScaledWindow) {
		allowance = uint64(tcpMaximumScaledWindow)
	}
	return growCongestionWindow(pipe, uint32(allowance))
}

func rackReorderingWindow(minimumRTT, smoothedRTT time.Duration, scale uint32) time.Duration {
	if minimumRTT <= 0 || smoothedRTT <= 0 {
		return 0
	}
	if scale == 0 {
		scale = 1
	}
	window := minimumRTT / 4
	if window <= 0 {
		return 0
	}
	if scale > uint32(smoothedRTT/window) {
		return smoothedRTT
	}
	window *= time.Duration(scale)
	if window > smoothedRTT {
		window = smoothedRTT
	}
	return window
}

func tcpClockTieTransmissionAfter(order, end, previousOrder, previousEnd uint32) bool {
	if order != previousOrder && order != 0 && previousOrder != 0 {
		return tcpSequenceGreater(order, previousOrder)
	}
	return tcpSequenceGreater(end, previousEnd)
}

func newerRACKSample(current, candidate tcpRACKSample) tcpRACKSample {
	if candidate.sentAt.IsZero() {
		return current
	}
	if candidate.sentAt.After(current.sentAt) || candidate.sentAt.Equal(current.sentAt) && tcpClockTieTransmissionAfter(candidate.order, candidate.end, current.order, current.end) {
		return candidate
	}
	return current
}

func validRACKSample(sample tcpRACKSample, minimumRTT time.Duration, timestampEcho uint32) tcpRACKSample {
	if sample.retransmitted {
		if sample.timestamp != 0 && timestampEcho != 0 && tcpSequenceLess(timestampEcho, sample.timestamp) {
			return tcpRACKSample{}
		}
		if minimumRTT > 0 && sample.rtt < minimumRTT {
			return tcpRACKSample{}
		}
	}
	return sample
}

func rackDeliveredAfter(delivered tcpRACKSample, segment sentTCPSegment, epoch time.Time) bool {
	transmittedAt := segment.transmittedAt(epoch)
	return delivered.sentAt.After(transmittedAt) || delivered.sentAt.Equal(transmittedAt) && tcpClockTieTransmissionAfter(delivered.order, delivered.end, segment.transmissionOrder, segment.end)
}

func rackAdvanceForwardACK(forward *uint32, set *bool, end uint32, retransmitted bool) bool {
	if !*set || tcpSequenceGreater(end, *forward) {
		*forward, *set = end, true
		return false
	}
	return tcpSequenceLess(end, *forward) && !retransmitted
}

func rackLossDelay(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration, epoch time.Time) (time.Duration, bool) {
	var maximum time.Duration
	found := false
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKed) || segment.state.has(sentTCPSegmentRACKLost) || !rackDeliveredAfter(delivered, segment, epoch) {
			continue
		}
		remaining := segment.transmittedAt(epoch).Add(delivered.rtt + reorderingWindow).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if !found || remaining > maximum {
			maximum, found = remaining, true
		}
	}
	return maximum, found
}

func markRACKLoss(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration, epoch time.Time) bool {
	lost := false
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.state.has(sentTCPSegmentSACKed) && rackDeliveredAfter(delivered, *segment, epoch) && !now.Before(segment.transmittedAt(epoch).Add(delivered.rtt+reorderingWindow)) {
			segment.state.set(sentTCPSegmentRACKLost, true)
			segment.state.set(sentTCPSegmentSACKRetried, false)
		}
		lost = lost || segment.state.has(sentTCPSegmentRACKLost) && !segment.state.has(sentTCPSegmentSACKRetried)
	}
	return lost
}

func hasRACKLoss(outstanding []sentTCPSegment) bool {
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentRACKLost) && !segment.state.has(sentTCPSegmentSACKRetried) {
			return true
		}
	}
	return false
}

func firstRACKLoss(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if outstanding[index].state.has(sentTCPSegmentRACKLost) && !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return -1
}

func splitTCPSegments(outstanding []sentTCPSegment, mss int) []sentTCPSegment {
	result := make([]sentTCPSegment, 0, len(outstanding))
	for _, segment := range outstanding {
		payloadSize := segment.dataSize()
		if payloadSize <= mss {
			result = append(result, segment)
			continue
		}
		for offset := 0; offset < payloadSize; offset += mss {
			end := offset + mss
			if end > payloadSize {
				end = payloadSize
			}
			part := segment
			part.sequence = segment.sequence + uint32(offset)
			part.end = segment.sequence + uint32(end)
			part.state.set(sentTCPSegmentCWR, offset == 0 && segment.state.has(sentTCPSegmentCWR))
			if end != payloadSize {
				part.flags &^= TCPFlagPSH | TCPFlagFIN
			} else if part.flags&TCPFlagFIN != 0 {
				part.end++
			}
			result = append(result, part)
		}
	}
	return result
}

func trimAcknowledgedTCPSegment(segment *sentTCPSegment, acknowledgement uint32) {
	if segment == nil || !tcpSequenceGreater(acknowledgement, segment.sequence) || !tcpSequenceLess(acknowledgement, segment.end) {
		return
	}
	if skip := acknowledgement - segment.sequence; skip >= uint32(segment.dataSize()) {
		segment.flags &^= TCPFlagPSH
	}
	segment.sequence = acknowledgement
	segment.state.set(sentTCPSegmentCWR, false)
}

func clampMSS(value, maximum int) int {
	if value < tcpMinimumPeerMSS {
		value = tcpMinimumPeerMSS
	}
	if value > maximum {
		value = maximum
	}
	return value
}

func tcpEffectiveSendMSS(peerMSS, pathMSS int, timestamp bool) int {
	maximum := clampMSS(peerMSS, pathMSS)
	if timestamp {
		maximum -= tcpTimestampOptionSize
	}
	return maximum
}

func tcpSegmentPayloadLimit(peerMSS, pathMSS, optionSize int) int {
	if pathMSS < peerMSS {
		peerMSS = pathMSS
	}
	return peerMSS - optionSize
}

func defaultTCPPeerMSS(address netip.Addr) int {
	if address.Is4() {
		return 536
	}
	return 1220
}

func initialTCPWindow(mss int) uint32 {
	window := 10 * mss
	minimum := 2 * mss
	if minimum < 14600 {
		minimum = 14600
	}
	if window > minimum {
		window = minimum
	}
	return uint32(window)
}

func tcpRestartWindow(window uint32, mss int, idle, rto time.Duration) uint32 {
	restart := initialTCPWindow(mss)
	if window < restart {
		restart = window
	}
	if rto <= 0 {
		return restart
	}
	for idle -= rto; idle > 0 && window > restart; idle -= rto {
		window /= 2
	}
	if window < restart {
		return restart
	}
	return window
}

func tcpCurrentSlowStartThreshold(window, threshold uint32) uint32 {
	current := window - window/4
	if threshold > current {
		return threshold
	}
	return current
}

func tcpSACKRenegingDelay(smoothedRTT time.Duration) time.Duration {
	delay := smoothedRTT / 2
	if delay < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	return delay
}

func tcpCompressedSACKDelay(smoothedRTT time.Duration) time.Duration {
	if smoothedRTT <= 0 {
		return tcpMaximumCompressedSACKDelay
	}
	delay := smoothedRTT/100*33 + smoothedRTT%100*33/100
	if delay > tcpMaximumCompressedSACKDelay {
		return tcpMaximumCompressedSACKDelay
	}
	return delay
}

func growCongestionWindow(window, delta uint32) uint32 {
	if window >= tcpMaximumScaledWindow || delta >= tcpMaximumScaledWindow-window {
		return tcpMaximumScaledWindow
	}
	return window + delta
}

func newRenoPartialACKWindow(window, acknowledged uint32, mss int) uint32 {
	if acknowledged >= window {
		window = 0
	} else {
		window -= acknowledged
	}
	minimum := uint32(mss)
	if acknowledged >= minimum {
		window = growCongestionWindow(window, minimum)
	}
	if window < minimum {
		window = minimum
	}
	return window
}

func (c *TCPConn) receiveTCPData(sequence uint32, payload []byte, fin bool, receiveWindow uint32, receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
	owner := payload
	finSequence := sequence + uint32(len(payload))
	if tcpSequenceLess(sequence, *receiveNext) {
		skip := *receiveNext - sequence
		if skip < uint32(len(payload)) {
			payload = payload[skip:]
			sequence = *receiveNext
		} else {
			payload = nil
			sequence = *receiveNext
			fin = fin && finSequence == *receiveNext
		}
	}
	if sequence == *receiveNext && len(*outOfOrder) == 0 {
		originalPayloadSize := len(payload)
		if uint64(len(payload)) > uint64(receiveWindow) {
			payload = payload[:receiveWindow]
		}
		accepted := c.appendReadBuffer(payload, owner, 0)
		*receiveNext += uint32(accepted)
		closed := fin && accepted == originalPayloadSize &&
			(originalPayloadSize == 0 || uint64(originalPayloadSize) < uint64(receiveWindow))
		if closed {
			*receiveNext++
		}
		return accepted != 0 || closed, closed
	}
	if !c.storeTCPOutOfOrder(*receiveNext, receiveWindow, sequence, payload, owner, fin, outOfOrder, outOfOrderBytes) && tcpSequenceGreater(sequence, *receiveNext) {
		return false, false
	}
	return c.promoteTCPReceived(receiveNext, outOfOrder, outOfOrderBytes)
}

func (c *TCPConn) promoteTCPReceived(receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
	delivered, remoteClosed := false, false
	for len(*outOfOrder) != 0 && !remoteClosed {
		piece := (*outOfOrder)[0]
		owner := piece.payload
		if tcpSequenceGreater(piece.sequence, *receiveNext) {
			break
		}
		*outOfOrder = (*outOfOrder)[1:]
		*outOfOrderBytes -= len(piece.payload)
		pieceFINSequence := piece.sequence + uint32(len(piece.payload))
		if tcpSequenceLess(piece.sequence, *receiveNext) {
			skip := *receiveNext - piece.sequence
			if skip < uint32(len(piece.payload)) {
				piece.payload = piece.payload[skip:]
				piece.sequence = *receiveNext
			} else {
				piece.payload = nil
				piece.sequence = *receiveNext
				piece.fin = piece.fin && pieceFINSequence == *receiveNext
			}
		}
		accepted := c.appendTCPReadBuffer(piece.payload, owner, *outOfOrderBytes, true)
		*receiveNext += uint32(accepted)
		delivered = delivered || accepted != 0
		if accepted != len(piece.payload) {
			remaining := retainTCPPayload(piece.payload[accepted:], owner)
			*outOfOrder = append([]tcpReceivedPiece{{sequence: *receiveNext, payload: remaining, fin: piece.fin}}, *outOfOrder...)
			*outOfOrderBytes += len(remaining)
			break
		}
		if piece.fin {
			*receiveNext++
			remoteClosed = true
		}
	}
	if remoteClosed {
		*outOfOrder = nil
		*outOfOrderBytes = 0
	}
	c.outOfOrderUnread.Store(int64(*outOfOrderBytes))
	return delivered || remoteClosed, remoteClosed
}

type tcpDataFragment struct {
	offset  uint32
	payload []byte
}

func (c *TCPConn) storeTCPOutOfOrder(receiveNext, receiveWindow, sequence uint32, payload, owner []byte, fin bool, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) bool {
	distance := sequence - receiveNext
	available := c.receiveAvailable(*outOfOrderBytes)
	if available < 0 {
		available = 0
	}
	if distance >= receiveWindow && !(distance == 0 && len(payload) == 0 && fin) {
		return false
	}
	originalPayloadSize := len(payload)
	if maximumPayload := int(receiveWindow - distance); len(payload) > maximumPayload {
		payload = payload[:maximumPayload]
	}
	fin = fin && (distance == 0 && len(payload) == 0 || uint64(distance)+uint64(originalPayloadSize) < uint64(receiveWindow))
	incomingFINSequence := sequence + uint32(originalPayloadSize)
	var existingFINSequence uint32
	hasExistingFIN := false
	for _, existing := range *outOfOrder {
		if existing.fin {
			existingFINSequence = existing.sequence + uint32(len(existing.payload))
			hasExistingFIN = true
			break
		}
	}
	if hasExistingFIN {
		fin = fin && !tcpSequenceGreater(incomingFINSequence, existingFINSequence)
		payloadEnd := sequence + uint32(len(payload))
		if tcpSequenceGreater(payloadEnd, existingFINSequence) {
			if !tcpSequenceLess(sequence, existingFINSequence) {
				payload = nil
			} else {
				payload = payload[:existingFINSequence-sequence]
			}
		}
	}
	var fragmentWorkspace [2]tcpDataFragment
	fragments := fragmentWorkspace[:0]
	if len(payload) != 0 {
		start, end := distance, distance+uint32(len(payload))
		cursor := start
		for _, existing := range *outOfOrder {
			existingStart := existing.sequence - receiveNext
			existingEnd := existingStart + uint32(len(existing.payload))
			if existingEnd <= cursor {
				continue
			}
			if existingStart >= end {
				break
			}
			if cursor < existingStart {
				fragmentEnd := existingStart
				if fragmentEnd > end {
					fragmentEnd = end
				}
				fragments = append(fragments, tcpDataFragment{
					offset:  cursor,
					payload: payload[cursor-start : fragmentEnd-start],
				})
			}
			if existingEnd > cursor {
				cursor = existingEnd
			}
			if cursor >= end {
				break
			}
		}
		if cursor < end {
			fragments = append(fragments, tcpDataFragment{offset: cursor, payload: payload[cursor-start:]})
		}
	}
	addedBytes := 0
	for _, fragment := range fragments {
		addedBytes += len(fragment.payload)
	}
	upperCount := len(*outOfOrder) + len(fragments)
	if fin {
		upperCount++
	}
	reuseScoreboard := addedBytes <= available && upperCount <= tcpMaximumOutOfOrder && cap(*outOfOrder) >= upperCount
	var candidate []tcpReceivedPiece
	if reuseScoreboard {
		candidate = (*outOfOrder)[:len(*outOfOrder)]
	} else {
		candidate = append([]tcpReceivedPiece(nil), (*outOfOrder)...)
	}
	for _, fragment := range fragments {
		retained := retainTCPPayload(fragment.payload, owner)
		candidate = append(candidate, tcpReceivedPiece{sequence: receiveNext + fragment.offset, payload: retained})
	}
	if fin {
		candidate = append(candidate, tcpReceivedPiece{sequence: incomingFINSequence, fin: true})
	}
	candidate = normalizeTCPReceivedPieces(receiveNext, candidate)
	bytes := 0
	for _, piece := range candidate {
		bytes += len(piece.payload)
	}
	if bytes > *outOfOrderBytes+available || len(candidate) > tcpMaximumOutOfOrder {
		if !reuseScoreboard {
			return false
		}
	}
	*outOfOrder, *outOfOrderBytes = candidate, bytes
	c.mu.Lock()
	c.outOfOrderUnread.Store(int64(bytes))
	reset := c.userClosed && addedBytes != 0
	c.mu.Unlock()
	if reset {
		c.abort(net.ErrClosed)
	}
	return len(fragments) != 0 || fin
}

func normalizeTCPReceivedPieces(receiveNext uint32, pieces []tcpReceivedPiece) []tcpReceivedPiece {
	sort.SliceStable(pieces, func(left, right int) bool {
		leftOffset, rightOffset := pieces[left].sequence-receiveNext, pieces[right].sequence-receiveNext
		if leftOffset != rightOffset {
			return leftOffset < rightOffset
		}
		return len(pieces[left].payload) > len(pieces[right].payload)
	})
	var finOffset uint32
	hasFIN := false
	for _, piece := range pieces {
		if piece.fin {
			offset := piece.sequence - receiveNext + uint32(len(piece.payload))
			if !hasFIN || offset < finOffset {
				finOffset, hasFIN = offset, true
			}
		}
	}
	result := pieces[:0]
	for _, piece := range pieces {
		piece.fin = false
		pieceOffset := piece.sequence - receiveNext
		if hasFIN {
			if pieceOffset >= finOffset {
				continue
			}
			if pieceEnd := pieceOffset + uint32(len(piece.payload)); pieceEnd > finOffset {
				owner := piece.payload
				piece.payload = retainTCPPayload(piece.payload[:finOffset-pieceOffset], owner)
			}
		}
		if len(piece.payload) == 0 {
			continue
		}
		if len(result) == 0 {
			result = append(result, piece)
			continue
		}
		previous := &result[len(result)-1]
		previousEnd := previous.sequence + uint32(len(previous.payload))
		if tcpSequenceGreater(previousEnd, piece.sequence) {
			skip := previousEnd - piece.sequence
			if skip < uint32(len(piece.payload)) {
				owner := piece.payload
				piece.sequence += skip
				piece.payload = retainTCPPayload(piece.payload[skip:], owner)
				result = append(result, piece)
			}
		} else {
			result = append(result, piece)
		}
	}
	if hasFIN {
		finSequence := receiveNext + finOffset
		attached := false
		if len(result) != 0 {
			last := &result[len(result)-1]
			if last.sequence+uint32(len(last.payload)) == finSequence {
				last.fin = true
				attached = true
			}
		}
		if !attached {
			result = append(result, tcpReceivedPiece{sequence: finSequence, fin: true})
		}
	}
	for index := len(result); index < len(pieces); index++ {
		pieces[index] = tcpReceivedPiece{}
	}
	return result
}

func tcpSequenceLess(left, right uint32) bool { return int32(left-right) < 0 }

func tcpSequenceGreater(left, right uint32) bool { return tcpSequenceLess(right, left) }

func tcpSequenceLessEqual(left, right uint32) bool { return !tcpSequenceGreater(left, right) }

func tcpSequenceGreaterEqual(left, right uint32) bool { return !tcpSequenceLess(left, right) }

func tcpAcceptableSendSequence(sendUnacknowledged, sendNext, sendWindow uint32, sendWindowScale uint8) uint32 {
	if sendWindow == 0 {
		return sendUnacknowledged
	}
	windowEnd := sendUnacknowledged + sendWindow
	if !tcpSequenceLess(windowEnd, sendNext) || sendNext-windowEnd < uint32(1)<<sendWindowScale {
		return sendNext
	}
	return windowEnd
}

func tcpChallengeACKSequence(segment tcpSegment, sendUnacknowledged, sendNext, currentSendWindow uint32, sendWindowScale uint8) uint32 {
	fallback := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, currentSendWindow, sendWindowScale)
	if segment.flags != TCPFlagACK || len(segment.payload) != 0 || segment.acknowledgement-sendUnacknowledged > sendNext-sendUnacknowledged {
		return fallback
	}
	sendWindow := uint32(segment.window) << sendWindowScale
	return tcpAcceptableSendSequence(segment.acknowledgement, sendNext, sendWindow, sendWindowScale)
}

func tcpECNStartsRecovery(active bool, acknowledgement, recoveryPoint uint32) bool {
	return !active || tcpSequenceGreater(acknowledgement, recoveryPoint)
}

func tcpSegmentAcceptable(sequence, length, receiveNext, receiveWindow uint32) bool {
	if receiveWindow == 0 {
		return length == 0 && sequence == receiveNext
	}
	if sequence-receiveNext < receiveWindow {
		return true
	}
	return length != 0 && sequence+length-1-receiveNext < receiveWindow
}

func tcpKeepAliveOrWindowProbe(segment tcpSegment, length, receiveNext, receiveWindow uint32) bool {
	if segment.flags&(TCPFlagRST|TCPFlagSYN|TCPFlagFIN) != 0 || segment.flags&TCPFlagACK == 0 || segment.sequence != receiveNext-1 {
		return false
	}
	return length <= 1
}

func tcpWindowUpdate(ackAdvanced bool, sequence, lastSequence uint32, advertisedWindow uint16, peerScale uint8, currentWindow uint32) (uint32, bool) {
	if ackAdvanced || tcpSequenceGreater(sequence, lastSequence) {
		return uint32(advertisedWindow) << peerScale, true
	}
	if sequence != lastSequence {
		return 0, false
	}
	window := uint32(advertisedWindow) << peerScale
	return window, window > currentWindow || window == 0
}

func tcpPAWSDisorderedACK(segment tcpSegment, state *tcpEstablishedState, timestamp uint32) (drop, accept bool) {
	if segment.flags&TCPFlagACK == 0 || len(segment.payload) != 0 || segment.flags&(TCPFlagSYN|TCPFlagFIN|TCPFlagRST) != 0 {
		return false, false
	}
	if segment.sequence != state.receiveNext {
		return tcpSequenceLess(segment.sequence, state.receiveNext), false
	}
	if segment.acknowledgement != state.sendUnacknowledged {
		return false, false
	}
	window := uint32(segment.window) << state.peerScale
	windowUpdate := tcpSequenceGreater(segment.sequence, state.peerWindowSequence) ||
		segment.sequence == state.peerWindowSequence &&
			(window > state.peerWindow || window == 0)
	if windowUpdate {
		return false, false
	}
	return false, int32(state.connection.recentTimestamp-timestamp) <= int32(tcpPAWSReplayTicks(state.rtt.rto))
}

func tcpDuplicateACKEvidence(segment tcpSegment, peerSACK, newSACKInfo, ackAdvanced bool, sendUnacknowledged, previousWindow, peerWindow uint32) bool {
	if peerSACK {
		return newSACKInfo
	}
	return !ackAdvanced && segment.acknowledgement == sendUnacknowledged && previousWindow == peerWindow &&
		len(segment.payload) == 0 && segment.flags&(TCPFlagSYN|TCPFlagFIN) == 0
}

var _ net.Conn = (*TCPConn)(nil)

var _ io.ReaderFrom = (*TCPConn)(nil)
var _ io.WriterTo = (*TCPConn)(nil)

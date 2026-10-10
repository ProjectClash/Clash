package mipstack

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"syscall"
	"time"
)

type ipv6FragmentPoint struct {
	previous       int
	insertion      int
	next           byte
	atomicOffset   int
	atomicPrevious int
}

type fragmentRangeCursor struct {
	total           int
	capacity        int
	alignedCapacity int
	offset          int
}

func newFragmentRangeCursor(total, capacity int) (fragmentRangeCursor, bool) {
	alignedCapacity := capacity &^ 7
	if total <= 0 || alignedCapacity < 8 {
		return fragmentRangeCursor{}, false
	}
	return fragmentRangeCursor{total: total, capacity: capacity, alignedCapacity: alignedCapacity}, true
}

func (c *fragmentRangeCursor) next() (offset, size int, more, ok bool) {
	if c.offset >= c.total {
		return 0, 0, false, false
	}
	offset = c.offset
	size = c.total - offset
	if size > c.capacity {
		size = c.alignedCapacity
	}
	c.offset += size
	return offset, size, c.offset < c.total, true
}

func inspectIPv6ForwarderFragmentPoint(packet []byte) (ipv6FragmentPoint, bool) {
	return inspectIPv6FragmentPoint(packet, true)
}

func inspectIPv6FragmentPoint(packet []byte, rejectActiveRouting bool) (ipv6FragmentPoint, bool) {
	if len(packet) < 40 {
		return ipv6FragmentPoint{}, false
	}
	payload := packet[40:]
	next, offset, previous := packet[6], 0, -1
	point := ipv6FragmentPoint{
		previous: 6, insertion: 40, next: packet[6],
		atomicOffset: -1, atomicPrevious: -1,
	}
	seenHop, fragmentableStarted := false, false
	for {
		switch next {
		case IPv6ExtensionHeaderHopByHop:
			if offset != 0 || seenHop {
				return ipv6FragmentPoint{}, false
			}
			headerOffset := offset
			length, valid := ipv6ExtensionHeaderUnit8Length(payload[offset:])
			if !valid {
				return ipv6FragmentPoint{}, false
			}
			next, previous, offset = payload[offset], offset, offset+length
			seenHop = true
			point.previous, point.insertion, point.next = 40+headerOffset, 40+offset, next
		case IPv6ExtensionHeaderRouting:
			if fragmentableStarted {
				return ipv6FragmentPoint{}, false
			}
			headerOffset := offset
			length, valid := ipv6ExtensionHeaderUnit8Length(payload[offset:])
			if !valid {
				return ipv6FragmentPoint{}, false
			}
			header := payload[offset : offset+length]
			next, previous, offset = header[0], offset, offset+length
			if rejectActiveRouting && header[3] != 0 {
				return ipv6FragmentPoint{}, false
			}
			point.previous, point.insertion, point.next = 40+headerOffset, 40+offset, next
		case IPv6ExtensionHeaderDestination:
			length, valid := ipv6ExtensionHeaderUnit8Length(payload[offset:])
			if !valid {
				return ipv6FragmentPoint{}, false
			}
			next, previous, offset = payload[offset], offset, offset+length
		case IPv6ExtensionHeaderAuthentication, IPv6ExtensionHeaderMobility:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return ipv6FragmentPoint{}, false
			}
			next, previous, offset = payload[offset], offset, offset+length
			fragmentableStarted = true
		case IPv6ExtensionHeaderFragment:
			if point.atomicOffset >= 0 {
				return ipv6FragmentPoint{}, false
			}
			headerOffset, preceding := offset, previous
			if len(payload)-offset < 8 {
				return ipv6FragmentPoint{}, false
			}
			header := payload[offset : offset+8]
			next, previous, offset = header[0], offset, offset+8
			if binary.BigEndian.Uint16(header[2:4])&0xfff9 != 0 {
				return ipv6FragmentPoint{}, false
			}
			point.atomicOffset = 40 + headerOffset
			point.atomicPrevious = ipv6NextHeaderFieldOffset(preceding)
		default:
			return point, true
		}
	}
}

const (
	fragmentMaximumSets = 128
	fragmentMaximumPieces = 256
	fragmentMaximumBytes = 4 * 1024 * 1024
	fragmentMaximumDatagram = 65535
	fragmentIPv4Lifetime = 30 * time.Second
	fragmentIPv6Lifetime = 60 * time.Second
)

type sourceFragmentation struct {
	allow        bool
	dontFragment bool
}

type ipFragmentLayout struct {
	options          ipPacketOptions
	identification   uint32
	payloadSize      uint16
	fragmentCapacity uint16
	headerSize       uint8
}

func (policy sourceFragmentation) requiresIPv4ID() bool {
	return policy.allow || !policy.dontFragment
}

func sourceFragmentationForMode(mode PathMTUDiscovery) sourceFragmentation {
	switch mode {
	case PathMTUDiscoveryWant:
		return sourceFragmentation{allow: true, dontFragment: true}
	case PathMTUDiscoveryDo, PathMTUDiscoveryProbe:
		return sourceFragmentation{dontFragment: true}
	case PathMTUDiscoveryInterface:
		return sourceFragmentation{}
	case PathMTUDiscoveryOmit, PathMTUDiscoveryDont:
		return sourceFragmentation{allow: true}
	default:
		return sourceFragmentation{allow: true}
	}
}

func (s *Stack) pathMTUOutputPolicy(destination netip.Addr, mode PathMTUDiscovery) (int, sourceFragmentation) {
	mtu := s.network.Load().mtu
	if mode < PathMTUDiscoveryProbe {
		mtu = s.mtuFor(destination)
	}
	return mtu, sourceFragmentationForMode(mode)
}

func (mode PathMTUDiscovery) acceptsPathMTU() bool {
	return mode != PathMTUDiscoveryInterface && mode != PathMTUDiscoveryOmit
}

type fragmentKey struct {
	source, target netip.Addr
	identification uint32
	protocol       byte
	v6             bool
	loopback       bool
}

type fragmentPiece struct {
	offset int
	data   []byte
}

type IPPacketReassembly struct {
	state  ipPacketReassemblyState
	active bool
}

type ipPacketReassemblyEntry struct {
	state          ipPacketReassemblyState
	created        time.Time
	updated        time.Time
	accountedBytes int
}

type ipPacketReassemblyState struct {
	pieces      []fragmentPiece
	total       int
	bytes       int
	protocol    byte
	source      netip.Addr
	target      netip.Addr
	identifier  uint32
	v6          bool
	ecnMask     byte
	maximum     int
	maxSize     int
	maxDFSize   int
	header      []byte
	nextHeader  int
	firstPacket []byte
}

type ipPacketReassemblyFragment struct {
	source     netip.Addr
	target     netip.Addr
	protocol   byte
	offset     int
	more       bool
	payload    []byte
	identifier uint32
	v6         bool
	ecn        byte
	maximum    int
	packetSize int
	df         bool
	header     []byte
	nextHeader int
	original   []byte
	owned      bool
}

func (f ipPacketReassemblyFragment) reassemblyKey(loopback bool) fragmentKey {
	key := fragmentKey{
		source: f.source, target: f.target, identification: f.identifier,
		v6: f.v6, loopback: loopback,
	}
	if !f.v6 {
		key.protocol = f.protocol
	}
	return key
}

type parsedFragment struct {
	ipPacketReassemblyFragment
	truncated     bool
	parameter     bool
	parameterCode byte
	parameterAt   uint32
}

func (r *IPPacketReassembly) Add(fragment IPPacket) (packet IPPacket, complete bool, err error) {
	parsed, err := publicReassemblyFragment(fragment)
	if err != nil {
		return IPPacket{}, false, err
	}
	if !r.active {
		r.state.start(parsed)
		r.active = true
	} else if !r.state.matches(parsed) {
		return IPPacket{}, false, syscall.EINVAL
	}
	wire, pending, _, err := r.state.addFragment(parsed, 0)
	if err != nil {
		r.Reset()
		return IPPacket{}, false, err
	}
	if pending {
		return IPPacket{}, false, nil
	}
	r.Reset()
	packet, err = ParseIPPacket(wire)
	if err != nil {
		return IPPacket{}, false, err
	}
	return packet, true, nil
}

func (r *IPPacketReassembly) Reset() {
	*r = IPPacketReassembly{}
}

func publicReassemblyFragment(packet IPPacket) (ipPacketReassemblyFragment, error) {
	packet, headerSize, totalSize, err := packet.wireLayout(true)
	if err != nil {
		return ipPacketReassemblyFragment{}, err
	}
	view, fragmented := packet.Fragment()
	if !fragmented || view.IsAtomic() {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	if packet.Source.Is4() {
		fragment := ipPacketReassemblyFragment{
			source: packet.Source, target: packet.Destination,
			protocol: byte(packet.Protocol), offset: view.Offset, more: view.MoreFragments,
			payload: view.Payload, identifier: view.Identification, ecn: byte(packet.TrafficClass) & 3,
			maximum: fragmentMaximumDatagram - headerSize, packetSize: totalSize, df: packet.DontFragment,
			nextHeader: 9,
		}
		if view.Offset == 0 {
			wire := make([]byte, totalSize)
			marshalPublicIPPacket(wire, packet, headerSize, true)
			fragment.payload = wire[headerSize:]
			fragment.header = wire[:headerSize]
			fragment.original = wire
			fragment.owned = true
		}
		return fragment, nil
	}
	fragmentOffset, nextHeaderOffset, valid := locateIPv6FragmentHeader(byte(packet.Protocol), packet.Payload)
	if !valid || fragmentOffset+8 > len(packet.Payload) {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	if view.Offset == 0 && view.MoreFragments && !ipv6FirstFragmentHeaderComplete(byte(view.Protocol), view.Payload) {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	maximum := fragmentMaximumDatagram
	if view.Offset == 0 {
		maximum -= fragmentOffset
	}
	fragment := ipPacketReassemblyFragment{
		source: packet.Source, target: packet.Destination, v6: true,
		protocol: byte(view.Protocol), offset: view.Offset, more: view.MoreFragments,
		payload: packet.Payload[fragmentOffset+8:], identifier: view.Identification,
		ecn:     byte(packet.TrafficClass) & 3,
		maximum: maximum, packetSize: totalSize,
	}
	if view.Offset == 0 {
		wire := make([]byte, totalSize)
		marshalPublicIPPacket(wire, packet, headerSize, true)
		wireOffset := 40 + fragmentOffset
		fragment.original = wire
		fragment.header = wire[:wireOffset]
		fragment.payload = wire[wireOffset+8:]
		fragment.nextHeader = nextHeaderOffset
		fragment.owned = true
	}
	return fragment, nil
}

func locateIPv6FragmentHeader(first byte, payload []byte) (fragmentOffset, nextHeaderOffset int, ok bool) {
	next, offset, previous := first, 0, -1
	for isTraversableIPv6ExtensionHeader(next) {
		length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
		if !valid {
			return 0, 0, false
		}
		if next == IPv6ExtensionHeaderFragment {
			return offset, ipv6NextHeaderFieldOffset(previous), true
		}
		previous = offset
		next, offset = payload[offset], offset+length
	}
	return 0, 0, false
}

func (r *ipPacketReassemblyState) start(fragment ipPacketReassemblyFragment) {
	*r = ipPacketReassemblyState{
		total: -1, protocol: fragment.protocol,
		source: fragment.source, target: fragment.target,
		identifier: fragment.identifier, v6: fragment.v6,
		ecnMask: 1 << fragment.ecn,
		maximum: fragmentMaximumDatagram,
	}
	if fragment.v6 || fragment.offset == 0 {
		r.maximum = fragment.maximum
	} else {
		r.maximum -= 20
	}
}

func (r *ipPacketReassemblyState) matches(fragment ipPacketReassemblyFragment) bool {
	return r.v6 == fragment.v6 && r.source == fragment.source && r.target == fragment.target &&
		r.identifier == fragment.identifier && (r.v6 || r.protocol == fragment.protocol)
}

func (r *ipPacketReassemblyState) addFragment(fragment ipPacketReassemblyFragment, maximumPieces int) (_ []byte, pending, added bool, err error) {
	if !fragment.v6 && fragment.more && len(fragment.payload)%8 != 0 {
		trimmed := len(fragment.payload) &^ 7
		discarded := len(fragment.payload) - trimmed
		fragment.payload = fragment.payload[:trimmed]
		fragment.original = fragment.original[:len(fragment.original)-discarded]
		fragment.packetSize -= discarded
	}
	end := fragment.offset + len(fragment.payload)
	if len(fragment.payload) == 0 || end > r.maximum || r.total > r.maximum || r.total >= 0 && end > r.total {
		return nil, false, false, syscall.EINVAL
	}
	duplicate, overlaps := fragmentRangeState(r.pieces, fragment.offset, end)
	if overlaps && !duplicate {
		return nil, false, false, syscall.EINVAL
	}
	if !fragment.more && r.total >= 0 && r.total != end {
		return nil, false, false, syscall.EINVAL
	}
	if !fragment.more {
		r.total = end
		for _, existing := range r.pieces {
			if existing.offset+len(existing.data) > r.total {
				return nil, false, false, syscall.EINVAL
			}
		}
	}
	if duplicate {
		return nil, true, false, nil
	}
	if fragment.offset == 0 {
		r.protocol = fragment.protocol
		r.nextHeader = fragment.nextHeader
		r.maximum = fragment.maximum
		if r.total > r.maximum {
			return nil, false, false, syscall.EINVAL
		}
		for _, existing := range r.pieces {
			if existing.offset+len(existing.data) > r.maximum {
				return nil, false, false, syscall.EINVAL
			}
		}
	}
	if maximumPieces > 0 && len(r.pieces) >= maximumPieces {
		return nil, false, false, ErrResourceLimit
	}
	candidateECN := r.ecnMask | 1<<fragment.ecn
	if candidateECN&1 != 0 && candidateECN != 1 {
		return nil, false, false, syscall.EINVAL
	}
	r.ecnMask = candidateECN
	retainedBytes := len(fragment.payload)
	if fragment.offset == 0 {
		if len(fragment.original) == 0 || len(fragment.header) < 20 || len(fragment.header) > len(fragment.original) ||
			len(fragment.payload) > len(fragment.original)-len(fragment.header) {
			return nil, false, false, syscall.EINVAL
		}
		retainedBytes = len(fragment.original)
	}
	var data []byte
	if fragment.offset == 0 {
		if fragment.owned {
			r.firstPacket = fragment.original
		} else {
			r.firstPacket = append([]byte(nil), fragment.original...)
		}
		r.header = r.firstPacket[:len(fragment.header)]
		payloadOffset := len(r.firstPacket) - len(fragment.payload)
		data = r.firstPacket[payloadOffset:]
	} else {
		data = append([]byte(nil), fragment.payload...)
	}
	piece := fragmentPiece{offset: fragment.offset, data: data}
	insertAt := sort.Search(len(r.pieces), func(index int) bool {
		return r.pieces[index].offset > fragment.offset
	})
	r.pieces = append(r.pieces, fragmentPiece{})
	copy(r.pieces[insertAt+1:], r.pieces[insertAt:])
	r.pieces[insertAt] = piece
	r.bytes += retainedBytes
	if fragment.packetSize > r.maxSize {
		r.maxSize = fragment.packetSize
	}
	if fragment.df && fragment.packetSize > r.maxDFSize {
		r.maxDFSize = fragment.packetSize
	}
	if !r.complete() {
		return nil, true, true, nil
	}
	wire := r.finishWire()
	if wire == nil {
		return nil, false, true, syscall.EINVAL
	}
	return wire, false, true, nil
}

func (r *ipPacketReassemblyState) complete() bool {
	overhead := len(r.header)
	if r.v6 && overhead != 0 {
		overhead += 8
	}
	return r.total >= 0 && r.bytes-overhead == r.total
}

func (r *ipPacketReassemblyState) finishWire() []byte {
	ecn, valid := fragmentECN(r.ecnMask)
	if !valid {
		return nil
	}
	dontFragment := !r.v6 && r.maxDFSize != 0 && r.maxDFSize == r.maxSize
	packet := buildReassembledPacket(r, dontFragment)
	setPacketECN(packet, ecn)
	return packet
}

func (s *Stack) runFragmentCleaner() {
	timer := newOwnedTimer()
	defer timer.close()
	var timeout <-chan time.Time
	for {
		s.fragmentMu.Lock()
		now := time.Now()
		expired := s.cleanFragmentsLocked(now)
		next, haveNext := s.nextFragmentExpiryLocked()
		s.fragmentMu.Unlock()
		s.sendFragmentTimeouts(expired)
		timer.stop()
		timeout = nil
		if haveNext {
			delay := time.Until(next)
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		select {
		case <-timeout:
			timer.consumed()
		case <-s.fragmentWake:
		case <-s.closeCh:
			return
		}
	}
}

func (s *Stack) reassembleParsedFragmentStatus(fragment parsedFragment, now time.Time, loopback bool) (_ []byte, pending bool) {
	network := s.network.Load()
	if fragment.truncated || fragment.parameter || !s.acceptsInboundDestination(network, fragment.target, loopback) ||
		!validInboundFragmentSource(network, fragment.source, fragment.target, fragment.protocol) {
		return nil, false
	}
	key := fragment.reassemblyKey(loopback)
	s.fragmentMu.Lock()
	select {
	case <-s.closeCh:
		s.fragmentMu.Unlock()
		return nil, false
	default:
	}
	expired := s.cleanFragmentsLocked(now)
	defer func() {
		s.fragmentMu.Unlock()
		s.sendFragmentTimeouts(expired)
	}()
	entry := s.fragments[key]
	if entry == nil {
		for len(s.fragments) >= fragmentMaximumSets {
			s.evictOldestFragmentExceptLocked(nil)
		}
		entry = &ipPacketReassemblyEntry{created: now, updated: now}
		entry.state.start(fragment.ipPacketReassemblyFragment)
		s.fragments[key] = entry
		select {
		case s.fragmentWake <- struct{}{}:
		default:
		}
	}
	packet, pending, added, err := entry.state.addFragment(fragment.ipPacketReassemblyFragment, fragmentMaximumPieces)
	s.fragmentBytes += entry.state.bytes - entry.accountedBytes
	entry.accountedBytes = entry.state.bytes
	if err != nil {
		s.removeFragmentLocked(key, entry)
		return nil, false
	}
	if now.Before(entry.created) {
		entry.created = now
		select {
		case s.fragmentWake <- struct{}{}:
		default:
		}
	}
	if added && now.After(entry.updated) {
		entry.updated = now
	}
	for pending && s.fragmentBytes > fragmentMaximumBytes && len(s.fragments) > 1 {
		if !s.evictOldestFragmentExceptLocked(entry) {
			break
		}
	}
	if pending && s.fragmentBytes > fragmentMaximumBytes {
		s.removeFragmentLocked(key, entry)
		return nil, false
	}
	if pending {
		return nil, true
	}
	s.removeFragmentLocked(key, entry)
	return packet, false
}

func fragmentRangeState(pieces []fragmentPiece, start, end int) (covered, overlaps bool) {
	if start >= end {
		return false, false
	}
	first := sort.Search(len(pieces), func(index int) bool {
		return pieces[index].offset+len(pieces[index].data) > start
	})
	if first == len(pieces) || pieces[first].offset >= end {
		return false, false
	}
	cursor := start
	for _, piece := range pieces[first:] {
		if piece.offset >= end {
			break
		}
		if piece.offset > cursor {
			return false, true
		}
		cursor = piece.offset + len(piece.data)
		if cursor >= end {
			return true, true
		}
	}
	return false, true
}

func buildReassembledPacket(state *ipPacketReassemblyState, dontFragment bool) []byte {
	if !state.v6 {
		if len(state.header) < 20 || len(state.header)+state.total > 65535 {
			return nil
		}
		packet := make([]byte, len(state.header)+state.total)
		copy(packet, state.header)
		for _, piece := range state.pieces {
			copy(packet[len(state.header)+piece.offset:], piece.data)
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		field := uint16(0)
		if dontFragment {
			field = 0x4000
		}
		binary.BigEndian.PutUint16(packet[6:8], field)
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:len(state.header)]))
		return packet
	}
	if len(state.header) < 40 || state.nextHeader < 0 || state.nextHeader >= len(state.header) || len(state.header)-40+state.total > 65535 {
		return nil
	}
	packet := make([]byte, len(state.header)+state.total)
	copy(packet, state.header)
	packet[state.nextHeader] = state.protocol
	for _, piece := range state.pieces {
		copy(packet[len(state.header)+piece.offset:], piece.data)
	}
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	return packet
}

func parseFragment(packet []byte, skipChecksum bool) (parsedFragment, bool) {
	if len(packet) < 1 {
		return parsedFragment{}, false
	}
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return parsedFragment{}, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		field := binary.BigEndian.Uint16(packet[6:8])
		if headerSize < 20 || totalSize <= headerSize || totalSize > len(packet) || !skipChecksum && checksum(packet[:headerSize]) != 0 || field&0x3fff == 0 || field&0x8000 != 0 {
			return parsedFragment{}, false
		}
		source := netip.AddrFrom4([4]byte(packet[12:16]))
		target := netip.AddrFrom4([4]byte(packet[16:20]))
		identifier := uint32(binary.BigEndian.Uint16(packet[4:6]))
		protocol := packet[9]
		if optionAt, malformed := malformedIPv4Option(packet[20:headerSize]); malformed {
			return parsedFragment{
				ipPacketReassemblyFragment: ipPacketReassemblyFragment{
					source: source, target: target, protocol: protocol, offset: int(field&0x1fff) * 8,
					identifier: identifier, original: packet[:totalSize],
				},
				parameter: true, parameterAt: uint32(20 + optionAt),
			}, true
		}
		if !validateIPv4Options(packet[20:headerSize]) {
			return parsedFragment{}, false
		}
		return parsedFragment{
			ipPacketReassemblyFragment: ipPacketReassemblyFragment{
				source: source, target: target, protocol: protocol,
				offset: int(field&0x1fff) * 8, more: field&0x2000 != 0,
				payload: packet[headerSize:totalSize], identifier: identifier, ecn: packet[1] & 3,
				maximum: fragmentMaximumDatagram - headerSize, packetSize: totalSize, df: field&0x4000 != 0,
				header: packet[:headerSize], nextHeader: 9, original: packet[:totalSize],
			},
		}, true
	}
	if packet[0]>>4 != 6 || len(packet) < 48 {
		return parsedFragment{}, false
	}
	end := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if end > len(packet) {
		return parsedFragment{}, false
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	target := netip.AddrFrom16([16]byte(packet[24:40]))
	payload6 := packet[40:end]
	next, offset, previous := packet[6], 0, -1
	seenHop := false
	for {
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			headerType, headerOffset := next, offset
			if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
				return parsedFragment{
					ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
					parameter:                  true, parameterCode: 1, parameterAt: uint32(ipv6NextHeaderFieldOffset(previous)),
				}, true
			}
			length, valid := ipv6ExtensionHeaderUnit8Length(payload6[offset:])
			if !valid {
				return parsedFragment{}, false
			}
			header := payload6[offset : offset+length]
			next, previous, offset = header[0], offset, offset+length
			valid, action, optionOffset := inspectIPv6Options(header)
			if !valid {
				if action >= 2 && (action == 2 || !target.IsMulticast()) {
					return parsedFragment{
						ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
						parameter:                  true, parameterCode: 2, parameterAt: uint32(40 + headerOffset + optionOffset),
					}, true
				}
				return parsedFragment{}, false
			}
			if headerType == IPv6ExtensionHeaderHopByHop {
				seenHop = true
			}
		case IPv6ExtensionHeaderRouting:
			headerOffset := offset
			length, valid := ipv6ExtensionHeaderUnit8Length(payload6[offset:])
			if !valid {
				return parsedFragment{}, false
			}
			header := payload6[offset : offset+length]
			next, previous, offset = header[0], offset, offset+length
			if header[3] != 0 {
				return parsedFragment{
					ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
					parameter:                  true, parameterCode: 0, parameterAt: uint32(40 + headerOffset + 2),
				}, true
			}
		case IPv6ExtensionHeaderFragment:
			headerOffset, preceding := offset, previous
			if len(payload6)-offset < 8 {
				return parsedFragment{}, false
			}
			header := payload6[offset : offset+8]
			next, previous, offset = header[0], offset, offset+8
			field := binary.BigEndian.Uint16(header[2:4])
			if field&0xfff9 == 0 {
				return parsedFragment{}, false
			}
			protocol := next
			identifier := binary.BigEndian.Uint32(header[4:8])
			fragmentOffset := int(field & 0xfff8)
			more := field&1 != 0
			payload := payload6[offset:]
			maximum := fragmentMaximumDatagram
			if fragmentOffset == 0 {
				maximum -= headerOffset
			}
			parameter := more && len(payload)%8 != 0
			parameterAt := uint32(4)
			if fragmentOffset > maximum-len(payload) {
				parameter = true
				parameterAt = uint32(40 + headerOffset + 2)
			}
			return parsedFragment{
				ipPacketReassemblyFragment: ipPacketReassemblyFragment{
					source: source, target: target, protocol: protocol,
					offset: fragmentOffset, more: more, payload: payload,
					identifier: identifier, v6: true, ecn: packet[1] >> 4 & 3,
					header: packet[:40+headerOffset], nextHeader: ipv6NextHeaderFieldOffset(preceding),
					maximum: maximum, original: packet[:end],
				},
				truncated: fragmentOffset == 0 && more && !ipv6FirstFragmentHeaderComplete(protocol, payload),
				parameter: parameter, parameterAt: parameterAt,
			}, true
		default:
			return parsedFragment{}, false
		}
	}
}

func ipv6FirstFragmentHeaderComplete(next byte, payload []byte) bool {
	offset := 0
	for {
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
			IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderAuthentication,
			IPv6ExtensionHeaderMobility:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return false
			}
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderFragment:
			return false
		default:
			_, complete := ipv6FirstFragmentUpperLayerLength(next, payload[offset:])
			return complete
		}
	}
}

func ipv6FirstFragmentUpperLayerLength(protocol byte, payload []byte) (int, bool) {
	required := 0
	switch protocol {
	case ProtocolNoNextHeader:
		return 0, true
	case ProtocolTCP:
		if len(payload) < tcpHeaderSize {
			return 0, false
		}
		required = int(payload[12]>>4) * 4
		if required < tcpHeaderSize {
			required = tcpHeaderSize
		}
	case ProtocolIGMP, ProtocolUDP, ProtocolICMPv4, ProtocolICMPv6, ProtocolESP, 136:
		required = 8
	case 4:
		if len(payload) < 20 {
			return 0, false
		}
		required = int(payload[0]&0x0f) * 4
		if required < 20 {
			required = 20
		}
	case 33:
		if len(payload) < 12 {
			return 0, false
		}
		required = int(payload[4]) * 4
		minimum := 12
		if payload[8]&1 != 0 {
			minimum = 16
		}
		if required < minimum {
			required = minimum
		}
	case 41:
		required = 40
	case 132:
		required = 12
	default:
		return 0, true
	}
	return required, required <= len(payload)
}

func fragmentECN(mask byte) (byte, bool) {
	switch mask {
	case 1 << 0:
		return 0, true
	case 1 << 1:
		return 1, true
	case 1 << 2:
		return 2, true
	case 1 << 3, 1<<3 | 1<<1, 1<<3 | 1<<2, 1<<3 | 1<<1 | 1<<2:
		return 3, true
	default:
		return 0, false
	}
}

func (s *Stack) cleanFragmentsLocked(now time.Time) []*ipPacketReassemblyEntry {
	var expired []*ipPacketReassemblyEntry
	for key, entry := range s.fragments {
		if !now.Before(fragmentExpiry(entry)) {
			s.removeFragmentLocked(key, entry)
			s.stats.fragmentTimeouts.Add(1)
			if len(entry.state.firstPacket) != 0 {
				expired = append(expired, entry)
			}
		}
	}
	return expired
}

func fragmentExpiry(entry *ipPacketReassemblyEntry) time.Time {
	lifetime := fragmentIPv4Lifetime
	if entry.state.v6 {
		lifetime = fragmentIPv6Lifetime
	}
	return entry.created.Add(lifetime)
}

func (s *Stack) nextFragmentExpiryLocked() (time.Time, bool) {
	var next time.Time
	for _, entry := range s.fragments {
		expiry := fragmentExpiry(entry)
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}
	return next, !next.IsZero()
}

func (s *Stack) sendFragmentTimeouts(expired []*ipPacketReassemblyEntry) {
	for _, entry := range expired {
		_ = s.sendFragmentReassemblyTimeout(entry)
	}
}

func (s *Stack) evictOldestFragmentExceptLocked(except *ipPacketReassemblyEntry) bool {
	var oldestKey fragmentKey
	var oldest *ipPacketReassemblyEntry
	for key, entry := range s.fragments {
		if entry == except {
			continue
		}
		if oldest == nil || entry.updated.Before(oldest.updated) {
			oldestKey, oldest = key, entry
		}
	}
	if oldest != nil {
		s.removeFragmentLocked(oldestKey, oldest)
		s.stats.fragmentEvictions.Add(1)
		return true
	}
	return false
}

func (s *Stack) removeFragmentLocked(key fragmentKey, entry *ipPacketReassemblyEntry) {
	if s.fragments[key] != entry {
		return
	}
	delete(s.fragments, key)
	s.fragmentBytes -= entry.accountedBytes
	entry.accountedBytes = 0
}

func (s *Stack) discardFragment(key fragmentKey) {
	s.fragmentMu.Lock()
	if entry := s.fragments[key]; entry != nil {
		s.removeFragmentLocked(key, entry)
	}
	s.fragmentMu.Unlock()
}

func (s *Stack) pruneFragments(network *networkState) {
	s.fragmentMu.Lock()
	for key, entry := range s.fragments {
		if !s.acceptsInboundDestination(network, key.target, key.loopback) {
			s.removeFragmentLocked(key, entry)
		}
	}
	s.fragmentMu.Unlock()
}

func (s *Stack) ipFragmentLayoutForMTU(source, target netip.Addr, payloadSize int, fragmentation sourceFragmentation, options ipPacketOptions, mtu int, layout *ipFragmentLayout) error {
	if !fragmentation.allow {
		return syscall.EMSGSIZE
	}
	baseHeaderSize := ipHeaderSize(source, target, payloadSize)
	if baseHeaderSize == 0 || baseHeaderSize+payloadSize <= mtu {
		return syscall.EMSGSIZE
	}
	fragmentHeaderSize := baseHeaderSize
	if source.Is6() {
		fragmentHeaderSize += 8
	}
	ranges, valid := newFragmentRangeCursor(payloadSize, mtu-fragmentHeaderSize)
	if !valid {
		return syscall.EMSGSIZE
	}
	*layout = ipFragmentLayout{
		options:          options,
		payloadSize:      uint16(payloadSize),
		fragmentCapacity: uint16(ranges.capacity),
		headerSize:       uint8(fragmentHeaderSize),
	}
	if source.Is4() {
		layout.identification = uint32(uint16(s.ipv4ID.Add(1)))
	} else {
		layout.identification = s.ipv6FragmentID.Add(1)
	}
	return nil
}

func buildIPFragmentPackets(source, target netip.Addr, protocol byte, payload []byte, layout ipFragmentLayout) [][]byte {
	if len(payload) != int(layout.payloadSize) {
		return nil
	}
	ranges, valid := newFragmentRangeCursor(int(layout.payloadSize), int(layout.fragmentCapacity))
	if !valid {
		return nil
	}
	packets := make([][]byte, 0, (len(payload)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		packet := make([]byte, int(layout.headerSize)+size)
		if !marshalIPFragmentHeader(packet, source, target, protocol, layout.identification, offset, more, layout.options) {
			return nil
		}
		copy(packet[int(layout.headerSize):], payload[offset:offset+size])
		packets = append(packets, packet)
	}
	return packets
}

func (s *Stack) writeBestEffortIPPayloadForMTU(source, target netip.Addr, protocol byte, payload []byte, fragmentation sourceFragmentation, options ipPacketOptions, mtu int, checksumValidated bool) error {
	headerSize := ipHeaderSize(source, target, len(payload))
	if headerSize == 0 {
		return syscall.EMSGSIZE
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = s.automaticFlowLabel(source, target, protocol, payload)
		options.flowLabelSet = true
	}
	if headerSize+len(payload) > mtu {
		var layout ipFragmentLayout
		if err := s.ipFragmentLayoutForMTU(source, target, len(payload), fragmentation, options, mtu, &layout); err != nil {
			return err
		}
		err := s.tryWriteIPFragmentsLayout(source, target, protocol, payload, nil, layout, checksumValidated)
		if err == ErrResourceLimit {
			return nil
		}
		return err
	}
	var identification uint16
	if source.Is4() && fragmentation.requiresIPv4ID() {
		identification = uint16(s.ipv4ID.Add(1))
	}
	queue, loopback := s.outputQueueFor(target)
	slot, err := s.tryReservePacket(queue)
	if err == ErrResourceLimit {
		slot, err = s.replaceBestEffortPacket(queue)
	}
	if err != nil {
		if err == ErrResourceLimit {
			return nil
		}
		return err
	}
	packetSize := headerSize + len(payload)
	var packet []byte
	var reusable bool
	if packetSize <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(packetSize)
	} else {
		packet, reusable = s.acquireLargeOutputBuffer(packetSize)
	}
	if !marshalIPHeader(packet, source, target, protocol, identification, fragmentation.dontFragment, options) {
		s.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	copy(packet[headerSize:], payload)
	if !queue.enqueueReservedPacket(slot, packet, reusable, checksumValidated) {
		return ErrClosed
	}
	s.recordOutput(loopback)
	return nil
}

func (s *Stack) tryWriteIPSocketPayloadForMTU(source, target netip.Addr, protocol byte, payload []byte, fragmentation sourceFragmentation, options ipPacketOptions, mtu int) error {
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = s.automaticFlowLabel(source, target, protocol, payload)
		options.flowLabelSet = true
	}
	headerSize := ipHeaderSize(source, target, len(payload))
	if headerSize == 0 {
		return syscall.EMSGSIZE
	}
	if headerSize+len(payload) <= mtu {
		var identification uint16
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(s.ipv4ID.Add(1))
		}
		queue, loopback := s.outputQueueFor(target)
		slot, err := s.tryReservePacket(queue)
		if err == ErrResourceLimit {
			slot, err = s.replaceBestEffortPacket(queue)
		}
		if err != nil {
			return err
		}
		packetSize := headerSize + len(payload)
		var packet []byte
		var reusable bool
		if packetSize <= packetReusableBufferLimit {
			packet, reusable = queue.acquireBuffer(packetSize)
		} else {
			packet, reusable = s.acquireLargeOutputBuffer(packetSize)
		}
		if !marshalIPHeader(packet, source, target, protocol, identification, fragmentation.dontFragment, options) {
			s.releaseOutputBuffer(queue, packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		copy(packet[headerSize:], payload)
		if !queue.enqueueReservedPacket(slot, packet, reusable, false) {
			return ErrClosed
		}
		s.recordOutput(loopback)
		return nil
	}
	var layout ipFragmentLayout
	if err := s.ipFragmentLayoutForMTU(source, target, len(payload), fragmentation, options, mtu, &layout); err != nil {
		return err
	}
	return s.tryWriteIPFragmentsLayout(source, target, protocol, payload, nil, layout, false)
}

func (s *Stack) writeIPPayload(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool) error {
	if _, routed := s.network.Load().routeFor(target); !routed {
		return syscall.ENETUNREACH
	}
	fragmentation := sourceFragmentation{allow: allowFragment, dontFragment: !allowFragment}
	return s.writeBestEffortIPPayloadForMTU(source, target, protocol, payload, fragmentation, ipPacketOptions{}, s.mtuFor(target), true)
}

func (s *Stack) tryWriteIPFragmentsLayout(source, target netip.Addr, protocol byte, first, second []byte, layout ipFragmentLayout, checksumValidated bool) error {
	payloadSize := len(first) + len(second)
	if payloadSize != int(layout.payloadSize) {
		return syscall.EMSGSIZE
	}
	ranges, valid := newFragmentRangeCursor(int(layout.payloadSize), int(layout.fragmentCapacity))
	if !valid {
		return syscall.EMSGSIZE
	}
	queue, loopback := s.outputQueueFor(target)
	if loopback {
		payload := first
		if len(second) != 0 {
			payload = make([]byte, payloadSize)
			copy(payload, first)
			copy(payload[len(first):], second)
		}
		packets := buildIPFragmentPackets(source, target, protocol, payload, layout)
		if len(packets) == 0 {
			return syscall.EMSGSIZE
		}
		return s.tryWriteLoopbackPackets(packets, checksumValidated)
	}
	prefix := first
	if len(prefix) == 0 {
		prefix = second
	}
	flow := queue.ipFlowKey(source, target, protocol, layout.options.flowLabel, prefix)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		slot, err := s.tryReservePacket(queue)
		if err == ErrResourceLimit {
			slot, err = s.replaceBestEffortPacket(queue)
		}
		if err != nil {
			return err
		}
		packetSize := int(layout.headerSize) + size
		var packet []byte
		var reusable bool
		if packetSize <= packetReusableBufferLimit {
			packet, reusable = queue.acquireBuffer(packetSize)
		} else {
			packet, reusable = s.acquireLargeOutputBuffer(packetSize)
		}
		if !marshalIPFragmentHeader(packet, source, target, protocol, layout.identification, offset, more, layout.options) {
			s.releaseOutputBuffer(queue, packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		copyIPPayloadParts(packet[int(layout.headerSize):], offset, first, second)
		if !queue.enqueueReservedPacketForFlow(slot, packet, reusable, flow, checksumValidated) {
			return ErrClosed
		}
		s.recordOutput(loopback)
	}
	return nil
}

func copyIPPayloadParts(destination []byte, offset int, first, second []byte) {
	if offset < len(first) {
		n := copy(destination, first[offset:])
		destination = destination[n:]
		offset = 0
	} else {
		offset -= len(first)
	}
	if len(destination) != 0 {
		copy(destination, second[offset:])
	}
}

func marshalPublicIPv4Fragments(packet IPPacket, mtu int) ([][]byte, error) {
	headerSize := 20 + (len(packet.IPv4Options)+3)&^3
	ranges, valid := newFragmentRangeCursor(len(packet.Payload), mtu-headerSize)
	if !valid {
		return nil, syscall.EMSGSIZE
	}
	laterOptions := laterIPv4FragmentOptions(packet.IPv4Options)
	fragments := make([][]byte, 0, (len(packet.Payload)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, moreRange, ok := ranges.next(); ok; offset, size, moreRange, ok = ranges.next() {
		more := packet.MoreFragments || moreRange
		options := laterOptions
		if packet.FragmentOffset+offset == 0 {
			options = packet.IPv4Options
		}
		fragment := packet
		fragment.DontFragment = false
		fragment.MoreFragments = more
		fragment.FragmentOffset = packet.FragmentOffset + offset
		fragment.IPv4Options = options
		fragment.Payload = packet.Payload[offset : offset+size]
		fragmentHeaderSize := 20 + (len(options)+3)&^3
		wire := make([]byte, fragmentHeaderSize+size)
		marshalPublicIPPacket(wire, fragment, fragmentHeaderSize, true)
		fragments = append(fragments, wire)
	}
	return fragments, nil
}

func marshalPublicIPv6Fragments(packet IPPacket, totalSize, mtu int, identification uint32) ([][]byte, error) {
	if !isTraversableIPv6ExtensionHeader(byte(packet.Protocol)) {
		return marshalPublicIPv6PayloadFragments(packet, mtu, identification)
	}
	wire := make([]byte, totalSize)
	marshalPublicIPPacket(wire, packet, 40, true)
	point, valid := inspectIPv6FragmentPoint(wire, false)
	if !valid {
		return nil, syscall.EINVAL
	}
	if point.atomicOffset >= 0 {
		wire[point.atomicPrevious] = wire[point.atomicOffset]
		copy(wire[point.atomicOffset:], wire[point.atomicOffset+8:])
		wire = wire[:len(wire)-8]
		binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)-40))
		point, valid = inspectIPv6FragmentPoint(wire, false)
		if !valid || point.atomicOffset >= 0 {
			return nil, syscall.EINVAL
		}
	}
	capacity := mtu - point.insertion - 8
	fragmentable := wire[point.insertion:]
	ranges, valid := newFragmentRangeCursor(len(fragmentable), capacity)
	if !valid {
		return nil, syscall.EMSGSIZE
	}
	firstHeaderEnd, valid := ipv6FirstFragmentHeaderEnd(wire, point)
	if !valid || firstHeaderEnd-point.insertion > ranges.alignedCapacity {
		return nil, syscall.EMSGSIZE
	}
	fragments := make([][]byte, 0, (len(fragmentable)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		fragment := make([]byte, point.insertion+8+size)
		copy(fragment, wire[:point.insertion])
		fragment[point.previous] = IPv6ExtensionHeaderFragment
		header := fragment[point.insertion : point.insertion+8]
		header[0] = point.next
		field := uint16(offset)
		if more {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[point.insertion+8:], fragmentable[offset:offset+size])
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func marshalPublicIPv6PayloadFragments(packet IPPacket, mtu int, identification uint32) ([][]byte, error) {
	capacity := mtu - 48
	ranges, valid := newFragmentRangeCursor(len(packet.Payload), capacity)
	if !valid {
		return nil, syscall.EMSGSIZE
	}
	required, complete := ipv6FirstFragmentUpperLayerLength(byte(packet.Protocol), packet.Payload)
	if !complete || required > ranges.alignedCapacity {
		return nil, syscall.EMSGSIZE
	}
	fragments := make([][]byte, 0, (len(packet.Payload)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		fragment := make([]byte, 48+size)
		marshalPublicIPv6BaseHeader(fragment, packet, IPv6ExtensionHeaderFragment, 8+size)
		header := fragment[40:48]
		header[0] = byte(packet.Protocol)
		field := uint16(offset)
		if more {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[48:], packet.Payload[offset:offset+size])
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func ipv6FirstFragmentHeaderEnd(packet []byte, point ipv6FragmentPoint) (int, bool) {
	payload := packet[point.insertion:]
	next, offset := point.next, 0
	for isTraversableIPv6ExtensionHeader(next) {
		if next == IPv6ExtensionHeaderFragment {
			return 0, false
		}
		length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
		if !valid {
			return 0, false
		}
		next, offset = payload[offset], offset+length
	}
	required, complete := ipv6FirstFragmentUpperLayerLength(next, payload[offset:])
	return point.insertion + offset + required, complete
}

func marshalIPFragmentHeader(packet []byte, source, target netip.Addr, protocol byte, identification uint32, offset int, more bool, options ipPacketOptions) bool {
	if source.Is4() {
		if !marshalIPHeader(packet, source, target, protocol, uint16(identification), false, options) {
			return false
		}
		field := uint16(offset / 8)
		if more {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(packet[6:8], field)
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		return true
	}
	if !marshalIPHeader(packet, source, target, IPv6ExtensionHeaderFragment, 0, false, options) {
		return false
	}
	fragment := packet[40:48]
	fragment[0], fragment[1] = protocol, 0
	field := uint16(offset)
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(fragment[2:4], field)
	binary.BigEndian.PutUint32(fragment[4:8], identification)
	return true
}

func (s *Stack) icmpForwarderIPPackets(reply icmpForwarderIPPacket, mtu int) ([][]byte, error) {
	if reply.parsed.source.Is4() && binary.BigEndian.Uint16(reply.packet[4:6]) == 0 {
		binary.BigEndian.PutUint16(reply.packet[4:6], uint16(s.ipv4ID.Add(1)))
		headerSize := int(reply.packet[0]&0x0f) * 4
		reply.packet[10], reply.packet[11] = 0, 0
		binary.BigEndian.PutUint16(reply.packet[10:12], checksum(reply.packet[:headerSize]))
	}
	if len(reply.packet) <= mtu {
		return [][]byte{reply.packet}, nil
	}
	if reply.parsed.source.Is4() {
		if reply.ipv4DF {
			return nil, syscall.EMSGSIZE
		}
		identification := binary.BigEndian.Uint16(reply.packet[4:6])
		packets := fragmentICMPForwarderIPv4(reply.packet, mtu, identification)
		if len(packets) == 0 {
			return nil, syscall.EMSGSIZE
		}
		return packets, nil
	}
	identification := s.ipv6FragmentID.Add(1)
	packet := reply.packet
	point := reply.ipv6Fragment
	transportOffset := len(packet) - len(reply.parsed.payload)
	if point.atomicOffset >= 0 {
		identification = binary.BigEndian.Uint32(packet[point.atomicOffset+4 : point.atomicOffset+8])
		packet[point.atomicPrevious] = packet[point.atomicOffset]
		copy(packet[point.atomicOffset:], packet[point.atomicOffset+8:])
		packet = packet[:len(packet)-8]
		transportOffset -= 8
		var ok bool
		point, ok = inspectIPv6ForwarderFragmentPoint(packet)
		if !ok || point.atomicOffset >= 0 {
			return nil, syscall.EINVAL
		}
	}
	packets := fragmentICMPForwarderIPv6(packet, point, transportOffset, mtu, identification)
	if len(packets) == 0 {
		return nil, syscall.EMSGSIZE
	}
	return packets, nil
}

func laterIPv4FragmentOptions(options []byte) []byte {
	if len(options) == 0 {
		return nil
	}
	result := append([]byte(nil), options...)
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == IPv4HeaderOptionEnd {
			for index := offset + 1; index < len(result); index++ {
				result[index] = 0
			}
			break
		}
		if kind == IPv4HeaderOptionNOP {
			offset++
			continue
		}
		length := ipv4HeaderOptionLength(options[offset:])
		if length == 0 {
			break
		}
		if kind&0x80 == 0 {
			for index := offset; index < offset+length; index++ {
				result[index] = 1
			}
		}
		offset += length
	}
	return result
}

func fragmentICMPForwarderIPv4(packet []byte, mtu int, identification uint16) [][]byte {
	originalHeaderSize := int(packet[0]&0x0f) * 4
	payload := packet[originalHeaderSize:]
	copiedOptions := laterIPv4FragmentOptions(packet[20:originalHeaderSize])
	ranges, valid := newFragmentRangeCursor(len(payload), mtu-originalHeaderSize)
	if !valid {
		return nil
	}
	fragments := make([][]byte, 0, (len(payload)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		options := copiedOptions
		if offset == 0 {
			options = packet[20:originalHeaderSize]
		}
		headerSize := 20 + len(options)
		fragment := make([]byte, headerSize+size)
		copy(fragment[:20], packet[:20])
		copy(fragment[20:headerSize], options)
		if contentSize, valid := ipv4OptionsContentLength(fragment[20:headerSize]); valid {
			for index := 20 + contentSize; index < headerSize; index++ {
				fragment[index] = 0
			}
		}
		fragment[0] = 0x40 | byte(headerSize/4)
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[4:6], identification)
		field := uint16(offset / 8)
		if more {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], field)
		fragment[10], fragment[11] = 0, 0
		binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:headerSize]))
		copy(fragment[headerSize:], payload[offset:offset+size])
		fragments = append(fragments, fragment)
	}
	return fragments
}

func fragmentICMPForwarderIPv6(packet []byte, point ipv6FragmentPoint, transportOffset, mtu int, identification uint32) [][]byte {
	prefix := packet[:point.insertion]
	fragmentable := packet[point.insertion:]
	ranges, valid := newFragmentRangeCursor(len(fragmentable), mtu-len(prefix)-8)
	if !valid {
		return nil
	}
	icmpEnd := transportOffset + 8
	if icmpEnd-point.insertion > ranges.alignedCapacity {
		return nil
	}
	fragments := make([][]byte, 0, (len(fragmentable)+ranges.alignedCapacity-1)/ranges.alignedCapacity)
	for offset, size, more, ok := ranges.next(); ok; offset, size, more, ok = ranges.next() {
		fragment := make([]byte, len(prefix)+8+size)
		copy(fragment, prefix)
		fragment[point.previous] = IPv6ExtensionHeaderFragment
		header := fragment[len(prefix) : len(prefix)+8]
		header[0], header[1] = point.next, 0
		field := uint16(offset)
		if more {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[len(prefix)+8:], fragmentable[offset:offset+size])
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
		fragments = append(fragments, fragment)
	}
	return fragments
}

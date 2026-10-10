package mipstack

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	udpHeaderSize = 8
	udpDefaultReceiveCapacity = 4 * 1024 * 1024
	udpDatagramMetadataSize = 96
)

type UDPDatagram struct {
	Source netip.AddrPort
	Destination netip.AddrPort
	ChecksumDisabled bool
	Payload []byte
}

func udpWireLength(udp []byte) (int, bool) {
	if len(udp) < udpHeaderSize {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < udpHeaderSize || length > len(udp) {
		return 0, false
	}
	return length, true
}

func (p IPPacket) UDPDatagram() (UDPDatagram, error) {
	udp, pseudoHeaderSafe, err := p.upperLayerForProtocol(ProtocolUDP)
	if err != nil {
		return UDPDatagram{}, err
	}
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	length, valid := udpWireLength(udp)
	if !valid {
		return UDPDatagram{}, syscall.EINVAL
	}
	checksumValue := binary.BigEndian.Uint16(udp[6:8])
	if source.Is6() && checksumValue == 0 {
		return UDPDatagram{}, syscall.EINVAL
	}
	if checksumValue != 0 {
		if !pseudoHeaderSafe {
			return UDPDatagram{}, syscall.EPROTONOSUPPORT
		}
		if transportChecksum(source, destination, ProtocolUDP, udp[:length]) != 0 {
			return UDPDatagram{}, syscall.EINVAL
		}
	}
	return UDPDatagram{
		Source:           netip.AddrPortFrom(source, binary.BigEndian.Uint16(udp[0:2])),
		Destination:      netip.AddrPortFrom(destination, binary.BigEndian.Uint16(udp[2:4])),
		ChecksumDisabled: checksumValue == 0,
		Payload:          udp[udpHeaderSize:length],
	}, nil
}

func (d UDPDatagram) MarshalBinary() ([]byte, error) { return d.AppendBinary(nil) }

func (d UDPDatagram) AppendBinary(dst []byte) ([]byte, error) {
	normalized, totalSize, err := d.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicUDPDatagram(dst[start:], normalized)
	return dst, nil
}

func (d UDPDatagram) wireLayout() (UDPDatagram, int, error) {
	if d.Source.Addr().Zone() != "" || d.Destination.Addr().Zone() != "" {
		return UDPDatagram{}, 0, syscall.EINVAL
	}
	source, destination := d.Source.Addr().Unmap(), d.Destination.Addr().Unmap()
	if !d.Source.IsValid() || !d.Destination.IsValid() || source.Is4() != destination.Is4() || source.Is6() && d.ChecksumDisabled {
		return UDPDatagram{}, 0, syscall.EINVAL
	}
	d.Source, d.Destination = netip.AddrPortFrom(source, d.Source.Port()), netip.AddrPortFrom(destination, d.Destination.Port())
	if len(d.Payload) > 65535-udpHeaderSize {
		return UDPDatagram{}, 0, syscall.EMSGSIZE
	}
	return d, udpHeaderSize + len(d.Payload), nil
}

func marshalPublicUDPDatagram(dst []byte, d UDPDatagram) {
	copy(dst[udpHeaderSize:], d.Payload)
	marshalUDPHeaderFields(dst[:udpHeaderSize], d.Source.Port(), d.Destination.Port(), len(dst))
	if d.ChecksumDisabled {
		return
	}
	writeUDPChecksumValue(dst[:udpHeaderSize], transportChecksumParts(
		d.Source.Addr(), d.Destination.Addr(), ProtocolUDP, len(dst), dst[:udpHeaderSize], dst[udpHeaderSize:],
	))
}

type udpDatagram struct {
	payload []byte
	source  netip.AddrPort
	target  netip.Addr
	options ipPacketOptions
}

type UDPConnInfo struct {
	LocalAddress netip.AddrPort
	RemoteAddress netip.AddrPort
	Closed bool
	ReceiveQueuePackets int
	ReceiveQueueBytes int
	ReceiveQueueCapacity int
	ReceiveErrors bool
	ErrorQueueEntries int
	ErrorQueueBytes int
	ErrorsDropped uint64
	PacketsSent uint64
	BytesSent uint64
	PacketsReceived uint64
	BytesReceived uint64
	PacketsDropped uint64
	ICMPErrors uint64
	PathMTU int
	PathMTUDiscovery PathMTUDiscovery
	HopLimit int
	MulticastHopLimit int
	MulticastLoopback bool
	Broadcast bool
	TrafficClass uint8
	FlowLabel uint32
	LastError error
}

type udpReuseEndpoints interface {
	empty() bool
	connections() []*UDPConn
	contains(connection *UDPConn) bool
	overlaps(address netip.Addr, port uint16, dual bool) bool
	connection(binding, local, remote netip.AddrPort) *UDPConn
	add(connection *UDPConn)
	remove(connection *UDPConn) bool
}

type udpSocketBinding interface {
	available(stack *Stack, address netip.Addr, port uint16, dual bool) bool
	register(stack *Stack, connection *UDPConn) error
}

type udpNetwork byte

const (
	udpNetworkGeneric udpNetwork = iota
	udpNetworkIPv4
	udpNetworkIPv6
)

func newUDPNetwork(network string) udpNetwork {
	switch network {
	case "udp4":
		return udpNetworkIPv4
	case "udp6":
		return udpNetworkIPv6
	default:
		return udpNetworkGeneric
	}
}

func (n udpNetwork) name() string {
	switch n {
	case udpNetworkIPv4:
		return "udp4"
	case udpNetworkIPv6:
		return "udp6"
	default:
		return "udp"
	}
}

type exclusiveUDPSocketBinding struct{}

type reuseAddressUDPSocketBinding struct{}

type UDPConn struct {
	stack *Stack
	net   udpNetwork
	port  uint16
	v6    bool
	dual  bool
	forwarded    bool
	reuseAddress bool
	reusePort    bool
	local        netip.Addr
	remote       netip.AddrPort

	datagramSocketWriteControl

	mu                sync.Mutex
	receive           datagramQueue[udpDatagram]
	receiveSpare      []byte
	receiveNotify     chan struct{}
	receiveCapacity   int
	queuedBytes       int
	errorState        *datagramSocketErrorState
	receiveErrors     bool
	readDeadline      datagramSocketDeadline
	recentTargets     recentDestinationCache[netip.AddrPort]
	defaultOptions    ipPacketOptions
	pathMTUDiscovery  PathMTUDiscovery
	multicastHopLimit byte
	multicastLoopback bool
	broadcast         bool
	automaticLabel    uint32
	packetsSent       atomic.Uint64
	bytesSent         atomic.Uint64
	packetsReceived   atomic.Uint64
	bytesReceived     atomic.Uint64
	packetsDropped    atomic.Uint64
}

type udpWriteParameters struct {
	source           netip.Addr
	target           netip.AddrPort
	options          ipPacketOptions
	pathMTUDiscovery PathMTUDiscovery
	receiveErrors    bool
	nonUnicast       bool
}

type udpDatagramWriter func(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast bool) error

func newUDPConn(stack *Stack, network string, port uint16, v6 bool, local netip.Addr, remote netip.AddrPort, options datagramSocketOptionSet) *UDPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: udpDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1}
	if stack != nil {
		defaults = stack.network.Load().udpDefaults.DatagramSocketDefaults
	}
	defaults = applyDatagramSocketOptions(defaults, options, udpDatagramMetadataSize)
	connection := &UDPConn{
		stack: stack, net: newUDPNetwork(network), port: port, v6: v6, local: local, remote: remote,
		datagramSocketWriteControl: datagramSocketWriteControl{closed: make(chan struct{})},
		receiveCapacity:            defaults.ReceiveBuffer,
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, hopLimitSet: options.hopLimit.set,
			trafficClassSet: options.trafficClass.set, flowLabelSet: defaults.FlowLabel != 0 || options.flowLabel.set,
		},
		receiveErrors:     defaults.ReceiveErrors,
		pathMTUDiscovery:  defaults.PathMTUDiscovery,
		multicastHopLimit: byte(defaults.MulticastHopLimit), multicastLoopback: !defaults.DisableMulticastLoopback,
		broadcast: !defaults.DisableBroadcast,
	}
	if remote.IsValid() && stack != nil && local.Is6() && remote.Addr().Is6() && defaults.FlowLabel == 0 && !options.flowLabel.set {
		connection.automaticLabel = stack.automaticTransportFlowLabel(local, remote.Addr(), ProtocolUDP, port, remote.Port())
	}
	return connection
}

func (exclusiveUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	return stack.udpReuse == nil || !stack.udpReuse.overlaps(address, port, dual)
}

func (exclusiveUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
	stack.udp[udpKey{address: connection.local, port: connection.port}] = connection
	return nil
}

func (reuseAddressUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	return reusableUDPBindingAvailable(stack, address, port, dual, true, false)
}

func (reuseAddressUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
	connection.reuseAddress = true
	return registerReusableUDP(stack, connection)
}

func (s *Stack) handleUDP(packet ipPacket, destination inboundDestinationClass, skipChecksum bool) error {
	udp := packet.payload
	length, valid := udpWireLength(udp)
	if !valid {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	checksumValue := binary.BigEndian.Uint16(udp[6:8])
	if packet.source.Is6() && checksumValue == 0 || !skipChecksum && checksumValue != 0 && transportChecksum(packet.source, packet.target, ProtocolUDP, udp[:length]) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(udp[0:2])
	targetPort := binary.BigEndian.Uint16(udp[2:4])
	source := netip.AddrPortFrom(packet.source, sourcePort)
	target := netip.AddrPortFrom(packet.target, targetPort)
	packet.payload = udp[:length]
	if destination == inboundDestinationMulticast {
		s.mu.RLock()
		multicast := s.multicast
		s.mu.RUnlock()
		if multicast != nil {
			multicast.deliverUDP(packet, sourcePort, targetPort)
		}
		return nil
	}
	if destination == inboundDestinationBroadcast {
		s.deliverBroadcastUDP(packet, source, targetPort)
		return nil
	}
	localDestination := destination == inboundDestinationLocalUnicast
	s.mu.RLock()
	connection := s.udpForwardedConnectionLocked(target, source)
	if connection == nil && localDestination {
		connection = s.udpOrdinaryConnectionLocked(target, source)
	}
	forwarder := s.udpForwarder
	s.mu.RUnlock()
	if connection == nil {
		options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
		if forwarder != nil && forwarder.handlePacket(packet, ForwarderFlow{Source: source, Destination: target}, options) {
			return nil
		}
		if !localDestination {
			return nil
		}
		_ = s.sendPortUnreachable(packet)
		return nil
	}
	if (!connection.local.IsUnspecified() && packet.target != connection.local) || (connection.remote.IsValid() && source != connection.remote) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	connection.enqueue(udp[udpHeaderSize:length], source, packet.target, ipPacketOptions{
		hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel,
	})
	return nil
}

func (s *Stack) deliverBroadcastUDP(packet ipPacket, source netip.AddrPort, targetPort uint16) {
	s.mu.RLock()
	var matchedStorage [8]*UDPConn
	matched := matchedStorage[:0]
	consider := func(connection *UDPConn) {
		if connection.forwarded || connection.port != targetPort || !connection.local.IsUnspecified() ||
			connection.local.Is6() && !connection.dual ||
			connection.remote.IsValid() && connection.remote != source {
			return
		}
		matched = append(matched, connection)
	}
	for _, connection := range s.udp {
		consider(connection)
	}
	if s.udpReuse != nil {
		for _, connection := range s.udpReuse.connections() {
			consider(connection)
		}
	}
	s.mu.RUnlock()
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	for _, connection := range matched {
		connection.enqueue(packet.payload[udpHeaderSize:], source, packet.target, options)
	}
}

func (s *Stack) udpConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udpForwardedConnectionLocked(local, remote); connection != nil {
		return connection
	}
	return s.udpOrdinaryConnectionLocked(local, remote)
}

func (s *Stack) udpForwardedConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udpForwarded[udpFlowKey{local: local, remote: remote}]; connection != nil {
		return connection
	}
	return s.udpForwarded[udpFlowKey{local: local}]
}

func (s *Stack) udpOrdinaryConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udp[udpKey{address: local.Addr(), port: local.Port()}]; connection != nil {
		return connection
	}
	if s.udpReuse != nil {
		if connection := s.udpReuse.connection(local, local, remote); connection != nil {
			return connection
		}
	}
	wildcard := netip.IPv4Unspecified()
	if local.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	wildcardLocal := netip.AddrPortFrom(wildcard, local.Port())
	if connection := s.udp[udpKey{address: wildcard, port: local.Port()}]; connection != nil {
		return connection
	}
	if s.udpReuse != nil {
		if connection := s.udpReuse.connection(wildcardLocal, local, remote); connection != nil {
			return connection
		}
	}
	if local.Addr().Is4() {
		dualLocal := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		if connection := s.udp[udpKey{address: dualLocal.Addr(), port: local.Port()}]; connection != nil && connection.dual {
			return connection
		}
		if s.udpReuse != nil {
			if connection := s.udpReuse.connection(dualLocal, local, remote); connection != nil && connection.dual {
				return connection
			}
		}
	}
	return nil
}

func (f *UDPForwarder) acceptUDP(request *UDPForwarderRequest, options datagramSocketOptionSet) (*UDPConn, error) {
	stack := f.stack
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != f {
		return nil, net.ErrClosed
	}
	state := stack.network.Load()
	local, remote := request.flow.Destination, request.flow.Source
	if !state.acceptsInboundDestination(local.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(remote.Addr()); !routed {
		return nil, syscall.ENETUNREACH
	}
	key := udpFlowKey{local: local, remote: remote}
	if stack.udpForwardedConnectionLocked(local, remote) != nil || networkStateHasLocal(state, local.Addr()) && stack.udpOrdinaryConnectionLocked(local, remote) != nil {
		return nil, syscall.EADDRINUSE
	}
	network := "udp4"
	if local.Addr().Is6() {
		network = "udp6"
	}
	connection := newUDPConn(stack, network, local.Port(), local.Addr().Is6(), local.Addr(), remote, options)
	connection.forwarded = true
	connection.enqueue(request.Payload(), remote, local.Addr(), request.options)
	if stack.udpForwarded == nil {
		stack.udpForwarded = make(map[udpFlowKey]*UDPConn)
	}
	stack.udpForwarded[key] = connection
	stack.stats.activeUDPSockets.Add(1)
	return connection, nil
}

func (f *UDPForwarder) listenUDP(request *UDPForwarderRequest, options datagramSocketOptionSet) (*UDPConn, error) {
	stack := f.stack
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != f {
		return nil, net.ErrClosed
	}
	state := stack.network.Load()
	local, remote := request.flow.Destination, request.flow.Source
	if !state.acceptsInboundDestination(local.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	key := udpFlowKey{local: local}
	for existing := range stack.udpForwarded {
		if existing.local == local {
			return nil, syscall.EADDRINUSE
		}
	}
	if networkStateHasLocal(state, local.Addr()) &&
		!stack.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, local.Addr(), local.Port(), false) {
		return nil, syscall.EADDRINUSE
	}
	network := "udp4"
	if local.Addr().Is6() {
		network = "udp6"
	}
	connection := newUDPConn(stack, network, local.Port(), local.Addr().Is6(), local.Addr(), netip.AddrPort{}, options)
	connection.forwarded = true
	connection.enqueue(request.Payload(), remote, local.Addr(), request.options)
	if stack.udpForwarded == nil {
		stack.udpForwarded = make(map[udpFlowKey]*UDPConn)
	}
	stack.udpForwarded[key] = connection
	stack.stats.activeUDPSockets.Add(1)
	return connection, nil
}

func validateUDPForwarderReply(flow ForwarderFlow, payload []byte, source netip.AddrPort) (netip.AddrPort, error) {
	address := source.Addr()
	if !source.IsValid() {
		return netip.AddrPort{}, syscall.EINVAL
	}
	address = address.WithZone("").Unmap()
	if address.Is6() != flow.Source.Addr().Unmap().Is6() {
		return netip.AddrPort{}, syscall.EINVAL
	}
	if err := validateUDPForwarderReplyPayload(address.Is6(), payload); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, source.Port()), nil
}

func validateUDPForwarderReplyPayload(ipv6 bool, payload []byte) error {
	maximumPayload := 65535 - udpHeaderSize
	if !ipv6 {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return syscall.EMSGSIZE
	}
	return nil
}

func (f *forwarderRuntime) replyUDPFlow(flow ForwarderFlow, payload []byte, source netip.AddrPort) (int, error) {
	local, remote := flow.Destination, flow.Source
	state := f.stack.network.Load()
	if !state.acceptsInboundDestination(local.Addr()) {
		return 0, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(remote.Addr()); !routed {
		return 0, syscall.ENETUNREACH
	}
	defaults := state.udpDefaults.DatagramSocketDefaults
	options := ipPacketOptions{
		hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
		flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
	}
	if err := f.stack.writeBestEffortUDPDatagram(source.Addr(), remote.Addr(), source.Port(), remote.Port(), payload, options, defaults.PathMTUDiscovery); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *UDPConn) acceptsLocal(address netip.Addr) bool {
	return c.local.IsUnspecified() || c.local == address.Unmap()
}

func (c *UDPConn) enqueue(payload []byte, source netip.AddrPort, target netip.Addr, options ipPacketOptions) {
	size := udpDatagramSize(payload)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	default:
	}
	if size > c.receiveCapacity || c.queuedBytes+c.errorState.bytes() > c.receiveCapacity-size {
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	}
	var retained []byte
	if len(payload) != 0 {
		if cap(c.receiveSpare) >= len(payload) {
			retained = c.receiveSpare[:len(payload)]
			c.receiveSpare = nil
			copy(retained, payload)
		} else {
			retained = append([]byte(nil), payload...)
		}
	}
	datagram := udpDatagram{payload: retained, source: source, target: target, options: options}
	c.receive.push(datagram)
	c.queuedBytes += size
	c.packetsReceived.Add(1)
	c.bytesReceived.Add(uint64(len(payload)))
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

func (c *UDPConn) notifyReceiveLocked() {
	if c.receiveNotify == nil {
		return
	}
	if c.receive.len() != 0 || c.errorState != nil && c.errorState.pending != nil {
		select {
		case c.receiveNotify <- struct{}{}:
		default:
		}
		return
	}
	select {
	case <-c.receiveNotify:
	default:
	}
}

func (c *UDPConn) receiveNotificationLocked() <-chan struct{} {
	if c.receiveNotify == nil {
		c.receiveNotify = make(chan struct{}, 1)
	}
	return c.receiveNotify
}

func udpDatagramSize(payload []byte) int {
	return udpDatagramMetadataSize + len(payload)
}

func (c *UDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, source, _, _, _, err := c.readDatagram(buffer, nil)
	var address net.Addr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

func (c *UDPConn) ReadFromUDP(buffer []byte) (int, *net.UDPAddr, error) {
	n, source, _, _, _, err := c.readDatagram(buffer, nil)
	var address *net.UDPAddr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

func (c *UDPConn) ReadFromUDPAddrPort(buffer []byte) (int, netip.AddrPort, error) {
	n, source, _, _, _, err := c.readDatagram(buffer, nil)
	if err != nil {
		return n, source, c.operationError("read", c.remoteAddr(), err)
	}
	return n, source, nil
}

func (c *UDPConn) ReadFromWithBuffer(getBuffer func(sizeHint int) []byte) (int, net.Addr, error) {
	if getBuffer == nil {
		return 0, nil, c.operationError("read", c.remoteAddr(), syscall.EINVAL)
	}
	n, source, _, _, _, err := c.readDatagram(nil, getBuffer)
	var address net.Addr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

func (c *UDPConn) ReadFromUDPWithBuffer(getBuffer func(sizeHint int) []byte) (int, *net.UDPAddr, error) {
	if getBuffer == nil {
		return 0, nil, c.operationError("read", c.remoteAddr(), syscall.EINVAL)
	}
	n, source, _, _, _, err := c.readDatagram(nil, getBuffer)
	var address *net.UDPAddr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

func (c *UDPConn) ReadFromUDPAddrPortWithBuffer(getBuffer func(sizeHint int) []byte) (int, netip.AddrPort, error) {
	if getBuffer == nil {
		return 0, netip.AddrPort{}, c.operationError("read", c.remoteAddr(), syscall.EINVAL)
	}
	n, source, _, _, _, err := c.readDatagram(nil, getBuffer)
	if err != nil {
		return n, source, c.operationError("read", c.remoteAddr(), err)
	}
	return n, source, nil
}

func (c *UDPConn) ReadMsgUDP(buffer, oob []byte) (n, oobn, flags int, address *net.UDPAddr, err error) {
	var source netip.AddrPort
	n, oobn, flags, source, err = c.readMsgUDPAddrPort(buffer, oob)
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	return
}

func (c *UDPConn) ReadMsgUDPAddrPort(buffer, oob []byte) (n, oobn, flags int, source netip.AddrPort, err error) {
	return c.readMsgUDPAddrPort(buffer, oob)
}

func (c *UDPConn) readMsgUDPAddrPort(buffer, oob []byte) (n, oobn, flags int, source netip.AddrPort, err error) {
	var target netip.Addr
	var options ipPacketOptions
	var truncated bool
	n, source, target, options, truncated, err = c.readDatagram(buffer, nil)
	if truncated {
		flags |= MessageFlagTruncated
	}
	if err != nil {
		err = c.operationError("read", c.remoteAddr(), err)
		return
	}
	var specDst netip.Addr
	if target.Is4() {
		specDst = c.stack.network.Load().inboundIPv4PacketInfoSource(source.Addr(), target)
	}
	control, controlErr := controlMessageForRead(specDst, target, options)
	if controlErr != nil {
		err = c.operationError("read", c.remoteAddr(), controlErr)
		return
	}
	oobn = copy(oob, control)
	if oobn < len(control) {
		flags |= MessageFlagControlTruncated
	}
	return
}

func (c *UDPConn) ReadBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^(MessageFlagPeek|MessageFlagDontWait|MessageFlagTruncated|MessageFlagErrorQueue) != 0 {
		return 0, c.operationError("read", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	if flags&MessageFlagErrorQueue != 0 {
		return c.readErrorBatch(messages, flags)
	}
	var network *networkState
	for index := range messages {
		wait := index == 0 && flags&MessageFlagDontWait == 0
		err := c.readBatchMessage(&messages[index], flags, wait, index == 0, &network)
		if err != nil {
			if index != 0 {
				return index, nil
			}
			return index, err
		}
	}
	return len(messages), nil
}

func (c *UDPConn) readBatchMessage(message *SocketMessage, flags int, wait, consumeErrors bool, network **networkState) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	n, source, target, options, truncated, err := c.readDatagramBuffers(message.Buffers, wait, consumeErrors, flags&MessageFlagPeek != 0, flags&MessageFlagTruncated != 0)
	if err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	var specDst netip.Addr
	if target.Is4() {
		if *network == nil {
			*network = c.stack.network.Load()
		}
		specDst = (*network).inboundIPv4PacketInfoSource(source.Addr(), target)
	}
	control, err := controlMessageForRead(specDst, target, options)
	if err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	resultFlags := 0
	if truncated {
		resultFlags |= MessageFlagTruncated
	}
	oobn := copy(message.OOB, control)
	if oobn < len(control) {
		resultFlags |= MessageFlagControlTruncated
	}
	message.N, message.NN, message.Flags = n, oobn, resultFlags
	if source.IsValid() {
		message.Addr = net.UDPAddrFromAddrPort(source)
	} else {
		message.Addr = nil
	}
	return nil
}

func (c *UDPConn) Read(buffer []byte) (int, error) {
	n, _, _, _, _, err := c.readDatagram(buffer, nil)
	if err != nil {
		return n, c.operationError("read", c.remoteAddr(), err)
	}
	return n, nil
}

func (c *UDPConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	if getBuffer == nil {
		return 0, c.operationError("read", c.remoteAddr(), syscall.EINVAL)
	}
	n, _, _, _, _, err := c.readDatagram(nil, getBuffer)
	if err != nil {
		return n, c.operationError("read", c.remoteAddr(), err)
	}
	return n, nil
}

func (c *UDPConn) readDatagram(buffer []byte, getBuffer func(sizeHint int) []byte) (n int, source netip.AddrPort, target netip.Addr, options ipPacketOptions, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		default:
		}
		if pending := c.errorState.takePending(); pending != nil {
			c.notifyReceiveLocked()
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, pending
		}
		datagram, ok := c.receive.pop()
		if ok {
			c.queuedBytes -= udpDatagramSize(datagram.payload)
			c.notifyReceiveLocked()
			c.mu.Unlock()
			if getBuffer != nil {
				buffer = getBuffer(len(datagram.payload))
			}
			n = copy(buffer, datagram.payload)
			if cap(datagram.payload) != 0 && cap(datagram.payload) <= datagramReusablePayloadLimit {
				c.mu.Lock()
				select {
				case <-c.closed:
				default:
					if cap(datagram.payload) > cap(c.receiveSpare) {
						c.receiveSpare = datagram.payload[:0]
					}
				}
				c.mu.Unlock()
			}
			return n, datagram.source, datagram.target, datagram.options, n < len(datagram.payload), nil
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		}
	}
}

func (c *UDPConn) readDatagramBuffers(buffers [][]byte, wait, consumeErrors, peek, returnLength bool) (n int, source netip.AddrPort, target netip.Addr, options ipPacketOptions, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		default:
		}
		if consumeErrors {
			if pending := c.errorState.takePending(); pending != nil {
				c.notifyReceiveLocked()
				c.mu.Unlock()
				return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, pending
			}
		}
		var datagram udpDatagram
		var ok bool
		if peek {
			datagram, ok = c.receive.peek()
		} else {
			datagram, ok = c.receive.pop()
		}
		if ok {
			if !peek {
				c.queuedBytes -= udpDatagramSize(datagram.payload)
				c.notifyReceiveLocked()
			}
			n = copyMessagePayload(buffers, datagram.payload)
			truncated = n < len(datagram.payload)
			if truncated && returnLength {
				n = len(datagram.payload)
			}
			c.mu.Unlock()
			if !peek && cap(datagram.payload) != 0 && cap(datagram.payload) <= datagramReusablePayloadLimit {
				c.mu.Lock()
				select {
				case <-c.closed:
				default:
					if cap(datagram.payload) > cap(c.receiveSpare) {
						c.receiveSpare = datagram.payload[:0]
					}
				}
				c.mu.Unlock()
			}
			return n, datagram.source, datagram.target, datagram.options, truncated, nil
		}
		if !wait {
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, syscall.EAGAIN
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		}
	}
}

func (c *UDPConn) readErrorBatch(messages []SocketMessage, flags int) (int, error) {
	for index := range messages {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", c.remoteAddr(), net.ErrClosed)
		default:
		}
		ok, err := c.errorState.readMessage(&messages[index], flags)
		if !ok {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", c.remoteAddr(), syscall.EAGAIN)
		}
		if err != nil {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", c.remoteAddr(), err)
		}
		c.notifyReceiveLocked()
		c.mu.Unlock()
	}
	return len(messages), nil
}

func (c *UDPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	netAddress := address
	if udp, ok := address.(*net.UDPAddr); ok {
		netAddress = udpNetAddr(udp)
		if c.remote.IsValid() {
			return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
	}
	target, err := udpAddrPort(address)
	if err != nil {
		return 0, c.operationError("write", netAddress, err)
	}
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", netAddress, err)
	}
	return n, nil
}

func (c *UDPConn) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	netAddress := udpNetAddr(address)
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	if address == nil {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
	}
	return c.writeToUDPAddrPort(payload, address.AddrPort(), address)
}

func (c *UDPConn) WriteToUDPAddrPort(payload []byte, address netip.AddrPort) (int, error) {
	netAddress := addrPortUDPAddr{address}
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	target := netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", netAddress, err)
	}
	return n, nil
}

func (c *UDPConn) writeToUDPAddrPort(payload []byte, target netip.AddrPort, address net.Addr) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", address, net.ErrWriteToConnected)
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", address, err)
	}
	return n, nil
}

func (c *UDPConn) Write(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP socket is not connected"))
	}
	n, err := c.writeTo(payload, c.remote)
	if err != nil {
		return n, c.operationError("write", c.remoteAddr(), err)
	}
	return n, nil
}

func (c *UDPConn) WritePathMTUProbe(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP socket is not connected"))
	}
	if c.remote.Addr().IsMulticast() || c.stack.network.Load().broadcastDestination(c.remote.Addr()) {
		return 0, c.operationError("write", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToFromWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", c.remoteAddr(), err)
	}
	return n, nil
}

func (c *UDPConn) WritePathMTUProbeTo(payload []byte, target netip.AddrPort) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", net.UDPAddrFromAddrPort(target), net.ErrWriteToConnected)
	}
	if target.Addr().IsMulticast() || c.stack.network.Load().broadcastDestination(target.Addr()) {
		return 0, c.operationError("write", net.UDPAddrFromAddrPort(target), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToFromWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", net.UDPAddrFromAddrPort(target), err)
	}
	return n, nil
}

func (c *UDPConn) ConfirmPathMTU(mtu int) error {
	if !c.remote.IsValid() {
		return c.setOperationError(syscall.ENOTCONN)
	}
	if err := c.stack.ConfirmPathMTU(c.remote.Addr(), mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *UDPConn) ConfirmPathMTUFor(target netip.Addr, mtu int) error {
	if c.remote.IsValid() {
		return c.setOperationError(net.ErrWriteToConnected)
	}
	if err := c.stack.ConfirmPathMTU(target, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *UDPConn) WriteMsgUDP(payload, oob []byte, address *net.UDPAddr) (n, oobn int, err error) {
	netAddress := udpNetAddr(address)
	var target netip.AddrPort
	if c.remote.IsValid() {
		if address != nil {
			return 0, 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
		target = c.remote
	} else {
		if address == nil {
			return 0, 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
		}
		target = address.AddrPort()
	}
	n, oobn, err = c.writeMsgUDPAddrPort(payload, oob, target)
	if err != nil {
		return n, oobn, c.operationError("write", netAddress, err)
	}
	return n, oobn, nil
}

func (c *UDPConn) WriteMsgUDPAddrPort(payload, oob []byte, address netip.AddrPort) (n, oobn int, err error) {
	netAddress := addrPortUDPAddr{address}
	if c.remote.IsValid() {
		if address.IsValid() {
			return 0, 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
		address = c.remote
	} else {
		if !address.IsValid() {
			return 0, 0, c.operationError("write", netAddress, errors.New("mipstack: UDP destination is required"))
		}
	}
	n, oobn, err = c.writeMsgUDPAddrPort(payload, oob, address)
	if err != nil {
		return n, oobn, c.operationError("write", netAddress, err)
	}
	return n, oobn, nil
}

func (c *UDPConn) WriteBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^MessageFlagDontWait != 0 {
		return 0, c.operationError("write", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	for index := range messages {
		message := &messages[index]
		n, oobn, err := c.writeBatchMessage(message)
		if err != nil {
			if index != 0 {
				return index, nil
			}
			return index, err
		}
		message.N, message.NN, message.Flags = n, oobn, 0
	}
	return len(messages), nil
}

func (c *UDPConn) writeBatchMessage(message *SocketMessage) (int, int, error) {
	var target netip.AddrPort
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationError("write", message.Addr, net.ErrWriteToConnected)
		}
		target = c.remote
	} else {
		address = message.Addr
		var err error
		target, err = udpAddrPort(address)
		if err != nil {
			return 0, 0, c.operationError("write", address, err)
		}
		target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
	}
	maximum := 65535 - udpHeaderSize
	if validated.Addr().Is4() {
		maximum -= 20
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
	}
	if payloadSize > maximum {
		return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), syscall.EMSGSIZE)
	}
	if len(message.Buffers) == 1 {
		if err = c.writeError(); err != nil {
			return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
		}
		source, options, parseErr := parseControlMessageForWrite(message.OOB, validated.Addr().Is6())
		if parseErr != nil {
			return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), parseErr)
		}
		n, err := c.writeToFromWith(message.Buffers[0], validated, source, options, c.writeDatagram)
		if err != nil {
			return n, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
		}
		return n, len(message.OOB), nil
	}
	if err = c.writeError(); err != nil {
		return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Addr().Is6())
	if err != nil {
		return 0, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
	}
	n, err := c.writeBuffersToFrom(message.Buffers, payloadSize, validated, source, options)
	if err != nil {
		return n, 0, c.operationError("write", c.writeBatchErrorAddress(address), err)
	}
	return n, len(message.OOB), nil
}

func (c *UDPConn) writeBatchErrorAddress(address net.Addr) net.Addr {
	if address != nil {
		return address
	}
	return c.remoteAddr()
}

func (c *UDPConn) writeMsgUDPAddrPort(payload, oob []byte, target netip.AddrPort) (n, oobn int, err error) {
	target, err = c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, err
	}
	if err = c.writeError(); err != nil {
		return 0, 0, err
	}
	source, options, err := parseControlMessageForWrite(oob, target.Addr().Is6())
	if err != nil {
		return 0, 0, err
	}
	n, err = c.writeToFrom(payload, target, source, options)
	if err != nil {
		return n, 0, err
	}
	return n, len(oob), nil
}

func (c *UDPConn) writeTo(payload []byte, target netip.AddrPort) (int, error) {
	return c.writeToFrom(payload, target, netip.Addr{}, ipPacketOptions{})
}

func (c *UDPConn) writeToFrom(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	return c.writeToFromWith(payload, target, packetInfoSource, options, c.writeDatagram)
}

func (c *UDPConn) prepareWrite(target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (udpWriteParameters, error) {
	target, err := c.validateWriteTarget(target)
	if err != nil {
		return udpWriteParameters{}, err
	}
	if err = c.writeError(); err != nil {
		return udpWriteParameters{}, err
	}
	options, pathMTUDiscovery, receiveErrors, pendingErr := c.writeOptions(options)
	if pendingErr != nil {
		return udpWriteParameters{}, pendingErr
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	var source netip.Addr
	nonUnicast := false
	if c.forwarded {
		if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() && packetInfoSource != c.local {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		state := c.stack.network.Load()
		if !state.acceptsInboundDestination(c.local) {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		if _, routed := state.routeFor(target.Addr()); !routed {
			return udpWriteParameters{}, syscall.ENETUNREACH
		}
		source = c.local
	} else {
		source, nonUnicast, err = c.stack.sourceForOutput(target.Addr(), requestedSource)
		if err != nil {
			return udpWriteParameters{}, err
		}
	}
	return udpWriteParameters{
		source: source.Unmap(), target: target, options: options,
		pathMTUDiscovery: pathMTUDiscovery, receiveErrors: receiveErrors, nonUnicast: nonUnicast,
	}, nil
}

func (c *UDPConn) writeToFromWith(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions, write udpDatagramWriter) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	maximumPayload := 65535 - udpHeaderSize
	if parameters.target.Addr().Is4() {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	linkErr := write(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), payload, parameters.options, parameters.pathMTUDiscovery, parameters.nonUnicast)
	if !parameters.nonUnicast && datagramWriteNeedsCorrelation(linkErr) {
		c.rememberTarget(parameters.target)
	}
	writeErr := datagramLinkWriteError(linkErr, parameters.receiveErrors)
	if writeErr != nil {
		if errors.Is(writeErr, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, writeErr
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

func (c *UDPConn) writeBuffersToFrom(buffers [][]byte, payloadSize int, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	maximumPayload := 65535 - udpHeaderSize
	if parameters.target.Addr().Is4() {
		maximumPayload -= 20
	}
	if payloadSize > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	if parameters.nonUnicast {
		payload, gatherErr := gatherMessagePayload(buffers, maximumPayload)
		if gatherErr != nil {
			return 0, gatherErr
		}
		err = c.writeNonUnicastDatagram(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), payload, parameters.options, parameters.pathMTUDiscovery)
	} else {
		mtu, fragmentation := c.stack.pathMTUOutputPolicy(parameters.target.Addr(), parameters.pathMTUDiscovery)
		err = c.writeDatagramBuffersForMTU(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), buffers, payloadSize, parameters.options, fragmentation, mtu)
	}
	if !parameters.nonUnicast && datagramWriteNeedsCorrelation(err) {
		c.rememberTarget(parameters.target)
	}
	err = datagramLinkWriteError(err, parameters.receiveErrors)
	if err != nil {
		return 0, err
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(payloadSize))
	return payloadSize, nil
}

func (c *UDPConn) writeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast bool) error {
	if nonUnicast {
		return c.writeNonUnicastDatagram(source, target, sourcePort, targetPort, payload, options, pathMTUDiscovery)
	}
	mtu, fragmentation := c.stack.pathMTUOutputPolicy(target, pathMTUDiscovery)
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, mtu)
}

func (s *Stack) writeBestEffortUDPDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery) error {
	udpSize := udpHeaderSize + len(payload)
	if udpSize > 65535 {
		return syscall.EMSGSIZE
	}
	mtu, fragmentation := s.pathMTUOutputPolicy(target, pathMTUDiscovery)
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = s.automaticTransportFlowLabel(source, target, ProtocolUDP, sourcePort, targetPort)
		options.flowLabelSet = true
	}
	if ipSize+udpSize <= mtu {
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
		packetSize := ipSize + udpSize
		var packet []byte
		var reusable bool
		if packetSize <= packetReusableBufferLimit {
			packet, reusable = queue.acquireBuffer(packetSize)
		} else {
			packet, reusable = s.acquireLargeOutputBuffer(packetSize)
		}
		if !marshalIPHeader(packet, source, target, ProtocolUDP, identification, fragmentation.dontFragment, options) {
			s.releaseOutputBuffer(queue, packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		marshalUDPDatagram(packet[ipSize:], source, target, sourcePort, targetPort, payload)
		if !queue.enqueueReservedPacket(slot, packet, reusable, true) {
			return ErrClosed
		}
		s.recordOutput(loopback)
		return nil
	}
	var layout ipFragmentLayout
	if err := s.ipFragmentLayoutForMTU(source, target, udpSize, fragmentation, options, mtu, &layout); err != nil {
		return err
	}
	var udpHeader [udpHeaderSize]byte
	marshalUDPHeaderFields(udpHeader[:], sourcePort, targetPort, udpSize)
	writeUDPChecksumValue(udpHeader[:], transportChecksumParts(source, target, ProtocolUDP, udpSize, udpHeader[:], payload))
	err := s.tryWriteIPFragmentsLayout(source, target, ProtocolUDP, udpHeader[:], payload, layout, true)
	if err == ErrResourceLimit {
		return nil
	}
	return err
}

func (c *UDPConn) writePathMTUProbeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, _ PathMTUDiscovery, _ bool) error {
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, sourceFragmentation{dontFragment: true}, c.stack.network.Load().mtu)
}

func (c *UDPConn) writeDatagramForMTU(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, fragmentation sourceFragmentation, mtu int) error {
	udpSize := udpHeaderSize + len(payload)
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.automaticLabel
		if options.flowLabel == 0 || !c.remote.IsValid() || target != c.remote.Addr() || sourcePort != c.port || targetPort != c.remote.Port() {
			options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, ProtocolUDP, sourcePort, targetPort)
		}
		options.flowLabelSet = true
	}
	if ipSize+udpSize <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		queue, loopback := c.stack.outputQueueFor(target)
		slot, err := c.stack.tryReservePacket(queue)
		if err == ErrResourceLimit {
			slot, err = c.stack.replaceBestEffortPacket(queue)
		}
		if err != nil {
			return err
		}
		packetSize := ipSize + udpSize
		var packet []byte
		var reusable bool
		if packetSize <= packetReusableBufferLimit {
			packet, reusable = queue.acquireBuffer(packetSize)
		} else {
			packet, reusable = c.stack.acquireLargeOutputBuffer(packetSize)
		}
		if !marshalIPHeader(packet, source, target, ProtocolUDP, identification, fragmentation.dontFragment, options) {
			c.stack.releaseOutputBuffer(queue, packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		udp := packet[ipSize:]
		marshalUDPDatagram(udp, source, target, sourcePort, targetPort, payload)
		if !queue.enqueueReservedPacket(slot, packet, reusable, true) {
			return ErrClosed
		}
		c.stack.recordOutput(loopback)
		return nil
	}
	var layout ipFragmentLayout
	if err := c.stack.ipFragmentLayoutForMTU(source, target, udpSize, fragmentation, options, mtu, &layout); err != nil {
		return err
	}
	var udpHeader [udpHeaderSize]byte
	marshalUDPHeaderFields(udpHeader[:], sourcePort, targetPort, udpSize)
	writeUDPChecksumValue(udpHeader[:], transportChecksumParts(source, target, ProtocolUDP, udpSize, udpHeader[:], payload))
	return c.stack.tryWriteIPFragmentsLayout(source, target, ProtocolUDP, udpHeader[:], payload, layout, true)
}

func (c *UDPConn) writeDatagramBuffersForMTU(source, target netip.Addr, sourcePort, targetPort uint16, buffers [][]byte, payloadSize int, options ipPacketOptions, fragmentation sourceFragmentation, mtu int) error {
	udpSize := udpHeaderSize + payloadSize
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if ipSize+udpSize > mtu {
		if !fragmentation.allow {
			return syscall.EMSGSIZE
		}
		payload, err := gatherMessagePayload(buffers, payloadSize)
		if err != nil {
			return err
		}
		return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, mtu)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.automaticLabel
		if options.flowLabel == 0 || !c.remote.IsValid() || target != c.remote.Addr() || sourcePort != c.port || targetPort != c.remote.Port() {
			options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, ProtocolUDP, sourcePort, targetPort)
		}
		options.flowLabelSet = true
	}
	identification := uint16(0)
	if source.Is4() && fragmentation.requiresIPv4ID() {
		identification = uint16(c.stack.ipv4ID.Add(1))
	}
	queue, loopback := c.stack.outputQueueFor(target)
	slot, err := c.stack.tryReservePacket(queue)
	if err == ErrResourceLimit {
		slot, err = c.stack.replaceBestEffortPacket(queue)
	}
	if err != nil {
		return err
	}
	packetSize := ipSize + udpSize
	var packet []byte
	var reusable bool
	if packetSize <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(packetSize)
	} else {
		packet, reusable = c.stack.acquireLargeOutputBuffer(packetSize)
	}
	if !marshalIPHeader(packet, source, target, ProtocolUDP, identification, fragmentation.dontFragment, options) {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	udp := packet[ipSize:]
	marshalUDPHeaderFields(udp[:udpHeaderSize], sourcePort, targetPort, udpSize)
	if copied := copyMessageBuffers(udp[udpHeaderSize:], buffers); copied != payloadSize {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EINVAL
	}
	writeUDPChecksumValue(udp[:udpHeaderSize], transportChecksum(source, target, ProtocolUDP, udp))
	if !queue.enqueueReservedPacket(slot, packet, reusable, true) {
		return ErrClosed
	}
	c.stack.recordOutput(loopback)
	return nil
}

func marshalUDPDatagram(dst []byte, source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) {
	marshalUDPHeaderFields(dst[:udpHeaderSize], sourcePort, targetPort, len(dst))
	copy(dst[udpHeaderSize:], payload)
	writeUDPChecksumValue(dst[:udpHeaderSize], transportChecksum(source, target, ProtocolUDP, dst))
}

func writeUDPChecksumValue(header []byte, value uint16) {
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(header[6:8], value)
}

func marshalUDPHeaderFields(header []byte, sourcePort, targetPort uint16, length int) {
	binary.BigEndian.PutUint16(header[0:2], sourcePort)
	binary.BigEndian.PutUint16(header[2:4], targetPort)
	binary.BigEndian.PutUint16(header[4:6], uint16(length))
	binary.BigEndian.PutUint16(header[6:8], 0)
}

func (c *UDPConn) rememberTarget(target netip.AddrPort) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if c.remote.IsValid() {
		return
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.recentTargets.remember(target, monotonicStampAt(c.stack.timestampEpoch, time.Now()))
	c.mu.Unlock()
}

func (c *UDPConn) acceptsError(target netip.AddrPort) bool {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if c.remote.IsValid() {
		return target == c.remote
	}
	c.mu.Lock()
	exists := c.recentTargets.contains(target, monotonicStampAt(c.stack.timestampEpoch, time.Now()))
	c.mu.Unlock()
	return exists
}

func (c *UDPConn) acceptsPathMTU() bool {
	c.mu.Lock()
	accepted := c.pathMTUDiscovery.acceptsPathMTU()
	c.mu.Unlock()
	return accepted
}

func (c *UDPConn) deliverError(target netip.AddrPort, networkError ICMPError) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	pending, queued := linuxDatagramICMPReport(networkError, c.remote.IsValid(), c.receiveErrors, false, c.pathMTUDiscovery)
	if !pending {
		c.mu.Unlock()
		return
	}
	operationError := &net.OpError{
		Op: "read", Net: c.net.name(), Source: c.LocalAddr(),
		Addr: net.UDPAddrFromAddrPort(target), Err: networkError,
	}
	if c.errorState == nil {
		c.errorState = &datagramSocketErrorState{}
	}
	errorState := c.errorState
	errorState.lastError = operationError
	errorState.pending = operationError
	errorState.icmpErrors++
	if !queued {
		c.notifyReceiveLocked()
		c.mu.Unlock()
		return
	}
	size := socketErrorSize(networkError)
	if size > c.receiveCapacity || c.queuedBytes+errorState.queuedBytes > c.receiveCapacity-size {
		errorState.dropped++
		c.notifyReceiveLocked()
		c.mu.Unlock()
		return
	}
	var payload []byte
	if len(networkError.QuotedPayload) >= udpHeaderSize {
		payload = networkError.QuotedPayload[udpHeaderSize:]
	}
	errorState.push(queuedSocketError{err: operationError, payload: payload, size: size})
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

func udpAddrPort(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, errors.New("mipstack: UDP destination is required")
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		if udp == nil {
			return netip.AddrPort{}, errors.New("mipstack: UDP destination is required")
		}
		return udp.AddrPort(), nil
	}
	result, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, errors.New("mipstack: invalid UDP destination")
	}
	return result, nil
}

func (c *UDPConn) validateWriteTarget(target netip.AddrPort) (netip.AddrPort, error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	address := target.Addr()
	if !target.IsValid() || address.IsUnspecified() || address.Zone() != "" {
		return netip.AddrPort{}, errors.New("mipstack: invalid UDP destination")
	}
	if !c.dual && address.Is6() != c.v6 {
		family := "IPv4"
		if c.v6 {
			family = "IPv6"
		}
		return netip.AddrPort{}, &net.AddrError{Err: "non-" + family + " address", Addr: address.String()}
	}
	return target, nil
}

type addrPortUDPAddr struct{ netip.AddrPort }

func (addrPortUDPAddr) Network() string { return "udp" }

func udpNetAddr(address *net.UDPAddr) net.Addr {
	if address == nil {
		return nil
	}
	return address
}

func (c *UDPConn) Close() error {
	if c.stack.closeUDP(c) {
		return nil
	}
	return c.operationError("close", c.remoteAddr(), net.ErrClosed)
}

func (c *UDPConn) closeFromStack() {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.readDeadline.stop()
	c.writeDeadline.stop()
	c.receive.clear()
	c.errorState.releaseRetained()
	c.receiveSpare = nil
	c.receiveNotify = nil
	c.queuedBytes = 0
	c.recentTargets = recentDestinationCache[netip.AddrPort]{}
	close(c.closed)
	c.mu.Unlock()
}

func (c *UDPConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.local, c.port))
}

func (c *UDPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

func (c *UDPConn) Info() UDPConnInfo {
	c.mu.Lock()
	automaticFlowLabel := !c.defaultOptions.flowLabelSet
	flowLabel := c.defaultOptions.flowLabel
	if !c.v6 && !c.dual {
		flowLabel = 0
	}
	errorEntries, errorBytes := c.errorState.len(), c.errorState.bytes()
	var lastError error
	var icmpErrors, errorsDropped uint64
	if c.errorState != nil {
		lastError = c.errorState.lastError
		icmpErrors, errorsDropped = c.errorState.icmpErrors, c.errorState.dropped
	}
	info := UDPConnInfo{
		LocalAddress: netip.AddrPortFrom(c.local, c.port), RemoteAddress: c.remote,
		ReceiveQueuePackets: c.receive.len(), ReceiveQueueBytes: c.queuedBytes, ReceiveQueueCapacity: c.receiveCapacity,
		ReceiveErrors: c.receiveErrors, ErrorQueueEntries: errorEntries, ErrorQueueBytes: errorBytes,
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
		PathMTUDiscovery:  c.pathMTUDiscovery,
		MulticastHopLimit: int(c.multicastHopLimit), MulticastLoopback: c.multicastLoopback, Broadcast: c.broadcast,
		FlowLabel: flowLabel, LastError: lastError, ICMPErrors: icmpErrors, ErrorsDropped: errorsDropped,
	}
	select {
	case <-c.closed:
		info.Closed = true
	default:
	}
	c.mu.Unlock()
	info.PacketsSent, info.BytesSent = c.packetsSent.Load(), c.bytesSent.Load()
	info.PacketsReceived, info.BytesReceived = c.packetsReceived.Load(), c.bytesReceived.Load()
	info.PacketsDropped = c.packetsDropped.Load()
	if c.remote.IsValid() && !c.remote.Addr().IsMulticast() && !c.stack.network.Load().broadcastDestination(c.remote.Addr()) {
		info.PathMTU = c.stack.mtuFor(c.remote.Addr())
		if c.remote.Addr().Is6() && automaticFlowLabel {
			info.FlowLabel = c.stack.automaticTransportFlowLabel(c.local, c.remote.Addr(), ProtocolUDP, c.port, c.remote.Port())
		}
	}
	return info
}

func (c *UDPConn) remoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(c.remote)
}

func (c *UDPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.readDeadline.set(deadline)
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.readDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	if bytes < udpDatagramMetadataSize {
		bytes = udpDatagramMetadataSize
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.receiveCapacity = bytes
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) SetReceiveErrors(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		if c.receiveErrors && !enabled {
			c.errorState.purgeQueue()
		}
		c.receiveErrors = enabled
		c.notifyReceiveLocked()
		return nil
	}
}

func (c *UDPConn) ReceiveErrors() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.receiveErrors, nil
	}
}

func (c *UDPConn) ReadError() (*net.OpError, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, c.operationError("read", c.remoteAddr(), net.ErrClosed)
	default:
	}
	queued, ok := c.errorState.pop()
	if !ok {
		c.mu.Unlock()
		return nil, c.operationError("read", c.remoteAddr(), syscall.EAGAIN)
	}
	c.notifyReceiveLocked()
	c.mu.Unlock()
	return queued.err, nil
}

func (c *UDPConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.mu.Unlock()
		return nil
	}
}

func (c *UDPConn) SetPathMTUDiscovery(mode PathMTUDiscovery) error {
	if !mode.valid() {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.pathMTUDiscovery = mode
		return nil
	}
}

func (c *UDPConn) PathMTUDiscovery() (PathMTUDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return PathMTUDiscoveryDont, c.setOperationError(net.ErrClosed)
	default:
		return c.pathMTUDiscovery, nil
	}
}

func (c *UDPConn) SetHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 || hopLimit == 0 && (!c.v6 || c.dual) {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.hopLimit, c.defaultOptions.hopLimitSet = byte(hopLimit), true
		c.mu.Unlock()
		return nil
	}
}

func (c *UDPConn) SetTrafficClass(value int) error {
	if value < 0 || value > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.trafficClass = byte(value)
		c.mu.Unlock()
		return nil
	}
}

func (c *UDPConn) SetFlowLabel(label uint32) error {
	if label > ipv6MaximumFlowLabel {
		return c.setOperationError(syscall.EINVAL)
	}
	if !c.v6 && !c.dual {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.flowLabel, c.defaultOptions.flowLabelSet = label, true
		c.mu.Unlock()
		return nil
	}
}

func (c *UDPConn) writeOptions(options ipPacketOptions) (ipPacketOptions, PathMTUDiscovery, bool, error) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	pathMTUDiscovery := c.pathMTUDiscovery
	receiveErrors := c.receiveErrors
	pending := c.errorState.takePending()
	if pending != nil {
		c.notifyReceiveLocked()
	}
	c.mu.Unlock()
	if pending != nil {
		return options, pathMTUDiscovery, receiveErrors, pending.Err
	}
	return options, pathMTUDiscovery, receiveErrors, nil
}

func (c *UDPConn) operationError(operation string, target net.Addr, err error) error {
	return socketOperationError(operation, c.net.name(), c.LocalAddr(), target, err)
}

func (c *UDPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net.name(), nil, c.LocalAddr(), err)
}

func socketOperationError(operation, network string, source, target net.Addr, err error) error {
	if err == nil {
		return nil
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		return err
	}
	return &net.OpError{Op: operation, Net: network, Source: source, Addr: target, Err: err}
}

var _ net.PacketConn = (*UDPConn)(nil)

var _ net.Conn = (*UDPConn)(nil)

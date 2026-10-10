package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ipDefaultReceiveCapacity = 4 * 1024 * 1024
	ipDatagramMetadataSize = 96
)

type ICMPv4Filter struct {
	blocked uint32
}

func (f *ICMPv4Filter) Accept(typ uint8) {
	f.blocked &^= uint32(1) << (typ & 31)
}

func (f *ICMPv4Filter) Block(typ uint8) {
	f.blocked |= uint32(1) << (typ & 31)
}

func (f *ICMPv4Filter) SetAll(block bool) {
	if block {
		f.blocked = ^uint32(0)
	} else {
		f.blocked = 0
	}
}

func (f *ICMPv4Filter) WillBlock(typ uint8) bool {
	return f.blocked&(uint32(1)<<(typ&31)) != 0
}

type ICMPv6Filter struct {
	blocked [8]uint32
}

func (f *ICMPv6Filter) Accept(typ uint8) {
	f.blocked[typ>>5] &^= uint32(1) << (typ & 31)
}

func (f *ICMPv6Filter) Block(typ uint8) {
	f.blocked[typ>>5] |= uint32(1) << (typ & 31)
}

func (f *ICMPv6Filter) SetAll(block bool) {
	value := uint32(0)
	if block {
		value = ^uint32(0)
	}
	for index := range f.blocked {
		f.blocked[index] = value
	}
}

func (f *ICMPv6Filter) WillBlock(typ uint8) bool {
	return f.blocked[typ>>5]&(uint32(1)<<(typ&31)) != 0
}

type ipDatagram struct {
	payload []byte
	source  netip.Addr
	target  netip.Addr
	options ipPacketOptions
}

type IPConnInfo struct {
	LocalAddress netip.Addr
	RemoteAddress netip.Addr
	Protocol uint8
	IPHeaderIncludedOnWrite bool
	IPHeaderIncludedOnRead bool
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

type ipKey struct {
	address  netip.Addr
	protocol byte
}

type ipEndpoints interface {
	deliver(stack *Stack, packet ipPacket) bool
	deliverError(stack *Stack, networkError ICMPError) bool
	updateConfig(stack *Stack, network *networkState)
	closeAll()
}

type ipEndpointState struct {
	bindings map[ipKey]map[*IPConn]struct{}
}

const ipEndpointInlineFanout = 8

type ipConnICMPFilter struct {
	blocked [8]uint32
}

type IPConn struct {
	stack                   *Stack
	net                     string
	protocol                byte
	v6                      bool
	dual                    bool
	receiveErrors           bool
	ipHeaderIncludedOnWrite atomic.Bool
	local                   netip.Addr
	remote                  netip.Addr

	datagramSocketWriteControl

	mu                     sync.Mutex
	receive                datagramQueue[ipDatagram]
	receiveSpare           []byte
	receiveNotify          chan struct{}
	receiveCapacity        int
	queuedBytes            int
	errorState             *datagramSocketErrorState
	readDeadline           datagramSocketDeadline
	recentTargets          recentDestinationCache[netip.Addr]
	pathMTUDiscovery       PathMTUDiscovery
	icmpFilter             *ipConnICMPFilter
	ipv6ChecksumOffset     int
	packetsSent            atomic.Uint64
	bytesSent              atomic.Uint64
	packetsReceived        atomic.Uint64
	bytesReceived          atomic.Uint64
	packetsDropped         atomic.Uint64
	defaultOptions         ipPacketOptions
	ipHeaderIncludedOnRead bool
	multicastHopLimit      byte
	multicastLoopback      bool
	broadcast              bool
}

type ipWriteParameters struct {
	source           netip.Addr
	target           netip.Addr
	options          ipPacketOptions
	pathMTUDiscovery PathMTUDiscovery
	checksumOffset   int
	receiveErrors    bool
	nonUnicast       bool
}

type ipPayloadWriter func(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast bool) error

func (s *Stack) ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error) {
	return s.listenIP(ctx, network, local, socketOptionSet{})
}

func (s *Stack) listenIP(ctx context.Context, network string, local netip.Addr, options socketOptionSet) (net.PacketConn, error) {
	local = local.Unmap()
	target := ipNetAddr(local)
	wrap := func(err error) (net.PacketConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	protocol, err := parseIPNetwork(network, local)
	if err != nil {
		return wrap(err)
	}
	if local.IsValid() && (local.IsMulticast() || local.Zone() != "") {
		return wrap(errors.New("mipstack: invalid IP listen address"))
	}
	if local.IsValid() && !local.IsUnspecified() && !s.isLocal(local) {
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
	family := network[:strings.LastIndexByte(network, ':')]
	local, dual, err := listenAddress(state, family, "ip", local)
	if err != nil {
		return wrap(err)
	}
	if err = options.validateFamily(socketOptionIPListen, local.Is6(), dual); err != nil {
		return wrap(err)
	}
	if err = options.validateIPSocket(protocol, local.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !local.IsUnspecified() && !networkStateHasLocal(state, local) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	connection := newIPConn(s, network, protocol, local, netip.Addr{}, options)
	connection.dual = dual
	s.ipEndpointStateLocked().register(connection)
	s.stats.activeIPSockets.Add(1)
	return connection, nil
}

func (s *Stack) DialIP(ctx context.Context, network string, source, remote netip.Addr) (net.Conn, error) {
	return s.dialIP(ctx, network, source, remote, socketOptionSet{})
}

func (s *Stack) dialIP(ctx context.Context, network string, source, remote netip.Addr, options socketOptionSet) (net.Conn, error) {
	remote = remote.Unmap()
	target := ipNetAddr(remote)
	wrap := func(local net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, local, target, err)
	}
	protocol, err := parseIPNetwork(network, remote)
	if err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.IsUnspecified() || remote.Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid IP destination"))
	}
	if err = options.validateFamily(socketOptionIPDial, remote.Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if err = options.validateIPSocket(protocol, remote.Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	source = source.Unmap()
	if source.IsValid() && source.Zone() != "" {
		return wrap(nil, syscall.EINVAL)
	}
	family := network[:strings.LastIndexByte(network, ':')]
	if source.IsValid() && source.IsUnspecified() && source.Is6() != remote.Is6() && family != "ip" {
		addressFamily := "IPv6"
		if remote.Is4() {
			addressFamily = "IPv4"
		}
		return wrap(ipNetAddr(source), &net.AddrError{Err: "non-" + addressFamily + " address", Addr: source.String()})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(nil, ErrClosed)
	}
	local, err := s.sourceForRequested(remote, source)
	if err != nil {
		return wrap(ipNetAddr(source), err)
	}
	connection := newIPConn(s, network, protocol, local, remote, options)
	s.ipEndpointStateLocked().register(connection)
	s.stats.activeIPSockets.Add(1)
	return connection, nil
}

func parseIPNetwork(network string, address netip.Addr) (byte, error) {
	separator := strings.LastIndexByte(network, ':')
	if separator < 0 {
		return 0, net.UnknownNetworkError(network)
	}
	family, protocolName := network[:separator], network[separator+1:]
	switch family {
	case "ip":
	case "ip4":
		if address.IsValid() && address.Is6() {
			return 0, syscall.EAFNOSUPPORT
		}
	case "ip6":
		if address.IsValid() && address.Is4() {
			return 0, syscall.EAFNOSUPPORT
		}
	default:
		return 0, net.UnknownNetworkError(network)
	}
	var protocol byte
	switch strings.ToLower(protocolName) {
	case "icmp":
		protocol = ProtocolICMPv4
	case "igmp":
		protocol = 2
	case "tcp":
		protocol = ProtocolTCP
	case "udp":
		protocol = ProtocolUDP
	case "ipv6-icmp":
		protocol = ProtocolICMPv6
	default:
		for _, character := range protocolName {
			if character < '0' || character > '9' {
				return 0, &net.AddrError{Err: "unknown IP protocol specified", Addr: protocolName}
			}
		}
		value, err := strconv.ParseUint(protocolName, 10, 8)
		if err != nil {
			return 0, &net.AddrError{Err: "unknown IP protocol specified", Addr: protocolName}
		}
		protocol = byte(value)
	}
	if err := validateIPProtocol(protocol); err != nil {
		return 0, err
	}
	return protocol, nil
}

func validateIPProtocol(protocol byte) error {
	if protocol == 0 {
		return errors.New("mipstack: invalid IP protocol")
	}
	return nil
}

func newIPConn(stack *Stack, network string, protocol byte, local, remote netip.Addr, options socketOptionSet) *IPConn {
	defaults := IPSocketDefaults{DatagramSocketDefaults: DatagramSocketDefaults{
		ReceiveBuffer: ipDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1,
	}}
	if stack != nil {
		defaults = stack.network.Load().ipDefaults
	}
	datagramDefaults := applyDatagramSocketOptions(defaults.DatagramSocketDefaults, options.datagram, ipDatagramMetadataSize)
	headerIncludedOnWrite := defaults.IPHeaderIncludedOnWrite
	if options.ip.headerIncludedOnWrite != socketOptionBoolOverrideUnset {
		headerIncludedOnWrite = options.ip.headerIncludedOnWrite == socketOptionBoolOverrideEnabled
	}
	headerIncludedOnRead := defaults.IPHeaderIncludedOnRead
	if options.ip.headerIncludedOnRead != socketOptionBoolOverrideUnset {
		headerIncludedOnRead = options.ip.headerIncludedOnRead == socketOptionBoolOverrideEnabled
	}
	checksumOffset := -1
	if local.Is6() && protocol == ProtocolICMPv6 {
		checksumOffset = 2
	}
	if checksum := options.ip.ipv6Checksum; checksum.set {
		if checksum.value.enabled {
			checksumOffset = checksum.value.offset
		} else {
			checksumOffset = -1
		}
	}
	connection := &IPConn{
		stack: stack, net: network, protocol: protocol, v6: local.Is6(), local: local, remote: remote,
		datagramSocketWriteControl: datagramSocketWriteControl{closed: make(chan struct{})},
		receiveCapacity:            datagramDefaults.ReceiveBuffer,
		ipHeaderIncludedOnRead:     headerIncludedOnRead,
		defaultOptions: ipPacketOptions{
			hopLimit: byte(datagramDefaults.HopLimit), trafficClass: datagramDefaults.TrafficClass,
			flowLabel: datagramDefaults.FlowLabel, hopLimitSet: options.datagram.hopLimit.set,
			trafficClassSet: options.datagram.trafficClass.set, flowLabelSet: datagramDefaults.FlowLabel != 0 || options.datagram.flowLabel.set,
		},
		receiveErrors:     datagramDefaults.ReceiveErrors,
		pathMTUDiscovery:  datagramDefaults.PathMTUDiscovery,
		multicastHopLimit: byte(datagramDefaults.MulticastHopLimit), multicastLoopback: !datagramDefaults.DisableMulticastLoopback,
		broadcast: !datagramDefaults.DisableBroadcast, ipv6ChecksumOffset: checksumOffset,
	}
	if filter := options.ip.icmpV4Filter.value; protocol == ProtocolICMPv4 && filter != (ICMPv4Filter{}) {
		connection.icmpFilter = &ipConnICMPFilter{}
		connection.icmpFilter.blocked[0] = filter.blocked
	} else if filter := options.ip.icmpV6Filter.value; protocol == ProtocolICMPv6 && filter != (ICMPv6Filter{}) {
		connection.icmpFilter = &ipConnICMPFilter{blocked: filter.blocked}
	}
	connection.ipHeaderIncludedOnWrite.Store(headerIncludedOnWrite)
	return connection
}

func (s *Stack) ipEndpointStateLocked() *ipEndpointState {
	if s.ip == nil {
		state := &ipEndpointState{bindings: make(map[ipKey]map[*IPConn]struct{})}
		s.ip = state
		return state
	}
	return s.ip.(*ipEndpointState)
}

func (state *ipEndpointState) register(connection *IPConn) {
	key := ipKey{address: connection.local, protocol: connection.protocol}
	bindings := state.bindings[key]
	if bindings == nil {
		bindings = make(map[*IPConn]struct{})
		state.bindings[key] = bindings
	}
	bindings[connection] = struct{}{}
}

func (state *ipEndpointState) deliver(stack *Stack, packet ipPacket) bool {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return false
	}
	var connectionStorage [ipEndpointInlineFanout]*IPConn
	connections := state.connectionsForLocked(connectionStorage[:0], packet.target, packet.protocol)
	stack.mu.RUnlock()
	accepted := false
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		accepted = true
		connection.enqueuePacket(packet, options)
	}
	return accepted
}

func (state *ipEndpointState) connectionsForLocked(storage []*IPConn, address netip.Addr, protocol byte) []*IPConn {
	connections := storage
	for connection := range state.bindings[ipKey{address: address, protocol: protocol}] {
		connections = append(connections, connection)
	}
	wildcard := netip.IPv4Unspecified()
	if address.Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	for connection := range state.bindings[ipKey{address: wildcard, protocol: protocol}] {
		connections = append(connections, connection)
	}
	if address.Is4() {
		for connection := range state.bindings[ipKey{address: netip.IPv6Unspecified(), protocol: protocol}] {
			if connection.dual {
				connections = append(connections, connection)
			}
		}
	}
	return connections
}

func (state *ipEndpointState) deliverError(stack *Stack, networkError ICMPError) bool {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return false
	}
	var connectionStorage [ipEndpointInlineFanout]*IPConn
	connections := state.connectionsForLocked(connectionStorage[:0], networkError.QuotedSource, networkError.QuotedProtocol)
	stack.mu.RUnlock()
	accepted := false
	acceptedPathMTU := false
	for _, connection := range connections {
		if !connection.acceptsError(networkError.QuotedTarget) {
			continue
		}
		accepted = true
		acceptedPathMTU = acceptedPathMTU || connection.acceptsPathMTU()
		connectionError := cloneICMPError(networkError)
		connection.deliverError(networkError.QuotedTarget, connectionError)
	}
	if acceptedPathMTU && networkError.MTU != 0 && stack.observePathMTU(networkError.QuotedTarget, networkError.MTU) {
		stack.notifyTCPPathMTU(networkError.QuotedTarget, nil)
	}
	return accepted
}

func (state *ipEndpointState) empty() bool { return len(state.bindings) == 0 }

func (state *ipEndpointState) connections() []*IPConn {
	var connections []*IPConn
	for _, bindings := range state.bindings {
		for connection := range bindings {
			connections = append(connections, connection)
		}
	}
	return connections
}

func (state *ipEndpointState) updateConfig(stack *Stack, network *networkState) {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return
	}
	connections := state.connections()
	stack.mu.RUnlock()
	for _, connection := range connections {
		if connection.dual && !networkStateHasFamily(network, false) && !networkStateHasFamily(network, true) ||
			!connection.dual && connection.local.IsUnspecified() && !networkStateHasFamily(network, connection.v6) ||
			!connection.local.IsUnspecified() && !networkStateHasLocal(network, connection.local) {
			stack.closeIP(connection)
			continue
		}
		if connection.remote.IsValid() {
			if !network.hasOutputPath(connection.remote) {
				stack.closeIP(connection)
			}
		}
	}
}

func (state *ipEndpointState) closeAll() {
	connections := state.connections()
	state.bindings = nil
	for _, connection := range connections {
		connection.closeFromStack()
	}
}

func (state *ipEndpointState) remove(connection *IPConn) bool {
	key := ipKey{address: connection.local, protocol: connection.protocol}
	bindings := state.bindings[key]
	if _, exists := bindings[connection]; !exists {
		return false
	}
	delete(bindings, connection)
	if len(bindings) == 0 {
		delete(state.bindings, key)
	}
	return true
}

func (c *IPConn) enqueuePacket(packet ipPacket, options ipPacketOptions) {
	payload := packet.payload
	if c.ipHeaderIncludedOnRead {
		payload = packet.original
	}
	size := ipDatagramMetadataSize + len(payload)
	c.mu.Lock()
	filter := c.icmpFilter
	blocked := filter != nil && len(packet.payload) != 0 && (packet.source.Is4() && c.protocol == ProtocolICMPv4 && packet.payload[0] < 32 && filter.blocked[0]&(uint32(1)<<packet.payload[0]) != 0 ||
		packet.source.Is6() && c.protocol == ProtocolICMPv6 && filter.blocked[packet.payload[0]>>5]&(uint32(1)<<(packet.payload[0]&31)) != 0)
	if blocked || packet.source.Is6() && c.protocol != ProtocolICMPv6 && c.ipv6ChecksumOffset >= 0 &&
		(c.ipv6ChecksumOffset > len(packet.payload)-2 || transportChecksum(packet.source, packet.target, c.protocol, packet.payload) != 0) {
		c.mu.Unlock()
		return
	}
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
	datagram := ipDatagram{payload: retained, source: packet.source, target: packet.target, options: options}
	c.receive.push(datagram)
	c.queuedBytes += size
	c.packetsReceived.Add(1)
	c.bytesReceived.Add(uint64(len(payload)))
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

func (c *IPConn) notifyReceiveLocked() {
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

func (c *IPConn) receiveNotificationLocked() <-chan struct{} {
	if c.receiveNotify == nil {
		c.receiveNotify = make(chan struct{}, 1)
	}
	return c.receiveNotify
}

func (c *IPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, datagram, _, err := c.readDatagram(buffer, nil)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

func (c *IPConn) ReadFromIP(buffer []byte) (int, *net.IPAddr, error) {
	n, datagram, _, err := c.readDatagram(buffer, nil)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

func (c *IPConn) ReadFromWithBuffer(getBuffer func(sizeHint int) []byte) (int, net.Addr, error) {
	if getBuffer == nil {
		return 0, nil, c.operationError("read", syscall.EINVAL)
	}
	n, datagram, _, err := c.readDatagram(nil, getBuffer)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

func (c *IPConn) ReadFromIPWithBuffer(getBuffer func(sizeHint int) []byte) (int, *net.IPAddr, error) {
	if getBuffer == nil {
		return 0, nil, c.operationError("read", syscall.EINVAL)
	}
	n, datagram, _, err := c.readDatagram(nil, getBuffer)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

func (c *IPConn) ReadMsgIP(buffer, oob []byte) (n, oobn, flags int, address *net.IPAddr, err error) {
	var datagram ipDatagram
	var truncated bool
	n, datagram, truncated, err = c.readDatagram(buffer, nil)
	address = ipNetAddr(datagram.source)
	if truncated {
		flags |= MessageFlagTruncated
	}
	if err != nil {
		err = c.operationError("read", err)
		return
	}
	var specDst netip.Addr
	if datagram.target.Is4() {
		specDst = c.stack.network.Load().inboundIPv4PacketInfoSource(datagram.source, datagram.target)
	}
	control, controlErr := controlMessageForRead(specDst, datagram.target, datagram.options)
	if controlErr != nil {
		err = c.operationError("read", controlErr)
		return
	}
	oobn = copy(oob, control)
	if oobn < len(control) {
		flags |= MessageFlagControlTruncated
	}
	return
}

func (c *IPConn) ReadBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^(MessageFlagPeek|MessageFlagDontWait|MessageFlagTruncated|MessageFlagErrorQueue) != 0 {
		return 0, c.operationError("read", syscall.EOPNOTSUPP)
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

func (c *IPConn) readBatchMessage(message *SocketMessage, flags int, wait, consumeErrors bool, network **networkState) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return c.operationError("read", err)
	}
	n, datagram, truncated, err := c.readDatagramBuffers(message.Buffers, wait, consumeErrors, flags&MessageFlagPeek != 0, flags&MessageFlagTruncated != 0)
	if err != nil {
		return c.operationError("read", err)
	}
	var specDst netip.Addr
	if datagram.target.Is4() {
		if *network == nil {
			*network = c.stack.network.Load()
		}
		specDst = (*network).inboundIPv4PacketInfoSource(datagram.source, datagram.target)
	}
	control, err := controlMessageForRead(specDst, datagram.target, datagram.options)
	if err != nil {
		return c.operationError("read", err)
	}
	resultFlags := 0
	if truncated {
		resultFlags |= MessageFlagTruncated
	}
	oobn := copy(message.OOB, control)
	if oobn < len(control) {
		resultFlags |= MessageFlagControlTruncated
	}
	message.N, message.NN, message.Flags, message.Addr = n, oobn, resultFlags, ipNetAddr(datagram.source)
	return nil
}

func (c *IPConn) Read(buffer []byte) (int, error) {
	n, _, _, err := c.readDatagram(buffer, nil)
	if err != nil {
		return n, c.operationError("read", err)
	}
	return n, nil
}

func (c *IPConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	if getBuffer == nil {
		return 0, c.operationError("read", syscall.EINVAL)
	}
	n, _, _, err := c.readDatagram(nil, getBuffer)
	if err != nil {
		return n, c.operationError("read", err)
	}
	return n, nil
}

func (c *IPConn) readDatagram(buffer []byte, getBuffer func(sizeHint int) []byte) (n int, datagram ipDatagram, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		default:
		}
		if pending := c.errorState.takePending(); pending != nil {
			c.notifyReceiveLocked()
			c.mu.Unlock()
			return 0, ipDatagram{}, false, pending
		}
		queued, ok := c.receive.pop()
		if ok {
			datagram = queued
			c.queuedBytes -= ipDatagramMetadataSize + len(datagram.payload)
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
			return n, datagram, n < len(datagram.payload), nil
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

func (c *IPConn) readDatagramBuffers(buffers [][]byte, wait, consumeErrors, peek, returnLength bool) (n int, datagram ipDatagram, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		default:
		}
		if consumeErrors {
			if pending := c.errorState.takePending(); pending != nil {
				c.notifyReceiveLocked()
				c.mu.Unlock()
				return 0, ipDatagram{}, false, pending
			}
		}
		var queued ipDatagram
		var ok bool
		if peek {
			queued, ok = c.receive.peek()
		} else {
			queued, ok = c.receive.pop()
		}
		if ok {
			datagram = queued
			if !peek {
				c.queuedBytes -= ipDatagramMetadataSize + len(datagram.payload)
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
			return n, datagram, truncated, nil
		}
		if !wait {
			c.mu.Unlock()
			return 0, ipDatagram{}, false, syscall.EAGAIN
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

func (c *IPConn) readErrorBatch(messages []SocketMessage, flags int) (int, error) {
	for index := range messages {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", net.ErrClosed)
		default:
		}
		ok, err := c.errorState.readMessage(&messages[index], flags)
		if !ok {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", syscall.EAGAIN)
		}
		if err != nil {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", err)
		}
		c.notifyReceiveLocked()
		c.mu.Unlock()
	}
	return len(messages), nil
}

func (c *IPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	ipAddress, ok := address.(*net.IPAddr)
	if !ok {
		return 0, c.operationErrorTo("write", address, syscall.EINVAL)
	}
	return c.WriteToIP(payload, ipAddress)
}

func (c *IPConn) WriteToIP(payload []byte, address *net.IPAddr) (int, error) {
	netAddress := ipAddrNet(address)
	if c.remote.IsValid() {
		return 0, c.operationErrorTo("write", netAddress, net.ErrWriteToConnected)
	}
	target, err := ipAddr(address)
	if err != nil {
		return 0, c.operationErrorTo("write", netAddress, err)
	}
	var n int
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, target, netip.Addr{}, ipPacketOptions{})
	} else {
		n, err = c.writeTo(payload, target, netip.Addr{}, ipPacketOptions{})
	}
	if err != nil {
		return n, c.operationErrorTo("write", netAddress, err)
	}
	return n, nil
}

func (c *IPConn) Write(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", errors.New("mipstack: IP socket is not connected"))
	}
	var n int
	var err error
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, c.remote, netip.Addr{}, ipPacketOptions{})
	} else {
		n, err = c.writeTo(payload, c.remote, netip.Addr{}, ipPacketOptions{})
	}
	if err != nil {
		return n, c.operationError("write", err)
	}
	return n, nil
}

func (c *IPConn) WritePathMTUProbe(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", errors.New("mipstack: IP socket is not connected"))
	}
	if c.remote.IsMulticast() || c.stack.network.Load().broadcastDestination(c.remote) {
		return 0, c.operationError("write", syscall.EOPNOTSUPP)
	}
	n, err := c.writeToWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload)
	if err != nil {
		return n, c.operationError("write", err)
	}
	return n, nil
}

func (c *IPConn) WritePathMTUProbeTo(payload []byte, target netip.Addr) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationErrorTo("write", ipNetAddr(target), net.ErrWriteToConnected)
	}
	if target.IsMulticast() || c.stack.network.Load().broadcastDestination(target) {
		return 0, c.operationErrorTo("write", ipNetAddr(target), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload)
	if err != nil {
		return n, c.operationErrorTo("write", ipNetAddr(target), err)
	}
	return n, nil
}

func (c *IPConn) ConfirmPathMTU(mtu int) error {
	if !c.remote.IsValid() {
		return c.operationError("set", errors.New("mipstack: IP socket is not connected"))
	}
	if err := c.stack.ConfirmPathMTU(c.remote, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *IPConn) ConfirmPathMTUFor(target netip.Addr, mtu int) error {
	if c.remote.IsValid() {
		return c.setOperationError(net.ErrWriteToConnected)
	}
	if err := c.stack.ConfirmPathMTU(target, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *IPConn) WriteMsgIP(payload, oob []byte, address *net.IPAddr) (n, oobn int, err error) {
	netAddress := ipAddrNet(address)
	if c.remote.IsValid() {
		return 0, 0, c.operationErrorTo("write", netAddress, net.ErrWriteToConnected)
	}
	target, err := ipAddr(address)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	target, err = c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	if err = c.writeError(); err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	source, options, err := parseControlMessageForWrite(oob, target.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, target, source, options)
	} else {
		n, err = c.writeTo(payload, target, source, options)
	}
	if err != nil {
		return n, 0, c.operationErrorTo("write", netAddress, err)
	}
	return n, len(oob), nil
}

func (c *IPConn) WriteBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^MessageFlagDontWait != 0 {
		return 0, c.operationError("write", syscall.EOPNOTSUPP)
	}
	if c.ipHeaderIncludedOnWrite.Load() {
		return c.writeHeaderIncludedBatch(messages)
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

func (c *IPConn) writeBatchMessage(message *SocketMessage) (int, int, error) {
	var target netip.Addr
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationErrorTo("write", message.Addr, net.ErrWriteToConnected)
		}
		target = c.remote
	} else {
		address = message.Addr
		ipAddress, ok := address.(*net.IPAddr)
		if !ok || ipAddress == nil {
			return 0, 0, c.operationErrorTo("write", address, syscall.EINVAL)
		}
		var err error
		target, err = ipAddr(ipAddress)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	maximum := 65535
	if validated.Is4() {
		maximum -= 20
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	if payloadSize > maximum {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), syscall.EMSGSIZE)
	}
	if len(message.Buffers) == 1 {
		if err = c.writeError(); err != nil {
			return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
		}
		source, options, parseErr := parseControlMessageForWrite(message.OOB, validated.Is6())
		if parseErr != nil {
			return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), parseErr)
		}
		n, writeErr := c.writeToWith(message.Buffers[0], validated, source, options, c.writePayload)
		if writeErr != nil {
			return n, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), writeErr)
		}
		return n, len(message.OOB), nil
	}
	if err = c.writeError(); err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	n, err := c.writeBuffersTo(message.Buffers, payloadSize, validated, source, options)
	if err != nil {
		return n, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	return n, len(message.OOB), nil
}

func (c *IPConn) writeHeaderIncludedBatch(messages []SocketMessage) (int, error) {
	for index := range messages {
		message := &messages[index]
		n, oobn, err := c.writeHeaderIncludedBatchMessage(message)
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

func (c *IPConn) writeHeaderIncludedBatchMessage(message *SocketMessage) (int, int, error) {
	var target netip.Addr
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationErrorTo("write", message.Addr, net.ErrWriteToConnected)
		}
		target = c.remote
	} else {
		address = message.Addr
		ipAddress, ok := address.(*net.IPAddr)
		if !ok || ipAddress == nil {
			return 0, 0, c.operationErrorTo("write", address, syscall.EINVAL)
		}
		var err error
		target, err = ipAddr(ipAddress)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	if payloadSize > 65535 {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), syscall.EMSGSIZE)
	}
	if err = c.writeError(); err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	var payload []byte
	if len(message.Buffers) == 1 {
		payload = message.Buffers[0]
	} else {
		payload, err = gatherMessagePayload(message.Buffers, 65535)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
		}
	}
	n, err := c.writeHeaderIncluded(payload, validated, source, options)
	if err != nil {
		return n, 0, c.operationErrorTo("write", c.writeBatchErrorAddress(address), err)
	}
	return n, len(message.OOB), nil
}

func (c *IPConn) writeBatchErrorAddress(address net.Addr) net.Addr {
	if address != nil {
		return address
	}
	return c.remoteAddr()
}

func (c *IPConn) writeTo(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	return c.writeToWith(payload, target, packetInfoSource, options, c.writePayload)
}

func (c *IPConn) writeHeaderIncluded(input []byte, target, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options, true)
	if err != nil {
		return 0, err
	}
	if len(input) > c.stack.network.Load().mtu {
		return 0, syscall.EMSGSIZE
	}
	layout, err := parseHeaderIncludedPacket(input, parameters.source, parameters.target)
	if err != nil {
		return 0, err
	}
	if parameters.nonUnicast {
		c.mu.Lock()
		_, external, loopback, policyErr := nonUnicastOutputPolicy(parameters.target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, ipPacketOptions{hopLimit: layout.hopLimit, hopLimitSet: true})
		c.mu.Unlock()
		if policyErr != nil {
			return 0, policyErr
		}
		err = c.stack.tryWriteNonUnicastPacket(len(input), external, loopback, func(destination []byte) bool {
			c.marshalHeaderIncludedPacket(destination, input, layout)
			return true
		}, false)
	} else {
		queue, loopback := c.stack.outputQueueFor(parameters.target)
		var slot uint16
		slot, err = c.stack.tryReservePacket(queue)
		if err == ErrResourceLimit {
			slot, err = c.stack.replaceBestEffortPacket(queue)
		}
		if err == nil {
			var packet []byte
			var reusable bool
			if len(input) <= packetReusableBufferLimit {
				packet, reusable = queue.acquireBuffer(len(input))
			} else {
				packet, reusable = c.stack.acquireLargeOutputBuffer(len(input))
			}
			c.marshalHeaderIncludedPacket(packet, input, layout)
			if !queue.enqueueReservedPacket(slot, packet, reusable, false) {
				err = ErrClosed
			} else {
				c.stack.recordOutput(loopback)
			}
		}
	}
	if !parameters.nonUnicast && datagramWriteNeedsCorrelation(err) {
		c.rememberTarget(layout.packetTarget)
	}
	err = datagramLinkWriteError(err, parameters.receiveErrors)
	if err != nil {
		return 0, err
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(input)))
	return len(input), nil
}

type headerIncludedPacketLayout struct {
	packetTarget netip.Addr
	source       [4]byte
	headerSize   int
	hopLimit     byte
	ipv4         bool
	fillSource   bool
	fillID       bool
}

func parseHeaderIncludedPacket(input []byte, selectedSource, routeTarget netip.Addr) (headerIncludedPacketLayout, error) {
	if len(input) == 0 || !routeTarget.IsValid() {
		return headerIncludedPacketLayout{}, syscall.EINVAL
	}
	switch input[0] >> 4 {
	case 4:
		if !routeTarget.Is4() || len(input) < 20 || len(input) > 65535 {
			return headerIncludedPacketLayout{}, syscall.EINVAL
		}
		headerSize := int(input[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(input) {
			return headerIncludedPacketLayout{}, syscall.EINVAL
		}
		fillSource := binary.BigEndian.Uint32(input[12:16]) == 0
		var source [4]byte
		if fillSource {
			if !selectedSource.Is4() {
				return headerIncludedPacketLayout{}, syscall.EINVAL
			}
			source = selectedSource.As4()
		}
		return headerIncludedPacketLayout{
			packetTarget: netip.AddrFrom4([4]byte(input[16:20])), source: source,
			headerSize: headerSize, hopLimit: input[8], ipv4: true, fillSource: fillSource,
			fillID: binary.BigEndian.Uint16(input[4:6]) == 0,
		}, nil
	case 6:
		if !routeTarget.Is6() || len(input) < 40 {
			return headerIncludedPacketLayout{}, syscall.EINVAL
		}
		return headerIncludedPacketLayout{packetTarget: netip.AddrFrom16([16]byte(input[24:40])), hopLimit: input[7]}, nil
	default:
		return headerIncludedPacketLayout{}, syscall.EINVAL
	}
}

func (c *IPConn) marshalHeaderIncludedPacket(destination, input []byte, layout headerIncludedPacketLayout) {
	copy(destination, input)
	if !layout.ipv4 {
		return
	}
	if layout.fillSource {
		copy(destination[12:16], layout.source[:])
	}
	binary.BigEndian.PutUint16(destination[2:4], uint16(len(destination)))
	if layout.fillID {
		binary.BigEndian.PutUint16(destination[4:6], uint16(c.stack.ipv4ID.Add(1)))
	}
	destination[10], destination[11] = 0, 0
	binary.BigEndian.PutUint16(destination[10:12], checksum(destination[:layout.headerSize]))
}

func (c *IPConn) prepareWrite(target, packetInfoSource netip.Addr, options ipPacketOptions, headerIncluded bool) (ipWriteParameters, error) {
	target, err := c.validateWriteTarget(target)
	if err != nil {
		return ipWriteParameters{}, err
	}
	if err = c.writeError(); err != nil {
		return ipWriteParameters{}, err
	}
	options, pathMTUDiscovery, checksumOffset, receiveErrors, pendingErr := c.writeOptions(options, headerIncluded)
	if pendingErr != nil {
		return ipWriteParameters{}, pendingErr
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return ipWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	source, nonUnicast, err := c.stack.sourceForOutput(target, requestedSource)
	if err != nil {
		return ipWriteParameters{}, err
	}
	if !source.Is6() {
		checksumOffset = -1
	}
	return ipWriteParameters{
		source: source, target: target, options: options,
		pathMTUDiscovery: pathMTUDiscovery, checksumOffset: checksumOffset,
		receiveErrors: receiveErrors, nonUnicast: nonUnicast,
	}, nil
}

func setIPv6PayloadChecksum(payload []byte, source, target netip.Addr, protocol byte, offset int) error {
	if offset < 0 || !source.Is6() || !target.Is6() {
		return nil
	}
	if offset > len(payload)-2 {
		return syscall.EINVAL
	}
	payload[offset], payload[offset+1] = 0, 0
	value := transportChecksum(source, target, protocol, payload)
	if protocol == ProtocolUDP && value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(payload[offset:offset+2], value)
	return nil
}

func (c *IPConn) writeToWith(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions, write ipPayloadWriter) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options, false)
	if err != nil {
		return 0, err
	}
	if parameters.checksumOffset >= 0 {
		payload = append([]byte(nil), payload...)
		if err = setIPv6PayloadChecksum(payload, parameters.source, parameters.target, c.protocol, parameters.checksumOffset); err != nil {
			return 0, err
		}
	}
	linkErr := write(parameters.source, parameters.target, payload, parameters.options, parameters.pathMTUDiscovery, parameters.nonUnicast)
	if !parameters.nonUnicast && datagramWriteNeedsCorrelation(linkErr) {
		c.rememberTarget(parameters.target)
	}
	err = datagramLinkWriteError(linkErr, parameters.receiveErrors)
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, err
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

func (c *IPConn) writeBuffersTo(buffers [][]byte, payloadSize int, target, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options, false)
	if err != nil {
		return 0, err
	}
	maximum := 65535
	if parameters.target.Is4() {
		maximum -= 20
	}
	if payloadSize > maximum {
		return 0, syscall.EMSGSIZE
	}
	if parameters.nonUnicast {
		payload, gatherErr := gatherMessagePayload(buffers, maximum)
		if gatherErr != nil {
			return 0, gatherErr
		}
		if checksumErr := setIPv6PayloadChecksum(payload, parameters.source, parameters.target, c.protocol, parameters.checksumOffset); checksumErr != nil {
			return 0, checksumErr
		}
		err = c.writeNonUnicastPayload(parameters.source, parameters.target, payload, parameters.options, parameters.pathMTUDiscovery)
	} else {
		mtu, fragmentation := c.stack.pathMTUOutputPolicy(parameters.target, parameters.pathMTUDiscovery)
		err = c.writePayloadBuffersForMTU(parameters.source, parameters.target, buffers, payloadSize, parameters.options, fragmentation, mtu, parameters.checksumOffset)
	}
	if !parameters.nonUnicast && datagramWriteNeedsCorrelation(err) {
		c.rememberTarget(parameters.target)
	}
	err = datagramLinkWriteError(err, parameters.receiveErrors)
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, err
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(payloadSize))
	return payloadSize, nil
}

func (c *IPConn) writePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast bool) error {
	if nonUnicast {
		return c.writeNonUnicastPayload(source, target, payload, options, pathMTUDiscovery)
	}
	mtu, fragmentation := c.stack.pathMTUOutputPolicy(target, pathMTUDiscovery)
	return c.stack.tryWriteIPSocketPayloadForMTU(source, target, c.protocol, payload, fragmentation, options, mtu)
}

func (c *IPConn) writePayloadBuffersForMTU(source, target netip.Addr, buffers [][]byte, payloadSize int, options ipPacketOptions, fragmentation sourceFragmentation, mtu, checksumOffset int) error {
	headerSize := ipHeaderSize(source, target, payloadSize)
	if headerSize == 0 {
		return syscall.EMSGSIZE
	}
	if headerSize+payloadSize > mtu {
		if !fragmentation.allow {
			return syscall.EMSGSIZE
		}
		payload, err := gatherMessagePayload(buffers, payloadSize)
		if err != nil {
			return err
		}
		if err = setIPv6PayloadChecksum(payload, source, target, c.protocol, checksumOffset); err != nil {
			return err
		}
		return c.stack.tryWriteIPSocketPayloadForMTU(source, target, c.protocol, payload, fragmentation, options, mtu)
	}
	if source.Is6() && !options.flowLabelSet {
		var prefix [6]byte
		prefixSize := copyMessageBuffers(prefix[:], buffers)
		options.flowLabel = c.stack.automaticFlowLabel(source, target, c.protocol, prefix[:prefixSize])
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
	packetSize := headerSize + payloadSize
	var packet []byte
	var reusable bool
	if packetSize <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(packetSize)
	} else {
		packet, reusable = c.stack.acquireLargeOutputBuffer(packetSize)
	}
	if !marshalIPHeader(packet, source, target, c.protocol, identification, fragmentation.dontFragment, options) {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	payload := packet[headerSize:]
	if copied := copyMessageBuffers(payload, buffers); copied != payloadSize {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EINVAL
	}
	if err = setIPv6PayloadChecksum(payload, source, target, c.protocol, checksumOffset); err != nil {
		c.stack.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		return err
	}
	if !queue.enqueueReservedPacket(slot, packet, reusable, false) {
		return ErrClosed
	}
	c.stack.recordOutput(loopback)
	return nil
}

func (c *IPConn) writePathMTUProbePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, _ PathMTUDiscovery, _ bool) error {
	return c.stack.tryWriteIPSocketPayloadForMTU(source, target, c.protocol, payload, sourceFragmentation{dontFragment: true}, options, c.stack.network.Load().mtu)
}

func (c *IPConn) Close() error {
	if c.stack.closeIP(c) {
		return nil
	}
	return c.operationError("close", net.ErrClosed)
}

func (c *IPConn) closeFromStack() {
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
	c.recentTargets = recentDestinationCache[netip.Addr]{}
	c.icmpFilter = nil
	close(c.closed)
	c.mu.Unlock()
}

func (c *IPConn) LocalAddr() net.Addr { return ipNetAddr(c.local) }

func (c *IPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

func (c *IPConn) Info() IPConnInfo {
	c.mu.Lock()
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
	info := IPConnInfo{
		LocalAddress: c.local, RemoteAddress: c.remote, Protocol: c.protocol,
		IPHeaderIncludedOnWrite: c.ipHeaderIncludedOnWrite.Load(), IPHeaderIncludedOnRead: c.ipHeaderIncludedOnRead,
		ReceiveQueuePackets: c.receive.len(), ReceiveQueueBytes: c.queuedBytes, ReceiveQueueCapacity: c.receiveCapacity,
		ReceiveErrors: c.receiveErrors, ErrorQueueEntries: errorEntries, ErrorQueueBytes: errorBytes,
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
		PathMTUDiscovery:  c.pathMTUDiscovery,
		MulticastHopLimit: int(c.multicastHopLimit), MulticastLoopback: c.multicastLoopback, Broadcast: c.broadcast,
		FlowLabel: flowLabel,
		LastError: lastError, ICMPErrors: icmpErrors, ErrorsDropped: errorsDropped,
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
	if c.remote.IsValid() && !c.remote.IsMulticast() && !c.stack.network.Load().broadcastDestination(c.remote) {
		info.PathMTU = c.stack.mtuFor(c.remote)
	}
	return info
}

func (c *IPConn) SetIPHeaderIncludedOnWrite(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.ipHeaderIncludedOnWrite.Store(enabled)
		return nil
	}
}

func (c *IPConn) SetICMPv4Filter(filter ICMPv4Filter) error {
	if c.v6 && !c.dual {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv4 {
		return c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			if filter == (ICMPv4Filter{}) {
				return nil
			}
			c.icmpFilter = &ipConnICMPFilter{}
		}
		c.icmpFilter.blocked[0] = filter.blocked
		if filter == (ICMPv4Filter{}) {
			c.icmpFilter = nil
		}
		return nil
	}
}

func (c *IPConn) ICMPv4Filter() (ICMPv4Filter, error) {
	if c.v6 && !c.dual {
		return ICMPv4Filter{}, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv4 {
		return ICMPv4Filter{}, c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ICMPv4Filter{}, c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			return ICMPv4Filter{}, nil
		}
		return ICMPv4Filter{blocked: c.icmpFilter.blocked[0]}, nil
	}
}

func (c *IPConn) SetICMPv6Filter(filter ICMPv6Filter) error {
	if !c.v6 {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv6 {
		return c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			if filter == (ICMPv6Filter{}) {
				return nil
			}
			c.icmpFilter = &ipConnICMPFilter{}
		}
		c.icmpFilter.blocked = filter.blocked
		if filter == (ICMPv6Filter{}) {
			c.icmpFilter = nil
		}
		return nil
	}
}

func (c *IPConn) ICMPv6Filter() (ICMPv6Filter, error) {
	if !c.v6 {
		return ICMPv6Filter{}, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv6 {
		return ICMPv6Filter{}, c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ICMPv6Filter{}, c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			return ICMPv6Filter{}, nil
		}
		return ICMPv6Filter{blocked: c.icmpFilter.blocked}, nil
	}
}

func (c *IPConn) SetIPv6Checksum(enabled bool, offset int) error {
	if !c.v6 {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol == ProtocolICMPv6 || enabled && (offset < 0 || offset&1 != 0) {
		return c.setOperationError(syscall.EINVAL)
	}
	if !enabled {
		offset = -1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.ipv6ChecksumOffset = offset
		return nil
	}
}

func (c *IPConn) IPv6Checksum() (enabled bool, offset int, err error) {
	if !c.v6 {
		return false, 0, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, 0, c.setOperationError(net.ErrClosed)
	default:
		if c.ipv6ChecksumOffset < 0 {
			return false, 0, nil
		}
		return true, c.ipv6ChecksumOffset, nil
	}
}

func (c *IPConn) remoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return ipNetAddr(c.remote)
}

func (c *IPConn) SetDeadline(deadline time.Time) error {
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

func (c *IPConn) SetReadDeadline(deadline time.Time) error {
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

func (c *IPConn) SetWriteDeadline(deadline time.Time) error {
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

func (c *IPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	if bytes < ipDatagramMetadataSize {
		bytes = ipDatagramMetadataSize
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

func (c *IPConn) SetReceiveErrors(enabled bool) error {
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

func (c *IPConn) ReceiveErrors() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.receiveErrors, nil
	}
}

func (c *IPConn) ReadError() (*net.OpError, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, c.operationError("read", net.ErrClosed)
	default:
	}
	queued, ok := c.errorState.pop()
	if !ok {
		c.mu.Unlock()
		return nil, c.operationError("read", syscall.EAGAIN)
	}
	c.notifyReceiveLocked()
	c.mu.Unlock()
	return queued.err, nil
}

func (c *IPConn) SetWriteBuffer(bytes int) error {
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

func (c *IPConn) SetPathMTUDiscovery(mode PathMTUDiscovery) error {
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

func (c *IPConn) PathMTUDiscovery() (PathMTUDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return PathMTUDiscoveryDont, c.setOperationError(net.ErrClosed)
	default:
		return c.pathMTUDiscovery, nil
	}
}

func (c *IPConn) SetHopLimit(hopLimit int) error {
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

func (c *IPConn) SetTrafficClass(value int) error {
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

func (c *IPConn) SetFlowLabel(label uint32) error {
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

func (c *IPConn) rememberTarget(target netip.Addr) {
	target = target.Unmap()
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

func (c *IPConn) acceptsError(target netip.Addr) bool {
	target = target.Unmap()
	if c.remote.IsValid() {
		return target == c.remote
	}
	c.mu.Lock()
	exists := c.recentTargets.contains(target, monotonicStampAt(c.stack.timestampEpoch, time.Now()))
	c.mu.Unlock()
	return exists
}

func (c *IPConn) acceptsPathMTU() bool {
	c.mu.Lock()
	accepted := c.pathMTUDiscovery.acceptsPathMTU()
	c.mu.Unlock()
	return accepted
}

func (c *IPConn) deliverError(target netip.Addr, networkError ICMPError) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	pending, queued := linuxDatagramICMPReport(networkError, c.remote.IsValid(), c.receiveErrors, true, c.pathMTUDiscovery)
	if !pending {
		c.mu.Unlock()
		return
	}
	operationError := &net.OpError{
		Op: "read", Net: c.net, Source: c.LocalAddr(), Addr: ipNetAddr(target), Err: networkError,
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
	payload := networkError.QuotedPayload
	if c.ipHeaderIncludedOnWrite.Load() && len(networkError.QuotedPacket) != 0 {
		payload = networkError.QuotedPacket
	}
	errorState.push(queuedSocketError{err: operationError, payload: payload, size: size})
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

func (c *IPConn) writeOptions(options ipPacketOptions, headerIncluded bool) (ipPacketOptions, PathMTUDiscovery, int, bool, error) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	pathMTUDiscovery := c.pathMTUDiscovery
	checksumOffset := c.ipv6ChecksumOffset
	receiveErrors := c.receiveErrors
	var pending *net.OpError
	if headerIncluded {
		pending = c.errorState.takePending()
	}
	if pending != nil {
		c.notifyReceiveLocked()
	}
	c.mu.Unlock()
	if pending != nil {
		return options, pathMTUDiscovery, checksumOffset, receiveErrors, pending.Err
	}
	return options, pathMTUDiscovery, checksumOffset, receiveErrors, nil
}

func (c *IPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), c.remoteAddr(), err)
}

func (c *IPConn) operationErrorTo(operation string, target net.Addr, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), target, err)
}

func (c *IPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net, nil, c.LocalAddr(), err)
}

func ipNetAddr(address netip.Addr) *net.IPAddr {
	if !address.IsValid() {
		return nil
	}
	return &net.IPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone()}
}

func ipAddrNet(address *net.IPAddr) net.Addr {
	if address == nil {
		return nil
	}
	return address
}

func ipAddr(address *net.IPAddr) (netip.Addr, error) {
	if address == nil || address.Zone != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	result, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return netip.Addr{}, syscall.EINVAL
	}
	result = result.Unmap()
	if !result.IsValid() || result.IsUnspecified() {
		return netip.Addr{}, syscall.EINVAL
	}
	return result, nil
}

func (c *IPConn) validateWriteTarget(target netip.Addr) (netip.Addr, error) {
	target = target.Unmap()
	if !target.IsValid() || target.IsUnspecified() || target.Zone() != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	if !c.dual && target.Is6() != c.v6 {
		family := "IPv4"
		if c.v6 {
			family = "IPv6"
		}
		return netip.Addr{}, &net.AddrError{Err: "non-" + family + " address", Addr: target.String()}
	}
	return target, nil
}

var _ net.Conn = (*IPConn)(nil)
var _ net.PacketConn = (*IPConn)(nil)

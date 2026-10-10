package mipstack

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
)

type ForwarderFlow struct {
	Source netip.AddrPort
	Destination netip.AddrPort
}

type TCPForwarderOptions struct {
	MaxInFlight int
}

type UDPForwarderOptions struct{}

type IPForwarderOptions struct{}

type ICMPForwarderOptions struct{}

type TCPForwarderHandler func(*TCPForwarderRequest)

type UDPForwarderHandler func(*UDPForwarderRequest)

type IPForwarderHandler func(*IPForwarderRequest)

type ICMPForwarderHandler func(*ICMPForwarderRequest)

type ForwarderInfo struct {
	Closed bool
	Pending int
	MaxInFlight int
	Requests uint64
	Accepted uint64
	Replies uint64
	ReplyErrors uint64
	Dropped uint64
	Rejected uint64
}

type forwarderRequestState uint32

const (
	forwarderRequestPending forwarderRequestState = iota
	forwarderRequestClaimed
	forwarderRequestReplyStarted
	forwarderRequestDetached
	forwarderRequestAccepted
	forwarderRequestDropped
	forwarderRequestRejected
	forwarderRequestCompleted
)

type forwarderResponderState uint32

const (
	forwarderResponderActive forwarderResponderState = iota
	forwarderResponderRepliesOnly
	forwarderResponderDropped
	forwarderResponderRejected
)

type forwarderDetachMode uint8

const (
	forwarderDetachWithInput forwarderDetachMode = iota
	forwarderDetachForReplies
)

type forwarderRuntime struct {
	stack  *Stack
	closed atomic.Bool
	done   chan struct{}

	requestCount atomic.Uint64
	accepted     atomic.Uint64
	replies      atomic.Uint64
	replyErrors  atomic.Uint64
	dropped      atomic.Uint64
	rejected     atomic.Uint64
}

func (f *forwarderRuntime) validateDestination(destination netip.Addr) error {
	if f.closed.Load() {
		return net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(destination) {
		return syscall.EADDRNOTAVAIL
	}
	return nil
}

func (f *forwarderRuntime) count(state forwarderRequestState) {
	switch state {
	case forwarderRequestAccepted:
		f.accepted.Add(1)
	case forwarderRequestDropped:
		f.dropped.Add(1)
	case forwarderRequestRejected:
		f.rejected.Add(1)
	}
}

func (f *forwarderRuntime) info(pending, maxInFlight int) ForwarderInfo {
	return ForwarderInfo{
		Closed:      f.closed.Load(),
		Pending:     pending,
		MaxInFlight: maxInFlight,
		Requests:    f.requestCount.Load(),
		Accepted:    f.accepted.Load(),
		Replies:     f.replies.Load(),
		ReplyErrors: f.replyErrors.Load(),
		Dropped:     f.dropped.Load(),
		Rejected:    f.rejected.Load(),
	}
}

func (f *forwarderRuntime) close() bool {
	if f.closed.Swap(true) {
		return false
	}
	close(f.done)
	return true
}

func (f *forwarderRuntime) Done() <-chan struct{} { return f.done }

type forwarderResponder struct {
	runtime *forwarderRuntime
	packet  ipPacket
	state   atomic.Uint32
}

func (r *forwarderResponder) beginReply() error {
	state := forwarderResponderState(r.state.Load())
	if state != forwarderResponderActive && state != forwarderResponderRepliesOnly {
		return net.ErrClosed
	}
	if err := r.runtime.validateDestination(r.packet.target); err != nil {
		r.runtime.replyErrors.Add(1)
		return err
	}
	return nil
}

func (r *forwarderResponder) beginInputReply() error {
	if forwarderResponderState(r.state.Load()) != forwarderResponderActive {
		return net.ErrClosed
	}
	if err := r.runtime.validateDestination(r.packet.target); err != nil {
		r.runtime.replyErrors.Add(1)
		return err
	}
	return nil
}

func (r *forwarderResponder) recordReply(err error) error {
	if err != nil {
		r.runtime.replyErrors.Add(1)
	} else {
		r.runtime.replies.Add(1)
	}
	return err
}

func (r *forwarderResponder) finish(state forwarderResponderState) error {
	if state != forwarderResponderDropped && state != forwarderResponderRejected {
		panic("invalid forwarder responder terminal state")
	}
	if !r.state.CompareAndSwap(uint32(forwarderResponderActive), uint32(state)) {
		return net.ErrClosed
	}
	switch state {
	case forwarderResponderDropped:
		r.runtime.dropped.Add(1)
	case forwarderResponderRejected:
		r.runtime.rejected.Add(1)
	}
	return nil
}

func (r *forwarderResponder) restrictToReplies() error {
	for {
		switch forwarderResponderState(r.state.Load()) {
		case forwarderResponderRepliesOnly:
			return nil
		case forwarderResponderActive:
			if r.state.CompareAndSwap(uint32(forwarderResponderActive), uint32(forwarderResponderRepliesOnly)) {
				return nil
			}
		default:
			return net.ErrClosed
		}
	}
}

func (r *forwarderResponder) beginReject() error {
	if err := r.finish(forwarderResponderRejected); err != nil {
		return err
	}
	return r.runtime.validateDestination(r.packet.target)
}

func (r *forwarderResponder) Drop() error {
	return r.finish(forwarderResponderDropped)
}

func (r *forwarderResponder) Done() <-chan struct{} { return r.runtime.done }

type TCPForwarder struct {
	*forwarderRuntime

	handler     TCPForwarderHandler
	maxInFlight int

	mu       sync.Mutex
	requests map[tcpKey]*TCPForwarderRequest
	handlers map[*TCPForwarderRequest]struct{}
}

type TCPForwarderRequest struct {
	forwarder  *TCPForwarder
	key        tcpKey
	segment    tcpSegment
	state      atomic.Uint32
	done       chan struct{}
	doneClosed atomic.Bool
}

type UDPForwarder struct {
	*forwarderRuntime

	handler UDPForwarderHandler

	mu       sync.Mutex
	requests map[udpFlowKey]*UDPForwarderRequest
}

type UDPForwarderRequest struct {
	forwarder *UDPForwarder
	flow      ForwarderFlow
	packet    ipPacket
	options   ipPacketOptions
	state     atomic.Uint32
}

type UDPForwarderResponder struct {
	forwarderResponder

	flow    ForwarderFlow
	payload []byte
}

type IPForwarderMessage struct {
	Source netip.Addr
	Destination netip.Addr
	Protocol uint8
	HopLimit uint8
	TrafficClass uint8
	FlowLabel uint32
	Payload []byte
}

type IPForwarder struct {
	*forwarderRuntime

	handler IPForwarderHandler

	mu       sync.Mutex
	requests map[*IPForwarderRequest]struct{}
}

type IPForwarderRequest struct {
	forwarder *IPForwarder
	packet    ipPacket
	state     atomic.Uint32
}

type IPForwarderResponder struct {
	forwarderResponder

	message IPForwarderMessage
}

type ICMPForwarderMessage struct {
	Source netip.Addr
	Destination netip.Addr
	Type uint8
	Code uint8
	Payload []byte
}

func (m ICMPForwarderMessage) ICMPMessage() (ICMPMessage, error) {
	if len(m.Payload) < 2 || m.Type != m.Payload[0] || m.Code != m.Payload[1] {
		return ICMPMessage{}, syscall.EINVAL
	}
	protocol := ProtocolICMPv4
	if m.Source.Unmap().Is6() {
		protocol = ProtocolICMPv6
	}
	return (IPPacket{
		Source: m.Source, Destination: m.Destination,
		Protocol: protocol, Payload: m.Payload,
	}).ICMPMessage()
}

func (m *ICMPForwarderMessage) SetICMPMessage(message ICMPMessage) error {
	if m == nil {
		return syscall.EINVAL
	}
	normalized, totalSize, err := message.wireLayout()
	if err != nil {
		return err
	}
	payload := extendForAppend(m.Payload[:0], totalSize)
	marshalPublicICMPMessage(payload, normalized)
	*m = ICMPForwarderMessage{
		Source: normalized.Source, Destination: normalized.Destination,
		Type: normalized.Type, Code: normalized.Code, Payload: payload,
	}
	return nil
}

func (m ICMPForwarderMessage) IsEchoRequest() bool {
	if len(m.Payload) < 2 || m.Type != m.Payload[0] || m.Code != m.Payload[1] {
		return false
	}
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return false
	}
	request, valid := classifyICMPEcho(protocol, m.Payload[0], m.Payload[1], len(m.Payload)-4)
	return valid && request
}

type ICMPForwarder struct {
	*forwarderRuntime

	handler ICMPForwarderHandler

	mu       sync.Mutex
	requests map[*ICMPForwarderRequest]struct{}
}

type ICMPForwarderRequest struct {
	forwarder *ICMPForwarder
	packet    ipPacket
	state     atomic.Uint32
}

type ICMPForwarderResponder struct {
	forwarderResponder

	message      ICMPForwarderMessage
	rejectPacket ipPacket
	rejectable   bool
}

type tcpForwarderEndpoints interface {
	handleSegment(segment tcpSegment, key tcpKey) bool
	handleTimeWaitSegment(segment tcpSegment, key tcpKey) bool
	updateConfig(network *networkState)
	closeFromStack()
}

type udpForwarderEndpoints interface {
	handlePacket(packet ipPacket, flow ForwarderFlow, options ipPacketOptions) bool
	updateConfig(network *networkState)
	closeFromStack()
}

type ipForwarderEndpoints interface {
	handlePacket(packet ipPacket) bool
	updateConfig(network *networkState)
	closeFromStack()
}

type icmpForwarderEndpoints interface {
	handlePacket(packet ipPacket) bool
	updateConfig(network *networkState)
	closeFromStack()
}

func NewTCPForwarder(stack *Stack, options TCPForwarderOptions, handler TCPForwarderHandler) (*TCPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	if options.MaxInFlight < 0 {
		return nil, syscall.EINVAL
	}
	maximum := options.MaxInFlight
	if maximum == 0 {
		maximum = stack.network.Load().tcpDefaults.SYNBacklog
	}
	forwarder := &TCPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		maxInFlight:      maximum,
		requests:         make(map[tcpKey]*TCPForwarderRequest),
		handlers:         make(map[*TCPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.tcpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.tcpForwarder = forwarder
	stack.tcpTimeWaitReplacer = replaceTCPTimeWait
	return forwarder, nil
}

func NewUDPForwarder(stack *Stack, options UDPForwarderOptions, handler UDPForwarderHandler) (*UDPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &UDPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[udpFlowKey]*UDPForwarderRequest),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.udpForwarder = forwarder
	return forwarder, nil
}

func NewIPForwarder(stack *Stack, options IPForwarderOptions, handler IPForwarderHandler) (*IPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &IPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[*IPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.ipForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.ipForwarder = forwarder
	return forwarder, nil
}

func NewICMPForwarder(stack *Stack, options ICMPForwarderOptions, handler ICMPForwarderHandler) (*ICMPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &ICMPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[*ICMPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.icmpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.icmpForwarder = forwarder
	return forwarder, nil
}

func (r *TCPForwarderRequest) Flow() ForwarderFlow {
	return ForwarderFlow{Source: r.key.remote, Destination: r.key.local}
}

func (r *TCPForwarderRequest) Done() <-chan struct{} { return r.done }

func (r *TCPForwarderRequest) closeDone() {
	if r.doneClosed.CompareAndSwap(false, true) {
		close(r.done)
	}
}

func (r *TCPForwarderRequest) Accept(ctx context.Context, options ...SocketOption) (*TCPConn, error) {
	if ctx == nil {
		panic("nil Context")
	}
	parsed, err := parseSocketOptions(options, socketOptionTCPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionTCPDial, r.key.local.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if !r.claim() {
		return nil, ErrForwarderRequestCompleted
	}
	connection, result, err := r.forwarder.acceptTCP(r, parsed.tcp)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	select {
	case err = <-result:
		if err != nil {
			r.finish(forwarderRequestDropped)
			return nil, err
		}
		r.finish(forwarderRequestAccepted)
		return connection, nil
	case <-ctx.Done():
		connection.abort(ctx.Err())
		r.finish(forwarderRequestDropped)
		return nil, ctx.Err()
	case <-r.forwarder.stack.closeCh:
		connection.abortWithoutReset(ErrClosed)
		r.finish(forwarderRequestDropped)
		return nil, ErrClosed
	}
}

func (r *TCPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

func (r *TCPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.rejectTCPSegment(r.key, r.segment)
}

func (r *UDPForwarderRequest) Flow() ForwarderFlow { return r.flow }

func (r *UDPForwarderRequest) Payload() []byte { return r.packet.payload[udpHeaderSize:] }

func (r *UDPForwarderRequest) Accept(options ...SocketOption) (*UDPConn, error) {
	parsed, err := parseSocketOptions(options, socketOptionUDPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionUDPDial, r.flow.Destination.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if _, ok := r.claim(); !ok {
		return nil, ErrForwarderRequestCompleted
	}
	connection, err := r.forwarder.acceptUDP(r, parsed.datagram)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	r.finish(forwarderRequestAccepted)
	return connection, nil
}

func (r *UDPForwarderRequest) Listen(options ...SocketOption) (*UDPConn, error) {
	parsed, err := parseSocketOptions(options, socketOptionUDPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionUDPDial, r.flow.Destination.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if _, ok := r.claim(); !ok {
		return nil, ErrForwarderRequestCompleted
	}
	connection, err := r.forwarder.listenUDP(r, parsed.datagram)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	r.finish(forwarderRequestAccepted)
	return connection, nil
}

func (r *UDPForwarderRequest) Reply(payload []byte) (int, error) {
	return r.replyFrom(payload, r.flow.Destination)
}

func (r *UDPForwarderRequest) ReplyFrom(payload []byte, source netip.AddrPort) (int, error) {
	return r.replyFrom(payload, source)
}

func (r *UDPForwarderRequest) replyFrom(payload []byte, source netip.AddrPort) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	validated, err := validateUDPForwarderReply(r.flow, payload, source)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return 0, err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return 0, net.ErrClosed
	}
	n, err := r.forwarder.replyUDPFlow(r.flow, payload, validated)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return n, err
	}
	r.forwarder.replies.Add(1)
	return n, nil
}

func (r *UDPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

func (r *UDPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendPortUnreachable(r.packet)
}

func (r *IPForwarderRequest) Message() IPForwarderMessage {
	return ipForwarderMessage(r.packet, r.packet.payload)
}

func (r *IPForwarderRequest) Reply(payload []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	err := r.forwarder.replyIPPayload(r.packet, payload)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

func (r *IPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

func (r *IPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendProtocolUnreachable(r.packet)
}

func (r *ICMPForwarderRequest) Message() ICMPForwarderMessage {
	return ICMPForwarderMessage{
		Source: r.packet.source, Destination: r.packet.target,
		Type: r.packet.payload[0], Code: r.packet.payload[1], Payload: r.packet.payload,
	}
}

func (r *ICMPForwarderRequest) IPPacket() []byte { return r.packet.original }

func (r *ICMPForwarderRequest) Reply(payload []byte) error {
	return r.reply(payload, false)
}

func (r *ICMPForwarderRequest) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.writeReply(payload, owned)
}

func (r *ICMPForwarderRequest) writeReply(payload []byte, owned bool) error {
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	var err error
	if owned {
		err = r.forwarder.stack.writeOwnedICMPReply(r.packet, payload)
	} else {
		err = r.forwarder.stack.writeICMPReply(r.packet, payload)
	}
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

func (r *ICMPForwarderRequest) ReplyIPPacket(packet []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, err := prepareICMPForwarderIPPacket(packet, r.packet.source)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	if err = r.forwarder.stack.writeICMPForwarderIPPacket(r.packet, reply); err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

func (r *ICMPForwarderRequest) ReplyEcho() error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.packet.payload)
	if !ok {
		r.forwarder.replyErrors.Add(1)
		return syscall.EINVAL
	}
	return r.writeReply(reply, true)
}

func (r *ICMPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

func (r *ICMPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendAdministrativeUnreachable(r.packet)
}

func (f *TCPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.tcpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.tcpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

func (f *UDPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.udpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.udpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

func (f *IPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.ipForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.ipForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

func (f *ICMPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.icmpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.icmpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

func (f *TCPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, f.maxInFlight)
}

func (f *UDPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

func (f *IPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

func (f *ICMPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

func (f *TCPForwarder) admitSegment(segment tcpSegment, key tcpKey) (handled, admitted bool) {
	if key.remote.Port() == 0 || segment.flags&TCPFlagSYN == 0 || segment.flags&(TCPFlagACK|TCPFlagRST|TCPFlagFIN) != 0 {
		return false, false
	}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false, false
	}
	if _, exists := f.requests[key]; exists {
		f.mu.Unlock()
		return true, true
	}
	if len(f.requests) >= f.maxInFlight {
		f.dropped.Add(1)
		f.mu.Unlock()
		f.stack.stats.inboundDroppedPackets.Add(1)
		return true, false
	}
	request := &TCPForwarderRequest{forwarder: f, key: key, segment: segment, done: make(chan struct{})}
	f.requests[key] = request
	f.handlers[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	go func() {
		defer func() {
			_ = request.Drop()
			request.closeDone()
			f.removeHandler(request)
		}()
		f.handler(request)
	}()
	return true, true
}

func (f *TCPForwarder) handleSegment(segment tcpSegment, key tcpKey) bool {
	handled, _ := f.admitSegment(segment, key)
	return handled
}

func (f *TCPForwarder) handleTimeWaitSegment(segment tcpSegment, key tcpKey) bool {
	_, admitted := f.admitSegment(segment, key)
	return admitted
}

func (f *UDPForwarder) handlePacket(packet ipPacket, flow ForwarderFlow, options ipPacketOptions) bool {
	key := udpFlowKey{local: flow.Destination, remote: flow.Source}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	if _, exists := f.requests[key]; exists {
		f.dropped.Add(1)
		f.mu.Unlock()
		f.stack.stats.inboundDroppedPackets.Add(1)
		return true
	}
	request := &UDPForwarderRequest{forwarder: f, flow: flow, packet: packet, options: options}
	f.requests[key] = request
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

func (f *IPForwarder) handlePacket(packet ipPacket) bool {
	request := &IPForwarderRequest{forwarder: f, packet: packet}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	f.requests[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

func (f *ICMPForwarder) handlePacket(packet ipPacket) bool {
	request := &ICMPForwarderRequest{forwarder: f, packet: packet}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	f.requests[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

func (r *TCPForwarderRequest) claim() bool {
	return r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestClaimed))
}

func (r *TCPForwarderRequest) complete(state forwarderRequestState) bool {
	if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(state)) {
		return false
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

func (r *TCPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

func (f *TCPForwarder) remove(request *TCPForwarderRequest) {
	f.mu.Lock()
	if f.requests[request.key] == request {
		delete(f.requests, request.key)
	}
	f.mu.Unlock()
}

func (f *TCPForwarder) removeHandler(request *TCPForwarderRequest) {
	f.mu.Lock()
	delete(f.handlers, request)
	f.mu.Unlock()
}

func (r *UDPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

func (r *UDPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

func (r *UDPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

func (r *UDPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

func (r *UDPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

func (f *UDPForwarder) remove(request *UDPForwarderRequest) {
	key := udpFlowKey{local: request.flow.Destination, remote: request.flow.Source}
	f.mu.Lock()
	if f.requests[key] == request {
		delete(f.requests, key)
	}
	f.mu.Unlock()
}

func (r *IPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

func (r *IPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

func (r *IPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

func (r *IPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

func (r *IPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

func (f *IPForwarder) remove(request *IPForwarderRequest) {
	f.mu.Lock()
	delete(f.requests, request)
	f.mu.Unlock()
}

func (r *ICMPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

func (r *ICMPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

func (r *ICMPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

func (r *ICMPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

func (r *ICMPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

func (f *ICMPForwarder) remove(request *ICMPForwarderRequest) {
	f.mu.Lock()
	delete(f.requests, request)
	f.mu.Unlock()
}

func (f *TCPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for key, request := range f.requests {
		if network.acceptsInboundDestination(key.local.Addr()) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, key)
			f.dropped.Add(1)
			request.closeDone()
		}
	}
	f.mu.Unlock()
}

func (f *UDPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for key, request := range f.requests {
		if network.acceptsInboundDestination(key.local.Addr()) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, key)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, key)
		}
	}
	f.mu.Unlock()
}

func (f *IPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for request := range f.requests {
		if network.acceptsInboundDestination(request.packet.target) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, request)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, request)
		}
	}
	f.mu.Unlock()
}

func (f *ICMPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for request := range f.requests {
		if network.acceptsInboundDestination(request.packet.target) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, request)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, request)
		}
	}
	f.mu.Unlock()
}

func (f *TCPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*TCPForwarderRequest, 0, len(f.requests))
	for _, request := range f.requests {
		requests = append(requests, request)
	}
	handlers := make([]*TCPForwarderRequest, 0, len(f.handlers))
	for request := range f.handlers {
		handlers = append(handlers, request)
	}
	f.requests = nil
	f.handlers = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		}
	}
	for _, request := range handlers {
		request.closeDone()
	}
}

func (f *UDPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*UDPForwarderRequest, 0, len(f.requests))
	for _, request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

func (f *IPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*IPForwarderRequest, 0, len(f.requests))
	for request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

func (f *ICMPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*ICMPForwarderRequest, 0, len(f.requests))
	for request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

func (r *UDPForwarderRequest) Detach() (*UDPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func (r *UDPForwarderRequest) DetachForReplies() (*UDPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func copyForwarderRejectPacket(packet ipPacket) ipPacket {
	quoteLength := len(packet.original)
	if packet.source.Is4() {
		headerLength := int(packet.original[0]&0x0f) * 4
		if quoteLength > headerLength+8 {
			quoteLength = headerLength + 8
		}
	} else if maximum := ipv6MinimumMTU - 48; quoteLength > maximum {
		quoteLength = maximum
	}
	packet.payload = nil
	packet.original = append([]byte(nil), packet.original[:quoteLength]...)
	return packet
}

func copyForwarderPacket(packet ipPacket) ipPacket {
	original := append([]byte(nil), packet.original...)
	copied, ok := parseIPPacket(original, true)
	if !ok || copied.parameterError {
		return ipPacket{}
	}
	return copied
}

func (f *UDPForwarder) detach(request *UDPForwarderRequest, mode forwarderDetachMode) (*UDPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.flow.Destination.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	var payload []byte
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderRejectPacket(packet)
		payload = append([]byte(nil), request.Payload()...)
	}
	responder := &UDPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		flow:    request.flow,
		payload: payload,
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	}
	key := udpFlowKey{local: request.flow.Destination, remote: request.flow.Source}
	if f.requests[key] == request {
		delete(f.requests, key)
	}
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

func (r *UDPForwarderResponder) Flow() ForwarderFlow { return r.flow }

func (r *UDPForwarderResponder) Payload() []byte { return r.payload }

func (r *UDPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	return nil
}

func (r *UDPForwarderResponder) Reply(payload []byte) (int, error) {
	return r.replyFrom(payload, r.flow.Destination)
}

func (r *UDPForwarderResponder) ReplyFrom(payload []byte, source netip.AddrPort) (int, error) {
	return r.replyFrom(payload, source)
}

func (r *UDPForwarderResponder) replyFrom(payload []byte, source netip.AddrPort) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	validated, err := validateUDPForwarderReply(r.flow, payload, source)
	if err != nil {
		return 0, r.recordReply(err)
	}
	n, err := r.runtime.replyUDPFlow(r.flow, payload, validated)
	return n, r.recordReply(err)
}

func (r *UDPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	return r.runtime.stack.sendPortUnreachable(r.packet)
}

func (r *UDPForwarderResponder) RejectFlow() error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.recordReply(r.runtime.stack.sendPortUnreachable(ipPacket{
		source:   r.flow.Source.Addr(),
		target:   r.flow.Destination.Addr(),
		original: flowUDPQuote(r.flow),
	}))
}

func flowUDPQuote(flow ForwarderFlow) []byte {
	source, target := flow.Source.Addr(), flow.Destination.Addr()
	var quote, udp []byte
	if source.Is4() {
		quote = make([]byte, 20+udpHeaderSize)
		quote[0] = 0x45
		binary.BigEndian.PutUint16(quote[2:], uint16(len(quote)))
		quote[8] = 64
		quote[9] = ProtocolUDP
		s4, t4 := source.As4(), target.As4()
		copy(quote[12:16], s4[:])
		copy(quote[16:20], t4[:])
		binary.BigEndian.PutUint16(quote[10:], checksum(quote[:20]))
		udp = quote[20:]
	} else {
		quote = make([]byte, 40+udpHeaderSize)
		quote[0] = 0x60
		binary.BigEndian.PutUint16(quote[4:], udpHeaderSize)
		quote[6] = ProtocolUDP
		quote[7] = 64
		s16, t16 := source.As16(), target.As16()
		copy(quote[8:24], s16[:])
		copy(quote[24:40], t16[:])
		udp = quote[40:]
	}
	binary.BigEndian.PutUint16(udp[0:], flow.Source.Port())
	binary.BigEndian.PutUint16(udp[2:], flow.Destination.Port())
	binary.BigEndian.PutUint16(udp[4:], udpHeaderSize)
	return quote
}

func (r *IPForwarderRequest) Detach() (*IPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func (r *IPForwarderRequest) DetachForReplies() (*IPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func (f *IPForwarder) detach(request *IPForwarderRequest, mode forwarderDetachMode) (*IPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.packet.target) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	var payload []byte
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderRejectPacket(packet)
		payload = append([]byte(nil), request.packet.payload...)
	}
	responder := &IPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		message: ipForwarderMessage(packet, payload),
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	}
	delete(f.requests, request)
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

func ipForwarderMessage(packet ipPacket, payload []byte) IPForwarderMessage {
	return IPForwarderMessage{
		Source: packet.source, Destination: packet.target, Protocol: packet.protocol,
		HopLimit: packet.hopLimit, TrafficClass: packet.trafficClass,
		FlowLabel: packet.flowLabel, Payload: payload,
	}
}

func (f *forwarderRuntime) replyIPPayload(packet ipPacket, payload []byte) error {
	network := f.stack.network.Load()
	if !network.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := network.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	defaults := network.ipDefaults.DatagramSocketDefaults
	options := ipPacketOptions{
		hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
		flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
	}
	mtu, fragmentation := f.stack.pathMTUOutputPolicy(packet.source, defaults.PathMTUDiscovery)
	return f.stack.writeBestEffortIPPayloadForMTU(packet.target, packet.source, packet.protocol, payload, fragmentation, options, mtu, false)
}

func (r *IPForwarderResponder) Message() IPForwarderMessage { return r.message }

func (r *IPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.message.Payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	return nil
}

func (r *IPForwarderResponder) Reply(payload []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.recordReply(r.runtime.replyIPPayload(r.packet, payload))
}

func (r *IPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	return r.runtime.stack.sendProtocolUnreachable(r.packet)
}

func (r *ICMPForwarderRequest) Detach() (*ICMPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func (r *ICMPForwarderRequest) DetachForReplies() (*ICMPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

func (f *ICMPForwarder) detach(request *ICMPForwarderRequest, mode forwarderDetachMode) (*ICMPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.packet.target) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderPacket(packet)
		if len(packet.original) == 0 {
			return nil, syscall.EINVAL
		}
	}
	responder := &ICMPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		message: ICMPForwarderMessage{
			Source: packet.source, Destination: packet.target,
			Type: request.packet.payload[0], Code: request.packet.payload[1], Payload: packet.payload,
		},
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	} else {
		responder.rejectPacket = copyForwarderRejectPacket(request.packet)
		responder.rejectable = !packetInvokesICMPError(request.packet.original)
	}
	delete(f.requests, request)
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

func (r *ICMPForwarderResponder) Message() ICMPForwarderMessage { return r.message }

func (r *ICMPForwarderResponder) IPPacket() []byte { return r.packet.original }

func (r *ICMPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.message.Payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	r.rejectPacket = ipPacket{}
	r.rejectable = false
	return nil
}

func (r *ICMPForwarderResponder) Reply(payload []byte) error {
	return r.reply(payload, false)
}

func (r *ICMPForwarderResponder) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.writeReply(payload, owned)
}

func (r *ICMPForwarderResponder) writeReply(payload []byte, owned bool) error {
	var err error
	if owned {
		err = r.runtime.stack.writeOwnedICMPReply(r.packet, payload)
	} else {
		err = r.runtime.stack.writeICMPReply(r.packet, payload)
	}
	return r.recordReply(err)
}

func (r *ICMPForwarderResponder) ReplyIPPacket(packet []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, err := prepareICMPForwarderIPPacket(packet, r.packet.source)
	if err != nil {
		return r.recordReply(err)
	}
	return r.recordReply(r.runtime.stack.writeICMPForwarderIPPacket(r.packet, reply))
}

func (r *ICMPForwarderResponder) ReplyEcho() error {
	if err := r.beginInputReply(); err != nil {
		return err
	}
	if !r.message.IsEchoRequest() {
		return r.recordReply(syscall.EINVAL)
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.message.Payload)
	if !ok {
		return r.recordReply(syscall.EINVAL)
	}
	return r.writeReply(reply, true)
}

func (r *ICMPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	var err error
	if r.rejectable {
		err = r.runtime.stack.sendAdministrativeUnreachable(r.rejectPacket)
	}
	return err
}

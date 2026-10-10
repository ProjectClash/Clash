// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"container/heap"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sleep"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/ports"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type EndpointState tcpip.EndpointState

const (
	_ EndpointState = iota
	StateEstablished
	StateSynSent
	StateSynRecv
	StateFinWait1
	StateFinWait2
	StateTimeWait
	StateClose
	StateCloseWait
	StateLastAck
	StateListen
	StateClosing

	StateInitial
	StateBound
	StateConnecting
	StateError
)

const (
	rcvAdvWndScale = 1

	SegOverheadFactor = 2
)

type connDirectionState uint32

const (
	connDirectionStateOpen      connDirectionState = 0
	connDirectionStateRcvClosed connDirectionState = 1
	connDirectionStateSndClosed connDirectionState = 2
	connDirectionStateAll       connDirectionState = connDirectionStateOpen | connDirectionStateRcvClosed | connDirectionStateSndClosed
)

func (s EndpointState) connected() bool {
	switch s {
	case StateEstablished, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		return true
	default:
		return false
	}
}

func (s EndpointState) connecting() bool {
	switch s {
	case StateConnecting, StateSynSent, StateSynRecv:
		return true
	default:
		return false
	}
}

func (s EndpointState) internal() bool {
	switch s {
	case StateInitial, StateBound, StateConnecting, StateError:
		return true
	default:
		return false
	}
}

func (s EndpointState) handshake() bool {
	switch s {
	case StateSynSent, StateSynRecv:
		return true
	default:
		return false
	}
}

func (s EndpointState) closed() bool {
	switch s {
	case StateClose, StateError:
		return true
	default:
		return false
	}
}

func (s EndpointState) String() string {
	switch s {
	case StateInitial:
		return "INITIAL"
	case StateBound:
		return "BOUND"
	case StateConnecting:
		return "CONNECTING"
	case StateError:
		return "ERROR"
	case StateEstablished:
		return "ESTABLISHED"
	case StateSynSent:
		return "SYN-SENT"
	case StateSynRecv:
		return "SYN-RCVD"
	case StateFinWait1:
		return "FIN-WAIT1"
	case StateFinWait2:
		return "FIN-WAIT2"
	case StateTimeWait:
		return "TIME-WAIT"
	case StateClose:
		return "CLOSED"
	case StateCloseWait:
		return "CLOSE-WAIT"
	case StateLastAck:
		return "LAST-ACK"
	case StateListen:
		return "LISTEN"
	case StateClosing:
		return "CLOSING"
	default:
		panic("unreachable")
	}
}

type SACKInfo struct {
	Blocks [MaxSACKBlocks]header.SACKBlock

	NumBlocks int
}

type ReceiveErrors struct {
	tcpip.ReceiveErrors

	SegmentQueueDropped tcpip.StatCounter

	ChecksumErrors tcpip.StatCounter

	ListenOverflowSynDrop tcpip.StatCounter

	ListenOverflowAckDrop tcpip.StatCounter

	ZeroRcvWindowState tcpip.StatCounter

	WantZeroRcvWindow tcpip.StatCounter
}

type SendErrors struct {
	tcpip.SendErrors

	SegmentSendToNetworkFailed tcpip.StatCounter

	SynSendToNetworkFailed tcpip.StatCounter

	Retransmits tcpip.StatCounter

	FastRetransmit tcpip.StatCounter

	Timeouts tcpip.StatCounter
}

type Stats struct {
	SegmentsReceived tcpip.StatCounter

	SegmentsSent tcpip.StatCounter

	FailedConnectionAttempts tcpip.StatCounter

	ReceiveErrors ReceiveErrors

	ReadErrors tcpip.ReadErrors

	SendErrors SendErrors

	WriteErrors tcpip.WriteErrors
}

func (*Stats) IsEndpointStats() {}

type sndQueueInfo struct {
	sndQueueMu sndQueueMutex `state:"nosave"`
	TCPSndBufState
}

func (sq *sndQueueInfo) CloneState(other *TCPSndBufState) {
	other.SndBufSize = sq.SndBufSize
	other.SndBufUsed = sq.SndBufUsed
	other.SndClosed = sq.SndClosed
	other.PacketTooBigCount = sq.PacketTooBigCount
	other.SndMTU = sq.SndMTU
	other.AutoTuneSndBufDisabled = atomicbitops.FromUint32(sq.AutoTuneSndBufDisabled.RacyLoad())
}

type Endpoint struct {
	TCPEndpointStateInner
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	endpointEntry `state:"nosave"`

	pendingProcessingMu pendingProcessingMutex `state:"nosave"`

	pendingProcessing bool `state:"nosave"`

	stack       *stack.Stack
	protocol    *protocol
	waiterQueue *waiter.Queue `state:"wait"`

	hardError tcpip.Error

	lastErrorMu lastErrorMutex `state:"nosave"`
	lastError   tcpip.Error

	rcvQueueMu rcvQueueMutex `state:"nosave"`

	TCPRcvBufState

	rcvMemUsed atomicbitops.Int32

	mu          sync.CrossGoroutineMutex `state:"nosave"`
	ownedByUser atomicbitops.Uint32

	rcvQueue segmentList `state:"wait"`

	state atomicbitops.Uint32 `state:".(EndpointState)"`

	connectionDirectionState atomicbitops.Uint32

	origEndpointState uint32 `state:"nosave"`

	isPortReserved    bool
	isRegistered      bool
	boundNICID        tcpip.NICID
	route             *stack.Route `state:"nosave"`
	ipv4TTL           uint8
	ipv6HopLimit      int16
	isConnectNotified bool

	h *handshake

	portFlags ports.Flags

	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags
	boundDest         tcpip.FullAddress

	effectiveNetProtos []tcpip.NetworkProtocolNumber

	recentTSTime tcpip.MonotonicTime

	shutdownFlags tcpip.ShutdownFlags

	tcpRecovery tcpip.TCPRecovery

	sack SACKInfo

	delay uint32

	scoreboard *SACKScoreboard

	segmentQueue segmentQueue `state:"wait"`

	userMSS uint16

	maxSynRetries uint8

	windowClamp uint32

	sndQueueInfo sndQueueInfo

	cc tcpip.CongestionControlOption

	keepalive keepalive

	userTimeout time.Duration

	deferAccept time.Duration

	acceptMu sync.Mutex `state:"nosave"`

	acceptQueue acceptQueue

	rcv *receiver `state:"wait"`

	snd *sender `state:"wait"`

	drainDone chan struct{} `state:"nosave"`

	undrain chan struct{} `state:"nosave"`

	probe TCPProbeFunc `state:"nosave"`

	connectingAddress tcpip.Address

	amss uint16

	sendTOS uint8

	gso stack.GSO

	stats Stats

	tcpLingerTimeout time.Duration

	closed bool

	txHash uint32

	owner tcpip.PacketOwner

	ops tcpip.SocketOptions

	lastOutOfWindowAckTime tcpip.MonotonicTime

	finWait2Timer tcpip.Timer `state:"nosave"`

	timeWaitTimer tcpip.Timer `state:"nosave"`

	listenCtx *listenContext `state:"nosave"`

	limRdr *io.LimitedReader `state:"nosave"`

	pmtud tcpip.PMTUDStrategy

	alsoBindToV4 bool

	terminateAtRestore bool
}

func calculateAdvertisedMSS(userMSS uint16, r *stack.Route) uint16 {
	maxMSS := uint16(r.MTU() - header.TCPMinimumSize)

	if userMSS != 0 && userMSS < maxMSS {
		return userMSS
	}

	return maxMSS
}

func (e *Endpoint) isOwnedByUser() bool {
	return e.ownedByUser.Load() == 1
}

func (e *Endpoint) LockUser() {
	const iterations = 5
	for i := 0; i < iterations; i++ {
		if !e.TryLock() {
			if e.ownedByUser.Load() == 1 {
				e.mu.Lock()
				e.ownedByUser.Store(1)
				return
			}
			continue
		}
		e.ownedByUser.Store(1)
		return
	}

	for i := 0; i < iterations; i++ {
		if !e.TryLock() {
			if e.ownedByUser.Load() == 1 {
				e.mu.Lock()
				e.ownedByUser.Store(1)
				return
			}
			runtime.Gosched()
			continue
		}
		e.ownedByUser.Store(1)
		return
	}

	e.mu.Lock()
	e.ownedByUser.Store(1)
}

func (e *Endpoint) UnlockUser() {
	e.segmentQueue.mu.Lock()
	if e.segmentQueue.emptyLocked() {
		if e.ownedByUser.Swap(0) != 1 {
			panic("e.UnlockUser() called without calling e.LockUser()")
		}
		e.mu.Unlock()
		e.segmentQueue.mu.Unlock()
		return
	}
	e.segmentQueue.mu.Unlock()

	if e.ownedByUser.Swap(0) != 1 {
		panic("e.UnlockUser() called without calling e.LockUser()")
	}
	processor := e.protocol.dispatcher.selectProcessor(e.ID)
	e.mu.Unlock()

	processor.queueEndpoint(e)
}

func (e *Endpoint) StopWork() {
	e.mu.Lock()
}

func (e *Endpoint) ResumeWork() {
	e.mu.Unlock()
}

func (e *Endpoint) AssertLockHeld(locked *Endpoint) {
	if e != locked {
		panic("AssertLockHeld failed: locked endpoint != asserting endpoint")
	}
}

func (e *Endpoint) TryLock() bool {
	return e.mu.TryLock()
}

func (e *Endpoint) setEndpointState(state EndpointState) {
	oldstate := EndpointState(e.state.Swap(uint32(state)))
	switch state {
	case StateEstablished:
		e.stack.Stats().TCP.CurrentEstablished.Increment()
		e.stack.Stats().TCP.CurrentConnected.Increment()
	case StateError:
		fallthrough
	case StateClose:
		if oldstate == StateCloseWait || oldstate == StateEstablished {
			e.stack.Stats().TCP.EstablishedResets.Increment()
		}
		if oldstate.connected() {
			e.stack.Stats().TCP.CurrentConnected.Decrement()
		}
		fallthrough
	default:
		if oldstate == StateEstablished {
			e.stack.Stats().TCP.CurrentEstablished.Decrement()
		}
	}
}

func (e *Endpoint) EndpointState() EndpointState {
	return EndpointState(e.state.Load())
}

func (e *Endpoint) setRecentTimestamp(recentTS uint32) {
	e.RecentTS = recentTS
	e.recentTSTime = e.stack.Clock().NowMonotonic()
}

func (e *Endpoint) recentTimestamp() uint32 {
	return e.RecentTS
}

func calculateTTL(route *stack.Route, ipv4TTL uint8, ipv6HopLimit int16) uint8 {
	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if ipv4TTL == tcpip.UseDefaultIPv4TTL {
			return route.DefaultTTL()
		}
		return ipv4TTL
	case header.IPv6ProtocolNumber:
		if ipv6HopLimit == tcpip.UseDefaultIPv6HopLimit {
			return route.DefaultTTL()
		}
		return uint8(ipv6HopLimit)
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}
}

type keepalive struct {
	keepaliveMutex `state:"nosave"`
	idle           time.Duration
	interval       time.Duration
	count          int
	unacked        int
	timer timer       `state:"nosave"`
	waker sleep.Waker `state:"nosave"`
}

func newEndpoint(s *stack.Stack, protocol *protocol, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *Endpoint {
	e := &Endpoint{
		stack:    s,
		protocol: protocol,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: header.TCPProtocolNumber,
		},
		sndQueueInfo: sndQueueInfo{
			TCPSndBufState: TCPSndBufState{
				SndMTU: math.MaxInt32,
			},
		},
		waiterQueue: waiterQueue,
		state:       atomicbitops.FromUint32(uint32(StateInitial)),
		keepalive: keepalive{
			idle:     DefaultKeepaliveIdle,
			interval: DefaultKeepaliveInterval,
			count:    DefaultKeepaliveCount,
		},
		ipv4TTL:      tcpip.UseDefaultIPv4TTL,
		ipv6HopLimit: tcpip.UseDefaultIPv6HopLimit,
		txHash:        s.InsecureRNG().Uint32(),
		windowClamp:   DefaultReceiveBufferSize,
		maxSynRetries: DefaultSynRetries,
		limRdr:        &io.LimitedReader{},
	}
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits, GetTCPReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetQuickAck(true)
	e.ops.SetSendBufferSize(DefaultSendBufferSize, false)
	e.ops.SetReceiveBufferSize(DefaultReceiveBufferSize, false)

	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false)
	}

	var cs tcpip.CongestionControlOption
	if err := s.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	var mrb tcpip.TCPModerateReceiveBufferOption
	if err := s.TransportProtocolOption(ProtocolNumber, &mrb); err == nil {
		e.RcvAutoParams.Disabled = !bool(mrb)
	}

	var de tcpip.TCPDelayEnabled
	if err := s.TransportProtocolOption(ProtocolNumber, &de); err == nil && de {
		e.ops.SetDelayOption(true)
	}

	var tcpLT tcpip.TCPLingerTimeoutOption
	if err := s.TransportProtocolOption(ProtocolNumber, &tcpLT); err == nil {
		e.tcpLingerTimeout = time.Duration(tcpLT)
	}

	var synRetries tcpip.TCPSynRetriesOption
	if err := s.TransportProtocolOption(ProtocolNumber, &synRetries); err == nil {
		e.maxSynRetries = uint8(synRetries)
	}

	e.probe = protocol.probe
	e.segmentQueue.ep = e

	e.keepalive.timer.init(e.stack.Clock(), timerHandler(e, e.keepaliveTimerExpired))

	return e
}

func (e *Endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.EventMask(0)

	switch e.EndpointState() {
	case StateInitial, StateBound:
		result |= waiter.EventHUp

	case StateConnecting, StateSynSent, StateSynRecv:

	case StateClose, StateError, StateTimeWait:
		result = mask

	case StateListen:
		if (mask & waiter.ReadableEvents) != 0 {
			e.acceptMu.Lock()
			if e.acceptQueue.endpoints.Len() != 0 {
				result |= waiter.ReadableEvents
			}
			e.acceptMu.Unlock()
		}
	}
	if e.EndpointState().connected() {
		if (mask & waiter.WritableEvents) != 0 {
			e.sndQueueInfo.sndQueueMu.Lock()
			sndBufSize := e.getSendBufferSize()
			if e.sndQueueInfo.SndClosed || e.sndQueueInfo.SndBufUsed < sndBufSize {
				result |= waiter.WritableEvents
			}
			if e.sndQueueInfo.SndClosed {
				e.updateConnDirectionState(connDirectionStateSndClosed)
			}
			e.sndQueueInfo.sndQueueMu.Unlock()
		}

		if (mask & waiter.ReadableEvents) != 0 {
			e.rcvQueueMu.Lock()
			if e.RcvBufUsed > 0 || e.RcvClosed {
				result |= waiter.ReadableEvents
			}
			if e.RcvClosed {
				e.updateConnDirectionState(connDirectionStateRcvClosed)
			}
			e.rcvQueueMu.Unlock()
		}
	}

	if e.connDirectionState() == connDirectionStateRcvClosed {
		result |= waiter.EventRdHUp
	}

	return result
}

func (e *Endpoint) purgePendingRcvQueue() {
	if e.rcv != nil {
		for e.rcv.pendingRcvdSegments.Len() > 0 {
			s := heap.Pop(&e.rcv.pendingRcvdSegments).(*segment)
			s.DecRef()
		}
	}
}

func (e *Endpoint) purgeReadQueue() {
	if e.rcv != nil {
		e.rcvQueueMu.Lock()
		defer e.rcvQueueMu.Unlock()
		for {
			s := e.rcvQueue.Front()
			if s == nil {
				break
			}
			e.rcvQueue.Remove(s)
			s.DecRef()
		}
		e.RcvBufUsed = 0
	}
}

func (e *Endpoint) purgeWriteQueue() {
	if e.snd != nil {
		e.sndQueueInfo.sndQueueMu.Lock()
		defer e.sndQueueInfo.sndQueueMu.Unlock()
		e.snd.updateWriteNext(nil)
		for s := e.snd.writeList.Front(); s != nil; s = e.snd.writeList.Front() {
			e.snd.writeList.Remove(s)
			s.DecRef()
		}
		e.sndQueueInfo.SndBufUsed = 0
		e.sndQueueInfo.SndClosed = true
		e.snd.SndNxt = e.snd.SndUna
	}
}

func (e *Endpoint) Abort() {
	defer e.drainClosingSegmentQueue()
	e.LockUser()
	defer e.UnlockUser()
	defer e.purgeReadQueue()
	switch state := e.EndpointState(); {
	case state.connected():
		e.resetConnectionLocked(&tcpip.ErrAborted{})
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	}
	e.closeLocked()
}

func (e *Endpoint) Close() {
	e.LockUser()
	if e.closed {
		e.UnlockUser()
		return
	}

	e.closeLocked()
	e.purgeReadQueue()
	if e.EndpointState() == StateClose || e.EndpointState() == StateError {
		e.UnlockUser()
		e.drainClosingSegmentQueue()
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	}
	e.UnlockUser()
}

func (e *Endpoint) closeLocked() {
	linger := e.SocketOptions().GetLinger()
	if linger.Enabled && linger.Timeout == 0 {
		s := e.EndpointState()
		isResetState := s == StateEstablished || s == StateCloseWait || s == StateFinWait1 || s == StateFinWait2 || s == StateSynRecv
		if isResetState {
			e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			return
		}
	}

	e.shutdownLocked(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	e.closeNoShutdownLocked()
}

func (e *Endpoint) closeNoShutdownLocked() {
	if e.EndpointState() == StateListen && e.isPortReserved {
		if e.isRegistered {
			e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
			e.isRegistered = false
		}

		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         e.TransportEndpointInfo.ID.LocalAddress,
			Port:         e.TransportEndpointInfo.ID.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		e.stack.ReleasePort(portRes)
		e.isPortReserved = false
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
		e.boundDest = tcpip.FullAddress{}
	}

	e.closed = true
	tcpip.AddDanglingEndpoint(e)

	eventMask := waiter.ReadableEvents | waiter.WritableEvents

	switch e.EndpointState() {
	case StateInitial, StateBound, StateListen:
		e.setEndpointState(StateClose)
		fallthrough
	case StateClose, StateError:
		eventMask |= waiter.EventHUp
		e.cleanupLocked()
	case StateConnecting, StateSynSent, StateSynRecv:
		eventMask |= waiter.EventHUp
		e.handshakeFailed(&tcpip.ErrAborted{})
		eventMask |= waiter.EventHUp
	case StateFinWait2:
		if e.finWait2Timer == nil {
			e.finWait2Timer = e.stack.Clock().AfterFunc(e.tcpLingerTimeout, e.finWait2TimerExpired)
		}
	}

	e.waiterQueue.Notify(eventMask)
}

func (e *Endpoint) closePendingAcceptableConnectionsLocked() {
	e.acceptMu.Lock()

	pendingEndpoints := e.acceptQueue.pendingEndpoints
	e.acceptQueue.pendingEndpoints = nil

	completedEndpoints := make([]*Endpoint, 0, e.acceptQueue.endpoints.Len())
	for n := e.acceptQueue.endpoints.Front(); n != nil; n = n.Next() {
		completedEndpoints = append(completedEndpoints, n.Value.(*Endpoint))
	}
	e.acceptQueue.endpoints.Init()
	e.acceptQueue.capacity = 0
	e.acceptMu.Unlock()

	for n := range pendingEndpoints {
		n.Abort()
	}

	for _, n := range completedEndpoints {
		n.Abort()
	}
}

func (e *Endpoint) cleanupLocked() {
	if e.snd != nil {
		e.snd.resendTimer.cleanup()
		e.snd.probeTimer.cleanup()
		e.snd.reorderTimer.cleanup()
		e.snd.corkTimer.cleanup()
	}

	if e.finWait2Timer != nil {
		e.finWait2Timer.Stop()
	}

	if e.timeWaitTimer != nil {
		e.timeWaitTimer.Stop()
	}

	if e.h != nil && e.h.listenEP != nil {
		lEP := e.h.listenEP
		lEP.acceptMu.Lock()
		delete(lEP.acceptQueue.pendingEndpoints, e)
		lEP.acceptMu.Unlock()
	}

	e.closePendingAcceptableConnectionsLocked()
	e.keepalive.timer.cleanup()

	if e.isRegistered {
		e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
		e.isRegistered = false
	}

	if e.isPortReserved {
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         e.TransportEndpointInfo.ID.LocalAddress,
			Port:         e.TransportEndpointInfo.ID.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		e.stack.ReleasePort(portRes)
		e.isPortReserved = false
	}
	e.boundBindToDevice = 0
	e.boundPortFlags = ports.Flags{}
	e.boundDest = tcpip.FullAddress{}

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	e.purgeWriteQueue()
	if e.closed {
		e.purgeReadQueue()
	}
	e.stack.CompleteTransportEndpointCleanup(e)
	tcpip.DeleteDanglingEndpoint(e)
}

func wndFromSpace(space int) int {
	return space >> rcvAdvWndScale
}

func (e *Endpoint) initialReceiveWindow() int {
	rcvWnd := wndFromSpace(e.receiveBufferAvailable())
	if rcvWnd > math.MaxUint16 {
		rcvWnd = math.MaxUint16
	}

	routeWnd := InitialCwnd * int(calculateAdvertisedMSS(e.userMSS, e.route)) * 2
	if rcvWnd > routeWnd {
		rcvWnd = routeWnd
	}
	rcvWndScale := e.rcvWndScaleForHandshake()

	rcvWnd = (rcvWnd >> uint8(rcvWndScale)) << uint8(rcvWndScale)

	if rcvWnd == 0 {
		rcvWnd = 1
	}

	return rcvWnd
}

func (e *Endpoint) ModerateRecvBuf(copied int) {
	e.LockUser()
	defer e.UnlockUser()

	sendNonZeroWindowUpdate := false

	e.rcvQueueMu.Lock()
	if e.RcvAutoParams.Disabled {
		e.rcvQueueMu.Unlock()
		return
	}
	now := e.stack.Clock().NowMonotonic()
	if rtt := e.RcvAutoParams.RTT; rtt == 0 || now.Sub(e.RcvAutoParams.MeasureTime) < rtt {
		e.RcvAutoParams.CopiedBytes += copied
		e.rcvQueueMu.Unlock()
		return
	}
	prevRTTCopied := e.RcvAutoParams.CopiedBytes + copied
	prevCopied := e.RcvAutoParams.PrevCopiedBytes
	rcvWnd := 0
	if prevRTTCopied > prevCopied {
		rcvWnd = prevRTTCopied*2 + 16*int(e.amss)

		grow := (rcvWnd * (prevRTTCopied - prevCopied)) / prevCopied

		rcvWnd += grow * 2

		if minRcvWnd := int(e.amss) * InitialCwnd * 2; rcvWnd < minRcvWnd {
			rcvWnd = minRcvWnd
		}

		if max := e.maxReceiveBufferSize(); rcvWnd > max {
			rcvWnd = max
		}

		rcvBufSize := int(e.ops.GetReceiveBufferSize())
		if rcvWnd > rcvBufSize {
			availBefore := wndFromSpace(e.receiveBufferAvailableLocked(rcvBufSize))
			e.ops.SetReceiveBufferSize(int64(rcvWnd), false)
			availAfter := wndFromSpace(e.receiveBufferAvailableLocked(rcvWnd))
			if crossed, above := e.windowCrossedACKThresholdLocked(availAfter-availBefore, rcvBufSize); crossed && above {
				sendNonZeroWindowUpdate = true
			}
		}

		e.RcvAutoParams.PrevCopiedBytes = prevRTTCopied
	}
	e.RcvAutoParams.MeasureTime = now
	e.RcvAutoParams.CopiedBytes = 0
	e.rcvQueueMu.Unlock()

	if e.EndpointState().connected() && sendNonZeroWindowUpdate {
		e.rcv.nonZeroWindow()
	}
}

func (e *Endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}

func (e *Endpoint) hardErrorLocked() tcpip.Error {
	err := e.hardError
	e.hardError = nil
	return err
}

func (e *Endpoint) lastErrorLocked() tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()
	err := e.lastError
	e.lastError = nil
	return err
}

func (e *Endpoint) LastError() tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()
	if err := e.hardErrorLocked(); err != nil {
		return err
	}
	return e.lastErrorLocked()
}

func (e *Endpoint) LastErrorLocked() tcpip.Error {
	return e.lastErrorLocked()
}

func (e *Endpoint) UpdateLastError(err tcpip.Error) {
	e.LockUser()
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
	e.UnlockUser()
}

func (e *Endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	if err := e.checkReadLocked(); err != nil {
		if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
			e.stats.ReadErrors.ReadClosed.Increment()
		}
		return tcpip.ReadResult{}, err
	}

	var err error
	done := 0
	s := e.rcvQueue.Front()
	for s != nil {
		var n int
		n, err = s.ReadTo(dst, opts.Peek)
		done += n

		if opts.Peek {
			s = s.Next()
		} else {
			sendNonZeroWindowUpdate := false
			memDelta := 0
			for {
				seg := e.rcvQueue.Front()
				if seg == nil || seg.payloadSize() != 0 {
					break
				}
				e.rcvQueue.Remove(seg)
				memDelta += seg.segMemSize()
				seg.DecRef()
			}
			e.rcvQueueMu.Lock()
			e.RcvBufUsed -= n
			s = e.rcvQueue.Front()

			if memDelta > 0 {
				if crossed, above := e.windowCrossedACKThresholdLocked(memDelta, int(e.ops.GetReceiveBufferSize())); crossed && above {
					sendNonZeroWindowUpdate = true
				}
			}
			e.rcvQueueMu.Unlock()

			if e.EndpointState().connected() && sendNonZeroWindowUpdate {
				e.rcv.nonZeroWindow()
			}
		}

		if err != nil {
			break
		}
	}

	if done == 0 && err != nil {
		return tcpip.ReadResult{}, &tcpip.ErrBadBuffer{}
	}
	return tcpip.ReadResult{
		Count: done,
		Total: done,
	}, nil
}

func (e *Endpoint) checkReadLocked() tcpip.Error {
	e.rcvQueueMu.Lock()
	defer e.rcvQueueMu.Unlock()
	if e.EndpointState() == StateSynSent {
		return &tcpip.ErrWouldBlock{}
	}

	bufUsed := e.RcvBufUsed
	if s := e.EndpointState(); !s.connected() && s != StateClose && bufUsed == 0 {
		if s == StateError {
			if err := e.hardErrorLocked(); err != nil {
				return err
			}
			return &tcpip.ErrClosedForReceive{}
		}
		e.stats.ReadErrors.NotConnected.Increment()
		return &tcpip.ErrNotConnected{}
	}

	if e.RcvBufUsed == 0 {
		if e.RcvClosed || !e.EndpointState().connected() {
			return &tcpip.ErrClosedForReceive{}
		}
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

func (e *Endpoint) isEndpointWritableLocked() (int, tcpip.Error) {
	switch s := e.EndpointState(); {
	case s == StateError:
		if err := e.hardErrorLocked(); err != nil {
			return 0, err
		}
		return 0, &tcpip.ErrClosedForSend{}
	case !s.connecting() && !s.connected():
		return 0, &tcpip.ErrClosedForSend{}
	case s.connecting():
		return 0, &tcpip.ErrWouldBlock{}
	}

	if e.sndQueueInfo.SndClosed {
		return 0, &tcpip.ErrClosedForSend{}
	}

	sndBufSize := e.getSendBufferSize()
	avail := sndBufSize - e.sndQueueInfo.SndBufUsed
	if avail <= 0 {
		return 0, &tcpip.ErrWouldBlock{}
	}
	return avail, nil
}

func (e *Endpoint) readFromPayloader(p tcpip.Payloader, opts tcpip.WriteOptions, avail int) (buffer.Buffer, tcpip.Error) {
	limRdr := e.limRdr
	if !opts.Atomic {
		defer func() {
			e.limRdr = limRdr
		}()
		e.limRdr = nil

		e.sndQueueInfo.sndQueueMu.Unlock()
		defer e.sndQueueInfo.sndQueueMu.Lock()

		e.UnlockUser()
		defer e.LockUser()
	}

	var payload buffer.Buffer
	if l := p.Len(); l < avail {
		avail = l
	}
	if avail == 0 {
		return payload, nil
	}
	if _, err := payload.WriteFromReaderAndLimitedReader(p, int64(avail), limRdr); err != nil {
		payload.Release()
		return buffer.Buffer{}, &tcpip.ErrBadBuffer{}
	}
	return payload, nil
}

func (e *Endpoint) queueSegment(p tcpip.Payloader, opts tcpip.WriteOptions) (*segment, int, tcpip.Error) {
	e.sndQueueInfo.sndQueueMu.Lock()
	defer e.sndQueueInfo.sndQueueMu.Unlock()

	avail, err := e.isEndpointWritableLocked()
	if err != nil {
		e.stats.WriteErrors.WriteClosed.Increment()
		return nil, 0, err
	}

	buf, err := e.readFromPayloader(p, opts, avail)
	if err != nil {
		return nil, 0, err
	}

	if buf.Size() == 0 {
		return nil, 0, nil
	}

	if !opts.Atomic {
		avail, err := e.isEndpointWritableLocked()
		if err != nil {
			e.stats.WriteErrors.WriteClosed.Increment()
			buf.Release()
			return nil, 0, err
		}

		if int64(avail) < buf.Size() {
			buf.Truncate(int64(avail))
		}
	}

	size := int(buf.Size())
	s := newOutgoingSegment(e.TransportEndpointInfo.ID, e.stack.Clock(), buf, e.ops.GetMark())
	e.sndQueueInfo.SndBufUsed += size
	e.snd.writeList.PushBack(s)

	return s, size, nil
}

func (e *Endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {

	e.LockUser()
	defer e.UnlockUser()

	nextSeg, n, err := e.queueSegment(p, opts)
	if n == 0 || err != nil {
		return 0, err
	}

	e.sendData(nextSeg)
	return int64(n), nil
}

func (e *Endpoint) selectWindowLocked(rcvBufSize int) (wnd seqnum.Size) {
	wndFromAvailable := wndFromSpace(e.receiveBufferAvailableLocked(rcvBufSize))
	maxWindow := wndFromSpace(rcvBufSize)
	wndFromUsedBytes := maxWindow - e.RcvBufUsed

	newWnd := wndFromAvailable
	if newWnd > wndFromUsedBytes {
		newWnd = wndFromUsedBytes
	}
	if newWnd < 0 {
		newWnd = 0
	}
	return seqnum.Size(newWnd)
}

func (e *Endpoint) selectWindow() (wnd seqnum.Size) {
	e.rcvQueueMu.Lock()
	wnd = e.selectWindowLocked(int(e.ops.GetReceiveBufferSize()))
	e.rcvQueueMu.Unlock()
	return wnd
}

func (e *Endpoint) windowCrossedACKThresholdLocked(deltaBefore int, rcvBufSize int) (crossed bool, above bool) {
	newAvail := int(e.selectWindowLocked(rcvBufSize))
	oldAvail := newAvail - deltaBefore
	if oldAvail < 0 {
		oldAvail = 0
	}
	threshold := int(e.amss)
	const rcvBufFraction = 2
	if wndThreshold := wndFromSpace(rcvBufSize / rcvBufFraction); threshold > wndThreshold {
		threshold = wndThreshold
	}

	switch {
	case oldAvail < threshold && newAvail >= threshold:
		return true, true
	case oldAvail >= threshold && newAvail < threshold:
		return true, false
	}
	return false, false
}

func (e *Endpoint) OnReuseAddressSet(v bool) {
	e.LockUser()
	e.portFlags.TupleOnly = v
	e.UnlockUser()
}

func (e *Endpoint) OnReusePortSet(v bool) {
	e.LockUser()
	e.portFlags.LoadBalanced = v
	e.UnlockUser()
}

func (e *Endpoint) OnKeepAliveSet(bool) {
	e.LockUser()
	e.resetKeepaliveTimer(true)
	e.UnlockUser()
}

func (e *Endpoint) OnDelayOptionSet(v bool) {
	if !v {
		e.LockUser()
		defer e.UnlockUser()
		if e.EndpointState().connected() {
			e.sendData(nil)
		}
	}
}

func (e *Endpoint) OnCorkOptionSet(v bool) {
	if !v {
		e.LockUser()
		defer e.UnlockUser()
		if e.snd != nil {
			e.snd.corkTimer.disable()
		}
		if e.EndpointState().connected() {
			e.sendData(nil)
		}
	}
}

func (e *Endpoint) getSendBufferSize() int {
	return int(e.ops.GetSendBufferSize())
}

func (e *Endpoint) OnSetReceiveBufferSize(rcvBufSz, oldSz int64) (newSz int64, postSet func()) {
	e.LockUser()

	sendNonZeroWindowUpdate := false
	e.rcvQueueMu.Lock()

	scale := uint8(0)
	if e.rcv != nil {
		scale = e.rcv.RcvWndScale
	}
	if rcvBufSz>>scale == 0 {
		rcvBufSz = 1 << scale
	}

	availBefore := wndFromSpace(e.receiveBufferAvailableLocked(int(oldSz)))
	availAfter := wndFromSpace(e.receiveBufferAvailableLocked(int(rcvBufSz)))
	e.RcvAutoParams.Disabled = true

	if crossed, above := e.windowCrossedACKThresholdLocked(availAfter-availBefore, int(rcvBufSz)); crossed && above {
		sendNonZeroWindowUpdate = true
	}

	e.rcvQueueMu.Unlock()

	postSet = func() {
		e.LockUser()
		defer e.UnlockUser()
		if e.EndpointState().connected() && sendNonZeroWindowUpdate {
			e.rcv.nonZeroWindow()
		}

	}
	e.UnlockUser()
	return rcvBufSz, postSet
}

func (e *Endpoint) OnSetSendBufferSize(sz int64) int64 {
	e.sndQueueInfo.TCPSndBufState.AutoTuneSndBufDisabled.Store(1)
	return sz
}

func (e *Endpoint) WakeupWriters() {
	e.LockUser()
	defer e.UnlockUser()

	sendBufferSize := e.getSendBufferSize()
	e.sndQueueInfo.sndQueueMu.Lock()
	notify := (sendBufferSize - e.sndQueueInfo.SndBufUsed) >= e.sndQueueInfo.SndBufUsed>>1
	e.sndQueueInfo.sndQueueMu.Unlock()

	if notify {
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

func (e *Endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	const inetECNMask = 3

	switch opt {
	case tcpip.KeepaliveCountOption:
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.count = v
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true)
		e.UnlockUser()

	case tcpip.IPv4TOSOption:
		e.LockUser()
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.UnlockUser()

	case tcpip.IPv6TrafficClassOption:
		e.LockUser()
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.UnlockUser()

	case tcpip.MaxSegOption:
		userMSS := v
		if userMSS < header.TCPMinimumMSS || userMSS > header.TCPMaximumMSS {
			return &tcpip.ErrInvalidOptionValue{}
		}
		e.LockUser()
		e.userMSS = uint16(userMSS)
		e.UnlockUser()

	case tcpip.MTUDiscoverOption:
		switch v := tcpip.PMTUDStrategy(v); v {
		case tcpip.PMTUDiscoveryWant, tcpip.PMTUDiscoveryDont, tcpip.PMTUDiscoveryDo, tcpip.PMTUDiscoveryProbe:
			e.LockUser()
			e.pmtud = v
			e.UnlockUser()
		default:
			return &tcpip.ErrNotSupported{}
		}

	case tcpip.IPv4TTLOption:
		e.LockUser()
		e.ipv4TTL = uint8(v)
		e.UnlockUser()

	case tcpip.IPv6HopLimitOption:
		e.LockUser()
		e.ipv6HopLimit = int16(v)
		e.UnlockUser()

	case tcpip.TCPSynCountOption:
		if v < 1 || v > 255 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		e.LockUser()
		e.maxSynRetries = uint8(v)
		e.UnlockUser()

	case tcpip.TCPWindowClampOption:
		if v == 0 {
			e.LockUser()
			switch e.EndpointState() {
			case StateClose, StateInitial:
				e.windowClamp = 0
				e.UnlockUser()
				return nil
			default:
				e.UnlockUser()
				return &tcpip.ErrInvalidOptionValue{}
			}
		}
		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
			if v < rs.Min/2 {
				v = rs.Min / 2
			}
		}
		e.LockUser()
		e.windowClamp = uint32(v)
		e.UnlockUser()
	}
	return nil
}

func (e *Endpoint) HasNIC(id int32) bool {
	return id == 0 || e.stack.HasNIC(tcpip.NICID(id))
}

func (e *Endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch v := opt.(type) {
	case *tcpip.KeepaliveIdleOption:
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(*v)
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true)
		e.UnlockUser()

	case *tcpip.KeepaliveIntervalOption:
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(*v)
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true)
		e.UnlockUser()

	case *tcpip.TCPUserTimeoutOption:
		e.LockUser()
		e.userTimeout = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.CongestionControlOption:
		var avail tcpip.TCPAvailableCongestionControlOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &avail); err != nil {
			return err
		}
		availCC := strings.Split(string(avail), " ")
		for _, cc := range availCC {
			if *v == tcpip.CongestionControlOption(cc) {
				e.LockUser()
				state := e.EndpointState()
				e.cc = *v
				switch state {
				case StateEstablished:
					if e.EndpointState() == state {
						e.snd.cc = e.snd.initCongestionControl(e.cc)
					}
				}
				e.UnlockUser()
				return nil
			}
		}

		return &tcpip.ErrNoSuchFile{}

	case *tcpip.TCPLingerTimeoutOption:
		e.LockUser()

		switch {
		case *v < 0:
			*v = -1
		case *v == 0:
			var stackLingerTimeout tcpip.TCPLingerTimeoutOption
			if err := e.stack.TransportProtocolOption(ProtocolNumber, &stackLingerTimeout); err != nil {
				panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %+v) = %v", ProtocolNumber, &stackLingerTimeout, err))
			}
			*v = stackLingerTimeout
		case *v > tcpip.TCPLingerTimeoutOption(MaxTCPLingerTimeout):
			*v = tcpip.TCPLingerTimeoutOption(MaxTCPLingerTimeout)
		default:
		}

		e.tcpLingerTimeout = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.TCPDeferAcceptOption:
		e.LockUser()
		if time.Duration(*v) > MaxRTO {
			*v = tcpip.TCPDeferAcceptOption(MaxRTO)
		}
		e.deferAccept = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return nil
	}
	return nil
}

func (e *Endpoint) readyReceiveSize() (int, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	if e.EndpointState() == StateListen {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	e.rcvQueueMu.Lock()
	defer e.rcvQueueMu.Unlock()

	return e.RcvBufUsed, nil
}

func (e *Endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		v := e.keepalive.count
		e.keepalive.Unlock()
		return v, nil

	case tcpip.IPv4TOSOption:
		e.LockUser()
		v := int(e.sendTOS)
		e.UnlockUser()
		return v, nil

	case tcpip.IPv6TrafficClassOption:
		e.LockUser()
		v := int(e.sendTOS)
		e.UnlockUser()
		return v, nil

	case tcpip.MaxSegOption:
		v := header.TCPDefaultMSS
		e.LockUser()
		if state := e.EndpointState(); e.userMSS > 0 && (state.internal() || state == StateClose || state == StateListen) {
			v = int(e.userMSS)
		}
		e.UnlockUser()
		return v, nil

	case tcpip.MTUDiscoverOption:
		e.LockUser()
		v := e.pmtud
		e.UnlockUser()
		return int(v), nil

	case tcpip.ReceiveQueueSizeOption:
		return e.readyReceiveSize()

	case tcpip.IPv4TTLOption:
		e.LockUser()
		v := int(e.ipv4TTL)
		e.UnlockUser()
		return v, nil

	case tcpip.IPv6HopLimitOption:
		e.LockUser()
		v := int(e.ipv6HopLimit)
		e.UnlockUser()
		return v, nil

	case tcpip.TCPSynCountOption:
		e.LockUser()
		v := int(e.maxSynRetries)
		e.UnlockUser()
		return v, nil

	case tcpip.TCPWindowClampOption:
		e.LockUser()
		v := int(e.windowClamp)
		e.UnlockUser()
		return v, nil

	case tcpip.MulticastTTLOption:
		return 1, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

func (e *Endpoint) getTCPInfo() tcpip.TCPInfoOption {
	info := tcpip.TCPInfoOption{}
	e.LockUser()
	if state := e.EndpointState(); state.internal() {
		info.State = tcpip.EndpointState(StateClose)
	} else {
		info.State = tcpip.EndpointState(state)
	}
	snd := e.snd
	if snd != nil {
		snd.rtt.Lock()
		info.RTT = snd.rtt.TCPRTTState.SRTT
		info.RTTVar = snd.rtt.TCPRTTState.RTTVar
		snd.rtt.Unlock()

		info.RTO = snd.RTO
		info.CcState = snd.state
		info.SndSsthresh = uint32(snd.Ssthresh)
		info.SndCwnd = uint32(snd.SndCwnd)
		info.ReorderSeen = snd.rc.Reord
	}
	e.UnlockUser()
	return info
}

func (e *Endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch o := opt.(type) {
	case *tcpip.TCPInfoOption:
		*o = e.getTCPInfo()

	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIdleOption(e.keepalive.idle)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIntervalOption(e.keepalive.interval)
		e.keepalive.Unlock()

	case *tcpip.TCPUserTimeoutOption:
		e.LockUser()
		*o = tcpip.TCPUserTimeoutOption(e.userTimeout)
		e.UnlockUser()

	case *tcpip.CongestionControlOption:
		e.LockUser()
		*o = e.cc
		e.UnlockUser()

	case *tcpip.TCPLingerTimeoutOption:
		e.LockUser()
		*o = tcpip.TCPLingerTimeoutOption(e.tcpLingerTimeout)
		e.UnlockUser()

	case *tcpip.TCPDeferAcceptOption:
		e.LockUser()
		*o = tcpip.TCPDeferAcceptOption(e.deferAccept)
		e.UnlockUser()

	case *tcpip.OriginalDestinationOption:
		e.LockUser()
		ipt := e.stack.IPTables()
		addr, port, err := ipt.OriginalDst(e.TransportEndpointInfo.ID, e.NetProto, ProtocolNumber)
		e.UnlockUser()
		if err != nil {
			return err
		}
		*o = tcpip.OriginalDestinationOption{
			Addr: addr,
			Port: port,
		}

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
	return nil
}

func (e *Endpoint) checkV4MappedLocked(addr tcpip.FullAddress, bind bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, e.ops.GetV6Only(), bind)
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

func (*Endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *Endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()
	err := e.connect(addr, true)
	if err != nil {
		if !err.IgnoreStats() {
			e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
		}
	}
	return err
}

func (e *Endpoint) registerEndpoint(addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber, nicID tcpip.NICID) tcpip.Error {
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if e.TransportEndpointInfo.ID.LocalPort != 0 {
		err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
		if err != nil {
			return err
		}
	} else {
		sameAddr := e.TransportEndpointInfo.ID.LocalAddress == e.TransportEndpointInfo.ID.RemoteAddress

		var twReuse tcpip.TCPTimeWaitReuseOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &twReuse); err != nil {
			panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %#v) = %s", ProtocolNumber, &twReuse, err))
		}

		reuse := twReuse == tcpip.TCPTimeWaitReuseGlobal
		if twReuse == tcpip.TCPTimeWaitReuseLoopbackOnly {
			switch netProto {
			case header.IPv4ProtocolNumber:
				reuse = header.IsV4LoopbackAddress(e.TransportEndpointInfo.ID.LocalAddress) && header.IsV4LoopbackAddress(e.TransportEndpointInfo.ID.RemoteAddress)
			case header.IPv6ProtocolNumber:
				reuse = e.TransportEndpointInfo.ID.LocalAddress == header.IPv6Loopback && e.TransportEndpointInfo.ID.RemoteAddress == header.IPv6Loopback
			}
		}

		bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
		if _, err := e.stack.PickEphemeralPort(e.stack.SecureRNG(), func(p uint16) (bool, tcpip.Error) {
			if sameAddr && p == e.TransportEndpointInfo.ID.RemotePort {
				return false, nil
			}
			portRes := ports.Reservation{
				Networks:     netProtos,
				Transport:    ProtocolNumber,
				Addr:         e.TransportEndpointInfo.ID.LocalAddress,
				Port:         p,
				Flags:        e.portFlags,
				BindToDevice: bindToDevice,
				Dest:         addr,
			}
			if _, err := e.stack.ReservePort(e.stack.SecureRNG(), portRes, nil); err != nil {
				if _, ok := err.(*tcpip.ErrPortInUse); !ok || !reuse {
					return false, nil
				}
				transEPID := e.TransportEndpointInfo.ID
				transEPID.LocalPort = p
				transEP := e.stack.FindTransportEndpoint(netProto, ProtocolNumber, transEPID, nicID)
				if transEP == nil {
					return false, nil
				}

				tcpEP := transEP.(*Endpoint)
				tcpEP.LockUser()
				if tcpEP.EndpointState() != StateTimeWait || e.stack.Clock().NowMonotonic().Sub(tcpEP.recentTSTime) < 1*time.Second {
					tcpEP.UnlockUser()
					return false, nil
				}
				tcpEP.transitionToStateCloseLocked()
				tcpEP.drainClosingSegmentQueue()
				tcpEP.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
				tcpEP.UnlockUser()
				portRes := ports.Reservation{
					Networks:     netProtos,
					Transport:    ProtocolNumber,
					Addr:         e.TransportEndpointInfo.ID.LocalAddress,
					Port:         p,
					Flags:        e.portFlags,
					BindToDevice: bindToDevice,
					Dest:         addr,
				}
				if _, err := e.stack.ReservePort(e.stack.SecureRNG(), portRes, nil); err != nil {
					return false, nil
				}
			}

			id := e.TransportEndpointInfo.ID
			id.LocalPort = p
			if err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.portFlags, bindToDevice); err != nil {
				portRes := ports.Reservation{
					Networks:     netProtos,
					Transport:    ProtocolNumber,
					Addr:         e.TransportEndpointInfo.ID.LocalAddress,
					Port:         p,
					Flags:        e.portFlags,
					BindToDevice: bindToDevice,
					Dest:         addr,
				}
				e.stack.ReleasePort(portRes)
				if _, ok := err.(*tcpip.ErrPortInUse); ok {
					return false, nil
				}
				return false, err
			}

			e.TransportEndpointInfo.ID = id
			e.isPortReserved = true
			e.boundBindToDevice = bindToDevice
			e.boundPortFlags = e.portFlags
			e.boundDest = addr
			return true, nil
		}); err != nil {
			e.stack.Stats().TCP.FailedPortReservations.Increment()
			return err
		}
	}
	return nil
}

func (e *Endpoint) connect(addr tcpip.FullAddress, handshake bool) tcpip.Error {
	connectingAddr := addr.Addr

	addr, netProto, err := e.checkV4MappedLocked(addr, false)
	if err != nil {
		return err
	}

	if e.EndpointState().connected() {
		if !e.isConnectNotified {
			e.isConnectNotified = true
			return nil
		}
		return &tcpip.ErrAlreadyConnected{}
	}

	nicID := addr.NIC
	switch e.EndpointState() {
	case StateBound:
		if e.boundNICID == 0 {
			break
		}

		if nicID != 0 && nicID != e.boundNICID {
			return &tcpip.ErrHostUnreachable{}
		}

		nicID = e.boundNICID

	case StateInitial:

	case StateConnecting, StateSynSent, StateSynRecv:
		return &tcpip.ErrAlreadyConnecting{}

	case StateError:
		if err := e.hardErrorLocked(); err != nil {
			return err
		}
		return &tcpip.ErrConnectionAborted{}

	default:
		return &tcpip.ErrInvalidEndpointState{}
	}

	r, err := e.stack.FindRoute(nicID, e.TransportEndpointInfo.ID.LocalAddress, addr.Addr, netProto, false)
	if err != nil {
		return err
	}
	defer r.Release()

	e.TransportEndpointInfo.ID.LocalAddress = r.LocalAddress()
	e.TransportEndpointInfo.ID.RemoteAddress = r.RemoteAddress()
	e.TransportEndpointInfo.ID.RemotePort = addr.Port

	oldState := e.EndpointState()
	e.setEndpointState(StateConnecting)
	if err := e.registerEndpoint(addr, netProto, r.NICID()); err != nil {
		e.setEndpointState(oldState)
		if _, ok := err.(*tcpip.ErrPortInUse); ok {
			return &tcpip.ErrBadLocalAddress{}
		}
		return err
	}

	e.isRegistered = true
	r.Acquire()
	e.route = r
	e.boundNICID = nicID
	e.effectiveNetProtos = []tcpip.NetworkProtocolNumber{netProto}
	e.connectingAddress = connectingAddr

	if e.alsoBindToV4 {
		portRes := ports.Reservation{
			Networks:  []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber},
			Transport: ProtocolNumber,
			Port:      e.TransportEndpointInfo.ID.LocalPort,
		}
		e.stack.ReleasePort(portRes)
	}

	e.initGSO()

	if !handshake {
		e.segmentQueue.mu.Lock()
		for _, l := range []segmentList{e.segmentQueue.list, e.snd.writeList.writeList} {
			for s := l.Front(); s != nil; s = s.Next() {
				s.id = e.TransportEndpointInfo.ID
			}
		}
		e.segmentQueue.mu.Unlock()
		e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		e.setEndpointState(StateEstablished)
		e.ops.SetSendBufferSize(e.computeTCPSendBufferSize(), false)
		return &tcpip.ErrConnectStarted{}
	}

	h := e.newHandshake()
	e.setEndpointState(StateSynSent)
	h.start()
	e.stack.Stats().TCP.ActiveConnectionOpenings.Increment()

	return &tcpip.ErrConnectStarted{}
}

func (*Endpoint) ConnectEndpoint(tcpip.Endpoint) tcpip.Error {
	return &tcpip.ErrInvalidEndpointState{}
}

func (e *Endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()

	if e.EndpointState().connecting() {
		e.handshakeFailed(&tcpip.ErrConnectionReset{})
		e.waiterQueue.Notify(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
		return nil
	}

	return e.shutdownLocked(flags)
}

func (e *Endpoint) shutdownLocked(flags tcpip.ShutdownFlags) tcpip.Error {
	e.shutdownFlags |= flags
	switch {
	case e.EndpointState().connected():
		if e.shutdownFlags&tcpip.ShutdownRead != 0 {
			e.rcvQueueMu.Lock()
			e.RcvClosed = true
			rcvBufUsed := e.RcvBufUsed
			e.rcvQueueMu.Unlock()
			if e.shutdownFlags&tcpip.ShutdownWrite != 0 && rcvBufUsed > 0 {
				e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
				return nil
			}
			events := waiter.ReadableEvents
			if e.shutdownFlags&tcpip.ShutdownWrite == 0 {
				events |= waiter.EventRdHUp
			}
			e.waiterQueue.Notify(events)
		}

		if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
			e.sndQueueInfo.sndQueueMu.Lock()
			if e.sndQueueInfo.SndClosed {
				e.sndQueueInfo.sndQueueMu.Unlock()
				if e.EndpointState() == StateTimeWait {
					return &tcpip.ErrNotConnected{}
				}
				return nil
			}

			s := newOutgoingSegment(e.TransportEndpointInfo.ID, e.stack.Clock(), buffer.Buffer{}, e.ops.GetMark())
			e.snd.writeList.PushBack(s)
			e.updateConnDirectionState(connDirectionStateSndClosed)
			switch e.EndpointState() {
			case StateCloseWait:
				e.setEndpointState(StateLastAck)
			default:
				e.setEndpointState(StateFinWait1)
			}
			e.sndQueueInfo.SndClosed = true
			e.sndQueueInfo.sndQueueMu.Unlock()

			e.sendData(s)

			e.snd.Closed = true

			e.waiterQueue.Notify(waiter.WritableEvents)
		}

		return nil
	case e.EndpointState() == StateListen:
		if e.shutdownFlags&tcpip.ShutdownRead != 0 {
			e.rcvQueueMu.Lock()
			e.RcvClosed = true
			e.rcvQueueMu.Unlock()
			e.closePendingAcceptableConnectionsLocked()
			e.waiterQueue.Notify(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
		}
		return nil
	default:
		return &tcpip.ErrNotConnected{}
	}
}

func (e *Endpoint) Listen(backlog int) tcpip.Error {
	if err := e.listen(backlog); err != nil {
		if !err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
		}
		return err
	}
	return nil
}

func (e *Endpoint) listen(backlog int) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()

	if e.EndpointState() == StateListen && !e.closed {
		e.acceptMu.Lock()
		defer e.acceptMu.Unlock()

		if e.acceptQueue.endpoints.Len() > backlog {
			return &tcpip.ErrInvalidEndpointState{}
		}
		e.acceptQueue.capacity = backlog

		if e.acceptQueue.pendingEndpoints == nil {
			e.acceptQueue.pendingEndpoints = make(map[*Endpoint]struct{})
		}

		e.shutdownFlags = 0
		e.updateConnDirectionState(connDirectionStateOpen)
		e.rcvQueueMu.Lock()
		e.RcvClosed = false
		e.rcvQueueMu.Unlock()

		return nil
	}

	if e.EndpointState() == StateInitial {
		if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
			return err
		}
	}

	if e.EndpointState() != StateBound {
		e.stats.ReadErrors.InvalidEndpointState.Increment()
		return &tcpip.ErrInvalidEndpointState{}
	}

	e.setEndpointState(StateListen)
	if err := e.stack.RegisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice); err != nil {
		e.transitionToStateCloseLocked()
		return err
	}

	e.isRegistered = true

	e.acceptMu.Lock()
	if e.acceptQueue.pendingEndpoints == nil {
		e.acceptQueue.pendingEndpoints = make(map[*Endpoint]struct{})
	}
	if e.acceptQueue.capacity == 0 {
		e.acceptQueue.capacity = backlog
	}
	e.acceptMu.Unlock()

	rcvWnd := seqnum.Size(e.receiveBufferAvailable())
	e.listenCtx = newListenContext(e.stack, e.protocol, e, rcvWnd, e.ops.GetV6Only(), e.NetProto)

	return nil
}

func (e *Endpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	e.rcvQueueMu.Lock()
	rcvClosed := e.RcvClosed
	e.rcvQueueMu.Unlock()
	if rcvClosed || e.EndpointState() != StateListen {
		return nil, nil, &tcpip.ErrInvalidEndpointState{}
	}

	var n *Endpoint
	e.acceptMu.Lock()
	if element := e.acceptQueue.endpoints.Front(); element != nil {
		n = e.acceptQueue.endpoints.Remove(element).(*Endpoint)
	}
	e.acceptMu.Unlock()
	if n == nil {
		return nil, nil, &tcpip.ErrWouldBlock{}
	}
	if peerAddr != nil {
		*peerAddr = n.getRemoteAddress()
	}
	return n, n.waiterQueue, nil
}

func (e *Endpoint) Bind(addr tcpip.FullAddress) (err tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	return e.bindLocked(addr)
}

func (e *Endpoint) bindLocked(addr tcpip.FullAddress) (err tcpip.Error) {
	if e.EndpointState() != StateInitial {
		return &tcpip.ErrAlreadyBound{}
	}

	e.BindAddr = addr.Addr
	addr, netProto, err := e.checkV4MappedLocked(addr, true)
	if err != nil {
		return err
	}

	netProtos := []tcpip.NetworkProtocolNumber{netProto}

	if netProto == header.IPv6ProtocolNumber {
		stackHasV4 := e.stack.CheckNetworkProtocol(header.IPv4ProtocolNumber)
		alsoBindToV4 := !e.ops.GetV6Only() && addr.Addr == tcpip.Address{} && stackHasV4
		if alsoBindToV4 {
			netProtos = append(netProtos, header.IPv4ProtocolNumber)
			e.alsoBindToV4 = true
		}
	}

	var nic tcpip.NICID
	if addr.Addr.Len() != 0 {
		nic = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nic == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
		e.TransportEndpointInfo.ID.LocalAddress = addr.Addr
	}

	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	portRes := ports.Reservation{
		Networks:     netProtos,
		Transport:    ProtocolNumber,
		Addr:         addr.Addr,
		Port:         addr.Port,
		Flags:        e.portFlags,
		BindToDevice: bindToDevice,
		Dest:         tcpip.FullAddress{},
	}
	port, err := e.stack.ReservePort(e.stack.SecureRNG(), portRes, func(p uint16) (bool, tcpip.Error) {
		id := e.TransportEndpointInfo.ID
		id.LocalPort = p
		if err := e.stack.CheckRegisterTransportEndpoint(netProtos, ProtocolNumber, id, e.portFlags, bindToDevice); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		e.stack.Stats().TCP.FailedPortReservations.Increment()
		return err
	}

	e.boundBindToDevice = bindToDevice
	e.boundPortFlags = e.portFlags
	e.boundNICID = nic
	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.TransportEndpointInfo.ID.LocalPort = port

	e.setEndpointState(StateBound)

	return nil
}

func (e *Endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	return tcpip.FullAddress{
		Addr: e.TransportEndpointInfo.ID.LocalAddress,
		Port: e.TransportEndpointInfo.ID.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

func (e *Endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	if !e.EndpointState().connected() {
		return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
	}

	return e.getRemoteAddress(), nil
}

func (e *Endpoint) getRemoteAddress() tcpip.FullAddress {
	return tcpip.FullAddress{
		Addr: e.TransportEndpointInfo.ID.RemoteAddress,
		Port: e.TransportEndpointInfo.ID.RemotePort,
		NIC:  e.boundNICID,
	}
}

func (*Endpoint) HandlePacket(stack.TransportEndpointID, *stack.PacketBuffer) {
}

func (e *Endpoint) enqueueSegment(s *segment) bool {
	if !e.segmentQueue.enqueue(s) {
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.SegmentQueueDropped.Increment()
		return false
	}
	return true
}

func (e *Endpoint) onICMPError(err tcpip.Error, transErr stack.TransportError, pkt *stack.PacketBuffer) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()

	var recvErr bool
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		recvErr = e.SocketOptions().GetIPv4RecvError()
	case header.IPv6ProtocolNumber:
		recvErr = e.SocketOptions().GetIPv6RecvError()
	default:
		panic(fmt.Sprintf("unhandled network protocol number = %d", pkt.NetworkProtocolNumber))
	}

	if recvErr {
		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:   err,
			Cause: transErr,
			Payload: pkt.Data().AsRange().ToView(),
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.TransportEndpointInfo.ID.RemoteAddress,
				Port: e.TransportEndpointInfo.ID.RemotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.TransportEndpointInfo.ID.LocalAddress,
				Port: e.TransportEndpointInfo.ID.LocalPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
	}

	if e.EndpointState().connecting() {
		e.mu.Lock()
		if e.h != nil && e.h.listenEP != nil {
			lEP := e.h.listenEP
			lEP.acceptMu.Lock()
			delete(lEP.acceptQueue.pendingEndpoints, e)
			lEP.acceptMu.Unlock()
			lEP.stats.FailedConnectionAttempts.Increment()
		}
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		e.cleanupLocked()
		e.hardError = err
		e.setEndpointState(StateError)
		e.mu.Unlock()
		e.drainClosingSegmentQueue()
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
}

func (e *Endpoint) HandleError(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	handlePacketTooBig := func(mtu uint32) {
		e.sndQueueInfo.sndQueueMu.Lock()
		update := false
		if v := int(mtu); v < e.sndQueueInfo.SndMTU {
			e.sndQueueInfo.SndMTU = v
			update = true
		}
		newMTU := e.sndQueueInfo.SndMTU
		e.sndQueueInfo.sndQueueMu.Unlock()
		if update {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.snd != nil {
				e.snd.updateMaxPayloadSize(newMTU, 1)
			}
		}
	}

	switch transErr.Kind() {
	case stack.PacketTooBigTransportError:
		handlePacketTooBig(transErr.Info())
	case stack.DestinationHostUnreachableTransportError:
		e.onICMPError(&tcpip.ErrHostUnreachable{}, transErr, pkt)
	case stack.DestinationNetworkUnreachableTransportError:
		e.onICMPError(&tcpip.ErrNetworkUnreachable{}, transErr, pkt)
	case stack.DestinationPortUnreachableTransportError:
		e.onICMPError(&tcpip.ErrConnectionRefused{}, transErr, pkt)
	case stack.DestinationProtoUnreachableTransportError:
		e.onICMPError(&tcpip.ErrUnknownProtocolOption{}, transErr, pkt)
	case stack.SourceRouteFailedTransportError:
		e.onICMPError(&tcpip.ErrNotSupported{}, transErr, pkt)
	case stack.SourceHostIsolatedTransportError:
		e.onICMPError(&tcpip.ErrNoNet{}, transErr, pkt)
	case stack.DestinationHostDownTransportError:
		e.onICMPError(&tcpip.ErrHostDown{}, transErr, pkt)
	}
}

func (e *Endpoint) updateSndBufferUsage(v int) {
	sendBufferSize := e.getSendBufferSize()
	e.sndQueueInfo.sndQueueMu.Lock()
	notify := e.sndQueueInfo.SndBufUsed >= sendBufferSize>>1
	e.sndQueueInfo.SndBufUsed -= v

	newSndBufSz := e.computeTCPSendBufferSize()

	notify = notify && e.sndQueueInfo.SndBufUsed < int(newSndBufSz)>>1
	e.sndQueueInfo.sndQueueMu.Unlock()

	if notify {
		e.ops.SetSendBufferSize(newSndBufSz, false)
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

func (e *Endpoint) readyToRead(s *segment) {
	e.rcvQueueMu.Lock()
	if s != nil {
		e.RcvBufUsed += s.payloadSize()
		s.IncRef()
		e.rcvQueue.PushBack(s)
	} else {
		e.RcvClosed = true
	}
	e.rcvQueueMu.Unlock()
	e.waiterQueue.Notify(waiter.ReadableEvents)
}

func (e *Endpoint) receiveBufferAvailableLocked(rcvBufSize int) int {
	memUsed := e.receiveMemUsed()
	if memUsed >= rcvBufSize {
		return 0
	}

	return rcvBufSize - memUsed
}

func (e *Endpoint) receiveBufferAvailable() int {
	e.rcvQueueMu.Lock()
	available := e.receiveBufferAvailableLocked(int(e.ops.GetReceiveBufferSize()))
	e.rcvQueueMu.Unlock()
	return available
}

func (e *Endpoint) receiveBufferUsed() int {
	e.rcvQueueMu.Lock()
	used := e.RcvBufUsed
	e.rcvQueueMu.Unlock()
	return used
}

func (e *Endpoint) receiveMemUsed() int {
	return int(e.rcvMemUsed.Load())
}

func (e *Endpoint) updateReceiveMemUsed(delta int) {
	e.rcvMemUsed.Add(int32(delta))
}

func (e *Endpoint) maxReceiveBufferSize() int {
	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err != nil {
		return MaxBufferSize
	}
	return rs.Max
}

func (e *Endpoint) connDirectionState() connDirectionState {
	return connDirectionState(e.connectionDirectionState.Load())
}

func (e *Endpoint) updateConnDirectionState(state connDirectionState) connDirectionState {
	return connDirectionState(e.connectionDirectionState.Swap(uint32(e.connDirectionState() | state)))
}

func (e *Endpoint) rcvWndScaleForHandshake() int {
	bufSizeForScale := e.ops.GetReceiveBufferSize()

	e.rcvQueueMu.Lock()
	autoTuningDisabled := e.RcvAutoParams.Disabled
	e.rcvQueueMu.Unlock()
	if autoTuningDisabled {
		return FindWndScale(seqnum.Size(bufSizeForScale))
	}

	return FindWndScale(seqnum.Size(e.maxReceiveBufferSize()))
}

func (e *Endpoint) updateRecentTimestamp(tsVal uint32, maxSentAck seqnum.Value, segSeq seqnum.Value) {
	if e.SendTSOk && seqnum.Value(e.recentTimestamp()).LessThan(seqnum.Value(tsVal)) && segSeq.LessThanEq(maxSentAck) {
		e.setRecentTimestamp(tsVal)
	}
}

func (e *Endpoint) maybeEnableTimestamp(synOpts header.TCPSynOptions) {
	if synOpts.TS {
		e.SendTSOk = true
		e.setRecentTimestamp(synOpts.TSVal)
	}
}

func (e *Endpoint) tsVal(now tcpip.MonotonicTime) uint32 {
	return e.TSOffset.TSVal(now)
}

func (e *Endpoint) tsValNow() uint32 {
	return e.tsVal(e.stack.Clock().NowMonotonic())
}

func (e *Endpoint) elapsed(now tcpip.MonotonicTime, tsEcr uint32) time.Duration {
	return e.TSOffset.Elapsed(now, tsEcr)
}

func (e *Endpoint) maybeEnableSACKPermitted(synOpts header.TCPSynOptions) {
	var v tcpip.TCPSACKEnabled
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &v); err != nil {
		return
	}
	if bool(v) && synOpts.SACKPermitted {
		e.SACKPermitted = true
		e.stack.TransportProtocolOption(ProtocolNumber, &e.tcpRecovery)
	}
}

func (e *Endpoint) maxOptionSize() (size int) {
	var maxSackBlocks [header.TCPMaxSACKBlocks]header.SACKBlock
	options := e.makeOptions(maxSackBlocks[:])
	size = len(options)
	putOptions(options)

	return size
}

func (e *Endpoint) completeStateLocked(s *TCPEndpointState) {
	s.TCPEndpointStateInner = e.TCPEndpointStateInner
	s.ID = TCPEndpointID(e.TransportEndpointInfo.ID)
	s.SegTime = e.stack.Clock().NowMonotonic()
	s.Receiver = e.rcv.TCPReceiverState
	s.Sender = e.snd.TCPSenderState

	sndBufSize := e.getSendBufferSize()
	e.sndQueueInfo.sndQueueMu.Lock()
	e.sndQueueInfo.CloneState(&s.SndBufState)
	s.SndBufState.SndBufSize = sndBufSize
	e.sndQueueInfo.sndQueueMu.Unlock()

	e.rcvQueueMu.Lock()
	s.RcvBufState = e.TCPRcvBufState
	e.rcvQueueMu.Unlock()

	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])
	s.SACK.ReceivedBlocks, s.SACK.MaxSACKED = e.scoreboard.Copy()

	e.snd.rtt.Lock()
	s.Sender.RTTState = e.snd.rtt.TCPRTTState
	e.snd.rtt.Unlock()

	if cubic, ok := e.snd.cc.(*cubicState); ok {
		s.Sender.Cubic = cubic.TCPCubicState
		s.Sender.Cubic.TimeSinceLastCongestion = e.stack.Clock().NowMonotonic().Sub(s.Sender.Cubic.T)
	}

	s.Sender.RACKState = e.snd.rc.TCPRACKState
	s.Sender.RetransmitTS = e.snd.retransmitTS
	s.Sender.SpuriousRecovery = e.snd.spuriousRecovery
}

func (e *Endpoint) initHostGSO() {
	switch e.route.NetProto() {
	case header.IPv4ProtocolNumber:
		e.gso.Type = stack.GSOTCPv4
		e.gso.L3HdrLen = header.IPv4MinimumSize
	case header.IPv6ProtocolNumber:
		e.gso.Type = stack.GSOTCPv6
		e.gso.L3HdrLen = header.IPv6MinimumSize
	default:
		panic(fmt.Sprintf("Unknown netProto: %v", e.NetProto))
	}
	e.gso.NeedsCsum = true
	e.gso.CsumOffset = header.TCPChecksumOffset
	e.gso.MaxSize = e.route.GSOMaxSize()
}

func (e *Endpoint) initGSO() {
	if e.route.HasHostGSOCapability() {
		e.initHostGSO()
	} else if e.route.HasGVisorGSOCapability() {
		e.gso = stack.GSO{
			MaxSize:   e.route.GSOMaxSize(),
			Type:      stack.GSOGvisor,
			NeedsCsum: false,
		}
	}
}

func (e *Endpoint) State() uint32 {
	return uint32(e.EndpointState())
}

func (e *Endpoint) Info() tcpip.EndpointInfo {
	e.LockUser()
	ret := e.TransportEndpointInfo
	e.UnlockUser()
	return &ret
}

func (e *Endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

func (e *Endpoint) Wait() {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
	e.waiterQueue.EventRegister(&waitEntry)
	defer e.waiterQueue.EventUnregister(&waitEntry)
	switch e.EndpointState() {
	case StateClose, StateError:
		return
	}
	<-notifyCh
}

func (e *Endpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

func GetTCPSendBufferLimits(sh tcpip.StackHandler) tcpip.SendBufferSizeOption {
	ss := sh.(*stack.Stack).TCPSendBufferLimits()
	return tcpip.SendBufferSizeOption(ss)
}

func (e *Endpoint) allowOutOfWindowAck() bool {
	now := e.stack.Clock().NowMonotonic()

	if e.lastOutOfWindowAckTime != (tcpip.MonotonicTime{}) {
		var limit stack.TCPInvalidRateLimitOption
		if err := e.stack.Option(&limit); err != nil {
			panic(fmt.Sprintf("e.stack.Option(%+v) failed with error: %s", limit, err))
		}
		if now.Sub(e.lastOutOfWindowAckTime) < time.Duration(limit) {
			return false
		}
	}

	e.lastOutOfWindowAckTime = now
	return true
}

func GetTCPReceiveBufferLimits(s tcpip.StackHandler) tcpip.ReceiveBufferSizeOption {
	var ss tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err != nil {
		panic(fmt.Sprintf("s.TransportProtocolOption(%d, %#v) = %s", header.TCPProtocolNumber, ss, err))
	}

	return tcpip.ReceiveBufferSizeOption(ss)
}

func (e *Endpoint) computeTCPSendBufferSize() int64 {
	curSndBufSz := int64(e.getSendBufferSize())

	if disabled := e.sndQueueInfo.TCPSndBufState.AutoTuneSndBufDisabled.Load(); disabled == 1 {
		return curSndBufSz
	}

	const packetOverheadFactor = 2
	curMSS := e.snd.MaxPayloadSize
	numSeg := InitialCwnd
	if numSeg < e.snd.SndCwnd {
		numSeg = e.snd.SndCwnd
	}

	newSndBufSz := int64(numSeg * curMSS * packetOverheadFactor)
	if newSndBufSz < curSndBufSz {
		return curSndBufSz
	}
	if ss := GetTCPSendBufferLimits(e.stack); int64(ss.Max) < newSndBufSz {
		newSndBufSz = int64(ss.Max)
	}

	return newSndBufSz
}

func (e *Endpoint) GetAcceptConn() bool {
	return EndpointState(e.State()) == StateListen
}

func (e *Endpoint) getExperimentOptionValue(route *stack.Route) uint16 {
	if nic, err := e.stack.GetNICByID(route.OutgoingNIC()); err == nil && nic.GetExperimentIPOptionEnabled() {
		return e.ops.GetExperimentOptionValue()
	}
	return 0
}

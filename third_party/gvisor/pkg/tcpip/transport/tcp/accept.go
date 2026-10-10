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
	"container/list"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/ports"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	tsLen = 8

	tsMask = (1 << tsLen) - 1

	tsOffset = 24

	hashMask = (1 << tsOffset) - 1

	maxTSDiff = 2
)

var (
	mssTable = []uint16{536, 1300, 1440, 1460}
)

func encodeMSS(mss uint16) uint32 {
	for i := len(mssTable) - 1; i > 0; i-- {
		if mss >= mssTable[i] {
			return uint32(i)
		}
	}
	return 0
}

type listenContext struct {
	stack    *stack.Stack
	protocol *protocol

	rcvWnd seqnum.Size

	nonce [2][sha1.BlockSize]byte

	listenEP *Endpoint

	hasherMu hasherMutex
	hasher hash.Hash

	v6Only bool

	netProto tcpip.NetworkProtocolNumber
}

func timeStamp(clock tcpip.Clock) uint32 {
	return uint32(clock.NowMonotonic().Sub(tcpip.MonotonicTime{}).Seconds()) >> 6 & tsMask
}

func newListenContext(stk *stack.Stack, protocol *protocol, listenEP *Endpoint, rcvWnd seqnum.Size, v6Only bool, netProto tcpip.NetworkProtocolNumber) *listenContext {
	l := &listenContext{
		stack:    stk,
		protocol: protocol,
		rcvWnd:   rcvWnd,
		hasher:   sha1.New(),
		v6Only:   v6Only,
		netProto: netProto,
		listenEP: listenEP,
	}

	for i := range l.nonce {
		if _, err := io.ReadFull(stk.SecureRNG().Reader, l.nonce[i][:]); err != nil {
			panic(err)
		}
	}

	return l
}

func (l *listenContext) cookieHash(id stack.TransportEndpointID, ts uint32, nonceIndex int) uint32 {

	var payload [8]byte
	binary.BigEndian.PutUint16(payload[0:], id.LocalPort)
	binary.BigEndian.PutUint16(payload[2:], id.RemotePort)
	binary.BigEndian.PutUint32(payload[4:], ts)

	l.hasherMu.Lock()
	l.hasher.Reset()

	l.hasher.Write(payload[:])
	l.hasher.Write(l.nonce[nonceIndex][:])
	l.hasher.Write(id.LocalAddress.AsSlice())
	l.hasher.Write(id.RemoteAddress.AsSlice())

	h := l.hasher.Sum(nil)
	l.hasherMu.Unlock()

	return binary.BigEndian.Uint32(h[:])
}

func (l *listenContext) createCookie(id stack.TransportEndpointID, seq seqnum.Value, data uint32) seqnum.Value {
	ts := timeStamp(l.stack.Clock())
	v := l.cookieHash(id, 0, 0) + uint32(seq) + (ts << tsOffset)
	v += (l.cookieHash(id, ts, 1) + data) & hashMask
	return seqnum.Value(v)
}

func (l *listenContext) isCookieValid(id stack.TransportEndpointID, cookie seqnum.Value, seq seqnum.Value) (uint32, bool) {
	ts := timeStamp(l.stack.Clock())
	v := uint32(cookie) - l.cookieHash(id, 0, 0) - uint32(seq)
	cookieTS := v >> tsOffset
	if ((ts - cookieTS) & tsMask) > maxTSDiff {
		return 0, false
	}

	return (v - l.cookieHash(id, cookieTS, 1)) & hashMask, true
}

func (l *listenContext) createConnectingEndpoint(s *segment, rcvdSynOpts header.TCPSynOptions, queue *waiter.Queue) (n *Endpoint, _ tcpip.Error) {
	netProto := l.netProto
	if netProto == 0 {
		netProto = s.pkt.NetworkProtocolNumber
	}

	route, err := l.stack.FindRoute(s.pkt.NICID, s.pkt.Network().DestinationAddress(), s.pkt.Network().SourceAddress(), s.pkt.NetworkProtocolNumber, false)
	if err != nil {
		return nil, err
	}

	n = newEndpoint(l.stack, l.protocol, netProto, queue)
	n.mu.Lock()
	n.ops.SetV6Only(l.v6Only)
	n.TransportEndpointInfo.ID = s.id
	n.boundNICID = s.pkt.NICID
	n.route = route
	n.effectiveNetProtos = []tcpip.NetworkProtocolNumber{s.pkt.NetworkProtocolNumber}
	n.ops.SetReceiveBufferSize(int64(l.rcvWnd), false)
	n.amss = calculateAdvertisedMSS(n.userMSS, n.route)
	n.setEndpointState(StateConnecting)

	n.maybeEnableTimestamp(rcvdSynOpts)
	n.maybeEnableSACKPermitted(rcvdSynOpts)

	n.initGSO()

	initWnd := n.initialReceiveWindow()
	n.rcvQueueMu.Lock()
	n.RcvAutoParams.PrevCopiedBytes = initWnd
	n.rcvQueueMu.Unlock()

	return n, nil
}

func (l *listenContext) startHandshake(s *segment, opts header.TCPSynOptions, queue *waiter.Queue, owner tcpip.PacketOwner) (h *handshake, _ tcpip.Error) {
	irs := s.sequenceNumber
	isn := generateSecureISN(s.id, l.stack.Clock(), l.protocol.seqnumSecret)
	ep, err := l.createConnectingEndpoint(s, opts, queue)
	if err != nil {
		return nil, err
	}

	ep.owner = owner

	deferAccept := time.Duration(0)
	if l.listenEP != nil {
		if l.listenEP.EndpointState() != StateListen {

			ep.mu.Unlock()
			ep.Close()

			return nil, &tcpip.ErrConnectionAborted{}
		}

		l.listenEP.propagateInheritableOptionsLocked(ep)

		if !ep.reserveTupleLocked() {
			ep.mu.Unlock()
			ep.Close()

			return nil, &tcpip.ErrConnectionAborted{}
		}

		deferAccept = l.listenEP.deferAccept
	}

	if err := ep.stack.RegisterTransportEndpoint(
		ep.effectiveNetProtos,
		ProtocolNumber,
		ep.TransportEndpointInfo.ID,
		ep,
		ep.boundPortFlags,
		ep.boundBindToDevice,
	); err != nil {
		ep.mu.Unlock()
		ep.Close()

		ep.drainClosingSegmentQueue()

		return nil, err
	}

	ep.isRegistered = true

	h = ep.newPassiveHandshake(isn, irs, opts, deferAccept)
	h.listenEP = l.listenEP
	h.start()
	h.ep.mu.Unlock()
	return h, nil
}

func (l *listenContext) performHandshake(s *segment, opts header.TCPSynOptions, queue *waiter.Queue, owner tcpip.PacketOwner) (*Endpoint, tcpip.Error) {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	queue.EventRegister(&waitEntry)
	defer queue.EventUnregister(&waitEntry)

	h, err := l.startHandshake(s, opts, queue, owner)
	if err != nil {
		return nil, err
	}

	<-notifyCh

	ep := h.ep
	ep.mu.Lock()
	if !ep.EndpointState().connected() {
		ep.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		ep.stats.FailedConnectionAttempts.Increment()
		ep.h = nil
		ep.mu.Unlock()
		ep.Close()
		ep.notifyAborted()
		ep.drainClosingSegmentQueue()
		err := ep.LastError()
		if err == nil {
			err = &tcpip.ErrConnectionAborted{}
		}
		return nil, err
	}

	ep.isConnectNotified = true

	ep.rcv.RcvWndScale = ep.h.effectiveRcvWndScale()

	ep.h = nil
	ep.mu.Unlock()
	return ep, nil
}

func (e *Endpoint) propagateInheritableOptionsLocked(n *Endpoint) {
	n.userTimeout = e.userTimeout
	n.portFlags = e.portFlags
	n.boundBindToDevice = e.boundBindToDevice
	n.boundPortFlags = e.boundPortFlags
	n.userMSS = e.userMSS
	n.ops.SetMark(e.ops.GetMark())
}

func (e *Endpoint) reserveTupleLocked() bool {
	dest := tcpip.FullAddress{
		Addr: e.TransportEndpointInfo.ID.RemoteAddress,
		Port: e.TransportEndpointInfo.ID.RemotePort,
	}
	portRes := ports.Reservation{
		Networks:     e.effectiveNetProtos,
		Transport:    ProtocolNumber,
		Addr:         e.TransportEndpointInfo.ID.LocalAddress,
		Port:         e.TransportEndpointInfo.ID.LocalPort,
		Flags:        e.boundPortFlags,
		BindToDevice: e.boundBindToDevice,
		Dest:         dest,
	}
	if !e.stack.ReserveTuple(portRes) {
		e.stack.Stats().TCP.FailedPortReservations.Increment()
		return false
	}

	e.isPortReserved = true
	e.boundDest = dest
	return true
}

func (e *Endpoint) notifyAborted() {
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (e *Endpoint) acceptQueueIsFull() bool {
	e.acceptMu.Lock()
	full := e.acceptQueue.isFull()
	e.acceptMu.Unlock()
	return full
}

type acceptQueue struct {
	endpoints list.List `state:".([]*Endpoint)"`

	pendingEndpoints map[*Endpoint]struct{}

	capacity int
}

func (a *acceptQueue) isFull() bool {
	return a.endpoints.Len() >= a.capacity
}

func (e *Endpoint) handleListenSegment(ctx *listenContext, s *segment) tcpip.Error {
	e.rcvQueueMu.Lock()
	rcvClosed := e.RcvClosed
	e.rcvQueueMu.Unlock()
	if rcvClosed || s.flags.Contains(header.TCPFlagSyn|header.TCPFlagAck) {
		return replyWithReset(e.stack, s, e.sendTOS, e.ipv4TTL, e.ipv6HopLimit)
	}

	switch {
	case s.flags.Contains(header.TCPFlagRst):
		e.stack.Stats().DroppedPackets.Increment()
		return nil

	case s.flags.Contains(header.TCPFlagSyn):
		if e.acceptQueueIsFull() {
			e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()
			e.stats.ReceiveErrors.ListenOverflowSynDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		opts := parseSynSegmentOptions(s)

		useSynCookies, err := func() (bool, tcpip.Error) {
			var alwaysUseSynCookies tcpip.TCPAlwaysUseSynCookies
			if err := e.stack.TransportProtocolOption(header.TCPProtocolNumber, &alwaysUseSynCookies); err != nil {
				panic(fmt.Sprintf("TransportProtocolOption(%d, %T) = %s", header.TCPProtocolNumber, alwaysUseSynCookies, err))
			}
			if alwaysUseSynCookies {
				return true, nil
			}
			e.acceptMu.Lock()
			defer e.acceptMu.Unlock()

			if len(e.acceptQueue.pendingEndpoints) == e.acceptQueue.capacity-1 {
				return true, nil
			}

			h, err := ctx.startHandshake(s, opts, &waiter.Queue{}, e.owner)
			if err != nil {
				e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
				e.stats.FailedConnectionAttempts.Increment()
				return false, err
			}
			e.acceptQueue.pendingEndpoints[h.ep] = struct{}{}

			return false, nil
		}()
		if err != nil {
			return err
		}
		if !useSynCookies {
			return nil
		}

		net := s.pkt.Network()
		route, err := e.stack.FindRoute(s.pkt.NICID, net.DestinationAddress(), net.SourceAddress(), s.pkt.NetworkProtocolNumber, false)
		if err != nil {
			return err
		}
		defer route.Release()

		synOpts := header.TCPSynOptions{
			WS:    -1,
			TS:    opts.TS,
			TSEcr: opts.TSVal,
			MSS:   calculateAdvertisedMSS(e.userMSS, route),
		}
		if opts.TS {
			offset := e.protocol.tsOffset(net.DestinationAddress(), net.SourceAddress())
			now := e.stack.Clock().NowMonotonic()
			synOpts.TSVal = offset.TSVal(now)
		}
		cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
		fields := tcpFields{
			id:        s.id,
			ttl:       calculateTTL(route, e.ipv4TTL, e.ipv6HopLimit),
			tos:       e.sendTOS,
			flags:     header.TCPFlagSyn | header.TCPFlagAck,
			seq:       cookie,
			ack:       s.sequenceNumber + 1,
			rcvWnd:    ctx.rcvWnd,
			df:        e.pmtud == tcpip.PMTUDiscoveryWant || e.pmtud == tcpip.PMTUDiscoveryDo || e.pmtud == tcpip.PMTUDiscoveryProbe,
			expOptVal: e.getExperimentOptionValue(route),
		}
		if err := e.sendSynTCP(route, fields, synOpts); err != nil {
			return err
		}
		e.stack.Stats().TCP.ListenOverflowSynCookieSent.Increment()
		return nil

	case s.flags.Contains(header.TCPFlagAck):
		iss := s.ackNumber - 1
		irs := s.sequenceNumber - 1

		netProtos := []tcpip.NetworkProtocolNumber{s.pkt.NetworkProtocolNumber}
		if s.id.LocalAddress.To4() != (tcpip.Address{}) {
			netProtos = []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
		}
		for _, netProto := range netProtos {
			if newEP := e.stack.FindTransportEndpoint(netProto, ProtocolNumber, s.id, s.pkt.NICID); newEP != nil && newEP != e {
				tcpEP := newEP.(*Endpoint)
				if !tcpEP.EndpointState().connected() {
					continue
				}
				if !tcpEP.enqueueSegment(s) {
					return nil
				}
				tcpEP.notifyProcessor()
				return nil
			}
		}

		data, ok := ctx.isCookieValid(s.id, iss, irs)
		if !ok || int(data) >= len(mssTable) {
			e.stack.Stats().TCP.ListenOverflowInvalidSynCookieRcvd.Increment()
			e.stack.Stats().DroppedPackets.Increment()

			return replyWithReset(e.stack, s, e.sendTOS, e.ipv4TTL, e.ipv6HopLimit)
		}

		e.acceptMu.Lock()
		if e.acceptQueue.isFull() {
			e.acceptMu.Unlock()
			e.stack.Stats().TCP.ListenOverflowAckDrop.Increment()
			e.stats.ReceiveErrors.ListenOverflowAckDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		e.stack.Stats().TCP.ListenOverflowSynCookieRcvd.Increment()
		rcvdSynOptions := header.TCPSynOptions{
			MSS: mssTable[data],
			WS: -1,
		}

		if s.parsedOptions.TS {
			rcvdSynOptions.TS = true
			rcvdSynOptions.TSVal = s.parsedOptions.TSVal
			rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
		}

		n, err := ctx.createConnectingEndpoint(s, rcvdSynOptions, &waiter.Queue{})
		if err != nil {
			e.acceptMu.Unlock()
			return err
		}

		e.propagateInheritableOptionsLocked(n)

		if !n.reserveTupleLocked() {
			n.mu.Unlock()
			e.acceptMu.Unlock()
			n.Close()

			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
			return nil
		}

		if err := n.stack.RegisterTransportEndpoint(
			n.effectiveNetProtos,
			ProtocolNumber,
			n.TransportEndpointInfo.ID,
			n,
			n.boundPortFlags,
			n.boundBindToDevice,
		); err != nil {
			n.mu.Unlock()
			e.acceptMu.Unlock()
			n.Close()

			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
			return err
		}

		n.isRegistered = true
		net := s.pkt.Network()
		n.TSOffset = n.protocol.tsOffset(net.DestinationAddress(), net.SourceAddress())

		n.isConnectNotified = true
		h := handshake{
			ep:                  n,
			iss:                 iss,
			ackNum:              irs + 1,
			rcvWnd:              seqnum.Size(n.initialReceiveWindow()),
			sndWnd:              s.window,
			rcvWndScale:         e.rcvWndScaleForHandshake(),
			sndWndScale:         rcvdSynOptions.WS,
			mss:                 rcvdSynOptions.MSS,
			sampleRTTWithTSOnly: true,
		}
		h.ep.AssertLockHeld(n)
		h.transitionToStateEstablishedLocked(s)
		n.mu.Unlock()

		if (s.flags.Contains(header.TCPFlagFin) || s.payloadSize() > 0) && n.enqueueSegment(s) {
			n.notifyProcessor()
		}

		e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()

		e.acceptQueue.endpoints.PushBack(n)
		e.acceptMu.Unlock()

		e.waiterQueue.Notify(waiter.ReadableEvents)
		return nil

	default:
		e.stack.Stats().DroppedPackets.Increment()
		return nil
	}
}

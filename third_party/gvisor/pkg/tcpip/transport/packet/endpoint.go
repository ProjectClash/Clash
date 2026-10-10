// Copyright 2019 The gVisor Authors.
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

package packet

import (
	"io"
	"math"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type tpacketVersion int

const (
	tpacketVersion1 tpacketVersion = iota
	tpacketVersion2
)

var _ stack.MappablePacketEndpoint = (*endpoint)(nil)

type packet struct {
	packetEntry
	data       *stack.PacketBuffer
	receivedAt time.Time `state:".(int64)"`
	senderAddr tcpip.FullAddress
	packetInfo tcpip.LinkPacketInfo
}

type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	stack       *stack.Stack
	waiterQueue *waiter.Queue
	cooked      bool
	ops         tcpip.SocketOptions
	stats       tcpip.TransportEndpointStats

	rcvMu rcvMutex `state:"nosave"`
	rcvList packetList
	rcvBufSize int
	rcvClosed bool
	rcvDisabled bool

	mu endpointRWMutex `state:"nosave"`
	closed bool
	boundNetProto tcpip.NetworkProtocolNumber
	boundNIC tcpip.NICID

	lastErrorMu lastErrorMutex `state:"nosave"`
	lastError tcpip.Error

	packetMmapMu packetMmapRWMutex `state:"nosave"`
	packetMMapVersion tpacketVersion
	packetMMapReserve int
	packetMMapEp stack.PacketMMapEndpoint
}

func NewEndpoint(s *stack.Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) tcpip.Endpoint {
	ep := &endpoint{
		stack:         s,
		cooked:        cooked,
		boundNetProto: netProto,
		waiterQueue:   waiterQueue,
	}
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	ep.ops.SetReceiveBufferSize(32*1024, false)

	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.ops.SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		ep.ops.SetReceiveBufferSize(int64(rs.Default), false)
	}

	s.RegisterPacketEndpoint(0, netProto, ep)

	return ep
}

func (ep *endpoint) Abort() {
	ep.Close()
}

func (ep *endpoint) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.closed {
		return
	}
	ep.stack.UnregisterPacketEndpoint(ep.boundNIC, ep.boundNetProto, ep)

	ep.packetMmapMu.Lock()
	if ep.packetMMapEp != nil {
		ep.packetMMapEp.Close()
		ep.packetMMapEp = nil
	}
	ep.packetMmapMu.Unlock()

	ep.rcvMu.Lock()
	defer ep.rcvMu.Unlock()

	ep.rcvClosed = true
	ep.rcvBufSize = 0
	for !ep.rcvList.Empty() {
		p := ep.rcvList.Front()
		ep.rcvList.Remove(p)
		p.data.DecRef()
	}

	ep.closed = true
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (*endpoint) ModerateRecvBuf(int) {}

func (ep *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	ep.rcvMu.Lock()

	if ep.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if ep.rcvClosed {
			ep.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		ep.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	packet := ep.rcvList.Front()
	if !opts.Peek {
		ep.rcvList.Remove(packet)
		defer packet.data.DecRef()
		ep.rcvBufSize -= packet.data.Size()
	}

	ep.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: packet.data.Size(),
		ControlMessages: tcpip.ReceivableControlMessages{
			HasTimestamp: true,
			Timestamp:    packet.receivedAt,
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = packet.senderAddr
	}
	if opts.NeedLinkPacketInfo {
		res.LinkPacketInfo = packet.packetInfo
	}

	n, err := packet.data.Data().ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

func (ep *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	if !ep.stack.PacketEndpointWriteSupported() {
		return 0, &tcpip.ErrNotSupported{}
	}

	ep.mu.Lock()
	closed := ep.closed
	nicID := ep.boundNIC
	proto := ep.boundNetProto
	ep.mu.Unlock()
	if closed {
		return 0, &tcpip.ErrClosedForSend{}
	}

	var remote tcpip.LinkAddress
	if to := opts.To; to != nil {
		remote = to.LinkAddr

		if n := to.NIC; n != 0 {
			nicID = n
		}

		if p := to.Port; p != 0 {
			proto = tcpip.NetworkProtocolNumber(p)
		}
	}

	if nicID == 0 {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	if p.Len() > header.DatagramMaximumSize {
		return 0, &tcpip.ErrMessageTooLong{}
	}

	var payload buffer.Buffer
	if _, err := payload.WriteFromReader(p, int64(p.Len())); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}
	payloadSz := payload.Size()

	mark := ep.ops.GetMark()
	if err := func() tcpip.Error {
		if ep.cooked {
			return ep.stack.WritePacketToRemoteWithMark(nicID, remote, proto, payload, mark)
		}
		return ep.stack.WriteRawPacketWithMark(nicID, proto, payload, mark)
	}(); err != nil {
		return 0, err
	}
	return payloadSz, nil
}

func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Connect(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (ep *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {

	ep.mu.Lock()
	defer ep.mu.Unlock()

	netProto := tcpip.NetworkProtocolNumber(addr.Port)
	if netProto == 0 {
		netProto = ep.boundNetProto
	}

	if ep.boundNIC == addr.NIC && ep.boundNetProto == netProto {
		return nil
	}

	ep.stack.UnregisterPacketEndpoint(ep.boundNIC, ep.boundNetProto, ep)
	ep.boundNIC = 0
	ep.boundNetProto = 0

	if err := ep.stack.RegisterPacketEndpoint(addr.NIC, netProto, ep); err != nil {
		return err
	}

	ep.boundNIC = addr.NIC
	ep.boundNetProto = netProto
	return nil
}

func (ep *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  ep.boundNIC,
		Port: uint16(ep.boundNetProto),
	}, nil
}

func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

func (ep *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.WritableEvents & mask

	if (mask & waiter.ReadableEvents) != 0 {
		ep.packetMmapMu.RLock()
		if ep.packetMMapEp != nil {
			result |= ep.packetMMapEp.Readiness(mask)
		}
		ep.packetMmapMu.RUnlock()
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() || ep.rcvClosed {
			result |= waiter.ReadableEvents
		}
		ep.rcvMu.Unlock()
	}

	return result
}

func (ep *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil
	case *tcpip.TpacketReq:
		ep.rcvMu.Lock()
		defer ep.rcvMu.Unlock()
		if !ep.rcvList.Empty() {
			return &tcpip.ErrWouldBlock{}
		}
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (ep *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	switch opt {
	case tcpip.PacketMMapVersionOption:
		ep.packetMmapMu.Lock()
		defer ep.packetMmapMu.Unlock()
		version := tpacketVersion(v)
		switch version {
		case tpacketVersion1, tpacketVersion2:
			if ep.packetMMapEp != nil {
				return &tcpip.ErrEndpointBusy{}
			}
			ep.packetMMapVersion = version
			return nil
		default:
			return &tcpip.ErrInvalidOptionValue{}
		}
	case tcpip.PacketMMapReserveOption:
		ep.packetMmapMu.Lock()
		defer ep.packetMmapMu.Unlock()
		if ep.packetMMapEp != nil {
			return &tcpip.ErrEndpointBusy{}
		}
		if uint32(v) > uint32(math.MaxInt32) {
			return &tcpip.ErrInvalidOptionValue{}
		}
		ep.packetMMapReserve = v
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (ep *endpoint) LastError() tcpip.Error {
	ep.lastErrorMu.Lock()
	defer ep.lastErrorMu.Unlock()

	err := ep.lastError
	ep.lastError = nil
	return err
}

func (ep *endpoint) UpdateLastError(err tcpip.Error) {
	ep.lastErrorMu.Lock()
	ep.lastError = err
	ep.lastErrorMu.Unlock()
}

func (ep *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch opt := opt.(type) {
	case *tcpip.TpacketStats:
		ep.packetMmapMu.RLock()
		defer ep.packetMmapMu.RUnlock()
		if ep.packetMMapEp == nil {
			return nil
		}
		*opt = ep.packetMMapEp.Stats()
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (ep *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() {
			p := ep.rcvList.Front()
			v = p.data.Size()
		}
		ep.rcvMu.Unlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

func (ep *endpoint) HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	ep.packetMmapMu.RLock()
	if ep.packetMMapEp != nil {
		if handled := ep.packetMMapEp.HandlePacket(nicID, netProto, pkt); handled {
			ep.packetMmapMu.RUnlock()
			return
		}
	}
	ep.packetMmapMu.RUnlock()

	wasEmpty := ep.handlePacketInner(nicID, netProto, pkt)

	ep.stats.PacketsReceived.Increment()
	if wasEmpty {
		ep.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (ep *endpoint) HandlePacketMMapCopy(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	_ = ep.handlePacketInner(nicID, netProto, pkt)
}

func (ep *endpoint) handlePacketInner(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) bool {
	ep.rcvMu.Lock()

	if ep.rcvClosed {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ClosedReceiver.Increment()
		return false
	}

	rcvBufSize := ep.ops.GetReceiveBufferSize()
	if ep.rcvDisabled || ep.rcvBufSize >= int(rcvBufSize) {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return false
	}

	wasEmpty := ep.rcvBufSize == 0

	rcvdPkt := packet{
		packetInfo: tcpip.LinkPacketInfo{
			Protocol: netProto,
			PktType:  pkt.PktType,
		},
		senderAddr: tcpip.FullAddress{
			NIC: nicID,
		},
		receivedAt: ep.stack.Clock().Now(),
	}

	if len(pkt.LinkHeader().Slice()) != 0 {
		hdr := header.Ethernet(pkt.LinkHeader().Slice())
		rcvdPkt.senderAddr.LinkAddr = hdr.SourceAddress()
	}

	pktBuf := pkt.ToBuffer()
	if ep.cooked {
		pktBuf.TrimFront(int64(len(pkt.LinkHeader().Slice()) + len(pkt.VirtioNetHeader().Slice())))
	}
	rcvdPkt.data = stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pktBuf})

	ep.rcvList.PushBack(&rcvdPkt)
	ep.rcvBufSize += rcvdPkt.data.Size()
	ep.rcvMu.Unlock()
	return wasEmpty
}

func (*endpoint) State() uint32 {
	return 0
}

func (ep *endpoint) Info() tcpip.EndpointInfo {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return &stack.TransportEndpointInfo{NetProto: ep.boundNetProto}
}

func (ep *endpoint) Stats() tcpip.EndpointStats {
	return &ep.stats
}

func (*endpoint) SetOwner(tcpip.PacketOwner) {}

func (ep *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &ep.ops
}

func (ep *endpoint) GetPacketMMapOpts(req *tcpip.TpacketReq, isRx bool) stack.PacketMMapOpts {
	ep.packetMmapMu.Lock()
	defer ep.packetMmapMu.Unlock()

	return stack.PacketMMapOpts{
		Req:            req,
		IsRx:           isRx,
		Cooked:         ep.cooked,
		Stack:          ep.stack,
		Wq:             ep.waiterQueue,
		PacketEndpoint: ep,
		Version:        int(ep.packetMMapVersion),
		Reserve:        uint32(ep.packetMMapReserve),
	}
}

func (ep *endpoint) SetPacketMMapEndpoint(m stack.PacketMMapEndpoint) {
	ep.packetMmapMu.Lock()
	defer ep.packetMmapMu.Unlock()
	ep.packetMMapEp = m
}

func (ep *endpoint) GetPacketMMapEndpoint() stack.PacketMMapEndpoint {
	ep.packetMmapMu.RLock()
	defer ep.packetMmapMu.RUnlock()
	return ep.packetMMapEp
}

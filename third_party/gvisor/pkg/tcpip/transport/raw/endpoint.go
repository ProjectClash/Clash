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

package raw

import (
	"fmt"
	"io"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/internal/network"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type rawPacket struct {
	rawPacketEntry
	data       *stack.PacketBuffer
	receivedAt time.Time `state:".(int64)"`
	senderAddr tcpip.FullAddress
	packetInfo tcpip.IPPacketInfo

	tosOrTClass uint8
	ttlOrHopLimit uint8
}

type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	stack       *stack.Stack
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue
	associated  bool

	net   network.Endpoint
	stats tcpip.TransportEndpointStats
	ops   tcpip.SocketOptions

	rcvMu sync.Mutex `state:"nosave"`
	rcvList rawPacketList
	rcvBufSize int
	rcvClosed bool
	rcvDisabled bool

	mu sync.RWMutex `state:"nosave"`

	ipv6ChecksumOffset int
	icmpv6Filter tcpip.ICMPv6Filter
}

func NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return newEndpoint(stack, netProto, transProto, waiterQueue, true)
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, tcpip.Error) {
	ipv6ChecksumOffset := -1
	if netProto == header.IPv6ProtocolNumber && transProto == header.ICMPv6ProtocolNumber {
		ipv6ChecksumOffset = header.ICMPv6ChecksumOffset
	}

	e := &endpoint{
		stack:              s,
		transProto:         transProto,
		waiterQueue:        waiterQueue,
		associated:         associated,
		ipv6ChecksumOffset: ipv6ChecksumOffset,
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetHeaderIncluded(!associated)
	e.ops.SetSendBufferSize(32*1024, false)
	e.ops.SetReceiveBufferSize(32*1024, false)
	e.net.Init(s, netProto, transProto, &e.ops, waiterQueue)

	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false)
	}

	if !associated {
		e.ops.SetReceiveBufferSize(0, false)
		e.waiterQueue = nil
		return e, nil
	}

	if err := e.stack.RegisterRawTransportEndpoint(netProto, e.transProto, e); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *endpoint) WakeupWriters() {
	e.net.MaybeSignalWritable()
}

func (e *endpoint) HasNIC(id int32) bool {
	return e.stack.HasNIC(tcpip.NICID(id))
}

func (e *endpoint) Abort() {
	e.Close()
}

func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.net.State() == transport.DatagramEndpointStateClosed {
		return
	}

	e.net.Close()

	if !e.associated {
		return
	}

	e.stack.UnregisterRawTransportEndpoint(e.net.NetProto(), e.transProto, e)

	e.rcvMu.Lock()
	defer e.rcvMu.Unlock()

	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
		p.data.DecRef()
	}

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (*endpoint) ModerateRecvBuf(int) {}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.net.SetOwner(owner)
}

func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		e.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	pkt := e.rcvList.Front()
	if !opts.Peek {
		e.rcvList.Remove(pkt)
		defer pkt.data.DecRef()
		e.rcvBufSize -= pkt.data.Data().Size()
	}

	e.rcvMu.Unlock()

	cm := tcpip.ReceivableControlMessages{
		HasTimestamp: true,
		Timestamp:    pkt.receivedAt,
	}
	switch netProto := e.net.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if e.ops.GetReceiveTOS() {
			cm.HasTOS = true
			cm.TOS = pkt.tosOrTClass
		}
		if e.ops.GetReceiveTTL() {
			cm.HasTTL = true
			cm.TTL = pkt.ttlOrHopLimit
		}
		if e.ops.GetReceivePacketInfo() {
			cm.HasIPPacketInfo = true
			cm.PacketInfo = pkt.packetInfo
		}
	case header.IPv6ProtocolNumber:
		if e.ops.GetReceiveTClass() {
			cm.HasTClass = true
			cm.TClass = uint32(pkt.tosOrTClass)
		}
		if e.ops.GetReceiveHopLimit() {
			cm.HasHopLimit = true
			cm.HopLimit = pkt.ttlOrHopLimit
		}
		if e.ops.GetIPv6ReceivePacketInfo() {
			cm.HasIPv6PacketInfo = true
			cm.IPv6PacketInfo = tcpip.IPv6PacketInfo{
				NIC:  pkt.packetInfo.NIC,
				Addr: pkt.packetInfo.DestinationAddr,
			}
		}
	default:
		panic(fmt.Sprintf("unrecognized network protocol = %d", netProto))
	}

	res := tcpip.ReadResult{
		Total:           pkt.data.Data().Size(),
		ControlMessages: cm,
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = pkt.senderAddr
	}

	n, err := pkt.data.Data().ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	netProto := e.net.NetProto()
	if !e.associated && netProto == header.IPv6ProtocolNumber {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	if opts.To != nil {
		if netProto == header.IPv6ProtocolNumber && opts.To.Addr.BitLen() != header.IPv6AddressSizeBits {
			return 0, &tcpip.ErrInvalidOptionValue{}
		}
	}

	n, err := e.write(p, opts)
	switch err.(type) {
	case nil:
		e.stats.PacketsSent.Increment()
	case *tcpip.ErrMessageTooLong, *tcpip.ErrInvalidOptionValue:
		e.stats.WriteErrors.InvalidArgs.Increment()
	case *tcpip.ErrClosedForSend:
		e.stats.WriteErrors.WriteClosed.Increment()
	case *tcpip.ErrInvalidEndpointState:
		e.stats.WriteErrors.InvalidEndpointState.Increment()
	case *tcpip.ErrHostUnreachable, *tcpip.ErrBroadcastDisabled, *tcpip.ErrNetworkUnreachable:
		e.stats.SendErrors.NoRoute.Increment()
	default:
		e.stats.SendErrors.SendToNetworkFailed.Increment()
	}
	return n, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	e.mu.Lock()
	ctx, err := e.net.AcquireContextForWrite(opts)
	ipv6ChecksumOffset := e.ipv6ChecksumOffset
	e.mu.Unlock()
	if err != nil {
		return 0, err
	}
	defer ctx.Release()

	if p.Len() > int(ctx.MTU()) {
		return 0, &tcpip.ErrMessageTooLong{}
	}

	if p.Len() > header.DatagramMaximumSize {
		return 0, &tcpip.ErrMessageTooLong{}
	}

	var payload buffer.Buffer
	defer payload.Release()
	if _, err := payload.WriteFromReader(p, int64(p.Len())); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}
	payloadSz := payload.Size()

	if packetInfo := ctx.PacketInfo(); packetInfo.NetProto == header.IPv6ProtocolNumber && ipv6ChecksumOffset >= 0 &&
		!(e.ops.GetHeaderIncluded() && e.transProto == header.ICMPv6ProtocolNumber) {
		if payload.Size() < int64(ipv6ChecksumOffset+checksum.Size) {
			return 0, &tcpip.ErrInvalidOptionValue{}
		}

		payloadView, _ := payload.PullUp(ipv6ChecksumOffset, int(payload.Size())-ipv6ChecksumOffset)
		xsum := header.PseudoHeaderChecksum(e.transProto, packetInfo.LocalAddress, packetInfo.RemoteAddress, uint16(payload.Size()))
		checksum.Put(payloadView.AsSlice(), 0)
		xsum = checksum.Combine(payload.Checksum(0), xsum)
		checksum.Put(payloadView.AsSlice(), ^xsum)
	}

	pkt := ctx.TryNewPacketBuffer(int(ctx.PacketInfo().MaxHeaderLength), payload.Clone())
	if pkt == nil {
		return 0, &tcpip.ErrWouldBlock{}
	}
	defer pkt.DecRef()

	if err := ctx.WritePacket(pkt, e.ops.GetHeaderIncluded()); err != nil {
		return 0, err
	}

	return payloadSz, nil
}

func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	netProto := e.net.NetProto()

	if netProto == header.IPv6ProtocolNumber && addr.Addr.BitLen() != header.IPv6AddressSizeBits {
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	return e.net.ConnectAndThen(addr, func(_ tcpip.NetworkProtocolNumber, _, _ stack.TransportEndpointID) tcpip.Error {
		if e.associated {
			if err := e.stack.RegisterRawTransportEndpoint(netProto, e.transProto, e); err != nil {
				return err
			}
			e.stack.UnregisterRawTransportEndpoint(netProto, e.transProto, e)
		}

		return nil
	})
}

func (e *endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	if e.net.State() != transport.DatagramEndpointStateConnected {
		return &tcpip.ErrNotConnected{}
	}
	return nil
}

func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	return e.net.BindAndThen(addr, func(netProto tcpip.NetworkProtocolNumber, _ tcpip.Address) tcpip.Error {
		if !e.associated {
			return nil
		}

		if err := e.stack.RegisterRawTransportEndpoint(netProto, e.transProto, e); err != nil {
			return err
		}
		e.stack.UnregisterRawTransportEndpoint(netProto, e.transProto, e)
		return nil
	})
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	a := e.net.GetLocalAddress()
	a.Port = uint16(e.transProto)
	return a, nil
}

func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	var result waiter.EventMask

	if e.net.HasSendSpace() {
		result |= waiter.WritableEvents & mask
	}

	if (mask & waiter.ReadableEvents) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	return result
}

func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch opt := opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil

	case *tcpip.ICMPv6Filter:
		if e.net.NetProto() != header.IPv6ProtocolNumber {
			return &tcpip.ErrUnknownProtocolOption{}
		}

		if e.transProto != header.ICMPv6ProtocolNumber {
			return &tcpip.ErrInvalidOptionValue{}
		}

		e.mu.Lock()
		defer e.mu.Unlock()
		e.icmpv6Filter = *opt
		return nil
	default:
		return e.net.SetSockOpt(opt)
	}
}

func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	switch opt {
	case tcpip.IPv6Checksum:
		if e.net.NetProto() != header.IPv6ProtocolNumber {
			return &tcpip.ErrUnknownProtocolOption{}
		}

		if e.transProto == header.ICMPv6ProtocolNumber {
			return &tcpip.ErrInvalidOptionValue{}
		}

		if v > 0 && v%checksum.Size != 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}

		e.mu.Lock()
		defer e.mu.Unlock()
		e.ipv6ChecksumOffset = v
		return nil
	default:
		return e.net.SetSockOptInt(opt, v)
	}
}

func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch opt := opt.(type) {
	case *tcpip.ICMPv6Filter:
		if e.net.NetProto() != header.IPv6ProtocolNumber {
			return &tcpip.ErrUnknownProtocolOption{}
		}

		if e.transProto != header.ICMPv6ProtocolNumber {
			return &tcpip.ErrInvalidOptionValue{}
		}

		e.mu.RLock()
		defer e.mu.RUnlock()
		*opt = e.icmpv6Filter
		return nil

	default:
		return e.net.GetSockOpt(opt)
	}
}

func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.data.Data().Size()
		}
		e.rcvMu.Unlock()
		return v, nil

	case tcpip.IPv6Checksum:
		if e.net.NetProto() != header.IPv6ProtocolNumber {
			return 0, &tcpip.ErrUnknownProtocolOption{}
		}

		e.mu.Lock()
		defer e.mu.Unlock()
		return e.ipv6ChecksumOffset, nil

	default:
		return e.net.GetSockOptInt(opt)
	}
}

func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	notifyReadableEvents := func() bool {
		e.mu.RLock()
		defer e.mu.RUnlock()
		e.rcvMu.Lock()
		defer e.rcvMu.Unlock()

		if e.rcvClosed || !e.associated {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.ClosedReceiver.Increment()
			return false
		}

		rcvBufSize := e.ops.GetReceiveBufferSize()
		if e.rcvDisabled || e.rcvBufSize >= int(rcvBufSize) {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
			return false
		}

		net := pkt.Network()
		dstAddr := net.DestinationAddress()
		srcAddr := net.SourceAddress()
		info := e.net.Info()

		switch state := e.net.State(); state {
		case transport.DatagramEndpointStateInitial:
		case transport.DatagramEndpointStateConnected:
			if info.ID.RemoteAddress != srcAddr {
				return false
			}

			fallthrough
		case transport.DatagramEndpointStateBound:
			if info.BindNICID != 0 && info.BindNICID != pkt.NICID {
				return false
			}

			if info.BindAddr != (tcpip.Address{}) && info.BindAddr != dstAddr {
				return false
			}
		default:
			panic(fmt.Sprintf("unhandled state = %s", state))
		}

		wasEmpty := e.rcvBufSize == 0

		packet := &rawPacket{
			senderAddr: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: srcAddr,
			},
			packetInfo: tcpip.IPPacketInfo{
				LocalAddr:       dstAddr,
				DestinationAddr: dstAddr,
				NIC:             pkt.NICID,
			},
		}

		packet.tosOrTClass, _ = pkt.Network().TOS()
		switch pkt.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			packet.ttlOrHopLimit = header.IPv4(pkt.NetworkHeader().Slice()).TTL()
		case header.IPv6ProtocolNumber:
			packet.ttlOrHopLimit = header.IPv6(pkt.NetworkHeader().Slice()).HopLimit()
		}

		transportHeader := pkt.TransportHeader().Slice()
		var combinedBuf buffer.Buffer
		defer combinedBuf.Release()
		switch info.NetProto {
		case header.IPv4ProtocolNumber:
			networkHeader := pkt.NetworkHeader().Slice()
			headers := buffer.NewView(len(networkHeader) + len(transportHeader))
			headers.Write(networkHeader)
			headers.Write(transportHeader)
			combinedBuf = buffer.MakeWithView(headers)
			pktBuf := pkt.Data().ToBuffer()
			combinedBuf.Merge(&pktBuf)
		case header.IPv6ProtocolNumber:
			if e.transProto == header.ICMPv6ProtocolNumber {
				if len(transportHeader) < header.ICMPv6MinimumSize {
					return false
				}

				if e.icmpv6Filter.ShouldDeny(uint8(header.ICMPv6(transportHeader).Type())) {
					return false
				}
			}

			if e.ops.GetHeaderIncluded() {
				networkHeader := pkt.NetworkHeader().Slice()
				headers := buffer.NewView(len(networkHeader) + len(transportHeader))
				headers.Write(networkHeader)
				headers.Write(transportHeader)
				combinedBuf = buffer.MakeWithView(headers)
				pktBuf := pkt.Data().ToBuffer()
				combinedBuf.Merge(&pktBuf)
				break
			}

			combinedBuf = buffer.MakeWithView(pkt.TransportHeader().View())
			pktBuf := pkt.Data().ToBuffer()
			combinedBuf.Merge(&pktBuf)

			if checksumOffset := e.ipv6ChecksumOffset; checksumOffset >= 0 {
				bufSize := int(combinedBuf.Size())
				if bufSize < checksumOffset+checksum.Size {
					return false
				}

				xsum := header.PseudoHeaderChecksum(e.transProto, srcAddr, dstAddr, uint16(bufSize))
				xsum = checksum.Combine(combinedBuf.Checksum(0), xsum)
				if xsum != 0xFFFF {
					return false
				}
			}
		default:
			panic(fmt.Sprintf("unrecognized protocol number = %d", info.NetProto))
		}

		packet.data = stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: combinedBuf.Clone()})
		packet.receivedAt = e.stack.Clock().Now()

		e.rcvList.PushBack(packet)
		e.rcvBufSize += packet.data.Data().Size()
		e.stats.PacketsReceived.Increment()

		return wasEmpty
	}()

	if notifyReadableEvents {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (e *endpoint) State() uint32 {
	return uint32(e.net.State())
}

func (e *endpoint) Info() tcpip.EndpointInfo {
	ret := e.net.Info()
	return &ret
}

func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

func (*endpoint) Wait() {}

func (*endpoint) LastError() tcpip.Error {
	return nil
}

func (e *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

func (e *endpoint) setReceiveDisabled(v bool) {
	e.rcvMu.Lock()
	defer e.rcvMu.Unlock()
	e.rcvDisabled = v
}

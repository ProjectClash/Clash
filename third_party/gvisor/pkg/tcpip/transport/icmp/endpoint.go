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

package icmp

import (
	"fmt"
	"io"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/ports"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/internal/network"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type icmpPacket struct {
	icmpPacketEntry
	senderAddress tcpip.FullAddress
	packetInfo    tcpip.IPPacketInfo
	data          *stack.PacketBuffer
	receivedAt    time.Time `state:".(int64)"`

	tosOrTClass uint8
	ttlOrHopLimit uint8
}

type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	stack       *stack.Stack
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue
	net         network.Endpoint
	stats       tcpip.TransportEndpointStats
	ops         tcpip.SocketOptions

	rcvMu      sync.Mutex `state:"nosave"`
	rcvReady   bool
	rcvList    icmpPacketList
	rcvBufSize int
	rcvClosed  bool

	mu sync.RWMutex `state:"nosave"`
	frozen bool
	ident  uint16
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	ep := &endpoint{
		stack:       s,
		transProto:  transProto,
		waiterQueue: waiterQueue,
	}
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	ep.ops.SetSendBufferSize(32*1024, false)
	ep.ops.SetReceiveBufferSize(32*1024, false)
	ep.net.Init(s, netProto, transProto, &ep.ops, waiterQueue)

	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.ops.SetSendBufferSize(int64(ss.Default), false)
	}
	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		ep.ops.SetReceiveBufferSize(int64(rs.Default), false)
	}
	return ep, nil
}

func (e *endpoint) WakeupWriters() {
	e.net.MaybeSignalWritable()
}

func (e *endpoint) Abort() {
	e.Close()
}

func (e *endpoint) Close() {
	notify := func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()

		switch state := e.net.State(); state {
		case transport.DatagramEndpointStateInitial:
		case transport.DatagramEndpointStateClosed:
			return false
		case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
			info := e.net.Info()
			info.ID.LocalPort = e.ident
			e.stack.UnregisterTransportEndpoint([]tcpip.NetworkProtocolNumber{info.NetProto}, e.transProto, info.ID, e, ports.Flags{}, tcpip.NICID(e.ops.GetBindToDevice()))
		default:
			panic(fmt.Sprintf("unhandled state = %s", state))
		}

		e.net.Shutdown()
		e.net.Close()

		e.rcvMu.Lock()
		defer e.rcvMu.Unlock()
		e.rcvClosed = true
		e.rcvBufSize = 0
		for !e.rcvList.Empty() {
			p := e.rcvList.Front()
			e.rcvList.Remove(p)
			p.data.DecRef()
		}

		return true
	}()

	if notify {
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
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

	p := e.rcvList.Front()
	if !opts.Peek {
		e.rcvList.Remove(p)
		defer p.data.DecRef()
		e.rcvBufSize -= p.data.Data().Size()
	}

	e.rcvMu.Unlock()

	cm := tcpip.ReceivableControlMessages{
		HasTimestamp: true,
		Timestamp:    p.receivedAt,
	}
	switch netProto := e.net.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if e.ops.GetReceiveTOS() {
			cm.HasTOS = true
			cm.TOS = p.tosOrTClass
		}
		if e.ops.GetReceivePacketInfo() {
			cm.HasIPPacketInfo = true
			cm.PacketInfo = p.packetInfo
		}
		if e.ops.GetReceiveTTL() {
			cm.HasTTL = true
			cm.TTL = p.ttlOrHopLimit
		}
	case header.IPv6ProtocolNumber:
		if e.ops.GetReceiveTClass() {
			cm.HasTClass = true
			cm.TClass = uint32(p.tosOrTClass)
		}
		if e.ops.GetIPv6ReceivePacketInfo() {
			cm.HasIPv6PacketInfo = true
			cm.IPv6PacketInfo = tcpip.IPv6PacketInfo{
				NIC:  p.packetInfo.NIC,
				Addr: p.packetInfo.DestinationAddr,
			}
		}
		if e.ops.GetReceiveHopLimit() {
			cm.HasHopLimit = true
			cm.HopLimit = p.ttlOrHopLimit
		}
	default:
		panic(fmt.Sprintf("unrecognized network protocol = %d", netProto))
	}

	res := tcpip.ReadResult{
		Total:           p.data.Data().Size(),
		ControlMessages: cm,
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = p.senderAddress
	}

	n, err := p.data.Data().ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

func (e *endpoint) prepareForWriteInner(to *tcpip.FullAddress) (retry bool, err tcpip.Error) {
	switch e.net.State() {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateConnected:
		return false, nil
	case transport.DatagramEndpointStateBound:
		if to == nil {
			return false, &tcpip.ErrDestinationRequired{}
		}
		return false, nil
	default:
		return false, &tcpip.ErrInvalidEndpointState{}
	}

	e.mu.RUnlock()
	e.mu.Lock()
	defer e.mu.DowngradeLock()

	if e.net.State() != transport.DatagramEndpointStateInitial {
		return true, nil
	}

	if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
		return false, err
	}

	return true, nil
}

func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
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

func (e *endpoint) prepareForWrite(opts tcpip.WriteOptions) (network.WriteContext, uint16, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for {
		retry, err := e.prepareForWriteInner(opts.To)
		if err != nil {
			return network.WriteContext{}, 0, err
		}

		if !retry {
			break
		}
	}

	ctx, err := e.net.AcquireContextForWrite(opts)
	return ctx, e.ident, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	ctx, ident, err := e.prepareForWrite(opts)
	if err != nil {
		return 0, err
	}
	defer ctx.Release()

	if p.Len() > header.DatagramMaximumSize {
		return 0, &tcpip.ErrMessageTooLong{}
	}

	v := buffer.NewView(p.Len())
	defer v.Release()
	if _, err := io.CopyN(v, p, int64(p.Len())); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}
	n := v.Size()

	switch netProto, pktInfo := e.net.NetProto(), ctx.PacketInfo(); netProto {
	case header.IPv4ProtocolNumber:
		if err := send4(e.stack, &ctx, ident, v, pktInfo.MaxHeaderLength); err != nil {
			return 0, err
		}

	case header.IPv6ProtocolNumber:
		if err := send6(e.stack, &ctx, ident, v, pktInfo.LocalAddress, pktInfo.RemoteAddress, pktInfo.MaxHeaderLength); err != nil {
			return 0, err
		}
	default:
		panic(fmt.Sprintf("unhandled network protocol = %d", netProto))
	}

	return int64(n), nil
}

var _ tcpip.SocketOptionsHandler = (*endpoint)(nil)

func (e *endpoint) HasNIC(id int32) bool {
	return e.stack.HasNIC(tcpip.NICID(id))
}

func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return e.net.SetSockOpt(opt)
}

func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.net.SetSockOptInt(opt, v)
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

	default:
		return e.net.GetSockOptInt(opt)
	}
}

func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return e.net.GetSockOpt(opt)
}

func send4(s *stack.Stack, ctx *network.WriteContext, ident uint16, data *buffer.View, maxHeaderLength uint16) tcpip.Error {
	if data.Size() < header.ICMPv4MinimumSize {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := ctx.TryNewPacketBuffer(header.ICMPv4MinimumSize+int(maxHeaderLength), buffer.Buffer{})
	if pkt == nil {
		return &tcpip.ErrWouldBlock{}
	}
	defer pkt.DecRef()

	icmpv4 := header.ICMPv4(pkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	copy(icmpv4, data.AsSlice())
	icmpv4.SetIdent(ident)
	data.TrimFront(header.ICMPv4MinimumSize)

	if icmpv4.Type() != header.ICMPv4Echo || icmpv4.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	icmpv4.SetChecksum(0)
	icmpv4.SetChecksum(^checksum.Checksum(icmpv4, checksum.Checksum(data.AsSlice(), 0)))
	pkt.Data().AppendView(data.Clone())

	stats := s.Stats().ICMP.V4.PacketsSent

	if err := ctx.WritePacket(pkt, false); err != nil {
		stats.Dropped.Increment()
		return err
	}

	stats.EchoRequest.Increment()
	return nil
}

func send6(s *stack.Stack, ctx *network.WriteContext, ident uint16, data *buffer.View, src, dst tcpip.Address, maxHeaderLength uint16) tcpip.Error {
	if data.Size() < header.ICMPv6EchoMinimumSize {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := ctx.TryNewPacketBuffer(header.ICMPv6MinimumSize+int(maxHeaderLength), buffer.Buffer{})
	if pkt == nil {
		return &tcpip.ErrWouldBlock{}
	}
	defer pkt.DecRef()

	icmpv6 := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	copy(icmpv6, data.AsSlice())
	icmpv6.SetIdent(ident)
	data.TrimFront(header.ICMPv6MinimumSize)

	if icmpv6.Type() != header.ICMPv6EchoRequest || icmpv6.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt.Data().AppendView(data.Clone())
	pktData := pkt.Data()
	icmpv6.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpv6,
		Src:         src,
		Dst:         dst,
		PayloadCsum: pktData.Checksum(),
		PayloadLen:  pktData.Size(),
	}))

	stats := s.Stats().ICMP.V6.PacketsSent

	if err := ctx.WritePacket(pkt, false); err != nil {
		stats.Dropped.Increment()
		return err
	}

	stats.EchoRequest.Increment()
	return nil
}

func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.net.ConnectAndThen(addr, func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error {
		nextID.LocalPort = e.ident

		nextID, err := e.registerWithStack(netProto, nextID)
		if err != nil {
			return err
		}

		e.ident = nextID.LocalPort
		return nil
	})
	if err != nil {
		return err
	}

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (*endpoint) ConnectEndpoint(tcpip.Endpoint) tcpip.Error {
	return &tcpip.ErrInvalidEndpointState{}
}

func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
		return &tcpip.ErrNotConnected{}
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}

	if flags&tcpip.ShutdownWrite != 0 {
		if err := e.net.Shutdown(); err != nil {
			return err
		}
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.ReadableEvents)
		}
	}

	return nil
}

func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (e *endpoint) registerWithStack(netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.Error) {
	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	if id.LocalPort != 0 {
		return id, e.stack.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{netProto}, e.transProto, id, e, ports.Flags{}, bindToDevice)
	}

	_, err := e.stack.PickEphemeralPort(e.stack.SecureRNG(), func(p uint16) (bool, tcpip.Error) {
		id.LocalPort = p
		err := e.stack.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{netProto}, e.transProto, id, e, ports.Flags{}, bindToDevice)
		switch err.(type) {
		case nil:
			return true, nil
		case *tcpip.ErrPortInUse:
			return false, nil
		default:
			return false, err
		}
	})

	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	if e.net.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	err := e.net.BindAndThen(addr, func(boundNetProto tcpip.NetworkProtocolNumber, boundAddr tcpip.Address) tcpip.Error {
		id := stack.TransportEndpointID{
			LocalPort:    addr.Port,
			LocalAddress: addr.Addr,
		}
		id, err := e.registerWithStack(boundNetProto, id)
		if err != nil {
			return err
		}

		e.ident = id.LocalPort
		return nil
	})
	if err != nil {
		return err
	}

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (e *endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast ||
		header.IsV4MulticastAddress(addr) ||
		header.IsV6MulticastAddress(addr) ||
		e.stack.IsSubnetBroadcast(nicID, e.net.NetProto(), addr)
}

func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	if addr.Addr.BitLen() != 0 && e.isBroadcastOrMulticast(addr.NIC, addr.Addr) {
		return &tcpip.ErrBadLocalAddress{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return e.bindLocked(addr)
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.net.GetLocalAddress()
	addr.Port = e.ident
	return addr, nil
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if addr, connected := e.net.GetRemoteAddress(); connected {
		return addr, nil
	}

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

func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	switch e.net.NetProto() {
	case header.IPv4ProtocolNumber:
		h := header.ICMPv4(pkt.TransportHeader().Slice())
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	case header.IPv6ProtocolNumber:
		h := header.ICMPv6(pkt.TransportHeader().Slice())
		if len(h) < header.ICMPv6MinimumSize || h.Type() != header.ICMPv6EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	}

	e.rcvMu.Lock()

	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	net := pkt.Network()
	dstAddr := net.DestinationAddress()
	packet := &icmpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
		},
		packetInfo: tcpip.IPPacketInfo{
			NIC:             pkt.NICID,
			DestinationAddr: dstAddr,
		},
	}

	packet.tosOrTClass, _ = net.TOS()
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		packet.ttlOrHopLimit = header.IPv4(pkt.NetworkHeader().Slice()).TTL()
	case header.IPv6ProtocolNumber:
		packet.ttlOrHopLimit = header.IPv6(pkt.NetworkHeader().Slice()).HopLimit()
	}

	pktBuf := pkt.ToBuffer()
	pktBuf.TrimFront(int64(pkt.HeaderSize() - len(pkt.TransportHeader().Slice())))
	packet.data = stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pktBuf})

	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Data().Size()

	packet.receivedAt = e.stack.Clock().Now()

	e.rcvMu.Unlock()
	e.stats.PacketsReceived.Increment()
	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (*endpoint) HandleError(stack.TransportError, *stack.PacketBuffer) {}

func (e *endpoint) State() uint32 {
	return uint32(e.net.State())
}

func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ret := e.net.Info()
	ret.ID.LocalPort = e.ident
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

func (e *endpoint) freeze() {
	e.mu.Lock()
	e.frozen = true
	e.mu.Unlock()
}

func (e *endpoint) thaw() {
	e.mu.Lock()
	e.frozen = false
	e.mu.Unlock()
}

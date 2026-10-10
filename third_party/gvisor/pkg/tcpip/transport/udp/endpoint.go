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

package udp

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"time"

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

type udpPacket struct {
	udpPacketEntry
	netProto           tcpip.NetworkProtocolNumber
	senderAddress      tcpip.FullAddress
	destinationAddress tcpip.FullAddress
	packetInfo         tcpip.IPPacketInfo
	pkt                *stack.PacketBuffer
	receivedAt         time.Time `state:".(int64)"`
	tosOrTClass uint8
	ttlOrHopLimit uint8
}

type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	stack       *stack.Stack
	waiterQueue *waiter.Queue
	net         network.Endpoint
	stats       tcpip.TransportEndpointStats
	ops         tcpip.SocketOptions

	rcvMu      sync.Mutex `state:"nosave"`
	rcvReady   bool
	rcvList    udpPacketList
	rcvBufSize int
	rcvClosed  bool

	lastErrorMu sync.Mutex `state:"nosave"`
	lastError   tcpip.Error

	mu        sync.RWMutex `state:"nosave"`
	portFlags ports.Flags

	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	readShutdown bool

	effectiveNetProtos []tcpip.NetworkProtocolNumber

	frozen bool

	localPort  uint16
	remotePort uint16
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       s,
		waiterQueue: waiterQueue,
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetSendBufferSize(32*1024, false)
	e.ops.SetReceiveBufferSize(32*1024, false)
	e.net.Init(s, netProto, header.UDPProtocolNumber, &e.ops, waiterQueue)

	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false)
	}

	return e
}

func (e *endpoint) WakeupWriters() {
	e.net.MaybeSignalWritable()
}

func (e *endpoint) LastError() tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()

	err := e.lastError
	e.lastError = nil
	return err
}

func (e *endpoint) UpdateLastError(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
}

func (e *endpoint) Abort() {
	e.Close()
}

func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeLocked()
}

func (e *endpoint) closeLocked() {
	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateClosed:
		return
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		id := e.net.Info().ID
		id.LocalPort = e.localPort
		id.RemotePort = e.remotePort
		e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, id, e, e.boundPortFlags, e.boundBindToDevice)
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}

	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
		p.pkt.DecRef()
	}
	e.rcvMu.Unlock()

	e.net.Shutdown()
	e.net.Close()
	e.readShutdown = true

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (*endpoint) ModerateRecvBuf(int) {}

func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if err := e.LastError(); err != nil {
		return tcpip.ReadResult{}, err
	}

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
		defer p.pkt.DecRef()
		e.rcvBufSize -= p.pkt.Data().Size()
	}
	e.rcvMu.Unlock()

	cm := tcpip.ReceivableControlMessages{
		HasTimestamp: true,
		Timestamp:    p.receivedAt,
	}
	switch p.netProto {
	case header.IPv4ProtocolNumber:
		if e.ops.GetReceiveTOS() {
			cm.HasTOS = true
			cm.TOS = p.tosOrTClass
		}
		if e.ops.GetReceiveTTL() {
			cm.HasTTL = true
			cm.TTL = p.ttlOrHopLimit
		}
		if e.ops.GetReceivePacketInfo() {
			cm.HasIPPacketInfo = true
			cm.PacketInfo = p.packetInfo
		}
	case header.IPv6ProtocolNumber:
		if e.ops.GetReceiveTClass() {
			cm.HasTClass = true
			cm.TClass = uint32(p.tosOrTClass)
		}
		if e.ops.GetReceiveHopLimit() {
			cm.HasHopLimit = true
			cm.HopLimit = p.ttlOrHopLimit
		}
		if e.ops.GetIPv6ReceivePacketInfo() {
			cm.HasIPv6PacketInfo = true
			cm.IPv6PacketInfo = tcpip.IPv6PacketInfo{
				NIC:  p.packetInfo.NIC,
				Addr: p.packetInfo.DestinationAddr,
			}
		}
	default:
		panic(fmt.Sprintf("unrecognized network protocol = %d", p.netProto))
	}

	if e.ops.GetReceiveOriginalDstAddress() {
		cm.HasOriginalDstAddress = true
		cm.OriginalDstAddress = p.destinationAddress
	}

	res := tcpip.ReadResult{
		Total:           p.pkt.Data().Size(),
		ControlMessages: cm,
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = p.senderAddress
	}
	if opts.NeedReceivedExperimentOption {
		expOptVal, _ := p.pkt.ExperimentOptionValue()
		res.ReceivedExperimentOption = expOptVal
	}

	n, err := p.pkt.Data().ReadTo(dst, opts.Peek)
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

var _ tcpip.EndpointWithPreflight = (*endpoint)(nil)

func (e *endpoint) Preflight(opts tcpip.WriteOptions) tcpip.Error {
	var r bytes.Reader
	udpInfo, err := e.prepareForWrite(&r, opts)
	if err == nil {
		udpInfo.ctx.Release()
	}
	return err
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

func (e *endpoint) prepareForWrite(p tcpip.Payloader, opts tcpip.WriteOptions) (udpPacketInfo, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for {
		retry, err := e.prepareForWriteInner(opts.To)
		if err != nil {
			return udpPacketInfo{}, err
		}

		if !retry {
			break
		}
	}

	dst, connected := e.net.GetRemoteAddress()
	dst.Port = e.remotePort
	if opts.To != nil {
		if opts.To.Port == 0 {
			return udpPacketInfo{}, &tcpip.ErrInvalidEndpointState{}
		}

		dst = *opts.To
	} else if !connected {
		return udpPacketInfo{}, &tcpip.ErrDestinationRequired{}
	}

	ctx, err := e.net.AcquireContextForWrite(opts)
	if err != nil {
		return udpPacketInfo{}, err
	}

	if p.Len() > header.UDPMaximumPacketSize {
		if ctx.PacketInfo().NetProto == header.IPv6ProtocolNumber {
			so := e.SocketOptions()
			if so.GetIPv6RecvError() {
				so.QueueLocalErr(
					&tcpip.ErrMessageTooLong{},
					e.net.NetProto(),
					uint32(p.Len()),
					dst,
					nil,
				)
			}
		}
		ctx.Release()
		return udpPacketInfo{}, &tcpip.ErrMessageTooLong{}
	}

	return udpPacketInfo{
		ctx:        ctx,
		localPort:  e.localPort,
		remotePort: dst.Port,
	}, nil
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {

	if err := e.LastError(); err != nil {
		return 0, err
	}

	udpInfo, err := e.prepareForWrite(p, opts)
	if err != nil {
		return 0, err
	}
	defer udpInfo.ctx.Release()

	dataSz := p.Len()
	pktInfo := udpInfo.ctx.PacketInfo()
	pkt, err := udpInfo.ctx.TryNewPacketBufferFromPayloader(header.UDPMinimumSize+int(pktInfo.MaxHeaderLength), p)
	if err != nil {
		return 0, err
	}
	defer pkt.DecRef()

	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: udpInfo.localPort,
		DstPort: udpInfo.remotePort,
		Length:  length,
	})

	if pktInfo.RequiresTXTransportChecksum &&
		(!e.ops.GetNoChecksum() || pktInfo.NetProto == header.IPv6ProtocolNumber) {
		xsum := udp.CalculateChecksum(checksum.Combine(
			header.PseudoHeaderChecksum(ProtocolNumber, pktInfo.LocalAddress, pktInfo.RemoteAddress, length),
			pkt.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udp.SetChecksum(xsum)
	}
	if err := udpInfo.ctx.WritePacket(pkt, false); err != nil {
		e.stack.Stats().UDP.PacketSendErrors.Increment()
		return 0, err
	}

	e.stack.Stats().UDP.PacketsSent.Increment()
	return int64(dataSz), nil
}

func (e *endpoint) OnReuseAddressSet(v bool) {
	e.mu.Lock()
	e.portFlags.MostRecent = v
	e.mu.Unlock()
}

func (e *endpoint) OnReusePortSet(v bool) {
	e.mu.Lock()
	e.portFlags.LoadBalanced = v
	e.mu.Unlock()
}

func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.net.SetSockOptInt(opt, v)
}

var _ tcpip.SocketOptionsHandler = (*endpoint)(nil)

func (e *endpoint) HasNIC(id int32) bool {
	return e.stack.HasNIC(tcpip.NICID(id))
}

func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return e.net.SetSockOpt(opt)
}

func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.pkt.Data().Size()
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

type udpPacketInfo struct {
	ctx        network.WriteContext
	localPort  uint16
	remotePort uint16
}

func (e *endpoint) Disconnect() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.net.State() != transport.DatagramEndpointStateConnected {
		return nil
	}
	var (
		id  stack.TransportEndpointID
		btd tcpip.NICID
	)

	boundPortFlags := e.boundPortFlags

	info := e.net.Info()
	info.ID.LocalPort = e.localPort
	info.ID.RemotePort = e.remotePort
	if e.net.WasBound() {
		var err tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    info.ID.LocalPort,
			LocalAddress: info.ID.LocalAddress,
		}
		id, btd, err = e.registerWithStack(e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		boundPortFlags = e.boundPortFlags
	} else {
		if info.ID.LocalPort != 0 {
			portRes := ports.Reservation{
				Networks:     e.effectiveNetProtos,
				Transport:    ProtocolNumber,
				Addr:         info.ID.LocalAddress,
				Port:         info.ID.LocalPort,
				Flags:        boundPortFlags,
				BindToDevice: e.boundBindToDevice,
				Dest:         tcpip.FullAddress{},
			}
			e.stack.ReleasePort(portRes)
			e.boundPortFlags = ports.Flags{}
		}
	}

	e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, info.ID, e, boundPortFlags, e.boundBindToDevice)
	e.boundBindToDevice = btd
	e.localPort = id.LocalPort
	e.remotePort = id.RemotePort

	e.net.Disconnect()

	return nil
}

func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.net.ConnectAndThen(addr, func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error {
		nextID.LocalPort = e.localPort
		nextID.RemotePort = addr.Port

		netProtos := []tcpip.NetworkProtocolNumber{netProto}
		if netProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() && e.stack.CheckNetworkProtocol(header.IPv4ProtocolNumber) {
			netProtos = []tcpip.NetworkProtocolNumber{
				header.IPv4ProtocolNumber,
				header.IPv6ProtocolNumber,
			}
		}

		oldPortFlags := e.boundPortFlags

		if e.localPort != 0 {
			previousID.LocalPort = e.localPort
			previousID.RemotePort = e.remotePort
			e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, previousID, e, oldPortFlags, e.boundBindToDevice)
		}

		nextID, btd, err := e.registerWithStack(netProtos, nextID)
		if err != nil {
			return err
		}

		e.localPort = nextID.LocalPort
		e.remotePort = nextID.RemotePort
		e.boundBindToDevice = btd
		e.effectiveNetProtos = netProtos
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
		e.readShutdown = true

		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.ReadableEvents)
		}
	}

	if e.net.State() == transport.DatagramEndpointStateBound {
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

func (e *endpoint) registerWithStack(netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.NICID, tcpip.Error) {
	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	if e.localPort == 0 {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.portFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		port, err := e.stack.ReservePort(e.stack.SecureRNG(), portRes, nil)
		if err != nil {
			return id, bindToDevice, err
		}
		id.LocalPort = port
	}
	e.boundPortFlags = e.portFlags

	err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.boundPortFlags, bindToDevice)
	if err != nil {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundPortFlags = ports.Flags{}
	}
	return id, bindToDevice, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	if e.net.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	err := e.net.BindAndThen(addr, func(boundNetProto tcpip.NetworkProtocolNumber, boundAddr tcpip.Address) tcpip.Error {
		netProtos := []tcpip.NetworkProtocolNumber{boundNetProto}
		if boundNetProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() && boundAddr == (tcpip.Address{}) && e.stack.CheckNetworkProtocol(header.IPv4ProtocolNumber) {
			netProtos = []tcpip.NetworkProtocolNumber{
				header.IPv6ProtocolNumber,
				header.IPv4ProtocolNumber,
			}
		}

		id := stack.TransportEndpointID{
			LocalPort:    addr.Port,
			LocalAddress: boundAddr,
		}
		id, btd, err := e.registerWithStack(netProtos, id)
		if err != nil {
			return err
		}

		e.localPort = id.LocalPort
		e.boundBindToDevice = btd
		e.effectiveNetProtos = netProtos
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

func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr)
	if err != nil {
		return err
	}

	return nil
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.net.GetLocalAddress()
	addr.Port = e.localPort
	return addr, nil
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr, connected := e.net.GetRemoteAddress()
	if !connected || e.remotePort == 0 {
		return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
	}

	addr.Port = e.remotePort
	return addr, nil
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	var result waiter.EventMask

	if e.net.HasSendSpace() {
		result |= waiter.WritableEvents & mask
	}

	if mask&waiter.ReadableEvents != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	e.lastErrorMu.Lock()
	hasError := e.lastError != nil
	e.lastErrorMu.Unlock()
	if hasError {
		result |= waiter.EventErr
	}
	return result
}

func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	hdr := header.UDP(pkt.TransportHeader().Slice())
	netHdr := pkt.Network()
	lengthValid, csumValid := header.UDPValid(
		hdr,
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		pkt.NetworkProtocolNumber,
		netHdr.SourceAddress(),
		netHdr.DestinationAddress(),
		pkt.RXChecksumValidated)
	if !lengthValid {
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}

	if !csumValid {
		e.stack.Stats().UDP.ChecksumErrors.Increment()
		e.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	e.stack.Stats().UDP.PacketsReceived.Increment()
	e.stats.PacketsReceived.Increment()

	e.rcvMu.Lock()
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	packet := &udpPacket{
		netProto: pkt.NetworkProtocolNumber,
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
			Port: hdr.SourcePort(),
		},
		destinationAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.LocalAddress,
			Port: hdr.DestinationPort(),
		},
		pkt: pkt.Clone(),
	}
	e.rcvList.PushBack(packet)
	e.rcvBufSize += pkt.Data().Size()

	packet.tosOrTClass, _ = pkt.Network().TOS()
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		packet.ttlOrHopLimit = header.IPv4(pkt.NetworkHeader().Slice()).TTL()
	case header.IPv6ProtocolNumber:
		packet.ttlOrHopLimit = header.IPv6(pkt.NetworkHeader().Slice()).HopLimit()
	}

	localAddr := pkt.Network().DestinationAddress()
	packet.packetInfo.LocalAddr = localAddr
	packet.packetInfo.DestinationAddr = localAddr
	packet.packetInfo.NIC = pkt.NICID
	packet.receivedAt = e.stack.Clock().Now()

	e.rcvMu.Unlock()

	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (e *endpoint) onICMPError(err tcpip.Error, transErr stack.TransportError, pkt *stack.PacketBuffer) {
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
		payload := pkt.Data().AsRange().ToView()
		udp := header.UDP(payload.AsSlice())
		if len(udp) >= header.UDPMinimumSize {
			payload.TrimFront(header.UDPMinimumSize)
		}

		id := e.net.Info().ID
		e.mu.RLock()
		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:     err,
			Cause:   transErr,
			Payload: payload,
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: id.RemoteAddress,
				Port: e.remotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: id.LocalAddress,
				Port: e.localPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
		e.mu.RUnlock()
	}

	e.waiterQueue.Notify(waiter.EventErr)
}

func (e *endpoint) HandleError(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	switch transErr.Kind() {
	case stack.DestinationPortUnreachableTransportError:
		if e.net.State() == transport.DatagramEndpointStateConnected {
			e.onICMPError(&tcpip.ErrConnectionRefused{}, transErr, pkt)
		}
	}
}

func (e *endpoint) State() uint32 {
	return uint32(e.net.State())
}

func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	info := e.net.Info()
	info.ID.LocalPort = e.localPort
	info.ID.RemotePort = e.remotePort
	return &info
}

func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

func (*endpoint) Wait() {}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.net.SetOwner(owner)
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

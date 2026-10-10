// Copyright 2021 The gVisor Authors.
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

package network

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type Endpoint struct {
	stack       *stack.Stack
	ops         *tcpip.SocketOptions
	netProto    tcpip.NetworkProtocolNumber
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue

	mu sync.RWMutex `state:"nosave"`
	wasBound bool
	owner tcpip.PacketOwner
	writeShutdown bool
	effectiveNetProto tcpip.NetworkProtocolNumber
	connectedRoute *stack.Route `state:"nosave"`
	multicastMemberships map[multicastMembership]struct{}
	ipv4TTL uint8
	ipv6HopLimit int16
	multicastTTL uint8
	multicastAddr tcpip.Address
	multicastNICID tcpip.NICID
	ipv6MulticastNICID tcpip.NICID
	ipv4TOS uint8
	ipv6TClass uint8
	pmtud tcpip.PMTUDStrategy

	infoMu sync.RWMutex `state:"nosave"`
	info stack.TransportEndpointInfo

	state atomicbitops.Uint32

	sendBufferSizeInUseMu sync.RWMutex `state:"nosave"`
	sendBufferSizeInUse int64 `state:"nosave"`
}

type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

func (e *Endpoint) Init(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ops *tcpip.SocketOptions, waiterQueue *waiter.Queue) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.multicastMemberships != nil {
		panic(fmt.Sprintf("endpoint is already initialized; got e.multicastMemberships = %#v, want = nil", e.multicastMemberships))
	}

	switch netProto {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}

	e.stack = s
	e.ops = ops
	e.netProto = netProto
	e.transProto = transProto
	e.waiterQueue = waiterQueue
	e.infoMu.Lock()
	e.info = stack.TransportEndpointInfo{
		NetProto:   netProto,
		TransProto: transProto,
	}
	e.infoMu.Unlock()
	e.effectiveNetProto = netProto
	e.ipv4TTL = tcpip.UseDefaultIPv4TTL
	e.ipv6HopLimit = tcpip.UseDefaultIPv6HopLimit

	e.multicastTTL = 1
	e.multicastMemberships = make(map[multicastMembership]struct{})
	e.setEndpointState(transport.DatagramEndpointStateInitial)
}

func (e *Endpoint) NetProto() tcpip.NetworkProtocolNumber {
	return e.netProto
}

func (e *Endpoint) setEndpointState(state transport.DatagramEndpointState) {
	e.state.Store(uint32(state))
}

func (e *Endpoint) State() transport.DatagramEndpointState {
	return transport.DatagramEndpointState(e.state.Load())
}

func (e *Endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State() == transport.DatagramEndpointStateClosed {
		return
	}

	for mem := range e.multicastMemberships {
		proto, err := e.multicastNetProto(mem.multicastAddr)
		if err != nil {
			panic("non multicast address in an existing membership")
		}
		e.stack.LeaveGroup(proto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = nil

	if e.connectedRoute != nil {
		e.connectedRoute.Release()
		e.connectedRoute = nil
	}

	e.setEndpointState(transport.DatagramEndpointStateClosed)
}

func (e *Endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner = owner
}

func (e *Endpoint) calculateTTL(route *stack.Route) uint8 {
	remoteAddress := route.RemoteAddress()
	if header.IsV4MulticastAddress(remoteAddress) || header.IsV6MulticastAddress(remoteAddress) {
		return e.multicastTTL
	}

	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if e.ipv4TTL == 0 {
			return route.DefaultTTL()
		}
		return e.ipv4TTL
	case header.IPv6ProtocolNumber:
		if e.ipv6HopLimit == -1 {
			return route.DefaultTTL()
		}
		return uint8(e.ipv6HopLimit)
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}
}

type WriteContext struct {
	e     *Endpoint
	route *stack.Route
	ttl   uint8
	tos   uint8
	df    bool
}

func (c *WriteContext) MTU() uint32 {
	return c.route.MTU()
}

func (c *WriteContext) Release() {
	c.route.Release()
	*c = WriteContext{}
}

type WritePacketInfo struct {
	NetProto                    tcpip.NetworkProtocolNumber
	LocalAddress, RemoteAddress tcpip.Address
	MaxHeaderLength             uint16
	RequiresTXTransportChecksum bool
}

func (c *WriteContext) PacketInfo() WritePacketInfo {
	return WritePacketInfo{
		NetProto:                    c.route.NetProto(),
		LocalAddress:                c.route.LocalAddress(),
		RemoteAddress:               c.route.RemoteAddress(),
		MaxHeaderLength:             c.route.MaxHeaderLength(),
		RequiresTXTransportChecksum: c.route.RequiresTXTransportChecksum(),
	}
}

func (c *WriteContext) TryNewPacketBuffer(reserveHdrBytes int, data buffer.Buffer) *stack.PacketBuffer {
	e := c.e

	e.sendBufferSizeInUseMu.Lock()
	defer e.sendBufferSizeInUseMu.Unlock()

	if !e.hasSendSpaceRLocked() {
		return nil
	}

	mark := e.ops.GetMark()
	return c.newPacketBufferLocked(reserveHdrBytes, data, mark)
}

func (c *WriteContext) TryNewPacketBufferFromPayloader(reserveHdrBytes int, payloader tcpip.Payloader) (*stack.PacketBuffer, tcpip.Error) {
	e := c.e

	e.sendBufferSizeInUseMu.Lock()
	defer e.sendBufferSizeInUseMu.Unlock()

	if !e.hasSendSpaceRLocked() {
		return nil, &tcpip.ErrWouldBlock{}
	}
	var data buffer.Buffer
	if _, err := data.WriteFromReader(payloader, int64(payloader.Len())); err != nil {
		data.Release()
		return nil, &tcpip.ErrBadBuffer{}
	}
	mark := e.ops.GetMark()
	return c.newPacketBufferLocked(reserveHdrBytes, data, mark), nil
}

func (c *WriteContext) newPacketBufferLocked(reserveHdrBytes int, data buffer.Buffer, mark uint32) *stack.PacketBuffer {
	e := c.e
	var expOptVal uint16
	if nic, err := c.e.stack.GetNICByID(c.route.OutgoingNIC()); err == nil && nic.GetExperimentIPOptionEnabled() {
		expOptVal = c.e.ops.GetExperimentOptionValue()
	}
	if c.route.NetProto() == header.IPv6ProtocolNumber && expOptVal != 0 {
		reserveHdrBytes += header.IPv6ExperimentHdrLength
	}
	pktSize := int64(reserveHdrBytes) + int64(data.Size())
	e.sendBufferSizeInUse += pktSize

	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserveHdrBytes,
		Payload:            data,
		Mark:               mark,
		OnRelease: func() {
			e.sendBufferSizeInUseMu.Lock()
			if got := e.sendBufferSizeInUse; got < pktSize {
				e.sendBufferSizeInUseMu.Unlock()
				panic(fmt.Sprintf("e.sendBufferSizeInUse=(%d) < pktSize(=%d)", got, pktSize))
			}
			e.sendBufferSizeInUse -= pktSize
			signal := e.hasSendSpaceRLocked()
			e.sendBufferSizeInUseMu.Unlock()

			if signal {
				e.waiterQueue.Notify(waiter.WritableEvents)
			}
		},
	})
}

func (c *WriteContext) WritePacket(pkt *stack.PacketBuffer, headerIncluded bool) tcpip.Error {
	c.e.mu.RLock()
	pkt.Owner = c.e.owner
	c.e.mu.RUnlock()

	if headerIncluded {
		return c.route.WriteHeaderIncludedPacket(pkt)
	}

	var expOptVal uint16
	if nic, err := c.e.stack.GetNICByID(c.route.OutgoingNIC()); err == nil && nic.GetExperimentIPOptionEnabled() {
		expOptVal = c.e.ops.GetExperimentOptionValue()
	}

	err := c.route.WritePacket(stack.NetworkHeaderParams{
		Protocol:              c.e.transProto,
		TTL:                   c.ttl,
		TOS:                   c.tos,
		DF:                    c.df,
		ExperimentOptionValue: expOptVal,
	}, pkt)

	if _, ok := err.(*tcpip.ErrNoBufferSpace); ok {
		var recvErr bool
		switch netProto := c.route.NetProto(); netProto {
		case header.IPv4ProtocolNumber:
			recvErr = c.e.ops.GetIPv4RecvError()
		case header.IPv6ProtocolNumber:
			recvErr = c.e.ops.GetIPv6RecvError()
		default:
			panic(fmt.Sprintf("unhandled network protocol number = %d", netProto))
		}

		if !recvErr {
			err = nil
		}
	}

	return err
}

func (e *Endpoint) MaybeSignalWritable() {
	e.sendBufferSizeInUseMu.RLock()
	signal := e.hasSendSpaceRLocked()
	e.sendBufferSizeInUseMu.RUnlock()

	if signal {
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

func (e *Endpoint) HasSendSpace() bool {
	e.sendBufferSizeInUseMu.RLock()
	defer e.sendBufferSizeInUseMu.RUnlock()
	return e.hasSendSpaceRLocked()
}

func (e *Endpoint) hasSendSpaceRLocked() bool {
	return e.ops.GetSendBufferSize() > e.sendBufferSizeInUse
}

func (e *Endpoint) AcquireContextForWrite(opts tcpip.WriteOptions) (WriteContext, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if opts.More {
		return WriteContext{}, &tcpip.ErrInvalidOptionValue{}
	}

	if e.State() == transport.DatagramEndpointStateClosed {
		return WriteContext{}, &tcpip.ErrInvalidEndpointState{}
	}

	if e.writeShutdown {
		return WriteContext{}, &tcpip.ErrClosedForSend{}
	}

	ipv6PktInfoValid := e.effectiveNetProto == header.IPv6ProtocolNumber && opts.ControlMessages.HasIPv6PacketInfo

	route := e.connectedRoute
	to := opts.To
	info := e.Info()
	switch to {
	case nil:
		if e.State() != transport.DatagramEndpointStateConnected {
			return WriteContext{}, &tcpip.ErrDestinationRequired{}
		}

		if !ipv6PktInfoValid {
			route.Acquire()
			break
		}

		to = &tcpip.FullAddress{
			NIC:  info.RegisterNICID,
			Addr: info.ID.RemoteAddress,
		}
		fallthrough
	default:
		nicID := to.NIC
		if nicID == 0 {
			nicID = tcpip.NICID(e.ops.GetBindToDevice())
		}

		var localAddr tcpip.Address
		if ipv6PktInfoValid {

			pktInfoNICID := opts.ControlMessages.IPv6PacketInfo.NIC
			pktInfoAddr := opts.ControlMessages.IPv6PacketInfo.Addr

			if pktInfoNICID != 0 {
				if nicID != 0 && nicID != pktInfoNICID {
					return WriteContext{}, &tcpip.ErrHostUnreachable{}
				}

				if pktInfoAddr.BitLen() == 0 {
					if info.BindNICID != 0 && info.BindNICID != pktInfoNICID {
						return WriteContext{}, &tcpip.ErrHostUnreachable{}
					}
					if info.ID.LocalAddress.BitLen() != 0 && e.stack.CheckLocalAddress(pktInfoNICID, header.IPv6ProtocolNumber, info.ID.LocalAddress) == 0 {
						return WriteContext{}, &tcpip.ErrBadLocalAddress{}
					}
				}

				nicID = pktInfoNICID
			}

			if pktInfoAddr.BitLen() != 0 {
				if e.stack.CheckLocalAddress(nicID, header.IPv6ProtocolNumber, pktInfoAddr) == 0 {
					return WriteContext{}, &tcpip.ErrBadLocalAddress{}
				}

				localAddr = pktInfoAddr
			}
		} else {
			if info.BindNICID != 0 {
				if nicID != 0 && nicID != info.BindNICID {
					return WriteContext{}, &tcpip.ErrHostUnreachable{}
				}

				nicID = info.BindNICID
			}
			if nicID == 0 {
				nicID = info.RegisterNICID
			}
		}

		dst, netProto, err := e.checkV4Mapped(*to, false)
		if err != nil {
			return WriteContext{}, err
		}

		route, _, err = e.connectRouteRLocked(nicID, localAddr, dst, netProto)
		if err != nil {
			return WriteContext{}, err
		}
	}

	if !e.ops.GetBroadcast() && route.IsOutboundBroadcast() {
		route.Release()
		return WriteContext{}, &tcpip.ErrBroadcastDisabled{}
	}

	var tos uint8
	var ttl uint8
	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		tos = e.ipv4TOS
		if opts.ControlMessages.HasTTL {
			ttl = opts.ControlMessages.TTL
		} else {
			ttl = e.calculateTTL(route)
		}
	case header.IPv6ProtocolNumber:
		tos = e.ipv6TClass
		if opts.ControlMessages.HasHopLimit {
			ttl = opts.ControlMessages.HopLimit
		} else {
			ttl = e.calculateTTL(route)
		}
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}

	df := e.pmtud == tcpip.PMTUDiscoveryWant || e.pmtud == tcpip.PMTUDiscoveryDo || e.pmtud == tcpip.PMTUDiscoveryProbe

	return WriteContext{
		e:     e,
		route: route,
		ttl:   ttl,
		tos:   tos,
		df:    df,
	}, nil
}

func (e *Endpoint) Disconnect() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State() != transport.DatagramEndpointStateConnected {
		return
	}

	info := e.Info()
	if e.wasBound {
		info.ID = stack.TransportEndpointID{
			LocalAddress: info.BindAddr,
		}
		e.setEndpointState(transport.DatagramEndpointStateBound)
	} else {
		info.ID = stack.TransportEndpointID{}
		e.setEndpointState(transport.DatagramEndpointStateInitial)
	}
	e.setInfo(info)

	e.connectedRoute.Release()
	e.connectedRoute = nil
}

func (e *Endpoint) connectRouteRLocked(nicID tcpip.NICID, localAddr tcpip.Address, addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (*stack.Route, tcpip.NICID, tcpip.Error) {
	if localAddr.BitLen() == 0 {
		localAddr = e.Info().ID.LocalAddress
		if e.isBroadcastOrMulticast(nicID, netProto, localAddr) {
			localAddr = tcpip.Address{}
		}

		if header.IsV4MulticastAddress(addr.Addr) {
			if nicID == 0 {
				nicID = e.multicastNICID
			}
			if localAddr == (tcpip.Address{}) && nicID == 0 {
				localAddr = e.multicastAddr
			}
		}
		if header.IsV6MulticastAddress(addr.Addr) && nicID == 0 {
			nicID = e.ipv6MulticastNICID
		}
	}

	r, err := e.stack.FindRoute(nicID, localAddr, addr.Addr, netProto, e.ops.GetMulticastLoop())
	if err != nil {
		return nil, 0, err
	}
	return r, nicID, nil
}

func (e *Endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	return e.ConnectAndThen(addr, func(_ tcpip.NetworkProtocolNumber, _, _ stack.TransportEndpointID) tcpip.Error {
		return nil
	})
}

func (e *Endpoint) ConnectAndThen(addr tcpip.FullAddress, f func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	info := e.Info()
	nicID := addr.NIC
	switch e.State() {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		if info.BindNICID == 0 {
			break
		}

		if nicID != 0 && nicID != info.BindNICID {
			return &tcpip.ErrInvalidEndpointState{}
		}

		nicID = info.BindNICID
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4Mapped(addr, false)
	if err != nil {
		return err
	}

	r, nicID, err := e.connectRouteRLocked(nicID, tcpip.Address{}, addr, netProto)
	if err != nil {
		return err
	}

	id := stack.TransportEndpointID{
		LocalAddress:  info.ID.LocalAddress,
		RemoteAddress: r.RemoteAddress(),
	}
	if e.State() == transport.DatagramEndpointStateInitial {
		id.LocalAddress = r.LocalAddress()
	}

	if err := f(r.NetProto(), info.ID, id); err != nil {
		r.Release()
		return err
	}

	if e.connectedRoute != nil {
		e.connectedRoute.Release()
	}
	e.connectedRoute = r
	info.ID = id
	info.RegisterNICID = nicID
	e.setInfo(info)
	e.effectiveNetProto = netProto
	e.setEndpointState(transport.DatagramEndpointStateConnected)
	return nil
}

func (e *Endpoint) Shutdown() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch state := e.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
		return &tcpip.ErrNotConnected{}
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		e.writeShutdown = true
		return nil
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}

func (e *Endpoint) checkV4Mapped(addr tcpip.FullAddress, bind bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	info := e.Info()
	unwrapped, netProto, err := info.AddrNetProtoLocked(addr, e.ops.GetV6Only(), bind)
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

func (e *Endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr) || e.stack.IsSubnetBroadcast(nicID, netProto, addr)
}

func (e *Endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	return e.BindAndThen(addr, func(tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.Error {
		return nil
	})
}

func (e *Endpoint) BindAndThen(addr tcpip.FullAddress, f func(tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.Error) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4Mapped(addr, true)
	if err != nil {
		return err
	}

	nicID := addr.NIC
	if addr.Addr.BitLen() != 0 && !e.isBroadcastOrMulticast(addr.NIC, netProto, addr.Addr) {
		nicID = e.stack.CheckLocalAddress(nicID, netProto, addr.Addr)
		if nicID == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
	}

	if err := f(netProto, addr.Addr); err != nil {
		return err
	}

	e.wasBound = true

	info := e.Info()
	info.ID = stack.TransportEndpointID{
		LocalAddress: addr.Addr,
	}
	info.BindNICID = addr.NIC
	info.RegisterNICID = nicID
	info.BindAddr = addr.Addr
	e.setInfo(info)
	e.effectiveNetProto = netProto
	e.setEndpointState(transport.DatagramEndpointStateBound)
	return nil
}

func (e *Endpoint) WasBound() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.wasBound
}

func (e *Endpoint) GetLocalAddress() tcpip.FullAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()

	info := e.Info()
	addr := info.BindAddr
	if e.State() == transport.DatagramEndpointStateConnected {
		addr = e.connectedRoute.LocalAddress()
	}

	return tcpip.FullAddress{
		NIC:  info.RegisterNICID,
		Addr: addr,
	}
}

func (e *Endpoint) GetRemoteAddress() (tcpip.FullAddress, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.State() != transport.DatagramEndpointStateConnected {
		return tcpip.FullAddress{}, false
	}

	return tcpip.FullAddress{
		Addr: e.connectedRoute.RemoteAddress(),
		NIC:  e.Info().RegisterNICID,
	}, true
}

func (e *Endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	switch opt {
	case tcpip.MTUDiscoverOption:
		switch tcpip.PMTUDStrategy(v) {
		case tcpip.PMTUDiscoveryWant, tcpip.PMTUDiscoveryDont, tcpip.PMTUDiscoveryDo, tcpip.PMTUDiscoveryProbe:
			e.mu.Lock()
			e.pmtud = tcpip.PMTUDStrategy(v)
			e.mu.Unlock()
		default:
			return &tcpip.ErrNotSupported{}
		}

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		e.multicastTTL = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv4TTLOption:
		e.mu.Lock()
		e.ipv4TTL = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6HopLimitOption:
		e.mu.Lock()
		e.ipv6HopLimit = int16(v)
		e.mu.Unlock()

	case tcpip.IPv4TOSOption:
		e.mu.Lock()
		e.ipv4TOS = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6TrafficClassOption:
		e.mu.Lock()
		e.ipv6TClass = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6MulticastInterfaceOption:
		if v != 0 && !e.stack.CheckNIC(tcpip.NICID(v)) {
			return &tcpip.ErrUnknownNICID{}
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		nic := tcpip.NICID(v)
		if info := e.Info(); info.BindNICID != 0 && info.BindNICID != nic {
			return &tcpip.ErrInvalidEndpointState{}
		}
		e.ipv6MulticastNICID = nic
	}

	return nil
}

func (e *Endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.MTUDiscoverOption:
		e.mu.Lock()
		v := int(e.pmtud)
		e.mu.Unlock()
		return v, nil

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		v := int(e.multicastTTL)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv4TTLOption:
		e.mu.Lock()
		v := int(e.ipv4TTL)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv6HopLimitOption:
		e.mu.Lock()
		v := int(e.ipv6HopLimit)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv4TOSOption:
		e.mu.RLock()
		v := int(e.ipv4TOS)
		e.mu.RUnlock()
		return v, nil

	case tcpip.IPv6TrafficClassOption:
		e.mu.RLock()
		v := int(e.ipv6TClass)
		e.mu.RUnlock()
		return v, nil

	case tcpip.IPv6MulticastInterfaceOption:
		e.mu.RLock()
		v := int(e.ipv6MulticastNICID)
		e.mu.RUnlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

func (e *Endpoint) multicastNetProto(addr tcpip.Address) (tcpip.NetworkProtocolNumber, tcpip.Error) {
	switch {
	case header.IsV4MulticastAddress(addr):
		return header.IPv4ProtocolNumber, nil
	case header.IsV6MulticastAddress(addr):
		return header.IPv6ProtocolNumber, nil
	default:
		return 0, &tcpip.ErrInvalidOptionValue{}
	}
}

func (e *Endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch v := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		defer e.mu.Unlock()

		fa := tcpip.FullAddress{Addr: v.InterfaceAddr}
		fa, netProto, err := e.checkV4Mapped(fa, true)
		if err != nil {
			return err
		}
		nic := v.NIC
		addr := fa.Addr

		if nic == 0 && addr == (tcpip.Address{}) {
			e.multicastAddr = tcpip.Address{}
			e.multicastNICID = 0
			break
		}

		if nic != 0 {
			if !e.stack.CheckNIC(nic) {
				return &tcpip.ErrBadLocalAddress{}
			}
		} else {
			nic = e.stack.CheckLocalAddress(0, netProto, addr)
			if nic == 0 {
				return &tcpip.ErrBadLocalAddress{}
			}
		}

		if info := e.Info(); info.BindNICID != 0 && info.BindNICID != nic {
			return &tcpip.ErrInvalidEndpointState{}
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case *tcpip.AddMembershipOption:
		proto, err := e.multicastNetProto(v.MulticastAddr)
		if err != nil {
			return err
		}

		nicID := v.NIC
		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, tcpip.Address{}, v.MulticastAddr, proto, false); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, proto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return &tcpip.ErrUnknownDevice{}
		}

		memToInsert := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToInsert]; ok {
			return &tcpip.ErrPortInUse{}
		}

		if err := e.stack.JoinGroup(proto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToInsert] = struct{}{}

	case *tcpip.RemoveMembershipOption:
		proto, err := e.multicastNetProto(v.MulticastAddr)
		if err != nil {
			return err
		}

		nicID := v.NIC
		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, tcpip.Address{}, v.MulticastAddr, proto, false); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, proto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return &tcpip.ErrUnknownDevice{}
		}

		memToRemove := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToRemove]; !ok {
			return &tcpip.ErrBadLocalAddress{}
		}

		if err := e.stack.LeaveGroup(proto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		delete(e.multicastMemberships, memToRemove)

	case *tcpip.SocketDetachFilterOption:
		return nil
	}
	return nil
}

func (e *Endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch o := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		*o = tcpip.MulticastInterfaceOption{
			NIC:           e.multicastNICID,
			InterfaceAddr: e.multicastAddr,
		}
		e.mu.Unlock()

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
	return nil
}

func (e *Endpoint) Info() stack.TransportEndpointInfo {
	e.infoMu.RLock()
	defer e.infoMu.RUnlock()
	return e.info
}

func (e *Endpoint) setInfo(info stack.TransportEndpointInfo) {
	e.infoMu.Lock()
	defer e.infoMu.Unlock()
	e.info = info
}

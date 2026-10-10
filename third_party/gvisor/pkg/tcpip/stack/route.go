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

package stack

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type Route struct {
	routeInfo routeInfo

	localAddressNIC *nic

	mu routeRWMutex

	localAddressEndpoint AssignableAddressEndpoint

	remoteLinkAddress tcpip.LinkAddress

	outgoingNIC *nic

	linkRes *linkResolver

	neighborEntry *neighborEntry

	mtu uint32
}

type routeInfo struct {
	RemoteAddress tcpip.Address

	LocalAddress tcpip.Address

	LocalLinkAddress tcpip.LinkAddress

	NextHop tcpip.Address

	NetProto tcpip.NetworkProtocolNumber

	Loop PacketLooping
}

func (r *Route) RemoteAddress() tcpip.Address {
	return r.routeInfo.RemoteAddress
}

func (r *Route) LocalAddress() tcpip.Address {
	return r.routeInfo.LocalAddress
}

func (r *Route) LocalLinkAddress() tcpip.LinkAddress {
	return r.routeInfo.LocalLinkAddress
}

func (r *Route) NextHop() tcpip.Address {
	return r.routeInfo.NextHop
}

func (r *Route) NetProto() tcpip.NetworkProtocolNumber {
	return r.routeInfo.NetProto
}

func (r *Route) Loop() PacketLooping {
	return r.routeInfo.Loop
}

func (r *Route) OutgoingNIC() tcpip.NICID {
	return r.outgoingNIC.id
}

type RouteInfo struct {
	routeInfo

	RemoteLinkAddress tcpip.LinkAddress
}

func (r *Route) Fields() RouteInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fieldsLocked()
}

func (r *Route) fieldsLocked() RouteInfo {
	return RouteInfo{
		routeInfo:         r.routeInfo,
		RemoteLinkAddress: r.remoteLinkAddress,
	}
}

func constructAndValidateRoute(netProto tcpip.NetworkProtocolNumber, addressEndpoint AssignableAddressEndpoint, localAddressNIC, outgoingNIC *nic, gateway, localAddr, remoteAddr tcpip.Address, handleLocal, multicastLoop bool, mtu uint32) *Route {
	if localAddr.BitLen() == 0 {
		localAddr = addressEndpoint.AddressWithPrefix().Address
	}

	if localAddressNIC != outgoingNIC && header.IsV6LinkLocalUnicastAddress(localAddr) {
		addressEndpoint.DecRef()
		return nil
	}

	if remoteAddr.BitLen() == 0 {
		remoteAddr = localAddr
	}

	r := makeRoute(
		netProto,
		gateway,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		addressEndpoint,
		handleLocal,
		multicastLoop,
		mtu,
	)

	return r
}

func makeRoute(netProto tcpip.NetworkProtocolNumber, gateway, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint, handleLocal, multicastLoop bool, mtu uint32) *Route {
	if localAddressNIC.stack != outgoingNIC.stack {
		panic("cannot create a route with NICs from different stacks")
	}

	if localAddr.BitLen() == 0 {
		localAddr = localAddressEndpoint.AddressWithPrefix().Address
	}

	loop := PacketOut

	if !outgoingNIC.IsLoopback() {
		if handleLocal && localAddr != (tcpip.Address{}) && remoteAddr == localAddr {
			loop = PacketLoop
		} else if multicastLoop && (header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)) {
			loop |= PacketLoop
		} else if remoteAddr == header.IPv4Broadcast {
			loop |= PacketLoop
		} else if subnet := localAddressEndpoint.AddressWithPrefix().Subnet(); subnet.IsBroadcast(remoteAddr) {
			loop |= PacketLoop
		}
	}

	r := makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop, mtu)
	if r.Loop()&PacketOut == 0 {
		return r
	}

	if r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilityResolutionRequired != 0 {
		if linkRes, ok := r.outgoingNIC.linkAddrResolvers[r.NetProto()]; ok {
			r.linkRes = linkRes
		}
	}

	if gateway.BitLen() > 0 {
		r.routeInfo.NextHop = gateway
		return r
	}

	if r.linkRes == nil {
		return r
	}

	if linkAddr, ok := r.linkRes.resolver.ResolveStaticAddress(r.RemoteAddress()); ok {
		r.ResolveWith(linkAddr)
		return r
	}

	if subnet := localAddressEndpoint.Subnet(); subnet.IsBroadcast(remoteAddr) {
		r.ResolveWith(header.EthernetBroadcastAddress)
		return r
	}

	if r.RemoteAddress() == r.LocalAddress() {
		r.ResolveWith(r.LocalLinkAddress())
	}

	return r
}

func makeRouteInner(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint, loop PacketLooping, mtu uint32) *Route {
	if mtu != 0 {
		adjusted := mtu - outgoingNIC.getNetworkEndpoint(netProto).EndpointHeaderSize()
		if adjusted > mtu {
			mtu = 0
		} else {
			mtu = adjusted
		}
	}
	r := &Route{
		routeInfo: routeInfo{
			NetProto:         netProto,
			LocalAddress:     localAddr,
			LocalLinkAddress: outgoingNIC.NetworkLinkEndpoint.LinkAddress(),
			RemoteAddress:    remoteAddr,
			Loop:             loop,
		},
		localAddressNIC: localAddressNIC,
		outgoingNIC:     outgoingNIC,
		mtu:             mtu,
	}

	r.mu.Lock()
	r.localAddressEndpoint = localAddressEndpoint
	r.mu.Unlock()

	return r
}

func makeLocalRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint) *Route {
	loop := PacketLoop
	if outgoingNIC.IsLoopback() {
		loop = PacketOut
	}
	return makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop, 0)
}

func (r *Route) RemoteLinkAddress() tcpip.LinkAddress {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.remoteLinkAddress
}

func (r *Route) NICID() tcpip.NICID {
	return r.outgoingNIC.ID()
}

func (r *Route) MaxHeaderLength() uint16 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).MaxHeaderLength()
}

func (r *Route) Stats() tcpip.Stats {
	return r.outgoingNIC.stack.Stats()
}

func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, totalLen uint16) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress(), r.RemoteAddress(), totalLen)
}

func (r *Route) RequiresTXTransportChecksum() bool {
	if r.local() {
		return false
	}
	return r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilityTXChecksumOffload == 0
}

func (r *Route) HasGVisorGSOCapability() bool {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.SupportedGSO() == GVisorGSOSupported
	}
	return false
}

func (r *Route) HasHostGSOCapability() bool {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.SupportedGSO() == HostGSOSupported
	}
	return false
}

func (r *Route) HasSaveRestoreCapability() bool {
	return r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilitySaveRestore != 0
}

func (r *Route) GSOMaxSize() uint32 {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

func (r *Route) ResolveWith(addr tcpip.LinkAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remoteLinkAddress = addr
}

type ResolvedFieldsResult struct {
	RouteInfo RouteInfo
	Err       tcpip.Error
}

func (r *Route) ResolvedFields(afterResolve func(ResolvedFieldsResult)) tcpip.Error {
	_, _, err := r.resolvedFields(afterResolve)
	return err
}

func (r *Route) resolvedFields(afterResolve func(ResolvedFieldsResult)) (RouteInfo, <-chan struct{}, tcpip.Error) {
	r.mu.RLock()
	fields := r.fieldsLocked()
	resolutionRequired := r.isResolutionRequiredRLocked()
	r.mu.RUnlock()
	if !resolutionRequired {
		if afterResolve != nil {
			afterResolve(ResolvedFieldsResult{RouteInfo: fields, Err: nil})
		}
		return fields, nil, nil
	}

	var linkAddressResolutionRequestLocalAddr tcpip.Address
	if r.localAddressNIC == r.outgoingNIC {
		linkAddressResolutionRequestLocalAddr = r.LocalAddress()
	}

	nEntry := r.getCachedNeighborEntry()
	if nEntry != nil {
		if addr, ok := nEntry.getRemoteLinkAddress(); ok {
			fields.RemoteLinkAddress = addr
			if afterResolve != nil {
				afterResolve(ResolvedFieldsResult{RouteInfo: fields, Err: nil})
			}
			return fields, nil, nil
		}
	}
	afterResolveFields := fields
	entry, ch, err := r.linkRes.neigh.entry(r.nextHop(), linkAddressResolutionRequestLocalAddr, func(lrr LinkResolutionResult) {
		if afterResolve != nil {
			if lrr.Err == nil {
				afterResolveFields.RemoteLinkAddress = lrr.LinkAddress
			}

			afterResolve(ResolvedFieldsResult{RouteInfo: afterResolveFields, Err: lrr.Err})
		}
	})
	if err == nil {
		fields.RemoteLinkAddress, _ = entry.getRemoteLinkAddress()
	}
	r.setCachedNeighborEntry(entry)
	return fields, ch, err
}

func (r *Route) getCachedNeighborEntry() *neighborEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.neighborEntry
}

func (r *Route) setCachedNeighborEntry(entry *neighborEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.neighborEntry = entry
}

func (r *Route) nextHop() tcpip.Address {
	if r.NextHop().BitLen() == 0 {
		return r.RemoteAddress()
	}
	return r.NextHop()
}

func (r *Route) local() bool {
	return r.Loop() == PacketLoop || r.outgoingNIC.IsLoopback()
}

func (r *Route) IsResolutionRequired() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isResolutionRequiredRLocked()
}

func (r *Route) isResolutionRequiredRLocked() bool {
	return len(r.remoteLinkAddress) == 0 && r.linkRes != nil && r.isValidForOutgoingRLocked() && !r.local()
}

func (r *Route) isValidForOutgoing() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isValidForOutgoingRLocked()
}

func (r *Route) isValidForOutgoingRLocked() bool {
	if !r.outgoingNIC.Enabled() {
		return false
	}

	localAddressEndpoint := r.localAddressEndpoint
	if localAddressEndpoint == nil || !r.localAddressNIC.isValidForOutgoing(localAddressEndpoint) {
		return false
	}

	if r.outgoingNIC != r.localAddressNIC && !isNICForwarding(r.localAddressNIC, r.NetProto()) && (!r.outgoingNIC.stack.handleLocal || !r.outgoingNIC.hasAddress(r.NetProto(), r.RemoteAddress())) {
		return false
	}

	return true
}

func (r *Route) WritePacket(params NetworkHeaderParams, pkt *PacketBuffer) tcpip.Error {
	if !r.isValidForOutgoing() {
		return &tcpip.ErrInvalidEndpointState{}
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).WritePacket(r, params, pkt)
}

func (r *Route) WriteHeaderIncludedPacket(pkt *PacketBuffer) tcpip.Error {
	if !r.isValidForOutgoing() {
		return &tcpip.ErrInvalidEndpointState{}
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).WriteHeaderIncludedPacket(r, pkt)
}

func (r *Route) DefaultTTL() uint8 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).DefaultTTL()
}

func (r *Route) MTU() uint32 {
	if r.mtu > 0 {
		return r.mtu
	}
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).MTU()
}

func (r *Route) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ep := r.localAddressEndpoint; ep != nil {
		ep.DecRef()
	}
}

func (r *Route) Acquire() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.acquireLocked()
}

func (r *Route) acquireLocked() {
	if ep := r.localAddressEndpoint; ep != nil {
		if !ep.TryIncRef() {
			panic(fmt.Sprintf("failed to increment reference count for local address endpoint = %s", r.LocalAddress()))
		}
	}
}

func (r *Route) Stack() *Stack {
	return r.outgoingNIC.stack
}

func (r *Route) isV4Broadcast(addr tcpip.Address) bool {
	if addr == header.IPv4Broadcast {
		return true
	}

	r.mu.RLock()
	localAddressEndpoint := r.localAddressEndpoint
	r.mu.RUnlock()
	if localAddressEndpoint == nil {
		return false
	}

	subnet := localAddressEndpoint.Subnet()
	return subnet.IsBroadcast(addr)
}

func (r *Route) IsOutboundBroadcast() bool {
	return r.isV4Broadcast(r.RemoteAddress())
}

func (r *Route) ConfirmReachable() {
	if entry := r.getCachedNeighborEntry(); entry != nil {
		entry.handleUpperLevelConfirmation()
	}
}

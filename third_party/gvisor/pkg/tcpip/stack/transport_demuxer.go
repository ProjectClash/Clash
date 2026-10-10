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
	"github.com/metacubex/gvisor/pkg/tcpip/hash/jenkins"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/ports"
)

type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

type transportEndpoints struct {
	mu transportEndpointsRWMutex `state:"nosave"`
	endpoints map[TransportEndpointID]*endpointsByNIC
	rawEndpoints []RawTransportEndpoint
}

func (eps *transportEndpoints) unregisterEndpoint(id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	eps.mu.Lock()
	defer eps.mu.Unlock()
	epsByNIC, ok := eps.endpoints[id]
	if !ok {
		return
	}
	if !epsByNIC.unregisterEndpoint(bindToDevice, ep, flags) {
		return
	}
	delete(eps.endpoints, id)
}

func (eps *transportEndpoints) transportEndpoints() []TransportEndpoint {
	eps.mu.RLock()
	defer eps.mu.RUnlock()
	es := make([]TransportEndpoint, 0, len(eps.endpoints))
	for _, e := range eps.endpoints {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

func (eps *transportEndpoints) iterEndpointsLocked(id TransportEndpointID, yield func(*endpointsByNIC) bool) {
	if ep, ok := eps.endpoints[id]; ok {
		if !yield(ep) {
			return
		}
	}

	nid := id

	nid.LocalAddress = tcpip.Address{}
	if ep, ok := eps.endpoints[nid]; ok {
		if !yield(ep) {
			return
		}
	}

	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = tcpip.Address{}
	nid.RemotePort = 0
	if ep, ok := eps.endpoints[nid]; ok {
		if !yield(ep) {
			return
		}
	}

	nid.LocalAddress = tcpip.Address{}
	if ep, ok := eps.endpoints[nid]; ok {
		if !yield(ep) {
			return
		}
	}
}

func (eps *transportEndpoints) findAllEndpointsLocked(id TransportEndpointID) []*endpointsByNIC {
	var matchedEPs []*endpointsByNIC
	eps.iterEndpointsLocked(id, func(ep *endpointsByNIC) bool {
		matchedEPs = append(matchedEPs, ep)
		return true
	})
	return matchedEPs
}

func (eps *transportEndpoints) findEndpointLocked(id TransportEndpointID) *endpointsByNIC {
	var matchedEP *endpointsByNIC
	eps.iterEndpointsLocked(id, func(ep *endpointsByNIC) bool {
		matchedEP = ep
		return false
	})
	return matchedEP
}

type endpointsByNIC struct {
	seed uint32

	mu endpointsByNICRWMutex `state:"nosave"`
	endpoints map[tcpip.NICID]*multiPortEndpoint
}

func (epsByNIC *endpointsByNIC) transportEndpoints() []TransportEndpoint {
	epsByNIC.mu.RLock()
	defer epsByNIC.mu.RUnlock()
	var eps []TransportEndpoint
	for _, ep := range epsByNIC.endpoints {
		eps = append(eps, ep.transportEndpoints()...)
	}
	return eps
}

func (epsByNIC *endpointsByNIC) handlePacket(id TransportEndpointID, pkt *PacketBuffer) bool {
	epsByNIC.mu.RLock()

	mpep, ok := epsByNIC.endpoints[pkt.NICID]
	if !ok {
		if mpep, ok = epsByNIC.endpoints[0]; !ok {
			epsByNIC.mu.RUnlock()
			return false
		}
	}

	if isInboundMulticastOrBroadcast(pkt, id.LocalAddress) {
		mpep.handlePacketAll(id, pkt)
		epsByNIC.mu.RUnlock()
		return true
	}
	transEP := mpep.selectEndpoint(id, epsByNIC.seed)
	if queuedProtocol, mustQueue := mpep.demux.queuedProtocols[protocolIDs{mpep.netProto, mpep.transProto}]; mustQueue {
		queuedProtocol.QueuePacket(transEP, id, pkt)
		epsByNIC.mu.RUnlock()
		return true
	}
	epsByNIC.mu.RUnlock()

	transEP.HandlePacket(id, pkt)
	return true
}

func (epsByNIC *endpointsByNIC) handleError(n *nic, id TransportEndpointID, transErr TransportError, pkt *PacketBuffer) {
	epsByNIC.mu.RLock()

	mpep, ok := epsByNIC.endpoints[n.ID()]
	if !ok {
		mpep, ok = epsByNIC.endpoints[0]
	}
	if !ok {
		epsByNIC.mu.RUnlock()
		return
	}


	transEP := mpep.selectEndpoint(id, epsByNIC.seed)
	epsByNIC.mu.RUnlock()

	transEP.HandleError(transErr, pkt)
}

func (epsByNIC *endpointsByNIC) registerEndpoint(d *transportDemuxer, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, t TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	epsByNIC.mu.Lock()
	defer epsByNIC.mu.Unlock()

	multiPortEp, ok := epsByNIC.endpoints[bindToDevice]
	if !ok {
		multiPortEp = &multiPortEndpoint{
			demux:      d,
			netProto:   netProto,
			transProto: transProto,
		}
	}

	if err := multiPortEp.singleRegisterEndpoint(t, flags); err != nil {
		return err
	}
	if !ok {
		epsByNIC.endpoints[bindToDevice] = multiPortEp
	}
	return nil
}

func (epsByNIC *endpointsByNIC) checkEndpoint(flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	epsByNIC.mu.RLock()
	defer epsByNIC.mu.RUnlock()

	multiPortEp, ok := epsByNIC.endpoints[bindToDevice]
	if !ok {
		return nil
	}

	return multiPortEp.singleCheckEndpoint(flags)
}

func (epsByNIC *endpointsByNIC) unregisterEndpoint(bindToDevice tcpip.NICID, t TransportEndpoint, flags ports.Flags) bool {
	epsByNIC.mu.Lock()
	defer epsByNIC.mu.Unlock()
	multiPortEp, ok := epsByNIC.endpoints[bindToDevice]
	if !ok {
		return false
	}
	if multiPortEp.unregisterEndpoint(t, flags) {
		delete(epsByNIC.endpoints, bindToDevice)
	}
	return len(epsByNIC.endpoints) == 0
}

type transportDemuxer struct {
	stack *Stack

	protocol        map[protocolIDs]*transportEndpoints
	queuedProtocols map[protocolIDs]queuedTransportProtocol
}

type queuedTransportProtocol interface {
	QueuePacket(ep TransportEndpoint, id TransportEndpointID, pkt *PacketBuffer)
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{
		stack:           stack,
		protocol:        make(map[protocolIDs]*transportEndpoints),
		queuedProtocols: make(map[protocolIDs]queuedTransportProtocol),
	}

	for netProto := range stack.networkProtocols {
		for proto := range stack.transportProtocols {
			protoIDs := protocolIDs{netProto, proto}
			d.protocol[protoIDs] = &transportEndpoints{
				endpoints: make(map[TransportEndpointID]*endpointsByNIC),
			}
			qTransProto, isQueued := (stack.transportProtocols[proto].proto).(queuedTransportProtocol)
			if isQueued {
				d.queuedProtocols[protoIDs] = qTransProto
			}
		}
	}

	return d
}

func (d *transportDemuxer) registerEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	for i, n := range netProtos {
		if err := d.singleRegisterEndpoint(n, protocol, id, ep, flags, bindToDevice); err != nil {
			d.unregisterEndpoint(netProtos[:i], protocol, id, ep, flags, bindToDevice)
			return err
		}
	}

	return nil
}

func (d *transportDemuxer) checkEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	for _, n := range netProtos {
		if err := d.singleCheckEndpoint(n, protocol, id, flags, bindToDevice); err != nil {
			return err
		}
	}

	return nil
}

type multiPortEndpoint struct {
	demux      *transportDemuxer
	netProto   tcpip.NetworkProtocolNumber
	transProto tcpip.TransportProtocolNumber

	flags ports.FlagCounter

	mu multiPortEndpointRWMutex `state:"nosave"`
	endpoints []TransportEndpoint
}

func (ep *multiPortEndpoint) transportEndpoints() []TransportEndpoint {
	ep.mu.RLock()
	eps := append([]TransportEndpoint(nil), ep.endpoints...)
	ep.mu.RUnlock()
	return eps
}

func reciprocalScale(val, n uint32) uint32 {
	return uint32((uint64(val) * uint64(n)) >> 32)
}

func (ep *multiPortEndpoint) selectEndpoint(id TransportEndpointID, seed uint32) TransportEndpoint {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	if len(ep.endpoints) == 1 {
		return ep.endpoints[0]
	}

	if ep.flags.SharedFlags().ToFlags().Effective().MostRecent {
		return ep.endpoints[len(ep.endpoints)-1]
	}

	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8),
	}

	h := jenkins.Sum32(seed)
	h.Write(payload)
	h.Write(id.LocalAddress.AsSlice())
	h.Write(id.RemoteAddress.AsSlice())
	hash := h.Sum32()

	idx := reciprocalScale(hash, uint32(len(ep.endpoints)))
	return ep.endpoints[idx]
}

func (ep *multiPortEndpoint) handlePacketAll(id TransportEndpointID, pkt *PacketBuffer) {
	ep.mu.RLock()
	queuedProtocol, mustQueue := ep.demux.queuedProtocols[protocolIDs{ep.netProto, ep.transProto}]
	for _, endpoint := range ep.endpoints[:len(ep.endpoints)-1] {
		clone := pkt.Clone()
		if mustQueue {
			queuedProtocol.QueuePacket(endpoint, id, clone)
		} else {
			endpoint.HandlePacket(id, clone)
		}
		clone.DecRef()
	}
	if endpoint := ep.endpoints[len(ep.endpoints)-1]; mustQueue {
		queuedProtocol.QueuePacket(endpoint, id, pkt)
	} else {
		endpoint.HandlePacket(id, pkt)
	}
	ep.mu.RUnlock()
}

func (ep *multiPortEndpoint) singleRegisterEndpoint(t TransportEndpoint, flags ports.Flags) tcpip.Error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	bits := flags.Bits() & ports.MultiBindFlagMask

	if len(ep.endpoints) != 0 {
		if ep.flags.TotalRefs() > 0 && bits&ep.flags.SharedFlags() == 0 {
			return &tcpip.ErrPortInUse{}
		}
	}

	ep.endpoints = append(ep.endpoints, t)
	ep.flags.AddRef(bits)

	return nil
}

func (ep *multiPortEndpoint) singleCheckEndpoint(flags ports.Flags) tcpip.Error {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	bits := flags.Bits() & ports.MultiBindFlagMask

	if len(ep.endpoints) != 0 {
		if ep.flags.TotalRefs() > 0 && bits&ep.flags.SharedFlags() == 0 {
			return &tcpip.ErrPortInUse{}
		}
	}

	return nil
}

func (ep *multiPortEndpoint) unregisterEndpoint(t TransportEndpoint, flags ports.Flags) bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	for i, endpoint := range ep.endpoints {
		if endpoint == t {
			copy(ep.endpoints[i:], ep.endpoints[i+1:])
			ep.endpoints[len(ep.endpoints)-1] = nil
			ep.endpoints = ep.endpoints[:len(ep.endpoints)-1]

			ep.flags.DropRef(flags.Bits() & ports.MultiBindFlagMask)
			break
		}
	}
	return len(ep.endpoints) == 0
}

func (d *transportDemuxer) singleRegisterEndpoint(netProto tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	if id.RemotePort != 0 {
		flags.LoadBalanced = false
	}

	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()
	epsByNIC, ok := eps.endpoints[id]
	if !ok {
		epsByNIC = &endpointsByNIC{
			endpoints: make(map[tcpip.NICID]*multiPortEndpoint),
			seed:      d.stack.seed,
		}
	}
	if err := epsByNIC.registerEndpoint(d, netProto, protocol, ep, flags, bindToDevice); err != nil {
		return err
	}
	if !ok {
		eps.endpoints[id] = epsByNIC
	}
	return nil
}

func (d *transportDemuxer) singleCheckEndpoint(netProto tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	if id.RemotePort != 0 {
		flags.LoadBalanced = false
	}

	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	eps.mu.RLock()
	defer eps.mu.RUnlock()

	epsByNIC, ok := eps.endpoints[id]
	if !ok {
		return nil
	}

	return epsByNIC.checkEndpoint(flags, bindToDevice)
}

func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	if id.RemotePort != 0 {
		flags.LoadBalanced = false
	}

	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.unregisterEndpoint(id, ep, flags, bindToDevice)
		}
	}
}

func (d *transportDemuxer) deliverPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{pkt.NetworkProtocolNumber, protocol}]
	if !ok {
		return false
	}

	if protocol == header.UDPProtocolNumber && isInboundMulticastOrBroadcast(pkt, id.LocalAddress) {
		eps.mu.RLock()
		destEPs := eps.findAllEndpointsLocked(id)
		eps.mu.RUnlock()
		if len(destEPs) == 0 {
			d.stack.stats.UDP.UnknownPortErrors.Increment()
			return false
		}
		for _, ep := range destEPs[:len(destEPs)-1] {
			clone := pkt.Clone()
			ep.handlePacket(id, clone)
			clone.DecRef()
		}
		destEPs[len(destEPs)-1].handlePacket(id, pkt)
		return true
	}

	if protocol == header.TCPProtocolNumber && (!isSpecified(id.LocalAddress) || !isSpecified(id.RemoteAddress) || isInboundMulticastOrBroadcast(pkt, id.LocalAddress)) {
		d.stack.stats.TCP.InvalidSegmentsReceived.Increment()
		return true
	}

	eps.mu.RLock()
	ep := eps.findEndpointLocked(id)
	eps.mu.RUnlock()
	if ep == nil {
		if protocol == header.UDPProtocolNumber {
			d.stack.stats.UDP.UnknownPortErrors.Increment()
		}
		return false
	}
	return ep.handlePacket(id, pkt)
}

func (d *transportDemuxer) deliverRawPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) bool {
	eps, ok := d.protocol[protocolIDs{pkt.NetworkProtocolNumber, protocol}]
	if !ok {
		return false
	}

	eps.mu.RLock()
	var rawEPs []RawTransportEndpoint
	if n := len(eps.rawEndpoints); n != 0 {
		rawEPs = make([]RawTransportEndpoint, n)
		if m := copy(rawEPs, eps.rawEndpoints); m != n {
			panic(fmt.Sprintf("unexpected copy = %d, want %d", m, n))
		}
	}
	eps.mu.RUnlock()
	for _, rawEP := range rawEPs {
		clone := pkt.Clone()
		rawEP.HandlePacket(clone)
		clone.DecRef()
	}

	return len(rawEPs) != 0
}

func (d *transportDemuxer) deliverError(n *nic, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, transErr TransportError, pkt *PacketBuffer, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{net, trans}]
	if !ok {
		return false
	}

	eps.mu.RLock()
	ep := eps.findEndpointLocked(id)
	eps.mu.RUnlock()
	if ep == nil {
		return false
	}

	ep.handleError(n, id, transErr, pkt)
	return true
}

func (d *transportDemuxer) findTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, id TransportEndpointID, nicID tcpip.NICID) TransportEndpoint {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		return nil
	}

	eps.mu.RLock()
	epsByNIC := eps.findEndpointLocked(id)
	if epsByNIC == nil {
		eps.mu.RUnlock()
		return nil
	}

	epsByNIC.mu.RLock()
	eps.mu.RUnlock()

	mpep, ok := epsByNIC.endpoints[nicID]
	if !ok {
		if mpep, ok = epsByNIC.endpoints[0]; !ok {
			epsByNIC.mu.RUnlock()
			return nil
		}
	}

	ep := mpep.selectEndpoint(id, epsByNIC.seed)
	epsByNIC.mu.RUnlock()
	return ep
}

func (d *transportDemuxer) registerRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) tcpip.Error {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	eps.mu.Lock()
	eps.rawEndpoints = append(eps.rawEndpoints, ep)
	eps.mu.Unlock()

	return nil
}

func (d *transportDemuxer) unregisterRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		panic(fmt.Errorf("tried to unregister endpoint with unsupported network and transport protocol pair: %d, %d", netProto, transProto))
	}

	eps.mu.Lock()
	for i, rawEP := range eps.rawEndpoints {
		if rawEP == ep {
			lastIdx := len(eps.rawEndpoints) - 1
			eps.rawEndpoints[i] = eps.rawEndpoints[lastIdx]
			eps.rawEndpoints[lastIdx] = nil
			eps.rawEndpoints = eps.rawEndpoints[:lastIdx]
			break
		}
	}
	eps.mu.Unlock()
}

func isInboundMulticastOrBroadcast(pkt *PacketBuffer, localAddr tcpip.Address) bool {
	return pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(localAddr) || header.IsV6MulticastAddress(localAddr)
}

func isSpecified(addr tcpip.Address) bool {
	return addr != header.IPv4Any && addr != header.IPv6Any
}

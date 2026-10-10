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
	"reflect"
	"sort"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type linkResolver struct {
	resolver LinkAddressResolver

	neigh neighborCache
}

var _ NetworkInterface = (*nic)(nil)
var _ NetworkDispatcher = (*nic)(nil)

type nic struct {
	NetworkLinkEndpoint

	stack   *Stack
	id      tcpip.NICID
	name    string
	context NICContext

	stats sharedStats

	enableDisableMu nicRWMutex `state:"nosave"`

	networkEndpoints          map[tcpip.NetworkProtocolNumber]NetworkEndpoint
	linkAddrResolvers         map[tcpip.NetworkProtocolNumber]*linkResolver
	duplicateAddressDetectors map[tcpip.NetworkProtocolNumber]DuplicateAddressDetector

	enabled atomicbitops.Bool

	spoofing atomicbitops.Bool

	promiscuous atomicbitops.Bool

	linkResQueue packetsPendingLinkResolution

	packetEPsMu packetEPsRWMutex `state:"nosave"`

	packetEPs map[tcpip.NetworkProtocolNumber]*packetEndpointList

	qDisc QueueingDiscipline

	deliverLinkPackets bool

	Primary *nic

	experimentIPOptionEnabled bool

	allowPromiscuousSource atomicbitops.Bool
}

func makeNICStats(global tcpip.NICStats) sharedStats {
	var stats sharedStats
	tcpip.InitStatCounters(reflect.ValueOf(&stats.local).Elem())
	stats.init(&stats.local, &global)
	return stats
}

type packetEndpointList struct {
	mu packetEndpointListRWMutex `state:"nosave"`

	eps []PacketEndpoint
}

func (p *packetEndpointList) add(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eps = append(p.eps, ep)
}

func (p *packetEndpointList) remove(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, epOther := range p.eps {
		if epOther == ep {
			p.eps = append(p.eps[:i], p.eps[i+1:]...)
			break
		}
	}
}

func (p *packetEndpointList) len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.eps)
}

func (p *packetEndpointList) forEach(fn func(PacketEndpoint)) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, ep := range p.eps {
		fn(ep)
	}
}

var _ QueueingDiscipline = (*delegatingQueueingDiscipline)(nil)

type delegatingQueueingDiscipline struct {
	LinkWriter
}

func (*delegatingQueueingDiscipline) Close() {}

func (qDisc *delegatingQueueingDiscipline) WritePacket(pkt *PacketBuffer) tcpip.Error {
	var pkts PacketBufferList
	pkts.PushBack(pkt)
	_, err := qDisc.LinkWriter.WritePackets(pkts)
	return err
}

func newNIC(stack *Stack, id tcpip.NICID, ep LinkEndpoint, opts NICOptions) *nic {

	qDisc := opts.QDisc
	if qDisc == nil {
		qDisc = &delegatingQueueingDiscipline{LinkWriter: ep}
	}

	nic := &nic{
		NetworkLinkEndpoint:       ep,
		stack:                     stack,
		id:                        id,
		name:                      opts.Name,
		context:                   opts.Context,
		stats:                     makeNICStats(stack.Stats().NICs),
		networkEndpoints:          make(map[tcpip.NetworkProtocolNumber]NetworkEndpoint),
		linkAddrResolvers:         make(map[tcpip.NetworkProtocolNumber]*linkResolver),
		duplicateAddressDetectors: make(map[tcpip.NetworkProtocolNumber]DuplicateAddressDetector),
		packetEPs:                 make(map[tcpip.NetworkProtocolNumber]*packetEndpointList),
		qDisc:                     qDisc,
		deliverLinkPackets:        opts.DeliverLinkPackets,
		experimentIPOptionEnabled: opts.EnableExperimentIPOption,
	}
	nic.linkResQueue.init(nic)

	resolutionRequired := ep.Capabilities()&CapabilityResolutionRequired != 0

	for _, netProto := range stack.networkProtocols {
		netNum := netProto.Number()
		netEP := netProto.NewEndpoint(nic, nic)
		nic.networkEndpoints[netNum] = netEP

		if resolutionRequired {
			if r, ok := netEP.(LinkAddressResolver); ok {
				l := &linkResolver{resolver: r}
				l.neigh.init(nic, r)
				nic.linkAddrResolvers[r.LinkAddressProtocol()] = l
			}
		}

		if d, ok := netEP.(DuplicateAddressDetector); ok {
			nic.duplicateAddressDetectors[d.DuplicateAddressProtocol()] = d
		}
	}

	nic.NetworkLinkEndpoint.Attach(nic)

	return nic
}

func (n *nic) getNetworkEndpoint(proto tcpip.NetworkProtocolNumber) NetworkEndpoint {
	return n.networkEndpoints[proto]
}

func (n *nic) Enabled() bool {
	return n.enabled.Load()
}

func (n *nic) setEnabled(v bool) bool {
	return n.enabled.Swap(v) != v
}

func (n *nic) disable() {
	n.enableDisableMu.Lock()
	defer n.enableDisableMu.Unlock()
	n.disableLocked()
}

func (n *nic) disableLocked() {
	if !n.Enabled() {
		return
	}


	for _, ep := range n.networkEndpoints {
		ep.Disable()

		netProto := ep.NetworkProtocolNumber()
		switch err := n.clearNeighbors(netProto); err.(type) {
		case nil, *tcpip.ErrNotSupported:
		default:
			panic(fmt.Sprintf("n.clearNeighbors(%d): %s", netProto, err))
		}
	}

	if !n.setEnabled(false) {
		panic("should have only done work to disable the NIC if it was enabled")
	}
}

func (n *nic) enable() tcpip.Error {
	n.enableDisableMu.Lock()
	defer n.enableDisableMu.Unlock()

	if !n.setEnabled(true) {
		return nil
	}

	for _, ep := range n.networkEndpoints {
		if err := ep.Enable(); err != nil {
			return err
		}
	}

	return nil
}

func (n *nic) remove(closeLinkEndpoint bool) (func(), tcpip.Error) {
	n.enableDisableMu.Lock()

	n.disableLocked()

	for _, ep := range n.networkEndpoints {
		ep.Close()
	}

	n.enableDisableMu.Unlock()

	n.linkResQueue.cancel()

	var deferAct func()
	n.qDisc.Close()
	n.NetworkLinkEndpoint.Attach(nil)
	if closeLinkEndpoint {
		ep := n.NetworkLinkEndpoint
		ep.SetOnCloseAction(nil)
		deferAct = ep.Close
	}

	return deferAct, nil
}

func (n *nic) setPromiscuousMode(enable bool) {
	n.promiscuous.Store(enable)
}

func (n *nic) Promiscuous() bool {
	return n.promiscuous.Load()
}

func (n *nic) IsLoopback() bool {
	return n.NetworkLinkEndpoint.Capabilities()&CapabilityLoopback != 0
}

func (n *nic) WritePacket(r *Route, pkt *PacketBuffer) tcpip.Error {
	routeInfo, _, err := r.resolvedFields(nil)
	switch err.(type) {
	case nil:
		pkt.EgressRoute = routeInfo
		return n.writePacket(pkt)
	case *tcpip.ErrWouldBlock:
		return n.linkResQueue.enqueue(r, pkt)
	default:
		return err
	}
}

func (n *nic) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, pkt *PacketBuffer) tcpip.Error {
	pkt.EgressRoute = RouteInfo{
		routeInfo: routeInfo{
			NetProto:         pkt.NetworkProtocolNumber,
			LocalLinkAddress: n.LinkAddress(),
		},
		RemoteLinkAddress: remoteLinkAddr,
	}
	return n.writePacket(pkt)
}

func (n *nic) writePacket(pkt *PacketBuffer) tcpip.Error {
	n.NetworkLinkEndpoint.AddHeader(pkt)
	return n.writeRawPacket(pkt)
}

func (n *nic) writeRawPacketWithLinkHeaderInPayload(pkt *PacketBuffer) tcpip.Error {
	if !n.NetworkLinkEndpoint.ParseHeader(pkt) {
		return &tcpip.ErrMalformedHeader{}
	}
	return n.writeRawPacket(pkt)
}

func (n *nic) writeRawPacket(pkt *PacketBuffer) tcpip.Error {
	pkt.PktType = tcpip.PacketOutgoing

	if n.deliverLinkPackets {
		n.DeliverLinkPacket(pkt.NetworkProtocolNumber, pkt)
	}

	if err := n.qDisc.WritePacket(pkt); err != nil {
		if _, ok := err.(*tcpip.ErrNoBufferSpace); ok {
			n.stats.txPacketsDroppedNoBufferSpace.Increment()
		}
		return err
	}

	n.stats.tx.packets.Increment()
	n.stats.tx.bytes.IncrementBy(uint64(pkt.Size()))
	return nil
}

func (n *nic) setSpoofing(enable bool) {
	n.spoofing.Store(enable)
}

func (n *nic) Spoofing() bool {
	return n.spoofing.Load()
}

func (n *nic) setAllowPromiscuousSource(enable bool) {
	n.allowPromiscuousSource.Store(enable)
}

func (n *nic) AllowPromiscuousSource() bool {
	return n.allowPromiscuousSource.Load()
}

func (n *nic) primaryEndpoint(protocol tcpip.NetworkProtocolNumber, remoteAddr, srcHint tcpip.Address) AssignableAddressEndpoint {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireOutgoingPrimaryAddress(remoteAddr, srcHint, n.Spoofing())
}

type getAddressBehaviour int

const (
	spoofing getAddressBehaviour = iota

	promiscuous
)

func (n *nic) getAddress(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, promiscuous)
}

func (n *nic) hasAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	ep := n.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint)
	if ep != nil {
		ep.DecRef()
		return true
	}

	return false
}

func (n *nic) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, address, peb, spoofing)
}

func (n *nic) getAddressOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, tempRef getAddressBehaviour) AssignableAddressEndpoint {
	var spoofingOrPromiscuous bool
	switch tempRef {
	case spoofing:
		spoofingOrPromiscuous = n.Spoofing()
	case promiscuous:
		spoofingOrPromiscuous = n.Promiscuous()
	}
	return n.getAddressOrCreateTempInner(protocol, address, spoofingOrPromiscuous, peb)
}

func (n *nic) getAddressOrCreateTempInner(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, createTemp bool, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireAssignedAddress(address, createTemp, peb, false)
}

func (n *nic) addAddress(protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	ep := n.getNetworkEndpoint(protocolAddress.Protocol)
	if ep == nil {
		return &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	addressEndpoint, err := addressableEndpoint.AddAndAcquirePermanentAddress(protocolAddress.AddressWithPrefix, properties)
	if err == nil {
		addressEndpoint.DecRef()
	}
	return err
}

func (n *nic) allPermanentAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PermanentAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

func (n *nic) primaryAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress

	protocolNumbers := make([]tcpip.NetworkProtocolNumber, 0, len(n.networkEndpoints))
	for p := range n.networkEndpoints {
		protocolNumbers = append(protocolNumbers, p)
	}
	sort.Slice(protocolNumbers, func(i, j int) bool {
		return protocolNumbers[i] < protocolNumbers[j]
	})

	for _, p := range protocolNumbers {
		addressableEndpoint, ok := n.networkEndpoints[p].(AddressableEndpoint)
		if !ok {
			continue
		}
		for _, a := range addressableEndpoint.PrimaryAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

func (n *nic) PrimaryAddress(proto tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	ep := n.getNetworkEndpoint(proto)
	if ep == nil {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrNotSupported{}
	}

	return addressableEndpoint.MainAddress(), nil
}

func (n *nic) removeAddress(addr tcpip.Address) tcpip.Error {
	for _, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		switch err := addressableEndpoint.RemovePermanentAddress(addr); err.(type) {
		case *tcpip.ErrBadLocalAddress:
			continue
		default:
			return err
		}
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (n *nic) setAddressLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	for _, ep := range n.networkEndpoints {
		ep, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		switch err := ep.SetLifetimes(addr, lifetimes); err.(type) {
		case *tcpip.ErrBadLocalAddress:
			continue
		default:
			return err
		}
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (n *nic) getLinkAddress(addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, onResolve func(LinkResolutionResult)) tcpip.Error {
	linkRes, ok := n.linkAddrResolvers[protocol]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	if linkAddr, ok := linkRes.resolver.ResolveStaticAddress(addr); ok {
		onResolve(LinkResolutionResult{LinkAddress: linkAddr, Err: nil})
		return nil
	}

	_, _, err := linkRes.neigh.entry(addr, localAddr, onResolve)
	return err
}

func (n *nic) neighbors(protocol tcpip.NetworkProtocolNumber) ([]NeighborEntry, tcpip.Error) {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		return linkRes.neigh.entries(), nil
	}

	return nil, &tcpip.ErrNotSupported{}
}

func (n *nic) addStaticNeighbor(addr tcpip.Address, protocol tcpip.NetworkProtocolNumber, linkAddress tcpip.LinkAddress) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		linkRes.neigh.addStaticEntry(addr, linkAddress)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) removeNeighbor(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		if !linkRes.neigh.removeEntry(addr) {
			return &tcpip.ErrBadAddress{}
		}
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) clearNeighbors(protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		linkRes.neigh.clear()
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) joinGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {

	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return &tcpip.ErrNotSupported{}
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return gep.JoinGroup(addr)
}

func (n *nic) leaveGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return &tcpip.ErrNotSupported{}
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return gep.LeaveGroup(addr)
}

func (n *nic) isInGroup(addr tcpip.Address) bool {
	for _, ep := range n.networkEndpoints {
		gep, ok := ep.(GroupAddressableEndpoint)
		if !ok {
			continue
		}

		if gep.IsInGroup(addr) {
			return true
		}
	}

	return false
}

func (n *nic) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	enabled := n.Enabled()
	if !enabled {
		n.stats.disabledRx.packets.Increment()
		n.stats.disabledRx.bytes.IncrementBy(uint64(pkt.Data().Size()))
		return
	}

	n.stats.rx.packets.Increment()
	n.stats.rx.bytes.IncrementBy(uint64(pkt.Data().Size()))

	networkEndpoint := n.getNetworkEndpoint(protocol)
	if networkEndpoint == nil {
		n.stats.unknownL3ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return
	}

	pkt.RXChecksumValidated = n.NetworkLinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0

	if n.deliverLinkPackets {
		n.DeliverLinkPacket(protocol, pkt)
	}

	networkEndpoint.HandlePacket(pkt)
}

func (n *nic) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	var packetEPPkt *PacketBuffer
	defer func() {
		if packetEPPkt != nil {
			packetEPPkt.DecRef()
		}
	}()
	deliverPacketEPs := func(ep PacketEndpoint) {
		if packetEPPkt == nil {
			packetEPPkt = NewPacketBuffer(PacketBufferOptions{
				Payload: BufferSince(pkt.LinkHeader()),
			})
			packetEPPkt.LinkHeader().Consume(len(pkt.LinkHeader().Slice()))
			packetEPPkt.PktType = pkt.PktType
			if packetEPPkt.PktType == 0 {
				packetEPPkt.PktType = tcpip.PacketHost
			}
		}

		clone := packetEPPkt.Clone()
		defer clone.DecRef()
		ep.HandlePacket(n.id, protocol, clone)
	}

	n.packetEPsMu.Lock()
	protoEPs, protoEPsOK := n.packetEPs[protocol]
	anyEPs, anyEPsOK := n.packetEPs[header.EthernetProtocolAll]
	n.packetEPsMu.Unlock()

	if pkt.PktType != tcpip.PacketOutgoing && protoEPsOK {
		protoEPs.forEach(deliverPacketEPs)
	}
	if anyEPsOK {
		anyEPs.forEach(deliverPacketEPs)
	}
}

func (n *nic) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) TransportPacketDisposition {
	res, _ := n.deliverTransportPacket(protocol, pkt)
	return res
}

func (n *nic) DeliverTransportPacketWithDefaultHandlerResult(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) (TransportPacketDisposition, bool) {
	return n.deliverTransportPacket(protocol, pkt)
}

func (n *nic) deliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) (TransportPacketDisposition, bool) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stats.unknownL4ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return TransportPacketProtocolUnreachable, false
	}

	transProto := state.proto

	if len(pkt.TransportHeader().Slice()) == 0 {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	}

	srcPort, dstPort, err := transProto.ParsePorts(pkt.TransportHeader().Slice())
	if err != nil {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	}

	netProto, ok := n.stack.networkProtocols[pkt.NetworkProtocolNumber]
	if !ok {
		panic(fmt.Sprintf("expected network protocol = %d, have = %#v", pkt.NetworkProtocolNumber, n.stack.networkProtocolNumbers()))
	}

	src, dst := netProto.ParseAddresses(pkt.NetworkHeader().Slice())
	id := TransportEndpointID{
		LocalPort:     dstPort,
		LocalAddress:  dst,
		RemotePort:    srcPort,
		RemoteAddress: src,
	}
	if n.stack.demux.deliverPacket(protocol, pkt, id) {
		return TransportPacketHandled, false
	}

	if state.defaultHandler != nil {
		if state.defaultHandler(id, pkt) {
			return TransportPacketHandled, true
		}
	}

	switch res := transProto.HandleUnknownDestinationPacket(id, pkt); res {
	case UnknownDestinationPacketMalformed:
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	case UnknownDestinationPacketUnhandled:
		return TransportPacketDestinationPortUnreachable, false
	case UnknownDestinationPacketHandled:
		return TransportPacketHandled, false
	default:
		panic(fmt.Sprintf("unrecognized result from HandleUnknownDestinationPacket = %d", res))
	}
}

func (n *nic) DeliverTransportError(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, transErr TransportError, pkt *PacketBuffer) {
	state, ok := n.stack.transportProtocols[trans]
	if !ok {
		return
	}

	transProto := state.proto

	transHeader, ok := pkt.Data().PullUp(8)
	if !ok {
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(transHeader)
	if err != nil {
		return
	}

	id := TransportEndpointID{srcPort, local, dstPort, remote}
	if n.stack.demux.deliverError(n, net, trans, transErr, pkt, id) {
		return
	}
}

func (n *nic) DeliverRawPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) {
	if protocol == header.ICMPv4ProtocolNumber && len(pkt.TransportHeader().Slice())+pkt.Data().Size() < header.ICMPv4MinimumSize {
		return
	}
	n.stack.demux.deliverRawPacket(protocol, pkt)
}

func (n *nic) ID() tcpip.NICID {
	return n.id
}

func (n *nic) Name() string {
	return n.name
}

func (n *nic) nudConfigs(protocol tcpip.NetworkProtocolNumber) (NUDConfigurations, tcpip.Error) {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		return linkRes.neigh.config(), nil
	}

	return NUDConfigurations{}, &tcpip.ErrNotSupported{}
}

func (n *nic) setNUDConfigs(protocol tcpip.NetworkProtocolNumber, c NUDConfigurations) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		c.resetInvalidFields()
		linkRes.neigh.setConfig(c)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) registerPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.packetEPsMu.Lock()
	defer n.packetEPsMu.Unlock()

	eps, ok := n.packetEPs[netProto]
	if !ok {
		eps = new(packetEndpointList)
		n.packetEPs[netProto] = eps
	}
	eps.add(ep)
}

func (n *nic) unregisterPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.packetEPsMu.Lock()
	defer n.packetEPsMu.Unlock()

	eps, ok := n.packetEPs[netProto]
	if !ok {
		return
	}
	eps.remove(ep)
	if eps.len() == 0 {
		delete(n.packetEPs, netProto)
	}
}

func (n *nic) isValidForOutgoing(ep AssignableAddressEndpoint) bool {
	return n.Enabled() && ep.IsAssigned(n.Spoofing())
}

func (n *nic) HandleNeighborProbe(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	if l, ok := n.linkAddrResolvers[protocol]; ok {
		l.neigh.handleProbe(addr, linkAddr)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) HandleNeighborConfirmation(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) tcpip.Error {
	if l, ok := n.linkAddrResolvers[protocol]; ok {
		l.neigh.handleConfirmation(addr, linkAddr, flags)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) CheckLocalAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	if n.Spoofing() {
		return true
	}

	if addressEndpoint := n.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
		return true
	}

	return false
}

func (n *nic) checkDuplicateAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, h DADCompletionHandler) (DADCheckAddressDisposition, tcpip.Error) {
	d, ok := n.duplicateAddressDetectors[protocol]
	if !ok {
		return 0, &tcpip.ErrNotSupported{}
	}

	return d.CheckDuplicateAddress(addr, h), nil
}

func (n *nic) setForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingEP.SetForwarding(enable), nil
}

func (n *nic) forwarding(protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingEP.Forwarding(), nil
}

func (n *nic) multicastForwardingEndpoint(protocol tcpip.NetworkProtocolNumber) (MulticastForwardingNetworkEndpoint, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(MulticastForwardingNetworkEndpoint)
	if !ok {
		return nil, &tcpip.ErrNotSupported{}
	}

	return forwardingEP, nil
}

func (n *nic) setMulticastForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	ep, err := n.multicastForwardingEndpoint(protocol)
	if err != nil {
		return false, err
	}

	return ep.SetMulticastForwarding(enable), nil
}

func (n *nic) multicastForwarding(protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	ep, err := n.multicastForwardingEndpoint(protocol)
	if err != nil {
		return false, err
	}

	return ep.MulticastForwarding(), nil
}

func (n *nic) GetExperimentIPOptionEnabled() bool {
	return n.experimentIPOptionEnabled
}

type CoordinatorNIC interface {
	AddNIC(n *nic) tcpip.Error
	DelNIC(n *nic) tcpip.Error
}

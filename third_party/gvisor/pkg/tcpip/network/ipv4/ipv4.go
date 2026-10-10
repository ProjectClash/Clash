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

package ipv4

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/network/hash"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/fragmentation"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/multicast"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	ReassembleTimeout = 30 * time.Second

	ProtocolNumber = header.IPv4ProtocolNumber

	MaxTotalSize = 0xffff

	DefaultTTL = 64

	buckets = 2048

	fragmentblockSize = 8
)

const (
	forwardingDisabled = 0
	forwardingEnabled  = 1
)

var martianPacketLogger = log.BasicRateLimitedLogger(time.Minute)

var ipv4BroadcastAddr = header.IPv4Broadcast.WithPrefix()

var _ stack.LinkResolvableNetworkEndpoint = (*endpoint)(nil)
var _ stack.ForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.MulticastForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)
var _ IGMPEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol
	stats      sharedStats

	enabled atomicbitops.Uint32

	forwarding atomicbitops.Uint32

	multicastForwarding atomicbitops.Uint32

	mu sync.RWMutex `state:"nosave"`

	addressableEndpointState stack.AddressableEndpointState

	igmp igmpState
}

func (e *endpoint) SetIGMPVersion(v IGMPVersion) IGMPVersion {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.setIGMPVersionLocked(v)
}

func (e *endpoint) GetIGMPVersion() IGMPVersion {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getIGMPVersionLocked()
}

func (e *endpoint) setIGMPVersionLocked(v IGMPVersion) IGMPVersion {
	return e.igmp.setVersion(v)
}

func (e *endpoint) getIGMPVersionLocked() IGMPVersion {
	return e.igmp.getVersion()
}

func (e *endpoint) HandleLinkResolutionFailure(pkt *stack.PacketBuffer) {
	if pkt.NetworkPacketInfo.IsForwardedPacket {
		e.protocol.returnError(&icmpReasonHostUnreachable{}, pkt, false)
		e.stats.ip.Forwarding.Errors.Increment()
		e.stats.ip.Forwarding.HostUnreachable.Increment()
		return
	}
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: pkt.ToBuffer(),
	})
	defer pkt.DecRef()
	pkt.NICID = e.nic.ID()
	pkt.NetworkProtocolNumber = ProtocolNumber
	e.handleControl(&icmpv4DestinationHostUnreachableSockError{}, pkt)
}

func (p *protocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:        nic,
		dispatcher: dispatcher,
		protocol:   p,
	}
	e.mu.Lock()
	e.addressableEndpointState.Init(e, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: false})
	e.igmp.init(e)
	e.mu.Unlock()

	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())

	stackStats := p.stack.Stats()
	e.stats.ip.Init(&e.stats.localStats.IP, &stackStats.IP)
	e.stats.icmp.init(&e.stats.localStats.ICMP, &stackStats.ICMP.V4)
	e.stats.igmp.init(&e.stats.localStats.IGMP, &stackStats.IGMP)

	p.mu.Lock()
	p.eps[nic.ID()] = e
	p.mu.Unlock()

	return e
}

func (p *protocol) findEndpointWithAddress(addr tcpip.Address) *endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint, true); addressEndpoint != nil {
			return e
		}
	}

	return nil
}

func (p *protocol) getEndpointForNIC(id tcpip.NICID) (*endpoint, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ep, ok := p.eps[id]
	return ep, ok
}

func (p *protocol) forgetEndpoint(nicID tcpip.NICID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.eps, nicID)
}

func (e *endpoint) Forwarding() bool {
	return e.forwarding.Load() == forwardingEnabled
}

func (e *endpoint) setForwarding(v bool) bool {
	forwarding := uint32(forwardingDisabled)
	if v {
		forwarding = forwardingEnabled
	}

	return e.forwarding.Swap(forwarding) != forwardingDisabled
}

func (e *endpoint) SetForwarding(forwarding bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	prevForwarding := e.setForwarding(forwarding)
	if prevForwarding == forwarding {
		return prevForwarding
	}

	if forwarding {
		if err := e.joinGroupLocked(header.IPv4AllRoutersGroup); err != nil {
			panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", header.IPv4AllRoutersGroup, err))
		}

		return prevForwarding
	}

	switch err := e.leaveGroupLocked(header.IPv4AllRoutersGroup).(type) {
	case nil:
	case *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("e.leaveGroupLocked(%s): %s", header.IPv4AllRoutersGroup, err))
	}

	return prevForwarding
}

func (e *endpoint) MulticastForwarding() bool {
	return e.multicastForwarding.Load() == forwardingEnabled
}

func (e *endpoint) SetMulticastForwarding(forwarding bool) bool {
	updatedForwarding := uint32(forwardingDisabled)
	if forwarding {
		updatedForwarding = forwardingEnabled
	}

	return e.multicastForwarding.Swap(updatedForwarding) != forwardingDisabled
}

func (e *endpoint) Enable() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enableLocked()
}

func (e *endpoint) enableLocked() tcpip.Error {
	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}

	if !e.setEnabled(true) {
		return nil
	}

	e.addressableEndpointState.OnNetworkEndpointEnabledChanged()

	ep, err := e.addressableEndpointState.AddAndAcquirePermanentAddress(ipv4BroadcastAddr, stack.AddressProperties{PEB: stack.NeverPrimaryEndpoint})
	if err != nil {
		return err
	}
	ep.DecRef()

	e.igmp.initializeAll()

	if err := e.joinGroupLocked(header.IPv4AllSystems); err != nil {
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", header.IPv4AllSystems, err))
	}

	return nil
}

func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

func (e *endpoint) isEnabled() bool {
	return e.enabled.Load() == 1
}

func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return e.enabled.Swap(1) == 0
	}
	return e.enabled.Swap(0) == 1
}

func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.isEnabled() {
		return
	}

	switch err := e.leaveGroupLocked(header.IPv4AllSystems).(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv4AllSystems, err))
	}

	e.igmp.softLeaveAll()

	switch err := e.addressableEndpointState.RemovePermanentAddress(ipv4BroadcastAddr.Address); err.(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when removing address = %s: %s", ipv4BroadcastAddr.Address, err))
	}

	e.igmp.resetV1Present()

	if !e.setEnabled(false) {
		panic("should have only done work to disable the endpoint if it was enabled")
	}

	e.addressableEndpointState.OnNetworkEndpointEnabledChanged()
}

func (e *endpoint) emitMulticastEvent(eventGenerator func(stack.MulticastForwardingEventDispatcher)) {
	e.protocol.mu.RLock()
	defer e.protocol.mu.RUnlock()

	if mcastDisp := e.protocol.multicastForwardingDisp; mcastDisp != nil {
		eventGenerator(mcastDisp)
	}
}

func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

func (e *endpoint) MTU() uint32 {
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv4MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

func (e *endpoint) EndpointHeaderSize() uint32 {
	return header.IPv4MinimumSize
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv4MaximumHeaderSize
}

func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

func (e *endpoint) getID() uint16 {
	rng := e.protocol.stack.SecureRNG()
	id := rng.Uint16()
	for id == 0 {
		id = rng.Uint16()
	}
	return id
}

func (e *endpoint) addIPHeader(srcAddr, dstAddr tcpip.Address, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams, options header.IPv4OptionsSerializer) tcpip.Error {
	if expVal := params.ExperimentOptionValue; expVal != 0 {
		options = append(options, &header.IPv4SerializableExperimentOption{Tag: expVal})
	}
	hdrLen := header.IPv4MinimumSize
	var optLen int
	if options != nil {
		optLen = int(options.Length())
	}
	hdrLen += optLen
	if hdrLen > header.IPv4MaximumHeaderSize {
		return &tcpip.ErrMessageTooLong{}
	}
	ipH := header.IPv4(pkt.NetworkHeader().Push(hdrLen))
	length := pkt.Size()
	if length > math.MaxUint16 {
		return &tcpip.ErrMessageTooLong{}
	}

	fields := header.IPv4Fields{
		TotalLength: uint16(length),
		TTL:         params.TTL,
		TOS:         params.TOS,
		Protocol:    uint8(params.Protocol),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Options:     options,
	}
	if params.DF {
		fields.Flags = header.IPv4FlagDontFragment
	} else {
		fields.ID = e.getID()
	}
	ipH.Encode(&fields)

	ipH.SetChecksum(^ipH.CalculateChecksum())
	pkt.NetworkProtocolNumber = ProtocolNumber
	return nil
}

func (e *endpoint) handleFragments(_ *stack.Route, networkMTU uint32, pkt *stack.PacketBuffer, handler func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	fragmentPayloadSize := networkMTU &^ 7
	networkHeader := header.IPv4(pkt.NetworkHeader().Slice())
	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadSize, pkt.AvailableHeaderBytes()+len(networkHeader))
	defer pf.Release()

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader)
		err := handler(fragPkt)
		fragPkt.DecRef()
		if err != nil {
			return n, pf.RemainingFragmentCount() + 1, err
		}
		n++
		if !more {
			return n, pf.RemainingFragmentCount(), nil
		}
	}
}

func recalculateChecksum(pkt *stack.PacketBuffer, r *stack.Route) tcpip.Error {
	if pkt.RXChecksumValidated {
		return nil
	}
	if pkt.GSOOptions.Type != stack.GSONone && pkt.GSOOptions.NeedsCsum {
		return nil
	}
	transportHeader := pkt.TransportHeader().Slice()
	netHdr := header.IPv4(pkt.NetworkHeader().Slice())
	switch pkt.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		if len(transportHeader) < header.TCPMinimumSize {
			return &tcpip.ErrMalformedHeader{}
		}
		tcp := header.TCP(transportHeader)
		xsum := r.PseudoHeaderChecksum(header.TCPProtocolNumber, netHdr.PayloadLength())
		xsum = checksum.Combine(xsum, pkt.Data().Checksum())
		tcp.SetChecksum(0)
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	case header.UDPProtocolNumber:
		if len(transportHeader) < header.UDPMinimumSize {
			return &tcpip.ErrMalformedHeader{}
		}
		udp := header.UDP(transportHeader)
		xsum := r.PseudoHeaderChecksum(header.UDPProtocolNumber, netHdr.PayloadLength())
		xsum = checksum.Combine(xsum, pkt.Data().Checksum())
		udp.SetChecksum(0)
		csum := ^udp.CalculateChecksum(xsum)
		if csum == 0 {
			csum = 0xFFFF
		}
		udp.SetChecksum(csum)
	}
	return nil
}

func (e *endpoint) WritePacket(r *stack.Route, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) tcpip.Error {
	if err := e.addIPHeader(r.LocalAddress(), r.RemoteAddress(), pkt, params, nil); err != nil {
		return err
	}

	return e.writePacket(r, pkt)
}

func (e *endpoint) writePacket(r *stack.Route, pkt *stack.PacketBuffer) tcpip.Error {
	netHeader := header.IPv4(pkt.NetworkHeader().Slice())
	dstAddr := netHeader.DestinationAddress()
	stk := e.protocol.stack

	outNicName := stk.FindNICNameFromID(e.nic.ID())
	if ok := stk.IPTables().CheckOutput(pkt, r, outNicName); !ok {
		e.stats.ip.IPTablesOutputDropped.Increment()
		return nil
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckOutput(pkt, r, stack.IP) {
			return nil
		}
	}

	if newDstAddr := netHeader.DestinationAddress(); dstAddr != newDstAddr {
		if ep := e.protocol.findEndpointWithAddress(newDstAddr); ep != nil {
			ep.handleLocalPacket(pkt, true)
			return nil
		}

		stk := e.protocol.stack
		newRoute, err := stk.FindRoute(0, netHeader.SourceAddress(), newDstAddr, header.IPv4ProtocolNumber, false)
		if err != nil {
			return err
		}
		defer newRoute.Release()

		if !r.RequiresTXTransportChecksum() && newRoute.RequiresTXTransportChecksum() {
			if err := recalculateChecksum(pkt, newRoute); err != nil {
				return err
			}
		}

		r = newRoute

		forwardToEp, ok := e.protocol.getEndpointForNIC(r.NICID())
		if !ok {
			return &tcpip.ErrUnknownNICID{}
		}
		return forwardToEp.writePacketPostRouting(r, pkt, true)
	}

	return e.writePacketPostRouting(r, pkt, false)
}

func (e *endpoint) writePacketPostRouting(r *stack.Route, pkt *stack.PacketBuffer, headerIncluded bool) tcpip.Error {
	if r.Loop()&stack.PacketLoop != 0 {
		e.handleLocalPacket(pkt, !headerIncluded)
	}
	if r.Loop()&stack.PacketOut == 0 {
		return nil
	}

	stk := e.protocol.stack
	outNicName := stk.FindNICNameFromID(e.nic.ID())
	if ok := stk.IPTables().CheckPostrouting(pkt, r, e, outNicName); !ok {
		e.stats.ip.IPTablesPostroutingDropped.Increment()
		return nil
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckPostrouting(pkt, r, stack.IP) {
			return nil
		}
	}

	stats := e.stats.ip

	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(len(pkt.NetworkHeader().Slice())))
	if err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	if packetMustBeFragmented(pkt, networkMTU) {
		h := header.IPv4(pkt.NetworkHeader().Slice())
		if h.Flags()&header.IPv4FlagDontFragment != 0 && pkt.NetworkPacketInfo.IsForwardedPacket {
			return &tcpip.ErrMessageTooLong{}
		}
		sent, remain, err := e.handleFragments(r, networkMTU, pkt, func(fragPkt *stack.PacketBuffer) tcpip.Error {
			return e.nic.WritePacket(r, fragPkt)
		})
		stats.PacketsSent.IncrementBy(uint64(sent))
		stats.OutgoingPacketErrors.IncrementBy(uint64(remain))
		return err
	}

	if err := e.nic.WritePacket(r, pkt); err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}
	stats.PacketsSent.Increment()
	return nil
}

func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) tcpip.Error {
	h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}

	hdrLen := header.IPv4(h).HeaderLength()
	if hdrLen < header.IPv4MinimumSize {
		return &tcpip.ErrMalformedHeader{}
	}

	h, ok = pkt.Data().PullUp(int(hdrLen))
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}
	ipH := header.IPv4(h)

	pktSize := pkt.Data().Size()
	ipH.SetTotalLength(uint16(pktSize))

	if ipH.SourceAddress() == header.IPv4Any {
		ipH.SetSourceAddress(r.LocalAddress())
	}

	if ipH.ID() == 0 {
		if ipH.Flags()&header.IPv4FlagDontFragment == 0 || ipH.Flags()&header.IPv4FlagMoreFragments != 0 || ipH.FragmentOffset() > 0 {
			ipH.SetID(e.getID())
		}
	}

	ipH.SetChecksum(0)
	ipH.SetChecksum(^ipH.CalculateChecksum())

	if !parse.IPv4(pkt) || !header.IPv4(pkt.NetworkHeader().Slice()).IsValid(pktSize) {
		return &tcpip.ErrMalformedHeader{}
	}

	return e.writePacketPostRouting(r, pkt, true)
}

func (e *endpoint) forwardPacketWithRoute(route *stack.Route, pkt *stack.PacketBuffer, updateOptions bool) ip.ForwardingError {
	h := header.IPv4(pkt.NetworkHeader().Slice())
	stk := e.protocol.stack

	inNicName := stk.FindNICNameFromID(e.nic.ID())
	outNicName := stk.FindNICNameFromID(route.NICID())
	if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
		e.stats.ip.IPTablesForwardDropped.Increment()
		return nil
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckForward(pkt, route, stack.IP) {
			return nil
		}
	}

	newPkt := pkt.DeepCopyForForwarding(int(route.MaxHeaderLength()))
	newHdr := header.IPv4(newPkt.NetworkHeader().Slice())
	defer newPkt.DecRef()

	forwardToEp, ok := e.protocol.getEndpointForNIC(route.NICID())
	if !ok {
		return &ip.ErrUnknownOutputEndpoint{}
	}

	if updateOptions {
		if err := forwardToEp.updateOptionsForForwarding(newPkt); err != nil {
			return err
		}
	}

	ttl := h.TTL()
	newHdr.SetTTL(ttl - 1)
	newHdr.SetChecksum(0)
	newHdr.SetChecksum(^newHdr.CalculateChecksum())

	if route.RequiresTXTransportChecksum() {
		newPkt.CalculateTransportChecksum()
	}

	switch err := forwardToEp.writePacketPostRouting(route, newPkt, true); err.(type) {
	case nil:
		return nil
	case *tcpip.ErrMessageTooLong:
		_ = e.protocol.returnError(&icmpReasonFragmentationNeeded{
			mtu: forwardToEp.nic.MTU(),
		}, pkt, false)
		return &ip.ErrMessageTooLong{}
	case *tcpip.ErrNoBufferSpace:
		return &ip.ErrOutgoingDeviceNoBufferSpace{}
	default:
		return &ip.ErrOther{Err: err}
	}
}

func (e *endpoint) forwardUnicastPacket(pkt *stack.PacketBuffer) ip.ForwardingError {
	hView := pkt.NetworkHeader().View()
	defer hView.Release()
	h := header.IPv4(hView.AsSlice())

	dstAddr := h.DestinationAddress()

	if err := validateAddressesForForwarding(h); err != nil {
		return err
	}

	ttl := h.TTL()
	if ttl == 0 {
		_ = e.protocol.returnError(&icmpReasonTTLExceeded{}, pkt, false)
		return &ip.ErrTTLExceeded{}
	}

	if err := e.updateOptionsForForwarding(pkt); err != nil {
		return err
	}

	stk := e.protocol.stack

	if ep := e.protocol.findEndpointWithAddress(dstAddr); ep != nil {
		inNicName := stk.FindNICNameFromID(e.nic.ID())
		outNicName := stk.FindNICNameFromID(ep.nic.ID())
		if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
			e.stats.ip.IPTablesForwardDropped.Increment()
			return nil
		}

		if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
			if !nft.CheckForward(pkt, nil, stack.IP) {
				return nil
			}
		}

		ep.handleValidatedPacket(h, pkt, e.nic.Name())
		return nil
	}

	r, err := stk.FindRoute(0, tcpip.Address{}, dstAddr, ProtocolNumber, false)
	switch err.(type) {
	case nil:
	case *tcpip.ErrNetworkUnreachable:
		_ = e.protocol.returnError(&icmpReasonNetworkUnreachable{}, pkt, false)
		return &ip.ErrHostUnreachable{}
	default:
		return &ip.ErrOther{Err: err}
	}
	defer r.Release()

	return e.forwardPacketWithRoute(r, pkt, false)
}

func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.stats.ip

	stats.PacketsReceived.Increment()

	if !e.isEnabled() {
		stats.DisabledPacketsReceived.Increment()
		return
	}

	hView, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}
	h := header.IPv4(hView.AsSlice())
	defer hView.Release()

	if !e.nic.IsLoopback() {
		if !e.protocol.options.AllowExternalLoopbackTraffic {
			if header.IsV4LoopbackAddress(h.SourceAddress()) {
				martianPacketLogger.Infof("Martian packet dropped with loopback source address. If your traffic is unexpectedly dropped, you may want to allow martian packets.")
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}

			if header.IsV4LoopbackAddress(h.DestinationAddress()) {
				martianPacketLogger.Infof("Martian packet dropped with loopback destination address. If your traffic is unexpectedly dropped, you may want to allow martian packets.")
				stats.InvalidDestinationAddressesReceived.Increment()
				return
			}
		}

		stk := e.protocol.stack
		if stk.HandleLocal() {
			promiscuous := e.nic.Promiscuous()
			allowPromiscuousSource := promiscuous && e.nic.AllowPromiscuousSource()
			addressEndpoint := e.AcquireAssignedAddress(header.IPv4(pkt.NetworkHeader().Slice()).SourceAddress(), promiscuous && !allowPromiscuousSource, stack.CanBePrimaryEndpoint, true)
			if addressEndpoint != nil && (!allowPromiscuousSource || addressEndpoint.GetKind().IsPermanent()) {
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}
		}

		nicID := e.nic.ID()
		inNicName := stk.FindNICNameFromID(nicID)
		pkt.InputNICID = nicID
		if ok := stk.IPTables().CheckPrerouting(pkt, e, inNicName); !ok {
			stats.IPTablesPreroutingDropped.Increment()
			return
		}

		if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
			if !nft.CheckPrerouting(pkt, nil, stack.IP) {
				return
			}
		}
	}
	h = header.IPv4(pkt.NetworkHeader().Slice())
	e.handleValidatedPacket(h, pkt, e.nic.Name())
}

func (e *endpoint) handleLocalPacket(pkt *stack.PacketBuffer, canSkipRXChecksum bool) {
	stats := e.stats.ip
	stats.PacketsReceived.Increment()

	pkt = pkt.CloneToInbound()
	defer pkt.DecRef()
	pkt.RXChecksumValidated = canSkipRXChecksum

	hView, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}
	h := header.IPv4(hView.AsSlice())
	defer hView.Release()

	e.handleValidatedPacket(h, pkt, e.nic.Name())
}

func validateAddressesForForwarding(h header.IPv4) ip.ForwardingError {
	srcAddr := h.SourceAddress()

	if header.IPv4CurrentNetworkSubnet.Contains(srcAddr) {
		return &ip.ErrInitializingSourceAddress{}
	}

	return nil
}

func (e *endpoint) forwardMulticastPacket(h header.IPv4, pkt *stack.PacketBuffer) ip.ForwardingError {
	if err := validateAddressesForForwarding(h); err != nil {
		return err
	}

	if opts := h.Options(); len(opts) != 0 {
		if _, _, optProblem := e.processIPOptions(pkt, opts, &optionUsageVerify{}); optProblem != nil {
			return &ip.ErrParameterProblem{}
		}
	}

	routeKey := stack.UnicastSourceAndMulticastDestination{
		Source:      h.SourceAddress(),
		Destination: h.DestinationAddress(),
	}

	result, hasBufferSpace := e.protocol.multicastRouteTable.GetRouteOrInsertPending(routeKey, pkt)

	if !hasBufferSpace {
		return &ip.ErrNoMulticastPendingQueueBufferSpace{}
	}

	switch result.GetRouteResultState {
	case multicast.InstalledRouteFound:
		return e.forwardValidatedMulticastPacket(pkt, result.InstalledRoute)
	case multicast.NoRouteFoundAndPendingInserted:
		e.emitMulticastEvent(func(disp stack.MulticastForwardingEventDispatcher) {
			disp.OnMissingRoute(stack.MulticastPacketContext{
				stack.UnicastSourceAndMulticastDestination{h.SourceAddress(), h.DestinationAddress()},
				e.nic.ID(),
			})
		})
	case multicast.PacketQueuedInPendingRoute:
	default:
		panic(fmt.Sprintf("unexpected GetRouteResultState: %s", result.GetRouteResultState))
	}
	return &ip.ErrHostUnreachable{}
}

func (e *endpoint) updateOptionsForForwarding(pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv4(pkt.NetworkHeader().Slice())
	if opts := h.Options(); len(opts) != 0 {
		newOpts, _, optProblem := e.processIPOptions(pkt, opts, &optionUsageForward{})
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer: optProblem.Pointer,
				}, pkt, false)
			}
			return &ip.ErrParameterProblem{}
		}
		copied := copy(opts, newOpts)
		if copied != len(newOpts) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOpts)))
		}
		for i := copied; i < len(opts); i++ {
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}
	return nil
}

func (e *endpoint) forwardValidatedMulticastPacket(pkt *stack.PacketBuffer, installedRoute *multicast.InstalledRoute) ip.ForwardingError {
	if e.nic.ID() != installedRoute.ExpectedInputInterface {
		h := header.IPv4(pkt.NetworkHeader().Slice())
		e.emitMulticastEvent(func(disp stack.MulticastForwardingEventDispatcher) {
			disp.OnUnexpectedInputInterface(stack.MulticastPacketContext{
				stack.UnicastSourceAndMulticastDestination{h.SourceAddress(), h.DestinationAddress()},
				e.nic.ID(),
			}, installedRoute.ExpectedInputInterface)
		})
		return &ip.ErrUnexpectedMulticastInputInterface{}
	}

	for _, outgoingInterface := range installedRoute.OutgoingInterfaces {
		if err := e.forwardMulticastPacketForOutgoingInterface(pkt, outgoingInterface); err != nil {
			e.handleForwardingError(err)
			continue
		}
		installedRoute.SetLastUsedTimestamp(e.protocol.stack.Clock().NowMonotonic())
	}
	return nil
}

func (e *endpoint) forwardMulticastPacketForOutgoingInterface(pkt *stack.PacketBuffer, outgoingInterface stack.MulticastRouteOutgoingInterface) ip.ForwardingError {
	h := header.IPv4(pkt.NetworkHeader().Slice())

	if outgoingInterface.MinTTL > h.TTL() {
		return &ip.ErrTTLExceeded{}
	}

	route := e.protocol.stack.NewRouteForMulticast(outgoingInterface.ID, h.DestinationAddress(), e.NetworkProtocolNumber())

	if route == nil {
		return &ip.ErrHostUnreachable{}
	}
	defer route.Release()

	return e.forwardPacketWithRoute(route, pkt, true)
}

func (e *endpoint) handleValidatedPacket(h header.IPv4, pkt *stack.PacketBuffer, inNICName string) {
	pkt.NICID = e.nic.ID()

	if !h.More() && h.FragmentOffset() == 0 {
		e.dispatcher.DeliverRawPacket(h.TransportProtocol(), pkt)
	}

	stats := e.stats
	stats.ip.ValidPacketsReceived.Increment()

	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	if srcAddr == header.IPv4Broadcast || header.IsV4MulticastAddress(srcAddr) {
		stats.ip.InvalidSourceAddressesReceived.Increment()
		return
	}
	if addressEndpoint := e.AcquireAssignedAddress(srcAddr, false, stack.NeverPrimaryEndpoint, true); addressEndpoint != nil {
		subnet := addressEndpoint.Subnet()
		if subnet.IsBroadcast(srcAddr) {
			stats.ip.InvalidSourceAddressesReceived.Increment()
			return
		}
	}

	if header.IsV4MulticastAddress(dstAddr) {

		multicastForwarding := e.MulticastForwarding() && e.protocol.multicastForwarding()

		if multicastForwarding {
			e.handleForwardingError(e.forwardMulticastPacket(h, pkt))
		}

		if e.IsInGroup(dstAddr) {
			e.deliverPacketLocally(h, pkt, inNICName)
			return
		}

		if !multicastForwarding {
			stats.ip.InvalidDestinationAddressesReceived.Increment()
		}
		return
	}

	if addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint, true); addressEndpoint != nil {
		pkt.NetworkPacketInfo.LocalAddressTemporary = addressEndpoint.Temporary()
		subnet := addressEndpoint.AddressWithPrefix().Subnet()
		pkt.NetworkPacketInfo.LocalAddressBroadcast = subnet.IsBroadcast(dstAddr) || dstAddr == header.IPv4Broadcast
		e.deliverPacketLocally(h, pkt, inNICName)
	} else if e.Forwarding() {
		e.handleForwardingError(e.forwardUnicastPacket(pkt))
	} else {
		stats.ip.InvalidDestinationAddressesReceived.Increment()
	}
}

func (e *endpoint) handleForwardingError(err ip.ForwardingError) {
	stats := e.stats.ip
	switch err := err.(type) {
	case nil:
		return
	case *ip.ErrInitializingSourceAddress:
		stats.Forwarding.InitializingSource.Increment()
	case *ip.ErrLinkLocalSourceAddress:
		stats.Forwarding.LinkLocalSource.Increment()
	case *ip.ErrLinkLocalDestinationAddress:
		stats.Forwarding.LinkLocalDestination.Increment()
	case *ip.ErrTTLExceeded:
		stats.Forwarding.ExhaustedTTL.Increment()
	case *ip.ErrHostUnreachable:
		stats.Forwarding.Unrouteable.Increment()
	case *ip.ErrParameterProblem:
		stats.MalformedPacketsReceived.Increment()
	case *ip.ErrMessageTooLong:
		stats.Forwarding.PacketTooBig.Increment()
	case *ip.ErrNoMulticastPendingQueueBufferSpace:
		stats.Forwarding.NoMulticastPendingQueueBufferSpace.Increment()
	case *ip.ErrUnexpectedMulticastInputInterface:
		stats.Forwarding.UnexpectedMulticastInputInterface.Increment()
	case *ip.ErrUnknownOutputEndpoint:
		stats.Forwarding.UnknownOutputEndpoint.Increment()
	case *ip.ErrOutgoingDeviceNoBufferSpace:
		stats.Forwarding.OutgoingDeviceNoBufferSpace.Increment()
	case *ip.ErrOther:
		switch err := err.Err.(type) {
		case *tcpip.ErrClosedForSend:
			stats.Forwarding.OutgoingDeviceClosedForSend.Increment()
		default:
			panic(fmt.Sprintf("unrecognized tcpip forwarding error: %s", err))
		}
	default:
		panic(fmt.Sprintf("unrecognized forwarding error: %s", err))
	}
	stats.Forwarding.Errors.Increment()
}

func (e *endpoint) deliverPacketLocally(h header.IPv4, pkt *stack.PacketBuffer, inNICName string) {
	stats := e.stats
	stk := e.protocol.stack
	if ok := stk.IPTables().CheckInput(pkt, inNICName); !ok {
		stats.ip.IPTablesInputDropped.Increment()
		return
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckInput(pkt, nil, stack.IP) {
			return
		}
	}

	if h.More() || h.FragmentOffset() != 0 {
		if pkt.Data().Size()+len(pkt.TransportHeader().Slice()) == 0 {
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}
		if opts := h.Options(); len(opts) != 0 {
			if _, _, optProblem := e.processIPOptions(pkt, opts, &optionUsageVerify{}); optProblem != nil {
				if optProblem.NeedICMP {
					_ = e.protocol.returnError(&icmpReasonParamProblem{
						pointer: optProblem.Pointer,
					}, pkt, true)
					e.stats.ip.MalformedPacketsReceived.Increment()
				}
				return
			}
		}
		start := h.FragmentOffset()
		if int(start)+pkt.Data().Size() > header.IPv4MaximumPayloadSize {
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}

		proto := h.Protocol()
		resPkt, transProtoNum, ready, err := e.protocol.fragmentation.Process(
			fragmentation.FragmentID{
				Source:      h.SourceAddress(),
				Destination: h.DestinationAddress(),
				ID:          uint32(h.ID()),
				Protocol:    proto,
			},
			start,
			start+uint16(pkt.Data().Size())-1,
			h.More(),
			proto,
			pkt,
		)
		if err != nil {
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}
		if !ready {
			return
		}
		defer resPkt.DecRef()
		pkt = resPkt
		h = header.IPv4(pkt.NetworkHeader().Slice())

		h.SetTotalLength(uint16(pkt.Data().Size() + len(h)))
		h.SetFlagsFragmentOffset(0, 0)

		e.protocol.parseTransport(pkt, tcpip.TransportProtocolNumber(transProtoNum))

		e.dispatcher.DeliverRawPacket(h.TransportProtocol(), pkt)
	}
	stats.ip.PacketsDelivered.Increment()

	p := h.TransportProtocol()
	if p == header.ICMPv4ProtocolNumber {
		pkt.TransportProtocolNumber = p
		e.handleICMP(pkt)
		return
	}
	var hasRouterAlertOption bool
	if opts := h.Options(); len(opts) != 0 {
		newOpts, processedOpts, optProblem := e.processIPOptions(pkt, opts, &optionUsageReceive{})
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer: optProblem.Pointer,
				}, pkt, true)
				stats.ip.MalformedPacketsReceived.Increment()
			}
			return
		}
		hasRouterAlertOption = processedOpts.routerAlert
		copied := copy(opts, newOpts)
		if copied != len(newOpts) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOpts)))
		}
		for i := copied; i < len(opts); i++ {
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}
	if p == header.IGMPProtocolNumber {
		e.mu.Lock()
		e.igmp.handleIGMP(pkt, hasRouterAlertOption)
		e.mu.Unlock()
		return
	}

	switch res := e.dispatcher.DeliverTransportPacket(p, pkt); res {
	case stack.TransportPacketHandled:
	case stack.TransportPacketDestinationPortUnreachable:
		_ = e.protocol.returnError(&icmpReasonPortUnreachable{}, pkt, true)
	case stack.TransportPacketProtocolUnreachable:
		_ = e.protocol.returnError(&icmpReasonProtoUnreachable{}, pkt, true)
	default:
		panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
	}
}

func (e *endpoint) Close() {
	e.mu.Lock()
	e.disableLocked()
	e.addressableEndpointState.Cleanup()
	e.mu.Unlock()

	e.protocol.forgetEndpoint(e.nic.ID())
}

func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ep, err := e.addressableEndpointState.AddAndAcquireAddress(addr, properties, stack.Permanent)
	if err == nil {
		e.sendQueuedReports()
	}
	return ep, err
}

func (e *endpoint) sendQueuedReports() {
	e.igmp.sendQueuedReports()
}

func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.RemovePermanentAddress(addr)
}

func (e *endpoint) SetDeprecated(addr tcpip.Address, deprecated bool) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.SetDeprecated(addr, deprecated)
}

func (e *endpoint) SetLifetimes(addr tcpip.Address, lifetimes stack.AddressLifetimes) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.SetLifetimes(addr, lifetimes)
}

func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.MainAddress()
}

func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior, readOnly bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()

	loopback := e.nic.IsLoopback()
	return e.addressableEndpointState.AcquireAssignedAddressOrMatching(localAddr, func(addressEndpoint stack.AddressEndpoint) bool {
		subnet := addressEndpoint.Subnet()
		return subnet.IsBroadcast(localAddr) || (loopback && subnet.Contains(localAddr))
	}, allowTemp, tempPEB, readOnly)
}

func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint, allowExpired)
}

func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	return e.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, srcHint, allowExpired)
}

func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.PrimaryAddresses()
}

func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addressableEndpointState.PermanentAddresses()
}

func (e *endpoint) JoinGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.joinGroupLocked(addr)
}

func (e *endpoint) joinGroupLocked(addr tcpip.Address) tcpip.Error {
	if !header.IsV4MulticastAddress(addr) {
		return &tcpip.ErrBadAddress{}
	}

	e.igmp.joinGroup(addr)
	return nil
}

func (e *endpoint) LeaveGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leaveGroupLocked(addr)
}

func (e *endpoint) leaveGroupLocked(addr tcpip.Address) tcpip.Error {
	return e.igmp.leaveGroup(addr)
}

func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.igmp.isInGroup(addr)
}

func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.NetworkProtocol = (*protocol)(nil)
var _ stack.MulticastForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.RejectIPv4WithHandler = (*protocol)(nil)
var _ fragmentation.TimeoutHandler = (*protocol)(nil)

type protocol struct {
	stack *stack.Stack

	mu sync.RWMutex `state:"nosave"`

	eps map[tcpip.NICID]*endpoint

	icmpRateLimitedTypes map[header.ICMPv4Type]struct{}

	defaultTTL atomicbitops.Uint32

	ids    []atomicbitops.Uint32
	hashIV uint32
	idTS atomicbitops.Int64

	fragmentation *fragmentation.Fragmentation

	options Options

	multicastRouteTable multicast.RouteTable
	multicastForwardingDisp stack.MulticastForwardingEventDispatcher
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

func (*protocol) ParseAddresses(v []byte) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (p *protocol) SetDefaultTTL(ttl uint8) {
	p.defaultTTL.Store(uint32(ttl))
}

func (p *protocol) DefaultTTL() uint8 {
	return uint8(p.defaultTTL.Load())
}

func (p *protocol) Close() {
	p.fragmentation.Release()
	p.multicastRouteTable.Close()
}

func (*protocol) Wait() {}

func (p *protocol) validateUnicastSourceAndMulticastDestination(addresses stack.UnicastSourceAndMulticastDestination) tcpip.Error {
	if !p.isUnicastAddress(addresses.Source) {
		return &tcpip.ErrBadAddress{}
	}

	if !header.IsV4MulticastAddress(addresses.Destination) {
		return &tcpip.ErrBadAddress{}
	}

	return nil
}

func (p *protocol) multicastForwarding() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.multicastForwardingDisp != nil
}

func (p *protocol) newInstalledRoute(route stack.MulticastRoute) (*multicast.InstalledRoute, tcpip.Error) {
	if len(route.OutgoingInterfaces) == 0 {
		return nil, &tcpip.ErrMissingRequiredFields{}
	}

	if !p.stack.HasNIC(route.ExpectedInputInterface) {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	for _, outgoingInterface := range route.OutgoingInterfaces {
		if route.ExpectedInputInterface == outgoingInterface.ID {
			return nil, &tcpip.ErrMulticastInputCannotBeOutput{}
		}

		if !p.stack.HasNIC(outgoingInterface.ID) {
			return nil, &tcpip.ErrUnknownNICID{}
		}
	}
	return p.multicastRouteTable.NewInstalledRoute(route), nil
}

func (p *protocol) AddMulticastRoute(addresses stack.UnicastSourceAndMulticastDestination, route stack.MulticastRoute) tcpip.Error {
	if !p.multicastForwarding() {
		return &tcpip.ErrNotPermitted{}
	}

	if err := p.validateUnicastSourceAndMulticastDestination(addresses); err != nil {
		return err
	}

	installedRoute, err := p.newInstalledRoute(route)
	if err != nil {
		return err
	}

	pendingPackets := p.multicastRouteTable.AddInstalledRoute(addresses, installedRoute)

	for _, pkt := range pendingPackets {
		p.forwardPendingMulticastPacket(pkt, installedRoute)
	}
	return nil
}

func (p *protocol) RemoveMulticastRoute(addresses stack.UnicastSourceAndMulticastDestination) tcpip.Error {
	if err := p.validateUnicastSourceAndMulticastDestination(addresses); err != nil {
		return err
	}

	if removed := p.multicastRouteTable.RemoveInstalledRoute(addresses); !removed {
		return &tcpip.ErrHostUnreachable{}
	}

	return nil
}

func (p *protocol) EnableMulticastForwarding(disp stack.MulticastForwardingEventDispatcher) (bool, tcpip.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.multicastForwardingDisp != nil {
		return true, nil
	}

	if disp == nil {
		return false, &tcpip.ErrInvalidOptionValue{}
	}

	p.multicastForwardingDisp = disp
	return false, nil
}

func (p *protocol) DisableMulticastForwarding() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.multicastForwardingDisp = nil
	p.multicastRouteTable.RemoveAllInstalledRoutes()
}

func (p *protocol) MulticastRouteLastUsedTime(addresses stack.UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, tcpip.Error) {
	if err := p.validateUnicastSourceAndMulticastDestination(addresses); err != nil {
		return tcpip.MonotonicTime{}, err
	}

	timestamp, found := p.multicastRouteTable.GetLastUsedTimestamp(addresses)

	if !found {
		return tcpip.MonotonicTime{}, &tcpip.ErrHostUnreachable{}
	}

	return timestamp, nil
}

func (p *protocol) forwardPendingMulticastPacket(pkt *stack.PacketBuffer, installedRoute *multicast.InstalledRoute) {
	defer pkt.DecRef()

	ep, ok := p.getEndpointForNIC(pkt.NICID)

	if !ok {
		return
	}

	if !ep.MulticastForwarding() {
		return
	}

	ep.handleForwardingError(ep.forwardValidatedMulticastPacket(pkt, installedRoute))
}

func (p *protocol) isUnicastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != header.IPv4AddressSizeBits {
		return false
	}

	if addr == header.IPv4Any || addr == header.IPv4Broadcast {
		return false
	}

	if p.isSubnetLocalBroadcastAddress(addr) {
		return false
	}
	return !header.IsV4MulticastAddress(addr)
}

func (p *protocol) isSubnetLocalBroadcastAddress(addr tcpip.Address) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint, true); addressEndpoint != nil {
			subnet := addressEndpoint.Subnet()
			if subnet.IsBroadcast(addr) {
				return true
			}
		}
	}
	return false
}

func (p *protocol) parseAndValidate(pkt *stack.PacketBuffer) (*buffer.View, bool) {
	transProtoNum, hasTransportHdr, ok := p.Parse(pkt)
	if !ok {
		return nil, false
	}

	h := header.IPv4(pkt.NetworkHeader().Slice())
	if !h.IsValid(pkt.Size() - len(pkt.LinkHeader().Slice())) {
		return nil, false
	}

	if !pkt.RXChecksumValidated && !h.IsChecksumValid() {
		return nil, false
	}

	if hasTransportHdr {
		p.parseTransport(pkt, transProtoNum)
	}

	return pkt.NetworkHeader().View(), true
}

func (p *protocol) parseTransport(pkt *stack.PacketBuffer, transProtoNum tcpip.TransportProtocolNumber) {
	if transProtoNum == header.ICMPv4ProtocolNumber {
		_ = parse.ICMPv4(pkt)
		return
	}

	switch err := p.stack.ParsePacketBufferTransport(transProtoNum, pkt); err {
	case stack.ParsedOK:
	case stack.UnknownTransportProtocol, stack.TransportLayerParseError:
	default:
		panic(fmt.Sprintf("unexpected error parsing transport header = %d", err))
	}
}

func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	if ok := parse.IPv4(pkt); !ok {
		return 0, false, false
	}

	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	return ipHdr.TransportProtocol(), !ipHdr.More() && ipHdr.FragmentOffset() == 0, true
}

func (p *protocol) allowICMPReply(icmpType header.ICMPv4Type, code header.ICMPv4Code) bool {
	if icmpType == header.ICMPv4DstUnreachable && code == header.ICMPv4FragmentationNeeded {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.icmpRateLimitedTypes[icmpType]; ok {
		return p.stack.AllowICMPMessage()
	}
	return true
}

func (p *protocol) SendRejectionError(pkt *stack.PacketBuffer, rejectWith stack.RejectIPv4WithICMPType, inputHook bool) tcpip.Error {
	switch rejectWith {
	case stack.RejectIPv4WithICMPNetUnreachable:
		return p.returnError(&icmpReasonNetworkUnreachable{}, pkt, inputHook)
	case stack.RejectIPv4WithICMPHostUnreachable:
		return p.returnError(&icmpReasonHostUnreachable{}, pkt, inputHook)
	case stack.RejectIPv4WithICMPPortUnreachable:
		return p.returnError(&icmpReasonPortUnreachable{}, pkt, inputHook)
	case stack.RejectIPv4WithICMPNetProhibited:
		return p.returnError(&icmpReasonNetworkProhibited{}, pkt, inputHook)
	case stack.RejectIPv4WithICMPHostProhibited:
		return p.returnError(&icmpReasonHostProhibited{}, pkt, inputHook)
	case stack.RejectIPv4WithICMPAdminProhibited:
		return p.returnError(&icmpReasonAdministrativelyProhibited{}, pkt, inputHook)
	case stack.RejectIPv4WithTCPReset:
		return ip.RejectWithTCPReset(pkt, ProtocolNumber, p.stack, inputHook)
	default:
		panic(fmt.Sprintf("unhandled %[1]T = %[1]d", rejectWith))
	}
}

func calculateNetworkMTU(linkMTU, networkHeaderSize uint32) (uint32, tcpip.Error) {
	if linkMTU < header.IPv4MinimumMTU {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	if networkHeaderSize > header.IPv4MaximumHeaderSize {
		return 0, &tcpip.ErrMalformedHeader{}
	}

	networkMTU := linkMTU
	if networkMTU > MaxTotalSize {
		networkMTU = MaxTotalSize
	}

	return networkMTU - networkHeaderSize, nil
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32) bool {
	payload := len(pkt.TransportHeader().Slice()) + pkt.Data().Size()
	return pkt.GSOOptions.Type == stack.GSONone && uint32(payload) > networkMTU
}

func addressToUint32(addr tcpip.Address) uint32 {
	addrBytes := addr.As4()
	_ = addrBytes[3]
	return uint32(addrBytes[0]) | uint32(addrBytes[1])<<8 | uint32(addrBytes[2])<<16 | uint32(addrBytes[3])<<24
}

func hashRoute(srcAddr, dstAddr tcpip.Address, protocol tcpip.TransportProtocolNumber, hashIV uint32) uint32 {
	a := addressToUint32(srcAddr)
	b := addressToUint32(dstAddr)
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

type Options struct {
	IGMP IGMPOptions

	AllowExternalLoopbackTraffic bool
}

func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	ids := make([]atomicbitops.Uint32, buckets)

	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = atomicbitops.FromUint32(r[i])
	}
	hashIV := r[buckets]

	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:      s,
			ids:        ids,
			hashIV:     hashIV,
			defaultTTL: atomicbitops.FromUint32(DefaultTTL),
			options:    opts,
		}
		p.fragmentation = fragmentation.NewFragmentation(fragmentblockSize, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock(), p)
		p.eps = make(map[tcpip.NICID]*endpoint)
		p.icmpRateLimitedTypes = map[header.ICMPv4Type]struct{}{
			header.ICMPv4DstUnreachable: {},
			header.ICMPv4SrcQuench:      {},
			header.ICMPv4TimeExceeded:   {},
			header.ICMPv4ParamProblem:   {},
		}
		if err := p.multicastRouteTable.Init(multicast.DefaultConfig(s.Clock())); err != nil {
			panic(fmt.Sprintf("p.multicastRouteTable.Init(_): %s", err))
		}
		return p
	}
}

func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeader header.IPv4) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeaderLength := len(originalIPHeader)
	nextFragIPHeader := header.IPv4(fragPkt.NetworkHeader().Push(originalIPHeaderLength))
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	if copied := copy(nextFragIPHeader, originalIPHeader); copied != len(originalIPHeader) {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got = %d, want = %d", copied, originalIPHeaderLength))
	}

	flags := originalIPHeader.Flags()
	if more {
		flags |= header.IPv4FlagMoreFragments
	}
	nextFragIPHeader.SetFlagsFragmentOffset(flags, uint16(offset))
	nextFragIPHeader.SetTotalLength(uint16(nextFragIPHeader.HeaderLength()) + uint16(copied))
	nextFragIPHeader.SetChecksum(0)
	nextFragIPHeader.SetChecksum(^nextFragIPHeader.CalculateChecksum())

	return fragPkt, more
}

type optionAction uint8

const (
	optionRemove optionAction = iota

	optionProcess

	optionVerify

	optionPass
)

type optionActions struct {
	timestamp optionAction

	recordRoute optionAction

	routerAlert optionAction

	unknown optionAction
}

type optionsUsage interface {
	actions() optionActions
}

type optionUsageVerify struct{}

func (*optionUsageVerify) actions() optionActions {
	return optionActions{
		timestamp:   optionVerify,
		recordRoute: optionVerify,
		routerAlert: optionVerify,
		unknown:     optionRemove,
	}
}

type optionUsageReceive struct{}

func (*optionUsageReceive) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionPass,
	}
}

type optionUsageForward struct{}

func (*optionUsageForward) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionPass,
	}
}

type optionUsageEcho struct{}

func (*optionUsageEcho) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionRemove,
	}
}

func handleTimestamp(tsOpt header.IPv4OptionTimestamp, localAddress tcpip.Address, clock tcpip.Clock, usage optionsUsage) *header.IPv4OptParameterProblem {
	flags := tsOpt.Flags()
	var entrySize uint8
	switch flags {
	case header.IPv4OptionTimestampOnlyFlag:
		entrySize = header.IPv4OptionTimestampSize
	case
		header.IPv4OptionTimestampWithIPFlag,
		header.IPv4OptionTimestampWithPredefinedIPFlag:
		entrySize = header.IPv4OptionTimestampWithAddrSize
	default:
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSOFLWAndFLGOffset,
			NeedICMP: true,
		}
	}

	pointer := tsOpt.Pointer()
	if pointer <= header.IPv4OptionTimestampHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSPointerOffset,
			NeedICMP: true,
		}
	}
	nextSlot := pointer - (header.IPv4OptionTimestampHdrLength + 1)
	optLen := tsOpt.Size()
	dataLength := optLen - header.IPv4OptionTimestampHdrLength

	if pointer > optLen {
		if flags == header.IPv4OptionTimestampWithPredefinedIPFlag {
			return nil
		}

		if tsOpt.IncOverflow() != 0 {
			return nil
		}
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSOFLWAndFLGOffset,
			NeedICMP: true,
		}
	}
	if nextSlot+entrySize > dataLength {
		if false {
			if dataLength%entrySize != 0 {
				return &header.IPv4OptParameterProblem{
					Pointer:  header.IPv4OptionLengthOffset,
					NeedICMP: false,
				}
			}
		}
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSPointerOffset,
			NeedICMP: true,
		}
	}

	if usage.actions().timestamp == optionProcess {
		tsOpt.UpdateTimestamp(localAddress, clock)
	}
	return nil
}

func handleRecordRoute(rrOpt header.IPv4OptionRecordRoute, localAddress tcpip.Address, usage optionsUsage) *header.IPv4OptParameterProblem {
	optlen := rrOpt.Size()

	if optlen < header.IPv4AddressSize+header.IPv4OptionRecordRouteHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptionLengthOffset,
			NeedICMP: true,
		}
	}

	pointer := rrOpt.Pointer()
	if pointer <= header.IPv4OptionRecordRouteHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptRRPointerOffset,
			NeedICMP: true,
		}
	}

	if pointer > optlen {
		return nil
	}

	if pointer+header.IPv4AddressSize > optlen+1 {
		if false {
			if (optlen-header.IPv4OptionRecordRouteHdrLength)%header.IPv4AddressSize != 0 {
				return &header.IPv4OptParameterProblem{
					Pointer:  header.IPv4OptionLengthOffset,
					NeedICMP: true,
				}
			}
		}
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptRRPointerOffset,
			NeedICMP: true,
		}
	}
	if usage.actions().recordRoute == optionVerify {
		return nil
	}
	rrOpt.StoreAddress(localAddress)
	return nil
}

func handleRouterAlert(raOpt header.IPv4OptionRouterAlert) *header.IPv4OptParameterProblem {
	if raOpt.Value() != header.IPv4OptionRouterAlertValue {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptionRouterAlertValueOffset,
			NeedICMP: true,
		}
	}
	return nil
}

type optionTracker struct {
	timestamp   bool
	recordRoute bool
	routerAlert bool
}

func (e *endpoint) processIPOptions(pkt *stack.PacketBuffer, opts header.IPv4Options, usage optionsUsage) (header.IPv4Options, optionTracker, *header.IPv4OptParameterProblem) {
	stats := e.stats.ip
	optIter := opts.MakeIterator()

	var seenOptions [math.MaxUint8 + 1]bool

	localAddress := e.MainAddress().Address
	if localAddress.BitLen() == 0 {
		h := header.IPv4(pkt.NetworkHeader().Slice())
		dstAddr := h.DestinationAddress()
		if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(dstAddr) {
			return nil, optionTracker{}, &header.IPv4OptParameterProblem{
				NeedICMP: false,
			}
		}
		localAddress = dstAddr
	}

	var optionsProcessed optionTracker
	for {
		option, done, optProblem := optIter.Next()
		if done || optProblem != nil {
			return optIter.Finalize(), optionsProcessed, optProblem
		}
		optType := option.Type()
		if optType == header.IPv4OptionNOPType {
			optIter.PushNOPOrEnd(optType)
			continue
		}
		if optType == header.IPv4OptionListEndType {
			optIter.PushNOPOrEnd(optType)
			return optIter.Finalize(), optionsProcessed, nil
		}

		if seenOptions[optType] {
			return nil, optionTracker{}, &header.IPv4OptParameterProblem{
				Pointer:  optIter.ErrCursor,
				NeedICMP: true,
			}
		}
		seenOptions[optType] = true

		optLen, optProblem := func() (int, *header.IPv4OptParameterProblem) {
			switch option := option.(type) {
			case *header.IPv4OptionTimestamp:
				stats.OptionTimestampReceived.Increment()
				optionsProcessed.timestamp = true
				if usage.actions().timestamp != optionRemove {
					clock := e.protocol.stack.Clock()
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleTimestamp(header.IPv4OptionTimestamp(newBuffer), localAddress, clock, usage)
					return len(newBuffer), optProblem
				}

			case *header.IPv4OptionRecordRoute:
				stats.OptionRecordRouteReceived.Increment()
				optionsProcessed.recordRoute = true
				if usage.actions().recordRoute != optionRemove {
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleRecordRoute(header.IPv4OptionRecordRoute(newBuffer), localAddress, usage)
					return len(newBuffer), optProblem
				}

			case *header.IPv4OptionRouterAlert:
				stats.OptionRouterAlertReceived.Increment()
				optionsProcessed.routerAlert = true
				if usage.actions().routerAlert != optionRemove {
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleRouterAlert(header.IPv4OptionRouterAlert(newBuffer))
					return len(newBuffer), optProblem
				}

			default:
				stats.OptionUnknownReceived.Increment()
				if usage.actions().unknown == optionPass {
					return len(optIter.InitReplacement(option)), nil
				}
			}
			return 0, nil
		}()

		if optProblem != nil {
			optProblem.Pointer += optIter.ErrCursor
			return nil, optionTracker{}, optProblem
		}
		optIter.ConsumeBuffer(optLen)
	}
}

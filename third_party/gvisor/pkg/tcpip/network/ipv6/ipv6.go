// Copyright 2020 The gVisor Authors.
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

package ipv6

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/fragmentation"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/multicast"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	ReassembleTimeout = 60 * time.Second

	ProtocolNumber = header.IPv6ProtocolNumber

	maxPayloadSize = 0xffff

	DefaultTTL = 64

	buckets = 2048
)

const (
	forwardingDisabled = 0
	forwardingEnabled  = 1
)

var policyTable = [...]struct {
	subnet tcpip.Subnet

	label uint8
}{
	{
		subnet: header.IPv6Loopback.WithPrefix().Subnet(),
		label:  0,
	},
	{
		subnet: header.IPv4MappedIPv6Subnet,
		label:  4,
	},
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 32,
		}.Subnet(),
		label: 5,
	},
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 16,
		}.Subnet(),
		label: 2,
	},
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 7,
		}.Subnet(),
		label: 13,
	},
	{
		subnet: header.IPv6EmptySubnet,
		label:  1,
	},
}

func getLabel(addr tcpip.Address) uint8 {
	for _, p := range policyTable {
		if p.subnet.Contains(addr) {
			return p.label
		}
	}

	panic(fmt.Sprintf("should have a label for address = %s", addr))
}

var _ stack.DuplicateAddressDetector = (*endpoint)(nil)
var _ stack.LinkAddressResolver = (*endpoint)(nil)
var _ stack.LinkResolvableNetworkEndpoint = (*endpoint)(nil)
var _ stack.ForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.MulticastForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)
var _ stack.NDPEndpoint = (*endpoint)(nil)
var _ MLDEndpoint = (*endpoint)(nil)
var _ NDPEndpoint = (*endpoint)(nil)

type endpointMu struct {
	sync.RWMutex `state:"nosave"`

	addressableEndpointState stack.AddressableEndpointState
	ndp                      ndpState
	mld                      mldState
}

type dadMu struct {
	sync.Mutex `state:"nosave"`

	dad ip.DAD
}

type endpointDAD struct {
	mu dadMu
}

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol
	stats      sharedStats

	enabled atomicbitops.Uint32

	forwarding atomicbitops.Uint32

	multicastForwarding atomicbitops.Uint32

	mu endpointMu

	dad endpointDAD
}

type NICNameFromID func(tcpip.NICID, string) string

type OpaqueInterfaceIdentifierOptions struct {
	NICNameFromID NICNameFromID `state:"nosave"`

	SecretKey []byte
}

func (e *endpoint) CheckDuplicateAddress(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	e.dad.mu.Lock()
	defer e.dad.mu.Unlock()
	return e.dad.mu.dad.CheckDuplicateAddressLocked(addr, h)
}

func (e *endpoint) SetDADConfigurations(c stack.DADConfigurations) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dad.mu.Lock()
	defer e.dad.mu.Unlock()

	e.mu.ndp.dad.SetConfigsLocked(c)
	e.dad.mu.dad.SetConfigsLocked(c)
}

func (*endpoint) DuplicateAddressProtocol() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
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
	e.handleControl(&icmpv6DestinationAddressUnreachableSockError{}, pkt)
}

func (e *endpoint) onAddressAssignedLocked(addr tcpip.Address) {
	if header.IsV6LinkLocalUnicastAddress(addr) {
		e.mu.mld.sendQueuedReports()
	}
}

func (e *endpoint) InvalidateDefaultRouter(rtr tcpip.Address) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.mu.ndp.invalidateOffLinkRoute(offLinkRoute{dest: header.IPv6EmptySubnet, router: rtr})
}

func (e *endpoint) SetMLDVersion(v MLDVersion) MLDVersion {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.mld.setVersion(v)
}

func (e *endpoint) GetMLDVersion() MLDVersion {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.mld.getVersion()
}

func (e *endpoint) SetNDPConfigurations(c NDPConfigurations) {
	c.validate()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mu.ndp.configs = c
}

func (e *endpoint) NDPConfigurations() NDPConfigurations {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ndp.configs
}

func (e *endpoint) hasTentativeAddr(addr tcpip.Address) bool {
	e.mu.RLock()
	addressEndpoint := e.getAddressRLocked(addr)
	e.mu.RUnlock()
	return addressEndpoint != nil && addressEndpoint.GetKind() == stack.PermanentTentative
}

func (e *endpoint) dupTentativeAddrDetected(addr tcpip.Address, holderLinkAddr tcpip.LinkAddress, nonce []byte) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return &tcpip.ErrBadAddress{}
	}

	if addressEndpoint.GetKind() != stack.PermanentTentative {
		return &tcpip.ErrInvalidEndpointState{}
	}

	switch result := e.mu.ndp.dad.ExtendIfNonceEqualLocked(addr, nonce); result {
	case ip.Extended:
		return nil
	case ip.AlreadyExtended:
		return nil
	case ip.NoDADStateFound:
		panic(fmt.Sprintf("expected DAD state for tentative address %s", addr))
	case ip.NonceDisabled:
		fallthrough
	case ip.NonceNotEqual:
		if err := e.removePermanentEndpointLocked(addressEndpoint, false, stack.AddressRemovalDADFailed, &stack.DADDupAddrDetected{HolderLinkAddress: holderLinkAddr}); err != nil {
			return err
		}

		prefix := addressEndpoint.Subnet()

		switch t := addressEndpoint.ConfigType(); t {
		case stack.AddressConfigStatic:
		case stack.AddressConfigSlaac:
			if addressEndpoint.Temporary() {
				e.mu.ndp.regenerateTempSLAACAddr(prefix, false)
			} else {
				e.mu.ndp.regenerateSLAACAddr(prefix)
			}
		default:
			panic(fmt.Sprintf("unrecognized address config type = %d", t))
		}

		return nil
	default:
		panic(fmt.Sprintf("unhandled result = %d", result))
	}
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

	allRoutersGroups := [...]tcpip.Address{
		header.IPv6AllRoutersInterfaceLocalMulticastAddress,
		header.IPv6AllRoutersLinkLocalMulticastAddress,
		header.IPv6AllRoutersSiteLocalMulticastAddress,
	}

	if forwarding {
		for _, g := range allRoutersGroups {
			if err := e.joinGroupLocked(g); err != nil {
				panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", g, err))
			}
		}
	} else {
		for _, g := range allRoutersGroups {
			switch err := e.leaveGroupLocked(g).(type) {
			case nil:
			case *tcpip.ErrBadLocalAddress:
			default:
				panic(fmt.Sprintf("e.leaveGroupLocked(%s): %s", g, err))
			}
		}
	}

	e.mu.ndp.forwardingChanged(forwarding)
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

	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}

	if !e.setEnabled(true) {
		return nil
	}

	var err tcpip.Error
	e.mu.addressableEndpointState.ForEachEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		addr := addressEndpoint.AddressWithPrefix().Address
		if !header.IsV6UnicastAddress(addr) {
			return true
		}

		switch kind := addressEndpoint.GetKind(); kind {
		case stack.Permanent:
			addressEndpoint.SetKind(stack.PermanentTentative)
			fallthrough
		case stack.PermanentTentative:
			err = e.mu.ndp.startDuplicateAddressDetection(addr, addressEndpoint)
			return err == nil
		case stack.Temporary, stack.PermanentExpired:
			return true
		default:
			panic(fmt.Sprintf("address %s has unknown kind %d", addressEndpoint.AddressWithPrefix(), kind))
		}
	})
	e.mu.addressableEndpointState.OnNetworkEndpointEnabledChanged()
	if err != nil {
		return err
	}

	e.mu.mld.initializeAll()


	if err := e.joinGroupLocked(header.IPv6AllNodesMulticastAddress); err != nil {
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", header.IPv6AllNodesMulticastAddress, err))
	}

	if e.protocol.options.AutoGenLinkLocal && !e.nic.IsLoopback() {
		e.mu.ndp.doSLAAC(header.IPv6LinkLocalPrefix.Subnet(), header.NDPInfiniteLifetime, header.NDPInfiniteLifetime)
	}

	e.mu.ndp.startSolicitingRouters()
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

	e.mu.ndp.stopSolicitingRouters()
	e.mu.ndp.cleanupState()

	switch err := e.leaveGroupLocked(header.IPv6AllNodesMulticastAddress).(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv6AllNodesMulticastAddress, err))
	}

	e.mu.mld.softLeaveAll()

	e.mu.addressableEndpointState.ForEachEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		addrWithPrefix := addressEndpoint.AddressWithPrefix()
		switch kind := addressEndpoint.GetKind(); kind {
		case stack.Permanent, stack.PermanentTentative:
			if header.IsV6UnicastAddress(addrWithPrefix.Address) {
				e.mu.ndp.stopDuplicateAddressDetection(addrWithPrefix.Address, &stack.DADAborted{})
			}
		case stack.Temporary, stack.PermanentExpired:
		default:
			panic(fmt.Sprintf("address %s has unknown address kind %d", addrWithPrefix, kind))
		}
		return true
	})

	if !e.setEnabled(false) {
		panic("should have only done work to disable the endpoint if it was enabled")
	}

	e.mu.addressableEndpointState.OnNetworkEndpointEnabledChanged()
}

func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

func (e *endpoint) MTU() uint32 {
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv6MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

func (e *endpoint) EndpointHeaderSize() uint32 {
	return header.IPv6MinimumSize
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv6MinimumSize
}

func addIPHeader(srcAddr, dstAddr tcpip.Address, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams, extensionHeaders header.IPv6ExtHdrSerializer) tcpip.Error {
	if params.ExperimentOptionValue != 0 {
		extensionHeaders = append(extensionHeaders, &header.IPv6ExperimentExtHdr{Value: params.ExperimentOptionValue})
	}
	extHdrsLen := extensionHeaders.Length()
	length := pkt.Size() + extensionHeaders.Length()
	if length > math.MaxUint16 {
		return &tcpip.ErrMessageTooLong{}
	}
	header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize + extHdrsLen)).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(length),
		TransportProtocol: params.Protocol,
		HopLimit:          params.TTL,
		TrafficClass:      params.TOS,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
		ExtensionHeaders:  extensionHeaders,
	})
	pkt.NetworkProtocolNumber = ProtocolNumber
	return nil
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32) bool {
	payload := len(pkt.TransportHeader().Slice()) + pkt.Data().Size()
	return pkt.GSOOptions.Type == stack.GSONone && uint32(payload) > networkMTU
}

func (e *endpoint) handleFragments(r *stack.Route, networkMTU uint32, pkt *stack.PacketBuffer, transProto tcpip.TransportProtocolNumber, handler func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	networkHeader := header.IPv6(pkt.NetworkHeader().Slice())

	fragmentPayloadLen := (networkMTU - header.IPv6FragmentHeaderSize) &^ 7
	if fragmentPayloadLen < header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit {
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	if fragmentPayloadLen < uint32(len(pkt.TransportHeader().Slice())) {
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadLen, calculateFragmentReserve(pkt))
	defer pf.Release()
	id := e.getFragmentID()

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader, transProto, id)
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

func (e *endpoint) WritePacket(r *stack.Route, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) tcpip.Error {
	dstAddr := r.RemoteAddress()
	if err := addIPHeader(r.LocalAddress(), dstAddr, pkt, params, nil); err != nil {
		return err
	}

	stk := e.protocol.stack
	outNicName := stk.FindNICNameFromID(e.nic.ID())
	if ok := stk.IPTables().CheckOutput(pkt, r, outNicName); !ok {
		e.stats.ip.IPTablesOutputDropped.Increment()
		return nil
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckOutput(pkt, r, stack.IP6) {
			return nil
		}
	}

	if netHeader := header.IPv6(pkt.NetworkHeader().Slice()); dstAddr != netHeader.DestinationAddress() {
		if ep := e.protocol.findEndpointWithAddress(netHeader.DestinationAddress()); ep != nil {
			ep.handleLocalPacket(pkt, true)
			return nil
		}
	}

	return e.writePacket(r, pkt, params.Protocol, false)
}

func (e *endpoint) writePacket(r *stack.Route, pkt *stack.PacketBuffer, protocol tcpip.TransportProtocolNumber, headerIncluded bool) tcpip.Error {
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
		if !nft.CheckPostrouting(pkt, r, stack.IP6) {
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
		if pkt.NetworkPacketInfo.IsForwardedPacket {
			return &tcpip.ErrMessageTooLong{}
		}
		sent, remain, err := e.handleFragments(r, networkMTU, pkt, protocol, func(fragPkt *stack.PacketBuffer) tcpip.Error {
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
	h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}
	ipH := header.IPv6(h)

	pktSize := pkt.Data().Size()
	ipH.SetPayloadLength(uint16(pktSize - header.IPv6MinimumSize))

	if ipH.SourceAddress() == header.IPv6Any {
		ipH.SetSourceAddress(r.LocalAddress())
	}

	proto, _, _, _, ok := parse.IPv6(pkt)
	if !ok || !header.IPv6(pkt.NetworkHeader().Slice()).IsValid(pktSize) {
		return &tcpip.ErrMalformedHeader{}
	}

	return e.writePacket(r, pkt, proto, true)
}

func validateAddressesForForwarding(h header.IPv6) ip.ForwardingError {
	srcAddr := h.SourceAddress()

	if srcAddr.Unspecified() {
		return &ip.ErrInitializingSourceAddress{}
	}

	if header.IsV6LinkLocalUnicastAddress(srcAddr) {
		return &ip.ErrLinkLocalSourceAddress{}
	}

	if dstAddr := h.DestinationAddress(); header.IsV6LinkLocalUnicastAddress(dstAddr) || header.IsV6LinkLocalMulticastAddress(dstAddr) {
		return &ip.ErrLinkLocalDestinationAddress{}
	}
	return nil
}

func (e *endpoint) forwardUnicastPacket(pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv6(pkt.NetworkHeader().Slice())

	if err := validateAddressesForForwarding(h); err != nil {
		return err
	}

	hopLimit := h.HopLimit()
	if hopLimit <= 1 {
		_ = e.protocol.returnError(&icmpReasonHopLimitExceeded{}, pkt, false)
		return &ip.ErrTTLExceeded{}
	}

	stk := e.protocol.stack

	dstAddr := h.DestinationAddress()

	if ep := e.protocol.findEndpointWithAddress(dstAddr); ep != nil {
		inNicName := stk.FindNICNameFromID(e.nic.ID())
		outNicName := stk.FindNICNameFromID(ep.nic.ID())
		if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
			e.stats.ip.IPTablesForwardDropped.Increment()
			return nil
		}

		if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {

			if !nft.CheckForward(pkt, nil, stack.IP6) {
				return nil
			}
		}

		ep.handleValidatedPacket(h, pkt, e.nic.Name())
		return nil
	}

	if err := e.processExtensionHeaders(h, pkt, true); err != nil {
		return &ip.ErrParameterProblem{}
	}

	r, err := stk.FindRoute(0, tcpip.Address{}, dstAddr, ProtocolNumber, false)
	switch err.(type) {
	case nil:
	case *tcpip.ErrNetworkUnreachable:
		_ = e.protocol.returnError(&icmpReasonNetUnreachable{}, pkt, false)
		return &ip.ErrHostUnreachable{}
	default:
		return &ip.ErrOther{Err: err}
	}
	defer r.Release()

	return e.forwardPacketWithRoute(r, pkt)
}

func (e *endpoint) forwardPacketWithRoute(route *stack.Route, pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv6(pkt.NetworkHeader().Slice())
	stk := e.protocol.stack

	inNicName := stk.FindNICNameFromID(e.nic.ID())
	outNicName := stk.FindNICNameFromID(route.NICID())
	if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
		e.stats.ip.IPTablesForwardDropped.Increment()
		return nil
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckForward(pkt, route, stack.IP6) {
			return nil
		}
	}

	hopLimit := h.HopLimit()

	newPkt := pkt.DeepCopyForForwarding(int(route.MaxHeaderLength()))
	defer newPkt.DecRef()
	newHdr := header.IPv6(newPkt.NetworkHeader().Slice())

	newHdr.SetHopLimit(hopLimit - 1)

	if route.RequiresTXTransportChecksum() {
		newPkt.CalculateTransportChecksum()
	}

	forwardToEp, ok := e.protocol.getEndpointForNIC(route.NICID())
	if !ok {
		return &ip.ErrUnknownOutputEndpoint{}
	}

	switch err := forwardToEp.writePacket(route, newPkt, newPkt.TransportProtocolNumber, true); err.(type) {
	case nil:
		return nil
	case *tcpip.ErrMessageTooLong:
		_ = e.protocol.returnError(&icmpReasonPacketTooBig{}, pkt, false)
		return &ip.ErrMessageTooLong{}
	case *tcpip.ErrNoBufferSpace:
		return &ip.ErrOutgoingDeviceNoBufferSpace{}
	default:
		return &ip.ErrOther{Err: err}
	}
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
	defer hView.Release()
	h := header.IPv6(hView.AsSlice())

	if !checkV4Mapped(h, stats) {
		return
	}

	if !e.nic.IsLoopback() {
		if !e.protocol.options.AllowExternalLoopbackTraffic {
			if header.IsV6LoopbackAddress(h.SourceAddress()) {
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}

			if header.IsV6LoopbackAddress(h.DestinationAddress()) {
				stats.InvalidDestinationAddressesReceived.Increment()
				return
			}
		}

		stk := e.protocol.stack
		if stk.HandleLocal() {
			promiscuous := e.nic.Promiscuous()
			allowPromiscuousSource := promiscuous && e.nic.AllowPromiscuousSource()
			addressEndpoint := e.AcquireAssignedAddress(header.IPv6(pkt.NetworkHeader().Slice()).SourceAddress(), promiscuous && !allowPromiscuousSource, stack.CanBePrimaryEndpoint, true)
			if addressEndpoint != nil && (!allowPromiscuousSource || addressEndpoint.GetKind().IsPermanent()) {
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}
		}

		inNicName := stk.FindNICNameFromID(e.nic.ID())
		if ok := stk.IPTables().CheckPrerouting(pkt, e, inNicName); !ok {
			stats.IPTablesPreroutingDropped.Increment()
			return
		}

		if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
			if !nft.CheckPrerouting(pkt, nil, stack.IP6) {
				return
			}
		}
	}

	h = header.IPv6(pkt.NetworkHeader().Slice())
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
	defer hView.Release()
	h := header.IPv6(hView.AsSlice())

	if !checkV4Mapped(h, stats) {
		return
	}

	e.handleValidatedPacket(h, pkt, e.nic.Name())
}

func (e *endpoint) forwardMulticastPacket(h header.IPv6, pkt *stack.PacketBuffer) ip.ForwardingError {
	if err := validateAddressesForForwarding(h); err != nil {
		return err
	}

	if err := e.processExtensionHeaders(h, pkt, true); err != nil {
		return &ip.ErrParameterProblem{}
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

func (e *endpoint) forwardValidatedMulticastPacket(pkt *stack.PacketBuffer, installedRoute *multicast.InstalledRoute) ip.ForwardingError {
	if e.nic.ID() != installedRoute.ExpectedInputInterface {
		h := header.IPv6(pkt.NetworkHeader().Slice())
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
	h := header.IPv6(pkt.NetworkHeader().Slice())

	if outgoingInterface.MinTTL > h.HopLimit() {
		return &ip.ErrTTLExceeded{}
	}

	route := e.protocol.stack.NewRouteForMulticast(outgoingInterface.ID, h.DestinationAddress(), e.NetworkProtocolNumber())

	if route == nil {
		return &ip.ErrHostUnreachable{}
	}
	defer route.Release()
	return e.forwardPacketWithRoute(route, pkt)
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
		stats.Forwarding.ExtensionHeaderProblem.Increment()
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

func (e *endpoint) handleValidatedPacket(h header.IPv6, pkt *stack.PacketBuffer, inNICName string) {
	pkt.NICID = e.nic.ID()

	e.dispatcher.DeliverRawPacket(h.TransportProtocol(), pkt)

	stats := e.stats.ip
	stats.ValidPacketsReceived.Increment()

	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	if header.IsV6MulticastAddress(srcAddr) {
		stats.InvalidSourceAddressesReceived.Increment()
		return
	}

	if header.IsV6MulticastAddress(dstAddr) {

		multicastForwading := e.MulticastForwarding() && e.protocol.multicastForwarding()

		if multicastForwading {
			e.handleForwardingError(e.forwardMulticastPacket(h, pkt))
		}

		if e.IsInGroup(dstAddr) {
			e.deliverPacketLocally(h, pkt, inNICName)
			return
		}

		if !multicastForwading {
			stats.InvalidDestinationAddressesReceived.Increment()
		}

		return
	}

	if addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint, true); addressEndpoint != nil {
		e.deliverPacketLocally(h, pkt, inNICName)
	} else if e.Forwarding() {
		e.handleForwardingError(e.forwardUnicastPacket(pkt))
	} else {
		stats.InvalidDestinationAddressesReceived.Increment()
	}
}

func (e *endpoint) deliverPacketLocally(h header.IPv6, pkt *stack.PacketBuffer, inNICName string) {
	stats := e.stats.ip
	stk := e.protocol.stack
	if ok := stk.IPTables().CheckInput(pkt, inNICName); !ok {
		stats.IPTablesInputDropped.Increment()
		return
	}

	if nft := stk.NFTables(); nft != nil && stk.IsNFTablesConfigured() {
		if !nft.CheckInput(pkt, nil, stack.IP6) {
			return
		}
	}

	_ = e.processExtensionHeaders(h, pkt, false)
}

func (e *endpoint) processExtensionHeader(it *header.IPv6PayloadIterator, pkt **stack.PacketBuffer, h header.IPv6, routerAlert **header.IPv6RouterAlertOption, hasFragmentHeader *bool, forwarding bool) (bool, error) {
	stats := e.stats.ip
	dstAddr := h.DestinationAddress()
	previousHeaderStart := it.HeaderOffset()
	extHdr, done, err := it.Next()
	if err != nil {
		stats.MalformedPacketsReceived.Increment()
		return true, err
	}
	if done {
		return true, nil
	}
	defer extHdr.Release()

	if forwarding {
		if _, ok := extHdr.(header.IPv6HopByHopOptionsExtHdr); !ok {
			return true, nil
		}
	}

	switch extHdr := extHdr.(type) {
	case header.IPv6HopByHopOptionsExtHdr:
		if err := e.processIPv6HopByHopOptionsExtHdr(&extHdr, it, *pkt, dstAddr, routerAlert, previousHeaderStart, forwarding); err != nil {
			return true, err
		}
	case header.IPv6RoutingExtHdr:
		if err := e.processIPv6RoutingExtHeader(&extHdr, it, *pkt); err != nil {
			return true, err
		}
	case header.IPv6FragmentExtHdr:
		*hasFragmentHeader = true
		if extHdr.IsAtomic() {
			return false, nil
		}

		if err := e.processFragmentExtHdr(&extHdr, it, pkt, h); err != nil {
			return true, err
		}
	case header.IPv6DestinationOptionsExtHdr:
		if err := e.processIPv6DestinationOptionsExtHdr(&extHdr, it, *pkt, dstAddr); err != nil {
			return true, err
		}
	case header.IPv6RawPayloadHeader:
		if err := e.processIPv6RawPayloadHeader(&extHdr, it, *pkt, *routerAlert, previousHeaderStart, *hasFragmentHeader); err != nil {
			return true, err
		}
	case header.IPv6ExperimentExtHdr:
	default:
		panic(fmt.Sprintf("unrecognized type from it.Next() = %T", extHdr))
	}
	return false, nil
}

func (e *endpoint) processExtensionHeaders(h header.IPv6, pkt *stack.PacketBuffer, forwarding bool) error {
	v := pkt.NetworkHeader().View()
	if v != nil {
		v.TrimFront(header.IPv6MinimumSize)
	}
	buf := buffer.MakeWithView(v)
	buf.Append(pkt.TransportHeader().View())
	dataBuf := pkt.Data().ToBuffer()
	buf.Merge(&dataBuf)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(h.NextHeader()), buf)

	processingPkt := pkt.Clone()
	defer func() {
		processingPkt.DecRef()
		it.Release()
	}()

	var (
		hasFragmentHeader bool
		routerAlert       *header.IPv6RouterAlertOption
	)
	for {
		h := header.IPv6(pkt.NetworkHeader().Slice())
		if done, err := e.processExtensionHeader(&it, &processingPkt, h, &routerAlert, &hasFragmentHeader, forwarding); err != nil || done {
			return err
		}
	}
}

func (e *endpoint) processIPv6RawPayloadHeader(extHdr *header.IPv6RawPayloadHeader, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer, routerAlert *header.IPv6RouterAlertOption, previousHeaderStart uint32, hasFragmentHeader bool) error {
	stats := e.stats.ip

	trim := pkt.Data().Size() - int(extHdr.Buf.Size())

	trim += len(pkt.TransportHeader().Slice())

	if _, ok := pkt.Data().Consume(trim); !ok {
		stats.MalformedPacketsReceived.Increment()
		return fmt.Errorf("could not consume %d bytes", trim)
	}

	proto := tcpip.TransportProtocolNumber(extHdr.Identifier)
	if len(pkt.TransportHeader().Slice()) == 0 {
		e.protocol.parseTransport(pkt, proto)
	}

	stats.PacketsDelivered.Increment()
	if proto == header.ICMPv6ProtocolNumber {
		e.handleICMP(pkt, hasFragmentHeader, routerAlert)
		return nil
	}
	switch res := e.dispatcher.DeliverTransportPacket(proto, pkt); res {
	case stack.TransportPacketHandled:
		return nil
	case stack.TransportPacketDestinationPortUnreachable:
		_ = e.protocol.returnError(&icmpReasonPortUnreachable{}, pkt, true)
		return fmt.Errorf("destination port unreachable")
	case stack.TransportPacketProtocolUnreachable:
		prevHdrIDOffset := uint32(header.IPv6NextHeaderOffset)
		if previousHeaderStart != 0 {
			prevHdrIDOffset = previousHeaderStart
		}
		_ = e.protocol.returnError(&icmpReasonParameterProblem{
			code:    header.ICMPv6UnknownHeader,
			pointer: prevHdrIDOffset,
		}, pkt, true)
		return fmt.Errorf("transport protocol unreachable")
	default:
		panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
	}
}

func (e *endpoint) processIPv6RoutingExtHeader(extHdr *header.IPv6RoutingExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer) error {
	if extHdr.SegmentsLeft() == 0 {
		return nil
	}
	_ = e.protocol.returnError(&icmpReasonParameterProblem{
		code:    header.ICMPv6ErroneousHeader,
		pointer: it.ParseOffset(),
	}, pkt, true)
	return fmt.Errorf("found unrecognized routing type with non-zero segments left in header = %#v", extHdr)
}

func (e *endpoint) processIPv6DestinationOptionsExtHdr(extHdr *header.IPv6DestinationOptionsExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer, dstAddr tcpip.Address) error {
	stats := e.stats.ip
	optsIt := extHdr.Iter()
	var uopt *header.IPv6UnknownExtHdrOption
	defer func() {
		if uopt != nil {
			uopt.Data.Release()
		}
	}()

	for {
		opt, done, err := optsIt.Next()
		if err != nil {
			stats.MalformedPacketsReceived.Increment()
			return err
		}
		if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
			uopt = uo
		}
		if done {
			break
		}

		switch opt.UnknownAction() {
		case header.IPv6OptionUnknownActionSkip:
		case header.IPv6OptionUnknownActionDiscard:
			return fmt.Errorf("found unknown destination header option = %#v with discard action", opt)
		case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
			if header.IsV6MulticastAddress(dstAddr) {
				if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
					uopt = uo
				}
				return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
			}
			fallthrough
		case header.IPv6OptionUnknownActionDiscardSendICMP:
			_ = e.protocol.returnError(&icmpReasonParameterProblem{
				code:               header.ICMPv6UnknownOption,
				pointer:            it.ParseOffset() + optsIt.OptionOffset(),
				respondToMulticast: true,
			}, pkt, true)
			return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
		default:
			panic(fmt.Sprintf("unrecognized action for an unrecognized Destination extension header option = %#v", opt))
		}
		if uopt != nil {
			uopt.Data.Release()
			uopt = nil
		}
	}
	return nil
}

func (e *endpoint) processIPv6HopByHopOptionsExtHdr(extHdr *header.IPv6HopByHopOptionsExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer, dstAddr tcpip.Address, routerAlert **header.IPv6RouterAlertOption, previousHeaderStart uint32, forwarding bool) error {
	stats := e.stats.ip
	if previousHeaderStart != 0 {
		_ = e.protocol.returnError(&icmpReasonParameterProblem{
			code:    header.ICMPv6UnknownHeader,
			pointer: previousHeaderStart,
		}, pkt, !forwarding)
		return fmt.Errorf("found Hop-by-Hop header = %#v with non-zero previous header offset = %d", extHdr, previousHeaderStart)
	}

	optsIt := extHdr.Iter()
	var uopt *header.IPv6UnknownExtHdrOption
	defer func() {
		if uopt != nil {
			uopt.Data.Release()
		}
	}()

	for {
		opt, done, err := optsIt.Next()
		if err != nil {
			stats.MalformedPacketsReceived.Increment()
			return err
		}
		if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
			uopt = uo
		}
		if done {
			break
		}

		switch opt := opt.(type) {
		case *header.IPv6RouterAlertOption:
			if *routerAlert != nil {
				stats.MalformedPacketsReceived.Increment()
				return fmt.Errorf("found multiple Router Alert options (%#v, %#v)", opt, *routerAlert)
			}
			*routerAlert = opt
			stats.OptionRouterAlertReceived.Increment()
		default:
			switch opt.UnknownAction() {
			case header.IPv6OptionUnknownActionSkip:
			case header.IPv6OptionUnknownActionDiscard:
				return fmt.Errorf("found unknown Hop-by-Hop header option = %#v with discard action", opt)
			case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
				if header.IsV6MulticastAddress(dstAddr) {
					return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
				}
				fallthrough
			case header.IPv6OptionUnknownActionDiscardSendICMP:
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:               header.ICMPv6UnknownOption,
					pointer:            it.ParseOffset() + optsIt.OptionOffset(),
					respondToMulticast: true,
				}, pkt, !forwarding)
				return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
			default:
				panic(fmt.Sprintf("unrecognized action for an unrecognized Hop By Hop extension header option = %#v", opt))
			}
		}
		if uopt != nil {
			uopt.Data.Release()
			uopt = nil
		}
	}
	return nil
}

func (e *endpoint) processFragmentExtHdr(extHdr *header.IPv6FragmentExtHdr, it *header.IPv6PayloadIterator, pkt **stack.PacketBuffer, h header.IPv6) error {
	stats := e.stats.ip
	fragmentFieldOffset := it.ParseOffset()

	rawPayload := it.AsRawHeader(extHdr.FragmentOffset() != 0)
	defer rawPayload.Release()

	if extHdr.FragmentOffset() == 0 {
		var lastHdr header.IPv6PayloadHeader

		for {
			it, done, err := it.Next()
			if err != nil {
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				return err
			}
			if done {
				break
			}
			it.Release()

			lastHdr = it
		}

		switch lastHdr.(type) {
		case header.IPv6RawPayloadHeader:
		default:
			stats.MalformedPacketsReceived.Increment()
			stats.MalformedFragmentsReceived.Increment()
			return fmt.Errorf("known extension header = %#v present after fragment header in a non-initial fragment", lastHdr)
		}
	}

	fragmentPayloadLen := rawPayload.Buf.Size()
	if fragmentPayloadLen == 0 {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return fmt.Errorf("fragment has no payload")
	}

	if extHdr.More() && fragmentPayloadLen%header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit != 0 {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		_ = e.protocol.returnError(&icmpReasonParameterProblem{
			code:    header.ICMPv6ErroneousHeader,
			pointer: header.IPv6PayloadLenOffset,
		}, *pkt, true)
		return fmt.Errorf("found fragment length = %d that is not a multiple of 8 octets", fragmentPayloadLen)
	}

	start := extHdr.FragmentOffset() * header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit

	lengthAfterReassembly := int(start) + int(fragmentPayloadLen)
	if lengthAfterReassembly > header.IPv6MaximumPayloadSize {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		_ = e.protocol.returnError(&icmpReasonParameterProblem{
			code:    header.ICMPv6ErroneousHeader,
			pointer: fragmentFieldOffset,
		}, *pkt, true)
		return fmt.Errorf("determined that reassembled packet length = %d would exceed allowed length = %d", lengthAfterReassembly, header.IPv6MaximumPayloadSize)
	}

	resPkt, proto, ready, err := e.protocol.fragmentation.Process(
		fragmentation.FragmentID{
			Source:      h.SourceAddress(),
			Destination: h.DestinationAddress(),
			ID:          extHdr.ID(),
		},
		start,
		start+uint16(fragmentPayloadLen)-1,
		extHdr.More(),
		uint8(rawPayload.Identifier),
		*pkt,
	)
	if err != nil {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return err
	}

	if ready {
		it.Release()
		*it = header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(proto), resPkt.Data().ToBuffer())
		(*pkt).DecRef()
		*pkt = resPkt
	}
	return nil
}

func (e *endpoint) Close() {
	e.mu.Lock()
	e.disableLocked()
	e.mu.addressableEndpointState.Cleanup()
	e.mu.Unlock()

	e.protocol.forgetEndpoint(e.nic.ID())
}

func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	addrDisp := properties.Disp
	properties.Disp = nil
	addressEndpoint, err := e.addAndAcquirePermanentAddressLocked(addr, properties)
	if addrDisp != nil && err == nil {
		addressEndpoint.RegisterDispatcher(addrDisp)
	}
	return addressEndpoint, err
}

func (e *endpoint) addAndAcquirePermanentAddressLocked(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	addressEndpoint, err := e.mu.addressableEndpointState.AddAndAcquireAddress(addr, properties, stack.PermanentTentative)
	if err != nil {
		return nil, err
	}

	if !header.IsV6UnicastAddress(addr.Address) {
		return addressEndpoint, nil
	}

	if e.Enabled() {
		if err := e.mu.ndp.startDuplicateAddressDetection(addr.Address, addressEndpoint); err != nil {
			return nil, err
		}
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if err := e.joinGroupLocked(snmc); err != nil {
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", snmc, err))
	}

	return addressEndpoint, nil
}

func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil || !addressEndpoint.GetKind().IsPermanent() {
		return &tcpip.ErrBadLocalAddress{}
	}

	return e.removePermanentEndpointLocked(addressEndpoint, true, stack.AddressRemovalManualAction, &stack.DADAborted{})
}

func (e *endpoint) removePermanentEndpointLocked(addressEndpoint stack.AddressEndpoint, allowSLAACInvalidation bool, reason stack.AddressRemovalReason, dadResult stack.DADResult) tcpip.Error {
	addr := addressEndpoint.AddressWithPrefix()
	if addressEndpoint.ConfigType() == stack.AddressConfigSlaac {
		if addressEndpoint.Temporary() {
			e.mu.ndp.cleanupTempSLAACAddrResourcesAndNotify(addr)
		} else {
			e.mu.ndp.cleanupSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
		}
	}

	return e.removePermanentEndpointInnerLocked(addressEndpoint, reason, dadResult)
}

func (e *endpoint) removePermanentEndpointInnerLocked(addressEndpoint stack.AddressEndpoint, reason stack.AddressRemovalReason, dadResult stack.DADResult) tcpip.Error {
	addr := addressEndpoint.AddressWithPrefix()
	e.mu.ndp.stopDuplicateAddressDetection(addr.Address, dadResult)

	if err := e.mu.addressableEndpointState.RemovePermanentEndpoint(addressEndpoint, reason); err != nil {
		return err
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	err := e.leaveGroupLocked(snmc)
	if _, ok := err.(*tcpip.ErrBadLocalAddress); ok {
		err = nil
	}
	return err
}

func (e *endpoint) hasPermanentAddressRLocked(addr tcpip.Address) bool {
	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return false
	}
	return addressEndpoint.GetKind().IsPermanent()
}

func (e *endpoint) getAddressRLocked(localAddr tcpip.Address) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.GetAddress(localAddr)
}

func (e *endpoint) SetDeprecated(addr tcpip.Address, deprecated bool) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.SetDeprecated(addr, deprecated)
}

func (e *endpoint) SetLifetimes(addr tcpip.Address, lifetimes stack.AddressLifetimes) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.SetLifetimes(addr, lifetimes)
}

func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior, readOnly bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireAddressOrCreateTempLocked(localAddr, allowTemp, tempPEB, readOnly)
}

func (e *endpoint) acquireAddressOrCreateTempLocked(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior, readOnly bool) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.AcquireAssignedAddress(localAddr, allowTemp, tempPEB, readOnly)
}

func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint, allowExpired)
}

func (e *endpoint) getLinkLocalAddressRLocked() tcpip.Address {
	var linkLocalAddr tcpip.Address
	e.mu.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if addressEndpoint.IsAssigned(false) {
			if addr := addressEndpoint.AddressWithPrefix().Address; header.IsV6LinkLocalUnicastAddress(addr) {
				linkLocalAddr = addr
				return false
			}
		}
		return true
	})
	return linkLocalAddr
}

func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {

	type addrCandidate struct {
		addressEndpoint stack.AddressEndpoint
		addr            tcpip.Address
		scope           header.IPv6AddressScope

		label          uint8
		matchingPrefix uint8
	}

	if remoteAddr.BitLen() == 0 {
		return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, srcHint, allowExpired)
	}

	var cs []addrCandidate
	e.mu.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if !addressEndpoint.IsAssigned(allowExpired) {
			return true
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		scope, err := header.ScopeForIPv6Address(addr)
		if err != nil {
			panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", addr, err))
		}

		cs = append(cs, addrCandidate{
			addressEndpoint: addressEndpoint,
			addr:            addr,
			scope:           scope,
			label:           getLabel(addr),
			matchingPrefix:  remoteAddr.MatchingPrefix(addr),
		})

		return true
	})

	remoteScope, err := header.ScopeForIPv6Address(remoteAddr)
	if err != nil {
		panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", remoteAddr, err))
	}

	remoteLabel := getLabel(remoteAddr)

	sort.Slice(cs, func(i, j int) bool {
		sa := cs[i]
		sb := cs[j]

		if sa.addr == remoteAddr {
			return true
		}
		if sb.addr == remoteAddr {
			return false
		}

		if sa.scope < sb.scope {
			return sa.scope >= remoteScope
		} else if sb.scope < sa.scope {
			return sb.scope < remoteScope
		}

		if saDep, sbDep := sa.addressEndpoint.Deprecated(), sb.addressEndpoint.Deprecated(); saDep != sbDep {
			return sbDep
		}

		if sa, sb := sa.label == remoteLabel, sb.label == remoteLabel; sa != sb {
			if sa {
				return true
			}
			if sb {
				return false
			}
		}

		if saTemp, sbTemp := sa.addressEndpoint.Temporary(), sb.addressEndpoint.Temporary(); saTemp != sbTemp {
			return saTemp
		}

		if sa.matchingPrefix > sb.matchingPrefix {
			return true
		}
		if sb.matchingPrefix > sa.matchingPrefix {
			return false
		}

		return i < j
	})

	for _, c := range cs {
		if c.addressEndpoint.TryIncRef() {
			return c.addressEndpoint
		}
	}

	return nil
}

func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

func (e *endpoint) JoinGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.joinGroupLocked(addr)
}

func (e *endpoint) joinGroupLocked(addr tcpip.Address) tcpip.Error {
	if !header.IsV6MulticastAddress(addr) {
		return &tcpip.ErrBadAddress{}
	}

	e.mu.mld.joinGroup(addr)
	return nil
}

func (e *endpoint) LeaveGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leaveGroupLocked(addr)
}

func (e *endpoint) leaveGroupLocked(addr tcpip.Address) tcpip.Error {
	return e.mu.mld.leaveGroup(addr)
}

func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.mld.isInGroup(addr)
}

func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.NetworkProtocol = (*protocol)(nil)
var _ stack.MulticastForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.RejectIPv6WithHandler = (*protocol)(nil)
var _ fragmentation.TimeoutHandler = (*protocol)(nil)

type protocolMu struct {
	sync.RWMutex `state:"nosave"`

	eps map[tcpip.NICID]*endpoint

	icmpRateLimitedTypes map[header.ICMPv6Type]struct{}

	multicastForwardingDisp stack.MulticastForwardingEventDispatcher
}

type protocol struct {
	stack   *stack.Stack
	options Options

	mu protocolMu

	defaultTTL atomicbitops.Uint32

	fragmentation   *fragmentation.Fragmentation
	icmpRateLimiter *stack.ICMPRateLimiter

	multicastRouteTable multicast.RouteTable
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

func (p *protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

func (*protocol) ParseAddresses(b []byte) (src, dst tcpip.Address) {
	h := header.IPv6(b)
	return h.SourceAddress(), h.DestinationAddress()
}

func (p *protocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:        nic,
		dispatcher: dispatcher,
		protocol:   p,
	}

	const nonceSize = 6

	const maxMulticastSolicit = 3
	dadOptions := ip.DADOptions{
		Clock:              p.stack.Clock(),
		SecureRNG:          p.stack.SecureRNG().Reader,
		NonceSize:          nonceSize,
		ExtendDADTransmits: maxMulticastSolicit,
		Protocol:           &e.mu.ndp,
		NICID:              nic.ID(),
	}

	e.mu.Lock()
	e.mu.addressableEndpointState.Init(e, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: true})
	e.mu.ndp.init(e, dadOptions)
	e.mu.mld.init(e)
	e.dad.mu.Lock()
	e.dad.mu.dad.Init(&e.dad.mu, p.options.DADConfigs, dadOptions)
	e.dad.mu.Unlock()
	e.mu.Unlock()

	stackStats := p.stack.Stats()
	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())
	e.stats.ip.Init(&e.stats.localStats.IP, &stackStats.IP)
	e.stats.icmp.init(&e.stats.localStats.ICMP, &stackStats.ICMP.V6)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.mu.eps[nic.ID()] = e
	return e
}

func (p *protocol) findEndpointWithAddress(addr tcpip.Address) *endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.mu.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint, true); addressEndpoint != nil {
			return e
		}
	}

	return nil
}

func (p *protocol) getEndpointForNIC(id tcpip.NICID) (*endpoint, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ep, ok := p.mu.eps[id]
	return ep, ok
}

func (p *protocol) forgetEndpoint(nicID tcpip.NICID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.mu.eps, nicID)
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

func (e *endpoint) emitMulticastEvent(eventGenerator func(stack.MulticastForwardingEventDispatcher)) {
	e.protocol.mu.RLock()
	defer e.protocol.mu.RUnlock()
	if mcastDisp := e.protocol.mu.multicastForwardingDisp; mcastDisp != nil {
		eventGenerator(mcastDisp)
	}
}

func (p *protocol) Close() {
	p.fragmentation.Release()
	p.multicastRouteTable.Close()
}

func validateUnicastSourceAndMulticastDestination(addresses stack.UnicastSourceAndMulticastDestination) tcpip.Error {
	if !header.IsV6UnicastAddress(addresses.Source) || header.IsV6LinkLocalUnicastAddress(addresses.Source) {
		return &tcpip.ErrBadAddress{}
	}

	if !header.IsV6MulticastAddress(addresses.Destination) || header.IsV6LinkLocalMulticastAddress(addresses.Destination) {
		return &tcpip.ErrBadAddress{}
	}

	return nil
}

func (p *protocol) multicastForwarding() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mu.multicastForwardingDisp != nil
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

	if err := validateUnicastSourceAndMulticastDestination(addresses); err != nil {
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
	if err := validateUnicastSourceAndMulticastDestination(addresses); err != nil {
		return err
	}

	if removed := p.multicastRouteTable.RemoveInstalledRoute(addresses); !removed {
		return &tcpip.ErrHostUnreachable{}
	}

	return nil
}

func (p *protocol) MulticastRouteLastUsedTime(addresses stack.UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, tcpip.Error) {
	if err := validateUnicastSourceAndMulticastDestination(addresses); err != nil {
		return tcpip.MonotonicTime{}, err
	}

	timestamp, found := p.multicastRouteTable.GetLastUsedTimestamp(addresses)

	if !found {
		return tcpip.MonotonicTime{}, &tcpip.ErrHostUnreachable{}
	}

	return timestamp, nil
}

func (p *protocol) EnableMulticastForwarding(disp stack.MulticastForwardingEventDispatcher) (bool, tcpip.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.mu.multicastForwardingDisp != nil {
		return true, nil
	}

	if disp == nil {
		return false, &tcpip.ErrInvalidOptionValue{}
	}

	p.mu.multicastForwardingDisp = disp
	return false, nil
}

func (p *protocol) DisableMulticastForwarding() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mu.multicastForwardingDisp = nil
	p.multicastRouteTable.RemoveAllInstalledRoutes()
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

func (*protocol) Wait() {}

func (p *protocol) parseAndValidate(pkt *stack.PacketBuffer) (*buffer.View, bool) {
	transProtoNum, hasTransportHdr, ok := p.Parse(pkt)
	if !ok {
		return nil, false
	}

	h := header.IPv6(pkt.NetworkHeader().Slice())
	if !h.IsValid(pkt.Size() - len(pkt.LinkHeader().Slice())) {
		return nil, false
	}

	if hasTransportHdr {
		p.parseTransport(pkt, transProtoNum)
	}

	return pkt.NetworkHeader().View(), true
}

func (p *protocol) parseTransport(pkt *stack.PacketBuffer, transProtoNum tcpip.TransportProtocolNumber) {
	if transProtoNum == header.ICMPv6ProtocolNumber {
		_ = parse.ICMPv6(pkt)
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
	proto, _, fragOffset, fragMore, ok := parse.IPv6(pkt)
	if !ok {
		return 0, false, false
	}

	return proto, !fragMore && fragOffset == 0, true
}

func (p *protocol) allowICMPReply(icmpType header.ICMPv6Type) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.mu.icmpRateLimitedTypes[icmpType]; ok {
		return p.stack.AllowICMPMessage()
	}
	return true
}

func (p *protocol) SendRejectionError(pkt *stack.PacketBuffer, rejectWith stack.RejectIPv6WithICMPType, inputHook bool) tcpip.Error {
	switch rejectWith {
	case stack.RejectIPv6WithICMPNoRoute:
		return p.returnError(&icmpReasonNetUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPAddrUnreachable:
		return p.returnError(&icmpReasonHostUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPPortUnreachable:
		return p.returnError(&icmpReasonPortUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPAdminProhibited:
		return p.returnError(&icmpReasonAdministrativelyProhibited{}, pkt, inputHook)
	case stack.RejectIPv6WithTCPReset:
		return ip.RejectWithTCPReset(pkt, ProtocolNumber, p.stack, inputHook)
	default:
		panic(fmt.Sprintf("unhandled %[1]T = %[1]d", rejectWith))
	}
}

func calculateNetworkMTU(linkMTU, networkHeadersLen uint32) (uint32, tcpip.Error) {
	if linkMTU < header.IPv6MinimumMTU {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	if networkHeadersLen > header.IPv6MinimumMTU {
		return 0, &tcpip.ErrMalformedHeader{}
	}

	networkMTU := linkMTU - networkHeadersLen
	if networkMTU > maxPayloadSize {
		networkMTU = maxPayloadSize
	}
	return networkMTU, nil
}

type Options struct {
	NDPConfigs NDPConfigurations

	AutoGenLinkLocal bool

	NDPDisp NDPDispatcher

	OpaqueIIDOpts OpaqueInterfaceIdentifierOptions

	TempIIDSeed []byte

	MLD MLDOptions

	DADConfigs stack.DADConfigurations

	AllowExternalLoopbackTraffic bool
}

func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	opts.NDPConfigs.validate()

	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:   s,
			options: opts,
		}
		p.fragmentation = fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock(), p)
		p.mu.eps = make(map[tcpip.NICID]*endpoint)
		p.SetDefaultTTL(DefaultTTL)
		defaultIcmpTypes := make(map[header.ICMPv6Type]struct{})
		for i := header.ICMPv6Type(0); i < header.ICMPv6EchoRequest; i++ {
			switch i {
			case header.ICMPv6PacketTooBig:
			default:
				defaultIcmpTypes[i] = struct{}{}
			}
		}
		p.mu.icmpRateLimitedTypes = defaultIcmpTypes

		if err := p.multicastRouteTable.Init(multicast.DefaultConfig(s.Clock())); err != nil {
			panic(fmt.Sprintf("p.multicastRouteTable.Init(_): %s", err))
		}

		return p
	}
}

func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func calculateFragmentReserve(pkt *stack.PacketBuffer) int {
	return pkt.AvailableHeaderBytes() + len(pkt.NetworkHeader().Slice()) + header.IPv6FragmentHeaderSize
}

func (e *endpoint) getFragmentID() uint32 {
	rng := e.protocol.stack.SecureRNG()
	id := rng.Uint32()
	for id == 0 {
		id = rng.Uint32()
	}
	return id
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeaders header.IPv6, transportProto tcpip.TransportProtocolNumber, id uint32) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeadersLength := len(originalIPHeaders)

	s := header.IPv6ExtHdrSerializer{&header.IPv6SerializableFragmentExtHdr{
		FragmentOffset: uint16(offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
		M:              more,
		Identification: id,
	}}

	fragmentIPHeadersLength := originalIPHeadersLength + s.Length()
	fragmentIPHeaders := header.IPv6(fragPkt.NetworkHeader().Push(fragmentIPHeadersLength))

	if copied := copy(fragmentIPHeaders, originalIPHeaders); copied != originalIPHeadersLength {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got %d, want %d", copied, originalIPHeadersLength))
	}

	nextHeader, _ := s.Serialize(transportProto, fragmentIPHeaders[originalIPHeadersLength:])

	fragmentIPHeaders.SetNextHeader(nextHeader)
	fragmentIPHeaders.SetPayloadLength(uint16(copied + fragmentIPHeadersLength - header.IPv6MinimumSize))

	return fragPkt, more
}

func checkV4Mapped(h header.IPv6, stats ip.MultiCounterIPStats) bool {
	ret := true
	if header.IsV4MappedAddress(h.SourceAddress()) {
		stats.InvalidSourceAddressesReceived.Increment()
		ret = false
	}
	if header.IsV4MappedAddress(h.DestinationAddress()) {
		stats.InvalidDestinationAddressesReceived.Increment()
		ret = false
	}
	return ret
}

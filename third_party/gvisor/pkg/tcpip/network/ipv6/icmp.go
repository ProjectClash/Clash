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

package ipv6

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type icmpv6DestinationUnreachableSockError struct{}

func (*icmpv6DestinationUnreachableSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP6
}

func (*icmpv6DestinationUnreachableSockError) Type() uint8 {
	return uint8(header.ICMPv6DstUnreachable)
}

func (*icmpv6DestinationUnreachableSockError) Info() uint32 {
	return 0
}

var _ stack.TransportError = (*icmpv6DestinationNetworkUnreachableSockError)(nil)

type icmpv6DestinationNetworkUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

func (*icmpv6DestinationNetworkUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6NetworkUnreachable)
}

func (*icmpv6DestinationNetworkUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationNetworkUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6DestinationPortUnreachableSockError)(nil)

type icmpv6DestinationPortUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

func (*icmpv6DestinationPortUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6PortUnreachable)
}

func (*icmpv6DestinationPortUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationPortUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6DestinationAddressUnreachableSockError)(nil)

type icmpv6DestinationAddressUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

func (*icmpv6DestinationAddressUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6AddressUnreachable)
}

func (*icmpv6DestinationAddressUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationHostUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6PacketTooBigSockError)(nil)

type icmpv6PacketTooBigSockError struct {
	mtu uint32
}

func (*icmpv6PacketTooBigSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP6
}

func (*icmpv6PacketTooBigSockError) Type() uint8 {
	return uint8(header.ICMPv6PacketTooBig)
}

func (*icmpv6PacketTooBigSockError) Code() uint8 {
	return uint8(header.ICMPv6UnusedCode)
}

func (e *icmpv6PacketTooBigSockError) Info() uint32 {
	return e.mtu
}

func (*icmpv6PacketTooBigSockError) Kind() stack.TransportErrorKind {
	return stack.PacketTooBigTransportError
}

func (e *endpoint) checkLocalAddress(addr tcpip.Address) bool {
	if e.nic.Spoofing() {
		return true
	}

	if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint, true); addressEndpoint != nil {
		return true
	}
	return false
}

func (e *endpoint) handleControl(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return
	}
	hdr := header.IPv6(h)

	srcAddr := hdr.SourceAddress()
	if !e.checkLocalAddress(srcAddr) {
		return
	}

	p := hdr.TransportProtocol()
	dstAddr := hdr.DestinationAddress()

	if _, ok := pkt.Data().Consume(header.IPv6MinimumSize); !ok {
		panic("could not consume IPv6MinimumSize bytes")
	}
	if p == header.IPv6FragmentHeader {
		f, ok := pkt.Data().PullUp(header.IPv6FragmentHeaderSize)
		if !ok {
			return
		}
		fragHdr := header.IPv6Fragment(f)
		if !fragHdr.IsValid() || fragHdr.FragmentOffset() != 0 {
			return
		}
		p = fragHdr.TransportProtocol()

		if _, ok := pkt.Data().Consume(header.IPv6FragmentHeaderSize); !ok {
			panic("could not consume IPv6FragmentHeaderSize bytes")
		}
	}

	e.dispatcher.DeliverTransportError(srcAddr, dstAddr, ProtocolNumber, p, transErr, pkt)
}

func getLinkAddrOption(it header.NDPOptionIterator, getAddr func(header.NDPOption) tcpip.LinkAddress) (tcpip.LinkAddress, bool) {
	var linkAddr tcpip.LinkAddress
	for {
		opt, done, err := it.Next()
		if err != nil {
			return "", false
		}
		if done {
			break
		}
		if addr := getAddr(opt); len(addr) != 0 {
			if len(linkAddr) != 0 {
				return "", false
			}
			linkAddr = addr
		}
	}
	return linkAddr, true
}

func getSourceLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if src, ok := opt.(header.NDPSourceLinkLayerAddressOption); ok {
			return src.EthernetAddress()
		}
		return ""
	})
}

func getTargetLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if dst, ok := opt.(header.NDPTargetLinkLayerAddressOption); ok {
			return dst.EthernetAddress()
		}
		return ""
	})
}

func isMLDValid(pkt *stack.PacketBuffer, iph header.IPv6, routerAlert *header.IPv6RouterAlertOption) bool {
	if routerAlert == nil || routerAlert.Value != header.IPv6RouterAlertMLD {
		return false
	}
	if len(pkt.TransportHeader().Slice()) < header.ICMPv6HeaderSize+header.MLDMinimumSize {
		return false
	}
	if iph.HopLimit() != header.MLDHopLimit {
		return false
	}
	if !header.IsV6LinkLocalUnicastAddress(iph.SourceAddress()) {
		return false
	}
	return true
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer, hasFragmentHeader bool, routerAlert *header.IPv6RouterAlertOption) {
	sent := e.stats.icmp.packetsSent
	received := e.stats.icmp.packetsReceived
	h := header.ICMPv6(pkt.TransportHeader().Slice())
	if len(h) < header.ICMPv6MinimumSize {
		received.invalid.Increment()
		return
	}
	iph := header.IPv6(pkt.NetworkHeader().Slice())
	srcAddr := iph.SourceAddress()
	dstAddr := iph.DestinationAddress()

	payload := pkt.Data()
	if got, want := h.Checksum(), header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      h,
		Src:         srcAddr,
		Dst:         dstAddr,
		PayloadCsum: payload.Checksum(),
		PayloadLen:  payload.Size(),
	}); got != want {
		received.invalid.Increment()
		return
	}

	isNDPValid := func() bool {
		return !hasFragmentHeader && iph.HopLimit() == header.NDPHopLimit && h.Code() == 0
	}

	switch icmpType := h.Type(); icmpType {
	case header.ICMPv6PacketTooBig:
		received.packetTooBig.Increment()
		networkMTU, err := calculateNetworkMTU(h.MTU(), header.IPv6MinimumSize)
		if err != nil {
			networkMTU = 0
		}
		e.handleControl(&icmpv6PacketTooBigSockError{mtu: networkMTU}, pkt)

	case header.ICMPv6DstUnreachable:
		received.dstUnreachable.Increment()
		switch h.Code() {
		case header.ICMPv6NetworkUnreachable:
			e.handleControl(&icmpv6DestinationNetworkUnreachableSockError{}, pkt)
		case header.ICMPv6PortUnreachable:
			e.handleControl(&icmpv6DestinationPortUnreachableSockError{}, pkt)
		}
	case header.ICMPv6NeighborSolicit:
		received.neighborSolicit.Increment()
		if !isNDPValid() || len(h) < header.ICMPv6NeighborSolicitMinimumSize {
			received.invalid.Increment()
			return
		}

		ns := header.NDPNeighborSolicit(h.MessageBody())
		targetAddr := ns.TargetAddress()

		if header.IsV6MulticastAddress(targetAddr) {
			received.invalid.Increment()
			return
		}

		var it header.NDPOptionIterator
		{
			var err error
			it, err = ns.Options().Iter(false)
			if err != nil {
				received.invalid.Increment()
				return
			}
		}

		if e.hasTentativeAddr(targetAddr) {
			if srcAddr == header.IPv6Any {
				var nonce []byte
				for {
					opt, done, err := it.Next()
					if err != nil {
						received.invalid.Increment()
						return
					}
					if done {
						break
					}
					if n, ok := opt.(header.NDPNonceOption); ok {
						nonce = n.Nonce()
						break
					}
				}

				var holderLinkAddress tcpip.LinkAddress

				switch err := e.dupTentativeAddrDetected(targetAddr, holderLinkAddress, nonce); err.(type) {
				case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				default:
					panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
				}
			}

			return
		}


		if !e.checkLocalAddress(targetAddr) {
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		unspecifiedSource := srcAddr == header.IPv6Any
		if len(sourceLinkAddr) == 0 {
			if header.IsV6MulticastAddress(dstAddr) && !unspecifiedSource {
				received.invalid.Increment()
				return
			}
		} else if unspecifiedSource {
			received.invalid.Increment()
			return
		} else {
			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, srcAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

		if unspecifiedSource && !header.IsSolicitedNodeAddr(dstAddr) {
			received.invalid.Increment()
			return
		}

		remoteAddr := srcAddr
		if unspecifiedSource {
			remoteAddr = header.IPv6AllNodesMulticastAddress
		}

		r, err := e.protocol.stack.FindRoute(e.nic.ID(), targetAddr, remoteAddr, ProtocolNumber, false)
		if err != nil {
			return
		}
		defer r.Release()

		if len(sourceLinkAddr) != 0 {
			r.ResolveWith(sourceLinkAddr)
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(e.nic.LinkAddress()),
		}
		neighborAdvertSize := header.ICMPv6NeighborAdvertMinimumSize + optsSerializer.Length()
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + neighborAdvertSize,
		})
		defer pkt.DecRef()
		pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
		packet := header.ICMPv6(pkt.TransportHeader().Push(neighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.MessageBody())

		na.SetSolicitedFlag(!unspecifiedSource)
		na.SetOverrideFlag(true)
		na.SetRouterFlag(e.Forwarding())
		na.SetTargetAddress(targetAddr)
		na.Options().Serialize(optsSerializer)
		packet.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: packet,
			Src:    r.LocalAddress(),
			Dst:    r.RemoteAddress(),
		}))

		if err := r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, pkt); err != nil {
			sent.dropped.Increment()
			return
		}
		sent.neighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.neighborAdvert.Increment()
		if !isNDPValid() || len(h) < header.ICMPv6NeighborAdvertMinimumSize {
			received.invalid.Increment()
			return
		}

		na := header.NDPNeighborAdvert(h.MessageBody())

		it, err := na.Options().Iter(false)
		if err != nil {
			received.invalid.Increment()
			return
		}

		targetLinkAddr, ok := getTargetLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		targetAddr := na.TargetAddress()

		e.dad.mu.Lock()
		e.dad.mu.dad.StopLocked(targetAddr, &stack.DADDupAddrDetected{HolderLinkAddress: targetLinkAddr})
		e.dad.mu.Unlock()

		if e.hasTentativeAddr(targetAddr) {
			var nonce []byte

			switch err := e.dupTentativeAddrDetected(targetAddr, targetLinkAddr, nonce); err.(type) {
			case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				return
			default:
				panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
			}
		}


		if header.IsV6MulticastAddress(dstAddr) && na.SolicitedFlag() {
			received.invalid.Increment()
			return
		}

		switch err := e.nic.HandleNeighborConfirmation(ProtocolNumber, targetAddr, targetLinkAddr, stack.ReachabilityConfirmationFlags{
			Solicited: na.SolicitedFlag(),
			Override:  na.OverrideFlag(),
			IsRouter:  na.RouterFlag(),
		}); err.(type) {
		case nil:
		case *tcpip.ErrNotSupported:
		default:
			panic(fmt.Sprintf("unexpected error when informing NIC of neighbor confirmation message: %s", err))
		}

	case header.ICMPv6EchoRequest:
		received.echoRequest.Increment()
		replyPayload := pkt.Data().ToBuffer()
		replyHeader := make([]byte, header.ICMPv6EchoMinimumSize)
		copy(replyHeader, h[:header.ICMPv6EchoMinimumSize])

		defaultHandlerHandled := false
		if dispatcher, ok := e.dispatcher.(stack.TransportDispatcherWithDefaultHandlerResult); ok {
			_, defaultHandlerHandled = dispatcher.DeliverTransportPacketWithDefaultHandlerResult(header.ICMPv6ProtocolNumber, pkt)
		} else {
			e.dispatcher.DeliverTransportPacket(header.ICMPv6ProtocolNumber, pkt)
		}
		pkt = nil

		if defaultHandlerHandled {
			replyPayload.Release()
			return
		}

		e.sendICMPEchoReply(replyPayload, replyHeader, srcAddr, dstAddr, iph)

	case header.ICMPv6EchoReply:
		received.echoReply.Increment()
		if len(h) < header.ICMPv6EchoMinimumSize {
			received.invalid.Increment()
			return
		}
		e.dispatcher.DeliverTransportPacket(header.ICMPv6ProtocolNumber, pkt)

	case header.ICMPv6TimeExceeded:
		received.timeExceeded.Increment()

	case header.ICMPv6ParamProblem:
		received.paramProblem.Increment()

	case header.ICMPv6RouterSolicit:
		received.routerSolicit.Increment()


		if !isNDPValid() || len(h)-header.ICMPv6HeaderSize < header.NDPRSMinimumSize {
			received.invalid.Increment()
			return
		}

		if !e.Forwarding() {
			received.routerOnlyPacketsDroppedByHost.Increment()
			return
		}

		rs := header.NDPRouterSolicit(h.MessageBody())
		it, err := rs.Options().Iter(false)
		if err != nil {
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		if len(sourceLinkAddr) != 0 {
			if srcAddr == header.IPv6Any {
				received.invalid.Increment()
				return
			}

			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, srcAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

	case header.ICMPv6RouterAdvert:
		received.routerAdvert.Increment()


		if !isNDPValid() || len(h)-header.ICMPv6HeaderSize < header.NDPRAMinimumSize {
			received.invalid.Increment()
			return
		}

		routerAddr := srcAddr

		if !header.IsV6LinkLocalUnicastAddress(routerAddr) {
			received.invalid.Increment()
			return
		}

		ra := header.NDPRouterAdvert(h.MessageBody())
		it, err := ra.Options().Iter(false)
		if err != nil {
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}


		if len(sourceLinkAddr) != 0 {
			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, routerAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

		e.mu.Lock()
		e.mu.ndp.handleRA(routerAddr, ra)
		e.mu.Unlock()

	case header.ICMPv6RedirectMsg:
		received.redirectMsg.Increment()
		if !isNDPValid() {
			received.invalid.Increment()
			return
		}

	case header.ICMPv6MulticastListenerQuery,
		header.ICMPv6MulticastListenerReport,
		header.ICMPv6MulticastListenerV2Report,
		header.ICMPv6MulticastListenerDone:
		icmpBody := h.MessageBody()
		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			received.multicastListenerQuery.Increment()
		case header.ICMPv6MulticastListenerReport:
			received.multicastListenerReport.Increment()
		case header.ICMPv6MulticastListenerV2Report:
			received.multicastListenerReportV2.Increment()
		case header.ICMPv6MulticastListenerDone:
			received.multicastListenerDone.Increment()
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

		if !isMLDValid(pkt, iph, routerAlert) {
			received.invalid.Increment()
			return
		}

		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			e.mu.Lock()
			if len(icmpBody) >= header.MLDv2QueryMinimumSize {
				e.mu.mld.handleMulticastListenerQueryV2(header.MLDv2Query(icmpBody))
			} else {
				e.mu.mld.handleMulticastListenerQuery(header.MLD(icmpBody))
			}
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerReport:
			e.mu.Lock()
			e.mu.mld.handleMulticastListenerReport(header.MLD(icmpBody))
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerDone, header.ICMPv6MulticastListenerV2Report:
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

	default:
		received.unrecognized.Increment()
	}
}

func (e *endpoint) sendICMPEchoReply(replyPayload buffer.Buffer, replyHeader []byte, srcAddr, dstAddr tcpip.Address, ipHdr header.IPv6) {
	sent := e.stats.icmp.packetsSent

	localAddr := dstAddr
	if header.IsV6MulticastAddress(dstAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := e.protocol.stack.FindRoute(e.nic.ID(), localAddr, srcAddr, ProtocolNumber, false)
	if err != nil {
		replyPayload.Release()
		return
	}
	defer r.Release()

	if !e.protocol.allowICMPReply(header.ICMPv6EchoReply) {
		sent.rateLimited.Increment()
		replyPayload.Release()
		return
	}

	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
		Payload:            replyPayload,
	})
	defer replyPkt.DecRef()
	icmp := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
	replyPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	copy(icmp, replyHeader)
	icmp.SetType(header.ICMPv6EchoReply)
	replyData := replyPkt.Data()
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp,
		Src:         r.LocalAddress(),
		Dst:         r.RemoteAddress(),
		PayloadCsum: replyData.Checksum(),
		PayloadLen:  replyData.Size(),
	}))
	replyTClass, _ := ipHdr.TOS()
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      r.DefaultTTL(),
		TOS: replyTClass,
	}, replyPkt); err != nil {
		sent.dropped.Increment()
		return
	}
	sent.echoReply.Increment()
}

func (*endpoint) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

func (e *endpoint) LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	remoteAddr := targetAddr
	if len(remoteLinkAddr) == 0 {
		remoteAddr = header.SolicitedNodeAddr(targetAddr)
		remoteLinkAddr = header.EthernetAddressFromMulticastIPv6Address(remoteAddr)
	}

	if localAddr.BitLen() == 0 {
		addressEndpoint := e.AcquireOutgoingPrimaryAddress(remoteAddr, tcpip.Address{}, false)
		if addressEndpoint == nil {
			return &tcpip.ErrNetworkUnreachable{}
		}

		localAddr = addressEndpoint.AddressWithPrefix().Address
		addressEndpoint.DecRef()
	} else if !e.checkLocalAddress(localAddr) {
		return &tcpip.ErrBadLocalAddress{}
	}

	return e.sendNDPNS(localAddr, remoteAddr, targetAddr, remoteLinkAddr, header.NDPOptionsSerializer{
		header.NDPSourceLinkLayerAddressOption(e.nic.LinkAddress()),
	})
}

func (*endpoint) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}


type icmpReason interface {
	isICMPReason()
	respondsToMulticast() bool
}

type icmpReasonParameterProblem struct {
	code header.ICMPv6Code

	pointer uint32

	respondToMulticast bool
}

func (*icmpReasonParameterProblem) isICMPReason() {}

func (p *icmpReasonParameterProblem) respondsToMulticast() bool {
	return p.respondToMulticast
}

type icmpReasonAdministrativelyProhibited struct{}

func (*icmpReasonAdministrativelyProhibited) isICMPReason() {}

func (*icmpReasonAdministrativelyProhibited) respondsToMulticast() bool {
	return false
}

type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}

func (*icmpReasonPortUnreachable) respondsToMulticast() bool {
	return false
}

type icmpReasonNetUnreachable struct{}

func (*icmpReasonNetUnreachable) isICMPReason() {}

func (*icmpReasonNetUnreachable) respondsToMulticast() bool {
	return false
}

type icmpReasonHostUnreachable struct{}

func (*icmpReasonHostUnreachable) isICMPReason() {}

func (*icmpReasonHostUnreachable) respondsToMulticast() bool {
	return false
}

type icmpReasonPacketTooBig struct{}

func (*icmpReasonPacketTooBig) isICMPReason() {}

func (*icmpReasonPacketTooBig) respondsToMulticast() bool {
	return true
}

type icmpReasonHopLimitExceeded struct{}

func (*icmpReasonHopLimitExceeded) isICMPReason() {}

func (*icmpReasonHopLimitExceeded) respondsToMulticast() bool {
	return false
}

type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}

func (*icmpReasonReassemblyTimeout) respondsToMulticast() bool {
	return false
}

func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer, deliveredLocally bool) tcpip.Error {
	origIPHdr := header.IPv6(pkt.NetworkHeader().Slice())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	allowResponseToMulticast := reason.respondsToMulticast()
	isOrigDstMulticast := header.IsV6MulticastAddress(origIPHdrDst)
	if (!allowResponseToMulticast && isOrigDstMulticast) || origIPHdrSrc == header.IPv6Any {
		return nil
	}

	localAddr := origIPHdrDst
	if !deliveredLocally || isOrigDstMulticast {
		localAddr = tcpip.Address{}
	}
	route, err := p.stack.FindRoute(pkt.NICID, localAddr, origIPHdrSrc, ProtocolNumber, false)
	if err != nil {
		return err
	}
	defer route.Release()

	p.mu.Lock()
	netEP, ok := p.mu.eps[route.NICID()]
	p.mu.Unlock()
	if !ok {
		return &tcpip.ErrNotConnected{}
	}

	if pkt.TransportProtocolNumber == header.ICMPv6ProtocolNumber {
		if typ := header.ICMPv6(pkt.TransportHeader().Slice()).Type(); typ.IsErrorType() || typ == header.ICMPv6RedirectMsg {
			return nil
		}
	}

	sent := netEP.stats.icmp.packetsSent
	icmpType, icmpCode, counter, typeSpecific := func() (header.ICMPv6Type, header.ICMPv6Code, tcpip.MultiCounterStat, uint32) {
		switch reason := reason.(type) {
		case *icmpReasonParameterProblem:
			return header.ICMPv6ParamProblem, reason.code, sent.paramProblem, reason.pointer
		case *icmpReasonAdministrativelyProhibited:
			return header.ICMPv6DstUnreachable, header.ICMPv6Prohibited, sent.dstUnreachable, 0
		case *icmpReasonPortUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, sent.dstUnreachable, 0
		case *icmpReasonNetUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6NetworkUnreachable, sent.dstUnreachable, 0
		case *icmpReasonHostUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6AddressUnreachable, sent.dstUnreachable, 0
		case *icmpReasonPacketTooBig:
			return header.ICMPv6PacketTooBig, header.ICMPv6UnusedCode, sent.packetTooBig, 0
		case *icmpReasonHopLimitExceeded:
			return header.ICMPv6TimeExceeded, header.ICMPv6HopLimitExceeded, sent.timeExceeded, 0
		case *icmpReasonReassemblyTimeout:
			return header.ICMPv6TimeExceeded, header.ICMPv6ReassemblyTimeout, sent.timeExceeded, 0
		default:
			panic(fmt.Sprintf("unsupported ICMP type %T", reason))
		}
	}()

	if !p.allowICMPReply(icmpType) {
		sent.rateLimited.Increment()
		return nil
	}

	network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()

	mtu := int(route.MTU())
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil
	}
	payloadLen := network.Size() + transport.Size() + pkt.Data().Size()
	if payloadLen > available {
		payloadLen = available
	}
	payload := buffer.MakeWithView(network)
	payload.Append(transport)
	dataBuf := pkt.Data().ToBuffer()
	payload.Merge(&dataBuf)
	payload.Truncate(int64(payloadLen))

	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6ErrorHeaderSize,
		Payload:            payload,
	})
	defer newPkt.DecRef()
	newPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber

	icmpHdr := header.ICMPv6(newPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetTypeSpecific(typeSpecific)

	pktData := newPkt.Data()
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         route.LocalAddress(),
		Dst:         route.RemoteAddress(),
		PayloadCsum: pktData.Checksum(),
		PayloadLen:  pktData.Size(),
	}))
	if err := route.WritePacket(
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		newPkt,
	); err != nil {
		sent.dropped.Increment()
		return err
	}
	counter.Increment()
	return nil
}

func (p *protocol) OnReassemblyTimeout(pkt *stack.PacketBuffer) {
	if pkt != nil {
		p.returnError(&icmpReasonReassemblyTimeout{}, pkt, true)
	}
}

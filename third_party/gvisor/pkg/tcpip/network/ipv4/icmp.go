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

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type icmpv4DestinationUnreachableSockError struct{}

func (*icmpv4DestinationUnreachableSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP
}

func (*icmpv4DestinationUnreachableSockError) Type() uint8 {
	return uint8(header.ICMPv4DstUnreachable)
}

func (*icmpv4DestinationUnreachableSockError) Info() uint32 {
	return 0
}

var _ stack.TransportError = (*icmpv4DestinationHostUnreachableSockError)(nil)

type icmpv4DestinationHostUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4DestinationHostUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4HostUnreachable)
}

func (*icmpv4DestinationHostUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationHostUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4DestinationNetUnreachableSockError)(nil)

type icmpv4DestinationNetUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4DestinationNetUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4NetUnreachable)
}

func (*icmpv4DestinationNetUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationNetworkUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4DestinationPortUnreachableSockError)(nil)

type icmpv4DestinationPortUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4DestinationPortUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4PortUnreachable)
}

func (*icmpv4DestinationPortUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationPortUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4DestinationProtoUnreachableSockError)(nil)

type icmpv4DestinationProtoUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4DestinationProtoUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4ProtoUnreachable)
}

func (*icmpv4DestinationProtoUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationProtoUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4SourceRouteFailedSockError)(nil)

type icmpv4SourceRouteFailedSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4SourceRouteFailedSockError) Code() uint8 {
	return uint8(header.ICMPv4SourceRouteFailed)
}

func (*icmpv4SourceRouteFailedSockError) Kind() stack.TransportErrorKind {
	return stack.SourceRouteFailedTransportError
}

var _ stack.TransportError = (*icmpv4SourceHostIsolatedSockError)(nil)

type icmpv4SourceHostIsolatedSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4SourceHostIsolatedSockError) Code() uint8 {
	return uint8(header.ICMPv4SourceHostIsolated)
}

func (*icmpv4SourceHostIsolatedSockError) Kind() stack.TransportErrorKind {
	return stack.SourceHostIsolatedTransportError
}

var _ stack.TransportError = (*icmpv4DestinationHostUnknownSockError)(nil)

type icmpv4DestinationHostUnknownSockError struct {
	icmpv4DestinationUnreachableSockError
}

func (*icmpv4DestinationHostUnknownSockError) Code() uint8 {
	return uint8(header.ICMPv4DestinationHostUnknown)
}

func (*icmpv4DestinationHostUnknownSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationHostDownTransportError
}

var _ stack.TransportError = (*icmpv4FragmentationNeededSockError)(nil)

type icmpv4FragmentationNeededSockError struct {
	icmpv4DestinationUnreachableSockError

	mtu uint32
}

func (*icmpv4FragmentationNeededSockError) Code() uint8 {
	return uint8(header.ICMPv4FragmentationNeeded)
}

func (e *icmpv4FragmentationNeededSockError) Info() uint32 {
	return e.mtu
}

func (*icmpv4FragmentationNeededSockError) Kind() stack.TransportErrorKind {
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

func (e *endpoint) handleControl(errInfo stack.TransportError, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return
	}
	hdr := header.IPv4(h)

	srcAddr := hdr.SourceAddress()
	if !e.checkLocalAddress(srcAddr) {
		return
	}

	hlen := int(hdr.HeaderLength())
	if pkt.Data().Size() < hlen || hdr.FragmentOffset() != 0 {
		return
	}

	p := hdr.TransportProtocol()
	dstAddr := hdr.DestinationAddress()
	if _, ok := pkt.Data().Consume(hlen); !ok {
		panic(fmt.Sprintf("could not consume the IP header of %d bytes", hlen))
	}
	e.dispatcher.DeliverTransportError(srcAddr, dstAddr, ProtocolNumber, p, errInfo, pkt)
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer) {
	received := e.stats.icmp.packetsReceived
	h := header.ICMPv4(pkt.TransportHeader().Slice())
	if len(h) < header.ICMPv4MinimumSize {
		received.invalid.Increment()
		return
	}

	if checksum.Checksum(h, pkt.Data().Checksum()) != 0xffff {
		received.invalid.Increment()
		switch h.Type() {
		case header.ICMPv4Echo:
			e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)
		}
		return
	}

	iph := header.IPv4(pkt.NetworkHeader().Slice())
	var newOptions header.IPv4Options
	if opts := iph.Options(); len(opts) != 0 {
		var op optionsUsage
		if h.Type() == header.ICMPv4Echo {
			op = &optionUsageEcho{}
		} else {
			op = &optionUsageReceive{}
		}
		var optProblem *header.IPv4OptParameterProblem
		newOptions, _, optProblem = e.processIPOptions(pkt, opts, op)
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer: optProblem.Pointer,
				}, pkt, true)
				e.stats.ip.MalformedPacketsReceived.Increment()
			}
			return
		}
		copied := copy(opts, newOptions)
		if copied != len(newOptions) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOptions)))
		}
		for i := copied; i < len(opts); i++ {
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}

	switch h.Type() {
	case header.ICMPv4Echo:
		received.echoRequest.Increment()

		replyData := stack.PayloadSince(pkt.TransportHeader())
		defer replyData.Release()
		localAddressTemporary := pkt.NetworkPacketInfo.LocalAddressTemporary
		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		defaultHandlerHandled := false
		if dispatcher, ok := e.dispatcher.(stack.TransportDispatcherWithDefaultHandlerResult); ok {
			_, defaultHandlerHandled = dispatcher.DeliverTransportPacketWithDefaultHandlerResult(header.ICMPv4ProtocolNumber, pkt)
		} else {
			e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)
		}
		pkt = nil

		if defaultHandlerHandled || localAddressTemporary {
			return
		}

		e.sendICMPEchoReply(replyData, iph, newOptions, localAddressBroadcast)

	case header.ICMPv4EchoReply:
		received.echoReply.Increment()

		e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)

	case header.ICMPv4DstUnreachable:
		received.dstUnreachable.Increment()

		mtu := h.MTU()
		code := h.Code()
		switch code {
		case header.ICMPv4NetUnreachable,
			header.ICMPv4DestinationNetworkUnknown,
			header.ICMPv4NetUnreachableForTos,
			header.ICMPv4NetProhibited:
			e.handleControl(&icmpv4DestinationNetUnreachableSockError{}, pkt)
		case header.ICMPv4HostUnreachable,
			header.ICMPv4HostProhibited,
			header.ICMPv4AdminProhibited,
			header.ICMPv4HostUnreachableForTos,
			header.ICMPv4HostPrecedenceViolation,
			header.ICMPv4PrecedenceCutInEffect:
			e.handleControl(&icmpv4DestinationHostUnreachableSockError{}, pkt)
		case header.ICMPv4PortUnreachable:
			e.handleControl(&icmpv4DestinationPortUnreachableSockError{}, pkt)
		case header.ICMPv4FragmentationNeeded:
			networkMTU, err := calculateNetworkMTU(uint32(mtu), header.IPv4MinimumSize)
			if err != nil {
				networkMTU = 0
			}
			e.handleControl(&icmpv4FragmentationNeededSockError{mtu: networkMTU}, pkt)
		case header.ICMPv4ProtoUnreachable:
			e.handleControl(&icmpv4DestinationProtoUnreachableSockError{}, pkt)
		case header.ICMPv4SourceRouteFailed:
			e.handleControl(&icmpv4SourceRouteFailedSockError{}, pkt)
		case header.ICMPv4SourceHostIsolated:
			e.handleControl(&icmpv4SourceHostIsolatedSockError{}, pkt)
		case header.ICMPv4DestinationHostUnknown:
			e.handleControl(&icmpv4DestinationHostUnknownSockError{}, pkt)
		}
	case header.ICMPv4SrcQuench:
		received.srcQuench.Increment()

	case header.ICMPv4Redirect:
		received.redirect.Increment()

	case header.ICMPv4TimeExceeded:
		received.timeExceeded.Increment()

	case header.ICMPv4ParamProblem:
		received.paramProblem.Increment()

	case header.ICMPv4Timestamp:
		received.timestamp.Increment()

	case header.ICMPv4TimestampReply:
		received.timestampReply.Increment()

	case header.ICMPv4InfoRequest:
		received.infoRequest.Increment()

	case header.ICMPv4InfoReply:
		received.infoReply.Increment()

	default:
		received.invalid.Increment()
	}
}

func (e *endpoint) sendICMPEchoReply(replyData *buffer.View, ipHdr header.IPv4, newOptions header.IPv4Options, localAddressBroadcast bool) {
	sent := e.stats.icmp.packetsSent
	if !e.protocol.allowICMPReply(header.ICMPv4EchoReply, header.ICMPv4UnusedCode) {
		sent.rateLimited.Increment()
		return
	}

	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := e.protocol.stack.FindRoute(e.nic.ID(), localAddr, ipHdr.SourceAddress(), ProtocolNumber, false)
	if err != nil {
		return
	}
	defer r.Release()

	outgoingEP, ok := e.protocol.getEndpointForNIC(r.NICID())
	if !ok {
		sent.dropped.Increment()
		return
	}

	replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
	replyIPHdrView := buffer.NewView(int(replyHeaderLength))
	replyIPHdrView.Write(ipHdr[:header.IPv4MinimumSize])
	replyIPHdrView.Write(newOptions)
	replyIPHdr := header.IPv4(replyIPHdrView.AsSlice())
	replyIPHdr.SetHeaderLength(replyHeaderLength)
	replyIPHdr.SetSourceAddress(r.LocalAddress())
	replyIPHdr.SetDestinationAddress(r.RemoteAddress())
	replyIPHdr.SetTTL(r.DefaultTTL())
	replyIPHdr.SetTotalLength(uint16(len(replyIPHdr) + len(replyData.AsSlice())))
	replyIPHdr.SetChecksum(0)
	replyIPHdr.SetChecksum(^replyIPHdr.CalculateChecksum())

	replyICMPHdr := header.ICMPv4(replyData.AsSlice())
	replyICMPHdr.SetType(header.ICMPv4EchoReply)
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyIPHdrView)
	replyBuf.Append(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()
	if ok := parse.IPv4(replyPkt); !ok {
		panic("expected to parse IPv4 header we just created")
	}
	if ok := parse.ICMPv4(replyPkt); !ok {
		panic("expected to parse ICMPv4 header we just created")
	}

	if err := outgoingEP.writePacket(r, replyPkt); err != nil {
		sent.dropped.Increment()
		return
	}
	sent.echoReply.Increment()
}


type icmpReason interface {
	isICMPReason()
}

type icmpReasonNetworkProhibited struct{}

func (*icmpReasonNetworkProhibited) isICMPReason() {}

type icmpReasonHostProhibited struct{}

func (*icmpReasonHostProhibited) isICMPReason() {}

type icmpReasonAdministrativelyProhibited struct{}

func (*icmpReasonAdministrativelyProhibited) isICMPReason() {}

type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}

type icmpReasonProtoUnreachable struct{}

func (*icmpReasonProtoUnreachable) isICMPReason() {}

type icmpReasonTTLExceeded struct{}

func (*icmpReasonTTLExceeded) isICMPReason() {}

type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}

type icmpReasonParamProblem struct {
	pointer byte
}

func (*icmpReasonParamProblem) isICMPReason() {}

type icmpReasonNetworkUnreachable struct{}

func (*icmpReasonNetworkUnreachable) isICMPReason() {}

type icmpReasonFragmentationNeeded struct {
	mtu uint32
}

func (*icmpReasonFragmentationNeeded) isICMPReason() {}

type icmpReasonHostUnreachable struct{}

func (*icmpReasonHostUnreachable) isICMPReason() {}

func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer, deliveredLocally bool) tcpip.Error {
	origIPHdr := header.IPv4(pkt.NetworkHeader().Slice())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(origIPHdrDst) || origIPHdrSrc == header.IPv4Any {
		return nil
	}

	localAddr := origIPHdrDst
	if !deliveredLocally {
		localAddr = tcpip.Address{}
	}

	route, err := p.stack.FindRoute(pkt.NICID, localAddr, origIPHdrSrc, ProtocolNumber, false)
	if err != nil {
		return err
	}
	defer route.Release()

	p.mu.Lock()
	netEP, ok := p.eps[route.NICID()]
	p.mu.Unlock()
	if !ok {
		return &tcpip.ErrNotConnected{}
	}

	transportHeader := pkt.TransportHeader().Slice()

	if origIPHdr.Protocol() == uint8(header.ICMPv4ProtocolNumber) {
		if len(transportHeader) < header.ICMPv4MinimumSize {
			return nil
		}
		switch header.ICMPv4(transportHeader).Type() {
		case
			header.ICMPv4EchoReply,
			header.ICMPv4Echo,
			header.ICMPv4Timestamp,
			header.ICMPv4TimestampReply,
			header.ICMPv4InfoRequest,
			header.ICMPv4InfoReply:
		default:
			return nil
		}
	}

	sent := netEP.stats.icmp.packetsSent
	icmpType, icmpCode, counter, pointer, nextHopMTU := func() (header.ICMPv4Type, header.ICMPv4Code, tcpip.MultiCounterStat, byte, uint16) {
		switch reason := reason.(type) {
		case *icmpReasonNetworkProhibited:
			return header.ICMPv4DstUnreachable, header.ICMPv4NetProhibited, sent.dstUnreachable, 0, 0
		case *icmpReasonHostProhibited:
			return header.ICMPv4DstUnreachable, header.ICMPv4HostProhibited, sent.dstUnreachable, 0, 0
		case *icmpReasonAdministrativelyProhibited:
			return header.ICMPv4DstUnreachable, header.ICMPv4AdminProhibited, sent.dstUnreachable, 0, 0
		case *icmpReasonPortUnreachable:
			return header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable, sent.dstUnreachable, 0, 0
		case *icmpReasonProtoUnreachable:
			return header.ICMPv4DstUnreachable, header.ICMPv4ProtoUnreachable, sent.dstUnreachable, 0, 0
		case *icmpReasonNetworkUnreachable:
			return header.ICMPv4DstUnreachable, header.ICMPv4NetUnreachable, sent.dstUnreachable, 0, 0
		case *icmpReasonHostUnreachable:
			return header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable, sent.dstUnreachable, 0, 0
		case *icmpReasonFragmentationNeeded:
			mtu := reason.mtu
			if mtu > math.MaxUint16 {
				mtu = math.MaxUint16
			}
			return header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, sent.dstUnreachable, 0, uint16(mtu)
		case *icmpReasonTTLExceeded:
			return header.ICMPv4TimeExceeded, header.ICMPv4TTLExceeded, sent.timeExceeded, 0, 0
		case *icmpReasonReassemblyTimeout:
			return header.ICMPv4TimeExceeded, header.ICMPv4ReassemblyTimeout, sent.timeExceeded, 0, 0
		case *icmpReasonParamProblem:
			return header.ICMPv4ParamProblem, header.ICMPv4UnusedCode, sent.paramProblem, reason.pointer, 0
		default:
			panic(fmt.Sprintf("unsupported ICMP type %T", reason))
		}
	}()

	if !p.allowICMPReply(icmpType, icmpCode) {
		sent.rateLimited.Increment()
		return nil
	}

	mtu := int(route.MTU())
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize

	if available < len(origIPHdr)+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}

	payloadLen := len(origIPHdr) + len(transportHeader) + pkt.Data().Size()
	if payloadLen > available {
		payloadLen = available
	}


	payload := buffer.MakeWithView(pkt.NetworkHeader().View())
	payload.Append(pkt.TransportHeader().View())
	if dataCap := payloadLen - int(payload.Size()); dataCap > 0 {
		buf := pkt.Data().ToBuffer()
		buf.Truncate(int64(dataCap))
		payload.Merge(&buf)
	} else {
		payload.Truncate(int64(payloadLen))
	}

	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            payload,
	})
	defer icmpPkt.DecRef()

	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetType(icmpType)
	icmpHdr.SetPointer(pointer)
	icmpHdr.SetMTU(nextHopMTU)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data().Checksum()))

	if err := route.WritePacket(
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		icmpPkt,
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

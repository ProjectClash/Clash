// Copyright 2026 The gVisor Authors.
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

package ip

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

func ipv6FragmentOffset(pkt *stack.PacketBuffer, ipHdr header.IPv6) (uint16, bool) {
	if !header.IsExtensionHeader(ipHdr.NextHeader()) {
		return 0, false
	}

	netHeaderSlice := pkt.NetworkHeader().Slice()
	if len(netHeaderSlice) <= header.IPv6MinimumSize {
		return 0, false
	}

	buf := buffer.MakeWithData(netHeaderSlice[header.IPv6MinimumSize:])
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), buf)
	defer it.Release()

	for {
		extHdr, done, err := it.Next()
		if err != nil || done {
			break
		}
		switch extHdr := extHdr.(type) {
		case header.IPv6FragmentExtHdr:
			offset := extHdr.FragmentOffset()
			extHdr.Release()
			return offset, true
		default:
			extHdr.Release()
		}
	}

	return 0, false
}

func buildResetPayloadV4(ttl uint8, src, dst tcpip.Address, tcpHdr header.TCP, seq, ack uint32, flags header.TCPFlags) *buffer.View {
	totalHdrLen := header.IPv4MinimumSize + header.TCPMinimumSize
	v := buffer.NewViewSize(totalHdrLen)
	buf := v.AsSlice()

	rstIPHdr := header.IPv4(buf[:header.IPv4MinimumSize])
	rstIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalHdrLen),
		TTL:         ttl,
		Protocol:    uint8(header.TCPProtocolNumber),
		TOS:         stack.DefaultTOS,
		Flags:       header.IPv4FlagDontFragment,
		SrcAddr: dst,
		DstAddr: src,
	})

	rstTCPHdr := header.TCP(buf[header.IPv4MinimumSize:])
	rstTCPHdr.Encode(&header.TCPFields{
		SrcPort:    tcpHdr.DestinationPort(),
		DstPort:    tcpHdr.SourcePort(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
	})

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, dst, src, header.TCPMinimumSize)
	rstTCPHdr.SetChecksum(0)
	rstTCPHdr.SetChecksum(^rstTCPHdr.CalculateChecksum(xsum))

	return v
}

func buildResetPayloadV6(hopLimit uint8, src, dst tcpip.Address, tcpHdr header.TCP, seq, ack uint32, flags header.TCPFlags) *buffer.View {
	totalHdrLen := header.IPv6MinimumSize + header.TCPMinimumSize
	v := buffer.NewViewSize(totalHdrLen)
	buf := v.AsSlice()

	rstIPHdr := header.IPv6(buf[:header.IPv6MinimumSize])
	rstIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr: dst,
		DstAddr: src,
	})

	rstTCPHdr := header.TCP(buf[header.IPv6MinimumSize:])
	rstTCPHdr.Encode(&header.TCPFields{
		SrcPort:    tcpHdr.DestinationPort(),
		DstPort:    tcpHdr.SourcePort(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
	})

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, dst, src, header.TCPMinimumSize)
	rstTCPHdr.SetChecksum(0)
	rstTCPHdr.SetChecksum(^rstTCPHdr.CalculateChecksum(xsum))

	return v
}

func RejectWithTCPReset(pkt *stack.PacketBuffer, netProto tcpip.NetworkProtocolNumber, stk *stack.Stack, deliveredLocally bool) tcpip.Error {
	var src, dst tcpip.Address
	var ttl uint8
	isFragment := false

	switch netProto {
	case header.IPv4ProtocolNumber:
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		if len(ipHdr) < header.IPv4MinimumSize {
			return nil
		}
		if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
			return nil
		}
		if ipHdr.FragmentOffset() != 0 {
			return nil
		}
		isFragment = ipHdr.More()
		src = ipHdr.SourceAddress()
		dst = ipHdr.DestinationAddress()

		if header.IsV4MulticastAddress(dst) ||
			header.IsV4MulticastAddress(src) ||
			pkt.NetworkPacketInfo.LocalAddressBroadcast ||
			pkt.PktType == tcpip.PacketBroadcast || pkt.PktType == tcpip.PacketMulticast ||
			src == header.IPv4Any || dst == header.IPv4Any {
			return nil
		}

	case header.IPv6ProtocolNumber:
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		if len(ipHdr) < header.IPv6MinimumSize {
			return nil
		}
		fragOffset, ok := ipv6FragmentOffset(pkt, ipHdr)
		if ok && fragOffset != 0 {
			return nil
		}
		isFragment = ok
		src = ipHdr.SourceAddress()
		dst = ipHdr.DestinationAddress()

		if header.IsV6MulticastAddress(src) || header.IsV6MulticastAddress(dst) ||
			header.IsV4MappedAddress(src) || header.IsV4MappedAddress(dst) ||
			src == header.IPv6Any || dst == header.IPv6Any ||
			pkt.PktType == tcpip.PacketBroadcast || pkt.PktType == tcpip.PacketMulticast {
			return nil
		}

	default:
		return nil
	}

	tcpHdr := func(pkt *stack.PacketBuffer) header.TCP {
		transportHdr := pkt.TransportHeader().Slice()
		if len(transportHdr) >= header.TCPMinimumSize {
			return header.TCP(transportHdr)
		}
		if len(transportHdr) != 0 {
			return nil
		}
		b, ok := pkt.Data().PullUp(header.TCPMinimumSize)
		if !ok {
			return nil
		}
		hdr := header.TCP(b)
		hdrLen := int(hdr.DataOffset())
		if hdrLen < header.TCPMinimumSize || pkt.Data().Size() < hdrLen {
			return nil
		}
		tcpHdr, ok := pkt.Data().Consume(hdrLen)
		if !ok {
			return nil
		}
		pkt.TransportProtocolNumber = header.TCPProtocolNumber
		return header.TCP(tcpHdr)
	}(pkt)
	if tcpHdr == nil {
		return nil
	}

	if tcpHdr.Flags().Contains(header.TCPFlagRst) {
		return nil
	}

	if !isFragment {
		if !pkt.RXChecksumValidated && !tcpHdr.IsChecksumValid(src, dst, pkt.Data().Checksum(), uint16(pkt.Data().Size())) {
			return nil
		}
	}

	localAddr := dst
	if !deliveredLocally {
		localAddr = tcpip.Address{}
	}

	route, err := stk.FindRoute(0, localAddr, src, netProto, false)
	if err != nil {
		return err
	}
	defer route.Release()
	ttl = route.DefaultTTL()

	var seq uint32
	var ack uint32
	payloadLen := uint32(pkt.Data().Size())
	flags := header.TCPFlagRst

	if tcpHdr.Flags()&header.TCPFlagAck != 0 {
		seq = tcpHdr.AckNumber()
	} else {
		flags |= header.TCPFlagAck
		ack = tcpHdr.SequenceNumber() + payloadLen
		if tcpHdr.Flags()&header.TCPFlagSyn != 0 {
			ack++
		}
		if tcpHdr.Flags()&header.TCPFlagFin != 0 {
			ack++
		}
	}

	var v *buffer.View
	if netProto == header.IPv4ProtocolNumber {
		v = buildResetPayloadV4(ttl, src, dst, tcpHdr, seq, ack, flags)
	} else {
		v = buildResetPayloadV6(ttl, src, dst, tcpHdr, seq, ack, flags)
	}

	rstPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithView(v),
	})
	rstPkt.TransportProtocolNumber = header.TCPProtocolNumber
	defer rstPkt.DecRef()

	if err := route.WriteHeaderIncludedPacket(rstPkt); err != nil {
		return err
	}

	return nil
}

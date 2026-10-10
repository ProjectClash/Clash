//go:build with_gvisor

package tun

import (
	"context"
	"math"
	"net/netip"
	"os"
	"sync"

	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type UDPForwarder struct {
	ctx     context.Context
	stack   *stack.Stack
	handler Handler
}

func NewUDPForwarder(ctx context.Context, stack *stack.Stack, handler Handler) *UDPForwarder {
	return &UDPForwarder{
		ctx:     ctx,
		stack:   stack,
		handler: handler,
	}
}

func (f *UDPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	var upstreamMetadata M.Metadata
	upstreamMetadata.Source = M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	upstreamMetadata.Destination = M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	proto := header.IPv6ProtocolNumber
	if upstreamMetadata.Source.IsIPv4() {
		proto = header.IPv4ProtocolNumber
	}
	if _, err := f.handler.PrepareConnection(N.NetworkUDP, upstreamMetadata.Source, upstreamMetadata.Destination, nil, 0); err != nil {
		return false
	}
	gBuffer := pkt.Data().ToBuffer()
	sBuffer := buf.NewSize(int(gBuffer.Size()))
	gBuffer.Apply(func(view *buffer.View) {
		sBuffer.Write(view.AsSlice())
	})
	f.handler.NewPacket(
		f.ctx,
		upstreamMetadata.Source.AddrPort(),
		sBuffer,
		upstreamMetadata,
		func(natConn N.PacketConn) N.PacketWriter {
			return &UDPBackWriter{
				stack:           f.stack,
				source:          id.RemoteAddress,
				sourcePort:      id.RemotePort,
				sourceNetwork:   proto,
				destination:     id.LocalAddress,
				destinationPort: id.LocalPort,
			}
		},
	)
	return true
}

type UDPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
	destination     tcpip.Address
	destinationPort uint16
}

func (w *UDPBackWriter) ReportUnreachable() error {
	if w.destination.Len() == 0 {
		return os.ErrInvalid
	}
	appAddr := AddrFromAddress(w.source)
	remoteAddr := AddrFromAddress(w.destination)
	if !udpUnreachableAnswerable(appAddr, remoteAddr) || !w.stack.AllowICMPMessage() {
		return nil
	}
	quote := udpUnreachableQuote(netip.AddrPortFrom(appAddr, w.sourcePort), netip.AddrPortFrom(remoteAddr, w.destinationPort))

	route, err := w.stack.FindRoute(DefaultNIC, w.destination, w.source, w.sourceNetwork, false)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	var (
		message  []byte
		protocol tcpip.TransportProtocolNumber
	)
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		message = make([]byte, header.ICMPv4MinimumSize+len(quote))
		icmpHdr := header.ICMPv4(message)
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4PortUnreachable)
		copy(icmpHdr.Payload(), quote)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(quote, 0)))
		protocol = header.ICMPv4ProtocolNumber
	} else {
		message = make([]byte, header.ICMPv6DstUnreachableMinimumSize+len(quote))
		icmpHdr := header.ICMPv6(message)
		icmpHdr.SetType(header.ICMPv6DstUnreachable)
		icmpHdr.SetCode(header.ICMPv6PortUnreachable)
		copy(icmpHdr.Payload(), quote)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
			Src:         route.LocalAddress(),
			Dst:         route.RemoteAddress(),
			PayloadCsum: checksum.Checksum(quote, 0),
			PayloadLen:  len(quote),
		}))
		protocol = header.ICMPv6ProtocolNumber
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(message),
	})
	defer packet.DecRef()
	packet.TransportProtocolNumber = protocol
	if err := route.WritePacket(stack.NetworkHeaderParams{
		Protocol: protocol,
		TTL:      route.DefaultTTL(),
	}, packet); err != nil {
		return gonet.TranslateNetstackError(err)
	}
	return nil
}

func (w *UDPBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		DefaultNIC,
		AddressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return gonet.TranslateNetstackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

func gWriteUnreachable(gStack *stack.Stack, packet *stack.PacketBuffer) error {
	if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler).SendRejectionError(packet, stack.RejectIPv4WithICMPPortUnreachable, true))
	} else {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler).SendRejectionError(packet, stack.RejectIPv6WithICMPPortUnreachable, true))
	}
}

package tun

import (
	"net/netip"
	"os"

	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

func (c *UDPNatConn) ReportPortUnreachable(destination M.Socksaddr) error {
	writer, isGo := c.writer.(*GoPacketConn)
	if !isGo || !destination.IsIP() {
		return os.ErrInvalid
	}
	return writer.reportPortUnreachable(destination.Addr, destination.Port)
}

func (w *GoPacketConn) reportPortUnreachable(destination netip.Addr, port uint16) error {
	var quote []byte
	udpLength := uint16(header.UDPMinimumSize)
	if w.ipVersion == 4 {
		if !destination.Is4() && !destination.Is4In6() {
			return os.ErrInvalid
		}
		template := header.IPv4(w.template[:header.IPv4MinimumSize])
		quote = make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
		ipHdr := header.IPv4(quote)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(quote)),
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     template.DestinationAddr(),
			DstAddr:     destination.Unmap(),
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		if destination.Is4() {
			destination = netip.AddrFrom16(destination.As16())
		}
		template := header.IPv6(w.template[:header.IPv6MinimumSize])
		quote = make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
		header.IPv6(quote).Encode(&header.IPv6Fields{
			PayloadLength:     udpLength,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           template.DestinationAddr(),
			DstAddr:           destination,
		})
	}
	appPort := header.UDP(w.template[w.templateLength-header.UDPMinimumSize : w.templateLength]).DestinationPort()
	header.UDP(quote[len(quote)-header.UDPMinimumSize:]).Encode(&header.UDPFields{
		SrcPort: appPort,
		DstPort: port,
		Length:  udpLength,
	})
	reply, built := BuildICMPError(quote, ICMPErrorPortUnreachable, netip.Addr{}, 0, 0)
	if !built {
		return nil
	}
	return goIgnoreDropped(w.platformIO.writePacket(reply, ForwardFrameMeta{}))
}

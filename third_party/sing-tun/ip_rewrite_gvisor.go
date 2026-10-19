//go:build with_gvisor

package tun

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

func gvisorIPRewrite(writer GVisorTun, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) bool {
	if ipRewriteTable.Load() == nil {
		return false
	}
	headerSize := header.IPv4MinimumSize
	if protocol == header.IPv6ProtocolNumber {
		headerSize = header.IPv6MinimumSize
	}
	head, ok := pkt.Data().PullUp(headerSize)
	if !ok {
		return false
	}
	destination, ok := packetDestination(head)
	if !ok || ipRewriteActionFor(destination) == 0 {
		return false
	}
	packet := pkt.Data().AsRange().ToSlice()
	handled, writeBack, reply := applyIPRewrite(packet)
	if !handled {
		return false
	}
	if writeBack {
		gvisorWriteRaw(writer, protocol, packet)
	}
	if reply != nil {
		replyProtocol := header.IPv4ProtocolNumber
		if reply[0]>>4 == 6 {
			replyProtocol = header.IPv6ProtocolNumber
		}
		gvisorWriteRaw(writer, replyProtocol, reply)
	}
	return true
}

func gvisorWriteRaw(writer GVisorTun, protocol tcpip.NetworkProtocolNumber, packet []byte) {
	out := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	out.NetworkProtocolNumber = protocol
	_, _ = writer.WritePacket(out)
	out.DecRef()
}

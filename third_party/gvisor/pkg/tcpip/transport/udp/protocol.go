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

package udp

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	ProtocolNumber = header.UDPProtocolNumber

	MinBufferSize = 4 << 10

	DefaultSendBufferSize = 32 << 10

	DefaultReceiveBufferSize = 32 << 10

	MaxBufferSize = 4 << 20
)

type protocol struct {
	stack *stack.Stack
}

func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

func (p *protocol) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return newEndpoint(p.stack, netProto, waiterQueue), nil
}

func (p *protocol) NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, netProto, header.UDPProtocolNumber, waiterQueue)
}

func (*protocol) MinimumPacketSize() int {
	return header.UDPMinimumSize
}

func (*protocol) ParsePorts(v []byte) (src, dst uint16, err tcpip.Error) {
	h := header.UDP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

func (p *protocol) HandleUnknownDestinationPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	hdr := header.UDP(pkt.TransportHeader().Slice())
	netHdr := pkt.Network()
	lengthValid, csumValid := header.UDPValid(
		hdr,
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		pkt.NetworkProtocolNumber,
		netHdr.SourceAddress(),
		netHdr.DestinationAddress(),
		pkt.RXChecksumValidated)
	if !lengthValid {
		p.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return stack.UnknownDestinationPacketMalformed
	}

	if !csumValid {
		p.stack.Stats().UDP.ChecksumErrors.Increment()
		return stack.UnknownDestinationPacketMalformed
	}

	return stack.UnknownDestinationPacketUnhandled
}

func (*protocol) SetOption(tcpip.SettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*protocol) Option(tcpip.GettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*protocol) Close() {}

func (*protocol) Wait() {}

func (*protocol) Pause() {}

func (*protocol) Resume() {}

func (*protocol) Restore() {}

func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	return parse.UDP(pkt)
}

func NewProtocol(s *stack.Stack) stack.TransportProtocol {
	return &protocol{stack: s}
}

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

package icmp

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	ProtocolNumber4 = header.ICMPv4ProtocolNumber

	ProtocolNumber6 = header.ICMPv6ProtocolNumber
)

type protocol struct {
	stack *stack.Stack

	number tcpip.TransportProtocolNumber
}

func (p *protocol) Number() tcpip.TransportProtocolNumber {
	return p.number
}

func (p *protocol) netProto() tcpip.NetworkProtocolNumber {
	switch p.number {
	case ProtocolNumber4:
		return header.IPv4ProtocolNumber
	case ProtocolNumber6:
		return header.IPv6ProtocolNumber
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

func (p *protocol) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	if netProto != p.netProto() {
		return nil, &tcpip.ErrUnknownProtocol{}
	}
	return newEndpoint(p.stack, netProto, p.number, waiterQueue)
}

func (p *protocol) NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	if netProto != p.netProto() {
		return nil, &tcpip.ErrUnknownProtocol{}
	}
	return raw.NewEndpoint(p.stack, netProto, p.number, waiterQueue)
}

func (p *protocol) MinimumPacketSize() int {
	switch p.number {
	case ProtocolNumber4:
		return header.ICMPv4MinimumSize
	case ProtocolNumber6:
		return header.ICMPv6MinimumSize
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

func (p *protocol) ParsePorts(v []byte) (src, dst uint16, err tcpip.Error) {
	switch p.number {
	case ProtocolNumber4:
		hdr := header.ICMPv4(v)
		return 0, hdr.Ident(), nil
	case ProtocolNumber6:
		hdr := header.ICMPv6(v)
		return 0, hdr.Ident(), nil
	}
	panic(fmt.Sprint("unknown protocol number: ", p.number))
}

func (*protocol) HandleUnknownDestinationPacket(stack.TransportEndpointID, *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	return stack.UnknownDestinationPacketHandled
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
	return false
}

func NewProtocol4(s *stack.Stack) stack.TransportProtocol {
	return &protocol{stack: s, number: ProtocolNumber4}
}

func NewProtocol6(s *stack.Stack) stack.TransportProtocol {
	return &protocol{stack: s, number: ProtocolNumber6}
}

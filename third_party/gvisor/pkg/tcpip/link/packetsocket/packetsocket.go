// Copyright 2022 The gVisor Authors.
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

package packetsocket

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/nested"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)

type Endpoint struct {
	nested.Endpoint
}

func New(lower stack.LinkEndpoint) stack.LinkEndpoint {
	e := &Endpoint{}
	e.Endpoint.Init(lower, e)
	return e
}

func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.Endpoint.DeliverLinkPacket(protocol, pkt)

	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		e.Endpoint.DeliverLinkPacket(pkt.NetworkProtocolNumber, pkt)
	}

	return e.Endpoint.WritePackets(pkts)
}

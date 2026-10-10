// Copyright 2019 The gVisor Authors.
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

package muxed

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type InjectableEndpoint struct {
	routes map[tcpip.Address]stack.InjectableLinkEndpoint

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
}

func (m *InjectableEndpoint) MTU() uint32 {
	minMTU := ^uint32(0)
	for _, endpoint := range m.routes {
		if endpointMTU := endpoint.MTU(); endpointMTU < minMTU {
			minMTU = endpointMTU
		}
	}
	return minMTU
}

func (m *InjectableEndpoint) SetMTU(mtu uint32) {
	for _, endpoint := range m.routes {
		endpoint.SetMTU(mtu)
	}
}

func (m *InjectableEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	minCapabilities := stack.LinkEndpointCapabilities(^uint(0))
	for _, endpoint := range m.routes {
		minCapabilities &= endpoint.Capabilities()
	}
	return minCapabilities
}

func (m *InjectableEndpoint) MaxHeaderLength() uint16 {
	minHeaderLen := ^uint16(0)
	for _, endpoint := range m.routes {
		if headerLen := endpoint.MaxHeaderLength(); headerLen < minHeaderLen {
			minHeaderLen = headerLen
		}
	}
	return minHeaderLen
}

func (m *InjectableEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (m *InjectableEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

func (m *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	for _, endpoint := range m.routes {
		endpoint.Attach(dispatcher)
	}
	m.mu.Lock()
	m.dispatcher = dispatcher
	m.mu.Unlock()
}

func (m *InjectableEndpoint) IsAttached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dispatcher != nil
}

func (m *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	m.mu.RLock()
	d := m.dispatcher
	m.mu.RUnlock()
	d.DeliverNetworkPacket(protocol, pkt)
}

func (m *InjectableEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	i := 0
	for _, pkt := range pkts.AsSlice() {
		endpoint, ok := m.routes[pkt.EgressRoute.RemoteAddress]
		if !ok {
			return i, &tcpip.ErrHostUnreachable{}
		}

		var tmpPkts stack.PacketBufferList
		tmpPkts.PushBack(pkt)

		n, err := endpoint.WritePackets(tmpPkts)
		if err != nil {
			return i, err
		}

		i += n
	}

	return i, nil
}

func (m *InjectableEndpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	endpoint, ok := m.routes[dest]
	if !ok {
		return &tcpip.ErrHostUnreachable{}
	}
	return endpoint.InjectOutbound(dest, packet)
}

func (m *InjectableEndpoint) Wait() {
	for _, ep := range m.routes {
		ep.Wait()
	}
}

func (*InjectableEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("unsupported operation")
}

func (*InjectableEndpoint) AddHeader(*stack.PacketBuffer) {}

func (*InjectableEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (*InjectableEndpoint) Close() {}

func (*InjectableEndpoint) SetOnCloseAction(func()) {}

func NewInjectableEndpoint(routes map[tcpip.Address]stack.InjectableLinkEndpoint) *InjectableEndpoint {
	return &InjectableEndpoint{
		routes: routes,
	}
}

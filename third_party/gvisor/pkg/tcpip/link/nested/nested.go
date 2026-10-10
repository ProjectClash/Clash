// Copyright 2020 The gVisor Authors.
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

package nested

import (
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type Endpoint struct {
	child    stack.LinkEndpoint
	embedder stack.NetworkDispatcher

	mu         sync.RWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
}

var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

func (e *Endpoint) Init(child stack.LinkEndpoint, embedder stack.NetworkDispatcher) {
	e.child = child
	e.embedder = embedder
}

func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (e *Endpoint) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverLinkPacket(protocol, pkt)
	}
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
	var pass stack.NetworkDispatcher
	if dispatcher != nil {
		pass = e.embedder
	}
	e.child.Attach(pass)
}

func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	isAttached := e.dispatcher != nil
	e.mu.RUnlock()
	return isAttached
}

func (e *Endpoint) MTU() uint32 {
	return e.child.MTU()
}

func (e *Endpoint) SetMTU(mtu uint32) {
	e.child.SetMTU(mtu)
}

func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.child.Capabilities()
}

func (e *Endpoint) MaxHeaderLength() uint16 {
	return e.child.MaxHeaderLength()
}

func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.child.LinkAddress()
}

func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.child.SetLinkAddress(addr)
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	return e.child.WritePackets(pkts)
}

func (e *Endpoint) Wait() {
	e.child.Wait()
}

func (e *Endpoint) GSOMaxSize() uint32 {
	if e, ok := e.child.(stack.GSOEndpoint); ok {
		return e.GSOMaxSize()
	}
	return 0
}

func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	if e, ok := e.child.(stack.GSOEndpoint); ok {
		return e.SupportedGSO()
	}
	return stack.GSONotSupported
}

func (e *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return e.child.ARPHardwareType()
}

func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {
	e.child.AddHeader(pkt)
}

func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	return e.child.ParseHeader(pkt)
}

func (e *Endpoint) Close() {
	e.child.Close()
}

func (e *Endpoint) SetOnCloseAction(action func()) {
	e.child.SetOnCloseAction(action)
}

func (e *Endpoint) Child() stack.LinkEndpoint {
	return e.child
}

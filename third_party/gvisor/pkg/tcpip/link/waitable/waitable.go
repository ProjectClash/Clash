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

package waitable

import (
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)

type Endpoint struct {
	dispatchGate sync.Gate

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher

	writeGate sync.Gate
	lower     stack.LinkEndpoint
}

func New(lower stack.LinkEndpoint) *Endpoint {
	return &Endpoint{
		lower: lower,
	}
}

func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if !e.dispatchGate.Enter() {
		return
	}
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
	e.dispatchGate.Leave()
}

func (e *Endpoint) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if !e.dispatchGate.Enter() {
		return
	}
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverLinkPacket(protocol, pkt)
	}
	e.dispatchGate.Leave()
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
	e.lower.Attach(e)
}

func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *Endpoint) MTU() uint32 {
	return e.lower.MTU()
}

func (e *Endpoint) SetMTU(mtu uint32) {
	e.lower.SetMTU(mtu)
}

func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.lower.Capabilities()
}

func (e *Endpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}

func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lower.SetLinkAddress(addr)
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if !e.writeGate.Enter() {
		return pkts.Len(), nil
	}

	n, err := e.lower.WritePackets(pkts)
	e.writeGate.Leave()
	return n, err
}

func (e *Endpoint) WaitWrite() {
	e.writeGate.Close()
}

func (e *Endpoint) WaitDispatch() {
	e.dispatchGate.Close()
}

func (e *Endpoint) Wait() {}

func (e *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return e.lower.ARPHardwareType()
}

func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {
	e.lower.AddHeader(pkt)
}

func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	return e.lower.ParseHeader(pkt)
}

func (e *Endpoint) SetOnCloseAction(action func()) {
	e.lower.SetOnCloseAction(action)
}

func (e *Endpoint) Close() {
	e.lower.Close()
}

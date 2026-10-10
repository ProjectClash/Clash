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

package loopback

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	loopbackMTU = 65536
)

type endpoint struct {
	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
	addr tcpip.LinkAddress
	mtu uint32
}

func New() stack.LinkEndpoint {
	return &endpoint{
		mtu: loopbackMTU,
	}
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

func (e *endpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilityTXChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityLoopback
}

func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addr
}

func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addr = addr
}

func (*endpoint) Wait() {}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	for _, pkt := range pkts.AsSlice() {
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: pkt.ToBuffer(),
		})
		if d != nil {
			d.DeliverNetworkPacket(pkt.NetworkProtocolNumber, newPkt)
		}
		newPkt.DecRef()
	}
	return pkts.Len(), nil
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareLoopback
}

func (*endpoint) AddHeader(*stack.PacketBuffer) {}

func (*endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (*endpoint) Close() {}

func (*endpoint) SetOnCloseAction(func()) {}

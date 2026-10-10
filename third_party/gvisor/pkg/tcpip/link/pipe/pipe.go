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

package pipe

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*Endpoint)(nil)

func New(linkAddr1, linkAddr2 tcpip.LinkAddress, mtu uint32) (*Endpoint, *Endpoint) {
	ep1 := &Endpoint{
		linkAddr: linkAddr1,
		mtu:      mtu,
	}
	ep2 := &Endpoint{
		linkAddr: linkAddr2,
		mtu:      mtu,
	}
	ep1.linked = ep2
	ep2.linked = ep1
	return ep1, ep2
}

type Endpoint struct {
	linked *Endpoint

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
	linkAddr tcpip.LinkAddress
	mtu uint32
}

func (e *Endpoint) deliverPackets(pkts stack.PacketBufferList) {
	e.linked.mu.RLock()
	d := e.linked.dispatcher
	e.linked.mu.RUnlock()
	if d == nil {
		return
	}

	for _, pkt := range pkts.AsSlice() {
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: pkt.ToBuffer(),
		})
		d.DeliverNetworkPacket(pkt.NetworkProtocolNumber, newPkt)
		newPkt.DecRef()
	}
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := pkts.Len()
	e.deliverPackets(pkts)
	return n, nil
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (*Endpoint) Wait() {}

func (e *Endpoint) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

func (e *Endpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

func (*Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkAddr
}

func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (*Endpoint) AddHeader(*stack.PacketBuffer) {}

func (*Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *Endpoint) Close() {}

func (*Endpoint) SetOnCloseAction(func()) {}

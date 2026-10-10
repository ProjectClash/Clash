// Copyright 2024 The gVisor Authors.
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

package veth

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const DefaultBacklogSize = 1000

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

type veth struct {
	mu           vethRWMutex `state:"nosave"`
	closed       bool
	backlogQueue chan vethPacket `state:"nosave"`
	mtu          uint32
	endpoints    [2]Endpoint
}

func (v *veth) close() {
	v.mu.Lock()
	closed := v.closed
	v.closed = true
	v.mu.Unlock()
	if closed {
		return
	}

	for i := range v.endpoints {
		e := &v.endpoints[i]
		e.mu.Lock()
		action := e.onCloseAction
		e.onCloseAction = nil
		e.mu.Unlock()
		if action != nil {
			action()
		}
	}
	close(v.backlogQueue)
}

type vethPacket struct {
	e        *Endpoint
	protocol tcpip.NetworkProtocolNumber
	pkt      *stack.PacketBuffer
}

type Endpoint struct {
	peer *Endpoint

	veth *veth

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
	linkAddr tcpip.LinkAddress
	onCloseAction func() `state:"nosave"`
}

func NewPair(mtu, backlogQueueSize uint32) (*Endpoint, *Endpoint) {
	veth := veth{
		backlogQueue: make(chan vethPacket, backlogQueueSize),
		mtu:          mtu,
		endpoints: [2]Endpoint{
			{
				linkAddr: tcpip.GetRandMacAddr(),
			},
			{
				linkAddr: tcpip.GetRandMacAddr(),
			},
		},
	}
	a := &veth.endpoints[0]
	b := &veth.endpoints[1]
	a.peer = b
	b.peer = a
	a.veth = &veth
	b.veth = &veth
	go func() {
		for t := range veth.backlogQueue {
			t.e.InjectInbound(t.protocol, t.pkt)
			t.pkt.DecRef()
		}

	}()
	return a, b
}

func (e *Endpoint) Close() {
	e.veth.close()
}

func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
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

func (e *Endpoint) MTU() uint32 {
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()
	return e.veth.mtu
}

func (e *Endpoint) SetMTU(mtu uint32) {
	e.veth.mu.Lock()
	defer e.veth.mu.Unlock()
	e.veth.mtu = mtu
}

func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityTXChecksumOffload
}

func (*Endpoint) GSOMaxSize() uint32 {
	return stack.GVisorGSOMaxSize
}

func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GVisorGSOSupported
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

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()

	if e.veth.closed {
		return 0, nil
	}

	n := 0
	for _, pkt := range pkts.AsSlice() {
		payload := pkt.ToBuffer()
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload.DeepClone(),
		})
		payload.Release()
		select {
		case (e.veth.backlogQueue) <- vethPacket{
			e:        e.peer,
			protocol: pkt.NetworkProtocolNumber,
			pkt:      newPkt,
		}:
			n++
		default:
			newPkt.DecRef()
			return n, &tcpip.ErrNoBufferSpace{}
		}
	}
	return n, nil
}

func (*Endpoint) Wait() {}

func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {}

func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }

func (e *Endpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onCloseAction = action
}

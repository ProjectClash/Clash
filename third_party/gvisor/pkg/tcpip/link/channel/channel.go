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

package channel

import (
	"context"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type Notification interface {
	WriteNotify()
}

type NotificationHandle struct {
	n Notification
}

type queue struct {
	c  chan *stack.PacketBuffer
	mu queueRWMutex
	notify []*NotificationHandle
	closed bool
}

func (q *queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		close(q.c)
	}
	q.closed = true
}

func (q *queue) Read() *stack.PacketBuffer {
	select {
	case p := <-q.c:
		return p
	default:
		return nil
	}
}

func (q *queue) ReadContext(ctx context.Context) *stack.PacketBuffer {
	select {
	case pkt := <-q.c:
		return pkt
	case <-ctx.Done():
		return nil
	}
}

func (q *queue) Write(pkt *stack.PacketBuffer) tcpip.Error {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return &tcpip.ErrClosedForSend{}
	}

	wrote := false
	p := pkt.Clone()
	select {
	case q.c <- p:
		wrote = true
	default:
		p.DecRef()
	}
	notify := q.notify
	q.mu.RUnlock()

	if wrote {
		for _, h := range notify {
			h.n.WriteNotify()
		}
		return nil
	}
	return &tcpip.ErrNoBufferSpace{}
}

func (q *queue) Num() int {
	return len(q.c)
}

func (q *queue) AddNotify(notify Notification) *NotificationHandle {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := &NotificationHandle{n: notify}
	q.notify = append(q.notify, h)
	return h
}

func (q *queue) RemoveNotify(handle *NotificationHandle) {
	q.mu.Lock()
	defer q.mu.Unlock()
	notify := make([]*NotificationHandle, 0, len(q.notify))
	for _, h := range q.notify {
		if h != handle {
			notify = append(notify, h)
		}
	}
	q.notify = notify
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

type Endpoint struct {
	LinkEPCapabilities stack.LinkEndpointCapabilities
	SupportedGSOKind   stack.SupportedGSO

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
	linkAddr tcpip.LinkAddress
	mtu uint32

	q *queue
}

func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) *Endpoint {
	return &Endpoint{
		q: &queue{
			c: make(chan *stack.PacketBuffer, size),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}

func (e *Endpoint) Close() {
	e.q.Close()
	e.Drain()
}

func (e *Endpoint) Read() *stack.PacketBuffer {
	return e.q.Read()
}

func (e *Endpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	return e.q.ReadContext(ctx)
}

func (e *Endpoint) Drain() int {
	c := 0
	for pkt := e.Read(); pkt != nil; pkt = e.Read() {
		pkt.DecRef()
		c++
	}
	return c
}

func (e *Endpoint) NumQueued() int {
	return e.q.Num()
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
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

func (e *Endpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEPCapabilities
}

func (*Endpoint) GSOMaxSize() uint32 {
	return 1 << 15
}

func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	return e.SupportedGSOKind
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
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if err := e.q.Write(pkt); err != nil {
			if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok && n == 0 {
				return 0, err
			}
			break
		}
		n++
	}

	return n, nil
}

func (*Endpoint) Wait() {}

func (e *Endpoint) AddNotify(notify Notification) *NotificationHandle {
	return e.q.AddNotify(notify)
}

func (e *Endpoint) RemoveNotify(handle *NotificationHandle) {
	e.q.RemoveNotify(handle)
}

func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (*Endpoint) AddHeader(*stack.PacketBuffer) {}

func (*Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (*Endpoint) SetOnCloseAction(func()) {}

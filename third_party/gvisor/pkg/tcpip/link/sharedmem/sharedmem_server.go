// Copyright 2021 The gVisor Authors.
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

//go:build linux
// +build linux

package sharedmem

import (
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type serverEndpoint struct {
	bufferSize uint32

	rx serverRx

	stopRequested atomicbitops.Uint32

	completed sync.WaitGroup `state:"nosave"`

	peerFD int

	caps stack.LinkEndpointCapabilities

	hdrSize uint32

	virtioNetHeaderRequired bool

	onClosed func(tcpip.Error) `state:"nosave"`

	mu serverEndpointRWMutex `state:"nosave"`

	tx serverTx

	workerStarted bool

	addr tcpip.LinkAddress
	mtu uint32
}

func NewServerEndpoint(opts Options) (stack.LinkEndpoint, error) {
	e := &serverEndpoint{
		mtu:        opts.MTU,
		bufferSize: opts.BufferSize,
		addr:       opts.LinkAddress,
		peerFD:     opts.PeerFD,
		onClosed:   opts.OnClosed,
	}

	if err := e.tx.init(&opts.RX); err != nil {
		return nil, err
	}

	if err := e.rx.init(&opts.TX); err != nil {
		e.tx.cleanup()
		return nil, err
	}

	e.caps = stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		e.caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		e.caps |= stack.CapabilityTXChecksumOffload
	}

	if opts.LinkAddress != "" {
		e.hdrSize = header.EthernetMinimumSize
		e.caps |= stack.CapabilityResolutionRequired
	}

	return e, nil
}

func (*serverEndpoint) SetOnCloseAction(func()) {}

func (e *serverEndpoint) Close() {
	e.stopRequested.Store(1)
	e.rx.eventFD.Notify()

	e.mu.Lock()
	defer e.mu.Unlock()
	workerPresent := e.workerStarted

	if !workerPresent {
		e.tx.cleanup()
		e.rx.cleanup()
	}
}

func (e *serverEndpoint) Wait() {
	e.completed.Wait()
}

func (e *serverEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if !e.workerStarted && e.stopRequested.Load() == 0 {
		e.workerStarted = true
		e.completed.Add(1)
		if e.peerFD >= 0 {
			e.completed.Add(1)
			go func() {
				b := make([]byte, 1)
				_, errno := rawfile.BlockingRead(e.peerFD, b)
				if e.onClosed != nil {
					if errno == 0 {
						e.onClosed(nil)
					} else {
						e.onClosed(tcpip.TranslateErrno(errno))
					}
				}
				e.completed.Done()
			}()
		}
		go e.dispatchLoop(dispatcher)
	}
	e.mu.Unlock()
}

func (e *serverEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
}

func (e *serverEndpoint) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

func (e *serverEndpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

func (e *serverEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

func (e *serverEndpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

func (e *serverEndpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addr
}

func (e *serverEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addr = addr
}

func (e *serverEndpoint) AddHeader(pkt *stack.PacketBuffer) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.addr) == 0 {
		return
	}

	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

func (e *serverEndpoint) parseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (e *serverEndpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.addr) == 0 {
		return true
	}

	return e.parseHeader(pkt)
}

func (e *serverEndpoint) AddVirtioNetHeader(pkt *stack.PacketBuffer) {
	virtio := header.VirtioNetHeader(pkt.VirtioNetHeader().Push(header.VirtioNetHeaderSize))
	virtio.Encode(&header.VirtioNetHeaderFields{})
}

func (e *serverEndpoint) writePacketLocked(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if e.virtioNetHeaderRequired {
		e.AddVirtioNetHeader(pkt)
	}

	ok := e.tx.transmit(pkt)
	if !ok {
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

func (e *serverEndpoint) WritePacket(_ stack.RouteInfo, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.writePacketLocked(pkt.EgressRoute, pkt.NetworkProtocolNumber, pkt); err != nil {
		return err
	}
	e.tx.notify()
	return nil
}

func (e *serverEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	var err tcpip.Error
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, pkt := range pkts.AsSlice() {
		if err = e.writePacketLocked(pkt.EgressRoute, pkt.NetworkProtocolNumber, pkt); err != nil {
			break
		}
		n++
	}
	if err != nil && n == 0 {
		return 0, err
	}
	e.tx.notify()
	return n, nil
}

func (e *serverEndpoint) dispatchLoop(d stack.NetworkDispatcher) {
	for e.stopRequested.Load() == 0 {
		b := e.rx.receive()
		if b == nil {
			e.rx.EnableNotification()
			for {
				b = e.rx.receive()
				if b != nil {
					e.rx.DisableNotification()
					break
				}
				e.rx.waitForPackets()
			}
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(b),
		})
		if e.virtioNetHeaderRequired {
			_, ok := pkt.VirtioNetHeader().Consume(header.VirtioNetHeaderSize)
			if !ok {
				pkt.DecRef()
				continue
			}
		}
		var proto tcpip.NetworkProtocolNumber
		e.mu.RLock()
		addrLen := len(e.addr)
		e.mu.RUnlock()
		if addrLen != 0 {
			if !e.parseHeader(pkt) {
				pkt.DecRef()
				continue
			}
			proto = header.Ethernet(pkt.LinkHeader().Slice()).Type()
		} else {
			h, ok := pkt.Data().PullUp(1)
			if !ok {
				pkt.DecRef()
				continue
			}
			switch header.IPVersion(h) {
			case header.IPv4Version:
				proto = header.IPv4ProtocolNumber
			case header.IPv6Version:
				proto = header.IPv6ProtocolNumber
			default:
				pkt.DecRef()
				continue
			}
		}
		d.DeliverNetworkPacket(proto, pkt)
		pkt.DecRef()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.tx.cleanup()
	e.rx.cleanup()

	e.completed.Done()
}

func (e *serverEndpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

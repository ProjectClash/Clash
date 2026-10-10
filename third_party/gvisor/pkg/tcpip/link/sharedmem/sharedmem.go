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

//go:build linux
// +build linux

package sharedmem

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/eventfd"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/queue"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type QueueConfig struct {
	DataFD int

	EventFD eventfd.Eventfd

	TxPipeFD int

	RxPipeFD int

	SharedDataFD int
}

func (q *QueueConfig) FDs() []int {
	return []int{q.DataFD, q.EventFD.FD(), q.TxPipeFD, q.RxPipeFD, q.SharedDataFD}
}

func QueueConfigFromFDs(fds []int) (QueueConfig, error) {
	if len(fds) != 5 {
		return QueueConfig{}, fmt.Errorf("insufficient number of fds: len(fds): %d, want: 5", len(fds))
	}
	return QueueConfig{
		DataFD:       fds[0],
		EventFD:      eventfd.Wrap(fds[1]),
		TxPipeFD:     fds[2],
		RxPipeFD:     fds[3],
		SharedDataFD: fds[4],
	}, nil
}

type Options struct {
	MTU uint32

	BufferSize uint32

	LinkAddress tcpip.LinkAddress

	TX QueueConfig

	RX QueueConfig

	PeerFD int

	OnClosed func(err tcpip.Error)

	TXChecksumOffload bool

	RXChecksumOffload bool

	VirtioNetHeaderRequired bool

	GSOMaxSize uint32
}

var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.GSOEndpoint = (*endpoint)(nil)

type endpoint struct {
	bufferSize uint32

	peerFD int

	caps stack.LinkEndpointCapabilities

	hdrSize uint32

	gsoMaxSize uint32

	virtioNetHeaderRequired bool

	rx rx

	stopRequested atomicbitops.Uint32

	completed sync.WaitGroup

	onClosed func(tcpip.Error) `state:"nosave"`

	mu endpointRWMutex `state:"nosave"`

	tx tx

	workerStarted bool

	addr tcpip.LinkAddress
	mtu uint32
}

func New(opts Options) (stack.LinkEndpoint, error) {
	e := &endpoint{
		mtu:                     opts.MTU,
		bufferSize:              opts.BufferSize,
		addr:                    opts.LinkAddress,
		peerFD:                  opts.PeerFD,
		onClosed:                opts.OnClosed,
		virtioNetHeaderRequired: opts.VirtioNetHeaderRequired,
		gsoMaxSize:              opts.GSOMaxSize,
	}

	if err := e.tx.init(opts.BufferSize, &opts.TX); err != nil {
		return nil, err
	}

	if err := e.rx.init(opts.BufferSize, &opts.RX); err != nil {
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

	if opts.VirtioNetHeaderRequired {
		e.hdrSize += header.VirtioNetHeaderSize
	}

	return e, nil
}

func (e *endpoint) SetOnCloseAction(func()) {}

func (e *endpoint) Close() {
	if e.stopRequested.Swap(1) == 1 {
		return
	}
	e.rx.eventFD.Notify()

	e.mu.Lock()
	defer e.mu.Unlock()
	workerPresent := e.workerStarted

	if !workerPresent {
		e.tx.cleanup()
		e.rx.cleanup()
	}
}

func (e *endpoint) Wait() {
	e.completed.Wait()
	e.rx.eventFD.Close()
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.Close()
		return
	}
	e.mu.Lock()
	if !e.workerStarted && e.stopRequested.Load() == 0 {
		e.workerStarted = true
		e.completed.Add(1)

		if e.peerFD >= 0 {
			e.completed.Add(1)
			go func() {
				defer e.completed.Done()
				b := make([]byte, 1)
				_, errno := rawfile.BlockingRead(e.peerFD, b)
				if e.onClosed != nil {
					if errno == 0 {
						e.onClosed(nil)
					} else {
						e.onClosed(tcpip.TranslateErrno(errno))
					}
				}
			}()
		}

		go e.dispatchLoop(dispatcher)
	}
	e.mu.Unlock()
}

func (e *endpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
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

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
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

func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {
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

func (e *endpoint) parseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (e *endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.addr) == 0 {
		return true
	}

	return e.parseHeader(pkt)
}

func (e *endpoint) AddVirtioNetHeader(pkt *stack.PacketBuffer) {
	virtio := header.VirtioNetHeader(pkt.VirtioNetHeader().Push(header.VirtioNetHeaderSize))
	virtio.Encode(&header.VirtioNetHeaderFields{})
}

func (e *endpoint) writePacketLocked(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if e.virtioNetHeaderRequired {
		e.AddVirtioNetHeader(pkt)
	}

	b := pkt.ToBuffer()
	defer b.Release()
	ok := e.tx.transmit(b)
	if !ok {
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
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

func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) {
	limit := e.rx.q.PostedBuffersLimit()
	if l := uint64(len(e.rx.data)) / uint64(e.bufferSize); limit > l {
		limit = l
	}
	for i := uint64(0); i < limit; i++ {
		b := queue.RxBuffer{
			Offset: i * uint64(e.bufferSize),
			Size:   e.bufferSize,
			ID:     i,
		}
		if !e.rx.q.PostBuffers([]queue.RxBuffer{b}) {
			log.Warningf("Unable to post %v-th buffer", i)
		}
	}

	var rxb []queue.RxBuffer
	for e.stopRequested.Load() == 0 {
		var n uint32
		rxb, n = e.rx.postAndReceive(rxb, &e.stopRequested)

		v := buffer.NewView(int(n))
		v.Grow(int(n))
		offset := uint32(0)
		for i := range rxb {
			v.WriteAt(e.rx.data[rxb[i].Offset:][:rxb[i].Size], int(offset))
			offset += rxb[i].Size

			rxb[i].Size = e.bufferSize
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(v),
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

func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (e *endpoint) GSOMaxSize() uint32 {
	return e.gsoMaxSize
}

func (e *endpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GVisorGSOSupported
}

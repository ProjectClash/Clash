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

package xdp

import (
	"fmt"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/metacubex/gvisor/pkg/tcpip/link/stopfd"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/xdp"
)


const MTU = 1500

var _ stack.LinkEndpoint = (*endpoint)(nil)

type endpoint struct {
	fd int

	caps stack.LinkEndpointCapabilities

	closed func(tcpip.Error) `state:"nosave"`

	mu endpointRWMutex `state:"nosave"`
	networkDispatcher stack.NetworkDispatcher

	wg sync.WaitGroup `state:"nosave"`

	control *xdp.ControlBlock

	stopFD stopfd.StopFD

	addr tcpip.LinkAddress
}

type Options struct {
	FD int

	ClosedFunc func(tcpip.Error)

	Address tcpip.LinkAddress

	SaveRestore bool

	TXChecksumOffload bool

	RXChecksumOffload bool

	InterfaceIndex int

	Bind bool

	GRO bool

	QueueID uint32
}

func New(opts *Options) (stack.LinkEndpoint, error) {
	caps := stack.CapabilityResolutionRequired
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if err := unix.SetNonblock(opts.FD, true); err != nil {
		return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", opts.FD, err)
	}

	ep := &endpoint{
		fd:     opts.FD,
		caps:   caps,
		closed: opts.ClosedFunc,
		addr:   opts.Address,
	}

	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	ep.stopFD = stopFD

	const (
		frameSize = 2048
		umemSize  = 1 << 21
		nFrames   = umemSize / frameSize
	)
	xdpOpts := xdp.Opts{
		NFrames:      nFrames,
		FrameSize:    frameSize,
		NDescriptors: nFrames / 2,
		Bind:         opts.Bind,
	}
	ep.control, err = xdp.NewFromSocket(opts.FD, uint32(opts.InterfaceIndex), opts.QueueID, xdpOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP dispatcher: %v", err)
	}

	ep.control.UMEM.Lock()
	defer ep.control.UMEM.Unlock()

	ep.control.Fill.FillAll(&ep.control.UMEM)

	return ep, nil
}

func (ep *endpoint) Attach(networkDispatcher stack.NetworkDispatcher) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if networkDispatcher == nil && ep.IsAttached() {
		ep.stopFD.Stop()
		ep.Wait()
		ep.networkDispatcher = nil
		return
	}
	if networkDispatcher != nil && ep.networkDispatcher == nil {
		ep.networkDispatcher = networkDispatcher
		ep.wg.Add(1)
		go func() {
			defer ep.wg.Done()
			for {
				cont, err := ep.dispatch()
				if err != nil || !cont {
					if ep.closed != nil {
						ep.closed(err)
					}
					return
				}
			}
		}()
	}
}

func (ep *endpoint) IsAttached() bool {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.networkDispatcher != nil
}

func (ep *endpoint) MTU() uint32 {
	return MTU
}

func (*endpoint) SetMTU(uint32) {}

func (ep *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return ep.caps
}

func (ep *endpoint) MaxHeaderLength() uint16 {
	return uint16(header.EthernetMinimumSize)
}

func (ep *endpoint) LinkAddress() tcpip.LinkAddress {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.addr
}

func (ep *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.addr = addr
}

func (ep *endpoint) Wait() {
	ep.wg.Wait()
}

func (ep *endpoint) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

func (ep *endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (ep *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (ep *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var preallocatedBatch [fifo.BatchSize]unix.XDPDesc
	batch := preallocatedBatch[:0]

	ep.control.UMEM.Lock()

	ep.control.Completion.FreeAll(&ep.control.UMEM)

	nReserved, index := ep.control.TX.Reserve(&ep.control.UMEM, uint32(pkts.Len()))
	if nReserved == 0 {
		ep.control.UMEM.Unlock()
		return 0, &tcpip.ErrNoBufferSpace{}
	}

	for _, pkt := range pkts.AsSlice() {
		batch = append(batch, unix.XDPDesc{
			Addr: ep.control.UMEM.AllocFrame(),
			Len:  uint32(pkt.Size()),
		})
	}

	for i, pkt := range pkts.AsSlice() {
		frame := ep.control.UMEM.Get(batch[i])
		offset := 0
		var view *buffer.View
		views, pktOffset := pkt.AsViewList()
		for view = views.Front(); view != nil && pktOffset >= view.Size(); view = view.Next() {
			pktOffset -= view.Size()
		}
		offset += copy(frame[offset:], view.AsSlice()[pktOffset:])
		for view = view.Next(); view != nil; view = view.Next() {
			offset += copy(frame[offset:], view.AsSlice())
		}
		ep.control.TX.Set(index+uint32(i), batch[i])
	}

	ep.control.TX.Notify()

	ep.control.UMEM.Unlock()

	return pkts.Len(), nil
}

func (ep *endpoint) dispatch() (bool, tcpip.Error) {
	var views []*buffer.View

	for {
		stopped, errno := rawfile.BlockingPollUntilStopped(ep.stopFD.EFD, ep.fd, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return !stopped, tcpip.TranslateErrno(errno)
		}
		if stopped {
			return true, nil
		}

		for {
			nReceived, rxIndex := ep.control.RX.Peek()

			if nReceived == 0 {
				break
			}

			views = views[:0]

			ep.control.UMEM.Lock()
			for i := uint32(0); i < nReceived; i++ {
				descriptor := ep.control.RX.Get(rxIndex + i)
				data := ep.control.UMEM.Get(descriptor)
				view := buffer.NewView(len(data))
				view.Write(data)
				views = append(views, view)
				ep.control.UMEM.FreeFrame(descriptor.Addr)
			}
			ep.control.Fill.FillAll(&ep.control.UMEM)
			ep.control.UMEM.Unlock()

			ep.mu.RLock()
			d := ep.networkDispatcher
			ep.mu.RUnlock()
			for i := uint32(0); i < nReceived; i++ {
				view := views[i]
				data := view.AsSlice()

				netProto := header.Ethernet(data).Type()

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithView(view),
				})
				if !ep.ParseHeader(pkt) {
					panic("ParseHeader(_) must succeed")
				}
				d.DeliverNetworkPacket(netProto, pkt)
				pkt.DecRef()
			}
			ep.control.RX.Release(nReceived)
		}
	}
}

func (*endpoint) Close() {}

func (*endpoint) SetOnCloseAction(func()) {}

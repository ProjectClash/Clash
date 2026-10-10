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

package fdbased

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/stack/gro"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
	"github.com/metacubex/sing-tun/internal/stopfd_darwin"

	"golang.org/x/sys/unix"
)

type iovecBuffer struct {
	mtu    int
	views  []*buffer.View
	iovecs []unix.Iovec `state:"nosave"`
}

func newIovecBuffer(mtu uint32) *iovecBuffer {
	b := &iovecBuffer{
		mtu:    int(mtu),
		views:  make([]*buffer.View, 2),
		iovecs: make([]unix.Iovec, 2),
	}
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	if b.views[0] == nil {
		b.views[0] = buffer.NewViewSize(4)
		b.iovecs[0] = unix.Iovec{Base: b.views[0].BasePtr()}
		b.iovecs[0].SetLen(4)
	}
	if b.views[1] == nil {
		b.views[1] = buffer.NewViewSize(b.mtu)
		b.iovecs[1] = unix.Iovec{Base: b.views[1].BasePtr()}
		b.iovecs[1].SetLen(b.mtu)
	}
	return b.iovecs
}

func (b *iovecBuffer) pullBuffer(n int) buffer.Buffer {
	pulled := buffer.Buffer{}
	pulled.Append(b.views[0])
	pulled.Append(b.views[1])
	pulled.Truncate(int64(n))
	pulled.TrimFront(4)
	b.views[0] = nil
	b.views[1] = nil
	return pulled
}

func (b *iovecBuffer) release() {
	for _, v := range b.views {
		if v != nil {
			v.Release()
			v = nil
		}
	}
}

type readVDispatcher struct {
	stopfd.StopFD
	fd int

	e *endpoint

	buf *iovecBuffer

	mgr *processorManager

	poller *rawfile.Poller
}

func newReadVDispatcher(fd int, e *endpoint, opts *Options) (linkDispatcher, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	poller, err := rawfile.NewPoller(stopFD.ReadFD)
	if err != nil {
		return nil, err
	}
	d := &readVDispatcher{
		StopFD: stopFD,
		fd:     fd,
		e:      e,
		poller: poller,
	}
	d.buf = newIovecBuffer(opts.MTU)
	d.mgr = newProcessorManager(opts, e)
	d.mgr.start()
	return d, nil
}

func (d *readVDispatcher) release() {
	d.buf.release()
	d.mgr.close()
	_ = d.poller.Close()
}

func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	n, errno := rawfile.BlockingReadvUntilStoppedPolled(d.poller, d.fd, d.buf.nextIovecs())
	if n <= 0 || errno != 0 {
		return false, TranslateErrno(errno)
	}
	recordIngressRead(framedPacketPayloadBytes(n), 1)

	payload := d.buf.pullBuffer(n)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: payload,
	})
	defer pkt.DecRef()

	d.e.mu.RLock()
	addr := d.e.addr
	d.e.mu.RUnlock()
	if !d.e.parseInboundHeader(pkt, addr) {
		return false, nil
	}
	pkt.RXChecksumValidated = d.e.caps&stack.CapabilityRXChecksumOffload != 0
	d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
	d.mgr.wakeReady()
	return true, nil
}

type recvMMsgDispatcher struct {
	stopfd.StopFD
	fd int

	e *endpoint

	bufs []*iovecBuffer

	msgHdrs []rawfile.MsgHdrX `state:"nosave"`

	pkts stack.PacketBufferList

	gro gro.GRO

	mgr *processorManager

	poller *rawfile.Poller
}

func newRecvMMsgDispatcher(fd int, e *endpoint, opts *Options) (linkDispatcher, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	poller, err := rawfile.NewPoller(stopFD.ReadFD)
	if err != nil {
		return nil, err
	}
	d := &recvMMsgDispatcher{
		StopFD:  stopFD,
		fd:      fd,
		e:       e,
		bufs:    make([]*iovecBuffer, e.batchSize),
		msgHdrs: make([]rawfile.MsgHdrX, e.batchSize),
		poller:  poller,
	}
	for i := range d.bufs {
		d.bufs[i] = newIovecBuffer(opts.MTU)
	}
	d.gro.Init(false)
	d.mgr = newProcessorManager(opts, e)
	d.mgr.start()

	return d, nil
}

func (d *recvMMsgDispatcher) release() {
	for _, iov := range d.bufs {
		iov.release()
	}
	d.mgr.close()
	_ = d.poller.Close()
}

func (d *recvMMsgDispatcher) dispatch() (bool, tcpip.Error) {
	for k := range d.msgHdrs {
		iovecs := d.bufs[k].nextIovecs()
		iovLen := len(iovecs)
		d.msgHdrs[k] = rawfile.MsgHdrX{}
		d.msgHdrs[k].Msg.Iov = &iovecs[0]
		d.msgHdrs[k].Msg.SetIovlen(iovLen)
	}

	nMsgs, errno := rawfile.BlockingRecvMMsgUntilStoppedPolled(d.poller, d.fd, d.msgHdrs)
	if errno != 0 {
		return false, TranslateErrno(errno)
	}
	if nMsgs == -1 {
		return false, nil
	}
	readBytes := 0
	for k := 0; k < nMsgs; k++ {
		readBytes += framedPacketPayloadBytes(int(d.msgHdrs[k].DataLen))
	}
	recordIngressRead(readBytes, uint64(nMsgs))


	d.e.mu.RLock()
	addr := d.e.addr
	dsp := d.e.dispatcher
	d.e.mu.RUnlock()

	d.gro.Dispatcher = dsp
	defer d.pkts.Reset()

	for k := 0; k < nMsgs; k++ {
		n := int(d.msgHdrs[k].DataLen)
		payload := d.bufs[k].pullBuffer(n)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		d.pkts.PushBack(pkt)

		d.msgHdrs[k].Msg.Iovlen = 0

		if d.e.parseInboundHeader(pkt, addr) {
			pkt.RXChecksumValidated = d.e.caps&stack.CapabilityRXChecksumOffload != 0
			d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
		}
	}
	d.mgr.wakeReady()

	return true, nil
}

func framedPacketPayloadBytes(wireBytes int) int {
	const darwinProtocolFamilyHeaderBytes = 4
	if wireBytes <= darwinProtocolFamilyHeaderBytes {
		return 0
	}
	return wireBytes - darwinProtocolFamilyHeaderBytes
}

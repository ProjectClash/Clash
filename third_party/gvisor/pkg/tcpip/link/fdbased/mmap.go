// Copyright 2019 The gVisor Authors.
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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package fdbased

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/stopfd"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	tPacketAlignment = uintptr(16)
	tpStatusKernel   = 0
	tpStatusUser     = 1
	tpStatusCopy     = 2
	tpStatusLosing   = 4
)

const (
	tpFrameSize = 65536 + 128
	tpBlockSize = tpFrameSize * 32
	tpBlockNR   = 1
	tpFrameNR   = (tpBlockSize * tpBlockNR) / tpFrameSize
)

func tPacketAlign(v uintptr) uintptr {
	return (v + tPacketAlignment - 1) & uintptr(^(tPacketAlignment - 1))
}

type tPacketReq struct {
	tpBlockSize uint32
	tpBlockNR   uint32
	tpFrameSize uint32
	tpFrameNR   uint32
}

type tPacketHdr []byte

const (
	tpStatusOffset  = 0
	tpLenOffset     = 8
	tpSnapLenOffset = 12
	tpMacOffset     = 16
	tpNetOffset     = 18
	tpSecOffset     = 20
	tpUSecOffset    = 24
)

func (t tPacketHdr) tpLen() uint32 {
	return binary.LittleEndian.Uint32(t[tpLenOffset:])
}

func (t tPacketHdr) tpSnapLen() uint32 {
	return binary.LittleEndian.Uint32(t[tpSnapLenOffset:])
}

func (t tPacketHdr) tpMac() uint16 {
	return binary.LittleEndian.Uint16(t[tpMacOffset:])
}

func (t tPacketHdr) tpNet() uint16 {
	return binary.LittleEndian.Uint16(t[tpNetOffset:])
}

func (t tPacketHdr) tpSec() uint32 {
	return binary.LittleEndian.Uint32(t[tpSecOffset:])
}

func (t tPacketHdr) tpUSec() uint32 {
	return binary.LittleEndian.Uint32(t[tpUSecOffset:])
}

func (t tPacketHdr) Payload() []byte {
	return t[uint32(t.tpMac()) : uint32(t.tpMac())+t.tpSnapLen()]
}

type packetMMapDispatcher struct {
	stopfd.StopFD
	fd int

	e *endpoint

	ringBuffer []byte

	ringOffset int

	mgr *processorManager
}

func (d *packetMMapDispatcher) release() {
	d.mgr.close()
}

func (d *packetMMapDispatcher) readMMappedPackets() (stack.PacketBufferList, bool, tcpip.Error) {
	var pkts stack.PacketBufferList
	hdr := tPacketHdr(d.ringBuffer[d.ringOffset*tpFrameSize:])
	for hdr.tpStatus()&tpStatusUser == 0 {
		stopped, errno := rawfile.BlockingPollUntilStopped(d.EFD, d.fd, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return pkts, stopped, tcpip.TranslateErrno(errno)
		}
		if stopped {
			return pkts, true, nil
		}
		if hdr.tpStatus()&tpStatusCopy != 0 {
			hdr.setTPStatus(tpStatusKernel)
			d.ringOffset = (d.ringOffset + 1) % tpFrameNR
			hdr = (tPacketHdr)(d.ringBuffer[d.ringOffset*tpFrameSize:])
			continue
		}
	}

	for hdr.tpStatus()&tpStatusUser == 1 {
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(buffer.NewViewWithData(hdr.Payload())),
		}))
		hdr.setTPStatus(tpStatusKernel)
		d.ringOffset = (d.ringOffset + 1) % tpFrameNR
		hdr = tPacketHdr(d.ringBuffer[d.ringOffset*tpFrameSize:])
	}
	return pkts, false, nil
}

func (d *packetMMapDispatcher) dispatch() (bool, tcpip.Error) {
	pkts, stopped, err := d.readMMappedPackets()
	defer pkts.Reset()
	if err != nil || stopped {
		return false, err
	}
	d.e.mu.RLock()
	addr := d.e.addr
	d.e.mu.RUnlock()
	for _, pkt := range pkts.AsSlice() {
		if d.e.parseInboundHeader(pkt, addr) {
			d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
		}
	}
	if pkts.Len() > 0 {
		d.mgr.wakeReady()
	}
	return true, nil
}

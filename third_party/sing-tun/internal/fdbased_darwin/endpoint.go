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
	"fmt"
	"runtime"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
	"github.com/metacubex/sing/common"

	"golang.org/x/sys/unix"
)

type linkDispatcher interface {
	Stop()
	dispatch() (bool, tcpip.Error)
	release()
}

var (
	_ stack.LinkEndpoint = (*endpoint)(nil)
	_ stack.GSOEndpoint  = (*endpoint)(nil)
)

type fdInfo struct {
	fd int
}

type endpoint struct {
	fds []fdInfo

	hdrSize int

	caps stack.LinkEndpointCapabilities

	closed func(tcpip.Error) `state:"nosave"`

	inboundDispatchers []linkDispatcher

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher

	wg sync.WaitGroup `state:"nosave"`

	maxSyscallHeaderBytes uintptr

	writevMaxIovs int

	addr tcpip.LinkAddress

	mtu uint32

	batchSize int
	sendMsgX  bool

	writeAccess sync.Locker
}

type Options struct {
	FDs []int

	MTU uint32

	EthernetHeader bool

	ClosedFunc func(tcpip.Error)

	Address tcpip.LinkAddress

	SaveRestore bool

	TXChecksumOffload bool

	RXChecksumOffload bool

	MaxSyscallHeaderBytes int

	InterfaceIndex int

	ProcessorsPerChannel int

	RecvMsgX bool
	SendMsgX bool

	WriteAccess sync.Locker
}

func New(opts *Options) (stack.LinkEndpoint, error) {
	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if len(opts.FDs) == 0 {
		return nil, fmt.Errorf("opts.FD is empty, at least one FD must be specified")
	}

	if opts.MaxSyscallHeaderBytes < 0 {
		return nil, fmt.Errorf("opts.MaxSyscallHeaderBytes is negative")
	}
	var batchSize int
	if opts.RecvMsgX {
		batchSize = int((512*1024)/(opts.MTU)) + 1
	} else {
		batchSize = 1
	}

	e := &endpoint{
		mtu:                   opts.MTU,
		caps:                  caps,
		closed:                opts.ClosedFunc,
		addr:                  opts.Address,
		hdrSize:               hdrSize,
		maxSyscallHeaderBytes: uintptr(opts.MaxSyscallHeaderBytes),
		writevMaxIovs:         rawfile.MaxIovs,
		batchSize:             batchSize,
		sendMsgX:              opts.SendMsgX,
		writeAccess:           opts.WriteAccess,
	}
	if e.writeAccess == nil {
		e.writeAccess = new(sync.Mutex)
	}
	if e.maxSyscallHeaderBytes != 0 {
		if max := int(e.maxSyscallHeaderBytes / rawfile.SizeofIovec); max < e.writevMaxIovs {
			e.writevMaxIovs = max
		}
	}

	for _, fd := range opts.FDs {
		if err := unix.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", fd, err)
		}

		e.fds = append(e.fds, fdInfo{fd: fd})
		if opts.ProcessorsPerChannel == 0 {
			opts.ProcessorsPerChannel = common.Max(1, runtime.GOMAXPROCS(0)/len(opts.FDs))
		}

		var inboundDispatcher linkDispatcher
		var err error
		if opts.RecvMsgX {
			inboundDispatcher, err = newRecvMMsgDispatcher(fd, e, opts)
			if err != nil {
				return nil, fmt.Errorf("newRecvMMsgDispatcher(%d, %+v) = %v", fd, e, err)
			}
		} else {
			inboundDispatcher, err = newReadVDispatcher(fd, e, opts)
			if err != nil {
				return nil, fmt.Errorf("newReadVDispatcher(%d, %+v) = %v", fd, e, err)
			}
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	return e, nil
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()

	if dispatcher == nil && e.dispatcher != nil {
		for _, dispatcher := range e.inboundDispatchers {
			dispatcher.Stop()
		}
		e.dispatcher = nil
		e.mu.Unlock()
		e.Wait()
		return
	}
	defer e.mu.Unlock()
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		for i := range e.inboundDispatchers {
			e.wg.Add(1)
			go func(i int) {
				e.dispatchLoop(e.inboundDispatchers[i])
				e.wg.Done()
			}(i)
		}
	}
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

func (e *endpoint) Wait() {
	e.wg.Wait()
}

func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {
	if e.hdrSize > 0 {
		eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			SrcAddr: pkt.EgressRoute.LocalLinkAddress,
			DstAddr: pkt.EgressRoute.RemoteLinkAddress,
			Type:    pkt.NetworkProtocolNumber,
		})
	}
}

func (e *endpoint) parseHeader(pkt *stack.PacketBuffer) (header.Ethernet, bool) {
	if e.hdrSize <= 0 {
		return nil, true
	}
	hdrBytes, ok := pkt.LinkHeader().Consume(e.hdrSize)
	if !ok {
		return nil, false
	}
	hdr := header.Ethernet(hdrBytes)
	pkt.NetworkProtocolNumber = hdr.Type()
	return hdr, true
}

func (e *endpoint) parseInboundHeader(pkt *stack.PacketBuffer, wantAddr tcpip.LinkAddress) bool {
	hdr, ok := e.parseHeader(pkt)
	if !ok || e.hdrSize <= 0 {
		return ok
	}
	dstAddr := hdr.DestinationAddress()
	return dstAddr == wantAddr || byte(dstAddr[0])&0x01 == 1
}

func (e *endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := e.parseHeader(pkt)
	return ok
}

var (
	packetHeader4 = []byte{0x00, 0x00, 0x00, unix.AF_INET}
	packetHeader6 = []byte{0x00, 0x00, 0x00, unix.AF_INET6}
)

func (e *endpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	fdInfo := e.fds[pkt.Hash%uint32(len(e.fds))]
	fd := fdInfo.fd
	var vnetHdrBuf []byte
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		vnetHdrBuf = packetHeader4
	} else {
		vnetHdrBuf = packetHeader6
	}
	views := pkt.AsSlices()
	payloadBytes := 0
	for _, view := range views {
		payloadBytes += len(view)
	}
	numIovecs := len(views)
	if len(vnetHdrBuf) != 0 {
		numIovecs++
	}
	if numIovecs > e.writevMaxIovs {
		numIovecs = e.writevMaxIovs
	}

	var iovecsArr [8]unix.Iovec
	iovecs := iovecsArr[:0]
	if numIovecs > len(iovecsArr) {
		iovecs = make([]unix.Iovec, 0, numIovecs)
	}
	iovecs = rawfile.AppendIovecFromBytes(iovecs, vnetHdrBuf, numIovecs)
	for _, v := range views {
		iovecs = rawfile.AppendIovecFromBytes(iovecs, v, numIovecs)
	}
	recordEgressWriteAttempt()
	if errno := writeIovecWaitingForRoom(fd, iovecs); errno != 0 {
		recordEgressWriteError()
		return TranslateErrno(errno)
	}
	recordEgressWriteSuccess(1, uint64(payloadBytes))
	return nil
}

func writeIovecWaitingForRoom(fd int, iovecs []unix.Iovec) unix.Errno {
	waits := 0
	for {
		errno := rawfile.NonBlockingWriteIovec(fd, iovecs)
		switch {
		case errno == 0:
			return 0
		case errno == unix.EINTR:
			continue
		case !rawfile.BufferFull(errno):
			return errno
		case rawfile.WaitBufferFull(waits):
			waits++
			recordEgressWriteWait()
			continue
		default:
			recordEgressWriteWaitExhausted()
			return errno
		}
	}
}

func packetPayloadBytes(pkt *stack.PacketBuffer) uint64 {
	var bytes uint64
	for _, view := range pkt.AsSlices() {
		bytes += uint64(len(view))
	}
	return bytes
}

func (e *endpoint) sendBatch(batchFDInfo fdInfo, pkts []*stack.PacketBuffer) (int, tcpip.Error) {
	if !e.sendMsgX {
		var written int
		var err tcpip.Error
		for written < len(pkts) {
			if err = e.writePacket(pkts[written]); err != nil {
				break
			}
			written++
		}
		return written, err
	}

	e.writeAccess.Lock()
	defer e.writeAccess.Unlock()

	batchFD := batchFDInfo.fd
	mmsgHdrsStorage := make([]rawfile.MsgHdrX, 0, len(pkts))
	packets := 0
	for packets < len(pkts) {
		mmsgHdrs := mmsgHdrsStorage
		batch := pkts[packets:]
		syscallHeaderBytes := uintptr(0)
		for _, pkt := range batch {
			var vnetHdrBuf []byte
			if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
				vnetHdrBuf = packetHeader4
			} else {
				vnetHdrBuf = packetHeader6
			}
			views, offset := pkt.AsViewList()
			var skipped int
			var view *buffer.View
			for view = views.Front(); view != nil && offset >= view.Size(); view = view.Next() {
				offset -= view.Size()
				skipped++
			}

			numIovecs := views.Len() - skipped
			if len(vnetHdrBuf) != 0 {
				numIovecs++
			}
			if numIovecs > rawfile.MaxIovs {
				numIovecs = rawfile.MaxIovs
			}
			if e.maxSyscallHeaderBytes != 0 {
				syscallHeaderBytes += rawfile.SizeofMsgHdrX + uintptr(numIovecs)*rawfile.SizeofIovec
				if syscallHeaderBytes > e.maxSyscallHeaderBytes {
					break
				}
			}

			iovecs := make([]unix.Iovec, 0, numIovecs)
			iovecs = rawfile.AppendIovecFromBytes(iovecs, vnetHdrBuf, numIovecs)
			iovecs = rawfile.AppendIovecFromBytes(iovecs, view.AsSlice()[offset:], numIovecs)
			for view = view.Next(); view != nil; view = view.Next() {
				iovecs = rawfile.AppendIovecFromBytes(iovecs, view.AsSlice(), numIovecs)
			}

			var mmsgHdr rawfile.MsgHdrX
			mmsgHdr.Msg.Iov = &iovecs[0]
			mmsgHdr.Msg.SetIovlen(len(iovecs))
			mmsgHdrs = append(mmsgHdrs, mmsgHdr)
		}

		if len(mmsgHdrs) == 0 {
			pkt := batch[0]
			if err := e.writePacket(pkt); err != nil {
				return packets, err
			}
			packets++
		} else {
			waits := 0
			for len(mmsgHdrs) > 0 {
				recordEgressWriteAttempt()
				sent, errno := rawfile.NonBlockingSendMMsg(batchFD, mmsgHdrs)
				if errno != 0 {
					if errno == unix.EINTR {
						continue
					}
					if rawfile.BufferFull(errno) && rawfile.WaitBufferFull(waits) {
						waits++
						recordEgressWriteWait()
						continue
					}
					if rawfile.BufferFull(errno) {
						recordEgressWriteWaitExhausted()
					}
					recordEgressWriteError()
					return packets, TranslateErrno(errno)
				}
				waits = 0
				var payloadBytes uint64
				for _, pkt := range pkts[packets : packets+sent] {
					payloadBytes += packetPayloadBytes(pkt)
				}
				recordEgressWriteSuccess(uint64(sent), payloadBytes)
				packets += sent
				mmsgHdrs = mmsgHdrs[sent:]
			}
		}
	}

	return packets, nil
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	batch := make([]*stack.PacketBuffer, 0, e.batchSize)
	batchFDInfo := fdInfo{fd: -1}
	sentPackets := 0
	for _, pkt := range pkts.AsSlice() {
		if len(batch) == 0 {
			batchFDInfo = e.fds[pkt.Hash%uint32(len(e.fds))]
		}
		pktFDInfo := e.fds[pkt.Hash%uint32(len(e.fds))]
		if sendNow := pktFDInfo != batchFDInfo; !sendNow {
			batch = append(batch, pkt)
			continue
		}
		n, err := e.sendBatch(batchFDInfo, batch)
		sentPackets += n
		if err != nil {
			return sentPackets, err
		}
		batch = batch[:0]
		batch = append(batch, pkt)
		batchFDInfo = pktFDInfo
	}

	if len(batch) != 0 {
		n, err := e.sendBatch(batchFDInfo, batch)
		sentPackets += n
		if err != nil {
			return sentPackets, err
		}
	}
	return sentPackets, nil
}

func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			inboundDispatcher.release()
			return err
		}
	}
}

func (e *endpoint) GSOMaxSize() uint32 {
	return 0
}

func (e *endpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GSONotSupported
}

func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

func (e *endpoint) Close() {}

func (*endpoint) SetOnCloseAction(func()) {}

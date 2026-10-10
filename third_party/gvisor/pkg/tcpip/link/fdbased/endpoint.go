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

package fdbased

import (
	"fmt"
	"runtime"
	
	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type linkDispatcher interface {
	Stop()
	dispatch() (bool, tcpip.Error)
	release()
}

type PacketDispatchMode int

const BatchSize = 47

const (
	Readv PacketDispatchMode = iota
	RecvMMsg
	PacketMMap
)

func (p PacketDispatchMode) String() string {
	switch p {
	case Readv:
		return "Readv"
	case RecvMMsg:
		return "RecvMMsg"
	case PacketMMap:
		return "PacketMMap"
	default:
		return fmt.Sprintf("unknown packet dispatch mode '%d'", p)
	}
}

var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.GSOEndpoint = (*endpoint)(nil)

type fdInfo struct {
	fd       int
	isSocket bool
}

type endpoint struct {
	fds []fdInfo

	hdrSize int

	caps stack.LinkEndpointCapabilities

	closed func(tcpip.Error) `state:"nosave"`

	inboundDispatchers []linkDispatcher

	mu endpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher

	packetDispatchMode PacketDispatchMode

	gsoMaxSize uint32

	wg sync.WaitGroup `state:"nosave"`

	gsoKind stack.SupportedGSO

	maxSyscallHeaderBytes uintptr

	writevMaxIovs int

	addr tcpip.LinkAddress

	mtu uint32
}

type Options struct {
	FDs []int

	MTU uint32

	EthernetHeader bool

	ClosedFunc func(tcpip.Error)

	Address tcpip.LinkAddress

	SaveRestore bool

	GSOMaxSize uint32

	GVisorGSOEnabled bool

	PacketDispatchMode PacketDispatchMode

	TXChecksumOffload bool

	RXChecksumOffload bool

	MaxSyscallHeaderBytes int

	InterfaceIndex int

	GRO bool

	ProcessorsPerChannel int

	IsPacketSocket []bool

	PreConfigured bool
}

var fallbackFanoutID atomicbitops.Int32 = atomicbitops.FromInt32(int32(unix.Getpid()))

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

	e := &endpoint{
		mtu:                   opts.MTU,
		caps:                  caps,
		closed:                opts.ClosedFunc,
		addr:                  opts.Address,
		hdrSize:               hdrSize,
		packetDispatchMode:    opts.PacketDispatchMode,
		maxSyscallHeaderBytes: uintptr(opts.MaxSyscallHeaderBytes),
		writevMaxIovs:         rawfile.MaxIovs,
	}
	if e.maxSyscallHeaderBytes != 0 {
		if max := int(e.maxSyscallHeaderBytes / rawfile.SizeofIovec); max < e.writevMaxIovs {
			e.writevMaxIovs = max
		}
	}

	fid := int32(-1)

	for i, fd := range opts.FDs {
		if err := unix.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", fd, err)
		}

		isSocket, err := IsSocketFD(fd)
		if err != nil {
			return nil, err
		}
		e.fds = append(e.fds, fdInfo{fd: fd, isSocket: isSocket})
		if opts.GSOMaxSize != 0 {
			if opts.GVisorGSOEnabled {
				e.gsoKind = stack.GVisorGSOSupported
			} else {
				e.gsoKind = stack.HostGSOSupported
			}
			e.gsoMaxSize = opts.GSOMaxSize
		}
		if opts.ProcessorsPerChannel == 0 {
			opts.ProcessorsPerChannel = common.Max(1, runtime.GOMAXPROCS(0)/len(opts.FDs))
		}

		var isPacket bool
		if opts.PreConfigured {
			if opts.IsPacketSocket != nil && i < len(opts.IsPacketSocket) {
				isPacket = opts.IsPacketSocket[i]
			} else {
				return nil, fmt.Errorf("PreConfigured is true but IsPacketSocket is missing or too short (index %d, len %d)", i, len(opts.IsPacketSocket))
			}
		} else {
			var err error
			isPacket, err = IsPacketSocket(fd, isSocket)
			if err != nil {
				return nil, err
			}
		}

		if isPacket && !opts.PreConfigured {
			var err error
			if fid < 0 {
				fid, err = CreatePacketFanoutGroup(fd)
			} else {
				err = JoinPacketFanoutGroup(fd, fid)
			}
			if err != nil {
				return nil, fmt.Errorf("failed to enable PACKET_FANOUT option: %v", err)
			}
		}

		inboundDispatcher, err := createInboundDispatcher(e, fd, isSocket, opts)
		if err != nil {
			return nil, fmt.Errorf("createInboundDispatcher(...) = %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	return e, nil
}

func createInboundDispatcher(e *endpoint, fd int, isSocket bool, opts *Options) (linkDispatcher, error) {
	inboundDispatcher, err := newReadVDispatcher(fd, e, opts)
	if err != nil {
		return nil, fmt.Errorf("newReadVDispatcher(%d, %+v) = %v", fd, e, err)
	}

	if isSocket {
		switch e.packetDispatchMode {
		case PacketMMap:
			inboundDispatcher, err = newPacketMMapDispatcher(fd, e, opts)
			if err != nil {
				return nil, fmt.Errorf("newPacketMMapDispatcher(%d, %+v) = %v", fd, e, err)
			}
		case RecvMMsg:
			inboundDispatcher, err = newRecvMMsgDispatcher(fd, e, opts)
			if err != nil {
				return nil, fmt.Errorf("newRecvMMsgDispatcher(%d, %+v) = %v", fd, e, err)
			}
		case Readv:
		default:
			return nil, fmt.Errorf("unknown dispatch mode %d", e.packetDispatchMode)
		}
	}
	return inboundDispatcher, nil
}

func IsPacketSocket(fd int, isSocket bool) (bool, error) {
	if !isSocket {
		return false, nil
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false, fmt.Errorf("unix.Getsockname(%d) = %v", fd, err)
	}
	_, ok := sa.(*unix.SockaddrLinklayer)
	return ok, nil
}

func CreatePacketFanoutGroup(fd int) (int32, error) {
	const fanoutType = unix.PACKET_FANOUT_HASH
	fanoutArg := (fanoutType | unix.PACKET_FANOUT_FLAG_UNIQUEID) << 16
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
		uniqueIDErr := err
		fallbackID := fallbackFanoutID.Add(1)
		fanoutArg = (int(fallbackID) & 0xffff) | fanoutType<<16
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
			return 0, fmt.Errorf("UNIQUEID failed (%v); fallback fanout id %d also failed: %v", uniqueIDErr, fanoutArg&0xffff, err)
		}
		return int32(fanoutArg & 0xffff), nil
	}

	fanoutArg, err := unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT)
	if err != nil {
		return 0, fmt.Errorf("getsockopt(PACKET_FANOUT) failed: %v", err)
	}
	return int32(fanoutArg & 0xffff), nil
}

func JoinPacketFanoutGroup(fd int, fID int32) error {
	const fanoutType = unix.PACKET_FANOUT_HASH
	fanoutArg := (int(fID) & 0xffff) | fanoutType<<16
	return unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg)
}

func IsSocketFD(fd int) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false, fmt.Errorf("unix.Fstat(%v,...) failed: %v", fd, err)
	}
	return (stat.Mode & unix.S_IFSOCK) == unix.S_IFSOCK, nil
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

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (h *virtioNetHdr) marshal() []byte {
	buf := [virtioNetHdrSize]byte{
		0: byte(h.flags),
		1: byte(h.gsoType),


		2: byte(h.hdrLen),
		3: byte(h.hdrLen >> 8),

		4: byte(h.gsoSize),
		5: byte(h.gsoSize >> 8),

		6: byte(h.csumStart),
		7: byte(h.csumStart >> 8),

		8: byte(h.csumOffset),
		9: byte(h.csumOffset >> 8),
	}
	return buf[:]
}

const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

	_VIRTIO_NET_HDR_GSO_TCPV4 = 1
	_VIRTIO_NET_HDR_GSO_TCPV6 = 4
)

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

func (e *endpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	fdInfo := e.fds[pkt.Hash%uint32(len(e.fds))]
	fd := fdInfo.fd
	var vnetHdrBuf []byte
	if e.gsoKind == stack.HostGSOSupported {
		vnetHdr := virtioNetHdr{}
		if pkt.GSOOptions.Type != stack.GSONone {
			vnetHdr.hdrLen = uint16(pkt.HeaderSize())
			if pkt.GSOOptions.NeedsCsum {
				vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
				vnetHdr.csumStart = pkt.GSOOptions.L3HdrLen
				vnetHdr.csumOffset = pkt.GSOOptions.CsumOffset
			}
			if uint16(pkt.Data().Size()) > pkt.GSOOptions.MSS {
				switch pkt.GSOOptions.Type {
				case stack.GSOTCPv4:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
				case stack.GSOTCPv6:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
				default:
					panic(fmt.Sprintf("Unknown gso type: %v", pkt.GSOOptions.Type))
				}
				vnetHdr.gsoSize = pkt.GSOOptions.MSS
			}
		}
		vnetHdrBuf = vnetHdr.marshal()
	}

	views := pkt.AsSlices()
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
	if errno := rawfile.NonBlockingWriteIovec(fd, iovecs); errno != 0 {
		return tcpip.TranslateErrno(errno)
	}
	return nil
}

func (e *endpoint) sendBatch(batchFDInfo fdInfo, pkts []*stack.PacketBuffer) (int, tcpip.Error) {
	if !batchFDInfo.isSocket {
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

	batchFD := batchFDInfo.fd
	mmsgHdrsStorage := make([]rawfile.MMsgHdr, 0, len(pkts))
	packets := 0
	for packets < len(pkts) {
		mmsgHdrs := mmsgHdrsStorage
		batch := pkts[packets:]
		syscallHeaderBytes := uintptr(0)
		for _, pkt := range batch {
			var vnetHdrBuf []byte
			if e.gsoKind == stack.HostGSOSupported {
				vnetHdr := virtioNetHdr{}
				if pkt.GSOOptions.Type != stack.GSONone {
					vnetHdr.hdrLen = uint16(pkt.HeaderSize())
					if pkt.GSOOptions.NeedsCsum {
						vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
						vnetHdr.csumStart = pkt.GSOOptions.L3HdrLen
						vnetHdr.csumOffset = pkt.GSOOptions.CsumOffset
					}
					if pkt.GSOOptions.Type != stack.GSONone && uint16(pkt.Data().Size()) > pkt.GSOOptions.MSS {
						switch pkt.GSOOptions.Type {
						case stack.GSOTCPv4:
							vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
						case stack.GSOTCPv6:
							vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
						default:
							panic(fmt.Sprintf("Unknown gso type: %v", pkt.GSOOptions.Type))
						}
						vnetHdr.gsoSize = pkt.GSOOptions.MSS
					}
				}
				vnetHdrBuf = vnetHdr.marshal()
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
				syscallHeaderBytes += rawfile.SizeofMMsgHdr + uintptr(numIovecs)*rawfile.SizeofIovec
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

			var mmsgHdr rawfile.MMsgHdr
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
			for len(mmsgHdrs) > 0 {
				sent, errno := rawfile.NonBlockingSendMMsg(batchFD, mmsgHdrs)
				if errno != 0 {
					return packets, tcpip.TranslateErrno(errno)
				}
				packets += sent
				mmsgHdrs = mmsgHdrs[sent:]
			}
		}
	}

	return packets, nil
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	batch := make([]*stack.PacketBuffer, 0, BatchSize)
	batchFDInfo := fdInfo{fd: -1, isSocket: false}
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

func (e *endpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	if errno := rawfile.NonBlockingWrite(e.fds[0].fd, packet.AsSlice()); errno != 0 {
		return tcpip.TranslateErrno(errno)
	}
	return nil
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
	return e.gsoMaxSize
}

func (e *endpoint) SupportedGSO() stack.SupportedGSO {
	return e.gsoKind
}

func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

func (e *endpoint) Close() {}

func (*endpoint) SetOnCloseAction(func()) {}

type InjectableEndpoint struct {
	endpoint

	mu injectableEndpointRWMutex `state:"nosave"`
	dispatcher stack.NetworkDispatcher
}

func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

func (e *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func NewInjectable(fd int, mtu uint32, capabilities stack.LinkEndpointCapabilities) (*InjectableEndpoint, error) {
	unix.SetNonblock(fd, true)
	isSocket, err := IsSocketFD(fd)
	if err != nil {
		return nil, err
	}

	return &InjectableEndpoint{endpoint: endpoint{
		fds:           []fdInfo{{fd: fd, isSocket: isSocket}},
		mtu:           mtu,
		caps:          capabilities,
		writevMaxIovs: rawfile.MaxIovs,
	}}, nil
}

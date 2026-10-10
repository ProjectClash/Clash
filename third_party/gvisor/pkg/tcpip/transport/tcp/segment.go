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

package tcp

import (
	"fmt"
	"io"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type queueFlags uint8

const (
	SegOverheadSize = segSize + stack.PacketBufferStructSize + header.IPv4MaximumHeaderSize

	recvQ queueFlags = 1 << iota
	sendQ
)

var segmentPool = sync.Pool{
	New: func() any {
		return &segment{}
	},
}

type segment struct {
	segmentEntry
	segmentRefs

	ep     *Endpoint
	qFlags queueFlags
	id     stack.TransportEndpointID `state:"manual"`

	pkt *stack.PacketBuffer

	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          header.TCPFlags
	window         seqnum.Size
	csum uint16
	csumValid bool

	parsedOptions  header.TCPOptions
	options        []byte `state:".([]byte)"`
	hasNewSACKInfo bool
	rcvdTime       tcpip.MonotonicTime
	xmitTime  tcpip.MonotonicTime
	xmitCount uint32

	acked bool

	dataMemSize int

	lost bool
}

func newIncomingSegment(id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) (*segment, error) {
	hdr := header.TCP(pkt.TransportHeader().Slice())
	var srcAddr tcpip.Address
	var dstAddr tcpip.Address
	switch netProto := pkt.NetworkProtocolNumber; netProto {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(pkt.NetworkHeader().Slice())
		srcAddr = hdr.SourceAddress()
		dstAddr = hdr.DestinationAddress()
	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(pkt.NetworkHeader().Slice())
		srcAddr = hdr.SourceAddress()
		dstAddr = hdr.DestinationAddress()
	default:
		panic(fmt.Sprintf("unknown network protocol number %d", netProto))
	}

	csum, csumValid, ok := header.TCPValid(
		hdr,
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		srcAddr,
		dstAddr,
		pkt.RXChecksumValidated)
	if !ok {
		return nil, fmt.Errorf("header data offset does not respect size constraints: %d < offset < %d, got offset=%d", header.TCPMinimumSize, len(hdr), hdr.DataOffset())
	}

	s := newSegment()
	s.id = id
	s.options = hdr[header.TCPMinimumSize:]
	s.parsedOptions = header.ParseTCPOptions(hdr[header.TCPMinimumSize:])
	s.sequenceNumber = seqnum.Value(hdr.SequenceNumber())
	s.ackNumber = seqnum.Value(hdr.AckNumber())
	s.flags = hdr.Flags()
	s.window = seqnum.Size(hdr.WindowSize())
	s.rcvdTime = clock.NowMonotonic()
	s.dataMemSize = pkt.MemSize()
	s.pkt = pkt.Clone()
	s.csumValid = csumValid

	if !s.pkt.RXChecksumValidated {
		s.csum = csum
	}
	return s, nil
}

func newOutgoingSegment(id stack.TransportEndpointID, clock tcpip.Clock, buf buffer.Buffer, mark uint32) *segment {
	s := newSegment()
	s.id = id
	s.rcvdTime = clock.NowMonotonic()
	s.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buf,
		Mark:    mark,
	})
	s.dataMemSize = s.pkt.MemSize()
	return s
}

func (s *segment) clone() *segment {
	t := newSegment()
	t.id = s.id
	t.sequenceNumber = s.sequenceNumber
	t.ackNumber = s.ackNumber
	t.flags = s.flags
	t.window = s.window
	t.rcvdTime = s.rcvdTime
	t.xmitTime = s.xmitTime
	t.xmitCount = s.xmitCount
	t.ep = s.ep
	t.qFlags = s.qFlags
	t.dataMemSize = s.dataMemSize
	t.pkt = s.pkt.Clone()
	return t
}

func newSegment() *segment {
	s := segmentPool.Get().(*segment)
	*s = segment{}
	s.InitRefs()
	return s
}

func (s *segment) merge(oth *segment) {
	s.pkt.Data().Merge(oth.pkt.Data())
	s.dataMemSize = s.pkt.MemSize()
	oth.dataMemSize = oth.pkt.MemSize()
}

func (s *segment) setOwner(ep *Endpoint, qFlags queueFlags) {
	switch qFlags {
	case recvQ:
		ep.updateReceiveMemUsed(s.segMemSize())
	case sendQ:
	default:
		panic(fmt.Sprintf("unexpected queue flag %b", qFlags))
	}
	s.ep = ep
	s.qFlags = qFlags
}

func (s *segment) DecRef() {
	s.segmentRefs.DecRef(func() {
		if s.ep != nil {
			switch s.qFlags {
			case recvQ:
				s.ep.updateReceiveMemUsed(-s.segMemSize())
			case sendQ:
			default:
				panic(fmt.Sprintf("unexpected queue flag %b set for segment", s.qFlags))
			}
		}
		s.pkt.DecRef()
		s.pkt = nil
		segmentPool.Put(s)
	})
}

func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.payloadSize())
	if s.flags.Contains(header.TCPFlagSyn) {
		l++
	}
	if s.flags.Contains(header.TCPFlagFin) {
		l++
	}
	return l
}

func (s *segment) payloadSize() int {
	return s.pkt.Data().Size()
}

func (s *segment) segMemSize() int {
	return segSize + s.dataMemSize
}

func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{Start: s.sequenceNumber, End: s.sequenceNumber.Add(s.logicalLen())}
}

func (s *segment) TrimFront(ackLeft seqnum.Size) {
	s.pkt.Data().TrimFront(int(ackLeft))
}

func (s *segment) ReadTo(dst io.Writer, peek bool) (int, error) {
	return s.pkt.Data().ReadTo(dst, peek)
}

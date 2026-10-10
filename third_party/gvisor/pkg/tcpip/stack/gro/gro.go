// Copyright 2022 The gVisor Authors.
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

package gro

import (
	"bytes"
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)


const (
	groNBuckets = 8

	groNBucketsMask = groNBuckets - 1

	groBucketSize = 8

	groMaxPacketSize = 1 << 16
)

type groBucket struct {
	count int

	packets groPacketList

	packetsPrealloc [groBucketSize]groPacket

	allocIdxs [groBucketSize]int
}

func (gb *groBucket) full() bool {
	return gb.count == groBucketSize
}

func (gb *groBucket) insert(pkt *stack.PacketBuffer, ipHdr []byte, tcpHdr header.TCP) {
	groPkt := &gb.packetsPrealloc[gb.allocIdxs[gb.count]]
	*groPkt = groPacket{
		pkt:           pkt,
		ipHdr:         ipHdr,
		tcpHdr:        tcpHdr,
		initialLength: pkt.Data().Size(),
		idx:           groPkt.idx,
	}
	gb.count++
	gb.packets.PushBack(groPkt)
}

func (gb *groBucket) removeOldest() *stack.PacketBuffer {
	pkt := gb.packets.Front()
	gb.packets.Remove(pkt)
	gb.count--
	gb.allocIdxs[gb.count] = pkt.idx
	ret := pkt.pkt
	pkt.reset()
	return ret
}

func (gb *groBucket) removeOne(pkt *groPacket) {
	gb.packets.Remove(pkt)
	gb.count--
	gb.allocIdxs[gb.count] = pkt.idx
	pkt.reset()
}

func (gb *groBucket) findGROPacket4(pkt *stack.PacketBuffer, ipHdr header.IPv4, tcpHdr header.TCP) (*groPacket, bool) {
	for groPkt := gb.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
		groIPHdr := header.IPv4(groPkt.ipHdr)
		if ipHdr.SourceAddress() != groIPHdr.SourceAddress() || ipHdr.DestinationAddress() != groIPHdr.DestinationAddress() {
			continue
		}

		if tcpHdr.SourcePort() != groPkt.tcpHdr.SourcePort() || tcpHdr.DestinationPort() != groPkt.tcpHdr.DestinationPort() {
			continue
		}


		TOS, _ := ipHdr.TOS()
		groTOS, _ := groIPHdr.TOS()
		if ipHdr.TTL() != groIPHdr.TTL() || TOS != groTOS {
			return groPkt, true
		}

		if shouldFlushTCP(groPkt, tcpHdr) {
			return groPkt, true
		}

		if pkt.Data().Size()-header.IPv4MinimumSize-int(tcpHdr.DataOffset())+groPkt.pkt.Data().Size() >= groMaxPacketSize {
			return groPkt, true
		}

		return groPkt, false
	}

	return nil, false
}

func (gb *groBucket) findGROPacket6(pkt *stack.PacketBuffer, ipHdr header.IPv6, tcpHdr header.TCP) (*groPacket, bool) {
	for groPkt := gb.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
		groIPHdr := header.IPv6(groPkt.ipHdr)
		if ipHdr.SourceAddress() != groIPHdr.SourceAddress() || ipHdr.DestinationAddress() != groIPHdr.DestinationAddress() {
			continue
		}

		trafficClass, flowLabel := ipHdr.TOS()
		groTrafficClass, groFlowLabel := groIPHdr.TOS()
		if flowLabel != groFlowLabel || ipHdr.NextHeader() != groIPHdr.NextHeader() {
			continue
		}
		if !bytes.Equal(ipHdr[header.IPv6MinimumSize:], groIPHdr[header.IPv6MinimumSize:]) {
			continue
		}

		if tcpHdr.SourcePort() != groPkt.tcpHdr.SourcePort() || tcpHdr.DestinationPort() != groPkt.tcpHdr.DestinationPort() {
			continue
		}


		if shouldFlushTCP(groPkt, tcpHdr) {
			return groPkt, true
		}

		if trafficClass != groTrafficClass || ipHdr.HopLimit() != groIPHdr.HopLimit() {
			return groPkt, true
		}

		if pkt.Data().Size()-len(ipHdr)-int(tcpHdr.DataOffset())+groPkt.pkt.Data().Size() >= groMaxPacketSize {
			return groPkt, true
		}

		return groPkt, false
	}

	return nil, false
}

func (gb *groBucket) found(gd *GRO, groPkt *groPacket, flushGROPkt bool, pkt *stack.PacketBuffer, ipHdr []byte, tcpHdr header.TCP, updateIPHdr func([]byte, int)) {
	pktSize := pkt.Data().Size()
	flags := tcpHdr.Flags()
	dataOff := tcpHdr.DataOffset()
	tcpPayloadSize := pkt.Data().Size() - len(ipHdr) - int(dataOff)
	if flushGROPkt {
		pkt := groPkt.pkt
		gb.removeOne(groPkt)
		gd.handlePacket(pkt)
		pkt.DecRef()
		groPkt = nil
	} else if groPkt != nil {
		pkt.Data().TrimFront(len(ipHdr) + int(dataOff))
		groPkt.pkt.Data().Merge(pkt.Data())
		updateIPHdr(groPkt.ipHdr, tcpPayloadSize)
		groPkt.tcpHdr.SetFlags(uint8(groPkt.tcpHdr.Flags() | (flags & (header.TCPFlagFin | header.TCPFlagPsh))))

		pkt = nil
	}

	flush := header.TCPFlags(flags)&(header.TCPFlagUrg|header.TCPFlagPsh|header.TCPFlagRst|header.TCPFlagSyn|header.TCPFlagFin) != 0
	flush = flush || tcpPayloadSize == 0
	if groPkt != nil {
		flush = flush || pktSize != groPkt.initialLength
	}

	switch {
	case flush && groPkt != nil:
		pkt := groPkt.pkt
		gb.removeOne(groPkt)
		gd.handlePacket(pkt)
		pkt.DecRef()
	case flush && groPkt == nil:
		gd.handlePacket(pkt)
	case !flush && groPkt == nil:
		if gb.full() {
			toFlush := gb.removeOldest()
			gb.insert(pkt.IncRef(), ipHdr, tcpHdr)
			gd.handlePacket(toFlush)
			toFlush.DecRef()
		} else {
			gb.insert(pkt.IncRef(), ipHdr, tcpHdr)
		}
	default:
	}
}

type groPacket struct {
	groPacketEntry

	pkt *stack.PacketBuffer

	ipHdr []byte

	tcpHdr header.TCP

	initialLength int

	idx int
}

func (pk *groPacket) reset() {
	*pk = groPacket{
		idx: pk.idx,
	}
}

func (pk *groPacket) payloadSize() int {
	return pk.pkt.Data().Size() - len(pk.ipHdr) - int(pk.tcpHdr.DataOffset())
}

type GRO struct {
	enabled bool
	buckets [groNBuckets]groBucket

	Dispatcher stack.NetworkDispatcher
}

func (gd *GRO) Init(enabled bool) {
	gd.enabled = enabled
	for i := range gd.buckets {
		bucket := &gd.buckets[i]
		for j := range bucket.packetsPrealloc {
			bucket.allocIdxs[j] = j
			bucket.packetsPrealloc[j].idx = j
		}
	}
}

func (gd *GRO) Enqueue(pkt *stack.PacketBuffer) {
	if !gd.enabled {
		gd.handlePacket(pkt)
		return
	}

	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		gd.dispatch4(pkt)
	case header.IPv6ProtocolNumber:
		gd.dispatch6(pkt)
	default:
		gd.handlePacket(pkt)
	}
}

func (gd *GRO) dispatch4(pkt *stack.PacketBuffer) {

	hdrBytes, ok := pkt.Data().PullUp(header.IPv4MinimumSize + header.TCPMinimumSize)
	if !ok {
		gd.handlePacket(pkt)
		return
	}
	ipHdr := header.IPv4(hdrBytes)

	if ipHdr.FragmentOffset() != 0 || ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		gd.handlePacket(pkt)
		return
	}

	if ipHdr.HeaderLength() != header.IPv4MinimumSize || tcpip.TransportProtocolNumber(ipHdr.Protocol()) != header.TCPProtocolNumber {
		gd.handlePacket(pkt)
		return
	}
	tcpHdr := header.TCP(hdrBytes[header.IPv4MinimumSize:])
	ipHdr = ipHdr[:header.IPv4MinimumSize]
	dataOff := tcpHdr.DataOffset()
	if dataOff < header.TCPMinimumSize {
		gd.handlePacket(pkt)
		return
	}
	hdrBytes, ok = pkt.Data().PullUp(header.IPv4MinimumSize + int(dataOff))
	if !ok {
		gd.handlePacket(pkt)
		return
	}

	tcpHdr = header.TCP(hdrBytes[header.IPv4MinimumSize:])

	if !pkt.RXChecksumValidated {
		if !ipHdr.IsValid(pkt.Data().Size()) || !ipHdr.IsChecksumValid() {
			gd.handlePacket(pkt)
			return
		}
		payloadChecksum := pkt.Data().ChecksumAtOffset(header.IPv4MinimumSize + int(dataOff))
		tcpPayloadSize := pkt.Data().Size() - header.IPv4MinimumSize - int(dataOff)
		if !tcpHdr.IsChecksumValid(ipHdr.SourceAddress(), ipHdr.DestinationAddress(), payloadChecksum, uint16(tcpPayloadSize)) {
			gd.handlePacket(pkt)
			return
		}
		pkt.RXChecksumValidated = true
	}

	bucket := &gd.buckets[gd.bucketForPacket4(ipHdr, tcpHdr)&groNBucketsMask]
	groPkt, flushGROPkt := bucket.findGROPacket4(pkt, ipHdr, tcpHdr)
	bucket.found(gd, groPkt, flushGROPkt, pkt, ipHdr, tcpHdr, updateIPv4Hdr)
}

func (gd *GRO) dispatch6(pkt *stack.PacketBuffer) {

	hdrBytes, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		gd.handlePacket(pkt)
		return
	}
	ipHdr := header.IPv6(hdrBytes)

	transProto := tcpip.TransportProtocolNumber(ipHdr.NextHeader())
	buf := pkt.Data().ToBuffer()
	buf.TrimFront(header.IPv6MinimumSize)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(transProto), buf)
	ipHdrSize := int(header.IPv6MinimumSize)
	for {
		transProto = tcpip.TransportProtocolNumber(it.NextHeaderIdentifier())
		extHdr, done, err := it.Next()
		if err != nil {
			gd.handlePacket(pkt)
			return
		}
		if done {
			break
		}
		switch extHdr.(type) {
		case header.IPv6HopByHopOptionsExtHdr:
		case header.IPv6RoutingExtHdr:
		case header.IPv6DestinationOptionsExtHdr:
		case header.IPv6ExperimentExtHdr:
		default:
			ipHdrSize = int(it.HeaderOffset())
			done = true
		}
		extHdr.Release()
		if done {
			break
		}
	}

	hdrBytes, ok = pkt.Data().PullUp(ipHdrSize + header.TCPMinimumSize)
	if !ok {
		gd.handlePacket(pkt)
		return
	}
	ipHdr = header.IPv6(hdrBytes[:ipHdrSize])

	if transProto != header.TCPProtocolNumber {
		gd.handlePacket(pkt)
		return
	}
	tcpHdr := header.TCP(hdrBytes[ipHdrSize:])
	dataOff := tcpHdr.DataOffset()
	if dataOff < header.TCPMinimumSize {
		gd.handlePacket(pkt)
		return
	}

	hdrBytes, ok = pkt.Data().PullUp(ipHdrSize + int(dataOff))
	if !ok {
		gd.handlePacket(pkt)
		return
	}
	tcpHdr = header.TCP(hdrBytes[ipHdrSize:])

	if !pkt.RXChecksumValidated {
		if !ipHdr.IsValid(pkt.Data().Size()) {
			gd.handlePacket(pkt)
			return
		}
		payloadChecksum := pkt.Data().ChecksumAtOffset(ipHdrSize + int(dataOff))
		tcpPayloadSize := pkt.Data().Size() - ipHdrSize - int(dataOff)
		if !tcpHdr.IsChecksumValid(ipHdr.SourceAddress(), ipHdr.DestinationAddress(), payloadChecksum, uint16(tcpPayloadSize)) {
			gd.handlePacket(pkt)
			return
		}
		pkt.RXChecksumValidated = true
	}

	bucket := &gd.buckets[gd.bucketForPacket6(ipHdr, tcpHdr)&groNBucketsMask]
	groPkt, flushGROPkt := bucket.findGROPacket6(pkt, ipHdr, tcpHdr)
	bucket.found(gd, groPkt, flushGROPkt, pkt, ipHdr, tcpHdr, updateIPv6Hdr)
}

func (gd *GRO) bucketForPacket4(ipHdr header.IPv4, tcpHdr header.TCP) int {
	var sum int
	srcAddr := ipHdr.SourceAddress()
	for _, val := range srcAddr.AsSlice() {
		sum += int(val)
	}
	dstAddr := ipHdr.DestinationAddress()
	for _, val := range dstAddr.AsSlice() {
		sum += int(val)
	}
	sum += int(tcpHdr.SourcePort())
	sum += int(tcpHdr.DestinationPort())
	return sum
}

func (gd *GRO) bucketForPacket6(ipHdr header.IPv6, tcpHdr header.TCP) int {
	var sum int
	srcAddr := ipHdr.SourceAddress()
	for _, val := range srcAddr.AsSlice() {
		sum += int(val)
	}
	dstAddr := ipHdr.DestinationAddress()
	for _, val := range dstAddr.AsSlice() {
		sum += int(val)
	}
	sum += int(tcpHdr.SourcePort())
	sum += int(tcpHdr.DestinationPort())
	return sum
}

func (gd *GRO) Flush() {
	for i := range gd.buckets {
		for groPkt := gd.buckets[i].packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
			pkt := groPkt.pkt
			gd.buckets[i].removeOne(groPkt)
			gd.handlePacket(pkt)
			pkt.DecRef()
		}
	}
}

func (gd *GRO) handlePacket(pkt *stack.PacketBuffer) {
	gd.Dispatcher.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
}

func (gd *GRO) String() string {
	ret := "GRO state: \n"
	for i := range gd.buckets {
		bucket := &gd.buckets[i]
		ret += fmt.Sprintf("bucket %d: %d packets: ", i, bucket.count)
		for groPkt := bucket.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
			ret += fmt.Sprintf("%d, ", groPkt.pkt.Data().Size())
		}
		ret += "\n"
	}
	return ret
}

func shouldFlushTCP(groPkt *groPacket, tcpHdr header.TCP) bool {
	flags := tcpHdr.Flags()
	groPktFlags := groPkt.tcpHdr.Flags()
	dataOff := tcpHdr.DataOffset()
	if flags&header.TCPFlagCwr != 0 ||
		(flags^groPktFlags)&^(header.TCPFlagCwr|header.TCPFlagFin|header.TCPFlagPsh) != 0 ||
		tcpHdr.AckNumber() != groPkt.tcpHdr.AckNumber() ||
		dataOff != groPkt.tcpHdr.DataOffset() ||
		groPkt.tcpHdr.SequenceNumber()+uint32(groPkt.payloadSize()) != tcpHdr.SequenceNumber() {
		return true
	}
	return !bytes.Equal(tcpHdr[header.TCPMinimumSize:], groPkt.tcpHdr[header.TCPMinimumSize:])
}

func updateIPv4Hdr(ipHdrBytes []byte, newBytes int) {
	ipHdr := header.IPv4(ipHdrBytes)
	ipHdr.SetTotalLength(ipHdr.TotalLength() + uint16(newBytes))
}

func updateIPv6Hdr(ipHdrBytes []byte, newBytes int) {
	ipHdr := header.IPv6(ipHdrBytes)
	ipHdr.SetPayloadLength(ipHdr.PayloadLength() + uint16(newBytes))
}

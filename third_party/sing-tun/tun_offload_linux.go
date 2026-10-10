/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"

	"golang.org/x/sys/unix"
)

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) toGSOOptions() (GSOOptions, error) {
	var gsoType GSOType
	switch v.gsoType {
	case unix.VIRTIO_NET_HDR_GSO_NONE:
		gsoType = GSONone
	case unix.VIRTIO_NET_HDR_GSO_TCPV4:
		gsoType = GSOTCPv4
	case unix.VIRTIO_NET_HDR_GSO_TCPV6:
		gsoType = GSOTCPv6
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		gsoType = GSOUDPL4
	default:
		return GSOOptions{}, fmt.Errorf("unsupported virtio gsoType: %d", v.gsoType)
	}
	return GSOOptions{
		GSOType:    gsoType,
		HdrLen:     v.hdrLen,
		CsumStart:  v.csumStart,
		CsumOffset: v.csumOffset,
		GSOSize:    v.gsoSize,
		NeedsCsum:  v.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0,
	}, nil
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

const (
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	rxAck            uint32
	isV6             bool
}

type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, idealBatchSize),
		itemsPool:   make([][]tcpGROItem, idealBatchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, idealBatchSize)
	}
	return t
}

func newTCPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset int) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	key.isV6 = addrSize == 16
	return key
}

func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	t.insert(key, pkt, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

func (t *tcpGROTable) insert(key tcpFlowKey, pkt []byte, tcphOffset, tcphLen, bufsIndex int) {
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		sentSeq:   binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:    pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items, _ := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

type tcpGROItem struct {
	key       tcpFlowKey
	sentSeq   uint32
	bufsIndex uint16
	numMerged uint16
	gsoSize   uint16
	iphLen    uint8
	tcphLen   uint8
	pshSet    bool
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, k)
	}
}

type udpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	isV6             bool
}

type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem
	itemsPool   [][]udpGROItem
}

func newUDPGROTable() *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, idealBatchSize),
		itemsPool:   make([][]udpGROItem, idealBatchSize),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, idealBatchSize)
	}
	return u
}

func newUDPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset int) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

func (u *udpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	u.insert(key, pkt, udphOffset, bufsIndex, false)
	return nil, false
}

func (u *udpGROTable) insert(key udpFlowKey, pkt []byte, udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	item := udpGROItem{
		key:              key,
		bufsIndex:        uint16(bufsIndex),
		gsoSize:          uint16(len(pkt[udphOffset+udphLen:])),
		iphLen:           uint8(udphOffset),
		cSumKnownInvalid: cSumKnownInvalid,
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items, _ := u.itemsByFlow[item.key]
	items[i] = item
}

type udpGROItem struct {
	key              udpFlowKey
	bufsIndex        uint16
	numMerged        uint16
	gsoSize          uint16
	iphLen           uint8
	cSumKnownInvalid bool
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, k)
	}
}

type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	if pktA[0]>>4 == 6 {
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			return false
		}
		if pktA[7] != pktB[7] {
			return false
		}
	} else {
		if pktA[1] != pktB[1] {
			return false
		}
		if pktA[6]>>5 != pktB[6]>>5 {
			return false
		}
		if pktA[8] != pktB[8] {
			return false
		}
	}
	return true
}

func udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16, item udpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	pktTarget := bufs[item.bufsIndex][bufsOffset:]
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	if len(pktTarget[iphLen+udphLen:])%int(item.gsoSize) != 0 {
		return coalesceUnavailable
	}
	if gsoSize > item.gsoSize {
		return coalesceUnavailable
	}
	return coalesceAppend
}

func tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8, seq uint32, pshSet bool, gsoSize uint16, item tcpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	pktTarget := bufs[item.bufsIndex][bufsOffset:]
	if tcphLen != item.tcphLen {
		return coalesceUnavailable
	}
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen], pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			return coalesceUnavailable
		}
	}
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize
	if seq == item.sentSeq+uint32(lhsLen) {
		if item.pshSet {
			return coalesceUnavailable
		}
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize {
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq {
		if pshSet {
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

func checksumValid(pkt []byte, iphLen, proto uint8, isV6 bool) bool {
	srcAddrAt := ipv4SrcAddrOffset
	addrSize := 4
	if isV6 {
		srcAddrAt = ipv6SrcAddrOffset
		addrSize = 16
	}
	lenForPseudo := uint16(len(pkt) - int(iphLen))
	cSum := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(proto), pkt[srcAddrAt:srcAddrAt+addrSize], pkt[srcAddrAt+addrSize:srcAddrAt+addrSize*2], lenForPseudo)
	return ^checksum.Checksum(pkt[iphLen:], cSum) == 0
}

type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidCSum
	coalescePktInvalidCSum
	coalesceSuccess
)

func coalesceUDPPackets(pkt []byte, item *udpGROItem, bufs [][]byte, bufsOffset int, isV6 bool) coalesceResult {
	pktHead := bufs[item.bufsIndex][bufsOffset:]
	headersLen := item.iphLen + udphLen
	coalescedLen := len(bufs[item.bufsIndex][bufsOffset:]) + len(pkt) - int(headersLen)

	if cap(pktHead)-bufsOffset < coalescedLen {
		return coalesceInsufficientCap
	}
	if item.numMerged == 0 {
		if item.cSumKnownInvalid || !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_UDP, isV6) {
			return coalesceItemInvalidCSum
		}
	}
	if !checksumValid(pkt, item.iphLen, unix.IPPROTO_UDP, isV6) {
		return coalescePktInvalidCSum
	}
	extendBy := len(pkt) - int(headersLen)
	b := bufs[item.bufsIndex]
	bufs[item.bufsIndex] = b[:len(b)+extendBy]
	copy(bufs[item.bufsIndex][bufsOffset+len(pktHead):], pkt[headersLen:])

	item.numMerged++
	return coalesceSuccess
}

func coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int, gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, bufs [][]byte, bufsOffset int, isV6 bool) coalesceResult {
	var pktHead []byte
	headersLen := item.iphLen + item.tcphLen
	coalescedLen := len(bufs[item.bufsIndex][bufsOffset:]) + len(pkt) - int(headersLen)

	if mode == coalescePrepend {
		pktHead = pkt
		if cap(pkt)-bufsOffset < coalescedLen {
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		item.sentSeq = seq
		extendBy := coalescedLen - len(pktHead)
		b := bufs[pktBuffsIndex]
		bufs[pktBuffsIndex] = b[:len(b)+extendBy]
		copy(bufs[pktBuffsIndex][bufsOffset+len(pkt):], bufs[item.bufsIndex][bufsOffset+int(headersLen):])
		bufs[item.bufsIndex], bufs[pktBuffsIndex] = bufs[pktBuffsIndex], bufs[item.bufsIndex]
	} else {
		pktHead = bufs[item.bufsIndex][bufsOffset:]
		if cap(pktHead)-bufsOffset < coalescedLen {
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		if pshSet {
			item.pshSet = pshSet
			pktHead[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		extendBy := len(pkt) - int(headersLen)
		b := bufs[item.bufsIndex]
		bufs[item.bufsIndex] = b[:len(b)+extendBy]
		copy(bufs[item.bufsIndex][bufsOffset+len(pktHead):], pkt[headersLen:])
	}

	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}

	item.numMerged++
	return coalesceSuccess
}

const (
	ipv4FlagMoreFragments uint8 = 0x20
)

const (
	maxUint16 = 1<<16 - 1
)

type groResult int

const (
	groResultNoop groResult = iota
	groResultTableInsert
	groResultCoalesced
)

func tcpGRO(bufs [][]byte, offset int, pktI int, table *tcpGROTable, isV6 bool) groResult {
	pkt := bufs[pktI][offset:]
	if len(pkt) > maxUint16 {
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	if len(pkt) < iphLen+tcphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			return groResultNoop
		}
	}
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	if tcpFlags != tcpFlagACK {
		if pkt[iphLen+tcpFlagsOffset] != tcpFlagACK|tcpFlagPSH {
			return groResultNoop
		}
		pshSet = true
	}
	gsoSize := uint16(len(pkt) - tcphLen - iphLen)
	if gsoSize < 1 {
		return groResultNoop
	}
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	if len(bufs) == 1 {
		return groResultNoop
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	for i := len(items) - 1; i >= 0; i-- {
		item := items[i]
		can := tcpPacketsCanCoalesce(pkt, uint8(iphLen), uint8(tcphLen), seq, pshSet, gsoSize, item, bufs, offset)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(can, pkt, pktI, gsoSize, seq, pshSet, &item, bufs, offset, isV6)
			switch result {
			case coalesceSuccess:
				table.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidCSum:
				table.deleteAt(item.key, i)
			case coalescePktInvalidCSum:
				return groResultNoop
			default:
			}
		}
	}
	table.insert(newTCPFlowKey(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen), pkt, iphLen, tcphLen, pktI)
	return groResultTableInsert
}

func applyTCPCoalesceAccounting(bufs [][]byte, offset int, table *tcpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:     uint16(item.iphLen + item.tcphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 16,
				}
				pkt := bufs[item.bufsIndex][offset:]

				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen))
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					iphCSum := ^checksum.Checksum(pkt[:item.iphLen], 0)
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)
				}
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}

				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				psum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum.Checksum([]byte{}, psum))
			} else {
				hdr := virtioNetHdr{}
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func applyUDPCoalesceAccounting(bufs [][]byte, offset int, table *udpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:     uint16(item.iphLen + udphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 6,
				}
				pkt := bufs[item.bufsIndex][offset:]

				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen))
				} else {
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					iphCSum := ^checksum.Checksum(pkt[:item.iphLen], 0)
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)
				}
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}

				binary.BigEndian.PutUint16(pkt[item.iphLen+4:], uint16(len(pkt[item.iphLen:])))

				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				psum := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum.Checksum([]byte{}, psum))
			} else {
				hdr := virtioNetHdr{}
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type groCandidateType uint8

const (
	notGROCandidate groCandidateType = iota
	tcp4GROCandidate
	tcp6GROCandidate
	udp4GROCandidate
	udp6GROCandidate
)

type groDisablementFlags int

const (
	tcpGRODisabled groDisablementFlags = 1 << iota
	udpGRODisabled
)

func (g *groDisablementFlags) disableTCPGRO() {
	*g |= tcpGRODisabled
}

func (g *groDisablementFlags) canTCPGRO() bool {
	return (*g)&tcpGRODisabled == 0
}

func (g *groDisablementFlags) disableUDPGRO() {
	*g |= udpGRODisabled
}

func (g *groDisablementFlags) canUDPGRO() bool {
	return (*g)&udpGRODisabled == 0
}

func packetIsGROCandidate(b []byte, gro groDisablementFlags) groCandidateType {
	if len(b) < 28 {
		return notGROCandidate
	}
	if b[0]>>4 == 4 {
		if b[0]&0x0F != 5 {
			return notGROCandidate
		}
		if b[9] == unix.IPPROTO_TCP && len(b) >= 40 && gro.canTCPGRO() {
			return tcp4GROCandidate
		}
		if b[9] == unix.IPPROTO_UDP && gro.canUDPGRO() {
			return udp4GROCandidate
		}
	} else if b[0]>>4 == 6 {
		if b[6] == unix.IPPROTO_TCP && len(b) >= 60 && gro.canTCPGRO() {
			return tcp6GROCandidate
		}
		if b[6] == unix.IPPROTO_UDP && len(b) >= 48 && gro.canUDPGRO() {
			return udp6GROCandidate
		}
	}
	return notGROCandidate
}

const (
	udphLen = 8
)

func udpGRO(bufs [][]byte, offset int, pktI int, table *udpGROTable, isV6 bool) groResult {
	pkt := bufs[pktI][offset:]
	if len(pkt) > maxUint16 {
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	if len(pkt) < iphLen+udphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			return groResultNoop
		}
	}
	gsoSize := uint16(len(pkt) - udphLen - iphLen)
	if gsoSize < 1 {
		return groResultNoop
	}
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	if len(bufs) == 1 {
		return groResultNoop
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	item := items[len(items)-1]
	can := udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, item, bufs, offset)
	var pktCSumKnownInvalid bool
	if can == coalesceAppend {
		result := coalesceUDPPackets(pkt, &item, bufs, offset, isV6)
		switch result {
		case coalesceSuccess:
			table.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidCSum:
		case coalescePktInvalidCSum:
			pktCSumKnownInvalid = true
		default:
		}
	}
	table.insert(newUDPFlowKey(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen), pkt, iphLen, pktI, pktCSumKnownInvalid)
	return groResultTableInsert
}

func handleGRO(bufs [][]byte, offset int, tcpTable *tcpGROTable, udpTable *udpGROTable, gro groDisablementFlags, toWrite *[]int) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var result groResult
		switch packetIsGROCandidate(bufs[i][offset:], gro) {
		case tcp4GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, true)
		case udp4GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, false)
		case udp6GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, true)
		}
		switch result {
		case groResultNoop:
			hdr := virtioNetHdr{}
			err := hdr.encode(bufs[i][offset-virtioNetHdrLen:])
			if err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(bufs, offset, tcpTable)
	errUDP := applyUDPCoalesceAccounting(bufs, offset, udpTable)
	return errors.Join(errTCP, errUDP)
}

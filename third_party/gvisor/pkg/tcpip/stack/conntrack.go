// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/hash/jenkins"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcpconntrack"
)


const numBuckets = 1 << 14

const (
	establishedTimeout   time.Duration = 5 * 24 * time.Hour
	unestablishedTimeout time.Duration = 120 * time.Second
)

type ConnTrackState int

const (
	ConnTrackStateInvalid ConnTrackState = -1
	ConnTrackStateEstablished ConnTrackState = 0
	ConnTrackStateNew ConnTrackState = 2
	ConnTrackStateEstablishedReply ConnTrackState = 3
)

type ConnTrackDirection uint8

const (
	ConnTrackDirectionOriginal ConnTrackDirection = 0
	ConnTrackDirectionReply ConnTrackDirection = 1
)

type tuple struct {
	tupleEntry

	conn *conn

	reply bool

	tupleID tupleID
}

type tupleID struct {
	srcAddr tcpip.Address
	srcPortOrEchoRequestIdent uint16
	dstAddr                   tcpip.Address
	dstPortOrEchoReplyIdent uint16
	transProto              tcpip.TransportProtocolNumber
	netProto                tcpip.NetworkProtocolNumber
}

func (ti tupleID) reply() tupleID {
	return tupleID{
		srcAddr:                   ti.dstAddr,
		srcPortOrEchoRequestIdent: ti.dstPortOrEchoReplyIdent,
		dstAddr:                   ti.srcAddr,
		dstPortOrEchoReplyIdent:   ti.srcPortOrEchoRequestIdent,
		transProto:                ti.transProto,
		netProto:                  ti.netProto,
	}
}

type manipType int

const (
	manipNotPerformed manipType = iota

	manipPerformed

	manipPerformedNoop
)

type finalizeResult uint32

const (
	_ finalizeResult = iota

	finalizeResultSuccess
	finalizeResultConflict
)

type conn struct {
	ct *ConnTrack

	original tuple

	reply tuple

	finalizeOnce sync.Once `state:"nosave"`
	finalizeResult atomicbitops.Uint32

	mu connRWMutex `state:"nosave"`
	sourceManip manipType
	destinationManip manipType

	stateMu stateConnRWMutex `state:"nosave"`
	tcb tcpconntrack.TCB
	lastUsed tcpip.MonotonicTime
	replySeen bool
}

func (cn *conn) timedOut(now tcpip.MonotonicTime) bool {
	cn.stateMu.RLock()
	defer cn.stateMu.RUnlock()
	if cn.tcb.State() == tcpconntrack.ResultAlive {
		return now.Sub(cn.lastUsed) > establishedTimeout
	}
	return now.Sub(cn.lastUsed) > unestablishedTimeout
}

func (cn *conn) expiresIn() time.Duration {
	var timeout time.Duration
	var lastUsed tcpip.MonotonicTime
	cn.stateMu.RLock()
	state := cn.tcb.State()
	lastUsed = cn.lastUsed
	cn.stateMu.RUnlock()
	if state == tcpconntrack.ResultAlive {
		timeout = establishedTimeout
	} else {
		timeout = unestablishedTimeout
	}
	now := cn.ct.clock.NowMonotonic()
	expires := timeout - now.Sub(lastUsed)
	if expires < 0 {
		return 0
	}
	return expires
}

func (cn *conn) update(pkt *PacketBuffer, reply bool) {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()

	cn.lastUsed = cn.ct.clock.NowMonotonic()
	if reply {
		cn.replySeen = true
	}

	if pkt.TransportProtocolNumber != header.TCPProtocolNumber {
		return
	}

	tcpHeader := header.TCP(pkt.TransportHeader().Slice())

	if cn.tcb.IsEmpty() {
		cn.tcb.Init(tcpHeader, pkt.Data().Size())
		return
	}

	if reply {
		cn.tcb.UpdateStateReply(tcpHeader, pkt.Data().Size())
	} else {
		cn.tcb.UpdateStateOriginal(tcpHeader, pkt.Data().Size())
	}
}

type connTrackRNG interface {
	Uint32() uint32
}

type ConnTrack struct {
	seed uint32

	nftIDSeed uint32

	clock tcpip.Clock
	rng connTrackRNG `state:"nosave"`

	mu connTrackRWMutex `state:"nosave"`
	buckets []bucket
}

type bucket struct {
	mu bucketRWMutex `state:"nosave"`
	tuples tupleList
}

type netAndTransHeadersFunc func(icmpPayload []byte, minTransHdrLen int) (netHdr header.Network, transHdrBytes []byte)

func v4NetAndTransHdr(icmpPayload []byte, minTransHdrLen int) (header.Network, []byte) {
	netHdr := header.IPv4(icmpPayload)
	transHdr := icmpPayload[netHdr.HeaderLength():]
	return netHdr, transHdr[:minTransHdrLen]
}

func v6NetAndTransHdr(icmpPayload []byte, minTransHdrLen int) (header.Network, []byte) {
	netHdr := header.IPv6(icmpPayload)
	transHdr := icmpPayload[header.IPv6MinimumSize:]
	return netHdr, transHdr[:minTransHdrLen]
}

func getTupleIDForRegularPacket(netHdr header.Network, netProto tcpip.NetworkProtocolNumber, transHdr header.Transport, transProto tcpip.TransportProtocolNumber) tupleID {
	return tupleID{
		srcAddr:                   netHdr.SourceAddress(),
		srcPortOrEchoRequestIdent: transHdr.SourcePort(),
		dstAddr:                   netHdr.DestinationAddress(),
		dstPortOrEchoReplyIdent:   transHdr.DestinationPort(),
		transProto:                transProto,
		netProto:                  netProto,
	}
}

func getTupleIDForPacketInICMPError(pkt *PacketBuffer, getNetAndTransHdr netAndTransHeadersFunc, netProto tcpip.NetworkProtocolNumber, netLen int, transProto tcpip.TransportProtocolNumber) (tupleID, bool) {
	if netHdr, transHdr, ok := pkt.GetEmbeddedNetAndTransHeaders(netLen, getNetAndTransHdr, transProto); ok {
		return tupleID{
			srcAddr:                   netHdr.DestinationAddress(),
			srcPortOrEchoRequestIdent: transHdr.DestinationPort(),
			dstAddr:                   netHdr.SourceAddress(),
			dstPortOrEchoReplyIdent:   transHdr.SourcePort(),
			transProto:                transProto,
			netProto:                  netProto,
		}, true
	}

	return tupleID{}, false
}

type getTupleIDDisposition int

const (
	getTupleIDNotOK getTupleIDDisposition = iota
	getTupleIDOKAndAllowNewConn
	getTupleIDOKAndDontAllowNewConn
)

func getTupleIDForEchoPacket(pkt *PacketBuffer, ident uint16, request bool) tupleID {
	netHdr := pkt.Network()
	tid := tupleID{
		srcAddr:    netHdr.SourceAddress(),
		dstAddr:    netHdr.DestinationAddress(),
		transProto: pkt.TransportProtocolNumber,
		netProto:   pkt.NetworkProtocolNumber,
	}

	if request {
		tid.srcPortOrEchoRequestIdent = ident
	} else {
		tid.dstPortOrEchoReplyIdent = ident
	}

	return tid
}

func getTupleID(pkt *PacketBuffer) (tupleID, getTupleIDDisposition) {
	switch pkt.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		if transHeader := header.TCP(pkt.TransportHeader().Slice()); len(transHeader) >= header.TCPMinimumSize {
			return getTupleIDForRegularPacket(pkt.Network(), pkt.NetworkProtocolNumber, transHeader, pkt.TransportProtocolNumber), getTupleIDOKAndAllowNewConn
		}
	case header.UDPProtocolNumber:
		if transHeader := header.UDP(pkt.TransportHeader().Slice()); len(transHeader) >= header.UDPMinimumSize {
			return getTupleIDForRegularPacket(pkt.Network(), pkt.NetworkProtocolNumber, transHeader, pkt.TransportProtocolNumber), getTupleIDOKAndAllowNewConn
		}
	case header.ICMPv4ProtocolNumber:
		icmp := header.ICMPv4(pkt.TransportHeader().Slice())
		if len(icmp) < header.ICMPv4MinimumSize {
			return tupleID{}, getTupleIDNotOK
		}

		switch icmp.Type() {
		case header.ICMPv4Echo:
			return getTupleIDForEchoPacket(pkt, icmp.Ident(), true), getTupleIDOKAndAllowNewConn
		case header.ICMPv4EchoReply:
			return getTupleIDForEchoPacket(pkt, icmp.Ident(), false), getTupleIDOKAndDontAllowNewConn
		case header.ICMPv4DstUnreachable, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
		default:
			return tupleID{}, getTupleIDNotOK
		}

		h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
		if !ok {
			return tupleID{}, getTupleIDNotOK
		}

		ipv4 := header.IPv4(h)
		if ipv4.HeaderLength() > header.IPv4MinimumSize {
			return tupleID{}, getTupleIDNotOK
		}

		if tid, ok := getTupleIDForPacketInICMPError(pkt, v4NetAndTransHdr, header.IPv4ProtocolNumber, header.IPv4MinimumSize, ipv4.TransportProtocol()); ok {
			return tid, getTupleIDOKAndDontAllowNewConn
		}
	case header.ICMPv6ProtocolNumber:
		icmp := header.ICMPv6(pkt.TransportHeader().Slice())
		if len(icmp) < header.ICMPv6MinimumSize {
			return tupleID{}, getTupleIDNotOK
		}

		switch icmp.Type() {
		case header.ICMPv6EchoRequest:
			return getTupleIDForEchoPacket(pkt, icmp.Ident(), true), getTupleIDOKAndAllowNewConn
		case header.ICMPv6EchoReply:
			return getTupleIDForEchoPacket(pkt, icmp.Ident(), false), getTupleIDOKAndDontAllowNewConn
		case header.ICMPv6DstUnreachable, header.ICMPv6PacketTooBig, header.ICMPv6TimeExceeded, header.ICMPv6ParamProblem:
		default:
			return tupleID{}, getTupleIDNotOK
		}

		h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
		if !ok {
			return tupleID{}, getTupleIDNotOK
		}

		if tid, ok := getTupleIDForPacketInICMPError(pkt, v6NetAndTransHdr, header.IPv6ProtocolNumber, header.IPv6MinimumSize, header.IPv6(h).TransportProtocol()); ok {
			return tid, getTupleIDOKAndDontAllowNewConn
		}
	}

	return tupleID{}, getTupleIDNotOK
}

func (ct *ConnTrack) init() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.buckets = make([]bucket, numBuckets)
}

func (ct *ConnTrack) getConnAndUpdate(pkt *PacketBuffer, skipChecksumValidation bool) *tuple {
	t := func() *tuple {
		var allowNewConn bool
		tid, res := getTupleID(pkt)
		switch res {
		case getTupleIDNotOK:
			return nil
		case getTupleIDOKAndAllowNewConn:
			allowNewConn = true
		case getTupleIDOKAndDontAllowNewConn:
			allowNewConn = false
		default:
			panic(fmt.Sprintf("unhandled %[1]T = %[1]d", res))
		}

		switch pkt.TransportProtocolNumber {
		case header.TCPProtocolNumber:
			_, csumValid, ok := header.TCPValid(
				header.TCP(pkt.TransportHeader().Slice()),
				func() uint16 { return pkt.Data().Checksum() },
				uint16(pkt.Data().Size()),
				tid.srcAddr,
				tid.dstAddr,
				pkt.RXChecksumValidated || skipChecksumValidation)
			if !csumValid || !ok {
				return nil
			}
		case header.UDPProtocolNumber:
			lengthValid, csumValid := header.UDPValid(
				header.UDP(pkt.TransportHeader().Slice()),
				func() uint16 { return pkt.Data().Checksum() },
				uint16(pkt.Data().Size()),
				pkt.NetworkProtocolNumber,
				tid.srcAddr,
				tid.dstAddr,
				pkt.RXChecksumValidated || skipChecksumValidation)
			if !lengthValid || !csumValid {
				return nil
			}
		}

		ct.mu.RLock()
		bkt := &ct.buckets[ct.bucket(tid)]
		ct.mu.RUnlock()

		now := ct.clock.NowMonotonic()
		if t := bkt.connForTID(tid, now); t != nil {
			return t
		}

		if !allowNewConn {
			return nil
		}

		bkt.mu.Lock()
		defer bkt.mu.Unlock()

		if t := bkt.connForTIDRLocked(tid, now); t != nil {
			return t
		}

		conn := &conn{
			ct:       ct,
			original: tuple{tupleID: tid},
			reply:    tuple{tupleID: tid.reply(), reply: true},
			lastUsed: now,
		}
		conn.original.conn = conn
		conn.reply.conn = conn

		bkt.tuples.PushFront(&conn.original)
		return &conn.original
	}()
	if t != nil {
		t.conn.update(pkt, t.reply)
	}
	return t
}

func (ct *ConnTrack) GetConnAndUpdatePkt(pkt *PacketBuffer, skipChecksumValidation bool) {
	pkt.tuple = ct.getConnAndUpdate(pkt, skipChecksumValidation)
}

func (ct *ConnTrack) connForTID(tid tupleID) *tuple {
	ct.mu.RLock()
	bkt := &ct.buckets[ct.bucket(tid)]
	ct.mu.RUnlock()

	return bkt.connForTID(tid, ct.clock.NowMonotonic())
}

type ConnTrackInfo struct {
	State      ConnTrackState
	Direction  ConnTrackDirection
	SrcAddr    tcpip.Address
	DstAddr    tcpip.Address
	SrcPort    uint16
	DstPort    uint16
	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber
	Expiration time.Duration
	PseudoID   uint32
	Bytes      uint64
	Packets    uint64
}

type ConnTrackInfoOpts struct {
	FillState      bool
	UseReplyDir    bool
	FillPseudoID   bool
	FillExpiration bool
}

func (cn *conn) getTCPConnTrackState(useReplyDir bool) ConnTrackState {
	state := ConnTrackStateInvalid
	cn.stateMu.RLock()
	tcbState := cn.tcb.State()
	cn.stateMu.RUnlock()
	switch tcbState {
	case tcpconntrack.ResultConnecting:
		state = ConnTrackStateNew

	case tcpconntrack.ResultAlive, tcpconntrack.ResultReset,
		tcpconntrack.ResultClosedByOriginator, tcpconntrack.ResultClosedByResponder:

		if useReplyDir {
			state = ConnTrackStateEstablishedReply
		} else {
			state = ConnTrackStateEstablished
		}
	case tcpconntrack.ResultDrop:
		state = ConnTrackStateInvalid
	}
	return state
}

func (cn *conn) getConnTrackState(useReplyDir bool) ConnTrackState {
	state := ConnTrackStateInvalid
	if cn.original.tupleID.transProto == header.TCPProtocolNumber {
		return cn.getTCPConnTrackState(useReplyDir)
	}
	cn.stateMu.RLock()
	replySeen := cn.replySeen
	cn.stateMu.RUnlock()
	if useReplyDir {
		state = ConnTrackStateEstablishedReply
	} else if replySeen {
		state = ConnTrackStateEstablished
	} else {
		state = ConnTrackStateNew
	}
	return state
}

func (cn *conn) FillConnTrackInfo(opts ConnTrackInfoOpts, info *ConnTrackInfo) bool {
	state := ConnTrackStateInvalid
	if opts.FillState {
		state = cn.getConnTrackState(opts.UseReplyDir)
	}

	dir := ConnTrackDirectionOriginal
	t := &cn.original
	if opts.UseReplyDir {
		t = &cn.reply
		dir = ConnTrackDirectionReply
	}
	tID := t.tupleID

	pID := uint32(0)
	if opts.FillPseudoID {
		pID = tupleHash(cn.original.tupleID, cn.ct.nftIDSeed)
	}

	var expires time.Duration
	if opts.FillExpiration {
		expires = cn.expiresIn()
	}

	info.State = state
	info.Direction = dir
	info.SrcAddr = tID.srcAddr
	info.DstAddr = tID.dstAddr
	info.SrcPort = tID.srcPortOrEchoRequestIdent
	info.DstPort = tID.dstPortOrEchoReplyIdent
	info.NetProto = tID.netProto
	info.TransProto = tID.transProto
	info.Expiration = expires
	info.PseudoID = pID
	return true
}

func (bkt *bucket) connForTID(tid tupleID, now tcpip.MonotonicTime) *tuple {
	bkt.mu.RLock()
	defer bkt.mu.RUnlock()
	return bkt.connForTIDRLocked(tid, now)
}

func (bkt *bucket) connForTIDRLocked(tid tupleID, now tcpip.MonotonicTime) *tuple {
	for other := bkt.tuples.Front(); other != nil; other = other.Next() {
		if tid == other.tupleID && !other.conn.timedOut(now) {
			return other
		}
	}
	return nil
}

func (ct *ConnTrack) finalize(cn *conn) finalizeResult {
	ct.mu.RLock()
	buckets := ct.buckets
	ct.mu.RUnlock()

	{
		tid := cn.reply.tupleID
		id := ct.bucketWithTableLength(tid, len(buckets))

		bkt := &buckets[id]
		bkt.mu.Lock()
		t := bkt.connForTIDRLocked(tid, ct.clock.NowMonotonic())
		if t == nil {
			bkt.tuples.PushFront(&cn.reply)
			bkt.mu.Unlock()
			return finalizeResultSuccess
		}
		bkt.mu.Unlock()

		if t.conn == cn {
			return finalizeResultSuccess
		}
	}


	tid := cn.original.tupleID
	id := ct.bucketWithTableLength(tid, len(buckets))
	bkt := &buckets[id]
	bkt.mu.Lock()
	defer bkt.mu.Unlock()
	bkt.tuples.Remove(&cn.original)
	return finalizeResultConflict
}

func (cn *conn) getFinalizeResult() finalizeResult {
	return finalizeResult(cn.finalizeResult.Load())
}

func (cn *conn) finalize() bool {
	cn.finalizeOnce.Do(func() {
		cn.finalizeResult.Store(uint32(cn.ct.finalize(cn)))
	})

	switch res := cn.getFinalizeResult(); res {
	case finalizeResultSuccess:
		return true
	case finalizeResultConflict:
		return false
	default:
		panic(fmt.Sprintf("unhandled result = %d", res))
	}
}

func (ct *ConnTrack) bucket(id tupleID) int {
	return ct.bucketWithTableLength(id, len(ct.buckets))
}

func tupleHash(id tupleID, seed uint32) uint32 {
	h := jenkins.Sum32(seed)
	h.Write(id.srcAddr.AsSlice())
	h.Write(id.dstAddr.AsSlice())
	shortBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(shortBuf, id.srcPortOrEchoRequestIdent)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, id.dstPortOrEchoReplyIdent)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.transProto))
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.netProto))
	h.Write([]byte(shortBuf))
	return h.Sum32()
}

func (ct *ConnTrack) bucketWithTableLength(id tupleID, tableLength int) int {
	h := tupleHash(id, ct.seed)
	return int(h) % tableLength
}

func (ct *ConnTrack) reapUnused(start int, prevInterval time.Duration) (int, time.Duration) {
	const fractionPerReaping = 128
	const maxExpiredPct = 50
	const maxFullTraversal = 60 * time.Second
	const minInterval = 10 * time.Millisecond
	const maxInterval = maxFullTraversal / fractionPerReaping

	now := ct.clock.NowMonotonic()
	checked := 0
	expired := 0
	var idx int
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	for i := 0; i < len(ct.buckets)/fractionPerReaping; i++ {
		idx = (i + start) % len(ct.buckets)
		bkt := &ct.buckets[idx]
		bkt.mu.Lock()
		for tuple := bkt.tuples.Front(); tuple != nil; {
			nextTuple := tuple.Next()

			checked++
			if ct.reapTupleLocked(tuple, idx, bkt, now) {
				expired++
			}

			tuple = nextTuple
		}
		bkt.mu.Unlock()
	}
	idx++

	expiredPct := 0
	if checked != 0 {
		expiredPct = expired * 100 / checked
	}
	if expiredPct > maxExpiredPct {
		return idx, minInterval
	}
	if interval := prevInterval + minInterval; interval <= maxInterval {
		return idx, interval
	}
	return idx, maxInterval
}

func (ct *ConnTrack) reapTupleLocked(reapingTuple *tuple, bktID int, bkt *bucket, now tcpip.MonotonicTime) bool {
	if !reapingTuple.conn.timedOut(now) {
		return false
	}

	var otherTuple *tuple
	if reapingTuple.reply {
		otherTuple = &reapingTuple.conn.original
	} else {
		otherTuple = &reapingTuple.conn.reply
	}

	otherTupleBktID := ct.bucket(otherTuple.tupleID)
	replyTupleInserted := reapingTuple.conn.getFinalizeResult() == finalizeResultSuccess

	if bktID > otherTupleBktID && replyTupleInserted {
		return true
	}

	bkt.tuples.Remove(reapingTuple)

	if !replyTupleInserted {
		return true
	}

	if bktID == otherTupleBktID {
		bkt.tuples.Remove(otherTuple)
	} else {
		otherTupleBkt := &ct.buckets[otherTupleBktID]
		otherTupleBkt.mu.NestedLock(bucketLockOthertuple)
		otherTupleBkt.tuples.Remove(otherTuple)
		otherTupleBkt.mu.NestedUnlock(bucketLockOthertuple)
	}

	return true
}

func (ct *ConnTrack) originalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	tid := tupleID{
		srcAddr:                   epID.LocalAddress,
		srcPortOrEchoRequestIdent: epID.LocalPort,
		dstAddr:                   epID.RemoteAddress,
		dstPortOrEchoReplyIdent:   epID.RemotePort,
		transProto:                transProto,
		netProto:                  netProto,
	}
	t := ct.connForTID(tid)
	if t == nil {
		return tcpip.Address{}, 0, &tcpip.ErrNotConnected{}
	}

	t.conn.mu.RLock()
	defer t.conn.mu.RUnlock()
	if t.conn.destinationManip == manipNotPerformed {
		return tcpip.Address{}, 0, &tcpip.ErrInvalidOptionValue{}
	}

	id := t.conn.original.tupleID
	return id.dstAddr, id.dstPortOrEchoReplyIdent, nil
}

func NewConnTrack(clock tcpip.Clock, rng connTrackRNG, seed *uint32) *ConnTrack {
	if seed == nil {
		r := rng.Uint32()
		seed = &r
	}
	ct := &ConnTrack{
		clock:     clock,
		rng:       rng,
		seed:      *seed,
		nftIDSeed: rng.Uint32(),
	}
	ct.init()
	return ct
}

func NewConnTrackWithReaper(clock tcpip.Clock, rng connTrackRNG, seed *uint32) (*ConnTrack, tcpip.Timer) {
	ct := NewConnTrack(clock, rng, seed)
	var reaper tcpip.Timer
	bucket := 0
	interval := 1 * time.Second
	reaper = ct.clock.AfterFunc(interval, func() {
		bucket, interval = ct.reapUnused(bucket, interval)
		reaper.Reset(interval)
	})
	return ct, reaper
}

func NfConnTrackPriority(hook NFHook) (int, bool) {
	switch hook {
	case NFPrerouting:
		return -200, true
	case NFInput:
		return math.MaxInt32, true
	case NFPostrouting:
		return math.MaxInt32, true
	case NFOutput:
		return -200, true
	}
	return 0, false
}

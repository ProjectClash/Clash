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
	"math"
	"sort"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	MinRTO = 200 * time.Millisecond

	MaxRTO = 120 * time.Second

	MinSRTT = 1 * time.Millisecond

	InitialCwnd = 10

	nDupAckThreshold = 3

	MaxRetries = 15

	InitialSsthresh = math.MaxInt

	unknownRTT = time.Duration(-1)
)

type congestionControl interface {
	HandleLossDetected()

	HandleRTOExpired()

	Update(packetsAcked int, rtt time.Duration, ackTime tcpip.MonotonicTime)

	PostRecovery()
}

type lossRecovery interface {
	DoRecovery(rcvdSeg *segment, fastRetransmit bool)
}

type sender struct {
	TCPSenderState

	ep *Endpoint

	finSent bool

	lr lossRecovery

	firstRetransmittedSegXmitTime tcpip.MonotonicTime

	zeroWindowProbing bool `state:"nosave"`

	unackZeroWindowProbes uint32 `state:"nosave"`

	writeNext *segment

	writeList protectedWriteList

	resendTimer timer `state:"nosave"`

	rtt rtt

	minRTO time.Duration

	maxRTO time.Duration

	maxRetries uint32

	gso bool

	state tcpip.CongestionControlState

	cc congestionControl

	rc rackControl

	reorderTimer timer `state:"nosave"`

	probeTimer timer `state:"nosave"`

	spuriousRecovery bool

	retransmitTS uint32

	startCork bool

	corkTimer timer `state:"nosave"`
}

type protectedWriteList struct {
	writeList segmentList
	set       map[*segment]struct{}
}

func (wl *protectedWriteList) Front() *segment {
	return wl.writeList.Front()
}

func (wl *protectedWriteList) Back() *segment {
	return wl.writeList.Back()
}

func (wl *protectedWriteList) Remove(seg *segment) {
	if _, ok := wl.set[seg]; !ok {
		panic("segment not found write list")
	}
	wl.writeList.Remove(seg)
	delete(wl.set, seg)
}

func (wl *protectedWriteList) PushBack(seg *segment) {
	if _, ok := wl.set[seg]; ok {
		panic("segment already in write list")
	}
	wl.writeList.PushBack(seg)
	wl.set[seg] = struct{}{}
}

func (wl *protectedWriteList) InsertAfter(before, seg *segment) {
	if _, ok := wl.set[seg]; ok {
		panic("segment already in write list")
	}
	wl.writeList.InsertAfter(before, seg)
	wl.set[seg] = struct{}{}
}

type rtt struct {
	rttMutex `state:"nosave"`

	TCPRTTState
}

func initSender(ep *Endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) {
	maxPayloadSize := int(mss) - ep.maxOptionSize()

	ep.snd = &sender{
		ep: ep,
		TCPSenderState: TCPSenderState{
			SndWnd:           sndWnd,
			SndUna:           iss + 1,
			SndNxt:           iss + 1,
			RTTMeasureSeqNum: iss + 1,
			LastSendTime:     ep.stack.Clock().NowMonotonic(),
			MaxPayloadSize:   maxPayloadSize,
			MaxSentAck:       irs + 1,
			FastRecovery: TCPFastRecoveryState{
				Last:      iss,
				HighRxt:   iss,
				RescueRxt: iss,
			},
			RTO: 1 * time.Second,
		},
		gso: ep.gso.Type != stack.GSONone,
		writeList: protectedWriteList{
			set: make(map[*segment]struct{}),
		},
	}

	if ep.snd.gso {
		ep.snd.ep.gso.MSS = uint16(maxPayloadSize)
	}

	ep.snd.cc = ep.snd.initCongestionControl(ep.cc)
	ep.snd.lr = ep.snd.initLossRecovery()
	ep.snd.rc.init(ep.snd, iss)

	if sndWndScale > 0 {
		ep.snd.SndWndScale = uint8(sndWndScale)
	}

	ep.snd.resendTimer.init(ep.snd.ep.stack.Clock(), timerHandler(ep.snd.ep, ep.snd.retransmitTimerExpired))
	ep.snd.reorderTimer.init(ep.snd.ep.stack.Clock(), timerHandler(ep.snd.ep, ep.snd.rc.reorderTimerExpired))
	ep.snd.probeTimer.init(ep.snd.ep.stack.Clock(), timerHandler(ep.snd.ep, ep.snd.probeTimerExpired))
	ep.snd.corkTimer.init(ep.snd.ep.stack.Clock(), timerHandler(ep.snd.ep, ep.snd.corkTimerExpired))

	ep.snd.updateMaxPayloadSize(int(ep.snd.ep.route.MTU()), 0)
	ep.snd.ep.scoreboard = NewSACKScoreboard(uint16(ep.snd.MaxPayloadSize), iss)

	var minRTO tcpip.TCPMinRTOOption
	if err := ep.snd.ep.stack.TransportProtocolOption(ProtocolNumber, &minRTO); err != nil {
		panic(fmt.Sprintf("unable to get minRTO from stack: %s", err))
	}
	ep.snd.minRTO = time.Duration(minRTO)

	var maxRTO tcpip.TCPMaxRTOOption
	if err := ep.snd.ep.stack.TransportProtocolOption(ProtocolNumber, &maxRTO); err != nil {
		panic(fmt.Sprintf("unable to get maxRTO from stack: %s", err))
	}
	ep.snd.maxRTO = time.Duration(maxRTO)

	var maxRetries tcpip.TCPMaxRetriesOption
	if err := ep.snd.ep.stack.TransportProtocolOption(ProtocolNumber, &maxRetries); err != nil {
		panic(fmt.Sprintf("unable to get maxRetries from stack: %s", err))
	}
	ep.snd.maxRetries = uint32(maxRetries)
}

func (s *sender) initCongestionControl(congestionControlName tcpip.CongestionControlOption) congestionControl {
	s.SndCwnd = InitialCwnd
	s.Ssthresh = InitialSsthresh

	switch congestionControlName {
	case ccCubic:
		return newCubicCC(s)
	case ccReno:
		fallthrough
	default:
		return newRenoCC(s)
	}
}

func (s *sender) initLossRecovery() lossRecovery {
	if s.ep.SACKPermitted {
		return newSACKRecovery(s)
	}
	return newRenoRecovery(s)
}

func (s *sender) updateMaxPayloadSize(mtu, count int) {
	m := mtu - header.TCPMinimumSize

	m -= s.ep.maxOptionSize()

	if m >= s.MaxPayloadSize {
		return
	}

	if m <= 0 {
		m = 1
	}

	oldMSS := s.MaxPayloadSize
	s.MaxPayloadSize = m
	if s.gso {
		s.ep.gso.MSS = uint16(m)
	}

	if count == 0 {
		return
	}

	s.ep.scoreboard.smss = uint16(m)

	s.Outstanding -= count
	if s.Outstanding < 0 {
		s.Outstanding = 0
	}

	nextSeg := s.writeNext
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg == s.writeNext {
			break
		}

		if nextSeg == s.writeNext && seg.payloadSize() > m {
			nextSeg = seg
		}

		if s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			s.SackedOut -= s.pCount(seg, oldMSS)
			s.SackedOut += s.pCount(seg, s.MaxPayloadSize)
		}
	}

	s.updateWriteNext(nextSeg)
	s.sendData()
}

func (s *sender) sendAck() {
	s.sendEmptySegment(header.TCPFlagAck, s.SndNxt)
}

func (s *sender) updateRTO(rtt time.Duration) {
	if rtt < 0 {
		return
	}
	s.rtt.Lock()
	if !s.rtt.TCPRTTState.SRTTInited {
		s.rtt.TCPRTTState.RTTVar = rtt / 2
		s.rtt.TCPRTTState.SRTT = rtt
		s.rtt.TCPRTTState.SRTTInited = true
	} else {
		diff := s.rtt.TCPRTTState.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		if !s.ep.SendTSOk {
			s.rtt.TCPRTTState.RTTVar = (3*s.rtt.TCPRTTState.RTTVar + diff) / 4
			s.rtt.TCPRTTState.SRTT = (7*s.rtt.TCPRTTState.SRTT + rtt) / 8
		} else {
			if s.Outstanding == 0 {
				s.rtt.Unlock()
				return
			}
			expectedSamples := math.Ceil(float64(s.Outstanding) / 2)

			const alpha = 0.125
			const beta = 0.25

			alphaPrime := alpha / expectedSamples
			betaPrime := beta / expectedSamples
			rttVar := (1-betaPrime)*s.rtt.TCPRTTState.RTTVar.Seconds() + betaPrime*diff.Seconds()
			srtt := (1-alphaPrime)*s.rtt.TCPRTTState.SRTT.Seconds() + alphaPrime*rtt.Seconds()
			s.rtt.TCPRTTState.RTTVar = time.Duration(rttVar * float64(time.Second))
			s.rtt.TCPRTTState.SRTT = time.Duration(srtt * float64(time.Second))
		}
	}

	if s.rtt.TCPRTTState.SRTT < MinSRTT {
		s.rtt.TCPRTTState.SRTT = MinSRTT
	}

	s.RTO = s.rtt.TCPRTTState.SRTT + 4*s.rtt.TCPRTTState.RTTVar
	s.RTTState = s.rtt.TCPRTTState
	s.rtt.Unlock()
	if s.RTO < s.minRTO {
		s.RTO = s.minRTO
	}
	if s.RTO > s.maxRTO {
		s.RTO = s.maxRTO
	}
}

func (s *sender) resendSegment() {
	s.RTTMeasureSeqNum = s.SndNxt

	if seg := s.writeList.Front(); seg != nil {
		if seg.payloadSize() > s.MaxPayloadSize {
			s.splitSeg(seg, s.MaxPayloadSize)
		}

		s.FastRecovery.HighRxt = seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize())) - 1
		s.FastRecovery.RescueRxt = seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize())) - 1
		s.sendSegment(seg)
		s.ep.stack.Stats().TCP.FastRetransmit.Increment()
		s.ep.stats.SendErrors.FastRetransmit.Increment()

		s.SetPipe()
	}
}

func (s *sender) retransmitTimerExpired() tcpip.Error {
	if s.resendTimer.isUninitialized() || !s.resendTimer.checkExpiration() {
		return nil
	}

	s.spuriousRecovery = false
	s.retransmitTS = 0

	if s.writeList.Front() == nil {
		return nil
	}

	s.ep.stack.Stats().TCP.Timeouts.Increment()
	s.ep.stats.SendErrors.Timeouts.Increment()

	s.rc.tlpRxtOut = false

	uto := s.ep.userTimeout

	if s.firstRetransmittedSegXmitTime == (tcpip.MonotonicTime{}) {
		s.firstRetransmittedSegXmitTime = s.writeList.Front().xmitTime
	}

	elapsed := s.ep.stack.Clock().NowMonotonic().Sub(s.firstRetransmittedSegXmitTime)
	remaining := s.maxRTO
	if uto != 0 {
		remaining = uto - elapsed
	}

	if remaining <= 0 || s.unackZeroWindowProbes >= s.maxRetries {
		s.ep.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	s.RTO *= 2
	if s.RTO > s.maxRTO {
		s.RTO = s.maxRTO
	}

	if s.RTO > remaining {
		s.RTO = remaining
	}

	s.FastRecovery.Last = s.SndNxt - 1

	if s.FastRecovery.Active {
		s.leaveRecovery()
	}

	s.recordRetransmitTS()

	s.state = tcpip.RTORecovery
	s.cc.HandleRTOExpired()

	s.Outstanding = 0

	s.ep.scoreboard.Reset()
	s.updateWriteNext(s.writeList.Front())

	if s.zeroWindowProbing {
		s.sendZeroWindowProbe()
		return nil
	}

	seg := s.writeNext
	if seg != nil && seg.xmitCount > s.maxRetries {
		s.ep.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	s.sendData()

	return nil
}

func (s *sender) pCount(seg *segment, maxPayloadSize int) int {
	size := seg.payloadSize()
	if size == 0 {
		return 1
	}

	return (size-1)/maxPayloadSize + 1
}

func (s *sender) splitSeg(seg *segment, size int) {
	if seg.payloadSize() <= size {
		return
	}
	nSeg := seg.clone()
	nSeg.pkt.Data().TrimFront(size)
	nSeg.sequenceNumber.UpdateForward(seqnum.Size(size))
	s.writeList.InsertAfter(seg, nSeg)

	if seg.payloadSize() > s.MaxPayloadSize {
		seg.flags ^= header.TCPFlagPsh
	}
	seg.pkt.Data().CapLength(size)
}

func (s *sender) NextSeg(nextSegHint *segment) (nextSeg, hint *segment, rescueRtx bool) {
	var s3 *segment
	var s4 *segment
	for seg := nextSegHint; seg != nil; seg = seg.Next() {
		if !s.isAssignedSequenceNumber(seg) || s.SndNxt.LessThanEq(seg.sequenceNumber) {
			hint = nil
			break
		}
		segSeq := seg.sequenceNumber
		if smss := s.ep.scoreboard.SMSS(); seg.payloadSize() > int(smss) {
			s.splitSeg(seg, int(smss))
		}

		if !s.ep.scoreboard.IsSACKED(header.SACKBlock{Start: segSeq, End: segSeq.Add(1)}) {
			if s.FastRecovery.HighRxt.LessThan(segSeq) && segSeq.LessThan(s.ep.scoreboard.maxSACKED) {
				if s.ep.scoreboard.IsLost(segSeq) {
					return seg, seg.Next(), false
				}

				if s3 == nil {
					s3 = seg
					hint = seg.Next()
				}
			}
			if s.FastRecovery.RescueRxt.LessThan(s.SndUna - 1) {
				if s4 != nil {
					if s4.sequenceNumber.LessThan(segSeq) {
						s4 = seg
					}
				} else {
					s4 = seg
				}
			}
		}
	}

	for seg := s.writeNext; seg != nil; seg = seg.Next() {
		if s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(s.SndNxt) {
			continue
		}
		return seg, nil, false
	}

	if s3 != nil {
		return s3, hint, false
	}

	return s4, nil, true
}

func (s *sender) maybeSendSegment(seg *segment, limit int, end seqnum.Value) (sent bool) {
	if !s.isAssignedSequenceNumber(seg) {
		if seg.payloadSize() != 0 {
			available := int(s.SndNxt.Size(end))
			if available > limit {
				available = limit
			}

			var nextTooBig bool
			for nSeg := seg.Next(); nSeg != nil && nSeg.payloadSize() != 0; nSeg = seg.Next() {
				if seg.payloadSize()+nSeg.payloadSize() > available {
					nextTooBig = true
					break
				}
				seg.merge(nSeg)
				s.writeList.Remove(nSeg)
				nSeg.DecRef()
			}
			if !nextTooBig && seg.payloadSize() < available {
				if s.Outstanding > 0 && s.ep.ops.GetDelayOption() {
					return false
				}
				if s.ep.ops.GetCorkOption() {
					if seg.payloadSize() < s.MaxPayloadSize {
						if !s.startCork {
							s.startCork = true
							s.corkTimer.enable(MinRTO)
						}
						return false
					}
					s.startCork = false
					s.corkTimer.disable()
				}
			}
		}

		seg.sequenceNumber = s.SndNxt
		seg.flags = header.TCPFlagAck | header.TCPFlagPsh
	}

	var segEnd seqnum.Value
	if seg.payloadSize() == 0 {
		if s.writeList.Back() != seg {
			panic("FIN segments must be the final segment in the write list.")
		}
		seg.flags = header.TCPFlagAck | header.TCPFlagFin
		segEnd = seg.sequenceNumber.Add(1)
		s.finSent = true
	} else {
		if seg.flags&header.TCPFlagFin != 0 {
			panic("Netstack queues FIN segments without data.")
		}

		if !seg.sequenceNumber.LessThan(end) {
			return false
		}

		available := int(seg.sequenceNumber.Size(end))
		if available == 0 {
			return false
		}

		if s.SndUna != s.SndNxt {
			switch {
			case available >= seg.payloadSize():
			case available >= s.MaxPayloadSize:
			default:
				return false
			}
		}

		if available > limit {
			available = limit
		}

		if s.ep.gso.Type == stack.GSONone && available > s.MaxPayloadSize {
			available = s.MaxPayloadSize
		}

		if seg.payloadSize() > available {
			s.splitSeg(seg, available)
		}

		segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
	}

	if _, ok := s.writeList.set[seg]; !ok {
		panic("attempted to send segment not in write list")
	}

	s.sendSegment(seg)

	if s.SndNxt.LessThan(segEnd) {
		s.SndNxt = segEnd
	}

	return true
}

var zeroProbeJunk = []byte{0}

func (s *sender) sendZeroWindowProbe() {
	s.unackZeroWindowProbes++

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(zeroProbeJunk),
		Mark:    s.ep.ops.GetMark(),
	})
	defer pkt.DecRef()
	s.sendSegmentFromPacketBuffer(pkt, header.TCPFlagAck, s.SndUna-1)

	s.resendTimer.enable(s.RTO)
}

func (s *sender) enableZeroWindowProbing() {
	s.zeroWindowProbing = true
	if s.firstRetransmittedSegXmitTime == (tcpip.MonotonicTime{}) {
		s.firstRetransmittedSegXmitTime = s.ep.stack.Clock().NowMonotonic()
	}
	s.resendTimer.enable(s.RTO)
}

func (s *sender) disableZeroWindowProbing() {
	s.zeroWindowProbing = false
	s.unackZeroWindowProbes = 0
	s.firstRetransmittedSegXmitTime = tcpip.MonotonicTime{}
	s.resendTimer.disable()
}

func (s *sender) postXmit(dataSent bool, shouldScheduleProbe bool) {
	if dataSent {
		s.ep.disableKeepaliveTimer()
	}

	if s.writeNext != nil && s.SndWnd == 0 {
		s.enableZeroWindowProbing()
	}

	if s.SndUna == s.SndNxt {
		s.ep.resetKeepaliveTimer(false)
	} else {
		if shouldScheduleProbe && s.shouldSchedulePTO() {
			s.schedulePTO()
		} else if !s.resendTimer.enabled() {
			s.probeTimer.disable()
			if s.Outstanding > 0 {
				s.resendTimer.enable(s.RTO)
			}
		}
	}
}

func (s *sender) sendData() {
	limit := s.MaxPayloadSize
	if s.gso {
		limit = int(s.ep.gso.MaxSize - header.TCPTotalHeaderMaximumSize - 1)
	}
	end := s.SndUna.Add(s.SndWnd)

	if !s.FastRecovery.Active && s.state != tcpip.RTORecovery && s.ep.stack.Clock().NowMonotonic().Sub(s.LastSendTime) > s.RTO {
		if s.SndCwnd > InitialCwnd {
			s.SndCwnd = InitialCwnd
		}
	}

	var dataSent bool
	for seg := s.writeNext; seg != nil && s.Outstanding < s.SndCwnd; seg = seg.Next() {
		cwndLimit := uint64(s.SndCwnd-s.Outstanding) * uint64(s.MaxPayloadSize)
		if cwndLimit > 0 && cwndLimit < uint64(limit) {
			limit = int(cwndLimit)
		}
		if s.isAssignedSequenceNumber(seg) && s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			s.updateWriteNext(seg.Next())
			continue
		}
		if sent := s.maybeSendSegment(seg, limit, end); !sent {
			break
		}
		dataSent = true
		s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
		s.updateWriteNext(seg.Next())
	}

	s.postXmit(dataSent, true)
}

func (s *sender) enterRecovery() {
	s.spuriousRecovery = false
	s.retransmitTS = 0

	s.FastRecovery.Active = true
	s.SndCwnd = s.Ssthresh + 3
	s.SackedOut = 0
	s.DupAckCount = 0
	s.FastRecovery.First = s.SndUna
	s.FastRecovery.Last = s.SndNxt - 1
	s.FastRecovery.MaxCwnd = s.SndCwnd + s.Outstanding
	s.FastRecovery.HighRxt = s.SndUna
	s.FastRecovery.RescueRxt = s.SndUna

	s.recordRetransmitTS()

	if s.ep.SACKPermitted {
		s.state = tcpip.SACKRecovery
		s.ep.stack.Stats().TCP.SACKRecovery.Increment()
		if s.rc.tlpRxtOut {
			s.ep.stack.Stats().TCP.TLPRecovery.Increment()
		}
		s.rc.tlpRxtOut = false
		return
	}
	s.state = tcpip.FastRecovery
	s.ep.stack.Stats().TCP.FastRecovery.Increment()
}

func (s *sender) leaveRecovery() {
	s.FastRecovery.Active = false
	s.FastRecovery.MaxCwnd = 0
	s.DupAckCount = 0

	s.SndCwnd = s.Ssthresh
	s.cc.PostRecovery()
}

func (s *sender) isAssignedSequenceNumber(seg *segment) bool {
	return seg.flags != 0
}

func (s *sender) SetPipe() {
	if !s.ep.SACKPermitted || !s.FastRecovery.Active {
		return
	}
	pipe := 0
	smss := seqnum.Size(s.ep.scoreboard.SMSS())
	for s1 := s.writeList.Front(); s1 != nil && s1.payloadSize() != 0 && s.isAssignedSequenceNumber(s1); s1 = s1.Next() {
		segEnd := s1.sequenceNumber.Add(seqnum.Size(s1.payloadSize()))
		for startSeq := s1.sequenceNumber; startSeq.LessThan(segEnd); startSeq = startSeq.Add(smss) {
			endSeq := startSeq.Add(smss)
			if segEnd.LessThan(endSeq) {
				endSeq = segEnd
			}
			sb := header.SACKBlock{Start: startSeq, End: endSeq}
			if !s1.sequenceNumber.LessThan(s.SndNxt) {
				break
			}
			if s.ep.scoreboard.IsSACKED(sb) {
				continue
			}

			if !s.ep.scoreboard.IsRangeLost(sb) {
				pipe++
			}
			if s1.sequenceNumber.LessThanEq(s.FastRecovery.HighRxt) {
				pipe++
			}
		}
	}
	s.Outstanding = pipe
}

func (s *sender) shouldEnterRecovery() bool {
	return s.DupAckCount >= nDupAckThreshold ||
		(s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 && s.ep.scoreboard.IsLost(s.SndUna))
}

func (s *sender) detectLoss(seg *segment) (fastRetransmit bool) {

	if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		if s.rc.Reord {
			return false
		}
	}

	if !s.isDupAck(seg) {
		s.DupAckCount = 0
		return false
	}

	s.DupAckCount++

	if !s.shouldEnterRecovery() {
		s.FastRecovery.HighRxt = s.SndUna - 1
		s.SetPipe()
		s.state = tcpip.Disorder
		return false
	}

	if !s.FastRecovery.Last.LessThan(seg.ackNumber - 1) {
		s.DupAckCount = 0
		return false
	}
	s.cc.HandleLossDetected()
	s.enterRecovery()
	return true
}

func (s *sender) isDupAck(seg *segment) bool {
	if s.ep.SACKPermitted && !seg.hasNewSACKInfo {
		return false
	}

	return s.SndUna != s.SndNxt &&
		seg.logicalLen() == 0 &&
		!seg.flags.Intersects(header.TCPFlagFin|header.TCPFlagSyn) &&
		seg.ackNumber == s.SndUna &&
		s.SndWnd == seg.window
}

func (s *sender) walkSACK(rcvdSeg *segment) bool {
	s.rc.setDSACKSeen(false)

	hasDSACK := false
	idx := 0
	n := len(rcvdSeg.parsedOptions.SACKBlocks)
	if checkDSACK(rcvdSeg) {
		dsackBlock := rcvdSeg.parsedOptions.SACKBlocks[0]
		numDSACK := uint64(dsackBlock.End-dsackBlock.Start) / uint64(s.MaxPayloadSize)
		if numDSACK < 1 {
			numDSACK = 1
		}
		s.ep.stack.Stats().TCP.SegmentsAckedWithDSACK.IncrementBy(numDSACK)
		s.rc.setDSACKSeen(true)
		idx = 1
		n--
		hasDSACK = true
	}

	if n == 0 {
		return hasDSACK
	}

	sackBlocks := make([]header.SACKBlock, n)
	copy(sackBlocks, rcvdSeg.parsedOptions.SACKBlocks[idx:])
	sort.Slice(sackBlocks, func(i, j int) bool {
		return sackBlocks[j].Start.LessThan(sackBlocks[i].Start)
	})

	seg := s.writeList.Front()
	for _, sb := range sackBlocks {
		for seg != nil && seg.sequenceNumber.LessThan(sb.End) && seg.xmitCount != 0 {
			if sb.Start.LessThanEq(seg.sequenceNumber) && !seg.acked {
				s.rc.update(seg, rcvdSeg)
				s.rc.detectReorder(seg)
				seg.acked = true
				s.SackedOut += s.pCount(seg, s.MaxPayloadSize)
			}
			seg = seg.Next()
		}
	}
	return hasDSACK
}

func checkDSACK(rcvdSeg *segment) bool {
	n := len(rcvdSeg.parsedOptions.SACKBlocks)
	if n == 0 {
		return false
	}

	sb := rcvdSeg.parsedOptions.SACKBlocks[0]
	if sb.End.LessThan(sb.Start) {
		return false
	}

	if sb.Start.LessThan(rcvdSeg.ackNumber) {
		return true
	}

	if n > 1 {
		sb1 := rcvdSeg.parsedOptions.SACKBlocks[1]
		if sb1.End.LessThan(sb1.Start) {
			return false
		}

		if sb.End.LessThanEq(sb1.End) && sb1.Start.LessThanEq(sb.Start) {
			return true
		}
	}

	return false
}

func (s *sender) recordRetransmitTS() {
	if s.inRecovery() {
		return
	}

	s.retransmitTS = s.ep.tsValNow()
}

func (s *sender) detectSpuriousRecovery(hasDSACK bool, tsEchoReply uint32) {
	if s.spuriousRecovery {
		return
	}

	if tsEchoReply >= s.retransmitTS {
		return
	}

	if hasDSACK {
		return
	}

	numDSACK := s.ep.stack.Stats().TCP.SegmentsAckedWithDSACK.Value()
	if numDSACK == 0 && s.SndUna == s.SndNxt {
		return
	}

	s.spuriousRecovery = true
	s.ep.stack.Stats().TCP.SpuriousRecovery.Increment()

	if s.state == tcpip.RTORecovery {
		s.ep.stack.Stats().TCP.SpuriousRTORecovery.Increment()
	}
}

func (s *sender) inRecovery() bool {
	if s.state == tcpip.RTORecovery || s.state == tcpip.FastRecovery || s.state == tcpip.SACKRecovery {
		return true
	}
	return false
}

func (s *sender) handleRcvdSegment(rcvdSeg *segment) {
	bestRTT := unknownRTT

	if !rcvdSeg.parsedOptions.TS && s.RTTMeasureSeqNum.LessThan(rcvdSeg.ackNumber) {
		bestRTT = rcvdSeg.rcvdTime.Sub(s.RTTMeasureTime)
		s.updateRTO(bestRTT)
		s.RTTMeasureSeqNum = s.SndNxt
	}

	if s.ep.SendTSOk && rcvdSeg.parsedOptions.TS {
		s.ep.updateRecentTimestamp(rcvdSeg.parsedOptions.TSVal, s.MaxSentAck, rcvdSeg.sequenceNumber)
	}

	hasDSACK := false
	if s.ep.SACKPermitted {
		for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
			if rcvdSeg.ackNumber.LessThan(sb.Start) && s.SndUna.LessThan(sb.Start) && sb.End.LessThanEq(s.SndNxt) && !s.ep.scoreboard.IsSACKED(sb) {
				s.ep.scoreboard.Insert(sb)
				rcvdSeg.hasNewSACKInfo = true
			}
		}

		if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
			hasDSACK = s.walkSACK(rcvdSeg)
		}
		s.SetPipe()
	}

	ack := rcvdSeg.ackNumber
	fastRetransmit := false
	if s.FastRecovery.Active {
		if (ack-1).InRange(s.SndUna, s.SndNxt) && s.FastRecovery.Last.LessThan(ack) {
			s.leaveRecovery()
		}
	} else {
		fastRetransmit = s.detectLoss(rcvdSeg)
	}

	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		s.detectTLPRecovery(ack, rcvdSeg)
	}

	s.SndWnd = rcvdSeg.window

	if s.zeroWindowProbing && rcvdSeg.window > 0 &&
		(ack == s.SndUna || (ack-1).InRange(s.SndUna, s.SndNxt)) {
		s.disableZeroWindowProbing()
	}

	if s.zeroWindowProbing && s.unackZeroWindowProbes > 0 && ack == s.SndUna {
		s.unackZeroWindowProbes--
		return
	}

	if (ack - 1).InRange(s.SndUna, s.SndNxt) {
		s.DupAckCount = 0

		if s.ep.SendTSOk && rcvdSeg.parsedOptions.TSEcr != 0 {
			tsRTT := s.ep.elapsed(rcvdSeg.rcvdTime, rcvdSeg.parsedOptions.TSEcr)
			s.updateRTO(tsRTT)
			if bestRTT == unknownRTT {
				bestRTT = tsRTT
			}
		}

		if s.shouldSchedulePTO() {
			s.schedulePTO()
		} else {
			s.probeTimer.disable()
			s.resendTimer.enable(s.RTO)
		}

		acked := s.SndUna.Size(ack)
		s.SndUna = ack
		ackLeft := acked
		originalOutstanding := s.Outstanding
		for ackLeft > 0 {
			seg := s.writeList.Front()
			if seg == nil {
				panic(fmt.Sprintf("invalid state: there are %d unacknowledged bytes left, but the write list is empty:\n"+
					"TCPSenderState: %+v\nsender: %+v\nendpoint: %+v", ackLeft, s.TCPSenderState, s, s.ep))
			}

			datalen := seg.logicalLen()
			if datalen > ackLeft {
				prevCount := s.pCount(seg, s.MaxPayloadSize)
				seg.TrimFront(ackLeft)
				seg.sequenceNumber.UpdateForward(ackLeft)
				s.Outstanding -= prevCount - s.pCount(seg, s.MaxPayloadSize)
				break
			}

			if s.writeNext == seg {
				s.updateWriteNext(seg.Next())
			}

			if s.ep.SACKPermitted && !seg.acked && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
				s.rc.update(seg, rcvdSeg)
				s.rc.detectReorder(seg)
			}

			s.writeList.Remove(seg)

			if !s.ep.SACKPermitted || !s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				s.Outstanding -= s.pCount(seg, s.MaxPayloadSize)
			} else {
				s.SackedOut -= s.pCount(seg, s.MaxPayloadSize)
			}
			seg.DecRef()
			ackLeft -= datalen
		}

		s.ep.scoreboard.Delete(s.SndUna)

		if s.inRecovery() {
			s.detectSpuriousRecovery(hasDSACK, rcvdSeg.parsedOptions.TSEcr)
		}

		if !s.FastRecovery.Active {
			s.cc.Update(originalOutstanding-s.Outstanding, bestRTT, rcvdSeg.rcvdTime)
			if s.FastRecovery.Last.LessThan(s.SndUna) {
				s.state = tcpip.Open
				if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
					s.rc.exitRecovery()
				}
				s.reorderTimer.disable()
			}
		}

		s.ep.updateSndBufferUsage(int(acked))

		if s.Outstanding < 0 {
			s.Outstanding = 0
		}

		s.SetPipe()

		if s.SndUna == s.SndNxt {
			s.Outstanding = 0
			s.firstRetransmittedSegXmitTime = tcpip.MonotonicTime{}
			s.resendTimer.disable()
			s.probeTimer.disable()
		}
	}

	if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		s.rc.updateRACKReorderWindow()

		if numLost := s.rc.detectLoss(rcvdSeg.rcvdTime); numLost > 0 && !s.FastRecovery.Active {
			s.cc.HandleLossDetected()
			s.enterRecovery()
			fastRetransmit = true
		}

		if s.FastRecovery.Active {
			s.rc.DoRecovery(nil, fastRetransmit)
		}
	}

	if s.FastRecovery.Active && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 {
		s.lr.DoRecovery(rcvdSeg, fastRetransmit)
		if s.ep.SACKPermitted {
			return
		}
	}

	s.sendData()
}

func (s *sender) sendSegment(seg *segment) tcpip.Error {
	if seg.xmitCount > 0 {
		s.ep.stack.Stats().TCP.Retransmits.Increment()
		s.ep.stats.SendErrors.Retransmits.Increment()
		if s.SndCwnd < s.Ssthresh {
			s.ep.stack.Stats().TCP.SlowStartRetransmits.Increment()
		}
	}
	seg.xmitTime = s.ep.stack.Clock().NowMonotonic()
	seg.xmitCount++
	seg.lost = false

	err := s.sendSegmentFromPacketBuffer(seg.pkt, seg.flags, seg.sequenceNumber)

	if err != nil && seg.payloadSize() != 0 {
		if s.FastRecovery.Active && seg.xmitCount > 1 && s.ep.SACKPermitted {
			s.resendTimer.enable(s.RTO)
		} else {
			if !s.resendTimer.enabled() {
				s.resendTimer.enable(s.RTO)
			}
		}
	}

	return err
}

func (s *sender) sendSegmentFromPacketBuffer(pkt *stack.PacketBuffer, flags header.TCPFlags, seq seqnum.Value) tcpip.Error {
	s.LastSendTime = s.ep.stack.Clock().NowMonotonic()
	if seq == s.RTTMeasureSeqNum {
		s.RTTMeasureTime = s.LastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	s.MaxSentAck = rcvNxt

	pkt = pkt.Clone()
	defer pkt.DecRef()

	return s.ep.sendRaw(pkt, flags, seq, rcvNxt, rcvWnd)
}

func (s *sender) sendEmptySegment(flags header.TCPFlags, seq seqnum.Value) tcpip.Error {
	s.LastSendTime = s.ep.stack.Clock().NowMonotonic()
	if seq == s.RTTMeasureSeqNum {
		s.RTTMeasureTime = s.LastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	s.MaxSentAck = rcvNxt

	return s.ep.sendEmptyRaw(flags, seq, rcvNxt, rcvWnd)
}

func (s *sender) maybeSendOutOfWindowAck(seg *segment) {
	if seg.payloadSize() > 0 || s.ep.allowOutOfWindowAck() {
		s.sendAck()
	}
}

func (s *sender) updateWriteNext(seg *segment) {
	if s.writeNext != nil {
		s.writeNext.DecRef()
	}
	if seg != nil {
		seg.IncRef()
	}
	s.writeNext = seg
}

func (s *sender) corkTimerExpired() tcpip.Error {
	if s.corkTimer.isUninitialized() || !s.corkTimer.checkExpiration() {
		return nil
	}

	seg := s.writeNext
	if seg == nil {
		return nil
	}
	seg.sequenceNumber = s.SndNxt
	seg.flags = header.TCPFlagAck | header.TCPFlagPsh
	s.sendData()
	return nil
}

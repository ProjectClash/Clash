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

package tcp

import (
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

const (
	wcDelayedACKTimeout = 200 * time.Millisecond

	tcpRACKRecoveryThreshold = 16
)


type rackControl struct {
	TCPRACKState

	exitedRecovery bool

	minRTT time.Duration

	tlpRxtOut bool

	tlpHighRxt seqnum.Value

	snd *sender
}

func (rc *rackControl) init(snd *sender, iss seqnum.Value) {
	rc.FACK = iss
	rc.ReoWndIncr = 1
	rc.snd = snd
}

func (rc *rackControl) update(seg *segment, ackSeg *segment) {
	rtt := ackSeg.rcvdTime.Sub(seg.xmitTime)

	if seg.xmitCount > 1 {
		if ackSeg.parsedOptions.TS && ackSeg.parsedOptions.TSEcr != 0 {
			if ackSeg.parsedOptions.TSEcr < rc.snd.ep.tsVal(seg.xmitTime) {
				return
			}
		}
		if rtt < rc.minRTT {
			return
		}
	}

	rc.RTT = rtt

	if rtt < rc.minRTT || rc.minRTT == 0 {
		rc.minRTT = rtt
	}

	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
	if rc.XmitTime.Before(seg.xmitTime) || (seg.xmitTime == rc.XmitTime && rc.EndSequence.LessThan(endSeq)) {
		rc.XmitTime = seg.xmitTime
		rc.EndSequence = endSeq
	}
}

func (rc *rackControl) detectReorder(seg *segment) {
	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
	if rc.FACK.LessThan(endSeq) {
		rc.FACK = endSeq
		return
	}

	if endSeq.LessThan(rc.FACK) && seg.xmitCount == 1 {
		rc.Reord = true
	}
}

func (rc *rackControl) setDSACKSeen(dsackSeen bool) {
	rc.DSACKSeen = dsackSeen
}

func (s *sender) shouldSchedulePTO() bool {
	return s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 &&
		s.ep.SACKPermitted &&
		(s.state != tcpip.RTORecovery && s.state != tcpip.SACKRecovery) &&
		s.ep.scoreboard.Sacked() == 0
}

func (s *sender) schedulePTO() {
	pto := time.Second
	s.rtt.Lock()
	if s.rtt.TCPRTTState.SRTTInited && s.rtt.TCPRTTState.SRTT > 0 {
		pto = s.rtt.TCPRTTState.SRTT * 2
		if s.Outstanding == 1 {
			pto += wcDelayedACKTimeout
		}
	}
	s.rtt.Unlock()

	now := s.ep.stack.Clock().NowMonotonic()
	if s.resendTimer.enabled() {
		if now.Add(pto).After(s.resendTimer.target) {
			pto = s.resendTimer.target.Sub(now)
		}
		s.resendTimer.disable()
	}

	s.probeTimer.enable(pto)
}

func (s *sender) probeTimerExpired() tcpip.Error {
	if s.probeTimer.isUninitialized() || !s.probeTimer.checkExpiration() {
		return nil
	}

	var dataSent bool
	if s.writeNext != nil && s.writeNext.xmitCount == 0 && s.Outstanding < s.SndCwnd {
		dataSent = s.maybeSendSegment(s.writeNext, int(s.ep.scoreboard.SMSS()), s.SndUna.Add(s.SndWnd))
		if dataSent {
			s.Outstanding += s.pCount(s.writeNext, s.MaxPayloadSize)
			s.updateWriteNext(s.writeNext.Next())
		}
	}

	if !dataSent && !s.rc.tlpRxtOut {
		var highestSeqXmit *segment
		for highestSeqXmit = s.writeList.Front(); highestSeqXmit != nil; highestSeqXmit = highestSeqXmit.Next() {
			if highestSeqXmit.xmitCount == 0 {
				highestSeqXmit = nil
				break
			}
			if highestSeqXmit.Next() == nil || highestSeqXmit.Next().xmitCount == 0 {
				break
			}
		}

		if highestSeqXmit != nil {
			dataSent = s.maybeSendSegment(highestSeqXmit, int(s.ep.scoreboard.SMSS()), s.SndUna.Add(s.SndWnd))
			if dataSent {
				s.rc.tlpRxtOut = true
				s.rc.tlpHighRxt = s.SndNxt
			}
		}
	}

	s.postXmit(dataSent, false)
	return nil
}

func (s *sender) detectTLPRecovery(ack seqnum.Value, rcvdSeg *segment) {
	if !(s.ep.SACKPermitted && s.rc.tlpRxtOut) {
		return
	}

	if s.isDupAck(rcvdSeg) && ack == s.rc.tlpHighRxt {
		var sbAboveTLPHighRxt bool
		for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
			if s.rc.tlpHighRxt.LessThan(sb.End) {
				sbAboveTLPHighRxt = true
				break
			}
		}
		if !sbAboveTLPHighRxt {
			s.rc.tlpRxtOut = false
		}
	}

	if s.rc.tlpRxtOut && s.rc.tlpHighRxt.LessThanEq(ack) {
		s.rc.tlpRxtOut = false
		if !checkDSACK(rcvdSeg) {
			s.cc.HandleLossDetected()
			s.enterRecovery()
			s.leaveRecovery()
		}
	}
}

func (rc *rackControl) updateRACKReorderWindow() {
	dsackSeen := rc.DSACKSeen
	snd := rc.snd

	if snd.SndUna.LessThan(rc.RTTSeq) {
		dsackSeen = false
	}

	if dsackSeen {
		rc.ReoWndIncr++
		dsackSeen = false
		rc.RTTSeq = snd.SndNxt
		rc.ReoWndPersist = tcpRACKRecoveryThreshold
	} else if rc.exitedRecovery {
		rc.ReoWndPersist--
		if rc.ReoWndPersist <= 0 {
			rc.ReoWndIncr = 1
		}
		rc.exitedRecovery = false
	}

	if !rc.Reord {
		if snd.state == tcpip.RTORecovery || snd.state == tcpip.SACKRecovery {
			rc.ReoWnd = 0
			return
		}

		if snd.SackedOut >= nDupAckThreshold {
			rc.ReoWnd = 0
			return
		}
	}

	snd.rtt.Lock()
	srtt := snd.rtt.TCPRTTState.SRTT
	snd.rtt.Unlock()
	rc.ReoWnd = time.Duration((int64(rc.minRTT) / 4) * int64(rc.ReoWndIncr))
	if srtt < rc.ReoWnd {
		rc.ReoWnd = srtt
	}
}

func (rc *rackControl) exitRecovery() {
	rc.exitedRecovery = true
}

func (rc *rackControl) detectLoss(rcvTime tcpip.MonotonicTime) int {
	var timeout time.Duration
	numLost := 0
	for seg := rc.snd.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		if rc.snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			continue
		}

		if seg.lost && seg.xmitCount == 1 {
			numLost++
			continue
		}

		endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
		if seg.xmitTime.Before(rc.XmitTime) || (seg.xmitTime == rc.XmitTime && rc.EndSequence.LessThan(endSeq)) {
			timeRemaining := seg.xmitTime.Sub(rcvTime) + rc.RTT + rc.ReoWnd
			if timeRemaining <= 0 {
				seg.lost = true
				numLost++
			} else if timeRemaining > timeout {
				timeout = timeRemaining
			}
		}
	}

	if timeout != 0 && !rc.snd.reorderTimer.enabled() {
		rc.snd.reorderTimer.enable(timeout)
	}
	return numLost
}

func (rc *rackControl) reorderTimerExpired() tcpip.Error {
	if rc.snd.reorderTimer.isUninitialized() || !rc.snd.reorderTimer.checkExpiration() {
		return nil
	}

	numLost := rc.detectLoss(rc.snd.reorderTimer.target)
	if numLost == 0 {
		return nil
	}

	fastRetransmit := false
	if !rc.snd.FastRecovery.Active {
		rc.snd.cc.HandleLossDetected()
		rc.snd.enterRecovery()
		fastRetransmit = true
	}

	rc.DoRecovery(nil, fastRetransmit)
	return nil
}

func (rc *rackControl) DoRecovery(_ *segment, fastRetransmit bool) {
	snd := rc.snd
	if fastRetransmit {
		snd.resendSegment()
	}

	var dataSent bool
	for seg := snd.writeList.Front(); seg != nil && seg.xmitCount > 0; seg = seg.Next() {
		if seg == snd.writeNext {
			break
		}

		if !seg.lost {
			continue
		}

		if snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			seg.lost = false
			continue
		}

		if snd.Outstanding >= snd.SndCwnd {
			break
		}

		if sent := snd.maybeSendSegment(seg, int(snd.ep.scoreboard.SMSS()), snd.SndUna.Add(snd.SndWnd)); !sent {
			break
		}
		dataSent = true
		snd.Outstanding += snd.pCount(seg, snd.MaxPayloadSize)
	}

	snd.postXmit(dataSent, true)
}

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
	"container/heap"
	"math"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

type receiver struct {
	TCPReceiverState
	ep *Endpoint

	rcvWnd seqnum.Size

	rcvWUP seqnum.Value

	prevBufUsed int

	closed bool

	pendingRcvdSegments segmentHeap

	lastRcvdAckTime tcpip.MonotonicTime
}

func newReceiver(ep *Endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	return &receiver{
		ep: ep,
		TCPReceiverState: TCPReceiverState{
			RcvNxt:      irs + 1,
			RcvAcc:      irs.Add(rcvWnd + 1),
			RcvWndScale: rcvWndScale,
		},
		rcvWnd:          rcvWnd,
		rcvWUP:          irs + 1,
		lastRcvdAckTime: ep.stack.Clock().NowMonotonic(),
	}
}

func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	scaledWindowSize := r.rcvWnd >> r.RcvWndScale
	if scaledWindowSize > math.MaxUint16 {
		scaledWindowSize = math.MaxUint16
	}
	advertisedWindowSize := scaledWindowSize << r.RcvWndScale
	return header.Acceptable(segSeq, segLen, r.RcvNxt, r.RcvNxt.Add(advertisedWindowSize))
}

func (r *receiver) currentWindow() (curWnd seqnum.Size) {
	endOfWnd := r.rcvWUP.Add(r.rcvWnd)
	if endOfWnd.LessThan(r.RcvNxt) {
		return 0
	}
	return r.RcvNxt.Size(endOfWnd)
}

func (r *receiver) getSendParams() (RcvNxt seqnum.Value, rcvWnd seqnum.Size) {
	newWnd := r.ep.selectWindow()
	curWnd := r.currentWindow()
	unackLen := int(r.ep.snd.MaxSentAck.Size(r.RcvNxt))
	bufUsed := r.ep.receiveBufferUsed()

	toGrow := unackLen >= SegOverheadSize || bufUsed <= r.prevBufUsed

	if r.RcvNxt.Add(curWnd).LessThan(r.RcvNxt.Add(newWnd)) && toGrow {
		r.RcvAcc = r.RcvNxt.Add(newWnd)
	} else {
		if newWnd == 0 {
			r.ep.stats.ReceiveErrors.WantZeroRcvWindow.Increment()
		}
		newWnd = curWnd
	}

	if r.rcvWnd == 0 && newWnd != 0 {
		r.ep.rcvQueueMu.Lock()
		if crossed, above := r.ep.windowCrossedACKThresholdLocked(int(newWnd), int(r.ep.ops.GetReceiveBufferSize())); !crossed && !above {
			newWnd = 0
		}
		r.ep.rcvQueueMu.Unlock()
	}

	r.rcvWnd = newWnd
	r.rcvWUP = r.RcvNxt
	r.prevBufUsed = bufUsed
	scaledWnd := r.rcvWnd >> r.RcvWndScale
	if scaledWnd == 0 {
		r.ep.stats.ReceiveErrors.ZeroRcvWindowState.Increment()
	}

	if scaledWnd > math.MaxUint16 {
		scaledWnd = seqnum.Size(math.MaxUint16)

		r.rcvWnd = scaledWnd << r.RcvWndScale
	}
	return r.RcvNxt, scaledWnd
}

func (r *receiver) nonZeroWindow() {
	r.ep.snd.sendAck()
}

func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		if !r.RcvNxt.InWindow(segSeq, segLen) {
			return false
		}

		if segSeq.LessThan(r.RcvNxt) {
			diff := segSeq.Size(r.RcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.TrimFront(diff)
		}

		r.ep.readyToRead(s)

	} else if segSeq != r.RcvNxt {
		return false
	}

	r.RcvNxt = segSeq.Add(segLen)

	if r.RcvAcc.LessThan(r.RcvNxt) {
		r.RcvAcc = r.RcvNxt
	}

	TrimSACKBlockList(&r.ep.sack, r.RcvNxt)

	if s.flags.Contains(header.TCPFlagFin) {
		r.RcvNxt++

		r.ep.snd.sendAck()

		r.closed = true
		r.ep.readyToRead(nil)

		switch r.ep.EndpointState() {
		case StateEstablished:
			r.ep.setEndpointState(StateCloseWait)
		case StateFinWait1:
			if s.flags.Contains(header.TCPFlagAck) && r.ep.snd.finSent && s.ackNumber == r.ep.snd.SndNxt {
				r.ep.setEndpointState(StateTimeWait)
			} else {
				r.ep.setEndpointState(StateClosing)
			}
		case StateFinWait2:
			r.ep.setEndpointState(StateTimeWait)
		}

		first := 0
		if len(r.pendingRcvdSegments) != 0 && r.pendingRcvdSegments[0] == s {
			first = 1
		}

		for i := first; i < len(r.pendingRcvdSegments); i++ {
			r.PendingBufUsed -= r.pendingRcvdSegments[i].segMemSize()
			r.pendingRcvdSegments[i].DecRef()
			r.pendingRcvdSegments[i] = nil
		}
		r.pendingRcvdSegments = r.pendingRcvdSegments[:first]
		r.ep.updateConnDirectionState(connDirectionStateRcvClosed)

		return true
	}

	if s.flags.Contains(header.TCPFlagAck) && r.ep.snd.finSent && s.ackNumber == r.ep.snd.SndNxt {
		switch r.ep.EndpointState() {
		case StateFinWait1:
			r.ep.setEndpointState(StateFinWait2)
			if e := r.ep; e.closed {
				e.finWait2Timer = e.stack.Clock().AfterFunc(e.tcpLingerTimeout, e.finWait2TimerExpired)
			}

		case StateClosing:
			r.ep.setEndpointState(StateTimeWait)
		case StateLastAck:
			r.ep.transitionToStateCloseLocked()
		}
	}

	return true
}

func (r *receiver) updateRTT(rcvdTime tcpip.MonotonicTime) {
	r.ep.rcvQueueMu.Lock()
	if r.ep.RcvAutoParams.RTTMeasureTime == (tcpip.MonotonicTime{}) {
		r.ep.RcvAutoParams.RTTMeasureTime = rcvdTime
		r.ep.RcvAutoParams.RTTMeasureSeqNumber = r.RcvNxt.Add(r.rcvWnd)
		r.ep.rcvQueueMu.Unlock()
		return
	}
	if r.RcvNxt.LessThan(r.ep.RcvAutoParams.RTTMeasureSeqNumber) {
		r.ep.rcvQueueMu.Unlock()
		return
	}
	rtt := rcvdTime.Sub(r.ep.RcvAutoParams.RTTMeasureTime)
	if r.ep.RcvAutoParams.RTT == 0 || rtt < r.ep.RcvAutoParams.RTT {
		r.ep.RcvAutoParams.RTT = rtt
	}
	r.ep.RcvAutoParams.RTTMeasureTime = rcvdTime
	r.ep.RcvAutoParams.RTTMeasureSeqNumber = r.RcvNxt.Add(r.rcvWnd)
	r.ep.rcvQueueMu.Unlock()
}

func (r *receiver) handleRcvdSegmentClosing(s *segment, state EndpointState, closed bool) (drop bool, err tcpip.Error) {
	r.ep.rcvQueueMu.Lock()
	rcvClosed := r.ep.RcvClosed || r.closed
	r.ep.rcvQueueMu.Unlock()

	switch state {
	case StateCloseWait, StateClosing, StateLastAck:
		if !s.sequenceNumber.LessThanEq(r.RcvNxt) {
			return true, nil
		}
		fallthrough
	case StateFinWait1, StateFinWait2:
		if r.ep.snd.SndNxt.LessThan(s.ackNumber) {
			r.ep.snd.maybeSendOutOfWindowAck(s)
			return true, nil
		}

		endDataSeq := s.sequenceNumber.Add(seqnum.Size(s.payloadSize()))
		if state != StateCloseWait && rcvClosed && r.RcvNxt.LessThan(endDataSeq) {
			return true, &tcpip.ErrConnectionAborted{}
		}
		if state == StateFinWait1 {
			break
		}

		if s.sequenceNumber.Add(s.logicalLen()).LessThanEq(r.RcvNxt) ||
			s.logicalLen() == 0 {
			break
		}

		if closed && (!s.flags.Contains(header.TCPFlagFin) || s.sequenceNumber.Add(s.logicalLen()) != r.RcvNxt+1) {
			return true, &tcpip.ErrConnectionAborted{}
		}
	}

	segEnd := s.sequenceNumber.Add(seqnum.Size(s.payloadSize()))
	if rcvClosed && !segEnd.LessThanEq(r.RcvNxt) {
		return true, nil
	}
	return false, nil
}

func (r *receiver) handleRcvdSegment(s *segment) (drop bool, err tcpip.Error) {
	state := r.ep.EndpointState()
	closed := r.ep.closed

	segLen := seqnum.Size(s.payloadSize())
	segSeq := s.sequenceNumber

	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.maybeSendOutOfWindowAck(s)
		return true, nil
	}

	if state != StateEstablished {
		drop, err := r.handleRcvdSegmentClosing(s, state, closed)
		if drop || err != nil {
			return drop, err
		}
	}

	r.lastRcvdAckTime = s.rcvdTime

	if !r.consumeSegment(s, segSeq, segLen) {
		if segLen > 0 || s.flags.Contains(header.TCPFlagFin) {
			if rcvBufSize := r.ep.ops.GetReceiveBufferSize(); rcvBufSize > 0 && (r.PendingBufUsed+int(segLen)) < int(rcvBufSize-rcvBufSize/4) {
				r.ep.rcvQueueMu.Lock()
				r.PendingBufUsed += s.segMemSize()
				r.ep.rcvQueueMu.Unlock()
				s.IncRef()
				heap.Push(&r.pendingRcvdSegments, s)
				UpdateSACKBlocks(&r.ep.sack, segSeq, segSeq.Add(segLen), r.RcvNxt)
			}

			r.ep.snd.sendAck()
		}
		return false, nil
	}

	if segLen > 0 {
		r.updateRTT(s.rcvdTime)
	}

	for !r.closed && r.pendingRcvdSegments.Len() > 0 {
		s := r.pendingRcvdSegments[0]
		segLen := seqnum.Size(s.payloadSize())
		segSeq := s.sequenceNumber

		if !segSeq.Add(segLen-1).LessThan(r.RcvNxt) &&
			!r.consumeSegment(s, segSeq, segLen) {
			break
		}

		heap.Pop(&r.pendingRcvdSegments)
		r.ep.rcvQueueMu.Lock()
		r.PendingBufUsed -= s.segMemSize()
		r.ep.rcvQueueMu.Unlock()
		s.DecRef()
	}
	return false, nil
}

func (r *receiver) handleTimeWaitSegment(s *segment) (resetTimeWait bool, newSyn bool) {
	segSeq := s.sequenceNumber
	segLen := seqnum.Size(s.payloadSize())

	if s.flags.Contains(header.TCPFlagRst) {
		return false, false
	}



	if s.flags.Contains(header.TCPFlagSyn) && r.RcvNxt.LessThan(segSeq) {
		return false, true
	}

	if !s.flags.Contains(header.TCPFlagAck) {
		return false, false
	}

	if r.ep.SendTSOk && s.parsedOptions.TS {
		r.ep.updateRecentTimestamp(s.parsedOptions.TSVal, r.ep.snd.MaxSentAck, segSeq)
	}

	if segSeq.Add(1) == r.RcvNxt && s.flags.Contains(header.TCPFlagFin) {
		r.ep.snd.sendAck()
		return true, false
	}

	if segSeq != r.RcvNxt || segLen != 0 {
		r.ep.snd.sendAck()
	}
	return false, false
}

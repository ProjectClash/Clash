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

import "github.com/metacubex/gvisor/pkg/tcpip/seqnum"

type sackRecovery struct {
	s *sender
}

func newSACKRecovery(s *sender) *sackRecovery {
	return &sackRecovery{s: s}
}

func (sr *sackRecovery) handleSACKRecovery(limit int, end seqnum.Value) (dataSent bool) {
	snd := sr.s
	snd.SetPipe()

	if smss := int(snd.ep.scoreboard.SMSS()); limit > smss {
		limit = smss
	}

	nextSegHint := snd.writeList.Front()
	for snd.Outstanding < snd.SndCwnd {
		var nextSeg *segment
		var rescueRtx bool
		nextSeg, nextSegHint, rescueRtx = snd.NextSeg(nextSegHint)
		if nextSeg == nil {
			return dataSent
		}
		if !snd.isAssignedSequenceNumber(nextSeg) || snd.SndNxt.LessThanEq(nextSeg.sequenceNumber) {

			if sent := snd.maybeSendSegment(nextSeg, limit, end); !sent {
				return dataSent
			}
			dataSent = true
			snd.Outstanding++
			snd.updateWriteNext(nextSeg.Next())
			continue
		}

		snd.Outstanding++
		dataSent = true
		snd.sendSegment(nextSeg)

		segEnd := nextSeg.sequenceNumber.Add(nextSeg.logicalLen())
		if rescueRtx {
			snd.FastRecovery.RescueRxt = snd.FastRecovery.Last
		} else {
			snd.FastRecovery.HighRxt = segEnd - 1
		}
	}
	return dataSent
}

func (sr *sackRecovery) DoRecovery(rcvdSeg *segment, fastRetransmit bool) {
	snd := sr.s
	if fastRetransmit {
		snd.resendSegment()
	}

	if ack := rcvdSeg.ackNumber; !ack.InRange(snd.SndUna, snd.SndNxt+1) {
		return
	}

	end := snd.SndUna.Add(snd.SndWnd)
	dataSent := sr.handleSACKRecovery(snd.MaxPayloadSize, end)
	snd.postXmit(dataSent, true)
}

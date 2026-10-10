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

type renoRecovery struct {
	s *sender
}

func newRenoRecovery(s *sender) *renoRecovery {
	return &renoRecovery{s: s}
}

func (rr *renoRecovery) DoRecovery(rcvdSeg *segment, fastRetransmit bool) {
	ack := rcvdSeg.ackNumber
	snd := rr.s

	if !ack.InRange(snd.SndUna, snd.SndNxt+1) {
		return
	}

	if rcvdSeg.logicalLen() != 0 || snd.SndWnd != rcvdSeg.window {
		return
	}

	if !fastRetransmit && ack == snd.FastRecovery.First {
		if snd.SndCwnd < snd.FastRecovery.MaxCwnd {
			snd.SndCwnd++
		}
		return
	}

	snd.FastRecovery.First = ack
	snd.DupAckCount = 0
	snd.resendSegment()
}

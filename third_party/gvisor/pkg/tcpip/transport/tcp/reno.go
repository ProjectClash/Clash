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
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

type renoState struct {
	s *sender
}

func newRenoCC(s *sender) *renoState {
	return &renoState{s: s}
}

func (r *renoState) updateSlowStart(packetsAcked int) int {
	newcwnd := r.s.SndCwnd + packetsAcked
	if newcwnd >= r.s.Ssthresh {
		newcwnd = r.s.Ssthresh
		r.s.SndCAAckCount = 0
	}

	packetsAcked -= newcwnd - r.s.SndCwnd
	r.s.SndCwnd = newcwnd
	return packetsAcked
}

func (r *renoState) updateCongestionAvoidance(packetsAcked int) {
	r.s.SndCAAckCount += packetsAcked
	if r.s.SndCAAckCount >= r.s.SndCwnd {
		r.s.SndCwnd += r.s.SndCAAckCount / r.s.SndCwnd
		r.s.SndCAAckCount = r.s.SndCAAckCount % r.s.SndCwnd
	}
}

func (r *renoState) reduceSlowStartThreshold() {
	r.s.Ssthresh = r.s.Outstanding / 2
	if r.s.Ssthresh < 2 {
		r.s.Ssthresh = 2
	}

}

func (r *renoState) Update(packetsAcked int, _ time.Duration, _ tcpip.MonotonicTime) {
	if r.s.SndCwnd < r.s.Ssthresh {
		packetsAcked = r.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	}
	r.updateCongestionAvoidance(packetsAcked)
}

func (r *renoState) HandleLossDetected() {
	r.reduceSlowStartThreshold()
}

func (r *renoState) HandleRTOExpired() {
	r.reduceSlowStartThreshold()

	r.s.SndCwnd = 1
}

func (r *renoState) PostRecovery() {
}

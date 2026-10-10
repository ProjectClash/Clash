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
	"math"
	"time"

	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/tcpip"
)

const effectivelyInfinity = time.Duration(math.MaxInt64)

const (

	minRTTThresh = 4 * time.Millisecond
	maxRTTThresh = 16 * time.Millisecond

	minRTTDivisor = 8

	nRTTSample = 8

	ackDelta = 2 * time.Millisecond
)

type cubicState struct {
	TCPCubicState

	numCongestionEvents int

	s *sender
}

func newCubicCC(s *sender) *cubicState {
	now := s.ep.stack.Clock().NowMonotonic()
	return &cubicState{
		TCPCubicState: TCPCubicState{
			T:    now,
			Beta: 0.7,
			C:    0.4,
			EndSeq:  s.SndNxt,
			LastRTT: effectivelyInfinity,
			CurrRTT: effectivelyInfinity,
			LastAck:    now,
			RoundStart: now,
		},
		s: s,
	}
}

func (c *cubicState) enterCongestionAvoidance() {
	if c.numCongestionEvents == 0 {
		c.K = 0
		c.T = c.s.ep.stack.Clock().NowMonotonic()
		c.WLastMax = c.WMax
		c.WMax = float64(c.s.SndCwnd)
	}
}

func (c *cubicState) updateHyStart(rtt time.Duration, ackTime tcpip.MonotonicTime) {
	if rtt < 0 {
		return
	}
	now := ackTime
	if c.EndSeq.LessThan(c.s.SndUna) {
		c.beginHyStartRound(now)
	}
	if now.Sub(c.LastAck) < ackDelta &&
		c.LastRTT < effectivelyInfinity {
		c.LastAck = now
		if thresh := c.LastRTT / 2; now.Sub(c.RoundStart) > thresh {
			c.s.Ssthresh = c.s.SndCwnd
		}
	}

	c.CurrRTT = common.Min(c.CurrRTT, rtt)
	c.SampleCount++

	if c.SampleCount >= nRTTSample && c.LastRTT < effectivelyInfinity {
		thresh := common.Max(
			minRTTThresh,
			common.Min(maxRTTThresh, c.LastRTT/minRTTDivisor),
		)
		if c.CurrRTT >= (c.LastRTT + thresh) {
			c.s.Ssthresh = c.s.SndCwnd
		}
	}
}

func (c *cubicState) beginHyStartRound(now tcpip.MonotonicTime) {
	c.EndSeq = c.s.SndNxt
	c.SampleCount = 0
	c.LastRTT = c.CurrRTT
	c.CurrRTT = effectivelyInfinity
	c.LastAck = now
	c.RoundStart = now
}

func (c *cubicState) updateSlowStart(packetsAcked int) int {
	newcwnd := c.s.SndCwnd + packetsAcked
	enterCA := false
	if newcwnd >= c.s.Ssthresh {
		newcwnd = c.s.Ssthresh
		c.s.SndCAAckCount = 0
		enterCA = true
	}

	packetsAcked -= newcwnd - c.s.SndCwnd
	c.s.SndCwnd = newcwnd
	if enterCA {
		c.enterCongestionAvoidance()
	}
	return packetsAcked
}

func (c *cubicState) Update(packetsAcked int, rtt time.Duration, ackTime tcpip.MonotonicTime) {
	if c.s.Ssthresh == InitialSsthresh && c.s.SndCwnd < c.s.Ssthresh {
		c.updateHyStart(rtt, ackTime)
	}
	if c.s.SndCwnd < c.s.Ssthresh {
		packetsAcked = c.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	} else {
		c.s.rtt.Lock()
		srtt := c.s.rtt.TCPRTTState.SRTT
		c.s.rtt.Unlock()
		c.s.SndCwnd = c.getCwnd(packetsAcked, c.s.SndCwnd, srtt)
	}
}

func (c *cubicState) cubicCwnd(t float64) float64 {
	return c.C*math.Pow(t, 3.0) + c.WMax
}

func (c *cubicState) getCwnd(packetsAcked, sndCwnd int, srtt time.Duration) int {
	elapsed := c.s.ep.stack.Clock().NowMonotonic().Sub(c.T)
	elapsedSeconds := elapsed.Seconds()

	c.WC = c.cubicCwnd(elapsedSeconds - c.K)

	c.WEst = c.WMax*c.Beta + (3.0*((1.0-c.Beta)/(1.0+c.Beta)))*(elapsedSeconds/srtt.Seconds())

	if c.WC < c.WEst && float64(sndCwnd) < c.WEst {
		return int(c.WEst)
	}

	tEst := (elapsed + srtt).Seconds()
	wtRtt := c.cubicCwnd(tEst - c.K)
	cwnd := float64(sndCwnd)
	if wtRtt < cwnd {
		wtRtt = cwnd
	}
	for i := 0; i < packetsAcked; i++ {
		cwnd += (wtRtt - cwnd) / cwnd
	}
	return int(cwnd)
}

func (c *cubicState) HandleLossDetected() {
	c.numCongestionEvents++
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()
	c.reduceSlowStartThreshold()
}

func (c *cubicState) HandleRTOExpired() {
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.numCongestionEvents = 0
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()

	c.reduceSlowStartThreshold()

	c.s.SndCwnd = 1
}

func (c *cubicState) fastConvergence() {
	if c.WMax < c.WLastMax {
		c.WLastMax = c.WMax
		c.WMax = c.WMax * (1.0 + c.Beta) / 2.0
	} else {
		c.WLastMax = c.WMax
	}
	c.K = math.Cbrt(c.WMax * (1 - c.Beta) / c.C)
}

func (c *cubicState) PostRecovery() {
	c.T = c.s.ep.stack.Clock().NowMonotonic()
}

func (c *cubicState) reduceSlowStartThreshold() {
	c.s.Ssthresh = int(math.Max(float64(c.s.SndCwnd)*c.Beta, 2.0))
}

// Copyright (C) 2023  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package congestion

import (
	"math"
	"sync"
	"time"
)

type cubicOperationMode int

const (
	cubicSlowStart cubicOperationMode = iota
	cubicNormal
)

const (
	cubicBeta float64 = 0.7
	cubicC    float64 = 0.4
)

type CubicSendAlgorithm struct {
	minWindowSize                 uint32
	maxWindowSize                 uint32
	mode                          cubicOperationMode
	congestionWindow              uint32
	windowSizeBeforeLastReduction uint32
	lastReductionTime             float64
	accumulatedAcks               uint32
	mu                            sync.RWMutex
}

func NewCubicSendAlgorithm(minWindowSize, maxWindowSize uint32) *CubicSendAlgorithm {
	if minWindowSize > maxWindowSize {
		panic("minimum congestion window size is greater than maximum congestion window size")
	}
	return &CubicSendAlgorithm{
		minWindowSize:    minWindowSize,
		maxWindowSize:    maxWindowSize,
		mode:             cubicSlowStart,
		congestionWindow: minWindowSize,
	}
}

func (c *CubicSendAlgorithm) CongestionWindowSize() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.congestionWindow
}

func (c *CubicSendAlgorithm) InSlowStart() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode == cubicSlowStart
}

func (c *CubicSendAlgorithm) OnAck() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mode == cubicSlowStart {
		c.congestionWindow = c.congestionWindow + 1
		return c.inRange()
	}
	c.accumulatedAcks++
	k := math.Cbrt(float64(c.windowSizeBeforeLastReduction) * (1 - cubicBeta) / cubicC)
	t := float64(time.Now().UnixMicro())/1000000 - c.lastReductionTime
	c.congestionWindow = uint32(cubicC*(t-k)*(t-k)*(t-k)+float64(c.windowSizeBeforeLastReduction)) + c.accumulatedAcks/16
	return c.inRange()
}

func (c *CubicSendAlgorithm) OnLoss() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mode = cubicNormal
	c.lastReductionTime = float64(time.Now().UnixMicro()) / 1000000
	c.windowSizeBeforeLastReduction = c.congestionWindow
	c.accumulatedAcks = 0
	c.congestionWindow = uint32(float64(c.congestionWindow) * cubicBeta)
	c.congestionWindow = c.inRange()
	return c.congestionWindow
}

func (c *CubicSendAlgorithm) OnTimeout() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mode = cubicSlowStart
	c.congestionWindow = c.minWindowSize
	c.windowSizeBeforeLastReduction = 0
	c.lastReductionTime = 0
	c.accumulatedAcks = 0
	return c.congestionWindow
}

func (c *CubicSendAlgorithm) inRange() uint32 {
	if c.congestionWindow < c.minWindowSize {
		c.congestionWindow = c.minWindowSize
	} else if c.congestionWindow > c.maxWindowSize {
		c.congestionWindow = c.maxWindowSize
	}
	return c.congestionWindow
}

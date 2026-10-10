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
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	defaultBaseReachableTime = 30 * time.Second

	minimumBaseReachableTime = time.Millisecond

	defaultMinRandomFactor = 0.5

	defaultMaxRandomFactor = 1.5

	defaultRetransmitTimer = time.Second

	minimumRetransmitTimer = time.Millisecond

	defaultDelayFirstProbeTime = 5 * time.Second

	defaultMaxMulticastProbes = 3

	defaultMaxUnicastProbes = 3

	defaultMaxAnycastDelayTime = time.Second

	defaultMaxReachbilityConfirmations = 3
)

type NUDDispatcher interface {
	OnNeighborAdded(tcpip.NICID, NeighborEntry)

	OnNeighborChanged(tcpip.NICID, NeighborEntry)

	OnNeighborRemoved(tcpip.NICID, NeighborEntry)
}

type ReachabilityConfirmationFlags struct {
	Solicited bool

	Override bool

	IsRouter bool
}

type NUDConfigurations struct {
	BaseReachableTime time.Duration

	LearnBaseReachableTime bool

	MinRandomFactor float32

	MaxRandomFactor float32

	RetransmitTimer time.Duration

	LearnRetransmitTimer bool

	DelayFirstProbeTime time.Duration

	MaxMulticastProbes uint32

	MaxUnicastProbes uint32

	MaxAnycastDelayTime time.Duration

	MaxReachabilityConfirmations uint32
}

func DefaultNUDConfigurations() NUDConfigurations {
	return NUDConfigurations{
		BaseReachableTime:            defaultBaseReachableTime,
		LearnBaseReachableTime:       true,
		MinRandomFactor:              defaultMinRandomFactor,
		MaxRandomFactor:              defaultMaxRandomFactor,
		RetransmitTimer:              defaultRetransmitTimer,
		LearnRetransmitTimer:         true,
		DelayFirstProbeTime:          defaultDelayFirstProbeTime,
		MaxMulticastProbes:           defaultMaxMulticastProbes,
		MaxUnicastProbes:             defaultMaxUnicastProbes,
		MaxAnycastDelayTime:          defaultMaxAnycastDelayTime,
		MaxReachabilityConfirmations: defaultMaxReachbilityConfirmations,
	}
}

func (c *NUDConfigurations) resetInvalidFields() {
	if c.BaseReachableTime < minimumBaseReachableTime {
		c.BaseReachableTime = defaultBaseReachableTime
	}
	if c.MinRandomFactor <= 0 {
		c.MinRandomFactor = defaultMinRandomFactor
	}
	if c.MaxRandomFactor < c.MinRandomFactor {
		c.MaxRandomFactor = calcMaxRandomFactor(c.MinRandomFactor)
	}
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
	if c.DelayFirstProbeTime == 0 {
		c.DelayFirstProbeTime = defaultDelayFirstProbeTime
	}
	if c.MaxMulticastProbes == 0 {
		c.MaxMulticastProbes = defaultMaxMulticastProbes
	}
	if c.MaxUnicastProbes == 0 {
		c.MaxUnicastProbes = defaultMaxUnicastProbes
	}
}

func calcMaxRandomFactor(minRandomFactor float32) float32 {
	if minRandomFactor > defaultMaxRandomFactor {
		return minRandomFactor * 3
	}
	return defaultMaxRandomFactor
}

type nudStateMu struct {
	sync.RWMutex `state:"nosave"`

	config NUDConfigurations

	reachableTime time.Duration

	expiration            tcpip.MonotonicTime
	prevBaseReachableTime time.Duration
	prevMinRandomFactor   float32
	prevMaxRandomFactor   float32
}

type NUDState struct {
	clock tcpip.Clock
	rng *rand.Rand `state:"nosave"`
	mu  nudStateMu
}

func NewNUDState(c NUDConfigurations, clock tcpip.Clock, rng *rand.Rand) *NUDState {
	s := &NUDState{
		clock: clock,
		rng:   rng,
	}
	s.mu.config = c
	return s
}

func (s *NUDState) Config() NUDConfigurations {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mu.config
}

func (s *NUDState) SetConfig(c NUDConfigurations) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mu.config = c
}

func (s *NUDState) ReachableTime() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.clock.NowMonotonic().After(s.mu.expiration) ||
		s.mu.config.BaseReachableTime != s.mu.prevBaseReachableTime ||
		s.mu.config.MinRandomFactor != s.mu.prevMinRandomFactor ||
		s.mu.config.MaxRandomFactor != s.mu.prevMaxRandomFactor {
		s.recomputeReachableTimeLocked()
	}
	return s.mu.reachableTime
}

func (s *NUDState) recomputeReachableTimeLocked() {
	s.mu.prevBaseReachableTime = s.mu.config.BaseReachableTime
	s.mu.prevMinRandomFactor = s.mu.config.MinRandomFactor
	s.mu.prevMaxRandomFactor = s.mu.config.MaxRandomFactor

	randomFactor := s.mu.config.MinRandomFactor + s.rng.Float32()*(s.mu.config.MaxRandomFactor-s.mu.config.MinRandomFactor)

	if math.MaxInt64/randomFactor < float32(s.mu.config.BaseReachableTime) {
		s.mu.reachableTime = time.Duration(math.MaxInt64)
	} else if randomFactor == 1 {
		s.mu.reachableTime = s.mu.config.BaseReachableTime
	} else {
		reachableTime := int64(float32(s.mu.config.BaseReachableTime) * randomFactor)
		s.mu.reachableTime = time.Duration(reachableTime)
	}

	s.mu.expiration = s.clock.NowMonotonic().Add(2 * time.Hour)
}

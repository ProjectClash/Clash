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

package stack

import (
	"context"

	"golang.org/x/time/rate"
	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	icmpLimit = 1000

	icmpBurst = 50
)

type ICMPRateLimiter struct {
	limiter *rate.Limiter `state:"nosave"`
	clock   tcpip.Clock
	limit   rate.Limit
	burst   int
}

func (l *ICMPRateLimiter) afterLoad(context.Context) {
	l.limiter = rate.NewLimiter(l.limit, l.burst)
}

func NewICMPRateLimiter(clock tcpip.Clock) *ICMPRateLimiter {
	return &ICMPRateLimiter{
		clock:   clock,
		limiter: rate.NewLimiter(icmpLimit, icmpBurst),
		limit:   icmpLimit,
		burst:   icmpBurst,
	}
}

func (l *ICMPRateLimiter) SetLimit(limit rate.Limit) {
	l.limit = limit
	l.limiter.SetLimitAt(l.clock.Now(), limit)
}

func (l *ICMPRateLimiter) Limit() rate.Limit {
	return l.limiter.Limit()
}

func (l *ICMPRateLimiter) SetBurst(burst int) {
	l.burst = burst
	l.limiter.SetBurstAt(l.clock.Now(), burst)
}

func (l *ICMPRateLimiter) Burst() int {
	return l.limiter.Burst()
}

func (l *ICMPRateLimiter) Allow() bool {
	return l.limiter.AllowN(l.clock.Now(), 1)
}

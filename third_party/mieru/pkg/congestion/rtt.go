// MIT License
//
// Copyright (c) 2016 the quic-go authors & Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package congestion

import (
	"math"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/mathext"
)

const (
	rttAlpha          = 0.125
	oneMinusAlpha     = 1 - rttAlpha
	rttBeta           = 0.25
	oneMinusBeta      = 1 - rttBeta
	defaultInitialRTT = time.Second
	infDuration       = time.Duration(math.MaxInt64)
)

type RTTStats struct {
	hasMeasurement bool

	minRTT        time.Duration
	latestRTT     time.Duration
	smoothedRTT   time.Duration
	meanDeviation time.Duration

	maxAckDelay   time.Duration
	rtoMultiplier float64

	mu sync.Mutex
}

func NewRTTStats() *RTTStats {
	return &RTTStats{
		rtoMultiplier: 1.0,
	}
}

func (r *RTTStats) MinRTT() time.Duration { return r.minRTT }

func (r *RTTStats) LatestRTT() time.Duration { return r.latestRTT }

func (r *RTTStats) SmoothedRTT() time.Duration { return r.smoothedRTT }

func (r *RTTStats) MeanDeviation() time.Duration { return r.meanDeviation }

func (r *RTTStats) MaxAckDelay() time.Duration { return r.maxAckDelay }

func (r *RTTStats) RTO() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.SmoothedRTT() == 0 {
		return 2 * defaultInitialRTT
	}
	rto := r.SmoothedRTT() + mathext.Max(4*r.MeanDeviation(), 10*time.Millisecond)
	rto += r.MaxAckDelay()
	return time.Duration(float64(rto) * r.rtoMultiplier)
}

func (r *RTTStats) UpdateRTT(sample time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sample == infDuration || sample <= 0 {
		return
	}

	if r.minRTT == 0 || r.minRTT > sample {
		r.minRTT = sample
	}

	r.latestRTT = sample
	if !r.hasMeasurement {
		r.hasMeasurement = true
		r.smoothedRTT = sample
		r.meanDeviation = sample / 2
	} else {
		r.meanDeviation = time.Duration(oneMinusBeta*float32(r.meanDeviation/time.Microsecond)+rttBeta*float32(mathext.Abs(r.smoothedRTT-sample)/time.Microsecond)) * time.Microsecond
		r.smoothedRTT = time.Duration((float32(r.smoothedRTT/time.Microsecond)*oneMinusAlpha)+(float32(sample/time.Microsecond)*rttAlpha)) * time.Microsecond
	}
}

func (r *RTTStats) SetMaxAckDelay(mad time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxAckDelay = mad
}

func (r *RTTStats) SetRTOMultiplier(n float64) {
	if n <= 0 {
		panic("retransmission timeout multiplier must be greater than 0")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rtoMultiplier = n
}

func (r *RTTStats) SetInitialRTT(t time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.hasMeasurement {
		panic("initial RTT set after first measurement")
	}
	r.smoothedRTT = t
	r.latestRTT = t
}

func (r *RTTStats) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.latestRTT = 0
	r.minRTT = 0
	r.smoothedRTT = 0
	r.meanDeviation = 0
}

func (r *RTTStats) ExpireSmoothedMetrics() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.meanDeviation = mathext.Max(r.meanDeviation, mathext.Abs(r.smoothedRTT-r.latestRTT))
	r.smoothedRTT = mathext.Max(r.smoothedRTT, r.latestRTT)
}

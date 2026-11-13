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

package metrics

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enfein/mieru/v3/pkg/mathext"
	pb "github.com/enfein/mieru/v3/pkg/metrics/metricspb"
	"google.golang.org/protobuf/proto"
)

const compactIntervalMs = 1000

var tiers = [...]struct {
	width  int64
	retain int64
	label  pb.RollUpLabel
}{
	{time.Second.Milliseconds(), (120 * time.Second).Milliseconds(), pb.RollUpLabel_ROLL_UP_TO_SECOND},
	{time.Minute.Milliseconds(), (120 * time.Minute).Milliseconds(), pb.RollUpLabel_ROLL_UP_TO_MINUTE},
	{time.Hour.Milliseconds(), (8 * 24 * time.Hour).Milliseconds(), pb.RollUpLabel_ROLL_UP_TO_HOUR},
	{(24 * time.Hour).Milliseconds(), 0, pb.RollUpLabel_ROLL_UP_TO_DAY},
}

type bucket struct {
	start int64
	delta int64
}

type Counter struct {
	name  string
	value atomic.Int64

	timeSeries bool

	mu          sync.Mutex
	history     [len(tiers)][]bucket
	lastUpdate  int64
	nextCompact int64
}

var _ Metric = &Counter{}

func (c *Counter) Name() string {
	return c.name
}

func (c *Counter) Type() MetricType {
	if c.timeSeries {
		return COUNTER_TIME_SERIES
	} else {
		return COUNTER
	}
}

func (c *Counter) Add(delta int64) int64 {
	if delta < 0 {
		panic("Can't add a negative value to Counter")
	}
	if !c.timeSeries {
		return c.value.Add(delta)
	}
	return c.addWithTime(delta, time.Now())
}

func (c *Counter) Load() int64 {
	return c.value.Load()
}

func (c *Counter) Store(val int64) {
	panic("Store() is not supported by Counter")
}

func (c *Counter) DeltaBetween(t1, t2 time.Time) int64 {
	if t2.Before(t1) {
		panic("t2 must be later than t1")
	}
	if !c.timeSeries {
		panic(fmt.Sprintf("%s is not a time series Counter", c.name))
	}
	from, to := t1.UnixMilli(), t2.UnixMilli()
	c.mu.Lock()
	defer c.mu.Unlock()

	var sum int64
	for _, h := range c.history {
		i := sort.Search(len(h), func(i int) bool { return h[i].start > from })
		for ; i < len(h) && h[i].start <= to; i++ {
			sum += h[i].delta
		}
	}
	return sum
}

func (c *Counter) LastUpdateTime() time.Time {
	if !c.timeSeries {
		panic(fmt.Sprintf("%s is not a time series Counter", c.name))
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastUpdate == 0 {
		return time.Time{}
	}
	return time.UnixMilli(c.lastUpdate)
}

func (c *Counter) addWithTime(delta int64, t time.Time) int64 {
	if delta == 0 {
		return c.value.Load()
	}
	if !c.timeSeries {
		return c.value.Add(delta)
	}
	ms := t.UnixMilli()
	c.mu.Lock()
	defer c.mu.Unlock()

	c.record(0, ms, delta)
	c.lastUpdate = mathext.Max(c.lastUpdate, ms)
	if ms >= c.nextCompact {
		c.compact(ms)
		c.nextCompact = ms + compactIntervalMs
	}
	return c.value.Add(delta)
}

func (c *Counter) historyPB() (int64, []*pb.History) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, h := range c.history {
		n += len(h)
	}
	records := make([]*pb.History, 0, n)
	for i := len(tiers) - 1; i >= 0; i-- {
		for _, b := range c.history[i] {
			records = append(records, &pb.History{
				TimeUnixMilli: proto.Int64(b.start),
				Delta:         proto.Int64(b.delta),
				RollUp:        tiers[i].label.Enum(),
			})
		}
	}
	return c.value.Load(), records
}

func (c *Counter) loadHistory(records []*pb.History) {
	var loaded [len(tiers)][]bucket
	for _, r := range records {
		i := 0
		for j := range tiers {
			if tiers[j].label == r.GetRollUp() {
				i = j
				break
			}
		}
		loaded[i] = append(loaded[i], bucket{start: r.GetTimeUnixMilli(), delta: r.GetDelta()})
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = [len(tiers)][]bucket{}
	c.lastUpdate = 0
	c.nextCompact = 0
	for i, h := range loaded {
		sort.SliceStable(h, func(a, b int) bool { return h[a].start < h[b].start })
		for _, b := range h {
			c.record(i, b.start, b.delta)
			c.lastUpdate = mathext.Max(c.lastUpdate, b.start)
		}
	}
}

func (c *Counter) record(i int, ms, delta int64) {
	start := floorTo(ms, tiers[i].width)
	h := c.history[i]
	if n := len(h); n > 0 && start <= h[n-1].start {
		h[n-1].delta += delta
		return
	}
	c.history[i] = append(h, bucket{start: start, delta: delta})
}

func (c *Counter) compact(now int64) {
	for i := 0; i < len(tiers)-1; i++ {
		h := c.history[i]
		n := 0
		for n < len(h) && now-h[n].start > tiers[i].retain {
			c.record(i+1, h[n].start, h[n].delta)
			n++
		}
		if n > 0 {
			c.history[i] = h[:copy(h, h[n:])]
		}
	}
}

func floorTo(ms, width int64) int64 {
	r := ms % width
	if r < 0 {
		r += width
	}
	return ms - r
}

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

package protocol

import (
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/rng"
)

var (
	scheduleIdleTime = cipher.KeyRefreshInterval + time.Duration(rng.FixedIntVH(61))*time.Second
)

type ScheduleController struct {
	pending          int
	lastScheduleTime time.Time
	disableTime      time.Time
	mu               sync.Mutex
}

func (c *ScheduleController) IncPending() (ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.disableTime.IsZero() && time.Since(c.disableTime) > 0 {
		return false
	}
	c.pending++
	c.lastScheduleTime = time.Now()
	return true
}

func (c *ScheduleController) DecPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending--
	c.lastScheduleTime = time.Now()
}

func (c *ScheduleController) DisableTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disableTime
}

func (c *ScheduleController) IsDisabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.disableTime.IsZero() && time.Since(c.disableTime) > 0
}

func (c *ScheduleController) Idle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.disableTime.IsZero() && time.Since(c.lastScheduleTime) > scheduleIdleTime && time.Since(c.disableTime) > scheduleIdleTime
}

func (c *ScheduleController) TryDisableIdle() (ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.disableTime.IsZero() {
		return false
	}
	if c.pending > 0 {
		return false
	}
	if !c.lastScheduleTime.IsZero() && time.Since(c.lastScheduleTime) < scheduleIdleTime {
		return false
	}
	c.disableTime = time.Now()
	return true
}

func (c *ScheduleController) SetRemainingTime(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d < 0 || !c.disableTime.IsZero() {
		return
	}
	c.disableTime = time.Now().Add(d)
}

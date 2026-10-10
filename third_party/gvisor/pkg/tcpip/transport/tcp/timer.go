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

type timerState int

const (
	timerUninitialized timerState = iota
	timerStateDisabled
	timerStateEnabled
	timerStateOrphaned
)

type timer struct {
	state timerState

	clock tcpip.Clock

	target tcpip.MonotonicTime

	clockTarget tcpip.MonotonicTime

	timer tcpip.Timer

	callback func()
}

func (t *timer) init(clock tcpip.Clock, f func()) {
	t.state = timerStateDisabled
	t.clock = clock
	t.callback = f
}

func (t *timer) cleanup() {
	if t.timer == nil {
		return
	}
	t.timer.Stop()
	*t = timer{}
}

func (t *timer) isUninitialized() bool {
	return t.state == timerUninitialized
}

func (t *timer) checkExpiration() bool {
	if t.state == timerStateOrphaned {
		t.state = timerStateDisabled
		return false
	}

	now := t.clock.NowMonotonic()
	if now.Before(t.target) {
		t.clockTarget = t.target
		t.timer.Reset(t.target.Sub(now))
		return false
	}

	t.state = timerStateDisabled
	return true
}

func (t *timer) disable() {
	if t.state != timerStateDisabled {
		t.state = timerStateOrphaned
	}
}

func (t *timer) enabled() bool {
	return t.state == timerStateEnabled
}

func (t *timer) enable(d time.Duration) {
	t.target = t.clock.NowMonotonic().Add(d)

	if t.state == timerStateDisabled || t.target.Before(t.clockTarget) {
		t.clockTarget = t.target
		t.resetOrStart(d)
	}

	t.state = timerStateEnabled
}

func (t *timer) resetOrStart(d time.Duration) {
	if t.timer == nil {
		t.timer = t.clock.AfterFunc(d, t.callback)
	} else {
		t.timer.Reset(d)
	}
}

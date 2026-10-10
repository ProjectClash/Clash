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

package tcpip

import (
	"fmt"
	"time"
)

type stdClock struct {
	baseTime time.Time `state:"nosave"`

	monotonicOffset MonotonicTime
}

func NewStdClock() Clock {
	return &stdClock{
		baseTime: time.Now(),
	}
}

var _ Clock = (*stdClock)(nil)

func (*stdClock) Now() time.Time {
	return time.Now()
}

func (s *stdClock) NowMonotonic() MonotonicTime {
	sinceBase := time.Since(s.baseTime)
	if sinceBase < 0 {
		panic(fmt.Sprintf("got negative duration = %s since base time = %s", sinceBase, s.baseTime))
	}

	return s.monotonicOffset.Add(sinceBase)
}

func (*stdClock) AfterFunc(d time.Duration, f func()) Timer {
	return &stdTimer{
		t: time.AfterFunc(d, f),
	}
}

type stdTimer struct {
	t *time.Timer
}

var _ Timer = (*stdTimer)(nil)

func (st *stdTimer) Stop() bool {
	return st.t.Stop()
}

func (st *stdTimer) Reset(d time.Duration) {
	st.t.Reset(d)
}

func NewStdTimer(t *time.Timer) Timer {
	return &stdTimer{t: t}
}

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

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"
	"math"
	"time"
)

const (
	ClockTick = time.Second / CLOCKS_PER_SEC

	CLOCKS_PER_SEC = 100
)

const (
	CPUCLOCK_PROF  = 0
	CPUCLOCK_VIRT  = 1
	CPUCLOCK_SCHED = 2
	CPUCLOCK_MAX   = 3
	CLOCKFD        = CPUCLOCK_MAX

	CPUCLOCK_CLOCK_MASK     = 3
	CPUCLOCK_PERTHREAD_MASK = 4
)

const (
	CLOCK_REALTIME           = 0
	CLOCK_MONOTONIC          = 1
	CLOCK_PROCESS_CPUTIME_ID = 2
	CLOCK_THREAD_CPUTIME_ID  = 3
	CLOCK_MONOTONIC_RAW      = 4
	CLOCK_REALTIME_COARSE    = 5
	CLOCK_MONOTONIC_COARSE   = 6
	CLOCK_BOOTTIME           = 7
	CLOCK_REALTIME_ALARM     = 8
	CLOCK_BOOTTIME_ALARM     = 9
)

const (
	TIMER_ABSTIME = 1
)

const (
	TFD_CLOEXEC = O_CLOEXEC

	TFD_NONBLOCK = O_NONBLOCK

	TFD_TIMER_ABSTIME = 1 << 0

	TFD_TIMER_CANCEL_ON_SET = 1 << 1
)

const maxSecInDuration = math.MaxInt64 / int64(time.Second)

type TimeT int64

func NsecToTimeT(nsec int64) TimeT {
	return TimeT(nsec / 1e9)
}

type Timespec struct {
	_    structs.HostLayout
	Sec  int64
	Nsec int64
}

func (ts Timespec) Unix() (sec int64, nsec int64) {
	return int64(ts.Sec), int64(ts.Nsec)
}

func (ts Timespec) ToTime() time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

func (ts Timespec) ToNsec() int64 {
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

func (ts Timespec) ToNsecCapped() int64 {
	if ts.Sec > maxSecInDuration {
		return math.MaxInt64
	}
	return ts.ToNsec()
}

func (ts Timespec) ToDuration() time.Duration {
	return time.Duration(ts.ToNsecCapped())
}

func (ts Timespec) Valid() bool {
	return !(ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= int64(time.Second))
}

func NsecToTimespec(nsec int64) (ts Timespec) {
	ts.Sec = nsec / 1e9
	ts.Nsec = nsec % 1e9
	return
}

func DurationToTimespec(dur time.Duration) Timespec {
	return NsecToTimespec(dur.Nanoseconds())
}

const SizeOfTimeval = 16

type Timeval struct {
	_    structs.HostLayout
	Sec  int64
	Usec int64
}

func (tv Timeval) ToNsecCapped() int64 {
	if tv.Sec > maxSecInDuration {
		return math.MaxInt64
	}
	return int64(tv.Sec)*1e9 + int64(tv.Usec)*1e3
}

func (tv Timeval) ToDuration() time.Duration {
	return time.Duration(tv.ToNsecCapped())
}

func (tv Timeval) ToTime() time.Time {
	return time.Unix(tv.Sec, tv.Usec*1e3)
}

func NsecToTimeval(nsec int64) (tv Timeval) {
	nsec += 999
	tv.Sec = nsec / 1e9
	tv.Usec = nsec % 1e9 / 1e3
	return
}

func DurationToTimeval(dur time.Duration) Timeval {
	return NsecToTimeval(dur.Nanoseconds())
}

type Itimerspec struct {
	_        structs.HostLayout
	Interval Timespec
	Value    Timespec
}

func (its Itimerspec) Valid() bool {
	return its.Interval.Valid() && its.Value.Valid()
}

type ItimerVal struct {
	_        structs.HostLayout
	Interval Timeval
	Value    Timeval
}

type ClockT int64

func ClockTFromDuration(d time.Duration) ClockT {
	return ClockT(d / ClockTick)
}

type Tms struct {
	_      structs.HostLayout
	UTime  ClockT
	STime  ClockT
	CUTime ClockT
	CSTime ClockT
}

type TimerID int32

type StatxTimestamp struct {
	_    structs.HostLayout
	Sec  int64
	Nsec uint32
	_    int32
}

func (sxts StatxTimestamp) ToNsec() int64 {
	return int64(sxts.Sec)*1e9 + int64(sxts.Nsec)
}

func (sxts StatxTimestamp) ToNsecCapped() int64 {
	if sxts.Sec > maxSecInDuration {
		return math.MaxInt64
	}
	return sxts.ToNsec()
}

func NsecToStatxTimestamp(nsec int64) (ts StatxTimestamp) {
	return StatxTimestamp{
		Sec:  nsec / 1e9,
		Nsec: uint32(nsec % 1e9),
	}
}

func (sxts StatxTimestamp) ToTime() time.Time {
	return time.Unix(sxts.Sec, int64(sxts.Nsec))
}

type Utime struct {
	_       structs.HostLayout
	Actime  int64
	Modtime int64
}

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
)

const (
	RLIMIT_CPU        = 0
	RLIMIT_FSIZE      = 1
	RLIMIT_DATA       = 2
	RLIMIT_STACK      = 3
	RLIMIT_CORE       = 4
	RLIMIT_RSS        = 5
	RLIMIT_NPROC      = 6
	RLIMIT_NOFILE     = 7
	RLIMIT_MEMLOCK    = 8
	RLIMIT_AS         = 9
	RLIMIT_LOCKS      = 10
	RLIMIT_SIGPENDING = 11
	RLIMIT_MSGQUEUE   = 12
	RLIMIT_NICE       = 13
	RLIMIT_RTPRIO     = 14
	RLIMIT_RTTIME     = 15
)

type RLimit struct {
	_ structs.HostLayout
	Cur uint64
	Max uint64
}

const (
	RLimInfinity = ^uint64(0)

	DefaultStackSoftLimit = 8 * 1024 * 1024

	DefaultNprocLimit = FUTEX_TID_MASK / 2

	DefaultNofileSoftLimit = 1024

	DefaultNofileHardLimit = 4096

	DefaultMemlockLimit = 64 * 1024

	DefaultMsgqueueLimit = 819200
)

var InitRLimits = map[int]RLimit{
	RLIMIT_CPU:        {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_FSIZE:      {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_DATA:       {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_STACK:      {Cur: DefaultStackSoftLimit, Max: RLimInfinity},
	RLIMIT_CORE:       {Cur: 0, Max: RLimInfinity},
	RLIMIT_RSS:        {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_NPROC:      {Cur: DefaultNprocLimit, Max: DefaultNprocLimit},
	RLIMIT_NOFILE:     {Cur: DefaultNofileSoftLimit, Max: DefaultNofileHardLimit},
	RLIMIT_MEMLOCK:    {Cur: DefaultMemlockLimit, Max: DefaultMemlockLimit},
	RLIMIT_AS:         {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_LOCKS:      {Cur: RLimInfinity, Max: RLimInfinity},
	RLIMIT_SIGPENDING: {Cur: 0, Max: 0},
	RLIMIT_MSGQUEUE:   {Cur: DefaultMsgqueueLimit, Max: DefaultMsgqueueLimit},
	RLIMIT_NICE:       {Cur: 0, Max: 0},
	RLIMIT_RTPRIO:     {Cur: 0, Max: 0},
	RLIMIT_RTTIME:     {Cur: RLimInfinity, Max: RLimInfinity},
}

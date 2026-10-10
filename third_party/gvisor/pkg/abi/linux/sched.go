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

import "github.com/metacubex/gvisor/pkg/common/structs"

const (
	SCHED_NORMAL   = 0
	SCHED_FIFO     = 1
	SCHED_RR       = 2
	SCHED_BATCH    = 3
	SCHED_IDLE     = 5
	SCHED_DEADLINE = 6
	SCHED_MICROQ   = 16

	SCHED_RESET_ON_FORK = 0x40000000
)

const (
	PRIO_PGRP    = 0x1
	PRIO_PROCESS = 0x0
	PRIO_USER    = 0x2
)

type SchedAttr struct {
	_ structs.HostLayout

	Size uint32

	SchedPolicy   uint32
	SchedFlags    uint64
	SchedNice     int32
	SchedPriority uint32

	SchedRuntime  uint64
	SchedDeadline uint64
	SchedPeriod   uint64

	SchedUtilMin uint32
	SchedUtilMax uint32
}

const (
	SCHED_ATTR_SIZE_VER0 = 48
	SCHED_ATTR_SIZE_VER1 = 56

	SCHED_ATTR_SIZE_LATEST = SCHED_ATTR_SIZE_VER1
)

const (
	SCHED_FLAG_RESET_ON_FORK  = 0x01
	SCHED_FLAG_RECLAIM        = 0x02
	SCHED_FLAG_DL_OVERRUN     = 0x04
	SCHED_FLAG_KEEP_POLICY    = 0x08
	SCHED_FLAG_KEEP_PARAMS    = 0x10
	SCHED_FLAG_UTIL_CLAMP_MIN = 0x20
	SCHED_FLAG_UTIL_CLAMP_MAX = 0x40
)

const (
	IOPRIO_WHO_PROCESS = 1
	IOPRIO_WHO_PGRP    = 2
	IOPRIO_WHO_USER    = 3
)

const (
	IOPRIO_CLASS_NONE = 0
	IOPRIO_CLASS_RT   = 1
	IOPRIO_CLASS_BE   = 2
	IOPRIO_CLASS_IDLE = 3
)

const (
	IOPRIO_CLASS_SHIFT = 13
	IOPRIO_NR_CLASSES  = 8
	IOPRIO_CLASS_MASK  = IOPRIO_NR_CLASSES - 1
	IOPRIO_PRIO_MASK   = (1 << IOPRIO_CLASS_SHIFT) - 1
)

func UnwrapIOPrio(ioprio int) (ioclass int8, iopriodata uint16) {
	ioclass = int8((ioprio >> IOPRIO_CLASS_SHIFT) & (IOPRIO_CLASS_MASK))
	iopriodata = uint16(ioprio & IOPRIO_PRIO_MASK)
	return
}

// Copyright 2022 The gVisor Authors.
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
	IORING_SETUP_IOPOLL     = (1 << 0)
	IORING_SETUP_SQPOLL     = (1 << 1)
	IORING_SETUP_SQ_AFF     = (1 << 2)
	IORING_SETUP_CQSIZE     = (1 << 3)
	IORING_SETUP_CLAMP      = (1 << 4)
	IORING_SETUP_ATTACH_WQ  = (1 << 5)
	IORING_SETUP_R_DISABLED = (1 << 6)
	IORING_SETUP_SUBMIT_ALL = (1 << 7)
)

const (
	IORING_ENTER_GETEVENTS = (1 << 0)
)

const (
	IORING_FEAT_SINGLE_MMAP = (1 << 0)
)

const (
	IORING_SETUP_COOP_TASKRUN = (1 << 8)
	IORING_SETUP_TASKRUN_FLAG = (1 << 9)
	IORING_SETUP_SQE128       = (1 << 10)
	IORING_SETUP_CQE32        = (1 << 11)
)

const (
	IORING_MAX_ENTRIES    = (1 << 15)
	IORING_MAX_CQ_ENTRIES = (2 * IORING_MAX_ENTRIES)
)

const (
	IORING_OFF_SQ_RING = 0
	IORING_OFF_CQ_RING = 0x8000000
	IORING_OFF_SQES    = 0x10000000
)

const (
	IORING_OP_NOP   = 0
	IORING_OP_READV = 1
)

type IORingIndex uint32

type IOSqRingOffsets struct {
	_           structs.HostLayout
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

type IOCqRingOffsets struct {
	_           structs.HostLayout
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	Resv2       uint64
}

type IOUringParams struct {
	_            structs.HostLayout
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        IOSqRingOffsets
	CqOff        IOCqRingOffsets
}

type IOUringCqe struct {
	_        structs.HostLayout
	UserData uint64
	Res      int32
	Flags    uint32
}

type IOUring struct {
	_ structs.HostLayout
	Head uint32
	_    [60]byte
	Tail uint32
	_    [60]byte
}

type IORings struct {
	_             structs.HostLayout
	Sq            IOUring
	Cq            IOUring
	SqRingMask    uint32
	CqRingMask    uint32
	SqRingEntries uint32
	CqRingEntries uint32
	sqDropped     uint32
	sqFlags       int32
	cqFlags       uint32
	CqOverflow    uint32
	_             [32]byte
}

type IOUringSqe struct {
	_                   structs.HostLayout
	Opcode              uint8
	Flags               uint8
	IoPrio              uint16
	Fd                  int32
	OffOrAddrOrCmdOp    uint64
	AddrOrSpliceOff     uint64
	Len                 uint32
	specialFlags        uint32
	UserData            uint64
	BufIndexOrGroup     uint16
	personality         uint16
	spliceFDOrFileIndex int32
	addr3               uint64
	_                   uint64
}

const (
	_IOSqRingOffset        = 0
	_IOSqRingOffsetHead    = 0
	_IOSqRingOffsetTail    = 64
	_IOSqRingOffsetMask    = 256
	_IOSqRingOffsetEntries = 264
	_IOSqRingOffsetFlags   = 276
	_IOSqRingOffsetDropped = 272
)

func PreComputedIOSqRingOffsets() IOSqRingOffsets {
	return IOSqRingOffsets{
		Head:        _IOSqRingOffset + _IOSqRingOffsetHead,
		Tail:        _IOSqRingOffset + _IOSqRingOffsetTail,
		RingMask:    _IOSqRingOffsetMask,
		RingEntries: _IOSqRingOffsetEntries,
		Flags:       _IOSqRingOffsetFlags,
		Dropped:     _IOSqRingOffsetDropped,
	}
}

const (
	_IOCqRingOffset         = 128
	_IOCqRingOffsetHead     = 0
	_IOCqRingOffsetTail     = 64
	_IOCqRingOffsetMask     = 260
	_IOCqRingOffsetEntries  = 268
	_IOCqRingOffsetFlags    = 280
	_IOCqRingOffsetOverflow = 284
)

func PreComputedIOCqRingOffsets() IOCqRingOffsets {
	return IOCqRingOffsets{
		Head:        _IOCqRingOffset + _IOCqRingOffsetHead,
		Tail:        _IOCqRingOffset + _IOCqRingOffsetTail,
		RingMask:    _IOCqRingOffsetMask,
		RingEntries: _IOCqRingOffsetEntries,
		Overflow:    _IOCqRingOffsetOverflow,
		Flags:       _IOCqRingOffsetFlags,
	}
}

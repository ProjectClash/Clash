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
	"encoding/binary"
	"github.com/metacubex/gvisor/pkg/common/structs"
)

type AIORing struct {
	_                structs.HostLayout
	ID               uint32
	Nr               uint32
	Head             uint32
	Tail             uint32
	Magic            uint32
	CompatFeatures   uint32
	IncompatFeatures uint32
	HeaderLength     uint32
}

const AIORingSize = 32

const AIO_RING_MAGIC = 0xa10a10a1

const (
	IOCB_CMD_PREAD  = 0
	IOCB_CMD_PWRITE = 1
	IOCB_CMD_FSYNC  = 2
	IOCB_CMD_FDSYNC = 3
	IOCB_CMD_POLL    = 5
	IOCB_CMD_NOOP    = 6
	IOCB_CMD_PREADV  = 7
	IOCB_CMD_PWRITEV = 8
)

const (
	IOCB_FLAG_RESFD  = 1
	IOCB_FLAG_IOPRIO = 2
)

type IOCallback struct {
	_    structs.HostLayout
	Data uint64
	Key  uint32
	_    uint32

	OpCode  uint16
	ReqPrio int16
	FD      int32

	Buf    uint64
	Bytes  uint64
	Offset int64

	Reserved2 uint64
	Flags     uint32

	ResFD int32
}

type IOEvent struct {
	_       structs.HostLayout
	Data    uint64
	Obj     uint64
	Result  int64
	Result2 int64
}

var IOEventSize = binary.Size(IOEvent{})

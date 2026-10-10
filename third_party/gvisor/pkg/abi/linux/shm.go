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
)

const (
	SHM_RDONLY = 010000
	SHM_RND    = 020000
	SHM_REMAP  = 040000
	SHM_EXEC   = 0100000
)

const (
	SHM_DEST      = 01000
	SHM_LOCKED    = 02000
	SHM_HUGETLB   = 04000
	SHM_NORESERVE = 010000
)

const (
	SHM_LOCK   = 11
	SHM_UNLOCK = 12
	SHM_STAT   = 13
	SHM_INFO   = 14
)

const (
	SHMMIN = 1
	SHMMNI = 4096
	SHMMAX = math.MaxUint64 - 1<<24
	SHMALL = math.MaxUint64 - 1<<24
	SHMSEG = 4096
)

type ShmidDS struct {
	_          structs.HostLayout
	ShmPerm    IPCPerm
	ShmSegsz   uint64
	ShmAtime   TimeT
	ShmDtime   TimeT
	ShmCtime   TimeT
	ShmCpid    int32
	ShmLpid    int32
	ShmNattach uint64

	Unused4 uint64
	Unused5 uint64
}

type ShmParams struct {
	_      structs.HostLayout
	ShmMax uint64
	ShmMin uint64
	ShmMni uint64
	ShmSeg uint64
	ShmAll uint64
}

type ShmInfo struct {
	_             structs.HostLayout
	UsedIDs       int32
	_             [4]byte
	ShmTot        uint64
	ShmRss        uint64
	ShmSwp        uint64
	SwapAttempts  uint64
	SwapSuccesses uint64
}

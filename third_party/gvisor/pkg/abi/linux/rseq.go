// Copyright 2019 The gVisor Authors.
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
	RSEQ_FLAG_UNREGISTER = 1 << 0
)

const (
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT = 1 << 0

	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL = 1 << 1

	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE = 1 << 2
)

type RSeqCriticalSection struct {
	_ structs.HostLayout
	Version uint32

	Flags uint32

	Start uint64

	PostCommitOffset uint64

	Abort uint64
}

const (
	SizeOfRSeqCriticalSection = 32

	SizeOfRSeqSignature = 4
)

const (
	RSEQ_CPU_ID_UNINITIALIZED = ^uint32(0)

	RSEQ_CPU_ID_REGISTRATION_FAILED = ^uint32(1)
)

type RSeq struct {
	_ structs.HostLayout
	CPUIDStart uint32

	CPUID uint32

	RSeqCriticalSection uint64

	Flags uint32
}

const (
	SizeOfRSeq = 32

	AlignOfRSeq = 32

	OffsetOfRSeqCriticalSection = 8
)

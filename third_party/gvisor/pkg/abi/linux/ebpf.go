// Copyright 2026 The gVisor Authors.
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

	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/marshal"
)

type EBPFInstruction struct {
	_ structs.HostLayout

	Code      uint8
	Registers uint8
	Offset    int16
	Immediate int32
}

const (
	BPF_COMPLEXITY_LIMIT_INSNS = 1_000_000

	BPF_OBJ_NAME_LEN = 16

	BPF_INSTRUCTION_SIZE = 8

	BPF_CGROUP_MAX_PROGS = 64
)

const (
	BPF_MAP_CREATE = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	BPF_MAP_FREEZE
	BPF_BTF_GET_NEXT_ID
	BPF_MAP_LOOKUP_BATCH
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	BPF_MAP_UPDATE_BATCH
	BPF_MAP_DELETE_BATCH
	BPF_LINK_CREATE
	BPF_LINK_UPDATE
	BPF_LINK_GET_FD_BY_ID
	BPF_LINK_GET_NEXT_ID
	BPF_ENABLE_STATS
	BPF_ITER_CREATE
	BPF_LINK_DETACH
	BPF_PROG_BIND_MAP
	BPF_TOKEN_CREATE
	BPF_PROG_STREAM_READ_BY_FD
	BPF_PROG_ASSOC_STRUCT_OPS

	BPF_PROG_RUN = BPF_PROG_TEST_RUN
)

type BPFProgramType uint

const (
	BPF_PROG_TYPE_UNSPEC BPFProgramType = iota
	BPF_PROG_TYPE_SOCKET_FILTER
	BPF_PROG_TYPE_KPROBE
	BPF_PROG_TYPE_SCHED_CLS
	BPF_PROG_TYPE_SCHED_ACT
	BPF_PROG_TYPE_TRACEPOINT
	BPF_PROG_TYPE_XDP
	BPF_PROG_TYPE_PERF_EVENT
	BPF_PROG_TYPE_CGROUP_SKB
	BPF_PROG_TYPE_CGROUP_SOCK
	BPF_PROG_TYPE_LWT_IN
	BPF_PROG_TYPE_LWT_OUT
	BPF_PROG_TYPE_LWT_XMIT
	BPF_PROG_TYPE_SOCK_OPS
	BPF_PROG_TYPE_SK_SKB
	BPF_PROG_TYPE_CGROUP_DEVICE
	BPF_PROG_TYPE_SK_MSG
	BPF_PROG_TYPE_RAW_TRACEPOINT
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPF_PROG_TYPE_LIRC_MODE2
	BPF_PROG_TYPE_SK_REUSEPORT
	BPF_PROG_TYPE_FLOW_DISSECTOR
	BPF_PROG_TYPE_CGROUP_SYSCTL
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPF_PROG_TYPE_TRACING
	BPF_PROG_TYPE_STRUCT_OPS
	BPF_PROG_TYPE_EXT
	BPF_PROG_TYPE_LSM
	BPF_PROG_TYPE_SK_LOOKUP
	BPF_PROG_TYPE_SYSCALL
	BPF_PROG_TYPE_NETFILTER
)

type BPFAttachType uint

const (
	BPF_CGROUP_INET_INGRESS BPFAttachType = iota
	BPF_CGROUP_INET_EGRESS
	BPF_CGROUP_INET_SOCK_CREATE
	BPF_CGROUP_SOCK_OPS
	BPF_SK_SKB_STREAM_PARSER
	BPF_SK_SKB_STREAM_VERDICT
	BPF_CGROUP_DEVICE
	BPF_SK_MSG_VERDICT
	BPF_CGROUP_INET4_BIND
	BPF_CGROUP_INET6_BIND
	BPF_CGROUP_INET4_CONNECT
	BPF_CGROUP_INET6_CONNECT
	BPF_CGROUP_INET4_POST_BIND
	BPF_CGROUP_INET6_POST_BIND
	BPF_CGROUP_UDP4_SENDMSG
	BPF_CGROUP_UDP6_SENDMSG
	BPF_LIRC_MODE2
	BPF_FLOW_DISSECTOR
	BPF_CGROUP_SYSCTL
	BPF_CGROUP_UDP4_RECVMSG
	BPF_CGROUP_UDP6_RECVMSG
	BPF_CGROUP_GETSOCKOPT
	BPF_CGROUP_SETSOCKOPT
	BPF_TRACE_RAW_TP
	BPF_TRACE_FENTRY
	BPF_TRACE_FEXIT
	BPF_MODIFY_RETURN
	BPF_LSM_MAC
	BPF_TRACE_ITER
	BPF_CGROUP_INET4_GETPEERNAME
	BPF_CGROUP_INET6_GETPEERNAME
	BPF_CGROUP_INET4_GETSOCKNAME
	BPF_CGROUP_INET6_GETSOCKNAME
	BPF_XDP_DEVMAP
	BPF_CGROUP_INET_SOCK_RELEASE
	BPF_XDP_CPUMAP
	BPF_SK_LOOKUP
	BPF_XDP
	BPF_SK_SKB_VERDICT
	BPF_SK_REUSEPORT_SELECT
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
	BPF_PERF_EVENT
	BPF_TRACE_KPROBE_MULTI
	BPF_LSM_CGROUP
	BPF_STRUCT_OPS
	BPF_NETFILTER
	BPF_TCX_INGRESS
	BPF_TCX_EGRESS
	BPF_TRACE_UPROBE_MULTI
	BPF_CGROUP_UNIX_CONNECT
	BPF_CGROUP_UNIX_SENDMSG
	BPF_CGROUP_UNIX_RECVMSG
	BPF_CGROUP_UNIX_GETPEERNAME
	BPF_CGROUP_UNIX_GETSOCKNAME
	BPF_NETKIT_PRIMARY
	BPF_NETKIT_PEER
	BPF_TRACE_KPROBE_SESSION
	BPF_TRACE_UPROBE_SESSION
	BPF_TRACE_FSESSION
)

type BPFAttr interface {
	marshal.Marshallable

	implementsBPFAttr()
}

func (a *BPFAttrProgLoad) implementsBPFAttr()   {}
func (a *BPFAttrProgQuery) implementsBPFAttr()  {}
func (a *BPFAttrProgAttach) implementsBPFAttr() {}

type BPFAttrProgLoad struct {
	_ structs.HostLayout

	ProgType           uint32
	InstructionCount   uint32
	Instructions       uint64
	License            uint64
	LogLevel           uint32
	LogSize            uint32
	LogBuf             uint64
	KernVersion        uint32
	ProgFlags          uint32
	ProgName           [BPF_OBJ_NAME_LEN]byte
	ProgInterfaceIndex uint32
	ExpectedAttachType uint32
	ProgBTFFD          uint32
	FuncInfoRecSize    uint32
	FuncInfo           uint64
	FuncInfoCount      uint32
	LineInfoRecSize    uint32
	LineInfo           uint64
	LineInfoCount      uint32
	AttachBTFID        uint32
	AttachFD           uint32
	CoreReloCount      uint32
	FDArray            uint64
	CoreRelos          uint64
	CoreReloRecSize    uint32
	LogTrueSize        uint32
	ProgTokenFD        int32
	FDArrayCount       uint32
	Signature          uint64
	SignatureSize      uint32
	KeyringID          int32
}

type BPFAttrProgQuery struct {
	_ structs.HostLayout

	Target          uint32
	AttachType      uint32
	QueryFlags      uint32
	AttachFlags     uint32
	ProgIDs         uint64
	Count           uint32
	_               uint32
	ProgAttachFlags uint64
	LinkIDs         uint64
	LinkAttachFlags uint64
	Revision        uint64
}

type BPFAttrProgAttach struct {
	_ structs.HostLayout

	Target           uint32
	AttachBPFFD      uint32
	AttachType       uint32
	AttachFlags      uint32
	ReplaceBPFFD     uint32
	Relative         uint32
	ExpectedRevision uint64
}

var BPF_ATTR_SIZE = common.Max((*BPFAttrProgLoad)(nil).SizeBytes(), common.Max((*BPFAttrProgQuery)(nil).SizeBytes(), (*BPFAttrProgAttach)(nil).SizeBytes()))

const (
	BPF_F_ALLOW_OVERRIDE = 1 << iota
	BPF_F_ALLOW_MULTI
	BPF_F_REPLACE
	BPF_F_BEFORE
	BPF_F_AFTER
	BPF_F_ID
	BPF_F_PREORDER
	BPF_F_LINK = 1 << 13
)

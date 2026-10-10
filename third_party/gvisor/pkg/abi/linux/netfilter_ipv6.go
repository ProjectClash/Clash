// Copyright 2020 The gVisor Authors.
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

	"github.com/metacubex/gvisor/pkg/marshal"
	"github.com/metacubex/gvisor/pkg/marshal/primitive"
)


const (
	NF_IP6_PRI_FIRST             = math.MinInt
	NF_IP6_PRI_RAW_BEFORE_DEFRAG = -450
	NF_IP6_PRI_CONNTRACK_DEFRAG  = -400
	NF_IP6_PRI_RAW               = -300
	NF_IP6_PRI_SELINUX_FIRST     = -225
	NF_IP6_PRI_CONNTRACK         = -200
	NF_IP6_PRI_MANGLE            = -150
	NF_IP6_PRI_NAT_DST           = -100
	NF_IP6_PRI_FILTER            = 0
	NF_IP6_PRI_SECURITY          = 50
	NF_IP6_PRI_NAT_SRC           = 100
	NF_IP6_PRI_SELINUX_LAST      = 225
	NF_IP6_PRI_CONNTRACK_HELPER  = 300
	NF_IP6_PRI_LAST              = math.MaxInt
)

const (
	IP6T_BASE_CTL            = 64
	IP6T_SO_SET_REPLACE      = IPT_BASE_CTL
	IP6T_SO_SET_ADD_COUNTERS = IPT_BASE_CTL + 1
	IP6T_SO_SET_MAX          = IPT_SO_SET_ADD_COUNTERS

	IP6T_SO_GET_INFO            = IPT_BASE_CTL
	IP6T_SO_GET_ENTRIES         = IPT_BASE_CTL + 1
	IP6T_SO_GET_REVISION_MATCH  = IPT_BASE_CTL + 4
	IP6T_SO_GET_REVISION_TARGET = IPT_BASE_CTL + 5
	IP6T_SO_GET_MAX             = IP6T_SO_GET_REVISION_TARGET
)

const IP6T_ORIGINAL_DST = 80

type IP6TReplace struct {
	_           structs.HostLayout
	Name        TableName
	ValidHooks  uint32
	NumEntries  uint32
	Size        uint32
	HookEntry   [NF_INET_NUMHOOKS]uint32
	Underflow   [NF_INET_NUMHOOKS]uint32
	NumCounters uint32
	Counters    uint64
}

const SizeOfIP6TReplace = 96

type KernelIP6TGetEntries struct {
	_ structs.HostLayout
	IPTGetEntries
	Entrytable []KernelIP6TEntry `hostlayout:"ignore"`
}

func (ke *KernelIP6TGetEntries) SizeBytes() int {
	res := ke.IPTGetEntries.SizeBytes()
	for _, entry := range ke.Entrytable {
		res += entry.SizeBytes()
	}
	return res
}

func (ke *KernelIP6TGetEntries) MarshalBytes(dst []byte) []byte {
	dst = ke.IPTGetEntries.MarshalUnsafe(dst)
	for i := range ke.Entrytable {
		dst = ke.Entrytable[i].MarshalBytes(dst)
	}
	return dst
}

func (ke *KernelIP6TGetEntries) UnmarshalBytes(src []byte) []byte {
	src = ke.IPTGetEntries.UnmarshalUnsafe(src)
	for i := range ke.Entrytable {
		src = ke.Entrytable[i].UnmarshalBytes(src)
	}
	return src
}

var _ marshal.Marshallable = (*KernelIP6TGetEntries)(nil)

type IP6TEntry struct {
	_ structs.HostLayout
	IPv6 IP6TIP

	NFCache uint32

	TargetOffset uint16

	NextOffset uint16

	Comeback uint32

	_ [4]byte

	Counters XTCounters

}

const SizeOfIP6TEntry = 168

type KernelIP6TEntry struct {
	_     structs.HostLayout
	Entry IP6TEntry

	Elems primitive.ByteSlice `hostlayout:"ignore"`
}

func (ke *KernelIP6TEntry) SizeBytes() int {
	return ke.Entry.SizeBytes() + ke.Elems.SizeBytes()
}

func (ke *KernelIP6TEntry) MarshalBytes(dst []byte) []byte {
	dst = ke.Entry.MarshalUnsafe(dst)
	return ke.Elems.MarshalBytes(dst)
}

func (ke *KernelIP6TEntry) UnmarshalBytes(src []byte) []byte {
	src = ke.Entry.UnmarshalUnsafe(src)
	return ke.Elems.UnmarshalBytes(src)
}

var _ marshal.Marshallable = (*KernelIP6TEntry)(nil)

type IP6TIP struct {
	_ structs.HostLayout
	Src Inet6Addr

	Dst Inet6Addr

	SrcMask Inet6Addr

	DstMask Inet6Addr

	InputInterface [IFNAMSIZ]byte

	OutputInterface [IFNAMSIZ]byte

	InputInterfaceMask [IFNAMSIZ]byte

	OutputInterfaceMask [IFNAMSIZ]byte

	Protocol uint16

	TOS uint8

	Flags uint8

	InverseFlags uint8

	_ [3]byte
}

const SizeOfIP6TIP = 136

const (
	IP6T_F_PROTO = 0x01
	IP6T_F_TOS = 0x02
	IP6T_F_GOTO = 0x04
	IP6T_F_MASK = 0x07
)

const (
	IP6T_INV_VIA_IN = 0x01
	IP6T_INV_VIA_OUT = 0x02
	IP6T_INV_TOS = 0x04
	IP6T_INV_SRCIP = 0x08
	IP6T_INV_DSTIP = 0x10
	IP6T_INV_FRAG = 0x20
	IP6T_INV_MASK = 0x7F
)

type NFNATRange struct {
	_        structs.HostLayout
	Flags    uint32
	MinAddr  Inet6Addr
	MaxAddr  Inet6Addr
	MinProto uint16
	MaxProto uint16
}

const SizeOfNFNATRange = 40

type NFNATRange2 struct {
	_         structs.HostLayout
	Flags     uint32
	MinAddr   Inet6Addr
	MaxAddr   Inet6Addr
	MinProto  uint16
	MaxProto  uint16
	BaseProto uint16
	_         [6]byte
}

const SizeOfNFNATRange2 = 48

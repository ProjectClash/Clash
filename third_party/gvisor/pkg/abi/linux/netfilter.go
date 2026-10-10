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

	"github.com/metacubex/gvisor/pkg/marshal"
	"github.com/metacubex/gvisor/pkg/marshal/primitive"
)


const (
	NF_INET_PRE_ROUTING  = 0
	NF_INET_LOCAL_IN     = 1
	NF_INET_FORWARD      = 2
	NF_INET_LOCAL_OUT    = 3
	NF_INET_POST_ROUTING = 4
	NF_INET_NUMHOOKS     = 5
	NF_INET_INGRESS      = NF_INET_NUMHOOKS
)

const (
	NF_NETDEV_INGRESS = iota
	NF_NETDEV_EGRESS
	NF_NETDEV_NUMHOOKS
)

const (
	NFPROTO_UNSPEC = 0
	NFPROTO_INET   = 1
	NFPROTO_IPV4   = 2
	NFPROTO_ARP    = 3
	NFPROTO_NETDEV = 5
	NFPROTO_BRIDGE = 7
	NFPROTO_IPV6   = 10
)

const (
	NF_DROP        = 0
	NF_ACCEPT      = 1
	NF_STOLEN      = 2
	NF_QUEUE       = 3
	NF_REPEAT      = 4
	NF_STOP        = 5
	NF_MAX_VERDICT = NF_STOP
	NF_RETURN = -NF_REPEAT - 1
)

var VerdictStrings = map[int32]string{
	-NF_DROP - 1:   "DROP",
	-NF_ACCEPT - 1: "ACCEPT",
	-NF_QUEUE - 1:  "QUEUE",
	NF_RETURN:      "RETURN",
}

const (
	IPT_BASE_CTL            = 64
	IPT_SO_SET_REPLACE      = IPT_BASE_CTL
	IPT_SO_SET_ADD_COUNTERS = IPT_BASE_CTL + 1
	IPT_SO_SET_MAX          = IPT_SO_SET_ADD_COUNTERS

	IPT_SO_GET_INFO            = IPT_BASE_CTL
	IPT_SO_GET_ENTRIES         = IPT_BASE_CTL + 1
	IPT_SO_GET_REVISION_MATCH  = IPT_BASE_CTL + 2
	IPT_SO_GET_REVISION_TARGET = IPT_BASE_CTL + 3
	IPT_SO_GET_MAX             = IPT_SO_GET_REVISION_TARGET
)

const (
	SO_ORIGINAL_DST = 80
)

const (
	XT_FUNCTION_MAXNAMELEN  = 30
	XT_EXTENSION_MAXNAMELEN = 29
	XT_TABLE_MAXNAMELEN     = 32
)

type IPTEntry struct {
	_ structs.HostLayout
	IP IPTIP

	NFCache uint32

	TargetOffset uint16

	NextOffset uint16

	Comeback uint32

	Counters XTCounters

}

const SizeOfIPTEntry = 112

type KernelIPTEntry struct {
	_     structs.HostLayout
	Entry IPTEntry

	Elems primitive.ByteSlice `hostlayout:"ignore"`
}

func (ke *KernelIPTEntry) SizeBytes() int {
	return ke.Entry.SizeBytes() + ke.Elems.SizeBytes()
}

func (ke *KernelIPTEntry) MarshalBytes(dst []byte) []byte {
	dst = ke.Entry.MarshalUnsafe(dst)
	return ke.Elems.MarshalBytes(dst)
}

func (ke *KernelIPTEntry) UnmarshalBytes(src []byte) []byte {
	src = ke.Entry.UnmarshalUnsafe(src)
	return ke.Elems.UnmarshalBytes(src)
}

var _ marshal.Marshallable = (*KernelIPTEntry)(nil)

type IPTIP struct {
	_ structs.HostLayout
	Src InetAddr

	Dst InetAddr

	SrcMask InetAddr

	DstMask InetAddr

	InputInterface [IFNAMSIZ]byte

	OutputInterface [IFNAMSIZ]byte

	InputInterfaceMask [IFNAMSIZ]byte

	OutputInterfaceMask [IFNAMSIZ]byte

	Protocol uint16

	Flags uint8

	InverseFlags uint8
}

const (
	IPT_INV_VIA_IN = 0x01
	IPT_INV_VIA_OUT = 0x02
	IPT_INV_TOS = 0x04
	IPT_INV_SRCIP = 0x08
	IPT_INV_DSTIP = 0x10
	IPT_INV_FRAG = 0x20
	IPT_INV_PROTO = 0x40
	IPT_INV_MASK = 0x7F
)

const SizeOfIPTIP = 84

type XTCounters struct {
	_ structs.HostLayout
	Pcnt uint64

	Bcnt uint64
}

const SizeOfXTCounters = 16

type XTEntryMatch struct {
	_         structs.HostLayout
	MatchSize uint16
	Name      ExtensionName
	Revision  uint8
}

const SizeOfXTEntryMatch = 32

type KernelXTEntryMatch struct {
	_ structs.HostLayout
	XTEntryMatch
	Data []byte `hostlayout:"ignore"`
}

type XTGetRevision struct {
	_        structs.HostLayout
	Name     ExtensionName
	Revision uint8
}

const SizeOfXTGetRevision = 30

type XTEntryTarget struct {
	_          structs.HostLayout
	TargetSize uint16
	Name       ExtensionName
	Revision   uint8
}

const SizeOfXTEntryTarget = 32

type KernelXTEntryTarget struct {
	_ structs.HostLayout
	XTEntryTarget
	Data []byte `hostlayout:"ignore"`
}

type XTStandardTarget struct {
	_      structs.HostLayout
	Target XTEntryTarget
	Verdict int32
	_       [4]byte
}

const SizeOfXTStandardTarget = 40

type XTErrorTarget struct {
	_      structs.HostLayout
	Target XTEntryTarget
	Name   ErrorName
	_      [2]byte
}

const SizeOfXTErrorTarget = 64

const (
	NF_NAT_RANGE_MAP_IPS            = 1 << 0
	NF_NAT_RANGE_PROTO_SPECIFIED    = 1 << 1
	NF_NAT_RANGE_PROTO_RANDOM       = 1 << 2
	NF_NAT_RANGE_PERSISTENT         = 1 << 3
	NF_NAT_RANGE_PROTO_RANDOM_FULLY = 1 << 4
	NF_NAT_RANGE_PROTO_RANDOM_ALL   = (NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY)
	NF_NAT_RANGE_MASK               = (NF_NAT_RANGE_MAP_IPS |
		NF_NAT_RANGE_PROTO_SPECIFIED | NF_NAT_RANGE_PROTO_RANDOM |
		NF_NAT_RANGE_PERSISTENT | NF_NAT_RANGE_PROTO_RANDOM_FULLY)
)

type NfNATIPV4Range struct {
	_       structs.HostLayout
	Flags   uint32
	MinIP   [4]byte
	MaxIP   [4]byte
	MinPort uint16
	MaxPort uint16
}

type NfNATIPV4MultiRangeCompat struct {
	_         structs.HostLayout
	RangeSize uint32
	RangeIPV4 NfNATIPV4Range
}

type XTRedirectTarget struct {
	_       structs.HostLayout
	Target  XTEntryTarget
	NfRange NfNATIPV4MultiRangeCompat
	_       [4]byte
}

const SizeOfXTRedirectTarget = 56

type XTNATTargetV0 struct {
	_       structs.HostLayout
	Target  XTEntryTarget
	NfRange NfNATIPV4MultiRangeCompat
	_       [4]byte
}

const SizeOfXTNATTargetV0 = 56

type XTNATTargetV1 struct {
	_      structs.HostLayout
	Target XTEntryTarget
	Range  NFNATRange
}

const SizeOfXTNATTargetV1 = SizeOfXTEntryTarget + SizeOfNFNATRange

type XTNATTargetV2 struct {
	_      structs.HostLayout
	Target XTEntryTarget
	Range  NFNATRange2
}

const SizeOfXTNATTargetV2 = SizeOfXTEntryTarget + SizeOfNFNATRange2

type XTCTTargetInfoV0 struct {
	_         structs.HostLayout
	Target    XTEntryTarget
	Flags     uint16
	Zone      uint16
	CTEvents  uint32
	ExpEvents uint32
	Helper    [16]byte
	_         [4]byte
	_         [8]byte
}

const SizeOfXTCTTargetInfoV0 = 72

type IPTGetinfo struct {
	_          structs.HostLayout
	Name       TableName
	ValidHooks uint32
	HookEntry  [NF_INET_NUMHOOKS]uint32
	Underflow  [NF_INET_NUMHOOKS]uint32
	NumEntries uint32
	Size       uint32
}

const SizeOfIPTGetinfo = 84

type IPTGetEntries struct {
	_    structs.HostLayout
	Name TableName
	Size uint32
	_    [4]byte
}

const SizeOfIPTGetEntries = 40

type KernelIPTGetEntries struct {
	_ structs.HostLayout
	IPTGetEntries
	Entrytable []KernelIPTEntry `hostlayout:"ignore"`
}

func (ke *KernelIPTGetEntries) SizeBytes() int {
	res := ke.IPTGetEntries.SizeBytes()
	for _, entry := range ke.Entrytable {
		res += entry.SizeBytes()
	}
	return res
}

func (ke *KernelIPTGetEntries) MarshalBytes(dst []byte) []byte {
	dst = ke.IPTGetEntries.MarshalUnsafe(dst)
	for i := range ke.Entrytable {
		dst = ke.Entrytable[i].MarshalBytes(dst)
	}
	return dst
}

func (ke *KernelIPTGetEntries) UnmarshalBytes(src []byte) []byte {
	src = ke.IPTGetEntries.UnmarshalUnsafe(src)
	for i := range ke.Entrytable {
		src = ke.Entrytable[i].UnmarshalBytes(src)
	}
	return src
}

var _ marshal.Marshallable = (*KernelIPTGetEntries)(nil)

type IPTReplace struct {
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

const SizeOfIPTReplace = 96

type ExtensionName [XT_EXTENSION_MAXNAMELEN]byte

func (en ExtensionName) String() string {
	return goString(en[:])
}

type TableName [XT_TABLE_MAXNAMELEN]byte

func (tn TableName) String() string {
	return goString(tn[:])
}

type ErrorName [XT_FUNCTION_MAXNAMELEN]byte

func (en ErrorName) String() string {
	return goString(en[:])
}

func goString(cstring []byte) string {
	for i, c := range cstring {
		if c == 0 {
			return string(cstring[:i])
		}
	}
	return string(cstring)
}

type XTTCP struct {
	_ structs.HostLayout
	SourcePortStart uint16

	SourcePortEnd uint16

	DestinationPortStart uint16

	DestinationPortEnd uint16

	Option uint8

	FlagMask uint8

	FlagCompare uint8

	InverseFlags uint8
}

const SizeOfXTTCP = 12

const (
	XT_TCP_INV_SRCPT = 0x01
	XT_TCP_INV_DSTPT = 0x02
	XT_TCP_INV_FLAGS = 0x04
	XT_TCP_INV_OPTION = 0x08
	XT_TCP_INV_MASK = 0x0F
)

type XTUDP struct {
	_ structs.HostLayout
	SourcePortStart uint16

	SourcePortEnd uint16

	DestinationPortStart uint16

	DestinationPortEnd uint16

	InverseFlags uint8

	_ uint8
}

const SizeOfXTUDP = 10

const (
	XT_UDP_INV_SRCPT = 0x01
	XT_UDP_INV_DSTPT = 0x02
	XT_UDP_INV_MASK = 0x03
)

type IPTOwnerInfo struct {
	_ structs.HostLayout
	UID uint32

	GID uint32

	PID uint32

	SID uint32

	Comm [16]byte

	Match uint8

	Invert uint8 `marshal:"unaligned"`
}

const SizeOfIPTOwnerInfo = 34

type XTOwnerMatchInfo struct {
	_      structs.HostLayout
	UIDMin uint32
	UIDMax uint32
	GIDMin uint32
	GIDMax uint32
	Match  uint8
	Invert uint8
	_      [2]byte
}

const SizeOfXTOwnerMatchInfo = 20

const (
	XT_OWNER_UID = 1 << 0
	XT_OWNER_GID = 1 << 1
	XT_OWNER_SOCKET = 1 << 2
)

const XT_MULTI_PORTS = 15

const (
	XT_MULTIPORT_SOURCE      uint8 = 0x0
	XT_MULTIPORT_DESTINATION uint8 = 0x1
	XT_MULTIPORT_EITHER      uint8 = 0x2
)

type XTMultiport struct {
	_ structs.HostLayout
	Flags uint8

	Count uint8

	Ports [XT_MULTI_PORTS]uint16
}

type XTMultiportV1 struct {
	_ structs.HostLayout
	Flags uint8
	Count uint8
	Ports [XT_MULTI_PORTS]uint16

	Pflags [XT_MULTI_PORTS]uint8

	Invert uint8
}

const SizeOfXTMultiport = 2 + (XT_MULTI_PORTS * 2)

const SizeOfXTMultiportV1 = SizeOfXTMultiport + XT_MULTI_PORTS + 1

type XTMarkMtinfo1 struct {
	_      structs.HostLayout
	Mark   uint32
	Mask   uint32
	Invert uint8
	_      [3]byte
}

const SizeOfXTMarkMtinfo1 = 12

const (
	IPT_ICMP_NET_UNREACHABLE = iota
	IPT_ICMP_HOST_UNREACHABLE
	IPT_ICMP_PROT_UNREACHABLE
	IPT_ICMP_PORT_UNREACHABLE
	IPT_ICMP_ECHOREPLY
	IPT_ICMP_NET_PROHIBITED
	IPT_ICMP_HOST_PROHIBITED
	IPT_TCP_RESET
	IPT_ICMP_ADMIN_PROHIBITED
)

const (
	IP6T_ICMP6_NO_ROUTE = iota
	IP6T_ICMP6_ADM_PROHIBITED
	IP6T_ICMP6_NOT_NEIGHBOUR
	IP6T_ICMP6_ADDR_UNREACH
	IP6T_ICMP6_PORT_UNREACH
	IP6T_ICMP6_ECHOREPLY
	IP6T_TCP_RESET
	IP6T_ICMP6_POLICY_FAIL
	IP6T_ICMP6_REJECT_ROUTE
)

type IPTRejectInfo struct {
	_    structs.HostLayout
	With uint32
}

const SizeOfIPTRejectInfo = 4

type IP6TRejectInfo struct {
	_    structs.HostLayout
	With uint32
}

const SizeOfIP6TRejectInfo = 4

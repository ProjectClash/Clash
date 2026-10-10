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
	NETLINK_ROUTE          = 0
	NETLINK_UNUSED         = 1
	NETLINK_USERSOCK       = 2
	NETLINK_FIREWALL       = 3
	NETLINK_SOCK_DIAG      = 4
	NETLINK_NFLOG          = 5
	NETLINK_XFRM           = 6
	NETLINK_SELINUX        = 7
	NETLINK_ISCSI          = 8
	NETLINK_AUDIT          = 9
	NETLINK_FIB_LOOKUP     = 10
	NETLINK_CONNECTOR      = 11
	NETLINK_NETFILTER      = 12
	NETLINK_IP6_FW         = 13
	NETLINK_DNRTMSG        = 14
	NETLINK_KOBJECT_UEVENT = 15
	NETLINK_GENERIC        = 16
	NETLINK_SCSITRANSPORT  = 18
	NETLINK_ECRYPTFS       = 19
	NETLINK_RDMA           = 20
	NETLINK_CRYPTO         = 21
)

type SockAddrNetlink struct {
	_      structs.HostLayout
	Family uint16
	_      uint16
	PortID uint32
	Groups uint32
}

const SockAddrNetlinkSize = 12

type NetlinkMessageHeader struct {
	_      structs.HostLayout
	Length uint32
	Type   uint16
	Flags  uint16
	Seq    uint32
	PortID uint32
}

const NetlinkMessageHeaderSize = 16

const (
	NLM_F_REQUEST   = 0x1
	NLM_F_MULTI     = 0x2
	NLM_F_ACK       = 0x4
	NLM_F_ECHO      = 0x8
	NLM_F_DUMP_INTR = 0x10
)

const (
	NLM_F_ROOT   = 0x100
	NLM_F_MATCH  = 0x200
	NLM_F_ATOMIC = 0x400
	NLM_F_DUMP   = NLM_F_ROOT | NLM_F_MATCH
)

const (
	NLM_F_REPLACE = 0x100
	NLM_F_EXCL    = 0x200
	NLM_F_CREATE  = 0x400
	NLM_F_APPEND  = 0x800
)

const (
	NLM_F_NONREC = 0x100
	NLM_F_BULK   = 0x200
)

const (
	NLMSG_NOOP    = 0x1
	NLMSG_ERROR   = 0x2
	NLMSG_DONE    = 0x3
	NLMSG_OVERRUN = 0x4

	NLMSG_MIN_TYPE = 0x10
)

const NLMSG_ALIGNTO = 4

type NetlinkAttrHeader struct {
	_      structs.HostLayout
	Length uint16
	Type   uint16
}

const (
	NLA_F_NESTED        uint16 = 1 << 15
	NLA_F_NET_BYTEORDER        = 1 << 14
	NLA_TYPE_MASK              = ^(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
)

const NetlinkAttrHeaderSize = 4

const NLA_ALIGNTO = 4

const (
	NLA_UNSPEC = iota
	NLA_U8
	NLA_U16
	NLA_U32
	NLA_U64
	NLA_STRING
	NLA_FLAG
	NLA_MSECS
	NLA_NESTED
	NLA_NESTED_ARRAY
	NLA_NUL_STRING
	NLA_BINARY
	NLA_S8
	NLA_S16
	NLA_S32
	NLA_S64
	NLA_BITFIELD32
	NLA_REJECT
	NLA_BE16
	NLA_BE32
	__NLA_TYPE_MAX
	NLA_TYPE_MAX = __NLA_TYPE_MAX - 1
)

const (
	NETLINK_ADD_MEMBERSHIP   = 1
	NETLINK_DROP_MEMBERSHIP  = 2
	NETLINK_PKTINFO          = 3
	NETLINK_BROADCAST_ERROR  = 4
	NETLINK_NO_ENOBUFS       = 5
	NETLINK_LISTEN_ALL_NSID  = 8
	NETLINK_LIST_MEMBERSHIPS = 9
	NETLINK_CAP_ACK          = 10
	NETLINK_EXT_ACK          = 11
	NETLINK_DUMP_STRICT_CHK  = 12
)

type NetlinkErrorMessage struct {
	_      structs.HostLayout
	Error  int32
	Header NetlinkMessageHeader
}

const (
	RTNLGRP_LINK = 1
)

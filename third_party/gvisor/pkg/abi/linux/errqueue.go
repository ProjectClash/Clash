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

	"github.com/metacubex/gvisor/pkg/marshal"
)

const (
	SO_EE_ORIGIN_NONE  = 0
	SO_EE_ORIGIN_LOCAL = 1
	SO_EE_ORIGIN_ICMP  = 2
	SO_EE_ORIGIN_ICMP6 = 3
)

type SockExtendedErr struct {
	_      structs.HostLayout
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}

type SockErrCMsg interface {
	marshal.Marshallable

	CMsgLevel() uint32
	CMsgType() uint32
}

type SockErrCMsgIPv4 struct {
	_ structs.HostLayout
	SockExtendedErr
	Offender SockAddrInet
}

var _ SockErrCMsg = (*SockErrCMsgIPv4)(nil)

func (*SockErrCMsgIPv4) CMsgLevel() uint32 {
	return SOL_IP
}

func (*SockErrCMsgIPv4) CMsgType() uint32 {
	return IP_RECVERR
}

type SockErrCMsgIPv6 struct {
	_ structs.HostLayout
	SockExtendedErr
	Offender SockAddrInet6
}

var _ SockErrCMsg = (*SockErrCMsgIPv6)(nil)

func (*SockErrCMsgIPv6) CMsgLevel() uint32 {
	return SOL_IPV6
}

func (*SockErrCMsgIPv6) CMsgType() uint32 {
	return IPV6_RECVERR
}

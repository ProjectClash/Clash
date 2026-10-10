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

package header

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
)

type IGMP []byte

var _ Transport = (*IGMP)(nil)

const (
	IGMPMinimumSize = 8

	IGMPQueryMinimumSize = 8

	IGMPReportMinimumSize = 8

	IGMPLeaveMessageMinimumSize = 8

	IGMPTTL = 1

	igmpTypeOffset = 0

	igmpMaxRespTimeOffset = 1

	igmpChecksumOffset = 2

	igmpGroupAddressOffset = 4

	IGMPProtocolNumber tcpip.TransportProtocolNumber = 2
)

type IGMPType byte

const (
	IGMPMembershipQuery IGMPType = 0x11
	IGMPv1MembershipReport IGMPType = 0x12
	IGMPv2MembershipReport IGMPType = 0x16
	IGMPLeaveGroup IGMPType = 0x17
	IGMPv3MembershipReport IGMPType = 0x22
)

func (b IGMP) Type() IGMPType { return IGMPType(b[igmpTypeOffset]) }

func (b IGMP) SetType(t IGMPType) { b[igmpTypeOffset] = byte(t) }

func (b IGMP) MaxRespTime() time.Duration {
	return DecisecondToDuration(uint16(b[igmpMaxRespTimeOffset]))
}

func (b IGMP) SetMaxRespTime(m byte) { b[igmpMaxRespTimeOffset] = m }

func (b IGMP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[igmpChecksumOffset:])
}

func (b IGMP) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[igmpChecksumOffset:], checksum)
}

func (b IGMP) GroupAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(b[igmpGroupAddressOffset:][:IPv4AddressSize]))
}

func (b IGMP) SetGroupAddress(address tcpip.Address) {
	addrBytes := address.As4()
	if n := copy(b[igmpGroupAddressOffset:], addrBytes[:]); n != IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d", n, IPv4AddressSize))
	}
}

func (IGMP) SourcePort() uint16 {
	return 0
}

func (IGMP) DestinationPort() uint16 {
	return 0
}

func (IGMP) SetSourcePort(uint16) {
}

func (IGMP) SetDestinationPort(uint16) {
}

func (IGMP) Payload() []byte {
	return nil
}

func IGMPCalculateChecksum(h IGMP) uint16 {
	existingXsum := h.Checksum()
	h.SetChecksum(0)
	xsum := ^checksum.Checksum(h, 0)
	h.SetChecksum(existingXsum)
	return xsum
}

func DecisecondToDuration(ds uint16) time.Duration {
	return time.Duration(ds) * time.Second / 10
}

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

package header

import (
	"encoding/binary"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	ARPProtocolNumber tcpip.NetworkProtocolNumber = 0x0806

	ARPSize = 28
)

type ARPHardwareType uint16

const (
	ARPHardwareNone ARPHardwareType = 0
	ARPHardwareEther    ARPHardwareType = 1
	ARPHardwareLoopback ARPHardwareType = 2
)

type ARPOp uint16

const (
	ARPRequest ARPOp = 1
	ARPReply   ARPOp = 2
)

type ARP []byte

const (
	hTypeOffset                 = 0
	protocolOffset              = 2
	haAddressSizeOffset         = 4
	protoAddressSizeOffset      = 5
	opCodeOffset                = 6
	senderHAAddressOffset       = 8
	senderProtocolAddressOffset = senderHAAddressOffset + EthernetAddressSize
	targetHAAddressOffset       = senderProtocolAddressOffset + IPv4AddressSize
	targetProtocolAddressOffset = targetHAAddressOffset + EthernetAddressSize
)

func (a ARP) hardwareAddressType() ARPHardwareType {
	return ARPHardwareType(binary.BigEndian.Uint16(a[hTypeOffset:]))
}

func (a ARP) protocolAddressSpace() uint16 { return binary.BigEndian.Uint16(a[protocolOffset:]) }
func (a ARP) hardwareAddressSize() int     { return int(a[haAddressSizeOffset]) }
func (a ARP) protocolAddressSize() int     { return int(a[protoAddressSizeOffset]) }

func (a ARP) Op() ARPOp { return ARPOp(binary.BigEndian.Uint16(a[opCodeOffset:])) }

func (a ARP) SetOp(op ARPOp) {
	binary.BigEndian.PutUint16(a[opCodeOffset:], uint16(op))
}

func (a ARP) SetIPv4OverEthernet() {
	binary.BigEndian.PutUint16(a[hTypeOffset:], uint16(ARPHardwareEther))
	binary.BigEndian.PutUint16(a[protocolOffset:], uint16(IPv4ProtocolNumber))
	a[haAddressSizeOffset] = EthernetAddressSize
	a[protoAddressSizeOffset] = uint8(IPv4AddressSize)
}

func (a ARP) HardwareAddressSender() []byte {
	return a[senderHAAddressOffset : senderHAAddressOffset+EthernetAddressSize]
}

func (a ARP) ProtocolAddressSender() []byte {
	return a[senderProtocolAddressOffset : senderProtocolAddressOffset+IPv4AddressSize]
}

func (a ARP) HardwareAddressTarget() []byte {
	return a[targetHAAddressOffset : targetHAAddressOffset+EthernetAddressSize]
}

func (a ARP) ProtocolAddressTarget() []byte {
	return a[targetProtocolAddressOffset : targetProtocolAddressOffset+IPv4AddressSize]
}

func (a ARP) IsValid() bool {
	if len(a) < ARPSize {
		return false
	}
	return a.hardwareAddressType() == ARPHardwareEther &&
		a.protocolAddressSpace() == uint16(IPv4ProtocolNumber) &&
		a.hardwareAddressSize() == EthernetAddressSize &&
		a.protocolAddressSize() == IPv4AddressSize
}

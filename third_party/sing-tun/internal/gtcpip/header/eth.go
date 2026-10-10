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

	"github.com/metacubex/sing-tun/internal/gtcpip"
)

const (
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

type EthernetFields struct {
	SrcAddr tcpip.LinkAddress

	DstAddr tcpip.LinkAddress

	Type tcpip.NetworkProtocolNumber
}

type Ethernet []byte

const (
	EthernetMinimumSize = 14

	EthernetMaximumSize = 18

	EthernetAddressSize = 6

	UnspecifiedEthernetAddress = tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00")

	EthernetBroadcastAddress = tcpip.LinkAddress("\xff\xff\xff\xff\xff\xff")

	unicastMulticastFlagMask = 1

	unicastMulticastFlagByteIdx = 0
)

const (
	EthernetProtocolAll tcpip.NetworkProtocolNumber = 0x0003

	EthernetProtocolPUP tcpip.NetworkProtocolNumber = 0x0200
)

var Ethertypes = []tcpip.NetworkProtocolNumber{
	EthernetProtocolAll,
	EthernetProtocolPUP,
}

func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

func (b Ethernet) Encode(e *EthernetFields) {
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)
}

func IsMulticastEthernetAddress(addr tcpip.LinkAddress) bool {
	if len(addr) != EthernetAddressSize {
		return false
	}

	return addr[unicastMulticastFlagByteIdx]&unicastMulticastFlagMask != 0
}

func IsValidUnicastEthernetAddress(addr tcpip.LinkAddress) bool {
	if len(addr) != EthernetAddressSize {
		return false
	}

	if addr == UnspecifiedEthernetAddress {
		return false
	}

	if addr[unicastMulticastFlagByteIdx]&unicastMulticastFlagMask != 0 {
		return false
	}

	return true
}

func EthernetAddressFromMulticastIPv4Address(addr tcpip.Address) tcpip.LinkAddress {
	var linkAddrBytes [EthernetAddressSize]byte
	addrBytes := addr.As4()
	linkAddrBytes[0] = 0x1
	linkAddrBytes[2] = 0x5e
	linkAddrBytes[3] = addrBytes[1] & 0x7F
	copy(linkAddrBytes[4:], addrBytes[IPv4AddressSize-2:])
	return tcpip.LinkAddress(linkAddrBytes[:])
}

func EthernetAddressFromMulticastIPv6Address(addr tcpip.Address) tcpip.LinkAddress {
	addrBytes := addr.As16()
	linkAddrBytes := []byte(addrBytes[IPv6AddressSize-EthernetAddressSize:])
	linkAddrBytes[0] = 0x33
	linkAddrBytes[1] = 0x33
	return tcpip.LinkAddress(linkAddrBytes[:])
}

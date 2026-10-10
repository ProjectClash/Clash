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
	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	MaxIPPacketSize = 0xffff + 2*IPv6MinimumSize
)

type Transport interface {
	SourcePort() uint16

	DestinationPort() uint16

	Checksum() uint16

	SetSourcePort(uint16)

	SetDestinationPort(uint16)

	SetChecksum(uint16)

	Payload() []byte
}

type ChecksummableTransport interface {
	Transport

	SetSourcePortWithChecksumUpdate(port uint16)

	SetDestinationPortWithChecksumUpdate(port uint16)

	UpdateChecksumPseudoHeaderAddress(old, new tcpip.Address, fullChecksum bool)
}

type Network interface {
	SourceAddress() tcpip.Address

	DestinationAddress() tcpip.Address

	Checksum() uint16

	SetSourceAddress(tcpip.Address)

	SetDestinationAddress(tcpip.Address)

	SetChecksum(uint16)

	TransportProtocol() tcpip.TransportProtocolNumber

	Payload() []byte

	TOS() (uint8, uint32)

	SetTOS(t uint8, l uint32)
}

type ChecksummableNetwork interface {
	Network

	SetSourceAddressWithChecksumUpdate(tcpip.Address)

	SetDestinationAddressWithChecksumUpdate(tcpip.Address)
}

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
	nextHdrFrag = 0
	fragOff     = 2
	more        = 3
	idV6        = 4
)

var _ IPv6SerializableExtHdr = (*IPv6SerializableFragmentExtHdr)(nil)

type IPv6SerializableFragmentExtHdr struct {
	FragmentOffset uint16

	M bool

	Identification uint32
}

func (h *IPv6SerializableFragmentExtHdr) identifier() IPv6ExtensionHeaderIdentifier {
	return IPv6FragmentHeader
}

func (h *IPv6SerializableFragmentExtHdr) length() int {
	return IPv6FragmentHeaderSize
}

func (h *IPv6SerializableFragmentExtHdr) serializeInto(nextHeader uint8, b []byte) int {
	_ = b[IPv6FragmentHeaderSize:]
	binary.BigEndian.PutUint32(b[idV6:], h.Identification)
	binary.BigEndian.PutUint16(b[fragOff:], h.FragmentOffset<<ipv6FragmentExtHdrFragmentOffsetShift)
	b[nextHdrFrag] = nextHeader
	if h.M {
		b[more] |= ipv6FragmentExtHdrMFlagMask
	}
	return IPv6FragmentHeaderSize
}

type IPv6Fragment []byte

const (
	IPv6FragmentHeader = 44

	IPv6FragmentHeaderSize = 8
)

func (b IPv6Fragment) IsValid() bool {
	return len(b) >= IPv6FragmentHeaderSize
}

func (b IPv6Fragment) NextHeader() uint8 {
	return b[nextHdrFrag]
}

func (b IPv6Fragment) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[fragOff:]) >> 3
}

func (b IPv6Fragment) More() bool {
	return b[more]&1 > 0
}

func (b IPv6Fragment) Payload() []byte {
	return b[IPv6FragmentHeaderSize:]
}

func (b IPv6Fragment) ID() uint32 {
	return binary.BigEndian.Uint32(b[idV6:])
}

func (b IPv6Fragment) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}


func (b IPv6Fragment) Checksum() uint16 {
	panic("not supported")
}

func (b IPv6Fragment) SourceAddress() tcpip.Address {
	panic("not supported")
}

func (b IPv6Fragment) DestinationAddress() tcpip.Address {
	panic("not supported")
}

func (b IPv6Fragment) SetSourceAddress(tcpip.Address) {
	panic("not supported")
}

func (b IPv6Fragment) SetDestinationAddress(tcpip.Address) {
	panic("not supported")
}

func (b IPv6Fragment) SetChecksum(uint16) {
	panic("not supported")
}

func (b IPv6Fragment) TOS() (uint8, uint32) {
	panic("not supported")
}

func (b IPv6Fragment) SetTOS(t uint8, l uint32) {
	panic("not supported")
}

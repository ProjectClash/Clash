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
	"math"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
)

const (
	udpSrcPort  = 0
	udpDstPort  = 2
	udpLength   = 4
	udpChecksum = 6
)

const (
	UDPMaximumPacketSize = 0xffff
)

type UDPFields struct {
	SrcPort uint16

	DstPort uint16

	Length uint16

	Checksum uint16
}

type UDP []byte

const (
	UDPMinimumSize = 8

	UDPMaximumSize = math.MaxUint16

	UDPProtocolNumber tcpip.TransportProtocolNumber = 17
)

func (b UDP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[udpSrcPort:])
}

func (b UDP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[udpDstPort:])
}

func (b UDP) Length() uint16 {
	return binary.BigEndian.Uint16(b[udpLength:])
}

func (b UDP) Payload() []byte {
	return b[UDPMinimumSize:]
}

func (b UDP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[udpChecksum:])
}

func (b UDP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[udpSrcPort:], port)
}

func (b UDP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[udpDstPort:], port)
}

func (b UDP) SetChecksum(xsum uint16) {
	checksum.Put(b[udpChecksum:], xsum)
}

func (b UDP) SetLength(length uint16) {
	binary.BigEndian.PutUint16(b[udpLength:], length)
}

func (b UDP) CalculateChecksum(partialChecksum uint16) uint16 {
	xsum := checksum.Checksum(b[:udpChecksum], partialChecksum)
	xsum = checksum.Checksum(b[udpChecksum+2:UDPMinimumSize], xsum)
	return xsum
}

func (b UDP) IsChecksumValid(src, dst tcpip.Address, payloadChecksum uint16) bool {
	xsum := PseudoHeaderChecksum(UDPProtocolNumber, dst.AsSlice(), src.AsSlice(), b.Length())
	xsum = checksum.Combine(xsum, payloadChecksum)
	return checksum.Checksum(b[:UDPMinimumSize], xsum) == 0xffff
}

func (b UDP) Encode(u *UDPFields) {
	b.SetSourcePort(u.SrcPort)
	b.SetDestinationPort(u.DstPort)
	b.SetLength(u.Length)
	b.SetChecksum(u.Checksum)
}

func (b UDP) SetSourcePortWithChecksumUpdate(new uint16) {
	old := b.SourcePort()
	b.SetSourcePort(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

func (b UDP) SetDestinationPortWithChecksumUpdate(new uint16) {
	old := b.DestinationPort()
	b.SetDestinationPort(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

func (b UDP) UpdateChecksumPseudoHeaderAddress(old, new tcpip.Address, fullChecksum bool) {
	xsum := b.Checksum()
	if fullChecksum {
		xsum = ^xsum
	}

	xsum = checksumUpdate2ByteAlignedAddress(xsum, old, new)
	if fullChecksum {
		xsum = ^xsum
	}

	b.SetChecksum(xsum)
}

func UDPValid(hdr UDP, payloadChecksum func() uint16, payloadSize uint16, netProto tcpip.NetworkProtocolNumber, srcAddr, dstAddr tcpip.Address, skipChecksumValidation bool) (lengthValid, csumValid bool) {
	if length := hdr.Length(); length > payloadSize+UDPMinimumSize || length < UDPMinimumSize {
		return false, false
	}

	if skipChecksumValidation {
		return true, true
	}

	if netProto == IPv4ProtocolNumber && hdr.Checksum() == 0 {
		return true, true
	}

	return true, hdr.IsChecksumValid(srcAddr, dstAddr, payloadChecksum())
}

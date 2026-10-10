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
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
)

type ICMPv4 []byte

const (
	ICMPv4PayloadOffset = 8

	ICMPv4MinimumSize = 8

	ICMPv4MinimumErrorPayloadSize = 8

	ICMPv4ProtocolNumber tcpip.TransportProtocolNumber = 1

	icmpv4ChecksumOffset = 2

	icmpv4MTUOffset = 6

	icmpv4IdentOffset = 4

	icmpv4PointerOffset = 4

	icmpv4SequenceOffset = 6
)

type ICMPv4Type byte

type ICMPv4Code byte

const (
	ICMPv4EchoReply      ICMPv4Type = 0
	ICMPv4DstUnreachable ICMPv4Type = 3
	ICMPv4SrcQuench      ICMPv4Type = 4
	ICMPv4Redirect       ICMPv4Type = 5
	ICMPv4Echo           ICMPv4Type = 8
	ICMPv4TimeExceeded   ICMPv4Type = 11
	ICMPv4ParamProblem   ICMPv4Type = 12
	ICMPv4Timestamp      ICMPv4Type = 13
	ICMPv4TimestampReply ICMPv4Type = 14
	ICMPv4InfoRequest    ICMPv4Type = 15
	ICMPv4InfoReply      ICMPv4Type = 16
)

const (
	ICMPv4TTLExceeded       ICMPv4Code = 0
	ICMPv4ReassemblyTimeout ICMPv4Code = 1
)

const (
	ICMPv4NetUnreachable            ICMPv4Code = 0
	ICMPv4HostUnreachable           ICMPv4Code = 1
	ICMPv4ProtoUnreachable          ICMPv4Code = 2
	ICMPv4PortUnreachable           ICMPv4Code = 3
	ICMPv4FragmentationNeeded       ICMPv4Code = 4
	ICMPv4SourceRouteFailed         ICMPv4Code = 5
	ICMPv4DestinationNetworkUnknown ICMPv4Code = 6
	ICMPv4DestinationHostUnknown    ICMPv4Code = 7
	ICMPv4SourceHostIsolated        ICMPv4Code = 8
	ICMPv4NetProhibited             ICMPv4Code = 9
	ICMPv4HostProhibited            ICMPv4Code = 10
	ICMPv4NetUnreachableForTos      ICMPv4Code = 11
	ICMPv4HostUnreachableForTos     ICMPv4Code = 12
	ICMPv4AdminProhibited           ICMPv4Code = 13
	ICMPv4HostPrecedenceViolation   ICMPv4Code = 14
	ICMPv4PrecedenceCutInEffect     ICMPv4Code = 15
)

const ICMPv4UnusedCode ICMPv4Code = 0

func (b ICMPv4) Type() ICMPv4Type { return ICMPv4Type(b[0]) }

func (b ICMPv4) SetType(t ICMPv4Type) { b[0] = byte(t) }

func (b ICMPv4) Code() ICMPv4Code { return ICMPv4Code(b[1]) }

func (b ICMPv4) SetCode(c ICMPv4Code) { b[1] = byte(c) }

func (b ICMPv4) Pointer() byte { return b[icmpv4PointerOffset] }

func (b ICMPv4) SetPointer(c byte) { b[icmpv4PointerOffset] = c }

func (b ICMPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4ChecksumOffset:])
}

func (b ICMPv4) SetChecksum(cs uint16) {
	checksum.Put(b[icmpv4ChecksumOffset:], cs)
}

func (ICMPv4) SourcePort() uint16 {
	return 0
}

func (ICMPv4) DestinationPort() uint16 {
	return 0
}

func (ICMPv4) SetSourcePort(uint16) {
}

func (ICMPv4) SetDestinationPort(uint16) {
}

func (b ICMPv4) Payload() []byte {
	return b[ICMPv4PayloadOffset:]
}

func (b ICMPv4) MTU() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4MTUOffset:])
}

func (b ICMPv4) SetMTU(mtu uint16) {
	binary.BigEndian.PutUint16(b[icmpv4MTUOffset:], mtu)
}

func (b ICMPv4) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4IdentOffset:])
}

func (b ICMPv4) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv4IdentOffset:], ident)
}

func (b ICMPv4) SetIdentWithChecksumUpdate(new uint16) {
	old := b.Ident()
	b.SetIdent(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

func (b ICMPv4) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4SequenceOffset:])
}

func (b ICMPv4) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv4SequenceOffset:], sequence)
}

func ICMPv4Checksum(h ICMPv4, payloadCsum uint16) uint16 {
	xsum := payloadCsum

	xsum = checksum.Checksum(h[:2], xsum)
	xsum = checksum.Checksum(h[4:], xsum)

	return ^xsum
}

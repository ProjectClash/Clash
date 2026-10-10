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
	"errors"
	"fmt"
	"math"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing/common"
)

type IPv6ExtensionHeaderIdentifier uint8

const (
	IPv6HopByHopOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 0

	IPv6RoutingExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 43

	IPv6FragmentExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 44

	IPv6DestinationOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 60

	IPv6NoNextHeaderIdentifier IPv6ExtensionHeaderIdentifier = 59

	IPv6UnknownExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 254
)

const (
	ipv6UnknownExtHdrOptionActionMask = 192

	ipv6UnknownExtHdrOptionActionShift = 6

	ipv6RoutingExtHdrSegmentsLeftIdx = 1

	IPv6FragmentExtHdrLength = 8

	ipv6FragmentExtHdrFragmentOffsetOffset = 0

	ipv6FragmentExtHdrFragmentOffsetShift = 3

	ipv6FragmentExtHdrFlagsIdx = 1

	ipv6FragmentExtHdrMFlagMask = 1

	ipv6FragmentExtHdrIdentificationOffset = 2

	ipv6ExtHdrLenBytesPerUnit = 8

	ipv6ExtHdrLenBytesExcluded = 6

	IPv6FragmentExtHdrFragmentOffsetBytesPerUnit = 8
)

func padIPv6OptionsLength(length int) int {
	return (length + ipv6ExtHdrLenBytesPerUnit - 1) & ^(ipv6ExtHdrLenBytesPerUnit - 1)
}

func padIPv6Option(b []byte) {
	switch len(b) {
	case 0:
	case 1:
		b[ipv6ExtHdrOptionTypeOffset] = uint8(ipv6Pad1ExtHdrOptionIdentifier)
	default:
		s := b[ipv6ExtHdrOptionPayloadOffset:]
		common.ClearArray(s)
		b[ipv6ExtHdrOptionTypeOffset] = uint8(ipv6PadNExtHdrOptionIdentifier)
		b[ipv6ExtHdrOptionLengthOffset] = uint8(len(s))
	}
}

func ipv6OptionsAlignmentPadding(headerOffset int, align int, alignOffset int) int {
	padLen := headerOffset - alignOffset
	return ((padLen + align - 1) & ^(align - 1)) - padLen
}

type IPv6OptionUnknownAction int

const (
	IPv6OptionUnknownActionSkip IPv6OptionUnknownAction = 0

	IPv6OptionUnknownActionDiscard IPv6OptionUnknownAction = 1

	IPv6OptionUnknownActionDiscardSendICMP IPv6OptionUnknownAction = 2

	IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest IPv6OptionUnknownAction = 3
)

type IPv6ExtHdrOption interface {
	UnknownAction() IPv6OptionUnknownAction

	isIPv6ExtHdrOption()
}

type IPv6ExtHdrOptionIdentifier uint8

const (
	ipv6Pad1ExtHdrOptionIdentifier IPv6ExtHdrOptionIdentifier = 0

	ipv6PadNExtHdrOptionIdentifier IPv6ExtHdrOptionIdentifier = 1

	ipv6RouterAlertHopByHopOptionIdentifier IPv6ExtHdrOptionIdentifier = 5

	ipv6ExtHdrOptionTypeOffset = 0

	ipv6ExtHdrOptionLengthOffset = 1

	ipv6ExtHdrOptionPayloadOffset = 2
)

func ipv6UnknownActionFromIdentifier(id IPv6ExtHdrOptionIdentifier) IPv6OptionUnknownAction {
	return IPv6OptionUnknownAction((id & ipv6UnknownExtHdrOptionActionMask) >> ipv6UnknownExtHdrOptionActionShift)
}

var ErrMalformedIPv6ExtHdrOption = errors.New("malformed IPv6 extension header option")

type IPv6FragmentExtHdr [6]byte

func (IPv6FragmentExtHdr) isIPv6PayloadHeader() {}

func (IPv6FragmentExtHdr) Release() {}

func (b IPv6FragmentExtHdr) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[ipv6FragmentExtHdrFragmentOffsetOffset:]) >> ipv6FragmentExtHdrFragmentOffsetShift
}

func (b IPv6FragmentExtHdr) More() bool {
	return b[ipv6FragmentExtHdrFlagsIdx]&ipv6FragmentExtHdrMFlagMask != 0
}

func (b IPv6FragmentExtHdr) ID() uint32 {
	return binary.BigEndian.Uint32(b[ipv6FragmentExtHdrIdentificationOffset:])
}

func (b IPv6FragmentExtHdr) IsAtomic() bool {
	return !b.More() && b.FragmentOffset() == 0
}

type IPv6SerializableExtHdr interface {
	identifier() IPv6ExtensionHeaderIdentifier

	length() int

	serializeInto(nextHeader uint8, b []byte) int
}

var _ IPv6SerializableExtHdr = (*IPv6SerializableHopByHopExtHdr)(nil)

type IPv6SerializableHopByHopExtHdr []IPv6SerializableHopByHopOption

const (
	ipv6HopByHopExtHdrNextHeaderOffset = 0

	ipv6HopByHopExtHdrLengthOffset = 1

	ipv6HopByHopExtHdrOptionsOffset = 2

	ipv6HopByHopExtHdrUnaccountedLenWords = 1
)

func (IPv6SerializableHopByHopExtHdr) identifier() IPv6ExtensionHeaderIdentifier {
	return IPv6HopByHopOptionsExtHdrIdentifier
}

func (h IPv6SerializableHopByHopExtHdr) length() int {
	var total int
	for _, opt := range h {
		align, alignOffset := opt.alignment()
		total += ipv6OptionsAlignmentPadding(total, align, alignOffset)
		total += ipv6ExtHdrOptionPayloadOffset + int(opt.length())
	}
	return padIPv6OptionsLength(ipv6HopByHopExtHdrOptionsOffset + total)
}

func (h IPv6SerializableHopByHopExtHdr) serializeInto(nextHeader uint8, b []byte) int {
	optBuffer := b[ipv6HopByHopExtHdrOptionsOffset:]
	totalLength := ipv6HopByHopExtHdrOptionsOffset
	for _, opt := range h {
		align, alignOffset := opt.alignment()
		padLen := ipv6OptionsAlignmentPadding(totalLength, align, alignOffset)
		if padLen != 0 {
			padIPv6Option(optBuffer[:padLen])
			totalLength += padLen
			optBuffer = optBuffer[padLen:]
		}

		l := opt.serializeInto(optBuffer[ipv6ExtHdrOptionPayloadOffset:])
		optBuffer[ipv6ExtHdrOptionTypeOffset] = uint8(opt.identifier())
		optBuffer[ipv6ExtHdrOptionLengthOffset] = l
		l += ipv6ExtHdrOptionPayloadOffset
		totalLength += int(l)
		optBuffer = optBuffer[l:]
	}
	padded := padIPv6OptionsLength(totalLength)
	if padded != totalLength {
		padIPv6Option(optBuffer[:padded-totalLength])
		totalLength = padded
	}
	wordsLen := totalLength/ipv6ExtHdrLenBytesPerUnit - ipv6HopByHopExtHdrUnaccountedLenWords
	if wordsLen > math.MaxUint8 {
		panic(fmt.Sprintf("IPv6 hop by hop options too large: %d+1 64-bit words", wordsLen))
	}
	b[ipv6HopByHopExtHdrNextHeaderOffset] = nextHeader
	b[ipv6HopByHopExtHdrLengthOffset] = uint8(wordsLen)
	return totalLength
}

type IPv6SerializableHopByHopOption interface {
	identifier() IPv6ExtHdrOptionIdentifier

	length() uint8

	alignment() (align int, offset int)

	serializeInto([]byte) uint8
}

var _ IPv6SerializableHopByHopOption = (*IPv6RouterAlertOption)(nil)

type IPv6RouterAlertOption struct {
	Value IPv6RouterAlertValue
}

type IPv6RouterAlertValue uint16

const (
	IPv6RouterAlertMLD IPv6RouterAlertValue = 0
	IPv6RouterAlertRSVP IPv6RouterAlertValue = 1
	IPv6RouterAlertActiveNetworks IPv6RouterAlertValue = 2

	ipv6RouterAlertPayloadLength = 2

	ipv6RouterAlertAlignmentRequirement = 2

	ipv6RouterAlertAlignmentOffsetRequirement = 0
)

func (*IPv6RouterAlertOption) UnknownAction() IPv6OptionUnknownAction {
	return ipv6UnknownActionFromIdentifier(ipv6RouterAlertHopByHopOptionIdentifier)
}

func (*IPv6RouterAlertOption) isIPv6ExtHdrOption() {}

func (*IPv6RouterAlertOption) identifier() IPv6ExtHdrOptionIdentifier {
	return ipv6RouterAlertHopByHopOptionIdentifier
}

func (*IPv6RouterAlertOption) length() uint8 {
	return ipv6RouterAlertPayloadLength
}

func (*IPv6RouterAlertOption) alignment() (int, int) {
	return ipv6RouterAlertAlignmentRequirement, ipv6RouterAlertAlignmentOffsetRequirement
}

func (o *IPv6RouterAlertOption) serializeInto(b []byte) uint8 {
	binary.BigEndian.PutUint16(b, uint16(o.Value))
	return ipv6RouterAlertPayloadLength
}

type IPv6ExtHdrSerializer []IPv6SerializableExtHdr

func (s IPv6ExtHdrSerializer) Serialize(transportProtocol tcpip.TransportProtocolNumber, b []byte) (uint8, int) {
	nextHeader := uint8(transportProtocol)
	if len(s) == 0 {
		return nextHeader, 0
	}
	var totalLength int
	for i, h := range s[:len(s)-1] {
		length := h.serializeInto(uint8(s[i+1].identifier()), b)
		b = b[length:]
		totalLength += length
	}
	totalLength += s[len(s)-1].serializeInto(nextHeader, b)
	return uint8(s[0].identifier()), totalLength
}

func (s IPv6ExtHdrSerializer) Length() int {
	var totalLength int
	for _, h := range s {
		totalLength += h.length()
	}
	return totalLength
}

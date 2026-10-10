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
	"io"
	"math"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/tcpip"
)

type IPv6ExtensionHeaderIdentifier uint8

const (
	IPv6HopByHopOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 0

	IPv6RoutingExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 43

	IPv6FragmentExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 44

	IPv6DestinationOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 60

	IPv6AuthenticationExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 51

	IPv6NoNextHeaderIdentifier IPv6ExtensionHeaderIdentifier = 59

	IPv6ExperimentExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 253

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

type IPv6PayloadHeader interface {
	isIPv6PayloadHeader()

	Release()
}

type IPv6RawPayloadHeader struct {
	Identifier IPv6ExtensionHeaderIdentifier
	Buf        buffer.Buffer
}

func (IPv6RawPayloadHeader) isIPv6PayloadHeader() {}

func (i IPv6RawPayloadHeader) Release() {
	i.Buf.Release()
}

type ipv6OptionsExtHdr struct {
	buf *buffer.View
}

func (i ipv6OptionsExtHdr) Release() {
	if i.buf != nil {
		i.buf.Release()
	}
}

func (i ipv6OptionsExtHdr) Iter() IPv6OptionsExtHdrOptionsIterator {
	it := IPv6OptionsExtHdrOptionsIterator{}
	it.reader = i.buf
	return it
}

type IPv6OptionsExtHdrOptionsIterator struct {
	reader *buffer.View

	optionOffset uint32

	nextOptionOffset uint32
}

func (i *IPv6OptionsExtHdrOptionsIterator) OptionOffset() uint32 {
	return i.optionOffset
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

type IPv6UnknownExtHdrOption struct {
	Identifier IPv6ExtHdrOptionIdentifier
	Data       *buffer.View
}

func (o *IPv6UnknownExtHdrOption) UnknownAction() IPv6OptionUnknownAction {
	return ipv6UnknownActionFromIdentifier(o.Identifier)
}

func (*IPv6UnknownExtHdrOption) isIPv6ExtHdrOption() {}

func (i *IPv6OptionsExtHdrOptionsIterator) Next() (IPv6ExtHdrOption, bool, error) {
	for {
		i.optionOffset = i.nextOptionOffset
		temp, err := i.reader.ReadByte()
		if err != nil {
			return nil, true, nil
		}
		id := IPv6ExtHdrOptionIdentifier(temp)

		if id == ipv6Pad1ExtHdrOptionIdentifier {
			i.nextOptionOffset = i.optionOffset + 1
			continue
		}

		length, err := i.reader.ReadByte()
		if err != nil {
			if err != io.EOF {
				panic(fmt.Sprintf("unexpected error when reading the option's Length field for option with id = %d: %s", id, err))
			}

			return nil, true, fmt.Errorf("error when reading the option's Length field for option with id = %d: %w", id, io.ErrUnexpectedEOF)
		}

		if n := i.reader.Size(); n < int(length) {
			i.reader.TrimFront(i.reader.Size())

			return nil, true, fmt.Errorf("read %d out of %d option data bytes for option with id = %d: %w", n, length, id, io.ErrUnexpectedEOF)
		}

		i.nextOptionOffset = i.optionOffset + uint32(length) + 1 + 1

		switch id {
		case ipv6PadNExtHdrOptionIdentifier:
			i.reader.TrimFront(int(length))
			continue
		case ipv6RouterAlertHopByHopOptionIdentifier:
			var routerAlertValue [ipv6RouterAlertPayloadLength]byte
			if n, err := io.ReadFull(i.reader, routerAlertValue[:]); err != nil {
				switch err {
				case io.EOF, io.ErrUnexpectedEOF:
					return nil, true, fmt.Errorf("got invalid length (%d) for router alert option (want = %d): %w", length, ipv6RouterAlertPayloadLength, ErrMalformedIPv6ExtHdrOption)
				default:
					return nil, true, fmt.Errorf("read %d out of %d option data bytes for router alert option: %w", n, ipv6RouterAlertPayloadLength, err)
				}
			} else if n != int(length) {
				return nil, true, fmt.Errorf("got invalid length (%d) for router alert option (want = %d): %w", length, ipv6RouterAlertPayloadLength, ErrMalformedIPv6ExtHdrOption)
			}
			return &IPv6RouterAlertOption{Value: IPv6RouterAlertValue(binary.BigEndian.Uint16(routerAlertValue[:]))}, false, nil
		default:
			bytes := buffer.NewView(int(length))
			if n, err := io.CopyN(bytes, i.reader, int64(length)); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}

				return nil, true, fmt.Errorf("read %d out of %d option data bytes for option with id = %d: %w", n, length, id, err)
			}
			return &IPv6UnknownExtHdrOption{Identifier: id, Data: bytes}, false, nil
		}
	}
}

type IPv6HopByHopOptionsExtHdr struct {
	ipv6OptionsExtHdr
}

func (IPv6HopByHopOptionsExtHdr) isIPv6PayloadHeader() {}

type IPv6DestinationOptionsExtHdr struct {
	ipv6OptionsExtHdr
}

func (IPv6DestinationOptionsExtHdr) isIPv6PayloadHeader() {}

type IPv6ExperimentExtHdr struct {
	Value uint16
}

func (IPv6ExperimentExtHdr) Release() {}

func (IPv6ExperimentExtHdr) isIPv6PayloadHeader() {}

type IPv6RoutingExtHdr struct {
	Buf *buffer.View
}

func (IPv6RoutingExtHdr) isIPv6PayloadHeader() {}

func (b IPv6RoutingExtHdr) Release() {
	b.Buf.Release()
}

func (b IPv6RoutingExtHdr) SegmentsLeft() uint8 {
	return b.Buf.AsSlice()[ipv6RoutingExtHdrSegmentsLeftIdx]
}

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

type IPv6PayloadIterator struct {
	nextHdrIdentifier IPv6ExtensionHeaderIdentifier

	payload buffer.Buffer

	forceRaw bool

	headerOffset uint32

	parseOffset uint32

	nextOffset uint32
}

func (i IPv6PayloadIterator) HeaderOffset() uint32 {
	return i.headerOffset
}

func (i IPv6PayloadIterator) ParseOffset() uint32 {
	return i.headerOffset + i.parseOffset
}

func MakeIPv6PayloadIterator(nextHdrIdentifier IPv6ExtensionHeaderIdentifier, payload buffer.Buffer) IPv6PayloadIterator {
	return IPv6PayloadIterator{
		nextHdrIdentifier: nextHdrIdentifier,
		payload:           payload,
		nextOffset:        IPv6FixedHeaderSize,
	}
}

func (i *IPv6PayloadIterator) Release() {
	i.payload.Release()
}

func (i *IPv6PayloadIterator) AsRawHeader(consume bool) IPv6RawPayloadHeader {
	identifier := i.nextHdrIdentifier

	var buf buffer.Buffer
	if consume {
		buf = i.payload

		*i = IPv6PayloadIterator{
			nextHdrIdentifier: IPv6NoNextHeaderIdentifier,
			headerOffset:      i.headerOffset,
			nextOffset:        i.nextOffset,
		}
	} else {
		buf = i.payload.Clone()
	}

	return IPv6RawPayloadHeader{Identifier: identifier, Buf: buf}
}

func (i *IPv6PayloadIterator) Next() (IPv6PayloadHeader, bool, error) {
	i.headerOffset = i.nextOffset
	i.parseOffset = 0
	if i.forceRaw {
		return i.AsRawHeader(true), false, nil
	}

	switch i.nextHdrIdentifier {
	case IPv6HopByHopOptionsExtHdrIdentifier:
		nextHdrIdentifier, view, err := i.nextHeaderData(false, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{view}}, false, nil
	case IPv6RoutingExtHdrIdentifier:
		nextHdrIdentifier, view, err := i.nextHeaderData(false, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6RoutingExtHdr{view}, false, nil
	case IPv6FragmentExtHdrIdentifier:
		var data [6]byte
		nextHdrIdentifier, _, err := i.nextHeaderData(true, data[:])
		if err != nil {
			return nil, true, err
		}

		fragmentExtHdr := IPv6FragmentExtHdr(data)

		if fragmentExtHdr.FragmentOffset() != 0 {
			i.forceRaw = true
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return fragmentExtHdr, false, nil
	case IPv6DestinationOptionsExtHdrIdentifier:
		nextHdrIdentifier, view, err := i.nextHeaderData(false, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr{view}}, false, nil
	case IPv6ExperimentExtHdrIdentifier:
		var data [IPv6ExperimentHdrLength - ipv6ExperimentHdrValueOffset]byte
		nextHdrIdentifier, _, err := i.nextHeaderData(true, data[:])
		if err != nil {
			return nil, true, err
		}
		i.nextHdrIdentifier = nextHdrIdentifier
		hdr := IPv6ExperimentExtHdr{
			Value: binary.BigEndian.Uint16(data[:ipv6ExperimentHdrTagLength]),
		}
		return hdr, false, nil
	case IPv6NoNextHeaderIdentifier:
		return nil, true, nil

	default:
		return i.AsRawHeader(true), false, nil
	}
}

func (i *IPv6PayloadIterator) NextHeaderIdentifier() IPv6ExtensionHeaderIdentifier {
	return i.nextHdrIdentifier
}

func (i *IPv6PayloadIterator) nextHeaderData(ignoreLength bool, bytes []byte) (IPv6ExtensionHeaderIdentifier, *buffer.View, error) {
	rdr := i.payload.AsBufferReader()
	nextHdrIdentifier, err := rdr.ReadByte()
	if err != nil {
		return 0, nil, fmt.Errorf("error when reading the Next Header field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
	}
	i.parseOffset++

	var length uint8
	length, err = rdr.ReadByte()

	if err != nil {
		if ignoreLength {
			return 0, nil, fmt.Errorf("error when reading the Length field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
		}

		return 0, nil, fmt.Errorf("error when reading the Reserved field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
	}
	if ignoreLength {
		length = 0
	}

	i.parseOffset++

	i.nextOffset += uint32((length + 1) * ipv6ExtHdrLenBytesPerUnit)

	bytesLen := int(length)*ipv6ExtHdrLenBytesPerUnit + ipv6ExtHdrLenBytesExcluded
	if ignoreLength {
		if n := len(bytes); n < bytesLen {
			panic(fmt.Sprintf("bytes only has space for %d bytes but need space for %d bytes (length = %d) for extension header with id = %d", n, bytesLen, length, i.nextHdrIdentifier))
		}
		if n, err := io.ReadFull(&rdr, bytes); err != nil {
			return 0, nil, fmt.Errorf("read %d out of %d extension header data bytes (length = %d) for header with id = %d: %w", n, bytesLen, length, i.nextHdrIdentifier, err)
		}
		return IPv6ExtensionHeaderIdentifier(nextHdrIdentifier), nil, nil
	}
	v := buffer.NewView(bytesLen)
	if n, err := io.CopyN(v, &rdr, int64(bytesLen)); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		v.Release()
		return 0, nil, fmt.Errorf("read %d out of %d extension header data bytes (length = %d) for header with id = %d: %w", n, bytesLen, length, i.nextHdrIdentifier, err)
	}
	return IPv6ExtensionHeaderIdentifier(nextHdrIdentifier), v, nil
}

type IPv6SerializableExtHdr interface {
	identifier() IPv6ExtensionHeaderIdentifier

	length() int

	serializeInto(nextHeader uint8, b []byte) int
}

const (
	IPv6ExperimentHdrLength        = 8
	ipv6ExperimentNextHeaderOffset = 0
	ipv6ExperimentLengthOffset     = 1
	ipv6ExperimentHdrValueOffset   = 2
	ipv6ExperimentHdrTagLength     = 2
)

var _ IPv6SerializableExtHdr = (*IPv6ExperimentExtHdr)(nil)

func (h IPv6ExperimentExtHdr) identifier() IPv6ExtensionHeaderIdentifier {
	return IPv6ExperimentExtHdrIdentifier
}

func (h IPv6ExperimentExtHdr) length() int {
	return IPv6ExperimentHdrLength
}

func (h IPv6ExperimentExtHdr) serializeInto(nextHeader uint8, b []byte) int {
	b[ipv6ExperimentNextHeaderOffset] = nextHeader
	b[ipv6ExperimentLengthOffset] = (IPv6ExperimentHdrLength / ipv6ExtHdrLenBytesPerUnit) - 1
	binary.BigEndian.PutUint16(b[ipv6ExperimentHdrValueOffset:][:ipv6ExperimentHdrTagLength], uint16(h.Value))
	return IPv6ExperimentHdrLength
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

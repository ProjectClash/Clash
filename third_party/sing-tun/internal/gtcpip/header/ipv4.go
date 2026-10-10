// Copyright 2021 The gVisor Authors.
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
	"net/netip"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing/common"
)

const (
	versIHL = 0
	tos     = 1
	IPv4TotalLenOffset = 2
	id                 = 4
	flagsFO            = 6
	ttl                = 8
	protocol           = 9
	xsum               = 10
	srcAddr            = 12
	dstAddr            = 16
	options            = 20
)

type IPv4Fields struct {
	TOS uint8

	TotalLength uint16

	ID uint16

	Flags uint8

	FragmentOffset uint16

	TTL uint8

	Protocol uint8

	Checksum uint16

	SrcAddr netip.Addr

	DstAddr netip.Addr

	Options IPv4OptionsSerializer
}

type IPv4 []byte

const (
	IPv4MinimumSize = 20

	IPv4MaximumHeaderSize = 60

	IPv4MaximumOptionsSize = IPv4MaximumHeaderSize - IPv4MinimumSize

	IPv4MaximumPayloadSize = 65536

	MinIPFragmentPayloadSize = 8

	IPv4AddressSize = 4

	IPv4AddressSizeBits = 32

	IPv4ProtocolNumber tcpip.NetworkProtocolNumber = 0x0800

	IPv4Version = 4

	IPv4MinimumProcessableDatagramSize = 576

	IPv4MinimumMTU = 68
)

var (
	IPv4AllSystems = tcpip.AddrFrom4([4]byte{0xe0, 0x00, 0x00, 0x01})

	IPv4Broadcast = tcpip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff})

	IPv4Any = tcpip.AddrFrom4([4]byte{0x00, 0x00, 0x00, 0x00})

	IPv4AllRoutersGroup = tcpip.AddrFrom4([4]byte{0xe0, 0x00, 0x00, 0x02})

	IPv4Loopback = tcpip.AddrFrom4([4]byte{0x7f, 0x00, 0x00, 0x01})
)

const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

var ipv4LinkLocalUnicastSubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0xa9, 0xfe, 0x00, 0x00}), tcpip.MaskFrom("\xff\xff\x00\x00"))
	if err != nil {
		panic(err)
	}
	return subnet
}()

var ipv4LinkLocalMulticastSubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0xe0, 0x00, 0x00, 0x00}), tcpip.MaskFrom("\xff\xff\xff\x00"))
	if err != nil {
		panic(err)
	}
	return subnet
}()

var IPv4EmptySubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv4Any, tcpip.MaskFrom("\x00\x00\x00\x00"))
	if err != nil {
		panic(err)
	}
	return subnet
}()

var IPv4CurrentNetworkSubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv4Any, tcpip.MaskFrom("\xff\x00\x00\x00"))
	if err != nil {
		panic(err)
	}
	return subnet
}()

var IPv4LoopbackSubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0x7f, 0x00, 0x00, 0x00}), tcpip.MaskFrom("\xff\x00\x00\x00"))
	if err != nil {
		panic(err)
	}
	return subnet
}()

func IPVersion(b []byte) int {
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> ipVersionShift)
}

const (
	ipVersionShift = 4
	ipIHLMask      = 0x0f
	IPv4IHLStride  = 4
)

func (b IPv4) HeaderLength() uint8 {
	return (b[versIHL] & ipIHLMask) * IPv4IHLStride
}

func (b IPv4) SetHeaderLength(hdrLen uint8) {
	if hdrLen > IPv4MaximumHeaderSize {
		panic(fmt.Sprintf("got IPv4 Header size = %d, want <= %d", hdrLen, IPv4MaximumHeaderSize))
	}
	b[versIHL] = (IPv4Version << ipVersionShift) | ((hdrLen / IPv4IHLStride) & ipIHLMask)
}

func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[id:])
}

func (b IPv4) Protocol() uint8 {
	return b[protocol]
}

func (b IPv4) Flags() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

func (b IPv4) FlagsDarwinRaw() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

func (b IPv4) More() bool {
	return b.Flags()&IPv4FlagMoreFragments != 0
}

func (b IPv4) TTL() uint8 {
	return b[ttl]
}

func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

func (b IPv4) FragmentOffsetDarwinRaw() uint16 {
	return common.NativeEndian.Uint16(b[flagsFO:]) << 3
}

func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv4TotalLenOffset:])
}

func (b IPv4) TotalLengthDarwinRaw() uint16 {
	return common.NativeEndian.Uint16(b[IPv4TotalLenOffset:]) + uint16(b.HeaderLength())
}

func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[xsum:])
}

func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(b[srcAddr : srcAddr+IPv4AddressSize]))
}

func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(b[dstAddr : dstAddr+IPv4AddressSize]))
}

func (b IPv4) SourceAddressSlice() []byte {
	return []byte(b[srcAddr : srcAddr+IPv4AddressSize])
}

func (b IPv4) DestinationAddressSlice() []byte {
	return []byte(b[dstAddr : dstAddr+IPv4AddressSize])
}

func (b IPv4) SetSourceAddressWithChecksumUpdate(new tcpip.Address) {
	b.SetChecksum(^checksumUpdate2ByteAlignedAddress(^b.Checksum(), b.SourceAddress(), new))
	b.SetSourceAddress(new)
}

func (b IPv4) SetDestinationAddressWithChecksumUpdate(new tcpip.Address) {
	b.SetChecksum(^checksumUpdate2ByteAlignedAddress(^b.Checksum(), b.DestinationAddress(), new))
	b.SetDestinationAddress(new)
}

func padIPv4OptionsLength(length uint8) uint8 {
	return (length + IPv4IHLStride - 1) & ^uint8(IPv4IHLStride-1)
}

type IPv4Options []byte

func (b IPv4) Options() IPv4Options {
	hdrLen := b.HeaderLength()
	return IPv4Options(b[options:hdrLen:hdrLen])
}

func (b IPv4) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.Protocol())
}

func (b IPv4) Payload() []byte {
	return b[b.HeaderLength():][:b.PayloadLength()]
}

func (b IPv4) PayloadLength() uint16 {
	return b.TotalLength() - uint16(b.HeaderLength())
}

func (b IPv4) TOS() (uint8, uint32) {
	return b[tos], 0
}

func (b IPv4) SetTOS(v uint8, _ uint32) {
	b[tos] = v
}

func (b IPv4) SetTTL(v byte) {
	b[ttl] = v
}

func (b IPv4) SetTotalLength(totalLength uint16) {
	binary.BigEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
}

func (b IPv4) SetTotalLengthDarwinRaw(totalLength uint16) {
	common.NativeEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
}

func (b IPv4) SetChecksum(v uint16) {
	checksum.Put(b[xsum:], v)
}

func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	binary.BigEndian.PutUint16(b[flagsFO:], v)
}

func (b IPv4) SetFlagsFragmentOffsetDarwinRaw(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	common.NativeEndian.PutUint16(b[flagsFO:], v)
}

func (b IPv4) SetID(v uint16) {
	binary.BigEndian.PutUint16(b[id:], v)
}

func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	copy(b[srcAddr:srcAddr+IPv4AddressSize], addr.AsSlice())
}

func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	copy(b[dstAddr:dstAddr+IPv4AddressSize], addr.AsSlice())
}

func (b IPv4) CalculateChecksum() uint16 {
	xsum0 := checksum.Checksum(b[:xsum], 0)
	xsum0 = checksum.Checksum(b[xsum+2:b.HeaderLength()], xsum0)
	return xsum0
}

func (b IPv4) Encode(i *IPv4Fields) {
	hdrLen := uint8(IPv4MinimumSize)
	if len(i.Options) != 0 {
		hdrLen += i.Options.Serialize(b[options:])
	}
	if hdrLen > IPv4MaximumHeaderSize {
		panic(fmt.Sprintf("%d is larger than maximum IPv4 header size of %d", hdrLen, IPv4MaximumHeaderSize))
	}
	b.SetHeaderLength(hdrLen)
	b[tos] = i.TOS
	b.SetTotalLength(i.TotalLength)
	binary.BigEndian.PutUint16(b[id:], i.ID)
	b.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
	b[ttl] = i.TTL
	b[protocol] = i.Protocol
	b.SetChecksum(i.Checksum)
	copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr.AsSlice())
	copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr.AsSlice())
}

func (b IPv4) EncodePartial(partialChecksum, totalLength uint16) {
	b.SetTotalLength(totalLength)
	xsum := checksum.Checksum(b[IPv4TotalLenOffset:IPv4TotalLenOffset+2], partialChecksum)
	b.SetChecksum(^xsum)
}

func (b IPv4) IsValid(pktSize int) bool {
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(b.HeaderLength())
	tlen := int(b.TotalLength())
	if hlen < IPv4MinimumSize || hlen > tlen || tlen > pktSize {
		return false
	}

	if IPVersion(b) != IPv4Version {
		return false
	}

	return true
}

func IsV4LinkLocalUnicastAddress(addr tcpip.Address) bool {
	return ipv4LinkLocalUnicastSubnet.Contains(addr)
}

func IsV4LinkLocalMulticastAddress(addr tcpip.Address) bool {
	return ipv4LinkLocalMulticastSubnet.Contains(addr)
}

func (b IPv4) IsChecksumValid() bool {
	return checksum.Checksum(b[:b.HeaderLength()], 0) == 0xffff
}

func IsV4MulticastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv4AddressSizeBits {
		return false
	}
	addrBytes := addr.As4()
	return (addrBytes[0] & 0xf0) == 0xe0
}

func IsV4LoopbackAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv4AddressSizeBits {
		return false
	}
	addrBytes := addr.As4()
	return addrBytes[0] == 0x7f
}


type IPv4OptionType byte


const (
	IPv4OptionListEndType IPv4OptionType = 0

	IPv4OptionNOPType IPv4OptionType = 1

	IPv4OptionRouterAlertType IPv4OptionType = 20 | 0x80

	IPv4OptionRecordRouteType IPv4OptionType = 7

	IPv4OptionTimestampType IPv4OptionType = 68

	ipv4OptionTypeOffset = 0

	IPv4OptionLengthOffset = 1
)

type IPv4OptParameterProblem struct {
	Pointer  uint8
	NeedICMP bool
}

type IPv4Option interface {
	Type() IPv4OptionType

	Size() uint8

	Contents() []byte
}

var _ IPv4Option = (*IPv4OptionGeneric)(nil)

type IPv4OptionGeneric []byte

func (o *IPv4OptionGeneric) Type() IPv4OptionType {
	return IPv4OptionType((*o)[ipv4OptionTypeOffset])
}

func (o *IPv4OptionGeneric) Size() uint8 { return uint8(len(*o)) }

func (o *IPv4OptionGeneric) Contents() []byte { return *o }

type IPv4OptionIterator struct {
	options IPv4Options
	ErrCursor     uint8
	nextErrCursor uint8
	newOptions    [IPv4MaximumOptionsSize]byte
	writePoint    int
}

func (o IPv4Options) MakeIterator() IPv4OptionIterator {
	return IPv4OptionIterator{
		options:       o,
		nextErrCursor: IPv4MinimumSize,
	}
}

func (i *IPv4OptionIterator) InitReplacement(option IPv4Option) IPv4Options {
	replacementOption := i.RemainingBuffer()[:option.Size()]
	if copied := copy(replacementOption, option.Contents()); copied != len(replacementOption) {
		panic(fmt.Sprintf("copied %d bytes in the replacement option buffer, expected %d bytes", copied, len(replacementOption)))
	}
	return replacementOption
}

func (i *IPv4OptionIterator) RemainingBuffer() IPv4Options {
	return i.newOptions[i.writePoint:]
}

func (i *IPv4OptionIterator) ConsumeBuffer(size int) {
	i.writePoint += size
}

func (i *IPv4OptionIterator) PushNOPOrEnd(val IPv4OptionType) {
	if val > IPv4OptionNOPType {
		panic(fmt.Sprintf("invalid option type %d pushed onto option build buffer", val))
	}
	i.newOptions[i.writePoint] = byte(val)
	i.writePoint++
}

func (i *IPv4OptionIterator) Finalize() IPv4Options {
	options := IPv4Options(i.newOptions[:(i.writePoint+0x3) & ^0x3])
	i.writePoint = len(i.newOptions)
	return options
}

func (i *IPv4OptionIterator) Next() (IPv4Option, bool, *IPv4OptParameterProblem) {
	if len(i.options) == 0 {
		return nil, true, nil
	}

	i.ErrCursor = i.nextErrCursor

	optType := IPv4OptionType(i.options[ipv4OptionTypeOffset])

	if optType == IPv4OptionNOPType || optType == IPv4OptionListEndType {
		optionBody := i.options[:1]
		i.options = i.options[1:]
		i.nextErrCursor = i.ErrCursor + 1
		retval := IPv4OptionGeneric(optionBody)
		return &retval, false, nil
	}

	if len(i.options) == 1 {
		return nil, false, &IPv4OptParameterProblem{
			Pointer:  i.ErrCursor,
			NeedICMP: true,
		}
	}

	optLen := i.options[IPv4OptionLengthOffset]

	if optLen <= IPv4OptionLengthOffset || optLen > uint8(len(i.options)) {

		return nil, false, &IPv4OptParameterProblem{
			Pointer:  i.ErrCursor,
			NeedICMP: true,
		}
	}

	optionBody := i.options[:optLen]
	i.nextErrCursor = i.ErrCursor + optLen
	i.options = i.options[optLen:]

	switch optType {
	case IPv4OptionTimestampType:
		if optLen < IPv4OptionTimestampHdrLength {
			i.ErrCursor++
			return nil, false, &IPv4OptParameterProblem{
				Pointer:  i.ErrCursor,
				NeedICMP: true,
			}
		}
		retval := IPv4OptionTimestamp(optionBody)
		return &retval, false, nil

	case IPv4OptionRecordRouteType:
		if optLen < IPv4OptionRecordRouteHdrLength {
			i.ErrCursor++
			return nil, false, &IPv4OptParameterProblem{
				Pointer:  i.ErrCursor,
				NeedICMP: true,
			}
		}
		retval := IPv4OptionRecordRoute(optionBody)
		return &retval, false, nil

	case IPv4OptionRouterAlertType:
		if optLen != IPv4OptionRouterAlertLength {
			i.ErrCursor++
			return nil, false, &IPv4OptParameterProblem{
				Pointer:  i.ErrCursor,
				NeedICMP: true,
			}
		}
		retval := IPv4OptionRouterAlert(optionBody)
		return &retval, false, nil
	}
	retval := IPv4OptionGeneric(optionBody)
	return &retval, false, nil
}


type IPv4OptTSFlags uint8

const (
	IPv4OptionTimestampHdrLength = 4

	IPv4OptionTimestampSize = 4

	IPv4OptionTimestampWithAddrSize = IPv4AddressSize + IPv4OptionTimestampSize

	IPv4OptionTimestampMaxSize = IPv4MaximumOptionsSize

	IPv4OptionTimestampOnlyFlag IPv4OptTSFlags = 0

	IPv4OptionTimestampWithIPFlag IPv4OptTSFlags = 1

	IPv4OptionTimestampWithPredefinedIPFlag IPv4OptTSFlags = 3
)

func ipv4TimestampTime(clock tcpip.Clock) uint32 {
	now := clock.Now().UTC()
	midnight := now.Truncate(24 * time.Hour)
	return uint32(now.Sub(midnight).Milliseconds())
}

const (
	IPv4OptTSPointerOffset = 2

	IPv4OptTSOFLWAndFLGOffset = 3
	ipv4OptionTimestampOverflowshift      = 4
	ipv4OptionTimestampFlagsMask     byte = 0x0f
)

var _ IPv4Option = (*IPv4OptionTimestamp)(nil)

type IPv4OptionTimestamp []byte

func (ts *IPv4OptionTimestamp) Type() IPv4OptionType { return IPv4OptionTimestampType }

func (ts *IPv4OptionTimestamp) Size() uint8 { return uint8(len(*ts)) }

func (ts *IPv4OptionTimestamp) Contents() []byte { return *ts }

func (ts *IPv4OptionTimestamp) Pointer() uint8 {
	return (*ts)[IPv4OptTSPointerOffset]
}

func (ts *IPv4OptionTimestamp) Flags() IPv4OptTSFlags {
	return IPv4OptTSFlags((*ts)[IPv4OptTSOFLWAndFLGOffset] & ipv4OptionTimestampFlagsMask)
}

func (ts *IPv4OptionTimestamp) Overflow() uint8 {
	return (*ts)[IPv4OptTSOFLWAndFLGOffset] >> ipv4OptionTimestampOverflowshift
}

func (ts *IPv4OptionTimestamp) IncOverflow() uint8 {
	(*ts)[IPv4OptTSOFLWAndFLGOffset] += 1 << ipv4OptionTimestampOverflowshift
	return ts.Overflow()
}

func (ts *IPv4OptionTimestamp) UpdateTimestamp(addr tcpip.Address, clock tcpip.Clock) {
	slot := (*ts)[ts.Pointer()-1:]

	switch ts.Flags() {
	case IPv4OptionTimestampOnlyFlag:
		binary.BigEndian.PutUint32(slot, ipv4TimestampTime(clock))
		(*ts)[IPv4OptTSPointerOffset] += IPv4OptionTimestampSize
	case IPv4OptionTimestampWithIPFlag:
		if n := copy(slot, addr.AsSlice()); n != IPv4AddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, IPv4AddressSize))
		}
		binary.BigEndian.PutUint32(slot[IPv4AddressSize:], ipv4TimestampTime(clock))
		(*ts)[IPv4OptTSPointerOffset] += IPv4OptionTimestampWithAddrSize
	case IPv4OptionTimestampWithPredefinedIPFlag:
		if tcpip.AddrFrom4([4]byte(slot[:IPv4AddressSize])) == addr {
			binary.BigEndian.PutUint32(slot[IPv4AddressSize:], ipv4TimestampTime(clock))
			(*ts)[IPv4OptTSPointerOffset] += IPv4OptionTimestampWithAddrSize
		}
	}
}

const (
	IPv4OptionRecordRouteHdrLength = 3

	IPv4OptRRPointerOffset = 2
)

var _ IPv4Option = (*IPv4OptionRecordRoute)(nil)

type IPv4OptionRecordRoute []byte

func (rr *IPv4OptionRecordRoute) Pointer() uint8 {
	return (*rr)[IPv4OptRRPointerOffset]
}

func (rr *IPv4OptionRecordRoute) StoreAddress(addr tcpip.Address) {
	start := rr.Pointer() - 1
	if n := copy((*rr)[start:], addr.AsSlice()); n != IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, IPv4AddressSize))
	}
	(*rr)[IPv4OptRRPointerOffset] += IPv4AddressSize
}

func (rr *IPv4OptionRecordRoute) Type() IPv4OptionType { return IPv4OptionRecordRouteType }

func (rr *IPv4OptionRecordRoute) Size() uint8 { return uint8(len(*rr)) }

func (rr *IPv4OptionRecordRoute) Contents() []byte { return *rr }

const (
	IPv4OptionRouterAlertLength = 4

	IPv4OptionRouterAlertValue = 0

	IPv4OptionRouterAlertValueOffset = 2
)

var _ IPv4Option = (*IPv4OptionRouterAlert)(nil)

type IPv4OptionRouterAlert []byte

func (*IPv4OptionRouterAlert) Type() IPv4OptionType { return IPv4OptionRouterAlertType }

func (ra *IPv4OptionRouterAlert) Size() uint8 { return uint8(len(*ra)) }

func (ra *IPv4OptionRouterAlert) Contents() []byte { return *ra }

func (ra *IPv4OptionRouterAlert) Value() uint16 {
	return binary.BigEndian.Uint16(ra.Contents()[IPv4OptionRouterAlertValueOffset:])
}

type IPv4SerializableOption interface {
	optionType() IPv4OptionType
}

type IPv4SerializableOptionPayload interface {
	length() uint8

	serializeInto(buffer []byte) uint8
}

type IPv4OptionsSerializer []IPv4SerializableOption

func (s IPv4OptionsSerializer) Length() uint8 {
	var total uint8
	for _, opt := range s {
		total++
		if withPayload, ok := opt.(IPv4SerializableOptionPayload); ok {
			total += 1 + withPayload.length()
		}
	}
	return padIPv4OptionsLength(total)
}

func (s IPv4OptionsSerializer) Serialize(b []byte) uint8 {
	var total uint8
	for _, opt := range s {
		ty := opt.optionType()
		if withPayload, ok := opt.(IPv4SerializableOptionPayload); ok {
			l := 2 + withPayload.serializeInto(b[2:])
			b[0] = byte(ty)
			b[1] = l
			b = b[l:]
			total += l
			continue
		}
		b[0] = byte(ty)
		b = b[1:]
		total++
	}

	padded := padIPv4OptionsLength(total)
	b = b[:padded-total]
	common.ClearArray(b)
	return padded
}

var (
	_ IPv4SerializableOptionPayload = (*IPv4SerializableRouterAlertOption)(nil)
	_ IPv4SerializableOption        = (*IPv4SerializableRouterAlertOption)(nil)
)

type IPv4SerializableRouterAlertOption struct{}

func (*IPv4SerializableRouterAlertOption) optionType() IPv4OptionType {
	return IPv4OptionRouterAlertType
}

func (*IPv4SerializableRouterAlertOption) length() uint8 {
	return IPv4OptionRouterAlertLength - IPv4OptionRouterAlertValueOffset
}

func (o *IPv4SerializableRouterAlertOption) serializeInto(buffer []byte) uint8 {
	binary.BigEndian.PutUint16(buffer, IPv4OptionRouterAlertValue)
	return o.length()
}

var _ IPv4SerializableOption = (*IPv4SerializableNOPOption)(nil)

type IPv4SerializableNOPOption struct{}

func (*IPv4SerializableNOPOption) optionType() IPv4OptionType {
	return IPv4OptionNOPType
}

var _ IPv4SerializableOption = (*IPv4SerializableListEndOption)(nil)

type IPv4SerializableListEndOption struct{}

func (*IPv4SerializableListEndOption) optionType() IPv4OptionType {
	return IPv4OptionListEndType
}

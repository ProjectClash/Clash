// Copyright 2019 The gVisor Authors.
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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing/common"
)

type ndpOptionIdentifier uint8

const (
	ndpSourceLinkLayerAddressOptionType ndpOptionIdentifier = 1

	ndpTargetLinkLayerAddressOptionType ndpOptionIdentifier = 2

	ndpPrefixInformationType ndpOptionIdentifier = 3

	ndpNonceOptionType ndpOptionIdentifier = 14

	ndpRecursiveDNSServerOptionType ndpOptionIdentifier = 25

	ndpDNSSearchListOptionType ndpOptionIdentifier = 31
)

const (
	NDPLinkLayerAddressSize = 8

	ndpPrefixInformationLength = 30

	ndpPrefixInformationPrefixLengthOffset = 0

	ndpPrefixInformationFlagsOffset = 1

	ndpPrefixInformationOnLinkFlagMask = 1 << 7

	ndpPrefixInformationAutoAddrConfFlagMask = 1 << 6

	ndpPrefixInformationReserved1FlagsMask = 63

	ndpPrefixInformationValidLifetimeOffset = 2

	ndpPrefixInformationPreferredLifetimeOffset = 6

	ndpPrefixInformationReserved2Offset = 10

	ndpPrefixInformationReserved2Length = 4

	ndpPrefixInformationPrefixOffset = 14

	ndpRecursiveDNSServerLifetimeOffset = 2

	ndpRecursiveDNSServerAddressesOffset = 6

	minNDPRecursiveDNSServerBodySize = 22

	ndpDNSSearchListLifetimeOffset = 2

	ndpDNSSearchListDomainNamesOffset = 6

	minNDPDNSSearchListBodySize = 14

	maxDomainNameLabelLength = 63

	maxDomainNameLength = 255

	lengthByteUnits = 8

	NDPInfiniteLifetime = time.Second * math.MaxUint32
)

type NDPOptionIterator struct {
	opts *bytes.Buffer
}

var (
	ErrNDPOptMalformedBody   = errors.New("NDP option has a malformed body")
	ErrNDPOptMalformedHeader = errors.New("NDP option has a malformed header")
)

func (i *NDPOptionIterator) Next() (NDPOption, bool, error) {
	for {
		if i.opts.Len() == 0 {
			return nil, true, nil
		}

		temp, err := i.opts.ReadByte()
		if err != nil {
			if err != io.EOF {
				panic(fmt.Sprintf("unexpected error when reading the option's Type field: %s", err))
			}

			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Type field: %w", io.ErrUnexpectedEOF)
		}
		kind := ndpOptionIdentifier(temp)

		length, err := i.opts.ReadByte()
		if err != nil {
			if err != io.EOF {
				panic(fmt.Sprintf("unexpected error when reading the option's Length field for %s: %s", kind, err))
			}

			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Length field for %s: %w", kind, io.ErrUnexpectedEOF)
		}

		if length == 0 {
			return nil, true, fmt.Errorf("zero valued Length field for %s: %w", kind, ErrNDPOptMalformedHeader)
		}

		numBytes := int(length) * lengthByteUnits
		numBodyBytes := numBytes - 2
		body := i.opts.Next(numBodyBytes)
		if len(body) < numBodyBytes {
			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Body for %s: %w", kind, io.ErrUnexpectedEOF)
		}

		switch kind {
		case ndpSourceLinkLayerAddressOptionType:
			return NDPSourceLinkLayerAddressOption(body), false, nil

		case ndpTargetLinkLayerAddressOptionType:
			return NDPTargetLinkLayerAddressOption(body), false, nil

		case ndpNonceOptionType:
			return NDPNonceOption(body), false, nil

		case ndpRouteInformationType:
			if numBodyBytes > ndpRouteInformationMaxLength {
				return nil, true, fmt.Errorf("got %d bytes for NDP Route Information option's body, expected at max %d bytes: %w", numBodyBytes, ndpRouteInformationMaxLength, ErrNDPOptMalformedBody)
			}
			opt := NDPRouteInformation(body)
			if err := opt.hasError(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		case ndpPrefixInformationType:
			if numBodyBytes != ndpPrefixInformationLength {
				return nil, true, fmt.Errorf("got %d bytes for NDP Prefix Information option's body, expected %d bytes: %w", numBodyBytes, ndpPrefixInformationLength, ErrNDPOptMalformedBody)
			}

			return NDPPrefixInformation(body), false, nil

		case ndpRecursiveDNSServerOptionType:
			opt := NDPRecursiveDNSServer(body)
			if err := opt.checkAddresses(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		case ndpDNSSearchListOptionType:
			opt := NDPDNSSearchList(body)
			if err := opt.checkDomainNames(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		default:
		}
	}
}

type NDPOptions []byte

func (b NDPOptions) Iter(check bool) (NDPOptionIterator, error) {
	it := NDPOptionIterator{
		opts: bytes.NewBuffer(b),
	}

	if check {
		it2 := NDPOptionIterator{
			opts: bytes.NewBuffer(b),
		}

		for {
			if _, done, err := it2.Next(); err != nil || done {
				return it, err
			}
		}
	}

	return it, nil
}

func (b NDPOptions) Serialize(s NDPOptionsSerializer) int {
	done := 0

	for _, o := range s {
		l := paddedLength(o)

		if l == 0 {
			continue
		}

		b[0] = byte(o.kind())

		b[1] = uint8(l / lengthByteUnits)

		used := o.serializeInto(b[2:])

		if used+2 < l {
			common.ClearArray(b[used+2 : l])
		}

		b = b[l:]
		done += l
	}

	return done
}

type NDPOption interface {
	fmt.Stringer

	kind() ndpOptionIdentifier

	length() int

	serializeInto([]byte) int
}

func paddedLength(o NDPOption) int {
	l := o.length()

	if l == 0 {
		return 0
	}

	l += 2

	mask := lengthByteUnits - 1
	l += mask
	l &^= mask

	if l/lengthByteUnits > 255 {
		return 0
	}

	return l
}

type NDPOptionsSerializer []NDPOption

func (b NDPOptionsSerializer) Length() int {
	l := 0

	for _, o := range b {
		l += paddedLength(o)
	}

	return l
}

type NDPNonceOption []byte

func (o NDPNonceOption) kind() ndpOptionIdentifier {
	return ndpNonceOptionType
}

func (o NDPNonceOption) length() int {
	return len(o)
}

func (o NDPNonceOption) serializeInto(b []byte) int {
	return copy(b, o)
}

func (o NDPNonceOption) String() string {
	return fmt.Sprintf("%T(%x)", o, []byte(o))
}

func (o NDPNonceOption) Nonce() []byte {
	return o
}

type NDPSourceLinkLayerAddressOption tcpip.LinkAddress

func (o NDPSourceLinkLayerAddressOption) kind() ndpOptionIdentifier {
	return ndpSourceLinkLayerAddressOptionType
}

func (o NDPSourceLinkLayerAddressOption) length() int {
	return len(o)
}

func (o NDPSourceLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

func (o NDPSourceLinkLayerAddressOption) String() string {
	return fmt.Sprintf("%T(%s)", o, tcpip.LinkAddress(o))
}

func (o NDPSourceLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
}

type NDPTargetLinkLayerAddressOption tcpip.LinkAddress

func (o NDPTargetLinkLayerAddressOption) kind() ndpOptionIdentifier {
	return ndpTargetLinkLayerAddressOptionType
}

func (o NDPTargetLinkLayerAddressOption) length() int {
	return len(o)
}

func (o NDPTargetLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

func (o NDPTargetLinkLayerAddressOption) String() string {
	return fmt.Sprintf("%T(%s)", o, tcpip.LinkAddress(o))
}

func (o NDPTargetLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
}

type NDPPrefixInformation []byte

func (o NDPPrefixInformation) kind() ndpOptionIdentifier {
	return ndpPrefixInformationType
}

func (o NDPPrefixInformation) length() int {
	return ndpPrefixInformationLength
}

func (o NDPPrefixInformation) serializeInto(b []byte) int {
	used := copy(b, o)

	b[ndpPrefixInformationFlagsOffset] &^= ndpPrefixInformationReserved1FlagsMask

	reserved2 := b[ndpPrefixInformationReserved2Offset:][:ndpPrefixInformationReserved2Length]
	common.ClearArray(reserved2)

	return used
}

func (o NDPPrefixInformation) String() string {
	return fmt.Sprintf("%T(O=%t, A=%t, PL=%s, VL=%s, Prefix=%s)",
		o,
		o.OnLinkFlag(),
		o.AutonomousAddressConfigurationFlag(),
		o.PreferredLifetime(),
		o.ValidLifetime(),
		o.Subnet())
}

func (o NDPPrefixInformation) PrefixLength() uint8 {
	return o[ndpPrefixInformationPrefixLengthOffset]
}

func (o NDPPrefixInformation) OnLinkFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationOnLinkFlagMask != 0
}

func (o NDPPrefixInformation) AutonomousAddressConfigurationFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationAutoAddrConfFlagMask != 0
}

func (o NDPPrefixInformation) ValidLifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationValidLifetimeOffset:]))
}

func (o NDPPrefixInformation) PreferredLifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationPreferredLifetimeOffset:]))
}

func (o NDPPrefixInformation) Prefix() tcpip.Address {
	return tcpip.AddrFrom16Slice(o[ndpPrefixInformationPrefixOffset:][:IPv6AddressSize])
}

func (o NDPPrefixInformation) Subnet() tcpip.Subnet {
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   o.Prefix(),
		PrefixLen: int(o.PrefixLength()),
	}
	return addrWithPrefix.Subnet()
}

type NDPRecursiveDNSServer []byte

func (NDPRecursiveDNSServer) kind() ndpOptionIdentifier {
	return ndpRecursiveDNSServerOptionType
}

func (o NDPRecursiveDNSServer) length() int {
	return len(o)
}

func (o NDPRecursiveDNSServer) serializeInto(b []byte) int {
	used := copy(b, o)

	common.ClearArray(b[0:ndpRecursiveDNSServerLifetimeOffset])

	return used
}

func (o NDPRecursiveDNSServer) String() string {
	lt := o.Lifetime()
	addrs, err := o.Addresses()
	if err != nil {
		return fmt.Sprintf("%T([] valid for %s; err = %s)", o, lt, err)
	}
	return fmt.Sprintf("%T(%s valid for %s)", o, addrs, lt)
}

func (o NDPRecursiveDNSServer) Lifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpRecursiveDNSServerLifetimeOffset:]))
}

func (o NDPRecursiveDNSServer) Addresses() ([]tcpip.Address, error) {
	var addrs []tcpip.Address
	return addrs, o.iterAddresses(func(addr tcpip.Address) { addrs = append(addrs, addr) })
}

func (o NDPRecursiveDNSServer) checkAddresses() error {
	return o.iterAddresses(nil)
}

func (o NDPRecursiveDNSServer) iterAddresses(fn func(tcpip.Address)) error {
	if l := len(o); l < minNDPRecursiveDNSServerBodySize {
		return fmt.Errorf("got %d bytes for NDP Recursive DNS Server option's body, expected at least %d bytes: %w", l, minNDPRecursiveDNSServerBodySize, io.ErrUnexpectedEOF)
	}

	o = o[ndpRecursiveDNSServerAddressesOffset:]
	l := len(o)
	if l%IPv6AddressSize != 0 {
		return fmt.Errorf("NDP Recursive DNS Server option's body ends in the middle of an IPv6 address (addresses body size = %d bytes): %w", l, ErrNDPOptMalformedBody)
	}

	for i := 0; len(o) != 0; i++ {
		addr := tcpip.AddrFrom16Slice(o[:IPv6AddressSize])
		if !IsV6UnicastAddress(addr) {
			return fmt.Errorf("%d-th address (%s) in NDP Recursive DNS Server option is not a valid unicast IPv6 address: %w", i, addr, ErrNDPOptMalformedBody)
		}

		if fn != nil {
			fn(addr)
		}

		o = o[IPv6AddressSize:]
	}

	return nil
}

type NDPDNSSearchList []byte

func (o NDPDNSSearchList) kind() ndpOptionIdentifier {
	return ndpDNSSearchListOptionType
}

func (o NDPDNSSearchList) length() int {
	return len(o)
}

func (o NDPDNSSearchList) serializeInto(b []byte) int {
	used := copy(b, o)

	common.ClearArray(b[0:ndpDNSSearchListLifetimeOffset])

	return used
}

func (o NDPDNSSearchList) String() string {
	lt := o.Lifetime()
	domainNames, err := o.DomainNames()
	if err != nil {
		return fmt.Sprintf("%T([] valid for %s; err = %s)", o, lt, err)
	}
	return fmt.Sprintf("%T(%s valid for %s)", o, domainNames, lt)
}

func (o NDPDNSSearchList) Lifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpDNSSearchListLifetimeOffset:]))
}

func (o NDPDNSSearchList) DomainNames() ([]string, error) {
	var domainNames []string
	return domainNames, o.iterDomainNames(func(domainName string) { domainNames = append(domainNames, domainName) })
}

func (o NDPDNSSearchList) checkDomainNames() error {
	return o.iterDomainNames(nil)
}

func (o NDPDNSSearchList) iterDomainNames(fn func(string)) error {
	if l := len(o); l < minNDPDNSSearchListBodySize {
		return fmt.Errorf("got %d bytes for NDP DNS Search List  option's body, expected at least %d bytes: %w", l, minNDPDNSSearchListBodySize, io.ErrUnexpectedEOF)
	}

	var searchList bytes.Reader
	searchList.Reset(o[ndpDNSSearchListDomainNamesOffset:])

	var scratch [maxDomainNameLength]byte
	domainName := bytes.NewBuffer(scratch[:])

	for searchList.Len() != 0 {
		domainName.Reset()

		for {
			labelLenByte, err := searchList.ReadByte()
			if err != nil {
				if err != io.EOF {
					panic(fmt.Sprintf("unexpected error when reading a label's length: %s", err))
				}

				return fmt.Errorf("unexpected exhausted buffer while parsing a new label for a domain from NDP Search List option: %w", io.ErrUnexpectedEOF)
			}
			labelLen := int(labelLenByte)

			if labelLen == 0 {
				if domainName.Len() == 0 || fn == nil {
					break
				}

				domainName.Truncate(domainName.Len() - 1)
				fn(domainName.String())
				break
			}

			if labelLen > maxDomainNameLabelLength {
				return fmt.Errorf("label length of %d bytes is greater than the max label length of %d bytes for an NDP Search List option: %w", labelLen, maxDomainNameLabelLength, ErrNDPOptMalformedBody)
			}

			if labelLen+1 > domainName.Cap()-domainName.Len() {
				return fmt.Errorf("label would make an NDP Search List option's domain name longer than the max domain name length of %d bytes: %w", maxDomainNameLength, ErrNDPOptMalformedBody)
			}

			for i := 0; i < labelLen; i++ {
				b, err := searchList.ReadByte()
				if err != nil {
					if err != io.EOF {
						panic(fmt.Sprintf("unexpected error when reading domain name's label: %s", err))
					}

					return fmt.Errorf("read %d out of %d bytes for a domain name's label from NDP Search List option: %w", i, labelLen, io.ErrUnexpectedEOF)
				}


				if !isLetter(b) {
					if i == 0 {
						return fmt.Errorf("first character of a domain name's label in an NDP Search List option must be a letter, got character code = %d: %w", b, ErrNDPOptMalformedBody)
					}

					if b == '-' {
						if i == labelLen-1 {
							return fmt.Errorf("last character of a domain name's label in an NDP Search List option must not be a hyphen (-): %w", ErrNDPOptMalformedBody)
						}
					} else if !isDigit(b) {
						return fmt.Errorf("domain name's label in an NDP Search List option may only contain letters, digits and hyphens, got character code = %d: %w", b, ErrNDPOptMalformedBody)
					}
				}

				if isUpperLetter(b) {
					b = b - 'A' + 'a'
				}

				if err := domainName.WriteByte(b); err != nil {
					panic(fmt.Sprintf("unexpected error writing label to domain name buffer: %s", err))
				}
			}
			if err := domainName.WriteByte('.'); err != nil {
				panic(fmt.Sprintf("unexpected error writing trailing period to domain name buffer: %s", err))
			}
		}
	}

	return nil
}

func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z' || isUpperLetter(b)
}

func isUpperLetter(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

const (
	ndpRouteInformationType      = ndpOptionIdentifier(24)
	ndpRouteInformationMaxLength = 22

	ndpRouteInformationPrefixLengthIdx  = 0
	ndpRouteInformationFlagsIdx         = 1
	ndpRouteInformationPrfShift         = 3
	ndpRouteInformationPrfMask          = 3 << ndpRouteInformationPrfShift
	ndpRouteInformationRouteLifetimeIdx = 2
	ndpRouteInformationRoutePrefixIdx   = 6
)

type NDPRouteInformation []byte

func (NDPRouteInformation) kind() ndpOptionIdentifier {
	return ndpRouteInformationType
}

func (o NDPRouteInformation) length() int {
	return len(o)
}

func (o NDPRouteInformation) serializeInto(b []byte) int {
	return copy(b, o)
}

func (o NDPRouteInformation) String() string {
	return fmt.Sprintf("%T", o)
}

func (o NDPRouteInformation) PrefixLength() uint8 {
	return o[ndpRouteInformationPrefixLengthIdx]
}

func (o NDPRouteInformation) RoutePreference() NDPRoutePreference {
	return NDPRoutePreference((o[ndpRouteInformationFlagsIdx] & ndpRouteInformationPrfMask) >> ndpRouteInformationPrfShift)
}

func (o NDPRouteInformation) RouteLifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpRouteInformationRouteLifetimeIdx:]))
}

func (o NDPRouteInformation) Prefix() (tcpip.Subnet, error) {
	prefixLength := int(o.PrefixLength())
	if max := IPv6AddressSize * 8; prefixLength > max {
		return tcpip.Subnet{}, fmt.Errorf("got prefix length = %d, want <= %d", prefixLength, max)
	}

	prefix := o[ndpRouteInformationRoutePrefixIdx:]
	var addrBytes [IPv6AddressSize]byte
	if n := copy(addrBytes[:], prefix); n != len(prefix) {
		panic(fmt.Sprintf("got copy(addrBytes, prefix) = %d, want = %d", n, len(prefix)))
	}

	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom16(addrBytes),
		PrefixLen: prefixLength,
	}.Subnet(), nil
}

func (o NDPRouteInformation) hasError() error {
	l := len(o)
	if l < ndpRouteInformationRoutePrefixIdx {
		return fmt.Errorf("%T too small, got = %d bytes: %w", o, l, ErrNDPOptMalformedBody)
	}

	prefixLength := int(o.PrefixLength())
	if max := IPv6AddressSize * 8; prefixLength > max {
		return fmt.Errorf("got prefix length = %d, want <= %d: %w", prefixLength, max, ErrNDPOptMalformedBody)
	}

	l += 2
	lengthField := l / lengthByteUnits
	if prefixLength > 64 {
		if lengthField != 3 {
			return fmt.Errorf("Length field must be 3 when Prefix Length (%d) is > 64 (got = %d): %w", prefixLength, lengthField, ErrNDPOptMalformedBody)
		}
	} else if prefixLength > 0 {
		if lengthField != 2 && lengthField != 3 {
			return fmt.Errorf("Length field must be 2 or 3 when Prefix Length (%d) is between 0 and 64 (got = %d): %w", prefixLength, lengthField, ErrNDPOptMalformedBody)
		}
	} else if lengthField == 0 || lengthField > 3 {
		return fmt.Errorf("Length field must be 1, 2, or 3 when Prefix Length is zero (got = %d): %w", lengthField, ErrNDPOptMalformedBody)
	}

	return nil
}

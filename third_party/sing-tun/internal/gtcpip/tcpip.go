// Copyright 2024 The gVisor Authors.
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

package tcpip

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ipv4AddressSize    = 4
	ipv4ProtocolNumber = 0x0800
	ipv6AddressSize    = 16
	ipv6ProtocolNumber = 0x86dd
)

const (
	LinkAddressSize = 6
)

var (
	IPv4Zero = []byte{0, 0, 0, 0}
	IPv6Zero = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

var (
	errSubnetLengthMismatch = errors.New("subnet length of address and mask differ")
	errSubnetAddressMasked  = errors.New("subnet address has bits set outside the mask")
)

type TransportProtocolNumber uint32

type NetworkProtocolNumber uint32

type MonotonicTime struct {
	nanoseconds int64
}

func (mt MonotonicTime) String() string {
	return strconv.FormatInt(mt.nanoseconds, 10)
}

func MonotonicTimeInfinite() MonotonicTime {
	return MonotonicTime{nanoseconds: math.MaxInt64}
}

func (mt MonotonicTime) Before(u MonotonicTime) bool {
	return mt.nanoseconds < u.nanoseconds
}

func (mt MonotonicTime) After(u MonotonicTime) bool {
	return mt.nanoseconds > u.nanoseconds
}

func (mt MonotonicTime) Add(d time.Duration) MonotonicTime {
	return MonotonicTime{
		nanoseconds: time.Unix(0, mt.nanoseconds).Add(d).Sub(time.Unix(0, 0)).Nanoseconds(),
	}
}

func (mt MonotonicTime) Sub(u MonotonicTime) time.Duration {
	return time.Unix(0, mt.nanoseconds).Sub(time.Unix(0, u.nanoseconds))
}

func (mt MonotonicTime) Milliseconds() int64 {
	return mt.nanoseconds / 1e6
}

type Clock interface {
	Now() time.Time

	NowMonotonic() MonotonicTime

	AfterFunc(d time.Duration, f func()) Timer
}

type Timer interface {
	Stop() bool

	Reset(d time.Duration)
}

type Address struct {
	addr   [16]byte
	length int
}

func AddrFrom4(addr [4]byte) Address {
	ret := Address{
		length: 4,
	}
	copy(ret.addr[:], addr[:])
	return ret
}

func AddrFrom4Slice(addr []byte) Address {
	if len(addr) != 4 {
		panic(fmt.Sprintf("bad address length for address %v", addr))
	}
	ret := Address{
		length: 4,
	}
	copy(ret.addr[:], addr)
	return ret
}

func AddrFrom16(addr [16]byte) Address {
	ret := Address{
		length: 16,
	}
	copy(ret.addr[:], addr[:])
	return ret
}

func AddrFrom16Slice(addr []byte) Address {
	if len(addr) != 16 {
		panic(fmt.Sprintf("bad address length for address %v", addr))
	}
	ret := Address{
		length: 16,
	}
	copy(ret.addr[:], addr)
	return ret
}

func AddrFromSlice(addr []byte) Address {
	switch len(addr) {
	case ipv4AddressSize:
		return AddrFrom4Slice(addr)
	case ipv6AddressSize:
		return AddrFrom16Slice(addr)
	}
	return Address{}
}

func (a Address) As4() [4]byte {
	if a.Len() != 4 {
		panic(fmt.Sprintf("bad address length for address %v", a.addr))
	}
	return [4]byte(a.addr[:4])
}

func (a Address) As16() [16]byte {
	if a.Len() != 16 {
		panic(fmt.Sprintf("bad address length for address %v", a.addr))
	}
	return [16]byte(a.addr[:16])
}

func (a *Address) AsSlice() []byte {
	return a.addr[:a.length]
}

func (a Address) BitLen() int {
	return a.Len() * 8
}

func (a Address) Len() int {
	return a.length
}

func (a Address) WithPrefix() AddressWithPrefix {
	return AddressWithPrefix{
		Address:   a,
		PrefixLen: a.BitLen(),
	}
}

func (a Address) Unspecified() bool {
	for _, b := range a.addr {
		if b != 0 {
			return false
		}
	}
	return true
}

func (a Address) Equal(other Address) bool {
	return a == other
}

func (a Address) MatchingPrefix(b Address) uint8 {
	const bitsInAByte = 8

	if a.Len() != b.Len() {
		panic(fmt.Sprintf("addresses %s and %s do not have the same length", a, b))
	}

	var prefix uint8
	for i := 0; i < a.length; i++ {
		aByte := a.addr[i]
		bByte := b.addr[i]

		if aByte == bByte {
			prefix += bitsInAByte
			continue
		}

		mask := uint8(1) << (bitsInAByte - 1)
		for {
			if aByte&mask == bByte&mask {
				prefix++
				mask >>= 1
				continue
			}

			break
		}

		break
	}

	return prefix
}

type AddressMask struct {
	mask   [16]byte
	length int
}

func MaskFrom(str string) AddressMask {
	mask := AddressMask{length: len(str)}
	copy(mask.mask[:], str)
	return mask
}

func MaskFromBytes(bs []byte) AddressMask {
	mask := AddressMask{length: len(bs)}
	copy(mask.mask[:], bs)
	return mask
}

func (m AddressMask) String() string {
	return fmt.Sprintf("%x", m.mask)
}

func (m *AddressMask) AsSlice() []byte {
	return []byte(m.mask[:m.length])
}

func (m AddressMask) BitLen() int {
	return m.length * 8
}

func (m AddressMask) Len() int {
	return m.length
}

func (m AddressMask) Prefix() int {
	p := 0
	for _, b := range m.mask[:m.length] {
		p += bits.LeadingZeros8(^b)
	}
	return p
}

func (m AddressMask) Equal(other AddressMask) bool {
	return m == other
}

type Subnet struct {
	address Address
	mask    AddressMask
}

func NewSubnet(a Address, m AddressMask) (Subnet, error) {
	if a.Len() != m.Len() {
		return Subnet{}, errSubnetLengthMismatch
	}
	for i := 0; i < a.Len(); i++ {
		if a.addr[i]&^m.mask[i] != 0 {
			return Subnet{}, errSubnetAddressMasked
		}
	}
	return Subnet{a, m}, nil
}

func (s Subnet) String() string {
	return fmt.Sprintf("%s/%d", s.ID(), s.Prefix())
}

func (s *Subnet) Contains(a Address) bool {
	if a.Len() != s.address.Len() {
		return false
	}
	for i := 0; i < a.Len(); i++ {
		if a.addr[i]&s.mask.mask[i] != s.address.addr[i] {
			return false
		}
	}
	return true
}

func (s *Subnet) ID() Address {
	return s.address
}

func (s *Subnet) Bits() (ones int, zeros int) {
	ones = s.mask.Prefix()
	return ones, s.mask.BitLen() - ones
}

func (s *Subnet) Prefix() int {
	return s.mask.Prefix()
}

func (s *Subnet) Mask() AddressMask {
	return s.mask
}

func (s *Subnet) Broadcast() Address {
	addrCopy := s.address
	for i := 0; i < addrCopy.Len(); i++ {
		addrCopy.addr[i] |= ^s.mask.mask[i]
	}
	return addrCopy
}

func (s *Subnet) IsBroadcast(address Address) bool {
	if address.Len() != ipv4AddressSize {
		return false
	}

	return s.Prefix() <= 30 && s.Broadcast() == address
}

func (s Subnet) Equal(o Subnet) bool {
	return s == o
}

type LinkAddress string

func (a LinkAddress) String() string {
	switch len(a) {
	case 6:
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

func ParseMACAddress(s string) (LinkAddress, error) {
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ':' || c == '-'
	})
	if len(parts) != LinkAddressSize {
		return "", fmt.Errorf("inconsistent parts: %s", s)
	}
	addr := make([]byte, 0, len(parts))
	for _, part := range parts {
		u, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex digits: %s", s)
		}
		addr = append(addr, byte(u))
	}
	return LinkAddress(addr), nil
}

func GetRandMacAddr() LinkAddress {
	mac := make(net.HardwareAddr, LinkAddressSize)
	rand.Read(mac)
	mac[0] &^= 0x1
	mac[0] |= 0x2
	return LinkAddress(mac)
}

type AddressWithPrefix struct {
	Address Address

	PrefixLen int
}

func (a AddressWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", a.Address, a.PrefixLen)
}

func (a AddressWithPrefix) Subnet() Subnet {
	addrLen := a.Address.length
	if a.PrefixLen <= 0 {
		return Subnet{
			address: Address{length: addrLen},
			mask:    AddressMask{length: addrLen},
		}
	}
	if a.PrefixLen >= addrLen*8 {
		sub := Subnet{
			address: a.Address,
			mask:    AddressMask{length: addrLen},
		}
		for i := 0; i < addrLen; i++ {
			sub.mask.mask[i] = 0xff
		}
		return sub
	}

	sa := Address{length: addrLen}
	sm := AddressMask{length: addrLen}
	n := uint(a.PrefixLen)
	for i := 0; i < addrLen; i++ {
		if n >= 8 {
			sa.addr[i] = a.Address.addr[i]
			sm.mask[i] = 0xff
			n -= 8
			continue
		}
		sm.mask[i] = ^byte(0xff >> n)
		sa.addr[i] = a.Address.addr[i] & sm.mask[i]
		n = 0
	}

	s, err := NewSubnet(sa, sm)
	if err != nil {
		panic("invalid subnet: " + err.Error())
	}
	return s
}

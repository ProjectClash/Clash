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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/metacubex/sing-tun/internal/gtcpip"
)

const (
	versTCFL = 0
	IPv6PayloadLenOffset = 4
	IPv6NextHeaderOffset = 6
	hopLimit             = 7
	v6SrcAddr            = 8
	v6DstAddr            = v6SrcAddr + IPv6AddressSize

	IPv6FixedHeaderSize = v6DstAddr + IPv6AddressSize
)

type IPv6Fields struct {
	TrafficClass uint8

	FlowLabel uint32

	PayloadLength uint16

	TransportProtocol tcpip.TransportProtocolNumber

	HopLimit uint8

	SrcAddr netip.Addr

	DstAddr netip.Addr

	ExtensionHeaders IPv6ExtHdrSerializer
}

type IPv6 []byte

const (
	IPv6MinimumSize = IPv6FixedHeaderSize

	IPv6AddressSize = 16

	IPv6AddressSizeBits = 128

	IPv6MaximumPayloadSize = 65535

	IPv6ProtocolNumber tcpip.NetworkProtocolNumber = 0x86dd

	IPv6Version = 6

	IIDSize = 8

	IPv6MinimumMTU = 1280

	IIDOffsetInIPv6Address = 8

	OpaqueIIDSecretKeyMinBytes = 16

	ipv6MulticastAddressScopeByteIdx = 1

	ipv6MulticastAddressScopeMask = 0xF
)

var (
	IPv6AllNodesMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	IPv6AllRoutersInterfaceLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	IPv6AllRoutersLinkLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	IPv6AllRoutersSiteLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	IPv6Loopback = tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	IPv6Any = tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
)

var IPv6EmptySubnet = tcpip.AddressWithPrefix{
	Address:   IPv6Any,
	PrefixLen: 0,
}.Subnet()

var IPv4MappedIPv6Subnet = tcpip.AddressWithPrefix{
	Address:   tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}),
	PrefixLen: 96,
}.Subnet()

var IPv6LinkLocalPrefix = tcpip.AddressWithPrefix{
	Address:   tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
	PrefixLen: 64,
}

func (b IPv6) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv6PayloadLenOffset:])
}

func (b IPv6) HopLimit() uint8 {
	return b[hopLimit]
}

func (b IPv6) NextHeader() uint8 {
	return b[IPv6NextHeaderOffset]
}

func (b IPv6) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}

func (b IPv6) Payload() []byte {
	return b[IPv6MinimumSize:][:b.PayloadLength()]
}

func (b IPv6) SourceAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(b[v6SrcAddr:][:IPv6AddressSize]))
}

func (b IPv6) DestinationAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(b[v6DstAddr:][:IPv6AddressSize]))
}

func (b IPv6) SourceAddressSlice() []byte {
	return []byte(b[v6SrcAddr:][:IPv6AddressSize])
}

func (b IPv6) DestinationAddressSlice() []byte {
	return []byte(b[v6DstAddr:][:IPv6AddressSize])
}

func (IPv6) Checksum() uint16 {
	return 0
}

func (b IPv6) TOS() (uint8, uint32) {
	v := binary.BigEndian.Uint32(b[versTCFL:])
	return uint8(v >> 20), v & 0xfffff
}

func (b IPv6) SetTOS(t uint8, l uint32) {
	vtf := (6 << 28) | (uint32(t) << 20) | (l & 0xfffff)
	binary.BigEndian.PutUint32(b[versTCFL:], vtf)
}

func (b IPv6) SetPayloadLength(payloadLength uint16) {
	binary.BigEndian.PutUint16(b[IPv6PayloadLenOffset:], payloadLength)
}

func (b IPv6) SetSourceAddress(addr tcpip.Address) {
	copy(b[v6SrcAddr:][:IPv6AddressSize], addr.AsSlice())
}

func (b IPv6) SetDestinationAddress(addr tcpip.Address) {
	copy(b[v6DstAddr:][:IPv6AddressSize], addr.AsSlice())
}

func (b IPv6) SetHopLimit(v uint8) {
	b[hopLimit] = v
}

func (b IPv6) SetNextHeader(v uint8) {
	b[IPv6NextHeaderOffset] = v
}

func (IPv6) SetChecksum(uint16) {
}

func (b IPv6) Encode(i *IPv6Fields) {
	extHdr := b[IPv6MinimumSize:]
	b.SetTOS(i.TrafficClass, i.FlowLabel)
	b.SetPayloadLength(i.PayloadLength)
	b[hopLimit] = i.HopLimit
	b.SetSourceAddr(i.SrcAddr)
	b.SetDestinationAddr(i.DstAddr)
	nextHeader, _ := i.ExtensionHeaders.Serialize(i.TransportProtocol, extHdr)
	b[IPv6NextHeaderOffset] = nextHeader
}

func (b IPv6) IsValid(pktSize int) bool {
	if len(b) < IPv6MinimumSize {
		return false
	}

	dlen := int(b.PayloadLength())
	if dlen > pktSize-IPv6MinimumSize {
		return false
	}

	if IPVersion(b) != IPv6Version {
		return false
	}

	return true
}

func IsV4MappedAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}

	return IPv4MappedIPv6Subnet.Contains(addr)
}

func IsV6MulticastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}
	return addr.As16()[0] == 0xff
}

func IsV6UnicastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}

	if addr == IPv6Any {
		return false
	}

	return addr.As16()[0] != 0xff
}

var solicitedNodeMulticastPrefix = [13]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff}

func SolicitedNodeAddr(addr tcpip.Address) tcpip.Address {
	addrBytes := addr.As16()
	return tcpip.AddrFrom16([16]byte(append(solicitedNodeMulticastPrefix[:], addrBytes[len(addrBytes)-3:]...)))
}

func IsSolicitedNodeAddr(addr tcpip.Address) bool {
	addrBytes := addr.As16()
	return solicitedNodeMulticastPrefix == [13]byte(addrBytes[:len(addrBytes)-3])
}

func EthernetAdddressToModifiedEUI64IntoBuf(linkAddr tcpip.LinkAddress, buf []byte) {
	buf[0] = linkAddr[0] ^ 2
	buf[1] = linkAddr[1]
	buf[2] = linkAddr[2]
	buf[3] = 0xFF
	buf[4] = 0xFE
	buf[5] = linkAddr[3]
	buf[6] = linkAddr[4]
	buf[7] = linkAddr[5]
}

func EthernetAddressToModifiedEUI64(linkAddr tcpip.LinkAddress) [IIDSize]byte {
	var buf [IIDSize]byte
	EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, buf[:])
	return buf
}

func LinkLocalAddr(linkAddr tcpip.LinkAddress) tcpip.Address {
	lladdrb := [IPv6AddressSize]byte{
		0: 0xFE,
		1: 0x80,
	}
	EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, lladdrb[IIDOffsetInIPv6Address:])
	return tcpip.AddrFrom16(lladdrb)
}

func IsV6LinkLocalUnicastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}
	addrBytes := addr.As16()
	return addrBytes[0] == 0xfe && (addrBytes[1]&0xc0) == 0x80
}

func IsV6LoopbackAddress(addr tcpip.Address) bool {
	return addr == IPv6Loopback
}

func IsV6LinkLocalMulticastAddress(addr tcpip.Address) bool {
	return IsV6MulticastAddress(addr) && V6MulticastScope(addr) == IPv6LinkLocalMulticastScope
}

func AppendOpaqueInterfaceIdentifier(buf []byte, prefix tcpip.Subnet, nicName string, dadCounter uint8, secretKey []byte) []byte {
	h := sha256.New()
	prefixID := prefix.ID()
	h.Write([]byte(prefixID.AsSlice()[:IIDOffsetInIPv6Address]))
	h.Write([]byte(nicName))
	h.Write([]byte{dadCounter})
	h.Write(secretKey)

	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])

	return append(buf, sum[:IIDSize]...)
}

func LinkLocalAddrWithOpaqueIID(nicName string, dadCounter uint8, secretKey []byte) tcpip.Address {
	lladdrb := [IPv6AddressSize]byte{
		0: 0xFE,
		1: 0x80,
	}

	return tcpip.AddrFrom16([16]byte(AppendOpaqueInterfaceIdentifier(lladdrb[:IIDOffsetInIPv6Address], IPv6LinkLocalPrefix.Subnet(), nicName, dadCounter, secretKey)))
}

type IPv6AddressScope int

const (
	LinkLocalScope IPv6AddressScope = iota

	GlobalScope
)

func ScopeForIPv6Address(addr tcpip.Address) (IPv6AddressScope, tcpip.Error) {
	if addr.BitLen() != IPv6AddressSizeBits {
		return GlobalScope, &tcpip.ErrBadAddress{}
	}

	switch {
	case IsV6LinkLocalMulticastAddress(addr):
		return LinkLocalScope, nil

	case IsV6LinkLocalUnicastAddress(addr):
		return LinkLocalScope, nil

	default:
		return GlobalScope, nil
	}
}

func GenerateTempIPv6SLAACAddr(tempIIDHistory []byte, stableAddr tcpip.Address) tcpip.AddressWithPrefix {
	addrBytes := stableAddr.As16()
	h := sha256.New()
	h.Write(tempIIDHistory)
	h.Write(addrBytes[IIDOffsetInIPv6Address:])
	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])

	if n := copy(tempIIDHistory, sum[sha256.Size-IIDSize:]); n != IIDSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, IIDSize))
	}

	if n := copy(addrBytes[IIDOffsetInIPv6Address:], sum); n != IIDSize {
		panic(fmt.Sprintf("copied %d IID bytes, expected %d bytes", n, IIDSize))
	}

	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom16(addrBytes),
		PrefixLen: IIDOffsetInIPv6Address * 8,
	}
}

type IPv6MulticastScope uint8

const (
	IPv6Reserved0MulticastScope         = IPv6MulticastScope(0x0)
	IPv6InterfaceLocalMulticastScope    = IPv6MulticastScope(0x1)
	IPv6LinkLocalMulticastScope         = IPv6MulticastScope(0x2)
	IPv6RealmLocalMulticastScope        = IPv6MulticastScope(0x3)
	IPv6AdminLocalMulticastScope        = IPv6MulticastScope(0x4)
	IPv6SiteLocalMulticastScope         = IPv6MulticastScope(0x5)
	IPv6OrganizationLocalMulticastScope = IPv6MulticastScope(0x8)
	IPv6GlobalMulticastScope            = IPv6MulticastScope(0xE)
	IPv6ReservedFMulticastScope         = IPv6MulticastScope(0xF)
)

func V6MulticastScope(addr tcpip.Address) IPv6MulticastScope {
	addrBytes := addr.As16()
	return IPv6MulticastScope(addrBytes[ipv6MulticastAddressScopeByteIdx] & ipv6MulticastAddressScopeMask)
}

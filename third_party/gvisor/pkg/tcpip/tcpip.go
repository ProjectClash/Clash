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

package tcpip

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/rand"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	ipv4AddressSize = 4
	ipv6AddressSize = 16
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

type ErrSaveRejection struct {
	Err error
}

func (e *ErrSaveRejection) Error() string {
	return "save rejected due to unsupported networking state: " + e.Err.Error()
}

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

type NICID int32

type ShutdownFlags int

const (
	ShutdownRead ShutdownFlags = 1 << iota
	ShutdownWrite
)

type PacketType uint8

const (
	PacketHost PacketType = iota

	PacketOtherHost

	PacketOutgoing

	PacketBroadcast

	PacketMulticast
)

type FullAddress struct {
	NIC NICID

	Addr Address

	Port uint16

	LinkAddr LinkAddress
}

type Payloader interface {
	io.Reader

	Len() int
}

var _ Payloader = (*bytes.Buffer)(nil)
var _ Payloader = (*bytes.Reader)(nil)

var _ io.Writer = (*SliceWriter)(nil)

type SliceWriter []byte

func (s *SliceWriter) Write(b []byte) (int, error) {
	n := copy(*s, b)
	*s = (*s)[n:]
	var err error
	if n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}

var _ io.Writer = (*LimitedWriter)(nil)

type LimitedWriter struct {
	W io.Writer
	N int64
}

func (l *LimitedWriter) Write(p []byte) (int, error) {
	pLen := int64(len(p))
	if pLen > l.N {
		p = p[:l.N]
	}
	n, err := l.W.Write(p)
	n64 := int64(n)
	if err == nil && n64 != pLen {
		err = io.ErrShortWrite
	}
	l.N -= n64
	return n, err
}

type SendableControlMessages struct {
	HasTTL bool

	TTL uint8

	HasHopLimit bool

	HopLimit uint8

	HasIPv6PacketInfo bool

	IPv6PacketInfo IPv6PacketInfo
}

type ReceivableControlMessages struct {
	Timestamp time.Time `state:".(int64)"`

	HasInq bool

	Inq int32

	HasTOS bool

	TOS uint8

	HasTTL bool

	TTL uint8

	HasHopLimit bool

	HopLimit uint8

	HasTimestamp bool

	HasTClass bool

	TClass uint32

	HasIPPacketInfo bool

	PacketInfo IPPacketInfo

	HasIPv6PacketInfo bool

	IPv6PacketInfo IPv6PacketInfo

	HasOriginalDstAddress bool

	OriginalDstAddress FullAddress

	SockErr *SockError
}

type PacketOwner interface {
	KUID() uint32

	KGID() uint32
}

type ReadOptions struct {
	Peek bool

	NeedRemoteAddr bool

	NeedLinkPacketInfo bool

	NeedReceivedExperimentOption bool
}

type ReadResult struct {
	Count int

	Total int

	ControlMessages ReceivableControlMessages

	RemoteAddr FullAddress

	LinkPacketInfo LinkPacketInfo

	ReceivedExperimentOption uint16
}

type Endpoint interface {
	Close()

	Abort()

	Read(io.Writer, ReadOptions) (ReadResult, Error)

	Write(Payloader, WriteOptions) (int64, Error)

	Connect(address FullAddress) Error

	Disconnect() Error

	Shutdown(flags ShutdownFlags) Error

	Listen(backlog int) Error

	Accept(peerAddr *FullAddress) (Endpoint, *waiter.Queue, Error)

	Bind(address FullAddress) Error

	GetLocalAddress() (FullAddress, Error)

	GetRemoteAddress() (FullAddress, Error)

	Readiness(mask waiter.EventMask) waiter.EventMask

	SetSockOpt(opt SettableSocketOption) Error

	SetSockOptInt(opt SockOptInt, v int) Error

	GetSockOpt(opt GettableSocketOption) Error

	GetSockOptInt(SockOptInt) (int, Error)

	State() uint32

	ModerateRecvBuf(copied int)

	Info() EndpointInfo

	Stats() EndpointStats

	SetOwner(owner PacketOwner)

	LastError() Error

	SocketOptions() *SocketOptions
}

type EndpointWithPreflight interface {
	Preflight(WriteOptions) Error
}

type LinkPacketInfo struct {
	Protocol NetworkProtocolNumber

	PktType PacketType
}

type EndpointInfo interface {
	IsEndpointInfo()
}

type EndpointStats interface {
	IsEndpointStats()
}

type WriteOptions struct {
	To *FullAddress

	More bool

	EndOfRecord bool

	Atomic bool

	ControlMessages SendableControlMessages
}

type SockOptInt int

const (
	KeepaliveCountOption SockOptInt = iota

	IPv4TOSOption

	IPv6TrafficClassOption

	MaxSegOption

	MTUDiscoverOption

	MulticastTTLOption

	ReceiveQueueSizeOption

	SendQueueSizeOption

	IPv4TTLOption

	IPv6HopLimitOption

	TCPSynCountOption

	TCPWindowClampOption

	IPv6Checksum

	PacketMMapVersionOption

	PacketMMapReserveOption

	IPv6MulticastInterfaceOption
)

const (
	UseDefaultIPv4TTL = 0

	UseDefaultIPv6HopLimit = -1
)

type PMTUDStrategy int

const (
	PMTUDiscoveryWant PMTUDStrategy = iota

	PMTUDiscoveryDont

	PMTUDiscoveryDo

	PMTUDiscoveryProbe
)

type GettableNetworkProtocolOption interface {
	isGettableNetworkProtocolOption()
}

type SettableNetworkProtocolOption interface {
	isSettableNetworkProtocolOption()
}

type DefaultTTLOption uint8

func (*DefaultTTLOption) isGettableNetworkProtocolOption() {}

func (*DefaultTTLOption) isSettableNetworkProtocolOption() {}

type GettableTransportProtocolOption interface {
	isGettableTransportProtocolOption()
}

type SettableTransportProtocolOption interface {
	isSettableTransportProtocolOption()
}

type TCPSACKEnabled bool

func (*TCPSACKEnabled) isGettableTransportProtocolOption() {}

func (*TCPSACKEnabled) isSettableTransportProtocolOption() {}

type TCPRecovery int32

func (*TCPRecovery) isGettableTransportProtocolOption() {}

func (*TCPRecovery) isSettableTransportProtocolOption() {}

type TCPAlwaysUseSynCookies bool

func (*TCPAlwaysUseSynCookies) isGettableTransportProtocolOption() {}

func (*TCPAlwaysUseSynCookies) isSettableTransportProtocolOption() {}

const (
	TCPRACKLossDetection TCPRecovery = 1 << iota

	TCPRACKStaticReoWnd

	TCPRACKNoDupTh
)

type TCPDelayEnabled bool

func (*TCPDelayEnabled) isGettableTransportProtocolOption() {}

func (*TCPDelayEnabled) isSettableTransportProtocolOption() {}

type TCPSendBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPSendBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPSendBufferSizeRangeOption) isSettableTransportProtocolOption() {}

type TCPReceiveBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPReceiveBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPReceiveBufferSizeRangeOption) isSettableTransportProtocolOption() {}

type TCPAvailableCongestionControlOption string

func (*TCPAvailableCongestionControlOption) isGettableTransportProtocolOption() {}

func (*TCPAvailableCongestionControlOption) isSettableTransportProtocolOption() {}

type TCPModerateReceiveBufferOption bool

func (*TCPModerateReceiveBufferOption) isGettableTransportProtocolOption() {}

func (*TCPModerateReceiveBufferOption) isSettableTransportProtocolOption() {}

type GettableSocketOption interface {
	isGettableSocketOption()
}

type SettableSocketOption interface {
	isSettableSocketOption()
}

type ICMPv6Filter struct {
	DenyType [8]uint32
}

func (f *ICMPv6Filter) ShouldDeny(icmpType uint8) bool {
	const bitsInUint32 = 32
	i := icmpType / bitsInUint32
	b := icmpType % bitsInUint32
	return f.DenyType[i]&(1<<b) != 0
}

func (*ICMPv6Filter) isGettableSocketOption() {}

func (*ICMPv6Filter) isSettableSocketOption() {}

type TpacketReq struct {
	TpBlockSize uint32
	TpBlockNr   uint32
	TpFrameSize uint32
	TpFrameNr   uint32
}

func (*TpacketReq) isSettableSocketOption() {}

type TpacketStats struct {
	Packets uint32
	Dropped uint32
}

func (*TpacketStats) isGettableSocketOption() {}

type EndpointState uint8

type CongestionControlState int

const (
	Open CongestionControlState = iota
	RTORecovery
	FastRecovery
	SACKRecovery
	Disorder
)

type TCPInfoOption struct {
	RTT time.Duration

	RTTVar time.Duration

	RTO time.Duration

	State EndpointState

	CcState CongestionControlState

	SndCwnd uint32

	SndSsthresh uint32

	ReorderSeen bool
}

func (*TCPInfoOption) isGettableSocketOption() {}

type KeepaliveIdleOption time.Duration

func (*KeepaliveIdleOption) isGettableSocketOption() {}

func (*KeepaliveIdleOption) isSettableSocketOption() {}

type KeepaliveIntervalOption time.Duration

func (*KeepaliveIntervalOption) isGettableSocketOption() {}

func (*KeepaliveIntervalOption) isSettableSocketOption() {}

type TCPUserTimeoutOption time.Duration

func (*TCPUserTimeoutOption) isGettableSocketOption() {}

func (*TCPUserTimeoutOption) isSettableSocketOption() {}

type CongestionControlOption string

func (*CongestionControlOption) isGettableSocketOption() {}

func (*CongestionControlOption) isSettableSocketOption() {}

func (*CongestionControlOption) isGettableTransportProtocolOption() {}

func (*CongestionControlOption) isSettableTransportProtocolOption() {}

type TCPLingerTimeoutOption time.Duration

func (*TCPLingerTimeoutOption) isGettableSocketOption() {}

func (*TCPLingerTimeoutOption) isSettableSocketOption() {}

func (*TCPLingerTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPLingerTimeoutOption) isSettableTransportProtocolOption() {}

type TCPTimeWaitTimeoutOption time.Duration

func (*TCPTimeWaitTimeoutOption) isGettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableTransportProtocolOption() {}

type TCPDeferAcceptOption time.Duration

func (*TCPDeferAcceptOption) isGettableSocketOption() {}

func (*TCPDeferAcceptOption) isSettableSocketOption() {}

type TCPMinRTOOption time.Duration

func (*TCPMinRTOOption) isGettableSocketOption() {}

func (*TCPMinRTOOption) isSettableSocketOption() {}

func (*TCPMinRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMinRTOOption) isSettableTransportProtocolOption() {}

type TCPMaxRTOOption time.Duration

func (*TCPMaxRTOOption) isGettableSocketOption() {}

func (*TCPMaxRTOOption) isSettableSocketOption() {}

func (*TCPMaxRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRTOOption) isSettableTransportProtocolOption() {}

type TCPMaxRetriesOption uint64

func (*TCPMaxRetriesOption) isGettableSocketOption() {}

func (*TCPMaxRetriesOption) isSettableSocketOption() {}

func (*TCPMaxRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRetriesOption) isSettableTransportProtocolOption() {}

type TCPSynRetriesOption uint8

func (*TCPSynRetriesOption) isGettableSocketOption() {}

func (*TCPSynRetriesOption) isSettableSocketOption() {}

func (*TCPSynRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPSynRetriesOption) isSettableTransportProtocolOption() {}

type MulticastInterfaceOption struct {
	NIC           NICID
	InterfaceAddr Address
}

func (*MulticastInterfaceOption) isGettableSocketOption() {}

func (*MulticastInterfaceOption) isSettableSocketOption() {}

type MembershipOption struct {
	NIC           NICID
	InterfaceAddr Address
	MulticastAddr Address
}

type AddMembershipOption MembershipOption

func (*AddMembershipOption) isSettableSocketOption() {}

type RemoveMembershipOption MembershipOption

func (*RemoveMembershipOption) isSettableSocketOption() {}

type SocketDetachFilterOption int

func (*SocketDetachFilterOption) isSettableSocketOption() {}

type OriginalDestinationOption FullAddress

func (*OriginalDestinationOption) isGettableSocketOption() {}

type TCPTimeWaitReuseOption uint8

func (*TCPTimeWaitReuseOption) isGettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isSettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitReuseOption) isSettableTransportProtocolOption() {}

const (
	TCPTimeWaitReuseDisabled TCPTimeWaitReuseOption = iota

	TCPTimeWaitReuseGlobal

	TCPTimeWaitReuseLoopbackOnly
)

type LingerOption struct {
	Enabled bool
	Timeout time.Duration
}

type IPPacketInfo struct {
	NIC NICID

	LocalAddr Address

	DestinationAddr Address
}

type IPv6PacketInfo struct {
	Addr Address
	NIC  NICID
}

type SendBufferSizeOption struct {
	Min int

	Default int

	Max int
}

type ReceiveBufferSizeOption struct {
	Min int

	Default int

	Max int
}

type GetSendBufferLimits func(StackHandler) SendBufferSizeOption

func GetStackSendBufferLimits(so StackHandler) SendBufferSizeOption {
	var ss SendBufferSizeOption
	if err := so.Option(&ss); err != nil {
		panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
	}
	return ss
}

type GetReceiveBufferLimits func(StackHandler) ReceiveBufferSizeOption

func GetStackReceiveBufferLimits(so StackHandler) ReceiveBufferSizeOption {
	var ss ReceiveBufferSizeOption
	if err := so.Option(&ss); err != nil {
		panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
	}
	return ss
}

type Route struct {
	RouteEntry

	Destination Subnet

	Gateway Address

	NIC NICID

	SourceHint Address

	MTU uint32
}

func (r Route) String() string {
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, "%s", r.Destination)
	if r.Gateway.length > 0 {
		_, _ = fmt.Fprintf(&out, " via %s", r.Gateway)
	}
	_, _ = fmt.Fprintf(&out, " nic %d", r.NIC)
	return out.String()
}

func (r Route) Equal(to Route) bool {
	return r.Destination.Equal(to.Destination) && r.NIC == to.NIC
}

type TransportProtocolNumber uint32

type NetworkProtocolNumber uint32

type StatCounter struct {
	count atomicbitops.Uint64
}

func (s *StatCounter) Increment() {
	s.IncrementBy(1)
}

func (s *StatCounter) Decrement() {
	s.IncrementBy(^uint64(0))
}

func (s *StatCounter) Value() uint64 {
	return s.count.Load()
}

func (s *StatCounter) IncrementBy(v uint64) {
	s.count.Add(v)
}

func (s *StatCounter) String() string {
	return strconv.FormatUint(s.Value(), 10)
}

type MultiCounterStat struct {
	a *StatCounter
	b *StatCounter
}

func (m *MultiCounterStat) Init(a, b *StatCounter) {
	m.a = a
	m.b = b
}

func (m *MultiCounterStat) Increment() {
	m.a.Increment()
	m.b.Increment()
}

func (m *MultiCounterStat) IncrementBy(v uint64) {
	m.a.IncrementBy(v)
	m.b.IncrementBy(v)
}

type ICMPv4PacketStats struct {

	EchoRequest *StatCounter

	EchoReply *StatCounter

	DstUnreachable *StatCounter

	SrcQuench *StatCounter

	Redirect *StatCounter

	TimeExceeded *StatCounter

	ParamProblem *StatCounter

	Timestamp *StatCounter

	TimestampReply *StatCounter

	InfoRequest *StatCounter

	InfoReply *StatCounter

}

type ICMPv4SentPacketStats struct {

	ICMPv4PacketStats

	Dropped *StatCounter

	RateLimited *StatCounter

}

type ICMPv4ReceivedPacketStats struct {

	ICMPv4PacketStats

	Invalid *StatCounter

}

type ICMPv4Stats struct {

	PacketsSent ICMPv4SentPacketStats

	PacketsReceived ICMPv4ReceivedPacketStats

}

type ICMPv6PacketStats struct {

	EchoRequest *StatCounter

	EchoReply *StatCounter

	DstUnreachable *StatCounter

	PacketTooBig *StatCounter

	TimeExceeded *StatCounter

	ParamProblem *StatCounter

	RouterSolicit *StatCounter

	RouterAdvert *StatCounter

	NeighborSolicit *StatCounter

	NeighborAdvert *StatCounter

	RedirectMsg *StatCounter

	MulticastListenerQuery *StatCounter

	MulticastListenerReport *StatCounter

	MulticastListenerReportV2 *StatCounter

	MulticastListenerDone *StatCounter

}

type ICMPv6SentPacketStats struct {

	ICMPv6PacketStats

	Dropped *StatCounter

	RateLimited *StatCounter

}

type ICMPv6ReceivedPacketStats struct {

	ICMPv6PacketStats

	Unrecognized *StatCounter

	Invalid *StatCounter

	RouterOnlyPacketsDroppedByHost *StatCounter

}

type ICMPv6Stats struct {

	PacketsSent ICMPv6SentPacketStats

	PacketsReceived ICMPv6ReceivedPacketStats

}

type ICMPStats struct {
	V4 ICMPv4Stats

	V6 ICMPv6Stats
}

type IGMPPacketStats struct {

	MembershipQuery *StatCounter

	V1MembershipReport *StatCounter

	V2MembershipReport *StatCounter

	V3MembershipReport *StatCounter

	LeaveGroup *StatCounter

}

type IGMPSentPacketStats struct {

	IGMPPacketStats

	Dropped *StatCounter

}

type IGMPReceivedPacketStats struct {

	IGMPPacketStats

	Invalid *StatCounter

	ChecksumErrors *StatCounter

	Unrecognized *StatCounter

}

type IGMPStats struct {

	PacketsSent IGMPSentPacketStats

	PacketsReceived IGMPReceivedPacketStats

}

type IPForwardingStats struct {

	Unrouteable *StatCounter

	ExhaustedTTL *StatCounter

	InitializingSource *StatCounter

	LinkLocalSource *StatCounter

	LinkLocalDestination *StatCounter

	PacketTooBig *StatCounter

	HostUnreachable *StatCounter

	ExtensionHeaderProblem *StatCounter

	UnexpectedMulticastInputInterface *StatCounter

	UnknownOutputEndpoint *StatCounter

	NoMulticastPendingQueueBufferSpace *StatCounter

	OutgoingDeviceNoBufferSpace *StatCounter

	Errors *StatCounter

	OutgoingDeviceClosedForSend *StatCounter

}

type IPStats struct {

	PacketsReceived *StatCounter

	ValidPacketsReceived *StatCounter

	DisabledPacketsReceived *StatCounter

	InvalidDestinationAddressesReceived *StatCounter

	InvalidSourceAddressesReceived *StatCounter

	PacketsDelivered *StatCounter

	PacketsSent *StatCounter

	OutgoingPacketErrors *StatCounter

	MalformedPacketsReceived *StatCounter

	MalformedFragmentsReceived *StatCounter

	IPTablesPreroutingDropped *StatCounter

	IPTablesInputDropped *StatCounter

	IPTablesForwardDropped *StatCounter

	IPTablesOutputDropped *StatCounter

	IPTablesPostroutingDropped *StatCounter

	OptionTimestampReceived *StatCounter

	OptionRecordRouteReceived *StatCounter

	OptionRouterAlertReceived *StatCounter

	OptionUnknownReceived *StatCounter

	Forwarding IPForwardingStats

}

type ARPStats struct {

	PacketsReceived *StatCounter

	DisabledPacketsReceived *StatCounter

	MalformedPacketsReceived *StatCounter

	RequestsReceived *StatCounter

	RequestsReceivedUnknownTargetAddress *StatCounter

	OutgoingRequestInterfaceHasNoLocalAddressErrors *StatCounter

	OutgoingRequestBadLocalAddressErrors *StatCounter

	OutgoingRequestsDropped *StatCounter

	OutgoingRequestsSent *StatCounter

	RepliesReceived *StatCounter

	OutgoingRepliesDropped *StatCounter

	OutgoingRepliesSent *StatCounter

}

type TCPStats struct {
	ActiveConnectionOpenings *StatCounter

	PassiveConnectionOpenings *StatCounter

	CurrentEstablished *StatCounter

	CurrentConnected *StatCounter

	EstablishedResets *StatCounter

	EstablishedClosed *StatCounter

	EstablishedTimedout *StatCounter

	ListenOverflowSynDrop *StatCounter

	ListenOverflowAckDrop *StatCounter

	ListenOverflowSynCookieSent *StatCounter

	ListenOverflowSynCookieRcvd *StatCounter

	ListenOverflowInvalidSynCookieRcvd *StatCounter

	FailedConnectionAttempts *StatCounter

	ValidSegmentsReceived *StatCounter

	InvalidSegmentsReceived *StatCounter

	SegmentsSent *StatCounter

	SegmentSendErrors *StatCounter

	ResetsSent *StatCounter

	ResetsReceived *StatCounter

	Retransmits *StatCounter

	FastRecovery *StatCounter

	SACKRecovery *StatCounter

	TLPRecovery *StatCounter

	SlowStartRetransmits *StatCounter

	FastRetransmit *StatCounter

	Timeouts *StatCounter

	ChecksumErrors *StatCounter

	FailedPortReservations *StatCounter

	SegmentsAckedWithDSACK *StatCounter

	SpuriousRecovery *StatCounter

	SpuriousRTORecovery *StatCounter

	ForwardMaxInFlightDrop *StatCounter
}

type UDPStats struct {
	PacketsReceived *StatCounter

	UnknownPortErrors *StatCounter

	ReceiveBufferErrors *StatCounter

	MalformedPacketsReceived *StatCounter

	PacketsSent *StatCounter

	PacketSendErrors *StatCounter

	ChecksumErrors *StatCounter
}

type NICNeighborStats struct {

	UnreachableEntryLookups *StatCounter

	DroppedConfirmationForNoninitiatedNeighbor *StatCounter

	DroppedInvalidLinkAddressConfirmations *StatCounter

}

type NICPacketStats struct {

	Packets *StatCounter

	Bytes *StatCounter

}

type IntegralStatCounterMap struct {
	mu sync.RWMutex `state:"nosave"`
	counterMap map[uint64]*StatCounter
}

func (m *IntegralStatCounterMap) Keys() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []uint64
	for k := range m.counterMap {
		keys = append(keys, k)
	}
	return keys
}

func (m *IntegralStatCounterMap) Get(key uint64) (*StatCounter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	counter, ok := m.counterMap[key]
	return counter, ok
}

func (m *IntegralStatCounterMap) Init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counterMap = make(map[uint64]*StatCounter)
}

func (m *IntegralStatCounterMap) Increment(key uint64) {
	m.mu.RLock()
	counter, ok := m.counterMap[key]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		counter, ok = m.counterMap[key]
		if !ok {
			counter = new(StatCounter)
			m.counterMap[key] = counter
		}
		m.mu.Unlock()
	}
	counter.Increment()
}

type MultiIntegralStatCounterMap struct {
	a *IntegralStatCounterMap
	b *IntegralStatCounterMap
}

func (m *MultiIntegralStatCounterMap) Init(a, b *IntegralStatCounterMap) {
	m.a = a
	m.b = b
}

func (m *MultiIntegralStatCounterMap) Increment(key uint64) {
	m.a.Increment(key)
	m.b.Increment(key)
}

type NICStats struct {

	UnknownL3ProtocolRcvdPacketCounts *IntegralStatCounterMap

	UnknownL4ProtocolRcvdPacketCounts *IntegralStatCounterMap

	MalformedL4RcvdPackets *StatCounter

	Tx NICPacketStats

	TxPacketsDroppedNoBufferSpace *StatCounter

	Rx NICPacketStats

	DisabledRx NICPacketStats

	Neighbor NICNeighborStats

}

func (s NICStats) FillIn() NICStats {
	InitStatCounters(reflect.ValueOf(&s).Elem())
	return s
}

type Stats struct {

	DroppedPackets *StatCounter

	NICs NICStats

	ICMP ICMPStats

	IGMP IGMPStats

	IP IPStats

	ARP ARPStats

	TCP TCPStats

	UDP UDPStats
}

type ReceiveErrors struct {
	ReceiveBufferOverflow StatCounter

	MalformedPacketsReceived StatCounter

	ClosedReceiver StatCounter

	ChecksumErrors StatCounter
}

type SendErrors struct {
	SendToNetworkFailed StatCounter

	NoRoute StatCounter
}

type ReadErrors struct {
	ReadClosed StatCounter

	InvalidEndpointState StatCounter

	NotConnected StatCounter
}

type WriteErrors struct {
	WriteClosed StatCounter

	InvalidEndpointState StatCounter

	InvalidArgs StatCounter
}

type TransportEndpointStats struct {
	PacketsReceived StatCounter

	PacketsSent StatCounter

	ReceiveErrors ReceiveErrors

	ReadErrors ReadErrors

	SendErrors SendErrors

	WriteErrors WriteErrors
}

func (*TransportEndpointStats) IsEndpointStats() {}

func InitStatCounters(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		if s, ok := v.Addr().Interface().(**StatCounter); ok {
			if *s == nil {
				*s = new(StatCounter)
			}
		} else if s, ok := v.Addr().Interface().(**IntegralStatCounterMap); ok {
			if *s == nil {
				*s = new(IntegralStatCounterMap)
				(*s).Init()
			}
		} else {
			InitStatCounters(v)
		}
	}
}

func (s Stats) FillIn() Stats {
	InitStatCounters(reflect.ValueOf(&s).Elem())
	return s
}

func (src *TransportEndpointStats) Clone(dst *TransportEndpointStats) {
	clone(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem())
}

func clone(dst reflect.Value, src reflect.Value) {
	for i := 0; i < dst.NumField(); i++ {
		d := dst.Field(i)
		s := src.Field(i)
		if c, ok := s.Addr().Interface().(*StatCounter); ok {
			d.Addr().Interface().(*StatCounter).IncrementBy(c.Value())
		} else {
			clone(d, s)
		}
	}
}

func (a Address) String() string {
	switch l := a.Len(); l {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", int(a.addr[0]), int(a.addr[1]), int(a.addr[2]), int(a.addr[3]))
	case 16:
		start, end := -1, -1
		for i := 0; i < a.Len(); i += 2 {
			j := i
			for j < a.Len() && a.addr[j] == 0 && a.addr[j+1] == 0 {
				j += 2
			}
			if j > i+2 && j-i > end-start {
				start, end = i, j
			}
		}

		var b strings.Builder
		for i := 0; i < a.Len(); i += 2 {
			if i == start {
				b.WriteString("::")
				i = end
				if end >= a.Len() {
					break
				}
			} else if i > 0 {
				b.WriteByte(':')
			}
			v := uint16(a.addr[i+0])<<8 | uint16(a.addr[i+1])
			if v == 0 {
				b.WriteByte('0')
			} else {
				const digits = "0123456789abcdef"
				for i := uint(3); i < 4; i-- {
					if v := v >> (i * 4); v != 0 {
						b.WriteByte(digits[v&0xf])
					}
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprintf("%x", a.addr[:l])
	}
}

func (a Address) To4() Address {
	const (
		ipv4len = 4
		ipv6len = 16
	)
	if a.Len() == ipv4len {
		return a
	}
	if a.Len() == ipv6len &&
		isZeros(a.addr[:10]) &&
		a.addr[10] == 0xff &&
		a.addr[11] == 0xff {
		return AddrFrom4Slice(a.addr[12:16])
	}
	return Address{}
}

func isZeros(addr []byte) bool {
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
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

type ProtocolAddress struct {
	Protocol NetworkProtocolNumber

	AddressWithPrefix AddressWithPrefix
}

var (
	danglingEndpointsMu sync.Mutex

	danglingEndpoints = make(map[Endpoint]struct{})
)

func GetDanglingEndpoints() []Endpoint {
	danglingEndpointsMu.Lock()
	es := make([]Endpoint, 0, len(danglingEndpoints))
	for e := range danglingEndpoints {
		es = append(es, e)
	}
	danglingEndpointsMu.Unlock()
	return es
}

func ReleaseDanglingEndpoints() {
	eps := GetDanglingEndpoints()
	for _, ep := range eps {
		ep.Abort()
	}
}

func AddDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	danglingEndpoints[e] = struct{}{}
	danglingEndpointsMu.Unlock()
}

func DeleteDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	delete(danglingEndpoints, e)
	danglingEndpointsMu.Unlock()
}

var AsyncLoading sync.WaitGroup

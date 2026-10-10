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

package stack

import (
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type NetworkEndpointID struct {
	LocalAddress tcpip.Address
}

type TransportEndpointID struct {
	LocalPort uint16

	LocalAddress tcpip.Address

	RemotePort uint16

	RemoteAddress tcpip.Address
}

type NetworkPacketInfo struct {
	LocalAddressBroadcast bool

	LocalAddressTemporary bool

	IsForwardedPacket bool
}

type TransportErrorKind int

const (
	PacketTooBigTransportError TransportErrorKind = iota

	DestinationHostUnreachableTransportError

	DestinationPortUnreachableTransportError

	DestinationNetworkUnreachableTransportError

	DestinationProtoUnreachableTransportError

	SourceRouteFailedTransportError

	SourceHostIsolatedTransportError

	DestinationHostDownTransportError
)

type TransportError interface {
	tcpip.SockErrorCause

	Kind() TransportErrorKind
}

type TransportEndpoint interface {
	HandlePacket(TransportEndpointID, *PacketBuffer)

	HandleError(TransportError, *PacketBuffer)

	Abort()

	Wait()
}

type RawTransportEndpoint interface {
	HandlePacket(*PacketBuffer)
}

type PacketEndpoint interface {
	HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

type MappablePacketEndpoint interface {
	PacketEndpoint

	GetPacketMMapOpts(req *tcpip.TpacketReq, isRx bool) PacketMMapOpts

	SetPacketMMapEndpoint(ep PacketMMapEndpoint)

	GetPacketMMapEndpoint() PacketMMapEndpoint

	HandlePacketMMapCopy(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

type PacketMMapOpts struct {
	Req            *tcpip.TpacketReq
	IsRx           bool
	Cooked         bool
	Stack          *Stack
	Wq             *waiter.Queue
	PacketEndpoint MappablePacketEndpoint
	Version        int
	Reserve        uint32
}

type PacketMMapEndpoint interface {
	HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *PacketBuffer) bool

	Close()

	Readiness(mask waiter.EventMask) waiter.EventMask

	Stats() tcpip.TpacketStats
}

type UnknownDestinationPacketDisposition int

const (
	UnknownDestinationPacketMalformed UnknownDestinationPacketDisposition = iota

	UnknownDestinationPacketUnhandled

	UnknownDestinationPacketHandled
)

type TransportProtocol interface {
	Number() tcpip.TransportProtocolNumber

	NewEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	MinimumPacketSize() int

	ParsePorts(b []byte) (src, dst uint16, err tcpip.Error)

	HandleUnknownDestinationPacket(TransportEndpointID, *PacketBuffer) UnknownDestinationPacketDisposition

	SetOption(option tcpip.SettableTransportProtocolOption) tcpip.Error

	Option(option tcpip.GettableTransportProtocolOption) tcpip.Error

	Close()

	Wait()

	Pause()

	Resume()

	Restore()

	Parse(pkt *PacketBuffer) (ok bool)
}

type TransportPacketDisposition int

const (
	TransportPacketHandled TransportPacketDisposition = iota

	TransportPacketProtocolUnreachable

	TransportPacketDestinationPortUnreachable
)

type TransportDispatcher interface {
	DeliverTransportPacket(tcpip.TransportProtocolNumber, *PacketBuffer) TransportPacketDisposition

	DeliverTransportError(local, remote tcpip.Address, _ tcpip.NetworkProtocolNumber, _ tcpip.TransportProtocolNumber, _ TransportError, _ *PacketBuffer)

	DeliverRawPacket(tcpip.TransportProtocolNumber, *PacketBuffer)
}

type TransportDispatcherWithDefaultHandlerResult interface {
	TransportDispatcher

	DeliverTransportPacketWithDefaultHandlerResult(tcpip.TransportProtocolNumber, *PacketBuffer) (TransportPacketDisposition, bool)
}

type PacketLooping byte

const (
	PacketOut PacketLooping = 1 << iota

	PacketLoop
)

type NetworkHeaderParams struct {
	Protocol tcpip.TransportProtocolNumber

	TTL uint8

	TOS uint8

	DF bool

	ExperimentOptionValue uint16
}

type GroupAddressableEndpoint interface {
	JoinGroup(group tcpip.Address) tcpip.Error

	LeaveGroup(group tcpip.Address) tcpip.Error

	IsInGroup(group tcpip.Address) bool
}

type PrimaryEndpointBehavior int

const (
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	FirstPrimaryEndpoint

	NeverPrimaryEndpoint
)

func (peb PrimaryEndpointBehavior) String() string {
	switch peb {
	case CanBePrimaryEndpoint:
		return "CanBePrimaryEndpoint"
	case FirstPrimaryEndpoint:
		return "FirstPrimaryEndpoint"
	case NeverPrimaryEndpoint:
		return "NeverPrimaryEndpoint"
	default:
		panic(fmt.Sprintf("unknown primary endpoint behavior: %d", peb))
	}
}

type AddressConfigType int

const (
	AddressConfigStatic AddressConfigType = iota

	AddressConfigSlaac
)

type AddressLifetimes struct {
	Deprecated bool

	PreferredUntil tcpip.MonotonicTime

	ValidUntil tcpip.MonotonicTime
}

type AddressProperties struct {
	PEB        PrimaryEndpointBehavior
	ConfigType AddressConfigType
	Lifetimes AddressLifetimes
	Temporary bool
	Disp      AddressDispatcher
}

type AddressAssignmentState int

const (
	_ AddressAssignmentState = iota

	AddressDisabled

	AddressTentative

	AddressAssigned
)

func (state AddressAssignmentState) String() string {
	switch state {
	case AddressDisabled:
		return "Disabled"
	case AddressTentative:
		return "Tentative"
	case AddressAssigned:
		return "Assigned"
	default:
		panic(fmt.Sprintf("unknown address assignment state: %d", state))
	}
}

type AddressRemovalReason int

const (
	_ AddressRemovalReason = iota

	AddressRemovalManualAction

	AddressRemovalInterfaceRemoved

	AddressRemovalDADFailed

	AddressRemovalInvalidated
)

func (reason AddressRemovalReason) String() string {
	switch reason {
	case AddressRemovalManualAction:
		return "ManualAction"
	case AddressRemovalInterfaceRemoved:
		return "InterfaceRemoved"
	case AddressRemovalDADFailed:
		return "DADFailed"
	case AddressRemovalInvalidated:
		return "Invalidated"
	default:
		panic(fmt.Sprintf("unknown address removal reason: %d", reason))
	}
}

type AddressDispatcher interface {
	OnChanged(AddressLifetimes, AddressAssignmentState)

	OnRemoved(AddressRemovalReason)
}

type AssignableAddressEndpoint interface {
	AddressWithPrefix() tcpip.AddressWithPrefix

	Subnet() tcpip.Subnet

	IsAssigned(allowExpired bool) bool

	TryIncRef() bool

	DecRef()
}

type AddressEndpoint interface {
	AssignableAddressEndpoint

	GetKind() AddressKind

	SetKind(AddressKind)

	ConfigType() AddressConfigType

	Deprecated() bool

	SetDeprecated(bool)

	Lifetimes() AddressLifetimes

	SetLifetimes(AddressLifetimes)

	Temporary() bool

	RegisterDispatcher(AddressDispatcher)
}

type AddressKind int

const (
	PermanentTentative AddressKind = iota

	Permanent

	PermanentExpired

	Temporary
)

func (k AddressKind) IsPermanent() bool {
	switch k {
	case Permanent, PermanentTentative:
		return true
	case Temporary, PermanentExpired:
		return false
	default:
		panic(fmt.Sprintf("unrecognized address kind = %d", k))
	}
}

type AddressableEndpoint interface {
	AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error)

	RemovePermanentAddress(addr tcpip.Address) tcpip.Error

	SetLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error

	MainAddress() tcpip.AddressWithPrefix

	AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior, readOnly bool) AddressEndpoint

	AcquireOutgoingPrimaryAddress(remoteAddr, srcHint tcpip.Address, allowExpired bool) AddressEndpoint

	PrimaryAddresses() []tcpip.AddressWithPrefix

	PermanentAddresses() []tcpip.AddressWithPrefix
}

type NDPEndpoint interface {
	NetworkEndpoint

	InvalidateDefaultRouter(tcpip.Address)
}

type NetworkInterface interface {
	NetworkLinkEndpoint

	ID() tcpip.NICID

	IsLoopback() bool

	Name() string

	Enabled() bool

	Promiscuous() bool

	Spoofing() bool

	AllowPromiscuousSource() bool

	PrimaryAddress(tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error)

	CheckLocalAddress(tcpip.NetworkProtocolNumber, tcpip.Address) bool

	WritePacketToRemote(tcpip.LinkAddress, *PacketBuffer) tcpip.Error

	WritePacket(*Route, *PacketBuffer) tcpip.Error

	HandleNeighborProbe(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress) tcpip.Error

	HandleNeighborConfirmation(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress, ReachabilityConfirmationFlags) tcpip.Error
}

type LinkResolvableNetworkEndpoint interface {
	HandleLinkResolutionFailure(*PacketBuffer)
}

type NetworkEndpoint interface {
	Enable() tcpip.Error

	Enabled() bool

	Disable()

	DefaultTTL() uint8

	MTU() uint32

	EndpointHeaderSize() uint32

	MaxHeaderLength() uint16

	WritePacket(r *Route, params NetworkHeaderParams, pkt *PacketBuffer) tcpip.Error

	WriteHeaderIncludedPacket(r *Route, pkt *PacketBuffer) tcpip.Error

	HandlePacket(pkt *PacketBuffer)

	Close()

	NetworkProtocolNumber() tcpip.NetworkProtocolNumber

	Stats() NetworkEndpointStats
}

type NetworkEndpointStats interface {
	IsNetworkEndpointStats()
}

type IPNetworkEndpointStats interface {
	NetworkEndpointStats

	IPStats() *tcpip.IPStats
}

type ForwardingNetworkEndpoint interface {
	NetworkEndpoint

	Forwarding() bool

	SetForwarding(bool) bool
}

type MulticastForwardingNetworkEndpoint interface {
	ForwardingNetworkEndpoint

	MulticastForwarding() bool

	SetMulticastForwarding(bool) bool
}

type NetworkProtocol interface {
	Number() tcpip.NetworkProtocolNumber

	MinimumPacketSize() int

	ParseAddresses(b []byte) (src, dst tcpip.Address)

	NewEndpoint(nic NetworkInterface, dispatcher TransportDispatcher) NetworkEndpoint

	SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error

	Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error

	Close()

	Wait()

	Parse(pkt *PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool)
}

type UnicastSourceAndMulticastDestination struct {
	Source tcpip.Address
	Destination tcpip.Address
}

type MulticastRouteOutgoingInterface struct {
	ID tcpip.NICID

	MinTTL uint8
}

type MulticastRoute struct {
	ExpectedInputInterface tcpip.NICID

	OutgoingInterfaces []MulticastRouteOutgoingInterface
}

type MulticastForwardingNetworkProtocol interface {
	NetworkProtocol

	AddMulticastRoute(UnicastSourceAndMulticastDestination, MulticastRoute) tcpip.Error

	RemoveMulticastRoute(UnicastSourceAndMulticastDestination) tcpip.Error

	MulticastRouteLastUsedTime(UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, tcpip.Error)

	EnableMulticastForwarding(MulticastForwardingEventDispatcher) (bool, tcpip.Error)

	DisableMulticastForwarding()
}

type MulticastPacketContext struct {
	SourceAndDestination UnicastSourceAndMulticastDestination
	InputInterface tcpip.NICID
}

type MulticastForwardingEventDispatcher interface {
	OnMissingRoute(MulticastPacketContext)

	OnUnexpectedInputInterface(context MulticastPacketContext, expectedInputInterface tcpip.NICID)
}

type NetworkDispatcher interface {
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

	DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

type LinkEndpointCapabilities uint

const (
	CapabilityNone LinkEndpointCapabilities = 0
	CapabilityTXChecksumOffload LinkEndpointCapabilities = 1 << iota
	CapabilityRXChecksumOffload
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityLoopback
)

type LinkWriter interface {
	WritePackets(PacketBufferList) (int, tcpip.Error)
}

type NetworkLinkEndpoint interface {
	MTU() uint32

	SetMTU(mtu uint32)

	MaxHeaderLength() uint16

	LinkAddress() tcpip.LinkAddress

	SetLinkAddress(addr tcpip.LinkAddress)

	Capabilities() LinkEndpointCapabilities

	Attach(dispatcher NetworkDispatcher)

	IsAttached() bool

	Wait()

	ARPHardwareType() header.ARPHardwareType

	AddHeader(*PacketBuffer)

	ParseHeader(*PacketBuffer) bool

	Close()

	SetOnCloseAction(func())
}

type QueueingDiscipline interface {
	WritePacket(*PacketBuffer) tcpip.Error

	Close()
}

type LinkEndpoint interface {
	NetworkLinkEndpoint
	LinkWriter
}

type InjectableLinkEndpoint interface {
	LinkEndpoint

	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

	InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error
}

type DADResult interface {
	isDADResult()
}

var _ DADResult = (*DADSucceeded)(nil)

type DADSucceeded struct{}

func (*DADSucceeded) isDADResult() {}

var _ DADResult = (*DADError)(nil)

type DADError struct {
	Err tcpip.Error
}

func (*DADError) isDADResult() {}

var _ DADResult = (*DADAborted)(nil)

type DADAborted struct{}

func (*DADAborted) isDADResult() {}

var _ DADResult = (*DADDupAddrDetected)(nil)

type DADDupAddrDetected struct {
	HolderLinkAddress tcpip.LinkAddress
}

func (*DADDupAddrDetected) isDADResult() {}

type DADCompletionHandler func(DADResult)

type DADCheckAddressDisposition int

const (
	_ DADCheckAddressDisposition = iota

	DADDisabled

	DADStarting

	DADAlreadyRunning
)

const (
	defaultDupAddrDetectTransmits = 1
)

type DADConfigurations struct {
	DupAddrDetectTransmits uint8

	RetransmitTimer time.Duration
}

func DefaultDADConfigurations() DADConfigurations {
	return DADConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
	}
}

func (c *DADConfigurations) Validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

type DuplicateAddressDetector interface {
	CheckDuplicateAddress(tcpip.Address, DADCompletionHandler) DADCheckAddressDisposition

	SetDADConfigurations(c DADConfigurations)

	DuplicateAddressProtocol() tcpip.NetworkProtocolNumber
}

type LinkAddressResolver interface {
	LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error

	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

type RawFactory interface {
	NewUnassociatedEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	NewPacketEndpoint(stack *Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)
}

type GSOType int

const (
	GSONone GSOType = iota

	GSOTCPv4
	GSOTCPv6

	GSOGvisor
)

type GSO struct {
	Type GSOType
	NeedsCsum bool
	CsumOffset uint16

	MSS uint16
	L3HdrLen uint16

	MaxSize uint32
}

type SupportedGSO int

const (
	GSONotSupported SupportedGSO = iota

	HostGSOSupported

	GVisorGSOSupported
)

type GSOEndpoint interface {
	GSOMaxSize() uint32

	SupportedGSO() SupportedGSO
}

const GVisorGSOMaxSize = 1 << 16

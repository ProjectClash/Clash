/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	anySize                  = 1
	maxDNSSuffixStringLength = 256
	maxDHCPv6DUIDLength      = 130
	ifMaxStringSize          = 256
	ifMaxPhysAddressLength   = 32
)

type AddressFamily uint16

type IPAAFlags uint32

const (
	IPAAFlagDdnsEnabled IPAAFlags = 1 << iota
	IPAAFlagRegisterAdapterSuffix
	IPAAFlagDhcpv4Enabled
	IPAAFlagReceiveOnly
	IPAAFlagNoMulticast
	IPAAFlagIpv6OtherStatefulConfig
	IPAAFlagNetbiosOverTcpipEnabled
	IPAAFlagIpv4Enabled
	IPAAFlagIpv6Enabled
	IPAAFlagIpv6ManagedAddressConfigurationSupported
)

type IfOperStatus uint32

const (
	IfOperStatusUp IfOperStatus = iota + 1
	IfOperStatusDown
	IfOperStatusTesting
	IfOperStatusUnknown
	IfOperStatusDormant
	IfOperStatusNotPresent
	IfOperStatusLowerLayerDown
)

type IfType uint32

const (
	IfTypeOther                         IfType = 1
	IfTypeRegular1822                          = 2
	IfTypeHdh1822                              = 3
	IfTypeDdnX25                               = 4
	IfTypeRfc877X25                            = 5
	IfTypeEthernetCSMACD                       = 6
	IfTypeISO88023CSMACD                       = 7
	IfTypeISO88024Tokenbus                     = 8
	IfTypeISO88025Tokenring                    = 9
	IfTypeISO88026Man                          = 10
	IfTypeStarlan                              = 11
	IfTypeProteon10Mbit                        = 12
	IfTypeProteon80Mbit                        = 13
	IfTypeHyperchannel                         = 14
	IfTypeFddi                                 = 15
	IfTypeLapB                                 = 16
	IfTypeSdlc                                 = 17
	IfTypeDs1                                  = 18
	IfTypeE1                                   = 19
	IfTypeBasicISDN                            = 20
	IfTypePrimaryISDN                          = 21
	IfTypePropPoint2PointSerial                = 22
	IfTypePPP                                  = 23
	IfTypeSoftwareLoopback                     = 24
	IfTypeEon                                  = 25
	IfTypeEthernet3Mbit                        = 26
	IfTypeNsip                                 = 27
	IfTypeSlip                                 = 28
	IfTypeUltra                                = 29
	IfTypeDs3                                  = 30
	IfTypeSip                                  = 31
	IfTypeFramerelay                           = 32
	IfTypeRs232                                = 33
	IfTypePara                                 = 34
	IfTypeArcnet                               = 35
	IfTypeArcnetPlus                           = 36
	IfTypeAtm                                  = 37
	IfTypeMioX25                               = 38
	IfTypeSonet                                = 39
	IfTypeX25Ple                               = 40
	IfTypeIso88022LLC                          = 41
	IfTypeLocaltalk                            = 42
	IfTypeSmdsDxi                              = 43
	IfTypeFramerelayService                    = 44
	IfTypeV35                                  = 45
	IfTypeHssi                                 = 46
	IfTypeHippi                                = 47
	IfTypeModem                                = 48
	IfTypeAal5                                 = 49
	IfTypeSonetPath                            = 50
	IfTypeSonetVt                              = 51
	IfTypeSmdsIcip                             = 52
	IfTypePropVirtual                          = 53
	IfTypePropMultiplexor                      = 54
	IfTypeIEEE80212                            = 55
	IfTypeFibrechannel                         = 56
	IfTypeHippiinterface                       = 57
	IfTypeFramerelayInterconnect               = 58
	IfTypeAflane8023                           = 59
	IfTypeAflane8025                           = 60
	IfTypeCctemul                              = 61
	IfTypeFastether                            = 62
	IfTypeISDN                                 = 63
	IfTypeV11                                  = 64
	IfTypeV36                                  = 65
	IfTypeG703_64k                             = 66
	IfTypeG703_2mb                             = 67
	IfTypeQllc                                 = 68
	IfTypeFastetherFX                          = 69
	IfTypeChannel                              = 70
	IfTypeIEEE80211                            = 71
	IfTypeIBM370parchan                        = 72
	IfTypeEscon                                = 73
	IfTypeDlsw                                 = 74
	IfTypeISDNS                                = 75
	IfTypeISDNU                                = 76
	IfTypeLapD                                 = 77
	IfTypeIpswitch                             = 78
	IfTypeRsrb                                 = 79
	IfTypeAtmLogical                           = 80
	IfTypeDs0                                  = 81
	IfTypeDs0Bundle                            = 82
	IfTypeBsc                                  = 83
	IfTypeAsync                                = 84
	IfTypeCnr                                  = 85
	IfTypeIso88025rDtr                         = 86
	IfTypeEplrs                                = 87
	IfTypeArap                                 = 88
	IfTypePropCnls                             = 89
	IfTypeHostpad                              = 90
	IfTypeTermpad                              = 91
	IfTypeFramerelayMpi                        = 92
	IfTypeX213                                 = 93
	IfTypeAdsl                                 = 94
	IfTypeRadsl                                = 95
	IfTypeSdsl                                 = 96
	IfTypeVdsl                                 = 97
	IfTypeIso88025Crfprint                     = 98
	IfTypeMyrinet                              = 99
	IfTypeVoiceEm                              = 100
	IfTypeVoiceFxo                             = 101
	IfTypeVoiceFxs                             = 102
	IfTypeVoiceEncap                           = 103
	IfTypeVoiceOverip                          = 104
	IfTypeAtmDxi                               = 105
	IfTypeAtmFuni                              = 106
	IfTypeAtmIma                               = 107
	IfTypePPPmultilinkbundle                   = 108
	IfTypeIpoverCdlc                           = 109
	IfTypeIpoverClaw                           = 110
	IfTypeStacktostack                         = 111
	IfTypeVirtualipaddress                     = 112
	IfTypeMpc                                  = 113
	IfTypeIpoverAtm                            = 114
	IfTypeIso88025Fiber                        = 115
	IfTypeTdlc                                 = 116
	IfTypeGigabitethernet                      = 117
	IfTypeHdlc                                 = 118
	IfTypeLapF                                 = 119
	IfTypeV37                                  = 120
	IfTypeX25Mlp                               = 121
	IfTypeX25Huntgroup                         = 122
	IfTypeTransphdlc                           = 123
	IfTypeInterleave                           = 124
	IfTypeFast                                 = 125
	IfTypeIP                                   = 126
	IfTypeDocscableMaclayer                    = 127
	IfTypeDocscableDownstream                  = 128
	IfTypeDocscableUpstream                    = 129
	IfTypeA12mppswitch                         = 130
	IfTypeTunnel                               = 131
	IfTypeCoffee                               = 132
	IfTypeCes                                  = 133
	IfTypeAtmSubinterface                      = 134
	IfTypeL2Vlan                               = 135
	IfTypeL3Ipvlan                             = 136
	IfTypeL3Ipxvlan                            = 137
	IfTypeDigitalpowerline                     = 138
	IfTypeMediamailoverip                      = 139
	IfTypeDtm                                  = 140
	IfTypeDcn                                  = 141
	IfTypeIpforward                            = 142
	IfTypeMsdsl                                = 143
	IfTypeIEEE1394                             = 144
	IfTypeIfGsn                                = 145
	IfTypeDvbrccMaclayer                       = 146
	IfTypeDvbrccDownstream                     = 147
	IfTypeDvbrccUpstream                       = 148
	IfTypeAtmVirtual                           = 149
	IfTypeMplsTunnel                           = 150
	IfTypeSrp                                  = 151
	IfTypeVoiceoveratm                         = 152
	IfTypeVoiceoverframerelay                  = 153
	IfTypeIdsl                                 = 154
	IfTypeCompositelink                        = 155
	IfTypeSs7Siglink                           = 156
	IfTypePropWirelessP2P                      = 157
	IfTypeFrForward                            = 158
	IfTypeRfc1483                              = 159
	IfTypeUsb                                  = 160
	IfTypeIEEE8023adLag                        = 161
	IfTypeBgpPolicyAccounting                  = 162
	IfTypeFrf16MfrBundle                       = 163
	IfTypeH323Gatekeeper                       = 164
	IfTypeH323Proxy                            = 165
	IfTypeMpls                                 = 166
	IfTypeMfSiglink                            = 167
	IfTypeHdsl2                                = 168
	IfTypeShdsl                                = 169
	IfTypeDs1Fdl                               = 170
	IfTypePos                                  = 171
	IfTypeDvbAsiIn                             = 172
	IfTypeDvbAsiOut                            = 173
	IfTypePlc                                  = 174
	IfTypeNfas                                 = 175
	IfTypeTr008                                = 176
	IfTypeGr303Rdt                             = 177
	IfTypeGr303Idt                             = 178
	IfTypeIsup                                 = 179
	IfTypePropDocsWirelessMaclayer             = 180
	IfTypePropDocsWirelessDownstream           = 181
	IfTypePropDocsWirelessUpstream             = 182
	IfTypeHiperlan2                            = 183
	IfTypePropBwaP2MP                          = 184
	IfTypeSonetOverheadChannel                 = 185
	IfTypeDigitalWrapperOverheadChannel        = 186
	IfTypeAal2                                 = 187
	IfTypeRadioMac                             = 188
	IfTypeAtmRadio                             = 189
	IfTypeImt                                  = 190
	IfTypeMvl                                  = 191
	IfTypeReachDsl                             = 192
	IfTypeFrDlciEndpt                          = 193
	IfTypeAtmVciEndpt                          = 194
	IfTypeOpticalChannel                       = 195
	IfTypeOpticalTransport                     = 196
	IfTypeIEEE80216Wman                        = 237
	IfTypeWwanpp                               = 243
	IfTypeWwanpp2                              = 244
	IfTypeIEEE802154                           = 259
	IfTypeXboxWireless                         = 281
)

type MibIfEntryLevel uint32

const (
	MibIfEntryNormal                  MibIfEntryLevel = 0
	MibIfEntryNormalWithoutStatistics                 = 2
)

type NdisMedium uint32

const (
	NdisMedium802_3 NdisMedium = iota
	NdisMedium802_5
	NdisMediumFddi
	NdisMediumWan
	NdisMediumLocalTalk
	NdisMediumDix
	NdisMediumArcnetRaw
	NdisMediumArcnet878_2
	NdisMediumAtm
	NdisMediumWirelessWan
	NdisMediumIrda
	NdisMediumBpc
	NdisMediumCoWan
	NdisMedium1394
	NdisMediumInfiniBand
	NdisMediumTunnel
	NdisMediumNative802_11
	NdisMediumLoopback
	NdisMediumWiMAX
	NdisMediumIP
	NdisMediumMax
)

type NdisPhysicalMedium uint32

const (
	NdisPhysicalMediumUnspecified NdisPhysicalMedium = iota
	NdisPhysicalMediumWirelessLan
	NdisPhysicalMediumCableModem
	NdisPhysicalMediumPhoneLine
	NdisPhysicalMediumPowerLine
	NdisPhysicalMediumDSL
	NdisPhysicalMediumFibreChannel
	NdisPhysicalMedium1394
	NdisPhysicalMediumWirelessWan
	NdisPhysicalMediumNative802_11
	NdisPhysicalMediumBluetooth
	NdisPhysicalMediumInfiniband
	NdisPhysicalMediumWiMax
	NdisPhysicalMediumUWB
	NdisPhysicalMedium802_3
	NdisPhysicalMedium802_5
	NdisPhysicalMediumIrda
	NdisPhysicalMediumWiredWAN
	NdisPhysicalMediumWiredCoWan
	NdisPhysicalMediumOther
	NdisPhysicalMediumNative802_15_4
	NdisPhysicalMediumMax
)

type NetIfAccessType uint32

const (
	NetIfAccessLoopback NetIfAccessType = iota + 1
	NetIfAccessBroadcast
	NetIfAccessPointToPoint
	NetIfAccessPointToMultiPoint
	NetIfAccessMax
)

type NetIfAdminStatus uint32

const (
	NetIfAdminStatusUp NetIfAdminStatus = iota + 1
	NetIfAdminStatusDown
	NetIfAdminStatusTesting
)

type NetIfConnectionType uint32

const (
	NetIfConnectionDedicated NetIfConnectionType = iota + 1
	NetIfConnectionPassive
	NetIfConnectionDemand
	NetIfConnectionMaximum
)

type NetIfDirectionType uint32

const (
	NetIfDirectionSendReceive NetIfDirectionType = iota
	NetIfDirectionSendOnly
	NetIfDirectionReceiveOnly
	NetIfDirectionMaximum
)

type NetIfMediaConnectState uint32

const (
	MediaConnectStateUnknown NetIfMediaConnectState = iota
	MediaConnectStateConnected
	MediaConnectStateDisconnected
)

type DadState uint32

const (
	DadStateInvalid DadState = iota
	DadStateTentative
	DadStateDuplicate
	DadStateDeprecated
	DadStatePreferred
)

type PrefixOrigin uint32

const (
	PrefixOriginOther PrefixOrigin = iota
	PrefixOriginManual
	PrefixOriginWellKnown
	PrefixOriginDHCP
	PrefixOriginRouterAdvertisement
	PrefixOriginUnchanged = 1 << 4
)

type LinkLocalAddressBehavior int32

const (
	LinkLocalAddressAlwaysOff LinkLocalAddressBehavior = iota
	LinkLocalAddressDelayed
	LinkLocalAddressAlwaysOn
	LinkLocalAddressUnchanged = -1
)

type OffloadRod uint8

const (
	ChecksumSupported OffloadRod = 1 << iota
	OptionsSupported
	DatagramChecksumSupported
	StreamChecksumSupported
	StreamOptionsSupported
	FastPathCompatible
	LargeSendOffloadSupported
	GiantSendOffloadSupported
)

type RouteOrigin uint32

const (
	RouteOriginManual RouteOrigin = iota
	RouteOriginWellKnown
	RouteOriginDHCP
	RouteOriginRouterAdvertisement
	RouteOrigin6to4
)

type RouteProtocol uint32

const (
	RouteProtocolOther RouteProtocol = iota + 1
	RouteProtocolLocal
	RouteProtocolNetMgmt
	RouteProtocolIcmp
	RouteProtocolEgp
	RouteProtocolGgp
	RouteProtocolHello
	RouteProtocolRip
	RouteProtocolIsIs
	RouteProtocolEsIs
	RouteProtocolCisco
	RouteProtocolBbn
	RouteProtocolOspf
	RouteProtocolBgp
	RouteProtocolIdpr
	RouteProtocolEigrp
	RouteProtocolDvmrp
	RouteProtocolRpl
	RouteProtocolDHCP
	RouteProtocolNTAutostatic   = 10002
	RouteProtocolNTStatic       = 10006
	RouteProtocolNTStaticNonDOD = 10007
)

type RouterDiscoveryBehavior int32

const (
	RouterDiscoveryDisabled RouterDiscoveryBehavior = iota
	RouterDiscoveryEnabled
	RouterDiscoveryDHCP
	RouterDiscoveryUnchanged = -1
)

type SuffixOrigin uint32

const (
	SuffixOriginOther SuffixOrigin = iota
	SuffixOriginManual
	SuffixOriginWellKnown
	SuffixOriginDHCP
	SuffixOriginLinkLayerAddress
	SuffixOriginRandom
	SuffixOriginUnchanged = 1 << 4
)

type MibNotificationType uint32

const (
	MibParameterNotification MibNotificationType = iota
	MibAddInstance
	MibDeleteInstance
	MibInitialNotification
)

type ChangeCallback interface {
	Unregister() error
}

type TunnelType uint32

const (
	TunnelTypeNone    TunnelType = 0
	TunnelTypeOther              = 1
	TunnelTypeDirect             = 2
	TunnelType6to4               = 11
	TunnelTypeIsatap             = 13
	TunnelTypeTeredo             = 14
	TunnelTypeIPHTTPS            = 15
)

type InterfaceAndOperStatusFlags uint8

const (
	IAOSFHardwareInterface InterfaceAndOperStatusFlags = 1 << iota
	IAOSFFilterInterface
	IAOSFConnectorPresent
	IAOSFNotAuthenticated
	IAOSFNotMediaConnected
	IAOSFPaused
	IAOSFLowPower
	IAOSFEndPointInterface
)

type GAAFlags uint32

const (
	GAAFlagSkipUnicast GAAFlags = 1 << iota
	GAAFlagSkipAnycast
	GAAFlagSkipMulticast
	GAAFlagSkipDNSServer
	GAAFlagIncludePrefix
	GAAFlagSkipFriendlyName
	GAAFlagIncludeWinsInfo
	GAAFlagIncludeGateways
	GAAFlagIncludeAllInterfaces
	GAAFlagIncludeAllCompartments
	GAAFlagIncludeTunnelBindingOrder
	GAAFlagSkipDNSInfo

	GAAFlagDefault    GAAFlags = 0
	GAAFlagSkipAll             = GAAFlagSkipUnicast | GAAFlagSkipAnycast | GAAFlagSkipMulticast | GAAFlagSkipDNSServer | GAAFlagSkipFriendlyName | GAAFlagSkipDNSInfo
	GAAFlagIncludeAll          = GAAFlagIncludePrefix | GAAFlagIncludeWinsInfo | GAAFlagIncludeGateways | GAAFlagIncludeAllInterfaces | GAAFlagIncludeAllCompartments | GAAFlagIncludeTunnelBindingOrder
)

type ScopeLevel uint32

const (
	ScopeLevelInterface    ScopeLevel = 1
	ScopeLevelLink                    = 2
	ScopeLevelSubnet                  = 3
	ScopeLevelAdmin                   = 4
	ScopeLevelSite                    = 5
	ScopeLevelOrganization            = 8
	ScopeLevelGlobal                  = 14
	ScopeLevelCount                   = 16
)

type RouteData struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Metric      uint32
}

func (routeData *RouteData) String() string {
	return fmt.Sprintf("%+v", *routeData)
}

type IPAdapterDNSSuffix struct {
	Next *IPAdapterDNSSuffix
	str  [maxDNSSuffixStringLength]uint16
}

func (obj *IPAdapterDNSSuffix) String() string {
	return windows.UTF16ToString(obj.str[:])
}

func (addr *IPAdapterAddresses) AdapterName() string {
	return windows.BytePtrToString(addr.adapterName)
}

func (addr *IPAdapterAddresses) DNSSuffix() string {
	if addr.dnsSuffix == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.dnsSuffix)
}

func (addr *IPAdapterAddresses) Description() string {
	if addr.description == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.description)
}

func (addr *IPAdapterAddresses) FriendlyName() string {
	if addr.friendlyName == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.friendlyName)
}

func (addr *IPAdapterAddresses) PhysicalAddress() []byte {
	return addr.physicalAddress[:addr.physicalAddressLength]
}

func (addr *IPAdapterAddresses) DHCPv6ClientDUID() []byte {
	return addr.dhcpv6ClientDUID[:addr.dhcpv6ClientDUIDLength]
}

func (row *MibIPInterfaceRow) Init() {
	initializeIPInterfaceEntry(row)
}

func (row *MibIPInterfaceRow) get() error {
	if err := getIPInterfaceEntry(row); err != nil {
		return err
	}

	switch row.Family {
	case windows.AF_INET:
		if row.SitePrefixLength > 32 {
			row.SitePrefixLength = 0
		}
	case windows.AF_INET6:
		if row.SitePrefixLength > 128 {
			row.SitePrefixLength = 128
		}
	}

	return nil
}

func (row *MibIPInterfaceRow) Set() error {
	return setIPInterfaceEntry(row)
}

func (tab *mibIPInterfaceTable) get() (s []MibIPInterfaceRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

func (tab *mibIPInterfaceTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

func (row *MibIfRow2) Alias() string {
	return windows.UTF16ToString(row.alias[:])
}

func (row *MibIfRow2) Description() string {
	return windows.UTF16ToString(row.description[:])
}

func (row *MibIfRow2) PhysicalAddress() []byte {
	return row.physicalAddress[:row.physicalAddressLength]
}

func (row *MibIfRow2) PermanentPhysicalAddress() []byte {
	return row.permanentPhysicalAddress[:row.physicalAddressLength]
}

func (row *MibIfRow2) get() (ret error) {
	return getIfEntry2(row)
}

func (tab *mibIfTable2) get() (s []MibIfRow2) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

func (tab *mibIfTable2) free() {
	freeMibTable(unsafe.Pointer(tab))
}

type RawSockaddrInet struct {
	Family AddressFamily
	data   [26]byte
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&i))[:])
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (addr *RawSockaddrInet) SetAddrPort(addrPort netip.AddrPort) error {
	if addrPort.Addr().Is4() {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		addr4.Family = windows.AF_INET
		addr4.Addr = addrPort.Addr().As4()
		addr4.Port = htons(addrPort.Port())
		for i := 0; i < 8; i++ {
			addr4.Zero[i] = 0
		}
		return nil
	} else if addrPort.Addr().Is6() {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		addr6.Family = windows.AF_INET6
		addr6.Addr = addrPort.Addr().As16()
		addr6.Port = htons(addrPort.Port())
		addr6.Flowinfo = 0
		scopeId := uint32(0)
		if z := addrPort.Addr().Zone(); z != "" {
			if s, err := strconv.ParseUint(z, 10, 32); err == nil {
				scopeId = uint32(s)
			}
		}
		addr6.Scope_id = scopeId
		return nil
	}
	return windows.ERROR_INVALID_PARAMETER
}

func (addr *RawSockaddrInet) SetAddr(netAddr netip.Addr) error {
	return addr.SetAddrPort(netip.AddrPortFrom(netAddr, 0))
}

func (addr *RawSockaddrInet) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr(), addr.Port())
}

func (addr *RawSockaddrInet) Addr() netip.Addr {
	switch addr.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Addr)
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		a := netip.AddrFrom16(raw.Addr)
		if raw.Scope_id != 0 {
			a = a.WithZone(strconv.FormatUint(uint64(raw.Scope_id), 10))
		}
		return a
	}
	return netip.Addr{}
}

func (addr *RawSockaddrInet) Port() uint16 {
	switch addr.Family {
	case windows.AF_INET:
		return ntohs((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Port)
	case windows.AF_INET6:
		return ntohs((*windows.RawSockaddrInet6)(unsafe.Pointer(addr)).Port)
	}
	return 0
}

func (row *MibUnicastIPAddressRow) Init() {
	initializeUnicastIPAddressEntry(row)
}

func (row *MibUnicastIPAddressRow) get() error {
	return getUnicastIPAddressEntry(row)
}

func (row *MibUnicastIPAddressRow) Set() error {
	return setUnicastIPAddressEntry(row)
}

func (row *MibUnicastIPAddressRow) Create() error {
	return createUnicastIPAddressEntry(row)
}

func (row *MibUnicastIPAddressRow) Delete() error {
	return deleteUnicastIPAddressEntry(row)
}

func (tab *mibUnicastIPAddressTable) get() (s []MibUnicastIPAddressRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

func (tab *mibUnicastIPAddressTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

func (row *MibAnycastIPAddressRow) get() error {
	return getAnycastIPAddressEntry(row)
}

func (row *MibAnycastIPAddressRow) Create() error {
	return createAnycastIPAddressEntry(row)
}

func (row *MibAnycastIPAddressRow) Delete() error {
	return deleteAnycastIPAddressEntry(row)
}

func (tab *mibAnycastIPAddressTable) get() (s []MibAnycastIPAddressRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

func (tab *mibAnycastIPAddressTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

type IPAddressPrefix struct {
	RawPrefix    RawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

func (prefix *IPAddressPrefix) SetPrefix(netPrefix netip.Prefix) error {
	err := prefix.RawPrefix.SetAddr(netPrefix.Addr())
	if err != nil {
		return err
	}
	prefix.PrefixLength = uint8(netPrefix.Bits())
	return nil
}

func (prefix *IPAddressPrefix) Prefix() netip.Prefix {
	switch prefix.RawPrefix.Family {
	case windows.AF_INET:
		return netip.PrefixFrom(netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	case windows.AF_INET6:
		return netip.PrefixFrom(netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	}
	return netip.Prefix{}
}

type MibIPforwardRow2 struct {
	InterfaceLUID        LUID
	InterfaceIndex       uint32
	DestinationPrefix    IPAddressPrefix
	NextHop              RawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             RouteProtocol
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               RouteOrigin
}

func (row *MibIPforwardRow2) Init() {
	initializeIPForwardEntry(row)
}

func (row *MibIPforwardRow2) get() error {
	return getIPForwardEntry2(row)
}

func (row *MibIPforwardRow2) Set() error {
	return setIPForwardEntry2(row)
}

func (row *MibIPforwardRow2) Create() error {
	return createIPForwardEntry2(row)
}

func (row *MibIPforwardRow2) Delete() error {
	return deleteIPForwardEntry2(row)
}

func (tab *mibIPforwardTable2) get() (s []MibIPforwardRow2) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

func (tab *mibIPforwardTable2) free() {
	freeMibTable(unsafe.Pointer(tab))
}


type DnsInterfaceSettings struct {
	Version             uint32
	_                   [4]byte
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

const (
	DnsInterfaceSettingsVersion1 = 1
	DnsInterfaceSettingsVersion2 = 2
	DnsInterfaceSettingsVersion3 = 3

	DnsInterfaceSettingsFlagIPv6                        = 0x0001
	DnsInterfaceSettingsFlagNameserver                  = 0x0002
	DnsInterfaceSettingsFlagSearchList                  = 0x0004
	DnsInterfaceSettingsFlagRegistrationEnabled         = 0x0008
	DnsInterfaceSettingsFlagRegisterAdapterName         = 0x0010
	DnsInterfaceSettingsFlagDomain                      = 0x0020
	DnsInterfaceSettingsFlagHostname                    = 0x0040
	DnsInterfaceSettingsFlagEnableLLMNR                 = 0x0080
	DnsInterfaceSettingsFlagQueryAdapterName            = 0x0100
	DnsInterfaceSettingsFlagProfileNameserver           = 0x0200
	DnsInterfaceSettingsFlagDisableUnconstrainedQueries = 0x0400
	DnsInterfaceSettingsFlagSupplementalSearchList      = 0x0800
	DnsInterfaceSettingsFlagDOH                         = 0x1000
	DnsInterfaceSettingsFlagDOHProfile                  = 0x2000
)

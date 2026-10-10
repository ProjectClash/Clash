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

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"

	"github.com/metacubex/gvisor/pkg/marshal"
)

const (
	AF_UNSPEC     = 0
	AF_UNIX       = 1
	AF_INET       = 2
	AF_AX25       = 3
	AF_IPX        = 4
	AF_APPLETALK  = 5
	AF_NETROM     = 6
	AF_BRIDGE     = 7
	AF_ATMPVC     = 8
	AF_X25        = 9
	AF_INET6      = 10
	AF_ROSE       = 11
	AF_DECnet     = 12
	AF_NETBEUI    = 13
	AF_SECURITY   = 14
	AF_KEY        = 15
	AF_NETLINK    = 16
	AF_PACKET     = 17
	AF_ASH        = 18
	AF_ECONET     = 19
	AF_ATMSVC     = 20
	AF_RDS        = 21
	AF_SNA        = 22
	AF_IRDA       = 23
	AF_PPPOX      = 24
	AF_WANPIPE    = 25
	AF_LLC        = 26
	AF_IB         = 27
	AF_MPLS       = 28
	AF_CAN        = 29
	AF_TIPC       = 30
	AF_BLUETOOTH  = 31
	AF_IUCV       = 32
	AF_RXRPC      = 33
	AF_ISDN       = 34
	AF_PHONET     = 35
	AF_IEEE802154 = 36
	AF_CAIF       = 37
	AF_ALG        = 38
	AF_NFC        = 39
	AF_VSOCK      = 40
)

const (
	MSG_OOB              = 0x1
	MSG_PEEK             = 0x2
	MSG_DONTROUTE        = 0x4
	MSG_TRYHARD          = 0x4
	MSG_CTRUNC           = 0x8
	MSG_PROBE            = 0x10
	MSG_TRUNC            = 0x20
	MSG_DONTWAIT         = 0x40
	MSG_EOR              = 0x80
	MSG_WAITALL          = 0x100
	MSG_FIN              = 0x200
	MSG_EOF              = MSG_FIN
	MSG_SYN              = 0x400
	MSG_CONFIRM          = 0x800
	MSG_RST              = 0x1000
	MSG_ERRQUEUE         = 0x2000
	MSG_NOSIGNAL         = 0x4000
	MSG_MORE             = 0x8000
	MSG_WAITFORONE       = 0x10000
	MSG_SENDPAGE_NOTLAST = 0x20000
	MSG_ZEROCOPY         = 0x4000000
	MSG_FASTOPEN         = 0x20000000
	MSG_CMSG_CLOEXEC     = 0x40000000
)

const (
	SOL_IP      = 0
	SOL_SOCKET  = 1
	SOL_TCP     = 6
	SOL_UDP     = 17
	SOL_IPV6    = 41
	SOL_ICMPV6  = 58
	SOL_RAW     = 255
	SOL_PACKET  = 263
	SOL_NETLINK = 270
)

type SockType int

const (
	SOCK_STREAM    SockType = 1
	SOCK_DGRAM     SockType = 2
	SOCK_RAW       SockType = 3
	SOCK_RDM       SockType = 4
	SOCK_SEQPACKET SockType = 5
	SOCK_DCCP      SockType = 6
	SOCK_PACKET    SockType = 10
)

const SOCK_TYPE_MASK = 0xf

const (
	SOCK_CLOEXEC  = O_CLOEXEC
	SOCK_NONBLOCK = O_NONBLOCK
)

const (
	SHUT_RD   = 0
	SHUT_WR   = 1
	SHUT_RDWR = 2
)

const (
	PACKET_HOST      = 0
	PACKET_BROADCAST = 1
	PACKET_MULTICAST = 2
	PACKET_OTHERHOST = 3
	PACKET_OUTGOING  = 4
)

const (
	PACKET_ADD_MEMBERSHIP = 1
	PACKET_RX_RING        = 5
	PACKET_STATISTICS     = 6
	PACKET_AUXDATA        = 8
	PACKET_VERSION        = 10
	PACKET_HDRLEN         = 11
	PACKET_RESERVE        = 12
)

const (
	TP_STATUS_KERNEL          = 0
	TP_STATUS_USER            = 0x1
	TP_STATUS_COPY            = 0x2
	TP_STATUS_LOSING          = 0x4
	TP_STATUS_CSUM_NOT_READY  = 0x8
	TP_STATUS_VLAN_VALID      = 0x10
	TP_STATUS_BLK_TMO         = 0x20
	TP_STATUS_VLAN_TPID_VALID = 0x40
	TP_STATUS_CSUM_VALID      = 0x80
	TP_STATUS_GSO_TCP         = 0x100
)

type TpacketReq struct {
	_           structs.HostLayout
	TpBlockSize uint32
	TpBlockNr   uint32
	TpFrameSize uint32
	TpFrameNr   uint32
}

type TpacketHdr struct {
	_         structs.HostLayout
	TpStatus  uint64
	TpLen     uint32
	TpSnaplen uint32
	TpMac     uint16
	TpNet     uint16
	TpSec     uint32
	TpUsec    uint32
	_         [4]uint8
}

type Tpacket2Hdr struct {
	_          structs.HostLayout
	TpStatus   uint32
	TpLen      uint32
	TpSnaplen  uint32
	TpMac      uint16
	TpNet      uint16
	TpSec      uint32
	TpNSec     uint32
	TpVlanTci  uint16
	TpVlanTpid uint16
	_          [4]uint8
}

type TpacketStats struct {
	_       structs.HostLayout
	Packets uint32
	Dropped uint32
}

const (
	TPACKET_ALIGNMENT = 16
)

const (
	TPACKET_V1 = iota
	TPACKET_V2
)

var (
	TPACKET_HDRLEN = TPacketAlign(uint32((*TpacketHdr)(nil).SizeBytes()) + uint32((*SockAddrLink)(nil).SizeBytes()))
	TPACKET2_HDRLEN = TPacketAlign(uint32((*Tpacket2Hdr)(nil).SizeBytes()) + uint32((*SockAddrLink)(nil).SizeBytes()))
)

func TPacketAlign(x uint32) uint32 {
	return (x + TPACKET_ALIGNMENT - 1) &^ (TPACKET_ALIGNMENT - 1)
}

const (
	SO_DEBUG                 = 1
	SO_REUSEADDR             = 2
	SO_TYPE                  = 3
	SO_ERROR                 = 4
	SO_DONTROUTE             = 5
	SO_BROADCAST             = 6
	SO_SNDBUF                = 7
	SO_RCVBUF                = 8
	SO_KEEPALIVE             = 9
	SO_OOBINLINE             = 10
	SO_NO_CHECK              = 11
	SO_PRIORITY              = 12
	SO_LINGER                = 13
	SO_BSDCOMPAT             = 14
	SO_REUSEPORT             = 15
	SO_PASSCRED              = 16
	SO_PEERCRED              = 17
	SO_RCVLOWAT              = 18
	SO_SNDLOWAT              = 19
	SO_RCVTIMEO              = 20
	SO_SNDTIMEO              = 21
	SO_BINDTODEVICE          = 25
	SO_ATTACH_FILTER         = 26
	SO_DETACH_FILTER         = 27
	SO_GET_FILTER            = SO_ATTACH_FILTER
	SO_PEERNAME              = 28
	SO_TIMESTAMP             = 29
	SO_ACCEPTCONN            = 30
	SO_PEERSEC               = 31
	SO_SNDBUFFORCE           = 32
	SO_RCVBUFFORCE           = 33
	SO_PASSSEC               = 34
	SO_TIMESTAMPNS           = 35
	SO_MARK                  = 36
	SO_TIMESTAMPING          = 37
	SO_PROTOCOL              = 38
	SO_DOMAIN                = 39
	SO_RXQ_OVFL              = 40
	SO_WIFI_STATUS           = 41
	SO_PEEK_OFF              = 42
	SO_NOFCS                 = 43
	SO_LOCK_FILTER           = 44
	SO_SELECT_ERR_QUEUE      = 45
	SO_BUSY_POLL             = 46
	SO_MAX_PACING_RATE       = 47
	SO_BPF_EXTENSIONS        = 48
	SO_INCOMING_CPU          = 49
	SO_ATTACH_BPF            = 50
	SO_ATTACH_REUSEPORT_CBPF = 51
	SO_ATTACH_REUSEPORT_EBPF = 52
	SO_CNX_ADVICE            = 53
	SO_MEMINFO               = 55
	SO_INCOMING_NAPI_ID      = 56
	SO_COOKIE                = 57
	SO_PEERGROUPS            = 59
	SO_ZEROCOPY              = 60
	SO_TXTIME                = 61
	SO_BINDTOIFINDEX         = 62
	SO_TIMESTAMP_OLD         = 29
	SO_TIMESTAMPNS_OLD       = 35
	SO_TIMESTAMPING_OLD      = 37
	SO_TIMESTAMP_NEW         = 63
	SO_TIMESTAMPNS_NEW       = 64
	SO_TIMESTAMPING_NEW      = 65
	SO_RCVTIMEO_NEW          = 66
	SO_SNDTIMEO_NEW          = 67
	SO_DETACH_REUSEPORT_BPF  = 68
	SO_PREFER_BUSY_POLL      = 69
	SO_BUSY_POLL_BUDGET      = 70
	SO_NETNS_COOKIE          = 71
	SO_BUF_LOCK              = 72
	SO_RESERVE_MEM           = 73
	SO_TXREHASH              = 74
	SO_RCVMARK               = 75
	SO_PASSPIDFD             = 76
	SO_PEERPIDFD             = 77
	SO_DEVMEM_LINEAR         = 78
	SO_DEVMEM_DMABUF         = 79
	SO_DEVMEM_DONTNEED       = 80
	SO_RCVPRIORITY           = 82
)

const (
	SS_FREE          = 0
	SS_UNCONNECTED   = 1
	SS_CONNECTING    = 2
	SS_CONNECTED     = 3
	SS_DISCONNECTING = 4
)

const (
	TCP_ESTABLISHED uint32 = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	TCP_NEW_SYN_RECV
)

const SockAddrMax = 128

type InetAddr [4]byte

var SizeOfInetAddr = uint32((*InetAddr)(nil).SizeBytes())

type SockAddrInet struct {
	_      structs.HostLayout
	Family uint16
	Port   uint16
	Addr   InetAddr
	_      [8]uint8
}

type Inet6MulticastRequest struct {
	_              structs.HostLayout
	MulticastAddr  Inet6Addr
	InterfaceIndex int32
}

type InetMulticastRequest struct {
	_             structs.HostLayout
	MulticastAddr InetAddr
	InterfaceAddr InetAddr
}

type InetMulticastRequestWithNIC struct {
	_ structs.HostLayout
	InetMulticastRequest
	InterfaceIndex int32
}

type Inet6Addr [16]byte

type SockAddrInet6 struct {
	_        structs.HostLayout
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	Scope_id uint32
}

type SockAddrLink struct {
	_               structs.HostLayout
	Family          uint16
	Protocol        uint16
	InterfaceIndex  int32
	ARPHardwareType uint16
	PacketType      byte
	HardwareAddrLen byte
	HardwareAddr    [8]byte
}

const UnixPathMax = 108

type SockAddrUnix struct {
	_      structs.HostLayout
	Family uint16
	Path   [UnixPathMax]int8
}

type SockAddr interface {
	marshal.Marshallable

	implementsSockAddr()
}

func (s *SockAddrInet) implementsSockAddr()    {}
func (s *SockAddrInet6) implementsSockAddr()   {}
func (s *SockAddrLink) implementsSockAddr()    {}
func (s *SockAddrUnix) implementsSockAddr()    {}
func (s *SockAddrNetlink) implementsSockAddr() {}

type Linger struct {
	_      structs.HostLayout
	OnOff  int32
	Linger int32
}

const SizeOfLinger = 8

type TCPInfo struct {
	_ structs.HostLayout
	State uint8

	CaState uint8

	Retransmits uint8

	Probes uint8

	Backoff uint8

	Options uint8

	WindowScale uint8

	DeliveryRateAppLimited uint8

	RTO uint32

	ATO uint32

	SndMss uint32

	RcvMss uint32

	Unacked uint32

	Sacked uint32

	Lost uint32

	Retrans uint32

	Fackets uint32

	LastDataSent uint32
	LastAckSent  uint32
	LastDataRecv uint32
	LastAckRecv  uint32

	PMTU        uint32
	RcvSsthresh uint32
	RTT         uint32
	RTTVar      uint32
	SndSsthresh uint32
	SndCwnd     uint32
	Advmss      uint32
	Reordering  uint32

	RcvRTT uint32

	RcvSpace uint32

	TotalRetrans uint32

	PacingRate uint64

	MaxPacingRate uint64

	BytesAcked uint64

	BytesReceived uint64

	SegsOut uint32

	SegsIn uint32

	NotSentBytes uint32

	MinRTT uint32

	DataSegsIn uint32

	DataSegsOut uint32

	DeliveryRate uint64

	BusyTime uint64

	RwndLimited uint64

	SndBufLimited uint64

	Delivered uint32

	DeliveredCE uint32

	BytesSent uint64

	BytesRetrans uint64

	DSACKDups uint32

	ReordSeen uint32
}

var SizeOfTCPInfo = (*TCPInfo)(nil).SizeBytes()

const (
	SCM_CREDENTIALS = 0x2
	SCM_RIGHTS      = 0x1
)

type ControlMessageHeader struct {
	_      structs.HostLayout
	Length uint64
	Level  int32
	Type   int32
}

var SizeOfControlMessageHeader = (*ControlMessageHeader)(nil).SizeBytes()

type ControlMessageCredentials struct {
	_   structs.HostLayout
	PID int32
	UID uint32
	GID uint32
}

type ControlMessageIPPacketInfo struct {
	_               structs.HostLayout
	NIC             int32
	LocalAddr       InetAddr
	DestinationAddr InetAddr
}

type ControlMessageIPv6PacketInfo struct {
	_    structs.HostLayout
	Addr Inet6Addr
	NIC  uint32
}

var SizeOfControlMessageCredentials = (*ControlMessageCredentials)(nil).SizeBytes()

const SizeOfControlMessageRight = 4

const SizeOfControlMessageInq = 4

const SizeOfControlMessageTOS = 1

const SizeOfControlMessageTTL = 4

const SizeOfControlMessageTClass = 4

const SizeOfControlMessageHopLimit = 4

const SizeOfControlMessageIPPacketInfo = 12

const SizeOfControlMessageIPv6PacketInfo = 20

const SCM_MAX_FD = 253

const SO_ACCEPTCON = 1 << 16

type ICMP6Filter struct {
	_      structs.HostLayout
	Filter [8]uint32
}

var (
	ICMP6FilterSize   = (*ICMP6Filter)(nil).SizeBytes()
	SockAddrInetSize  = (*SockAddrInet)(nil).SizeBytes()
	SockAddrInet6Size = (*SockAddrInet6)(nil).SizeBytes()
	SockAddrLinkSize  = (*SockAddrLink)(nil).SizeBytes()
)

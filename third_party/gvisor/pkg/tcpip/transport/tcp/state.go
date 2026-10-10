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

package tcp

import (
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/internal/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

type TCPProbeFunc func(s *TCPEndpointState)

type TCPCubicState struct {
	WLastMax float64

	WMax float64

	T tcpip.MonotonicTime

	TimeSinceLastCongestion time.Duration

	C float64

	K float64

	Beta float64

	WC float64

	WEst float64

	EndSeq seqnum.Value

	CurrRTT time.Duration

	LastRTT time.Duration

	SampleCount uint

	LastAck tcpip.MonotonicTime

	RoundStart tcpip.MonotonicTime
}

type TCPRACKState struct {
	XmitTime tcpip.MonotonicTime

	EndSequence seqnum.Value

	FACK seqnum.Value

	RTT time.Duration

	Reord bool

	DSACKSeen bool

	ReoWnd time.Duration

	ReoWndIncr uint8

	ReoWndPersist int8

	RTTSeq seqnum.Value
}

type TCPEndpointID struct {
	LocalPort uint16

	LocalAddress tcpip.Address

	RemotePort uint16

	RemoteAddress tcpip.Address
}

type TCPFastRecoveryState struct {
	Active bool

	First seqnum.Value

	Last seqnum.Value

	MaxCwnd int

	HighRxt seqnum.Value

	RescueRxt seqnum.Value
}

type TCPReceiverState struct {
	RcvNxt seqnum.Value

	RcvAcc seqnum.Value

	RcvWndScale uint8

	PendingBufUsed int
}

type TCPRTTState struct {
	SRTT time.Duration

	RTTVar time.Duration

	SRTTInited bool
}

type TCPSenderState struct {
	LastSendTime tcpip.MonotonicTime

	DupAckCount int

	SndCwnd int

	Ssthresh int

	SndCAAckCount int

	Outstanding int

	SackedOut int

	SndWnd seqnum.Size

	SndUna seqnum.Value

	SndNxt seqnum.Value

	RTTMeasureSeqNum seqnum.Value

	RTTMeasureTime tcpip.MonotonicTime

	Closed bool

	RTO time.Duration

	RTTState TCPRTTState

	MaxPayloadSize int

	SndWndScale uint8

	MaxSentAck seqnum.Value

	FastRecovery TCPFastRecoveryState

	Cubic TCPCubicState

	RACKState TCPRACKState

	RetransmitTS uint32

	SpuriousRecovery bool
}

type TCPSACKInfo struct {
	Blocks []header.SACKBlock

	ReceivedBlocks []header.SACKBlock

	MaxSACKED seqnum.Value
}

type RcvBufAutoTuneParams struct {
	MeasureTime tcpip.MonotonicTime

	CopiedBytes int

	PrevCopiedBytes int

	RcvBufSize int

	RTT time.Duration

	RTTVar time.Duration

	RTTMeasureSeqNumber seqnum.Value

	RTTMeasureTime tcpip.MonotonicTime

	Disabled bool
}

type TCPRcvBufState struct {
	RcvBufUsed int

	RcvAutoParams RcvBufAutoTuneParams

	RcvClosed bool
}

type TCPSndBufState struct {
	SndBufSize int

	SndBufUsed int

	SndClosed bool

	PacketTooBigCount int

	SndMTU int

	AutoTuneSndBufDisabled atomicbitops.Uint32
}

type TCPEndpointStateInner struct {
	TSOffset tcp.TSOffset

	SACKPermitted bool

	SendTSOk bool

	RecentTS uint32
}

type TCPEndpointState struct {
	TCPEndpointStateInner

	ID TCPEndpointID

	SegTime tcpip.MonotonicTime

	RcvBufState TCPRcvBufState

	SndBufState TCPSndBufState

	SACK TCPSACKInfo

	Receiver TCPReceiverState

	Sender TCPSenderState
}

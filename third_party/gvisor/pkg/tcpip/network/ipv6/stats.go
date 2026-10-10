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

package ipv6

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.IPNetworkEndpointStats = (*Stats)(nil)

type Stats struct {
	IP tcpip.IPStats

	ICMP tcpip.ICMPv6Stats

	UnhandledRouterAdvertisements *tcpip.StatCounter
}

func (*Stats) IsNetworkEndpointStats() {}

func (s *Stats) IPStats() *tcpip.IPStats {
	return &s.IP
}

type sharedStats struct {
	localStats Stats
	ip         ip.MultiCounterIPStats
	icmp       multiCounterICMPv6Stats
}


type multiCounterICMPv6PacketStats struct {
	echoRequest               tcpip.MultiCounterStat
	echoReply                 tcpip.MultiCounterStat
	dstUnreachable            tcpip.MultiCounterStat
	packetTooBig              tcpip.MultiCounterStat
	timeExceeded              tcpip.MultiCounterStat
	paramProblem              tcpip.MultiCounterStat
	routerSolicit             tcpip.MultiCounterStat
	routerAdvert              tcpip.MultiCounterStat
	neighborSolicit           tcpip.MultiCounterStat
	neighborAdvert            tcpip.MultiCounterStat
	redirectMsg               tcpip.MultiCounterStat
	multicastListenerQuery    tcpip.MultiCounterStat
	multicastListenerReport   tcpip.MultiCounterStat
	multicastListenerReportV2 tcpip.MultiCounterStat
	multicastListenerDone     tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6PacketStats) init(a, b *tcpip.ICMPv6PacketStats) {
	m.echoRequest.Init(a.EchoRequest, b.EchoRequest)
	m.echoReply.Init(a.EchoReply, b.EchoReply)
	m.dstUnreachable.Init(a.DstUnreachable, b.DstUnreachable)
	m.packetTooBig.Init(a.PacketTooBig, b.PacketTooBig)
	m.timeExceeded.Init(a.TimeExceeded, b.TimeExceeded)
	m.paramProblem.Init(a.ParamProblem, b.ParamProblem)
	m.routerSolicit.Init(a.RouterSolicit, b.RouterSolicit)
	m.routerAdvert.Init(a.RouterAdvert, b.RouterAdvert)
	m.neighborSolicit.Init(a.NeighborSolicit, b.NeighborSolicit)
	m.neighborAdvert.Init(a.NeighborAdvert, b.NeighborAdvert)
	m.redirectMsg.Init(a.RedirectMsg, b.RedirectMsg)
	m.multicastListenerQuery.Init(a.MulticastListenerQuery, b.MulticastListenerQuery)
	m.multicastListenerReport.Init(a.MulticastListenerReport, b.MulticastListenerReport)
	m.multicastListenerReportV2.Init(a.MulticastListenerReportV2, b.MulticastListenerReportV2)
	m.multicastListenerDone.Init(a.MulticastListenerDone, b.MulticastListenerDone)
}



type multiCounterICMPv6SentPacketStats struct {
	multiCounterICMPv6PacketStats
	dropped     tcpip.MultiCounterStat
	rateLimited tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6SentPacketStats) init(a, b *tcpip.ICMPv6SentPacketStats) {
	m.multiCounterICMPv6PacketStats.init(&a.ICMPv6PacketStats, &b.ICMPv6PacketStats)
	m.dropped.Init(a.Dropped, b.Dropped)
	m.rateLimited.Init(a.RateLimited, b.RateLimited)
}



type multiCounterICMPv6ReceivedPacketStats struct {
	multiCounterICMPv6PacketStats
	unrecognized                   tcpip.MultiCounterStat
	invalid                        tcpip.MultiCounterStat
	routerOnlyPacketsDroppedByHost tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6ReceivedPacketStats) init(a, b *tcpip.ICMPv6ReceivedPacketStats) {
	m.multiCounterICMPv6PacketStats.init(&a.ICMPv6PacketStats, &b.ICMPv6PacketStats)
	m.unrecognized.Init(a.Unrecognized, b.Unrecognized)
	m.invalid.Init(a.Invalid, b.Invalid)
	m.routerOnlyPacketsDroppedByHost.Init(a.RouterOnlyPacketsDroppedByHost, b.RouterOnlyPacketsDroppedByHost)
}



type multiCounterICMPv6Stats struct {
	packetsSent     multiCounterICMPv6SentPacketStats
	packetsReceived multiCounterICMPv6ReceivedPacketStats
}

func (m *multiCounterICMPv6Stats) init(a, b *tcpip.ICMPv6Stats) {
	m.packetsSent.init(&a.PacketsSent, &b.PacketsSent)
	m.packetsReceived.init(&a.PacketsReceived, &b.PacketsReceived)
}


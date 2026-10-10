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

package ip

import "github.com/metacubex/gvisor/pkg/tcpip"


type MultiCounterIPForwardingStats struct {
	Unrouteable tcpip.MultiCounterStat

	ExhaustedTTL tcpip.MultiCounterStat

	InitializingSource tcpip.MultiCounterStat

	LinkLocalSource tcpip.MultiCounterStat

	LinkLocalDestination tcpip.MultiCounterStat

	PacketTooBig tcpip.MultiCounterStat

	HostUnreachable tcpip.MultiCounterStat

	ExtensionHeaderProblem tcpip.MultiCounterStat

	UnexpectedMulticastInputInterface tcpip.MultiCounterStat

	UnknownOutputEndpoint tcpip.MultiCounterStat

	NoMulticastPendingQueueBufferSpace tcpip.MultiCounterStat

	OutgoingDeviceNoBufferSpace tcpip.MultiCounterStat

	Errors tcpip.MultiCounterStat

	OutgoingDeviceClosedForSend tcpip.MultiCounterStat
}

func (m *MultiCounterIPForwardingStats) Init(a, b *tcpip.IPForwardingStats) {
	m.Unrouteable.Init(a.Unrouteable, b.Unrouteable)
	m.Errors.Init(a.Errors, b.Errors)
	m.InitializingSource.Init(a.InitializingSource, b.InitializingSource)
	m.LinkLocalSource.Init(a.LinkLocalSource, b.LinkLocalSource)
	m.LinkLocalDestination.Init(a.LinkLocalDestination, b.LinkLocalDestination)
	m.ExtensionHeaderProblem.Init(a.ExtensionHeaderProblem, b.ExtensionHeaderProblem)
	m.PacketTooBig.Init(a.PacketTooBig, b.PacketTooBig)
	m.ExhaustedTTL.Init(a.ExhaustedTTL, b.ExhaustedTTL)
	m.HostUnreachable.Init(a.HostUnreachable, b.HostUnreachable)
	m.UnexpectedMulticastInputInterface.Init(a.UnexpectedMulticastInputInterface, b.UnexpectedMulticastInputInterface)
	m.UnknownOutputEndpoint.Init(a.UnknownOutputEndpoint, b.UnknownOutputEndpoint)
	m.NoMulticastPendingQueueBufferSpace.Init(a.NoMulticastPendingQueueBufferSpace, b.NoMulticastPendingQueueBufferSpace)
	m.OutgoingDeviceNoBufferSpace.Init(a.OutgoingDeviceNoBufferSpace, b.OutgoingDeviceNoBufferSpace)
	m.OutgoingDeviceClosedForSend.Init(a.OutgoingDeviceClosedForSend, b.OutgoingDeviceClosedForSend)
}



type MultiCounterIPStats struct {
	PacketsReceived tcpip.MultiCounterStat

	ValidPacketsReceived tcpip.MultiCounterStat

	DisabledPacketsReceived tcpip.MultiCounterStat

	InvalidDestinationAddressesReceived tcpip.MultiCounterStat

	InvalidSourceAddressesReceived tcpip.MultiCounterStat

	PacketsDelivered tcpip.MultiCounterStat

	PacketsSent tcpip.MultiCounterStat

	OutgoingPacketErrors tcpip.MultiCounterStat

	MalformedPacketsReceived tcpip.MultiCounterStat

	MalformedFragmentsReceived tcpip.MultiCounterStat

	IPTablesPreroutingDropped tcpip.MultiCounterStat

	IPTablesInputDropped tcpip.MultiCounterStat

	IPTablesForwardDropped tcpip.MultiCounterStat

	IPTablesOutputDropped tcpip.MultiCounterStat

	IPTablesPostroutingDropped tcpip.MultiCounterStat


	OptionTimestampReceived tcpip.MultiCounterStat

	OptionRecordRouteReceived tcpip.MultiCounterStat

	OptionRouterAlertReceived tcpip.MultiCounterStat

	OptionUnknownReceived tcpip.MultiCounterStat

	Forwarding MultiCounterIPForwardingStats
}

func (m *MultiCounterIPStats) Init(a, b *tcpip.IPStats) {
	m.PacketsReceived.Init(a.PacketsReceived, b.PacketsReceived)
	m.ValidPacketsReceived.Init(a.ValidPacketsReceived, b.ValidPacketsReceived)
	m.DisabledPacketsReceived.Init(a.DisabledPacketsReceived, b.DisabledPacketsReceived)
	m.InvalidDestinationAddressesReceived.Init(a.InvalidDestinationAddressesReceived, b.InvalidDestinationAddressesReceived)
	m.InvalidSourceAddressesReceived.Init(a.InvalidSourceAddressesReceived, b.InvalidSourceAddressesReceived)
	m.PacketsDelivered.Init(a.PacketsDelivered, b.PacketsDelivered)
	m.PacketsSent.Init(a.PacketsSent, b.PacketsSent)
	m.OutgoingPacketErrors.Init(a.OutgoingPacketErrors, b.OutgoingPacketErrors)
	m.MalformedPacketsReceived.Init(a.MalformedPacketsReceived, b.MalformedPacketsReceived)
	m.MalformedFragmentsReceived.Init(a.MalformedFragmentsReceived, b.MalformedFragmentsReceived)
	m.IPTablesPreroutingDropped.Init(a.IPTablesPreroutingDropped, b.IPTablesPreroutingDropped)
	m.IPTablesInputDropped.Init(a.IPTablesInputDropped, b.IPTablesInputDropped)
	m.IPTablesForwardDropped.Init(a.IPTablesForwardDropped, b.IPTablesForwardDropped)
	m.IPTablesOutputDropped.Init(a.IPTablesOutputDropped, b.IPTablesOutputDropped)
	m.IPTablesPostroutingDropped.Init(a.IPTablesPostroutingDropped, b.IPTablesPostroutingDropped)
	m.OptionTimestampReceived.Init(a.OptionTimestampReceived, b.OptionTimestampReceived)
	m.OptionRecordRouteReceived.Init(a.OptionRecordRouteReceived, b.OptionRecordRouteReceived)
	m.OptionRouterAlertReceived.Init(a.OptionRouterAlertReceived, b.OptionRouterAlertReceived)
	m.OptionUnknownReceived.Init(a.OptionUnknownReceived, b.OptionUnknownReceived)
	m.Forwarding.Init(&a.Forwarding, &b.Forwarding)
}


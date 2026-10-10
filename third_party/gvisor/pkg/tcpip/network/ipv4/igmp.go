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

package ipv4

import (
	"fmt"
	"math"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	v1RouterPresentTimeout = 400 * time.Second

	v1MaxRespTime = 10 * time.Second

	UnsolicitedReportIntervalMax = 10 * time.Second
)

type protocolMode int

const (
	protocolModeV2OrV3 protocolMode = iota
	protocolModeV1
	protocolModeV1Compatibility
)

type IGMPVersion int

const (
	_ IGMPVersion = iota
	IGMPVersion1
	IGMPVersion2
	IGMPVersion3
)

type IGMPEndpoint interface {
	SetIGMPVersion(IGMPVersion) IGMPVersion

	GetIGMPVersion() IGMPVersion
}

type IGMPOptions struct {
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*igmpState)(nil)

type igmpState struct {
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState

	mode protocolMode

	igmpV1Job *tcpip.Job
}

func (igmp *igmpState) Enabled() bool {
	return igmp.ep.protocol.options.IGMP.Enabled && !igmp.ep.nic.IsLoopback() && igmp.ep.Enabled()
}

func (igmp *igmpState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	igmpType := header.IGMPv2MembershipReport
	switch igmp.mode {
	case protocolModeV2OrV3:
	case protocolModeV1, protocolModeV1Compatibility:
		igmpType = header.IGMPv1MembershipReport
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
	return igmp.writePacket(groupAddress, groupAddress, igmpType)
}

func (igmp *igmpState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	switch igmp.mode {
	case protocolModeV2OrV3:
		_, err := igmp.writePacket(header.IPv4AllRoutersGroup, groupAddress, header.IGMPLeaveGroup)
		return err
	case protocolModeV1, protocolModeV1Compatibility:
		return nil
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
}

func (igmp *igmpState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	return groupAddress != header.IPv4AllSystems
}

type igmpv3ReportBuilder struct {
	igmp *igmpState

	records []header.IGMPv3ReportGroupAddressRecordSerializer
}

func (b *igmpv3ReportBuilder) AddRecord(genericRecordType ip.MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address) {
	var recordType header.IGMPv3ReportRecordType
	switch genericRecordType {
	case ip.MulticastGroupProtocolV2ReportRecordModeIsInclude:
		recordType = header.IGMPv3ReportRecordModeIsInclude
	case ip.MulticastGroupProtocolV2ReportRecordModeIsExclude:
		recordType = header.IGMPv3ReportRecordModeIsExclude
	case ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode:
		recordType = header.IGMPv3ReportRecordChangeToIncludeMode
	case ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode:
		recordType = header.IGMPv3ReportRecordChangeToExcludeMode
	case ip.MulticastGroupProtocolV2ReportRecordAllowNewSources:
		recordType = header.IGMPv3ReportRecordAllowNewSources
	case ip.MulticastGroupProtocolV2ReportRecordBlockOldSources:
		recordType = header.IGMPv3ReportRecordBlockOldSources
	default:
		panic(fmt.Sprintf("unrecognied genericRecordType = %d", genericRecordType))
	}

	b.records = append(b.records, header.IGMPv3ReportGroupAddressRecordSerializer{
		RecordType:   recordType,
		GroupAddress: groupAddress,
		Sources:      nil,
	})
}

func (b *igmpv3ReportBuilder) Send() (sent bool, err tcpip.Error) {
	if len(b.records) == 0 {
		return false, err
	}

	options := header.IPv4OptionsSerializer{
		&header.IPv4SerializableRouterAlertOption{},
	}
	mtu := int(b.igmp.ep.MTU()) - int(options.Length())

	allSentWithSpecifiedAddress := true
	var firstErr tcpip.Error
	for records := b.records; len(records) != 0; {
		spaceLeft := mtu
		maxRecords := 0

		for ; maxRecords < len(records); maxRecords++ {
			tmp := spaceLeft - records[maxRecords].Length()
			if tmp > 0 {
				spaceLeft = tmp
			} else {
				break
			}
		}

		serializer := header.IGMPv3ReportSerializer{Records: records[:maxRecords]}
		records = records[maxRecords:]

		icmpView := buffer.NewViewSize(serializer.Length())
		serializer.SerializeInto(icmpView.AsSlice())
		if sentWithSpecifiedAddress, err := b.igmp.writePacketInner(
			icmpView,
			b.igmp.ep.stats.igmp.packetsSent.v3MembershipReport,
			options,
			header.IGMPv3RoutersAddress,
		); err != nil {
			if firstErr != nil {
				firstErr = nil
			}
			allSentWithSpecifiedAddress = false
		} else if !sentWithSpecifiedAddress {
			allSentWithSpecifiedAddress = false
		}
	}

	return allSentWithSpecifiedAddress, firstErr
}

func (igmp *igmpState) NewReportV2Builder() ip.MulticastGroupProtocolV2ReportBuilder {
	return &igmpv3ReportBuilder{igmp: igmp}
}

func (*igmpState) V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration {
	if code > math.MaxUint8 {
		panic(fmt.Sprintf("got IGMPv3 MaxRespCode = %d, want <= %d", code, math.MaxUint8))
	}
	return header.IGMPv3MaximumResponseDelay(uint8(code))
}

func (*igmpState) V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

func (igmp *igmpState) init(ep *endpoint) {
	igmp.ep = ep
	igmp.genericMulticastProtocol.Init(&ep.mu, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.InsecureRNG(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  igmp,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
	igmp.mode = protocolModeV2OrV3
	igmp.igmpV1Job = tcpip.NewJob(ep.protocol.stack.Clock(), &ep.mu, func() {
		igmp.mode = protocolModeV2OrV3
	})
}

func (igmp *igmpState) isSourceIPValidLocked(src tcpip.Address, messageType header.IGMPType) bool {
	if messageType == header.IGMPMembershipQuery {
		return true
	}

	var isSourceIPValid bool
	igmp.ep.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if subnet := addressEndpoint.Subnet(); subnet.Contains(src) {
			isSourceIPValid = true
			return false
		}
		return true
	})

	return isSourceIPValid
}

func (igmp *igmpState) isPacketValidLocked(pkt *stack.PacketBuffer, messageType header.IGMPType, hasRouterAlertOption bool) bool {
	iph := header.IPv4(pkt.NetworkHeader().Slice())

	if !hasRouterAlertOption || iph.TTL() != header.IGMPTTL {
		return false
	}

	return igmp.isSourceIPValidLocked(iph.SourceAddress(), messageType)
}

func (igmp *igmpState) handleIGMP(pkt *stack.PacketBuffer, hasRouterAlertOption bool) {
	received := igmp.ep.stats.igmp.packetsReceived
	hdr, ok := pkt.Data().PullUp(pkt.Data().Size())
	if !ok {
		received.invalid.Increment()
		return
	}
	h := header.IGMP(hdr)
	if len(h) < header.IGMPMinimumSize {
		received.invalid.Increment()
		return
	}

	if pkt.Data().Checksum() != 0xFFFF {
		received.checksumErrors.Increment()
		return
	}

	isValid := func(minimumSize int) bool {
		return len(hdr) >= minimumSize && igmp.isPacketValidLocked(pkt, h.Type(), hasRouterAlertOption)
	}

	switch h.Type() {
	case header.IGMPMembershipQuery:
		received.membershipQuery.Increment()
		if len(h) >= header.IGMPv3QueryMinimumSize {
			if isValid(header.IGMPv3QueryMinimumSize) {
				igmp.handleMembershipQueryV3(header.IGMPv3Query(h))
			} else {
				received.invalid.Increment()
			}
			return
		} else if !isValid(header.IGMPQueryMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipQuery(h.GroupAddress(), h.MaxRespTime())
	case header.IGMPv1MembershipReport:
		received.v1MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPv2MembershipReport:
		received.v2MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPLeaveGroup:
		received.leaveGroup.Increment()
		if !isValid(header.IGMPLeaveMessageMinimumSize) {
			received.invalid.Increment()
			return
		}

	default:
		received.unrecognized.Increment()
	}
}

func (igmp *igmpState) resetV1Present() {
	igmp.igmpV1Job.Cancel()
	switch igmp.mode {
	case protocolModeV2OrV3, protocolModeV1:
	case protocolModeV1Compatibility:
		igmp.mode = protocolModeV2OrV3
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
}

func (igmp *igmpState) handleMembershipQuery(groupAddress tcpip.Address, maxRespTime time.Duration) {
	if maxRespTime == 0 && igmp.Enabled() {
		switch igmp.mode {
		case protocolModeV2OrV3, protocolModeV1Compatibility:
			igmp.igmpV1Job.Cancel()
			igmp.igmpV1Job.Schedule(v1RouterPresentTimeout)
			igmp.mode = protocolModeV1Compatibility
		case protocolModeV1:
		default:
			panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
		}

		maxRespTime = v1MaxRespTime
	}

	igmp.genericMulticastProtocol.HandleQueryLocked(groupAddress, maxRespTime)
}

func (igmp *igmpState) handleMembershipQueryV3(igmpHdr header.IGMPv3Query) {
	sources, ok := igmpHdr.Sources()
	if !ok {
		return
	}

	igmp.genericMulticastProtocol.HandleQueryV2Locked(
		igmpHdr.GroupAddress(),
		uint16(igmpHdr.MaximumResponseCode()),
		sources,
		igmpHdr.QuerierRobustnessVariable(),
		igmpHdr.QuerierQueryInterval(),
	)
}

func (igmp *igmpState) handleMembershipReport(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.HandleReportLocked(groupAddress)
}

func (igmp *igmpState) writePacket(destAddress tcpip.Address, groupAddress tcpip.Address, igmpType header.IGMPType) (bool, tcpip.Error) {
	igmpView := buffer.NewViewSize(header.IGMPReportMinimumSize)
	igmpData := header.IGMP(igmpView.AsSlice())
	igmpData.SetType(igmpType)
	igmpData.SetGroupAddress(groupAddress)
	igmpData.SetChecksum(header.IGMPCalculateChecksum(igmpData))

	var reportType tcpip.MultiCounterStat
	sentStats := igmp.ep.stats.igmp.packetsSent
	switch igmpType {
	case header.IGMPv1MembershipReport:
		reportType = sentStats.v1MembershipReport
	case header.IGMPv2MembershipReport:
		reportType = sentStats.v2MembershipReport
	case header.IGMPLeaveGroup:
		reportType = sentStats.leaveGroup
	default:
		panic(fmt.Sprintf("unrecognized igmp type = %d", igmpType))
	}

	return igmp.writePacketInner(
		igmpView,
		reportType,
		header.IPv4OptionsSerializer{
			&header.IPv4SerializableRouterAlertOption{},
		},
		destAddress,
	)
}

func (igmp *igmpState) writePacketInner(buf *buffer.View, reportStat tcpip.MultiCounterStat, options header.IPv4OptionsSerializer, destAddress tcpip.Address) (bool, tcpip.Error) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(igmp.ep.MaxHeaderLength()),
		Payload:            buffer.MakeWithView(buf),
	})
	defer pkt.DecRef()

	addressEndpoint := igmp.ep.acquireOutgoingPrimaryAddressRLocked(destAddress, tcpip.Address{}, false)
	if addressEndpoint == nil {
		return false, nil
	}
	localAddr := addressEndpoint.AddressWithPrefix().Address
	addressEndpoint.DecRef()
	addressEndpoint = nil
	if err := igmp.ep.addIPHeader(localAddr, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.IGMPProtocolNumber,
		TTL:      header.IGMPTTL,
		TOS:      stack.DefaultTOS,
	}, options); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	sentStats := igmp.ep.stats.igmp.packetsSent
	if err := igmp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv4Address(destAddress), pkt); err != nil {
		sentStats.dropped.Increment()
		return false, err
	}
	reportStat.Increment()
	return true, nil
}

func (igmp *igmpState) joinGroup(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

func (igmp *igmpState) isInGroup(groupAddress tcpip.Address) bool {
	return igmp.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

func (igmp *igmpState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	if igmp.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (igmp *igmpState) softLeaveAll() {
	igmp.genericMulticastProtocol.MakeAllNonMemberLocked()
}

func (igmp *igmpState) initializeAll() {
	igmp.genericMulticastProtocol.InitializeGroupsLocked()
}

func (igmp *igmpState) sendQueuedReports() {
	igmp.genericMulticastProtocol.SendQueuedReportsLocked()
}

func (igmp *igmpState) setVersion(v IGMPVersion) IGMPVersion {
	prev := igmp.mode
	igmp.igmpV1Job.Cancel()

	var prevGenericModeV1 bool
	switch v {
	case IGMPVersion3:
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(false)
		igmp.mode = protocolModeV2OrV3
	case IGMPVersion2:
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(true)
		igmp.mode = protocolModeV2OrV3
	case IGMPVersion1:
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(true)
		igmp.mode = protocolModeV1
	default:
		panic(fmt.Sprintf("unrecognized version = %d", v))
	}

	return toIGMPVersion(prev, prevGenericModeV1)
}

func toIGMPVersion(mode protocolMode, genericV1 bool) IGMPVersion {
	switch mode {
	case protocolModeV2OrV3, protocolModeV1Compatibility:
		if genericV1 {
			return IGMPVersion2
		}
		return IGMPVersion3
	case protocolModeV1:
		return IGMPVersion1
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", mode))
	}
}

func (igmp *igmpState) getVersion() IGMPVersion {
	return toIGMPVersion(igmp.mode, igmp.genericMulticastProtocol.GetV1ModeLocked())
}

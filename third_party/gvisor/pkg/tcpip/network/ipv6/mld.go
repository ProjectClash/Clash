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
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	UnsolicitedReportIntervalMax = 10 * time.Second
)

type MLDVersion int

const (
	_ MLDVersion = iota
	MLDVersion1
	MLDVersion2
)

type MLDEndpoint interface {
	SetMLDVersion(MLDVersion) MLDVersion

	GetMLDVersion() MLDVersion
}

type MLDOptions struct {
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*mldState)(nil)

type mldState struct {
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState
}

func (mld *mldState) Enabled() bool {
	return mld.ep.protocol.options.MLD.Enabled && !mld.ep.nic.IsLoopback() && mld.ep.Enabled()
}

func (mld *mldState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	return mld.writePacket(groupAddress, groupAddress, header.ICMPv6MulticastListenerReport)
}

func (mld *mldState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	_, err := mld.writePacket(header.IPv6AllRoutersLinkLocalMulticastAddress, groupAddress, header.ICMPv6MulticastListenerDone)
	return err
}

func (mld *mldState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	if groupAddress == header.IPv6AllNodesMulticastAddress {
		return false
	}

	scope := header.V6MulticastScope(groupAddress)
	return scope != header.IPv6Reserved0MulticastScope && scope != header.IPv6InterfaceLocalMulticastScope
}

type mldv2ReportBuilder struct {
	mld *mldState

	records []header.MLDv2ReportMulticastAddressRecordSerializer
}

func (b *mldv2ReportBuilder) AddRecord(genericRecordType ip.MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address) {
	var recordType header.MLDv2ReportRecordType
	switch genericRecordType {
	case ip.MulticastGroupProtocolV2ReportRecordModeIsInclude:
		recordType = header.MLDv2ReportRecordModeIsInclude
	case ip.MulticastGroupProtocolV2ReportRecordModeIsExclude:
		recordType = header.MLDv2ReportRecordModeIsExclude
	case ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode:
		recordType = header.MLDv2ReportRecordChangeToIncludeMode
	case ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode:
		recordType = header.MLDv2ReportRecordChangeToExcludeMode
	case ip.MulticastGroupProtocolV2ReportRecordAllowNewSources:
		recordType = header.MLDv2ReportRecordAllowNewSources
	case ip.MulticastGroupProtocolV2ReportRecordBlockOldSources:
		recordType = header.MLDv2ReportRecordBlockOldSources
	default:
		panic(fmt.Sprintf("unrecognied genericRecordType = %d", genericRecordType))
	}

	b.records = append(b.records, header.MLDv2ReportMulticastAddressRecordSerializer{
		RecordType:       recordType,
		MulticastAddress: groupAddress,
		Sources:          nil,
	})
}

func (b *mldv2ReportBuilder) Send() (sent bool, err tcpip.Error) {
	if len(b.records) == 0 {
		return false, err
	}

	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}
	mtu := int(b.mld.ep.MTU()) - extensionHeaders.Length()

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

		serializer := header.MLDv2ReportSerializer{Records: records[:maxRecords]}
		records = records[maxRecords:]

		icmpView := buffer.NewViewSize(header.ICMPv6HeaderSize + serializer.Length())
		icmp := header.ICMPv6(icmpView.AsSlice())
		serializer.SerializeInto(icmp.MessageBody())
		if sentWithSpecifiedAddress, err := b.mld.writePacketInner(
			icmpView,
			header.ICMPv6MulticastListenerV2Report,
			b.mld.ep.stats.icmp.packetsSent.multicastListenerReportV2,
			extensionHeaders,
			header.MLDv2RoutersAddress,
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

func (mld *mldState) NewReportV2Builder() ip.MulticastGroupProtocolV2ReportBuilder {
	return &mldv2ReportBuilder{mld: mld}
}

func (*mldState) V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration {
	return header.MLDv2MaximumResponseDelay(code)
}

func (*mldState) V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

func (mld *mldState) init(ep *endpoint) {
	mld.ep = ep
	mld.genericMulticastProtocol.Init(&ep.mu.RWMutex, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.InsecureRNG(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  mld,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
}

func (mld *mldState) handleMulticastListenerQuery(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleQueryLocked(mldHdr.MulticastAddress(), mldHdr.MaximumResponseDelay())
}

func (mld *mldState) handleMulticastListenerQueryV2(mldHdr header.MLDv2Query) {
	sources, ok := mldHdr.Sources()
	if !ok {
		return
	}

	mld.genericMulticastProtocol.HandleQueryV2Locked(
		mldHdr.MulticastAddress(),
		mldHdr.MaximumResponseCode(),
		sources,
		mldHdr.QuerierRobustnessVariable(),
		mldHdr.QuerierQueryInterval(),
	)
}

func (mld *mldState) handleMulticastListenerReport(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleReportLocked(mldHdr.MulticastAddress())
}

func (mld *mldState) joinGroup(groupAddress tcpip.Address) {
	mld.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

func (mld *mldState) isInGroup(groupAddress tcpip.Address) bool {
	return mld.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

func (mld *mldState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	if mld.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (mld *mldState) softLeaveAll() {
	mld.genericMulticastProtocol.MakeAllNonMemberLocked()
}

func (mld *mldState) initializeAll() {
	mld.genericMulticastProtocol.InitializeGroupsLocked()
}

func (mld *mldState) sendQueuedReports() {
	mld.genericMulticastProtocol.SendQueuedReportsLocked()
}

func (mld *mldState) setVersion(v MLDVersion) MLDVersion {
	var prev bool
	switch v {
	case MLDVersion2:
		prev = mld.genericMulticastProtocol.SetV1ModeLocked(false)
	case MLDVersion1:
		prev = mld.genericMulticastProtocol.SetV1ModeLocked(true)
	default:
		panic(fmt.Sprintf("unrecognized version = %d", v))
	}

	return toMLDVersion(prev)
}

func toMLDVersion(v1Generic bool) MLDVersion {
	if v1Generic {
		return MLDVersion1
	}
	return MLDVersion2
}

func (mld *mldState) getVersion() MLDVersion {
	return toMLDVersion(mld.genericMulticastProtocol.GetV1ModeLocked())
}

func (mld *mldState) writePacket(destAddress, groupAddress tcpip.Address, mldType header.ICMPv6Type) (bool, tcpip.Error) {
	sentStats := mld.ep.stats.icmp.packetsSent
	var mldStat tcpip.MultiCounterStat
	switch mldType {
	case header.ICMPv6MulticastListenerReport:
		mldStat = sentStats.multicastListenerReport
	case header.ICMPv6MulticastListenerDone:
		mldStat = sentStats.multicastListenerDone
	default:
		panic(fmt.Sprintf("unrecognized mld type = %d", mldType))
	}

	icmpView := buffer.NewViewSize(header.ICMPv6HeaderSize + header.MLDMinimumSize)

	icmp := header.ICMPv6(icmpView.AsSlice())
	header.MLD(icmp.MessageBody()).SetMulticastAddress(groupAddress)
	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}

	return mld.writePacketInner(
		icmpView,
		mldType,
		mldStat,
		extensionHeaders,
		destAddress,
	)
}

func (mld *mldState) writePacketInner(buf *buffer.View, mldType header.ICMPv6Type, reportStat tcpip.MultiCounterStat, extensionHeaders header.IPv6ExtHdrSerializer, destAddress tcpip.Address) (bool, tcpip.Error) {
	icmp := header.ICMPv6(buf.AsSlice())
	icmp.SetType(mldType)

	localAddress := mld.ep.getLinkLocalAddressRLocked()
	if localAddress.BitLen() == 0 {
		localAddress = header.IPv6Any
	}

	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    localAddress,
		Dst:    destAddress,
	}))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(mld.ep.MaxHeaderLength()) + extensionHeaders.Length(),
		Payload:            buffer.MakeWithView(buf),
	})
	defer pkt.DecRef()

	if err := addIPHeader(localAddress, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.MLDHopLimit,
	}, extensionHeaders); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}
	if err := mld.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(destAddress), pkt); err != nil {
		mld.ep.stats.icmp.packetsSent.dropped.Increment()
		return false, err
	}
	reportStat.Increment()
	return localAddress != header.IPv6Any, nil
}

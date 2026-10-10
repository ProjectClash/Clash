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

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

const (
	unsolicitedTransmissionCount = 2

	minQueryResponseTransmissionCount = 1

	DefaultRobustnessVariable = 2

	DefaultQueryInterval = 125 * time.Second
)

type multicastGroupState struct {
	joins uint64

	transmissionLeft uint8

	lastToSendReport bool

	delayedReportJob *tcpip.Job

	delayedReportJobFiresAt time.Time `state:"nosave"`

	queriedIncludeSources map[tcpip.Address]struct{}

	deleteScheduled bool
}

func (m *multicastGroupState) cancelDelayedReportJob() {
	m.delayedReportJob.Cancel()
	m.delayedReportJobFiresAt = time.Time{}
	m.transmissionLeft = 0
}

func (m *multicastGroupState) clearQueriedIncludeSources() {
	for source := range m.queriedIncludeSources {
		delete(m.queriedIncludeSources, source)
	}
}

type GenericMulticastProtocolOptions struct {
	Rand *rand.Rand `state:"nosave"`

	Clock tcpip.Clock

	Protocol MulticastGroupProtocol

	MaxUnsolicitedReportDelay time.Duration
}

type MulticastGroupProtocolV2ReportRecordType int

const (
	_ MulticastGroupProtocolV2ReportRecordType = iota
	MulticastGroupProtocolV2ReportRecordModeIsInclude
	MulticastGroupProtocolV2ReportRecordModeIsExclude
	MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
	MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
	MulticastGroupProtocolV2ReportRecordAllowNewSources
	MulticastGroupProtocolV2ReportRecordBlockOldSources
)

type MulticastGroupProtocolV2ReportBuilder interface {
	AddRecord(recordType MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address)

	Send() (sent bool, err tcpip.Error)
}

type MulticastGroupProtocol interface {
	Enabled() bool

	SendReport(groupAddress tcpip.Address) (sent bool, err tcpip.Error)

	SendLeave(groupAddress tcpip.Address) tcpip.Error

	ShouldPerformProtocol(tcpip.Address) bool

	NewReportV2Builder() MulticastGroupProtocolV2ReportBuilder

	V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration

	V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration
}

type protocolMode int

const (
	protocolModeV2 protocolMode = iota
	protocolModeV1
	protocolModeV1Compatibility
)

type GenericMulticastProtocolState struct {
	_ sync.NoCopy `state:"nosave"`

	opts GenericMulticastProtocolOptions

	memberships map[tcpip.Address]multicastGroupState

	protocolMU *sync.RWMutex `state:"nosave"`

	robustnessVariable uint8
	queryInterval      time.Duration
	mode               protocolMode
	modeTimer          tcpip.Timer `state:"nosave"`

	generalQueryV2Timer tcpip.Timer `state:"nosave"`
	generalQueryV2TimerFiresAt time.Time `state:"nosave"`

	stateChangedReportV2Timer    tcpip.Timer `state:"nosave"`
	stateChangedReportV2TimerSet bool
}

func (g *GenericMulticastProtocolState) GetV1ModeLocked() bool {
	switch g.mode {
	case protocolModeV2, protocolModeV1Compatibility:
		return false
	case protocolModeV1:
		return true
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
}

func (g *GenericMulticastProtocolState) stopModeTimer() {
	if g.modeTimer != nil {
		g.modeTimer.Stop()
	}
}

func (g *GenericMulticastProtocolState) SetV1ModeLocked(v bool) bool {
	if g.GetV1ModeLocked() == v {
		return v
	}

	if v {
		g.stopModeTimer()
		g.cancelV2ReportTimers()
		g.mode = protocolModeV1
		return false
	}

	g.mode = protocolModeV2
	return true
}

func (g *GenericMulticastProtocolState) cancelV2ReportTimers() {
	if g.generalQueryV2Timer != nil {
		g.generalQueryV2Timer.Stop()
		g.generalQueryV2TimerFiresAt = time.Time{}
	}

	if g.stateChangedReportV2Timer != nil {
		g.stateChangedReportV2Timer.Stop()
		g.stateChangedReportV2TimerSet = false
	}
}

func (g *GenericMulticastProtocolState) Init(protocolMU *sync.RWMutex, opts GenericMulticastProtocolOptions) {
	if g.memberships != nil {
		panic("attempted to initialize generic membership protocol state twice")
	}

	*g = GenericMulticastProtocolState{
		opts:               opts,
		memberships:        make(map[tcpip.Address]multicastGroupState),
		protocolMU:         protocolMU,
		robustnessVariable: DefaultRobustnessVariable,
		queryInterval:      DefaultQueryInterval,
		mode:               protocolModeV2,
	}
}

func (g *GenericMulticastProtocolState) MakeAllNonMemberLocked() {
	if !g.opts.Protocol.Enabled() {
		return
	}

	g.stopModeTimer()
	g.cancelV2ReportTimers()

	var v2ReportBuilder MulticastGroupProtocolV2ReportBuilder
	var handler func(tcpip.Address, *multicastGroupState)
	switch g.mode {
	case protocolModeV2:
		v2ReportBuilder = g.opts.Protocol.NewReportV2Builder()
		handler = func(groupAddress tcpip.Address, info *multicastGroupState) {
			info.cancelDelayedReportJob()

			v2ReportBuilder.AddRecord(
				MulticastGroupProtocolV2ReportRecordChangeToIncludeMode,
				groupAddress,
			)
		}
	case protocolModeV1Compatibility:
		g.mode = protocolModeV2
		fallthrough
	case protocolModeV1:
		handler = g.transitionToNonMemberLocked
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	for groupAddress, info := range g.memberships {
		if !g.shouldPerformForGroup(groupAddress) {
			continue
		}

		handler(groupAddress, &info)

		if info.deleteScheduled {
			delete(g.memberships, groupAddress)
		} else {
			info.transmissionLeft = 0
			g.memberships[groupAddress] = info
		}
	}

	if v2ReportBuilder != nil {
		_, _ = v2ReportBuilder.Send()
	}
}

func (g *GenericMulticastProtocolState) InitializeGroupsLocked() {
	if !g.opts.Protocol.Enabled() {
		return
	}

	var v2ReportBuilder MulticastGroupProtocolV2ReportBuilder
	switch g.mode {
	case protocolModeV2:
		v2ReportBuilder = g.opts.Protocol.NewReportV2Builder()
	case protocolModeV1Compatibility, protocolModeV1:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	for groupAddress, info := range g.memberships {
		g.initializeNewMemberLocked(groupAddress, &info, v2ReportBuilder)
		g.memberships[groupAddress] = info
	}

	if v2ReportBuilder == nil {
		return
	}

	if sent, err := v2ReportBuilder.Send(); sent && err == nil {
		g.scheduleStateChangedTimer()
	} else {
		for groupAddress, info := range g.memberships {
			if !g.shouldPerformForGroup(groupAddress) {
				continue
			}

			info.transmissionLeft++
			g.memberships[groupAddress] = info
		}
	}
}

func (g *GenericMulticastProtocolState) SendQueuedReportsLocked() {
	if g.stateChangedReportV2TimerSet {
		return
	}

	for groupAddress, info := range g.memberships {
		if info.delayedReportJobFiresAt.IsZero() {
			switch g.mode {
			case protocolModeV2:
				g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, &info, MulticastGroupProtocolV2ReportRecordChangeToExcludeMode)
			case protocolModeV1Compatibility, protocolModeV1:
				g.maybeSendReportLocked(groupAddress, &info)
			default:
				panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
			}

			g.memberships[groupAddress] = info
		}
	}
}

func (g *GenericMulticastProtocolState) JoinGroupLocked(groupAddress tcpip.Address) {
	info, ok := g.memberships[groupAddress]
	if ok {
		info.joins++
		if info.joins > 1 {
			g.memberships[groupAddress] = info
			return
		}
	} else {
		info = multicastGroupState{
			joins:            1,
			lastToSendReport: false,
			delayedReportJob: tcpip.NewJob(g.opts.Clock, g.protocolMU, func() {
				if !g.opts.Protocol.Enabled() {
					panic(fmt.Sprintf("delayed report job fired for group %s while the multicast group protocol is disabled", groupAddress))
				}

				info, ok := g.memberships[groupAddress]
				if !ok {
					panic(fmt.Sprintf("expected to find group state for group = %s", groupAddress))
				}

				info.delayedReportJobFiresAt = time.Time{}

				switch g.mode {
				case protocolModeV2:
					reportBuilder := g.opts.Protocol.NewReportV2Builder()
					reportBuilder.AddRecord(MulticastGroupProtocolV2ReportRecordModeIsExclude, groupAddress)
					_, _ = reportBuilder.Send()
				case protocolModeV1Compatibility, protocolModeV1:
					g.maybeSendReportLocked(groupAddress, &info)
				default:
					panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
				}

				info.clearQueriedIncludeSources()
				g.memberships[groupAddress] = info
			}),
			queriedIncludeSources: make(map[tcpip.Address]struct{}),
		}
	}

	info.deleteScheduled = false
	info.clearQueriedIncludeSources()
	info.delayedReportJobFiresAt = time.Time{}
	info.lastToSendReport = false
	g.initializeNewMemberLocked(groupAddress, &info, nil)
	g.memberships[groupAddress] = info
}

func (g *GenericMulticastProtocolState) IsLocallyJoinedRLocked(groupAddress tcpip.Address) bool {
	info, ok := g.memberships[groupAddress]
	return ok && !info.deleteScheduled
}

func (g *GenericMulticastProtocolState) sendV2ReportAndMaybeScheduleChangedTimer(
	groupAddress tcpip.Address,
	info *multicastGroupState,
	recordType MulticastGroupProtocolV2ReportRecordType,
) bool {
	if info.transmissionLeft == 0 {
		return false
	}

	successfullySentAndHasMore := false

	reportBuilder := g.opts.Protocol.NewReportV2Builder()
	reportBuilder.AddRecord(recordType, groupAddress)
	if sent, err := reportBuilder.Send(); sent && err == nil {
		info.transmissionLeft--

		successfullySentAndHasMore = info.transmissionLeft != 0

		if successfullySentAndHasMore {
			g.scheduleStateChangedTimer()
		}
	}

	return successfullySentAndHasMore
}

func (g *GenericMulticastProtocolState) scheduleStateChangedTimer() {
	if g.stateChangedReportV2TimerSet {
		return
	}

	delay := g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay)
	if g.stateChangedReportV2Timer == nil {
		g.stateChangedReportV2Timer = g.opts.Clock.AfterFunc(delay, func() {
			g.protocolMU.Lock()
			defer g.protocolMU.Unlock()

			reportBuilder := g.opts.Protocol.NewReportV2Builder()
			nonEmptyReport := false
			for groupAddress, info := range g.memberships {
				if info.transmissionLeft == 0 || !g.shouldPerformForGroup(groupAddress) {
					continue
				}

				info.transmissionLeft--
				nonEmptyReport = true

				mode := MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if info.deleteScheduled {
					mode = MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}
				reportBuilder.AddRecord(mode, groupAddress)

				if info.deleteScheduled && info.transmissionLeft == 0 {
					delete(g.memberships, groupAddress)
				} else {
					g.memberships[groupAddress] = info
				}
			}

			_, _ = reportBuilder.Send()

			if nonEmptyReport {
				g.stateChangedReportV2Timer.Reset(g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay))
			} else {
				g.stateChangedReportV2TimerSet = false
			}
		})
	} else {
		g.stateChangedReportV2Timer.Reset(delay)
	}
	g.stateChangedReportV2TimerSet = true
}

func (g *GenericMulticastProtocolState) LeaveGroupLocked(groupAddress tcpip.Address) bool {
	info, ok := g.memberships[groupAddress]
	if !ok || info.joins == 0 {
		return false
	}

	info.joins--
	if info.joins != 0 {
		g.memberships[groupAddress] = info
		return true
	}

	info.deleteScheduled = true
	info.cancelDelayedReportJob()

	if !g.shouldPerformForGroup(groupAddress) {
		delete(g.memberships, groupAddress)
		return true
	}

	switch g.mode {
	case protocolModeV2:
		info.transmissionLeft = g.robustnessVariable
		if g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, &info, MulticastGroupProtocolV2ReportRecordChangeToIncludeMode) {
			g.memberships[groupAddress] = info
		} else {
			delete(g.memberships, groupAddress)
		}
	case protocolModeV1Compatibility, protocolModeV1:
		g.transitionToNonMemberLocked(groupAddress, &info)
		delete(g.memberships, groupAddress)
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	return true
}

func (g *GenericMulticastProtocolState) HandleQueryV2Locked(groupAddress tcpip.Address, maxResponseCode uint16, sources header.AddressIterator, robustnessVariable uint8, queryInterval time.Duration) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	switch g.mode {
	case protocolModeV1Compatibility, protocolModeV1:
		g.handleQueryInnerLocked(groupAddress, g.opts.Protocol.V2QueryMaxRespCodeToV1Delay(maxResponseCode))
		return
	case protocolModeV2:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	if robustnessVariable != 0 {
		g.robustnessVariable = robustnessVariable
	}

	if queryInterval != 0 {
		g.queryInterval = queryInterval
	}

	maxResponseTime := g.calculateDelayTimerDuration(g.opts.Protocol.V2QueryMaxRespCodeToV2Delay(maxResponseCode))

	now := g.opts.Clock.Now()
	if !g.generalQueryV2TimerFiresAt.IsZero() && g.generalQueryV2TimerFiresAt.Sub(now) <= maxResponseTime {
		return
	}

	if groupAddress.Unspecified() {
		if g.generalQueryV2Timer == nil {
			g.generalQueryV2Timer = g.opts.Clock.AfterFunc(maxResponseTime, func() {
				g.protocolMU.Lock()
				defer g.protocolMU.Unlock()

				g.generalQueryV2TimerFiresAt = time.Time{}

				reportBuilder := g.opts.Protocol.NewReportV2Builder()
				for groupAddress, info := range g.memberships {
					if info.deleteScheduled || !g.shouldPerformForGroup(groupAddress) {
						continue
					}

					reportBuilder.AddRecord(
						MulticastGroupProtocolV2ReportRecordModeIsExclude,
						groupAddress,
					)
				}

				_, _ = reportBuilder.Send()
			})
		} else {
			g.generalQueryV2Timer.Reset(maxResponseTime)
		}
		g.generalQueryV2TimerFiresAt = now.Add(maxResponseTime)
		return
	}

	if info, ok := g.memberships[groupAddress]; ok && !info.deleteScheduled && g.shouldPerformForGroup(groupAddress) {
		if info.delayedReportJobFiresAt.IsZero() || (!sources.Done() && len(info.queriedIncludeSources) != 0) {
			for {
				source, ok := sources.Next()
				if !ok {
					break
				}

				info.queriedIncludeSources[source] = struct{}{}
			}
		} else {
			info.clearQueriedIncludeSources()
		}
		g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
		g.memberships[groupAddress] = info
	}
}

func (g *GenericMulticastProtocolState) HandleQueryLocked(groupAddress tcpip.Address, maxResponseTime time.Duration) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	switch g.mode {
	case protocolModeV2, protocolModeV1Compatibility:
		modeRevertDelay := time.Duration(g.robustnessVariable) * g.queryInterval
		if g.modeTimer == nil {
			g.modeTimer = g.opts.Clock.AfterFunc(modeRevertDelay, func() {
				g.protocolMU.Lock()
				defer g.protocolMU.Unlock()
				g.mode = protocolModeV2
			})
		} else {
			g.modeTimer.Reset(modeRevertDelay)
		}
		g.mode = protocolModeV1Compatibility
		g.cancelV2ReportTimers()
	case protocolModeV1:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
	g.handleQueryInnerLocked(groupAddress, maxResponseTime)
}

func (g *GenericMulticastProtocolState) handleQueryInnerLocked(groupAddress tcpip.Address, maxResponseTime time.Duration) {
	maxResponseTime = g.calculateDelayTimerDuration(maxResponseTime)

	if groupAddress.Unspecified() {
		for groupAddress, info := range g.memberships {
			g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
			g.memberships[groupAddress] = info
		}
	} else if info, ok := g.memberships[groupAddress]; ok && !info.deleteScheduled {
		g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
		g.memberships[groupAddress] = info
	}
}

func (g *GenericMulticastProtocolState) HandleReportLocked(groupAddress tcpip.Address) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	if info, ok := g.memberships[groupAddress]; ok {
		info.cancelDelayedReportJob()
		info.lastToSendReport = false
		g.memberships[groupAddress] = info
	}
}

func (g *GenericMulticastProtocolState) initializeNewMemberLocked(groupAddress tcpip.Address, info *multicastGroupState, callersV2ReportBuilder MulticastGroupProtocolV2ReportBuilder) {
	if !g.shouldPerformForGroup(groupAddress) {
		return
	}

	info.lastToSendReport = false

	switch g.mode {
	case protocolModeV2:
		info.transmissionLeft = g.robustnessVariable
		if callersV2ReportBuilder == nil {
			g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, info, MulticastGroupProtocolV2ReportRecordChangeToExcludeMode)
		} else {
			callersV2ReportBuilder.AddRecord(MulticastGroupProtocolV2ReportRecordChangeToExcludeMode, groupAddress)
			info.transmissionLeft--
		}
	case protocolModeV1Compatibility, protocolModeV1:
		info.transmissionLeft = unsolicitedTransmissionCount
		g.maybeSendReportLocked(groupAddress, info)
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
}

func (g *GenericMulticastProtocolState) shouldPerformForGroup(groupAddress tcpip.Address) bool {
	return g.opts.Protocol.ShouldPerformProtocol(groupAddress) && g.opts.Protocol.Enabled()
}

func (g *GenericMulticastProtocolState) maybeSendReportLocked(groupAddress tcpip.Address, info *multicastGroupState) {
	if info.transmissionLeft == 0 {
		return
	}

	sent, err := g.opts.Protocol.SendReport(groupAddress)
	if err == nil && sent {
		info.lastToSendReport = true

		info.transmissionLeft--
		if info.transmissionLeft > 0 {
			g.setDelayTimerForAddressLocked(
				groupAddress,
				info,
				g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay),
			)
		}
	}
}

func (g *GenericMulticastProtocolState) maybeSendLeave(groupAddress tcpip.Address, lastToSendReport bool) {
	if !g.shouldPerformForGroup(groupAddress) || !lastToSendReport {
		return
	}

	_ = g.opts.Protocol.SendLeave(groupAddress)
}

func (g *GenericMulticastProtocolState) transitionToNonMemberLocked(groupAddress tcpip.Address, info *multicastGroupState) {
	info.cancelDelayedReportJob()
	g.maybeSendLeave(groupAddress, info.lastToSendReport)
	info.lastToSendReport = false
}

func (g *GenericMulticastProtocolState) setDelayTimerForAddressLocked(groupAddress tcpip.Address, info *multicastGroupState, maxResponseTime time.Duration) {
	if !g.shouldPerformForGroup(groupAddress) {
		return
	}

	if info.transmissionLeft < minQueryResponseTransmissionCount {
		info.transmissionLeft = minQueryResponseTransmissionCount
	}

	now := g.opts.Clock.Now()
	if !info.delayedReportJobFiresAt.IsZero() && info.delayedReportJobFiresAt.Sub(now) <= maxResponseTime {
		return
	}

	info.delayedReportJob.Cancel()
	info.delayedReportJob.Schedule(maxResponseTime)
	info.delayedReportJobFiresAt = now.Add(maxResponseTime)
}

func (g *GenericMulticastProtocolState) calculateDelayTimerDuration(maxRespTime time.Duration) time.Duration {
	if maxRespTime == 0 {
		return 0
	}
	return time.Duration(g.opts.Rand.Int63n(int64(maxRespTime)))
}

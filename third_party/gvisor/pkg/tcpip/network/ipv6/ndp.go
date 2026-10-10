// Copyright 2019 The gVisor Authors.
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
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	defaultMaxRtrSolicitations = 3

	defaultRtrSolicitationInterval = 4 * time.Second

	defaultMaxRtrSolicitationDelay = time.Second

	defaultHandleRAs = HandlingRAsEnabledWhenForwardingDisabled

	defaultDiscoverDefaultRouters = true

	defaultDiscoverMoreSpecificRoutes = true

	defaultDiscoverOnLinkPrefixes = true

	defaultAutoGenGlobalAddresses = true

	minimumRtrSolicitationInterval = 500 * time.Millisecond

	minimumMaxRtrSolicitationDelay = 0

	MaxDiscoveredOffLinkRoutes = 10

	MaxDiscoveredOnLinkPrefixes = 10

	MaxDiscoveredSLAACPrefixes = 10

	validPrefixLenForAutoGen = 64

	defaultAutoGenTempGlobalAddresses = true

	defaultMaxTempAddrValidLifetime = 7 * 24 * time.Hour

	defaultMaxTempAddrPreferredLifetime = 24 * time.Hour

	defaultRegenAdvanceDuration = 5 * time.Second

	minRegenAdvanceDuration = time.Duration(0)

	maxSLAACAddrLocalRegenAttempts = 10

	MinPrefixInformationValidLifetimeForUpdate = 2 * time.Hour

	MaxDesyncFactor = 10 * time.Minute

	MinMaxTempAddrPreferredLifetime = defaultRegenAdvanceDuration + MaxDesyncFactor + time.Hour

	MinMaxTempAddrValidLifetime = 2 * time.Hour
)

type NDPEndpoint interface {
	SetNDPConfigurations(NDPConfigurations)

	NDPConfigurations() NDPConfigurations
}

type DHCPv6ConfigurationFromNDPRA int

const (
	_ DHCPv6ConfigurationFromNDPRA = iota

	DHCPv6NoConfiguration

	DHCPv6ManagedAddress

	DHCPv6OtherConfigurations
)

type NDPDispatcher interface {
	OnDuplicateAddressDetectionResult(tcpip.NICID, tcpip.Address, stack.DADResult)

	OnOffLinkRouteUpdated(tcpip.NICID, tcpip.Subnet, tcpip.Address, header.NDPRoutePreference)

	OnOffLinkRouteInvalidated(tcpip.NICID, tcpip.Subnet, tcpip.Address)

	OnOnLinkPrefixDiscovered(tcpip.NICID, tcpip.Subnet)

	OnOnLinkPrefixInvalidated(tcpip.NICID, tcpip.Subnet)

	OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) stack.AddressDispatcher

	OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix)

	OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix)

	OnRecursiveDNSServerOption(tcpip.NICID, []tcpip.Address, time.Duration)

	OnDNSSearchListOption(tcpip.NICID, []string, time.Duration)

	OnDHCPv6Configuration(tcpip.NICID, DHCPv6ConfigurationFromNDPRA)
}

var _ fmt.Stringer = HandleRAsConfiguration(0)

type HandleRAsConfiguration int

const (
	HandlingRAsDisabled HandleRAsConfiguration = iota

	HandlingRAsEnabledWhenForwardingDisabled

	HandlingRAsAlwaysEnabled
)

func (c HandleRAsConfiguration) String() string {
	switch c {
	case HandlingRAsDisabled:
		return "HandlingRAsDisabled"
	case HandlingRAsEnabledWhenForwardingDisabled:
		return "HandlingRAsEnabledWhenForwardingDisabled"
	case HandlingRAsAlwaysEnabled:
		return "HandlingRAsAlwaysEnabled"
	default:
		return fmt.Sprintf("HandleRAsConfiguration(%d)", c)
	}
}

func (c HandleRAsConfiguration) enabled(forwarding bool) bool {
	switch c {
	case HandlingRAsDisabled:
		return false
	case HandlingRAsEnabledWhenForwardingDisabled:
		return !forwarding
	case HandlingRAsAlwaysEnabled:
		return true
	default:
		panic(fmt.Sprintf("unhandled HandleRAsConfiguration = %d", c))
	}
}

type NDPConfigurations struct {
	MaxRtrSolicitations uint8

	RtrSolicitationInterval time.Duration

	MaxRtrSolicitationDelay time.Duration

	HandleRAs HandleRAsConfiguration

	DiscoverDefaultRouters bool

	DiscoverMoreSpecificRoutes bool

	DiscoverOnLinkPrefixes bool

	AutoGenGlobalAddresses bool

	AutoGenAddressConflictRetries uint8

	AutoGenTempGlobalAddresses bool

	MaxTempAddrValidLifetime time.Duration

	MaxTempAddrPreferredLifetime time.Duration

	RegenAdvanceDuration time.Duration
}

func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		MaxRtrSolicitations:          defaultMaxRtrSolicitations,
		RtrSolicitationInterval:      defaultRtrSolicitationInterval,
		MaxRtrSolicitationDelay:      defaultMaxRtrSolicitationDelay,
		HandleRAs:                    defaultHandleRAs,
		DiscoverDefaultRouters:       defaultDiscoverDefaultRouters,
		DiscoverMoreSpecificRoutes:   defaultDiscoverMoreSpecificRoutes,
		DiscoverOnLinkPrefixes:       defaultDiscoverOnLinkPrefixes,
		AutoGenGlobalAddresses:       defaultAutoGenGlobalAddresses,
		AutoGenTempGlobalAddresses:   defaultAutoGenTempGlobalAddresses,
		MaxTempAddrValidLifetime:     defaultMaxTempAddrValidLifetime,
		MaxTempAddrPreferredLifetime: defaultMaxTempAddrPreferredLifetime,
		RegenAdvanceDuration:         defaultRegenAdvanceDuration,
	}
}

func (c *NDPConfigurations) validate() {
	if c.RtrSolicitationInterval < minimumRtrSolicitationInterval {
		c.RtrSolicitationInterval = defaultRtrSolicitationInterval
	}

	if c.MaxRtrSolicitationDelay < minimumMaxRtrSolicitationDelay {
		c.MaxRtrSolicitationDelay = defaultMaxRtrSolicitationDelay
	}

	if c.MaxTempAddrValidLifetime < MinMaxTempAddrValidLifetime {
		c.MaxTempAddrValidLifetime = MinMaxTempAddrValidLifetime
	}

	if c.MaxTempAddrPreferredLifetime < MinMaxTempAddrPreferredLifetime || c.MaxTempAddrPreferredLifetime > c.MaxTempAddrValidLifetime {
		c.MaxTempAddrPreferredLifetime = MinMaxTempAddrPreferredLifetime
	}

	if c.RegenAdvanceDuration < minRegenAdvanceDuration {
		c.RegenAdvanceDuration = minRegenAdvanceDuration
	}
}

type timer struct {
	done *bool

	timer tcpip.Timer `state:"nosave"`
}

type offLinkRoute struct {
	dest   tcpip.Subnet
	router tcpip.Address
}

type ndpState struct {
	_ sync.NoCopy `state:"nosave"`

	ep *endpoint

	configs NDPConfigurations

	dad ip.DAD

	offLinkRoutes map[offLinkRoute]offLinkRouteState

	rtrSolicitTimer timer

	onLinkPrefixes map[tcpip.Subnet]onLinkPrefixState

	slaacPrefixes map[tcpip.Subnet]slaacPrefixState

	dhcpv6Configuration DHCPv6ConfigurationFromNDPRA

	temporaryIIDHistory [header.IIDSize]byte

	temporaryAddressDesyncFactor time.Duration
}

type offLinkRouteState struct {
	prf header.NDPRoutePreference

	invalidationJob *tcpip.Job
}

type onLinkPrefixState struct {
	invalidationJob *tcpip.Job
}

type tempSLAACAddrState struct {
	deprecationJob *tcpip.Job

	invalidationJob *tcpip.Job

	regenJob *tcpip.Job

	createdAt tcpip.MonotonicTime

	addressEndpoint stack.AddressEndpoint

	regenerated bool
}

type stableAddrState struct {
	addressEndpoint stack.AddressEndpoint

	localGenerationFailures uint8
}

type slaacPrefixState struct {
	deprecationJob *tcpip.Job

	invalidationJob *tcpip.Job

	validUntil *tcpip.MonotonicTime

	preferredUntil *tcpip.MonotonicTime

	stableAddr stableAddrState

	tempAddrs map[tcpip.Address]tempSLAACAddrState


	generationAttempts uint8

	maxGenerationAttempts uint8
}

func (ndp *ndpState) startDuplicateAddressDetection(addr tcpip.Address, addressEndpoint stack.AddressEndpoint) tcpip.Error {
	if !header.IsV6UnicastAddress(addr) {
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	if addressEndpoint.GetKind() != stack.PermanentTentative {
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, ndp.ep.nic.ID()))
	}

	ret := ndp.dad.CheckDuplicateAddressLocked(addr, func(r stack.DADResult) {
		if addressEndpoint.GetKind() != stack.PermanentTentative {
			panic(fmt.Sprintf("ndpdad: addr %s is no longer tentative on NIC(%d)", addr, ndp.ep.nic.ID()))
		}

		var dadSucceeded bool
		switch r.(type) {
		case *stack.DADAborted, *stack.DADError, *stack.DADDupAddrDetected:
			dadSucceeded = false
		case *stack.DADSucceeded:
			dadSucceeded = true
		default:
			panic(fmt.Sprintf("unrecognized DAD result = %T", r))
		}

		if dadSucceeded {
			addressEndpoint.SetKind(stack.Permanent)
		}

		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionResult(ndp.ep.nic.ID(), addr, r)
		}

		if dadSucceeded {
			if addressEndpoint.ConfigType() == stack.AddressConfigSlaac && !addressEndpoint.Temporary() {
				ndp.regenerateTempSLAACAddr(addressEndpoint.AddressWithPrefix().Subnet(), true)
			}
			ndp.ep.onAddressAssignedLocked(addr)
		}
	})

	switch ret {
	case stack.DADStarting:
	case stack.DADAlreadyRunning:
		panic(fmt.Sprintf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, ndp.ep.nic.ID()))
	case stack.DADDisabled:
		addressEndpoint.SetKind(stack.Permanent)

		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionResult(ndp.ep.nic.ID(), addr, &stack.DADSucceeded{})
		}

		ndp.ep.onAddressAssignedLocked(addr)
	}

	return nil
}

func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address, reason stack.DADResult) {
	ndp.dad.StopLocked(addr, reason)
}

func (ndp *ndpState) handleRA(ip tcpip.Address, ra header.NDPRouterAdvert) {
	if !ndp.configs.HandleRAs.enabled(ndp.ep.Forwarding()) {
		ndp.ep.stats.localStats.UnhandledRouterAdvertisements.Increment()
		return
	}

	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		var configuration DHCPv6ConfigurationFromNDPRA
		switch {
		case ra.ManagedAddrConfFlag():
			configuration = DHCPv6ManagedAddress

		case ra.OtherConfFlag():
			configuration = DHCPv6OtherConfigurations

		default:
			configuration = DHCPv6NoConfiguration
		}

		if ndp.dhcpv6Configuration != configuration {
			ndp.dhcpv6Configuration = configuration
			ndpDisp.OnDHCPv6Configuration(ndp.ep.nic.ID(), configuration)
		}
	}

	if ndp.configs.DiscoverDefaultRouters {
		prf := ra.DefaultRouterPreference()
		if prf == header.ReservedRoutePreference {
			prf = header.MediumRoutePreference
		}

		ndp.handleOffLinkRouteDiscovery(offLinkRoute{dest: header.IPv6EmptySubnet, router: ip}, ra.RouterLifetime(), prf)
	}


	it, _ := ra.Options().Iter(false)
	for opt, done, _ := it.Next(); !done; opt, done, _ = it.Next() {
		switch opt := opt.(type) {
		case header.NDPRecursiveDNSServer:
			if ndp.ep.protocol.options.NDPDisp == nil {
				continue
			}

			addrs, _ := opt.Addresses()
			ndp.ep.protocol.options.NDPDisp.OnRecursiveDNSServerOption(ndp.ep.nic.ID(), addrs, opt.Lifetime())

		case header.NDPDNSSearchList:
			if ndp.ep.protocol.options.NDPDisp == nil {
				continue
			}

			domainNames, _ := opt.DomainNames()
			ndp.ep.protocol.options.NDPDisp.OnDNSSearchListOption(ndp.ep.nic.ID(), domainNames, opt.Lifetime())

		case header.NDPPrefixInformation:
			prefix := opt.Subnet()

			if header.IsV6LinkLocalUnicastAddress(prefix.ID()) {
				continue
			}

			if prefix.Prefix() == 0 {
				continue
			}

			if opt.OnLinkFlag() {
				ndp.handleOnLinkPrefixInformation(opt)
			}

			if opt.AutonomousAddressConfigurationFlag() {
				ndp.handleAutonomousPrefixInformation(opt)
			}

		case header.NDPRouteInformation:
			if !ndp.configs.DiscoverMoreSpecificRoutes {
				continue
			}

			dest, err := opt.Prefix()
			if err != nil {
				panic(fmt.Sprintf("%T.Prefix(): %s", opt, err))
			}

			prf := opt.RoutePreference()
			if prf == header.ReservedRoutePreference {
				continue
			}

			ndp.handleOffLinkRouteDiscovery(offLinkRoute{dest: dest, router: ip}, opt.RouteLifetime(), prf)
		}

	}
}

func (ndp *ndpState) invalidateOffLinkRoute(route offLinkRoute) {
	state, ok := ndp.offLinkRoutes[route]
	if !ok {
		return
	}

	state.invalidationJob.Cancel()
	delete(ndp.offLinkRoutes, route)

	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnOffLinkRouteInvalidated(ndp.ep.nic.ID(), route.dest, route.router)
	}
}

func (ndp *ndpState) handleOffLinkRouteDiscovery(route offLinkRoute, lifetime time.Duration, prf header.NDPRoutePreference) {
	ndpDisp := ndp.ep.protocol.options.NDPDisp
	if ndpDisp == nil {
		return
	}

	state, ok := ndp.offLinkRoutes[route]
	switch {
	case !ok && lifetime != 0:
		if len(ndp.offLinkRoutes) < MaxDiscoveredOffLinkRoutes {
			ndpDisp.OnOffLinkRouteUpdated(ndp.ep.nic.ID(), route.dest, route.router, prf)

			state := offLinkRouteState{
				prf: prf,
				invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
					ndp.invalidateOffLinkRoute(route)
				}),
			}

			state.invalidationJob.Schedule(lifetime)

			ndp.offLinkRoutes[route] = state
		}

	case ok && lifetime != 0:
		state.invalidationJob.Cancel()
		state.invalidationJob.Schedule(lifetime)

		if prf != state.prf {
			state.prf = prf

			ndpDisp.OnOffLinkRouteUpdated(ndp.ep.nic.ID(), route.dest, route.router, prf)
		}

		ndp.offLinkRoutes[route] = state

	case ok && lifetime == 0:
		ndp.invalidateOffLinkRoute(route)
	}
}

func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	ndpDisp := ndp.ep.protocol.options.NDPDisp
	if ndpDisp == nil {
		return
	}

	ndpDisp.OnOnLinkPrefixDiscovered(ndp.ep.nic.ID(), prefix)

	state := onLinkPrefixState{
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			ndp.invalidateOnLinkPrefix(prefix)
		}),
	}

	if l < header.NDPInfiniteLifetime {
		state.invalidationJob.Schedule(l)
	}

	ndp.onLinkPrefixes[prefix] = state
}

func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {
	s, ok := ndp.onLinkPrefixes[prefix]

	if !ok {
		return
	}

	s.invalidationJob.Cancel()
	delete(ndp.onLinkPrefixes, prefix)

	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnOnLinkPrefixInvalidated(ndp.ep.nic.ID(), prefix)
	}
}

func (ndp *ndpState) handleOnLinkPrefixInformation(pi header.NDPPrefixInformation) {
	prefix := pi.Subnet()
	prefixState, ok := ndp.onLinkPrefixes[prefix]
	vl := pi.ValidLifetime()

	if !ok && vl == 0 {
		return
	}

	if !ok && vl != 0 {
		if ndp.configs.DiscoverOnLinkPrefixes && len(ndp.onLinkPrefixes) < MaxDiscoveredOnLinkPrefixes {
			ndp.rememberOnLinkPrefix(prefix, vl)
		}
		return
	}

	if ok && vl == 0 {
		ndp.invalidateOnLinkPrefix(prefix)
		return
	}


	prefixState.invalidationJob.Cancel()

	if vl < header.NDPInfiniteLifetime {
		prefixState.invalidationJob.Schedule(vl)
	}

	ndp.onLinkPrefixes[prefix] = prefixState
}

func (ndp *ndpState) handleAutonomousPrefixInformation(pi header.NDPPrefixInformation) {
	vl := pi.ValidLifetime()
	pl := pi.PreferredLifetime()

	if pl > vl {
		return
	}

	prefix := pi.Subnet()

	if state, ok := ndp.slaacPrefixes[prefix]; ok {
		ndp.refreshSLAACPrefixLifetimes(prefix, &state, pl, vl)
		ndp.slaacPrefixes[prefix] = state
		return
	}

	if !ndp.configs.AutoGenGlobalAddresses {
		return
	}

	if len(ndp.slaacPrefixes) == MaxDiscoveredSLAACPrefixes {
		return
	}

	ndp.doSLAAC(prefix, pl, vl)
}

func (ndp *ndpState) doSLAAC(prefix tcpip.Subnet, pl, vl time.Duration) {
	if vl == 0 {
		return
	}

	if prefix.Prefix() != validPrefixLenForAutoGen {
		return
	}

	state := slaacPrefixState{
		deprecationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			state, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for the deprecated SLAAC prefix %s", prefix))
			}

			ndp.deprecateSLAACAddress(state.stableAddr.addressEndpoint)
		}),
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			state, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for the invalidated SLAAC prefix %s", prefix))
			}

			ndp.invalidateSLAACPrefix(prefix, state)
		}),
		tempAddrs:             make(map[tcpip.Address]tempSLAACAddrState),
		maxGenerationAttempts: ndp.configs.AutoGenAddressConflictRetries + 1,
	}

	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	if pl < header.NDPInfiniteLifetime {
		t := now.Add(pl)
		state.preferredUntil = &t
	}
	if vl < header.NDPInfiniteLifetime {
		t := now.Add(vl)
		state.validUntil = &t
	}

	if !ndp.generateSLAACAddr(prefix, &state) {
		return
	}


	if pl < header.NDPInfiniteLifetime && pl != 0 {
		state.deprecationJob.Schedule(pl)
	}

	if vl < header.NDPInfiniteLifetime {
		state.invalidationJob.Schedule(vl)
	}

	if state.stableAddr.addressEndpoint.GetKind() == stack.Permanent {
		ndp.generateTempSLAACAddr(prefix, &state, true)
	}

	ndp.slaacPrefixes[prefix] = state
}

func (ndp *ndpState) addAndAcquireSLAACAddr(addr tcpip.AddressWithPrefix, temporary bool, lifetimes stack.AddressLifetimes) stack.AddressEndpoint {
	addressEndpoint, err := ndp.ep.addAndAcquirePermanentAddressLocked(addr, stack.AddressProperties{
		PEB:        stack.FirstPrimaryEndpoint,
		ConfigType: stack.AddressConfigSlaac,
		Lifetimes:  lifetimes,
		Temporary:  temporary,
	})
	if err != nil {
		panic(fmt.Sprintf("ndp: error when adding SLAAC address %+v: %s", addr, err))
	}

	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		if disp := ndpDisp.OnAutoGenAddress(ndp.ep.nic.ID(), addr); disp != nil {
			addressEndpoint.RegisterDispatcher(disp)
		}
	}

	return addressEndpoint
}

func (ndp *ndpState) generateSLAACAddr(prefix tcpip.Subnet, state *slaacPrefixState) bool {
	if addressEndpoint := state.stableAddr.addressEndpoint; addressEndpoint != nil {
		panic(fmt.Sprintf("ndp: SLAAC prefix %s already has a permanent address %s", prefix, addressEndpoint.AddressWithPrefix()))
	}

	if state.generationAttempts == state.maxGenerationAttempts {
		return false
	}

	var generatedAddr tcpip.AddressWithPrefix
	prefixID := prefix.ID()
	addrBytes := prefixID.AsSlice()

	for i := 0; ; i++ {
		if i == maxSLAACAddrLocalRegenAttempts {
			return false
		}

		dadCounter := state.generationAttempts + state.stableAddr.localGenerationFailures
		if oIID := ndp.ep.protocol.options.OpaqueIIDOpts; oIID.NICNameFromID != nil {
			addrBytes = header.AppendOpaqueInterfaceIdentifier(
				addrBytes[:header.IIDOffsetInIPv6Address],
				prefix,
				oIID.NICNameFromID(ndp.ep.nic.ID(), ndp.ep.nic.Name()),
				dadCounter,
				oIID.SecretKey,
			)
		} else if dadCounter == 0 {
			linkAddr := ndp.ep.nic.LinkAddress()
			if !header.IsValidUnicastEthernetAddress(linkAddr) {
				return false
			}

			header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
		} else {
			return false
		}

		generatedAddr = tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16Slice(addrBytes),
			PrefixLen: validPrefixLenForAutoGen,
		}

		if !ndp.ep.hasPermanentAddressRLocked(generatedAddr.Address) {
			break
		}

		state.stableAddr.localGenerationFailures++
	}

	deprecated := state.preferredUntil != nil && !state.preferredUntil.After(ndp.ep.protocol.stack.Clock().NowMonotonic())
	var preferredUntil tcpip.MonotonicTime
	if !deprecated {
		if state.preferredUntil != nil {
			preferredUntil = *state.preferredUntil
		} else {
			preferredUntil = tcpip.MonotonicTimeInfinite()
		}
	}
	validUntil := tcpip.MonotonicTimeInfinite()
	if state.validUntil != nil {
		validUntil = *state.validUntil
	}
	if addressEndpoint := ndp.addAndAcquireSLAACAddr(generatedAddr, false, stack.AddressLifetimes{
		Deprecated:     deprecated,
		PreferredUntil: preferredUntil,
		ValidUntil:     validUntil,
	}); addressEndpoint != nil {
		state.stableAddr.addressEndpoint = addressEndpoint
		state.generationAttempts++
		return true
	}

	return false
}

func (ndp *ndpState) regenerateSLAACAddr(prefix tcpip.Subnet) {
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: SLAAC prefix state not found to regenerate address for %s", prefix))
	}

	if ndp.generateSLAACAddr(prefix, &state) {
		ndp.slaacPrefixes[prefix] = state
		return
	}

	ndp.invalidateSLAACPrefix(prefix, state)
}

func (ndp *ndpState) generateTempSLAACAddr(prefix tcpip.Subnet, prefixState *slaacPrefixState, resetGenAttempts bool) bool {
	if !ndp.configs.AutoGenTempGlobalAddresses || prefix == header.IPv6LinkLocalPrefix.Subnet() {
		return false
	}

	if resetGenAttempts {
		prefixState.generationAttempts = 0
		prefixState.maxGenerationAttempts = ndp.configs.AutoGenAddressConflictRetries + 1
	}

	if prefixState.generationAttempts == prefixState.maxGenerationAttempts {
		return false
	}

	stableAddr := prefixState.stableAddr.addressEndpoint.AddressWithPrefix().Address
	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	vl := ndp.configs.MaxTempAddrValidLifetime
	if prefixState.validUntil != nil {
		if prefixVL := prefixState.validUntil.Sub(now); vl > prefixVL {
			vl = prefixVL
		}
	}

	if vl <= 0 {
		return false
	}

	pl := ndp.configs.MaxTempAddrPreferredLifetime - ndp.temporaryAddressDesyncFactor
	if prefixState.preferredUntil != nil {
		if prefixPL := prefixState.preferredUntil.Sub(now); pl > prefixPL {
			pl = prefixPL
		}
	}

	if pl <= ndp.configs.RegenAdvanceDuration {
		return false
	}

	var generatedAddr tcpip.AddressWithPrefix
	for i := 0; ; i++ {
		if i == maxSLAACAddrLocalRegenAttempts {
			return false
		}

		generatedAddr = header.GenerateTempIPv6SLAACAddr(ndp.temporaryIIDHistory[:], stableAddr)
		if !ndp.ep.hasPermanentAddressRLocked(generatedAddr.Address) {
			break
		}
	}

	addressEndpoint := ndp.addAndAcquireSLAACAddr(generatedAddr, true, stack.AddressLifetimes{
		Deprecated:     false,
		PreferredUntil: now.Add(pl),
		ValidUntil:     now.Add(vl),
	})
	if addressEndpoint == nil {
		return false
	}

	state := tempSLAACAddrState{
		deprecationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to deprecate temporary address %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to deprecate temporary address %s", generatedAddr))
			}

			ndp.deprecateSLAACAddress(tempAddrState.addressEndpoint)
		}),
		invalidationJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to invalidate temporary address %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to invalidate temporary address %s", generatedAddr))
			}

			ndp.invalidateTempSLAACAddr(prefixState.tempAddrs, generatedAddr.Address, tempAddrState)
		}),
		regenJob: tcpip.NewJob(ndp.ep.protocol.stack.Clock(), &ndp.ep.mu, func() {
			prefixState, ok := ndp.slaacPrefixes[prefix]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry for %s to regenerate temporary address after %s", prefix, generatedAddr))
			}

			tempAddrState, ok := prefixState.tempAddrs[generatedAddr.Address]
			if !ok {
				panic(fmt.Sprintf("ndp: must have a tempAddr entry to regenerate temporary address after %s", generatedAddr))
			}

			if tempAddrState.regenerated {
				return
			}

			tempAddrState.regenerated = ndp.generateTempSLAACAddr(prefix, &prefixState, true)
			prefixState.tempAddrs[generatedAddr.Address] = tempAddrState
			ndp.slaacPrefixes[prefix] = prefixState
		}),
		createdAt:       now,
		addressEndpoint: addressEndpoint,
	}

	state.deprecationJob.Schedule(pl)
	state.invalidationJob.Schedule(vl)
	state.regenJob.Schedule(pl - ndp.configs.RegenAdvanceDuration)

	prefixState.generationAttempts++
	prefixState.tempAddrs[generatedAddr.Address] = state

	return true
}

func (ndp *ndpState) regenerateTempSLAACAddr(prefix tcpip.Subnet, resetGenAttempts bool) {
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: SLAAC prefix state not found to regenerate temporary address for %s", prefix))
	}

	ndp.generateTempSLAACAddr(prefix, &state, resetGenAttempts)
	ndp.slaacPrefixes[prefix] = state
}

func (ndp *ndpState) refreshSLAACPrefixLifetimes(prefix tcpip.Subnet, prefixState *slaacPrefixState, pl, vl time.Duration) {
	prefixState.deprecationJob.Cancel()

	now := ndp.ep.protocol.stack.Clock().NowMonotonic()

	deprecated := pl == 0
	if pl < header.NDPInfiniteLifetime {
		if !deprecated {
			prefixState.deprecationJob.Schedule(pl)
		}
		t := now.Add(pl)
		prefixState.preferredUntil = &t
	} else {
		prefixState.preferredUntil = nil
	}


	if vl >= header.NDPInfiniteLifetime {
		prefixState.invalidationJob.Cancel()
		prefixState.validUntil = nil
	} else {
		var effectiveVl time.Duration
		var rl time.Duration

		if prefixState.validUntil == nil {
			rl = header.NDPInfiniteLifetime
		} else {
			rl = prefixState.validUntil.Sub(now)
		}

		if vl > MinPrefixInformationValidLifetimeForUpdate || vl > rl {
			effectiveVl = vl
		} else if rl > MinPrefixInformationValidLifetimeForUpdate {
			effectiveVl = MinPrefixInformationValidLifetimeForUpdate
		}

		if effectiveVl != 0 {
			prefixState.invalidationJob.Cancel()
			prefixState.invalidationJob.Schedule(effectiveVl)
			t := now.Add(effectiveVl)
			prefixState.validUntil = &t
		}
	}

	{
		var preferredUntil tcpip.MonotonicTime
		if !deprecated {
			if prefixState.preferredUntil == nil {
				preferredUntil = tcpip.MonotonicTimeInfinite()
			} else {
				preferredUntil = *prefixState.preferredUntil
			}
		}
		validUntil := tcpip.MonotonicTimeInfinite()
		if prefixState.validUntil != nil {
			validUntil = *prefixState.validUntil
		}
		if addressEndpoint := prefixState.stableAddr.addressEndpoint; !addressEndpoint.Deprecated() && deprecated {
			if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
				ndpDisp.OnAutoGenAddressDeprecated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
			}
		}
		prefixState.stableAddr.addressEndpoint.SetLifetimes(stack.AddressLifetimes{
			Deprecated:     deprecated,
			PreferredUntil: preferredUntil,
			ValidUntil:     validUntil,
		})
	}

	if prefixState.stableAddr.addressEndpoint.GetKind() != stack.Permanent {
		return
	}

	var regenForAddr tcpip.Address
	allAddressesRegenerated := true
	for tempAddr, tempAddrState := range prefixState.tempAddrs {
		validUntil := tempAddrState.createdAt.Add(ndp.configs.MaxTempAddrValidLifetime)
		if prefixState.validUntil != nil && prefixState.validUntil.Before(validUntil) {
			validUntil = *prefixState.validUntil
		}

		newValidLifetime := validUntil.Sub(now)
		if newValidLifetime <= 0 {
			ndp.invalidateTempSLAACAddr(prefixState.tempAddrs, tempAddr, tempAddrState)
			continue
		}
		tempAddrState.invalidationJob.Cancel()
		tempAddrState.invalidationJob.Schedule(newValidLifetime)

		preferredUntil := tempAddrState.createdAt.Add(ndp.configs.MaxTempAddrPreferredLifetime - ndp.temporaryAddressDesyncFactor)
		if prefixState.preferredUntil != nil && prefixState.preferredUntil.Before(preferredUntil) {
			preferredUntil = *prefixState.preferredUntil
		}

		newPreferredLifetime := preferredUntil.Sub(now)
		tempAddrState.deprecationJob.Cancel()
		deprecated := newPreferredLifetime <= 0
		if !deprecated {
			tempAddrState.deprecationJob.Schedule(newPreferredLifetime)
		}

		if addressEndpoint := tempAddrState.addressEndpoint; !addressEndpoint.Deprecated() && deprecated {
			if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
				ndpDisp.OnAutoGenAddressDeprecated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
			}
		}
		tempAddrState.addressEndpoint.SetLifetimes(stack.AddressLifetimes{
			Deprecated:     deprecated,
			ValidUntil:     validUntil,
			PreferredUntil: preferredUntil,
		})

		tempAddrState.regenJob.Cancel()
		if tempAddrState.regenerated {
		} else {
			allAddressesRegenerated = false

			if newPreferredLifetime <= ndp.configs.RegenAdvanceDuration {
				regenForAddr = tempAddr
			} else {
				tempAddrState.regenJob.Schedule(newPreferredLifetime - ndp.configs.RegenAdvanceDuration)
			}
		}
	}

	if regenForAddr.BitLen() != 0 || allAddressesRegenerated {
		if state, ok := prefixState.tempAddrs[regenForAddr]; ndp.generateTempSLAACAddr(prefix, prefixState, true) && ok {
			state.regenerated = true
			prefixState.tempAddrs[regenForAddr] = state
		}
	}
}

func (ndp *ndpState) deprecateSLAACAddress(addressEndpoint stack.AddressEndpoint) {
	if addressEndpoint.Deprecated() {
		return
	}

	addressEndpoint.SetDeprecated(true)
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressDeprecated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
	}
}

func (ndp *ndpState) invalidateSLAACPrefix(prefix tcpip.Subnet, state slaacPrefixState) {
	ndp.cleanupSLAACPrefixResources(prefix, state)

	if addressEndpoint := state.stableAddr.addressEndpoint; addressEndpoint != nil {
		if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
			ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), addressEndpoint.AddressWithPrefix())
		}

		if err := ndp.ep.removePermanentEndpointInnerLocked(addressEndpoint, stack.AddressRemovalInvalidated, &stack.DADAborted{}); err != nil {
			panic(fmt.Sprintf("ndp: error removing stable SLAAC address %s: %s", addressEndpoint.AddressWithPrefix(), err))
		}
	}
}

func (ndp *ndpState) cleanupSLAACAddrResourcesAndNotify(addr tcpip.AddressWithPrefix, invalidatePrefix bool) {
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), addr)
	}

	prefix := addr.Subnet()
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok || state.stableAddr.addressEndpoint == nil || addr.Address != state.stableAddr.addressEndpoint.AddressWithPrefix().Address {
		return
	}

	if !invalidatePrefix {
		state.stableAddr.addressEndpoint.DecRef()
		state.stableAddr.addressEndpoint = nil
		ndp.slaacPrefixes[prefix] = state
		return
	}

	ndp.cleanupSLAACPrefixResources(prefix, state)
}

func (ndp *ndpState) cleanupSLAACPrefixResources(prefix tcpip.Subnet, state slaacPrefixState) {
	for tempAddr, tempAddrState := range state.tempAddrs {
		ndp.invalidateTempSLAACAddr(state.tempAddrs, tempAddr, tempAddrState)
	}

	if state.stableAddr.addressEndpoint != nil {
		state.stableAddr.addressEndpoint.DecRef()
		state.stableAddr.addressEndpoint = nil
	}
	state.deprecationJob.Cancel()
	state.invalidationJob.Cancel()
	delete(ndp.slaacPrefixes, prefix)
}

func (ndp *ndpState) invalidateTempSLAACAddr(tempAddrs map[tcpip.Address]tempSLAACAddrState, tempAddr tcpip.Address, tempAddrState tempSLAACAddrState) {
	ndp.cleanupTempSLAACAddrResourcesAndNotifyInner(tempAddrs, tempAddr, tempAddrState)

	if err := ndp.ep.removePermanentEndpointInnerLocked(tempAddrState.addressEndpoint, stack.AddressRemovalInvalidated, &stack.DADAborted{}); err != nil {
		panic(fmt.Sprintf("error removing temporary SLAAC address %s: %s", tempAddrState.addressEndpoint.AddressWithPrefix(), err))
	}
}

func (ndp *ndpState) cleanupTempSLAACAddrResourcesAndNotify(addr tcpip.AddressWithPrefix) {
	prefix := addr.Subnet()
	state, ok := ndp.slaacPrefixes[prefix]
	if !ok {
		panic(fmt.Sprintf("ndp: must have a slaacPrefixes entry to clean up temp addr %s resources", addr))
	}

	tempAddrState, ok := state.tempAddrs[addr.Address]
	if !ok {
		panic(fmt.Sprintf("ndp: must have a tempAddr entry to clean up temp addr %s resources", addr))
	}

	ndp.cleanupTempSLAACAddrResourcesAndNotifyInner(state.tempAddrs, addr.Address, tempAddrState)
}

func (ndp *ndpState) cleanupTempSLAACAddrResourcesAndNotifyInner(tempAddrs map[tcpip.Address]tempSLAACAddrState, tempAddr tcpip.Address, tempAddrState tempSLAACAddrState) {
	if ndpDisp := ndp.ep.protocol.options.NDPDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.ep.nic.ID(), tempAddrState.addressEndpoint.AddressWithPrefix())
	}

	tempAddrState.addressEndpoint.DecRef()
	tempAddrState.addressEndpoint = nil
	tempAddrState.deprecationJob.Cancel()
	tempAddrState.invalidationJob.Cancel()
	tempAddrState.regenJob.Cancel()
	delete(tempAddrs, tempAddr)
}

func (ndp *ndpState) cleanupState() {
	for prefix, state := range ndp.slaacPrefixes {
		ndp.invalidateSLAACPrefix(prefix, state)
	}

	for prefix := range ndp.onLinkPrefixes {
		ndp.invalidateOnLinkPrefix(prefix)
	}

	if got := len(ndp.onLinkPrefixes); got != 0 {
		panic(fmt.Sprintf("ndp: still have discovered on-link prefixes after cleaning up; found = %d", got))
	}

	for route := range ndp.offLinkRoutes {
		ndp.invalidateOffLinkRoute(route)
	}

	if got := len(ndp.offLinkRoutes); got != 0 {
		panic(fmt.Sprintf("ndp: still have discovered off-link routes after cleaning up; found = %d", got))
	}

	ndp.dhcpv6Configuration = 0
}

func (ndp *ndpState) startSolicitingRouters() {
	if ndp.rtrSolicitTimer.timer != nil {
		return
	}

	remaining := ndp.configs.MaxRtrSolicitations
	if remaining == 0 {
		return
	}

	if !ndp.configs.HandleRAs.enabled(ndp.ep.Forwarding()) {
		return
	}

	var delay time.Duration
	if ndp.configs.MaxRtrSolicitationDelay > 0 {
		delay = time.Duration(ndp.ep.protocol.stack.InsecureRNG().Int63n(int64(ndp.configs.MaxRtrSolicitationDelay)))
	}

	done := false

	ndp.rtrSolicitTimer = timer{
		done: &done,
		timer: ndp.ep.protocol.stack.Clock().AfterFunc(delay, func() {
			localAddr := header.IPv6Any
			if addressEndpoint := ndp.ep.AcquireOutgoingPrimaryAddress(header.IPv6AllRoutersLinkLocalMulticastAddress, tcpip.Address{}, false); addressEndpoint != nil {
				localAddr = addressEndpoint.AddressWithPrefix().Address
				addressEndpoint.DecRef()
			}

			var optsSerializer header.NDPOptionsSerializer
			linkAddress := ndp.ep.nic.LinkAddress()
			if localAddr != header.IPv6Any && header.IsValidUnicastEthernetAddress(linkAddress) {
				optsSerializer = header.NDPOptionsSerializer{
					header.NDPSourceLinkLayerAddressOption(linkAddress),
				}
			}
			payloadSize := header.ICMPv6HeaderSize + header.NDPRSMinimumSize + optsSerializer.Length()
			icmpView := buffer.NewView(payloadSize)
			icmpView.Grow(payloadSize)
			icmpData := header.ICMPv6(icmpView.AsSlice())
			icmpData.SetType(header.ICMPv6RouterSolicit)
			rs := header.NDPRouterSolicit(icmpData.MessageBody())
			rs.Options().Serialize(optsSerializer)
			icmpData.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpData,
				Src:    localAddr,
				Dst:    header.IPv6AllRoutersLinkLocalMulticastAddress,
			}))

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(ndp.ep.MaxHeaderLength()),
				Payload:            buffer.MakeWithView(icmpView),
			})
			defer pkt.DecRef()

			sent := ndp.ep.stats.icmp.packetsSent
			if err := addIPHeader(localAddr, header.IPv6AllRoutersLinkLocalMulticastAddress, pkt, stack.NetworkHeaderParams{
				Protocol: header.ICMPv6ProtocolNumber,
				TTL:      header.NDPHopLimit,
			}, nil); err != nil {
				panic(fmt.Sprintf("failed to add IP header: %s", err))
			}

			if err := ndp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllRoutersLinkLocalMulticastAddress), pkt); err != nil {
				sent.dropped.Increment()
				remaining = 0
			} else {
				sent.routerSolicit.Increment()
				remaining--
			}

			ndp.ep.mu.Lock()
			defer ndp.ep.mu.Unlock()

			if done {
				return
			}

			if remaining == 0 {
				ndp.stopSolicitingRouters()
				return
			}

			ndp.rtrSolicitTimer.timer.Reset(ndp.configs.RtrSolicitationInterval)
		}),
	}
}

func (ndp *ndpState) forwardingChanged(forwarding bool) {
	if forwarding {
		if ndp.configs.HandleRAs.enabled(forwarding) {
			return
		}

		ndp.stopSolicitingRouters()
		return
	}

	if ndp.ep.Enabled() {
		ndp.startSolicitingRouters()
	}
}

func (ndp *ndpState) stopSolicitingRouters() {
	if ndp.rtrSolicitTimer.timer == nil {
		return
	}

	ndp.rtrSolicitTimer.timer.Stop()
	*ndp.rtrSolicitTimer.done = true
	ndp.rtrSolicitTimer = timer{}
}

func (ndp *ndpState) init(ep *endpoint, dadOptions ip.DADOptions) {
	if ndp.offLinkRoutes != nil {
		panic("attempted to initialize NDP state twice")
	}

	ndp.ep = ep
	ndp.configs = ep.protocol.options.NDPConfigs
	ndp.dad.Init(&ndp.ep.mu, ep.protocol.options.DADConfigs, dadOptions)
	ndp.offLinkRoutes = make(map[offLinkRoute]offLinkRouteState)
	ndp.onLinkPrefixes = make(map[tcpip.Subnet]onLinkPrefixState)
	ndp.slaacPrefixes = make(map[tcpip.Subnet]slaacPrefixState)

	header.InitialTempIID(ndp.temporaryIIDHistory[:], ndp.ep.protocol.options.TempIIDSeed, ndp.ep.nic.ID())
	ndp.temporaryAddressDesyncFactor = time.Duration(ep.protocol.stack.InsecureRNG().Int63n(int64(MaxDesyncFactor)))
}

func (ndp *ndpState) SendDADMessage(addr tcpip.Address, nonce []byte) tcpip.Error {
	snmc := header.SolicitedNodeAddr(addr)
	return ndp.ep.sendNDPNS(header.IPv6Any, snmc, addr, header.EthernetAddressFromMulticastIPv6Address(snmc), header.NDPOptionsSerializer{
		header.NDPNonceOption(nonce),
	})
}

func (e *endpoint) sendNDPNS(srcAddr, dstAddr, targetAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, opts header.NDPOptionsSerializer) tcpip.Error {
	icmpView := buffer.NewView(header.ICMPv6NeighborSolicitMinimumSize + opts.Length())
	icmpView.Grow(header.ICMPv6NeighborSolicitMinimumSize + opts.Length())
	icmp := header.ICMPv6(icmpView.AsSlice())
	icmp.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(icmp.MessageBody())
	ns.SetTargetAddress(targetAddr)
	ns.Options().Serialize(opts)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    srcAddr,
		Dst:    dstAddr,
	}))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(e.MaxHeaderLength()),
		Payload:            buffer.MakeWithView(icmpView),
	})
	defer pkt.DecRef()

	if err := addIPHeader(srcAddr, dstAddr, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.NDPHopLimit,
	}, nil); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	sent := e.stats.icmp.packetsSent
	err := e.nic.WritePacketToRemote(remoteLinkAddr, pkt)
	if err != nil {
		sent.dropped.Increment()
	} else {
		sent.neighborSolicit.Increment()
	}
	return err
}

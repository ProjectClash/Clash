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

package stack

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

func (lifetimes *AddressLifetimes) sanitize() {
	if lifetimes.Deprecated {
		lifetimes.PreferredUntil = tcpip.MonotonicTime{}
	}
}

var _ AddressableEndpoint = (*AddressableEndpointState)(nil)

type AddressableEndpointState struct {
	networkEndpoint NetworkEndpoint
	options         AddressableEndpointStateOptions

	mu addressableEndpointStateRWMutex `state:"nosave"`
	endpoints map[tcpip.Address]*addressState `state:"nosave"`
	primary []*addressState `state:"nosave"`
}

type AddressableEndpointStateOptions struct {
	HiddenWhileDisabled bool
}

func (a *AddressableEndpointState) Init(networkEndpoint NetworkEndpoint, options AddressableEndpointStateOptions) {
	a.networkEndpoint = networkEndpoint
	a.options = options

	a.mu.Lock()
	defer a.mu.Unlock()
	a.endpoints = make(map[tcpip.Address]*addressState)
}

func (a *AddressableEndpointState) OnNetworkEndpointEnabledChanged() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.endpoints {
		ep.mu.Lock()
		ep.notifyChangedLocked()
		ep.mu.Unlock()
	}
}

func (a *AddressableEndpointState) GetAddress(addr tcpip.Address) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep, ok := a.endpoints[addr]
	if !ok {
		return nil
	}
	return ep
}

func (a *AddressableEndpointState) ForEachEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.endpoints {
		if !f(ep) {
			return
		}
	}
}

func (a *AddressableEndpointState) ForEachPrimaryEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.primary {
		if !f(ep) {
			return
		}
	}
}

func (a *AddressableEndpointState) releaseAddressState(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseAddressStateLocked(addrState)
}

func (a *AddressableEndpointState) releaseAddressStateLocked(addrState *addressState) {
	oldPrimary := a.primary
	for i, s := range a.primary {
		if s == addrState {
			a.primary = append(a.primary[:i], a.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(a.endpoints, addrState.addr.Address)
}

func (a *AddressableEndpointState) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error) {
	return a.AddAndAcquireAddress(addr, properties, Permanent)
}

func (a *AddressableEndpointState) AddAndAcquireTemporaryAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior) (AddressEndpoint, tcpip.Error) {
	return a.AddAndAcquireAddress(addr, AddressProperties{PEB: peb}, Temporary)
}

func (a *AddressableEndpointState) AddAndAcquireAddress(addr tcpip.AddressWithPrefix, properties AddressProperties, kind AddressKind) (AddressEndpoint, tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ep, err := a.addAndAcquireAddressLocked(addr, properties, kind)
	if ep == nil {
		return nil, err
	}
	return ep, err
}

func (a *AddressableEndpointState) addAndAcquireAddressLocked(addr tcpip.AddressWithPrefix, properties AddressProperties, kind AddressKind) (*addressState, tcpip.Error) {
	var permanent bool
	switch kind {
	case PermanentExpired:
		panic(fmt.Sprintf("cannot add address %s in PermanentExpired state", addr))
	case Permanent, PermanentTentative:
		permanent = true
	case Temporary:
	default:
		panic(fmt.Sprintf("unknown address kind: %d", kind))
	}
	attemptAddToPrimary := true
	addrState, ok := a.endpoints[addr.Address]
	if ok {
		if !permanent {
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		addrState.mu.RLock()
		if addrState.refs.ReadRefs() == 0 {
			panic(fmt.Sprintf("found an address that should have been released (ref count == 0); address = %s", addrState.addr))
		}
		isPermanent := addrState.kind.IsPermanent()
		addrState.mu.RUnlock()

		if isPermanent {
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		for i, s := range a.primary {
			if s == addrState {
				switch properties.PEB {
				case CanBePrimaryEndpoint:
					attemptAddToPrimary = false
				case FirstPrimaryEndpoint:
					if i == 0 {
						attemptAddToPrimary = false
					} else {
						a.primary = append(a.primary[:i], a.primary[i+1:]...)
					}
				case NeverPrimaryEndpoint:
					a.primary = append(a.primary[:i], a.primary[i+1:]...)
				default:
					panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
				}
				break
			}
		}
		addrState.refs.IncRef()
	} else {
		addrState = &addressState{
			addressableEndpointState: a,
			addr:                     addr,
			temporary:                properties.Temporary,
			subnet: addr.Subnet(),
		}
		addrState.refs.InitRefs()
		a.endpoints[addr.Address] = addrState
		addrState.kind = Temporary
	}

	addrState.mu.Lock()
	defer addrState.mu.Unlock()

	if permanent {
		if addrState.kind.IsPermanent() {
			panic(fmt.Sprintf("only non-permanent addresses should be promoted to permanent; address = %s", addrState.addr))
		}

		addrState.refs.IncRef()
		addrState.kind = kind
	}
	addrState.configType = properties.ConfigType
	lifetimes := properties.Lifetimes
	lifetimes.sanitize()
	addrState.lifetimes = lifetimes
	addrState.disp = properties.Disp

	if attemptAddToPrimary {
		switch properties.PEB {
		case NeverPrimaryEndpoint:
		case CanBePrimaryEndpoint:
			a.primary = append(a.primary, addrState)
		case FirstPrimaryEndpoint:
			if cap(a.primary) == len(a.primary) {
				a.primary = append([]*addressState{addrState}, a.primary...)
			} else {
				primaryCount := len(a.primary)
				a.primary = append(a.primary, nil)
				if n := copy(a.primary[1:], a.primary); n != primaryCount {
					panic(fmt.Sprintf("copied %d elements; expected = %d elements", n, primaryCount))
				}
				a.primary[0] = addrState
			}
		default:
			panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
		}
	}

	addrState.notifyChangedLocked()
	return addrState, nil
}

func (a *AddressableEndpointState) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentAddressLocked(addr)
}

func (a *AddressableEndpointState) removePermanentAddressLocked(addr tcpip.Address) tcpip.Error {
	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}

	return a.removePermanentEndpointLocked(addrState, AddressRemovalManualAction)
}

func (a *AddressableEndpointState) RemovePermanentEndpoint(ep AddressEndpoint, reason AddressRemovalReason) tcpip.Error {
	addrState, ok := ep.(*addressState)
	if !ok || addrState.addressableEndpointState != a {
		return &tcpip.ErrInvalidEndpointState{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentEndpointLocked(addrState, reason)
}

func (a *AddressableEndpointState) removePermanentEndpointLocked(addrState *addressState, reason AddressRemovalReason) tcpip.Error {
	if !addrState.GetKind().IsPermanent() {
		return &tcpip.ErrBadLocalAddress{}
	}

	addrState.remove(reason)
	a.decAddressRefLocked(addrState)
	return nil
}

func (a *AddressableEndpointState) decAddressRef(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decAddressRefLocked(addrState)
}

func (a *AddressableEndpointState) decAddressRefLocked(addrState *addressState) {
	destroy := false
	addrState.refs.DecRef(func() {
		destroy = true
	})

	if !destroy {
		return
	}
	addrState.mu.Lock()
	defer addrState.mu.Unlock()
	if addrState.kind.IsPermanent() {
		panic(fmt.Sprintf("permanent addresses should be removed through the AddressableEndpoint: addr = %s, kind = %d", addrState.addr, addrState.kind))
	}

	a.releaseAddressStateLocked(addrState)
}

func (a *AddressableEndpointState) SetDeprecated(addr tcpip.Address, deprecated bool) tcpip.Error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}
	addrState.SetDeprecated(deprecated)
	return nil
}

func (a *AddressableEndpointState) SetLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}
	addrState.SetLifetimes(lifetimes)
	return nil
}

func (a *AddressableEndpointState) MainAddress() tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep := a.acquirePrimaryAddressRLocked(tcpip.Address{}, tcpip.Address{}, func(ep *addressState) bool {
		switch kind := ep.GetKind(); kind {
		case Permanent:
			return a.networkEndpoint.Enabled() || !a.options.HiddenWhileDisabled
		case PermanentTentative, PermanentExpired, Temporary:
			return false
		default:
			panic(fmt.Sprintf("unknown address kind: %d", kind))
		}
	})
	if ep == nil {
		return tcpip.AddressWithPrefix{}
	}
	addr := ep.AddressWithPrefix()
	ep.decRefMustNotFree()
	return addr
}

func (a *AddressableEndpointState) acquirePrimaryAddressRLocked(remoteAddr, srcHint tcpip.Address, isValid func(*addressState) bool) *addressState {
	if remoteAddr.Len() == header.IPv4AddressSize && remoteAddr != (tcpip.Address{}) {
		var best *addressState
		var bestLen uint8
		for _, state := range a.primary {
			if !isValid(state) {
				continue
			}
			if state.addr.Address == srcHint && srcHint != (tcpip.Address{}) {
				best = state
				break
			}
			stateLen := state.addr.Address.MatchingPrefix(remoteAddr)
			if best == nil || bestLen < stateLen {
				best = state
				bestLen = stateLen
			}
		}
		if best != nil && best.TryIncRef() {
			return best
		}
	}

	var deprecatedEndpoint *addressState
	for _, ep := range a.primary {
		if !isValid(ep) {
			continue
		}

		if !ep.Deprecated() {
			if ep.TryIncRef() {
				if deprecatedEndpoint != nil {
					deprecatedEndpoint.decRefMustNotFree()
				}

				return ep
			}
		} else if deprecatedEndpoint == nil && ep.TryIncRef() {
			deprecatedEndpoint = ep
		}
	}

	return deprecatedEndpoint
}

func (a *AddressableEndpointState) AcquireAssignedAddressOrMatching(localAddr tcpip.Address, f func(AddressEndpoint) bool, allowTemp bool, tempPEB PrimaryEndpointBehavior, readOnly bool) AddressEndpoint {
	lookup := func() *addressState {
		if addrState, ok := a.endpoints[localAddr]; ok {
			if !addrState.IsAssigned(allowTemp) {
				return nil
			}

			if !readOnly && !addrState.TryIncRef() {
				panic(fmt.Sprintf("failed to increase the reference count for address = %s", addrState.addr))
			}

			return addrState
		}

		if f != nil {
			for _, addrState := range a.endpoints {
				if addrState.IsAssigned(allowTemp) && f(addrState) {
					if !readOnly && !addrState.TryIncRef() {
						continue
					}
					return addrState
				}
			}
		}
		return nil
	}
	a.mu.RLock()
	ep := lookup()
	a.mu.RUnlock()

	if ep != nil {
		return ep
	}

	if !allowTemp {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ep = lookup()
	if ep != nil {
		return ep
	}

	addr := localAddr.WithPrefix()
	ep, err := a.addAndAcquireAddressLocked(addr, AddressProperties{PEB: tempPEB, Temporary: true}, Temporary)
	if err != nil {
		panic(fmt.Sprintf("a.addAndAcquireAddressLocked(%s, AddressProperties{PEB: %s}, false): %s", addr, tempPEB, err))
	}

	if ep == nil {
		return nil
	}
	if readOnly {
		if ep.addressableEndpointState == a {
			ep.addressableEndpointState.decAddressRefLocked(ep)
		} else {
			ep.DecRef()
		}
	}
	return ep
}

func (a *AddressableEndpointState) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior, readOnly bool) AddressEndpoint {
	return a.AcquireAssignedAddressOrMatching(localAddr, nil, allowTemp, tempPEB, readOnly)
}

func (a *AddressableEndpointState) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, srcHint tcpip.Address, allowExpired bool) AddressEndpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	ep := a.acquirePrimaryAddressRLocked(remoteAddr, srcHint, func(ep *addressState) bool {
		return ep.IsAssigned(allowExpired)
	})

	if ep == nil {
		return nil
	}

	return ep
}

func (a *AddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	if a.options.HiddenWhileDisabled && !a.networkEndpoint.Enabled() {
		return addrs
	}
	for _, ep := range a.primary {
		switch kind := ep.GetKind(); kind {
		case PermanentTentative, PermanentExpired, Temporary:
			continue
		case Permanent:
		default:
			panic(fmt.Sprintf("address %s has unknown kind %d", ep.AddressWithPrefix(), kind))
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

func (a *AddressableEndpointState) PermanentAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.endpoints {
		if !ep.GetKind().IsPermanent() {
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

func (a *AddressableEndpointState) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ep := range a.endpoints {
		switch err := a.removePermanentEndpointLocked(ep, AddressRemovalInterfaceRemoved); err.(type) {
		case nil, *tcpip.ErrBadLocalAddress:
		default:
			panic(fmt.Sprintf("unexpected error from removePermanentEndpointLocked(%s): %s", ep.addr, err))
		}
	}
}

var _ AddressEndpoint = (*addressState)(nil)

type addressState struct {
	addressableEndpointState *AddressableEndpointState
	addr                     tcpip.AddressWithPrefix
	subnet                   tcpip.Subnet
	temporary                bool

	mu   addressStateRWMutex
	refs addressStateRefs
	kind AddressKind
	configType AddressConfigType
	lifetimes AddressLifetimes
	disp AddressDispatcher
}

func (a *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return a.addr
}

func (a *addressState) Subnet() tcpip.Subnet {
	return a.subnet
}

func (a *addressState) GetKind() AddressKind {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.kind
}

func (a *addressState) SetKind(kind AddressKind) {
	a.mu.Lock()
	defer a.mu.Unlock()

	prevKind := a.kind
	a.kind = kind
	if kind == PermanentExpired {
		a.notifyRemovedLocked(AddressRemovalManualAction)
	} else if prevKind != kind && a.addressableEndpointState.networkEndpoint.Enabled() {
		a.notifyChangedLocked()
	}
}

func (a *addressState) notifyRemovedLocked(reason AddressRemovalReason) {
	if disp := a.disp; disp != nil {
		a.disp.OnRemoved(reason)
		a.disp = nil
	}
}

func (a *addressState) remove(reason AddressRemovalReason) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.kind = PermanentExpired
	a.notifyRemovedLocked(reason)
}

func (a *addressState) IsAssigned(allowExpired bool) bool {
	switch kind := a.GetKind(); kind {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return allowExpired
	case Permanent, Temporary:
		return true
	default:
		panic(fmt.Sprintf("address %s has unknown kind %d", a.AddressWithPrefix(), kind))
	}
}

func (a *addressState) TryIncRef() bool {
	return a.refs.TryIncRef()
}

func (a *addressState) DecRef() {
	a.addressableEndpointState.decAddressRef(a)
}

func (a *addressState) decRefMustNotFree() {
	a.refs.DecRef(func() {
		panic(fmt.Sprintf("cannot decrease addressState %s without freeing the endpoint", a.addr))
	})
}

func (a *addressState) ConfigType() AddressConfigType {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.configType
}

func (a *addressState) notifyChangedLocked() {
	if a.disp == nil {
		return
	}

	state := AddressDisabled
	if a.addressableEndpointState.networkEndpoint.Enabled() {
		switch a.kind {
		case Permanent:
			state = AddressAssigned
		case PermanentTentative:
			state = AddressTentative
		case Temporary, PermanentExpired:
			return
		default:
			panic(fmt.Sprintf("unrecognized address kind = %d", a.kind))
		}
	}

	a.disp.OnChanged(a.lifetimes, state)
}

func (a *addressState) SetDeprecated(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var changed bool
	if a.lifetimes.Deprecated != d {
		a.lifetimes.Deprecated = d
		changed = true
	}
	if d {
		a.lifetimes.PreferredUntil = tcpip.MonotonicTime{}
	}
	if changed {
		a.notifyChangedLocked()
	}
}

func (a *addressState) Deprecated() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lifetimes.Deprecated
}

func (a *addressState) SetLifetimes(lifetimes AddressLifetimes) {
	a.mu.Lock()
	defer a.mu.Unlock()

	lifetimes.sanitize()

	var changed bool
	if a.lifetimes != lifetimes {
		changed = true
	}
	a.lifetimes = lifetimes
	if changed {
		a.notifyChangedLocked()
	}
}

func (a *addressState) Lifetimes() AddressLifetimes {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lifetimes
}

func (a *addressState) Temporary() bool {
	return a.temporary
}

func (a *addressState) RegisterDispatcher(disp AddressDispatcher) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if disp != nil {
		a.disp = disp
		a.notifyChangedLocked()
	}
}

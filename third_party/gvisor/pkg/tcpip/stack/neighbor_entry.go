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
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

const (
	immediateDuration time.Duration = 0
)

type NeighborEntry struct {
	Addr      tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt tcpip.MonotonicTime
}

type NeighborState uint8

const (
	Unknown NeighborState = iota
	Incomplete
	Reachable
	Stale
	Delay
	Probe
	Static
	Unreachable
)

type timer struct {
	done *bool

	timer tcpip.Timer `state:"nosave"`
}

type neighborEntryMu struct {
	neighborEntryRWMutex `state:"nosave"`

	neigh NeighborEntry

	done chan struct{} `state:"nosave"`

	onResolve []func(LinkResolutionResult) `state:"nosave"`

	isRouter bool

	timer timer
}

type neighborEntry struct {
	neighborEntryEntry

	cache *neighborCache

	nudState *NUDState

	mu neighborEntryMu
}

func newNeighborEntry(cache *neighborCache, remoteAddr tcpip.Address, nudState *NUDState) *neighborEntry {
	n := &neighborEntry{
		cache:    cache,
		nudState: nudState,
	}
	n.mu.Lock()
	n.mu.neigh = NeighborEntry{
		Addr:  remoteAddr,
		State: Unknown,
	}
	n.mu.Unlock()
	return n

}

func newStaticNeighborEntry(cache *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress, state *NUDState) *neighborEntry {
	entry := NeighborEntry{
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     Static,
		UpdatedAt: cache.nic.stack.clock.NowMonotonic(),
	}
	n := &neighborEntry{
		cache:    cache,
		nudState: state,
	}
	n.mu.Lock()
	n.mu.neigh = entry
	n.mu.Unlock()
	return n
}

func (e *neighborEntry) notifyCompletionLocked(err tcpip.Error) {
	res := LinkResolutionResult{LinkAddress: e.mu.neigh.LinkAddr, Err: err}
	for _, callback := range e.mu.onResolve {
		callback(res)
	}
	e.mu.onResolve = nil
	if ch := e.mu.done; ch != nil {
		close(ch)
		e.mu.done = nil
		e.cache.nic.stack.clock.AfterFunc(0, func() {
			e.cache.nic.linkResQueue.dequeue(ch, e.mu.neigh.LinkAddr, err)
		})
	}
}

func (e *neighborEntry) dispatchAddEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborAdded(e.cache.nic.id, e.mu.neigh)
	}
}

func (e *neighborEntry) dispatchChangeEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborChanged(e.cache.nic.id, e.mu.neigh)
	}
}

func (e *neighborEntry) dispatchRemoveEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborRemoved(e.cache.nic.id, e.mu.neigh)
	}
}

func (e *neighborEntry) cancelTimerLocked() {
	if e.mu.timer.timer != nil {
		e.mu.timer.timer.Stop()
		*e.mu.timer.done = true

		e.mu.timer = timer{}
	}
}

func (e *neighborEntry) removeLocked() {
	e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.NowMonotonic()
	e.dispatchRemoveEventLocked()
	e.setStateLocked(Unknown)
	e.cancelTimerLocked()
	e.notifyCompletionLocked(&tcpip.ErrAborted{})
}

func (e *neighborEntry) setStateLocked(next NeighborState) {
	e.cancelTimerLocked()

	prev := e.mu.neigh.State
	e.mu.neigh.State = next
	e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.NowMonotonic()
	config := e.nudState.Config()

	switch next {
	case Incomplete:
		panic(fmt.Sprintf("should never transition to Incomplete with setStateLocked; neigh = %#v, prev state = %s", e.mu.neigh, prev))

	case Reachable:
		done := false

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(e.nudState.ReachableTime(), func() {
				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					return
				}

				e.setStateLocked(Stale)
				e.dispatchChangeEventLocked()
			}),
		}

	case Delay:
		done := false

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(config.DelayFirstProbeTime, func() {
				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					return
				}

				e.setStateLocked(Probe)
				e.dispatchChangeEventLocked()
			}),
		}

	case Probe:
		done := false

		remaining := config.MaxUnicastProbes
		addr := e.mu.neigh.Addr
		linkAddr := e.mu.neigh.LinkAddr

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(immediateDuration, func() {
				var err tcpip.Error = &tcpip.ErrTimeout{}
				if remaining != 0 {
					err = e.cache.linkRes.LinkAddressRequest(addr, tcpip.Address{}, linkAddr)
				}

				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					return
				}

				if err != nil {
					e.setStateLocked(Unreachable)
					e.notifyCompletionLocked(err)
					e.dispatchChangeEventLocked()
					return
				}

				remaining--
				e.mu.timer.timer.Reset(config.RetransmitTimer)
			}),
		}

	case Unreachable:

	case Unknown, Stale, Static:

	default:
		panic(fmt.Sprintf("Invalid state transition from %q to %q", prev, next))
	}
}

func (e *neighborEntry) handlePacketQueuedLocked(localAddr tcpip.Address) {
	switch e.mu.neigh.State {
	case Unknown, Unreachable:
		prev := e.mu.neigh.State
		e.mu.neigh.State = Incomplete
		e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.NowMonotonic()

		switch prev {
		case Unknown:
			e.dispatchAddEventLocked()
		case Unreachable:
			e.dispatchChangeEventLocked()
			e.cache.nic.stats.neighbor.unreachableEntryLookups.Increment()
		}

		config := e.nudState.Config()

		done := false

		remaining := config.MaxMulticastProbes
		addr := e.mu.neigh.Addr

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(immediateDuration, func() {
				var err tcpip.Error = &tcpip.ErrTimeout{}
				if remaining != 0 {
					err = e.cache.linkRes.LinkAddressRequest(addr, localAddr, "")
				}

				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					return
				}

				if err != nil {
					e.setStateLocked(Unreachable)
					e.notifyCompletionLocked(err)
					e.dispatchChangeEventLocked()
					return
				}

				remaining--
				e.mu.timer.timer.Reset(config.RetransmitTimer)
			}),
		}

	case Stale:
		e.setStateLocked(Delay)
		e.dispatchChangeEventLocked()

	case Incomplete, Reachable, Delay, Probe, Static:
	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

func (e *neighborEntry) handleProbeLocked(remoteLinkAddr tcpip.LinkAddress) {

	switch e.mu.neigh.State {
	case Unknown:
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.dispatchAddEventLocked()

	case Incomplete:
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.notifyCompletionLocked(nil)
		e.dispatchChangeEventLocked()

	case Reachable, Delay, Probe:
		if e.mu.neigh.LinkAddr != remoteLinkAddr {
			e.mu.neigh.LinkAddr = remoteLinkAddr
			e.setStateLocked(Stale)
			e.dispatchChangeEventLocked()
		}

	case Stale:
		if e.mu.neigh.LinkAddr != remoteLinkAddr {
			e.mu.neigh.LinkAddr = remoteLinkAddr
			e.dispatchChangeEventLocked()
		}

	case Unreachable:
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.dispatchChangeEventLocked()

	case Static:

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

func (e *neighborEntry) handleConfirmationLocked(linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	switch e.mu.neigh.State {
	case Incomplete:
		if len(linkAddr) == 0 {
			e.cache.nic.stats.neighbor.droppedInvalidLinkAddressConfirmations.Increment()
			break
		}

		e.mu.neigh.LinkAddr = linkAddr
		if flags.Solicited {
			e.setStateLocked(Reachable)
		} else {
			e.setStateLocked(Stale)
		}
		e.dispatchChangeEventLocked()
		e.mu.isRouter = flags.IsRouter
		e.notifyCompletionLocked(nil)


	case Reachable, Stale, Delay, Probe:
		isLinkAddrDifferent := len(linkAddr) != 0 && e.mu.neigh.LinkAddr != linkAddr

		if isLinkAddrDifferent {
			if !flags.Override {
				if e.mu.neigh.State == Reachable {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				}
				break
			}

			e.mu.neigh.LinkAddr = linkAddr

			if !flags.Solicited {
				if e.mu.neigh.State != Stale {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				} else {
					e.dispatchChangeEventLocked()
				}
				break
			}
		}

		if flags.Solicited && (flags.Override || !isLinkAddrDifferent) {
			wasReachable := e.mu.neigh.State == Reachable
			e.setStateLocked(Reachable)
			e.notifyCompletionLocked(nil)
			if !wasReachable {
				e.dispatchChangeEventLocked()
			}
		}

		if e.mu.isRouter && !flags.IsRouter && header.IsV6UnicastAddress(e.mu.neigh.Addr) {
			ep := e.cache.nic.getNetworkEndpoint(header.IPv6ProtocolNumber)
			if ep == nil {
				panic("have a neighbor entry for an IPv6 router but no IPv6 network endpoint")
			}

			if ndpEP, ok := ep.(NDPEndpoint); ok {
				ndpEP.InvalidateDefaultRouter(e.mu.neigh.Addr)
			}
		}
		e.mu.isRouter = flags.IsRouter

	case Unknown, Unreachable, Static:

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

func (e *neighborEntry) handleUpperLevelConfirmation() {
	tryHandleConfirmation := func() bool {
		switch e.mu.neigh.State {
		case Stale, Delay, Probe:
			return true
		case Reachable:
			e.mu.timer.timer.Reset(e.nudState.ReachableTime())
			return false
		case Unknown, Incomplete, Unreachable, Static:
			return false
		default:
			panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
		}
	}

	e.mu.RLock()
	needsTransition := tryHandleConfirmation()
	e.mu.RUnlock()
	if !needsTransition {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if needsTransition := tryHandleConfirmation(); needsTransition {
		e.setStateLocked(Reachable)
		e.dispatchChangeEventLocked()
	}
}

func (e *neighborEntry) getRemoteLinkAddress() (tcpip.LinkAddress, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	switch e.mu.neigh.State {
	case Reachable, Static, Delay, Probe:
		return e.mu.neigh.LinkAddr, true
	case Unknown, Incomplete, Unreachable, Stale:
		return "", false
	default:
		panic(fmt.Sprintf("invalid state for neighbor entry %v: %v", e.mu.neigh, e.mu.neigh.State))
	}
}

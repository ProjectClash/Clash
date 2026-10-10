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

	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/tcpip"
)

const NeighborCacheSize = 512

type NeighborStats struct {
	UnreachableEntryLookups *tcpip.StatCounter
}

type dynamicCacheEntry struct {
	lru neighborEntryList

	count uint16
}

type neighborCacheMu struct {
	neighborCacheRWMutex `state:"nosave"`

	cache   map[tcpip.Address]*neighborEntry
	dynamic dynamicCacheEntry
}

type neighborCache struct {
	nic     *nic
	state   *NUDState
	linkRes LinkAddressResolver
	mu      neighborCacheMu
}

func (n *neighborCache) getOrCreateEntry(remoteAddr tcpip.Address) *neighborEntry {
	n.mu.Lock()
	defer n.mu.Unlock()

	if entry, ok := n.mu.cache[remoteAddr]; ok {
		entry.mu.RLock()
		if entry.mu.neigh.State != Static {
			n.mu.dynamic.lru.Remove(entry)
			n.mu.dynamic.lru.PushFront(entry)
		}
		entry.mu.RUnlock()
		return entry
	}

	entry := newNeighborEntry(n, remoteAddr, n.state)
	if n.mu.dynamic.count == NeighborCacheSize {
		e := n.mu.dynamic.lru.Back()
		e.mu.Lock()

		delete(n.mu.cache, e.mu.neigh.Addr)
		n.mu.dynamic.lru.Remove(e)
		n.mu.dynamic.count--

		e.removeLocked()
		e.mu.Unlock()
	}
	n.mu.cache[remoteAddr] = entry
	n.mu.dynamic.lru.PushFront(entry)
	n.mu.dynamic.count++
	return entry
}

func (n *neighborCache) entry(remoteAddr, localAddr tcpip.Address, onResolve func(LinkResolutionResult)) (*neighborEntry, <-chan struct{}, tcpip.Error) {
	entry := n.getOrCreateEntry(remoteAddr)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch s := entry.mu.neigh.State; s {
	case Stale:
		entry.handlePacketQueuedLocked(localAddr)
		fallthrough
	case Reachable, Static, Delay, Probe:
		if onResolve != nil {
			onResolve(LinkResolutionResult{LinkAddress: entry.mu.neigh.LinkAddr, Err: nil})
		}
		return entry, nil, nil
	case Unknown, Incomplete, Unreachable:
		if onResolve != nil {
			entry.mu.onResolve = append(entry.mu.onResolve, onResolve)
		}
		if entry.mu.done == nil {
			entry.mu.done = make(chan struct{})
		}
		entry.handlePacketQueuedLocked(localAddr)
		return entry, entry.mu.done, &tcpip.ErrWouldBlock{}
	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", s))
	}
}

func (n *neighborCache) entries() []NeighborEntry {
	n.mu.RLock()
	defer n.mu.RUnlock()

	entries := make([]NeighborEntry, 0, len(n.mu.cache))
	for _, entry := range n.mu.cache {
		entry.mu.RLock()
		entries = append(entries, entry.mu.neigh)
		entry.mu.RUnlock()
	}
	return entries
}

func (n *neighborCache) addStaticEntry(addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if entry, ok := n.mu.cache[addr]; ok {
		entry.mu.Lock()
		if entry.mu.neigh.State != Static {
			n.mu.dynamic.lru.Remove(entry)
			n.mu.dynamic.count--
		} else if entry.mu.neigh.LinkAddr == linkAddr {
			entry.mu.Unlock()
			return
		} else {
			entry.mu.neigh.LinkAddr = linkAddr
			entry.dispatchChangeEventLocked()
			entry.mu.Unlock()
			return
		}

		entry.removeLocked()
		entry.mu.Unlock()
	}

	entry := newStaticNeighborEntry(n, addr, linkAddr, n.state)
	n.mu.cache[addr] = entry

	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.dispatchAddEventLocked()
}

func (n *neighborCache) removeEntry(addr tcpip.Address) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, ok := n.mu.cache[addr]
	if !ok {
		return false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.mu.neigh.State != Static {
		n.mu.dynamic.lru.Remove(entry)
		n.mu.dynamic.count--
	}

	entry.removeLocked()
	delete(n.mu.cache, entry.mu.neigh.Addr)
	return true
}

func (n *neighborCache) clear() {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, entry := range n.mu.cache {
		entry.mu.Lock()
		entry.removeLocked()
		entry.mu.Unlock()
	}

	n.mu.dynamic.lru = neighborEntryList{}
	common.ClearMap(n.mu.cache)
	n.mu.dynamic.count = 0
}

func (n *neighborCache) config() NUDConfigurations {
	return n.state.Config()
}

func (n *neighborCache) setConfig(config NUDConfigurations) {
	config.resetInvalidFields()
	n.state.SetConfig(config)
}

func (n *neighborCache) handleProbe(remoteAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
	entry := n.getOrCreateEntry(remoteAddr)
	entry.mu.Lock()
	entry.handleProbeLocked(remoteLinkAddr)
	entry.mu.Unlock()
}

func (n *neighborCache) handleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	n.mu.RLock()
	entry, ok := n.mu.cache[addr]
	n.mu.RUnlock()
	if ok {
		entry.mu.Lock()
		entry.handleConfirmationLocked(linkAddr, flags)
		entry.mu.Unlock()
	} else {
		n.nic.stats.neighbor.droppedConfirmationForNoninitiatedNeighbor.Increment()
	}
}

func (n *neighborCache) init(nic *nic, r LinkAddressResolver) {
	*n = neighborCache{
		nic:     nic,
		state:   NewNUDState(nic.stack.nudConfigs, nic.stack.clock, nic.stack.insecureRNG),
		linkRes: r,
	}
	n.mu.Lock()
	n.mu.cache = make(map[tcpip.Address]*neighborEntry, NeighborCacheSize)
	n.mu.Unlock()
}

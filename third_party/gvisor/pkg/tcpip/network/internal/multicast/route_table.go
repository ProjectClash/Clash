// Copyright 2022 The gVisor Authors.
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

package multicast

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type RouteTable struct {


	installedMu sync.RWMutex `state:"nosave"`
	installedRoutes map[stack.UnicastSourceAndMulticastDestination]*InstalledRoute

	pendingMu sync.RWMutex `state:"nosave"`
	pendingRoutes map[stack.UnicastSourceAndMulticastDestination]PendingRoute
	cleanupPendingRoutesTimer tcpip.Timer `state:"nosave"`
	isCleanupRoutineRunning bool

	config Config
}

var (
	ErrNoBufferSpace = errors.New("unable to queue packet, no buffer space available")

	ErrMissingClock = errors.New("clock must not be nil")

	ErrAlreadyInitialized = errors.New("table is already initialized")
)

type InstalledRoute struct {
	stack.MulticastRoute

	lastUsedTimestampMu sync.RWMutex `state:"nosave"`
	lastUsedTimestamp tcpip.MonotonicTime
}

func (r *InstalledRoute) LastUsedTimestamp() tcpip.MonotonicTime {
	r.lastUsedTimestampMu.RLock()
	defer r.lastUsedTimestampMu.RUnlock()

	return r.lastUsedTimestamp
}

func (r *InstalledRoute) SetLastUsedTimestamp(monotonicTime tcpip.MonotonicTime) {
	r.lastUsedTimestampMu.Lock()
	defer r.lastUsedTimestampMu.Unlock()

	if monotonicTime.After(r.lastUsedTimestamp) {
		r.lastUsedTimestamp = monotonicTime
	}
}

type PendingRoute struct {
	packets []*stack.PacketBuffer

	expiration tcpip.MonotonicTime
}

func (p *PendingRoute) releasePackets() {
	for _, pkt := range p.packets {
		pkt.DecRef()
	}
}

func (p *PendingRoute) isExpired(currentTime tcpip.MonotonicTime) bool {
	return currentTime.After(p.expiration)
}

const (
	DefaultMaxPendingQueueSize uint8 = 3

	DefaultPendingRouteExpiration time.Duration = 10 * time.Second

	DefaultCleanupInterval time.Duration = 10 * time.Second
)

type Config struct {
	MaxPendingQueueSize uint8

	Clock tcpip.Clock
}

func DefaultConfig(clock tcpip.Clock) Config {
	return Config{
		MaxPendingQueueSize: DefaultMaxPendingQueueSize,
		Clock:               clock,
	}
}

func (r *RouteTable) Init(config Config) error {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	if r.installedRoutes != nil {
		return ErrAlreadyInitialized
	}

	if config.Clock == nil {
		return ErrMissingClock
	}

	r.config = config
	r.installedRoutes = make(map[stack.UnicastSourceAndMulticastDestination]*InstalledRoute)
	r.pendingRoutes = make(map[stack.UnicastSourceAndMulticastDestination]PendingRoute)

	return nil
}

func (r *RouteTable) Close() {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	if r.cleanupPendingRoutesTimer != nil {
		r.cleanupPendingRoutesTimer.Stop()
	}

	for key, route := range r.pendingRoutes {
		delete(r.pendingRoutes, key)
		route.releasePackets()
	}
}

func (r *RouteTable) maybeStopCleanupRoutineLocked() bool {
	if !r.isCleanupRoutineRunning {
		return true
	}

	if len(r.pendingRoutes) == 0 {
		r.cleanupPendingRoutesTimer.Stop()
		r.isCleanupRoutineRunning = false
		return true
	}

	return false
}

func (r *RouteTable) cleanupPendingRoutes() {
	currentTime := r.config.Clock.NowMonotonic()
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	for key, route := range r.pendingRoutes {
		if route.isExpired(currentTime) {
			delete(r.pendingRoutes, key)
			route.releasePackets()
		}
	}

	if stopped := r.maybeStopCleanupRoutineLocked(); !stopped {
		r.cleanupPendingRoutesTimer.Reset(DefaultCleanupInterval)
	}
}

func (r *RouteTable) newPendingRoute() PendingRoute {
	return PendingRoute{
		packets:    make([]*stack.PacketBuffer, 0, r.config.MaxPendingQueueSize),
		expiration: r.config.Clock.NowMonotonic().Add(DefaultPendingRouteExpiration),
	}
}

func (r *RouteTable) NewInstalledRoute(route stack.MulticastRoute) *InstalledRoute {
	return &InstalledRoute{
		MulticastRoute:    route,
		lastUsedTimestamp: r.config.Clock.NowMonotonic(),
	}
}

type GetRouteResult struct {
	GetRouteResultState GetRouteResultState

	InstalledRoute *InstalledRoute
}

type GetRouteResultState uint8

const (
	InstalledRouteFound GetRouteResultState = iota

	PacketQueuedInPendingRoute

	NoRouteFoundAndPendingInserted
)

func (e GetRouteResultState) String() string {
	switch e {
	case InstalledRouteFound:
		return "InstalledRouteFound"
	case PacketQueuedInPendingRoute:
		return "PacketQueuedInPendingRoute"
	case NoRouteFoundAndPendingInserted:
		return "NoRouteFoundAndPendingInserted"
	default:
		return fmt.Sprintf("%d", uint8(e))
	}
}

func (r *RouteTable) GetRouteOrInsertPending(key stack.UnicastSourceAndMulticastDestination, pkt *stack.PacketBuffer) (GetRouteResult, bool) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return GetRouteResult{GetRouteResultState: InstalledRouteFound, InstalledRoute: route}, true
	}

	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	pendingRoute, getRouteResultState := r.getOrCreatePendingRouteRLocked(key)
	if len(pendingRoute.packets) >= int(r.config.MaxPendingQueueSize) {
		return GetRouteResult{}, false
	}
	pendingRoute.packets = append(pendingRoute.packets, pkt.Clone())
	r.pendingRoutes[key] = pendingRoute

	if !r.isCleanupRoutineRunning {
		if r.cleanupPendingRoutesTimer == nil {
			r.cleanupPendingRoutesTimer = r.config.Clock.AfterFunc(DefaultCleanupInterval, r.cleanupPendingRoutes)
		} else {
			r.cleanupPendingRoutesTimer.Reset(DefaultCleanupInterval)
		}
		r.isCleanupRoutineRunning = true
	}

	return GetRouteResult{GetRouteResultState: getRouteResultState, InstalledRoute: nil}, true
}

func (r *RouteTable) getOrCreatePendingRouteRLocked(key stack.UnicastSourceAndMulticastDestination) (PendingRoute, GetRouteResultState) {
	if pendingRoute, ok := r.pendingRoutes[key]; ok {
		return pendingRoute, PacketQueuedInPendingRoute
	}
	return r.newPendingRoute(), NoRouteFoundAndPendingInserted
}

func (r *RouteTable) AddInstalledRoute(key stack.UnicastSourceAndMulticastDestination, route *InstalledRoute) []*stack.PacketBuffer {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()
	r.installedRoutes[key] = route

	r.pendingMu.Lock()
	pendingRoute, ok := r.pendingRoutes[key]
	delete(r.pendingRoutes, key)
	_ = r.maybeStopCleanupRoutineLocked()
	r.pendingMu.Unlock()

	if !ok || pendingRoute.isExpired(r.config.Clock.NowMonotonic()) {
		pendingRoute.releasePackets()
		return nil
	}

	return pendingRoute.packets
}

func (r *RouteTable) RemoveInstalledRoute(key stack.UnicastSourceAndMulticastDestination) bool {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()

	if _, ok := r.installedRoutes[key]; ok {
		delete(r.installedRoutes, key)
		return true
	}

	return false
}

func (r *RouteTable) RemoveAllInstalledRoutes() {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()

	for key := range r.installedRoutes {
		delete(r.installedRoutes, key)
	}
}

func (r *RouteTable) GetLastUsedTimestamp(key stack.UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, bool) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return route.LastUsedTimestamp(), true
	}
	return tcpip.MonotonicTime{}, false
}

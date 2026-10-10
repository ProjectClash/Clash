package clash

import (
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/iface"
	"github.com/ProjectClash/Clash/component/pause"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/log"
)

type interfaceUpdater struct {
	mu                   sync.Mutex
	bindDefaultInterface bool
	initialized          bool
	name                 string
	index                int32
	initialName          string
	initialIndex         int32
	isExpensive          bool
	isConstrained        bool
	supportsIPv4         bool
	supportsIPv6         bool
	received             uint64
	applied              uint64
	identityChanges      uint64

	settleMu         sync.Mutex
	settleGen        uint64
	settleStop       func() bool
	checkStop        func() bool
	resetMu          sync.Mutex
	pendingReset     bool
	pendingCheck     bool
	stopped          bool
	connectionResets uint64
}

type interfaceUpdateSnapshot struct {
	received         uint64
	applied          uint64
	identityChanges  uint64
	connectionResets uint64
}

var (
	flushInterfaceCache           = iface.FlushCache
	resetResolverConnection       = resolver.ResetConnection
	clearResolverCache            = resolver.ClearCache
	closeTrackedConnections       = CloseAllConnections
	resetOutboundSessions         = func() { resetEveryOutboundSession() }
	afterPathSettles              = func(d time.Duration, settle func()) func() bool { return time.AfterFunc(d, settle).Stop }
	afterPathChangeCheck          = func(d time.Duration, check func()) func() bool { return time.AfterFunc(d, check).Stop }
	checkProvidersAfterPathChange = checkProvidersInUseOnce
	readPhysicalResolvers         = physicalResolversForInterface
	dnsConfigurationChanged       = dnsInfoChanged
	networkPauseStarted           = atomic.NewTypedValue[time.Time](time.Time{})
)

func (u *interfaceUpdater) UpdateDefaultInterface(name string, index int32, isExpensive bool, isConstrained bool, supportsIPv4 bool, supportsIPv6 bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.received++
	wasInitialized := u.initialized
	changed := !u.initialized || u.name != name || u.index != index ||
		u.isExpensive != isExpensive || u.isConstrained != isConstrained ||
		u.supportsIPv4 != supportsIPv4 || u.supportsIPv6 != supportsIPv6
	newInterface := wasInitialized && u.name != name
	actedOn := wasInitialized && (newInterface || u.isExpensive != isExpensive || u.supportsIPv4 != supportsIPv4)
	if !changed {
		if u.initialized && dnsConfigurationChanged() {
			u.publishLivePhysicalResolvers()
		}
		return
	}
	u.applied++
	if !u.initialized {
		u.initialName = name
		u.initialIndex = index
	}
	u.initialized = true
	u.name = name
	u.index = index
	u.isExpensive = isExpensive
	u.isConstrained = isConstrained
	u.supportsIPv4 = supportsIPv4
	u.supportsIPv6 = supportsIPv6
	setPhysicalNetworkCapabilities(supportsIPv4, supportsIPv6)

	if u.bindDefaultInterface {
		dialer.DefaultInterface.Store(name)
	}
	publishedInterfaceIndex.Store(index)
	scheduleLANReconcile()
	if index == 0 || name == "" {
		if !pause.IsNetworkPaused() {
			networkPauseStarted.Store(time.Now())
		}
		pause.NetworkPause()
		log.Warnln("[Apple] no usable default network; periodic tasks are suspended until one returns")
	} else {
		if pause.IsNetworkPaused() {
			log.Warnln("[Apple] default network is back on %s (index=%d) after %s; periodic tasks resume",
				name, index, time.Since(networkPauseStarted.Load()).Round(time.Millisecond))
		}
		pause.NetworkWake()
	}
	if newInterface {
		u.identityChanges++
	}
	flushInterfaceCache()
	invalidateNetworkInterfaces()
	if actedOn {
		u.changeArrived(newInterface, index != 0 && name != "")
	}
	u.markSystemSubstitutes()
	log.Infoln("[Apple] default path -> %s (index=%d expensive=%v constrained=%v ipv4=%v ipv6=%v)",
		name, index, isExpensive, isConstrained, supportsIPv4, supportsIPv6)
}

const pathSettleDelay = 250 * time.Millisecond

const pathChangeCheckDelay = 2 * time.Second

func (u *interfaceUpdater) changeArrived(newInterface, havePath bool) {
	u.settleMu.Lock()
	if u.stopped {
		u.settleMu.Unlock()
		return
	}
	u.settleGen++
	gen := u.settleGen
	stopSettle, stopCheck := u.settleStop, u.checkStop
	u.settleStop, u.checkStop = nil, nil
	u.pendingReset = u.pendingReset || newInterface
	u.pendingCheck = true
	u.settleMu.Unlock()
	if stopSettle != nil {
		stopSettle()
	}
	if stopCheck != nil {
		stopCheck()
	}
	if !havePath {
		return
	}
	stop := afterPathSettles(pathSettleDelay, func() { u.settle(gen) })
	u.settleMu.Lock()
	if gen == u.settleGen && !u.stopped {
		u.settleStop = stop
	}
	u.settleMu.Unlock()
}

func (u *interfaceUpdater) settle(gen uint64) {
	u.resetMu.Lock()
	u.settleMu.Lock()
	if u.stopped || gen != u.settleGen {
		u.settleMu.Unlock()
		u.resetMu.Unlock()
		return
	}
	reset, check := u.pendingReset, u.pendingCheck
	u.pendingReset, u.pendingCheck, u.settleStop = false, false, nil
	if reset {
		u.connectionResets++
	}
	u.settleMu.Unlock()
	if reset {
		closeTrackedConnections()
		resetOutboundSessions()
		clearResolverCache()
		resetResolverConnection()
		log.Infoln("[Apple] the default interface changed: every connection is closed, and the outbound sessions and the resolver are reset")
	}
	u.resetMu.Unlock()
	if !check {
		return
	}
	stop := afterPathChangeCheck(pathChangeCheckDelay, func() { u.checkAfterChange(gen) })
	u.settleMu.Lock()
	current := gen == u.settleGen && !u.stopped
	if current {
		u.checkStop = stop
	}
	u.settleMu.Unlock()
	if !current {
		stop()
	}
}

func (u *interfaceUpdater) checkAfterChange(gen uint64) {
	u.settleMu.Lock()
	defer u.settleMu.Unlock()
	if u.stopped || gen != u.settleGen {
		return
	}
	u.checkStop = nil
	checkProvidersAfterPathChange()
}

func (u *interfaceUpdater) stopSettling() {
	u.settleMu.Lock()
	u.stopped = true
	u.settleGen++
	stopSettle, stopCheck := u.settleStop, u.checkStop
	u.settleStop, u.checkStop = nil, nil
	u.settleMu.Unlock()
	u.resetMu.Lock()
	u.resetMu.Unlock()
	if stopSettle != nil {
		stopSettle()
	}
	if stopCheck != nil {
		stopCheck()
	}
}

func (u *interfaceUpdater) markSystemSubstitutes() {
	if u.publishLivePhysicalResolvers() {
		return
	}
	stale := u.name != u.initialName || u.index != u.initialIndex
	if !dns.SetSystemSubstitutesStale(stale) {
		return
	}
	substitutes := systemDNSServerSubstitutes()
	if len(substitutes) == 0 {
		return
	}
	if stale {
		log.Warnln("[Apple] default path left %s (index=%d) for %s (index=%d): the system resolvers the App read before the tunnel (%s) are not reachable from here and the extension cannot read this network's; every `system` nameserver falls back to the configuration's other resolvers in its slot, then the main nameservers, then the built-in pair, until the path returns",
			u.initialName, u.initialIndex, u.name, u.index, strings.Join(substitutes, ", "))
		return
	}
	log.Warnln("[Apple] default path is back on %s (index=%d): the system resolvers the App read before the tunnel (%s) answer `system` nameservers again",
		u.name, u.index, strings.Join(substitutes, ", "))
}

func (u *interfaceUpdater) publishLivePhysicalResolvers() bool {
	usable, _ := usableSystemResolverSubstitutes(readPhysicalResolvers(u.index), currentTunnelPrefixes())
	if len(usable) == 0 {
		if dns.SetSystemSubstituteServers(nil) {
			log.Warnln("[Apple] default path %s (index=%d) exposes no readable resolvers of its own; the resolvers read from the previous path are dropped and `system` nameservers fall back",
				u.name, u.index)
		}
		dns.SetSystemSubstitutesStale(u.name != u.initialName || u.index != u.initialIndex)
		return false
	}
	if !dns.SetSystemSubstituteServers(usable) {
		return true
	}
	dns.SetSystemSubstitutesStale(false)
	log.Warnln("[Apple] default path %s (index=%d) resolves `system` nameservers through %s, read from this network's scoped resolvers",
		u.name, u.index, strings.Join(usable, ", "))
	return true
}

func (u *interfaceUpdater) refreshLivePhysicalResolvers() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.initialized {
		return
	}
	if !dnsConfigurationChanged() {
		return
	}
	u.publishLivePhysicalResolvers()
}

func (u *interfaceUpdater) snapshot() interfaceUpdateSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.settleMu.Lock()
	connectionResets := u.connectionResets
	u.settleMu.Unlock()
	return interfaceUpdateSnapshot{
		received:         u.received,
		applied:          u.applied,
		identityChanges:  u.identityChanges,
		connectionResets: connectionResets,
	}
}

func startInterfaceMonitor(platform PlatformInterface) (InterfaceUpdateListener, error) {
	if platform == nil {
		return nil, nil
	}
	bindDefaultInterface := platform.UsePlatformAutoDetectInterfaceControl()
	if !bindDefaultInterface && !watchesPathWithoutBinding(currentRuntimeProfile(), platform.UnderNetworkExtension()) {
		return nil, nil
	}
	listener := &interfaceUpdater{bindDefaultInterface: bindDefaultInterface}
	dns.SetSystemSubstitutesStale(false)
	dns.SetSystemSubstituteRefresh(listener.refreshLivePhysicalResolvers)
	if err := platform.StartDefaultInterfaceMonitor(listener); err != nil {
		dns.SetSystemSubstituteRefresh(nil)
		_ = platform.CloseDefaultInterfaceMonitor(listener)
		return nil, err
	}
	return listener, nil
}

func watchesPathWithoutBinding(profile runtimeProfile, underNetworkExtension bool) bool {
	switch profile {
	case runtimeProfileMacOSPacketTunnel:
		return true
	case runtimeProfileIOSPacketTunnel, runtimeProfileTVOSPacketTunnel:
		return underNetworkExtension
	}
	return false
}

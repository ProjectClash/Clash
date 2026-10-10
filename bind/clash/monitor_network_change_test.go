package clash

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/pause"
	"github.com/ProjectClash/Clash/dns"
)

type networkChangeTimers struct {
	mu    sync.Mutex
	armed []*networkChangeTimer
}

type networkChangeTimer struct {
	after   time.Duration
	run     func()
	stopped bool
	fired   bool
}

func (timers *networkChangeTimers) arm(after time.Duration, run func()) func() bool {
	timer := &networkChangeTimer{after: after, run: run}
	timers.mu.Lock()
	timers.armed = append(timers.armed, timer)
	timers.mu.Unlock()
	return func() bool {
		timers.mu.Lock()
		defer timers.mu.Unlock()
		pending := !timer.stopped && !timer.fired
		timer.stopped = true
		return pending
	}
}

func (timers *networkChangeTimers) fire(after time.Duration) int {
	timers.mu.Lock()
	var due []*networkChangeTimer
	for _, timer := range timers.armed {
		if timer.after == after && !timer.stopped && !timer.fired {
			timer.fired = true
			due = append(due, timer)
		}
	}
	timers.mu.Unlock()
	for _, timer := range due {
		timer.run()
	}
	return len(due)
}

func (timers *networkChangeTimers) pending(after time.Duration) int {
	timers.mu.Lock()
	defer timers.mu.Unlock()
	n := 0
	for _, timer := range timers.armed {
		if timer.after == after && !timer.stopped && !timer.fired {
			n++
		}
	}
	return n
}

type networkChangeProbe struct {
	timers                                   *networkChangeTimers
	closes, sessions, clears, resets, checks atomic.Int32
}

func newNetworkChangeProbe(t *testing.T) *networkChangeProbe {
	t.Helper()
	probe := &networkChangeProbe{timers: &networkChangeTimers{}}
	oldSettle, oldCheckTimer, oldCheck := afterPathSettles, afterPathChangeCheck, checkProvidersAfterPathChange
	oldFlush, oldReset, oldClose, oldSessions, oldClear, oldRead :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, readPhysicalResolvers
	previousInterface, previousIndex := dialer.DefaultInterface.Load(), publishedInterfaceIndex.Load()
	afterPathSettles = probe.timers.arm
	afterPathChangeCheck = probe.timers.arm
	checkProvidersAfterPathChange = func() { probe.checks.Add(1) }
	flushInterfaceCache = func() {}
	resetResolverConnection = func() { probe.resets.Add(1) }
	closeTrackedConnections = func() { probe.closes.Add(1) }
	resetOutboundSessions = func() { probe.sessions.Add(1) }
	clearResolverCache = func() { probe.clears.Add(1) }
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		afterPathSettles, afterPathChangeCheck, checkProvidersAfterPathChange = oldSettle, oldCheckTimer, oldCheck
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, readPhysicalResolvers =
			oldFlush, oldReset, oldClose, oldSessions, oldClear, oldRead
		dialer.DefaultInterface.Store(previousInterface)
		publishedInterfaceIndex.Store(previousIndex)
		pause.NetworkWake()
	})
	return probe
}

func (probe *networkChangeProbe) settle() {
	probe.timers.fire(pathSettleDelay)
	probe.timers.fire(pathChangeCheckDelay)
}

func (probe *networkChangeProbe) assertResets(t *testing.T, want int32) {
	t.Helper()
	if probe.closes.Load() != want || probe.sessions.Load() != want || probe.clears.Load() != want || probe.resets.Load() != want {
		t.Fatalf("flows/sessions/dns cache/dns connections reset %d/%d/%d/%d times, want %d of each",
			probe.closes.Load(), probe.sessions.Load(), probe.clears.Load(), probe.resets.Load(), want)
	}
}

func (probe *networkChangeProbe) assertChecks(t *testing.T, want int32) {
	t.Helper()
	if got := probe.checks.Load(); got != want {
		t.Fatalf("%d health-check rounds after the path changed, want %d", got, want)
	}
}

func TestTheFirstPathOfASessionOwesNothing(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	if armed := probe.timers.pending(pathSettleDelay); armed != 0 {
		t.Fatalf("the first path armed %d settles, want none", armed)
	}
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 0)
	if publishedInterfaceIndex.Load() != 26 {
		t.Fatalf("the first path must still be published at once, got index %d", publishedInterfaceIndex.Load())
	}
}

func TestANewInterfaceIsResetOnceItSettlesAndCheckedTwoSecondsLater(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	if publishedInterfaceIndex.Load() != 3 {
		t.Fatal("the new index must be published at once, not after the settle")
	}
	probe.assertResets(t, 0)
	if fired := probe.timers.fire(pathSettleDelay); fired != 1 {
		t.Fatalf("%d settles fired, want one", fired)
	}
	probe.assertResets(t, 1)
	probe.assertChecks(t, 0)
	if fired := probe.timers.fire(pathChangeCheckDelay); fired != 1 {
		t.Fatalf("%d health checks fired, want one", fired)
	}
	probe.assertChecks(t, 1)
	snapshot := u.snapshot()
	if snapshot.identityChanges != 1 || snapshot.connectionResets != 1 {
		t.Fatalf("telemetry identity/reset = %d/%d, want 1/1", snapshot.identityChanges, snapshot.connectionResets)
	}
}

func TestANewIndexUnderTheSameNameIsNoChange(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if publishedInterfaceIndex.Load() != 5 {
		t.Fatalf("published index %d, want 5", publishedInterfaceIndex.Load())
	}
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 0)
}

func TestAnExpensiveOrIPv4ChangeIsCheckedButNothingIsReset(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 4, true, false, true, true)
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 1)
	u.UpdateDefaultInterface("en0", 4, true, false, false, true)
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 2)
}

func TestAnIPv6OnlyChangeIsLeftAlone(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 4, false, false, true, false)
	if u.supportsIPv6 {
		t.Fatal("the path's IPv6 support must be published at once")
	}
	if armed := probe.timers.pending(pathSettleDelay); armed != 0 {
		t.Fatalf("an IPv6-only change armed %d settles, want none", armed)
	}
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 0)
}

func TestAConstrainedOnlyChangeIsLeftAlone(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 4, false, true, true, true)
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 0)
}

func TestNothingSettlesWithoutAPathAndItsReturnIsReset(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("", 0, false, false, false, false)
	if !pause.IsNetworkPaused() {
		t.Fatal("no path must still suspend the periodic work at once")
	}
	if armed := probe.timers.pending(pathSettleDelay); armed != 0 {
		t.Fatalf("%d settles armed with no path, want none", armed)
	}
	probe.settle()
	probe.assertResets(t, 0)
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	probe.settle()
	probe.assertResets(t, 1)
	probe.assertChecks(t, 1)
}

func TestAPathLostBeforeItsChangeSettledDefersTheReset(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	u.UpdateDefaultInterface("", 0, false, false, false, false)
	probe.settle()
	probe.assertResets(t, 0)
	probe.assertChecks(t, 0)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	probe.settle()
	probe.assertResets(t, 1)
	probe.assertChecks(t, 1)
}

func TestAFlagFlipInsideTheWindowKeepsTheResetANewInterfaceOwes(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, false, false, true, true)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	if fired := probe.timers.fire(pathSettleDelay); fired != 1 {
		t.Fatalf("%d settles fired for one burst, want one", fired)
	}
	probe.assertResets(t, 1)
}

func TestANewerChangeReplacesTheCheckThatWasWaiting(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	probe.timers.fire(pathSettleDelay)
	if armed := probe.timers.pending(pathChangeCheckDelay); armed != 1 {
		t.Fatalf("%d checks waiting, want one", armed)
	}
	u.UpdateDefaultInterface("pdp_ip0", 3, false, false, true, true)
	if armed := probe.timers.pending(pathChangeCheckDelay); armed != 0 {
		t.Fatalf("the newer change left %d stale checks waiting", armed)
	}
	probe.settle()
	probe.assertChecks(t, 1)
	probe.assertResets(t, 1)
}

func TestStoppingDropsTheResetAndTheCheckStillWaiting(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	probe.timers.fire(pathSettleDelay)
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.stopSettling()
	probe.settle()
	probe.assertResets(t, 1)
	probe.assertChecks(t, 0)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	if armed := probe.timers.pending(pathSettleDelay); armed != 0 {
		t.Fatalf("a callback after the stop armed %d settles", armed)
	}
	for _, timer := range probe.timers.armed {
		if !timer.fired {
			timer.run()
		}
	}
	probe.assertResets(t, 1)
	probe.assertChecks(t, 0)
}

func TestThePathIsWatchedWhetherOrNotSocketsAreBound(t *testing.T) {
	originalProfile := currentRuntimeProfile()
	t.Cleanup(func() {
		setupRuntimeProfile.Store(uint32(originalProfile))
		dns.SetSystemSubstituteRefresh(nil)
	})
	for _, profile := range []runtimeProfile{runtimeProfileIOSPacketTunnel, runtimeProfileTVOSPacketTunnel, runtimeProfileMacOSPacketTunnel} {
		setupRuntimeProfile.Store(uint32(profile))
		platform := &recordingPlatform{underNetworkExtension: true}
		listener, err := startInterfaceMonitor(platform)
		if err != nil {
			t.Fatalf("profile %d: startInterfaceMonitor: %v", profile, err)
		}
		updater, ok := listener.(*interfaceUpdater)
		if !ok || platform.monitorStarts != 1 {
			t.Fatalf("profile %d: listener %T, monitor starts %d; want an *interfaceUpdater started once", profile, listener, platform.monitorStarts)
		}
		if updater.bindDefaultInterface {
			t.Fatalf("profile %d: a platform that does not bind must not have the dialer's interface forced", profile)
		}
	}
	setupRuntimeProfile.Store(uint32(runtimeProfileMacOSApplication))
	if listener, err := startInterfaceMonitor(&recordingPlatform{underNetworkExtension: true}); err != nil || listener != nil {
		t.Fatalf("the macOS App runs no tunnel and watches no path: got (%v, %v)", listener, err)
	}
}

func TestStoppingWaitsForAResetAlreadyUnderWay(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	entered, release := make(chan struct{}), make(chan struct{})
	closeTrackedConnections = func() {
		close(entered)
		<-release
	}
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	settled := make(chan struct{})
	go func() {
		probe.timers.fire(pathSettleDelay)
		close(settled)
	}()
	<-entered
	stopped := make(chan struct{})
	go func() {
		u.stopSettling()
		close(stopped)
	}()
	select {
	case <-stopped:
		close(release)
		<-settled
		t.Fatal("the stop returned while a reset was under way")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-stopped
	<-settled
	if armed := probe.timers.pending(pathChangeCheckDelay); armed != 0 {
		t.Fatalf("a reset finishing after the stop armed %d checks", armed)
	}
}

func TestStoppingWaitsForACheckAlreadyUnderWay(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	entered, release := make(chan struct{}), make(chan struct{})
	checkProvidersAfterPathChange = func() {
		close(entered)
		<-release
	}
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	probe.timers.fire(pathSettleDelay)
	checked := make(chan struct{})
	go func() {
		probe.timers.fire(pathChangeCheckDelay)
		close(checked)
	}()
	<-entered
	stopped := make(chan struct{})
	go func() {
		u.stopSettling()
		close(stopped)
	}()
	select {
	case <-stopped:
		close(release)
		<-checked
		t.Fatal("the stop returned while a check was under way")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-stopped
	<-checked
}

func TestAPathCallbackNeverWaitsForAResetUnderWay(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	entered, release := make(chan struct{}), make(chan struct{})
	resetOutboundSessions = func() {
		close(entered)
		<-release
	}
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	settled := make(chan struct{})
	go func() {
		probe.timers.fire(pathSettleDelay)
		close(settled)
	}()
	<-entered
	done := make(chan struct{})
	go func() {
		u.UpdateDefaultInterface("pdp_ip0", 3, false, false, true, true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		<-done
		<-settled
		t.Fatal("a path callback waited behind a reset under way")
	}
	close(release)
	<-settled
}

func TestASettleWaitingForAResetHoldsNothingAPathCallbackNeeds(t *testing.T) {
	probe := newNetworkChangeProbe(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resetOutboundSessions = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	u := &interfaceUpdater{}
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 3, true, false, true, true)
	first := make(chan struct{})
	go func() {
		probe.timers.fire(pathSettleDelay)
		close(first)
	}()
	<-entered
	u.UpdateDefaultInterface("en0", 26, false, false, true, false)
	second := make(chan struct{})
	go func() {
		probe.timers.fire(pathSettleDelay)
		close(second)
	}()
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		u.UpdateDefaultInterface("en0", 26, true, false, true, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		<-done
		<-first
		<-second
		t.Fatal("a path callback waited behind a settle that was waiting for an earlier reset")
	}
	close(release)
	<-first
	<-second
}

package clash

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
)

func init() {
	afterPathSettles = func(_ time.Duration, settle func()) func() bool {
		settle()
		return func() bool { return false }
	}
	afterPathChangeCheck = func(_ time.Duration, check func()) func() bool {
		check()
		return func() bool { return false }
	}
	checkProvidersAfterPathChange = func() {}
}

func TestABurstOfPathCallbacksIsResetOnceWhenThePathSettles(t *testing.T) {
	orig := dialer.DefaultInterface.Load()
	previousIndex := publishedInterfaceIndex.Load()
	oldSettle, oldCheckTimer, oldCheck := afterPathSettles, afterPathChangeCheck, checkProvidersAfterPathChange
	afterPathSettles = func(d time.Duration, settle func()) func() bool { return time.AfterFunc(d, settle).Stop }
	afterPathChangeCheck = func(d time.Duration, check func()) func() bool { return time.AfterFunc(d, check).Stop }
	var closes, sessions, resolvers, checks atomic.Int32
	checkProvidersAfterPathChange = func() { checks.Add(1) }
	oldFlush, oldReset, oldClose, oldSessions, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache
	flushInterfaceCache, clearResolverCache = func() {}, func() {}
	resetResolverConnection = func() { resolvers.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	resetOutboundSessions = func() { sessions.Add(1) }
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		dialer.DefaultInterface.Store(orig)
		publishedInterfaceIndex.Store(previousIndex)
		afterPathSettles, afterPathChangeCheck, checkProvidersAfterPathChange = oldSettle, oldCheckTimer, oldCheck
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache =
			oldFlush, oldReset, oldClose, oldSessions, oldClear
		readPhysicalResolvers = previousRead
	})

	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	time.Sleep(pathSettleDelay + 100*time.Millisecond)
	if resolvers.Load() != 0 || closes.Load() != 0 {
		t.Fatalf("the first path reset the resolver %d times and the flows %d times, want neither", resolvers.Load(), closes.Load())
	}

	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, false, true)
	u.UpdateDefaultInterface("", 0, true, false, true, true)
	if publishedInterfaceIndex.Load() != 0 {
		t.Fatal("the index a dial binds to must be published at once, not after the settle")
	}
	u.UpdateDefaultInterface("", 0, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	if closes.Load() != 0 || sessions.Load() != 0 {
		t.Fatalf("reset inside the burst: closes=%d sessions=%d", closes.Load(), sessions.Load())
	}
	time.Sleep(pathSettleDelay + 150*time.Millisecond)
	if closes.Load() != 1 || sessions.Load() != 1 || resolvers.Load() != 1 {
		t.Fatalf("closes=%d sessions=%d resolvers=%d after the burst settled, want one of each", closes.Load(), sessions.Load(), resolvers.Load())
	}
	if checks.Load() != 0 {
		t.Fatal("the groups must not be re-tested before the new link has had its two seconds")
	}
	deadline := time.Now().Add(pathChangeCheckDelay + time.Second)
	for checks.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if checks.Load() != 1 {
		t.Fatalf("%d health-check rounds after the burst settled, want one", checks.Load())
	}
}

func TestAPendingResetIsDroppedWhenTheMonitorStops(t *testing.T) {
	oldSettle := afterPathSettles
	var armed func()
	afterPathSettles = func(_ time.Duration, settle func()) func() bool {
		armed = settle
		return func() bool { return true }
	}
	var closes atomic.Int32
	oldFlush, oldReset, oldClose, oldSessions, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache
	flushInterfaceCache, clearResolverCache, resetResolverConnection, resetOutboundSessions = func() {}, func() {}, func() {}, func() {}
	closeTrackedConnections = func() { closes.Add(1) }
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		afterPathSettles = oldSettle
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache =
			oldFlush, oldReset, oldClose, oldSessions, oldClear
		readPhysicalResolvers = previousRead
	})
	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	if armed == nil {
		t.Fatal("a new interface must arm a settle")
	}
	u.stopSettling()
	armed()
	if closes.Load() != 0 {
		t.Fatalf("a reset ran after the monitor stopped: %d", closes.Load())
	}
}

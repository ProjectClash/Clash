package clash

import (
	"sync/atomic"
	"testing"
)

func TestDNSCacheFlushTracksTheResolverReset(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear, oldSessions, oldRead :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache, resetOutboundSessions, readPhysicalResolvers
	var flushes, resets, closes, clears atomic.Int64
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	clearResolverCache = func() { clears.Add(1) }
	resetOutboundSessions = func() {}
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache, resetOutboundSessions, readPhysicalResolvers =
			oldFlush, oldReset, oldClose, oldClear, oldSessions, oldRead
	})

	updater := &interfaceUpdater{}

	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 0 || flushes.Load() != 1 {
		t.Fatalf("first path: clears=%d interface-cache flushes=%d, want 0 and 1", clears.Load(), flushes.Load())
	}

	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 0 || flushes.Load() != 1 {
		t.Fatalf("identical path: clears=%d interface-cache flushes=%d", clears.Load(), flushes.Load())
	}

	updater.UpdateDefaultInterface("en0", 4, true, true, true, true)
	updater.UpdateDefaultInterface("en0", 4, true, true, false, true)
	if clears.Load() != 0 {
		t.Fatalf("a flag or a family moving on the same interface flushed the DNS cache: clears=%d", clears.Load())
	}

	updater.UpdateDefaultInterface("pdp_ip0", 10, true, false, true, true)
	if clears.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("interface switch: clears=%d closes=%d, want one of each", clears.Load(), closes.Load())
	}

	if clears.Load() != resets.Load() {
		t.Fatalf("cache flush (%d) and connection reset (%d) disagree; both are invalidating "+
			"state scoped to the old path and must fire together", clears.Load(), resets.Load())
	}
	if flushes.Load() != 4 {
		t.Fatalf("interface-cache flushes=%d, want one per applied update (4)", flushes.Load())
	}
}

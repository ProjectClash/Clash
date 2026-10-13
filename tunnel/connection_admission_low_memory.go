//go:build with_low_memory

package tunnel

import "sync/atomic"

const lowMemoryTCPConnectionAdmissionLimit int64 = 416

var (
	activeTCPConnectionSlots   atomic.Int64
	rejectedTCPConnectionTotal atomic.Uint64
	evictedTCPConnectionTotal  atomic.Uint64
)

func acquireTCPConnectionSlot() bool {
	if tryAcquireTCPConnectionSlot() {
		return true
	}
	noteTCPConnectionRejected()
	return false
}

func tryAcquireTCPConnectionSlot() bool {
	for {
		active := activeTCPConnectionSlots.Load()
		if active >= lowMemoryTCPConnectionAdmissionLimit {
			return false
		}
		if activeTCPConnectionSlots.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func noteTCPConnectionRejected() { rejectedTCPConnectionTotal.Add(1) }

func noteTCPConnectionEvicted() { evictedTCPConnectionTotal.Add(1) }

func releaseTCPConnectionSlot() {
	activeTCPConnectionSlots.Add(-1)
}

func TCPConnectionAdmissionSnapshot() TCPConnectionAdmission {
	return TCPConnectionAdmission{
		Limit:    lowMemoryTCPConnectionAdmissionLimit,
		Active:   activeTCPConnectionSlots.Load(),
		Rejected: rejectedTCPConnectionTotal.Load(),
		Evicted:  evictedTCPConnectionTotal.Load(),
	}
}

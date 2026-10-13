//go:build with_low_memory

package tunnel

import "sync/atomic"

const lowMemoryUDPSessionLimit int64 = 128

var (
	activeUDPSessionSlots   atomic.Int64
	rejectedUDPSessionTotal atomic.Uint64
	evictedUDPSessionTotal  atomic.Uint64
)

func tryAcquireUDPSessionSlot() bool {
	for {
		active := activeUDPSessionSlots.Load()
		if active >= lowMemoryUDPSessionLimit {
			return false
		}
		if activeUDPSessionSlots.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func releaseUDPSessionSlot() { activeUDPSessionSlots.Add(-1) }

func noteUDPSessionRejected() { rejectedUDPSessionTotal.Add(1) }

func noteUDPSessionEvicted() { evictedUDPSessionTotal.Add(1) }

func UDPSessionAdmissionSnapshot() UDPSessionAdmission {
	return UDPSessionAdmission{
		Limit:    lowMemoryUDPSessionLimit,
		Active:   activeUDPSessionSlots.Load(),
		Rejected: rejectedUDPSessionTotal.Load(),
		Evicted:  evictedUDPSessionTotal.Load(),
	}
}

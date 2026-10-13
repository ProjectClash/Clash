//go:build !with_low_memory

package tunnel

func acquireTCPConnectionSlot() bool { return true }

func tryAcquireTCPConnectionSlot() bool { return true }

func noteTCPConnectionRejected() {}

func noteTCPConnectionEvicted() {}

func releaseTCPConnectionSlot() {}

func TCPConnectionAdmissionSnapshot() TCPConnectionAdmission {
	return TCPConnectionAdmission{}
}

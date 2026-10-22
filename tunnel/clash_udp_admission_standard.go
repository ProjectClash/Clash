//go:build !with_low_memory

package tunnel


func tryAcquireUDPSessionSlot() bool { return true }

func reserveUDPSessionSlot() {}

func cancelUDPSessionSlotReservation() {}

func tryTakeReservedUDPSessionSlot() bool { return true }

func releaseUDPSessionSlot() {}

func noteUDPSessionRejected() {}

func noteUDPSessionEvicted() {}

func UDPSessionAdmissionSnapshot() UDPSessionAdmission { return UDPSessionAdmission{} }

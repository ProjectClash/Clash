package tun

// GVisorTCPBufferBytes, when positive, pins the gVisor TCP send/receive buffer
// to a FIXED window (Default == Max == the value) for controlled benchmark runs
// — benchmark tooling sets it via the gomobile bind layer to A/B window
// sizes. When zero or negative (the default), the stack uses its adaptive range
// (4 KiB min / 32 KiB initial / 128 KiB max) and gVisor's receive-buffer
// moderation grows busy connections per measured demand; that range was chosen
// from on-device A/B numbers (see stack_gvisor.go).
//
// It lives in this un-tagged file (not stack_gvisor.go, which is //go:build
// with_gvisor) so the gomobile bind layer can set it from a build that does not
// itself compile the gVisor stack; stack_gvisor.go reads it at stack creation.
var GVisorTCPBufferBytes = 0

type GVisorPacketIOReport struct {
	IngressReadCalls       uint64
	IngressReadWouldBlock  uint64
	IngressReadPackets     uint64
	IngressReadBytes       uint64
	IngressReadErrors      uint64
	IngressDispatchPackets uint64
	IngressDispatchBytes   uint64
	ProcessorQueueDepth    uint64
	ProcessorQueuePeak     uint64
	EgressWriteCalls       uint64
	EgressWritePackets     uint64
	EgressWriteBytes       uint64
	EgressWriteErrors      uint64
	EgressWriteWaits         uint64
	EgressWriteWaitExhausted uint64
}

var GVisorPacketIOSnapshot func() GVisorPacketIOReport

type GVisorTCPWindowReport struct {
	MinBytes, DefaultBytes, MaxBytes int
	TCPConnections                   int
	ReceiveOccupancyP50Bytes, ReceiveOccupancyP95Bytes, ReceiveOccupancyMaxBytes int
	ConnectionsNearReceiveMax int
	SegmentQueueDroppedTotal uint64
}

var GVisorTCPWindowSnapshot func() GVisorTCPWindowReport

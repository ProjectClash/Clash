package fdbased

import (
	"sync/atomic"

	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
)

type PacketIOStats struct {
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

var packetIOCounters struct {
	ingressReadPackets       atomic.Uint64
	ingressReadBytes         atomic.Uint64
	ingressDispatchPackets   atomic.Uint64
	ingressDispatchBytes     atomic.Uint64
	processorQueueDepth      atomic.Uint64
	processorQueuePeak       atomic.Uint64
	egressWriteCalls         atomic.Uint64
	egressWritePackets       atomic.Uint64
	egressWriteBytes         atomic.Uint64
	egressWriteErrors        atomic.Uint64
	egressWriteWaits         atomic.Uint64
	egressWriteWaitExhausted atomic.Uint64
}

func ResetPacketIOStats() {
	rawfile.ResetPacketReadStats()
	packetIOCounters.ingressReadPackets.Store(0)
	packetIOCounters.ingressReadBytes.Store(0)
	packetIOCounters.ingressDispatchPackets.Store(0)
	packetIOCounters.ingressDispatchBytes.Store(0)
	packetIOCounters.processorQueueDepth.Store(0)
	packetIOCounters.processorQueuePeak.Store(0)
	packetIOCounters.egressWriteCalls.Store(0)
	packetIOCounters.egressWritePackets.Store(0)
	packetIOCounters.egressWriteBytes.Store(0)
	packetIOCounters.egressWriteErrors.Store(0)
	packetIOCounters.egressWriteWaits.Store(0)
	packetIOCounters.egressWriteWaitExhausted.Store(0)
}

func PacketIOStatsSnapshot() PacketIOStats {
	read := rawfile.PacketReadStatsSnapshot()
	return PacketIOStats{
		IngressReadCalls:         read.Syscalls,
		IngressReadWouldBlock:    read.WouldBlock,
		IngressReadPackets:       packetIOCounters.ingressReadPackets.Load(),
		IngressReadBytes:         packetIOCounters.ingressReadBytes.Load(),
		IngressReadErrors:        read.Errors,
		IngressDispatchPackets:   packetIOCounters.ingressDispatchPackets.Load(),
		IngressDispatchBytes:     packetIOCounters.ingressDispatchBytes.Load(),
		ProcessorQueueDepth:      packetIOCounters.processorQueueDepth.Load(),
		ProcessorQueuePeak:       packetIOCounters.processorQueuePeak.Load(),
		EgressWriteCalls:         packetIOCounters.egressWriteCalls.Load(),
		EgressWritePackets:       packetIOCounters.egressWritePackets.Load(),
		EgressWriteBytes:         packetIOCounters.egressWriteBytes.Load(),
		EgressWriteErrors:        packetIOCounters.egressWriteErrors.Load(),
		EgressWriteWaits:         packetIOCounters.egressWriteWaits.Load(),
		EgressWriteWaitExhausted: packetIOCounters.egressWriteWaitExhausted.Load(),
	}
}

func recordIngressRead(bytes int, packets uint64) {
	packetIOCounters.ingressReadPackets.Add(packets)
	if bytes > 0 {
		packetIOCounters.ingressReadBytes.Add(uint64(bytes))
	}
}

func recordIngressDispatch(bytes int) {
	packetIOCounters.ingressDispatchPackets.Add(1)
	if bytes > 0 {
		packetIOCounters.ingressDispatchBytes.Add(uint64(bytes))
	}
}

func recordProcessorQueued() {
	depth := packetIOCounters.processorQueueDepth.Add(1)
	for {
		peak := packetIOCounters.processorQueuePeak.Load()
		if depth <= peak || packetIOCounters.processorQueuePeak.CompareAndSwap(peak, depth) {
			return
		}
	}
}

func recordProcessorDequeued(packets uint64) {
	if packets == 0 {
		return
	}
	packetIOCounters.processorQueueDepth.Add(^(packets - 1))
}

func recordEgressWriteAttempt() {
	packetIOCounters.egressWriteCalls.Add(1)
}

func recordEgressWriteSuccess(packets uint64, bytes uint64) {
	packetIOCounters.egressWritePackets.Add(packets)
	packetIOCounters.egressWriteBytes.Add(bytes)
}

func recordEgressWriteError() {
	packetIOCounters.egressWriteErrors.Add(1)
}

func recordEgressWriteWait() {
	packetIOCounters.egressWriteWaits.Add(1)
}

func recordEgressWriteWaitExhausted() {
	packetIOCounters.egressWriteWaitExhausted.Add(1)
}

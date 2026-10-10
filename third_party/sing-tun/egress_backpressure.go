package tun

import "sync/atomic"

type TunEgressReport struct {
	WriteWaits, WriteWaitExhausted uint64
}

var tunEgressStats struct {
	waits, exhausted atomic.Uint64
}

func TunEgressSnapshot() TunEgressReport {
	return TunEgressReport{
		WriteWaits:         tunEgressStats.waits.Load(),
		WriteWaitExhausted: tunEgressStats.exhausted.Load(),
	}
}

func recordTunEgressWait()          { tunEgressStats.waits.Add(1) }
func recordTunEgressWaitExhausted() { tunEgressStats.exhausted.Add(1) }

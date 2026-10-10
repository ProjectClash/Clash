package clash

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter"
)

const (
	probeAdmissionStepBytes       = int64(3145728)
	probeAdmissionCeilingBytes    = int64(49283072)
	probeAdmissionChargeTTL       = time.Second
	probeAdmissionPoll            = 100 * time.Millisecond
	probeAdmissionMaxWait         = 3 * time.Second
	probeAdmissionForcedInterval  = time.Second
	probeAdmissionBackgroundGrace = 300 * time.Millisecond
)

type probeAdmissionVerdict uint8

const (
	probeAdmitted probeAdmissionVerdict = iota
	probeForced
	probeCtxExpired
	probeDeferred
)

type probeAdmissionConfig struct {
	stepBytes       int64
	ceilingBytes    int64
	chargeTTL       time.Duration
	poll            time.Duration
	maxWait         time.Duration
	forcedInterval  time.Duration
	backgroundGrace time.Duration
	footprint       func() int64
	scavenge        func()
}

var probeAdmissionCharges atomic.Int64

var probeAdmissionLastForcedNs atomic.Int64

func defaultProbeAdmissionConfig() probeAdmissionConfig {
	return probeAdmissionConfig{
		stepBytes:       probeAdmissionStepBytes,
		ceilingBytes:    probeAdmissionCeilingBytes,
		chargeTTL:       probeAdmissionChargeTTL,
		poll:            probeAdmissionPoll,
		maxWait:         probeAdmissionMaxWait,
		forcedInterval:  probeAdmissionForcedInterval,
		backgroundGrace: probeAdmissionBackgroundGrace,
		footprint:       MemoryFootprint,
		scavenge:        FreeMemory,
	}
}

func probeAdmissionWait(ctx context.Context, cfg probeAdmissionConfig) (waited time.Duration, verdict probeAdmissionVerdict) {
	return probeAdmissionAdmit(ctx, cfg, false)
}

func probeAdmissionAdmit(ctx context.Context, cfg probeAdmissionConfig, background bool) (waited time.Duration, verdict probeAdmissionVerdict) {
	charge := func() {
		probeAdmissionCharges.Add(1)
		time.AfterFunc(cfg.chargeTTL, func() { probeAdmissionCharges.Add(-1) })
	}
	tryReserve := func(footprint int64) bool {
		for {
			if ctx.Err() != nil {
				return false
			}
			charges := probeAdmissionCharges.Load()
			if footprint+(charges+1)*cfg.stepBytes > cfg.ceilingBytes {
				return false
			}
			if probeAdmissionCharges.CompareAndSwap(charges, charges+1) {
				time.AfterFunc(cfg.chargeTTL, func() { probeAdmissionCharges.Add(-1) })
				return true
			}
		}
	}
	tryForcedSlot := func() bool {
		for {
			if ctx.Err() != nil {
				return false
			}
			last := probeAdmissionLastForcedNs.Load()
			now := time.Now().UnixNano()
			if now-last < int64(cfg.forcedInterval) {
				return false
			}
			if probeAdmissionLastForcedNs.CompareAndSwap(last, now) {
				return true
			}
		}
	}
	start := time.Now()
	for {
		if ctx.Err() != nil {
			return time.Since(start), probeDeferred
		}
		footprint := cfg.footprint()
		if ctx.Err() != nil {
			return time.Since(start), probeDeferred
		}
		if footprint <= 0 {
			return time.Since(start), probeAdmitted
		}
		if tryReserve(footprint) {
			return time.Since(start), probeAdmitted
		}
		if background {
			if time.Since(start) >= cfg.backgroundGrace {
				return time.Since(start), probeDeferred
			}
		} else if time.Since(start) >= cfg.maxWait && tryForcedSlot() {
			if ctx.Err() != nil {
				return time.Since(start), probeDeferred
			}
			if cfg.scavenge != nil {
				cfg.scavenge()
			}
			if ctx.Err() != nil {
				return time.Since(start), probeDeferred
			}
			charge()
			return time.Since(start), probeForced
		}
		select {
		case <-ctx.Done():
			return time.Since(start), probeDeferred
		case <-time.After(cfg.poll):
		}
	}
}

func probeAdmissionShouldArm(budgetedPlatform, underNetworkExtension bool) bool {
	return budgetedPlatform && underNetworkExtension
}

func armProbeAdmission() {
	adapter.SetURLTestAdmission(newProbeAdmissionHook(defaultProbeAdmissionConfig()))
}

func newProbeAdmissionHook(cfg probeAdmissionConfig) func(context.Context) error {
	var diagnostics probeAdmissionDiagnostics
	return func(ctx context.Context) error {
		background := adapter.IsBackgroundProbe(ctx)
		waited, verdict := probeAdmissionAdmit(ctx, cfg, background)
		if waited >= cfg.poll || verdict == probeDeferred {
			diagnostics.record(waited, verdict, background, cfg.footprint)
		}
		if verdict == probeDeferred {
			return adapter.ErrURLTestDeferred
		}
		return nil
	}
}

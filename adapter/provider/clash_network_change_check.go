package provider

import (
	"sync"
	"time"

	"github.com/ProjectClash/Clash/common/singledo"
)

func (bp *baseProvider) HealthCheckAfterNetworkChange() {
	hc := bp.healthCheck
	if hc == nil || !hc.auto() {
		return
	}
	if hc.lazy && time.Since(hc.lastTouch.Load()) >= hc.interval {
		return
	}
	if hc.networkRounds.claim() {
		go hc.roundsAfterNetworkChange()
	}
}

type networkChangeRounds struct {
	mu      sync.Mutex
	running bool
	again   bool
}

func (r *networkChangeRounds) claim() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.again = true
		return false
	}
	r.running = true
	return true
}

func (r *networkChangeRounds) another(closed bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.again && !closed {
		r.again = false
		return true
	}
	r.running, r.again = false, false
	return false
}

func (hc *HealthCheck) roundsAfterNetworkChange() {
	for {
		if !holdBackgroundRound(hc.ctx) {
			hc.networkRounds.another(true)
			return
		}
		hc.round(singledo.NewSingle[struct{}](0), time.Time{}, true)
		if !hc.networkRounds.another(hc.ctx.Err() != nil) {
			return
		}
	}
}

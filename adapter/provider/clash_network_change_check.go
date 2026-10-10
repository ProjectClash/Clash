package provider

import (
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
	go hc.round(singledo.NewSingle[struct{}](0), time.Time{})
}

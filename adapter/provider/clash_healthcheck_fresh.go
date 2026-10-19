package provider

import (
	"time"

	C "github.com/ProjectClash/Clash/constant"
)


type urlTestRecordReader interface {
	LastURLTestRecord(url string) (record C.DelayHistory, alive bool, expected string, ok bool)
}

func measuredAliveSince(proxy C.Proxy, url string, expected string, timeout time.Duration, roundBegan time.Time) bool {
	reader, ok := proxy.(urlTestRecordReader)
	if !ok {
		return false
	}
	record, alive, asked, ok := reader.LastURLTestRecord(url)
	if !ok || !alive || record.Delay == 0 {
		return false
	}
	if asked != expected || time.Duration(record.Delay)*time.Millisecond > timeout {
		return false
	}
	return !record.Time.Before(roundBegan)
}

func (hc *HealthCheck) checkScheduled() {
	if !hc.scheduledHeld.CompareAndSwap(false, true) {
		return
	}
	defer hc.scheduledHeld.Store(false)
	hc.scheduledRound(time.Now())
}

func (hc *HealthCheck) scheduledOverdue() bool {
	last := hc.lastScheduled.Load()
	return last == 0 || time.Since(time.Unix(0, last)) >= hc.interval
}

func (hc *HealthCheck) untilScheduled() time.Duration {
	if hc.scheduledOverdue() {
		return hc.interval
	}
	return hc.interval - time.Since(time.Unix(0, hc.lastScheduled.Load()))
}

func (hc *HealthCheck) scheduledRound(began time.Time) {
	began, ok := scheduledRoundBegan(hc.ctx, began)
	if !ok {
		return
	}
	hc.lastScheduled.Store(began.UnixNano())
	hc.round(hc.scheduledDo, began, true)
}

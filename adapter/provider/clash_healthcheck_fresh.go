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
	hc.scheduledRound(time.Now())
}

func (hc *HealthCheck) scheduledRound(began time.Time) {
	began, ok := scheduledRoundBegan(hc.ctx, began)
	if !ok {
		return
	}
	hc.round(hc.scheduledDo, began, true)
}
